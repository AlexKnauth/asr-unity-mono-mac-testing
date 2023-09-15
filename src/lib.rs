use std::{path::Path, fs::File, io::{Read, self}, mem, slice};

use asr::{future::next_tick, Process, Address, string::ArrayCString, signature::Signature, Address64, game_engine::unity::mono::{self, Version}};
use bytemuck::CheckedBitPattern;

asr::async_main!(stable);

// --------------------------------------------------------
// --------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Hash, Debug)]
enum BinaryFormat {
    PE,
    MachO,
}

struct MachOFormatOffsets {
    number_of_commands: usize,
    load_commands: usize,
    command_size: usize,
    symbol_table_offset: usize,
    number_of_symbols: usize,
    string_table_offset: usize,
    nlist_value: usize,
    size_of_nlist_item: usize,
}

impl MachOFormatOffsets {
    const fn new() -> Self {
        // offsets taken from:
        //  - https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/Offsets/MachOFormatOffsets.cs
        //  - https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
        MachOFormatOffsets {
            number_of_commands: 0x10,
            load_commands: 0x20,
            command_size: 0x04,
            symbol_table_offset: 0x08,
            number_of_symbols: 0x0c,
            string_table_offset: 0x10,
            nlist_value: 0x08,
            size_of_nlist_item: 0x10,
        }
    }
}

struct Offsets {
    monoassembly_aname: u8,
    monoassembly_image: u8,
    monoassemblyname_name: u8,
    glist_next: u8,
    monoimage_class_cache: u16,
    monointernalhashtable_table: u8,
    monointernalhashtable_size: u8,
    monoclassdef_next_class_cache: u16,
    monoclassdef_klass: u8,
    monoclass_name: u8,
    monoclass_fields: u8,
    monoclassdef_field_count: u16,
    monoclass_runtime_info: u8,
    monoclass_vtable_size: u8,
    monoclass_parent: u8,
    monoclassfield_name: u8,
    monoclassfield_offset: u8,
    monoclassruntimeinfo_domain_vtables: u8,
    monovtable_vtable: u8,
    monoclassfieldalignment: u8,
}

impl Offsets {
    const fn new(version: mono::Version, is_64_bit: bool, format: BinaryFormat) -> &'static Self {
        match (is_64_bit, format) {
            (true, BinaryFormat::PE) => match version {
                Version::V1 => &Self {
                    monoassembly_aname: 0x10,
                    monoassembly_image: 0x58,
                    monoassemblyname_name: 0x0,
                    glist_next: 0x8,
                    monoimage_class_cache: 0x3D0,
                    monointernalhashtable_table: 0x20,
                    monointernalhashtable_size: 0x18,
                    monoclassdef_next_class_cache: 0x100,
                    monoclassdef_klass: 0x0,
                    monoclass_name: 0x48,
                    monoclass_fields: 0xA8,
                    monoclassdef_field_count: 0x94,
                    monoclass_runtime_info: 0xF8,
                    monoclass_vtable_size: 0x18, // MonoVtable.data
                    monoclass_parent: 0x30,
                    monoclassfield_name: 0x8,
                    monoclassfield_offset: 0x18,
                    monoclassruntimeinfo_domain_vtables: 0x8,
                    monovtable_vtable: 0x48,
                    monoclassfieldalignment: 0x20,
                },
                // 64-bit V2 matches Unity2019_4_2020_3_x64_PE_Offsets from
                // https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/Offsets/MonoLibraryOffsets.cs#L49
                Version::V2 => &Self {
                    monoassembly_aname: 0x10,
                    monoassembly_image: 0x60, // AssemblyImage = 0x44 + 0x1c
                    monoassemblyname_name: 0x0,
                    glist_next: 0x8,
                    monoimage_class_cache: 0x4C0, // ImageClassCache = 0x354 + 0x16c
                    monointernalhashtable_table: 0x20, // HashTableTable = 0x14 + 0xc
                    monointernalhashtable_size: 0x18, // HashTableSize = 0xc + 0xc
                    monoclassdef_next_class_cache: 0x108, // TypeDefinitionNextClassCache = 0xa8 + 0x34 + 0x10 + 0x18 + 0x4
                    monoclassdef_klass: 0x0,
                    monoclass_name: 0x48, // TypeDefinitionName = 0x2c + 0x1c
                    monoclass_fields: 0x98, // TypeDefinitionFields = 0x60 + 0x20 + 0x18
                    monoclassdef_field_count: 0x100, // TypeDefinitionFieldCount = 0xa4 + 0x34 + 0x10 + 0x18
                    monoclass_runtime_info: 0xD0, // TypeDefinitionRuntimeInfo = 0x84 + 0x34 + 0x18
                    monoclass_vtable_size: 0x5C, // TypeDefinitionVTableSize = 0x38 + 0x24
                    monoclass_parent: 0x30, // TypeDefinitionParent = 0x20 + 0x10
                    monoclassfield_name: 0x8,
                    monoclassfield_offset: 0x18,
                    monoclassruntimeinfo_domain_vtables: 0x8, // TypeDefinitionRuntimeInfoDomainVTables = 0x4 + 0x4
                    monovtable_vtable: 0x40, // VTable = 0x28 + 0x18
                    monoclassfieldalignment: 0x20,
                },
                Version::V3 => &Self {
                    monoassembly_aname: 0x10,
                    monoassembly_image: 0x60,
                    monoassemblyname_name: 0x0,
                    glist_next: 0x8,
                    monoimage_class_cache: 0x4D0,
                    monointernalhashtable_table: 0x20,
                    monointernalhashtable_size: 0x18,
                    monoclassdef_next_class_cache: 0x108,
                    monoclassdef_klass: 0x0,
                    monoclass_name: 0x48,
                    monoclass_fields: 0x98,
                    monoclassdef_field_count: 0x100,
                    monoclass_runtime_info: 0xD0,
                    monoclass_vtable_size: 0x5C,
                    monoclass_parent: 0x30,
                    monoclassfield_name: 0x8,
                    monoclassfield_offset: 0x18,
                    monoclassruntimeinfo_domain_vtables: 0x8,
                    monovtable_vtable: 0x48,
                    monoclassfieldalignment: 0x20,
                },
            },
            (false, BinaryFormat::PE) => match version {
                Version::V1 => &Self {
                    monoassembly_aname: 0x8,
                    monoassembly_image: 0x40,
                    monoassemblyname_name: 0x0,
                    glist_next: 0x4,
                    monoimage_class_cache: 0x2A0,
                    monointernalhashtable_table: 0x14,
                    monointernalhashtable_size: 0xC,
                    monoclassdef_next_class_cache: 0xA8,
                    monoclassdef_klass: 0x0,
                    monoclass_name: 0x30,
                    monoclass_fields: 0x74,
                    monoclassdef_field_count: 0x64,
                    monoclass_runtime_info: 0xA4,
                    monoclass_vtable_size: 0xC, // MonoVtable.data
                    monoclass_parent: 0x24,
                    monoclassfield_name: 0x4,
                    monoclassfield_offset: 0xC,
                    monoclassruntimeinfo_domain_vtables: 0x4,
                    monovtable_vtable: 0x28,
                    monoclassfieldalignment: 0x10,
                },
                // 32-bit V2 matches Unity2018_4_10_x86_PE_Offsets from
                // https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/Offsets/MonoLibraryOffsets.cs#L12
                Version::V2 => &Self {
                    monoassembly_aname: 0x8,
                    monoassembly_image: 0x44, // AssemblyImage
                    monoassemblyname_name: 0x0,
                    glist_next: 0x4,
                    monoimage_class_cache: 0x354, // ImageClassCache
                    monointernalhashtable_table: 0x14, // HashTableTable
                    monointernalhashtable_size: 0xC, // HashTableSize
                    monoclassdef_next_class_cache: 0xA8, // TypeDefinitionNextClassCache
                    monoclassdef_klass: 0x0,
                    monoclass_name: 0x2C, // TypeDefinitionName
                    monoclass_fields: 0x60, // TypeDefinitionFields
                    monoclassdef_field_count: 0xA4, // TypeDefinitionFieldCount
                    monoclass_runtime_info: 0x84, // TypeDefinitionRuntimeInfo
                    monoclass_vtable_size: 0x38, // TypeDefinitionVTableSize
                    monoclass_parent: 0x20, // TypeDefinitionParent
                    monoclassfield_name: 0x4,
                    monoclassfield_offset: 0xC,
                    monoclassruntimeinfo_domain_vtables: 0x4, // TypeDefinitionRuntimeInfoDomainVTables
                    monovtable_vtable: 0x28, // VTable
                    monoclassfieldalignment: 0x10,
                },
                Version::V3 => &Self {
                    monoassembly_aname: 0x8,
                    monoassembly_image: 0x48,
                    monoassemblyname_name: 0x0,
                    glist_next: 0x4,
                    monoimage_class_cache: 0x35C,
                    monointernalhashtable_table: 0x14,
                    monointernalhashtable_size: 0xC,
                    monoclassdef_next_class_cache: 0xA0,
                    monoclassdef_klass: 0x0,
                    monoclass_name: 0x2C,
                    monoclass_fields: 0x60,
                    monoclassdef_field_count: 0x9C,
                    monoclass_runtime_info: 0x7C,
                    monoclass_vtable_size: 0x38,
                    monoclass_parent: 0x20,
                    monoclassfield_name: 0x4,
                    monoclassfield_offset: 0xC,
                    monoclassruntimeinfo_domain_vtables: 0x4,
                    monovtable_vtable: 0x2C,
                    monoclassfieldalignment: 0x10,
                },
            },
            (true, BinaryFormat::MachO) => match version {
                Version::V1 => panic!("MachO V1 not supported"),
                // 64-bit MachO V2 matches Unity2019_4_2020_3_x64_MachO_Offsets from
                // https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/Offsets/MonoLibraryOffsets.cs#L86
                Version::V2 => &Self {
                    monoassembly_aname: 0x10,
                    monoassembly_image: 0x60, // AssemblyImage = 0x44 + 0x1c
                    monoassemblyname_name: 0x0,
                    glist_next: 0x8,
                    monoimage_class_cache: 0x4C0, // ImageClassCache = 0x354 + 0x16c
                    monointernalhashtable_table: 0x20, // HashTableTable = 0x14 + 0xc
                    monointernalhashtable_size: 0x18, // HashTableSize = 0xc + 0xc
                    monoclassdef_next_class_cache: 0x100, // TypeDefinitionNextClassCache = 0xa8 + 0x34 + 0x10 + 0x18 + 0x4 - 0x8
                    monoclassdef_klass: 0x0,
                    monoclass_name: 0x40, // TypeDefinitionName = 0x2c + 0x1c - 0x8
                    monoclass_fields: 0x90, // TypeDefinitionFields = 0x60 + 0x20 + 0x18 - 0x8
                    monoclassdef_field_count: 0xF8, // TypeDefinitionFieldCount = 0xa4 + 0x34 + 0x10 + 0x18 - 0x8
                    monoclass_runtime_info: 0xC8, // TypeDefinitionRuntimeInfo = 0x84 + 0x34 + 0x18 - 0x8
                    monoclass_vtable_size: 0x54, // TypeDefinitionVTableSize = 0x38 + 0x24 - 0x8
                    monoclass_parent: 0x28, // TypeDefinitionParent = 0x20 + 0x10 - 0x8
                    monoclassfield_name: 0x8,
                    monoclassfield_offset: 0x18,
                    monoclassruntimeinfo_domain_vtables: 0x8, // TypeDefinitionRuntimeInfoDomainVTables = 0x4 + 0x4
                    monovtable_vtable: 0x40, // VTable = 0x28 + 0x18
                    monoclassfieldalignment: 0x20,
                },
                Version::V3 => panic!("MachO V3 not supported"),
            },
            (false, BinaryFormat::MachO) => panic!("32-bit MachO format not supported"),
        }
    }
}

// --------------------------------------------------------

async fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        asr::print_message(&panic_info.to_string());
    }));

    // TODO: Set up some general state and settings.

    asr::print_message("Hello, World!");

    loop {
        let process = Process::wait_attach("Hollow Knight").await;
        process
            .until_closes(async {
                let a = attach(&process);

                // TODO: Load some initial information from the process.
                asr::print_message(&format!("done: {:?}", a));
                loop {
                    // TODO: Do something on every tick.
                    next_tick().await;
                }
            })
            .await;
    }
}

fn attach(process: &Process) -> Option<Address> {
    // TODO: Attach Unity / Mono stuff with code similar to
    // GetRootDomainFunctionAddressMachOFormat from:
    // https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/AssemblyImageFactory.cs#L160
    let unity_module = process.get_module_range("UnityPlayer.dylib").ok()?;
    let (unity_module_addr, unity_module_len) = unity_module;
    let process_path = process.get_path().ok()?;
    let contents_path = Path::new(&process_path).parent()?.parent()?;
    let unity_module_path = contents_path.join("Frameworks").join("UnityPlayer.dylib");
    let module_from_path = file_read_all_bytes(unity_module_path).ok()?;
    let macho_offsets = MachOFormatOffsets::new();
    let number_of_commands: u32 = slice_read(&module_from_path, macho_offsets.number_of_commands)?;

    let mut something_scene_something_address = Address::NULL;

    let mut offset_to_next_command: usize = macho_offsets.load_commands as usize;
    for _i in 0..number_of_commands {
        // Check if load command is LC_SYMTAB
        let next_command: i32 = slice_read(&module_from_path, offset_to_next_command)?;
        if next_command == 2 {
            let symbol_table_offset: u32 = slice_read(&module_from_path, offset_to_next_command + macho_offsets.symbol_table_offset)?;
            let number_of_symbols: u32 = slice_read(&module_from_path, offset_to_next_command + macho_offsets.number_of_symbols)?;
            let string_table_offset: u32 = slice_read(&module_from_path, offset_to_next_command + macho_offsets.string_table_offset)?;

            for j in 0..(number_of_symbols as usize) {
                let symbol_name_offset: u32 = slice_read(&module_from_path, symbol_table_offset as usize + (j * macho_offsets.size_of_nlist_item))?;
                let symbol_name: ArrayCString<128> = slice_read(&module_from_path, (string_table_offset + symbol_name_offset) as usize)?;

                if let Ok(symbol_name_str) = String::from_utf8(symbol_name.to_vec()) {
                    if symbol_name_str.to_lowercase().contains("scene") {
                        asr::print_message(&format!("symbol_name: {:?}", String::from_utf8(symbol_name.to_vec())));
                        let something_scene_something_offset: u32 = slice_read(&module_from_path, symbol_table_offset as usize + (j * macho_offsets.size_of_nlist_item) + macho_offsets.nlist_value)?;
                        asr::print_message(&format!("something_scene_something_offset: 0x{:X}", something_scene_something_offset));
                        asr::print_message(&format!("unity_module_len: 0x{:X}", unity_module_len));
                        something_scene_something_address = unity_module_addr + something_scene_something_offset;
                        break;
                    }
                }
            }

            break;
        } else {
            let command_size: u32 = slice_read(&module_from_path, offset_to_next_command + macho_offsets.command_size)?;
            offset_to_next_command += command_size as usize;
        }
    }

    if something_scene_something_address.is_null() {
        // return None;
    }

    if process.read::<u8>(something_scene_something_address).is_ok() {
        // return Some(something_scene_something_address);
    }

    let root_domain_function_offset_in_page = something_scene_something_address.value() & 0xfff;
    let number_of_pages = unity_module_len / 0x1000;
    const SIG_MONO_64: Signature<3> = Signature::new("48 8B 0D");
    asr::print_message("looking at offset in page...");
    asr::print_message(&format!("0x{:X}", root_domain_function_offset_in_page));
    for i in 0..number_of_pages {
        let a = Address::new(unity_module_addr.value() + (i * 0x1000) + root_domain_function_offset_in_page);
        if process.read::<u8>(a).is_ok() {
            let mb = SIG_MONO_64.scan_process_range(process, (a, 0x100));
            if let Some(b) = mb {
                let scan_address = b + 3;
                let mc = process.read::<i32>(scan_address).ok();
                if let Some(c) = mc {
                    let assemblies = scan_address + 0x4 + c;
                    if attach_scene_manager(process, assemblies).is_some() {
                        asr::print_message("found at offset in page.");
                        return Some(a);
                    }
                }
            }
        }
    }

    const SIG_64_BIT: Signature<13> = Signature::new("48 83 EC 20 4C 8B ?5 ???????? 33 F6");
    asr::print_message(&format!("SIG_64_BIT: {:?}", SIG_64_BIT.scan_process_range(process, unity_module)));

    const SIG_7: Signature<7> = Signature::new("48 83 EC 20 4C 8B ?5");
    let scan_7 = SIG_7.scan_process_range(process, unity_module);
    asr::print_message(&format!("SIG_7: {:?}", scan_7));
    if let Some(found_7) = scan_7 {
        let addr = found_7 + 7;
        if let Ok(at_7) = process.read::<i32>(addr) {
            asr::print_message(&format!("0x{:010X}", at_7));
            asr::print_message(&format!("0x{:010}", addr + 0x4 + at_7));
        }
    }

    asr::print_message("looking everywhere else...");

    for i in 0..(unity_module_len/8) {
        let a = Address::new(unity_module_addr.value() + (i * 8));
        if attach_scene_manager(process, a).is_some() {
            asr::print_message("found somewhere else.");
            let actual_offset_in_page = a.value() & 0xfff;
            asr::print_message(&format!("0x{:010X}", actual_offset_in_page));
            let actual_offset_in_module = a.value() - unity_module_addr.value();
            asr::print_message(&format!("0x{:010X}", actual_offset_in_module));
            asr::print_message(&format!("0x{:010X}", a.value()));
            return Some(a);
        }
    }

    None
}

fn attach_scene_manager(process: &Process, a: Address) -> Option<Address> {
    const ASSETS_SCENES: &[u8] = b"Assets/Scenes/";
    const ASSETS_SCENES_LEN: usize = ASSETS_SCENES.len();
    const SCENE_ASSET_PATH_OFFSET: u64 = 0x10;
    const ACTIVE_SCENE_OFFSET: u64 = 0x48;
    const ACTIVE_SCENE_CONTENTS_PATH: &[u64] = &[0, ACTIVE_SCENE_OFFSET, SCENE_ASSET_PATH_OFFSET, 0];

    let s1: ArrayCString<ASSETS_SCENES_LEN> = process.read_pointer_path64(a, ACTIVE_SCENE_CONTENTS_PATH).ok()?;
    if s1.matches(ASSETS_SCENES) {
        Some(a)
    } else {
        None
    }
}

fn file_read_all_bytes<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buffer: Vec<u8> = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

// like Process::read, except it reads from a slice instead
// of reading from the process memory
fn slice_read<T: CheckedBitPattern>(slice: &[u8], address: usize) -> Option<T> {
    let size = mem::size_of::<T>();
    let slice_src = &slice[address..(address + size)];
    unsafe {
        let mut value = mem::MaybeUninit::<T>::uninit();
        let slice_dst: &mut [u8] = slice::from_raw_parts_mut(value.as_mut_ptr().cast(), size);
        slice_dst.copy_from_slice(slice_src);
        if !T::is_valid_bit_pattern(&*value.as_ptr().cast::<T::Bits>()) {
            return None;
        }
        Some(value.assume_init())
    }
}
