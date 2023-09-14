use std::{path::Path, fs::File, io::{Read, self}, mem, slice};

use asr::{future::next_tick, Process, Address, string::ArrayCString, signature::Signature, Address64, game_engine::unity::mono};
use bytemuck::CheckedBitPattern;

asr::async_main!(stable);

// --------------------------------------------------------
// --------------------------------------------------------

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
    const fn new(version: mono::Version, is_64_bit: bool) -> &'static Self {
        match is_64_bit {
            true => match version {
                mono::Version::V1 => panic!("MachO V1 not supported"),
                // 64-bit MachO V2 matches Unity2019_4_2020_3_x64_MachO_Offsets from
                // https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/Offsets/MonoLibraryOffsets.cs#L86
                mono::Version::V2 => &Self {
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
                mono::Version::V3 => panic!("MachO V3 not supported"),
            },
            false => panic!("32-bit MachO format not supported"),
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
