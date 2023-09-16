use std::{path::Path, fs::File, io::{Read, self}, mem, slice};

use asr::{future::{next_tick, retry}, Process, Address, string::ArrayCString, signature::Signature, Address64, game_engine::unity::mono::{self, Version}};
use bytemuck::CheckedBitPattern;

asr::async_main!(stable);

// --------------------------------------------------------

const HOLLOW_KNIGHT_NAMES: [&str; 2] = [
    "hollow_knight.exe", // Windows
    "Hollow Knight", // Mac
];

const MONO_ASSEMBLY_FOREACH: &str = "_mono_assembly_foreach";
const MONO_ASSEMBLY_FOREACH_LEN: usize = MONO_ASSEMBLY_FOREACH.len();
const MONO_ASSEMBLY_FOREACH_LEN_1: usize = MONO_ASSEMBLY_FOREACH_LEN + 1;

const ITEMS_PER_TICK: u64 = 16384;

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
        let process = retry(|| {
            HOLLOW_KNIGHT_NAMES.into_iter().find_map(Process::attach)
        }).await;
        process
            .until_closes(async {
                let a = attach(&process).await;

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

async fn attach(process: &Process) -> Option<Address> {
    // TODO: Attach Unity / Mono stuff with code similar to
    // GetRootDomainFunctionAddressMachOFormat from:
    // https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/AssemblyImageFactory.cs#L160
    let mono_module = process.get_module_range("libmonobdwgc-2.0.dylib").ok()?;
    let (mono_module_addr, mono_module_len) = mono_module;

    let process_path = process.get_path().ok()?;
    let contents_path = Path::new(&process_path).parent()?.parent()?;
    let mono_module_path = contents_path.join("Frameworks").join("libmonobdwgc-2.0.dylib");
    let module_from_path = file_read_all_bytes(mono_module_path).ok()?;
    let macho_offsets = MachOFormatOffsets::new();
    let number_of_commands: u32 = slice_read(&module_from_path, macho_offsets.number_of_commands)?;

    let mut root_domain_function_offset: u32 = 0;

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
                let symbol_name: ArrayCString<MONO_ASSEMBLY_FOREACH_LEN_1> = slice_read(&module_from_path, (string_table_offset + symbol_name_offset) as usize)?;

                if symbol_name.matches(MONO_ASSEMBLY_FOREACH) {
                    root_domain_function_offset = slice_read(&module_from_path, symbol_table_offset as usize + (j * macho_offsets.size_of_nlist_item) + macho_offsets.nlist_value)?;
                    asr::print_message(&format!("MONO_ASSEMBLY_FOREACH_offset: {:X}", root_domain_function_offset));
                    asr::print_message(&format!("mono_module_len: {}", mono_module_len));
                    break;
                }
            }

            break;
        } else {
            let command_size: u32 = slice_read(&module_from_path, offset_to_next_command + macho_offsets.command_size)?;
            offset_to_next_command += command_size as usize;
        }
    }

    if root_domain_function_offset == 0 {
        return None;
    }
    let function_array: [u8; 0x100] = slice_read(&module_from_path, root_domain_function_offset as usize)?;
    asr::print_message(&format!("function_array: {:02X?}", function_array));

    let sig_function_array: Signature<0x100> = Signature::Simple(function_array);
    let root_domain_function_address = sig_function_array.scan_process_range(process, mono_module)?;

    if let Some(a) = memchr::memmem::find(&function_array, &[0x48, 0x8D, 0x0D]) {
        asr::print_message("found 48 8D 0D in function_array.");
        let scan_offset = a + 3;
        if let Some(relative) = slice_read::<i32>(&function_array, scan_offset) {
            let assemblies = root_domain_function_address + scan_offset as u32 + 0x4 + relative;
            asr::print_message(&format!("a: {:X}, scan_offset: {:X}, relative: {:X}, assemblies? {}", a, scan_offset, relative, assemblies));
            if attach_assemblies(process, assemblies).is_some() {
                asr::print_message("found RIP-relative in function_array.");
                asr::print_message(&format!("assemblies: {}", assemblies));
            }
        }
    } else {
        asr::print_message("48 8D 0D not found.");
    }

    next_tick().await;

    let mut assemblies_address = Address::NULL;

    let root_domain_function_offset_in_page = root_domain_function_address.value() & 0xfff;
    let number_of_pages = mono_module_len / 0x1000;
    const SIG_MONO_64: Signature<3> = Signature::new("48 8B 0D");
    // const SIG_3: Signature<3> = Signature::new("48 8D 0D");
    asr::print_message("looking at offset in page...");
    asr::print_message(&format!("0x{:X}", root_domain_function_offset_in_page));
    for i in 0..number_of_pages {
        let a = Address::new(mono_module_addr.value() + (i * 0x1000) + root_domain_function_offset_in_page);
        if process.read::<u8>(a).is_ok() {
            let mb = SIG_MONO_64.scan_process_range(process, (a, 0x100));
            if let Some(b) = mb {
                let scan_address = b + 3;
                let mc = process.read::<i32>(scan_address).ok();
                if let Some(c) = mc {
                    let assemblies = scan_address + 0x4 + c;
                    if attach_assemblies(process, assemblies).is_some() {
                        asr::print_message("found at offset in page.");
                        assemblies_address = assemblies;
                        break;
                    }
                }
            }
        }
        if 0 == i % 4 {
            next_tick().await;
        }
    }

    asr::print_message("looking everywhere else...");
    next_tick().await;

    for i in 0..(mono_module_len/8) {
        let a = Address::new(mono_module_addr.value() + (i * 8));
        if attach_assemblies(process, a).is_some() {
            asr::print_message("found somewhere else.");
            let actual_offset_in_page = a.value() & 0xfff;
            asr::print_message(&format!("0x{:X}", actual_offset_in_page));
            asr::print_message(&format!("0x{:X}", a.value() - mono_module_addr.value()));
            asr::print_message(&format!("0x{}", a));
            assemblies_address = a;
            break;
        }
        if 0 == i % ITEMS_PER_TICK {
            next_tick().await;
        }
    }

    if assemblies_address.is_null() {
        return None;
    }
    next_tick().await;

    for i in 0..(0x100 - 7) {
        let scan_offset = i + 3;
        if let Some(relative) = slice_read::<i32>(&function_array, scan_offset) {
            let assemblies = root_domain_function_address + scan_offset as u32 + 0x4 + relative;
            if assemblies == assemblies_address {
                asr::print_message("found stuff RIP-relative from function_array");
            }
        }
    }
    next_tick().await;

    let macho_addr = root_domain_function_address + (- (root_domain_function_offset as i32));
    for i in 0..(module_from_path.len() - 7) {
        let scan_offset = i + 3;
        if let Some(relative) = slice_read::<i32>(&module_from_path, scan_offset) {
            let assemblies = macho_addr + scan_offset as u32 + 0x4 + relative;
            if assemblies == assemblies_address {
                asr::print_message("found stuff RIP-relative from module_from_path");
            }
        }
    }
    next_tick().await;

    for i in 0..(mono_module_len - 7) {
        let a = mono_module_addr + i;
        let scan_address = a + 3;
        let mc = process.read::<i32>(scan_address).ok();
        if let Some(c) = mc {
            let assemblies = scan_address + 0x4 + c;
            if assemblies == assemblies_address {
                asr::print_message("found stuff RIP-relative?");
                if let (Ok(a0), Ok(a1), Ok(a2)) = (process.read::<u8>(a), process.read::<u8>(a + 1), process.read::<u8>(a + 2)) {
                    asr::print_message(&format!("{:02X} {:02X} {:02X}", a0, a1, a2));
                    asr::print_message(&format!("a: {}, scan_address: {}, c: {:X}, assemblies: {}", a, scan_address, c, assemblies));
                }
            }
        }
        if let Ok(d) = process.read::<Address64>(a) {
            if d.value() == assemblies_address.value() {
                asr::print_message("found stuff absolute?");
                asr::print_message(&format!("a: {}, d: {}", a, d));
            }
        }
        if let Ok(e) = process.read::<i32>(a) {
            let assemblies = mono_module_addr + e;
            if assemblies == assemblies_address {
                asr::print_message("found stuff with offset?");
                asr::print_message(&format!("a: {}, e: {:X}, assemblies: {}", a, e, assemblies));
            }
        }
        if 0 == i % ITEMS_PER_TICK {
            next_tick().await;
        }
    }

    // 554889E5 41574156 41545349 89F64989 FF488D3D 229A1B00 E82DCB0F 0085C075 41488B3D AA9A1B00 E8B8330E 004889C3 488D3D03 9A1B00E8 1ACB0F00 85C0754F 488B3D8B 9A1B004C 89FE4C89 F2E8E632 0E004889 DF5B415C 415E415F 5DE9EA2E 0E0089C3 89C7E863 FD0D0048 8D155EE3 0F00488D 0D84E30F 0031FFBE 04000000 4989C041 89D931C0 E8D6F10D 00EBFE41 89C489C7 E835FD0D 00488D15 70E30F00 488D0D98 E30F0031 FFBE0400 00004989 C04589E1 31C0E8A8 F10D00EB FE554889 E5415653 488D3D6F 991B00E8 6ECA0F00 85C00F85 C1000000 488D3D9B 991B00E8 5ACA0F00 85C00F85 DA000000 488B1DF7 991B0048 85DB7425 4C8B334C 89F7E8F0

    Some(assemblies_address)
}

fn attach_assemblies(process: &Process, assemblies_addr: Address) -> Option<Address> {
    let offsets = Offsets::new(mono::Version::V2, true, BinaryFormat::MachO);
    let mut assemblies = process.read::<Address64>(assemblies_addr).ok()?;
    let image = loop {
        let data = process.read::<Address64>(assemblies).ok()?;
        if data.is_null() { return None; }
        let name_addr = process.read::<Address64>(data + offsets.monoassembly_aname as u64 + offsets.monoassemblyname_name as u64).ok()?;
        let name = process.read::<ArrayCString<128>>(name_addr).ok()?;
        if name.matches("Assembly-CSharp") {
            asr::print_message("name.matches(\"Assembly-CSharp\")");
            break process.read::<Address64>(data + offsets.monoassembly_image as u64).ok()?;
        }
        assemblies = process.read::<Address64>(assemblies + offsets.glist_next as u64).ok()?;
    };
    Some(image.into())
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
