use std::{path::Path, fs::File, io::{Read, self}, mem};

use asr::{future::next_tick, Process, Address, string::ArrayCString, Address64, game_engine::unity::mono};
use bytemuck::CheckedBitPattern;
use memchr::memmem;

asr::async_main!(stable);

// --------------------------------------------------------

const UNITY_PLAYER_VERSION: &[u8] = b"Unity Player version ";
const UNITY_PLAYER_VERSION_LEN: usize = UNITY_PLAYER_VERSION.len();

// Magic mach-o header constants from:
// https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html

/* Constant for the magic field of the mach_header_32 (32-bit architectures) */
const MH_MAGIC_32: u32 = 0xfeedface; /* the mach magic number */
const MH_CIGAM_32: u32 = 0xcefaedfe; /* NXSwapInt(MH_MAGIC) */

/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
const MH_MAGIC_64: u32 = 0xfeedfacf; /* the 64-bit mach magic number */
const MH_CIGAM_64: u32 = 0xcffaedfe; /* NXSwapInt(MH_MAGIC_64) */

// --------------------------------------------------------

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
                mono::Version::V1 => &Self {
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
                mono::Version::V2 => &Self {
                    monoassembly_aname: 0x10,
                    monoassembly_image: 0x60,
                    monoassemblyname_name: 0x0,
                    glist_next: 0x8,
                    monoimage_class_cache: 0x4C0,
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
                    monovtable_vtable: 0x40,
                    monoclassfieldalignment: 0x20,
                },
                mono::Version::V3 => &Self {
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
            false => match version {
                mono::Version::V1 => &Self {
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
                mono::Version::V2 => &Self {
                    monoassembly_aname: 0x8,
                    monoassembly_image: 0x44,
                    monoassemblyname_name: 0x0,
                    glist_next: 0x4,
                    monoimage_class_cache: 0x354,
                    monointernalhashtable_table: 0x14,
                    monointernalhashtable_size: 0xC,
                    monoclassdef_next_class_cache: 0xA8,
                    monoclassdef_klass: 0x0,
                    monoclass_name: 0x2C,
                    monoclass_fields: 0x60,
                    monoclassdef_field_count: 0xA4,
                    monoclass_runtime_info: 0x84,
                    monoclass_vtable_size: 0x38,
                    monoclass_parent: 0x20,
                    monoclassfield_name: 0x4,
                    monoclassfield_offset: 0xC,
                    monoclassruntimeinfo_domain_vtables: 0x4,
                    monovtable_vtable: 0x28,
                    monoclassfieldalignment: 0x10,
                },
                mono::Version::V3 => &Self {
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
                let a = attach_auto_detect_default(&process);

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

fn attach_auto_detect_default(process: &Process) -> Option<(Address, Address)> {
    let version = detect_version(process)?;
    asr::print_message(&format!("version detected: {:?}", version));
    attach_default(process, version)
}

fn attach_default(process: &Process, version: mono::Version) -> Option<(Address, Address)> {
    attach(process, version, "Assembly-CSharp")
}

fn attach(process: &Process, version: mono::Version, assembly_name: &str) -> Option<(Address, Address)> {
    let mono_module = process.get_module_range("libmonobdwgc-2.0.dylib").ok()?;
    let (mono_module_addr, mono_module_len) = mono_module;
    let is_64_bit = is_64_bit(process)?;

    for i in 0..(mono_module_len/8) {
        let a = mono_module_addr + (i * 8);
        if let Some(image) = attach_assemblies(process, a, is_64_bit, version, assembly_name) {
            return Some((a, image));
        }
    }

    None
}

fn attach_assemblies(process: &Process, assemblies_addr: Address, is_64_bit: bool, version: mono::Version, assembly_name: &str) -> Option<Address> {
    let offsets = Offsets::new(version, is_64_bit);
    let mut assemblies = process.read::<Address64>(assemblies_addr).ok()?;
    let image = loop {
        let data = process.read::<Address64>(assemblies).ok()?;
        if data.is_null() { return None; }
        let name_addr = process.read::<Address64>(data + offsets.monoassembly_aname as u64 + offsets.monoassemblyname_name as u64).ok()?;
        let name = process.read::<ArrayCString<128>>(name_addr).ok()?;
        if name.matches(assembly_name) {
            break process.read::<Address64>(data + offsets.monoassembly_image as u64).ok()?;
        }
        assemblies = process.read::<Address64>(assemblies + offsets.glist_next as u64).ok()?;
    };
    Some(image.into())
}

fn detect_version(process: &Process) -> Option<mono::Version> {
    let process_path = process.get_path().ok()?;
    let contents_path = Path::new(&process_path).parent()?.parent()?;
    let info_plist_path = contents_path.join("Info.plist");
    let info_plist_bytes = file_read_all_bytes(info_plist_path).ok()?;
    // example: "Unity Player version 2020.2.2f1 "
    let upv = memmem::find(&info_plist_bytes, UNITY_PLAYER_VERSION)?;
    let version_string: ArrayCString<6> = slice_read(&info_plist_bytes, upv + UNITY_PLAYER_VERSION_LEN).ok()?;
    let (before, after) = version_string.split_at(version_string.iter().position(|&x| x == b'.')?);

    const ZERO: u8 = b'0';
    const NINE: u8 = b'9';

    let mut unity: u32 = 0;
    for &val in before {
        match val {
            ZERO..=NINE => unity = unity * 10 + (val - ZERO) as u32,
            _ => break,
        }
    }

    let mut unity_minor: u32 = 0;
    for &val in &after[1..] {
        match val {
            ZERO..=NINE => unity_minor = unity_minor * 10 + (val - ZERO) as u32,
            _ => break,
        }
    }

    Some(if (unity == 2021 && unity_minor >= 2) || (unity > 2021) {
        mono::Version::V3
    } else {
        mono::Version::V2
    })
}

fn is_64_bit(process: &Process) -> Option<bool> {
    let process_path = process.get_path().ok()?;
    let mut process_file = File::open(process_path).ok()?;
    let mut buffer: [u8; 4] = [0; 4];
    process_file.read_exact(&mut buffer).ok();
    let magic: u32 = bytemuck::checked::try_from_bytes(&buffer).ok().cloned()?;
    match magic {
        MH_MAGIC_64 | MH_CIGAM_64 => Some(true),
        MH_MAGIC_32 | MH_CIGAM_32 => Some(false),
        _ => None
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
fn slice_read<T: CheckedBitPattern>(slice: &[u8], address: usize) -> Result<T, bytemuck::checked::CheckedCastError> {
    let size = mem::size_of::<T>();
    let slice_src = &slice[address..(address + size)];
    bytemuck::checked::try_from_bytes(slice_src).cloned()
}
