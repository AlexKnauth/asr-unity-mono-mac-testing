use std::{path::Path, fs::File, io::{Read, self}, mem, slice};

use asr::{future::next_tick, Process, Address};
use bytemuck::CheckedBitPattern;

asr::async_main!(stable);

// --------------------------------------------------------

struct MachOFormatOffsets {
    number_of_commands: u8,
    load_commands: u8,
    command_size: u8,
    symbol_table_offset: u8,
    number_of_symbols: u8,
    string_table_offset: u8,
    nlist_value: u8,
    size_of_nlist_item: u8,
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

fn attach(process: &Process) -> Option<()> {
    // TODO: Attach Unity / Mono stuff with code similar to
    // GetRootDomainFunctionAddressMachOFormat from:
    // https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/AssemblyImageFactory.cs#L160
    let mono_module = process.get_module_range("libmonobdwgc-2.0.dylib").ok()?;
    let (mono_module_addr, mono_module_len) = mono_module;
    asr::print_message(&format!("attach found mono module: {}, {}", mono_module_addr, mono_module_len));
    let process_path = process.get_path().ok()?;
    let contents_path = Path::new(&process_path).parent()?.parent()?;
    let mono_module_path = contents_path.join("Frameworks").join("libmonobdwgc-2.0.dylib");
    let module_from_path = file_read_all_bytes(mono_module_path).ok()?;
    asr::print_message(&format!("module_from_path: {:X} {:X} {:X} {:X}", module_from_path[0], module_from_path[1], module_from_path[2], module_from_path[3]));
    let macho_offsets = MachOFormatOffsets::new();
    let number_of_commands: u32 = slice_read(&module_from_path, macho_offsets.number_of_commands as usize)?;
    asr::print_message(&format!("number_of_commands: {}", number_of_commands));
    Some(())
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
