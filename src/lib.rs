use std::{path::Path, fs::File, io::{Read, self}};

use asr::{future::next_tick, Process};

asr::async_main!(stable);

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
    Some(())
}

pub fn file_read_all_bytes<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buffer: Vec<u8> = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}
