
use asr::{future::next_tick, Process, game_engine::unity::mono};

asr::async_main!(stable);

// --------------------------------------------------------
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
                asr::print_message(&format!("done: {:?}", a.is_some()));
                loop {
                    // TODO: Do something on every tick.
                    next_tick().await;
                }
            })
            .await;
    }
}

fn attach_auto_detect_default(process: &Process) -> Option<(mono::Module, mono::Image)> {
    let module = mono::Module::attach_auto_detect(process)?;
    let image = module.get_default_image(process)?;
    Some((module, image))
}
