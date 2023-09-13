
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
                let a = wait_attach_game_manager(&process).await;

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

async fn wait_attach_game_manager(process: &Process) -> Option<(mono::Module, mono::Image, mono::Class)> {
    asr::print_message("attaching mono module image...");
    for _ in 0..0x10 { next_tick().await; }
    let (module, image) = attach_auto_detect_default(process)?;
    asr::print_message("attached mono module image");
    for _ in 0..0x10 { next_tick().await; }
    let game_manager_class = image.get_class(&process, &module, "GameManager")?;
    asr::print_message("GameManager class found");
    for _ in 0..0x10 { next_tick().await; }
    Some((module, image, game_manager_class))
}

fn attach_auto_detect_default(process: &Process) -> Option<(mono::Module, mono::Image)> {
    let module = mono::Module::attach_auto_detect(process)?;
    let image = module.get_default_image(process)?;
    Some((module, image))
}
