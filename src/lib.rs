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
                // TODO: Attach Unity / Mono stuff with code similar to
                // GetRootDomainFunctionAddressMachOFormat from:
                // https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/AssemblyImageFactory.cs#L160

                // TODO: Load some initial information from the process.
                loop {
                    // TODO: Do something on every tick.
                    next_tick().await;
                }
            })
            .await;
    }
}
