

use asr::future::next_tick;

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
        next_tick().await;
    }
}
