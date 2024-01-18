

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

    let m1 = asr::settings::Map::load();
    m1.insert("b", "this string is not a boolean");
    m1.store();

    let b2 = asr::settings::gui::add_bool("b", "b should be a bool", true);
    asr::print_message(&format!("b2: {}", b2));

    let m3 = asr::settings::Map::load();
    let b3 = m3.get("b");
    asr::print_message(&format!("b3: {:?}", b3));

    loop {
        next_tick().await;
    }
}
