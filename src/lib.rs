
use std::collections::BTreeMap;

use asr::{future::{next_tick, retry}, Process, game_engine::unity::{SceneManager, get_scene_name}, string::ArrayCString};

asr::async_main!(stable);

// --------------------------------------------------------

const SUPERLIMINAL_NAMES: [&str; 2] = [
    "SuperliminalSteam.exe", // Windows
    "SuperliminalSteam", // Mac
];

// --------------------------------------------------------

async fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        asr::print_message(&panic_info.to_string());
    }));

    // TODO: Set up some general state and settings.

    asr::print_message("Hello, World!");

    loop {
        let process = retry(|| {
            SUPERLIMINAL_NAMES.into_iter().find_map(Process::attach)
        }).await;
        process
            .until_closes(async {
                asr::print_message("attaching SceneManager...");
                for _ in 0..0x10 { next_tick().await; }
                let scene_manager = SceneManager::wait_attach(&process).await;
                asr::print_message("attached SceneManager");

                // TODO: Load some initial information from the process.
                let mut string_table: BTreeMap<(&str, u64), Option<String>> = BTreeMap::new();
                string_table.insert(("SceneManager", 0), None);
                loop {
                    // TODO: Do something on every tick.
                    let scene_manager_scene_name: Option<String> = scene_manager.get_current_scene_path::<64>(&process).ok().map(scene_path_to_name_string);
                    if Some(&scene_manager_scene_name) != string_table.get(&("SceneManager", 0)) {
                        string_table.insert(("SceneManager", 0), scene_manager_scene_name);
                        asr::print_message(&format!("SceneManager sceneName: {:?}", string_table.get(&("SceneManager", 0))));
                    }
                    next_tick().await;
                }
            })
            .await;
    }
}

pub fn scene_path_to_name_string<const N: usize>(scene_path: ArrayCString<N>) -> String {
    String::from_utf8(get_scene_name(&scene_path).to_vec()).unwrap()
}
