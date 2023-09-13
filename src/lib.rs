
use std::{cmp::min, collections::BTreeMap};

use asr::{future::next_tick, Process, game_engine::unity::mono, Address, Address64, string::ArrayWString};

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
                let (module, _image, game_manager_class, game_manager_instance) = wait_attach_game_manager(&process).await.expect("GameManager");
                let scene_name_offset = game_manager_class.get_field(&process, &module, "sceneName").expect("sceneName") as u64;
                let next_scene_name_offset = game_manager_class.get_field(&process, &module, "nextSceneName").expect("nextSceneName") as u64;

                // TODO: Load some initial information from the process.
                let mut string_table: BTreeMap<u64, Option<String>> = BTreeMap::new();
                string_table.insert(scene_name_offset, None);
                string_table.insert(next_scene_name_offset, None);
                loop {
                    // TODO: Do something on every tick.
                    let scene_name = read_pointer_path_string_object::<64>(&process, game_manager_instance, &[scene_name_offset]);
                    let next_scene_name = read_pointer_path_string_object::<64>(&process, game_manager_instance, &[next_scene_name_offset]);
                    if Some(&scene_name) != string_table.get(&scene_name_offset) {
                        string_table.insert(scene_name_offset, scene_name);
                        asr::print_message(&format!("sceneName: {:?}", string_table.get(&scene_name_offset)));
                    }
                    if Some(&next_scene_name) != string_table.get(&next_scene_name_offset) {
                        string_table.insert(next_scene_name_offset, next_scene_name);
                        asr::print_message(&format!("nextSceneName: {:?}", string_table.get(&next_scene_name_offset)));
                    }
                    next_tick().await;
                }
            })
            .await;
    }
}

async fn wait_attach_game_manager(process: &Process) -> Option<(mono::Module, mono::Image, mono::Class, Address)> {
    asr::print_message("attaching mono module image...");
    for _ in 0..0x10 { next_tick().await; }
    let (module, image) = attach_auto_detect_default(process)?;
    asr::print_message("attached mono module image");
    for _ in 0..0x10 { next_tick().await; }
    let game_manager_class = image.get_class(&process, &module, "GameManager")?;
    asr::print_message("GameManager class found");
    for _ in 0..0x10 { next_tick().await; }
    let game_manager_instance = game_manager_class.wait_get_static_instance(&process, &module, "_instance").await;
    asr::print_message("GameManager instance found");
    Some((module, image, game_manager_class, game_manager_instance))
}

fn attach_auto_detect_default(process: &Process) -> Option<(mono::Module, mono::Image)> {
    let module = mono::Module::attach_auto_detect(process)?;
    let image = module.get_default_image(process)?;
    Some((module, image))
}

fn read_pointer_path_string_object<const N: usize>(process: &Process, address: Address, path: &[u64]) -> Option<String> {
    let string_object: Address64 = process.read_pointer_path64(address, path).ok()?;
    read_string_object::<N>(process, string_object)
}

fn read_string_object<const N: usize>(process: &Process, a: Address64) -> Option<String> {
    const STRING_LEN_OFFSET: u64 = 0x10;
    const STRING_CONTENTS_OFFSET: u64 = 0x14;

    let n: u32 = process.read_pointer_path64(a, &[STRING_LEN_OFFSET]).ok()?;
    if !(n < 2048) { return None; }
    let w: ArrayWString<N> = process.read_pointer_path64(a, &[STRING_CONTENTS_OFFSET]).ok()?;
    if !(w.len() == min(n as usize, N)) { return None; }
    String::from_utf16(&w.to_vec()).ok()
}
