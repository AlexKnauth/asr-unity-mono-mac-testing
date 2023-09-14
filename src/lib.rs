
use std::{cmp::min, collections::BTreeMap};

use asr::{future::next_tick, Process, game_engine::unity::{mono, SceneManager, get_scene_name}, Address, Address64, string::{ArrayWString, ArrayCString}};

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
                asr::print_message("attaching SceneManager...");
                for _ in 0..0x10 { next_tick().await; }
                let scene_manager = SceneManager::wait_attach(&process).await;
                asr::print_message("attached SceneManager");
                let (module, _image, game_manager_class, game_manager_instance) = wait_attach_game_manager(&process).await.expect("GameManager");
                let scene_name_offset = game_manager_class.get_field(&process, &module, "sceneName").expect("sceneName") as u64;
                let next_scene_name_offset = game_manager_class.get_field(&process, &module, "nextSceneName").expect("nextSceneName") as u64;

                // TODO: Load some initial information from the process.
                let mut string_table: BTreeMap<(&str, u64), Option<String>> = BTreeMap::new();
                string_table.insert(("SceneManager", 0), None);
                string_table.insert(("GameManager", scene_name_offset), None);
                string_table.insert(("GameManager", next_scene_name_offset), None);
                loop {
                    // TODO: Do something on every tick.
                    let scene_manager_scene_name: Option<String> = scene_manager.get_current_scene_path::<64>(&process).ok().map(scene_path_to_name_string);
                    let scene_name = read_pointer_path_string_object::<64>(&process, game_manager_instance, &[scene_name_offset]);
                    let next_scene_name = read_pointer_path_string_object::<64>(&process, game_manager_instance, &[next_scene_name_offset]);
                    if Some(&scene_manager_scene_name) != string_table.get(&("SceneManager", 0)) {
                        string_table.insert(("SceneManager", 0), scene_manager_scene_name);
                        asr::print_message(&format!("SceneManager sceneName: {:?}", string_table.get(&("SceneManager", 0))));
                    }
                    if Some(&scene_name) != string_table.get(&("GameManager", scene_name_offset)) {
                        string_table.insert(("GameManager", scene_name_offset), scene_name);
                        asr::print_message(&format!("GameManager sceneName: {:?}", string_table.get(&("GameManager", scene_name_offset))));
                    }
                    if Some(&next_scene_name) != string_table.get(&("GameManager", next_scene_name_offset)) {
                        string_table.insert(("GameManager", next_scene_name_offset), next_scene_name);
                        asr::print_message(&format!("GameManager nextSceneName: {:?}", string_table.get(&("GameManager", next_scene_name_offset))));
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
    // class "System.String" field "m_stringLength"
    const STRING_LEN_OFFSET: u64 = 0x10;
    // class "System.String" field "m_firstChar"
    const STRING_CONTENTS_OFFSET: u64 = 0x14;

    let n: u32 = process.read_pointer_path64(a, &[STRING_LEN_OFFSET]).ok()?;
    if !(n < 2048) { return None; }
    let w: ArrayWString<N> = process.read_pointer_path64(a, &[STRING_CONTENTS_OFFSET]).ok()?;
    if !(w.len() == min(n as usize, N)) { return None; }
    String::from_utf16(&w.to_vec()).ok()
}

pub fn scene_path_to_name_string<const N: usize>(scene_path: ArrayCString<N>) -> String {
    String::from_utf8(get_scene_name(&scene_path).to_vec()).unwrap()
}
