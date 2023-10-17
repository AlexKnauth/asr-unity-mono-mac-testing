
use std::{cmp::min, collections::BTreeMap};

use asr::{
    future::{next_tick, retry},
    Process,
    game_engine::unity::{
        mono::{Image, Module, UnityPointer},
        SceneManager,
        get_scene_name
    },
    Address64, 
    string::{ArrayWString, ArrayCString}
};

asr::async_main!(stable);

// --------------------------------------------------------

const HOLLOW_KNIGHT_NAMES: [&str; 2] = [
    "hollow_knight.exe", // Windows
    "Hollow Knight", // Mac
];

const INIT_MAX_DIRTYNESS: usize = 0x10;

// --------------------------------------------------------

async fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        asr::print_message(&panic_info.to_string());
    }));

    // TODO: Set up some general state and settings.

    asr::print_message("Hello, World!");

    loop {
        let process = retry(|| {
            HOLLOW_KNIGHT_NAMES.into_iter().find_map(Process::attach)
        }).await;
        process
            .until_closes(async {
                asr::print_message("attaching SceneManager...");
                for _ in 0..0x10 { next_tick().await; }
                let scene_manager = SceneManager::wait_attach(&process).await;
                asr::print_message("attaching Module...");
                for _ in 0..0x10 { next_tick().await; }
                let module = Module::wait_attach_auto_detect(&process).await;
                asr::print_message("attaching Image...");
                for _ in 0..0x10 { next_tick().await; }
                let image = module.wait_get_default_image(&process).await;
                let mut game_manager_dirtyness = 0;
                let mut max_dirtyness = INIT_MAX_DIRTYNESS;
                asr::print_message("attached SceneManager, Module, and Image successfully");
                let game_manager_scene_name_pointer: UnityPointer<2> = UnityPointer::new("GameManager", 0, &["_instance", "sceneName"]);
                let game_manager_next_scene_name_pointer: UnityPointer<2> = UnityPointer::new("GameManager", 0, &["_instance", "nextSceneName"]);

                // TODO: Load some initial information from the process.
                let mut string_table: BTreeMap<&str, Option<String>> = BTreeMap::new();
                string_table.insert("SceneManager sceneName", None);
                string_table.insert("GameManager sceneName", None);
                string_table.insert("GameManager nextSceneName", None);
                loop {
                    // TODO: Do something on every tick.
                    let scene_manager_scene_name: Option<String> = scene_manager.get_current_scene_path::<64>(&process).ok().map(scene_path_to_name_string);
                    let scene_name = read_unity_pointer_string_object::<64>(&process, &module, &image, &game_manager_scene_name_pointer);
                    let next_scene_name = read_unity_pointer_string_object::<64>(&process, &module, &image, &game_manager_next_scene_name_pointer);
                    if scene_manager_scene_name.is_some() {
                        if scene_manager_scene_name == scene_name {
                            if 0 < game_manager_dirtyness {
                                asr::print_message(&format!("game_manager_dirtyness: {}", game_manager_dirtyness));
                            }
                            game_manager_dirtyness = 0;
                            max_dirtyness = INIT_MAX_DIRTYNESS;
                        } else {
                            game_manager_dirtyness += 1;
                        }
                    }
                    if Some(&scene_manager_scene_name) != string_table.get("SceneManager sceneName") {
                        string_table.insert("SceneManager sceneName", scene_manager_scene_name);
                        asr::print_message(&format!("SceneManager sceneName: {:?}", string_table.get("SceneManager sceneName")));
                    }
                    if Some(&scene_name) != string_table.get("GameManager sceneName") {
                        string_table.insert("GameManager sceneName", scene_name);
                        asr::print_message(&format!("GameManager sceneName: {:?}", string_table.get("GameManager sceneName")));
                    }
                    if Some(&next_scene_name) != string_table.get("GameManager nextSceneName") {
                        string_table.insert("GameManager nextSceneName", next_scene_name);
                        asr::print_message(&format!("GameManager nextSceneName: {:?}", string_table.get("GameManager nextSceneName")));
                    }
                    if max_dirtyness < game_manager_dirtyness {
                        asr::print_message(&format!("game_manager_dirtyness: {}", game_manager_dirtyness));
                        game_manager_dirtyness = 0;
                        max_dirtyness *= 2;
                    }
                    next_tick().await;
                }
            })
            .await;
    }
}

fn read_unity_pointer_string_object<const N: usize>(process: &Process, module: &Module, image: &Image, pointer: &UnityPointer<2>) -> Option<String> {
    let string_object: Address64 = pointer.deref(process, module, image).ok()?;
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
