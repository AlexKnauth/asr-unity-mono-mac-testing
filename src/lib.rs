mod hollow_knight_memory;

use asr::{
    future::{next_tick, retry},
    Process,
    game_engine::unity::{
        mono::Module,
        SceneManager,
        get_scene_name
    },
    string::ArrayCString
};
use hollow_knight_memory::{HollowKnightInfo, CSTR};

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

                // TODO: Load some initial information from the process.
                let mut scene_manager_scene_name: Option<String> = scene_manager.get_current_scene_path::<CSTR>(&process).ok().and_then(scene_path_to_name_string);
                let mut info = HollowKnightInfo::new();
                loop {
                    // TODO: Do something on every tick.
                    let prev_scene_manager_scene_name = &scene_manager_scene_name;
                    let curr_scene_manager_scene_name = scene_manager.get_current_scene_path::<CSTR>(&process).ok().and_then(scene_path_to_name_string);
                    if prev_scene_manager_scene_name != &curr_scene_manager_scene_name {
                        asr::print_message(&format!("SceneManager sceneName: {:?}", curr_scene_manager_scene_name));
                        scene_manager_scene_name = curr_scene_manager_scene_name;
                    }
                    info.print_changes(&process, &module, &image);
                    if scene_manager_scene_name.is_some() {
                        if scene_manager_scene_name.as_deref() == info.game_manager_scene_name() {
                            if 0 < game_manager_dirtyness {
                                asr::print_message(&format!("game_manager_dirtyness: {}", game_manager_dirtyness));
                            }
                            game_manager_dirtyness = 0;
                            max_dirtyness = INIT_MAX_DIRTYNESS;
                        } else {
                            game_manager_dirtyness += 1;
                        }
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

pub fn scene_path_to_name_string<const N: usize>(scene_path: ArrayCString<N>) -> Option<String> {
    String::from_utf8(get_scene_name(&scene_path).to_vec()).ok()
}
