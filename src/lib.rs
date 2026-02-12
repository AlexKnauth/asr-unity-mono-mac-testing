mod hollow_knight_memory;

use asr::{
    future::{next_tick, retry},
    game_engine::unity::{
        mono::Module,
        scene_manager::{self, SceneManager},
    },
    signature::Signature,
    string::ArrayCString,
    Process,
};
use hollow_knight_memory::{HollowKnightInfo, CSTR};

asr::async_main!(stable);

// --------------------------------------------------------

const HOLLOW_KNIGHT_NAMES: [&str; 7] = [
    "hollow_knight.exe",          // Windows
    "hollow_knight.x86_64", // Linux full executable name, just in case anything uses the non-truncated version
    "hollow_knight.x",      // Linux process name truncated to 15 characters
    "Hollow Knight",        // Mac
    "hollow_knight",        // Mac
    "Hollow Knight Silksong.exe", // Windows
    "Hollow Knight Silksong", // Mac, Linux
];

const INIT_MAX_DIRTYNESS: usize = 0x10;

// --------------------------------------------------------

async fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        asr::print_message(&panic_info.to_string());
    }));

    // TODO: Set up some general state and settings.

    asr::print_message("Hello, World!");

    let mut timer_state = asr::timer::state();

    loop {
        let process = retry(|| {
            let curr_timer_state = asr::timer::state();
            if curr_timer_state != timer_state {
                asr::print_message(&format!("timer state: {:?}", curr_timer_state));
                timer_state = curr_timer_state;
            }
            HOLLOW_KNIGHT_NAMES.into_iter().find_map(Process::attach)
        })
        .await;
        process
            .until_closes(async {
                asr::print_message("attaching SceneManager...");
                for _ in 0..0x10 {
                    next_tick().await;
                }
                let scene_manager = SceneManager::attach(&process);
                asr::print_message("attaching Module...");
                for _ in 0..0x10 {
                    next_tick().await;
                }
                let module = Module::wait_attach_auto_detect(&process).await;
                asr::print_message("attaching Image...");
                for _ in 0..0x10 {
                    next_tick().await;
                }
                let image = module.wait_get_default_image(&process).await;
                let mut game_manager_dirtyness = 0;
                let mut max_dirtyness = INIT_MAX_DIRTYNESS;
                asr::print_message("attached SceneManager, Module, and Image successfully");

                // TODO: Load some initial information from the process.
                let mut scene_manager_scene_name: Option<String> = scene_manager
                    .as_ref()
                    .and_then(|sm| sm.get_current_scene_path::<CSTR>(&process).ok())
                    .and_then(scene_path_to_name_string);
                let mut info = HollowKnightInfo::new();

                // signatures around the static reference to the GameManager
                next_tick().await;
                let gmc = image.wait_get_class(&process, &module, "GameManager").await;
                let gmst = gmc.wait_get_static_table(&process, &module).await;
                let gmsi_offset = gmc
                    .wait_get_field_offset(&process, &module, "_instance")
                    .await;
                let gmsi_location = gmst + gmsi_offset;
                let gmsi = gmc
                    .wait_get_static_instance(&process, &module, "_instance")
                    .await;
                next_tick().await;
                asr::print_message(&format!("location: {}, instance: {}", gmsi_location, gmsi));
                next_tick().await;
                let bs_location: [u8; 32] = process.read(gmsi_location + -10).unwrap();
                let bs_instance: [u8; 32] = process.read(gmsi + -10).unwrap();
                asr::print_message(&format!("bs_location: {:02X?}", bs_location));
                asr::print_message(&format!("bs_instance: {:02X?}", bs_instance));
                next_tick().await;
                /*
                location: 2727d332d08, instance: 2716404dc00
                bs_location: [00, 00, 90, FB, 99, 96, 73, 02, 00, 00, 00, DC, 04, 64, 71, 02, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 80, D2, 02, 64, 71, 02]
                bs_instance: [00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 90, 49, 7B, 62, 71, 02, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, F0, AC, C4, 00, 73, 02]

                location: 2a1fc912d08, instance: 2a1c02fac00
                bs_location: [00, 00, 40, A1, 7F, 11, A4, 02, 00, 00, 00, AC, 2F, C0, A1, 02, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 40, 52, 2A, C0, A1, 02]
                bs_instance: [00, 00, 00, 00, 00, 00, 00, 00, 00, 00, B0, 82, 35, FF, A3, 02, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 70, 12, C4, 80, A3, 02]

                pre-1.5 Normal:
                              83C41083EC0C57E8????????83C410EB3D8B05
                                                                    ^-------

                pre-1.5 API:
                          83C41083EC0C57393FE8????????83C410EB3F8B05
                                                                    ^-------

                1.5 Normal64:
                                                41FFD3E96300000048B8????????????????488B10488BCE488D6424009049BB
                                                                    ^---------------

                also 1.5 Normal64:
                  488BCE49BB????????????????41FFD3E9??000000488B1425
                                                                    ^---------------
                */
                const SIG_15_1: Signature<32> = Signature::new(
                    "41FFD3E96300000048B8????????????????488B10488BCE488D6424009049BB",
                );
                const SIG_15_2: Signature<25> =
                    Signature::new("488BCE49BB????????????????41FFD3E9??000000488B1425");
                let mut mab = None;
                for memory_range in process.memory_ranges() {
                    let Ok(range) = memory_range.range() else {
                        continue;
                    };
                    if let Some(a) = SIG_15_1.scan_process_range(&process, range) {
                        asr::print_message(&format!("a: {}", a));
                        if let Ok(aa) = process.read_pointer(a + 10, asr::PointerSize::Bit64) {
                            mab = Some(aa);
                            break;
                        }
                    }
                    if let Some(b) = SIG_15_2.scan_process_range(&process, range) {
                        asr::print_message(&format!("b: {}", b));
                        if let Ok(bb) = process.read_pointer(b + 25, asr::PointerSize::Bit64) {
                            mab = Some(bb);
                            break;
                        }
                    }
                }
                asr::print_message(&format!("mab: {:?}", mab));
                /*
                location: 22ceb9f2d08, instance: 22f0477ec00
                bs_location: [00, 00, 00, 40, 24, 0A, 2F, 02, 00, 00, 00, EC, 77, 04, 2F, 02, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, C0, FE, 89, 04, 2F, 02]
                bs_instance: [00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 58, 0F, 3D, F0, 2E, 02, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 40, DE, C4, 70, 2E, 02]
                a: 22f08b0dca0
                mab: Some(22ceb9f2d08)
                */
                let sig_location: Signature<8> = Signature::Simple(gmsi_location.value().to_le_bytes());
                let mut location_areas: Vec<[u8; 47]> = Vec::new();
                for memory_range in process.memory_ranges() {
                    let Ok(range) = memory_range.range() else {
                        continue;
                    };
                    for a in sig_location.scan_iter(&process, range) {
                        let Ok(bs) = process.read(a + -25) else {
                            continue;
                        };
                        location_areas.push(bs);
                    }
                }
                asr::print_message(&format!("location_count: {}", location_areas.len()));
                if location_areas.len() <= 32 {
                    
                    let mut s = String::new();
                    s.push_str("\n");
                    for location_area in location_areas {
                        for b in &location_area[0..25] {
                            s.push_str(&format!("{:02X?}", b));
                        }
                        for _ in &location_area[25..33] {
                            s.push_str("??");
                        }
                        for b in &location_area[33..] {
                            s.push_str(&format!("{:02X?}", b));
                        }
                        s.push_str("\n");
                    }
                    asr::print_message(&s);
                }

                loop {
                    // TODO: Do something on every tick.
                    /*
                    let mut changed = false;
                    let curr_timer_state = asr::timer::state();
                    if curr_timer_state != timer_state {
                        asr::print_message(&format!("timer state: {:?}", curr_timer_state));
                        timer_state = curr_timer_state;
                        changed = true;
                    }
                    let prev_scene_manager_scene_name = &scene_manager_scene_name;
                    let curr_scene_manager_scene_name = scene_manager
                        .as_ref()
                        .and_then(|sm| sm.get_current_scene_path::<CSTR>(&process).ok())
                        .and_then(scene_path_to_name_string);
                    if prev_scene_manager_scene_name != &curr_scene_manager_scene_name {
                        asr::print_message(&format!(
                            "SceneManager sceneName: {:?}",
                            curr_scene_manager_scene_name
                        ));
                        scene_manager_scene_name = curr_scene_manager_scene_name;
                        changed = true;
                    }
                    if info.print_changes(&process, &module, &image) {
                        changed = true;
                    }
                    if scene_manager_scene_name.is_some() {
                        if scene_manager_scene_name.as_deref() == info.game_manager_scene_name() {
                            if 0 < game_manager_dirtyness {
                                asr::print_message(&format!(
                                    "game_manager_dirtyness: {}",
                                    game_manager_dirtyness
                                ));
                            }
                            game_manager_dirtyness = 0;
                            max_dirtyness = INIT_MAX_DIRTYNESS;
                        } else {
                            game_manager_dirtyness += 1;
                        }
                    }
                    if max_dirtyness < game_manager_dirtyness {
                        asr::print_message(&format!(
                            "game_manager_dirtyness: {}",
                            game_manager_dirtyness
                        ));
                        game_manager_dirtyness = 0;
                        max_dirtyness *= 2;
                    }
                    if changed {
                        asr::print_message("  ---");
                    }
                    */
                    next_tick().await;
                }
            })
            .await;
    }
}

pub fn scene_path_to_name_string<const N: usize>(scene_path: ArrayCString<N>) -> Option<String> {
    String::from_utf8(scene_manager::get_name(&scene_path).to_vec()).ok()
}
