use std::cmp::min;
use std::collections::BTreeMap;

use asr::string::ArrayWString;
use asr::{Process, Address64};
use asr::game_engine::unity::mono::{Image, Module, UnityPointer};
use serde::{Deserialize, Serialize};
use serde_json::value::Value as JsonValue;
use serde_json::Number;

// --------------------------------------------------------

pub const CSTR: usize = 128;

// --------------------------------------------------------

#[derive(bytemuck::CheckedBitPattern, Clone, Copy, Deserialize, Serialize)] // bytemuck::Zeroable
#[repr(C)]
pub struct BossSequenceDoorCompletion {
    can_unlock: bool,
    unlocked: bool,
    pub completed: bool,
    all_bindings: bool,
    no_hits: bool,
    bound_nail: bool,
    bound_shell: bool,
    bound_charms: bool,
    bound_soul: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
enum Type {
    Bool,
    I32,
    String,
    BossSequenceDoorCompletion,
}

impl Type {
    fn read_unity_pointer_json<const N: usize>(&self, process: &Process, module: &Module, image: &Image, pointer: &UnityPointer<N>) -> Option<JsonValue> {
        match self {
            Type::Bool => Some(JsonValue::Bool(pointer.deref::<bool>(process, module, image).ok()?)),
            Type::I32 => Some(JsonValue::Number(Number::from(pointer.deref::<i32>(process, module, image).ok()?))),
            Type::String => Some(JsonValue::String(read_string_object::<CSTR>(process, pointer.deref(process, module, image).ok()?)?)),
            Type::BossSequenceDoorCompletion => serde_json::to_value(pointer.deref::<BossSequenceDoorCompletion>(process, module, image).ok()?).ok(),
        }
    }
}

// --------------------------------------------------------

const POINTER_DEPTH: usize = 4;

static HOLLOW_KNIGHT_POINTERS: &[(&str, (&str, u8, &[&str]), Type)] = &[
    ("GameManager versionNumber", ("GameManager", 0, &["_instance", "<inputHandler>k__BackingField", "debugInfo", "versionNumber"]), Type::String),
    ("PlayerData version", ("GameManager", 0, &["_instance", "playerData", "version"]), Type::String),

    ("GameManager sceneName", ("GameManager", 0, &["_instance", "sceneName"]), Type::String),
    ("GameManager nextSceneName", ("GameManager", 0, &["_instance", "nextSceneName"]), Type::String),
    ("GameManager gameState", ("GameManager", 0, &["_instance", "gameState"]), Type::I32),
    ("GameManager uiState vanilla", ("GameManager", 0, &["_instance", "<ui>k__BackingField", "uiState"]), Type::I32),
    ("GameManager uiState modded", ("GameManager", 0, &["_instance", "_uiInstance", "uiState"]), Type::I32),
    // ("GameManager camera teleporting", ("GameManager", 0, &["_instance", "<cameraCtrl>k__BackingField", "teleporting"]), Type::Bool),
    ("GameManager hazardRespawning", ("GameManager", 0, &["_instance", "<hero_ctrl>k__BackingField", "cState", "hazardRespawning"]), Type::Bool),
    // ("GameManager acceptingInput", ("GameManager", 0, &["_instance", "<inputHandler>k__BackingField", "acceptingInput"]), Type::Bool),
    ("GameManager transitionState", ("GameManager", 0, &["_instance", "<hero_ctrl>k__BackingField", "transitionState"]), Type::I32),
    ("GameManager tilemapDirty", ("GameManager", 0, &["_instance", "tilemapDirty"]), Type::Bool),
    ("PlayerData fireballLevel", ("GameManager", 0, &["_instance", "playerData", "fireballLevel"]), Type::I32),
    ("PlayerData hasDash", ("GameManager", 0, &["_instance", "playerData", "hasDash"]), Type::Bool),
    ("PlayerData hasShadowDash", ("GameManager", 0, &["_instance", "playerData", "hasShadowDash"]), Type::Bool),
    ("PlayerData hasWalljump", ("GameManager", 0, &["_instance", "playerData", "hasWalljump"]), Type::Bool),
    ("PlayerData hasDoubleJump", ("GameManager", 0, &["_instance", "playerData", "hasDoubleJump"]), Type::Bool),
    ("PlayerData hasSuperDash", ("GameManager", 0, &["_instance", "playerData", "hasSuperDash"]), Type::Bool),
    ("PlayerData hasAcidArmour", ("GameManager", 0, &["_instance", "playerData", "hasAcidArmour"]), Type::Bool),
    ("PlayerData hasDreamNail", ("GameManager", 0, &["_instance", "playerData", "hasDreamNail"]), Type::Bool),
    ("PlayerData hasDreamGate", ("GameManager", 0, &["_instance", "playerData", "hasDreamGate"]), Type::Bool),
    ("PlayerData dreamNailUpgraded", ("GameManager", 0, &["_instance", "playerData", "dreamNailUpgraded"]), Type::Bool),

    // PlayerData hasCyclone: actually means Cyclone Slash, from Mato
    ("PlayerData hasCyclone", ("GameManager", 0, &["_instance", "playerData", "hasCyclone"]), Type::Bool),
    // PlayerData hasDashSlash: secretly means Great Slash, from Sheo
    ("PlayerData hasDashSlash", ("GameManager", 0, &["_instance", "playerData", "hasDashSlash"]), Type::Bool),
    // PlayerData hasUpwardSlash: secretly means Dash Slash, from Oro
    ("PlayerData hasUpwardSlash", ("GameManager", 0, &["_instance", "playerData", "hasUpwardSlash"]), Type::Bool),

    ("PlayerData maxHealthBase", ("GameManager", 0, &["_instance", "playerData", "maxHealthBase"]), Type::I32),
    ("PlayerData heartPieces", ("GameManager", 0, &["_instance", "playerData", "heartPieces"]), Type::I32),
    ("PlayerData hasLantern", ("GameManager", 0, &["_instance", "playerData", "hasLantern"]), Type::Bool),
    ("PlayerData simpleKeys", ("GameManager", 0, &["_instance", "playerData", "simpleKeys"]), Type::I32),
    ("PlayerData hasSlykey", ("GameManager", 0, &["_instance", "playerData", "hasSlykey"]), Type::Bool),
    ("PlayerData hasWhiteKey", ("GameManager", 0, &["_instance", "playerData", "hasWhiteKey"]), Type::Bool),
    ("PlayerData geo", ("GameManager", 0, &["_instance", "playerData", "geo"]), Type::I32),
    ("PlayerData gotCharm_31", ("GameManager", 0, &["_instance", "playerData", "gotCharm_31"]), Type::Bool),
    ("PlayerData grubsCollected", ("GameManager", 0, &["_instance", "playerData", "grubsCollected"]), Type::I32),
    ("PlayerData killedBigFly", ("GameManager", 0, &["_instance", "playerData", "killedBigFly"]), Type::Bool),
    ("PlayerData killsBigFly", ("GameManager", 0, &["_instance", "playerData", "killsBigFly"]), Type::I32),
    ("PlayerData slyRescued", ("GameManager", 0, &["_instance", "playerData", "slyRescued"]), Type::Bool),
    ("PlayerData killedGorgeousHusk", ("GameManager", 0, &["_instance", "playerData", "killedGorgeousHusk"]), Type::Bool),
    ("PlayerData metRelicDealerShop", ("GameManager", 0, &["_instance", "playerData", "metRelicDealerShop"]), Type::Bool),
    ("PlayerData watcherChandelier", ("GameManager", 0, &["_instance", "playerData", "watcherChandelier"]), Type::Bool),
    ("PlayerData killedBlackKnight", ("GameManager", 0, &["_instance", "playerData", "killedBlackKnight"]), Type::Bool),
    ("PlayerData killedMegaJellyfish", ("GameManager", 0, &["_instance", "playerData", "killedMegaJellyfish"]), Type::Bool),
    ("PlayerData spiderCapture", ("GameManager", 0, &["_instance", "playerData", "spiderCapture"]), Type::Bool),
    ("PlayerData unchainedHollowKnight", ("GameManager", 0, &["_instance", "playerData", "unchainedHollowKnight"]), Type::Bool),

    ("PlayerData killedSpitter", ("GameManager", 0, &["_instance", "playerData", "killedSpitter"]), Type::Bool),
    ("PlayerData killsSpitter", ("GameManager", 0, &["_instance", "playerData", "killsSpitter"]), Type::I32),
    ("PlayerData killedSuperSpitter", ("GameManager", 0, &["_instance", "playerData", "killedSuperSpitter"]), Type::Bool),
    ("PlayerData killsSuperSpitter", ("GameManager", 0, &["_instance", "playerData", "killsSuperSpitter"]), Type::I32),
    ("PlayerData killedBuzzer", ("GameManager", 0, &["_instance", "playerData", "killedBuzzer"]), Type::Bool),
    ("PlayerData killsBuzzer", ("GameManager", 0, &["_instance", "playerData", "killsBuzzer"]), Type::I32),
    ("PlayerData killedBigBuzzer", ("GameManager", 0, &["_instance", "playerData", "killedBigBuzzer"]), Type::Bool),
    ("PlayerData killsBigBuzzer", ("GameManager", 0, &["_instance", "playerData", "killsBigBuzzer"]), Type::I32),
    ("PlayerData killedBurstingBouncer", ("GameManager", 0, &["_instance", "playerData", "killedBurstingBouncer"]), Type::Bool),
    ("PlayerData killsBurstingBouncer", ("GameManager", 0, &["_instance", "playerData", "killsBurstingBouncer"]), Type::I32),
    ("PlayerData killedColShield", ("GameManager", 0, &["_instance", "playerData", "killedColShield"]), Type::Bool),
    ("PlayerData killsColShield", ("GameManager", 0, &["_instance", "playerData", "killsColShield"]), Type::I32),
    ("PlayerData killedColRoller", ("GameManager", 0, &["_instance", "playerData", "killedColRoller"]), Type::Bool),
    ("PlayerData killsColRoller", ("GameManager", 0, &["_instance", "playerData", "killsColRoller"]), Type::I32),
    ("PlayerData killedColMiner", ("GameManager", 0, &["_instance", "playerData", "killedColMiner"]), Type::Bool),
    ("PlayerData killsColMiner", ("GameManager", 0, &["_instance", "playerData", "killsColMiner"]), Type::I32),
    ("PlayerData killedColWorm", ("GameManager", 0, &["_instance", "playerData", "killedColWorm"]), Type::Bool),
    ("PlayerData killsColWorm", ("GameManager", 0, &["_instance", "playerData", "killsColWorm"]), Type::I32),
    ("PlayerData killedColFlyingSentry", ("GameManager", 0, &["_instance", "playerData", "killedColFlyingSentry"]), Type::Bool),
    ("PlayerData killsColFlyingSentry", ("GameManager", 0, &["_instance", "playerData", "killsColFlyingSentry"]), Type::I32),
    ("PlayerData killedColMosquito", ("GameManager", 0, &["_instance", "playerData", "killedColMosquito"]), Type::Bool),
    ("PlayerData killsColMosquito", ("GameManager", 0, &["_instance", "playerData", "killsColMosquito"]), Type::I32),
    ("PlayerData killedCeilingDropper", ("GameManager", 0, &["_instance", "playerData", "killedCeilingDropper"]), Type::Bool),
    ("PlayerData killsCeilingDropper", ("GameManager", 0, &["_instance", "playerData", "killsCeilingDropper"]), Type::I32),
    ("PlayerData killedHopper", ("GameManager", 0, &["_instance", "playerData", "killedHopper"]), Type::Bool),
    ("PlayerData killsHopper", ("GameManager", 0, &["_instance", "playerData", "killsHopper"]), Type::I32),
    ("PlayerData killedGrassHopper", ("GameManager", 0, &["_instance", "playerData", "killedGrassHopper"]), Type::Bool),
    ("PlayerData killsGrassHopper", ("GameManager", 0, &["_instance", "playerData", "killsGrassHopper"]), Type::I32),
    ("PlayerData killedGiantHopper", ("GameManager", 0, &["_instance", "playerData", "killedGiantHopper"]), Type::Bool),
    ("PlayerData killsGiantHopper", ("GameManager", 0, &["_instance", "playerData", "killsGiantHopper"]), Type::I32),
    ("PlayerData killedGrubMimic", ("GameManager", 0, &["_instance", "playerData", "killedGrubMimic"]), Type::Bool),
    ("PlayerData killsGrubMimic", ("GameManager", 0, &["_instance", "playerData", "killsGrubMimic"]), Type::I32),
    ("PlayerData killedBlobble", ("GameManager", 0, &["_instance", "playerData", "killedBlobble"]), Type::Bool),
    ("PlayerData killsBlobble", ("GameManager", 0, &["_instance", "playerData", "killsBlobble"]), Type::I32),
    ("PlayerData killedOblobble", ("GameManager", 0, &["_instance", "playerData", "killedOblobble"]), Type::Bool),
    ("PlayerData killsOblobble", ("GameManager", 0, &["_instance", "playerData", "killsOblobble"]), Type::I32),
    ("PlayerData killedAngryBuzzer", ("GameManager", 0, &["_instance", "playerData", "killedAngryBuzzer"]), Type::Bool),
    ("PlayerData killsAngryBuzzer", ("GameManager", 0, &["_instance", "playerData", "killsAngryBuzzer"]), Type::I32),
    ("PlayerData killedColHopper", ("GameManager", 0, &["_instance", "playerData", "killedColHopper"]), Type::Bool),
    ("PlayerData killsColHopper", ("GameManager", 0, &["_instance", "playerData", "killsColHopper"]), Type::I32),
    ("PlayerData killedHeavyMantis", ("GameManager", 0, &["_instance", "playerData", "killedHeavyMantis"]), Type::Bool),
    ("PlayerData killsHeavyMantis", ("GameManager", 0, &["_instance", "playerData", "killsHeavyMantis"]), Type::I32),
    ("PlayerData killedMantisHeavyFlyer", ("GameManager", 0, &["_instance", "playerData", "killedMantisHeavyFlyer"]), Type::Bool),
    ("PlayerData killsMantisHeavyFlyer", ("GameManager", 0, &["_instance", "playerData", "killsMantisHeavyFlyer"]), Type::I32),
    ("PlayerData killedMage", ("GameManager", 0, &["_instance", "playerData", "killedMage"]), Type::Bool),
    ("PlayerData killsMage", ("GameManager", 0, &["_instance", "playerData", "killsMage"]), Type::I32),
    ("PlayerData killedMageKnight", ("GameManager", 0, &["_instance", "playerData", "killedMageKnight"]), Type::Bool),
    ("PlayerData killsMageKnight", ("GameManager", 0, &["_instance", "playerData", "killsMageKnight"]), Type::I32),
    ("PlayerData killedElectricMage", ("GameManager", 0, &["_instance", "playerData", "killedElectricMage"]), Type::Bool),
    ("PlayerData killsElectricMage", ("GameManager", 0, &["_instance", "playerData", "killsElectricMage"]), Type::I32),
    ("PlayerData killedLesserMawlek", ("GameManager", 0, &["_instance", "playerData", "killedLesserMawlek"]), Type::Bool),
    ("PlayerData killsLesserMawlek", ("GameManager", 0, &["_instance", "playerData", "killsLesserMawlek"]), Type::I32),
    ("PlayerData killedMawlek", ("GameManager", 0, &["_instance", "playerData", "killedMawlek"]), Type::Bool),
    ("PlayerData killsMawlek", ("GameManager", 0, &["_instance", "playerData", "killsMawlek"]), Type::I32),
    ("PlayerData killedLobsterLancer", ("GameManager", 0, &["_instance", "playerData", "killedLobsterLancer"]), Type::Bool),
    ("PlayerData killsLobsterLancer", ("GameManager", 0, &["_instance", "playerData", "killsLobsterLancer"]), Type::I32),


    ("PlayerData P1", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier1"]), Type::BossSequenceDoorCompletion),
    ("PlayerData P2", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier2"]), Type::BossSequenceDoorCompletion),
    ("PlayerData P3", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier3"]), Type::BossSequenceDoorCompletion),
    ("PlayerData P4", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier4"]), Type::BossSequenceDoorCompletion),
    ("PlayerData P5", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier5"]), Type::BossSequenceDoorCompletion),
];

pub struct HollowKnightInfo {
    map_json: BTreeMap<&'static str, JsonValue>,
    pointers: Vec<(&'static str, UnityPointer<POINTER_DEPTH>, Type)>,
}

impl HollowKnightInfo {
    pub fn new() -> Self {
        Self {
            map_json: BTreeMap::new(),
            pointers: HOLLOW_KNIGHT_POINTERS.into_iter().map(|(k, (c, n, f), t)| {
                (*k, UnityPointer::new(*c, *n, *f), t.clone())
            }).collect()
        }
    }
    pub fn print_changes(&mut self, process: &Process, module: &Module, image: &Image) {
        for (k, p, t) in self.pointers.iter() {
            let prev = self.map_json.get(k).unwrap_or(&JsonValue::Null);
            let curr = t.read_unity_pointer_json(process, module, image, p).unwrap_or_default();
            if prev != &curr {
                asr::print_message(&format!("{}: {}", k, curr));
                self.map_json.insert(k, curr);
            }
        }
    }
    pub fn game_manager_scene_name(&self) -> Option<&str> {
        self.map_json.get("GameManager sceneName")?.as_str()
    }
}

// --------------------------------------------------------

pub fn read_string_object<const N: usize>(process: &Process, a: Address64) -> Option<String> {
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