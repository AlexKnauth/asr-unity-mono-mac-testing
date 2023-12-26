use std::cmp::min;
use std::collections::BTreeMap;

use asr::string::ArrayWString;
use asr::{Process, Address64};
use asr::game_engine::unity::mono::{Image, Module, UnityPointer};
use serde_json::value::Value as JsonValue;
use serde_json::Number;

// --------------------------------------------------------

pub const CSTR: usize = 128;

// --------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
enum Type {
    Bool,
    I32,
    String
}

impl Type {
    fn read_unity_pointer_json<const N: usize>(&self, process: &Process, module: &Module, image: &Image, pointer: &UnityPointer<N>) -> Option<JsonValue> {
        match self {
            Type::Bool => Some(JsonValue::Bool(pointer.deref::<bool>(process, module, image).ok()?)),
            Type::I32 => Some(JsonValue::Number(Number::from(pointer.deref::<i32>(process, module, image).ok()?))),
            Type::String => Some(JsonValue::String(read_string_object::<CSTR>(process, pointer.deref(process, module, image).ok()?)?)),
        }
    }
}

// --------------------------------------------------------

const POINTER_DEPTH: usize = 4;

const HOLLOW_KNIGHT_POINTERS: &[(&str, (&str, u8, &[&str]), Type)] = &[
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
    ("PlayerData slyRescued", ("GameManager", 0, &["_instance", "playerData", "slyRescued"]), Type::Bool),
    ("PlayerData killedGorgeousHusk", ("GameManager", 0, &["_instance", "playerData", "killedGorgeousHusk"]), Type::Bool),
    ("PlayerData metRelicDealerShop", ("GameManager", 0, &["_instance", "playerData", "metRelicDealerShop"]), Type::Bool),
    ("PlayerData watcherChandelier", ("GameManager", 0, &["_instance", "playerData", "watcherChandelier"]), Type::Bool),
    ("PlayerData killedBlackKnight", ("GameManager", 0, &["_instance", "playerData", "killedBlackKnight"]), Type::Bool),
    ("PlayerData killedMegaJellyfish", ("GameManager", 0, &["_instance", "playerData", "killedMegaJellyfish"]), Type::Bool),
    ("PlayerData spiderCapture", ("GameManager", 0, &["_instance", "playerData", "spiderCapture"]), Type::Bool),
    ("PlayerData unchainedHollowKnight", ("GameManager", 0, &["_instance", "playerData", "unchainedHollowKnight"]), Type::Bool),

    ("PlayerData P1 completed", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier1", "completed"]), Type::Bool),
    ("PlayerData P2 completed", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier2", "completed"]), Type::Bool),
    ("PlayerData P3 completed", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier3", "completed"]), Type::Bool),
    ("PlayerData P4 completed", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier4", "completed"]), Type::Bool),
    ("PlayerData P5 completed", ("GameManager", 0, &["_instance", "playerData", "bossDoorStateTier5", "completed"]), Type::Bool),
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
