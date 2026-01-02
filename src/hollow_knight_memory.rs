use std::cmp::min;
use std::collections::BTreeMap;

use asr::game_engine::unity::mono::{Image, Module, UnityPointer};
use asr::string::ArrayWString;
use asr::{Address64, PointerSize, Process};
use serde::{Deserialize, Serialize};
use serde_json::value::Value as JsonValue;
use serde_json::Number;

// --------------------------------------------------------

pub const CSTR: usize = 128;

// --------------------------------------------------------

#[derive(bytemuck::CheckedBitPattern, Clone, Copy, Deserialize, Serialize)]
#[repr(C)]
pub struct Vector3 {
    x: f32,
    y: f32,
    z: f32,
}

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
#[allow(dead_code)]
enum Type {
    Bool,
    I32,
    F32,
    String,
    Vector3,
    BossSequenceDoorCompletion,
}

impl Type {
    fn read_unity_pointer_json<const N: usize>(
        &self,
        process: &Process,
        module: &Module,
        image: &Image,
        pointer: &UnityPointer<N>,
    ) -> Option<JsonValue> {
        match self {
            Type::Bool => Some(JsonValue::Bool(
                pointer.deref::<bool>(process, module, image).ok()?,
            )),
            Type::I32 => Some(JsonValue::Number(Number::from(
                pointer.deref::<i32>(process, module, image).ok()?,
            ))),
            Type::F32 => Some(JsonValue::Number(Number::from_f64(
                pointer.deref::<f32>(process, module, image).ok()?.into(),
            )?)),
            Type::String => Some(JsonValue::String(read_string_object::<CSTR>(
                process,
                pointer.deref(process, module, image).ok()?,
            )?)),
            Type::Vector3 => {
                serde_json::to_value(pointer.deref::<Vector3>(process, module, image).ok()?).ok()
            }
            Type::BossSequenceDoorCompletion => serde_json::to_value(
                pointer
                    .deref::<BossSequenceDoorCompletion>(process, module, image)
                    .ok()?,
            )
            .ok(),
        }
    }
}

// --------------------------------------------------------

const POINTER_DEPTH: usize = 5;

static HOLLOW_KNIGHT_POINTERS: &[(&str, (&str, usize, &[&str]), Type)] = &[
    (
        "PlayerData version",
        ("GameManager", 0, &["_instance", "playerData", "version"]),
        Type::String,
    ),
    (
        "GameManager sceneName",
        ("GameManager", 0, &["_instance", "sceneName"]),
        Type::String,
    ),
    (
        "GameManager nextSceneName",
        ("GameManager", 0, &["_instance", "nextSceneName"]),
        Type::String,
    ),
    (
        "GameManager entryGateName",
        ("GameManager", 0, &["_instance", "entryGateName"]),
        Type::String,
    ),
    (
        "GameManager GameState",
        (
            "GameManager",
            0,
            &["_instance", "<GameState>k__BackingField"],
        ),
        Type::I32,
    ),
    (
        "GameManager uiState vanilla",
        (
            "GameManager",
            0,
            &["_instance", "<ui>k__BackingField", "uiState"],
        ),
        Type::I32,
    ),
    // ("GameManager uiState modded", ("GameManager", 0, &["_instance", "_uiInstance", "uiState"]), Type::I32),
    (
        "GameManager menuState vanilla",
        (
            "GameManager",
            0,
            &["_instance", "<ui>k__BackingField", "menuState"],
        ),
        Type::I32,
    ),
    // ("GameManager menuState modded", ("GameManager", 0, &["_instance", "_uiInstance", "menuState"]), Type::I32),
    // ("GameManager camera target destination", ("GameManager", 0, &["_instance", "<cameraCtrl>k__BackingField", "camTarget", "destination"]), Type::Vector3),
    (
        "GameManager acceptingInput",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<inputHandler>k__BackingField",
                "acceptingInput",
            ],
        ),
        Type::Bool,
    ),
    (
        "GameManager focusing",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "focusing",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl hazardRespawning",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "hazardRespawning",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl hazardDeath",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "hazardDeath",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl recoilFrozen",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "recoilFrozen",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl recoiling",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "recoiling",
            ],
        ),
        Type::Bool,
    ),
    // recoilingRight
    // recoilingLeft
    (
        "hero_ctrl dead",
        (
            "GameManager",
            0,
            &["_instance", "<hero_ctrl>k__BackingField", "cState", "dead"],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl transitionState",
        (
            "GameManager",
            0,
            &["_instance", "<hero_ctrl>k__BackingField", "transitionState"],
        ),
        Type::I32,
    ),
    // isInvincible
    // invinciTest
    // ("hero_ctrl hero_state", ("GameManager", 0, &["_instance", "<hero_ctrl>k__BackingField", "hero_state"]), Type::I32),
    // hero_state 7 corresponds to either dashing/sprinting or being gooped...
    // maybe other things... how to tell when it's being gooped specifically?
    /*
    (
        "hero_ctrl hero_state",
        (
            "GameManager",
            0,
            &["_instance", "<hero_ctrl>k__BackingField", "hero_state"],
        ),
        Type::I32,
    ),
    */
    /*
    (
        "hero_ctrl controlReqlinquished",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "controlReqlinquished",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl controlRelinquishedFrame",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "controlRelinquishedFrame",
            ],
        ),
        Type::I32,
    ),
    */
    (
        "hero_ctrl quickeningTimeLeft",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "quickeningTimeLeft",
            ],
        ),
        Type::I32,
    ),
    (
        "hero_ctrl PoisonHealthCount",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "<PoisonHealthCount>k__BackingField",
            ],
        ),
        Type::I32,
    ),
    // shuttleCock seems to have something to do with Sprint-jumps / Supers
    /*
    (
        "hero_ctrl shuttleCock",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "shuttleCock",
            ],
        ),
        Type::Bool,
    ),
    */
    (
        "hero_ctrl swimming",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "swimming",
            ],
        ),
        Type::Bool,
    ),
    /*
    (
        "hero_ctrl attackCount",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "attackCount",
            ],
        ),
        Type::I32,
    ),
    */
    (
        "hero_ctrl bouncing",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "bouncing",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl shroomBouncing",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "shroomBouncing",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl recoilingDrill",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "recoilingDrill",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl isFrostDeath",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "isFrostDeath",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl onConveyor",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "onConveyor",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl onConveyorV",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "onConveyorV",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl inConveyorZone",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "inConveyorZone",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl freezeCharge",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "freezeCharge",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl inAcid",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "inAcid",
            ],
        ),
        Type::Bool,
    ),
    // mantling appears to be ledge-grabbing?
    /*
    (
        "hero_ctrl mantling",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "mantling",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl mantleRecovery",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "mantleRecovery",
            ],
        ),
        Type::Bool,
    ),
    */
    (
        "hero_ctrl isMaggoted",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "isMaggoted",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl inFrostRegion",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "inFrostRegion",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl isFrosted",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "isFrosted",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl isBinding",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "isBinding",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl isScrewDownAttacking",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "isScrewDownAttacking",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl evading",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "evading",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl whipLashing",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "whipLashing",
            ],
        ),
        Type::Bool,
    ),
    (
        "hero_ctrl fakeHurt",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "<hero_ctrl>k__BackingField",
                "cState",
                "fakeHurt",
            ],
        ),
        Type::Bool,
    ),
    (
        "GameManager IsInSceneTransition",
        (
            "GameManager",
            0,
            &["_instance", "<IsInSceneTransition>k__BackingField"],
        ),
        Type::Bool,
    ),
    (
        "GameManager isLoading",
        ("GameManager", 0, &["_instance", "isLoading"]),
        Type::Bool,
    ),
    (
        "GameManager sceneLoad",
        ("GameManager", 0, &["_instance", "sceneLoad"]),
        Type::I32,
    ),
    (
        "SceneLoad IsFetchAllowed",
        (
            "GameManager",
            0,
            &["_instance", "sceneLoad", "<IsFetchAllowed>k__BackingField"],
        ),
        Type::Bool,
    ),
    (
        "SceneLoad IsActivationAllowed",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "sceneLoad",
                "<IsActivationAllowed>k__BackingField",
            ],
        ),
        Type::Bool,
    ),
    (
        "SceneLoad IsUnloadAssetsRequired",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "sceneLoad",
                "<IsUnloadAssetsRequired>k__BackingField",
            ],
        ),
        Type::Bool,
    ),
    (
        "SceneLoad IsGarbageCollectRequired",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "sceneLoad",
                "<IsGarbageCollectRequired>k__BackingField",
            ],
        ),
        Type::Bool,
    ),
    (
        "SceneLoad IsFinished",
        (
            "GameManager",
            0,
            &["_instance", "sceneLoad", "<IsFinished>k__BackingField"],
        ),
        Type::Bool,
    ),
    (
        "SceneLoad WaitForFade",
        (
            "GameManager",
            0,
            &["_instance", "sceneLoad", "<WaitForFade>k__BackingField"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData cloakOdour_slabFly",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "cloakOdour_slabFly"],
        ),
        Type::I32,
    ),
    (
        "PlayerData disablePause",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "disablePause"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData currentInvPane",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "currentInvPane"],
        ),
        Type::I32,
    ),
    (
        "PlayerData respawnScene",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "respawnScene"],
        ),
        Type::String,
    ),
    (
        "PlayerData respawnMarkerName",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "respawnMarkerName"],
        ),
        Type::String,
    ),
    (
        "PlayerData respawnType",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "respawnType"],
        ),
        Type::I32,
    ),
    (
        "PlayerData nonLethalRespawnScene",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "nonLethalRespawnScene"],
        ),
        Type::String,
    ),
    (
        "PlayerData nonLethalRespawnMarker",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "nonLethalRespawnMarker"],
        ),
        Type::String,
    ),
    (
        "PlayerData nonLethalRespawnType",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "nonLethalRespawnType"],
        ),
        Type::I32,
    ),
    (
        "PlayerData hasActivatedBellBench",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "hasActivatedBellBench"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData hasSilkSpecial",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "hasSilkSpecial"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData hasNeedleThrow",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "hasNeedleThrow"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData hasDash",
        ("GameManager", 0, &["_instance", "playerData", "hasDash"]),
        Type::Bool,
    ),
    (
        "PlayerData hasBrolly",
        ("GameManager", 0, &["_instance", "playerData", "hasBrolly"]),
        Type::Bool,
    ),
    (
        "PlayerData hasWalljump",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "hasWalljump"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData hasDoubleJump",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "hasDoubleJump"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData maxHealthBase",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "maxHealthBase"],
        ),
        Type::I32,
    ),
    (
        "PlayerData maxHealth",
        ("GameManager", 0, &["_instance", "playerData", "maxHealth"]),
        Type::I32,
    ),
    (
        "PlayerData health",
        ("GameManager", 0, &["_instance", "playerData", "health"]),
        Type::I32,
    ),
    (
        "PlayerData healthBlue",
        ("GameManager", 0, &["_instance", "playerData", "healthBlue"]),
        Type::I32,
    ),
    (
        "PlayerData damagedBlue",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "damagedBlue"],
        ),
        Type::I32,
    ),
    (
        "PlayerData prevHealth",
        ("GameManager", 0, &["_instance", "playerData", "prevHealth"]),
        Type::I32,
    ),
    (
        "PlayerData heartPieces",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "heartPieces"],
        ),
        Type::I32,
    ),
    (
        "PlayerData geo",
        ("GameManager", 0, &["_instance", "playerData", "geo"]),
        Type::I32,
    ),
    (
        "PlayerData bossReturnEntryGate",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "bossReturnEntryGate"],
        ),
        Type::String,
    ),
    (
        "PlayerData bossStatueTargetLevel",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "bossStatueTargetLevel"],
        ),
        Type::I32,
    ),
    (
        "PlayerData currentBossStatueCompletionKey",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "currentBossStatueCompletionKey"],
        ),
        Type::String,
    ),
    (
        "PlayerData defeatedMossMother",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "defeatedMossMother"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData defeatedBellBeast",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "defeatedBellBeast"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData defeatedBellBeast",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "defeatedBellBeast"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData defeatedLace1",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "defeatedLace1"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData defeatedSongGolem",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "defeatedSongGolem"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData spinnerDefeated",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "spinnerDefeated"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData HasSeenNeedolin",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "HasSeenNeedolin"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData hasNeedolin",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "hasNeedolin"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData bellShrineBellhart",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "bellShrineBellhart"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData completionPercentage",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "completionPercentage"],
        ),
        Type::F32,
    ),
    // 0x18 is the offset to RuntimeData,
    // asr currently struggles to resolve it by name consistently
    // because it's part of a base class or something
    (
        "PlayerData Tools version",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "playerData",
                "Tools",
                "RuntimeData",
                "_version",
            ],
        ),
        Type::I32,
    ),
    (
        "PlayerData Tools entries",
        (
            "GameManager",
            0,
            &[
                "_instance",
                "playerData",
                "Tools",
                "RuntimeData",
                "_entries",
            ],
        ),
        Type::I32,
    ),
    (
        "PlayerData CollectedDustCageKey",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "CollectedDustCageKey"],
        ),
        Type::Bool,
    ),
    (
        "PlayerData MerchantEnclaveSimpleKey",
        (
            "GameManager",
            0,
            &["_instance", "playerData", "MerchantEnclaveSimpleKey"],
        ),
        Type::Bool,
    ),
];

pub struct HollowKnightInfo {
    map_json: BTreeMap<&'static str, JsonValue>,
    pointers: Vec<(&'static str, UnityPointer<POINTER_DEPTH>, Type)>,
}

impl HollowKnightInfo {
    pub fn new() -> Self {
        Self {
            map_json: BTreeMap::new(),
            pointers: HOLLOW_KNIGHT_POINTERS
                .into_iter()
                .map(|(k, (c, n, f), t)| (*k, UnityPointer::new(*c, *n, *f), t.clone()))
                .collect(),
        }
    }
    pub fn print_changes(&mut self, process: &Process, module: &Module, image: &Image) -> bool {
        let mut changed = false;
        for (k, p, t) in self.pointers.iter() {
            let prev = self.map_json.get(k).unwrap_or(&JsonValue::Null);
            let curr = t
                .read_unity_pointer_json(process, module, image, p)
                .unwrap_or_default();
            if prev != &curr {
                asr::print_message(&format!("{}: {}", k, curr));
                self.map_json.insert(k, curr);
                changed = true;
            }
        }
        changed
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

    let n: u32 = process
        .read_pointer_path(a, PointerSize::Bit64, &[STRING_LEN_OFFSET])
        .ok()?;
    if !(n < 2048) {
        return None;
    }
    let w: ArrayWString<N> = process
        .read_pointer_path(a, PointerSize::Bit64, &[STRING_CONTENTS_OFFSET])
        .ok()?;
    if !(w.len() == min(n as usize, N)) {
        return None;
    }
    String::from_utf16(&w.to_vec()).ok()
}
