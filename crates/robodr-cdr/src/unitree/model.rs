//! Unitree robot models, as far as the published SDKs describe them.
//!
//! Every entry is derived from the SDK sources, never from marketing
//! material; the source is in [`ModelInfo::source`]. Where the SDK does not
//! say something (a motor count, a topic), the field is `None` and the
//! crate README lists the gap.
//!
//! * DDS generation (`unitree_sdk2`): model directories
//!   `include/unitree/robot/{go2,b2,a2,as2,h1,h2,g1,r1}/` and
//!   `example/{go2,go2w,b2,b2w,a2,as2,h1,h2,g1,r1}/`.
//! * Legacy UDP generation (`unitree_legged_sdk`): `LeggedType { Aliengo,
//!   A1, Go1, B1 }` in `include/unitree_legged_sdk/quadruped.h`. The local
//!   v3.8.6 sources support Go1 only (`README.md`: "support robot: Go1; not
//!   support robot: Laikago, B1, Aliengo, A1. (Check release v3.3.1 ...)").

/// A Unitree robot model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnitreeModel {
    Go2,
    /// Wheeled Go2 (`example/go2w/`).
    Go2W,
    B2,
    /// Wheeled B2 (`example/b2w/`).
    B2W,
    A2,
    As2,
    /// The original H1 (`unitree_go` low-level types, `loco` service).
    H1,
    /// H1-2 (`unitree_hg` types; `example/h1/low_level/h1_27dof_example.cpp`).
    H1_2,
    H2,
    G1,
    R1,
    Go1,
    A1,
    Aliengo,
    B1,
}

/// Transport generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Generation {
    /// `unitree_sdk2`: DDS (Cyclone DDS) topics `rt/...`.
    Sdk2Dds,
    /// `unitree_legged_sdk`: raw UDP structs (see [`crate::unitree_legacy`]).
    LegacyUdp,
}

/// Which IDL package the low-level messages use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdlFamily {
    /// `unitree_go::msg::dds_` (20 motor slots).
    Go,
    /// `unitree_hg::msg::dds_` (35 motor slots).
    Hg,
    /// Legacy UDP `comm.h` structs (20 motor slots).
    LegacyComm,
}

/// Body plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Morphology {
    Quadruped,
    /// Quadruped with a wheel at each foot.
    WheeledQuadruped,
    Humanoid,
}

/// What the SDK says about a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelInfo {
    pub model: UnitreeModel,
    pub name: &'static str,
    pub generation: Generation,
    /// Low-level IDL family (`None`: no low-level interface in the SDK).
    pub idl: Option<IdlFamily>,
    /// For a model whose SDK ships no low-level type ([`ModelInfo::idl`]
    /// `None`): the family its low-level command is **inferred** to use
    /// from the rest of the SDK, never confirmed. A2 / AS2: `Go` (their
    /// sport state is `unitree_go::msg::dds_::SportModeState_`, their sport
    /// client uses the Go2 JSON types; `unitree_sdk2` and
    /// `unitree_sdk2_python` contain no A2 / AS2 low-level example, IDL or
    /// topic). Consumers that act on it must confirm it on the robot (the
    /// type its SEDP announces); see [`ModelInfo::lowcmd_idl`].
    pub inferred_idl: Option<IdlFamily>,
    pub morphology: Morphology,
    /// Motor slots in the low-level message (20 for go / legacy, 35 for hg).
    pub motor_slots: Option<usize>,
    /// Motors the SDK examples actually drive, if the examples say.
    /// Informational: every slot on the wire is evaluated, never only
    /// these (see [`ModelInfo::arm_sdk_weight_slot`]).
    pub actuated_motors: Option<usize>,
    /// The `motor_cmd` slot whose `q` carries the `rt/arm_sdk` blend weight
    /// (`kNotUsedJoint` in the arm-SDK examples): G1 29, H1 9, H1-2 27,
    /// H2 31. `None` where the SDK uses no slot: R1 carries the weight in
    /// `mode_pr` (× 100, `dds_wrapper/robots/r1/r1_pub.h`). A slot past
    /// [`ModelInfo::actuated_motors`] that still matters.
    pub arm_sdk_weight_slot: Option<usize>,
    /// Low-level command topic.
    pub lowcmd_topic: Option<&'static str>,
    /// Low-level state topic.
    pub lowstate_topic: Option<&'static str>,
    /// High-level state topics.
    pub sport_state_topics: &'static [&'static str],
    /// Other motion topics used by the examples (arm SDK, hands, IMU).
    pub other_topics: &'static [&'static str],
    /// API services the model's motion clients use (`rt/api/<svc>/request`).
    pub api_services: &'static [&'static str],
    /// Where this entry comes from.
    pub source: &'static str,
}

impl UnitreeModel {
    pub const ALL: [UnitreeModel; 15] = [
        UnitreeModel::Go2,
        UnitreeModel::Go2W,
        UnitreeModel::B2,
        UnitreeModel::B2W,
        UnitreeModel::A2,
        UnitreeModel::As2,
        UnitreeModel::H1,
        UnitreeModel::H1_2,
        UnitreeModel::H2,
        UnitreeModel::G1,
        UnitreeModel::R1,
        UnitreeModel::Go1,
        UnitreeModel::A1,
        UnitreeModel::Aliengo,
        UnitreeModel::B1,
    ];

    #[allow(clippy::type_complexity)] // one local row tuple, not a public type
    pub fn info(self) -> ModelInfo {
        use Generation::{LegacyUdp, Sdk2Dds};
        use IdlFamily::{Go, Hg, LegacyComm};
        use Morphology::{Humanoid, Quadruped, WheeledQuadruped};
        const LOW: (Option<&str>, Option<&str>) = (Some("rt/lowcmd"), Some("rt/lowstate"));
        let (name, generation, idl, morphology, actuated, low, sport, other, api, source): (
            &'static str,
            Generation,
            Option<IdlFamily>,
            Morphology,
            Option<usize>,
            (Option<&'static str>, Option<&'static str>),
            &'static [&'static str],
            &'static [&'static str],
            &'static [&'static str],
            &'static str,
        ) = match self {
            UnitreeModel::Go2 => (
                "Go2",
                Sdk2Dds,
                Some(Go),
                Quadruped,
                Some(12),
                LOW,
                &["rt/sportmodestate", "rt/lf/sportmodestate"],
                &["rt/lf/lowstate"],
                &["sport", "obstacles_avoid", "robot_state", "uwbswitch"],
                "unitree_sdk2 example/go2/go2_stand_example.cpp (12 joints), go2_sport_client.cpp; include/unitree/robot/go2/{sport,obstacles_avoid,robot_state,utrack}; unitree_sdk2_python example/wireless_controller (rt/lf/lowstate)",
            ),
            UnitreeModel::Go2W => (
                "Go2-W",
                Sdk2Dds,
                Some(Go),
                WheeledQuadruped,
                Some(16),
                LOW,
                &["rt/lf/sportmodestate"],
                &[],
                &["sport"],
                "unitree_sdk2 example/go2w/go2w_stand_example.cpp (legs 0..12, wheels 12..16), go2w_sport_client.cpp (go2::SportClient)",
            ),
            UnitreeModel::B2 => (
                "B2",
                Sdk2Dds,
                Some(Go),
                Quadruped,
                Some(12),
                LOW,
                &[],
                &[],
                &["sport", "motion_switcher", "robot_state"],
                "unitree_sdk2 example/b2/b2_stand_example.cpp (12 joints); include/unitree/robot/b2/{sport,motion_switcher,robot_state}",
            ),
            UnitreeModel::B2W => (
                "B2-W",
                Sdk2Dds,
                Some(Go),
                WheeledQuadruped,
                Some(16),
                LOW,
                &[],
                &[],
                &["sport"],
                "unitree_sdk2 example/b2w/b2w_stand_example.cpp (legs 0..12, wheels 12..16), b2w_sport_client.cpp (b2::SportClient)",
            ),
            UnitreeModel::A2 => (
                "A2",
                Sdk2Dds,
                None,
                Quadruped,
                None,
                (None, None),
                &["rt/lf/sportmodestate"],
                &[],
                &["sport"],
                "unitree_sdk2 example/a2/sport/a2_sport_state.cpp (unitree_go SportModeState_); include/unitree/robot/a2/sport; no low-level example",
            ),
            UnitreeModel::As2 => (
                "AS2",
                Sdk2Dds,
                None,
                Quadruped,
                None,
                (None, None),
                &["rt/lf/sportmodestate"],
                &[],
                &["sport"],
                "unitree_sdk2 example/as2/sport/as2_sport_state.cpp (unitree_go SportModeState_); include/unitree/robot/as2/sport; no low-level example",
            ),
            UnitreeModel::H1 => (
                "H1",
                Sdk2Dds,
                Some(Go),
                Humanoid,
                None,
                LOW,
                &[],
                &["rt/arm_sdk"],
                &["loco"],
                "unitree_sdk2 example/h1/low_level/humanoid.hpp + motors.hpp (unitree_go LowCmd_/LowState_, array of 20), high_level/h1_arm_sdk_dds_example.cpp; include/unitree/robot/h1/loco",
            ),
            UnitreeModel::H1_2 => (
                "H1-2",
                Sdk2Dds,
                Some(Hg),
                Humanoid,
                Some(27),
                LOW,
                &[],
                &["rt/arm_sdk"],
                &[],
                "unitree_sdk2 example/h1/low_level/h1_27dof_example.cpp (H1_NUM_MOTOR = 27, unitree_hg), h1_2_arm_sdk_dds_example.cpp",
            ),
            UnitreeModel::H2 => (
                "H2",
                Sdk2Dds,
                Some(Hg),
                Humanoid,
                Some(31),
                LOW,
                &[],
                &["rt/arm_sdk", "rt/secondary_imu"],
                &["sport", "arm"],
                "unitree_sdk2 example/h2/low_level/h2_ankle_swing_example.cpp (H2_NUM_MOTOR = 31); include/unitree/robot/h2/{loco,arm}",
            ),
            UnitreeModel::G1 => (
                "G1",
                Sdk2Dds,
                Some(Hg),
                Humanoid,
                Some(29),
                LOW,
                &[],
                &[
                    "rt/arm_sdk",
                    "rt/user_lowcmd",
                    "rt/hand_sdk",
                    "rt/waistpitchcmd",
                    "rt/waistpitchstate",
                    "rt/secondary_imu",
                    "rt/dex3/left/cmd",
                    "rt/dex3/right/cmd",
                    "rt/dex3/left/state",
                    "rt/dex3/right/state",
                    "rt/lf/dex3/left/state",
                    "rt/lf/dex3/right/state",
                ],
                &["sport", "arm", "agv", "motion_switcher"],
                "unitree_sdk2 example/g1/low_level/g1_ankle_swing_example.cpp (G1_NUM_MOTOR = 29), dex3/g1_dex3_example.cpp, high_level/g1_userctrl_dds_example.cpp (rt/user_lowcmd), high_level/g1_hand_sdk_example.cpp (rt/hand_sdk, go MotorCmds_), g1d/g1d_waist_example.cpp (rt/waistpitch*, hg MotorCmd_/MotorState_), g1d/g1d_arm_example.cpp (motion_switcher); include/unitree/robot/g1/{loco,arm,agv}",
            ),
            UnitreeModel::R1 => (
                "R1",
                Sdk2Dds,
                Some(Hg),
                Humanoid,
                Some(26),
                LOW,
                &[],
                &["rt/arm_sdk", "rt/secondary_imu"],
                &["sport"],
                "unitree_sdk2 example/r1/low_level/r1_ankle_swing_example.cpp (R1_NUM_MOTOR = 26); include/unitree/robot/r1/loco",
            ),
            UnitreeModel::Go1 => (
                "Go1",
                LegacyUdp,
                Some(LegacyComm),
                Quadruped,
                Some(12),
                (None, None),
                &[],
                &[],
                &[],
                "unitree_legged_sdk v3.8.6 include/unitree_legged_sdk/{comm.h,udp.h,quadruped.h} (12 joints FR/FL/RR/RL x 3)",
            ),
            UnitreeModel::A1 => (
                "A1",
                LegacyUdp,
                None,
                Quadruped,
                Some(12),
                (None, None),
                &[],
                &[],
                &[],
                "unitree_legged_sdk quadruped.h LeggedType::A1; frame layout only in release v3.3.1 (not available here)",
            ),
            UnitreeModel::Aliengo => (
                "Aliengo",
                LegacyUdp,
                None,
                Quadruped,
                Some(12),
                (None, None),
                &[],
                &[],
                &[],
                "unitree_legged_sdk quadruped.h LeggedType::Aliengo; frame layout only in release v3.3.1 (not available here)",
            ),
            UnitreeModel::B1 => (
                "B1",
                LegacyUdp,
                None,
                Quadruped,
                Some(12),
                (None, None),
                &[],
                &[],
                &[],
                "unitree_legged_sdk quadruped.h LeggedType::B1, b1_const.h; frame layout only in release v3.3.1 (not available here)",
            ),
        };
        // A2 / AS2: inferred, see `ModelInfo::inferred_idl`.
        let inferred_idl = match self {
            UnitreeModel::A2 | UnitreeModel::As2 => Some(Go),
            _ => None,
        };
        let arm_sdk_weight_slot = match self {
            // example/g1/high_level/g1_arm7_sdk_dds_example.cpp (kNotUsedJoint = 29),
            // dds_wrapper/robots/g1/g1_pub.h (motor_cmd()[29].q()).
            UnitreeModel::G1 => Some(29),
            // example/h1/high_level/h1_arm_sdk_dds_example.cpp (kNotUsedJoint = 9).
            UnitreeModel::H1 => Some(9),
            // example/h1/high_level/h1_2_arm_sdk_dds_example.cpp (kNotUsedJoint = 27).
            UnitreeModel::H1_2 => Some(27),
            // example/h2/high_level/h2_arm_sdk_dds_example.cpp (kArmSdkWeightJoint = 31).
            UnitreeModel::H2 => Some(31),
            _ => None,
        };
        let motor_slots = match idl {
            Some(Go) | Some(LegacyComm) => Some(crate::unitree::MOTOR_SLOTS_GO),
            Some(Hg) => Some(crate::unitree::MOTOR_SLOTS_HG),
            None => None,
        };
        ModelInfo {
            model: self,
            name,
            generation,
            idl,
            inferred_idl,
            morphology,
            motor_slots,
            actuated_motors: actuated,
            arm_sdk_weight_slot,
            lowcmd_topic: low.0,
            lowstate_topic: low.1,
            sport_state_topics: sport,
            other_topics: other,
            api_services: api,
            source,
        }
    }

    /// Shorthand for `self.info().lowcmd_idl()`.
    pub fn lowcmd_idl(self) -> Option<IdlFamily> {
        self.info().lowcmd_idl()
    }

    /// The model for a name as in [`ModelInfo::name`] or the enum variant
    /// (`"Go2"`, `"go2w"`, `"H1-2"`, `"h1_2"`, ...; case-insensitive,
    /// `-` / `_` ignored).
    pub fn from_name(name: &str) -> Option<UnitreeModel> {
        let norm = |s: &str| -> String {
            s.chars()
                .filter(|c| *c != '-' && *c != '_')
                .flat_map(char::to_lowercase)
                .collect()
        };
        let want = norm(name);
        Self::ALL
            .into_iter()
            .find(|m| norm(m.info().name) == want || norm(&format!("{m:?}")) == want)
    }
}

impl ModelInfo {
    /// The low-level family to check a configuration against: the SDK's
    /// ([`ModelInfo::idl`]) or, where the SDK has none, the inferred one
    /// ([`ModelInfo::inferred_idl`]).
    pub fn lowcmd_idl(&self) -> Option<IdlFamily> {
        self.idl.or(self.inferred_idl)
    }

    /// Motor slots of [`ModelInfo::lowcmd_idl`]'s message (20 / 35).
    pub fn lowcmd_motor_slots(&self) -> Option<usize> {
        match self.lowcmd_idl() {
            Some(IdlFamily::Go) | Some(IdlFamily::LegacyComm) => {
                Some(crate::unitree::MOTOR_SLOTS_GO)
            }
            Some(IdlFamily::Hg) => Some(crate::unitree::MOTOR_SLOTS_HG),
            None => None,
        }
    }

    /// `true` when the low-level family is inferred, not published.
    pub fn lowcmd_inferred(&self) -> bool {
        self.idl.is_none() && self.inferred_idl.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a2_and_as2_low_level_is_inferred_go_and_marked_so() {
        for m in [UnitreeModel::A2, UnitreeModel::As2] {
            let i = m.info();
            assert_eq!(i.idl, None, "{m:?}: no published low-level type");
            assert_eq!(i.inferred_idl, Some(IdlFamily::Go));
            assert_eq!(i.lowcmd_idl(), Some(IdlFamily::Go));
            assert_eq!(i.lowcmd_motor_slots(), Some(crate::unitree::MOTOR_SLOTS_GO));
            assert!(i.lowcmd_inferred());
            assert_eq!(i.motor_slots, None);
            assert_eq!(i.actuated_motors, None);
        }
        for m in UnitreeModel::ALL {
            let i = m.info();
            if !matches!(m, UnitreeModel::A2 | UnitreeModel::As2) {
                assert_eq!(i.inferred_idl, None, "{m:?}");
                assert_eq!(i.lowcmd_idl(), i.idl, "{m:?}");
                assert!(!i.lowcmd_inferred());
            }
        }
    }
}
