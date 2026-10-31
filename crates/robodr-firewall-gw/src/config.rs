//! The gateway configuration (`robodr-firewall-gw.json`).
//!
//! JSON, unknown keys refused everywhere. Example (see
//! `config/firewall-gw.unitree-g1.example.json`):
//!
//! ```json
//! {
//!   "mode": "enforce",
//!   "profile": "/etc/robodr/profile.json",
//!   "profile_trust": { "trusted_keys": "/etc/robodr/profile-trust.json" },
//!   "firewall": "/etc/robodr/firewall.json",
//!   "queue": { "num": 0, "on_gateway_down": "fail_closed",
//!              "controller_port": "enp2s0", "robot_port": "enp3s0" },
//!   "rtps": { "domain_ids": [0] },
//!   "channels": [
//!     { "firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd",
//!       "allowed_src_ips": ["192.168.123.164"] }
//!   ]
//! }
//! ```
//!
//! # `queue.on_gateway_down` — what happens when the gateway process is not
//! # there
//!
//! NFQUEUE has no listener when the gateway is stopped, crashed or
//! restarting, and the kernel then applies the rule's own flag:
//!
//! - **`fail_closed`** (**default**): the queued datagrams are dropped. The
//!   robot receives no motion command on the queued channels and its own
//!   command-timeout behaviour applies, exactly as when the controller
//!   itself fails. A security control that disappears must not open the
//!   path an attacker can open by crashing it.
//! - **`bypass`** (`queue ... bypass` / `--queue-bypass`): datagrams pass
//!   **unchecked**. For platforms whose OEM safety case says losing the
//!   command stream is the greater hazard. **Refused for a humanoid
//!   platform with a low-level joint channel** (the firewall refuses
//!   `fail_open` there for the same reason: it would forward unchecked
//!   frames to the motors).
//!
//! The same choice sets the queue's overflow behaviour
//! (`NFQA_CFG_F_FAIL_OPEN`): with `bypass`, datagrams the full queue cannot
//! hold pass; with `fail_closed` they are dropped. The rule flag is part of
//! the rendered ruleset (`robodr-firewall-gw ruleset`), so the two cannot
//! disagree.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use robodr_ros2_pipeline::ProfileTrustConfig;
use serde::Deserialize;

/// Largest configuration file read.
pub const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// `enforce` decides and rewrites; `observe` decides (records would-have
/// verdicts) and forwards every datagram unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayMode {
    Enforce,
    Observe,
}

/// See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnGatewayDown {
    #[default]
    FailClosed,
    Bypass,
}

/// NFQUEUE and bridge settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueConfig {
    /// NFQUEUE number (`0..=65535`).
    pub num: u16,
    #[serde(default)]
    pub on_gateway_down: OnGatewayDown,
    /// Kernel queue length (packets) before the overflow behaviour applies.
    #[serde(default = "default_max_len")]
    pub max_len: u32,
    /// Bridge port facing the controller (only datagrams **entering** here
    /// are queued; ruleset rendering).
    pub controller_port: String,
    /// Bridge port facing the robot (ruleset rendering).
    pub robot_port: String,
    /// 802.1Q VLAN ids (`1..=4094`, at most 16) whose IPv4 / ARP frames
    /// are bridged from the controller port (sales-readiness T44). Their
    /// IPv4 is queued and decided exactly like untagged traffic
    /// (`bridge-nf-filter-vlan-tagged`). Default: none (every tagged frame
    /// is dropped). Stacked tags (QinQ) are always dropped.
    #[serde(default)]
    pub vlan_ids: Vec<u16>,
}

fn default_max_len() -> u32 {
    1024
}

/// What to do with a datagram on an RTPS port that is not decidable as a
/// whole (not RTPS, truncated, malformed, DDS-Security, too many samples).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MalformedPolicy {
    /// **Default.** Drop it. Legitimate DDS stacks do not send such
    /// datagrams to the robot; deciding on part of one could forward a
    /// sample the gateway never saw the way the receiver sees it.
    #[default]
    Drop,
    /// Forward it unchanged (sites that use DDS-Security or another
    /// RTPS-like protocol on these ports; the gateway then enforces
    /// nothing in such datagrams).
    Pass,
}

/// A user DATA from a writer the gateway has no SEDP announcement for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownWriters {
    /// **Default.** Try each enforced channel's decoder (a `LowCmd_` must
    /// also carry a valid Unitree CRC, a request must be a known sport
    /// call); a match is decided as that channel (its source is then
    /// resolved as usual, so an unknown writer is a foreign source).
    #[default]
    Probe,
    /// Leave such samples alone (only SEDP-classified writers are decided).
    Pass,
}

/// Robot-side observation (`crate::observe`): an NFLOG **copy** of every
/// UDP datagram entering the bridge from the robot port. Never queued,
/// never dropped (the kernel forwards the original at once): it feeds the
/// arm-SDK engagement check (`rt/lowstate`) and the unqueued-locator check
/// of the robot's own discovery.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObserveConfig {
    /// Default `true`. `false`: no observe rule, no `rt/lowstate` (the
    /// arm-SDK engagement uses the conservative first-step rule), no
    /// robot-side locator check.
    pub enabled: bool,
    /// NFLOG group (`0..=65535`, default 4174; must not be shared with
    /// another NFLOG consumer such as ulogd).
    pub nflog_group: u16,
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            nflog_group: 4174,
        }
    }
}

/// RTPS settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RtpsConfig {
    /// DDS domain ids whose port range (7400 + 250·d .. +249) is queued.
    pub domain_ids: Vec<u16>,
    pub malformed_datagram: MalformedPolicy,
    pub unknown_writers: UnknownWriters,
    /// Most not-enforced writers remembered (SEDP on other topics, probe
    /// results; least recently used evicted first).
    pub max_writers: usize,
    /// Most writers classified as enforced (never downgraded; when full,
    /// a new enforced writer replaces one idle for
    /// `enforced_idle_evict_s`, or else is refused, reported, and probed
    /// instead). `1..=65536`, default 1024.
    pub max_enforced_writers: usize,
    /// How long (s) an enforced writer must have sent nothing and not been
    /// announced before a new enforced writer may take its place in a full
    /// table. `0`: never (a full table refuses every new enforced writer);
    /// else `60..=31536000`; default 3600.
    pub enforced_idle_evict_s: u64,
    /// Writers per enforced channel with sequence / replay state.
    pub max_writers_per_channel: usize,
    /// Where the learned writer -> channel map is persisted (so a gateway
    /// restart, which does not see the earlier SEDP again, keeps
    /// classifying the robot's existing writers).
    pub state_file: Option<PathBuf>,
    /// Largest forward step of a bound writer's sequence number that is
    /// decided at once. A larger jump is suppressed until the next sample
    /// of the same binding confirms it (see the crate docs). `1..=2^20`.
    pub max_sn_jump: u64,
    /// How long (ns) the (source IP, MAC) a writer's stream is bound to
    /// must have sent nothing before another (IP, MAC) presenting the same
    /// authorised GUID may continue it; until then such samples are binding
    /// conflicts (suppressed). `1 ms ..= 60 s`, default 1 s.
    pub binding_takeover_ns: u64,
    /// Further UDP port ranges `[lo, hi]` queued and decided as RTPS, for
    /// DDS stacks that do not use the RTPS well-known ports of
    /// `domain_ids` (Cyclone DDS `Discovery/Ports`, `ParticipantIndex`
    /// `none` with kernel-chosen unicast ports, Fast DDS ...). The gateway
    /// warns (`unqueued_locators`, status flag `port_bypass_risk`) when
    /// discovery announces a locator outside every queued range. At most
    /// 16 ranges.
    pub extra_port_ranges: Vec<[u16; 2]>,
}

impl Default for RtpsConfig {
    fn default() -> Self {
        Self {
            domain_ids: vec![0],
            malformed_datagram: MalformedPolicy::Drop,
            unknown_writers: UnknownWriters::Probe,
            max_writers: 4096,
            max_enforced_writers: 1024,
            enforced_idle_evict_s: 3600,
            max_writers_per_channel: 16,
            state_file: None,
            max_sn_jump: 64,
            binding_takeover_ns: 1_000_000_000,
            extra_port_ranges: Vec::new(),
        }
    }
}

/// The wire format of a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Codec {
    /// RTPS DATA, `unitree_go::msg::dds_::LowCmd_` (20 slots).
    UnitreeGoLowcmd,
    /// RTPS DATA, `unitree_hg::msg::dds_::LowCmd_` (35 slots).
    UnitreeHgLowcmd,
    /// RTPS DATA, `unitree_api::msg::dds_::Request_` of the sport service.
    UnitreeSportRequest,
    /// Legacy UDP `HighCmd` (129 octets).
    Go1HighCmd,
    /// Legacy UDP uncompressed `LowCmd` (734 octets).
    Go1LowCmd,
    /// Legacy UDP compressed `LowCmd` (614 octets, `LOW_CMD_LENGTH` of
    /// `unitree_legged_sdk` v3.8.6: what a real Go1 client sends; layout
    /// from the library's `refineCmd`, `robodr_cdr::unitree_legacy`).
    Go1LowCmdCompressed,
    /// RTPS DATA on an A2 / AS2 `rt/lowcmd`: **inferred** to be
    /// `unitree_go::msg::dds_::LowCmd_` (20 slots, CRC over the body). The
    /// SDK ships no A2 / AS2 low-level type or example; their sport state
    /// is `unitree_go::msg::dds_::SportModeState_`. Decoded exactly as
    /// `unitree_go_lowcmd`, with stricter rules: the firewall channel must
    /// have `require_crc`, `allow_battery_off` and
    /// `queue.on_gateway_down: bypass` are refused, and the profile must
    /// record the channel's type (learned from the robot's own SEDP), so a
    /// robot announcing another type never starts in enforce mode.
    UnitreeA2Lowcmd,
    /// RTPS DATA, `unitree_api::msg::dds_::Request_` of a humanoid's
    /// locomotion client (`robot_model` g1 / h2 / r1: service `sport`,
    /// topic `rt/api/sport/request`, ids 7xxx; h1: service `loco`, topic
    /// `rt/api/loco/request`, ids 8xxx).
    UnitreeLocoRequest,
    /// RTPS DATA, `unitree_hg::msg::dds_::LowCmd_` on `rt/arm_sdk` (G1,
    /// H1-2, H2, R1): every motor slot with gains / torque is decided
    /// whatever its mode octet; `motor_cmd[weight_slot].q` is the arm-SDK
    /// blend weight.
    UnitreeHgArmSdk,
    /// RTPS DATA, `unitree_go::msg::dds_::LowCmd_` on `rt/arm_sdk` (H1).
    UnitreeGoArmSdk,
    /// RTPS DATA, `unitree_hg::msg::dds_::HandCmd_` (Dex3,
    /// `rt/dex3/{left,right}/cmd`): decided, passed or suppressed.
    UnitreeDex3HandCmd,
    /// RTPS DATA, `unitree_go::msg::dds_::MotorCmds_` on `rt/hand_sdk` (G1
    /// hand SDK): decided, passed or suppressed.
    UnitreeHandSdk,
    /// RTPS DATA, ROS 2 `geometry_msgs/msg/Twist` (`rt/cmd_vel`).
    Ros2Twist,
    /// RTPS DATA, ROS 2 `geometry_msgs/msg/TwistStamped` (`rt/cmd_vel`).
    Ros2TwistStamped,
    /// RTPS DATA, `unitree_api::msg::dds_::Request_` of the G1 / H2 arm
    /// action service (`rt/api/arm/request`, `g1_arm_action_api.hpp`:
    /// `ExecuteAction` 7106, `ExecuteCustomAction` 7108,
    /// `StopCustomAction` 7113, `GetActionList` 7107): every call but a
    /// query refused unless in `allowed_api_ids`.
    UnitreeArmRequest,
    /// RTPS DATA, ROS 2 `trajectory_msgs/msg/JointTrajectory` (the topic of
    /// a `joint_trajectory_controller`): checked against `trajectory`
    /// (`crate::trajectory`), passed, time-scaled in place or suppressed.
    Ros2JointTrajectory,
    /// RTPS DATA, `unitree_api::msg::dds_::Request_` of the Go2
    /// `obstacles_avoid` service (`rt/api/obstacles_avoid/request`,
    /// `obstacles_avoid_api.hpp`): `Move` 1003 with `mode` 0 is a body
    /// velocity (decided and limited like the sport `Move`), `mode` 1 / 2 a
    /// position target, refused unless in `allowed_api_ids`; `SwitchSet`
    /// and `UseRemoteCommandFromApi` refused unless listed; `SwitchGet`
    /// passes.
    UnitreeObstaclesAvoidRequest,
    /// RTPS DATA, `unitree_api::msg::dds_::Request_` of the Go2 UWB
    /// tracking service (`rt/api/uwbswitch/request`, `utrack_api.hpp`):
    /// `SwitchSet` (the robot follows the UWB remote) refused unless in
    /// `allowed_api_ids`; the queries pass.
    #[serde(rename = "unitree_uwbswitch_request")]
    UnitreeUwbSwitchRequest,
    /// RTPS DATA, the `send_goal` request of a ROS 2
    /// `control_msgs/action/FollowJointTrajectory` action
    /// (`rq/<action>/_action/send_goalRequest`): its trajectory checked as
    /// [`Codec::Ros2JointTrajectory`], its multi-DOF part must be empty.
    Ros2FollowJointTrajectoryGoal,
}

/// The humanoid whose locomotion client a `unitree_loco_request` channel
/// carries (`robodr-cdr`'s api tables).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocoModel {
    G1,
    H1,
    H2,
    R1,
}

impl LocoModel {
    pub fn unitree(self) -> robodr_cdr::unitree::UnitreeModel {
        use robodr_cdr::unitree::UnitreeModel as M;
        match self {
            LocoModel::G1 => M::G1,
            LocoModel::H1 => M::H1,
            LocoModel::H2 => M::H2,
            LocoModel::R1 => M::R1,
        }
    }

    /// The topic of its locomotion client (`LOCO_SERVICE_NAME`: `"sport"`
    /// in `unitree_sdk2` `include/unitree/robot/{g1,h2,r1}/loco/*_loco_api.hpp`,
    /// `"loco"` in `h1/loco/h1_loco_api.hpp:11`).
    pub fn topic(self) -> &'static str {
        match self {
            LocoModel::H1 => "rt/api/loco/request",
            _ => "rt/api/sport/request",
        }
    }
}

impl Codec {
    pub fn is_rtps(self) -> bool {
        !matches!(
            self,
            Codec::Go1HighCmd | Codec::Go1LowCmd | Codec::Go1LowCmdCompressed
        )
    }

    /// `true` for joint-frame channels (checked with `check_joint`).
    pub fn is_joint(self) -> bool {
        matches!(
            self,
            Codec::UnitreeGoLowcmd
                | Codec::UnitreeA2Lowcmd
                | Codec::UnitreeHgLowcmd
                | Codec::Go1LowCmd
                | Codec::Go1LowCmdCompressed
                | Codec::UnitreeHgArmSdk
                | Codec::UnitreeGoArmSdk
                | Codec::UnitreeDex3HandCmd
                | Codec::UnitreeHandSdk
        )
    }

    /// `true` for the arm-SDK codecs.
    pub fn is_arm_sdk(self) -> bool {
        matches!(self, Codec::UnitreeHgArmSdk | Codec::UnitreeGoArmSdk)
    }

    /// `true` for the hand codecs (variable slot count: the firewall
    /// channel's).
    pub fn is_hand(self) -> bool {
        matches!(self, Codec::UnitreeDex3HandCmd | Codec::UnitreeHandSdk)
    }

    /// `true` for the ROS 2 twist codecs.
    pub fn is_ros2_twist(self) -> bool {
        matches!(self, Codec::Ros2Twist | Codec::Ros2TwistStamped)
    }

    /// `true` for the Unitree api request codecs (`Request_`).
    pub fn is_api_request(self) -> bool {
        matches!(
            self,
            Codec::UnitreeSportRequest
                | Codec::UnitreeLocoRequest
                | Codec::UnitreeArmRequest
                | Codec::UnitreeObstaclesAvoidRequest
                | Codec::UnitreeUwbSwitchRequest
        )
    }

    /// `true` for the ROS 2 joint-trajectory codecs (`crate::trajectory`).
    pub fn is_trajectory(self) -> bool {
        matches!(
            self,
            Codec::Ros2JointTrajectory | Codec::Ros2FollowJointTrajectoryGoal
        )
    }

    /// Motor slots of a joint codec (`None` for hands: the firewall
    /// channel's count).
    pub fn slots(self) -> Option<usize> {
        match self {
            Codec::UnitreeGoLowcmd
            | Codec::UnitreeA2Lowcmd
            | Codec::Go1LowCmd
            | Codec::Go1LowCmdCompressed
            | Codec::UnitreeGoArmSdk => Some(20),
            Codec::UnitreeHgLowcmd | Codec::UnitreeHgArmSdk => Some(35),
            _ => None,
        }
    }

    pub fn default_topic(self) -> Option<&'static str> {
        match self {
            Codec::UnitreeGoLowcmd | Codec::UnitreeHgLowcmd | Codec::UnitreeA2Lowcmd => {
                Some("rt/lowcmd")
            }
            Codec::UnitreeSportRequest => Some("rt/api/sport/request"),
            Codec::UnitreeHgArmSdk | Codec::UnitreeGoArmSdk => Some("rt/arm_sdk"),
            Codec::UnitreeHandSdk => Some("rt/hand_sdk"),
            Codec::Ros2Twist | Codec::Ros2TwistStamped => Some("rt/cmd_vel"),
            Codec::UnitreeArmRequest => Some("rt/api/arm/request"),
            Codec::UnitreeObstaclesAvoidRequest => Some("rt/api/obstacles_avoid/request"),
            Codec::UnitreeUwbSwitchRequest => Some("rt/api/uwbswitch/request"),
            // Loco: by `robot_model`; Dex3: left or right, must be named.
            _ => None,
        }
    }

    pub fn default_ports(self) -> &'static [u16] {
        match self {
            Codec::Go1HighCmd => &[8082],
            Codec::Go1LowCmd | Codec::Go1LowCmdCompressed => &[8007],
            _ => &[],
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Codec::UnitreeGoLowcmd => "unitree_go_lowcmd",
            Codec::UnitreeHgLowcmd => "unitree_hg_lowcmd",
            Codec::UnitreeSportRequest => "unitree_sport_request",
            Codec::Go1HighCmd => "go1_high_cmd",
            Codec::Go1LowCmd => "go1_low_cmd",
            Codec::Go1LowCmdCompressed => "go1_low_cmd_compressed",
            Codec::UnitreeA2Lowcmd => "unitree_a2_lowcmd",
            Codec::UnitreeLocoRequest => "unitree_loco_request",
            Codec::UnitreeHgArmSdk => "unitree_hg_arm_sdk",
            Codec::UnitreeGoArmSdk => "unitree_go_arm_sdk",
            Codec::UnitreeDex3HandCmd => "unitree_dex3_hand_cmd",
            Codec::UnitreeHandSdk => "unitree_hand_sdk",
            Codec::Ros2Twist => "ros2_twist",
            Codec::Ros2TwistStamped => "ros2_twist_stamped",
            Codec::UnitreeArmRequest => "unitree_arm_request",
            Codec::UnitreeObstaclesAvoidRequest => "unitree_obstacles_avoid_request",
            Codec::UnitreeUwbSwitchRequest => "unitree_uwbswitch_request",
            Codec::Ros2JointTrajectory => "ros2_joint_trajectory",
            Codec::Ros2FollowJointTrajectoryGoal => "ros2_follow_joint_trajectory_goal",
        }
    }

    /// The DDS type name the codec decodes.
    pub fn dds_type_name(self) -> &'static str {
        match self {
            Codec::UnitreeGoLowcmd | Codec::UnitreeGoArmSdk | Codec::UnitreeA2Lowcmd => {
                "unitree_go::msg::dds_::LowCmd_"
            }
            Codec::UnitreeHgLowcmd | Codec::UnitreeHgArmSdk => "unitree_hg::msg::dds_::LowCmd_",
            Codec::UnitreeSportRequest
            | Codec::UnitreeLocoRequest
            | Codec::UnitreeArmRequest
            | Codec::UnitreeObstaclesAvoidRequest
            | Codec::UnitreeUwbSwitchRequest => "unitree_api::msg::dds_::Request_",
            Codec::UnitreeDex3HandCmd => "unitree_hg::msg::dds_::HandCmd_",
            Codec::UnitreeHandSdk => "unitree_go::msg::dds_::MotorCmds_",
            Codec::Ros2Twist => "geometry_msgs::msg::dds_::Twist_",
            Codec::Ros2TwistStamped => "geometry_msgs::msg::dds_::TwistStamped_",
            Codec::Go1HighCmd => "unitree_legged_sdk::HighCmd",
            Codec::Go1LowCmd | Codec::Go1LowCmdCompressed => "unitree_legged_sdk::LowCmd",
            Codec::Ros2JointTrajectory => "trajectory_msgs::msg::dds_::JointTrajectory_",
            Codec::Ros2FollowJointTrajectoryGoal => {
                "control_msgs::action::dds_::FollowJointTrajectory_SendGoal_Request_"
            }
        }
    }
}

/// One enforced channel.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelConfig {
    /// The channel's name in the firewall configuration / profile (e.g.
    /// `/lowcmd`).
    pub firewall_channel: String,
    pub codec: Codec,
    /// RTPS codecs: the DDS topic (default `rt/lowcmd` /
    /// `rt/api/sport/request`).
    #[serde(default)]
    pub topic: Option<String>,
    /// Legacy codecs: destination UDP ports (default 8082 high / 8007 low).
    #[serde(default)]
    pub udp_ports: Vec<u16>,
    /// If non-empty, a datagram from any other source IP is a foreign
    /// source on this channel whatever its writer GUID says.
    #[serde(default)]
    pub allowed_src_ips: Vec<String>,
    /// Legacy codecs: source IP -> firewall source (`identity:<name>` or a
    /// GUID listed in the channel's `allowed_sources`). Other IPs are
    /// foreign.
    #[serde(default)]
    pub legacy_sources: BTreeMap<String, String>,
    /// Api requests / Go1 `HighCmd`: a request whose api id (a `HighCmd`
    /// whose mode) is not listed is suppressed. Velocity calls (`Move`,
    /// mode 2), stops and queries are decided without it. **Required** on
    /// `unitree_sport_request`, `unitree_obstacles_avoid_request`,
    /// `unitree_uwbswitch_request` (`allowed_api_ids`) and `go1_high_cmd`
    /// (`allowed_high_modes`): a missing list used to mean "everything"
    /// (gateway review, finding 6).
    #[serde(default)]
    pub allowed_api_ids: Option<Vec<i64>>,
    #[serde(default)]
    pub allowed_high_modes: Option<Vec<u8>>,
    /// If non-empty, a datagram whose source MAC (as the kernel reports it
    /// for the bridged frame) is not listed is a foreign source on this
    /// channel; a datagram without a reported MAC then is too. Format
    /// `aa:bb:cc:dd:ee:ff`.
    #[serde(default)]
    pub allowed_src_macs: Vec<String>,
    /// `unitree_go_lowcmd` only: forward frames whose `bms_cmd.off` is not
    /// zero (`0xA5` turns the robot's battery off). Default `false`: such a
    /// frame is refused (decided as an integrity failure, so the platform's
    /// substitute applies).
    #[serde(default)]
    pub allow_battery_off: bool,
    /// `unitree_loco_request` (required): which humanoid's locomotion
    /// client (`g1`, `h1`, `h2`, `r1`): its api table and default topic.
    #[serde(default)]
    pub robot_model: Option<LocoModel>,
    /// `unitree_loco_request`: `SetFsmId` values forwarded besides the
    /// model's `Start` (walking controller). Default none: `ZeroTorque` (0)
    /// and `Damp` (1) make a humanoid go limp and fall, the posture
    /// transitions (squat, sit, lie down, stand up) move the whole body;
    /// listing one is an explicit decision of the site.
    #[serde(default)]
    pub allowed_fsm_ids: Option<Vec<i64>>,
    /// `unitree_loco_request`: longest `SetVelocity` duration forwarded
    /// (s, `(0, 60]`, default 1.0 = the SDK's default). A longer one is
    /// rewritten to it (`Move(..., continous_move = true)` sends 864000 s).
    #[serde(default)]
    pub max_velocity_duration_s: Option<f64>,
    /// Arm-SDK codecs (required): the motor slot whose `q` is the blend
    /// weight (G1 29, H1-2 27, H2 31, H1 9: `kNotUsedJoint` /
    /// `kArmSdkWeightJoint` in the SDK examples).
    #[serde(default)]
    pub weight_slot: Option<usize>,
    /// Arm-SDK codecs: the largest weight forwarded (`[0, 1]`, default 1).
    #[serde(default)]
    pub max_weight: Option<f64>,
    /// Arm-SDK and hand-SDK codecs: the largest change of the blend weight
    /// from the last accepted frame (`(0, 1]`, default
    /// [`DEFAULT_MAX_WEIGHT_STEP`]). Beyond it the frame is refused (an
    /// integrity failure: a humanoid holds the last accepted frame).
    #[serde(default)]
    pub max_weight_step: Option<f64>,
    /// Arm-SDK and hand-SDK codecs: the largest rate of change of the blend
    /// weight, per second of gateway clock since the last accepted frame
    /// (`(0, 1000]`, default [`DEFAULT_MAX_WEIGHT_RATE`]).
    #[serde(default)]
    pub max_weight_rate_per_s: Option<f64>,
    /// Arm-SDK codecs: a weight rising from 0 (the arms handed to the SDK)
    /// is accepted only when every weighted slot's `q` (gains on) is within
    /// this distance (rad, `(0, 1]`, default 0.1) of the joint position the
    /// robot last reported in `rt/lowstate` (observed, never queued; see
    /// the README, "Arm SDK").
    #[serde(default)]
    pub engage_max_q_error: Option<f64>,
    /// Arm-SDK codecs: the oldest `rt/lowstate` sample the engagement check
    /// uses (ms, `1..=1000`, default 50).
    #[serde(default)]
    pub lowstate_max_age_ms: Option<u64>,
    /// Arm-SDK codecs: the robot's joint-state topic (default `rt/lowstate`).
    #[serde(default)]
    pub lowstate_topic: Option<String>,
    /// Arm-SDK codecs, no fresh `rt/lowstate`: the weight may leave 0 only
    /// up to this value (`(0, 1]`, default [`DEFAULT_MAX_WEIGHT_STEP`]) ...
    #[serde(default)]
    pub engage_first_step: Option<f64>,
    /// ... and rise above it only after this many accepted frames
    /// (`1..=100000`, default 50) whose weighted targets moved by at most
    /// `engage_stable_q` (rad, `(0, 1]`, default 0.01) from frame to frame.
    #[serde(default)]
    pub engage_stable_frames: Option<u32>,
    #[serde(default)]
    pub engage_stable_q: Option<f64>,
    /// Trajectory codecs (required): the joints, their bounds and the
    /// trajectory bounds ([`TrajectoryConfig`]).
    #[serde(default)]
    pub trajectory: Option<TrajectoryConfig>,
    /// Free text for the operator (ignored; at most 500 characters, no
    /// control characters). The shipped examples explain each channel here.
    #[serde(default)]
    pub note: Option<String>,
}

/// One joint of a trajectory channel.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryJointConfig {
    /// The joint name exactly as the controller knows it (1..=255 octets,
    /// no control characters).
    pub name: String,
    /// Position bounds (rad or m), finite, `min < max`.
    pub min_position: f64,
    pub max_position: f64,
    /// Speed bound (rad/s or m/s), finite, `> 0`; capped by the profile
    /// envelope's `max_joint_speed` of the channel.
    pub max_velocity: f64,
    /// Acceleration bound, finite, `> 0`.
    pub max_acceleration: f64,
    /// Effort bound (N·m or N), finite, `> 0`.
    pub max_effort: f64,
}

/// What a velocity / acceleration violation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnVelocityViolation {
    /// **Default.** The trajectory is suppressed.
    #[default]
    Reject,
    /// Slowed down in place by the smallest factor that fits, up to
    /// `max_time_scale` (`crate::trajectory`, "Time scaling").
    TimeScale,
}

/// The `service request header` layout in front of a `send_goal` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestHeader {
    /// `rmw_fastrtps_cpp` (Jazzy's default): none in the payload.
    #[default]
    None,
    /// `rmw_cyclonedds_cpp`: 16 octets (client GUID hash, sequence).
    Cyclone,
}

/// The bounds of a trajectory channel (`crate::trajectory`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryConfig {
    /// 1..=32 joints, distinct names.
    pub joints: Vec<TrajectoryJointConfig>,
    /// Most points per trajectory (1..=4096, default 256).
    #[serde(default = "default_max_points")]
    pub max_points: usize,
    /// Longest `time_from_start` of the last point (s, `(0, 3600]`,
    /// default 60).
    #[serde(default = "default_max_duration")]
    pub max_duration_s: f64,
    #[serde(default)]
    pub on_velocity_violation: OnVelocityViolation,
    /// Largest slow-down of `time_scale` (`[1, 100]`, default 4).
    #[serde(default = "default_max_time_scale")]
    pub max_time_scale: f64,
    /// `ros2_follow_joint_trajectory_goal` only: the RMW's request header.
    #[serde(default)]
    pub request_header: RequestHeader,
}

fn default_max_points() -> usize {
    256
}
fn default_max_duration() -> f64 {
    60.0
}
fn default_max_time_scale() -> f64 {
    4.0
}

impl TrajectoryConfig {
    fn validate(&self, at: &str, codec: Codec) -> Result<(), String> {
        if self.joints.is_empty() || self.joints.len() > crate::trajectory::MAX_JOINTS {
            return Err(format!("{at}: trajectory.joints: 1..=32 joints"));
        }
        for (i, j) in self.joints.iter().enumerate() {
            if j.name.is_empty()
                || j.name.len() >= crate::trajectory::MAX_NAME
                || j.name.chars().any(char::is_control)
            {
                return Err(format!(
                    "{at}: trajectory.joints[{i}].name: 1..=255 octets, no control characters"
                ));
            }
            if self.joints.iter().take(i).any(|k| k.name == j.name) {
                return Err(format!("{at}: trajectory joint {:?} listed twice", j.name));
            }
            let pos = |x: f64| x.is_finite() && x > 0.0;
            if !(j.min_position.is_finite()
                && j.max_position.is_finite()
                && j.min_position < j.max_position
                && pos(j.max_velocity)
                && pos(j.max_acceleration)
                && pos(j.max_effort))
            {
                return Err(format!(
                    "{at}: trajectory joint {:?}: finite bounds, min_position < max_position, \
                     max_velocity / max_acceleration / max_effort > 0",
                    j.name
                ));
            }
        }
        if !(1..=crate::trajectory::HARD_MAX_POINTS).contains(&self.max_points) {
            return Err(format!("{at}: trajectory.max_points must be in 1..=4096"));
        }
        if !(self.max_duration_s.is_finite()
            && self.max_duration_s > 0.0
            && self.max_duration_s <= 3600.0)
        {
            return Err(format!(
                "{at}: trajectory.max_duration_s must be in (0, 3600]"
            ));
        }
        if !(self.max_time_scale.is_finite() && (1.0..=100.0).contains(&self.max_time_scale)) {
            return Err(format!(
                "{at}: trajectory.max_time_scale must be in [1, 100]"
            ));
        }
        if codec != Codec::Ros2FollowJointTrajectoryGoal
            && self.request_header != RequestHeader::None
        {
            return Err(format!(
                "{at}: trajectory.request_header is for ros2_follow_joint_trajectory_goal only"
            ));
        }
        Ok(())
    }

    /// The decoder layout of `codec`.
    pub fn layout(&self, codec: Codec) -> crate::trajectory::Layout {
        use crate::trajectory::{GoalHeader, Layout};
        match (codec, self.request_header) {
            (Codec::Ros2FollowJointTrajectoryGoal, RequestHeader::Cyclone) => {
                Layout::Goal(GoalHeader::Cyclone)
            }
            (Codec::Ros2FollowJointTrajectoryGoal, RequestHeader::None) => {
                Layout::Goal(GoalHeader::None)
            }
            _ => Layout::Trajectory,
        }
    }
}

/// Default `max_weight_step` (per accepted frame).
pub const DEFAULT_MAX_WEIGHT_STEP: f64 = 0.02;
/// Default `max_weight_rate_per_s` (the SDK examples ramp at 0.2 /s,
/// `g1_arm7_sdk_dds_example.cpp:106`).
pub const DEFAULT_MAX_WEIGHT_RATE: f64 = 0.5;

/// The blend-weight dynamics of an arm-SDK / hand-SDK channel (defaults
/// applied).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WeightDynamics {
    pub max_step: f64,
    pub max_rate_per_s: f64,
    pub engage_max_q_error: f64,
    pub lowstate_max_age_ns: u64,
    pub engage_first_step: f64,
    pub engage_stable_frames: u32,
    pub engage_stable_q: f64,
}

impl ChannelConfig {
    pub fn topic(&self) -> Option<&str> {
        self.topic.as_deref().or(self.codec.default_topic()).or(
            match (self.codec, self.robot_model) {
                (Codec::UnitreeLocoRequest, Some(m)) => Some(m.topic()),
                _ => None,
            },
        )
    }

    /// The loco channel's duration cap (s).
    pub fn max_duration_s(&self) -> f64 {
        self.max_velocity_duration_s.unwrap_or(1.0)
    }

    /// The blend-weight dynamics (defaults applied).
    pub fn weight_dynamics(&self) -> WeightDynamics {
        WeightDynamics {
            max_step: self.max_weight_step.unwrap_or(DEFAULT_MAX_WEIGHT_STEP),
            max_rate_per_s: self
                .max_weight_rate_per_s
                .unwrap_or(DEFAULT_MAX_WEIGHT_RATE),
            engage_max_q_error: self.engage_max_q_error.unwrap_or(0.1),
            lowstate_max_age_ns: self.lowstate_max_age_ms.unwrap_or(50) * 1_000_000,
            engage_first_step: self.engage_first_step.unwrap_or(DEFAULT_MAX_WEIGHT_STEP),
            engage_stable_frames: self.engage_stable_frames.unwrap_or(50),
            engage_stable_q: self.engage_stable_q.unwrap_or(0.01),
        }
    }

    /// The arm-SDK channel's joint-state topic.
    pub fn lowstate_topic(&self) -> &str {
        self.lowstate_topic.as_deref().unwrap_or("rt/lowstate")
    }

    pub fn ports(&self) -> Vec<u16> {
        if self.udp_ports.is_empty() {
            self.codec.default_ports().to_vec()
        } else {
            self.udp_ports.clone()
        }
    }
}

/// The whole file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub mode: GatewayMode,
    /// The locked model profile (`robodr-commission lock` output).
    pub profile: PathBuf,
    /// Same keys as agentd's `sensor.profile_trust`. The gateway reads the
    /// anti-rollback `state_file` but never writes it (agentd owns it).
    #[serde(default)]
    pub profile_trust: ProfileTrustConfig,
    /// The Motion Firewall configuration (`robodr_firewall::FirewallConfig`).
    pub firewall: PathBuf,
    pub queue: QueueConfig,
    #[serde(default)]
    pub rtps: RtpsConfig,
    /// Robot-side observation (NFLOG copies; see [`ObserveConfig`]).
    #[serde(default)]
    pub observe: ObserveConfig,
    pub channels: Vec<ChannelConfig>,
    /// A datagram older than this when the gateway reads it (kernel queue
    /// timestamp) is not checked: the firewall's fault verdict applies
    /// (per `fault_policy`; a humanoid holds). Default 5 ms.
    #[serde(default = "default_max_queue_delay")]
    pub max_queue_delay_ns: u64,
    /// Overload reporting (`robot.gateway.overload`): late packets (above)
    /// are reported as one finding per this many ms at most. Default 60000
    /// (`1000..=3600000`).
    #[serde(default = "default_overload_interval")]
    pub overload_interval_ms: u64,
    /// Late packets in one overload interval from which the finding is
    /// High instead of Medium. Default 1000 (at least 1).
    #[serde(default = "default_overload_high_late")]
    pub overload_high_late: u64,
    /// Deviations (JSON lines). Default: none written (stats only).
    #[serde(default)]
    pub events_path: Option<PathBuf>,
    /// Most bytes written to `events_path` before it stops (and counts).
    #[serde(default = "default_events_max")]
    pub events_max_bytes: u64,
    /// Status / counters JSON, rewritten every housekeeping tick.
    #[serde(default)]
    pub status_path: Option<PathBuf>,
    /// Housekeeping period (drain events, status, watchdog), ms.
    #[serde(default = "default_housekeeping")]
    pub housekeeping_ms: u64,
    /// agentd's `gateway_feed` socket: the gateway's findings
    /// (`robot.gateway.*`) and the firewall's deviations go there as JSON
    /// lines (`crate::feed`). Default: none (events file only).
    #[serde(default)]
    pub findings_socket: Option<PathBuf>,
    /// The `restrict_motion` restriction file written by the executor's
    /// gateway adapter (`crate::restrict`), read every housekeeping tick.
    /// Default: none (no restriction can be applied).
    #[serde(default)]
    pub restriction_path: Option<PathBuf>,
    /// Go2 WebRTC sessions (`crate::webrtc`): detection from NFLOG copies,
    /// optional refusal of unlisted signalling, quarantine sets. Default:
    /// none.
    #[serde(default)]
    pub webrtc: Option<crate::webrtc::WebRtcConfig>,
    /// The robot behind the gateway (`robodr_cdr::unitree::UnitreeModel`
    /// name: `go2`, `a2`, `as2`, `g1`, ...). Optional; when set, the
    /// channels are cross-checked against it: an A2 / AS2 `rt/lowcmd` must
    /// use `unitree_a2_lowcmd` (not `unitree_go_lowcmd`) and no channel may
    /// `allow_battery_off`; `unitree_a2_lowcmd` is refused for any other
    /// model.
    #[serde(default)]
    pub robot_model: Option<String>,
    /// `sha256:<hex>` of the file this configuration was read from
    /// ([`GatewayConfig::load`]; not a key of the file). Recorded in the
    /// decision summaries (`crate::summary`).
    #[serde(skip)]
    pub source_sha256: Option<String>,
}

fn default_max_queue_delay() -> u64 {
    5_000_000
}
fn default_overload_interval() -> u64 {
    60_000
}
fn default_overload_high_late() -> u64 {
    1_000
}
fn default_events_max() -> u64 {
    64 << 20
}
fn default_housekeeping() -> u64 {
    100
}

/// DDS default port range of a domain (`PB = 7400`, `DG = 250`; every
/// participant id's metatraffic / user, unicast / multicast port).
pub fn domain_ports(domain: u16) -> Option<(u16, u16)> {
    let lo = 7400u32 + 250 * u32::from(domain);
    let hi = lo + 249;
    Some((u16::try_from(lo).ok()?, u16::try_from(hi).ok()?))
}

impl GatewayConfig {
    /// Parse the JSON text (structure only; [`crate::Gateway::new`]
    /// validates it against the firewall configuration and profile).
    pub fn from_json(text: &str) -> Result<Self, String> {
        let c: GatewayConfig = serde_json::from_str(text).map_err(|e| format!("config: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    /// Read and parse a file (size-capped).
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        use std::io::Read as _;
        let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut s = String::new();
        f.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut s)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if s.len() as u64 > MAX_CONFIG_BYTES {
            return Err(format!(
                "{}: larger than {MAX_CONFIG_BYTES} bytes",
                path.display()
            ));
        }
        let mut c = Self::from_json(&s)?;
        c.source_sha256 = Some(robodr_commission::trust::file_digest(s.as_bytes()));
        Ok(c)
    }

    /// Gateway review, finding 3: in enforce mode a Go2 (`robot_model`
    /// `go2` / `go2w`, or no `robot_model` and a sport channel: the model
    /// may be a Go2) must have a channel for every service that moves the
    /// body (`sport`, `obstacles_avoid`, `uwbswitch`), a B2 (`b2` / `b2w`)
    /// one for `sport`: a service without a channel is a motion path the
    /// gateway never decides.
    fn validate_motion_services(&self) -> Result<(), String> {
        use robodr_cdr::unitree::UnitreeModel as M;
        if self.mode != GatewayMode::Enforce {
            return Ok(());
        }
        let has = |c: Codec| self.channels.iter().any(|x| x.codec == c);
        let model = self.robot_model.as_deref().and_then(M::from_name);
        let go2 = matches!(model, Some(M::Go2 | M::Go2W))
            || (model.is_none() && has(Codec::UnitreeSportRequest));
        let b2 = matches!(model, Some(M::B2 | M::B2W));
        let mut need: Vec<Codec> = Vec::new();
        if go2 || b2 {
            need.push(Codec::UnitreeSportRequest);
        }
        if go2 {
            need.extend([
                Codec::UnitreeObstaclesAvoidRequest,
                Codec::UnitreeUwbSwitchRequest,
            ]);
        }
        let missing: Vec<&str> = need
            .into_iter()
            .filter(|c| !has(*c))
            .map(Codec::as_str)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "mode enforce on a {} needs a channel for every motion service; missing codec(s) \
                 {} (a service without a channel reaches the robot undecided; set robot_model \
                 if this is not a Go2)",
                if go2 { "Go2" } else { "B2" },
                missing.join(", ")
            ))
        }
    }

    /// Checks that need nothing but this file.
    pub fn validate(&self) -> Result<(), String> {
        if self.channels.is_empty() {
            return Err("channels: at least one channel is required".into());
        }
        self.profile_trust.validate()?;
        if let Some(name) = &self.robot_model {
            use robodr_cdr::unitree::UnitreeModel as M;
            let m = M::from_name(name)
                .ok_or_else(|| format!("robot_model {name:?} is not a Unitree model name"))?;
            let a2 = matches!(m, M::A2 | M::As2);
            for c in &self.channels {
                let at = &c.firewall_channel;
                let lowcmd = c.topic().is_some_and(|t| t == "rt/lowcmd");
                if a2
                    && lowcmd
                    && matches!(c.codec, Codec::UnitreeGoLowcmd | Codec::UnitreeGoArmSdk)
                {
                    return Err(format!(
                        "channel {at}: robot_model {name} must use codec unitree_a2_lowcmd on \
                         rt/lowcmd (its low-level type is inferred, not published)"
                    ));
                }
                if a2 && c.allow_battery_off {
                    return Err(format!(
                        "channel {at}: allow_battery_off is refused for robot_model {name}"
                    ));
                }
                if !a2 && c.codec == Codec::UnitreeA2Lowcmd {
                    return Err(format!(
                        "channel {at}: codec unitree_a2_lowcmd is for robot_model a2 / as2, not \
                         {name}"
                    ));
                }
            }
        }
        self.validate_motion_services()?;
        if let Some(w) = &self.webrtc {
            w.monitor_options()?;
            if !self.observe.enabled {
                return Err(
                    "webrtc needs observe.enabled (the robot side of a session comes from the \
                     observe copies)"
                        .into(),
                );
            }
            if w.nflog_group == self.observe.nflog_group {
                return Err("webrtc.nflog_group must differ from observe.nflog_group".into());
            }
            let legacy = self.legacy_ports();
            for p in &w.signalling_ports {
                if legacy.contains(p) {
                    return Err(format!("webrtc.signalling_ports: {p} is a legacy UDP port"));
                }
            }
        }
        for (what, p) in [("profile", &self.profile), ("firewall", &self.firewall)] {
            if !p.is_absolute() {
                return Err(format!("{what} must be an absolute path"));
            }
        }
        for p in [
            &self.events_path,
            &self.status_path,
            &self.rtps.state_file,
            &self.findings_socket,
            &self.restriction_path,
        ]
        .into_iter()
        .flatten()
        {
            if !p.is_absolute() {
                return Err(format!("{} must be an absolute path", p.display()));
            }
        }
        if self.queue.controller_port.is_empty()
            || self.queue.robot_port.is_empty()
            || self.queue.controller_port == self.queue.robot_port
        {
            return Err(
                "queue.controller_port and queue.robot_port must be two different interface names"
                    .into(),
            );
        }
        for n in [&self.queue.controller_port, &self.queue.robot_port] {
            if n.len() > 15
                || !n
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(format!("interface name {n:?} is not valid"));
            }
        }
        if self.queue.vlan_ids.len() > 16 {
            return Err("queue.vlan_ids: at most 16 VLAN ids".into());
        }
        let mut vids = std::collections::BTreeSet::new();
        for v in &self.queue.vlan_ids {
            if !(1..=4094).contains(v) || !vids.insert(*v) {
                return Err(format!(
                    "queue.vlan_ids: {v} is not a VLAN id (1..=4094) or is listed twice"
                ));
            }
        }
        if self.queue.max_len == 0 {
            return Err("queue.max_len must be >= 1".into());
        }
        if self.rtps.max_writers == 0 || self.rtps.max_writers_per_channel == 0 {
            return Err("rtps.max_writers and rtps.max_writers_per_channel must be >= 1".into());
        }
        if !(1..=65_536).contains(&self.rtps.max_enforced_writers) {
            return Err("rtps.max_enforced_writers must be 1..=65536".into());
        }
        let idle = self.rtps.enforced_idle_evict_s;
        if idle != 0 && !(60..=31_536_000).contains(&idle) {
            return Err("rtps.enforced_idle_evict_s must be 0 (never) or 60..=31536000".into());
        }
        if !(1..=1 << 20).contains(&self.rtps.max_sn_jump) {
            return Err("rtps.max_sn_jump must be in 1..=1048576".into());
        }
        if !(1_000_000..=60_000_000_000).contains(&self.rtps.binding_takeover_ns) {
            return Err("rtps.binding_takeover_ns must be in 1e6..=6e10 (1 ms ..= 60 s)".into());
        }
        let mut domains = self.rtps.domain_ids.clone();
        domains.sort_unstable();
        domains.dedup();
        for d in &domains {
            if domain_ports(*d).is_none() || *d > 232 {
                return Err(format!("rtps.domain_ids: {d} is out of range (0..=232)"));
            }
        }
        if self.rtps.extra_port_ranges.len() > 16 {
            return Err("rtps.extra_port_ranges: at most 16 ranges".into());
        }
        for [lo, hi] in &self.rtps.extra_port_ranges {
            if *lo == 0 || lo > hi {
                return Err(format!(
                    "rtps.extra_port_ranges: [{lo}, {hi}] is not a port range (1..=65535, lo <= hi)"
                ));
            }
        }
        if !(1..=10_000).contains(&self.housekeeping_ms) {
            return Err("housekeeping_ms must be in 1..=10000".into());
        }
        if self.max_queue_delay_ns == 0 || self.max_queue_delay_ns > 1_000_000_000 {
            return Err("max_queue_delay_ns must be in 1..=1e9".into());
        }
        if !(1_000..=3_600_000).contains(&self.overload_interval_ms) {
            return Err("overload_interval_ms must be in 1000..=3600000".into());
        }
        if self.overload_high_late == 0 {
            return Err("overload_high_late must be at least 1".into());
        }
        let mut topics = std::collections::BTreeSet::new();
        let mut ports = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for (i, c) in self.channels.iter().enumerate() {
            let at = format!("channels[{i}] ({})", c.firewall_channel);
            if !names.insert(c.firewall_channel.clone()) {
                return Err(format!("{at}: firewall_channel listed twice"));
            }
            for ip in &c.allowed_src_ips {
                ip.parse::<Ipv4Addr>().map_err(|_| {
                    format!("{at}: allowed_src_ips entry {ip:?} is not an IPv4 address")
                })?;
            }
            if c.codec.is_rtps() {
                let t = c.topic().unwrap_or("");
                if t.is_empty() {
                    return Err(format!("{at}: topic is empty"));
                }
                if !topics.insert(t.to_string()) {
                    return Err(format!("{at}: topic {t} is used by two channels"));
                }
                if !c.udp_ports.is_empty() || !c.legacy_sources.is_empty() {
                    return Err(format!(
                        "{at}: udp_ports / legacy_sources are for go1_* codecs only"
                    ));
                }
                if domains.is_empty() {
                    return Err(format!("{at}: an RTPS channel needs rtps.domain_ids"));
                }
            } else {
                if c.topic.is_some() {
                    return Err(format!("{at}: topic is for RTPS codecs only"));
                }
                for p in c.ports() {
                    if p == 0 || !ports.insert(p) {
                        return Err(format!("{at}: udp port {p} is invalid or used twice"));
                    }
                    for d in &domains {
                        if let Some((lo, hi)) = domain_ports(*d) {
                            if (lo..=hi).contains(&p) {
                                return Err(format!(
                                    "{at}: udp port {p} is inside the DDS port range of domain {d}"
                                ));
                            }
                        }
                    }
                    for [lo, hi] in &self.rtps.extra_port_ranges {
                        if (*lo..=*hi).contains(&p) {
                            return Err(format!(
                                "{at}: udp port {p} is inside rtps.extra_port_ranges [{lo}, {hi}]"
                            ));
                        }
                    }
                }
                for ip in c.legacy_sources.keys() {
                    ip.parse::<Ipv4Addr>().map_err(|_| {
                        format!("{at}: legacy_sources key {ip:?} is not an IPv4 address")
                    })?;
                }
            }
            // Gateway review, finding 6: a missing allowlist used to mean
            // "every call / mode" (tricks, flips, attitude, trajectory
            // following, unknown ids, Go1 mode 1 poses).
            if matches!(
                c.codec,
                Codec::UnitreeSportRequest
                    | Codec::UnitreeObstaclesAvoidRequest
                    | Codec::UnitreeUwbSwitchRequest
            ) && c.allowed_api_ids.is_none()
            {
                return Err(format!(
                    "{at}: codec {} needs allowed_api_ids (the non-velocity calls forwarded; [] \
                     for none: velocity, stop and queries only)",
                    c.codec.as_str()
                ));
            }
            if c.codec == Codec::Go1HighCmd && c.allowed_high_modes.is_none() {
                return Err(format!(
                    "{at}: codec go1_high_cmd needs allowed_high_modes (the modes forwarded \
                     besides 2, velocity; [0] for idle only)"
                ));
            }
            if c.allowed_api_ids.is_some() && !c.codec.is_api_request() {
                return Err(format!(
                    "{at}: allowed_api_ids is for the unitree_*_request codecs only"
                ));
            }
            let loco = c.codec == Codec::UnitreeLocoRequest;
            let needs_model = loco || c.codec == Codec::UnitreeArmRequest;
            if needs_model != c.robot_model.is_some() {
                return Err(format!(
                    "{at}: robot_model is required for unitree_loco_request and \
                     unitree_arm_request, and only for them"
                ));
            }
            if c.codec == Codec::UnitreeArmRequest
                && !matches!(c.robot_model, Some(LocoModel::G1 | LocoModel::H2))
            {
                return Err(format!(
                    "{at}: the arm action service exists on robot_model g1 and h2 only"
                ));
            }
            if !loco && (c.allowed_fsm_ids.is_some() || c.max_velocity_duration_s.is_some()) {
                return Err(format!(
                    "{at}: allowed_fsm_ids / max_velocity_duration_s are for unitree_loco_request only"
                ));
            }
            if let Some(d) = c.max_velocity_duration_s {
                if !(d.is_finite() && d > 0.0 && d <= 60.0) {
                    return Err(format!("{at}: max_velocity_duration_s must be in (0, 60]"));
                }
            }
            let arm = c.codec.is_arm_sdk();
            if arm != c.weight_slot.is_some() {
                return Err(format!(
                    "{at}: weight_slot is required for the arm-SDK codecs, and only for them"
                ));
            }
            if let (Some(w), Some(n)) = (c.weight_slot, c.codec.slots()) {
                if w >= n {
                    return Err(format!("{at}: weight_slot {w} is not a slot (0..{n})"));
                }
            }
            if !arm && c.max_weight.is_some() {
                return Err(format!("{at}: max_weight is for the arm-SDK codecs only"));
            }
            if let Some(w) = c.max_weight {
                if !(w.is_finite() && (0.0..=1.0).contains(&w)) {
                    return Err(format!("{at}: max_weight must be in [0, 1]"));
                }
            }
            let weighted = arm || c.codec == Codec::UnitreeHandSdk;
            if !weighted && (c.max_weight_step.is_some() || c.max_weight_rate_per_s.is_some()) {
                return Err(format!(
                    "{at}: max_weight_step / max_weight_rate_per_s are for the arm-SDK and \
                     hand-SDK codecs only"
                ));
            }
            if !arm
                && (c.engage_max_q_error.is_some()
                    || c.lowstate_max_age_ms.is_some()
                    || c.lowstate_topic.is_some()
                    || c.engage_first_step.is_some()
                    || c.engage_stable_frames.is_some()
                    || c.engage_stable_q.is_some())
            {
                return Err(format!(
                    "{at}: engage_* / lowstate_* are for the arm-SDK codecs only"
                ));
            }
            let unit = |v: Option<f64>| v.is_none_or(|x| x.is_finite() && x > 0.0 && x <= 1.0);
            for (k, v) in [
                ("max_weight_step", c.max_weight_step),
                ("engage_max_q_error", c.engage_max_q_error),
                ("engage_first_step", c.engage_first_step),
                ("engage_stable_q", c.engage_stable_q),
            ] {
                if !unit(v) {
                    return Err(format!("{at}: {k} must be in (0, 1]"));
                }
            }
            if c.max_weight_rate_per_s
                .is_some_and(|r| !(r.is_finite() && r > 0.0 && r <= 1000.0))
            {
                return Err(format!("{at}: max_weight_rate_per_s must be in (0, 1000]"));
            }
            if c.lowstate_max_age_ms
                .is_some_and(|m| !(1..=1000).contains(&m))
            {
                return Err(format!("{at}: lowstate_max_age_ms must be in 1..=1000"));
            }
            if c.engage_stable_frames
                .is_some_and(|n| !(1..=100_000).contains(&n))
            {
                return Err(format!("{at}: engage_stable_frames must be in 1..=100000"));
            }
            if c.lowstate_topic.as_deref().is_some_and(str::is_empty) {
                return Err(format!("{at}: lowstate_topic is empty"));
            }
            if c.note
                .as_deref()
                .is_some_and(|n| n.chars().count() > 500 || n.chars().any(char::is_control))
            {
                return Err(format!(
                    "{at}: note: at most 500 characters, no control characters"
                ));
            }
            for m in &c.allowed_src_macs {
                if crate::gateway::parse_mac(m).is_none() {
                    return Err(format!(
                        "{at}: allowed_src_macs entry {m:?} is not a MAC address (aa:bb:cc:dd:ee:ff)"
                    ));
                }
            }
            if !c.allowed_src_macs.is_empty() && !c.codec.is_rtps() {
                return Err(format!("{at}: allowed_src_macs is for RTPS codecs only"));
            }
            if c.allow_battery_off
                && !matches!(c.codec, Codec::UnitreeGoLowcmd | Codec::UnitreeGoArmSdk)
            {
                return Err(format!(
                    "{at}: allow_battery_off is for unitree_go_lowcmd only"
                ));
            }
            if c.allowed_high_modes.is_some() && c.codec != Codec::Go1HighCmd {
                return Err(format!("{at}: allowed_high_modes is for go1_high_cmd only"));
            }
            match (&c.trajectory, c.codec.is_trajectory()) {
                (Some(t), true) => t.validate(&at, c.codec)?,
                (None, false) => {}
                _ => {
                    return Err(format!(
                        "{at}: trajectory is required for the ros2_joint_trajectory / \
                         ros2_follow_joint_trajectory_goal codecs, and only for them"
                    ))
                }
            }
        }
        Ok(())
    }

    /// The queued DDS port ranges: the well-known range of every domain,
    /// then `rtps.extra_port_ranges`.
    pub fn rtps_port_ranges(&self) -> Vec<(u16, u16)> {
        if !self.channels.iter().any(|c| c.codec.is_rtps()) {
            return Vec::new();
        }
        let mut d = self.rtps.domain_ids.clone();
        d.sort_unstable();
        d.dedup();
        let mut v: Vec<(u16, u16)> = d.into_iter().filter_map(domain_ports).collect();
        v.extend(
            self.rtps
                .extra_port_ranges
                .iter()
                .map(|[lo, hi]| (*lo, *hi)),
        );
        v
    }

    /// Every legacy UDP port.
    pub fn legacy_ports(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self
            .channels
            .iter()
            .filter(|c| !c.codec.is_rtps())
            .flat_map(|c| c.ports())
            .collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> serde_json::Value {
        serde_json::json!({
            "mode": "enforce",
            "profile": "/etc/robodr/profile.json",
            "firewall": "/etc/robodr/firewall.json",
            "queue": {"num": 3, "controller_port": "eth0", "robot_port": "eth1"},
            "channels": [{"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd"}]
        })
    }

    #[test]
    fn parses_with_defaults() {
        let c = GatewayConfig::from_json(&base().to_string()).unwrap();
        assert_eq!(c.queue.on_gateway_down, OnGatewayDown::FailClosed);
        assert_eq!(c.rtps.domain_ids, vec![0]);
        assert_eq!(c.channels[0].topic(), Some("rt/lowcmd"));
        assert_eq!(c.rtps_port_ranges(), vec![(7400, 7649)]);
        assert_eq!(c.max_queue_delay_ns, 5_000_000);
        assert_eq!(c.rtps.max_sn_jump, 64);
        assert_eq!(c.rtps.binding_takeover_ns, 1_000_000_000);
        assert!(c.rtps.extra_port_ranges.is_empty());
        let mut v = base();
        v["rtps"] = serde_json::json!({"extra_port_ranges": [[30000, 32767]]});
        v["channels"] = serde_json::json!([
            {"firewall_channel": "/loco", "codec": "unitree_loco_request", "robot_model": "h1"},
            {"firewall_channel": "/arm", "codec": "unitree_hg_arm_sdk", "weight_slot": 29},
            {"firewall_channel": "/cmd_vel", "codec": "ros2_twist"},
            {"firewall_channel": "/hand", "codec": "unitree_dex3_hand_cmd", "topic": "rt/dex3/left/cmd"}
        ]);
        let c2 = GatewayConfig::from_json(&v.to_string()).unwrap();
        assert_eq!(c2.rtps_port_ranges(), vec![(7400, 7649), (30000, 32767)]);
        assert_eq!(c2.channels[0].topic(), Some("rt/api/loco/request"));
        assert_eq!(c2.channels[0].max_duration_s(), 1.0);
        assert_eq!(c2.channels[1].topic(), Some("rt/arm_sdk"));
        assert_eq!(c2.channels[2].topic(), Some("rt/cmd_vel"));
        assert!(!c.channels[0].allow_battery_off && c.channels[0].allowed_src_macs.is_empty());
        let mut v = base();
        v["channels"][0]["allowed_src_macs"] =
            serde_json::json!(["02:00:00:00:00:64", "AA-BB-CC-DD-EE-FF"]);
        assert!(GatewayConfig::from_json(&v.to_string()).is_ok());
        assert_eq!(
            crate::gateway::parse_mac("AA-bb-CC-dd-EE-ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aaa:bb:cc:dd:ee:f",
            "zz:bb:cc:dd:ee:ff",
        ] {
            assert_eq!(crate::gateway::parse_mac(bad), None, "{bad}");
        }
    }

    #[test]
    fn refuses_bad_configs() {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("unknown key", serde_json::json!({"bogus": 1})),
            (
                "relative path",
                serde_json::json!({"profile": "profile.json"}),
            ),
            (
                "same ports",
                serde_json::json!({"queue": {"num": 1, "controller_port": "eth0", "robot_port": "eth0"}}),
            ),
            ("no channels", serde_json::json!({"channels": []})),
            (
                "bad ip",
                serde_json::json!({"channels": [{"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd", "allowed_src_ips": ["x"]}]}),
            ),
            (
                "dup topic",
                serde_json::json!({"channels": [
                {"firewall_channel": "/a", "codec": "unitree_hg_lowcmd"},
                {"firewall_channel": "/b", "codec": "unitree_go_lowcmd"}]}),
            ),
            (
                "legacy port in dds range",
                serde_json::json!({"channels": [
                {"firewall_channel": "/h", "codec": "go1_high_cmd", "udp_ports": [7410]}]}),
            ),
            (
                "api ids on lowcmd",
                serde_json::json!({"channels": [
                {"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd", "allowed_api_ids": [1008]}]}),
            ),
            (
                "bad domain",
                serde_json::json!({"rtps": {"domain_ids": [300]}}),
            ),
            ("sn jump 0", serde_json::json!({"rtps": {"max_sn_jump": 0}})),
            (
                "takeover too short",
                serde_json::json!({"rtps": {"binding_takeover_ns": 1000}}),
            ),
            (
                "bad mac",
                serde_json::json!({"channels": [{"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd", "allowed_src_macs": ["02:00:00:00:00"]}]}),
            ),
            (
                "mac on legacy",
                serde_json::json!({"channels": [{"firewall_channel": "/h", "codec": "go1_high_cmd", "allowed_src_macs": ["02:00:00:00:00:01"]}]}),
            ),
            (
                "battery off on hg",
                serde_json::json!({"channels": [{"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd", "allow_battery_off": true}]}),
            ),
            (
                "loco without model",
                serde_json::json!({"channels": [{"firewall_channel": "/loco", "codec": "unitree_loco_request"}]}),
            ),
            (
                "model on lowcmd",
                serde_json::json!({"channels": [{"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd", "robot_model": "g1"}]}),
            ),
            (
                "duration too long",
                serde_json::json!({"channels": [{"firewall_channel": "/loco", "codec": "unitree_loco_request", "robot_model": "g1", "max_velocity_duration_s": 100.0}]}),
            ),
            (
                "arm without weight slot",
                serde_json::json!({"channels": [{"firewall_channel": "/arm", "codec": "unitree_hg_arm_sdk"}]}),
            ),
            (
                "weight slot out of range",
                serde_json::json!({"channels": [{"firewall_channel": "/arm", "codec": "unitree_hg_arm_sdk", "weight_slot": 35}]}),
            ),
            (
                "max weight > 1",
                serde_json::json!({"channels": [{"firewall_channel": "/arm", "codec": "unitree_hg_arm_sdk", "weight_slot": 29, "max_weight": 1.5}]}),
            ),
            (
                "dex3 without topic",
                serde_json::json!({"channels": [{"firewall_channel": "/hand", "codec": "unitree_dex3_hand_cmd"}]}),
            ),
            (
                "bad extra range",
                serde_json::json!({"rtps": {"extra_port_ranges": [[9000, 8000]]}}),
            ),
            (
                "legacy port in extra range",
                serde_json::json!({"rtps": {"extra_port_ranges": [[8000, 8100]]}, "channels": [
                {"firewall_channel": "/h", "codec": "go1_high_cmd"}]}),
            ),
            (
                "bad ifname",
                serde_json::json!({"queue": {"num": 1, "controller_port": "e;rm", "robot_port": "eth1"}}),
            ),
        ];
        for (what, patch) in cases {
            let mut v = base();
            for (k, val) in patch.as_object().unwrap() {
                v[k] = val.clone();
            }
            assert!(GatewayConfig::from_json(&v.to_string()).is_err(), "{what}");
        }
    }
}
