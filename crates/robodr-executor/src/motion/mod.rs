//! Motion actions (Sprint 8): `restrict_motion`, `safe_pause`,
//! `request_safe_state` and `rollback_config` through **platform
//! adapters**, each of which refuses to run unless the site set its
//! `oem_validated: true` in `executor.json` (`motion.<adapter>`), on top of
//! every rule of [`crate::decision::precheck`] (policy OEM-validated,
//! profile locked, morphology, safety state).
//!
//! | Action | Adapters | Apply | Revert |
//! |---|---|---|---|
//! | `restrict_motion` | `gateway` | restriction file for `robodr-firewall-gw` (caps / factor, expiry = TTL), read back from the gateway's status | file removed, read back; the gateway also lifts it at its expiry on its own |
//! | | `unitree_sport` | sport `SpeedLevel(level)` request (`rt/api/sport/request`), reply code 0 | `SpeedLevel(0)` (the SDK default: not necessarily the level before) |
//! | `safe_pause` | `nav2` | `CancelGoal` (zero id: every goal) on each action server, then a burst of zero `Twist` on `cmd_vel` | **nothing to undo**: goals are not restored, the operator re-issues the mission (documented) |
//! | | `ros2_control` | `SwitchController` STRICT: deactivate the motion controllers, activate the hold controllers | the inverse switch |
//! | | `px4` | MAVLink `DO_SET_MODE` AUTO.LOITER (hold), ack + heartbeat read back | **no mode change**: the vehicle stays in hold until its operator switches (a mission is never resumed by the executor) |
//! | `request_safe_state` | `px4` (hold / RTL per the policy's `safe_state`), `nav2`, `ros2_control` | as above | not reversible (an operator restores the robot) |
//! | `rollback_config` | `rollback` (`config: program` only) | the site's OEM-validated rollback program, `--verify` afterwards | not reversible |
//!
//! The decision ([`plan`]) adds, after the common rules: a two-person
//! approval for `safe_pause`, `request_safe_state` and `rollback_config`
//! (the SOC-signed body names at least two approvers, distinct, none the
//! requester: `approval_missing`; the on-robot planner can never order
//! them), the adapter configured (`no_adapter`) and validated
//! (`adapter_not_validated`), the safety state one the adapter allows
//! (`safety_state_not_allowed`; `rollback_config` only `idle`:
//! `requires_idle`), the policy's safe behaviour one the adapter can
//! carry out (`behaviour_unsupported`), the restriction's parameters
//! (`invalid_order`, `fall_hazard` below `min_motion_factor` on a robot
//! that balances). The engine re-checks the adapter's allowed states with
//! the safety state **at the moment of apply**.
//!
//! The protocols are implemented here ([`rtps`] + [`cdr`]: ROS 2 topics,
//! services and the Unitree SDK request / response over RTPS; [`mavlink`]:
//! MAVLink 2) and tested against in-process simulated peers
//! (`tests/motion.rs`); see the README for what was verified only that way.

pub mod adapters;
pub mod cdr;
pub mod mavlink;
pub mod rtps;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use robodr_responder::{ActionId, Morphology, ResponsePolicy, SafeBehaviour, SafetyState};
use serde::{Deserialize, Serialize};

use crate::decision::{codes, Refusal};
use crate::order::{Order, Origin};

/// A platform adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Gateway,
    UnitreeSport,
    Nav2,
    Ros2Control,
    Px4,
    Rollback,
}

impl AdapterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AdapterKind::Gateway => "gateway",
            AdapterKind::UnitreeSport => "unitree_sport",
            AdapterKind::Nav2 => "nav2",
            AdapterKind::Ros2Control => "ros2_control",
            AdapterKind::Px4 => "px4",
            AdapterKind::Rollback => "rollback",
        }
    }
}

/// The RMW whose service conventions the ROS 2 adapters follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rmw {
    /// `rmw_cyclonedds_cpp` (request header in the payload). The only one
    /// implemented: `rmw_fastrtps` carries it in the inline QoS.
    #[default]
    Cyclonedds,
}

fn default_timeout_ms() -> u64 {
    2000
}
fn default_resend_ms() -> u64 {
    200
}

/// The robot's ROS 2 participant the ROS 2 adapters talk to.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ros2Peer {
    #[serde(default)]
    pub domain_id: u32,
    pub peer_ip: Ipv4Addr,
    /// Its participant index (well-known unicast ports), default 0.
    #[serde(default)]
    pub peer_participant_id: u32,
    /// Explicit ports (when the DDS stack does not use the well-known
    /// ones).
    #[serde(default)]
    pub peer_meta_port: Option<u16>,
    #[serde(default)]
    pub peer_user_port: Option<u16>,
    /// This host's address on that network.
    pub local_ip: Ipv4Addr,
    #[serde(default)]
    pub rmw: Rmw,
    /// Deadline of one call (ms, 100..=30000).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Re-send interval while waiting (ms, 20..=timeout).
    #[serde(default = "default_resend_ms")]
    pub resend_ms: u64,
}

impl Ros2Peer {
    pub fn peer(&self) -> Result<rtps::Peer, String> {
        let (m, u) = rtps::unicast_ports(self.domain_id, self.peer_participant_id)
            .ok_or("domain_id / peer_participant_id out of range")?;
        Ok(rtps::Peer {
            ip: self.peer_ip,
            meta_port: self.peer_meta_port.unwrap_or(m),
            user_port: self.peer_user_port.unwrap_or(u),
            local_ip: self.local_ip,
            domain_id: self.domain_id,
        })
    }

    fn validate(&self, at: &str) -> Result<(), String> {
        if self.domain_id > 232 {
            return Err(format!("{at}.ros2.domain_id must be 0..=232"));
        }
        self.peer().map_err(|e| format!("{at}.ros2: {e}"))?;
        if !(100..=30_000).contains(&self.timeout_ms)
            || self.resend_ms < 20
            || self.resend_ms > self.timeout_ms
        {
            return Err(format!(
                "{at}.ros2: timeout_ms must be 100..=30000 and resend_ms 20..=timeout_ms"
            ));
        }
        if self.peer_ip.is_unspecified()
            || self.peer_ip.is_multicast()
            || self.local_ip.is_multicast()
        {
            return Err(format!("{at}.ros2: peer_ip / local_ip must be unicast"));
        }
        Ok(())
    }
}

fn default_verify_ms() -> u64 {
    3000
}

/// `motion.gateway`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayAdapter {
    #[serde(default)]
    pub oem_validated: bool,
    /// The gateway's `restriction_path` (the executor writes it).
    pub restriction_path: PathBuf,
    /// The gateway's `status_path` (the executor reads it back).
    pub status_path: PathBuf,
    #[serde(default = "default_verify_ms")]
    pub verify_timeout_ms: u64,
    #[serde(default)]
    pub allowed_states: Option<Vec<SafetyState>>,
}

fn default_sport_request() -> String {
    "rt/api/sport/request".into()
}
fn default_sport_response() -> String {
    "rt/api/sport/response".into()
}
fn default_speed_level() -> i32 {
    -1
}

/// `motion.unitree_sport`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitreeAdapter {
    #[serde(default)]
    pub oem_validated: bool,
    pub ros2: Ros2Peer,
    #[serde(default = "default_sport_request")]
    pub request_topic: String,
    #[serde(default = "default_sport_response")]
    pub response_topic: String,
    /// `SpeedLevel` while restricted (`-1` slow, the default; `0` normal).
    #[serde(default = "default_speed_level")]
    pub speed_level: i32,
    #[serde(default)]
    pub allowed_states: Option<Vec<SafetyState>>,
}

fn default_actions() -> Vec<String> {
    vec!["/navigate_to_pose".into(), "/navigate_through_poses".into()]
}
fn default_cmd_vel() -> String {
    "/cmd_vel".into()
}
fn default_zero_twists() -> u32 {
    10
}
fn default_twist_interval_ms() -> u64 {
    50
}

/// `motion.nav2`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nav2Adapter {
    #[serde(default)]
    pub oem_validated: bool,
    pub ros2: Ros2Peer,
    /// Action servers whose goals are cancelled (`/navigate_to_pose` ...).
    #[serde(default = "default_actions")]
    pub actions: Vec<String>,
    #[serde(default = "default_cmd_vel")]
    pub cmd_vel_topic: String,
    /// Zero twists published after the cancel (1..=100).
    #[serde(default = "default_zero_twists")]
    pub zero_twists: u32,
    #[serde(default = "default_twist_interval_ms")]
    pub zero_twist_interval_ms: u64,
    #[serde(default)]
    pub allowed_states: Option<Vec<SafetyState>>,
}

fn default_cm() -> String {
    "/controller_manager".into()
}
fn default_distro() -> cdr::Distro {
    cdr::Distro::Jazzy
}
fn default_switch_timeout() -> i32 {
    5
}

/// `motion.ros2_control`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ros2ControlAdapter {
    #[serde(default)]
    pub oem_validated: bool,
    pub ros2: Ros2Peer,
    #[serde(default = "default_cm")]
    pub controller_manager: String,
    #[serde(default = "default_distro")]
    pub distro: cdr::Distro,
    /// Controllers deactivated by the pause (the motion controllers).
    pub deactivate: Vec<String>,
    /// Controllers activated by the pause (a hold controller), may be
    /// empty.
    #[serde(default)]
    pub activate: Vec<String>,
    #[serde(default = "default_switch_timeout")]
    pub switch_timeout_s: i32,
    #[serde(default)]
    pub allowed_states: Option<Vec<SafetyState>>,
}

fn default_px4_target() -> u8 {
    1
}
fn default_gcs_sysid() -> u8 {
    250
}
fn default_gcs_compid() -> u8 {
    190
}
fn default_px4_timeout() -> u64 {
    3000
}

/// `motion.px4`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Px4Adapter {
    #[serde(default)]
    pub oem_validated: bool,
    /// The autopilot's MAVLink UDP endpoint.
    pub address: SocketAddrV4,
    /// Local address to bind (port 0: any).
    pub bind: SocketAddrV4,
    #[serde(default = "default_px4_target")]
    pub target_system: u8,
    #[serde(default = "default_px4_target")]
    pub target_component: u8,
    /// The executor's own MAVLink system / component id.
    #[serde(default = "default_gcs_sysid")]
    pub system_id: u8,
    #[serde(default = "default_gcs_compid")]
    pub component_id: u8,
    #[serde(default = "default_px4_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub allowed_states: Option<Vec<SafetyState>>,
}

fn default_rollback_timeout() -> u64 {
    120
}

/// `motion.rollback`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackAdapter {
    #[serde(default)]
    pub oem_validated: bool,
    /// The site's rollback program (absolute; run without a shell as
    /// `program --config program --to-version <v> --request-id <id>`, then
    /// `program --verify --config program --to-version <v>`; exit 0 =
    /// done).
    pub program: PathBuf,
    #[serde(default = "default_rollback_timeout")]
    pub timeout_s: u64,
}

fn default_pause_ttl() -> u64 {
    3600
}

/// `motion` in executor.json (absent: no motion action is executed; each
/// is refused `no_adapter`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MotionSection {
    /// Adapters that carry `restrict_motion`, applied in this order (at
    /// most 2: `gateway`, `unitree_sport`).
    #[serde(default)]
    pub restrict_motion: Vec<AdapterKind>,
    #[serde(default)]
    pub safe_pause: Option<AdapterKind>,
    #[serde(default)]
    pub request_safe_state: Option<AdapterKind>,
    #[serde(default)]
    pub rollback_config: Option<AdapterKind>,
    /// How long a `safe_pause` stays in force before the executor releases
    /// it (s; the contract gives it no TTL).
    #[serde(default = "default_pause_ttl")]
    pub safe_pause_ttl_s: u64,
    #[serde(default)]
    pub gateway: Option<GatewayAdapter>,
    #[serde(default)]
    pub unitree_sport: Option<UnitreeAdapter>,
    #[serde(default)]
    pub nav2: Option<Nav2Adapter>,
    #[serde(default)]
    pub ros2_control: Option<Ros2ControlAdapter>,
    #[serde(default)]
    pub px4: Option<Px4Adapter>,
    #[serde(default)]
    pub rollback: Option<RollbackAdapter>,
}

impl Default for MotionSection {
    fn default() -> Self {
        Self {
            restrict_motion: Vec::new(),
            safe_pause: None,
            request_safe_state: None,
            rollback_config: None,
            safe_pause_ttl_s: default_pause_ttl(),
            gateway: None,
            unitree_sport: None,
            nav2: None,
            ros2_control: None,
            px4: None,
            rollback: None,
        }
    }
}

fn topic_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_~".contains(&b))
}

impl MotionSection {
    /// The adapter's `oem_validated` and allowed states (`None`: not
    /// configured).
    pub fn adapter(&self, k: AdapterKind) -> Option<(bool, Option<&[SafetyState]>)> {
        match k {
            AdapterKind::Gateway => self
                .gateway
                .as_ref()
                .map(|a| (a.oem_validated, a.allowed_states.as_deref())),
            AdapterKind::UnitreeSport => self
                .unitree_sport
                .as_ref()
                .map(|a| (a.oem_validated, a.allowed_states.as_deref())),
            AdapterKind::Nav2 => self
                .nav2
                .as_ref()
                .map(|a| (a.oem_validated, a.allowed_states.as_deref())),
            AdapterKind::Ros2Control => self
                .ros2_control
                .as_ref()
                .map(|a| (a.oem_validated, a.allowed_states.as_deref())),
            AdapterKind::Px4 => self
                .px4
                .as_ref()
                .map(|a| (a.oem_validated, a.allowed_states.as_deref())),
            AdapterKind::Rollback => self.rollback.as_ref().map(|a| (a.oem_validated, None)),
        }
    }

    pub fn validate(&self, max_ttl_s: u64) -> Result<(), String> {
        if self.restrict_motion.len() > 2
            || self
                .restrict_motion
                .iter()
                .any(|k| !matches!(k, AdapterKind::Gateway | AdapterKind::UnitreeSport))
            || (self.restrict_motion.len() == 2
                && self.restrict_motion[0] == self.restrict_motion[1])
        {
            return Err(
                "motion.restrict_motion: at most gateway and unitree_sport, once each".into(),
            );
        }
        for (what, k) in [
            ("safe_pause", self.safe_pause),
            ("request_safe_state", self.request_safe_state),
        ] {
            if k.is_some_and(|k| {
                !matches!(
                    k,
                    AdapterKind::Nav2 | AdapterKind::Ros2Control | AdapterKind::Px4
                )
            }) {
                return Err(format!("motion.{what}: nav2, ros2_control or px4"));
            }
        }
        if self
            .rollback_config
            .is_some_and(|k| k != AdapterKind::Rollback)
        {
            return Err("motion.rollback_config: rollback".into());
        }
        let used = self
            .restrict_motion
            .iter()
            .copied()
            .chain(self.safe_pause)
            .chain(self.request_safe_state)
            .chain(self.rollback_config);
        for k in used {
            if self.adapter(k).is_none() {
                return Err(format!("motion.{} is named but not configured", k.as_str()));
            }
        }
        if self.safe_pause_ttl_s == 0 || self.safe_pause_ttl_s > max_ttl_s {
            return Err("motion.safe_pause_ttl_s must be 1..=ttl.max_s".into());
        }
        if let Some(g) = &self.gateway {
            if !g.restriction_path.is_absolute() || !g.status_path.is_absolute() {
                return Err(
                    "motion.gateway: restriction_path and status_path must be absolute".into(),
                );
            }
            if !(100..=60_000).contains(&g.verify_timeout_ms) {
                return Err("motion.gateway.verify_timeout_ms must be 100..=60000".into());
            }
        }
        if let Some(u) = &self.unitree_sport {
            u.ros2.validate("motion.unitree_sport")?;
            if !(-1..=1).contains(&u.speed_level)
                || !topic_ok(&u.request_topic)
                || !topic_ok(&u.response_topic)
            {
                return Err("motion.unitree_sport: speed_level -1..=1, topics valid".into());
            }
        }
        if let Some(n) = &self.nav2 {
            n.ros2.validate("motion.nav2")?;
            if n.actions.is_empty()
                || n.actions.len() > 8
                || !n.actions.iter().all(|a| topic_ok(a) && a.starts_with('/'))
                || !topic_ok(&n.cmd_vel_topic)
                || !(1..=100).contains(&n.zero_twists)
                || !(10..=1000).contains(&n.zero_twist_interval_ms)
            {
                return Err(
                    "motion.nav2: 1..=8 absolute action names, a cmd_vel topic, zero_twists \
                            1..=100, zero_twist_interval_ms 10..=1000"
                        .into(),
                );
            }
        }
        if let Some(c) = &self.ros2_control {
            c.ros2.validate("motion.ros2_control")?;
            let name_ok = |s: &String| {
                !s.is_empty()
                    && s.len() <= 128
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            };
            if c.deactivate.is_empty()
                || c.deactivate.len() + c.activate.len() > 16
                || !c.deactivate.iter().chain(&c.activate).all(name_ok)
                || c.deactivate.iter().any(|d| c.activate.contains(d))
                || !topic_ok(&c.controller_manager)
                || !(1..=60).contains(&c.switch_timeout_s)
            {
                return Err(
                    "motion.ros2_control: deactivate 1.., names [A-Za-z0-9_], none in both \
                            lists, switch_timeout_s 1..=60"
                        .into(),
                );
            }
        }
        if let Some(p) = &self.px4 {
            if p.address.ip().is_unspecified()
                || p.address.port() == 0
                || !(100..=30_000).contains(&p.timeout_ms)
            {
                return Err("motion.px4: address with a port, timeout_ms 100..=30000".into());
            }
            if p.system_id == p.target_system {
                return Err("motion.px4: system_id must differ from target_system".into());
            }
        }
        if let Some(r) = &self.rollback {
            if !r.program.is_absolute() || !(1..=3600).contains(&r.timeout_s) {
                return Err("motion.rollback: program absolute, timeout_s 1..=3600".into());
            }
        }
        Ok(())
    }
}

/// The parameters of a motion order (the control plane's, or the planner's
/// `limit_motion` factor).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MotionRequest {
    /// Planner `limit_motion`: the envelope scale, `(0, 1]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factor: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_linear_speed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_joint_speed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_zone: Option<String>,
    /// `rollback_config`: `profile` or `program`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_version: Option<String>,
}

// `Target` (which carries it) is `Eq`: the numbers are finite (validated
// by `Order::validate` before anything compares them), so `==` is total.
impl Eq for MotionRequest {}

/// What an accepted motion order does (the journal keeps it).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MotionSpec {
    pub action: ActionId,
    pub adapters: Vec<AdapterKind>,
    #[serde(default)]
    pub request: MotionRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behaviour: Option<SafeBehaviour>,
    /// An undo exists (`restrict_motion`, `safe_pause`).
    pub reversible: bool,
    /// The order id (the gateway restriction id; Unitree request ids
    /// derive from it).
    pub id: String,
    /// Wall-clock end of the action (the gateway restriction's expiry);
    /// set when it is applied.
    #[serde(default)]
    pub deadline_ms: u64,
}

impl MotionSpec {
    /// The safety states the adapters allow (the intersection).
    pub fn allowed(&self, m: &MotionSection, s: SafetyState) -> bool {
        self.adapters
            .iter()
            .all(|k| allowed_in(self.action, m.adapter(*k).and_then(|a| a.1), s))
    }
}

/// Default allowed states: a restriction in any state the safety system
/// does not own; a pause or safe state not while moving fast (an abrupt
/// stop at speed is itself a hazard: an OEM may list `moving_fast`); a
/// rollback only `idle`.
fn allowed_in(action: ActionId, listed: Option<&[SafetyState]>, s: SafetyState) -> bool {
    if s.safety_system_engaged() || s == SafetyState::Unknown {
        return false;
    }
    if action == ActionId::RollbackConfig {
        return s == SafetyState::Idle;
    }
    match listed {
        Some(l) => l.contains(&s),
        None => match action {
            ActionId::RestrictMotion => true,
            _ => matches!(
                s,
                SafetyState::Idle | SafetyState::MovingSlow | SafetyState::CollaborativeHumanNearby
            ),
        },
    }
}

/// The behaviours an adapter can carry out.
fn behaviour_ok(k: AdapterKind, action: ActionId, b: SafeBehaviour) -> bool {
    use SafeBehaviour as B;
    match k {
        AdapterKind::Nav2 => matches!(b, B::ControlledStop | B::PlatformDefined),
        AdapterKind::Ros2Control => matches!(b, B::ProtectiveStopCategory2 | B::PlatformDefined),
        AdapterKind::Px4 => {
            matches!(b, B::Hold | B::PlatformDefined)
                || (action == ActionId::RequestSafeState && b == B::ReturnToLaunch)
        }
        _ => false,
    }
}

/// The JSON name of a safety state.
pub fn state_name(s: SafetyState) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn refuse(code: &'static str, why: impl Into<String>) -> Refusal {
    Refusal::new(code, why)
}

/// A two-person action ([`robodr_responder::Approval::TwoPerson`]).
pub fn two_person(action: ActionId) -> bool {
    action.spec().approval == robodr_responder::Approval::TwoPerson
}

/// The on-robot planner never orders a two-person action, and a
/// control-plane order is only accepted with a verified approval
/// ([`crate::engine::Engine`] checks the approvers when it authenticates
/// the order: [`approvers_ok`]).
pub fn two_person_ok(order: &Order) -> Result<(), Refusal> {
    if !matches!(order.origin, Origin::ControlPlane { .. }) || !order.human_approved {
        return Err(refuse(
            codes::APPROVAL_MISSING,
            format!(
                "{} needs two people's approval on the SOC side: the on-robot planner can never \
                 order it",
                order.action.as_str()
            ),
        ));
    }
    Ok(())
}

/// The SOC-signed body's `approved_by` names at least two different
/// people, neither the requester (`approval_missing` otherwise).
pub fn approvers_ok(
    action: ActionId,
    requested_by: &str,
    approved_by: &[String],
) -> Result<(), Refusal> {
    let mut distinct: Vec<&str> = Vec::new();
    for a in approved_by {
        let a = a.trim();
        if a.is_empty() || a == requested_by.trim() || distinct.contains(&a) {
            continue;
        }
        distinct.push(a);
    }
    if distinct.len() < 2 {
        return Err(refuse(
            codes::APPROVAL_MISSING,
            format!(
                "{} is a two-person action: the SOC-signed request must name at least two \
                 approvers (approved_by), different people and neither the requester; it names \
                 {} usable",
                action.as_str(),
                distinct.len()
            ),
        ));
    }
    Ok(())
}

/// The motion part of [`crate::decision::precheck`] (module docs). Called
/// after the common rules (well formed, not a replay, morphology,
/// OEM-validated policy and locked profile, safety system not engaged,
/// state known).
pub fn plan(
    order: &Order,
    policy: &ResponsePolicy,
    m: &MotionSection,
    ttl: &crate::config::TtlSection,
) -> Result<crate::decision::Planned, Refusal> {
    let max_ttl_s = ttl.max_s;
    let action = order.action;
    let morph: Morphology = policy.morphology;
    if action.refused_for(morph) {
        return Err(refuse(
            codes::FALL_HAZARD,
            format!(
                "{} is never executed on a {} robot (it may de-energise or restart the \
                 controller of a robot that balances)",
                action.as_str(),
                morph.as_str()
            ),
        ));
    }
    let req = match &order.target {
        crate::order::Target::Motion(r) => r.clone(),
        crate::order::Target::None => MotionRequest::default(),
        _ => {
            return Err(refuse(
                codes::INVALID_ORDER,
                format!(
                    "{} takes no node, process or participant target",
                    action.as_str()
                ),
            ))
        }
    };
    let (adapters, behaviour, reversible, ttl) = match action {
        ActionId::RestrictMotion => {
            let caps = [req.max_linear_speed, req.max_joint_speed, req.factor];
            if caps.iter().all(Option::is_none)
                || caps.iter().flatten().any(|x| !(x.is_finite() && *x > 0.0))
                || req.factor.is_some_and(|f| f > 1.0)
                || req.config.is_some()
                || req.to_version.is_some()
            {
                return Err(refuse(
                    codes::INVALID_ORDER,
                    "restrict_motion needs a factor in (0, 1] or a cap > 0 (max_linear_speed, \
                     max_joint_speed)",
                ));
            }
            if morph.needs_active_balance()
                && req.factor.is_some_and(|f| f < policy.min_motion_factor)
            {
                return Err(refuse(
                    codes::FALL_HAZARD,
                    format!(
                        "factor {:?} is below the policy's min_motion_factor {} on a robot that \
                         balances",
                        req.factor, policy.min_motion_factor
                    ),
                ));
            }
            // A planner order names none: the executor's default.
            let ttl = order.ttl_s.unwrap_or(ttl.default_s);
            if ttl == 0 || ttl > max_ttl_s {
                return Err(refuse(
                    codes::TTL_OUT_OF_RANGE,
                    format!("ttl must be 1..={max_ttl_s} s"),
                ));
            }
            if m.restrict_motion.is_empty() {
                return Err(refuse(
                    codes::NO_ADAPTER,
                    "no restrict_motion adapter is configured (motion.restrict_motion)",
                ));
            }
            (m.restrict_motion.clone(), None, true, Some(ttl))
        }
        ActionId::SafePause | ActionId::RequestSafeState | ActionId::RollbackConfig => {
            two_person_ok(order)?;
            if order.ttl_s.is_some() {
                return Err(refuse(
                    codes::TTL_OUT_OF_RANGE,
                    format!("{} takes no TTL", action.as_str()),
                ));
            }
            let (k, b) = match action {
                ActionId::SafePause => (m.safe_pause, Some(policy.safe_pause)),
                ActionId::RequestSafeState => (m.request_safe_state, Some(policy.safe_state)),
                _ => {
                    if req.config.as_deref().unwrap_or("profile") != "program" {
                        return Err(refuse(
                            codes::NOT_EXECUTOR_ACTION,
                            "rollback_config of the profile is never executed: the profile's \
                             anti-rollback chain refuses an older version (re-sign the old \
                             content as a new version with robodr-commission instead)",
                        ));
                    }
                    if req.to_version.is_none() {
                        return Err(refuse(
                            codes::INVALID_ORDER,
                            "rollback_config needs to_version",
                        ));
                    }
                    (m.rollback_config, None)
                }
            };
            let Some(k) = k else {
                return Err(refuse(
                    codes::NO_ADAPTER,
                    format!("no adapter is configured for {} (motion)", action.as_str()),
                ));
            };
            if let Some(b) = b {
                if !behaviour_ok(k, action, b) {
                    return Err(refuse(
                        codes::BEHAVIOUR_UNSUPPORTED,
                        format!(
                            "the policy's behaviour {b:?} cannot be carried out by the {} adapter",
                            k.as_str()
                        ),
                    ));
                }
            }
            let ttl = (action == ActionId::SafePause).then_some(m.safe_pause_ttl_s);
            (vec![k], b, action == ActionId::SafePause, ttl)
        }
        _ => {
            return Err(refuse(
                codes::NOT_EXECUTOR_ACTION,
                format!("{} has no motion adapter", action.as_str()),
            ))
        }
    };
    for k in &adapters {
        match m.adapter(*k) {
            None => {
                return Err(refuse(
                    codes::NO_ADAPTER,
                    format!(
                        "adapter {} is not configured (motion.{})",
                        k.as_str(),
                        k.as_str()
                    ),
                ))
            }
            Some((false, _)) => {
                return Err(refuse(
                    codes::ADAPTER_NOT_VALIDATED,
                    format!(
                        "adapter {} is not OEM-validated for this site (motion.{}.oem_validated): \
                         nothing is sent to the platform",
                        k.as_str(),
                        k.as_str()
                    ),
                ))
            }
            Some((true, _)) => {}
        }
    }
    let spec = MotionSpec {
        action,
        adapters,
        request: req,
        behaviour,
        reversible,
        id: order.id.clone(),
        deadline_ms: 0,
    };
    if !spec.allowed(m, order.judged_state) {
        return Err(refuse(
            if action == ActionId::RollbackConfig {
                codes::REQUIRES_IDLE
            } else {
                codes::SAFETY_STATE_NOT_ALLOWED
            },
            format!(
                "{} is not allowed in safety state {} by its adapter(s)",
                action.as_str(),
                state_name(order.judged_state)
            ),
        ));
    }
    Ok(crate::decision::Planned {
        effect: crate::decision::Effect::Motion(spec),
        ttl_s: ttl,
    })
}

/// The executor's view of the platform for motion actions: apply,
/// read back and undo one spec. [`SystemPorts`] talks to the real
/// endpoints ([`adapters`]); tests inject their own.
pub trait MotionPorts {
    /// Apply and read back; `Ok(note)`.
    fn apply(&mut self, m: &MotionSection, spec: &MotionSpec) -> Result<String, String>;
    /// Undo (reversible actions); `Ok(note)`.
    fn revert(&mut self, m: &MotionSection, spec: &MotionSpec) -> Result<String, String>;
    /// Periodic read-back of an applied, reversible action.
    fn verify(&mut self, m: &MotionSection, spec: &MotionSpec) -> Result<(), String>;
}

/// The real adapters.
#[derive(Debug, Default)]
pub struct SystemPorts;

impl MotionPorts for SystemPorts {
    fn apply(&mut self, m: &MotionSection, spec: &MotionSpec) -> Result<String, String> {
        adapters::apply(m, spec)
    }
    fn revert(&mut self, m: &MotionSection, spec: &MotionSpec) -> Result<String, String> {
        adapters::revert(m, spec)
    }
    fn verify(&mut self, m: &MotionSection, spec: &MotionSpec) -> Result<(), String> {
        adapters::verify(m, spec)
    }
}
