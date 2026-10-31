//! Live operational context: the control mode, mission phase and
//! connectivity the responder grades every plan by, read from live sources
//! instead of only from `context.*` in the configuration (gap T46).
//!
//! As for the safety state, RoboDR only **reads**: bus sources are decoded
//! from the captured traffic through the same passive tap and the same
//! writer trust as [`crate::safety`] (commissioned `writers`, profile, IP
//! binding), and the uplink source is a status file the uplink writes.
//!
//! # Sources
//!
//! | source | config | field(s) |
//! |---|---|---|
//! | Unitree `SportModeState_` (`/sportmodestate`, `/lf/sportmodestate`) | `unitree_sport.phase` / `.control`: sport `mode` code -> value | phase, control |
//! | Unitree `WirelessController_` (`/wirelesscontroller`) | `wireless_controller`: a stick beyond `deadzone` or a pressed key -> `control` (default `manual`), held `hold_ms` after the last activity | control |
//! | ROS 2 lifecycle `TransitionEvent` (Nav2: `/bt_navigator/transition_event`, ...) | `lifecycle.states`: goal state name -> `{control, phase}` | control, phase |
//! | `robodr-uplink` status file (`uplink-status.json`) | `uplink_status.path` | connectivity |
//!
//! # Combining (never more permissive)
//!
//! Every field is combined on its own. Each source that speaks to the field
//! contributes, per fresh writer, the value it claims; a source with no
//! fresh reading (or a writer table that overflowed recently), a value its
//! mapping does not list, and a sample that does not decode contribute the
//! source's **`on_stale`** value instead (defaults: control `manual`,
//! phase `unknown`, connectivity `disconnected`). The result is the most
//! conservative contribution ([`control_rank`], [`phase_rank`],
//! [`connectivity_rank`]); a reading that "says nothing" (e.g. the remote
//! is idle) does not contribute. When nothing contributes, the configured
//! `context.*` value is used. So losing a live source never makes the
//! context more permissive than its `on_stale` value allows.
//!
//! Every change is appended to the black box as a
//! `robodr.context_transition` note ([`ContextTransition`]) and the current
//! view is in `status.json` (`safety_feed.context`).
//!
//! # Limits
//!
//! * The sport-mode codes and the remote's layout are from Unitree's SDK
//!   headers; the code -> phase / control mapping is commissioning data and
//!   must be checked on the robot (sales-readiness B1).
//! * Lifecycle events are published on change only. A lifecycle source is
//!   therefore **latched**: its last trusted event counts until the next
//!   one, and it reads `on_stale` only until the first event after the
//!   daemon starts. A node that crashes publishes nothing; pair it with
//!   `on_stale` values you can live with.
//! * The uplink status file must be readable by the daemon's user.
//!   `robodr-uplink` writes it mode 0600 under its own user, so with the
//!   shipped units it is not (a packaging change, see
//!   `crates/robodr-agentd/README.md`). An unreadable, symlinked,
//!   oversized, malformed, foreign-format or stale file reads `on_stale`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use robodr_cdr::lifecycle;
use robodr_cdr::unitree::GoWirelessController;
use robodr_responder::{Connectivity, ControlMode, MissionPhase};
use serde::{Deserialize, Serialize};

/// The note kind of a context change.
pub const TRANSITION_KIND: &str = "robodr.context_transition";
/// Default `on_stale.control`: a human may hold authority, so every
/// motion-affecting step needs approval.
pub const DEFAULT_STALE_CONTROL: ControlMode = ControlMode::Manual;
/// Default `on_stale.phase`.
pub const DEFAULT_STALE_PHASE: MissionPhase = MissionPhase::Unknown;
/// Default `on_stale.connectivity`.
pub const DEFAULT_STALE_CONNECTIVITY: Connectivity = Connectivity::Disconnected;
/// Default `wireless_controller.deadzone` (stick units, -1..1).
pub const DEFAULT_DEADZONE: f64 = 0.1;
/// Default `wireless_controller.hold_ms`.
pub const DEFAULT_HOLD_MS: u64 = 5_000;
/// Longest `wireless_controller.hold_ms`.
pub const MAX_HOLD_MS: u64 = 600_000;
/// Default `uplink_status.stale_after_ms`.
pub const DEFAULT_UPLINK_STALE_MS: u64 = 30_000;
/// Default `uplink_status.poll_ms`.
pub const DEFAULT_UPLINK_POLL_MS: u64 = 1_000;
/// Largest uplink status file read.
pub const MAX_UPLINK_STATUS_BYTES: u64 = 64 * 1024;
/// The status format the uplink writes (`robodr-uplink-status/1`).
pub const UPLINK_STATUS_FORMAT: &str = "robodr-uplink-status/1";
/// A status stamped further than this in the future is not believed.
pub const MAX_FUTURE_SKEW_MS: u64 = 60_000;
/// Longest a pending retry (`next_attempt_at_ms`) keeps a failing status
/// current.
pub const MAX_RETRY_HORIZON_MS: u64 = 24 * 3_600_000;

// ------------------------------------------------------------------ order --

/// How conservative a control mode is: a human in command gates every
/// motion-affecting step on approval; a local operator is nearest the robot.
pub fn control_rank(c: ControlMode) -> u8 {
    match c {
        ControlMode::Autonomous => 0,
        ControlMode::Teleop => 1,
        ControlMode::Manual => 2,
    }
}

/// How conservative a mission phase is: transient phases gate every
/// motion-affecting step on approval, `unknown` ranks above every steady
/// phase.
pub fn phase_rank(p: MissionPhase) -> u8 {
    match p {
        MissionPhase::Parked => 0,
        MissionPhase::Transit => 1,
        MissionPhase::Task => 2,
        MissionPhase::Unknown => 3,
        MissionPhase::Takeoff => 4,
        MissionPhase::Landing => 5,
    }
}

/// How conservative a connectivity is (disconnected: no approval channel).
pub fn connectivity_rank(c: Connectivity) -> u8 {
    match c {
        Connectivity::Connected => 0,
        Connectivity::Degraded => 1,
        Connectivity::Disconnected => 2,
    }
}

/// The most conservative of `vals` by `rank`.
pub fn most_conservative_by<T: Copy>(
    vals: impl IntoIterator<Item = T>,
    rank: fn(T) -> u8,
) -> Option<T> {
    vals.into_iter().max_by_key(|v| rank(*v))
}

// ----------------------------------------------------------------- claims --

/// What one reading says about one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Says<T> {
    /// Nothing now (e.g. the remote is idle): does not contribute.
    #[default]
    Nothing,
    Value(T),
    /// Unlisted value or undecodable sample: the source's `on_stale`.
    Unknown,
}

/// What one reading says about the context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CtxReading {
    pub control: Says<ControlMode>,
    pub phase: Says<MissionPhase>,
    pub connectivity: Says<Connectivity>,
}

impl CtxReading {
    /// Every field a source with `role` speaks to is unknown.
    pub fn unknown(role: &CtxRole) -> Self {
        CtxReading {
            control: if role.control.is_some() {
                Says::Unknown
            } else {
                Says::Nothing
            },
            phase: if role.phase.is_some() {
                Says::Unknown
            } else {
                Says::Nothing
            },
            connectivity: if role.connectivity.is_some() {
                Says::Unknown
            } else {
                Says::Nothing
            },
        }
    }
}

/// Which fields a source speaks to, each with the value it claims while it
/// has no fresh reading (`on_stale`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CtxRole {
    pub control: Option<ControlMode>,
    pub phase: Option<MissionPhase>,
    pub connectivity: Option<Connectivity>,
}

impl CtxRole {
    pub fn is_empty(&self) -> bool {
        self.control.is_none() && self.phase.is_none() && self.connectivity.is_none()
    }
}

/// `on_stale` of a context source: what each field reads while the source
/// is stale, unmapped or undecodable.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnStaleSection {
    #[serde(default)]
    pub control: Option<ControlMode>,
    #[serde(default)]
    pub phase: Option<MissionPhase>,
    #[serde(default)]
    pub connectivity: Option<Connectivity>,
}

impl OnStaleSection {
    /// The role of a source speaking to the given fields.
    pub fn role(&self, control: bool, phase: bool, connectivity: bool) -> CtxRole {
        CtxRole {
            control: control.then(|| self.control.unwrap_or(DEFAULT_STALE_CONTROL)),
            phase: phase.then(|| self.phase.unwrap_or(DEFAULT_STALE_PHASE)),
            connectivity: connectivity
                .then(|| self.connectivity.unwrap_or(DEFAULT_STALE_CONNECTIVITY)),
        }
    }

    /// `on_stale` must not name a field the source does not speak to, nor
    /// the least conservative value of a field (`autonomous`, `parked`,
    /// `connected`): a source that says nothing must never make the context
    /// more permissive (a fixed value belongs in `context.*`).
    pub fn check(&self, what: &str, role: &CtxRole) -> Result<(), String> {
        let permissive = [
            ("control", self.control == Some(ControlMode::Autonomous)),
            ("phase", self.phase == Some(MissionPhase::Parked)),
            (
                "connectivity",
                self.connectivity == Some(Connectivity::Connected),
            ),
        ];
        if let Some((f, _)) = permissive.iter().find(|(_, bad)| *bad) {
            return Err(format!(
                "{what}.on_stale.{f}: a stale source cannot claim the least conservative \
                 value; set the static value in context.{f} instead"
            ));
        }
        let extra = [
            ("control", self.control.is_some() && role.control.is_none()),
            ("phase", self.phase.is_some() && role.phase.is_none()),
            (
                "connectivity",
                self.connectivity.is_some() && role.connectivity.is_none(),
            ),
        ];
        match extra.iter().find(|(_, bad)| *bad) {
            Some((f, _)) => Err(format!(
                "{what}.on_stale.{f}: this source does not report {f}"
            )),
            None => Ok(()),
        }
    }
}

/// The live part of the operational context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LiveContext {
    pub control: ControlMode,
    pub phase: MissionPhase,
    pub connectivity: Connectivity,
}

/// Collects the contributions of every source, field by field.
#[derive(Debug, Default, Clone)]
pub struct Contributions {
    pub control: Vec<ControlMode>,
    pub phase: Vec<MissionPhase>,
    pub connectivity: Vec<Connectivity>,
}

fn push<T: Copy>(out: &mut Vec<T>, says: Says<T>, stale: Option<T>) {
    let Some(stale) = stale else {
        return; // the source does not speak to this field
    };
    match says {
        Says::Nothing => {}
        Says::Value(v) => out.push(v),
        Says::Unknown => out.push(stale),
    }
}

impl Contributions {
    /// A fresh reading of a source with `role`.
    pub fn reading(&mut self, r: &CtxReading, role: &CtxRole) {
        push(&mut self.control, r.control, role.control);
        push(&mut self.phase, r.phase, role.phase);
        push(&mut self.connectivity, r.connectivity, role.connectivity);
    }

    /// A source with `role` that has no fresh reading (or overflowed).
    pub fn stale(&mut self, role: &CtxRole) {
        self.reading(&CtxReading::unknown(role), role);
    }

    pub fn extend(&mut self, other: Contributions) {
        self.control.extend(other.control);
        self.phase.extend(other.phase);
        self.connectivity.extend(other.connectivity);
    }

    /// The combined context: per field the most conservative contribution,
    /// `fallback`'s value when nothing contributes.
    pub fn combine(&self, fallback: LiveContext) -> LiveContext {
        LiveContext {
            control: most_conservative_by(self.control.iter().copied(), control_rank)
                .unwrap_or(fallback.control),
            phase: most_conservative_by(self.phase.iter().copied(), phase_rank)
                .unwrap_or(fallback.phase),
            connectivity: most_conservative_by(
                self.connectivity.iter().copied(),
                connectivity_rank,
            )
            .unwrap_or(fallback.connectivity),
        }
    }

    /// Contributions to one field disagree.
    pub fn conflict(&self) -> bool {
        fn differ<T: PartialEq>(v: &[T]) -> bool {
            v.iter().any(|x| v.first().is_some_and(|f| f != x))
        }
        differ(&self.control) || differ(&self.phase) || differ(&self.connectivity)
    }

    /// What these contributions (one source's) amount to, for display.
    pub fn view(
        &self,
    ) -> (
        Option<ControlMode>,
        Option<MissionPhase>,
        Option<Connectivity>,
    ) {
        (
            most_conservative_by(self.control.iter().copied(), control_rank),
            most_conservative_by(self.phase.iter().copied(), phase_rank),
            most_conservative_by(self.connectivity.iter().copied(), connectivity_rank),
        )
    }
}

/// One context source in a transition / the status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextSourceView {
    pub name: String,
    pub fresh: bool,
    pub age_ms: Option<u64>,
    /// What the source contributes now (absent: nothing / not its field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<ControlMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<MissionPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connectivity: Option<Connectivity>,
    /// Why the source reads `on_stale` (uplink file errors), if it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A change of the live context (black-box note).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextTransition {
    pub kind: &'static str,
    pub from: LiveContext,
    pub to: LiveContext,
    pub at_ms: u64,
    /// Sources disagreed on a field (the most conservative value won).
    pub conflict: bool,
    pub sources: Vec<ContextSourceView>,
}

/// The live context in `status.json`.
#[derive(Debug, Clone, Serialize)]
pub struct ContextStatus {
    pub context: Option<LiveContext>,
    pub sources: Vec<ContextSourceView>,
}

// -------------------------------------------------------- mapping helpers --

/// One value of a `{control, phase}` mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtxEntry {
    #[serde(default)]
    pub control: Option<ControlMode>,
    #[serde(default)]
    pub phase: Option<MissionPhase>,
}

/// Look `key` up in a code -> value map the source speaks through:
/// listed -> the value, unlisted -> unknown, empty map -> nothing.
pub fn lookup<K: Ord, T: Copy>(map: &BTreeMap<K, T>, key: &K) -> Says<T> {
    if map.is_empty() {
        return Says::Nothing;
    }
    match map.get(key) {
        Some(v) => Says::Value(*v),
        None => Says::Unknown,
    }
}

/// Parse a `"<decimal 0..=255>" -> T` map.
pub fn u8_keys<T: Copy>(what: &str, m: &BTreeMap<String, T>) -> Result<BTreeMap<u8, T>, String> {
    if m.len() > crate::safety::MAX_VALUES {
        return Err(format!(
            "{what}: at most {} entries",
            crate::safety::MAX_VALUES
        ));
    }
    let mut out = BTreeMap::new();
    for (k, v) in m {
        let code: u8 = k.parse().map_err(|_| {
            format!(
                "{what}: key {:?} is not a decimal 0..=255",
                robodr_ros2_pipeline::sanitize(k)
            )
        })?;
        if out.insert(code, *v).is_some() {
            return Err(format!("{what}: value {code} listed twice"));
        }
    }
    Ok(out)
}

// ------------------------------------------------------- wireless remote --

/// `wireless_controller` of a topic source (`unitree_go::msg::dds_::
/// WirelessController_`).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirelessSection {
    /// A stick beyond this (absolute, -1..1) is activity.
    #[serde(default = "default_deadzone")]
    pub deadzone: f64,
    /// Activity counts this long after the last active sample.
    #[serde(default = "default_hold")]
    pub hold_ms: u64,
    /// The control mode while the remote is in use: `manual` (default) or
    /// `teleop`; never `autonomous`.
    #[serde(default = "default_remote_control")]
    pub control: ControlMode,
}

fn default_deadzone() -> f64 {
    DEFAULT_DEADZONE
}
fn default_hold() -> u64 {
    DEFAULT_HOLD_MS
}
fn default_remote_control() -> ControlMode {
    ControlMode::Manual
}

/// A validated `wireless_controller`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WirelessSpec {
    pub deadzone: f32,
    pub hold_ms: u64,
    pub control: ControlMode,
}

impl WirelessSection {
    pub fn resolve(&self, what: &str) -> Result<WirelessSpec, String> {
        if !(self.deadzone.is_finite() && self.deadzone > 0.0 && self.deadzone < 1.0) {
            return Err(format!(
                "{what}.wireless_controller.deadzone must be finite, > 0 and < 1"
            ));
        }
        if self.hold_ms > MAX_HOLD_MS {
            return Err(format!(
                "{what}.wireless_controller.hold_ms must be at most {MAX_HOLD_MS}"
            ));
        }
        if !self.control.human_in_command() {
            return Err(format!(
                "{what}.wireless_controller.control must be manual or teleop (a remote in \
                 use means a human is commanding motion)"
            ));
        }
        Ok(WirelessSpec {
            // Stick units; f32 is what the wire carries.
            deadzone: self.deadzone as f32,
            hold_ms: self.hold_ms,
            control: self.control,
        })
    }
}

/// Is the remote in use? `None` if a stick value is not finite.
pub fn remote_active(w: &GoWirelessController, deadzone: f32) -> Option<bool> {
    let sticks = [w.lx, w.ly, w.rx, w.ry];
    if sticks.iter().any(|v| !v.is_finite()) {
        return None;
    }
    Some(w.keys != 0 || sticks.iter().any(|v| v.abs() > deadzone))
}

/// The reading of one remote sample: `(says, last activity)`.
pub fn remote_reading(
    spec: &WirelessSpec,
    w: &GoWirelessController,
    prev_active_at: Option<u64>,
    now_ms: u64,
) -> (Says<ControlMode>, Option<u64>) {
    match remote_active(w, spec.deadzone) {
        None => (Says::Unknown, prev_active_at),
        Some(true) => (Says::Value(spec.control), Some(now_ms)),
        Some(false) => {
            let held = prev_active_at.is_some_and(|t| now_ms.saturating_sub(t) <= spec.hold_ms);
            if held {
                (Says::Value(spec.control), prev_active_at)
            } else {
                (Says::Nothing, prev_active_at)
            }
        }
    }
}

// -------------------------------------------------------------- lifecycle --

/// `lifecycle` of a topic source (`lifecycle_msgs/msg/TransitionEvent`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSection {
    /// Goal-state name (`unconfigured`, `inactive`, `active`, `finalized`,
    /// or a transition state such as `activating`) -> `{control, phase}`.
    pub states: BTreeMap<String, CtxEntry>,
}

/// A validated `lifecycle`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleSpec {
    pub control: BTreeMap<u8, ControlMode>,
    pub phase: BTreeMap<u8, MissionPhase>,
}

impl LifecycleSection {
    pub fn resolve(&self, what: &str) -> Result<LifecycleSpec, String> {
        if self.states.is_empty() {
            return Err(format!("{what}.lifecycle.states must not be empty"));
        }
        let mut control = BTreeMap::new();
        let mut phase = BTreeMap::new();
        for (name, e) in &self.states {
            let id = lifecycle::state_id(name).ok_or_else(|| {
                format!(
                    "{what}.lifecycle.states: {:?} is not a lifecycle state (unconfigured, \
                     inactive, active, finalized, configuring, cleaningup, shuttingdown, \
                     activating, deactivating, errorprocessing, unknown)",
                    robodr_ros2_pipeline::sanitize(name)
                )
            })?;
            if e.control.is_none() && e.phase.is_none() {
                return Err(format!(
                    "{what}.lifecycle.states.{name}: give control and/or phase"
                ));
            }
            if let Some(c) = e.control {
                control.insert(id, c);
            }
            if let Some(p) = e.phase {
                phase.insert(id, p);
            }
        }
        // A field one state maps must be mapped by every listed state, or
        // the others would read "unknown" for it: say so explicitly.
        for (name, e) in &self.states {
            if (!control.is_empty() && e.control.is_none())
                || (!phase.is_empty() && e.phase.is_none())
            {
                return Err(format!(
                    "{what}.lifecycle.states.{name}: every state must give the same fields \
                     (control and/or phase)"
                ));
            }
        }
        Ok(LifecycleSpec { control, phase })
    }
}

impl LifecycleSpec {
    /// The reading of a goal state.
    pub fn reading(&self, goal_state: u8) -> CtxReading {
        CtxReading {
            control: lookup(&self.control, &goal_state),
            phase: lookup(&self.phase, &goal_state),
            connectivity: Says::Nothing,
        }
    }

    /// The goal state is listed for every field this source speaks to.
    pub fn maps(&self, goal_state: u8) -> bool {
        (self.control.is_empty() || self.control.contains_key(&goal_state))
            && (self.phase.is_empty() || self.phase.contains_key(&goal_state))
    }
}

// ----------------------------------------------------------------- uplink --

/// `uplink_status` of the feed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UplinkSection {
    /// `<uplink state dir>/uplink-status.json`.
    pub path: PathBuf,
    /// A status older than this (by its `updated_at_ms`, wall clock) is
    /// stale, unless a retry it announces is still pending.
    #[serde(default = "default_uplink_stale")]
    pub stale_after_ms: u64,
    #[serde(default = "default_uplink_poll")]
    pub poll_ms: u64,
    /// Connectivity while the status is stale or unreadable.
    #[serde(default)]
    pub on_stale: Option<Connectivity>,
}

fn default_uplink_stale() -> u64 {
    DEFAULT_UPLINK_STALE_MS
}
fn default_uplink_poll() -> u64 {
    DEFAULT_UPLINK_POLL_MS
}

/// A validated `uplink_status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UplinkSpec {
    pub path: PathBuf,
    pub stale_after_ms: u64,
    pub poll_ms: u64,
    pub on_stale: Connectivity,
}

impl UplinkSection {
    pub fn resolve(&self) -> Result<UplinkSpec, String> {
        if self.path.as_os_str().is_empty() || !self.path.is_absolute() {
            return Err("safety_feed.uplink_status.path must be an absolute path".into());
        }
        if !(1_000..=crate::safety::MAX_STALE_AFTER_MS).contains(&self.stale_after_ms) {
            return Err(format!(
                "safety_feed.uplink_status.stale_after_ms must be 1000..={}",
                crate::safety::MAX_STALE_AFTER_MS
            ));
        }
        if !(100..=60_000).contains(&self.poll_ms) {
            return Err("safety_feed.uplink_status.poll_ms must be 100..=60000".into());
        }
        if self.on_stale == Some(Connectivity::Connected) {
            return Err(
                "safety_feed.uplink_status.on_stale: an unreadable or stale status cannot read \
                 connected"
                    .into(),
            );
        }
        Ok(UplinkSpec {
            path: self.path.clone(),
            stale_after_ms: self.stale_after_ms,
            poll_ms: self.poll_ms,
            on_stale: self.on_stale.unwrap_or(DEFAULT_STALE_CONNECTIVITY),
        })
    }
}

/// The fields of `uplink-status.json` used here (the rest is ignored).
#[derive(Debug, Deserialize)]
struct UplinkStatusFile {
    format: String,
    state: String,
    updated_at_ms: u64,
    #[serde(default)]
    next_attempt_at_ms: Option<u64>,
}

/// What an uplink status file says at wall time `now_wall_ms`:
/// `ok` -> connected, `retrying` / `starting` -> degraded, `blocked` ->
/// disconnected; anything else, a foreign format, a stamp more than
/// [`MAX_FUTURE_SKEW_MS`] ahead or a stale status -> `Err(why)`
/// (`on_stale`).
pub fn parse_uplink_status(
    bytes: &[u8],
    now_wall_ms: u64,
    stale_after_ms: u64,
) -> Result<Connectivity, String> {
    let s: UplinkStatusFile =
        serde_json::from_slice(bytes).map_err(|_| "not an uplink status file".to_string())?;
    if s.format != UPLINK_STATUS_FORMAT {
        return Err("unknown status format".into());
    }
    if s.updated_at_ms > now_wall_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
        return Err("status stamped in the future".into());
    }
    // A failing uplink waits (backoff) before it rewrites the file; the
    // status stays current until the announced attempt (bounded).
    let until = s
        .next_attempt_at_ms
        .filter(|n| *n >= s.updated_at_ms)
        .map(|n| n.min(s.updated_at_ms.saturating_add(MAX_RETRY_HORIZON_MS)))
        .unwrap_or(s.updated_at_ms);
    if now_wall_ms > until.saturating_add(stale_after_ms) {
        return Err("status is stale (uplink not running?)".into());
    }
    match s.state.as_str() {
        "ok" => Ok(Connectivity::Connected),
        "retrying" | "starting" => Ok(Connectivity::Degraded),
        "blocked" => Ok(Connectivity::Disconnected),
        _ => Err("unknown uplink state".into()),
    }
}

/// The uplink source: the last poll's result.
#[derive(Debug)]
pub struct UplinkSource {
    pub spec: UplinkSpec,
    last_poll_ms: Option<u64>,
    last: Result<Connectivity, String>,
}

impl UplinkSource {
    pub fn new(spec: UplinkSpec) -> Self {
        Self {
            spec,
            last_poll_ms: None,
            last: Err("not read yet".into()),
        }
    }

    /// Re-read the status file if `poll_ms` has passed (`now_ms`: daemon
    /// uptime; `now_wall_ms`: wall clock, the file's time base).
    pub fn poll(&mut self, now_ms: u64, now_wall_ms: u64) {
        if self
            .last_poll_ms
            .is_some_and(|t| now_ms.saturating_sub(t) < self.spec.poll_ms)
        {
            return;
        }
        self.last_poll_ms = Some(now_ms);
        self.last =
            crate::control::fsutil::read_capped_nofollow(&self.spec.path, MAX_UPLINK_STATUS_BYTES)
                .map_err(|e| format!("cannot read the status file: {}", e.kind()))
                .and_then(|b| parse_uplink_status(&b, now_wall_ms, self.spec.stale_after_ms));
    }

    /// Apply a status read elsewhere (tests, or a caller that read it).
    pub fn set(&mut self, now_ms: u64, r: Result<Connectivity, String>) {
        self.last_poll_ms = Some(now_ms);
        self.last = r;
    }

    pub fn contributions(&self) -> Contributions {
        Contributions {
            connectivity: vec![match &self.last {
                Ok(c) => *c,
                Err(_) => self.spec.on_stale,
            }],
            ..Contributions::default()
        }
    }

    pub fn view(&self, now_ms: u64) -> ContextSourceView {
        ContextSourceView {
            name: format!("uplink_status:{}", self.spec.path.display()),
            fresh: self.last.is_ok(),
            age_ms: self.last_poll_ms.map(|t| now_ms.saturating_sub(t)),
            control: None,
            phase: None,
            connectivity: Some(match &self.last {
                Ok(c) => *c,
                Err(_) => self.spec.on_stale,
            }),
            error: self.last.as_ref().err().cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_put_human_transient_and_disconnected_last() {
        let mut c = ControlMode::ALL.to_vec();
        c.sort_by_key(|x| control_rank(*x));
        assert_eq!(
            c,
            [
                ControlMode::Autonomous,
                ControlMode::Teleop,
                ControlMode::Manual
            ]
        );
        let mut p = MissionPhase::ALL.to_vec();
        p.sort_by_key(|x| phase_rank(*x));
        // Every transient phase outranks every steady one.
        for t in MissionPhase::ALL.iter().filter(|x| x.is_transient()) {
            for s in MissionPhase::ALL.iter().filter(|x| !x.is_transient()) {
                assert!(phase_rank(*t) > phase_rank(*s));
            }
        }
        let mut n = Connectivity::ALL.to_vec();
        n.sort_by_key(|x| connectivity_rank(*x));
        assert_eq!(n.last(), Some(&Connectivity::Disconnected));
    }

    #[test]
    fn combine_is_most_conservative_and_stale_reads_on_stale() {
        let fallback = LiveContext {
            control: ControlMode::Autonomous,
            phase: MissionPhase::Transit,
            connectivity: Connectivity::Connected,
        };
        let role = OnStaleSection::default().role(true, true, false);
        // Nothing contributes: the configuration.
        let mut c = Contributions::default();
        c.reading(&CtxReading::default(), &role);
        assert_eq!(c.combine(fallback), fallback);
        // A stale source: manual / unknown.
        let mut c = Contributions::default();
        c.stale(&role);
        let got = c.combine(fallback);
        assert_eq!(got.control, ControlMode::Manual);
        assert_eq!(got.phase, MissionPhase::Unknown);
        assert_eq!(got.connectivity, Connectivity::Connected, "not its field");
        // Disagreement: the most conservative wins.
        let mut c = Contributions::default();
        c.reading(
            &CtxReading {
                control: Says::Value(ControlMode::Autonomous),
                phase: Says::Value(MissionPhase::Parked),
                ..CtxReading::default()
            },
            &role,
        );
        c.reading(
            &CtxReading {
                control: Says::Value(ControlMode::Teleop),
                phase: Says::Value(MissionPhase::Landing),
                ..CtxReading::default()
            },
            &role,
        );
        assert!(c.conflict());
        let got = c.combine(fallback);
        assert_eq!(got.control, ControlMode::Teleop);
        assert_eq!(got.phase, MissionPhase::Landing);
        // on_stale only for fields the source reports.
        let s = OnStaleSection {
            connectivity: Some(Connectivity::Degraded),
            ..OnStaleSection::default()
        };
        assert!(s.check("x", &role).is_err());
        assert!(s.check("x", &s.role(false, false, true)).is_ok());
    }

    fn remote(lx: f32, keys: u16) -> GoWirelessController {
        GoWirelessController {
            lx,
            ly: 0.0,
            rx: 0.0,
            ry: 0.0,
            keys,
        }
    }

    #[test]
    fn remote_activity_holds_then_releases() {
        let spec = WirelessSection {
            deadzone: 0.1,
            hold_ms: 1000,
            control: ControlMode::Manual,
        }
        .resolve("t")
        .unwrap();
        let (s, a) = remote_reading(&spec, &remote(0.05, 0), None, 0);
        assert_eq!((s, a), (Says::Nothing, None), "inside the deadzone");
        let (s, a) = remote_reading(&spec, &remote(-0.5, 0), a, 10);
        assert_eq!((s, a), (Says::Value(ControlMode::Manual), Some(10)));
        let (s, a) = remote_reading(&spec, &remote(0.0, 0), a, 900);
        assert_eq!(s, Says::Value(ControlMode::Manual), "held");
        let (s, a) = remote_reading(&spec, &remote(0.0, 0), a, 1011);
        assert_eq!(s, Says::Nothing, "released after hold_ms");
        let (s, _) = remote_reading(&spec, &remote(0.0, 0x0010), a, 1012);
        assert_eq!(s, Says::Value(ControlMode::Manual), "a key is activity");
        let (s, _) = remote_reading(&spec, &remote(f32::NAN, 0), a, 1013);
        assert_eq!(s, Says::Unknown);
        // A remote never means autonomy.
        for bad in [
            WirelessSection {
                control: ControlMode::Autonomous,
                ..WirelessSection {
                    deadzone: 0.1,
                    hold_ms: 1,
                    control: ControlMode::Manual,
                }
            },
            WirelessSection {
                deadzone: 0.0,
                hold_ms: 1,
                control: ControlMode::Manual,
            },
            WirelessSection {
                deadzone: f64::NAN,
                hold_ms: 1,
                control: ControlMode::Manual,
            },
            WirelessSection {
                deadzone: 0.1,
                hold_ms: MAX_HOLD_MS + 1,
                control: ControlMode::Manual,
            },
        ] {
            assert!(bad.resolve("t").is_err());
        }
    }

    #[test]
    fn lifecycle_mapping() {
        let sec: LifecycleSection = serde_json::from_value(serde_json::json!({
            "states": {
                "active": {"control": "autonomous", "phase": "transit"},
                "inactive": {"control": "autonomous", "phase": "parked"}
            }
        }))
        .unwrap();
        let spec = sec.resolve("t").unwrap();
        let r = spec.reading(3);
        assert_eq!(r.control, Says::Value(ControlMode::Autonomous));
        assert_eq!(r.phase, Says::Value(MissionPhase::Transit));
        assert!(spec.maps(2));
        // Unlisted (e.g. activating): unknown, i.e. on_stale.
        assert_eq!(spec.reading(13).phase, Says::Unknown);
        assert!(!spec.maps(13));
        for bad in [
            serde_json::json!({"states": {}}),
            serde_json::json!({"states": {"Active": {"phase": "transit"}}}),
            serde_json::json!({"states": {"active": {}}}),
            serde_json::json!({"states": {"active": {"phase": "transit"},
                                          "inactive": {"control": "manual"}}}),
        ] {
            let s: LifecycleSection = serde_json::from_value(bad).unwrap();
            assert!(s.resolve("t").is_err());
        }
    }

    fn status(state: &str, updated: u64, next: Option<u64>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "format": UPLINK_STATUS_FORMAT, "state": state, "updated_at_ms": updated,
            "next_attempt_at_ms": next, "pid": 1, "extra": {"ignored": true}
        }))
        .unwrap()
    }

    #[test]
    fn uplink_status_mapping_and_staleness() {
        let now = 100 * 3_600_000;
        let st = 30_000;
        assert_eq!(
            parse_uplink_status(&status("ok", now - 1000, None), now, st),
            Ok(Connectivity::Connected)
        );
        assert_eq!(
            parse_uplink_status(&status("retrying", now - 1000, None), now, st),
            Ok(Connectivity::Degraded)
        );
        assert_eq!(
            parse_uplink_status(&status("blocked", now - 1000, None), now, st),
            Ok(Connectivity::Disconnected)
        );
        // Stale "ok" (the uplink died) is not connected.
        assert!(parse_uplink_status(&status("ok", now - 31_000, None), now, st).is_err());
        // A failing uplink in a long backoff stays current until its retry.
        assert_eq!(
            parse_uplink_status(
                &status("blocked", now - 600_000, Some(now + 300_000)),
                now,
                st
            ),
            Ok(Connectivity::Disconnected)
        );
        // ... but not forever, and not from the future.
        assert!(
            parse_uplink_status(&status("ok", now - 25 * 3_600_000, Some(u64::MAX)), now, st)
                .is_err()
        );
        assert!(parse_uplink_status(&status("ok", now + 120_000, None), now, st).is_err());
        assert!(parse_uplink_status(&status("great", now, None), now, st).is_err());
        assert!(parse_uplink_status(b"{}", now, st).is_err());
        assert!(parse_uplink_status(b"\xff", now, st).is_err());
        let foreign = serde_json::to_vec(&serde_json::json!({
            "format": "other/1", "state": "ok", "updated_at_ms": now
        }))
        .unwrap();
        assert!(parse_uplink_status(&foreign, now, st).is_err());
    }

    #[test]
    fn uplink_source_reads_files_safely() {
        let dir = std::env::temp_dir().join(format!("robodr-uplink-ctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("uplink-status.json");
        let spec = UplinkSection {
            path: path.clone(),
            stale_after_ms: 30_000,
            poll_ms: 1_000,
            on_stale: None,
        }
        .resolve()
        .unwrap();
        let mut u = UplinkSource::new(spec);
        let wall = 5_000_000;
        // Missing: on_stale (disconnected).
        u.poll(0, wall);
        assert_eq!(
            u.contributions().connectivity,
            vec![Connectivity::Disconnected]
        );
        std::fs::write(&path, status("ok", wall, None)).unwrap();
        u.poll(10, wall);
        assert_eq!(
            u.contributions().connectivity,
            vec![Connectivity::Disconnected],
            "poll_ms"
        );
        u.poll(1_000, wall);
        assert_eq!(
            u.contributions().connectivity,
            vec![Connectivity::Connected]
        );
        // A symlink is refused (never followed).
        let real = dir.join("real.json");
        std::fs::write(&real, status("ok", wall, None)).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        u.poll(2_000, wall);
        assert_eq!(
            u.contributions().connectivity,
            vec![Connectivity::Disconnected]
        );
        assert!(u.view(2_000).error.is_some());
        // An oversized file is refused before it is parsed.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, vec![b' '; (MAX_UPLINK_STATUS_BYTES + 1) as usize]).unwrap();
        u.poll(3_000, wall);
        assert_eq!(
            u.contributions().connectivity,
            vec![Connectivity::Disconnected]
        );
        let _ = std::fs::remove_dir_all(&dir);
        // Relative paths and silly intervals are refused.
        for (p, s, q) in [
            ("rel.json", 30_000, 1_000),
            ("/a", 10, 1_000),
            ("/a", 30_000, 1),
        ] {
            assert!(UplinkSection {
                path: p.into(),
                stale_after_ms: s,
                poll_ms: q,
                on_stale: None
            }
            .resolve()
            .is_err());
        }
    }
}
