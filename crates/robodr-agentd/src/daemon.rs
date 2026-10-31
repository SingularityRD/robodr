//! The daemon: inputs -> pipeline -> agent -> black box + spool, plus
//! housekeeping and self-health. See the crate docs for the picture.
//!
//! # Main loop
//!
//! One thread owns the [`Pipeline`], the [`Agent`] (and through it the black
//! box, a single writer) and the [`Spool`]. It waits on the shared bounded
//! queue with a timeout and handles at most [`BATCH`] items before it checks
//! the clock, so housekeeping runs on time even under a flood. Every
//! `tick_ms` (default 1 s) it:
//!
//! 1. calls `Pipeline::tick` (expire held SEDP announcements) and
//!    `Pipeline::capture_findings` with the capture source's latest health;
//! 2. handles inputs that ended (drain the queue first, then for the capture
//!    input `Pipeline::finish`, as `robodr-ros2-watch` does at end of input);
//! 3. evaluates self-health ([`crate::health`]) and the early warnings
//!    ([`crate::selfcheck`]: credential expiry, kernel clock, wall-clock
//!    jumps, free disk space, executor reachability) and reports issues;
//!    every `self_health.health_record_ms` it reports the signed
//!    `robot.agent.health` record (findings contract 2.5);
//! 4. writes `status.json` into the spool; prunes acked spool records;
//! 5. every `heartbeat_ms`, appends a `robodr.agentd_heartbeat` note to the
//!    black box (state, reasons, per-input counters, pipeline / agent /
//!    spool counters).
//!
//! When every input has ended and `exit_when_inputs_end` is off (a live
//! daemon whose capture died, stdin EOF), the queue reports `Disconnected`
//! immediately; the loop then sleeps until its next deadline instead of
//! spinning, keeps ticking (status, heartbeat, watchdog) and reports the
//! state `unknown` ("every input has ended"). An input thread that vanished
//! without reporting its end (a panic) is marked ended with an error, so it
//! raises `robot.agent.input_ended`.
//!
//! # Liveness and staleness
//!
//! The main loop sends `WATCHDOG=1` to systemd (when `NOTIFY_SOCKET` is
//! set; see [`crate::notify`]) at most every [`WATCHDOG_PING`], `READY=1`
//! after start and `STOPPING=1` at shutdown. `status.json` carries
//! `updated_mono_ms` (`CLOCK_MONOTONIC`), `boot_id` and `stale_after_ms`
//! (2 x `tick_ms` + `lag_ms`): if the loop stalls (slow fsync, a hang), the
//! file stops changing and a consumer must read it as `unknown`
//! ([`effective_state`]), never trust a stale `ok`.
//!
//! # Shutdown
//!
//! When `should_stop()` returns `true` (SIGTERM/SIGINT in the binary) or,
//! with `exit_when_inputs_end`, once every input has ended and the queue is
//! empty: stop flags are set, the queue is drained (bounded by its
//! capacity), `Pipeline::finish` reports held announcements, a final
//! `robodr.agentd_stop` note is written, the black box is sealed
//! (`Agent::finish`) and the seal is copied to `<spool>/checkpoint.json` for
//! the exporter to take off-unit. Input threads that block in a read with a
//! timeout are joined; the stdin reader is not (it may block forever).
//!
//! # Live motion data
//!
//! Datagrams go through `Pipeline::process_datagram_with_motion`: besides
//! findings, the pipeline decodes user DATA on the profile's motion channels
//! and the configured feedback topics into `MotionCommand` /
//! `MotionFeedback` events (see `robodr_ros2_pipeline::motion`), stamped
//! with the daemon clock's monotonic time at the moment the datagram is
//! handled (live capture). A **pcap replay** is stamped on its own
//! timeline instead: each packet's record timestamp, offset onto the
//! daemon's monotonic clock at the first replayed packet and held
//! non-decreasing ([`ReplayTimeline`]). The file is read as fast as the
//! daemon can, so its handling time says nothing about when the robot sent
//! what: with handling time, the motion monitor's latency and persistence
//! windows (and the firewall's rate checks) judged the replay by host load.
//! The same timeline is the detection time of every event handled while
//! the replay runs ([`robodr_agent::Agent::handle_with_joint_at`]);
//! evidence keeps the daemon clock. Each event goes through
//! `Agent::handle`, exactly like a JSONL event: `Profile::evaluate` (envelope), the Motion Firewall, the motion
//! monitor (commands and per-publisher feedback), the black box and the
//! spool. So the pipeline's own envelope evaluation is switched off here
//! (`evaluate_commands = false`), to report each over-envelope command once,
//! with the event as evidence; the pipeline still reports undecodable,
//! unattributed and source-mismatched samples.
//!
//! **The firewall only records.** The daemon reads a copy of the traffic;
//! it is not inline and cannot pass, limit or drop anything. Its firewall
//! therefore runs with `FailBehaviour::PassThroughObserveOnly`: every
//! verdict is a recorded *would-have* (`enforcing: false` in the black box),
//! never an output. Enforcement belongs in a gateway on the command path.
//!
//! # Safety state
//!
//! Every plan is graded by the robot's safety state. With a `safety_feed`
//! ([`crate::safety`]) it is re-evaluated before each deviation is
//! planned and on every tick (so staleness is noticed on a quiet bus):
//! each datagram first goes through the pipeline (which updates the
//! binding table), then through the feed's passive tap, so an e-stop
//! sample grades the motion commands of the same datagram. Every change is
//! a `robodr.safety_state_transition` note in the black box, the current
//! view is `safety_feed` in `status.json`, and the feed's findings
//! (untrusted writer, undecodable or unmapped value) go through the agent
//! like the pipeline's. Without a feed, `context.safety_state` is used.
//!
//! # Correlation
//!
//! With `correlation` enabled (the default), every outcome the daemon
//! reports (pipeline and safety-feed findings, the agent's own profile /
//! firewall / motion-monitor deviations, self-health issues) is also fed
//! to a `robodr_correlate::Correlator` as a signal: rule, severity, the
//! deviation's (already stricter) mode, the source IP (`src:<ip>`) or
//! participant (`participant:<guid prefix>`) entity, and the deviation's
//! black-box record as evidence reference. A correlated finding
//! (`robot.correlate.*`) is recorded in full (every contributing signal) as
//! a `robodr.correlated_finding` note, then handed to the agent like a
//! sensor finding; it is observe-only whenever any contributor was. The
//! engine's expiry runs on every tick, its counters are in `status.json`
//! and the heartbeat, and a rising eviction / refusal count is reported as
//! the observe-only self-health finding `robot.agent.correlation_pressure`.
//! The engine is told, every tick, which entities are the robot's own (the
//! profile's participants and the IPs bound or pinned to them), so their
//! pending state is protected from eviction by a flood of fresh entities;
//! evicting pending evidence anyway is reported per rule as the
//! observe-only correlated finding `robot.correlate.correlation_state_evicted`.
//! Correlation only adds findings; nothing is suppressed.
//!
//! # Host threats (Pulsar)
//!
//! With `host_threats` ([`crate::host`]), the `robodr-threat-forward`
//! Pulsar module delivers every Pulsar threat (except the ROS 2 sensor's
//! own) over a peer-checked unix socket. Each one is reported as a
//! finding under the rule's own `robot.host.<rule>` id (contract 2.5,
//! `robodr_ocsf::HOST_RULES`; `robot.host.pulsar_threat` for a rule RoboDR
//! does not ship) (`Detector::Sensor`, source
//! `host:<module>`, the threat's severity) and fed to the correlator as
//! `Signal::host(<Pulsar rule name>)` with the `process` entity
//! (the pid), so the host-dependent default rules
//! (`coordinated_intrusion`, `credential_theft`,
//! `trojaned_package_key_access`, `defense_tampering`,
//! `host_process_persistence`) fire here. The forwarder's heartbeats keep
//! the input live; a forwarder that is gone makes the input silent and the
//! state `unknown`.
//!
//! # Evidence store upkeep
//!
//! Every tick writes the black box's `head.json` high-water mark if records
//! were appended since the last one (`Agent::mark_blackbox_head`), bounding
//! the unmarked tail in time on a quiet bus. What the recorder found when it
//! opened (or reopened after an outage) is reported once per recorder as
//! observe-only self-health findings with the recorder's own severity:
//! quarantined segments and damage as `robot.agent.evidence_quarantined`
//! (High = failing media, Critical = tampering, e.g. a stray segment file
//! or a closed segment cut on a frame boundary), truncation as Critical
//! `robot.agent.evidence_truncated`.
//!
//! Without `blackbox.head_anchor` the daemon warns at start and the status
//! file says `"blackbox": {"anchored": false, ...}`: `head.json` alone
//! cannot reveal a cut of the newest records combined with a rollback of
//! `head.json`, or a wiped store. The `file` anchor is only as strong as
//! the storage it lives on; a deployment needs the `tpm_nv_counter` anchor
//! (`robodr_blackbox::TpmNvCounterAnchor`: TPM 2.0 NV counter plus a
//! sidecar signed with the black-box key) or the `remote` anchor
//! (`robodr_blackbox::RemoteHeadAnchor`: marks signed with the black-box
//! key, held by a `robodr-anchor-receiver` off the unit, queried at open
//! with a nonce, answers signed by the receiver).
//!
//! # Finding signatures
//!
//! With `finding_signing`, the agent signs every finding with the dedicated
//! Ed25519 finding key (`Agent::with_finding_signer`); the detached
//! signature is the spooled record's last header, `robodr-finding-sig`
//! (contract §2a).
//!
//! # What the daemon does with a plan
//!
//! By default nothing. The agent's executor is the default `NoopExecutor`:
//! plans (dispositions, `would_have`) are recorded in the black box and
//! carried in the finding, never executed. With `executor.enabled` and
//! `planner_orders` (executor v1, [`crate::executor_link`]) the eligible
//! network steps of a recorded plan are handed to `robodr-executor`.
//!
//! # Control-plane requests
//!
//! With `control_plane` ([`crate::control`], `robodr-control-plane/v2`),
//! listener threads terminate mutual TLS, authenticate SOC action requests
//! and hand them over a bounded channel (evidence exports are built on the
//! listener threads; only their black-box note comes here); the main loop
//! takes up to [`crate::control::CALLS_PER_POLL`] per iteration and judges
//! each against the safety state *at that moment* (the live feed is
//! re-evaluated first), the operational context and the response policy,
//! records request and decision as a `robodr.control_plane_request` note
//! (fsynced), journaled around it in `control_plane.state_dir` (so the
//! state survives a restart), and answers. Without executor v1 the executor
//! is the recording one: an accepted request is answered
//! `recorded_not_executed`, nothing reaches the robot. With it, accepted
//! requests are staged and dispatched to `robodr-executor` once stored, and
//! every outcome the link reports is journalled at once
//! ([`crate::control::api::Engine::sync`]).
//! Failed authentications and authenticated invalid requests become the
//! observe-only self-health findings
//! `robot.agent.control_plane_unauthenticated` (High) and
//! `robot.agent.control_plane_invalid` (Medium), rate-limited by
//! `health_report_ms`. The control plane is not an input: a quiet SOC never
//! makes the state `unknown`.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use robodr_agent::{
    Agent, AgentConfig, AgentStats, Detector, Finished, FirewallSettings, JointInput,
    MonitorSettings, Outcome,
};
use robodr_blackbox::{Clock, RecorderConfig, SystemClock, TimeSource, Timestamp};
use robodr_correlate::{CorrelatedFinding, Correlator, EntityKind, Limits, Signal};
use robodr_events::profile::Profile;
use robodr_events::RobotEvent;
use robodr_firewall::FailBehaviour;
use robodr_ocsf::{AttestationStatus, PlatformFamily as OcsfPlatform, RobotInfo, Subject};
use robodr_responder::{OperationalContext, SafetyState};
use robodr_ros2_pipeline::config::CaptureInput;
use robodr_ros2_pipeline::{
    sanitize, Finding, MotionSample, Pipeline, PipelineStats, ProfileStatus, SharedHealth,
};
use serde::Serialize;

use crate::config::{check_daemon_dirs, resolve_path, EventInputConfig, Resolved};
use crate::control::{api as cp_api, ControlPlane, ControlStatus};
use crate::health::{
    rules as health_rules, DaemonSnapshot, HealthConfig, HealthMonitor, HealthState, InputSnapshot,
    Issue, Recovery, State,
};
use crate::input::{self, Feed, InputStats, Msg, Payload, QueueBudget};
use crate::notify::{monotonic_ms, Notifier};
use crate::safety::{FeedFinding, FeedStatus, SafetyFeed, Transition};
use crate::safety_feed::context::LiveContext;
use crate::spool::{Spool, SpoolClass, SpoolError, SpoolStats};

/// Most queued items handled between two clock checks.
pub const BATCH: usize = 256;
/// Status file name in the spool root.
pub const STATUS_FILE: &str = "status.json";
/// Checkpoint copy in the spool root.
pub const CHECKPOINT_FILE: &str = "checkpoint.json";
/// Model label used for the agent when the profile failed validation.
pub const UNVALIDATED_MODEL: &str = "unvalidated-profile";
/// Most time between two `WATCHDOG=1` keep-alives from a healthy main loop
/// (`WatchdogSec=` must be well above it).
pub const WATCHDOG_PING: Duration = Duration::from_secs(1);
/// Longest sleep of the main loop (signal / stop latency).
const MAX_WAIT: Duration = Duration::from_millis(50);

/// The state a consumer should show for a `status.json` read at
/// `now_mono_ms` (`CLOCK_MONOTONIC`, ms; see [`crate::notify::monotonic_ms`])
/// on the boot `boot_id`: the file's `state`, unless the daemon is not
/// running, the status is from another boot, it is older than its
/// `stale_after_ms`, or a field is missing or malformed, in which case
/// [`State::Unknown`].
pub fn effective_state(status: &serde_json::Value, now_mono_ms: u64, boot_id: &str) -> State {
    let fresh = status["running"].as_bool() == Some(true)
        && status["boot_id"].as_str() == Some(boot_id)
        && match (
            status["updated_mono_ms"].as_u64(),
            status["stale_after_ms"].as_u64(),
        ) {
            (Some(at), Some(stale)) => now_mono_ms.saturating_sub(at) <= stale,
            _ => false,
        };
    if !fresh {
        return State::Unknown;
    }
    match status["state"].as_str() {
        Some("ok") => State::Ok,
        Some("degraded") => State::Degraded,
        _ => State::Unknown,
    }
}

/// Daemon counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DaemonStats {
    pub datagrams: u64,
    pub events: u64,
    /// Decoded low-level joint frames handed to the agent's joint firewall
    /// (with their command; also counted in `motion_events`).
    pub joint_frames: u64,
    /// Motion commands / feedback decoded from datagrams and handed to the
    /// agent.
    pub motion_events: u64,
    pub outcomes: u64,
    pub findings_spooled: u64,
    /// Outcomes whose finding could not be built/validated.
    pub finding_errors: u64,
    pub health_findings: u64,
    pub ticks: u64,
    pub heartbeats: u64,
    /// Heartbeat / status notes the black box did not take.
    pub note_errors: u64,
    pub max_queue_age_ms: u64,
    /// Correlated findings (`robot.correlate.*`) handed to the agent.
    pub correlated_findings: u64,
    /// `head.json` high-water marks written by the housekeeping timer.
    pub head_marks: u64,
    /// High-water marks the timer could not write.
    pub head_mark_errors: u64,
    /// Pulsar threats taken from the host-threat socket (finding + signal).
    pub host_threats: u64,
    /// In-path gateway findings taken from the gateway feed.
    pub gateway_findings: u64,
    /// Gateway decision summaries recorded in the black box (T19).
    pub gateway_summaries: u64,
    /// Gateway decision summaries the black box could not take.
    pub gateway_summary_errors: u64,
    /// Gateway lines folded by the feed limit (recorded in the black box,
    /// reported in an aggregate; `crate::gateway_feed`, T82).
    pub gateway_folded: u64,
    /// Aggregates of folded gateway lines reported.
    pub gateway_aggregates: u64,
    /// Forwarder heartbeats received.
    pub host_heartbeats: u64,
    /// In-path gateway feed heartbeats received.
    pub gateway_heartbeats: u64,
    /// Host threats of `robodr-sensor-ros2` dropped (seen via the pipeline).
    pub host_threats_own_skipped: u64,
}

/// Why the daemon stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// `should_stop()` (a signal).
    Requested,
    /// `exit_when_inputs_end` and every input ended.
    InputsEnded,
}

/// What a run produced.
#[derive(Debug, Clone)]
pub struct Summary {
    pub reason: StopReason,
    pub stats: DaemonStats,
    pub agent: AgentStats,
    pub pipeline: PipelineStats,
    pub spool: SpoolStats,
    pub last_state: HealthState,
    /// The black box's final seal (also in `<spool>/checkpoint.json`).
    pub finished: Finished,
}

/// The daemon could not start or stop cleanly.
#[derive(Debug)]
pub enum DaemonError {
    Config(String),
    Io(String),
    Agent(robodr_agent::AgentError),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::Config(m) | DaemonError::Io(m) => f.write_str(m),
            DaemonError::Agent(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// The production clock shared by the daemon and the agent (one monotonic
/// origin, so the agent's time guard never sees two clocks).
#[derive(Clone)]
struct SharedClock(Arc<SystemClock>);

impl Clock for SharedClock {
    fn now(&self) -> Timestamp {
        self.0.now()
    }
}

/// An input thread's body, given its feed.
type InputBody = Box<dyn FnOnce(Feed) + Send>;

/// How an input feeds the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputKind {
    Capture,
    Spdp,
    Events,
}

struct InputHandle {
    name: String,
    kind: InputKind,
    stats: Arc<InputStats>,
    thread: Option<JoinHandle<()>>,
    /// Join at shutdown (false for stdin).
    joinable: bool,
    /// `Pipeline::finish` etc. already done for its end.
    end_handled: bool,
}

#[derive(Serialize)]
struct InputStatus<'a> {
    name: &'a str,
    received: u64,
    dropped: u64,
    budget_drops: u64,
    malformed: u64,
    rejected_connections: u64,
    /// Open connections (socket inputs).
    connections: u64,
    /// Items the producer reported lost before they reached this input.
    upstream_dropped: u64,
    last_rx_age_ms: Option<u64>,
    ended: bool,
    end_error: Option<String>,
}

/// The black box's external high-water-mark anchor, as configured.
#[derive(Serialize)]
struct BlackboxStatus {
    /// An external head anchor is configured. `false` = a cut of the
    /// newest records plus a rolled-back `head.json`, or a wiped store,
    /// cannot be detected on the unit. Never `true` without one.
    anchored: bool,
    /// `"none"` or the configured kind (`"file"`).
    anchor_kind: &'static str,
    /// Failed anchor reads/writes by the current recorder.
    anchor_failures: u64,
    /// `head.json` marks the current recorder could not write.
    mark_failures: u64,
}

#[derive(Serialize)]
struct Status<'a> {
    /// The safety state plans are graded by right now.
    safety_state: SafetyState,
    /// The live feed's view (absent without `safety_feed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    safety_feed: Option<FeedStatus>,
    kind: &'static str,
    robot_id: &'a str,
    wall_ms: u64,
    uptime_ms: u64,
    /// `CLOCK_MONOTONIC` (ms) when this status was written.
    updated_mono_ms: u64,
    boot_id: &'a str,
    /// Older than this (by `CLOCK_MONOTONIC`) = stale = unknown.
    stale_after_ms: u64,
    running: bool,
    #[serde(flatten)]
    health: &'a HealthState,
    profile_status: &'a str,
    inputs: Vec<InputStatus<'a>>,
    daemon: &'a DaemonStats,
    pipeline: &'a PipelineStats,
    agent: AgentStats,
    spool: SpoolStats,
    /// Discovery-flood aggregation (red team F1, [`crate::flood`]).
    discovery_flood: crate::flood::FloodStats,
    /// Correlation engine counters (absent when correlation is disabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    correlation: Option<robodr_correlate::Stats>,
    /// Findings carry a `robodr-finding-sig` signature.
    signs_findings: bool,
    evidence_degraded: bool,
    /// Black-box anchoring (see `blackbox.head_anchor`).
    blackbox: BlackboxStatus,
    queue_bytes: usize,
    queue_bytes_max: usize,
    /// The control-plane API's counters (absent when it is off).
    #[serde(skip_serializing_if = "Option::is_none")]
    control_plane: Option<ControlStatus>,
    /// executor v1 link counters (absent when the executor is off).
    #[serde(skip_serializing_if = "Option::is_none")]
    executor: Option<crate::executor_link::LinkStats>,
    /// How each private key is protected at rest (T66): TPM-sealed or the
    /// flagged file fallback.
    key_protection: &'a crate::key_protection::KeyReport,
    /// Early-warning probes (sales-readiness T5 - T7, T40, T41).
    self_health: &'a SelfView,
}

/// What the early-warning probes saw at the last tick (`status.json`
/// `self_health`; the health record carries the same values).
#[derive(Debug, Clone, Default, Serialize)]
struct SelfView {
    /// Health records emitted so far, and the period (0: off).
    health_records: u64,
    health_record_ms: u64,
    clock: robodr_ocsf::ClockHealth,
    disks: Vec<robodr_ocsf::DiskHealth>,
    /// Certificate `notAfter` / CRL `nextUpdate`, with `days_to_expiry`.
    credentials: Vec<robodr_ocsf::CredentialExpiry>,
    reachability: Vec<robodr_ocsf::Reachability>,
}

/// The agent's view of the profile: what the pipeline enforces. A profile
/// the pipeline refuses to enforce (file check failed) runs observe-only in
/// the agent too; a profile that fails validation is replaced by an empty,
/// unlocked profile (everything is reported, observe-only, nothing acted
/// upon), so the daemon stays useful instead of blind.
pub fn agent_profile(pipeline: &Pipeline) -> Profile {
    match pipeline.status() {
        ProfileStatus::Enforcing | ProfileStatus::Observing => pipeline.profile().clone(),
        ProfileStatus::FileRejected(_) => Profile {
            locked: false,
            ..pipeline.profile().clone()
        },
        ProfileStatus::Refused(_) => Profile {
            model: UNVALIDATED_MODEL.into(),
            locked: false,
            ..Profile::default()
        },
    }
}

struct Daemon<'a> {
    r: &'a Resolved,
    log: &'a mut dyn Write,
    epoch: Instant,
    clock: SharedClock,
    pipeline: Pipeline,
    agent: Agent,
    spool: Spool,
    inputs: Vec<InputHandle>,
    capture_health: SharedHealth,
    rx: Receiver<Msg>,
    stop_inputs: Arc<AtomicBool>,
    /// The latest status (the bytes of `status.json`), served on
    /// `spool.status_socket`.
    status_snapshot: Arc<std::sync::Mutex<Arc<Vec<u8>>>>,
    status_server: Option<std::thread::JoinHandle<()>>,
    budget: Arc<QueueBudget>,
    /// Every sender of the queue is gone (all input threads exited).
    inputs_gone: bool,
    notifier: Notifier,
    /// The live safety-state feed, if configured.
    feed: Option<SafetyFeed>,
    /// Identity counters last handed to the agent / feed.
    identity_seen: robodr_ros2_pipeline::IdentityStats,
    health: HealthMonitor,
    last_state: HealthState,
    stats: DaemonStats,
    /// Largest queue latency since the last tick.
    tick_max_age_ms: u64,
    /// The enforced locked profile's anti-rollback record, re-recorded in
    /// every heartbeat (see [`crate::profile_chain`]).
    profile_accepted: Option<robodr_commission::trust::AcceptedState>,
    /// The correlation engine (`None` = disabled).
    correlator: Option<Correlator>,
    /// Discovery-flood aggregation of pipeline findings ([`crate::flood`]).
    flood: crate::flood::FloodGuard,
    /// The gateway feed's flood limit ([`crate::gateway_feed::FeedLimiter`]).
    gateway_limit: crate::gateway_feed::FeedLimiter,
    /// `groups_evicted + groups_refused` at the last pressure report.
    correlation_pressure_reported: u64,
    /// When the last pressure finding was raised (daemon ms).
    correlation_pressure_at_ms: Option<u64>,
    /// Recorder generation (`AgentStats::blackbox_reopens`) whose open
    /// incidents were last reported.
    incidents_reported: Option<u64>,
    /// `blackbox.retention` pressure / unexported-drop findings (T15).
    retention_watch: crate::retention::RetentionWatch,
    /// Per input: the forwarder's cumulative `dropped` at its last
    /// heartbeat (host-threat inputs only).
    host_upstream_seen: Vec<u64>,
    /// The control-plane API (`None` = off).
    control: Option<ControlPlane>,
    /// Control-plane counters at their last finding, and when it was raised
    /// (unauthenticated, invalid).
    control_reported: [u64; 2],
    control_reported_at_ms: [Option<u64>; 2],
    /// The control-plane journals' heads last recorded in the black box
    /// (gap 1: [`crate::control::anchor`]).
    state_heads_recorded: Option<crate::control::anchor::StateHeads>,
    /// The black-box segment that holds the newest head note, and the one
    /// the latest heartbeat went to (review of gap 1, finding 3: a head
    /// note is re-recorded whenever the black box moved to a new segment,
    /// so a cyclic store never ages every one of them out).
    state_heads_segment: Option<u64>,
    last_note_segment: Option<u64>,
    /// The executor journal head last recorded, and its segment (findings
    /// 1 and 2).
    executor_head_recorded: Option<(robodr_executor::journal::JournalHead, u64)>,
    /// executor v1: requests whose failed revert was reported (one finding
    /// per request until a revert of it succeeds).
    revert_failed_reported: std::collections::BTreeSet<String>,
    /// executor v1: the link to robodr-executor (`None` = off).
    executor: Option<crate::executor_link::ExecutorLink>,
    /// Early warnings: credential expiry, clock, disk, executor
    /// reachability ([`crate::selfcheck`]).
    warnings: crate::selfcheck::Warnings,
    /// What the early-warning probes saw at the last tick (`status.json`
    /// `self_health`, the health record).
    self_view: SelfView,
    /// Health records emitted, and when the last one was (daemon ms).
    health_records: u64,
    health_record_at_ms: u64,
    /// The packet timeline of a pcap replay (`None` for a live capture:
    /// handling time is the observation time there).
    replay: Option<ReplayTimeline>,
}

/// A replayed capture's packet timeline on the daemon's clocks.
///
/// The first replayed packet with a timestamp anchors the capture's clock
/// to the daemon's (monotonic ns and `Instant` at that moment); every
/// later packet is placed at `anchor + (its timestamp - the first's)`,
/// independent of when the daemon gets to handle it. Out-of-order or
/// earlier records (merged interfaces, a stepped capture clock) are held at
/// the latest position: the timeline never goes back.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ReplayTimeline {
    /// (capture ns, daemon mono ns, `Instant`) of the first timestamped
    /// packet.
    origin: Option<(u64, u64, Instant)>,
    /// Offset of the latest position from the anchor (ns).
    offset: u64,
}

impl ReplayTimeline {
    /// Place a packet captured at `captured_ns` (record time); `mono_now`
    /// and `instant_now` anchor the timeline on the first call. Returns
    /// the packet's position (daemon mono ns).
    fn place(&mut self, captured_ns: u64, mono_now: u64, instant_now: Instant) -> u64 {
        let (c0, m0, _) = *self
            .origin
            .get_or_insert((captured_ns, mono_now, instant_now));
        self.offset = self.offset.max(captured_ns.saturating_sub(c0));
        m0.saturating_add(self.offset)
    }

    /// The current position (daemon mono ns), once anchored.
    fn position(&self) -> Option<u64> {
        self.origin.map(|(_, m0, _)| m0.saturating_add(self.offset))
    }

    /// The current position as an `Instant` (the pipeline's clock), once
    /// anchored.
    fn instant(&self) -> Option<Instant> {
        self.origin.map(|(_, _, i0)| {
            i0.checked_add(Duration::from_nanos(self.offset))
                .unwrap_or(i0)
        })
    }
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Build everything, run until stopped, shut down in order.
/// `sd_notify` goes to `NOTIFY_SOCKET` from the environment, if set.
pub fn run(
    r: &Resolved,
    should_stop: &dyn Fn() -> bool,
    log: &mut dyn Write,
) -> Result<Summary, DaemonError> {
    run_with(r, should_stop, log, Notifier::from_env())
}

/// [`run`] with an explicit `sd_notify` target.
pub fn run_with(
    r: &Resolved,
    should_stop: &dyn Fn() -> bool,
    log: &mut dyn Write,
    notifier: Notifier,
) -> Result<Summary, DaemonError> {
    let mut d = Daemon::start(r, log, notifier)?;
    d.notifier.notify("READY=1\nSTATUS=started");
    let reason = d.main_loop(should_stop);
    d.notifier.notify("STOPPING=1");
    d.shutdown(reason)
}

impl<'a> Daemon<'a> {
    fn start(
        r: &'a Resolved,
        log: &'a mut dyn Write,
        notifier: Notifier,
    ) -> Result<Self, DaemonError> {
        let epoch = Instant::now();
        let clock = SharedClock(Arc::new(SystemClock::new(TimeSource::Unknown)));
        let cfg = &r.config;
        for w in &r.warnings {
            let _ = writeln!(log, "robodr-agentd: warning: {}", sanitize(w));
        }
        // Create the black-box and spool directories (0700, as the recorder
        // and the spool would) and re-check that they are apart on their
        // canonical paths: a symlink or `..` the configuration check could
        // not see (created since, or racing) must not alias them.
        for d in [&cfg.blackbox.dir, &cfg.spool.dir] {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(d)
                .map_err(|e| DaemonError::Io(format!("creating {}: {e}", d.display())))?;
        }
        check_daemon_dirs(cfg, r.sensor.profile_trust.state_file.as_deref(), |p| {
            match std::fs::canonicalize(p) {
                Ok(c) => Ok(c),
                // The state directory may not exist yet.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(resolve_path(p)),
                Err(e) => Err(format!("{}: {e}", p.display())),
            }
        })
        .map_err(DaemonError::Config)?;
        // Persist the anti-rollback state the accepted profile implies
        // before enforcing it; if that fails, do not enforce (fail closed).
        let mut loaded = r.profile.clone();
        if let (Some(c), Ok(())) = (&r.profile_state_commit, &loaded.file_check) {
            if let Err(e) = c.commit() {
                loaded.file_check = Err(e);
            }
        }
        let accepted_ok = loaded.file_check.is_ok();
        // The agent evaluates decoded commands itself (with evidence); see
        // the module docs.
        let mut popts = r.sensor.pipeline.clone();
        popts.motion.evaluate_commands = false;
        let pipeline = Pipeline::from_loaded(loaded, popts);
        if let Some(m) = pipeline.status_message() {
            let _ = writeln!(log, "robodr-agentd: warning: {m}");
        }

        // The agent.
        let profile = agent_profile(&pipeline);
        let validated = !matches!(pipeline.status(), ProfileStatus::Refused(_));
        let context = OperationalContext {
            platform: r.policy.platform,
            morphology: r.policy.morphology,
            phase: cfg.context.phase,
            connectivity: cfg.context.connectivity,
            control: cfg.context.control,
            operator_present: cfg.context.operator_present,
            profile_locked: profile.locked,
        };
        let robot = RobotInfo {
            id: cfg.robot.id.clone(),
            model: cfg
                .robot
                .model
                .clone()
                .unwrap_or_else(|| profile.model.clone()),
            platform_family: OcsfPlatform::LinuxRos2,
            site: cfg.robot.site.clone(),
            firmware: None,
        };
        let mut bcfg = RecorderConfig::new(&cfg.blackbox.dir, &cfg.robot.id, &r.boot_id);
        if let Some(ret) = &cfg.blackbox.retention {
            // T15: the configured retention must fit on the black box's
            // filesystem (the nearest existing directory, before the first
            // start creates it).
            let fs_dir = cfg
                .blackbox
                .dir
                .ancestors()
                .find(|d| d.is_dir())
                .unwrap_or(&cfg.blackbox.dir);
            ret.check_space(
                crate::retention::segments_bytes(&cfg.blackbox.dir),
                crate::control::evidence::free_bytes(fs_dir),
            )
            .map_err(DaemonError::Config)?;
            ret.apply(&mut bcfg);
        }
        match &cfg.blackbox.head_anchor {
            Some(crate::config::HeadAnchorConfig::File { path }) => {
                let a = robodr_blackbox::FileHeadAnchor::new(path)
                    .map_err(|e| DaemonError::Config(format!("blackbox.head_anchor: {e}")))?;
                bcfg.head_anchor = Some(Arc::new(a));
            }
            Some(a @ crate::config::HeadAnchorConfig::TpmNvCounter { .. }) => {
                let bad = |e: String| DaemonError::Config(format!("blackbox.head_anchor: {e}"));
                let tc = a
                    .tpm_config()
                    .unwrap_or_else(|| Err("not a TPM anchor".into()))
                    .map_err(bad)?;
                // The sidecar is signed with the black-box key.
                let signer =
                    crate::config::signer_for(&r.key_algorithm, &r.key, r.key_id.as_deref())
                        .map_err(bad)?;
                let mut a = robodr_blackbox::TpmNvCounterAnchor::new(&tc, signer)
                    .map_err(|e| bad(e.to_string()))?;
                // Only to name a sidecar left under a retired key in the
                // error: such a sidecar is refused (re-sign it with
                // `robodr-blackbox rotate --tpm-sidecar`).
                if let Some(p) = &r.previous_keys {
                    a = a.with_previous_keys(p.clone());
                }
                bcfg.head_anchor = Some(Arc::new(a));
            }
            Some(a @ crate::config::HeadAnchorConfig::Remote { .. }) => {
                let bad = |e: String| DaemonError::Config(format!("blackbox.head_anchor: {e}"));
                let (rc, rkey) = a
                    .remote_config(&cfg.robot.id)
                    .unwrap_or_else(|| Err("not a remote anchor".into()))
                    .map_err(bad)?;
                // Marks are signed with the black-box key.
                let signer =
                    crate::config::signer_for(&r.key_algorithm, &r.key, r.key_id.as_deref())
                        .map_err(bad)?;
                let a = robodr_blackbox::RemoteHeadAnchor::new(rc, Box::new(rkey), signer)
                    .map_err(|e| bad(e.to_string()))?;
                bcfg.head_anchor = Some(Arc::new(a));
            }
            // Never claim anchoring without one (status: anchored false).
            None => {}
        }
        let mut acfg = AgentConfig::new(robot, profile, r.policy.clone(), context, bcfg);
        acfg.profile_version = robodr_commission::trust::version_label(
            pipeline.profile(),
            pipeline.status() == &ProfileStatus::Enforcing,
        );
        acfg.attestation = AttestationStatus::Unknown;
        acfg.kafka_partitions = cfg.robot.kafka_partitions;
        acfg.findings_topic = cfg.findings.topic.clone();
        acfg.data_source = cfg.findings.data_source.clone();
        acfg.max_contract_minor = cfg.findings.max_contract_minor;
        match (&cfg.firewall, validated) {
            (Some(fw), true) => {
                // Low-level joint channels (Unitree LowCmd) come with the
                // file's platform (morphology, hold time, ...).
                let joint = r
                    .firewall_joint
                    .as_ref()
                    .map(|fc| fc.joint_channels.clone())
                    .unwrap_or_default();
                let mut fs = FirewallSettings::from_profile_and_joints(
                    &acfg.profile,
                    &fw.allow,
                    &fw.max_angular,
                    joint,
                )
                .map_err(DaemonError::Agent)?;
                if let Some(fc) = &r.firewall_joint {
                    fs.platform = fc.platform;
                }
                // Not inline: verdicts are recorded would-haves only.
                fs.platform.fail_behaviour = FailBehaviour::PassThroughObserveOnly;
                acfg.firewall = Some(fs);
            }
            (Some(_), false) => {
                let _ = writeln!(
                    log,
                    "robodr-agentd: warning: firewall disabled: the profile failed validation"
                );
            }
            (None, _) => {}
        }
        if let (Some(mc), Some(m)) = (&r.monitor, &cfg.motion_monitor) {
            let mut ms = MonitorSettings::new(mc.clone());
            ms.feedback_sources = m.feedback_sources.clone();
            acfg.monitor = Some(ms);
        }
        let signer = crate::config::signer_for(&r.key_algorithm, &r.key, r.key_id.as_deref())
            .map_err(|e| DaemonError::Config(format!("black-box key: {e}")))?;
        // Records signed before an in-place key rotation verify under
        // `blackbox.previous_keys`; without the key that signed a retained
        // record the black box is refused (fail closed), with the remedy.
        let mut agent = Agent::new_with_keys(
            acfg,
            signer,
            None,
            r.previous_keys.clone(),
            Box::new(clock.clone()),
        )
        .map_err(|e| match e {
            robodr_agent::AgentError::BlackBox(b) if b.to_string().contains("previous key") => {
                DaemonError::Config(format!(
                    "black box {}: {b}. If the black-box key was rotated, list the retired \
                     key's public file in blackbox.previous_keys (OPERATIONS 4.3)",
                    cfg.blackbox.dir.display()
                ))
            }
            e => DaemonError::Agent(e),
        })?;
        if let Some((key, key_id)) = &r.finding_key {
            let fs = crate::config::signer_for(
                robodr_blackbox::sign_ed25519::ED25519,
                key,
                Some(key_id),
            )
            .map_err(|e| DaemonError::Config(format!("finding key: {e}")))?;
            agent = agent.with_finding_signer(fs).map_err(DaemonError::Agent)?;
        }
        // executor v1 (off unless `executor.enabled`): the link to the
        // separate robodr-executor process; the planner's eligible steps go
        // to it when `planner_orders` is set.
        let executor = match &r.executor {
            None => None,
            Some(spec) => {
                // Review of gap 1 (findings 1 and 2): the newest executor
                // journal head the black box holds goes back to the
                // executor with every event poll (an older journal put back
                // is reset there).
                let bb_signer =
                    crate::config::signer_for(&r.key_algorithm, &r.key, r.key_id.as_deref())
                        .map_err(|e| DaemonError::Config(format!("black-box key: {e}")))?;
                let (anchor, unverified) = crate::control::anchor::latest_executor_head(
                    &crate::control::evidence::DirSource(agent.blackbox_dir().to_path_buf()),
                    &cfg.robot.id,
                    bb_signer.as_ref(),
                )
                .map_err(|e| {
                    DaemonError::Io(format!(
                        "executor: reading the black box for the executor's journal head: {e}"
                    ))
                })?;
                if unverified > 0 {
                    let _ = writeln!(
                        log,
                        "robodr-agentd: executor: {unverified} executor journal head note(s) in \
                         the black box do not verify under the current key: ignored"
                    );
                }
                let link = crate::executor_link::ExecutorLink::start_anchored(
                    spec,
                    crate::executor_link::SafetyCell::default(),
                    anchor,
                )
                .map_err(DaemonError::Io)?;
                if link.planner_orders {
                    agent =
                        agent.with_executor(Box::new(link.planner_executor(r.policy.morphology)));
                }
                let _ = writeln!(
                    log,
                    "robodr-agentd: executor v1 enabled ({}): accepted requests{} are handed \
                     to robodr-executor",
                    spec.socket.display(),
                    if link.planner_orders {
                        " and eligible plan steps"
                    } else {
                        ""
                    }
                );
                Some(link)
            }
        };
        let correlator = r
            .correlation
            .clone()
            .map(|rules| Correlator::new(rules, Limits::default()));

        let spool = Spool::open(&cfg.spool.dir, cfg.spool.max_bytes, cfg.spool.max_files)
            .map_err(|e| DaemonError::Io(format!("spool {}: {e}", cfg.spool.dir.display())))?;

        // The control plane (before the input threads: a bind failure then
        // leaves nothing running). Answers and evidence manifests are signed
        // with the finding key (required with control_plane, config.rs).
        let control = match &r.control_plane {
            None => None,
            Some(spec) => {
                let Some((key, key_id)) = &r.finding_key else {
                    return Err(DaemonError::Config(
                        "control_plane needs finding_signing: every answer is signed with the \
                         finding key"
                            .into(),
                    ));
                };
                let signer = crate::config::signer_for(
                    robodr_blackbox::sign_ed25519::ED25519,
                    key,
                    Some(key_id),
                )
                .map_err(|e| DaemonError::Config(format!("finding key: {e}")))?;
                let bb_dir = agent.blackbox_dir().to_path_buf();
                let robot = cfg.robot.id.clone();
                // Gap 1: the journals are sealed under a key derived from
                // the black-box key and compared with the newest head the
                // black box holds for them.
                let seal_key = crate::control::journal::Sealing::derive_key(&r.key.0)
                    .map_err(DaemonError::Config)?;
                let bb_signer =
                    crate::config::signer_for(&r.key_algorithm, &r.key, r.key_id.as_deref())
                        .map_err(|e| DaemonError::Config(format!("black-box key: {e}")))?;
                // Review of gap 1, finding 6: only authentic notes settle a
                // decision.
                let reconcile = |ids: &[String]| {
                    crate::control::evidence::find_decision_notes(
                        &crate::control::evidence::DirSource(bb_dir.clone()),
                        &robot,
                        ids,
                        bb_signer.as_ref(),
                    )
                };
                let anchors = crate::control::anchor::latest(
                    &crate::control::evidence::DirSource(bb_dir.clone()),
                    &robot,
                    bb_signer.as_ref(),
                )
                .map_err(|e| {
                    DaemonError::Io(format!(
                        "control plane: reading the black box for the state heads: {e}"
                    ))
                })?;
                if anchors.unverified > 0 {
                    let _ = writeln!(
                        log,
                        "robodr-agentd: control plane: {} state head note(s) in the black box \
                         do not verify under the current key (another key, or tampered): ignored",
                        anchors.unverified
                    );
                }
                let mut cp = ControlPlane::start(
                    spec,
                    &cfg.robot.id,
                    signer,
                    &bb_dir,
                    &reconcile,
                    seal_key,
                    &anchors,
                    bb_signer.as_ref(),
                )
                .map_err(DaemonError::Io)?;
                // executor v1: accepted requests go to robodr-executor; the
                // requests restored from the journal keep the executor's
                // last journalled word.
                if let Some(link) = &executor {
                    cp.engine
                        .set_executor(Box::new(link.control_executor(r.policy.morphology)));
                    // What happened while agentd was down (a TTL lifted, a
                    // pending order verified): asked once, journalled as
                    // the answers come in.
                    link.resync(cp.engine.open_executor_requests());
                }
                let st = cp.state_status().clone();
                let _ =
                    writeln!(
                    log,
                    "robodr-agentd: control plane ({}) on {} ({} SOC key(s){}{}); requests are \
                     judged and recorded, {}; state: {} request(s) restored, \
                     {} dangling decision(s) settled from the black box",
                    crate::control::auth::API_VERSION,
                    cp.status().listening.join(", "),
                    spec.keys.len(),
                    if spec.tls.is_some() { ", mutual TLS" } else { "" },
                    if spec.evidence.is_some() { ", evidence API" } else { "" },
                    if executor.is_some() {
                        "accepted ones are handed to robodr-executor (executor v1)"
                    } else {
                        "never executed"
                    },
                    st.restored,
                    st.resolved_committed + st.resolved_aborted,
                );
                if st.journal_damaged > 0 || st.replay.damaged > 0 {
                    let _ = writeln!(
                        log,
                        "robodr-agentd: control plane: the state journals were damaged \
                         ({} request entr(ies), {} nonce entr(ies) skipped; copy in {}); \
                         requests signed before this start are refused",
                        st.journal_damaged,
                        st.replay.damaged,
                        st.journal_quarantined.as_deref().unwrap_or("quarantine/")
                    );
                }
                if st.rebuilt_from_blackbox + st.rebuilt_reverts + st.lost_request_ids > 0 {
                    let _ = writeln!(
                        log,
                        "robodr-agentd: control plane: request journal rebuilt from the black \
                         box: {} request(s), {} revert record(s) restored, {} request id(s) \
                         unreadable (refused)",
                        st.rebuilt_from_blackbox, st.rebuilt_reverts, st.lost_request_ids
                    );
                }
                if let Some(why) = &st.refusing_new_request_ids {
                    let _ = writeln!(
                        log,
                        "robodr-agentd: control plane: {why}: every new request id is refused \
                         until a restart reconciles the journal"
                    );
                }
                if let Some(f) = st.replay.fence {
                    let _ = writeln!(
                        log,
                        "robodr-agentd: control plane: replay store fenced at {f}: requests \
                         signed at or before it are refused"
                    );
                }
                Some(cp)
            }
        };

        // Inputs.
        let (tx, rx) = sync_channel::<Msg>(cfg.daemon.queue_capacity);
        let budget = QueueBudget::new(cfg.daemon.queue_bytes);
        let stop_inputs = Arc::new(AtomicBool::new(false));
        let capture_health = SharedHealth::new();
        let mut inputs: Vec<InputHandle> = Vec::new();
        let mut add = |name: String, kind: InputKind, joinable: bool| {
            let stats = Arc::new(InputStats::default());
            let feed = Feed::with_budget(
                tx.clone(),
                inputs.len(),
                stats.clone(),
                epoch,
                budget.clone(),
            );
            inputs.push(InputHandle {
                name,
                kind,
                stats,
                thread: None,
                joinable,
                end_handled: false,
            });
            feed
        };
        let mut spawns: Vec<(Feed, InputBody)> = Vec::new();
        if let Some(cap) = &r.sensor.capture {
            let name = match &cap.input {
                CaptureInput::Live { interfaces } if interfaces.is_empty() => {
                    "capture:any".to_string()
                }
                CaptureInput::Live { interfaces } => format!("capture:{}", interfaces.join(",")),
                CaptureInput::Replay { .. } => "pcap".to_string(),
            };
            let src = cap.open(stop_inputs.clone()).map_err(|e| {
                DaemonError::Io(format!(
                    "opening {name}: {} (live capture needs CAP_NET_RAW)",
                    sanitize(&e.to_string())
                ))
            })?;
            let feed = add(name, InputKind::Capture, true);
            let health = capture_health.clone();
            spawns.push((
                feed,
                Box::new(move |f| input::run_datagram_source(src, health, f)),
            ));
        }
        if let Some(spdp) = r.sensor.spdp {
            let sock = robodr_ros2_pipeline::socket::bind_spdp_multicast(
                spdp.group,
                spdp.port,
                spdp.interface,
            )
            .and_then(|s| {
                s.set_nonblocking(false)?;
                s.set_read_timeout(Some(Duration::from_millis(500)))?;
                Ok(s)
            })
            .map_err(|e| {
                DaemonError::Io(format!(
                    "SPDP socket {}:{}: {e} (set sensor.listen_spdp = false to use capture only)",
                    spdp.group, spdp.port
                ))
            })?;
            let feed = add(format!("spdp:{}", spdp.port), InputKind::Spdp, true);
            let stop = stop_inputs.clone();
            spawns.push((feed, Box::new(move |f| input::run_udp(sock, stop, f))));
        }
        for ei in &cfg.event_inputs {
            match ei {
                EventInputConfig::Stdin => {
                    let feed = add("stdin".into(), InputKind::Events, false);
                    let stop = stop_inputs.clone();
                    spawns.push((feed, Box::new(move |f| input::run_stdin(stop, f))));
                }
                EventInputConfig::UnixSocket {
                    path,
                    max_connections,
                } => {
                    let l = input::bind_event_socket(path).map_err(|e| {
                        DaemonError::Io(format!("event socket {}: {e}", path.display()))
                    })?;
                    let feed = add(
                        format!("socket:{}", path.display()),
                        InputKind::Events,
                        true,
                    );
                    let (stop, max) = (stop_inputs.clone(), *max_connections);
                    spawns.push((
                        feed,
                        Box::new(move |f| input::run_unix_listener(l, max, stop, f)),
                    ));
                }
            }
        }
        let feed = r.safety_feed.clone().map(SafetyFeed::new);
        if let Some(sock) = r.safety_feed.as_ref().and_then(|f| f.socket.as_ref()) {
            // Review L-D: never the exporters' group as a feeder group.
            sock.check_feeder_groups(crate::host::group_gid(
                std::path::Path::new("/etc/group"),
                "robodr",
            ))
            .map_err(DaemonError::Config)?;
            let l = input::bind_socket(&sock.path, sock.mode, sock.group).map_err(|e| {
                DaemonError::Io(format!("safety socket {}: {e}", sock.path.display()))
            })?;
            let input_feed = add(
                format!("safety:{}", sock.path.display()),
                InputKind::Events,
                true,
            );
            let (stop, max) = (stop_inputs.clone(), sock.max_connections);
            // Review H1: only root, this daemon's uid and the configured
            // feeders may report a safety state (never another service).
            let policy = sock.peer_policy(crate::config::effective_uid());
            spawns.push((
                input_feed,
                Box::new(move |f| {
                    input::run_unix_listener_peers(
                        l,
                        max,
                        stop,
                        f,
                        input::parse_safety_line,
                        Some(policy),
                    )
                }),
            ));
        }
        if let Some(h) = &r.host_threats {
            let l =
                crate::host::bind_host_socket(h, crate::config::effective_uid()).map_err(|e| {
                    DaemonError::Io(format!("host_threats socket {}: {e}", h.path.display()))
                })?;
            let input_feed = add(
                format!("host:{}", h.path.display()),
                InputKind::Events,
                true,
            );
            let (stop, max, allowed) = (
                stop_inputs.clone(),
                h.max_connections,
                h.allowed_uids.clone(),
            );
            spawns.push((
                input_feed,
                Box::new(move |f| {
                    input::run_unix_listener_peers(
                        l,
                        max,
                        stop,
                        f,
                        crate::host::parse_host_line,
                        Some(input::PeerPolicy::uids(allowed)),
                    )
                }),
            ));
        }
        if let Some(h) = &r.gateway_feed {
            let l =
                crate::host::bind_host_socket(h, crate::config::effective_uid()).map_err(|e| {
                    DaemonError::Io(format!("gateway_feed socket {}: {e}", h.path.display()))
                })?;
            let input_feed = add(
                format!("gateway:{}", h.path.display()),
                InputKind::Events,
                true,
            );
            let (stop, max, allowed) = (
                stop_inputs.clone(),
                h.max_connections,
                h.allowed_uids.clone(),
            );
            spawns.push((
                input_feed,
                Box::new(move |f| {
                    input::run_unix_listener_peers(
                        l,
                        max,
                        stop,
                        f,
                        crate::gateway_feed::parse_gateway_line,
                        Some(input::PeerPolicy::uids(allowed)),
                    )
                }),
            ));
        }
        // The status socket (review H1): the robot's safety state, from this
        // process alone, for robodr-deliverd (which checks SO_PEERCRED).
        let status_snapshot: Arc<std::sync::Mutex<Arc<Vec<u8>>>> = Arc::default();
        let status_server = match &cfg.spool.status_socket {
            None => None,
            Some(p) => {
                let l = input::bind_event_socket(p)
                    .map_err(|e| DaemonError::Io(format!("status socket {}: {e}", p.display())))?;
                let (stop, snap) = (stop_inputs.clone(), status_snapshot.clone());
                Some(
                    std::thread::Builder::new()
                        .name("agentd-status".into())
                        .spawn(move || serve_status(l, stop, snap))
                        .map_err(|e| DaemonError::Io(format!("spawning status thread: {e}")))?,
                )
            }
        };
        drop(tx);
        for (i, (feed, body)) in spawns.into_iter().enumerate() {
            let h = std::thread::Builder::new()
                .name(format!("agentd-in-{i}"))
                .spawn(move || body(feed))
                .map_err(|e| DaemonError::Io(format!("spawning input thread: {e}")))?;
            if let Some(input) = inputs.get_mut(i) {
                input.thread = Some(h);
            }
        }

        let health = HealthMonitor::new(
            HealthConfig {
                silence_ms: cfg.daemon.silence_ms,
                lag_ms: cfg.daemon.lag_ms,
                report_ms: cfg.daemon.health_report_ms,
                ends_expected: cfg.daemon.exit_when_inputs_end,
            },
            inputs.len(),
        );
        let mut d = Self {
            r,
            log,
            epoch,
            clock,
            pipeline,
            agent,
            spool,
            inputs,
            capture_health,
            rx,
            stop_inputs,
            budget,
            inputs_gone: false,
            notifier,
            feed,
            identity_seen: Default::default(),
            health,
            last_state: HealthState {
                state: State::Unknown,
                reasons: vec!["starting".into()],
            },
            stats: DaemonStats::default(),
            tick_max_age_ms: 0,
            profile_accepted: None,
            correlator,
            flood: crate::flood::FloodGuard::default(),
            gateway_limit: crate::gateway_feed::FeedLimiter::default(),
            correlation_pressure_reported: 0,
            correlation_pressure_at_ms: None,
            incidents_reported: None,
            retention_watch: crate::retention::RetentionWatch::default(),
            host_upstream_seen: Vec::new(),
            control,
            control_reported: [0; 2],
            control_reported_at_ms: [None; 2],
            state_heads_recorded: None,
            state_heads_segment: None,
            last_note_segment: None,
            executor_head_recorded: None,
            revert_failed_reported: std::collections::BTreeSet::new(),
            executor,
            warnings: crate::selfcheck::Warnings::new(
                cfg.daemon.self_health.clone(),
                cfg.daemon.health_report_ms,
            ),
            self_view: SelfView::default(),
            health_records: 0,
            health_record_at_ms: 0,
            replay: r
                .sensor
                .capture
                .as_ref()
                .filter(|c| matches!(c.input, CaptureInput::Replay { .. }))
                .map(|_| ReplayTimeline::default()),
            status_snapshot,
            status_server,
        };
        #[derive(Serialize)]
        struct StartNote<'b> {
            kind: &'static str,
            version: &'static str,
            robot_id: &'b str,
            profile_model: &'b str,
            profile_status: &'b str,
            inputs: Vec<&'b str>,
            safety_state: robodr_responder::SafetyState,
            correlation_rules: Option<usize>,
            signs_findings: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            control_plane: Option<Vec<String>>,
        }
        let initial_safety = d.safety();
        let note = StartNote {
            kind: "robodr.agentd_start",
            version: env!("CARGO_PKG_VERSION"),
            robot_id: &cfg.robot.id,
            profile_model: &d.pipeline.profile().model,
            profile_status: d.pipeline.status().as_str(),
            inputs: d.inputs.iter().map(|i| i.name.as_str()).collect(),
            safety_state: initial_safety,
            correlation_rules: d.correlator.as_ref().map(|c| c.rules().len()),
            signs_findings: d.agent.signs_findings(),
            control_plane: d.control.as_ref().map(|c| c.status().listening),
        };
        let now = d.clock.now();
        if let Err(e) = d.agent.record_note(now, "start note", &note, true) {
            d.stats.note_errors += 1;
            let _ = writeln!(d.log, "robodr-agentd: start note not recorded: {e:?}");
        }
        // The control plane's state at start (restored requests, settled
        // decisions, journal damage, replay fence) is evidence too.
        if let Some(cp) = d.control.as_ref() {
            let st = cp.status();
            let note = serde_json::json!({
                "kind": "robodr.control_plane_start",
                "api": st.api,
                "listening": st.listening,
                "tls": st.tls,
                "evidence_api": st.evidence.is_some(),
                "state": st.state,
            });
            let now = d.clock.now();
            if let Err(e) = d
                .agent
                .record_note(now, "control-plane start note", &note, true)
            {
                d.stats.note_errors += 1;
                let _ = writeln!(
                    d.log,
                    "robodr-agentd: control-plane start note not recorded: {e:?}"
                );
            }
        }
        d.control_state_at_start();
        d.profile_witness(accepted_ok);
        d.evidence_incidents();
        d.retention_tick();
        let names: Vec<String> = d.inputs.iter().map(|i| sanitize(&i.name)).collect();
        let _ = writeln!(
            d.log,
            "robodr-agentd: started for robot {} (profile {}: {}), inputs: {}",
            sanitize(&cfg.robot.id),
            sanitize(&d.pipeline.profile().model),
            d.pipeline.status().as_str(),
            names.join(", ")
        );
        let found = d.pipeline.status_findings();
        d.sensor_findings(found);
        d.write_status(true);
        Ok(d)
    }

    fn now_ms(&self) -> u64 {
        ms(self.epoch.elapsed())
    }

    /// At start: record the enforced profile in the black box (the second
    /// anti-rollback witness, [`crate::profile_chain`]) and report a state
    /// file that is missing or behind the black box as a Critical,
    /// observe-only finding.
    fn profile_witness(&mut self, accepted_ok: bool) {
        let enforcing = self.pipeline.status() == &ProfileStatus::Enforcing;
        if let (true, true, Some(acc)) = (accepted_ok, enforcing, &self.r.profile_accepted) {
            let note = crate::profile_chain::accepted_note(
                acc,
                self.r.profile_signed_by.as_deref(),
                self.r.profile_decision,
            );
            let now = self.clock.now();
            match self.agent.record_note(now, "profile accepted", &note, true) {
                Ok(_) => self.profile_accepted = Some(acc.clone()),
                Err(e) => {
                    self.stats.note_errors += 1;
                    let _ = writeln!(
                        self.log,
                        "robodr-agentd: accepted profile not recorded in the black box: {}",
                        sanitize(&e.join("; "))
                    );
                }
            }
        }
        if let Some(alarm) = &self.r.profile_alarm {
            let detail = alarm.to_string();
            let _ = writeln!(self.log, "robodr-agentd: CRITICAL: {}", sanitize(&detail));
            let dev = robodr_events::Deviation::new(
                robodr_ros2_pipeline::profile_trust::PROFILE_STATE_TAMPERED,
                robodr_events::Severity::Critical,
                detail,
            );
            let subject = Subject {
                node: Some("robodr-agentd".into()),
                ..Subject::default()
            };
            let now = self.clock.now();
            let safety = self.r.config.context.safety_state;
            // Self-health: observe-only by construction, never a request.
            let o = self.agent.handle_external(
                now,
                Detector::SelfHealth,
                "agentd:profile_state",
                subject,
                dev,
                safety,
            );
            self.stats.health_findings += 1;
            self.emit(o);
        }
        // T11 / T12: a safety configuration file that claims more than the
        // commissioning signed (`crate::commissioned`). Observe-only.
        for detail in self.r.config_unattested.clone() {
            let _ = writeln!(self.log, "robodr-agentd: {}", sanitize(&detail));
            let dev = robodr_events::Deviation::new(
                crate::commissioned::CONFIG_UNATTESTED,
                robodr_events::Severity::High,
                detail,
            );
            let subject = Subject {
                node: Some("robodr-agentd".into()),
                ..Subject::default()
            };
            let now = self.clock.now();
            let safety = self.r.config.context.safety_state;
            let o = self.agent.handle_external(
                now,
                Detector::SelfHealth,
                "agentd:config_unattested",
                subject,
                dev,
                safety,
            );
            self.stats.health_findings += 1;
            self.emit(o);
        }
    }

    fn main_loop(&mut self, should_stop: &dyn Fn() -> bool) -> StopReason {
        let tick = Duration::from_millis(self.r.config.daemon.tick_ms);
        let heartbeat = Duration::from_millis(self.r.config.daemon.heartbeat_ms);
        let mut next_tick = Instant::now() + tick;
        let mut next_heartbeat = Instant::now();
        let mut next_ping = Instant::now();
        loop {
            if should_stop() {
                return StopReason::Requested;
            }
            if Instant::now() >= next_ping {
                // From the loop itself: a stalled loop stops the pings.
                self.notifier.notify("WATCHDOG=1");
                next_ping = Instant::now() + WATCHDOG_PING;
            }
            let wait = next_tick
                .saturating_duration_since(Instant::now())
                .min(MAX_WAIT);
            if self.inputs_gone {
                // Nothing can arrive any more: sleep instead of polling a
                // disconnected queue (which returns at once).
                std::thread::sleep(wait);
            } else {
                self.receive(wait, next_tick);
            }
            self.control_poll();
            self.executor_poll();
            let now = Instant::now();
            if now >= next_tick {
                let delay = ms(now.duration_since(next_tick));
                self.tick(delay);
                // Do not try to catch up missed ticks one by one.
                next_tick = (next_tick + tick).max(now);
                if now >= next_heartbeat {
                    self.heartbeat("robodr.agentd_heartbeat");
                    self.record_state_heads("heartbeat");
                    self.record_executor_head("heartbeat", false);
                    next_heartbeat = now + heartbeat;
                }
                if self.r.config.daemon.exit_when_inputs_end
                    && self.inputs.iter().all(|i| i.end_handled)
                {
                    // Everything an input queued was sent before it ended.
                    while let Ok(m) = self.rx.try_recv() {
                        self.handle(m);
                    }
                    return StopReason::InputsEnded;
                }
            }
        }
    }

    /// Wait up to `wait` for an item, then handle up to [`BATCH`] items, but
    /// not past `next_tick`.
    fn receive(&mut self, wait: Duration, next_tick: Instant) {
        match self.rx.recv_timeout(wait) {
            Ok(m) => {
                self.handle(m);
                for _ in 1..BATCH {
                    // Housekeeping first when it is due (slow items,
                    // e.g. fsync of critical evidence, add up).
                    if Instant::now() >= next_tick {
                        break;
                    }
                    match self.rx.try_recv() {
                        Ok(m) => self.handle(m),
                        Err(_) => break,
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => self.on_disconnected(),
        }
    }

    fn on_disconnected(&mut self) {
        if std::mem::replace(&mut self.inputs_gone, true) {
            return;
        }
        // Every feed was dropped, so every input thread is done. One that
        // did not report its end (a panic) is marked ended with an error.
        for i in &self.inputs {
            if !i.stats.ended.load(Ordering::SeqCst) {
                *i.stats
                    .end_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some("input thread exited without reporting an end".into());
                i.stats.ended.store(true, Ordering::SeqCst);
            }
        }
        let _ = writeln!(
            self.log,
            "robodr-agentd: every input has ended; the agent receives nothing"
        );
    }

    fn handle(&mut self, m: Msg) {
        let age = ms(m.at.elapsed());
        // Receipt time (when the input queued it), not processing time:
        // queue lag must not make a safety reading look fresher.
        let received_ms = ms(m.at.saturating_duration_since(self.epoch));
        self.tick_max_age_ms = self.tick_max_age_ms.max(age);
        self.stats.max_queue_age_ms = self.stats.max_queue_age_ms.max(age);
        match m.payload {
            Payload::Datagram(d) => {
                self.stats.datagrams += 1;
                let captured_ns = d
                    .captured_at
                    .map(|t| u64::try_from(t.as_nanos()).unwrap_or(u64::MAX));
                let handled_ns = self.clock.now().mono_ns;
                // A replayed packet is observed at its own record time (see
                // "Live motion data"); a live one when it is handled.
                let replayed = self
                    .inputs
                    .get(m.input)
                    .is_some_and(|i| i.kind == InputKind::Capture);
                let capture_ns = match (self.replay.as_mut(), captured_ns) {
                    (Some(tl), Some(c)) if replayed => tl.place(c, handled_ns, Instant::now()),
                    _ => handled_ns,
                };
                let pipeline_now = self.pipeline_now();
                let out =
                    self.pipeline
                        .process_datagram_with_motion_at(&d, pipeline_now, capture_ns);
                // The feed's tap after the pipeline (binding updated from
                // this datagram), before anything of it is planned.
                let fed = match self.feed.as_mut() {
                    Some(f) => f.observe_datagram(
                        &d,
                        self.pipeline.profile(),
                        self.pipeline.binding(),
                        received_ms,
                    ),
                    None => Vec::new(),
                };
                self.feed_findings(fed);
                self.sync_identities();
                self.sensor_findings(out.findings);
                for s in out.motion {
                    self.motion_sample(s, captured_ns.unwrap_or(capture_ns));
                }
            }
            Payload::Safety(report) => {
                let fed = match self.feed.as_mut() {
                    Some(f) => f.observe_report_from(m.conn, report, received_ms),
                    None => Vec::new(),
                };
                // Record a transition now, not at the next plan.
                self.safety();
                self.feed_findings(fed);
            }
            Payload::Host(crate::host::HostLine::Heartbeat(hb)) => {
                self.host_heartbeat(m.input, hb);
            }
            Payload::Host(crate::host::HostLine::Threat(t)) => self.host_threat(&t),
            Payload::Gateway(g) => self.gateway_finding(&g),
            Payload::GatewaySummary(g) => self.gateway_summary(&g),
            Payload::GatewayHeartbeat(hb) => {
                // Activity on the input (it is not silent); the gateway's
                // own drops count as upstream drops, as a forwarder's.
                self.stats.gateway_heartbeats += 1;
                self.upstream_dropped(m.input, hb.dropped);
            }
            Payload::Event(ev) => {
                self.stats.events += 1;
                if let Some(link) = self.executor.as_mut() {
                    link.observe_event(&ev);
                }
                let safety = self.safety();
                let now = self.clock.now();
                let detect_ns = self.detect_ns();
                let outs = self
                    .agent
                    .handle_with_joint_at(now, detect_ns, &ev, None, safety);
                for o in outs {
                    self.emit(o);
                }
            }
        }
    }

    /// Hand the participant identities the pipeline resolved (fresh GUIDs
    /// of restarted processes) to the Motion Firewall and the safety feed,
    /// when they changed.
    fn sync_identities(&mut self) {
        let st = self.pipeline.stats().identity;
        if st == self.identity_seen {
            return;
        }
        self.identity_seen = st;
        let held = self.pipeline.identity_holders();
        self.agent.set_source_identities(
            held.iter()
                .map(|(p, n)| (robodr_rtps::hex12(p), n.clone()))
                .collect(),
        );
        if let Some(f) = self.feed.as_mut() {
            f.set_identities(held.into_iter().collect());
        }
    }

    /// A decoded motion command / feedback -> agent (profile, firewall,
    /// motion monitor) -> spool.
    ///
    /// A command whose source the binding refused (unbound, contested or
    /// source-mismatched; the pipeline already raised the finding) loses its
    /// writer GUID first: the firewall model then sees an unknown source, so
    /// a GUID claimed by a spoofer never authorises a command.
    ///
    /// A decoded low-level joint frame (Unitree `LowCmd`, ...) goes with its
    /// command to the agent's joint firewall (recording-only, like every
    /// verdict here), stamped `joint_stamp_ns`: the datagram's capture
    /// time, so the firewall's rate / gap checks see the real inter-arrival
    /// times, not the daemon's processing times.
    fn motion_sample(&mut self, mut s: MotionSample, joint_stamp_ns: u64) {
        self.stats.motion_events += 1;
        if s.attribution.is_refused() {
            if let RobotEvent::MotionCommand(c) = &mut s.event {
                c.source_guid = None;
            }
        }
        let joint = s.joint.and_then(|j| {
            Some(JointInput {
                frame: joint_frame(&j)?,
                stamp_ns: joint_stamp_ns,
            })
        });
        if joint.is_some() {
            self.stats.joint_frames += 1;
        }
        let safety = self.safety();
        let now = self.clock.now();
        let detect_ns = self.detect_ns();
        let outs =
            self.agent
                .handle_with_joint_at(now, detect_ns, &s.event, joint.as_ref(), safety);
        for o in outs {
            self.emit(o);
        }
    }

    /// The detection time for the agent's time-dependent detectors: the
    /// replay's packet timeline while one runs (so events handled between
    /// packets do not move the motion monitor along the daemon's clock),
    /// else `None` (the event's own time).
    fn detect_ns(&self) -> Option<u64> {
        self.replay.as_ref().and_then(ReplayTimeline::position)
    }

    /// [`Self::detect_ns`], or the daemon clock: the time of a correlation
    /// signal.
    fn signal_ns(&self) -> u64 {
        self.detect_ns().unwrap_or_else(|| self.clock.now().mono_ns)
    }

    /// The pipeline's clock: the replay's packet timeline while one runs
    /// (discovery expiry and grace windows), else now.
    fn pipeline_now(&self) -> Instant {
        self.replay
            .as_ref()
            .and_then(ReplayTimeline::instant)
            .unwrap_or_else(Instant::now)
    }

    /// Pipeline findings -> agent -> spool; per-participant discovery
    /// findings of a flooding source are folded into one aggregate
    /// ([`crate::flood`]): recorded in the black box and correlated, not
    /// reported one by one.
    fn sensor_findings(&mut self, found: Vec<Finding>) {
        for f in found {
            let ns = self.signal_ns();
            let wall_ms = self.clock.now().wall_ns / 1_000_000;
            let protected = f
                .participant
                .is_some_and(|p| self.pipeline.binding().is_protected(&p));
            let item = crate::flood::Item {
                deviation: &f.deviation,
                src_ip: &f.src_ip,
                participant: f.participant.as_ref(),
                protected,
            };
            match self.flood.admit(item, ns, wall_ms) {
                crate::flood::Admit::Pass => {}
                crate::flood::Admit::Fold(reports) => {
                    self.fold(&f);
                    for r in reports {
                        self.flood_report(r);
                    }
                    continue;
                }
            }
            let safety = self.safety();
            let now = self.clock.now();
            let subject = Subject {
                src_ip: Some(f.src_ip.clone()),
                ..Subject::default()
            };
            let source = format!("src:{}", f.src_ip);
            let o = self.agent.handle_external(
                now,
                Detector::Sensor,
                &source,
                subject,
                f.deviation,
                safety,
            );
            self.emit(o);
        }
    }

    /// A folded finding: its deviation record in the black box (as the
    /// agent writes it for a reported one) and its correlation signal.
    fn fold(&mut self, f: &Finding) {
        let now = self.clock.now();
        let r = match self
            .agent
            .record_deviation(now, Detector::Sensor, &f.deviation)
        {
            Ok(r) => Some(r),
            Err(_) => {
                self.stats.note_errors += 1;
                None
            }
        };
        let source = format!("src:{}", f.src_ip);
        self.correlate_deviation(&f.deviation, &source, r.as_ref());
    }

    /// A discovery-flood aggregate: reported like a pipeline finding.
    fn flood_report(&mut self, r: crate::flood::FloodReport) {
        let safety = self.safety();
        let now = self.clock.now();
        let source = match &r.src_ip {
            Some(ip) => format!("src:{ip}"),
            None => "flood:many_sources".to_string(),
        };
        // One finding id per flood episode (review L10): the subject is
        // the source plus the episode's synthetic node name.
        let subject = Subject {
            src_ip: r.src_ip.clone(),
            node: Some(r.episode.clone()),
            ..Subject::default()
        };
        let o = self.agent.handle_external(
            now,
            Detector::Sensor,
            &source,
            subject,
            r.deviation,
            safety,
        );
        self.emit(o);
    }

    /// Close quiet floods (tick) or every flood (`all`, at stop).
    fn flood_close(&mut self, all: bool) {
        let reports = if all {
            self.flood.flush()
        } else {
            let ns = self.signal_ns();
            self.flood.tick(ns)
        };
        for r in reports {
            self.flood_report(r);
        }
    }

    /// The safety state to grade a plan by now: the feed's (re-evaluated,
    /// a change recorded) or the configured one.
    fn safety(&mut self) -> SafetyState {
        let now_ms = self.now_ms();
        let Some(feed) = self.feed.as_mut() else {
            return self.r.config.context.safety_state;
        };
        let transition = feed.evaluate(now_ms);
        let state = feed.state();
        if let Some(t) = transition {
            self.transition_note(&t);
        }
        // Every plan is graded by the context of the same moment.
        self.live_context();
        state
    }

    /// The configured `context.*` (control, phase, connectivity).
    fn configured_context(&self) -> LiveContext {
        let c = &self.r.config.context;
        LiveContext {
            control: c.control,
            phase: c.phase,
            connectivity: c.connectivity,
        }
    }

    /// The live operational context (`crate::safety_feed::context`):
    /// re-evaluated, a change recorded in the black box and handed to the
    /// agent for every later plan. The configured one without context
    /// sources.
    fn live_context(&mut self) -> LiveContext {
        let fallback = self.configured_context();
        let now_ms = self.now_ms();
        let wall_ms = self.clock.now().wall_ns / 1_000_000;
        let Some((live, transition)) = self
            .feed
            .as_mut()
            .and_then(|f| f.evaluate_context(now_ms, wall_ms, fallback))
        else {
            return fallback;
        };
        if let Some(t) = transition {
            self.agent
                .set_operational(live.control, live.phase, live.connectivity);
            let _ = writeln!(
                self.log,
                "robodr-agentd: operational context control {:?} -> {:?}, phase {:?} -> {:?}, \
                 connectivity {:?} -> {:?}{}",
                t.from.control,
                t.to.control,
                t.from.phase,
                t.to.phase,
                t.from.connectivity,
                t.to.connectivity,
                if t.conflict {
                    " (sources disagree: most conservative taken)"
                } else {
                    ""
                }
            );
            let now = self.clock.now();
            if self
                .agent
                .record_note(now, "context transition", &t, false)
                .is_err()
            {
                self.stats.note_errors += 1;
            }
        }
        live
    }

    fn transition_note(&mut self, t: &Transition) {
        let _ = writeln!(
            self.log,
            "robodr-agentd: safety state {} -> {}{}",
            t.from.as_str(),
            t.to.as_str(),
            if t.conflict {
                " (sources disagree: most conservative taken)"
            } else {
                ""
            }
        );
        // Engaged / unknown ends are durable evidence (fsync).
        let critical = [t.from, t.to].iter().any(|c| {
            matches!(c, crate::safety::Claim::State(s)
                if s.safety_system_engaged() || *s == SafetyState::Unknown)
        });
        let now = self.clock.now();
        if self
            .agent
            .record_note(now, "safety transition", t, critical)
            .is_err()
        {
            self.stats.note_errors += 1;
        }
    }

    /// Safety-feed findings -> agent -> spool.
    fn feed_findings(&mut self, found: Vec<FeedFinding>) {
        for f in found {
            let _ = writeln!(
                self.log,
                "robodr-agentd: safety feed: {}: {}",
                f.deviation.rule_str(),
                sanitize(&f.deviation.detail)
            );
            let safety = self.safety();
            let now = self.clock.now();
            // Socket-source findings have no IP (a local gateway).
            let from_bus = !f.src_ip.is_empty();
            let subject = Subject {
                src_ip: from_bus.then(|| f.src_ip.clone()),
                topic: Some(f.topic.clone()),
                participant_guid: if from_bus {
                    f.writer.get(..24).map(str::to_string)
                } else {
                    None
                },
                ..Subject::default()
            };
            let source = if from_bus {
                format!("src:{}", f.src_ip)
            } else {
                "agentd:safety_socket".to_string()
            };
            let o = self.agent.handle_external(
                now,
                Detector::Sensor,
                &source,
                subject,
                f.deviation,
                safety,
            );
            self.emit(o);
        }
    }

    fn emit(&mut self, o: Outcome) {
        self.stats.outcomes += 1;
        // Critical findings have a share of the spool lesser ones cannot
        // fill (red team F1, `spool` module docs); health findings their
        // own reserve.
        let class = if o.detector == Detector::SelfHealth {
            SpoolClass::Health
        } else if o.deviation.severity >= robodr_events::Severity::Critical {
            SpoolClass::Critical
        } else {
            SpoolClass::Normal
        };
        match &o.finding {
            Some(f) => match self.spool.write_from(f, class, &o.source) {
                Ok(_) => self.stats.findings_spooled += 1,
                Err(SpoolError::Full) => {}
                Err(e) => {
                    let _ = writeln!(self.log, "robodr-agentd: {e}");
                }
            },
            None => {
                self.stats.finding_errors += 1;
                let _ = writeln!(
                    self.log,
                    "robodr-agentd: finding for {} not built: {}",
                    sanitize(o.deviation.rule_str()),
                    sanitize(&o.finding_errors.join("; "))
                );
            }
        }
        if !o.evidence.errors.is_empty() {
            let _ = writeln!(
                self.log,
                "robodr-agentd: evidence errors for {}: {}",
                sanitize(o.deviation.rule_str()),
                sanitize(&o.evidence.errors.join("; "))
            );
        }
        self.correlate(&o);
    }

    /// A forwarder heartbeat: liveness (already counted by the input) and
    /// the forwarder's own losses, added to the input's `upstream_dropped`
    /// (a smaller count than last time = the forwarder restarted).
    fn host_heartbeat(&mut self, input: usize, hb: crate::host::HostHeartbeat) {
        self.stats.host_heartbeats += 1;
        self.upstream_dropped(input, hb.dropped);
    }

    /// A forwarder's cumulative `dropped` (host-threat forwarder, gateway
    /// feed): the increase since its last heartbeat is added to the
    /// input's `upstream_dropped`.
    fn upstream_dropped(&mut self, input: usize, dropped: u64) {
        if self.host_upstream_seen.len() < self.inputs.len() {
            self.host_upstream_seen.resize(self.inputs.len(), 0);
        }
        let Some(seen) = self.host_upstream_seen.get_mut(input) else {
            return;
        };
        let delta = if dropped >= *seen {
            dropped - *seen
        } else {
            dropped
        };
        *seen = dropped;
        if delta > 0 {
            if let Some(i) = self.inputs.get(input) {
                i.stats.upstream_dropped.fetch_add(delta, Ordering::Relaxed);
            }
        }
    }

    /// An in-path gateway finding (`crate::gateway_feed`): agent (black
    /// box, plan), spool and correlation like any sensor finding; the
    /// subject is the gateway's channel.
    fn gateway_finding(&mut self, g: &crate::gateway_feed::GatewayLine) {
        self.stats.gateway_findings += 1;
        // The feed's flood limit (T82): a line past its (rule, channel)
        // budget is recorded in the black box only and reported in the
        // window's aggregate.
        let ns = self.signal_ns();
        let (admit, closed) = self.gateway_limit.admit(g, ns);
        for a in closed {
            self.gateway_aggregate(&a);
        }
        if admit == crate::gateway_feed::Admit::Fold {
            self.stats.gateway_folded += 1;
            let now = self.clock.now();
            if self
                .agent
                .record_deviation(now, Detector::Sensor, &g.deviation())
                .is_err()
            {
                self.stats.note_errors += 1;
            }
            return;
        }
        self.gateway_report(g);
    }

    /// A gateway decision summary (T19): a black-box note, signed and
    /// chained like every record; start and stop are critical notes.
    fn gateway_summary(&mut self, g: &crate::gateway_feed::GatewaySummary) {
        let now = self.clock.now();
        let critical = g.event != crate::gateway_feed::SummaryEvent::Interval;
        match self.agent.record_note(now, "gateway summary", g, critical) {
            Ok(_) => self.stats.gateway_summaries += 1,
            Err(_) => self.stats.gateway_summary_errors += 1,
        }
    }

    /// An aggregate of folded gateway lines: reported like a line.
    fn gateway_aggregate(&mut self, a: &crate::gateway_feed::GatewayLine) {
        self.stats.gateway_aggregates += 1;
        self.gateway_report(a);
    }

    /// Close an expired feed-limit window (tick) or the open one (`all`,
    /// at stop) and report its aggregates.
    fn gateway_close(&mut self, all: bool) {
        let out = if all {
            self.gateway_limit.flush()
        } else {
            let ns = self.signal_ns();
            self.gateway_limit.tick(ns)
        };
        for a in out {
            self.gateway_aggregate(&a);
        }
    }

    fn gateway_report(&mut self, g: &crate::gateway_feed::GatewayLine) {
        let _ = writeln!(
            self.log,
            "robodr-agentd: gateway: {} x{}: {}",
            sanitize(&g.rule),
            g.count,
            sanitize(&g.detail)
        );
        let safety = self.safety();
        let now = self.clock.now();
        let subject = Subject {
            topic: g.channel.clone(),
            ..Subject::default()
        };
        let o = self.agent.handle_external(
            now,
            Detector::Sensor,
            &g.source(),
            subject,
            g.deviation(),
            safety,
        );
        self.emit(o);
    }

    /// A Pulsar threat: a `robot.host.<rule>` finding (its own id for a
    /// shipped rule, else `robot.host.pulsar_threat`; agent, black box,
    /// spool), then a host-side correlation signal named by the Pulsar
    /// rule, with the process entity and the finding's evidence.
    fn host_threat(&mut self, t: &crate::host::HostThreat) {
        if t.is_own_sensor() {
            // Already reported through the pipeline: never twice.
            self.stats.host_threats_own_skipped += 1;
            return;
        }
        self.stats.host_threats += 1;
        let _ = writeln!(
            self.log,
            "robodr-agentd: host threat: {} (module {}, pid {}, {})",
            sanitize(&t.rule),
            sanitize(&t.source),
            t.pid,
            sanitize(&t.image)
        );
        let safety = self.safety();
        let now = self.clock.now();
        let source = format!("host:{}", t.source);
        let o = self.agent.handle_external(
            now,
            Detector::Sensor,
            &source,
            Subject::default(),
            t.deviation(),
            safety,
        );
        let mut sig = Signal::host(self.signal_ns(), t.rule.clone(), t.severity())
            .with_mode(o.deviation.mode)
            .with_entity(EntityKind::Process, t.process_entity());
        if let Some(r) = &o.evidence.deviation {
            sig = sig.with_evidence_ref(r.uri(&self.r.config.robot.id));
        }
        // `emit` does not correlate the `robot.host.*` finding itself: the
        // signal below (named by the Pulsar rule) stands for it.
        self.emit(o);
        if self.correlator.is_some() {
            self.observe_signal(&sig);
        }
    }

    /// Feed one reported outcome to the correlation engine and report what
    /// it completes. Correlated findings, the engine's own health finding
    /// and host-threat findings (fed as their Pulsar rule by
    /// [`Self::host_threat`]) are not fed here.
    fn correlate(&mut self, o: &Outcome) {
        self.correlate_deviation(&o.deviation, &o.source, o.evidence.deviation.as_ref());
    }

    /// One deviation (reported or folded) into the correlator.
    fn correlate_deviation(
        &mut self,
        dev: &robodr_events::Deviation,
        source: &str,
        evidence: Option<&robodr_ocsf::BlackBoxRef>,
    ) {
        let rule = dev.rule_str();
        if self.correlator.is_none()
            || rule.starts_with(robodr_correlate::RULE_ID_PREFIX)
            || rule == health_rules::CORRELATION_PRESSURE
            || rule == crate::selfcheck::rules::HEALTH
            || crate::host::is_host_rule(rule)
        {
            return;
        }
        let mut sig = Signal::from_deviation(self.signal_ns(), dev);
        if let Some(ip) = source.strip_prefix("src:") {
            sig = sig.with_entity(EntityKind::Ip, ip);
        } else if let Some(p) = source.strip_prefix("participant:") {
            sig = sig.with_entity(EntityKind::Participant, p);
        }
        if let Some(r) = evidence {
            sig = sig.with_evidence_ref(r.uri(&self.r.config.robot.id));
        }
        self.observe_signal(&sig);
    }

    /// One signal into the correlator; report what it completes.
    fn observe_signal(&mut self, sig: &Signal) {
        let found = match self.correlator.as_mut() {
            Some(c) => {
                let mut f = c.observe(sig);
                // Eviction notices (observe-only) are reported like findings.
                f.extend(c.take_notices());
                f
            }
            None => Vec::new(),
        };
        for f in found {
            self.correlated(f);
        }
    }

    /// Tell the correlator which entities are the robot's own (profiled
    /// participants, IPs bound or pinned to them): their pending state is
    /// best protected from eviction.
    fn correlation_known(&mut self) {
        let now = self.pipeline_now();
        let Some(c) = self.correlator.as_mut() else {
            return;
        };
        let participants = self.pipeline.profile().participants.clone();
        c.set_known_entities(EntityKind::Participant, participants);
        let ips = self.pipeline.binding().profiled_ips(now);
        c.set_known_entities(EntityKind::Ip, ips.iter().map(|ip| ip.to_string()));
    }

    /// A correlated finding: the full record (every contributing signal)
    /// as a black-box note, then the agent (plan, finding) and the spool.
    fn correlated(&mut self, f: CorrelatedFinding) {
        #[derive(Serialize)]
        struct Note<'b> {
            kind: &'static str,
            #[serde(flatten)]
            finding: &'b CorrelatedFinding,
        }
        self.stats.correlated_findings += 1;
        let _ = writeln!(
            self.log,
            "robodr-agentd: correlation: {}: {}",
            f.rule,
            sanitize(&f.detail)
        );
        let now = self.clock.now();
        let critical = f.severity >= robodr_events::Severity::High;
        let note = Note {
            kind: "robodr.correlated_finding",
            finding: &f,
        };
        if self
            .agent
            .record_note(now, "correlated finding", &note, critical)
            .is_err()
        {
            self.stats.note_errors += 1;
        }
        let mut subject = Subject::default();
        match &f.group {
            Some(g) if g.kind == EntityKind::Ip => subject.src_ip = Some(g.value.clone()),
            Some(g) if g.kind == EntityKind::Participant => {
                subject.participant_guid = Some(g.value.clone());
            }
            _ => {}
        }
        let source = match &f.group {
            Some(g) => format!("correlate:{}:{}:{}", f.rule, g.kind.as_str(), g.value),
            None => format!("correlate:{}", f.rule),
        };
        let safety = self.safety();
        let now = self.clock.now();
        let o = self.agent.handle_external(
            now,
            Detector::Sensor,
            &source,
            subject,
            f.to_deviation(),
            safety,
        );
        self.emit(o);
    }

    /// Gap 1: what the control plane found in its sealed state at start.
    /// A one-time upgrade of v1 journals is recorded
    /// (`robodr.control_plane_state_upgraded`); damage, an edit, another
    /// key or a rollback is a `robot.agent.control_plane_state_untrusted`
    /// finding (the control plane has already failed safe: replay fence,
    /// reconciliation with the black box); then the heads are anchored.
    fn control_state_at_start(&mut self) {
        let Some(st) = self.control.as_ref().map(|c| c.state_status().clone()) else {
            return;
        };
        if st.journal_upgraded_from_v1 || st.replay.upgraded_from_v1 {
            let note = serde_json::json!({
                "kind": crate::control::anchor::STATE_UPGRADED_NOTE,
                "robot_id": self.r.config.robot.id,
                "key_id": st.seal_key_id,
                "requests_upgraded": st.journal_upgraded_from_v1,
                "nonces_upgraded": st.replay.upgraded_from_v1,
                "rebuilt_from_blackbox": st.rebuilt_from_blackbox,
                "replay_fence": st.replay.fence,
            });
            let now = self.clock.now();
            if self
                .agent
                .record_note(now, "control-plane state upgrade", &note, true)
                .is_err()
            {
                self.stats.note_errors += 1;
            }
            let _ = writeln!(
                self.log,
                "robodr-agentd: control plane: unsealed v1 state journals upgraded to {} (one \
                 time): reconciled with the black box, replay store fenced",
                crate::control::journal::FORMAT
            );
        }
        if let Some((sev, detail)) = crate::control::anchor::integrity_alarm(&st) {
            let dev = robodr_events::Deviation::new(
                health_rules::CONTROL_PLANE_STATE_UNTRUSTED,
                sev,
                detail,
            );
            self.self_health("agentd:control_plane", dev);
        }
        self.record_state_heads("start");
    }

    /// Gap 1: record where the control-plane journals end as a signed
    /// black-box note (`start`, `stop`, and `heartbeat` when a head moved;
    /// see [`crate::control::anchor`]).
    fn record_state_heads(&mut self, reason: &str) {
        let Some(cp) = self.control.as_ref() else {
            return;
        };
        let heads = cp.state_heads();
        // Review of gap 1, finding 3: unchanged heads are recorded again
        // once the black box moved to another segment, so the newest
        // segments always hold one (a cyclic store drops the oldest).
        if reason == "heartbeat"
            && !crate::control::anchor::head_note_due(
                self.state_heads_recorded.as_ref() != Some(&heads),
                self.state_heads_segment,
                self.last_note_segment,
            )
        {
            return;
        }
        let note = crate::control::anchor::head_note(
            &self.r.config.robot.id,
            reason,
            &cp.state_status().seal_key_id,
            &heads,
        );
        let now = self.clock.now();
        match self
            .agent
            .record_note(now, "control-plane state head", &note, true)
        {
            Ok(r) => {
                self.state_heads_recorded = Some(heads);
                self.state_heads_segment = Some(r.segment);
                self.last_note_segment = Some(r.segment);
            }
            Err(e) => {
                self.stats.note_errors += 1;
                let _ = writeln!(
                    self.log,
                    "robodr-agentd: control-plane state head not recorded: {e:?}"
                );
            }
        }
    }

    /// Review of gap 1 (findings 1 and 2): record the executor's journal
    /// head as a signed black-box note (`robodr.executor_journal_head`)
    /// when it changed, or when the black box moved to another segment
    /// since the last one (`heartbeat`), and at once when its epoch
    /// changed or it went backwards (`force`). At the next start agentd
    /// sends the newest one back as the anchor.
    fn record_executor_head(&mut self, reason: &str, force: bool) {
        let Some(head) = self.executor.as_ref().and_then(|l| l.journal_head()) else {
            return;
        };
        if !force {
            if let Some((h, seg)) = &self.executor_head_recorded {
                if !crate::control::anchor::head_note_due(
                    *h != head,
                    Some(*seg),
                    self.last_note_segment,
                ) {
                    return;
                }
            }
        }
        let note =
            crate::control::anchor::executor_head_note(&self.r.config.robot.id, reason, &head);
        let now = self.clock.now();
        match self
            .agent
            .record_note(now, "executor journal head", &note, true)
        {
            Ok(r) => {
                self.executor_head_recorded = Some((head, r.segment));
                self.last_note_segment = Some(r.segment);
            }
            Err(e) => {
                self.stats.note_errors += 1;
                let _ = writeln!(
                    self.log,
                    "robodr-agentd: executor journal head not recorded: {}",
                    sanitize(&e.join("; "))
                );
            }
        }
    }

    /// Raise an observe-only self-health deviation (not an input issue).
    fn self_health(&mut self, source: &str, dev: robodr_events::Deviation) {
        self.stats.health_findings += 1;
        let _ = writeln!(
            self.log,
            "robodr-agentd: health: {}: {}",
            dev.rule_str(),
            sanitize(&dev.detail)
        );
        let subject = Subject {
            node: Some("robodr-agentd".into()),
            ..Subject::default()
        };
        let safety = self.safety();
        let now = self.clock.now();
        let o = self
            .agent
            .handle_external(now, Detector::SelfHealth, source, subject, dev, safety);
        self.emit(o);
    }

    /// Report what the black box found when it was opened (or reopened
    /// after an outage), once per recorder: quarantined segments and
    /// damage as `robot.agent.evidence_quarantined` with the highest
    /// severity the recorder gave them (High = failing media, Critical =
    /// tampering), truncation as Critical `robot.agent.evidence_truncated`.
    /// Both are observe-only self-health findings.
    fn evidence_incidents(&mut self) {
        use robodr_blackbox::OpenIncident;
        let generation = self.agent.stats().blackbox_reopens;
        if self.incidents_reported == Some(generation) {
            return;
        }
        let incidents = self.agent.blackbox_open_incidents().to_vec();
        if self.agent.evidence_degraded() && incidents.is_empty() {
            // No recorder right now: look again once it is back.
            return;
        }
        self.incidents_reported = Some(generation);
        let (trunc, damage): (Vec<_>, Vec<_>) = incidents
            .iter()
            .partition(|i| matches!(i, OpenIncident::TruncationDetected { .. }));
        if let Some(sev) = damage.iter().map(|i| i.severity()).max() {
            let list = damage
                .iter()
                .map(|i| format!("[{:?}] {i}", i.severity()))
                .collect::<Vec<_>>()
                .join("; ");
            let detail = format!(
                "the black box quarantined {} damaged evidence item(s) when it was opened; \
                 they were copied to quarantine/ and documented by signed recovery records, and \
                 recording continued: {}: {list}",
                damage.len(),
                if sev >= robodr_events::Severity::Critical {
                    "the log was edited (tampering), not plausible storage failure"
                } else {
                    "the storage is failing or the log was edited"
                }
            );
            let dev =
                robodr_events::Deviation::new(health_rules::EVIDENCE_QUARANTINED, sev, detail);
            self.self_health("agentd:blackbox", dev);
        }
        if !trunc.is_empty() {
            let list = trunc
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            let detail = format!(
                "the black box found authentic evidence of records beyond its head when it was \
                 opened: the log was cut (signed TruncationDetected record written, sequence \
                 numbers not reused): {list}"
            );
            let dev = robodr_events::Deviation::new(
                health_rules::EVIDENCE_TRUNCATED,
                robodr_events::Severity::Critical,
                detail,
            );
            self.self_health("agentd:blackbox", dev);
        }
    }

    /// T15: report unexported evidence filling the black box's retention
    /// before it is dropped, and any drop of unexported evidence
    /// (`crate::retention`). Re-reads the export cursor an exporter in
    /// another process moved.
    fn retention_tick(&mut self) {
        let ret = self.r.config.blackbox.retention.clone().unwrap_or_default();
        let Some(st) = self.agent.blackbox_retention() else {
            return;
        };
        let saturation = ret.mode == crate::retention::RetentionKind::Saturation;
        // The recorder generation: a reopened recorder counts its drops
        // from 0 again.
        let generation = self.agent.stats().blackbox_reopens;
        let now_ms = self.now_ms();
        for dev in
            self.retention_watch
                .observe(&st, ret.warn_percent, saturation, generation, now_ms)
        {
            self.self_health("agentd:blackbox", dev);
        }
    }

    /// Correlation housekeeping: expire state on a quiet bus; report a
    /// rising eviction / refusal count (rate-limited like other health
    /// counters).
    fn correlation_tick(&mut self) {
        let now_ns = self.signal_ns();
        self.correlation_known();
        let Some(c) = self.correlator.as_mut() else {
            return;
        };
        c.tick(now_ns);
        let st = *c.stats();
        let pressure = st.groups_evicted.saturating_add(st.groups_refused);
        if pressure <= self.correlation_pressure_reported {
            return;
        }
        let now_ms = self.now_ms();
        let every = self.r.config.daemon.health_report_ms;
        if self
            .correlation_pressure_at_ms
            .is_some_and(|t| now_ms.saturating_sub(t) < every)
        {
            return;
        }
        let delta = pressure - self.correlation_pressure_reported;
        self.correlation_pressure_reported = pressure;
        self.correlation_pressure_at_ms = Some(now_ms);
        let dev = robodr_events::Deviation::new(
            health_rules::CORRELATION_PRESSURE,
            robodr_events::Severity::Medium,
            format!(
                "the correlation engine evicted {} and refused {} pending groups ({delta} since \
                 the last report): many fresh entities within a window, possibly a flood \
                 aimed at hiding a correlation",
                st.groups_evicted, st.groups_refused
            ),
        );
        self.self_health("agentd:correlation", dev);
    }

    /// Write the black box's high-water mark if records were appended since
    /// the last one.
    fn mark_head(&mut self) {
        match self.agent.mark_blackbox_head() {
            Ok(true) => self.stats.head_marks += 1,
            Ok(false) => {}
            // An unavailable black box is already reported (evidence_degraded).
            Err(_) if self.agent.evidence_degraded() => {}
            Err(e) => {
                self.stats.head_mark_errors += 1;
                if self.stats.head_mark_errors.is_power_of_two() {
                    let _ = writeln!(
                        self.log,
                        "robodr-agentd: black-box high-water mark not written ({} so far): {}",
                        self.stats.head_mark_errors,
                        sanitize(&e)
                    );
                }
            }
        }
    }

    fn health_issue(&mut self, issue: Issue) {
        self.stats.health_findings += 1;
        let dev = issue.deviation();
        let _ = writeln!(
            self.log,
            "robodr-agentd: health: {}: {}",
            dev.rule_str(),
            sanitize(&dev.detail)
        );
        let source = match issue.input() {
            Some(i) => format!("input:{i}"),
            None => "agentd".to_string(),
        };
        let subject = Subject {
            node: Some("robodr-agentd".into()),
            topic: issue.input().map(str::to_string),
            ..Subject::default()
        };
        let safety = self.safety();
        let now = self.clock.now();
        let o =
            self.agent
                .handle_external(now, Detector::SelfHealth, &source, subject, dev, safety);
        self.emit(o);
    }

    /// Probe credentials, clock, disks and reachability, refresh
    /// [`SelfView`] and report what got worse ([`crate::selfcheck`]).
    fn early_warnings(&mut self) {
        use crate::selfcheck::{
            clock_health, credential, file_age_ms, fs_space, kernel_clock, TIMESYNC_MARKER,
        };
        use robodr_ocsf::{DiskHealth, ReachState, Reachability};
        let now_ms = self.now_ms();
        let wall_ms = self.clock.now().wall_ns / 1_000_000;
        // Credentials: the control plane's own certificate and its CRLs.
        let mut creds = Vec::new();
        if let Some(t) = self.r.control_plane.as_ref().and_then(|c| c.tls.as_ref()) {
            if let Some(na) = t.server_not_after {
                creds.push(credential("control_plane.server_cert", na, wall_ms));
            }
            if let Some(crl) = &t.crl {
                for u in crl.status().in_use {
                    if let Some(nu) = u.next_update {
                        creds.push(credential(
                            &format!("control_plane.crl:{}", u.issuer),
                            nu,
                            wall_ms,
                        ));
                    }
                }
            }
        }
        // Clock: adjtimex(2), refused under the shipped unit's seccomp
        // filter (the record then says so), else timesyncd's marker.
        let kernel = kernel_clock();
        let wall_jumps = self.agent.stats().wall_clock_jumps;
        let clock = clock_health(
            kernel,
            file_age_ms(std::path::Path::new(TIMESYNC_MARKER), wall_ms),
            wall_jumps,
        );
        let kernel = kernel.ok();
        // Disks.
        let mut dirs: Vec<(&str, &std::path::Path)> = vec![
            ("blackbox", self.r.config.blackbox.dir.as_path()),
            ("spool", self.r.config.spool.dir.as_path()),
        ];
        if let Some(c) = &self.r.control_plane {
            dirs.push(("control_plane", c.state_dir.as_path()));
        }
        let disks: Vec<DiskHealth> = dirs
            .into_iter()
            .filter_map(|(name, dir)| {
                fs_space(dir).map(|(free_bytes, total_bytes)| DiskHealth {
                    name: name.into(),
                    free_bytes,
                    total_bytes,
                })
            })
            .collect();
        // Reachability: the executor link, the gateway feed and the Pulsar
        // forwarder (their sockets are inputs: heard within silence_ms).
        let silence = self.r.config.daemon.silence_ms;
        let input_reach = |component: &str, prefix: &str| -> Reachability {
            let (state, last_ok_age_ms) = crate::selfcheck::inputs_reachability(
                self.inputs
                    .iter()
                    .filter(|i| i.name.starts_with(prefix))
                    .map(|i| (i.stats.ended.load(Ordering::SeqCst), i.stats.last_rx_ms())),
                now_ms,
                silence,
            );
            Reachability {
                component: component.into(),
                state,
                last_ok_age_ms,
            }
        };
        let exec = self.executor.as_ref().map(|l| l.reach());
        let reachability = vec![
            Reachability {
                component: "executor".into(),
                state: match &exec {
                    None => ReachState::NotConfigured,
                    Some(r) if r.unreachable_for_ms.is_some() => ReachState::Unreachable,
                    Some(r) if r.last_ok_age_ms.is_some() => ReachState::Reachable,
                    Some(_) => ReachState::Unknown,
                },
                last_ok_age_ms: exec.as_ref().and_then(|r| r.last_ok_age_ms),
            },
            input_reach("gateway", "gateway:"),
            input_reach("pulsard", "host:"),
        ];

        let mut found = self.warnings.credentials(now_ms, &creds);
        found.extend(self.warnings.clock(now_ms, kernel, wall_jumps));
        found.extend(self.warnings.disks(&disks));
        found.extend(self.warnings.executor(
            exec.as_ref().and_then(|r| r.unreachable_for_ms),
            exec.as_ref().and_then(|r| r.last_error.as_deref()),
        ));
        self.self_view = SelfView {
            health_records: self.health_records,
            health_record_ms: self.warnings.config().health_record_ms,
            clock,
            disks,
            credentials: creds,
            reachability,
        };
        for w in found {
            self.self_health("agentd:self_health", w.deviation());
        }
    }

    /// Every `daemon.self_health.health_record_ms` (first one period after
    /// start): the signed `robot.agent.health` finding (findings contract
    /// 2.5, §3g) with what [`Self::early_warnings`] just saw.
    fn health_record(&mut self) {
        use robodr_ocsf::{
            AgentHealth, BlackBoxHealth, ComponentVersion, HealthCounters, HealthLabel,
            InputFreshness,
        };
        let every = self.warnings.config().health_record_ms;
        let now_ms = self.now_ms();
        if every == 0 || now_ms.saturating_sub(self.health_record_at_ms) < every {
            return;
        }
        self.health_record_at_ms = now_ms;
        self.health_records += 1;
        self.self_view.health_records = self.health_records;
        let spool = self.spool.stats();
        let inputs = self
            .inputs
            .iter()
            .map(|i| InputFreshness {
                name: i.name.clone(),
                last_rx_age_ms: i.stats.last_rx_ms().map(|t| now_ms.saturating_sub(t)),
                received: i.stats.received.load(Ordering::Relaxed),
                dropped: i
                    .stats
                    .dropped
                    .load(Ordering::Relaxed)
                    .saturating_add(i.stats.upstream_dropped.load(Ordering::Relaxed)),
                malformed: i.stats.malformed.load(Ordering::Relaxed),
                ended: i.stats.ended.load(Ordering::SeqCst),
            })
            .collect();
        let v = &self.self_view;
        let record = AgentHealth {
            state: match self.last_state.state {
                State::Ok => HealthLabel::Ok,
                State::Degraded => HealthLabel::Degraded,
                State::Unknown => HealthLabel::Unknown,
            },
            reasons: self.last_state.reasons.clone(),
            interval_ms: every,
            uptime_ms: now_ms,
            seq: self.health_records,
            versions: vec![
                ComponentVersion {
                    component: "robodr-agentd".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                },
                ComponentVersion {
                    component: robodr_ocsf::CONTRACT_NAME.into(),
                    version: robodr_ocsf::CONTRACT_VERSION.into(),
                },
            ],
            inputs,
            counters: HealthCounters {
                findings_spooled: self.stats.findings_spooled,
                finding_errors: self.stats.finding_errors,
                health_findings: self.stats.health_findings,
                spool_dropped: spool.dropped_full,
                spool_write_errors: spool.write_errors,
                note_errors: self.stats.note_errors,
            },
            blackbox: BlackBoxHealth {
                degraded: self.agent.evidence_degraded(),
                anchored: self.agent.blackbox_anchored(),
                anchor_failures: self.agent.blackbox_anchor_failures(),
            },
            reachability: v.reachability.clone(),
            credentials: v.credentials.clone(),
            clock: v.clock,
            disks: v.disks.clone(),
        };
        let st = match record.state {
            HealthLabel::Ok => "ok",
            HealthLabel::Degraded => "degraded",
            HealthLabel::Unknown => "unknown",
        };
        let dev = robodr_events::Deviation::new(
            crate::selfcheck::rules::HEALTH,
            robodr_events::Severity::Low,
            format!(
                "health record {} of robodr-agentd (state {st}, up {} s)",
                self.health_records,
                now_ms / 1000
            ),
        );
        let subject = Subject {
            node: Some("robodr-agentd".into()),
            ..Subject::default()
        };
        let safety = self.safety();
        let now = self.clock.now();
        let o = self
            .agent
            .report_health(now, "agentd:health", subject, dev, record, safety);
        self.emit(o);
    }

    fn snapshots(&self) -> Vec<InputSnapshot> {
        self.inputs
            .iter()
            .map(|i| InputSnapshot {
                name: i.name.clone(),
                last_rx_ms: i.stats.last_rx_ms(),
                // The producer's own losses count like queue drops.
                dropped: i
                    .stats
                    .dropped
                    .load(Ordering::Relaxed)
                    .saturating_add(i.stats.upstream_dropped.load(Ordering::Relaxed)),
                malformed: i.stats.malformed.load(Ordering::Relaxed),
                last_malformed: i.stats.last_malformed(),
                ended: i.stats.ended.load(Ordering::SeqCst),
                end_error: i.stats.end_error(),
            })
            .collect()
    }

    /// Handle inputs that ended since the last tick.
    fn handle_ended(&mut self) {
        let newly: Vec<usize> = self
            .inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| !input.end_handled && input.stats.ended.load(Ordering::SeqCst))
            .map(|(i, _)| i)
            .collect();
        if newly.is_empty() {
            return;
        }
        // Everything the input queued was sent before `ended` was set.
        while let Ok(m) = self.rx.try_recv() {
            self.handle(m);
        }
        for i in newly {
            let Some(input) = self.inputs.get_mut(i) else {
                continue;
            };
            input.end_handled = true;
            let err = input.stats.end_error();
            let _ = writeln!(
                self.log,
                "robodr-agentd: input {} ended{}",
                sanitize(&input.name),
                err.as_deref()
                    .map(|e| format!(" with an error: {e}"))
                    .unwrap_or_default()
            );
            if input.kind == InputKind::Capture {
                let mut found = Vec::new();
                if let Some(h) = self.capture_health.latest() {
                    found.extend(self.pipeline.capture_findings(&h));
                }
                found.extend(self.pipeline.finish());
                self.sensor_findings(found);
            }
        }
    }

    fn tick(&mut self, delay_ms: u64) {
        self.stats.ticks += 1;
        // Staleness is noticed (and recorded) even on a quiet bus.
        self.safety();
        let now = self.pipeline_now();
        let mut found = self.pipeline.tick_at(now);
        self.sync_identities();
        if let Some(h) = self.capture_health.latest() {
            found.extend(self.pipeline.capture_findings(&h));
        }
        self.sensor_findings(found);
        self.flood_close(false);
        self.gateway_close(false);
        self.handle_ended();

        let spool = self.spool.stats();
        let capture = self.capture_health.latest().unwrap_or_default();
        let snap = DaemonSnapshot {
            max_queue_age_ms: std::mem::take(&mut self.tick_max_age_ms),
            tick_delay_ms: delay_ms,
            spool_dropped: spool.dropped_full,
            spool_write_errors: spool.write_errors,
            evidence_degraded: self.agent.evidence_degraded(),
            profile_not_enforced: self.pipeline.status() != &ProfileStatus::Enforcing,
            all_inputs_gone: self.inputs_gone,
            capture_zenoh: capture.zenoh,
            capture_rtps: capture.rtps,
        };
        let inputs = self.snapshots();
        let (state, issues, recoveries) = self.health.evaluate(self.now_ms(), &inputs, &snap);
        if state.state != self.last_state.state {
            let _ = writeln!(
                self.log,
                "robodr-agentd: state {:?} -> {:?}: {}",
                self.last_state.state,
                state.state,
                sanitize(&state.reasons.join("; "))
            );
        }
        self.last_state = state;
        let st = match self.last_state.state {
            State::Ok => "ok",
            State::Degraded => "degraded",
            State::Unknown => "unknown",
        };
        self.notifier.notify(&format!("STATUS=state {st}"));
        for i in issues {
            self.health_issue(i);
        }
        for r in recoveries {
            self.recovery_note(&r);
        }
        self.correlation_tick();
        self.control_findings();
        self.early_warnings();
        self.health_record();
        self.evidence_incidents();
        self.retention_tick();
        self.mark_head();
        for f in self.agent.take_faults() {
            let _ = writeln!(
                self.log,
                "robodr-agentd: agent fault {:?}: {}",
                f.kind,
                sanitize(&f.detail)
            );
        }
        if let Err(e) = self.spool.prune(0, 0) {
            let _ = writeln!(self.log, "robodr-agentd: spool prune: {e}");
        }
        self.write_status(true);
    }

    /// Judge, record and answer the control-plane calls that are waiting
    /// (at most [`crate::control::CALLS_PER_POLL`]).
    fn control_poll(&mut self) {
        let Some(mut cp) = self.control.take() else {
            return;
        };
        for m in cp.take_calls() {
            let a = cp.engine.handle(&m.call, &m.meta, self);
            let what = match &m.call {
                cp_api::Call::Submit(r) => Some(format!("{} {}", r.action.as_str(), r.request_id)),
                cp_api::Call::Revert(id, _) => Some(format!("revert {id}")),
                cp_api::Call::Invalid(e) => Some(format!("invalid request ({})", e.code)),
                _ => None,
            };
            if let Some(what) = what {
                let status = a
                    .body
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| {
                        a.body
                            .pointer("/error/code")
                            .and_then(serde_json::Value::as_str)
                    })
                    .unwrap_or("?");
                let code = a
                    .body
                    .pointer("/refusal/code")
                    .and_then(serde_json::Value::as_str)
                    .map(|c| format!(" ({c})"))
                    .unwrap_or_default();
                let _ = writeln!(
                    self.log,
                    "robodr-agentd: control plane: {} from key {}: {status}{code}",
                    sanitize(&what),
                    sanitize(&m.meta.key_id)
                );
            }
            // The connection may have given up (timeout): nothing to do.
            let _ = m.reply.try_send(a);
        }
        self.control = Some(cp);
    }

    /// Rising control-plane failure counters become observe-only
    /// self-health findings, at most one per counter every
    /// `health_report_ms`.
    fn control_findings(&mut self) {
        let Some(cp) = &self.control else {
            return;
        };
        let counts = [
            cp.counters().unauthenticated.load(Ordering::Relaxed),
            cp.engine.stats.invalid,
        ];
        let last = cp.counters().last_auth_failure();
        let now_ms = self.now_ms();
        let every = self.r.config.daemon.health_report_ms;
        for (i, &count) in counts.iter().enumerate() {
            let (Some(reported), Some(reported_at)) = (
                self.control_reported.get_mut(i),
                self.control_reported_at_ms.get_mut(i),
            ) else {
                continue;
            };
            if count <= *reported || reported_at.is_some_and(|t| now_ms.saturating_sub(t) < every) {
                continue;
            }
            let delta = count - *reported;
            *reported = count;
            *reported_at = Some(now_ms);
            let dev = if i == 0 {
                robodr_events::Deviation::new(
                    health_rules::CONTROL_PLANE_UNAUTHENTICATED,
                    robodr_events::Severity::High,
                    format!(
                        "the control-plane API refused {delta} request(s) that failed \
                         authentication ({} in total; bad or missing signature, unknown key, \
                         stale timestamp or replayed nonce): someone without a SOC key may be \
                         trying to request robot actions; nothing was judged or executed; last: \
                         {}",
                        count,
                        last.as_deref().unwrap_or("-")
                    ),
                )
            } else {
                robodr_events::Deviation::new(
                    health_rules::CONTROL_PLANE_INVALID,
                    robodr_events::Severity::Medium,
                    format!(
                        "the control-plane API refused {delta} authenticated request(s) as \
                         invalid ({} in total: an action, parameter, ttl or authority the API \
                         never allows); each is recorded as a robodr.control_plane_rejected \
                         note; nothing was executed",
                        count
                    ),
                )
            };
            self.self_health("agentd:control_plane", dev);
        }
    }

    fn recovery_note(&mut self, r: &Recovery) {
        #[derive(Serialize)]
        struct Note<'b> {
            kind: &'static str,
            #[serde(flatten)]
            recovery: &'b Recovery,
        }
        let _ = writeln!(self.log, "robodr-agentd: health: recovered: {r:?}");
        let now = self.clock.now();
        let note = Note {
            kind: "robodr.agentd_recovery",
            recovery: r,
        };
        if self
            .agent
            .record_note(now, "recovery note", &note, false)
            .is_err()
        {
            self.stats.note_errors += 1;
        }
    }

    fn input_status(&self) -> Vec<InputStatus<'_>> {
        let now = self.now_ms();
        self.inputs
            .iter()
            .map(|i| InputStatus {
                name: &i.name,
                received: i.stats.received.load(Ordering::Relaxed),
                dropped: i.stats.dropped.load(Ordering::Relaxed),
                budget_drops: i.stats.budget_drops.load(Ordering::Relaxed),
                malformed: i.stats.malformed.load(Ordering::Relaxed),
                rejected_connections: i.stats.rejected_connections.load(Ordering::Relaxed),
                connections: i.stats.connections.load(Ordering::Relaxed),
                upstream_dropped: i.stats.upstream_dropped.load(Ordering::Relaxed),
                last_rx_age_ms: i.stats.last_rx_ms().map(|t| now.saturating_sub(t)),
                ended: i.stats.ended.load(Ordering::SeqCst),
                end_error: i.stats.end_error(),
            })
            .collect()
    }

    fn write_status(&mut self, running: bool) {
        let wall_ms = self.clock.now().wall_ns / 1_000_000;
        let safety_state = self.safety();
        let now_ms = self.now_ms();
        let status = Status {
            safety_state,
            safety_feed: self.feed.as_ref().map(|f| f.status(now_ms)),
            kind: "robodr.agentd_status",
            robot_id: &self.r.config.robot.id,
            wall_ms,
            uptime_ms: self.now_ms(),
            updated_mono_ms: monotonic_ms(),
            boot_id: &self.r.boot_id,
            stale_after_ms: self
                .r
                .config
                .daemon
                .tick_ms
                .saturating_mul(2)
                .saturating_add(self.r.config.daemon.lag_ms),
            running,
            health: &self.last_state,
            profile_status: self.pipeline.status().as_str(),
            inputs: self.input_status(),
            daemon: &self.stats,
            pipeline: self.pipeline.stats(),
            agent: self.agent.stats(),
            spool: self.spool.stats(),
            discovery_flood: self.flood.stats(),
            correlation: self.correlator.as_ref().map(|c| *c.stats()),
            signs_findings: self.agent.signs_findings(),
            evidence_degraded: self.agent.evidence_degraded(),
            blackbox: BlackboxStatus {
                anchored: self.agent.blackbox_anchored(),
                anchor_kind: self
                    .r
                    .config
                    .blackbox
                    .head_anchor
                    .as_ref()
                    .map_or("none", |a| a.kind()),
                anchor_failures: self.agent.blackbox_anchor_failures(),
                mark_failures: self.agent.blackbox_mark_failures(),
            },
            queue_bytes: self.budget.used(),
            queue_bytes_max: self.budget.max(),
            control_plane: self.control.as_ref().map(ControlPlane::status),
            executor: self.executor.as_ref().map(|l| l.stats()),
            key_protection: &self.r.key_protection,
            self_health: &self.self_view,
        };
        let res = serde_json::to_vec_pretty(&status)
            .map_err(std::io::Error::other)
            .and_then(|b| {
                let b = Arc::new(b);
                if let Ok(mut g) = self.status_snapshot.lock() {
                    *g = b.clone();
                }
                self.spool.write_side_file(STATUS_FILE, &b)
            });
        if let Err(e) = res {
            let _ = writeln!(self.log, "robodr-agentd: writing status: {e}");
        }
    }

    fn heartbeat(&mut self, kind: &'static str) {
        #[derive(Serialize)]
        struct Heartbeat<'b> {
            kind: &'static str,
            uptime_ms: u64,
            #[serde(flatten)]
            health: &'b HealthState,
            inputs: Vec<InputStatus<'b>>,
            daemon: &'b DaemonStats,
            pipeline: &'b PipelineStats,
            agent: AgentStats,
            spool: SpoolStats,
            #[serde(skip_serializing_if = "Option::is_none")]
            profile_accepted: Option<&'b robodr_commission::trust::AcceptedState>,
            #[serde(skip_serializing_if = "Option::is_none")]
            correlation: Option<robodr_correlate::Stats>,
            #[serde(skip_serializing_if = "Option::is_none")]
            control_plane: Option<ControlStatus>,
        }
        self.stats.heartbeats += 1;
        let stats = self.stats;
        let hb = Heartbeat {
            kind,
            uptime_ms: self.now_ms(),
            health: &self.last_state,
            inputs: self.input_status(),
            daemon: &stats,
            pipeline: self.pipeline.stats(),
            agent: self.agent.stats(),
            spool: self.spool.stats(),
            profile_accepted: self.profile_accepted.as_ref(),
            correlation: self.correlator.as_ref().map(|c| *c.stats()),
            control_plane: self.control.as_ref().map(ControlPlane::status),
        };
        // Serialise first: `hb` borrows self immutably.
        let value = serde_json::to_value(&hb).unwrap_or(serde_json::Value::Null);
        let now = self.clock.now();
        match self.agent.record_note(now, "heartbeat", &value, false) {
            Ok(r) => self.last_note_segment = Some(r.segment),
            Err(e) => {
                self.stats.note_errors += 1;
                let _ = writeln!(
                    self.log,
                    "robodr-agentd: heartbeat not recorded: {}",
                    sanitize(&e.join("; "))
                );
            }
        }
    }

    fn shutdown(mut self, reason: StopReason) -> Result<Summary, DaemonError> {
        let _ = writeln!(self.log, "robodr-agentd: stopping ({reason:?})");
        // No request is judged during shutdown: queued ones are answered
        // 503 by their connections (the channel closes).
        if let Some(cp) = self.control.as_mut() {
            cp.shutdown();
        }
        self.stop_inputs.store(true, Ordering::SeqCst);
        if let Some(h) = self.status_server.take() {
            let _ = h.join();
        }
        // Join inputs that poll the stop flag (bounded by their timeouts);
        // stdin may block forever and is left behind.
        for i in &mut self.inputs {
            if i.joinable {
                if let Some(h) = i.thread.take() {
                    let _ = h.join();
                }
            }
        }
        // Drain what is queued (bounded by the queue capacity).
        while let Ok(m) = self.rx.try_recv() {
            self.handle(m);
        }
        let mut found = Vec::new();
        if let Some(h) = self.capture_health.latest() {
            found.extend(self.pipeline.capture_findings(&h));
        }
        found.extend(self.pipeline.finish());
        self.sensor_findings(found);
        self.flood_close(true);
        self.gateway_close(true);
        // Gap 1: the listeners are joined and the queue drained, so nothing
        // is appended after this head: the next start may verify it exactly.
        self.record_state_heads("stop");
        self.record_executor_head("stop", false);
        self.heartbeat("robodr.agentd_stop");
        self.write_status(false);
        let pipeline = *self.pipeline.stats();
        let finished = self.agent.finish().map_err(DaemonError::Agent)?;
        if let Err(e) = self
            .spool
            .write_side_file(CHECKPOINT_FILE, finished.checkpoint.to_json().as_bytes())
        {
            let _ = writeln!(self.log, "robodr-agentd: writing checkpoint copy: {e}");
        }
        let _ = writeln!(
            self.log,
            "robodr-agentd: stopped: {} datagrams, {} events, {} findings spooled, black box sealed at seq {}",
            self.stats.datagrams, self.stats.events, self.stats.findings_spooled, finished.checkpoint.seq
        );
        Ok(Summary {
            reason,
            stats: self.stats,
            agent: finished.stats,
            pipeline,
            spool: self.spool.stats(),
            last_state: self.last_state,
            finished,
        })
    }
}

/// The control-plane engine's view of the daemon.
impl cp_api::Host for Daemon<'_> {
    fn safety_state(&mut self) -> SafetyState {
        self.safety()
    }

    fn safety_source(&self) -> &'static str {
        if self.feed.is_some() {
            "safety_feed"
        } else {
            "configuration"
        }
    }

    fn context(&self) -> OperationalContext {
        let c = &self.r.config.context;
        // The live context as last evaluated (`safety_feed` context
        // sources), else the configured one.
        let live = self
            .feed
            .as_ref()
            .and_then(SafetyFeed::live_context)
            .unwrap_or(LiveContext {
                control: c.control,
                phase: c.phase,
                connectivity: c.connectivity,
            });
        OperationalContext {
            platform: self.r.policy.platform,
            morphology: self.r.policy.morphology,
            phase: live.phase,
            connectivity: live.connectivity,
            control: live.control,
            operator_present: c.operator_present,
            // Locked in the agent *and* enforced by the pipeline.
            profile_locked: self.agent.profile().locked
                && self.pipeline.status() == &ProfileStatus::Enforcing,
        }
    }

    fn policy(&self) -> &robodr_responder::ResponsePolicy {
        &self.r.policy
    }

    fn caps(&self) -> cp_api::EnvelopeCaps {
        cp_api::EnvelopeCaps::of(self.agent.profile())
    }

    fn health(&self) -> &'static str {
        match self.last_state.state {
            State::Ok => "ok",
            State::Degraded => "degraded",
            State::Unknown => "unknown",
        }
    }

    fn wall_ms(&self) -> u64 {
        self.clock.now().wall_ns / 1_000_000
    }

    fn record(&mut self, what: &str, note: &serde_json::Value) -> Result<String, String> {
        let now = self.clock.now();
        match self.agent.record_note(now, what, note, true) {
            Ok(r) => Ok(r.uri(&self.r.config.robot.id)),
            Err(e) => {
                self.stats.note_errors += 1;
                Err(e.join("; "))
            }
        }
    }
}

/// A decoded Unitree joint command frame as the Motion Firewall's
/// [`robodr_firewall::JointFrame`]: every slot on the wire (mode octet via
/// `MotorMode::from_u8`: any non-zero mode is enabled), the decoder's CRC
/// verdict and the hg `LowCmd`'s `mode_pr` / `mode_machine`. `None` only for
/// a frame wider than the firewall's `MAX_MOTORS` (35, the widest Unitree
/// layout), which the decoder never produces: such a frame is not checked
/// (and counted as a missing joint frame by the agent) rather than cut.
pub fn joint_frame(
    j: &robodr_ros2_pipeline::JointCommandSample,
) -> Option<robodr_firewall::JointFrame> {
    use robodr_firewall::{JointFrame, MotorCmd, MotorMode};
    let motors: Vec<MotorCmd> = j
        .frame
        .as_slice()
        .iter()
        .map(|m| MotorCmd {
            mode: MotorMode::from_u8(m.mode),
            q: f64::from(m.q),
            dq: f64::from(m.dq),
            tau: f64::from(m.tau),
            kp: f64::from(m.kp),
            kd: f64::from(m.kd),
        })
        .collect();
    let mut f = JointFrame::from_slice(&motors, j.crc_ok)?;
    f.mode_pr = j.mode_pr;
    f.mode_machine = j.mode_machine;
    Some(f)
}

// --- executor v1 -------------------------------------------------------------
// Kept apart from the control-plane code: the link to robodr-executor
// (`executor.enabled`, crate::executor_link).
impl Daemon<'_> {
    /// Publish the safety state for the executor's apply-time re-check,
    /// dispatch staged orders whose request / plan is in the black box, do
    /// `record_evidence` marks, and record the executor's events.
    fn executor_poll(&mut self) {
        let Some(link) = self.executor.take() else {
            return;
        };
        let state = self.safety();
        link.safety().set(state);
        for st in link.take_staged() {
            use crate::executor_link::Staged;
            match st {
                Staged::Submit(o) => {
                    // A control-plane order goes out only once its request
                    // is stored (i.e. recorded); a planner order's plan was
                    // recorded before the agent offered it.
                    let recorded = match &o.origin {
                        // CP review finding 3: the stored request must be
                        // the one this order was made for.
                        robodr_executor::Origin::ControlPlane { .. } => {
                            crate::executor_link::release_ok(
                                &o,
                                self.control.as_ref().and_then(|c| c.engine.get(&o.id)),
                            )
                        }
                        robodr_executor::Origin::Planner { .. } => true,
                    };
                    if recorded {
                        // A quarantine carries the participant's SPDP
                        // unicast locators (the executor refuses it
                        // without): its own last trusted ones, also after
                        // it left (red team F3), only on addresses it was
                        // seen sending from, never another participant's,
                        // none for a contested prefix (review H1, H2, M5);
                        // a GUID-prefix-only quarantine is vouched for when
                        // none is left. A SOC request keeps the named
                        // prefix's locators remembered (review M6).
                        if let (
                            robodr_executor::Origin::ControlPlane { .. },
                            robodr_executor::order::Target::Participant { guid_prefix, .. },
                        ) = (&o.origin, &o.target)
                        {
                            self.pipeline.note_soc_reference(&guid_prefix.0);
                        }
                        let now = self.pipeline_now();
                        let binding = self.pipeline.binding();
                        let o =
                            link.with_locators(o, crate::executor_link::vouch_with(binding, now));
                        link.dispatch(Staged::Submit(o));
                    } else {
                        link.count_dropped();
                    }
                }
                Staged::Revert { id, reason, soc } => {
                    let recorded = self
                        .control
                        .as_ref()
                        .and_then(|c| c.engine.get(&id))
                        .is_some_and(|s| s.revert.is_some());
                    if recorded {
                        link.dispatch(Staged::Revert { id, reason, soc });
                    } else {
                        link.count_dropped();
                    }
                }
                Staged::Evidence(o) => {
                    let refs: Vec<String> = self
                        .control
                        .as_ref()
                        .and_then(|c| c.engine.get(&o.id))
                        .filter(|s| crate::executor_link::release_ok(&o, Some(s)))
                        .map(|s| vec![s.evidence.clone()])
                        .unwrap_or_default();
                    if refs.is_empty() {
                        link.count_dropped();
                        continue;
                    }
                    let robot = self.r.config.robot.id.clone();
                    let now_ms = cp_api::Host::wall_ms(self);
                    let mut sink = EvidenceSink {
                        daemon: self,
                        robot: &robot,
                    };
                    let out = robodr_executor::evidence::record(&o, &refs, &mut sink, now_ms);
                    link.put(out);
                }
            }
        }
        // Journal every changed outcome at once (control plane v2): a
        // request that reached `verified` reads `verified` after a restart
        // even if nobody asked for it before.
        let changed = link.take_changed();
        if let Some(cp) = self.control.as_mut() {
            for id in changed {
                cp.engine.sync(&id);
            }
        }
        for ev in link.take_events() {
            let note = serde_json::json!({
                "kind": "robodr.executor_event",
                "event": ev,
            });
            let critical = matches!(
                ev.kind,
                robodr_executor::journal::EventKind::RevertFailed
                    | robodr_executor::journal::EventKind::Drift
                    | robodr_executor::journal::EventKind::RemovedExternally
                    | robodr_executor::journal::EventKind::JournalReset
                    | robodr_executor::journal::EventKind::Overridden
            );
            let now = self.clock.now();
            if self
                .agent
                .record_note(now, "executor event", &note, critical)
                .is_err()
            {
                self.stats.note_errors += 1;
            }
            let _ = writeln!(
                self.log,
                "robodr-agentd: executor: {:?} {} {}",
                ev.kind,
                sanitize(ev.id.as_deref().unwrap_or("-")),
                sanitize(&ev.detail)
            );
            self.executor_event_finding(&ev);
        }
        let alarms = link.take_head_alarms();
        self.executor = Some(link);
        // Review of gap 1 (findings 1 and 2): an executor journal that was
        // reset, replaced or rolled back is recorded at once and reported.
        for (_, alarm) in alarms {
            self.record_executor_head("changed", true);
            let dev = robodr_events::Deviation::new(
                health_rules::EXECUTOR_JOURNAL_RESET,
                robodr_events::Severity::High,
                alarm,
            );
            self.self_health("agentd:executor", dev);
        }
        if self.executor_head_recorded.is_none() {
            // The first head agentd learns is anchored at once.
            self.record_executor_head("first", false);
        }
    }

    /// S5 / gap 2: an executor event that leaves the robot in an unknown
    /// state is a finding, not only a black-box note: a failed (stuck)
    /// revert, whose rules may still be in force, is High once per request
    /// until a revert of it succeeds (the executor retries every tick and
    /// reports every retry); a journal reset (unreadable, or failing its
    /// seal) is High each time.
    fn executor_event_finding(&mut self, ev: &robodr_executor::journal::Event) {
        use robodr_executor::journal::EventKind;
        let id = ev.id.as_deref().unwrap_or("-");
        let action = ev
            .action
            .map_or_else(|| "-".to_string(), |a| a.as_str().to_string());
        let dev = match ev.kind {
            EventKind::Reverted | EventKind::Expired => {
                self.revert_failed_reported.remove(id);
                return;
            }
            EventKind::RevertFailed => {
                if !self.revert_failed_reported.insert(id.to_string()) {
                    return;
                }
                // The TTL the SOC asked for, when it is a control-plane
                // request (the executor's detail carries its own).
                let ttl = self
                    .control
                    .as_ref()
                    .and_then(|c| c.engine.get(id))
                    .and_then(|s| s.request.ttl_seconds)
                    .map_or_else(|| "-".to_string(), |t| format!("{t}s"));
                robodr_events::Deviation::new(
                    health_rules::EXECUTOR_REVERT_FAILED,
                    robodr_events::Severity::High,
                    format!(
                        "robodr-executor could not revert action {action} of request {} (ttl \
                         {ttl}); its rules may still be in force and the executor retries every \
                         tick: check `robodr-executor status`; error: {}",
                        sanitize(id),
                        sanitize(&ev.detail)
                    ),
                )
            }
            EventKind::Overridden => match pause_overridden(ev) {
                Some(d) => d,
                None => return,
            },
            EventKind::Commissioning => {
                match executor_commissioning_finding(ev, self.r.executor_bound) {
                    Some(d) => d,
                    None => return,
                }
            }
            EventKind::JournalReset => robodr_events::Deviation::new(
                health_rules::EXECUTOR_JOURNAL_RESET,
                robodr_events::Severity::High,
                format!(
                    "robodr-executor found its journal unreadable or failing its seal and started \
                     empty: every action it held was lifted and its history is lost; it refuses \
                     orders until `robodr-executor rearm`: {}",
                    sanitize(&ev.detail)
                ),
            ),
            _ => return,
        };
        self.self_health("agentd:executor", dev);
    }
}

/// Sales-readiness T42: the executor's safe_pause latch found the robot set
/// moving again while paused (a navigation goal, a flight-mode change) and
/// paused it again: a High finding per event, naming the request and what
/// was found.
fn pause_overridden(ev: &robodr_executor::journal::Event) -> Option<robodr_events::Deviation> {
    if ev.kind != robodr_executor::journal::EventKind::Overridden {
        return None;
    }
    Some(robodr_events::Deviation::new(
        health_rules::EXECUTOR_PAUSE_OVERRIDDEN,
        robodr_events::Severity::High,
        format!(
            "robodr-executor found the robot set moving while safe_pause {} is in force and \
             paused it again: {}",
            sanitize(ev.id.as_deref().unwrap_or("-")),
            sanitize(&ev.detail)
        ),
    ))
}

/// Review WP6: the executor's signed-commissioning notes (`commissioning`
/// events). A flag it does not honour, or its `commissioning` section
/// removed or changed at runtime (a tamper indicator), is a High
/// `robot.agent.config_unattested` finding; UNSIGNED flags are one too when
/// agentd's trusted locked profile binds an executor file
/// (`executor_bound`: the unit was commissioned with signed flags, so an
/// executor started without its section is a downgrade). A lab-only
/// chain (agentd warns about it itself) and notes that cleared raise
/// nothing.
fn executor_commissioning_finding(
    ev: &robodr_executor::journal::Event,
    executor_bound: bool,
) -> Option<robodr_events::Deviation> {
    use robodr_executor::config::{note_class, NoteClass};
    if ev.kind != robodr_executor::journal::EventKind::Commissioning {
        return None;
    }
    let why = match note_class(&ev.detail) {
        NoteClass::Unattested => "robodr-executor does not honour a commissioning claim",
        NoteClass::Unsigned if executor_bound => {
            "robodr-executor runs with UNSIGNED oem_validated flags (no `commissioning` \
             section) on a unit whose trusted profile binds its files"
        }
        NoteClass::Unsigned | NoteClass::LabOnly | NoteClass::Cleared => return None,
    };
    Some(robodr_events::Deviation::new(
        crate::commissioned::CONFIG_UNATTESTED,
        robodr_events::Severity::High,
        format!("{why}: {}", sanitize(&ev.detail)),
    ))
}

#[cfg(test)]
mod executor_commissioning_tests {
    use robodr_executor::journal::{Event, EventKind};

    fn ev(kind: EventKind, detail: &str) -> Event {
        Event {
            seq: 1,
            at_ms: 1,
            kind,
            id: None,
            action: None,
            detail: detail.into(),
        }
    }

    /// Review WP6: before, a commissioning change was a `reconciled` event
    /// and executor start notes were not journalled; neither reached the
    /// SOC as a finding.
    #[test]
    fn executor_commissioning_notes_are_findings() {
        use super::executor_commissioning_finding as f;
        let removed = ev(
            EventKind::Commissioning,
            "WARNING: the `commissioning` section of /etc/robodr/executor.json was removed \
             since this executor read it; still verifying against the section it had",
        );
        let d = f(&removed, false).unwrap();
        assert_eq!(d.rule, "robot.agent.config_unattested");
        assert_eq!(d.severity, robodr_events::Severity::High);
        assert!(d.detail.contains("removed"), "{}", d.detail);

        let unsigned = ev(
            EventKind::Commissioning,
            robodr_executor::config::UNSIGNED_NOTE,
        );
        assert!(f(&unsigned, false).is_none());
        let d = f(&unsigned, true).unwrap();
        assert!(d.detail.contains("UNSIGNED"), "{}", d.detail);

        let lab = ev(
            EventKind::Commissioning,
            &format!(
                "WARNING: /etc/robodr/profile.json: {}",
                robodr_commission::poc::LAB_ONLY_BANNER
            ),
        );
        assert!(f(&lab, true).is_none());
        let cleared = ev(
            EventKind::Commissioning,
            robodr_executor::config::NOTES_CLEARED,
        );
        assert!(f(&cleared, true).is_none());
        // Another kind with the same text is not this finding.
        assert!(f(&ev(EventKind::Reconciled, "nothing to do"), true).is_none());
    }
}

#[cfg(test)]
mod pause_overridden_tests {
    use robodr_executor::journal::{Event, EventKind};

    /// T42: an `overridden` executor event is a High finding; other kinds
    /// are not this one.
    #[test]
    fn an_overridden_pause_is_a_high_finding() {
        let ev: Event = serde_json::from_value(serde_json::json!({
            "seq": 7, "at_ms": 1, "kind": "overridden", "id": "p-1",
            "action": "safe_pause",
            "detail": "HIGH: nav2: 1 navigation goal(s) sent while paused were cancelled"
        }))
        .unwrap();
        let d = super::pause_overridden(&ev).unwrap();
        assert_eq!(d.rule, "robot.agent.executor_pause_overridden");
        assert_eq!(d.severity, robodr_events::Severity::High);
        assert!(
            d.detail.contains("p-1") && d.detail.contains("navigation goal"),
            "{d:?}"
        );
        assert!(
            robodr_ocsf::builder::rule_known(&d.rule),
            "no catalog entry"
        );
        let mut other = ev.clone();
        other.kind = EventKind::Drift;
        assert!(super::pause_overridden(&other).is_none());
    }
}

/// The black box as the `record_evidence` adapter's sink.
struct EvidenceSink<'d, 'a> {
    daemon: &'d mut Daemon<'a>,
    robot: &'d str,
}

impl robodr_executor::evidence::EvidenceSink for EvidenceSink<'_, '_> {
    fn mark(&mut self, note: &serde_json::Value) -> Result<String, String> {
        // Critical: fsynced before the reference is returned.
        cp_api::Host::record(self.daemon, "evidence mark", note)
    }

    fn verify(&mut self, reference: &str) -> Result<(), String> {
        let prefix = format!("robodr-blackbox://{}/", self.robot);
        let hash = reference.rsplit_once("?sha256=").map(|(_, h)| h);
        if reference.starts_with(&prefix)
            && hash.is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            Ok(())
        } else {
            Err(format!(
                "unexpected evidence reference {}",
                sanitize(reference)
            ))
        }
    }
}

/// Serve the latest status on the status socket (`spool.status_socket`,
/// review H1): every connection gets the current `status.json` bytes and
/// is closed; nothing is read from it. A connection that does not take the
/// bytes within a second is dropped. Until the first status is written a
/// connection is closed empty (the reader treats that as `unknown`).
/// Removes the socket file on exit, if it is still the one bound here.
fn serve_status(
    sock: input::EventSocket,
    stop: Arc<AtomicBool>,
    snapshot: Arc<std::sync::Mutex<Arc<Vec<u8>>>>,
) {
    while !stop.load(Ordering::Relaxed) {
        match sock.listener.accept() {
            Ok((mut conn, _)) => {
                let bytes = snapshot.lock().map(|g| g.clone()).unwrap_or_default();
                if conn.set_nonblocking(false).is_ok()
                    && conn.set_write_timeout(Some(Duration::from_secs(1))).is_ok()
                {
                    let _ = conn.write_all(&bytes);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    sock.remove_if_ours();
}

#[cfg(test)]
mod status_socket_tests {
    use super::*;
    use std::io::Read;

    /// Review H1: the status socket serves the latest status bytes, from
    /// this process (the reader checks SO_PEERCRED), empty before the
    /// first status.
    #[test]
    fn serves_the_latest_status() {
        let d = std::env::temp_dir().join(format!("agentd-status-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join("status.sock");
        let l = input::bind_event_socket(&path).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let snap: Arc<std::sync::Mutex<Arc<Vec<u8>>>> = Arc::default();
        let h = {
            let (stop, snap) = (stop.clone(), snap.clone());
            std::thread::spawn(move || serve_status(l, stop, snap))
        };
        let read = || {
            let mut c = std::os::unix::net::UnixStream::connect(&path).unwrap();
            assert_eq!(
                crate::host::peer_uid(&c).unwrap(),
                crate::config::effective_uid()
            );
            let mut b = Vec::new();
            c.read_to_end(&mut b).unwrap();
            b
        };
        assert!(read().is_empty());
        *snap.lock().unwrap() = Arc::new(b"{\"running\":true}".to_vec());
        assert_eq!(read(), b"{\"running\":true}");
        stop.store(true, Ordering::SeqCst);
        h.join().unwrap();
        assert!(!path.exists(), "the socket is removed at stop");
        std::fs::remove_dir_all(&d).unwrap();
    }
}

#[cfg(test)]
mod replay_timeline_tests {
    use super::ReplayTimeline;
    use std::time::{Duration, Instant};

    #[test]
    fn packets_are_placed_by_record_time_not_by_handling_time() {
        let i0 = Instant::now();
        let mut tl = ReplayTimeline::default();
        assert_eq!(tl.position(), None);
        assert_eq!(tl.instant(), None);
        // Anchored at the first packet: capture 5 s -> daemon 100 ms.
        assert_eq!(tl.place(5_000_000_000, 100_000_000, i0), 100_000_000);
        // Handled "much later" or "at once": only the record time counts.
        assert_eq!(
            tl.place(5_250_000_000, 9_000_000_000, i0 + Duration::from_secs(9)),
            350_000_000
        );
        assert_eq!(tl.place(6_000_000_000, 0, i0), 1_100_000_000);
        assert_eq!(tl.position(), Some(1_100_000_000));
        assert_eq!(tl.instant(), Some(i0 + Duration::from_secs(1)));
        // An earlier record (merged interfaces) never moves it back.
        assert_eq!(tl.place(5_500_000_000, 0, i0), 1_100_000_000);
        assert_eq!(tl.place(1, 0, i0), 1_100_000_000);
        assert_eq!(tl.position(), Some(1_100_000_000));
    }
}
