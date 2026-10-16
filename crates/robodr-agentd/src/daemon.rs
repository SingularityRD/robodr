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
//! 3. evaluates self-health ([`crate::health`]) and reports issues;
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
//! handled. Each event goes through `Agent::handle`, exactly like a JSONL
//! event: `Profile::evaluate` (envelope), the Motion Firewall, the motion
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
//! # What the daemon does with a plan
//!
//! Nothing. The agent's executor is the default `NoopExecutor`: plans
//! (dispositions, `would_have`) are recorded in the black box and carried in
//! the finding, never executed. Wiring an executor is future work and must
//! follow `robodr_agent::executor`'s contract.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use robodr_agent::{
    Agent, AgentConfig, AgentStats, Detector, Finished, FirewallSettings, MonitorSettings, Outcome,
};
use robodr_blackbox::{Clock, RecorderConfig, SystemClock, TimeSource, Timestamp};
use robodr_events::profile::Profile;
use robodr_firewall::FailBehaviour;
use robodr_ocsf::{AttestationStatus, PlatformFamily as OcsfPlatform, RobotInfo, Subject};
use robodr_responder::OperationalContext;
use robodr_ros2_pipeline::config::CaptureInput;
use robodr_ros2_pipeline::{
    sanitize, Finding, MotionSample, Pipeline, PipelineStats, ProfileStatus, SharedHealth,
};
use serde::Serialize;

use crate::config::{check_daemon_dirs, resolve_path, EventInputConfig, Resolved};
use crate::health::{
    DaemonSnapshot, HealthConfig, HealthMonitor, HealthState, InputSnapshot, Issue, Recovery, State,
};
use crate::input::{self, Feed, InputStats, Msg, Payload, QueueBudget};
use crate::notify::{monotonic_ms, Notifier};
use crate::spool::{Spool, SpoolError, SpoolStats};

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
    last_rx_age_ms: Option<u64>,
    ended: bool,
    end_error: Option<String>,
}

#[derive(Serialize)]
struct Status<'a> {
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
    evidence_degraded: bool,
    queue_bytes: usize,
    queue_bytes_max: usize,
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
    budget: Arc<QueueBudget>,
    /// Every sender of the queue is gone (all input threads exited).
    inputs_gone: bool,
    notifier: Notifier,
    health: HealthMonitor,
    last_state: HealthState,
    stats: DaemonStats,
    /// Largest queue latency since the last tick.
    tick_max_age_ms: u64,
    /// The enforced locked profile's anti-rollback record, re-recorded in
    /// every heartbeat (see [`crate::profile_chain`]).
    profile_accepted: Option<robodr_commission::trust::AcceptedState>,
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
        let mut acfg = AgentConfig::new(
            robot,
            profile,
            r.policy.clone(),
            context,
            RecorderConfig::new(&cfg.blackbox.dir, &cfg.robot.id, &r.boot_id),
        );
        acfg.profile_version = robodr_commission::trust::version_label(
            pipeline.profile(),
            pipeline.status() == &ProfileStatus::Enforcing,
        );
        acfg.attestation = AttestationStatus::Unknown;
        acfg.kafka_partitions = cfg.robot.kafka_partitions;
        match (&cfg.firewall, validated) {
            (Some(fw), true) => {
                let mut fs =
                    FirewallSettings::from_profile(&acfg.profile, &fw.allow, &fw.max_angular)
                        .map_err(DaemonError::Agent)?;
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
        let agent =
            Agent::new(acfg, signer, Box::new(clock.clone())).map_err(DaemonError::Agent)?;

        let spool = Spool::open(&cfg.spool.dir, cfg.spool.max_bytes, cfg.spool.max_files)
            .map_err(|e| DaemonError::Io(format!("spool {}: {e}", cfg.spool.dir.display())))?;

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
        drop(tx);
        for (i, (feed, body)) in spawns.into_iter().enumerate() {
            let h = std::thread::Builder::new()
                .name(format!("agentd-in-{i}"))
                .spawn(move || body(feed))
                .map_err(|e| DaemonError::Io(format!("spawning input thread: {e}")))?;
            inputs[i].thread = Some(h);
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
            health,
            last_state: HealthState {
                state: State::Unknown,
                reasons: vec!["starting".into()],
            },
            stats: DaemonStats::default(),
            tick_max_age_ms: 0,
            profile_accepted: None,
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
        }
        let note = StartNote {
            kind: "robodr.agentd_start",
            version: env!("CARGO_PKG_VERSION"),
            robot_id: &cfg.robot.id,
            profile_model: &d.pipeline.profile().model,
            profile_status: d.pipeline.status().as_str(),
            inputs: d.inputs.iter().map(|i| i.name.as_str()).collect(),
            safety_state: cfg.context.safety_state,
        };
        let now = d.clock.now();
        if let Err(e) = d.agent.record_note(now, "start note", &note, true) {
            d.stats.note_errors += 1;
            let _ = writeln!(d.log, "robodr-agentd: start note not recorded: {e:?}");
        }
        d.profile_witness(accepted_ok);
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
            let now = Instant::now();
            if now >= next_tick {
                let delay = ms(now.duration_since(next_tick));
                self.tick(delay);
                // Do not try to catch up missed ticks one by one.
                next_tick = (next_tick + tick).max(now);
                if now >= next_heartbeat {
                    self.heartbeat("robodr.agentd_heartbeat");
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
        self.tick_max_age_ms = self.tick_max_age_ms.max(age);
        self.stats.max_queue_age_ms = self.stats.max_queue_age_ms.max(age);
        match m.payload {
            Payload::Datagram(d) => {
                self.stats.datagrams += 1;
                let capture_ns = self.clock.now().mono_ns;
                let out = self.pipeline.process_datagram_with_motion(&d, capture_ns);
                self.sensor_findings(out.findings);
                for s in out.motion {
                    self.motion_sample(s);
                }
            }
            Payload::Event(ev) => {
                self.stats.events += 1;
                let now = self.clock.now();
                let safety = self.r.config.context.safety_state;
                let outs = self.agent.handle(now, &ev, safety);
                for o in outs {
                    self.emit(o);
                }
            }
        }
    }

    /// A decoded motion command / feedback -> agent (profile, firewall,
    /// motion monitor) -> spool.
    fn motion_sample(&mut self, s: MotionSample) {
        self.stats.motion_events += 1;
        let now = self.clock.now();
        let safety = self.r.config.context.safety_state;
        let outs = self.agent.handle(now, &s.event, safety);
        for o in outs {
            self.emit(o);
        }
    }

    /// Pipeline findings -> agent -> spool.
    fn sensor_findings(&mut self, found: Vec<Finding>) {
        let safety = self.r.config.context.safety_state;
        for f in found {
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

    fn emit(&mut self, o: Outcome) {
        self.stats.outcomes += 1;
        let reserve = o.detector == Detector::SelfHealth;
        match &o.finding {
            Some(f) => match self.spool.write(f, reserve) {
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
        let now = self.clock.now();
        let safety = self.r.config.context.safety_state;
        let o =
            self.agent
                .handle_external(now, Detector::SelfHealth, &source, subject, dev, safety);
        self.emit(o);
    }

    fn snapshots(&self) -> Vec<InputSnapshot> {
        self.inputs
            .iter()
            .map(|i| InputSnapshot {
                name: i.name.clone(),
                last_rx_ms: i.stats.last_rx_ms(),
                dropped: i.stats.dropped.load(Ordering::Relaxed),
                malformed: i.stats.malformed.load(Ordering::Relaxed),
                last_malformed: i.stats.last_malformed(),
                ended: i.stats.ended.load(Ordering::SeqCst),
                end_error: i.stats.end_error(),
            })
            .collect()
    }

    /// Handle inputs that ended since the last tick.
    fn handle_ended(&mut self) {
        let newly: Vec<usize> = (0..self.inputs.len())
            .filter(|&i| {
                !self.inputs[i].end_handled && self.inputs[i].stats.ended.load(Ordering::SeqCst)
            })
            .collect();
        if newly.is_empty() {
            return;
        }
        // Everything the input queued was sent before `ended` was set.
        while let Ok(m) = self.rx.try_recv() {
            self.handle(m);
        }
        for i in newly {
            self.inputs[i].end_handled = true;
            let err = self.inputs[i].stats.end_error();
            let _ = writeln!(
                self.log,
                "robodr-agentd: input {} ended{}",
                sanitize(&self.inputs[i].name),
                err.as_deref()
                    .map(|e| format!(" with an error: {e}"))
                    .unwrap_or_default()
            );
            if self.inputs[i].kind == InputKind::Capture {
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
        let mut found = self.pipeline.tick();
        if let Some(h) = self.capture_health.latest() {
            found.extend(self.pipeline.capture_findings(&h));
        }
        self.sensor_findings(found);
        self.handle_ended();

        let spool = self.spool.stats();
        let snap = DaemonSnapshot {
            max_queue_age_ms: std::mem::take(&mut self.tick_max_age_ms),
            tick_delay_ms: delay_ms,
            spool_dropped: spool.dropped_full,
            spool_write_errors: spool.write_errors,
            evidence_degraded: self.agent.evidence_degraded(),
            profile_not_enforced: self.pipeline.status() != &ProfileStatus::Enforcing,
            all_inputs_gone: self.inputs_gone,
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
                last_rx_age_ms: i.stats.last_rx_ms().map(|t| now.saturating_sub(t)),
                ended: i.stats.ended.load(Ordering::SeqCst),
                end_error: i.stats.end_error(),
            })
            .collect()
    }

    fn write_status(&mut self, running: bool) {
        let wall_ms = self.clock.now().wall_ns / 1_000_000;
        let status = Status {
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
            evidence_degraded: self.agent.evidence_degraded(),
            queue_bytes: self.budget.used(),
            queue_bytes_max: self.budget.max(),
        };
        let res = serde_json::to_vec_pretty(&status)
            .map_err(std::io::Error::other)
            .and_then(|b| self.spool.write_side_file(STATUS_FILE, &b));
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
        };
        // Serialise first: `hb` borrows self immutably.
        let value = serde_json::to_value(&hb).unwrap_or(serde_json::Value::Null);
        let now = self.clock.now();
        if let Err(e) = self.agent.record_note(now, "heartbeat", &value, false) {
            self.stats.note_errors += 1;
            let _ = writeln!(
                self.log,
                "robodr-agentd: heartbeat not recorded: {}",
                sanitize(&e.join("; "))
            );
        }
    }

    fn shutdown(mut self, reason: StopReason) -> Result<Summary, DaemonError> {
        let _ = writeln!(self.log, "robodr-agentd: stopping ({reason:?})");
        self.stop_inputs.store(true, Ordering::SeqCst);
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
