//! Offline replay: a JSON Lines file of `RobotEvent`s (the same format
//! `robodr-commission` reads) through the full agent chain, then the
//! black-box verifier and the evidence-link check. The `robodr-replay`
//! binary is a thin argument parser over [`run`] and [`verify`].
//!
//! Time is a [`ReplayClock`]: wall time starts at `start_wall_ms`, the
//! monotonic clock at 0, and event `k` (1-based, counting events, not lines)
//! is observed at `k * step_ns`. `MotionFeedback.timestamp_ns` in the input
//! must use that monotonic base for the motion monitor's stamp checks.
//!
//! # Guarantees
//!
//! * **Deterministic.** Same input files, options and key give byte-identical
//!   findings, outcomes and black-box segments. [`run`] therefore refuses a
//!   black-box directory that already holds anything: resuming an existing
//!   chain would mix old evidence into the run and change every hash.
//! * **Cannot act.** The agent is marked as a replay (every
//!   [`crate::ExecutionRequest`] has `replay: true`, for which an executor
//!   must do nothing), and [`run`] accepts no executor at all, only an
//!   optional dry-run log of what would have been requested.
//! * **Bounded.** At most [`ReplayOptions::max_retained_outcomes`] outcomes
//!   are kept in the summary (counts cover all of them); evidence links are
//!   de-duplicated, so link resolution is bounded by the black box's own
//!   retention. Config files are size-capped and parsed strictly (unknown
//!   fields refused).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use robodr_blackbox::{HmacSha256Key, RecorderConfig, Report, TimeSource};
use robodr_commission::{EventSource, JsonlSource};
use robodr_events::profile::Profile;
use robodr_motion::{FeedbackSource, MonitorConfig};
use robodr_ocsf::{AttestationStatus, PlatformFamily as OcsfPlatform, RobotInfo};
use robodr_responder::{
    Connectivity, ControlMode, MissionPhase, OperationalContext, ResponsePolicy, SafetyState,
};

use crate::agent::{Agent, AgentStats};
use crate::clock::ReplayClock;
use crate::config::{strict_from_str, AgentConfig, AgentError, FirewallSettings, MonitorSettings};
use crate::evidence::{finding_refs, resolve_links, verify_blackbox, LinkReport};
use crate::executor::LoggingExecutor;
use crate::outcome::{AgentFault, Outcome};

/// Max size of a profile / policy / monitor-config file.
pub const MAX_CONFIG_BYTES: u64 = 16 << 20;

/// Max size of a findings file read by [`verify`].
pub const MAX_FINDINGS_BYTES: u64 = 256 << 20;

/// Default for [`ReplayOptions::max_retained_outcomes`].
pub const DEFAULT_MAX_RETAINED_OUTCOMES: usize = 10_000;

/// Everything a replay needs.
#[derive(Debug, Clone)]
pub struct ReplayOptions {
    pub events: PathBuf,
    pub profile: PathBuf,
    pub policy: PathBuf,
    pub blackbox: PathBuf,
    /// HMAC key bytes (>= 32). Placeholder authenticator; see robodr-blackbox.
    pub key: Vec<u8>,
    /// Key id; `None` derives one from the key.
    pub key_id: Option<String>,
    pub robot_id: String,
    pub site: String,
    /// Robot model for the finding; `None` uses the profile's model.
    pub model: Option<String>,
    pub profile_version: String,
    pub boot_id: String,
    pub safety: SafetyState,
    pub control: ControlMode,
    pub phase: MissionPhase,
    pub connectivity: Connectivity,
    pub operator_present: bool,
    pub start_wall_ms: u64,
    pub step_ns: u64,
    pub firewall: bool,
    /// Per-channel allowed writer GUIDs for the firewall (see
    /// [`FirewallSettings::from_profile`] for the permissive default).
    pub firewall_allow: BTreeMap<String, Vec<String>>,
    pub monitor: Option<MonitorConfig>,
    pub feedback_sources: BTreeMap<String, FeedbackSource>,
    pub record_all_events: bool,
    pub kafka_partitions: Option<u32>,
    /// Outcomes kept in [`ReplaySummary::outcomes`]; later ones are only
    /// counted (memory stays bounded on large inputs).
    pub max_retained_outcomes: usize,
}

impl ReplayOptions {
    /// Defaults for everything but the paths, key and robot id.
    pub fn new(
        events: impl Into<PathBuf>,
        profile: impl Into<PathBuf>,
        policy: impl Into<PathBuf>,
        blackbox: impl Into<PathBuf>,
        key: Vec<u8>,
        robot_id: impl Into<String>,
    ) -> Self {
        Self {
            events: events.into(),
            profile: profile.into(),
            policy: policy.into(),
            blackbox: blackbox.into(),
            key,
            key_id: None,
            robot_id: robot_id.into(),
            site: "replay".into(),
            model: None,
            profile_version: "replay".into(),
            boot_id: "replay-boot".into(),
            safety: SafetyState::Unknown,
            control: ControlMode::Autonomous,
            phase: MissionPhase::Transit,
            connectivity: Connectivity::Connected,
            operator_present: true,
            // 2026-01-01T00:00:00Z
            start_wall_ms: 1_767_225_600_000,
            step_ns: 20_000_000,
            firewall: false,
            firewall_allow: BTreeMap::new(),
            monitor: None,
            feedback_sources: BTreeMap::new(),
            record_all_events: false,
            kafka_partitions: None,
            max_retained_outcomes: DEFAULT_MAX_RETAINED_OUTCOMES,
        }
    }
}

/// Replay errors (usage / input / I/O). A verification failure is not an
/// error: it is reported in [`ReplaySummary`].
#[derive(Debug)]
pub enum ReplayError {
    Io(String),
    Input(String),
    Config(String),
    Agent(AgentError),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayError::Io(m) | ReplayError::Input(m) | ReplayError::Config(m) => f.write_str(m),
            ReplayError::Agent(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// What a replay produced.
#[derive(Debug, Clone)]
pub struct ReplaySummary {
    pub events: u64,
    /// The first [`ReplayOptions::max_retained_outcomes`] outcomes.
    pub outcomes: Vec<Outcome>,
    /// Outcomes produced but not retained.
    pub outcomes_dropped: u64,
    /// Deviations per severity (lower-case name), over all outcomes.
    pub by_severity: BTreeMap<String, u64>,
    /// Outcomes per disposition (snake_case name), over all outcomes.
    pub by_disposition: BTreeMap<String, u64>,
    /// Agent faults retained at the end of the run.
    pub faults: Vec<AgentFault>,
    pub stats: AgentStats,
    /// Black-box verifier report (with the run's final checkpoint).
    pub report: Report,
    /// Evidence-link resolution over every finding written.
    pub links: LinkReport,
}

impl ReplaySummary {
    /// Chain intact and every evidence link resolves.
    pub fn verified(&self) -> bool {
        self.report.is_intact() && self.links.is_ok()
    }
}

/// Read a size-capped UTF-8 file.
pub fn read_capped(path: &Path) -> Result<String, ReplayError> {
    let meta =
        std::fs::metadata(path).map_err(|e| ReplayError::Io(format!("{}: {e}", path.display())))?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ReplayError::Config(format!(
            "{}: larger than {MAX_CONFIG_BYTES} bytes",
            path.display()
        )));
    }
    std::fs::read_to_string(path).map_err(|e| ReplayError::Io(format!("{}: {e}", path.display())))
}

/// Load a profile file (strict: unknown fields are refused). The agent
/// validates it on start.
pub fn load_profile(path: &Path) -> Result<Profile, ReplayError> {
    let text = read_capped(path)?;
    strict_from_str(&text)
        .map_err(|e| ReplayError::Config(format!("{}: not a profile: {e}", path.display())))
}

/// Load a motion monitor config file (strict: unknown fields are refused).
/// The monitor validates its values on start.
pub fn load_monitor_config(path: &Path) -> Result<MonitorConfig, ReplayError> {
    let text = read_capped(path)?;
    strict_from_str(&text)
        .map_err(|e| ReplayError::Config(format!("{}: not a monitor config: {e}", path.display())))
}

/// Load and validate a response policy file.
pub fn load_policy(path: &Path) -> Result<ResponsePolicy, ReplayError> {
    let text = read_capped(path)?;
    ResponsePolicy::from_json(&text)
        .map_err(|e| ReplayError::Config(format!("{}: {e}", path.display())))
}

fn hmac_key(key: &[u8], key_id: Option<&str>) -> Result<HmacSha256Key, ReplayError> {
    match key_id {
        Some(id) => HmacSha256Key::new(id, key),
        None => HmacSha256Key::with_derived_id(key),
    }
    .map_err(|e| ReplayError::Config(format!("black-box key: {e}")))
}

/// Build the agent for `opts` (exposed for tests that drive it by hand).
pub fn build_agent(opts: &ReplayOptions) -> Result<Agent, ReplayError> {
    if opts.step_ns == 0 {
        return Err(ReplayError::Config("step must be > 0".into()));
    }
    let profile = load_profile(&opts.profile)?;
    let policy = load_policy(&opts.policy)?;
    let context = OperationalContext {
        platform: policy.platform,
        phase: opts.phase,
        connectivity: opts.connectivity,
        control: opts.control,
        operator_present: opts.operator_present,
        profile_locked: profile.locked,
    };
    let robot = RobotInfo {
        id: opts.robot_id.clone(),
        model: opts.model.clone().unwrap_or_else(|| profile.model.clone()),
        platform_family: OcsfPlatform::LinuxRos2,
        site: opts.site.clone(),
        firmware: None,
    };
    let mut cfg = AgentConfig::new(
        robot,
        profile,
        policy,
        context,
        RecorderConfig::new(&opts.blackbox, &opts.robot_id, &opts.boot_id),
    );
    cfg.profile_version = opts.profile_version.clone();
    cfg.attestation = AttestationStatus::Unknown;
    cfg.kafka_partitions = opts.kafka_partitions;
    cfg.record_all_events = opts.record_all_events;
    if opts.firewall {
        cfg.firewall = Some(FirewallSettings::from_profile(
            &cfg.profile,
            &opts.firewall_allow,
        ));
    }
    if let Some(mc) = &opts.monitor {
        let mut ms = MonitorSettings::new(mc.clone());
        ms.feedback_sources = opts.feedback_sources.clone();
        cfg.monitor = Some(ms);
    }
    let signer = hmac_key(&opts.key, opts.key_id.as_deref())?;
    let clock = ReplayClock::new(
        opts.start_wall_ms.saturating_mul(1_000_000),
        0,
        opts.step_ns,
        TimeSource::Unknown,
    );
    let mut agent =
        Agent::new(cfg, Box::new(signer), Box::new(clock)).map_err(ReplayError::Agent)?;
    agent.mark_replay();
    Ok(agent)
}

/// A replay must start a fresh chain (see the module docs).
fn require_fresh_blackbox(dir: &Path) -> Result<(), ReplayError> {
    match std::fs::read_dir(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ReplayError::Io(format!("{}: {e}", dir.display()))),
        Ok(mut it) => {
            if it.next().is_some() {
                Err(ReplayError::Config(format!(
                    "{}: black-box directory is not empty; a replay needs a fresh one",
                    dir.display()
                )))
            } else {
                Ok(())
            }
        }
    }
}

/// Run a replay. Every validated finding is written to `findings` as one
/// JSON line (the exact `robot-edr.findings` record value); if `outcomes` is
/// given, every [`Outcome`] is written to it as one JSON line. If `plan_log`
/// is given, a dry-run line per plan is written to it
/// ([`LoggingExecutor`]); no other executor can be attached to a replay. At
/// the end the black box is sealed and verified, and every evidence link is
/// resolved. `opts.blackbox` must be absent or empty.
pub fn run(
    opts: &ReplayOptions,
    findings: &mut dyn Write,
    mut outcomes: Option<&mut dyn Write>,
    plan_log: Option<Box<dyn Write>>,
) -> Result<ReplaySummary, ReplayError> {
    require_fresh_blackbox(&opts.blackbox)?;
    let mut agent = build_agent(opts)?;
    if let Some(w) = plan_log {
        agent = agent.with_executor(Box::new(LoggingExecutor::new(w)));
    }
    let mut source =
        JsonlSource::open(&opts.events).map_err(|e| ReplayError::Input(e.to_string()))?;
    let mut all = Vec::new();
    let mut dropped = 0u64;
    let mut by_severity: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_disposition: BTreeMap<String, u64> = BTreeMap::new();
    let mut refs = BTreeSet::new();
    let mut input_error = None;
    let mut io_error = None;
    let mut events = 0u64;
    while let Some(item) = source.next_event() {
        let ev = match item {
            Ok(ev) => ev,
            Err(e) => {
                input_error = Some(e.to_string());
                break;
            }
        };
        events += 1;
        for o in agent.tick(&ev.event, opts.safety) {
            let res = (|| -> std::io::Result<()> {
                if let Some(f) = &o.finding {
                    writeln!(findings, "{}", f.value)?;
                }
                if let Some(w) = outcomes.as_mut() {
                    let line = serde_json::to_string(&o).map_err(std::io::Error::other)?;
                    writeln!(w, "{line}")?;
                }
                Ok(())
            })();
            if let Err(e) = res {
                io_error.get_or_insert(e.to_string());
            }
            *by_severity
                .entry(format!("{:?}", o.deviation.severity).to_lowercase())
                .or_default() += 1;
            *by_disposition.entry(enum_name(&o.disposition)).or_default() += 1;
            if let Some(f) = &o.finding {
                if let Ok(env) = robodr_ocsf::parse_and_validate(&f.value) {
                    refs.extend(finding_refs(&env));
                }
            }
            if all.len() < opts.max_retained_outcomes {
                all.push(o);
            } else {
                dropped += 1;
            }
        }
        if io_error.is_some() {
            break;
        }
    }
    // Seal the black box even if the input was bad: what was recorded stays
    // verifiable.
    let faults = agent.take_faults();
    let finished = agent.finish().map_err(ReplayError::Agent)?;
    if let Some(e) = io_error {
        return Err(ReplayError::Io(format!("writing output: {e}")));
    }
    if let Some(e) = input_error {
        return Err(ReplayError::Input(e));
    }
    let verifier = hmac_key(&opts.key, opts.key_id.as_deref())?;
    let report = verify_blackbox(
        &opts.blackbox,
        &verifier,
        Some(finished.checkpoint),
        Some(&opts.robot_id),
    )
    .map_err(|e| ReplayError::Io(format!("{}: {e}", opts.blackbox.display())))?;
    let refs: Vec<_> = refs.into_iter().collect();
    let links = resolve_links(&opts.blackbox, &verifier, &refs)
        .map_err(|e| ReplayError::Io(format!("{}: {e}", opts.blackbox.display())))?;
    Ok(ReplaySummary {
        events,
        outcomes: all,
        outcomes_dropped: dropped,
        by_severity,
        by_disposition,
        faults,
        stats: finished.stats,
        report,
        links,
    })
}

/// Result of [`verify`].
#[derive(Debug, Clone)]
pub struct VerifySummary {
    pub report: Report,
    /// Present when a findings file was given.
    pub links: Option<LinkReport>,
    /// Findings lines that failed validation (line number, errors).
    pub invalid_findings: Vec<(usize, String)>,
}

impl VerifySummary {
    pub fn verified(&self) -> bool {
        self.report.is_intact()
            && self.links.as_ref().is_none_or(LinkReport::is_ok)
            && self.invalid_findings.is_empty()
    }
}

/// Verify an existing black-box directory (with its own checkpoint.json, or
/// none), and optionally resolve the evidence links of a findings JSONL file.
pub fn verify(
    blackbox: &Path,
    key: &[u8],
    key_id: Option<&str>,
    robot_id: Option<&str>,
    findings: Option<&Path>,
) -> Result<VerifySummary, ReplayError> {
    let verifier = hmac_key(key, key_id)?;
    let report = verify_blackbox(blackbox, &verifier, None, robot_id)
        .map_err(|e| ReplayError::Io(format!("{}: {e}", blackbox.display())))?;
    let mut invalid = Vec::new();
    let links = match findings {
        None => None,
        Some(p) => {
            let meta = std::fs::metadata(p)
                .map_err(|e| ReplayError::Io(format!("{}: {e}", p.display())))?;
            if meta.len() > MAX_FINDINGS_BYTES {
                return Err(ReplayError::Input(format!(
                    "{}: larger than {MAX_FINDINGS_BYTES} bytes",
                    p.display()
                )));
            }
            let text = std::fs::read_to_string(p)
                .map_err(|e| ReplayError::Io(format!("{}: {e}", p.display())))?;
            let mut refs = Vec::new();
            for (i, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                match robodr_ocsf::parse_and_validate(line) {
                    Ok(env) => refs.extend(finding_refs(&env)),
                    Err(errs) => invalid.push((
                        i + 1,
                        errs.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join("; "),
                    )),
                }
            }
            Some(
                resolve_links(blackbox, &verifier, &refs)
                    .map_err(|e| ReplayError::Io(format!("{}: {e}", blackbox.display())))?,
            )
        }
    };
    Ok(VerifySummary {
        report,
        links,
        invalid_findings: invalid,
    })
}

/// The serde (snake_case) name of a unit enum value.
fn enum_name<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "unknown".into(),
    }
}

/// Human-readable multi-line summary of a verifier report.
pub fn describe_report(report: &Report) -> String {
    let mut s = format!(
        "black box: {} frames, {} records verified, seq {}..{}, last seal seq {}, {}\n",
        report.frames,
        report.verified_records,
        report.first_seq.map_or("-".into(), |v| v.to_string()),
        report.last_seq.map_or("-".into(), |v| v.to_string()),
        report.last_seal_seq.map_or("-".into(), |v| v.to_string()),
        if report.is_clean() {
            "CLEAN"
        } else if report.is_intact() {
            "INTACT (warnings)"
        } else {
            "TAMPERED"
        }
    );
    for f in &report.findings {
        s.push_str(&format!("  {f}\n"));
    }
    s
}
