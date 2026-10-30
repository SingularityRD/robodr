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
//!
//! # Profile trust
//!
//! The profile is loaded with the same trust check as the sensor
//! ([`load_trusted_profile`], `robodr_commission::trust`): a **locked**
//! profile is enforced only if it carries metadata and a valid detached
//! signature (`<profile>.sig`) from a key in
//! [`ReplayOptions::trusted_keys`]. Otherwise the replay runs observe-only
//! (the profile is treated as unlocked) and the first outcome is a
//! `robot.ros2.profile_refused` finding saying why. The version carried in
//! findings is the signed `metadata.profile_version` (the former
//! `--profile-version` option was removed). Anti-rollback is opt-in for
//! replays ([`ReplayOptions::profile_state`]): forensic replays of old
//! recordings legitimately use old profiles. With
//! [`ReplayOptions::trust_roots`], a root-signed `min_profile_version` in
//! the trust file and a signed revocation list
//! ([`ReplayOptions::revocation_list`], [`ReplayOptions::revocation_policy`])
//! apply exactly as on the robot (`robodr_commission::trust::evaluate_profile_trust`).
//! A replay starts a fresh black box, so it has no black-box witness for
//! the state file.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use robodr_blackbox::{
    HmacSha256Key, KeyFile, RecorderConfig, Report, Signer, TimeSource, Verifier,
};
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

/// Rule id of the "profile not enforced" finding (same as the sensor's).
pub const PROFILE_REFUSED: &str = "robot.ros2.profile_refused";

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
    /// Key bytes: an HMAC key (>= 32 bytes, the placeholder authenticator)
    /// or a 32-byte Ed25519 seed, per [`ReplayOptions::key_algorithm`].
    /// Wiped on drop.
    pub key: zeroize::Zeroizing<Vec<u8>>,
    /// Key id; `None` derives one from the key.
    pub key_id: Option<String>,
    /// `"hmac-sha256"` (default, for compatibility) or `"ed25519"`.
    pub key_algorithm: String,
    pub robot_id: String,
    pub site: String,
    /// Robot model for the finding; `None` uses the profile's model.
    pub model: Option<String>,
    /// Trusted profile signing keys (`robodr-profile-trust/v1`). `None`:
    /// no locked profile is trusted (the replay runs observe-only).
    pub trusted_keys: Option<PathBuf>,
    /// Anti-rollback state file (read, and rewritten when a newer signed
    /// profile is accepted). `None`: no rollback check.
    pub profile_state: Option<PathBuf>,
    /// Operator rollback flag: the exact digest of an older profile file to
    /// accept despite `profile_state`.
    pub allow_profile_rollback: Option<String>,
    /// Trust roots (`robodr-trust-roots/v1`): verify the revocation list and
    /// a trust-file `min_profile_version`.
    pub trust_roots: Option<PathBuf>,
    /// Signed revocation list (`robodr-profile-revocations/v1`; needs
    /// `trust_roots`).
    pub revocation_list: Option<PathBuf>,
    /// What a missing `revocation_list` file means.
    pub revocation_policy: robodr_commission::trust::RevocationPolicy,
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
    /// Per-channel angular speed bound (rad/s) for the firewall's Twist
    /// channels. Required for every one of them (see
    /// [`FirewallSettings::from_profile`]).
    pub firewall_max_angular: BTreeMap<String, f64>,
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
        key: impl Into<zeroize::Zeroizing<Vec<u8>>>,
        robot_id: impl Into<String>,
    ) -> Self {
        Self {
            events: events.into(),
            profile: profile.into(),
            policy: policy.into(),
            blackbox: blackbox.into(),
            key: key.into(),
            key_id: None,
            key_algorithm: robodr_blackbox::sign::HMAC_SHA256.into(),
            robot_id: robot_id.into(),
            site: "replay".into(),
            model: None,
            trusted_keys: None,
            profile_state: None,
            allow_profile_rollback: None,
            trust_roots: None,
            revocation_list: None,
            revocation_policy: Default::default(),
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
            firewall_max_angular: BTreeMap::new(),
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
    /// Why the profile was not enforced (`None`: enforced, or a draft).
    pub profile_refused: Option<String>,
    /// The profile version label carried in findings.
    pub profile_version: String,
}

impl ReplaySummary {
    /// The evidence that was written is sound: chain intact and every
    /// evidence link of every finding written resolves. Says nothing about
    /// findings that were never written (see [`Self::findings_lost`]).
    pub fn evidence_verified(&self) -> bool {
        self.report.is_intact() && self.links.is_ok()
    }

    /// Findings produced but not written (they failed OCSF validation, e.g.
    /// a replay clock past what a finding can carry). Their deviations are
    /// in the black box; the findings output is incomplete.
    pub fn findings_lost(&self) -> u64 {
        self.stats.finding_errors
    }

    /// Fully verified: [`Self::evidence_verified`] and no finding lost. A
    /// replay that dropped findings is never reported as verified, however
    /// intact the chain is (`robodr-replay` exits 3 for that case).
    pub fn verified(&self) -> bool {
        self.evidence_verified() && self.findings_lost() == 0
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

/// Load a profile file's content (strict: unknown fields are refused; the
/// lock seal member is tolerated). **No trust check**: use
/// [`load_trusted_profile`] for what is enforced. The agent validates it
/// on start.
pub fn load_profile(path: &Path) -> Result<Profile, ReplayError> {
    let text = read_capped(path)?;
    parse_profile_content(&text)
        .map_err(|e| ReplayError::Config(format!("{}: not a profile: {e}", path.display())))
}

fn parse_profile_content(text: &str) -> Result<Profile, String> {
    let mut v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if let Some(o) = v.as_object_mut() {
        o.remove(robodr_commission::profile_file::SEAL_KEY);
    }
    strict_from_str(&v.to_string())
}

/// A profile as the replay will use it.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustedProfile {
    /// The profile; `locked` is forced to `false` when refused.
    pub profile: Profile,
    /// Version label for findings (`robodr_commission::trust::version_label`).
    pub version_label: String,
    /// Why a locked profile is not enforced.
    pub refused: Option<String>,
}

/// Load the profile with the trust check described in the module docs.
/// A file that is not a profile at all is an error; a profile that is not
/// trusted comes back with `refused` set and `locked = false`.
pub fn load_trusted_profile(opts: &ReplayOptions) -> Result<TrustedProfile, ReplayError> {
    use robodr_commission::trust::{
        evaluate_profile_trust, store_state, validate_rollback_flag, version_label, TrustInputs,
    };
    use robodr_commission::ProfileFileError;
    let path = &opts.profile;
    let text = read_capped(path)?;
    if let Some(f) = &opts.allow_profile_rollback {
        validate_rollback_flag(f).map_err(ReplayError::Config)?;
    }
    if opts.revocation_list.is_some() && opts.trust_roots.is_none() {
        return Err(ReplayError::Config(
            "a revocation list needs trust roots (--trust-roots)".into(),
        ));
    }
    let inputs = TrustInputs {
        trusted_keys: opts.trusted_keys.as_deref(),
        trust_roots: opts.trust_roots.as_deref(),
        revocation_list: opts.revocation_list.as_deref(),
        revocation_policy: opts.revocation_policy,
        state_file: opts.profile_state.as_deref(),
        allow_rollback: opts.allow_profile_rollback.as_deref(),
        ..Default::default()
    };
    // (reason, whether it is a trust refusal rather than a format error)
    let (refusal, trust_refusal) = match evaluate_profile_trust(path, &text, &inputs).result {
        Ok(a) => {
            let written = match (&a.state_write, &opts.profile_state) {
                (Some(st), Some(sp)) => store_state(sp, st),
                _ => Ok(()),
            };
            match written {
                Ok(()) => {
                    let v = a.verified;
                    let label = version_label(&v.profile, v.profile.locked);
                    return Ok(TrustedProfile {
                        profile: v.profile,
                        version_label: label,
                        refused: None,
                    });
                }
                Err(e) => (ProfileFileError::from(e).to_string(), true),
            }
        }
        Err(e) => {
            let t = matches!(e, ProfileFileError::Untrusted { .. });
            (e.to_string(), t)
        }
    };
    // Not trusted (or not a strict profile file): keep what can be
    // observed against (unknown keys are still refused). A hand-written
    // draft that only fails the strict file format is observed as before.
    let mut profile = parse_profile_content(&text)
        .map_err(|e| ReplayError::Config(format!("{}: not a profile: {e}", path.display())))?;
    if !profile.locked && !trust_refusal {
        return Ok(TrustedProfile {
            profile,
            version_label: "draft".into(),
            refused: None,
        });
    }
    profile.locked = false;
    Ok(TrustedProfile {
        profile,
        version_label: "untrusted".into(),
        refused: Some(refusal),
    })
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

/// The key of `opts` as a key file (Ed25519 seed or HMAC key).
fn key_file(
    opts_key: &[u8],
    key_id: Option<&str>,
    algorithm: &str,
) -> Result<KeyFile, ReplayError> {
    let r = match algorithm {
        robodr_blackbox::sign_ed25519::ED25519 => {
            let seed: &[u8; 32] = opts_key.try_into().map_err(|_| {
                ReplayError::Config("black-box key: an ed25519 seed is 32 bytes".into())
            })?;
            KeyFile::ed25519_from_seed(seed, key_id)
        }
        robodr_blackbox::sign::HMAC_SHA256 => {
            // Same checks and id derivation as before.
            let k = hmac_key(opts_key, key_id)?;
            KeyFile::hmac_from_secret(opts_key, Some(Signer::key_id(&k)))
        }
        a => {
            return Err(ReplayError::Config(format!(
                "black-box key: unsupported algorithm {a:?}"
            )))
        }
    };
    r.map_err(|e| ReplayError::Config(format!("black-box key: {e}")))
}

/// Signer for the replay's black box.
fn signer_for(opts: &ReplayOptions) -> Result<Box<dyn Signer>, ReplayError> {
    key_file(&opts.key, opts.key_id.as_deref(), &opts.key_algorithm)?
        .signer()
        .map_err(|e| ReplayError::Config(format!("black-box key: {e}")))
}

/// Verifier matching [`signer_for`].
fn verifier_for(opts: &ReplayOptions) -> Result<Box<dyn Verifier>, ReplayError> {
    key_file(&opts.key, opts.key_id.as_deref(), &opts.key_algorithm)?
        .verifier()
        .map_err(|e| ReplayError::Config(format!("black-box key: {e}")))
}

/// Build the agent for `opts` (exposed for tests that drive it by hand).
/// The profile goes through [`load_trusted_profile`]; an untrusted locked
/// profile yields an observe-only agent (see [`build_agent_checked`] for
/// the refusal reason).
pub fn build_agent(opts: &ReplayOptions) -> Result<Agent, ReplayError> {
    build_agent_checked(opts).map(|(a, _)| a)
}

/// [`build_agent`] plus the profile trust outcome.
pub fn build_agent_checked(opts: &ReplayOptions) -> Result<(Agent, TrustedProfile), ReplayError> {
    if opts.step_ns == 0 {
        return Err(ReplayError::Config("step must be > 0".into()));
    }
    let trusted = load_trusted_profile(opts)?;
    let profile = trusted.profile.clone();
    let policy = load_policy(&opts.policy)?;
    let context = OperationalContext {
        platform: policy.platform,
        morphology: policy.morphology,
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
    cfg.profile_version = trusted.version_label.clone();
    cfg.attestation = AttestationStatus::Unknown;
    cfg.kafka_partitions = opts.kafka_partitions;
    cfg.record_all_events = opts.record_all_events;
    if opts.firewall {
        cfg.firewall = Some(
            FirewallSettings::from_profile(
                &cfg.profile,
                &opts.firewall_allow,
                &opts.firewall_max_angular,
            )
            .map_err(ReplayError::Agent)?,
        );
    }
    if let Some(mc) = &opts.monitor {
        let mut ms = MonitorSettings::new(mc.clone());
        ms.feedback_sources = opts.feedback_sources.clone();
        cfg.monitor = Some(ms);
    }
    let signer = signer_for(opts)?;
    let clock = ReplayClock::new(
        opts.start_wall_ms.saturating_mul(1_000_000),
        0,
        opts.step_ns,
        TimeSource::Unknown,
    );
    let mut agent = Agent::new(cfg, signer, Box::new(clock)).map_err(ReplayError::Agent)?;
    agent.mark_replay();
    Ok((agent, trusted))
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
/// JSON line (the exact findings record value); if `outcomes` is
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
    let (mut agent, trusted) = build_agent_checked(opts)?;
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
    // An untrusted profile is itself the first finding (observe-only).
    let mut pending: Vec<Outcome> = Vec::new();
    if let Some(why) = &trusted.refused {
        let detail = format!(
            "model profile '{}' is not enforced (observe-only): {why}",
            trusted.profile.model
        );
        let now = robodr_blackbox::Timestamp {
            wall_ns: opts.start_wall_ms.saturating_mul(1_000_000),
            mono_ns: 0,
            source: TimeSource::Unknown,
        };
        pending.push(agent.handle_external(
            now,
            crate::Detector::Sensor,
            "profile",
            robodr_ocsf::Subject::default(),
            robodr_events::Deviation::new(PROFILE_REFUSED, robodr_events::Severity::High, detail),
            opts.safety,
        ));
    }
    loop {
        let batch = if pending.is_empty() {
            let Some(item) = source.next_event() else {
                break;
            };
            let ev = match item {
                Ok(ev) => ev,
                Err(e) => {
                    input_error = Some(e.to_string());
                    break;
                }
            };
            events += 1;
            agent.tick(&ev.event, opts.safety)
        } else {
            std::mem::take(&mut pending)
        };
        for o in batch {
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
    let verifier = verifier_for(opts)?;
    let report = verify_blackbox(
        &opts.blackbox,
        verifier.as_ref(),
        Some(finished.checkpoint),
        Some(&opts.robot_id),
    )
    .map_err(|e| ReplayError::Io(format!("{}: {e}", opts.blackbox.display())))?;
    let refs: Vec<_> = refs.into_iter().collect();
    let links = resolve_links(&opts.blackbox, verifier.as_ref(), &refs)
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
        profile_refused: trusted.refused,
        profile_version: trusted.version_label,
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
///
/// Records verify only under the key id (and algorithm) their chain names.
/// Without `key_id` the HMAC key is filed under the chain's own recorded
/// `hmac-sha256` key id (the key bytes authenticate, the id only names
/// them); with `key_id` it must be the chain's.
pub fn verify(
    blackbox: &Path,
    key: &[u8],
    key_id: Option<&str>,
    robot_id: Option<&str>,
    findings: Option<&Path>,
) -> Result<VerifySummary, ReplayError> {
    let mut verifier = hmac_key(key, key_id)?;
    if key_id.is_none() {
        if let Ok(r) = verify_blackbox(blackbox, &verifier, None, None) {
            if let Some(id) = r.identity.filter(|i| {
                i.algorithm == robodr_blackbox::sign::HMAC_SHA256
                    && i.key_id != Verifier::key_id(&verifier)
            }) {
                verifier = hmac_key(key, Some(&id.key_id))?;
            }
        }
    }
    verify_with(blackbox, &verifier, robot_id, findings)
}

/// [`verify`] with any verifier, e.g. an Ed25519 public key
/// ([`robodr_blackbox::KeyFile::verifier`] of a `.pub` file) or a keyring:
/// verification needs no secret.
pub fn verify_with(
    blackbox: &Path,
    verifier: &dyn Verifier,
    robot_id: Option<&str>,
    findings: Option<&Path>,
) -> Result<VerifySummary, ReplayError> {
    let report = verify_blackbox(blackbox, verifier, None, robot_id)
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
                resolve_links(blackbox, verifier, &refs)
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    use robodr_blackbox::{Finding, FindingKind, FindingLevel};

    use crate::outcome::Disposition;

    const KEY: [u8; 32] = [0x42; 32];

    fn examples() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
    }

    /// A fresh, empty directory (removed by the test).
    fn tmpdir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "robodr-replay-unit-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn demo_opts(bb: &Path) -> ReplayOptions {
        let ex = examples();
        ReplayOptions::new(
            ex.join("rogue-ugv.jsonl"),
            ex.join("ugv-demo.profile.json"),
            ex.join("policy-oem-validated.json"),
            bb,
            KEY.to_vec(),
            "ugv-007",
        )
    }

    #[test]
    fn options_defaults_are_conservative() {
        let o = ReplayOptions::new("e", "p", "q", "b", vec![1], "r");
        assert_eq!(o.events, PathBuf::from("e"));
        assert_eq!(o.blackbox, PathBuf::from("b"));
        assert_eq!(o.robot_id, "r");
        // Unknown safety state by default: motion steps always need a human.
        assert_eq!(o.safety, SafetyState::Unknown);
        assert_eq!(o.control, ControlMode::Autonomous);
        assert!(!o.firewall && o.monitor.is_none() && !o.record_all_events);
        assert!(o.step_ns > 0);
        assert_eq!(o.max_retained_outcomes, DEFAULT_MAX_RETAINED_OUTCOMES);
        assert_eq!(o.key_id, None);
        assert_eq!(o.model, None);
    }

    #[test]
    fn error_display_is_the_message() {
        assert_eq!(ReplayError::Io("a".into()).to_string(), "a");
        assert_eq!(ReplayError::Input("b".into()).to_string(), "b");
        assert_eq!(ReplayError::Config("c".into()).to_string(), "c");
    }

    #[test]
    fn read_capped_errors() {
        let d = tmpdir("cap");
        // Missing.
        assert!(matches!(
            read_capped(&d.join("missing")),
            Err(ReplayError::Io(m)) if m.contains("missing")
        ));
        // Over the cap (sparse: nothing is actually read).
        let big = d.join("big.json");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(MAX_CONFIG_BYTES + 1)
            .unwrap();
        assert!(matches!(read_capped(&big), Err(ReplayError::Config(m)) if m.contains("larger")));
        // Not UTF-8.
        let bin = d.join("bin.json");
        std::fs::write(&bin, b"{\xff}").unwrap();
        assert!(matches!(read_capped(&bin), Err(ReplayError::Io(_))));
        // A directory.
        assert!(read_capped(&d).is_err());
        // Fine.
        std::fs::write(d.join("ok"), "x").unwrap();
        assert_eq!(read_capped(&d.join("ok")).unwrap(), "x");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn loaders_are_strict() {
        let d = tmpdir("load");
        let ex = examples();
        assert!(load_profile(&ex.join("ugv-demo.profile.json")).is_ok());
        assert!(load_policy(&ex.join("policy-oem-validated.json")).is_ok());

        let w = |name: &str, text: &str| {
            let p = d.join(name);
            std::fs::write(&p, text).unwrap();
            p
        };
        // Profile: garbage, unknown field, wrong types.
        let prof = std::fs::read_to_string(ex.join("ugv-demo.profile.json")).unwrap();
        let extra = prof.replacen('{', "{\"extra\": 1,", 1);
        for text in ["", "null", "[]", "{", extra.as_str(), "{\"model\": 5}"] {
            let p = w("p.json", text);
            assert!(
                matches!(load_profile(&p), Err(ReplayError::Config(m)) if m.contains("not a profile")),
                "{text:?}"
            );
        }
        // Policy: an e-stop cell above record is refused at load.
        let pol = std::fs::read_to_string(ex.join("policy-oem-validated.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&pol).unwrap();
        v["matrix"]["estop_active"]["critical"] = "safe_pause".into();
        let p = w("q.json", &v.to_string());
        assert!(matches!(load_policy(&p), Err(ReplayError::Config(m)) if m.contains("record")));
        let p = w("q2.json", "{}");
        assert!(matches!(load_policy(&p), Err(ReplayError::Config(_))));
        // Monitor config: unknown fields refused.
        let p = w("m.json", "{\"bogus\": true}");
        assert!(matches!(
            load_monitor_config(&p),
            Err(ReplayError::Config(m)) if m.contains("not a monitor config")
        ));
        assert!(matches!(
            load_monitor_config(&d.join("none.json")),
            Err(ReplayError::Io(_))
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn hmac_key_requires_a_long_enough_key() {
        assert!(matches!(
            hmac_key(&[0u8; 8], None),
            Err(ReplayError::Config(m)) if m.starts_with("black-box key")
        ));
        assert!(hmac_key(&[], Some("id")).is_err());
        assert!(hmac_key(&KEY, None).is_ok());
        assert!(hmac_key(&KEY, Some("my-key")).is_ok());
    }

    #[test]
    fn fresh_blackbox_rule() {
        let d = tmpdir("fresh");
        // Absent: fine (it will be created).
        assert!(require_fresh_blackbox(&d.join("absent")).is_ok());
        // Empty: fine.
        assert!(require_fresh_blackbox(&d).is_ok());
        // Anything inside, even an empty subdirectory or a dotfile: refused.
        std::fs::write(d.join(".hidden"), b"").unwrap();
        assert!(matches!(
            require_fresh_blackbox(&d),
            Err(ReplayError::Config(m)) if m.contains("not empty")
        ));
        // A regular file where the directory should be: an error.
        let f = d.join(".hidden");
        assert!(matches!(
            require_fresh_blackbox(&f),
            Err(ReplayError::Io(_))
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn enum_names_are_serde_names() {
        for (d, want) in [
            (Disposition::ObserveOnly, "observe_only"),
            (Disposition::Suppressed, "suppressed"),
            (Disposition::RecordOnly, "record_only"),
            (
                Disposition::AwaitingHumanApproval,
                "awaiting_human_approval",
            ),
            (Disposition::Eligible, "eligible"),
        ] {
            assert_eq!(enum_name(&d), want);
        }
        // Anything that is not a plain string falls back.
        assert_eq!(enum_name(&5u8), "unknown");
        assert_eq!(enum_name(&serde_json::json!({"a": 1})), "unknown");
    }

    fn finding(level: FindingLevel) -> Finding {
        Finding {
            level,
            kind: FindingKind::TornTail { len: 3 },
            location: None,
        }
    }

    #[test]
    fn describe_report_states() {
        let r = Report::default();
        let s = describe_report(&r);
        assert!(s.starts_with("black box: 0 frames, 0 records verified, seq -..-"));
        assert!(s.contains("last seal seq -, CLEAN"));
        assert_eq!(s.lines().count(), 1);

        let r = Report {
            findings: vec![finding(FindingLevel::Warning)],
            frames: 3,
            verified_records: 2,
            first_seq: Some(0),
            last_seq: Some(1),
            last_seal_seq: Some(1),
            ..Report::default()
        };
        let s = describe_report(&r);
        assert!(s.contains("3 frames, 2 records verified, seq 0..1, last seal seq 1"));
        assert!(s.contains("INTACT (warnings)"));
        assert_eq!(s.lines().count(), 2);

        let r = Report {
            findings: vec![finding(FindingLevel::Info), finding(FindingLevel::Tamper)],
            ..Report::default()
        };
        let s = describe_report(&r);
        assert!(s.contains("TAMPERED"));
        assert_eq!(s.lines().count(), 3);
        assert!(s.lines().skip(1).all(|l| l.starts_with("  [")));
    }

    #[test]
    fn verify_summary_verified_needs_everything() {
        let ok = |links: Option<LinkReport>, invalid: Vec<(usize, String)>, tamper: bool| {
            VerifySummary {
                report: Report {
                    findings: if tamper {
                        vec![finding(FindingLevel::Tamper)]
                    } else {
                        vec![finding(FindingLevel::Warning)]
                    },
                    ..Report::default()
                },
                links,
                invalid_findings: invalid,
            }
            .verified()
        };
        let good = LinkReport {
            checked: 2,
            resolved: 2,
            problems: vec![],
        };
        let bad = LinkReport {
            checked: 2,
            resolved: 1,
            problems: vec!["x".into()],
        };
        assert!(ok(None, vec![], false), "warnings alone still verify");
        assert!(ok(Some(good.clone()), vec![], false));
        assert!(!ok(Some(bad), vec![], false));
        assert!(!ok(Some(good.clone()), vec![(3, "e".into())], false));
        assert!(!ok(Some(good), vec![], true));
        assert!(!ok(None, vec![], true));
    }

    #[test]
    fn build_agent_validates_before_creating_anything() {
        let d = tmpdir("build");
        let bb = d.join("bb");
        // Zero step.
        let mut o = demo_opts(&bb);
        o.step_ns = 0;
        assert!(matches!(build_agent(&o), Err(ReplayError::Config(m)) if m.contains("step")));
        // Short key.
        let mut o = demo_opts(&bb);
        o.key = vec![1; 4].into();
        assert!(matches!(build_agent(&o), Err(ReplayError::Config(_))));
        // Firewall without the Twist angular bound.
        let mut o = demo_opts(&bb);
        o.firewall = true;
        assert!(matches!(build_agent(&o), Err(ReplayError::Agent(_))));
        // Missing profile / policy.
        let mut o = demo_opts(&bb);
        o.profile = d.join("nope.json");
        assert!(matches!(build_agent(&o), Err(ReplayError::Io(_))));
        let mut o = demo_opts(&bb);
        o.policy = d.join("nope.json");
        assert!(matches!(build_agent(&o), Err(ReplayError::Io(_))));
        assert!(!bb.exists(), "nothing created on a config error");
        // Valid: a replay agent (its plans are marked as replayed).
        let agent = build_agent(&demo_opts(&bb)).unwrap();
        assert!(agent.is_replay());
        drop(agent);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn run_refuses_a_used_blackbox_and_does_not_touch_it() {
        let d = tmpdir("used");
        std::fs::write(d.join("segment"), b"old evidence").unwrap();
        let res = run(&demo_opts(&d), &mut Vec::new(), None, None);
        assert!(matches!(res, Err(ReplayError::Config(m)) if m.contains("fresh")));
        assert_eq!(std::fs::read(d.join("segment")).unwrap(), b"old evidence");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn run_and_verify_round_trip_with_key_id_and_plan_log() {
        let d = tmpdir("rt");
        let bb = d.join("bb");
        let mut o = demo_opts(&bb);
        o.safety = SafetyState::MovingSlow;
        o.key_id = Some("site-key-1".into());
        o.firewall = true;
        o.firewall_max_angular = BTreeMap::from([("/cmd_vel".to_string(), 1.0)]);
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut findings = Vec::new();
        let sum = run(&o, &mut findings, None, Some(Box::new(Shared(log.clone())))).unwrap();
        assert!(sum.verified());
        assert_eq!(sum.events, 16);
        let log = String::from_utf8(log.lock().unwrap().clone()).unwrap();
        assert!(log.contains("replay"), "{log}");
        let fpath = d.join("f.jsonl");
        std::fs::write(&fpath, &findings).unwrap();
        // Same key: verified. The key id is a label; authentication rests on
        // the key bytes, so another id with the same bytes still verifies
        // and different bytes do not.
        let v = verify(&bb, &KEY, Some("site-key-1"), Some("ugv-007"), Some(&fpath)).unwrap();
        assert!(v.verified(), "{:?}", v.report);
        assert!(verify(&bb, &KEY, None, None, None).unwrap().verified());
        assert!(!verify(&bb, &[0x43; 32], Some("site-key-1"), None, None)
            .unwrap()
            .verified());
        // Oversize findings file is refused before reading.
        let big = d.join("big.jsonl");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(MAX_FINDINGS_BYTES + 1)
            .unwrap();
        assert!(matches!(
            verify(&bb, &KEY, Some("site-key-1"), None, Some(&big)),
            Err(ReplayError::Input(m)) if m.contains("larger")
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
