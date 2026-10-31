//! The decision chain for one robot.
//!
//! ```text
//! RobotEvent ─┬─ Profile::evaluate ──────────────┐
//!             ├─ Firewall::check (MotionCommand)  ├─► Deviation(s), stamped with the profile's mode
//!             └─ ConsistencyMonitor (cmd/feedback)┘
//!   per deviation:
//!     Responder::plan(deviation, source, SafetyState, OperationalContext, mono ms) ─► ResponsePlan
//!     backstop: check_invariants + observe-only guard ─► (plan, Disposition)
//!     Recorder: event (once per event) + firewall verdict + deviation + plan note ─► BlackBoxRef(s)
//!     FindingBuilder(... evidence = those refs) ─► validated robodr.findings record
//!     Executor::submit(plan)  — dry-run / no-op; the agent executes nothing
//! ```
//!
//! # Invariants held here
//!
//! * **Observe mode covers every detector.** Every deviation (profile,
//!   firewall, monitor) is stamped with `profile.mode()`. The responder is
//!   given `profile_locked = profile.locked && !deviation.is_observe_only()`,
//!   so an observe-only deviation always yields a `Record`-only plan. The
//!   agent re-checks this after planning (defence in depth).
//! * **Backstop.** Every plan is re-checked with
//!   [`robodr_responder::check_invariants`]; a violating plan (never expected)
//!   is replaced by `Record` + approval and the violation is reported in
//!   [`Outcome::guard_violation`].
//! * **Nothing is executed.** Plans go to an [`Executor`]; the default is
//!   [`NoopExecutor`]. See [`crate::executor`] for the contract a real
//!   executor must follow.
//! * **Detections survive storage failure.** If a black-box append fails or
//!   is refused, the outcome and finding are still produced, without that
//!   evidence link, and the error is reported in [`EvidenceLinks::errors`].
//!   The plan is never weakened or dropped because evidence could not be
//!   written (losing storage must not make the robot less protected).
//!
//! # Failure handling (fail-safe)
//!
//! Every internal failure is turned into an [`AgentFault`], kept in a
//! bounded in-memory log ([`Agent::faults`], newest
//! [`MAX_RETAINED_FAULTS`]) and, whenever the black box can take it, written
//! as a signed `robodr.agent_fault` note. Faults never feed the responder, so
//! an agent-internal problem cannot by itself cause a motion request.
//!
//! * **Black-box write failure.** An I/O failure poisons the recorder; the
//!   agent then drops it and reopens the directory (the recorder resumes the
//!   chain, quarantines a torn tail and signs a `Resume` record), at most once
//!   per [`BLACKBOX_REOPEN_BACKOFF_NS`] of monotonic time, and retries the
//!   append once. While the black box is down, detections, plans and
//!   findings continue without evidence links. When it is back, a
//!   `evidence_recovered` fault note records how many appends were lost.
//! * **Responder output violating an invariant** is replaced by `Record` +
//!   human approval (see [`guard`]); the rejected plan is kept in the
//!   black-box plan note for review.
//! * **Clock anomalies** (monotonic regression, wall/monotonic jump) are
//!   handled by [`crate::clock::TimeGuard`] and recorded as faults.
//!
//! The release profile builds with `panic = "abort"`, so a panic in a
//! dependency cannot be caught here; the chain is written not to panic on
//! hostile input (tested), and the platform's safety system is never
//! dependent on this process being alive.
//!
//! # Time
//!
//! [`Agent::handle`] takes the event's observation time; [`Agent::tick`]
//! reads it from the injected clock. Times pass through a
//! [`crate::clock::TimeGuard`]: `mono_ns` never goes backwards and wall jumps
//! are reported (see [`crate::clock`]).
//!
//! The detectors that measure time between events (the Motion Firewall's
//! rate checks and the motion monitor's latency / persistence windows) use
//! the event's `mono_ns` by default. [`Agent::handle_with_joint_at`] gives
//! them an explicit detection time instead, on the timeline the events
//! were *observed* on: a capture replayed faster or slower than it was
//! recorded must be judged by its own packet timestamps, not by how fast
//! this process happened to read it. Evidence keeps the guarded `now`.
//!
//! # Mapping `MotionCommand` to the firewall and the motion monitor
//!
//! `MotionCommand` carries the command's signed body-frame values
//! (`Twist.linear.x` as `linear_speed`, `Twist.angular.z` as
//! `angular_speed`, REP 103) and the max joint speed, but no source stamp:
//! * Twist channel: `linear = (linear_speed, linear_y, linear_z)`,
//!   `angular = (angular_x, angular_y, angular_speed)` (an absent axis is 0
//!   for the firewall; the firewall bounds each vector's norm, so a
//!   holonomic or hostile sideways component is bounded too). A command with
//!   only `joint_speed` becomes a 1-joint command (kind mismatch → reject).
//!   Every Twist channel has an explicit `max_angular_speed` (see
//!   [`crate::FirewallSettings::from_profile`]).
//! * Joint channel with `count` joints: every joint gets `joint_speed` (the
//!   max |joint speed|; the firewall's per-joint limit sees the same maximum).
//!   A command with only `linear_speed` becomes a twist (kind mismatch).
//! * Source: `source_guid` resolved by the firewall policy (exact GUID, else
//!   its 24-char participant prefix, so a spec listing a participant
//!   authorises all of that participant's writers), else `SourceId::UNKNOWN`.
//!   A command from a source not allowed on the channel is dropped by the
//!   firewall (its default `ForeignSourceAction::Drop`) and reported.
//!   Unknown channel: an id no policy channel has.
//! * Stamp = observation time (`mono_ns`), so the firewall's stale / future
//!   checks cannot fire here; out-of-order still fires for two commands from
//!   one source at the same `mono_ns`.
//!
//! The motion monitor gets the same signed values as a `CommandSample` with
//! `direction_known: true` (an axis the command does not mention stays
//! `None`, "no expectation", not zero), so it can see a robot moving against
//! its command.
//!
//! # Motion feedback
//!
//! `MotionFeedback.measured_linear_speed` is a magnitude, while the monitor
//! compares signed values by default (`SourceConfig::signed`). The agent
//! feeds the signed `linear_velocity` / `angular_velocity` when the producer
//! gives them. A magnitude-only sample is used only for a source the monitor
//! compares by magnitude (`signed = false`, e.g. GNSS, or
//! `compare_magnitudes`); otherwise its linear axis is withheld and counted
//! in [`AgentStats::feedback_magnitude_dropped`] (a magnitude against a
//! signed reversing command would be a false "moving against its command").
//! A `publisher_guid` that parses as a 16-byte GUID is passed whole to
//! `on_feedback_guid` (compared exactly by the monitor, so an attacker
//! cannot collide with the real writer by choosing its GUID); any other
//! string is interned to a dense id (bounded by
//! [`MAX_INTERNED_PUBLISHERS`]) and passed to `on_feedback_from`. Either
//! way an injected second publisher on a feedback topic is seen; samples
//! without a GUID use `on_feedback` (one shared slot).
//!
//! In the finding, commanded speeds are reported as magnitudes and a
//! non-finite value is omitted (the findings contract accepts only finite,
//! non-negative numbers). The raw value is kept in the deviation's tainted
//! detail and in the black-box event record, so a NaN command still yields a
//! valid Critical finding.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::sign::SignError;
use robodr_blackbox::{
    AppendOutcome, Checkpoint, Clock, PreviousKeys, Recorder, RecorderConfig, Signer, Timestamp,
    Verifier,
};
use robodr_events::profile::Profile;
use robodr_events::{Deviation, Mode, MotionCommand, RobotEvent, Severity};
use robodr_firewall::{
    ChannelId, ChannelKind, Command, Firewall, JointCommand, JointFrame, JointLimitReasons,
    JointVelocities, JointVerdict, JointWouldHave, LimitReasons, Motion, Policy, SourceId,
    SubstituteKind, Twist, Vec3, Verdict,
};
use robodr_motion::{CommandSample, ConsistencyMonitor, FeedbackSample};
use robodr_ocsf::{
    BlackBoxRef, FindingBuilder, HumanProximity, Mode as OcsfMode, MotionState, ProfileRef,
    RobotContext, Subject,
};
use robodr_responder::{
    check_invariants, OperationalContext, Responder, ResponseAction, ResponsePlan, SafetyState,
    Step,
};
use serde::Serialize;

use crate::clock::{ClockAnomaly, FollowClock, TimeGuard};
use crate::config::{
    profile_sha256, AgentConfig, AgentError, MonitorSettings, MAX_TRACKED_FINDINGS,
};
use crate::executor::{ExecutionRequest, Executor, NoopExecutor};
use crate::outcome::{
    AgentFault, Detector, Disposition, EvidenceLinks, FaultKind, FindingOutput,
    FirewallVerdictRecord, Outcome,
};

/// Newest faults kept in memory by [`Agent::faults`]; older ones are
/// dropped (and counted in [`AgentStats::faults_dropped`]).
pub const MAX_RETAINED_FAULTS: usize = 256;

/// Minimum monotonic time between two attempts to reopen a failed black box.
pub const BLACKBOX_REOPEN_BACKOFF_NS: u64 = 1_000_000_000;

/// Counters for operators and tests. All saturating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AgentStats {
    pub events: u64,
    pub deviations: u64,
    pub findings: u64,
    pub finding_errors: u64,
    pub records_appended: u64,
    pub evidence_errors: u64,
    pub guard_violations: u64,
    pub clock_regressions: u64,
    pub wall_clock_jumps: u64,
    pub firewall_checks: u64,
    /// Agent faults raised (all kinds).
    pub faults: u64,
    /// Faults evicted from the bounded in-memory log.
    pub faults_dropped: u64,
    /// Successful black-box reopens after a failure.
    pub blackbox_reopens: u64,
    /// Feedback samples whose linear axis was not given to the motion
    /// monitor: only the magnitude (`measured_linear_speed`) was present and
    /// the monitor compares signed values for that source (see
    /// [`crate::agent`], "Motion feedback").
    pub feedback_magnitude_dropped: u64,
    /// Feedback publishers beyond [`MAX_INTERNED_PUBLISHERS`] (hashed ids).
    pub publishers_hashed: u64,
    /// Low-level joint frames checked by the joint firewall
    /// ([`Agent::handle_with_joint`]); also counted in `firewall_checks`.
    pub joint_firewall_checks: u64,
    /// Commands on a low-level joint channel that came without their decoded
    /// frame (e.g. a JSONL event): the joint firewall could not check them
    /// (the profile envelope still did).
    pub joint_frames_missing: u64,
    /// Joint frames whose stamp was older than the joint firewall's clock
    /// (capture timestamps out of order): checked at the clock's time
    /// instead, never as a clock regression.
    pub joint_clock_clamped: u64,
}

/// A decoded low-level joint frame that accompanies a `MotionCommand` (see
/// [`Agent::handle_with_joint`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JointInput {
    /// Every slot on the wire, with the decoder's CRC verdict and the
    /// frame-level `mode_pr` / `mode_machine`.
    pub frame: JointFrame,
    /// When the frame was observed, ns, in the joint firewall's own clock
    /// domain (e.g. capture timestamps). Used as both the frame stamp and
    /// the firewall's `now`, so the rate / gap checks measure the real
    /// inter-arrival time, not the agent's processing time. Must be
    /// non-decreasing; an older stamp is clamped (counted).
    pub stamp_ns: u64,
}

/// A signer shared between the agent and every recorder it opens, so a
/// failed recorder can be dropped and the directory reopened with the same
/// key. Key id and algorithm are captured once.
#[derive(Clone)]
struct SharedSigner {
    algorithm: String,
    key_id: String,
    inner: Arc<Mutex<Box<dyn Signer>>>,
}

impl SharedSigner {
    fn new(signer: Box<dyn Signer>) -> Self {
        Self {
            algorithm: signer.algorithm().to_string(),
            key_id: signer.key_id().to_string(),
            inner: Arc::new(Mutex::new(signer)),
        }
    }
}

impl Signer for SharedSigner {
    fn algorithm(&self) -> &str {
        &self.algorithm
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sign(message)
    }
    // Forwarded so a self-verifying signer (HMAC) still opens with
    // `Recorder::open`: the recorder authenticates the existing chain tail
    // and its signed state files (export cursor, checkpoint) with it.
    fn verify_own(&self, message: &[u8], signature: &[u8]) -> Option<bool> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .verify_own(message, signature)
    }
    fn public_fingerprint(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .public_fingerprint()
    }
}

/// A verifier for the recorder's own key, shared between every recorder the
/// agent opens (signers that cannot self-verify, e.g. a TPM-held key whose
/// public half is configured separately).
#[derive(Clone)]
struct SharedVerifier(Arc<dyn Verifier + Send + Sync>);

impl Verifier for SharedVerifier {
    fn algorithm(&self) -> &str {
        self.0.algorithm()
    }
    fn key_id(&self) -> &str {
        self.0.key_id()
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.0.verify(message, signature)
    }
    fn key_fingerprint(&self, key_id: &str) -> Option<String> {
        self.0.key_fingerprint(key_id)
    }
}

/// Open (or resume) the black box with the agent's key. A signer that can
/// check its own signatures needs no verifier; otherwise the configured one
/// is used. Records signed before a key rotation are authenticated with
/// `previous` ([`Recorder::open_with_keys`]); without it a log that holds
/// such records is refused (fail closed).
fn open_recorder(
    cfg: &RecorderConfig,
    signer: &SharedSigner,
    verifier: Option<&SharedVerifier>,
    previous: Option<&PreviousKeys>,
    clock: &FollowClock,
) -> Result<Recorder, robodr_blackbox::Error> {
    Recorder::open_with_keys(
        cfg.clone(),
        Box::new(signer.clone()),
        verifier.map(|v| Box::new(v.clone()) as Box<dyn Verifier>),
        previous
            .filter(|p| !p.is_empty())
            .map(|p| Box::new(p.clone()) as Box<dyn Verifier>),
        Box::new(clock.clone()),
    )
}

/// Message signed by a would-be finding key to prove it is not the
/// black-box key (domain-separated: neither a record nor a finding).
const KEY_SEPARATION_PROBE: &[u8] = b"robodr-agent/finding-key-separation-probe/v1\0";

/// Note payload for an agent fault in the black box.
#[derive(Serialize)]
struct FaultNote<'a> {
    kind: &'static str,
    fault: FaultKind,
    mono_ns: u64,
    wall_ns: u64,
    detail: &'a str,
    clock: Option<ClockAnomaly>,
}

/// Note payload for a plan in the black box.
#[derive(Serialize)]
struct PlanNote<'a> {
    kind: &'static str,
    deviation: Option<&'a BlackBoxRef>,
    disposition: Disposition,
    guard_violation: Option<&'a str>,
    plan: &'a ResponsePlan,
    /// The responder's plan the backstop replaced, if it did.
    rejected_plan: Option<&'a ResponsePlan>,
}

/// Note payload for a firewall verdict in the black box.
#[derive(Serialize)]
struct VerdictNote<'a> {
    event: Option<&'a BlackBoxRef>,
    #[serde(flatten)]
    verdict: &'a FirewallVerdictRecord,
}

struct FirewallState {
    fw: Firewall,
    kinds: BTreeMap<String, ChannelKind>,
    /// Participant prefix (24 hex) -> the profile identity it holds right
    /// now ([`Agent::set_source_identities`]): a restarted writer with a
    /// fresh GUID is matched against `identity:<name>` sources.
    identities: BTreeMap<String, String>,
    /// The low-level joint-frame firewall (its own instance: its clock is
    /// the frames' observation time, see [`JointInput::stamp_ns`]).
    joint: Option<JointFirewall>,
}

struct JointFirewall {
    fw: Firewall,
    channels: std::collections::BTreeSet<String>,
    last_now: Option<u64>,
}

impl FirewallState {
    fn is_joint_channel(&self, channel: &str) -> bool {
        self.joint
            .as_ref()
            .is_some_and(|j| j.channels.contains(channel))
    }
}

struct MonitorState {
    monitor: ConsistencyMonitor,
    settings: MonitorSettings,
    publishers: PublisherIds,
}

/// Most distinct feedback publisher GUIDs given a dense id; beyond it,
/// [`robodr_motion::publisher_id`] (a 32-bit hash) is used and counted in
/// [`AgentStats::publishers_hashed`].
pub const MAX_INTERNED_PUBLISHERS: usize = 1024;

/// Interned feedback-publisher ids for
/// [`ConsistencyMonitor::on_feedback_from`]. Dense ids (1, 2, ...) cannot
/// be collided on purpose, unlike a hash of an attacker-chosen GUID; the
/// table is bounded, and an overflow falls back to the hash (counted).
#[derive(Default)]
struct PublisherIds {
    ids: BTreeMap<String, u32>,
}

impl PublisherIds {
    fn intern(&mut self, guid: &str, stats: &mut AgentStats) -> u32 {
        let key = guid.to_ascii_lowercase();
        if let Some(id) = self.ids.get(&key) {
            return *id;
        }
        if self.ids.len() < MAX_INTERNED_PUBLISHERS {
            // 0 is PUBLISHER_UNKNOWN; the table never exceeds u32 range.
            let id = u32::try_from(self.ids.len() + 1).unwrap_or(u32::MAX);
            self.ids.insert(key, id);
            return id;
        }
        stats.publishers_hashed = stats.publishers_hashed.saturating_add(1);
        robodr_motion::publisher_id(key.as_bytes())
    }
}

/// The RoboDR agent for one robot. See the module docs.
pub struct Agent {
    profile: Profile,
    context: OperationalContext,
    ocsf: RobotContext,
    attestation: robodr_ocsf::AttestationStatus,
    partitions: Option<u32>,
    record_all_events: bool,
    responder: Responder,
    /// `None` while the black box is unavailable (see module docs).
    recorder: Option<Recorder>,
    blackbox_cfg: RecorderConfig,
    signer: SharedSigner,
    /// Explicit verifier for `signer`'s key, if the signer cannot verify.
    verifier: Option<SharedVerifier>,
    /// Retired black-box keys (after a key rotation), for every (re)open.
    previous_keys: Option<PreviousKeys>,
    /// Monotonic time of the first failure of the current outage.
    blackbox_down_since: Option<u64>,
    last_reopen_attempt: Option<u64>,
    /// Appends lost during the current outage.
    lost_while_down: u64,
    follow: FollowClock,
    clock: Box<dyn Clock>,
    time: TimeGuard,
    firewall: Option<FirewallState>,
    monitor: Option<MonitorState>,
    executor: Box<dyn Executor>,
    /// Optional Ed25519 key signing every finding record (contract 1.2,
    /// `robodr_ocsf::sig`). Separate from the black-box key on purpose.
    finding_signer: Option<Box<dyn Signer>>,
    /// Plans are marked as coming from a replay (see [`ExecutionRequest`]).
    replay: bool,
    seen: BTreeMap<String, (u64, u64)>,
    faults: VecDeque<AgentFault>,
    stats: AgentStats,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("robot", &self.ocsf.robot.id)
            .field("profile_locked", &self.profile.locked)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// Result of [`Agent::finish`].
#[derive(Debug, Clone)]
pub struct Finished {
    /// Final seal of the black box. Keep it off-unit: it is the trusted
    /// checkpoint for [`crate::evidence::verify_blackbox`].
    pub checkpoint: Checkpoint,
    pub stats: AgentStats,
}

impl Agent {
    /// Validate everything, open (or resume) the black box and build the
    /// detectors. Reads `clock` once for the black box's opening records.
    ///
    /// `signer` must be able to verify its own signatures
    /// ([`Signer::verify_own`], e.g. the HMAC key): the black box
    /// authenticates the chain it resumes. Otherwise use
    /// [`Agent::new_with_verifier`].
    pub fn new(
        cfg: AgentConfig,
        signer: Box<dyn Signer>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, AgentError> {
        Self::build(cfg, signer, None, None, clock)
    }

    /// [`Agent::new`] / [`Agent::new_with_verifier`] for a black box whose
    /// key was rotated: `previous_keys` (this unit's retired keys, public
    /// halves suffice) authenticate the records signed before the rotation
    /// at open and at every reopen ([`Recorder::open_with_keys`]). Without
    /// the key that signed a retained record, the black box is refused.
    pub fn new_with_keys(
        cfg: AgentConfig,
        signer: Box<dyn Signer>,
        verifier: Option<Arc<dyn Verifier + Send + Sync>>,
        previous_keys: Option<PreviousKeys>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, AgentError> {
        Self::build(
            cfg,
            signer,
            verifier.map(SharedVerifier),
            previous_keys,
            clock,
        )
    }

    /// [`Agent::new`] for a signer that cannot verify its own signatures:
    /// `verifier` checks the signer's key (same key id and algorithm) when
    /// the black box is opened and every time it is reopened.
    pub fn new_with_verifier(
        cfg: AgentConfig,
        signer: Box<dyn Signer>,
        verifier: Arc<dyn Verifier + Send + Sync>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, AgentError> {
        Self::build(cfg, signer, Some(SharedVerifier(verifier)), None, clock)
    }

    fn build(
        cfg: AgentConfig,
        signer: Box<dyn Signer>,
        verifier: Option<SharedVerifier>,
        previous_keys: Option<PreviousKeys>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, AgentError> {
        cfg.validate()?;
        let responder = Responder::new(cfg.policy).map_err(AgentError::Policy)?;
        let firewall = match cfg.firewall {
            None => None,
            Some(fs) => {
                // A joint channel is checked by the joint firewall only: the
                // twist / joint-velocity firewall gets the profile without
                // it, the joint firewall the profile with only its channels.
                let mut twist_profile = cfg.profile.clone();
                twist_profile.retain_motion_channels(|k| !fs.joint_channels.contains_key(k));
                let policy = Policy::compile(&twist_profile, fs.platform, &fs.channels)
                    .map_err(AgentError::Firewall)?;
                let joint = if fs.joint_channels.is_empty() {
                    None
                } else {
                    let mut joint_profile = cfg.profile.clone();
                    joint_profile.retain_motion_channels(|k| fs.joint_channels.contains_key(k));
                    let jp = Policy::compile_with_joints(
                        &joint_profile,
                        fs.platform,
                        &BTreeMap::new(),
                        &fs.joint_channels,
                    )
                    .map_err(AgentError::Firewall)?;
                    Some(JointFirewall {
                        fw: Firewall::new(jp),
                        channels: fs.joint_channels.keys().cloned().collect(),
                        last_now: None,
                    })
                };
                let kinds = fs
                    .channels
                    .iter()
                    .map(|(k, s)| (k.clone(), s.kind))
                    .collect();
                Some(FirewallState {
                    fw: Firewall::new(policy),
                    kinds,
                    identities: BTreeMap::new(),
                    joint,
                })
            }
        };
        let monitor = match cfg.monitor {
            None => None,
            Some(settings) => Some(MonitorState {
                monitor: ConsistencyMonitor::new(settings.config.clone())
                    .map_err(AgentError::Monitor)?,
                settings,
                publishers: PublisherIds::default(),
            }),
        };
        let mode = if cfg.profile.locked {
            OcsfMode::Enforce
        } else {
            OcsfMode::Observe
        };
        let mut ocsf = RobotContext::new(
            cfg.robot,
            ProfileRef {
                version: cfg.profile_version,
                sha256: profile_sha256(&cfg.profile),
            },
            mode,
        );
        ocsf.data_source = cfg.data_source;
        ocsf.topic = cfg.findings_topic;
        let start = clock.now();
        // Fail at start, not on every finding, if the trusted labels (model,
        // site, profile version, ...) cannot produce a valid finding.
        probe_finding(&ocsf, start, cfg.kafka_partitions).map_err(AgentError::Config)?;
        let follow = FollowClock::new(start);
        let signer = SharedSigner::new(signer);
        let recorder = open_recorder(
            &cfg.blackbox,
            &signer,
            verifier.as_ref(),
            previous_keys.as_ref(),
            &follow,
        )
        .map_err(AgentError::BlackBox)?;
        let context = OperationalContext {
            profile_locked: cfg.profile.locked,
            ..cfg.context
        };
        Ok(Self {
            profile: cfg.profile,
            context,
            ocsf,
            attestation: cfg.attestation,
            partitions: cfg.kafka_partitions,
            record_all_events: cfg.record_all_events,
            responder,
            recorder: Some(recorder),
            blackbox_cfg: cfg.blackbox,
            signer,
            verifier,
            previous_keys,
            blackbox_down_since: None,
            last_reopen_attempt: None,
            lost_while_down: 0,
            follow,
            clock,
            time: TimeGuard::new(start, cfg.clock_jump_tolerance_ns),
            firewall,
            monitor,
            executor: Box::new(NoopExecutor),
            finding_signer: None,
            replay: false,
            seen: BTreeMap::new(),
            faults: VecDeque::new(),
            stats: AgentStats::default(),
        })
    }

    /// Mark every [`ExecutionRequest`] from this agent as a replay: an
    /// executor must act on nothing (see [`crate::executor`]).
    pub(crate) fn mark_replay(&mut self) {
        self.replay = true;
    }

    /// Whether this agent's plans are marked as replayed.
    pub fn is_replay(&self) -> bool {
        self.replay
    }

    /// The newest agent faults (at most [`MAX_RETAINED_FAULTS`]), oldest
    /// first.
    pub fn faults(&self) -> impl Iterator<Item = &AgentFault> {
        self.faults.iter()
    }

    /// Remove and return the retained faults (e.g. to forward them to a
    /// health channel).
    pub fn take_faults(&mut self) -> Vec<AgentFault> {
        self.faults.drain(..).collect()
    }

    /// `true` while the black box is failing (appends are being lost).
    pub fn evidence_degraded(&self) -> bool {
        self.blackbox_down_since.is_some()
    }

    /// Replace the executor (default: [`NoopExecutor`]).
    #[must_use]
    pub fn with_executor(mut self, executor: Box<dyn Executor>) -> Self {
        self.executor = executor;
        self
    }

    /// Sign every finding record with `signer` (detached signature in the
    /// `robodr-finding-sig` header; see `robodr_ocsf::sig`). Must be an
    /// Ed25519 key; it is probed once here so a broken backend fails at
    /// start. It must be a key dedicated to findings: the black-box key is
    /// refused ([`AgentError::Config`]), by key id and by a signature test
    /// (a probe signed with the finding key that the black-box key's own
    /// verifier accepts is the same key under another name). Findings leave
    /// the unit; a shared key would let anyone who obtains it from a
    /// finding consumer's side of the deployment forge evidence too, and
    /// the two keys rotate on different schedules.
    ///
    /// If signing a finding later fails, the finding is still emitted
    /// **unsigned** and the failure is reported in the outcome's errors:
    /// strict consumers will drop it, the black box still has the evidence.
    pub fn with_finding_signer(mut self, signer: Box<dyn Signer>) -> Result<Self, AgentError> {
        if signer.key_id() == self.signer.key_id() {
            return Err(AgentError::Config(format!(
                "finding signer: key id {:?} is the black-box key; use a dedicated finding key",
                signer.key_id()
            )));
        }
        let probe = signer
            .sign(KEY_SEPARATION_PROBE)
            .map_err(|e| AgentError::Config(format!("finding signer: {e}")))?;
        let same = match &self.verifier {
            Some(v) => v.verify(KEY_SEPARATION_PROBE, &probe),
            None => self.signer.verify_own(KEY_SEPARATION_PROBE, &probe) == Some(true),
        };
        if same {
            return Err(AgentError::Config(
                "finding signer: it is the black-box key under another key id; use a \
                 dedicated finding key"
                    .into(),
            ));
        }
        robodr_ocsf::sign_value("", signer.as_ref())
            .map_err(|e| AgentError::Config(format!("finding signer: {e}")))?;
        self.finding_signer = Some(signer);
        Ok(self)
    }

    /// Whether findings are signed ([`Agent::with_finding_signer`]).
    pub fn signs_findings(&self) -> bool {
        self.finding_signer.is_some()
    }

    /// The participant identities currently held, prefix (24 hex) ->
    /// identity name, as resolved by the sensor pipeline. Used by the Motion
    /// Firewall for `identity:<name>` sources; replaces the previous map.
    pub fn set_source_identities(&mut self, held: BTreeMap<String, String>) {
        if let Some(fs) = self.firewall.as_mut() {
            fs.identities = held;
        }
    }

    /// Replace the live part of the operational context (control mode,
    /// mission phase, connectivity) that every later plan is made with, as
    /// read from live sources by the caller (`robodr-agentd`'s context
    /// feed). The platform, morphology, operator presence and profile lock
    /// stay as configured.
    pub fn set_operational(
        &mut self,
        control: robodr_responder::ControlMode,
        phase: robodr_responder::MissionPhase,
        connectivity: robodr_responder::Connectivity,
    ) {
        self.context.control = control;
        self.context.phase = phase;
        self.context.connectivity = connectivity;
    }

    /// The operational context plans are made with (before the per-plan
    /// observe-mode downgrade).
    pub fn context(&self) -> OperationalContext {
        self.context
    }

    pub fn stats(&self) -> AgentStats {
        self.stats
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The black-box directory.
    pub fn blackbox_dir(&self) -> &std::path::Path {
        &self.blackbox_cfg.dir
    }

    /// Current head `(seq, hash)` of the black box (`None` while it is
    /// unavailable).
    pub fn blackbox_head(&self) -> Option<(u64, robodr_blackbox::Hash)> {
        self.recorder.as_ref().and_then(Recorder::head)
    }

    /// Write the black box's `head.json` high-water mark now if records were
    /// appended since the last mark (`Recorder::mark_head`). Call it from a
    /// housekeeping timer so the unmarked tail is bounded in time while no
    /// records arrive. `Ok(true)` = a mark was written, `Ok(false)` =
    /// nothing new to mark, `Err` = the black box is unavailable or the
    /// mark failed (recording goes on; see `Recorder::mark_failures`).
    pub fn mark_blackbox_head(&mut self) -> Result<bool, String> {
        let Some(rec) = self.recorder.as_mut() else {
            return Err("black box unavailable".into());
        };
        let Some((seq, _)) = rec.head() else {
            return Ok(false);
        };
        if rec.head_mark().is_some_and(|m| m >= seq) {
            return Ok(false);
        }
        rec.mark_head().map(|()| true).map_err(|e| e.to_string())
    }

    /// Closed black-box segments the current recorder found damaged and
    /// quarantined when it was opened (or last reopened after an outage).
    /// Empty while the black box is unavailable.
    pub fn blackbox_quarantined(&self) -> &[u64] {
        self.recorder
            .as_ref()
            .map_or(&[], Recorder::quarantined_at_open)
    }

    /// Evidence trouble the current recorder found when it was opened (or
    /// last reopened after an outage): quarantined segments with the
    /// recorder's severity, damage quarantined from the active segment,
    /// truncation (always critical). Empty while the black box is
    /// unavailable.
    pub fn blackbox_open_incidents(&self) -> &[robodr_blackbox::OpenIncident] {
        self.recorder.as_ref().map_or(&[], Recorder::open_incidents)
    }

    /// Whether the black box has an external head anchor configured
    /// (`RecorderConfig::head_anchor`). Without one, a cut of the newest
    /// records combined with a rollback of `head.json` (or a wiped store)
    /// is not detectable on the unit.
    pub fn blackbox_anchored(&self) -> bool {
        self.blackbox_cfg.head_anchor.is_some()
    }

    /// Failed writes / reads of the external head anchor by the current
    /// recorder (0 while the black box is unavailable).
    pub fn blackbox_anchor_failures(&self) -> u64 {
        self.recorder.as_ref().map_or(0, Recorder::anchor_failures)
    }

    /// `head.json` marks the current recorder could not write.
    pub fn blackbox_mark_failures(&self) -> u64 {
        self.recorder.as_ref().map_or(0, Recorder::mark_failures)
    }

    /// Handle `event` at the injected clock's current time.
    pub fn tick(&mut self, event: &RobotEvent, safety: SafetyState) -> Vec<Outcome> {
        let now = self.clock.now();
        self.handle(now, event, safety)
    }

    /// Run the full chain for one event observed at `now` while the platform
    /// reports `safety`. Returns one [`Outcome`] per deviation (possibly
    /// none). Never panics; never executes anything.
    pub fn handle(
        &mut self,
        now: Timestamp,
        event: &RobotEvent,
        safety: SafetyState,
    ) -> Vec<Outcome> {
        self.handle_with_joint(now, event, None, safety)
    }

    /// [`Agent::handle`] for a `MotionCommand` decoded from a low-level
    /// joint frame (Unitree `LowCmd`): on a channel the firewall settings
    /// list as a joint channel ([`crate::FirewallSettings::joint_channels`])
    /// the frame is checked slot by slot with `Firewall::check_joint` (its
    /// verdict recorded as `robodr.firewall_joint_verdict`) instead of the
    /// twist / joint-velocity model. A command on a joint channel without a
    /// frame is not checked by the firewall (counted in
    /// [`AgentStats::joint_frames_missing`]); `joint` on any other channel is
    /// ignored. Profile evaluation and the motion monitor are unchanged.
    pub fn handle_with_joint(
        &mut self,
        now: Timestamp,
        event: &RobotEvent,
        joint: Option<&JointInput>,
        safety: SafetyState,
    ) -> Vec<Outcome> {
        self.handle_with_joint_at(now, None, event, joint, safety)
    }

    /// [`Agent::handle_with_joint`] with an explicit detection time
    /// `detect_ns` (monotonic ns on the event's observation timeline) for
    /// the time-dependent detectors: the twist firewall's rate checks and
    /// the motion monitor (commands, feedback, safety-stop grace, expiry).
    /// `None` uses the guarded `now.mono_ns`, as [`Agent::handle_with_joint`]
    /// does. Every caller must keep `detect_ns` on one non-decreasing
    /// timeline (the monitor holds a regression; it never rewinds).
    /// Evidence (black box, findings) is stamped with `now` either way.
    pub fn handle_with_joint_at(
        &mut self,
        now: Timestamp,
        detect_ns: Option<u64>,
        event: &RobotEvent,
        joint: Option<&JointInput>,
        safety: SafetyState,
    ) -> Vec<Outcome> {
        let now = self.observe_time(now);
        self.stats.events = self.stats.events.saturating_add(1);
        let mono = detect_ns.unwrap_or(now.mono_ns);
        let mode = self.profile.mode();

        // 1. Detection.
        let mut found: Vec<(Detector, Deviation)> = Vec::new();
        if let Some(d) = self.profile.evaluate(event) {
            found.push((Detector::Profile, d));
        }
        let mut verdict: Option<FirewallVerdictRecord> = None;
        if let RobotEvent::MotionCommand(c) = event {
            if let Some(fs) = self.firewall.as_mut() {
                if fs.is_joint_channel(&c.channel) {
                    match joint {
                        Some(j) => {
                            let (rec, devs, clamped) = check_joint_firewall(fs, c, j);
                            self.stats.firewall_checks =
                                self.stats.firewall_checks.saturating_add(1);
                            self.stats.joint_firewall_checks =
                                self.stats.joint_firewall_checks.saturating_add(1);
                            if clamped {
                                self.stats.joint_clock_clamped =
                                    self.stats.joint_clock_clamped.saturating_add(1);
                            }
                            verdict = Some(rec);
                            found.extend(devs.into_iter().map(|d| (Detector::Firewall, d)));
                        }
                        None => {
                            self.stats.joint_frames_missing =
                                self.stats.joint_frames_missing.saturating_add(1);
                        }
                    }
                } else {
                    let (rec, devs) = check_firewall(fs, c, mono);
                    self.stats.firewall_checks = self.stats.firewall_checks.saturating_add(1);
                    verdict = Some(rec);
                    found.extend(devs.into_iter().map(|d| (Detector::Firewall, d)));
                }
            }
        }
        if let Some(ms) = self.monitor.as_mut() {
            let mut hits = Vec::new();
            if safety != SafetyState::Unknown {
                ms.monitor
                    .set_safety_stop(mono, safety.safety_system_engaged());
            }
            match event {
                RobotEvent::MotionCommand(c) => ms
                    .monitor
                    .on_command(&command_sample(c, mono), |f| hits.push(f)),
                RobotEvent::MotionFeedback(f) => {
                    let source = ms.settings.source_for(&f.channel);
                    let (linear, magnitude_dropped) = feedback_linear(&ms.monitor, source, f);
                    if magnitude_dropped {
                        self.stats.feedback_magnitude_dropped =
                            self.stats.feedback_magnitude_dropped.saturating_add(1);
                    }
                    let sample = FeedbackSample {
                        t_ns: f.timestamp_ns,
                        source,
                        linear,
                        angular: f.angular_velocity,
                        joint_speed_max: f.measured_joint_speed,
                    };
                    match f.publisher_guid.as_deref() {
                        Some(g) => match robodr_motion::PublisherKey::from_guid_str(g) {
                            Some(key) => ms
                                .monitor
                                .on_feedback_key(mono, key, &sample, |x| hits.push(x)),
                            None => {
                                let id = ms.publishers.intern(g, &mut self.stats);
                                ms.monitor
                                    .on_feedback_from(mono, id, &sample, |x| hits.push(x));
                            }
                        },
                        None => ms.monitor.on_feedback(mono, &sample, |x| hits.push(x)),
                    }
                }
                _ => ms.monitor.tick(mono, |x| hits.push(x)),
            }
            found.extend(
                hits.iter()
                    .map(|h| (Detector::MotionMonitor, h.to_deviation())),
            );
        }
        let found: Vec<(Detector, Deviation)> = found
            .into_iter()
            .map(|(k, d)| (k, d.with_mode(mode)))
            .collect();

        // 2. Evidence for the event itself (once per event).
        let notable_verdict = verdict.as_ref().is_some_and(|v| v.is_notable());
        let mut shared_errors = Vec::new();
        let event_ref = if self.record_all_events || !found.is_empty() || notable_verdict {
            let critical = found.iter().any(|(_, d)| d.severity >= Severity::High);
            self.append("event", &mut shared_errors, |r| {
                r.append_event(event, critical)
            })
        } else {
            None
        };
        let verdict_ref = match &verdict {
            Some(v) if notable_verdict || self.record_all_events => {
                let note = VerdictNote {
                    event: event_ref.as_ref(),
                    verdict: v,
                };
                let critical = v.verdict == "rejected";
                self.append("firewall verdict", &mut shared_errors, |r| {
                    r.append_note(&note, critical)
                })
            }
            _ => None,
        };

        // 3. Per deviation: plan, evidence, finding, executor.
        let mut outcomes = Vec::with_capacity(found.len());
        for (detector, dev) in found {
            let source = source_key(event);
            let is_fw = detector == Detector::Firewall;
            let evidence = EvidenceLinks {
                event: event_ref.clone(),
                firewall_verdict: if is_fw { verdict_ref.clone() } else { None },
                errors: shared_errors.clone(),
                ..EvidenceLinks::default()
            };
            outcomes.push(self.respond(
                now,
                safety,
                detector,
                source,
                dev,
                FindingSubject::Event(event),
                evidence,
                if is_fw { verdict.clone() } else { None },
            ));
        }
        outcomes
    }

    /// Run the response half of the chain for a deviation raised **outside**
    /// the agent: the ROS 2 detection pipeline ([`Detector::Sensor`]) or a
    /// daemon's own health checks ([`Detector::SelfHealth`]).
    ///
    /// The deviation is planned, recorded (deviation + plan note) and turned
    /// into a validated finding exactly like one the agent detected itself,
    /// with the same invariants:
    ///
    /// * **Mode.** The deviation keeps the stricter of its own mode and the
    ///   profile's (observe wins), so a pipeline running observe-only (e.g.
    ///   profile refused) can never yield an action plan here.
    /// * **Self-health is never acted on.** A [`Detector::SelfHealth`]
    ///   deviation is always stamped observe-only: an agent-internal problem
    ///   (or an attacker starving an input) cannot by itself cause a motion
    ///   request. It is still recorded and reported.
    ///
    /// `source` is the responder's escalation key (e.g. `src:<ip>` or
    /// `input:<name>`); `subject` feeds the finding's subject and uid.
    /// Never panics; never executes anything.
    pub fn handle_external(
        &mut self,
        now: Timestamp,
        detector: Detector,
        source: &str,
        subject: Subject,
        dev: Deviation,
        safety: SafetyState,
    ) -> Outcome {
        let now = self.observe_time(now);
        let observe = detector == Detector::SelfHealth
            || dev.is_observe_only()
            || self.profile.mode() == Mode::Observe;
        let dev = dev.with_mode(if observe {
            Mode::Observe
        } else {
            Mode::Enforce
        });
        self.respond(
            now,
            safety,
            detector,
            source.to_string(),
            dev,
            FindingSubject::Explicit(subject),
            EvidenceLinks::default(),
            None,
        )
    }

    /// Record a deviation in the black box only, exactly as
    /// [`Agent::handle_external`] records it (same mode rule, same record
    /// kind and criticality), but without a response plan, a finding or an
    /// executor submission. For deviations a caller folds into one
    /// aggregate finding (agentd's discovery-flood guard): each one stays
    /// evidence. Returns the record's reference, or why it was not written.
    pub fn record_deviation(
        &mut self,
        now: Timestamp,
        detector: Detector,
        dev: &Deviation,
    ) -> Result<BlackBoxRef, Vec<String>> {
        self.observe_time(now);
        let observe = detector == Detector::SelfHealth
            || dev.is_observe_only()
            || self.profile.mode() == Mode::Observe;
        let dev = dev.clone().with_mode(if observe {
            Mode::Observe
        } else {
            Mode::Enforce
        });
        let mut errors = Vec::new();
        self.append("deviation", &mut errors, |r| r.append_deviation(&dev))
            .ok_or(errors)
    }

    /// Append a free-form JSON note to the black box at `now` (e.g. a
    /// daemon heartbeat). Goes through the same outage handling as every
    /// other append (reopen with backoff, `evidence_recovered` fault).
    /// Returns the record's reference, or why it was not written.
    pub fn record_note<T: Serialize>(
        &mut self,
        now: Timestamp,
        what: &str,
        note: &T,
        critical: bool,
    ) -> Result<BlackBoxRef, Vec<String>> {
        self.observe_time(now);
        let mut errors = Vec::new();
        self.append(what, &mut errors, |r| r.append_note(note, critical))
            .ok_or(errors)
    }

    /// Sanitise `now` through the time guard, move the recorder's clock and
    /// record any clock anomaly.
    fn observe_time(&mut self, now: Timestamp) -> Timestamp {
        let (now, anomaly) = self.time.observe(now);
        self.follow.set(now);
        if let Some(a) = anomaly {
            self.clock_fault(now, a);
        }
        now
    }

    /// Plan, record, report and submit one deviation (time already
    /// sanitised). `evidence` carries the links already written for the
    /// triggering event / verdict and their errors.
    #[allow(clippy::too_many_arguments)]
    fn respond(
        &mut self,
        now: Timestamp,
        safety: SafetyState,
        detector: Detector,
        source: String,
        dev: Deviation,
        subject: FindingSubject<'_>,
        mut evidence: EvidenceLinks,
        firewall: Option<FirewallVerdictRecord>,
    ) -> Outcome {
        self.stats.deviations = self.stats.deviations.saturating_add(1);
        let ctx = OperationalContext {
            profile_locked: self.profile.locked && !dev.is_observe_only(),
            ..self.context
        };
        let proposed = self
            .responder
            .plan(&dev, &source, safety, &ctx, now.mono_ns / 1_000_000);
        let (plan, guard_violation) = guard(proposed.clone(), &dev, safety, &ctx);
        if guard_violation.is_some() {
            self.stats.guard_violations = self.stats.guard_violations.saturating_add(1);
        }
        let disposition = Disposition::of(&plan);

        evidence.deviation = self.append("deviation", &mut evidence.errors, |r| {
            r.append_deviation(&dev)
        });
        let note = PlanNote {
            kind: "robodr.response_plan",
            deviation: evidence.deviation.as_ref(),
            disposition,
            guard_violation: guard_violation.as_deref(),
            plan: &plan,
            rejected_plan: guard_violation.is_some().then_some(&proposed),
        };
        let critical = plan.max_step > Step::Record || dev.severity >= Severity::High;
        let mut errs = Vec::new();
        evidence.plan = self.append("plan", &mut errs, |r| r.append_note(&note, critical));
        evidence.errors.extend(errs);

        let refs = evidence.refs();
        let (finding, finding_errors) = self.build_finding(&dev, subject, safety, now, &refs);
        if finding.is_some() {
            self.stats.findings = self.stats.findings.saturating_add(1);
        } else {
            self.stats.finding_errors = self.stats.finding_errors.saturating_add(1);
        }

        self.executor.submit(&ExecutionRequest {
            plan: &plan,
            disposition,
            safety_state: safety,
            context: &ctx,
            evidence: &refs,
            finding_id: finding.as_ref().map(|f| f.key.as_str()),
            replay: self.replay,
        });

        Outcome {
            detector,
            source,
            deviation: dev,
            plan,
            disposition,
            guard_violation,
            evidence,
            firewall,
            finding,
            finding_errors,
        }
    }

    /// Seal and close the black box. Returns the final checkpoint. If the
    /// black box is down, one last reopen is attempted (ignoring the
    /// backoff) so what was recorded is sealed.
    pub fn finish(mut self) -> Result<Finished, AgentError> {
        if self.recorder.is_none() {
            self.last_reopen_attempt = None;
            self.try_reopen();
        }
        let stats = self.stats;
        let recorder = self
            .recorder
            .take()
            .ok_or(AgentError::BlackBox(robodr_blackbox::Error::Poisoned))?;
        let checkpoint = recorder.close().map_err(AgentError::BlackBox)?;
        Ok(Finished { checkpoint, stats })
    }

    fn clock_fault(&mut self, now: Timestamp, a: ClockAnomaly) {
        let (kind, detail) = match a {
            ClockAnomaly::MonoRegression {
                observed_ns,
                held_ns,
            } => {
                self.stats.clock_regressions = self.stats.clock_regressions.saturating_add(1);
                (
                    FaultKind::ClockRegression,
                    format!("monotonic time went back from {held_ns} to {observed_ns} ns; held"),
                )
            }
            ClockAnomaly::WallJump {
                wall_delta_ns,
                mono_delta_ns,
            } => {
                self.stats.wall_clock_jumps = self.stats.wall_clock_jumps.saturating_add(1);
                (
                    FaultKind::WallClockJump,
                    format!(
                        "wall time moved {wall_delta_ns} ns while monotonic moved {mono_delta_ns} ns"
                    ),
                )
            }
        };
        self.fault(kind, now, detail, Some(a), true);
    }

    /// Raise a fault: keep it in memory and, if `to_blackbox`, append it as a
    /// critical note (through [`Self::append`], whose own failures are
    /// recorded in memory only, so this never recurses).
    fn fault(
        &mut self,
        kind: FaultKind,
        now: Timestamp,
        detail: String,
        clock: Option<ClockAnomaly>,
        to_blackbox: bool,
    ) {
        self.stats.faults = self.stats.faults.saturating_add(1);
        let record = if to_blackbox {
            let note = FaultNote {
                kind: "robodr.agent_fault",
                fault: kind,
                mono_ns: now.mono_ns,
                wall_ns: now.wall_ns,
                detail: &detail,
                clock,
            };
            let mut errs = Vec::new();
            self.append("agent fault", &mut errs, |r| r.append_note(&note, true))
        } else {
            None
        };
        if self.faults.len() >= MAX_RETAINED_FAULTS {
            self.faults.pop_front();
            self.stats.faults_dropped = self.stats.faults_dropped.saturating_add(1);
        }
        self.faults.push_back(AgentFault {
            kind,
            mono_ns: now.mono_ns,
            wall_ns: now.wall_ns,
            detail,
            clock,
            record,
        });
    }

    /// Drop the failed recorder and reopen the directory. Rate-limited by
    /// [`BLACKBOX_REOPEN_BACKOFF_NS`]. Returns `true` if a recorder is open
    /// afterwards.
    fn try_reopen(&mut self) -> bool {
        let now = self.time.last();
        if let Some(t) = self.last_reopen_attempt {
            if now.mono_ns.saturating_sub(t) < BLACKBOX_REOPEN_BACKOFF_NS {
                return false;
            }
        }
        self.last_reopen_attempt = Some(now.mono_ns);
        // Single writer: the old recorder (and its file handle) goes first.
        self.recorder = None;
        match open_recorder(
            &self.blackbox_cfg,
            &self.signer,
            self.verifier.as_ref(),
            self.previous_keys.as_ref(),
            &self.follow,
        ) {
            Ok(r) => {
                self.recorder = Some(r);
                self.stats.blackbox_reopens = self.stats.blackbox_reopens.saturating_add(1);
                true
            }
            Err(e) => {
                self.fault(
                    FaultKind::EvidenceRecoveryFailed,
                    now,
                    format!("reopening the black box failed: {e}"),
                    None,
                    false,
                );
                false
            }
        }
    }

    /// First failed append of an outage: remember it (in memory only; the
    /// black box is the thing that failed).
    fn evidence_down(&mut self, what: &str, e: &robodr_blackbox::Error) {
        if self.blackbox_down_since.is_none() {
            let now = self.time.last();
            self.blackbox_down_since = Some(now.mono_ns);
            self.fault(
                FaultKind::EvidenceWriteFailed,
                now,
                format!("{what}: {e}"),
                None,
                false,
            );
        }
    }

    /// A successful append after an outage: record the gap in the chain.
    fn evidence_up(&mut self) {
        let Some(since) = self.blackbox_down_since.take() else {
            return;
        };
        let lost = std::mem::take(&mut self.lost_while_down);
        let now = self.time.last();
        let detail = format!(
            "black box available again; {lost} appends lost since mono {since} ns ({} reopens so far)",
            self.stats.blackbox_reopens
        );
        self.fault(FaultKind::EvidenceRecovered, now, detail, None, true);
    }

    fn append(
        &mut self,
        what: &str,
        errors: &mut Vec<String>,
        mut f: impl FnMut(&mut Recorder) -> Result<AppendOutcome, robodr_blackbox::Error>,
    ) -> Option<BlackBoxRef> {
        use robodr_blackbox::Error as BbError;
        let mut retried = false;
        loop {
            let r = match self.recorder.as_mut() {
                Some(rec) => f(rec),
                None => Err(BbError::Poisoned),
            };
            match r {
                Ok(AppendOutcome::Recorded { seq, hash }) => {
                    self.stats.records_appended = self.stats.records_appended.saturating_add(1);
                    // The record went into the newest segment (rotation
                    // happens before a write, never after it).
                    let segment = self
                        .recorder
                        .as_ref()
                        .and_then(|r| r.segments().last().copied())
                        .unwrap_or(0);
                    let out = BlackBoxRef {
                        segment,
                        seq,
                        sha256: to_hex(&hash),
                    };
                    self.evidence_up();
                    return Some(out);
                }
                Ok(AppendOutcome::Refused(why)) => {
                    self.stats.evidence_errors = self.stats.evidence_errors.saturating_add(1);
                    errors.push(format!("{what}: refused by black box ({why:?})"));
                    return None;
                }
                Err(e) => {
                    // Per-record problems (too large, encoding) say nothing
                    // about the recorder; everything else is an outage.
                    let outage = !matches!(e, BbError::PayloadTooLarge { .. } | BbError::Encode(_));
                    if outage {
                        self.evidence_down(what, &e);
                        // A poisoned or missing recorder (or an I/O failure,
                        // e.g. during rotation) needs a reopen; a signing
                        // failure does not (nothing was written).
                        let reopen = matches!(e, BbError::Poisoned | BbError::Io(_));
                        if reopen && !retried && self.try_reopen() {
                            retried = true;
                            continue;
                        }
                        self.lost_while_down = self.lost_while_down.saturating_add(1);
                    }
                    self.stats.evidence_errors = self.stats.evidence_errors.saturating_add(1);
                    let msg = if self.recorder.is_none() {
                        format!("{what}: black box unavailable ({e})")
                    } else {
                        format!("{what}: {e}")
                    };
                    errors.push(msg);
                    return None;
                }
            }
        }
    }

    fn build_finding(
        &mut self,
        dev: &Deviation,
        subject: FindingSubject<'_>,
        safety: SafetyState,
        now: Timestamp,
        refs: &[BlackBoxRef],
    ) -> (Option<FindingOutput>, Vec<String>) {
        let wall_ms = now.wall_ns / 1_000_000;
        let mut b = FindingBuilder::from_deviation(dev, &self.ocsf)
            .safety_state(ocsf_safety(safety))
            .attestation(self.attestation);
        let event = match subject {
            FindingSubject::Event(ev) => {
                b = b.event(ev);
                Some(ev)
            }
            FindingSubject::Explicit(s) => {
                b = b.subject(s);
                None
            }
        };
        if let Some(RobotEvent::MotionCommand(c)) = event {
            // The findings contract only carries finite, non-negative speeds.
            // Commands are magnitudes (sign is ignored by detection), so send
            // |v|; a non-finite value is omitted here and survives verbatim in
            // the tainted detail and in the black-box event record.
            let clean = |v: Option<f64>| v.filter(|x| x.is_finite()).map(f64::abs);
            let sanitized = MotionCommand {
                linear_speed: clean(c.linear_speed),
                joint_speed: clean(c.joint_speed),
                ..c.clone()
            };
            b = b.command(&sanitized, self.profile.motion_envelopes.get(&c.channel));
        }
        let uid = b.finding_uid();
        let (first, count) = match self.seen.get_mut(&uid) {
            Some((first, count)) => {
                *count = count.saturating_add(1);
                (*first, *count)
            }
            None => {
                if self.seen.len() < MAX_TRACKED_FINDINGS {
                    self.seen.insert(uid, (wall_ms, 1));
                }
                (wall_ms, 1)
            }
        };
        // Wall time may step backwards (NTP); first <= last is required.
        b = b.seen(first.min(wall_ms), wall_ms).occurrences(count);
        for r in refs {
            b = b.evidence(r.clone());
        }
        let env = match b.build() {
            Ok(env) => env,
            Err(errs) => return (None, errs.iter().map(ToString::to_string).collect()),
        };
        match robodr_ocsf::record(&env, self.partitions) {
            Ok(mut rec) => {
                let mut errors = Vec::new();
                if let Some(signer) = &self.finding_signer {
                    if let Err(e) = robodr_ocsf::sign_record(&mut rec, signer.as_ref()) {
                        errors.push(format!("finding emitted unsigned: {e}"));
                    }
                }
                (
                    Some(FindingOutput {
                        topic: rec.topic,
                        key: rec.key,
                        partition: rec.partition,
                        value: rec.value,
                        headers: rec
                            .headers
                            .into_iter()
                            .map(|(k, v)| (k.to_string(), v))
                            .collect(),
                    }),
                    errors,
                )
            }
            Err(errs) => (None, errs.iter().map(ToString::to_string).collect()),
        }
    }
}

/// What a finding is about: the triggering event (subject and command taken
/// from it) or an explicit subject (externally raised deviations).
enum FindingSubject<'a> {
    Event(&'a RobotEvent),
    Explicit(Subject),
}

/// Build and validate one finding from the trusted configuration alone.
fn probe_finding(
    ctx: &RobotContext,
    now: Timestamp,
    partitions: Option<u32>,
) -> Result<(), String> {
    let dev = Deviation::new(
        "robot.agent.config_check",
        Severity::Low,
        "configuration probe",
    );
    let ms = now.wall_ns / 1_000_000;
    let env = FindingBuilder::from_deviation(&dev, ctx)
        .seen(ms, ms)
        .occurrences(1)
        .build()
        .map_err(|e| join_errors("trusted labels do not give a valid finding", &e))?;
    robodr_ocsf::record(&env, partitions)
        .map(|_| ())
        .map_err(|e| join_errors("trusted labels do not give a valid finding", &e))
}

fn join_errors<E: std::fmt::Display>(what: &str, errs: &[E]) -> String {
    let parts: Vec<String> = errs.iter().map(ToString::to_string).collect();
    format!("{what}: {}", parts.join("; "))
}

/// Escalation key: deviations from one participant escalate together.
pub fn source_key(event: &RobotEvent) -> String {
    let prefix = |g: &str| g.get(..24).unwrap_or(g).to_ascii_lowercase();
    match event {
        RobotEvent::Ros2ParticipantDiscovered(p) => {
            format!("participant:{}", prefix(&p.guid_prefix))
        }
        RobotEvent::Ros2WriterDiscovered(e) | RobotEvent::Ros2ReaderDiscovered(e) => {
            format!("participant:{}", prefix(&e.guid_prefix))
        }
        RobotEvent::MotionCommand(c) => match &c.source_guid {
            Some(g) => format!("participant:{}", prefix(g)),
            None => format!("channel:{}", c.channel),
        },
        RobotEvent::MotionFeedback(f) => format!("channel:{}", f.channel),
    }
}

/// The agent's backstop on a responder plan. Returns the plan to use and the
/// reason it was replaced, if it was.
pub fn guard(
    plan: ResponsePlan,
    dev: &Deviation,
    state: SafetyState,
    ctx: &OperationalContext,
) -> (ResponsePlan, Option<String>) {
    let violation = match check_invariants(&plan, state, ctx) {
        Err(v) => Some(format!("invariant violated: {v}")),
        Ok(())
            if dev.is_observe_only()
                && (!plan.observe_only
                    || plan.actions.iter().any(|a| a.step() != Step::Record)) =>
        {
            Some("observe-only deviation produced an action plan".to_string())
        }
        Ok(()) => None,
    };
    match violation {
        None => (plan, None),
        Some(v) => (
            ResponsePlan {
                max_step: Step::Record,
                actions: vec![ResponseAction::Record],
                requires_human_approval: true,
                observe_only: plan.observe_only || dev.is_observe_only(),
                would_have: None,
                ..plan
            },
            Some(v),
        ),
    }
}

/// Map the responder's safety state onto the finding's (motion, proximity).
/// Proximity is only asserted when the platform says a human is near;
/// otherwise it is unknown (absence is never claimed).
pub fn ocsf_safety(s: SafetyState) -> robodr_ocsf::SafetyState {
    let (motion, human) = match s {
        SafetyState::Idle | SafetyState::EStopActive | SafetyState::SafeStateActive => {
            (MotionState::Stationary, HumanProximity::Unknown)
        }
        SafetyState::MovingSlow | SafetyState::MovingFast => {
            (MotionState::Moving, HumanProximity::Unknown)
        }
        SafetyState::CollaborativeHumanNearby => (MotionState::Unknown, HumanProximity::Detected),
        SafetyState::Unknown => (MotionState::Unknown, HumanProximity::Unknown),
    };
    robodr_ocsf::SafetyState {
        motion,
        human_proximity: human,
    }
}

/// The firewall source of a command's GUID: the exact endpoint GUID first;
/// then its 24-hex-char participant prefix, so a spec that lists a
/// participant authorises that participant's writers; last, the participant
/// identity its prefix holds (`identity:<name>`). `SourceId::UNKNOWN` when
/// nothing matches (or there is no GUID).
fn resolve_source(
    fw: &Firewall,
    identities: &BTreeMap<String, String>,
    guid: Option<&str>,
) -> SourceId {
    guid.and_then(|g| {
        fw.source_id(g)
            .or_else(|| g.get(..24).and_then(|p| fw.source_id(p)))
            .or_else(|| {
                let name = identities.get(&g.get(..24)?.to_ascii_lowercase())?;
                fw.source_id(&format!(
                    "{}{name}",
                    robodr_firewall::IDENTITY_SOURCE_PREFIX
                ))
            })
    })
    .unwrap_or(SourceId::UNKNOWN)
}

fn to_firewall_command(fs: &FirewallState, c: &MotionCommand, now: u64) -> Command {
    let source = resolve_source(&fs.fw, &fs.identities, c.source_guid.as_deref());
    let channel = fs.fw.channel_id(&c.channel).unwrap_or(ChannelId(u16::MAX));
    // Signed body-frame values, as on the wire (REP 103), on all six axes:
    // the firewall bounds the norm of each vector, so a holonomic (or
    // hostile) `linear.y/z` / `angular.x/y` must reach it.
    let yaw = c.angular_speed.unwrap_or(0.0);
    let (ly, lz) = (c.linear_y.unwrap_or(0.0), c.linear_z.unwrap_or(0.0));
    let (ax, ay) = (c.angular_x.unwrap_or(0.0), c.angular_y.unwrap_or(0.0));
    let twist = |v: f64| Motion::Twist(Twist::new(Vec3::new(v, ly, lz), Vec3::new(ax, ay, yaw)));
    let joints = |n: usize, v: f64| {
        Motion::Joints(
            JointVelocities::from_slice(&vec![v; n.clamp(1, robodr_firewall::MAX_JOINTS)])
                .unwrap_or_else(|| JointVelocities::zeros(1)),
        )
    };
    let motion = match fs.kinds.get(&c.channel) {
        Some(ChannelKind::Joints { count }) => match (c.joint_speed, c.linear_speed) {
            (None, Some(l)) => twist(l),
            (j, _) => joints(*count, j.unwrap_or(0.0)),
        },
        _ => match (c.linear_speed, c.joint_speed) {
            (None, Some(j)) => joints(1, j),
            (l, _) => twist(l.unwrap_or(0.0)),
        },
    };
    Command {
        source,
        channel,
        stamp_ns: now,
        motion,
    }
}

/// The motion monitor's view of a command: the same signed values the
/// firewall's `Twist` carries (`linear.x`, `angular.z`), with an axis the
/// command does not mention left as "no expectation" (`None`) rather than
/// zero.
fn command_sample(c: &MotionCommand, now: u64) -> CommandSample<'_> {
    CommandSample {
        t_ns: now,
        channel: &c.channel,
        linear: c.linear_speed,
        angular: c.angular_speed,
        joint_speed_max: c.joint_speed,
        direction_known: true,
    }
}

/// Linear feedback for the monitor: the signed `linear_velocity` when given;
/// the magnitude `measured_linear_speed` only when the monitor compares
/// magnitudes for `source` (unsigned source, or `compare_magnitudes`).
/// Otherwise the axis is withheld (`None`, and `true` is returned so it is
/// counted): a magnitude compared against a signed command would turn every
/// reversing manoeuvre into a "robot moves against its command" finding.
fn feedback_linear(
    monitor: &ConsistencyMonitor,
    source: robodr_motion::FeedbackSource,
    f: &robodr_events::MotionFeedback,
) -> (Option<f64>, bool) {
    if f.linear_velocity.is_some() {
        return (f.linear_velocity, false);
    }
    let cfg = monitor.config();
    let magnitudes_ok = cfg.compare_magnitudes || !cfg.sources.get(source).signed;
    match f.measured_linear_speed {
        Some(m) if magnitudes_ok => (Some(m), false),
        Some(_) => (None, true),
        None => (None, false),
    }
}

fn output_speed(cmd: &Command) -> f64 {
    match &cmd.motion {
        Motion::Twist(t) => {
            let l = t.linear;
            (l.x * l.x + l.y * l.y + l.z * l.z).sqrt()
        }
        Motion::Joints(j) => j.as_slice().iter().fold(0.0_f64, |m, v| m.max(v.abs())),
    }
}

fn check_firewall(
    fs: &mut FirewallState,
    c: &MotionCommand,
    now: u64,
) -> (FirewallVerdictRecord, Vec<Deviation>) {
    let cmd = to_firewall_command(fs, c, now);
    let v = fs.fw.check(&cmd, now);
    let mut rec = FirewallVerdictRecord {
        kind: "robodr.firewall_verdict",
        channel: c.channel.clone(),
        source_guid: c.source_guid.clone(),
        verdict: "passed",
        reject_reason: None,
        limit_reasons: Vec::new(),
        would_have: None,
        substitute: None,
        output_speed: v.output().map(output_speed),
        enforcing: fs.fw.is_enforcing(),
        joint: None,
    };
    match &v {
        Verdict::Passed { would_have, .. } => {
            rec.would_have = would_have.map(|w| format!("{w:?}"));
        }
        Verdict::Limited { reasons, .. } => {
            rec.verdict = "limited";
            for (bit, name) in [
                (LimitReasons::SPEED, "speed"),
                (LimitReasons::ACCELERATION, "acceleration"),
                (LimitReasons::JERK, "jerk"),
            ] {
                if reasons.contains(bit) {
                    rec.limit_reasons.push(name);
                }
            }
        }
        Verdict::Rejected { reason, substitute } => {
            rec.verdict = "rejected";
            rec.reject_reason = Some(format!("{reason:?}"));
            rec.substitute = substitute.map(|s| match s.kind {
                SubstituteKind::Zero => "zero",
                SubstituteKind::HoldLast => "hold_last",
            });
        }
    }
    (rec, fs.fw.drain_deviations())
}

/// Check one low-level joint frame with the joint firewall (see
/// [`Agent::handle_with_joint`]). Returns the verdict record, the drained
/// deviations and whether the stamp was clamped to the firewall's clock.
fn check_joint_firewall(
    fs: &mut FirewallState,
    c: &MotionCommand,
    j: &JointInput,
) -> (FirewallVerdictRecord, Vec<Deviation>, bool) {
    let identities = &fs.identities;
    let Some(jf) = fs.joint.as_mut() else {
        // Unreachable: only called for a joint channel.
        return (
            FirewallVerdictRecord {
                kind: "robodr.firewall_joint_verdict",
                channel: c.channel.clone(),
                source_guid: c.source_guid.clone(),
                verdict: "not_checked",
                reject_reason: None,
                limit_reasons: Vec::new(),
                would_have: None,
                substitute: None,
                output_speed: None,
                enforcing: false,
                joint: None,
            },
            Vec::new(),
            false,
        );
    };
    // The joint firewall's clock is the frames' observation time, kept
    // non-decreasing: two capture threads may interleave their stamps.
    let (now, clamped) = match jf.last_now {
        Some(last) if j.stamp_ns < last => (last, true),
        _ => (j.stamp_ns, false),
    };
    jf.last_now = Some(now);
    let source = resolve_source(&jf.fw, identities, c.source_guid.as_deref());
    let channel = jf.fw.channel_id(&c.channel).unwrap_or(ChannelId(u16::MAX));
    let cmd = JointCommand::new(source, channel, now, j.frame);
    let v = jf.fw.check_joint(&cmd, now);
    let output_speed = v.output().map(|o| {
        o.frame
            .motors()
            .iter()
            .filter(|m| m.kd != 0.0)
            .fold(0.0_f64, |m, x| m.max(x.dq.abs()))
    });
    let mut rec = FirewallVerdictRecord {
        kind: "robodr.firewall_joint_verdict",
        channel: c.channel.clone(),
        source_guid: c.source_guid.clone(),
        verdict: "passed",
        reject_reason: None,
        limit_reasons: Vec::new(),
        would_have: None,
        substitute: None,
        output_speed,
        enforcing: jf.fw.is_enforcing(),
        joint: Some(crate::outcome::JointVerdictDetail {
            slots: j.frame.slots(),
            crc_ok: j.frame.crc_ok,
            mode_pr: j.frame.mode_pr,
            mode_machine: j.frame.mode_machine,
            stamp_ns: now,
        }),
    };
    match &v {
        JointVerdict::Passed { would_have, .. } => {
            rec.would_have = would_have.as_ref().map(|w| match w {
                JointWouldHave::Limited { reasons, .. } => {
                    format!("limited: {}", joint_limit_names(*reasons).join(", "))
                }
                JointWouldHave::Rejected { reason } => format!("rejected: {reason:?}"),
            });
        }
        JointVerdict::Limited { reasons, .. } => {
            rec.verdict = "limited";
            rec.limit_reasons = joint_limit_names(*reasons);
        }
        JointVerdict::Rejected { reason, substitute } => {
            rec.verdict = "rejected";
            rec.reject_reason = Some(format!("{reason:?}"));
            rec.substitute = substitute.map(|s| match s.kind {
                SubstituteKind::Zero => "zero",
                SubstituteKind::HoldLast => "hold_last",
            });
        }
    }
    (rec, jf.fw.drain_deviations(), clamped)
}

/// The names of a joint limit set (`position`, `velocity`, `torque`, `gain`,
/// `step`, `pd_torque`).
fn joint_limit_names(reasons: JointLimitReasons) -> Vec<&'static str> {
    [
        (JointLimitReasons::POSITION, "position"),
        (JointLimitReasons::VELOCITY, "velocity"),
        (JointLimitReasons::TORQUE, "torque"),
        (JointLimitReasons::GAIN, "gain"),
        (JointLimitReasons::STEP, "step"),
        (JointLimitReasons::PD_TORQUE, "pd_torque"),
    ]
    .into_iter()
    .filter(|(bit, _)| reasons.contains(*bit))
    .map(|(_, name)| name)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::Mode;
    use robodr_responder::{
        plan_stateless, Connectivity, ControlMode, MissionPhase, PlatformFamily, Rationale,
        ResponsePolicy,
    };

    fn ctx(locked: bool) -> OperationalContext {
        OperationalContext {
            platform: PlatformFamily::Ugv,
            morphology: robodr_responder::Morphology::WheeledMobile,
            phase: MissionPhase::Transit,
            connectivity: Connectivity::Connected,
            control: ControlMode::Autonomous,
            operator_present: true,
            profile_locked: locked,
        }
    }

    #[test]
    fn guard_passes_valid_plans_unchanged() {
        let mut pol = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        pol.oem_validated = true;
        pol.morphology = robodr_responder::Morphology::WheeledMobile;
        let dev = Deviation::new("robot.x", Severity::Critical, "d");
        let p = plan_stateless(&pol, &dev, "s", SafetyState::MovingFast, &ctx(true));
        let (q, v) = guard(p.clone(), &dev, SafetyState::MovingFast, &ctx(true));
        assert_eq!(v, None);
        assert_eq!(p, q);
    }

    #[test]
    fn guard_replaces_invariant_violations() {
        let dev = Deviation::new("robot.x", Severity::Critical, "d");
        // Hand-made broken plan: safe-state request while the e-stop is engaged.
        let bad = ResponsePlan {
            rule: "robot.x".into(),
            severity: Severity::Critical,
            source: "s".into(),
            safety_state: SafetyState::EStopActive,
            max_step: Step::LimitMotion,
            actions: vec![
                ResponseAction::Record,
                ResponseAction::LimitMotion { factor: 0.5 },
            ],
            requires_human_approval: false,
            observe_only: false,
            suppressed: false,
            would_have: None,
            rationale: Rationale::default(),
            morphology: Default::default(),
            advisory: Vec::new(),
        };
        let (q, v) = guard(bad, &dev, SafetyState::EStopActive, &ctx(true));
        assert!(v.unwrap().contains("ActionWhileSafetySystemEngaged"));
        assert_eq!(q.actions, vec![ResponseAction::Record]);
        assert!(q.requires_human_approval);
        assert!(check_invariants(&q, SafetyState::EStopActive, &ctx(true)).is_ok());
    }

    #[test]
    fn guard_catches_observe_only_deviation_with_actions() {
        // A plan made for a locked context but a deviation in observe mode
        // (what would happen if the agent forgot to downgrade the context).
        let mut pol = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        pol.oem_validated = true;
        pol.morphology = robodr_responder::Morphology::WheeledMobile;
        let dev = Deviation::new("robot.x", Severity::High, "d").with_mode(Mode::Observe);
        // The responder itself now refuses to act on an observe-mode
        // deviation, so build the acting plan from its enforce-mode twin.
        let acting = dev.clone().with_mode(Mode::Enforce);
        let p = plan_stateless(&pol, &acting, "s", SafetyState::MovingSlow, &ctx(true));
        assert!(p.max_step > Step::Record);
        let (q, v) = guard(p, &dev, SafetyState::MovingSlow, &ctx(true));
        assert!(v.unwrap().contains("observe-only"));
        assert_eq!(q.steps(), vec![Step::Record]);
        assert!(q.observe_only);
        assert_eq!(Disposition::of(&q), Disposition::ObserveOnly);
    }

    #[test]
    fn source_key_groups_by_participant_prefix() {
        let c = MotionCommand {
            channel: "/cmd_vel".into(),
            source_guid: Some("0F0F0F0F0F0F0F0F0F0F0F0F000001c1".into()),
            linear_speed: Some(1.0),
            joint_speed: None,
            angular_speed: None,
            ..Default::default()
        };
        assert_eq!(
            source_key(&RobotEvent::MotionCommand(c.clone())),
            "participant:0f0f0f0f0f0f0f0f0f0f0f0f"
        );
        let anon = MotionCommand {
            source_guid: None,
            ..c
        };
        assert_eq!(
            source_key(&RobotEvent::MotionCommand(anon)),
            "channel:/cmd_vel"
        );
        // Non-ASCII GUIDs must not panic on slicing.
        let weird = MotionCommand {
            channel: "/x".into(),
            source_guid: Some("ééééééééééééééé".into()),
            linear_speed: None,
            joint_speed: None,
            angular_speed: None,
            ..Default::default()
        };
        assert!(source_key(&RobotEvent::MotionCommand(weird)).starts_with("participant:"));
    }

    #[test]
    fn publisher_ids_are_dense_case_insensitive_and_bounded() {
        let mut ids = PublisherIds::default();
        let mut st = AgentStats::default();
        let a = ids.intern("AA00", &mut st);
        assert_eq!(a, 1);
        assert_eq!(ids.intern("aa00", &mut st), 1);
        assert_eq!(ids.intern("bb00", &mut st), 2);
        for i in 0..MAX_INTERNED_PUBLISHERS {
            ids.intern(&format!("g{i}"), &mut st);
        }
        assert_eq!(ids.ids.len(), MAX_INTERNED_PUBLISHERS);
        let h = ids.intern("overflow", &mut st);
        assert_ne!(h, robodr_motion::PUBLISHER_UNKNOWN);
        assert!(st.publishers_hashed >= 1);
        // Known ids keep resolving after the overflow.
        assert_eq!(ids.intern("AA00", &mut st), 1);
    }

    #[test]
    fn command_sample_keeps_sign_and_absent_axes() {
        let c = MotionCommand {
            channel: "/cmd_vel".into(),
            source_guid: None,
            linear_speed: Some(-0.3),
            joint_speed: None,
            angular_speed: Some(0.2),
            ..Default::default()
        };
        let s = command_sample(&c, 7);
        assert_eq!(s.linear, Some(-0.3));
        assert_eq!(s.angular, Some(0.2));
        assert_eq!(s.joint_speed_max, None);
        assert!(s.direction_known);
        let no_yaw = MotionCommand {
            angular_speed: None,
            ..c
        };
        assert_eq!(command_sample(&no_yaw, 7).angular, None);
    }

    #[test]
    fn safety_mapping_never_claims_absence_of_humans() {
        for s in SafetyState::ALL {
            assert_ne!(ocsf_safety(s).human_proximity, HumanProximity::NotDetected);
        }
        assert_eq!(
            ocsf_safety(SafetyState::MovingFast).motion,
            MotionState::Moving
        );
    }
}
