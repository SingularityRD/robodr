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
//!     FindingBuilder(... evidence = those refs) ─► validated robot-edr.findings record
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
//!
//! # Time
//!
//! [`Agent::handle`] takes the event's observation time; [`Agent::tick`]
//! reads it from the injected clock. `mono_ns` is clamped so it never goes
//! backwards (regressions are counted in [`AgentStats`]).
//!
//! # Mapping `MotionCommand` to the firewall
//!
//! `MotionCommand` carries magnitudes only and no source stamp:
//! * Twist channel: `linear = (linear_speed, 0, 0)`, angular zero. A command
//!   with only `joint_speed` becomes a 1-joint command (kind mismatch → reject).
//! * Joint channel with `count` joints: every joint gets `joint_speed` (the
//!   max |joint speed|; the firewall's per-joint limit sees the same maximum).
//!   A command with only `linear_speed` becomes a twist (kind mismatch).
//! * Source: `source_guid` resolved by the firewall policy (exact GUID, else
//!   its 24-char participant prefix, so a spec listing a participant
//!   authorises all of that participant's writers), else `SourceId::UNKNOWN`.
//!   Unknown channel: an id no policy channel has.
//! * Stamp = observation time (`mono_ns`), so the firewall's stale / future
//!   checks cannot fire here; out-of-order still fires for two commands from
//!   one source at the same `mono_ns`.
//!
//! In the finding, commanded speeds are reported as magnitudes and a
//! non-finite value is omitted (the findings contract accepts only finite,
//! non-negative numbers). The raw value is kept in the deviation's tainted
//! detail and in the black-box event record, so a NaN command still yields a
//! valid Critical finding.

use std::collections::BTreeMap;

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::{AppendOutcome, Checkpoint, Clock, Recorder, Signer, Timestamp};
use robodr_events::profile::Profile;
use robodr_events::{Deviation, MotionCommand, RobotEvent, Severity};
use robodr_firewall::{
    ChannelId, ChannelKind, Command, Firewall, JointVelocities, LimitReasons, Motion, Policy,
    SourceId, SubstituteKind, Twist, Vec3, Verdict,
};
use robodr_motion::{CommandSample, ConsistencyMonitor, FeedbackSample};
use robodr_ocsf::{
    BlackBoxRef, FindingBuilder, HumanProximity, Mode as OcsfMode, MotionState, ProfileRef,
    RobotContext,
};
use robodr_responder::{
    check_invariants, OperationalContext, Responder, ResponseAction, ResponsePlan, SafetyState,
    Step,
};
use serde::Serialize;

use crate::clock::FollowClock;
use crate::config::{
    profile_sha256, AgentConfig, AgentError, MonitorSettings, MAX_TRACKED_FINDINGS,
};
use crate::executor::{ExecutionRequest, Executor, NoopExecutor};
use crate::outcome::{
    Detector, Disposition, EvidenceLinks, FindingOutput, FirewallVerdictRecord, Outcome,
};

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
    pub firewall_checks: u64,
}

/// Note payload for a plan in the black box.
#[derive(Serialize)]
struct PlanNote<'a> {
    kind: &'static str,
    deviation: Option<&'a BlackBoxRef>,
    disposition: Disposition,
    guard_violation: Option<&'a str>,
    plan: &'a ResponsePlan,
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
}

struct MonitorState {
    monitor: ConsistencyMonitor,
    settings: MonitorSettings,
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
    recorder: Recorder,
    follow: FollowClock,
    clock: Box<dyn Clock>,
    firewall: Option<FirewallState>,
    monitor: Option<MonitorState>,
    executor: Box<dyn Executor>,
    seen: BTreeMap<String, (u64, u64)>,
    last_mono: Option<u64>,
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
    pub fn new(
        cfg: AgentConfig,
        signer: Box<dyn Signer>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, AgentError> {
        cfg.profile.validate().map_err(AgentError::Profile)?;
        if !robodr_ocsf::validate::is_valid_robot_id(&cfg.robot.id) {
            return Err(AgentError::Config(format!(
                "robot id {:?} must match [A-Za-z0-9._-]{{1,64}}",
                cfg.robot.id
            )));
        }
        if cfg.context.platform != cfg.policy.platform {
            return Err(AgentError::Config(format!(
                "context platform {:?} does not match policy platform {:?}",
                cfg.context.platform, cfg.policy.platform
            )));
        }
        let responder = Responder::new(cfg.policy).map_err(AgentError::Policy)?;
        let firewall = match cfg.firewall {
            None => None,
            Some(fs) => {
                let policy = Policy::compile(&cfg.profile, fs.platform, &fs.channels)
                    .map_err(AgentError::Firewall)?;
                let kinds = fs
                    .channels
                    .iter()
                    .map(|(k, s)| (k.clone(), s.kind))
                    .collect();
                Some(FirewallState {
                    fw: Firewall::new(policy),
                    kinds,
                })
            }
        };
        let monitor = match cfg.monitor {
            None => None,
            Some(settings) => Some(MonitorState {
                monitor: ConsistencyMonitor::new(settings.config.clone())
                    .map_err(AgentError::Monitor)?,
                settings,
            }),
        };
        let mode = if cfg.profile.locked {
            OcsfMode::Enforce
        } else {
            OcsfMode::Observe
        };
        let ocsf = RobotContext::new(
            cfg.robot,
            ProfileRef {
                version: cfg.profile_version,
                sha256: profile_sha256(&cfg.profile),
            },
            mode,
        );
        let start = clock.now();
        let follow = FollowClock::new(start);
        let recorder = Recorder::open(cfg.blackbox, signer, Box::new(follow.clone()))
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
            recorder,
            follow,
            clock,
            firewall,
            monitor,
            executor: Box::new(NoopExecutor),
            seen: BTreeMap::new(),
            last_mono: Some(start.mono_ns),
            stats: AgentStats::default(),
        })
    }

    /// Replace the executor (default: [`NoopExecutor`]).
    #[must_use]
    pub fn with_executor(mut self, executor: Box<dyn Executor>) -> Self {
        self.executor = executor;
        self
    }

    pub fn stats(&self) -> AgentStats {
        self.stats
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The black-box directory.
    pub fn blackbox_dir(&self) -> &std::path::Path {
        self.recorder.dir()
    }

    /// Current head `(seq, hash)` of the black box.
    pub fn blackbox_head(&self) -> Option<(u64, robodr_blackbox::Hash)> {
        self.recorder.head()
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
        let now = self.observe_time(now);
        self.follow.set(now);
        self.stats.events = self.stats.events.saturating_add(1);
        let mono = now.mono_ns;
        let mode = self.profile.mode();

        // 1. Detection.
        let mut found: Vec<(Detector, Deviation)> = Vec::new();
        if let Some(d) = self.profile.evaluate(event) {
            found.push((Detector::Profile, d));
        }
        let mut verdict: Option<FirewallVerdictRecord> = None;
        if let RobotEvent::MotionCommand(c) = event {
            if let Some(fs) = self.firewall.as_mut() {
                let (rec, devs) = check_firewall(fs, c, mono);
                self.stats.firewall_checks = self.stats.firewall_checks.saturating_add(1);
                verdict = Some(rec);
                found.extend(devs.into_iter().map(|d| (Detector::Firewall, d)));
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
                    .on_command(&CommandSample::from_motion_command(c, mono), |f| {
                        hits.push(f)
                    }),
                RobotEvent::MotionFeedback(f) => {
                    let sample = FeedbackSample {
                        t_ns: f.timestamp_ns,
                        source: ms.settings.source_for(&f.channel),
                        linear: f.measured_linear_speed,
                        angular: None,
                        joint_speed_max: f.measured_joint_speed,
                    };
                    ms.monitor.on_feedback(mono, &sample, |x| hits.push(x));
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
            self.stats.deviations = self.stats.deviations.saturating_add(1);
            let source = source_key(event);
            let ctx = OperationalContext {
                profile_locked: self.profile.locked && !dev.is_observe_only(),
                ..self.context
            };
            let plan = self
                .responder
                .plan(&dev, &source, safety, &ctx, mono / 1_000_000);
            let (plan, guard_violation) = guard(plan, &dev, safety, &ctx);
            if guard_violation.is_some() {
                self.stats.guard_violations = self.stats.guard_violations.saturating_add(1);
            }
            let disposition = Disposition::of(&plan);

            let mut evidence = EvidenceLinks {
                event: event_ref.clone(),
                firewall_verdict: if detector == Detector::Firewall {
                    verdict_ref.clone()
                } else {
                    None
                },
                errors: shared_errors.clone(),
                ..EvidenceLinks::default()
            };
            evidence.deviation = self.append("deviation", &mut evidence.errors, |r| {
                r.append_deviation(&dev)
            });
            let note = PlanNote {
                kind: "robodr.response_plan",
                deviation: evidence.deviation.as_ref(),
                disposition,
                guard_violation: guard_violation.as_deref(),
                plan: &plan,
            };
            let critical = plan.max_step > Step::Record || dev.severity >= Severity::High;
            let mut errs = Vec::new();
            evidence.plan = self.append("plan", &mut errs, |r| r.append_note(&note, critical));
            evidence.errors.extend(errs);

            let refs = evidence.refs();
            let (finding, finding_errors) = self.build_finding(&dev, event, safety, now, &refs);
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
            });

            outcomes.push(Outcome {
                detector,
                source,
                deviation: dev,
                plan,
                disposition,
                guard_violation,
                evidence,
                firewall: if detector == Detector::Firewall {
                    verdict.clone()
                } else {
                    None
                },
                finding,
                finding_errors,
            });
        }
        outcomes
    }

    /// Seal and close the black box. Returns the final checkpoint.
    pub fn finish(self) -> Result<Finished, AgentError> {
        let stats = self.stats;
        let checkpoint = self.recorder.close().map_err(AgentError::BlackBox)?;
        Ok(Finished { checkpoint, stats })
    }

    fn observe_time(&mut self, now: Timestamp) -> Timestamp {
        let mono = match self.last_mono {
            Some(prev) if now.mono_ns < prev => {
                self.stats.clock_regressions = self.stats.clock_regressions.saturating_add(1);
                prev
            }
            _ => now.mono_ns,
        };
        self.last_mono = Some(mono);
        Timestamp {
            mono_ns: mono,
            ..now
        }
    }

    fn append(
        &mut self,
        what: &str,
        errors: &mut Vec<String>,
        f: impl FnOnce(&mut Recorder) -> Result<AppendOutcome, robodr_blackbox::Error>,
    ) -> Option<BlackBoxRef> {
        let r = f(&mut self.recorder);
        match r {
            Ok(AppendOutcome::Recorded { seq, hash }) => {
                self.stats.records_appended = self.stats.records_appended.saturating_add(1);
                // The record went into the newest segment (rotation happens
                // before a write, never after it).
                let segment = self.recorder.segments().last().copied().unwrap_or(0);
                Some(BlackBoxRef {
                    segment,
                    seq,
                    sha256: to_hex(&hash),
                })
            }
            Ok(AppendOutcome::Refused(why)) => {
                self.stats.evidence_errors = self.stats.evidence_errors.saturating_add(1);
                errors.push(format!("{what}: refused by black box ({why:?})"));
                None
            }
            Err(e) => {
                self.stats.evidence_errors = self.stats.evidence_errors.saturating_add(1);
                errors.push(format!("{what}: {e}"));
                None
            }
        }
    }

    fn build_finding(
        &mut self,
        dev: &Deviation,
        event: &RobotEvent,
        safety: SafetyState,
        now: Timestamp,
        refs: &[BlackBoxRef],
    ) -> (Option<FindingOutput>, Vec<String>) {
        let wall_ms = now.wall_ns / 1_000_000;
        let mut b = FindingBuilder::from_deviation(dev, &self.ocsf)
            .event(event)
            .safety_state(ocsf_safety(safety))
            .attestation(self.attestation);
        if let RobotEvent::MotionCommand(c) = event {
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
            Ok(rec) => (
                Some(FindingOutput {
                    topic: rec.topic.to_string(),
                    key: rec.key,
                    partition: rec.partition,
                    value: rec.value,
                    headers: rec
                        .headers
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                }),
                Vec::new(),
            ),
            Err(errs) => (None, errs.iter().map(ToString::to_string).collect()),
        }
    }
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

fn to_firewall_command(fs: &FirewallState, c: &MotionCommand, now: u64) -> Command {
    // Exact endpoint GUID first; then its 24-hex-char participant prefix, so
    // a spec that lists a participant authorises that participant's writers.
    let source = c
        .source_guid
        .as_deref()
        .and_then(|g| {
            fs.fw
                .source_id(g)
                .or_else(|| g.get(..24).and_then(|p| fs.fw.source_id(p)))
        })
        .unwrap_or(SourceId::UNKNOWN);
    let channel = fs.fw.channel_id(&c.channel).unwrap_or(ChannelId(u16::MAX));
    let twist = |v: f64| Motion::Twist(Twist::new(Vec3::new(v, 0.0, 0.0), Vec3::ZERO));
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
        };
        assert!(source_key(&RobotEvent::MotionCommand(weird)).starts_with("participant:"));
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
