//! Operations on profiles: [`lock`], [`diff`], [`merge_profiles`] and the
//! re-run [`Checker`].
//!
//! None of these act on the robot. `lock` only flips a flag after
//! validation; `check` only evaluates and reports.

use crate::input::{EventSource, InputError};
use robodr_events::profile::{Envelope, Profile};
use robodr_events::{Deviation, MotionCommand, RobotEvent, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// ---------------------------------------------------------------- lock ----

/// Why a profile cannot be locked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum LockRefusal {
    AlreadyLocked,
    EmptyModel,
    NoParticipants,
    NoWriterTopics,
    /// A motion channel whose envelope constrains nothing.
    MissingEnvelope {
        channel: String,
    },
    /// A bound that is NaN, infinite or negative (only possible in a
    /// hand-edited or non-JSON-sourced profile).
    InvalidBound {
        channel: String,
        dimension: String,
    },
}

impl fmt::Display for LockRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockRefusal::AlreadyLocked => write!(f, "profile is already locked"),
            LockRefusal::EmptyModel => write!(f, "model name is empty"),
            LockRefusal::NoParticipants => write!(f, "profile has no participants (empty profile)"),
            LockRefusal::NoWriterTopics => {
                write!(f, "profile has no writer topics (empty profile)")
            }
            LockRefusal::MissingEnvelope { channel } => write!(
                f,
                "motion channel {channel} has no envelope (no linear or joint bound)"
            ),
            LockRefusal::InvalidBound { channel, dimension } => write!(
                f,
                "motion channel {channel}: {dimension} bound is not a finite, non-negative number"
            ),
        }
    }
}

/// Validate a draft profile and return it with `locked = true`. All reasons
/// to refuse are collected, so the OEM sees everything at once.
pub fn lock(profile: &Profile) -> Result<Profile, Vec<LockRefusal>> {
    let mut why = Vec::new();
    if profile.locked {
        why.push(LockRefusal::AlreadyLocked);
    }
    if profile.model.trim().is_empty() {
        why.push(LockRefusal::EmptyModel);
    }
    if profile.participants.is_empty() {
        why.push(LockRefusal::NoParticipants);
    }
    if profile.writer_topics.is_empty() {
        why.push(LockRefusal::NoWriterTopics);
    }
    for (ch, env) in &profile.motion_envelopes {
        if env.max_linear_speed.is_none() && env.max_joint_speed.is_none() {
            why.push(LockRefusal::MissingEnvelope {
                channel: ch.clone(),
            });
        }
        for (dim, b) in [
            ("linear", env.max_linear_speed),
            ("joint", env.max_joint_speed),
        ] {
            if let Some(b) = b {
                if !b.is_finite() || b < 0.0 {
                    why.push(LockRefusal::InvalidBound {
                        channel: ch.clone(),
                        dimension: dim.into(),
                    });
                }
            }
        }
    }
    if why.is_empty() {
        let mut p = profile.clone();
        p.locked = true;
        Ok(p)
    } else {
        Err(why)
    }
}

// ---------------------------------------------------------------- merge ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    NoProfiles,
    ModelMismatch(String, String),
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeError::NoProfiles => write!(f, "nothing to merge"),
            MergeError::ModelMismatch(a, b) => write!(
                f,
                "refusing to merge profiles of different models ({a:?} vs {b:?})"
            ),
        }
    }
}

impl std::error::Error for MergeError {}

/// Union already-learned profiles (e.g. one per mission). Participants and
/// writer topics are unioned; per channel and dimension the larger bound
/// wins. `None` is read as "not observed" (the learner's meaning), so a bound
/// from one profile is kept when the other has none. The result is always
/// unlocked: a merged profile must be reviewed and locked again.
///
/// Prefer [`crate::Learner::merge`] when the raw runs are available: it
/// computes percentiles and warnings over all samples, and applies the margin
/// once. Merging profiles applies whatever margins each profile already had.
pub fn merge_profiles(profiles: &[Profile]) -> Result<Profile, MergeError> {
    let first = profiles.first().ok_or(MergeError::NoProfiles)?;
    let mut out = Profile {
        model: first.model.clone(),
        locked: false,
        ..Default::default()
    };
    for p in profiles {
        if p.model != out.model {
            return Err(MergeError::ModelMismatch(
                out.model.clone(),
                p.model.clone(),
            ));
        }
        out.participants.extend(p.participants.iter().cloned());
        out.writer_topics.extend(p.writer_topics.iter().cloned());
        for (ch, env) in &p.motion_envelopes {
            let e = out.motion_envelopes.entry(ch.clone()).or_default();
            e.max_linear_speed = max_opt(e.max_linear_speed, env.max_linear_speed);
            e.max_joint_speed = max_opt(e.max_joint_speed, env.max_joint_speed);
        }
    }
    Ok(out)
}

fn max_opt(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

// ---------------------------------------------------------------- diff ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// The new profile allows more (bound raised or removed).
    Loosened,
    /// The new profile allows less (bound lowered or added).
    Tightened,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvelopeChange {
    pub channel: String,
    pub dimension: String,
    pub old: Option<f64>,
    pub new: Option<f64>,
    pub direction: Direction,
}

/// What changed between two profiles, for OEM review before re-locking.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProfileDiff {
    pub model: Option<(String, String)>,
    pub locked: Option<(bool, bool)>,
    pub participants_added: BTreeSet<String>,
    pub participants_removed: BTreeSet<String>,
    pub writer_topics_added: BTreeSet<String>,
    pub writer_topics_removed: BTreeSet<String>,
    pub motion_channels_added: BTreeMap<String, Envelope>,
    pub motion_channels_removed: BTreeMap<String, Envelope>,
    pub envelope_changes: Vec<EnvelopeChange>,
}

impl ProfileDiff {
    pub fn is_empty(&self) -> bool {
        *self == ProfileDiff::default()
    }

    /// Does the new profile permit anything the old one did not? These are
    /// the changes that deserve the hardest look.
    pub fn loosens(&self) -> bool {
        !self.participants_added.is_empty()
            || !self.writer_topics_added.is_empty()
            || !self.motion_channels_added.is_empty()
            || self
                .envelope_changes
                .iter()
                .any(|c| c.direction == Direction::Loosened)
    }
}

/// Compare `old` to `new`.
pub fn diff(old: &Profile, new: &Profile) -> ProfileDiff {
    let mut d = ProfileDiff::default();
    if old.model != new.model {
        d.model = Some((old.model.clone(), new.model.clone()));
    }
    if old.locked != new.locked {
        d.locked = Some((old.locked, new.locked));
    }
    d.participants_added = new
        .participants
        .difference(&old.participants)
        .cloned()
        .collect();
    d.participants_removed = old
        .participants
        .difference(&new.participants)
        .cloned()
        .collect();
    d.writer_topics_added = new
        .writer_topics
        .difference(&old.writer_topics)
        .cloned()
        .collect();
    d.writer_topics_removed = old
        .writer_topics
        .difference(&new.writer_topics)
        .cloned()
        .collect();
    for (ch, env) in &new.motion_envelopes {
        match old.motion_envelopes.get(ch) {
            None => {
                d.motion_channels_added.insert(ch.clone(), env.clone());
            }
            Some(o) => {
                for (dim, a, b) in [
                    ("linear", o.max_linear_speed, env.max_linear_speed),
                    ("joint", o.max_joint_speed, env.max_joint_speed),
                ] {
                    let direction = match (a, b) {
                        (Some(x), Some(y)) if y > x => Direction::Loosened,
                        (Some(x), Some(y)) if y < x => Direction::Tightened,
                        (Some(_), None) => Direction::Loosened,
                        (None, Some(_)) => Direction::Tightened,
                        _ => continue,
                    };
                    d.envelope_changes.push(EnvelopeChange {
                        channel: ch.clone(),
                        dimension: dim.into(),
                        old: a,
                        new: b,
                        direction,
                    });
                }
            }
        }
    }
    for (ch, env) in &old.motion_envelopes {
        if !new.motion_envelopes.contains_key(ch) {
            d.motion_channels_removed.insert(ch.clone(), env.clone());
        }
    }
    d
}

fn bound(v: Option<f64>) -> String {
    v.map_or_else(|| "unbounded".into(), |v| v.to_string())
}

fn env_str(e: &Envelope) -> String {
    format!(
        "linear {} m/s, joint {} rad/s",
        bound(e.max_linear_speed),
        bound(e.max_joint_speed)
    )
}

impl fmt::Display for ProfileDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return writeln!(f, "profiles are identical");
        }
        if let Some((a, b)) = &self.model {
            writeln!(f, "~ model: {a} -> {b}")?;
        }
        if let Some((a, b)) = &self.locked {
            writeln!(f, "~ locked: {a} -> {b}")?;
        }
        for g in &self.participants_added {
            writeln!(f, "+ participant {g}   [LOOSENS]")?;
        }
        for g in &self.participants_removed {
            writeln!(f, "- participant {g}")?;
        }
        for t in &self.writer_topics_added {
            writeln!(f, "+ writer topic {t}   [LOOSENS]")?;
        }
        for t in &self.writer_topics_removed {
            writeln!(f, "- writer topic {t}")?;
        }
        for (c, e) in &self.motion_channels_added {
            writeln!(f, "+ motion channel {c} ({})   [LOOSENS]", env_str(e))?;
        }
        for (c, e) in &self.motion_channels_removed {
            writeln!(f, "- motion channel {c} (was {})", env_str(e))?;
        }
        for c in &self.envelope_changes {
            writeln!(
                f,
                "~ envelope {} {}: {} -> {}   [{}]",
                c.channel,
                c.dimension,
                bound(c.old),
                bound(c.new),
                match c.direction {
                    Direction::Loosened => "LOOSENS",
                    Direction::Tightened => "tightens",
                }
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- check ---

/// Rule id for speeds the profile evaluation cannot judge (NaN / inf /
/// negative). `Profile::evaluate` compares with `>`, which is false for NaN,
/// so the checker adds this commissioning-side rule to keep a corrupted
/// stream from passing as "zero deviations".
pub const RULE_ANOMALOUS_SPEED: &str = "commission.motion.anomalous_speed";

/// Maximum findings stored verbatim; all are counted.
pub const MAX_STORED_FINDINGS: usize = 10_000;

/// One deviation and where it came from.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CheckFinding {
    pub source: String,
    pub position: u64,
    pub deviation: Deviation,
}

/// Result of re-running a profile over events.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CheckReport {
    pub model: String,
    pub profile_locked: bool,
    pub events: u64,
    pub deviations_total: u64,
    pub by_rule: BTreeMap<String, u64>,
    pub findings: Vec<CheckFinding>,
}

/// Deviations for one event: the profile's own verdict plus the
/// anomalous-speed rule.
pub fn check_event(profile: &Profile, event: &RobotEvent) -> Vec<Deviation> {
    let mut out: Vec<Deviation> = profile.evaluate(event).into_iter().collect();
    if let RobotEvent::MotionCommand(c) = event {
        if let Some(d) = anomalous_speed(c) {
            out.push(d);
        }
    }
    out
}

fn anomalous_speed(c: &MotionCommand) -> Option<Deviation> {
    for (dim, v) in [("linear", c.linear_speed), ("joint", c.joint_speed)] {
        if let Some(v) = v {
            if !v.is_finite() || v < 0.0 {
                return Some(Deviation::new(
                    RULE_ANOMALOUS_SPEED,
                    Severity::High,
                    format!(
                        "{dim} speed {v} on {} cannot be checked against the envelope",
                        c.channel
                    ),
                ));
            }
        }
    }
    None
}

/// Streams events through a profile and collects deviations.
pub struct Checker<'p> {
    profile: &'p Profile,
    report: CheckReport,
}

impl<'p> Checker<'p> {
    pub fn new(profile: &'p Profile) -> Self {
        Self {
            profile,
            report: CheckReport {
                model: profile.model.clone(),
                profile_locked: profile.locked,
                ..Default::default()
            },
        }
    }

    pub fn observe(&mut self, source: &str, position: u64, event: &RobotEvent) {
        self.report.events += 1;
        for deviation in check_event(self.profile, event) {
            self.report.deviations_total += 1;
            *self
                .report
                .by_rule
                .entry(deviation.rule.to_string())
                .or_insert(0) += 1;
            if self.report.findings.len() < MAX_STORED_FINDINGS {
                self.report.findings.push(CheckFinding {
                    source: source.to_string(),
                    position,
                    deviation,
                });
            }
        }
    }

    /// Check a whole source (strict on input errors).
    pub fn ingest(&mut self, src: &mut dyn EventSource) -> Result<(), InputError> {
        let label = src.label().to_string();
        while let Some(r) = src.next_event() {
            let se = r?;
            self.observe(&label, se.position, &se.event);
        }
        Ok(())
    }

    pub fn finish(self) -> CheckReport {
        self.report
    }
}

impl fmt::Display for CheckReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.profile_locked {
            writeln!(
                f,
                "note: profile {} is NOT locked (observe mode); checking anyway",
                self.model
            )?;
        }
        for x in &self.findings {
            writeln!(
                f,
                "{}:{}: [{:?}] {}: {}",
                x.source, x.position, x.deviation.severity, x.deviation.rule, x.deviation.detail
            )?;
        }
        if (self.findings.len() as u64) < self.deviations_total {
            writeln!(
                f,
                "... {} more deviations not shown",
                self.deviations_total - self.findings.len() as u64
            )?;
        }
        for (r, n) in &self.by_rule {
            writeln!(f, "  {r}: {n}")?;
        }
        writeln!(
            f,
            "{} deviation(s) over {} event(s) against profile {}",
            self.deviations_total, self.events, self.model
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::graph::Participant;

    fn base() -> Profile {
        let mut p = Profile {
            model: "ugv".into(),
            ..Default::default()
        };
        p.participants.insert("a".repeat(24));
        p.writer_topics.insert("/cmd_vel".into());
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(0.5),
                max_joint_speed: None,
            },
        );
        p
    }

    #[test]
    fn lock_sets_flag_and_preserves_content() {
        let l = lock(&base()).unwrap();
        assert!(l.locked);
        let mut back = l.clone();
        back.locked = false;
        assert_eq!(back, base());
    }

    #[test]
    fn lock_refuses_and_lists_every_reason() {
        let mut p = base();
        p.locked = true;
        assert_eq!(lock(&p).unwrap_err(), vec![LockRefusal::AlreadyLocked]);

        let empty = Profile::default();
        let why = lock(&empty).unwrap_err();
        assert!(why.contains(&LockRefusal::EmptyModel));
        assert!(why.contains(&LockRefusal::NoParticipants));
        assert!(why.contains(&LockRefusal::NoWriterTopics));

        let mut p = base();
        p.motion_envelopes
            .insert("/arm".into(), Envelope::default());
        p.motion_envelopes.insert(
            "/bad".into(),
            Envelope {
                max_linear_speed: Some(f64::NAN),
                max_joint_speed: Some(-1.0),
            },
        );
        let why = lock(&p).unwrap_err();
        assert_eq!(
            why,
            vec![
                LockRefusal::MissingEnvelope {
                    channel: "/arm".into()
                },
                LockRefusal::InvalidBound {
                    channel: "/bad".into(),
                    dimension: "linear".into()
                },
                LockRefusal::InvalidBound {
                    channel: "/bad".into(),
                    dimension: "joint".into()
                },
            ]
        );
        assert!(why[0].to_string().contains("/arm"));
    }

    #[test]
    fn lock_allows_profile_without_motion_channels() {
        let mut p = base();
        p.motion_envelopes.clear();
        assert!(lock(&p).is_ok());
    }

    #[test]
    fn diff_identical_is_empty() {
        let d = diff(&base(), &base());
        assert!(d.is_empty());
        assert!(!d.loosens());
        assert_eq!(d.to_string(), "profiles are identical\n");
    }

    #[test]
    fn diff_reports_every_kind_of_change() {
        let old = base();
        let mut new = lock(&base()).unwrap();
        new.model = "ugv2".into();
        new.participants.insert("b".repeat(24));
        new.participants.remove(&"a".repeat(24));
        new.writer_topics.insert("/odom".into());
        new.writer_topics.remove("/cmd_vel");
        new.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_linear_speed = Some(0.4);
        new.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_joint_speed = Some(1.0);
        new.motion_envelopes
            .insert("/arm".into(), Envelope::default());
        let d = diff(&old, &new);
        assert_eq!(d.model, Some(("ugv".into(), "ugv2".into())));
        assert_eq!(d.locked, Some((false, true)));
        assert!(d.participants_added.contains(&"b".repeat(24)));
        assert!(d.participants_removed.contains(&"a".repeat(24)));
        assert!(d.writer_topics_added.contains("/odom"));
        assert!(d.writer_topics_removed.contains("/cmd_vel"));
        assert!(d.motion_channels_added.contains_key("/arm"));
        assert_eq!(d.envelope_changes.len(), 2);
        assert_eq!(d.envelope_changes[0].direction, Direction::Tightened);
        assert_eq!(d.envelope_changes[1].direction, Direction::Tightened);
        assert!(d.loosens()); // participants/topics/channels added
        let s = d.to_string();
        assert!(s.contains("+ participant bbbb"));
        assert!(
            s.contains("~ envelope /cmd_vel linear: 0.5 -> 0.4   [tightens]"),
            "{s}"
        );

        // Reverse direction: raising / removing bounds loosens.
        let r = diff(&new, &old);
        assert!(r.motion_channels_removed.contains_key("/arm"));
        assert!(r
            .envelope_changes
            .iter()
            .all(|c| c.direction == Direction::Loosened));
        serde_json::to_string(&r).unwrap();
    }

    #[test]
    fn merge_profiles_unions_and_takes_max() {
        let a = base();
        let mut b = base();
        b.participants.insert("b".repeat(24));
        b.writer_topics.insert("/odom".into());
        b.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(0.3),
                max_joint_speed: Some(2.0),
            },
        );
        let mut c = lock(&base()).unwrap();
        c.motion_envelopes.insert(
            "/arm".into(),
            Envelope {
                max_linear_speed: None,
                max_joint_speed: Some(1.0),
            },
        );
        let m = merge_profiles(&[a.clone(), b.clone(), c.clone()]).unwrap();
        assert!(!m.locked);
        assert_eq!(m.participants.len(), 2);
        assert_eq!(m.writer_topics.len(), 2);
        assert_eq!(
            m.motion_envelopes["/cmd_vel"],
            Envelope {
                max_linear_speed: Some(0.5),
                max_joint_speed: Some(2.0)
            }
        );
        assert_eq!(m.motion_envelopes["/arm"].max_joint_speed, Some(1.0));
        // Order independent.
        assert_eq!(merge_profiles(&[c, b, a]).unwrap(), m);
    }

    #[test]
    fn merge_profiles_errors() {
        assert_eq!(merge_profiles(&[]).unwrap_err(), MergeError::NoProfiles);
        let mut other = base();
        other.model = "arm".into();
        assert!(matches!(
            merge_profiles(&[base(), other]).unwrap_err(),
            MergeError::ModelMismatch(..)
        ));
    }

    #[test]
    fn checker_counts_deviations() {
        let p = lock(&base()).unwrap();
        let mut c = Checker::new(&p);
        c.observe(
            "x",
            1,
            &RobotEvent::Ros2ParticipantDiscovered(Participant {
                guid_prefix: "a".repeat(24),
                src_ip: "10.0.0.1".into(),
                locators: vec![],
            }),
        );
        c.observe(
            "x",
            2,
            &RobotEvent::Ros2ParticipantDiscovered(Participant {
                guid_prefix: "f".repeat(24),
                src_ip: "10.0.0.66".into(),
                locators: vec![],
            }),
        );
        let mv = |v: f64| {
            RobotEvent::MotionCommand(MotionCommand {
                channel: "/cmd_vel".into(),
                source_guid: None,
                linear_speed: Some(v),
                joint_speed: None,
            })
        };
        c.observe("x", 3, &mv(0.4));
        c.observe("x", 4, &mv(f64::NAN));
        c.observe("x", 5, &mv(-1.0));
        c.observe("x", 6, &mv(0.6));
        let r = c.finish();
        assert_eq!(r.events, 6);
        assert_eq!(r.deviations_total, 4);
        assert_eq!(r.by_rule["robot.ros2.unknown_participant"], 1);
        assert_eq!(r.by_rule[RULE_ANOMALOUS_SPEED], 2);
        assert_eq!(r.by_rule["robot.motion.linear_over_envelope"], 1);
        assert_eq!(r.findings[0].position, 2);
        let s = r.to_string();
        assert!(
            s.contains("x:2: [High] robot.ros2.unknown_participant"),
            "{s}"
        );
        assert!(s.contains("4 deviation(s) over 6 event(s)"));
        serde_json::to_string(&r).unwrap();
    }

    #[test]
    fn unlocked_profile_check_says_so() {
        let p = base();
        let r = Checker::new(&p).finish();
        assert!(r.to_string().contains("NOT locked"));
        assert!(r.to_string().contains("0 deviation(s)"));
    }
}
