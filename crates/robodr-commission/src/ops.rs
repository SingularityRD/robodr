//! Operations on profiles: [`lock`], [`diff`], [`merge_profiles`] and the
//! re-run [`Checker`].
//!
//! None of these act on the robot. `lock` only flips a flag after
//! validation and operator sign-off; `check` only evaluates and reports.
//!
//! # Lock semantics
//!
//! A draft becomes a locked profile only through [`lock`] (in memory) or
//! [`lock_draft_text`] (from the draft file's bytes, what the CLI uses).
//! Both refuse, listing every reason at once, unless:
//! * the draft is not already locked, names a model, has participants and
//!   writer topics, gives every motion channel at least one bound, and
//!   passes `Profile::validate` (the sensor's own load-time check);
//! * a [`Signoff`] is supplied for *this* draft: same model, same SHA-256
//!   of the draft bytes, a non-empty operator and every item confirmed;
//! * the sign-off's item set is the one generated for the draft
//!   (`items_sha256`, so items cannot be deleted) and covers the floor
//!   recomputed from the draft itself ([`required_items`]: every motion
//!   channel reviewed);
//! * no envelope bound exceeds the [`HardCaps`] (default
//!   [`DEFAULT_HARD_CAP_LINEAR`] / [`DEFAULT_HARD_CAP_JOINT`], the same caps
//!   `learn` applies): a hand-edited `1e300` m/s cannot be locked. [`merge_profiles`]
//!   enforces the same caps.
//!
//! The CLI then writes the result sealed (see `profile_file`), so the
//! locked file cannot be edited or half-written without `check`, `diff`
//! and `merge` refusing it.

use crate::input::{EventSource, InputError};
use crate::learner::{DEFAULT_HARD_CAP_JOINT, DEFAULT_HARD_CAP_LINEAR};
use crate::profile_file::parse_profile_text;
use crate::signoff::{covers, draft_digest, required_items, sha256_hex, Signoff};
use robodr_events::profile::{Envelope, EnvelopeField, Profile, ProfileError};
use robodr_events::{Deviation, MotionCommand, RobotEvent, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// ---------------------------------------------------------------- caps ----

/// Absolute upper bounds on any envelope a profile may be locked or merged
/// with. Defaults match `learn`'s hard caps; a platform commissioned with
/// higher `--hard-cap-*` values passes the same values to `lock` / `merge`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HardCaps {
    /// m/s.
    pub linear: f64,
    /// rad/s.
    pub joint: f64,
}

impl Default for HardCaps {
    fn default() -> Self {
        Self {
            linear: DEFAULT_HARD_CAP_LINEAR,
            joint: DEFAULT_HARD_CAP_JOINT,
        }
    }
}

/// One bound above a hard cap: `(channel, dimension, value, cap)`.
fn over_caps(p: &Profile, caps: &HardCaps) -> Vec<(String, &'static str, f64, f64)> {
    let mut out = Vec::new();
    for (ch, env) in &p.motion_envelopes {
        for (dim, v, cap) in [
            ("linear", env.max_linear_speed, caps.linear),
            ("joint", env.max_joint_speed, caps.joint),
        ] {
            // NaN / negative bounds are reported by `Profile::validate`;
            // a NaN cap (caller bug) refuses everything.
            if let Some(v) = v.filter(|v| v.is_finite()) {
                // Not `v <= cap` (false for a NaN cap: refuse).
                if !matches!(
                    v.partial_cmp(&cap),
                    Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
                ) {
                    out.push((ch.clone(), dim, v, cap));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------- lock ----

/// Why a profile cannot be locked.
#[derive(Debug, Clone, PartialEq, Serialize)]
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
    /// Any other `Profile::validate` error (bad GUID, mangled or relative
    /// ROS name, empty raw topic or motion channel).
    InvalidProfile {
        error: ProfileError,
    },
    /// The draft file is not a strictly well-formed profile.
    UnreadableDraft {
        error: String,
    },
    /// The sign-off file is malformed.
    SignoffInvalid {
        error: String,
    },
    SignoffModelMismatch {
        signoff: String,
        profile: String,
    },
    /// The sign-off was produced for a different draft (or the draft was
    /// edited after the sign-off list was generated).
    SignoffDigestMismatch,
    /// Nobody put their name on the sign-off.
    SignoffNoOperator,
    /// An item the operator has not confirmed.
    Unconfirmed {
        id: String,
        why: String,
    },
    /// The sign-off's items are not the set generated for this draft
    /// (`items_sha256` mismatch: an item was deleted, added or reworded).
    SignoffItemsTampered,
    /// The draft requires a confirmed review the sign-off lacks (see
    /// `signoff::required_items`).
    RequiredItemMissing {
        subject: String,
        why: String,
    },
    /// An envelope bound above the hard cap.
    ExceedsHardCap {
        channel: String,
        dimension: String,
        value: f64,
        cap: f64,
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
            LockRefusal::InvalidProfile { error } => write!(f, "{error}"),
            LockRefusal::UnreadableDraft { error } => write!(f, "draft: {error}"),
            LockRefusal::SignoffInvalid { error } => write!(f, "sign-off: {error}"),
            LockRefusal::SignoffModelMismatch { signoff, profile } => write!(
                f,
                "sign-off is for model {signoff:?}, profile is {profile:?}"
            ),
            LockRefusal::SignoffDigestMismatch => write!(
                f,
                "sign-off does not belong to this draft (profile_sha256 differs): the draft was \
                 edited or the wrong sign-off file was given; re-run learn, or generate a \
                 conservative list with `robodr-commission signoff`"
            ),
            LockRefusal::SignoffNoOperator => {
                write!(f, "sign-off has no operator name (fill in \"operator\")")
            }
            LockRefusal::Unconfirmed { id, why } => {
                write!(f, "not confirmed by the operator: {id} ({why})")
            }
            LockRefusal::SignoffItemsTampered => write!(
                f,
                "sign-off items were deleted, added or reworded (items_sha256 differs): confirm \
                 items, do not remove them; re-run learn or `robodr-commission signoff`"
            ),
            LockRefusal::RequiredItemMissing { subject, why } => {
                write!(f, "required sign-off missing for {subject}: {why}")
            }
            LockRefusal::ExceedsHardCap {
                channel,
                dimension,
                value,
                cap,
            } => write!(
                f,
                "motion channel {channel}: {dimension} bound {value} exceeds the hard cap {cap} \
                 (pass --hard-cap-{dimension} if the platform really is that fast)"
            ),
        }
    }
}

/// Validate a draft profile against its operator sign-off and return it
/// with `locked = true`. All reasons to refuse are collected, so the OEM
/// sees everything at once (see the module docs). The sign-off is bound to
/// [`draft_digest`]`(profile)`, i.e. the bytes `learn` writes.
pub fn lock(profile: &Profile, signoff: &Signoff) -> Result<Profile, Vec<LockRefusal>> {
    lock_with_caps(profile, signoff, &HardCaps::default())
}

/// [`lock`] with explicit hard caps.
pub fn lock_with_caps(
    profile: &Profile,
    signoff: &Signoff,
    caps: &HardCaps,
) -> Result<Profile, Vec<LockRefusal>> {
    lock_with_digest(profile, signoff, &draft_digest(profile), caps)
}

/// [`lock`] for a draft read from disk: the sign-off is checked against the
/// SHA-256 of `draft_text` itself, and the text must parse strictly
/// (`profile_file::parse_profile_text`: all keys, no unknown keys).
pub fn lock_draft_text(draft_text: &str, signoff: &Signoff) -> Result<Profile, Vec<LockRefusal>> {
    lock_draft_text_with_caps(draft_text, signoff, &HardCaps::default())
}

/// [`lock_draft_text`] with explicit hard caps.
pub fn lock_draft_text_with_caps(
    draft_text: &str,
    signoff: &Signoff,
    caps: &HardCaps,
) -> Result<Profile, Vec<LockRefusal>> {
    let profile = parse_profile_text(draft_text).map_err(|e| {
        vec![LockRefusal::UnreadableDraft {
            error: e.to_string(),
        }]
    })?;
    lock_with_digest(&profile, signoff, &sha256_hex(draft_text.as_bytes()), caps)
}

fn lock_with_digest(
    profile: &Profile,
    signoff: &Signoff,
    digest: &str,
    caps: &HardCaps,
) -> Result<Profile, Vec<LockRefusal>> {
    let mut why = lockable_with_caps(profile, caps);
    if let Err(error) = signoff.check_shape() {
        why.push(LockRefusal::SignoffInvalid { error });
    }
    if signoff.model != profile.model {
        why.push(LockRefusal::SignoffModelMismatch {
            signoff: signoff.model.clone(),
            profile: profile.model.clone(),
        });
    }
    if signoff.profile_sha256 != digest {
        why.push(LockRefusal::SignoffDigestMismatch);
    }
    if signoff.operator.trim().is_empty() {
        why.push(LockRefusal::SignoffNoOperator);
    }
    if !signoff.items_intact() {
        why.push(LockRefusal::SignoffItemsTampered);
    }
    for i in signoff.unconfirmed() {
        why.push(LockRefusal::Unconfirmed {
            id: i.id.clone(),
            why: i.reason.clone(),
        });
    }
    for (subject, reason) in required_items(profile) {
        if !signoff.items.iter().any(|i| covers(i, &subject)) {
            why.push(LockRefusal::RequiredItemMissing {
                subject,
                why: reason,
            });
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

/// The content checks of [`lock`] alone (no sign-off): already locked,
/// empty, a motion channel without any bound, a bound above the default
/// [`HardCaps`], and every [`Profile::validate`] error. Empty means the
/// content is lockable.
pub fn lockable(profile: &Profile) -> Vec<LockRefusal> {
    lockable_with_caps(profile, &HardCaps::default())
}

/// [`lockable`] with explicit hard caps.
pub fn lockable_with_caps(profile: &Profile, caps: &HardCaps) -> Vec<LockRefusal> {
    let mut why = Vec::new();
    if profile.locked {
        why.push(LockRefusal::AlreadyLocked);
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
    }
    for (channel, dim, value, cap) in over_caps(profile, caps) {
        why.push(LockRefusal::ExceedsHardCap {
            channel,
            dimension: dim.into(),
            value,
            cap,
        });
    }
    if let Err(errors) = profile.validate() {
        why.extend(errors.into_iter().map(|e| {
            match e {
                ProfileError::EmptyModel => LockRefusal::EmptyModel,
                ProfileError::InvalidEnvelopeLimit { channel, field, .. } => {
                    LockRefusal::InvalidBound {
                        channel,
                        dimension: match field {
                            EnvelopeField::MaxLinearSpeed => "linear",
                            EnvelopeField::MaxJointSpeed => "joint",
                            EnvelopeField::MaxLateralSpeed => "lateral",
                            EnvelopeField::MaxVerticalSpeed => "vertical",
                            EnvelopeField::MaxRollPitchRate => "roll_pitch",
                        }
                        .into(),
                    }
                }
                error => LockRefusal::InvalidProfile { error },
            }
        }));
    }
    why
}

// ---------------------------------------------------------------- merge ---

#[derive(Debug, Clone, PartialEq)]
pub enum MergeError {
    NoProfiles,
    ModelMismatch(String, String),
    /// Some profiles enforce reader topics (non-empty `reader_topics`) and
    /// some do not: a union would silently start enforcing readers that the
    /// non-enforcing profiles never recorded.
    ReaderEnforcementMismatch,
    /// An input fails `Profile::validate` (NaN/inf/negative bounds, bad
    /// names): merging would carry garbage into the result.
    InvalidInput {
        index: usize,
        errors: Vec<String>,
    },
    /// An input has an envelope bound above the hard cap.
    ExceedsHardCap {
        index: usize,
        channel: String,
        dimension: String,
        value: f64,
        cap: f64,
    },
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeError::NoProfiles => write!(f, "nothing to merge"),
            MergeError::ModelMismatch(a, b) => write!(
                f,
                "refusing to merge profiles of different models ({a:?} vs {b:?})"
            ),
            MergeError::ReaderEnforcementMismatch => write!(
                f,
                "refusing to merge: some profiles enforce reader_topics and some do not \
                 (re-learn all missions with or without --learn-readers)"
            ),
            MergeError::InvalidInput { index, errors } => write!(
                f,
                "refusing to merge: profile #{} fails validation: {}",
                index + 1,
                errors.join("; ")
            ),
            MergeError::ExceedsHardCap {
                index,
                channel,
                dimension,
                value,
                cap,
            } => write!(
                f,
                "refusing to merge: profile #{} channel {channel}: {dimension} bound {value} \
                 exceeds the hard cap {cap}",
                index + 1
            ),
        }
    }
}

impl std::error::Error for MergeError {}

/// Union already-learned profiles (e.g. one per mission). Participants,
/// writer topics, services, actions, raw DDS topics and reader topics are
/// unioned (reader topics only if every profile enforces them, or none does:
/// see [`MergeError::ReaderEnforcementMismatch`]); per channel and dimension
/// the larger bound wins. `None` is read as "not observed" (the learner's meaning), so a bound
/// from one profile is kept when the other has none. The result is always
/// unlocked: a merged profile must be reviewed and locked again.
///
/// Prefer [`crate::Learner::merge`] when the raw runs are available: it
/// computes percentiles and warnings over all samples, and applies the margin
/// once. Merging profiles applies whatever margins each profile already had.
pub fn merge_profiles(profiles: &[Profile]) -> Result<Profile, MergeError> {
    merge_profiles_with_caps(profiles, &HardCaps::default())
}

/// [`merge_profiles`] with explicit hard caps: an input with a bound above
/// a cap is refused ([`MergeError::ExceedsHardCap`]), so the "larger bound
/// wins" rule can never carry an unbounded value into the result.
pub fn merge_profiles_with_caps(
    profiles: &[Profile],
    caps: &HardCaps,
) -> Result<Profile, MergeError> {
    let first = profiles.first().ok_or(MergeError::NoProfiles)?;
    for (index, p) in profiles.iter().enumerate() {
        if let Err(errs) = p.validate() {
            return Err(MergeError::InvalidInput {
                index,
                errors: errs.iter().map(ToString::to_string).collect(),
            });
        }
        if let Some((channel, dim, value, cap)) = over_caps(p, caps).into_iter().next() {
            return Err(MergeError::ExceedsHardCap {
                index,
                channel,
                dimension: dim.into(),
                value,
                cap,
            });
        }
    }
    let enforcing = !first.reader_topics.is_empty();
    if profiles
        .iter()
        .any(|p| p.reader_topics.is_empty() == enforcing)
    {
        return Err(MergeError::ReaderEnforcementMismatch);
    }
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
        out.services.extend(p.services.iter().cloned());
        out.actions.extend(p.actions.iter().cloned());
        out.raw_dds_topics.extend(p.raw_dds_topics.iter().cloned());
        out.reader_topics.extend(p.reader_topics.iter().cloned());
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
    pub services_added: BTreeSet<String>,
    pub services_removed: BTreeSet<String>,
    pub actions_added: BTreeSet<String>,
    pub actions_removed: BTreeSet<String>,
    pub raw_dds_topics_added: BTreeSet<String>,
    pub raw_dds_topics_removed: BTreeSet<String>,
    pub reader_topics_added: BTreeSet<String>,
    pub reader_topics_removed: BTreeSet<String>,
    /// Reader-topic enforcement (non-empty `reader_topics`) switched:
    /// `(old, new)`. Off -> on tightens; on -> off loosens.
    pub reader_enforcement: Option<(bool, bool)>,
    pub motion_channels_added: BTreeMap<String, Envelope>,
    pub motion_channels_removed: BTreeMap<String, Envelope>,
    pub envelope_changes: Vec<EnvelopeChange>,
}

impl ProfileDiff {
    pub fn is_empty(&self) -> bool {
        *self == ProfileDiff::default()
    }

    /// Reader topics added while enforcement was already on (adding the
    /// first reader topics switches enforcement on, which tightens).
    pub fn reader_topics_loosen(&self) -> bool {
        self.reader_enforcement.is_none() && !self.reader_topics_added.is_empty()
    }

    /// Does the new profile permit anything the old one did not? These are
    /// the changes that deserve the hardest look.
    pub fn loosens(&self) -> bool {
        !self.participants_added.is_empty()
            || !self.writer_topics_added.is_empty()
            || !self.services_added.is_empty()
            || !self.actions_added.is_empty()
            || !self.raw_dds_topics_added.is_empty()
            || self.reader_topics_loosen()
            || self.reader_enforcement == Some((true, false))
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
    let sets = |a: &BTreeSet<String>, b: &BTreeSet<String>| {
        (
            b.difference(a).cloned().collect::<BTreeSet<_>>(),
            a.difference(b).cloned().collect::<BTreeSet<_>>(),
        )
    };
    (d.services_added, d.services_removed) = sets(&old.services, &new.services);
    (d.actions_added, d.actions_removed) = sets(&old.actions, &new.actions);
    (d.raw_dds_topics_added, d.raw_dds_topics_removed) =
        sets(&old.raw_dds_topics, &new.raw_dds_topics);
    (d.reader_topics_added, d.reader_topics_removed) = sets(&old.reader_topics, &new.reader_topics);
    let (eo, en) = (!old.reader_topics.is_empty(), !new.reader_topics.is_empty());
    if eo != en {
        d.reader_enforcement = Some((eo, en));
    }
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
        for (what, added, removed) in [
            ("service", &self.services_added, &self.services_removed),
            ("action", &self.actions_added, &self.actions_removed),
        ] {
            for n in added {
                writeln!(f, "+ {what} {n}   [LOOSENS]")?;
            }
            for n in removed {
                writeln!(f, "- {what} {n}")?;
            }
        }
        for n in &self.raw_dds_topics_added {
            writeln!(f, "+ raw DDS topic {n:?}   [LOOSENS]")?;
        }
        for n in &self.raw_dds_topics_removed {
            writeln!(f, "- raw DDS topic {n:?}")?;
        }
        match self.reader_enforcement {
            Some((false, true)) => {
                writeln!(f, "~ reader-topic enforcement: off -> on   [tightens]")?
            }
            Some((true, false)) => {
                writeln!(f, "~ reader-topic enforcement: on -> off   [LOOSENS]")?
            }
            _ => {}
        }
        let mark = if self.reader_topics_loosen() {
            "   [LOOSENS]"
        } else {
            ""
        };
        for t in &self.reader_topics_added {
            writeln!(f, "+ reader topic {t}{mark}")?;
        }
        for t in &self.reader_topics_removed {
            writeln!(f, "- reader topic {t}")?;
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
            // Non-finite values are already a Critical
            // `robot.motion.non_finite_command` from `Profile::evaluate`;
            // only the commissioning-specific negative-magnitude anomaly
            // is added here.
            if v.is_finite() && v < 0.0 {
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

    /// Lock with a fully confirmed conservative sign-off.
    fn lk(p: &Profile) -> Result<Profile, Vec<LockRefusal>> {
        lock(p, &Signoff::for_profile(p).confirm_all("test-operator"))
    }

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
                ..Default::default()
            },
        );
        p
    }

    #[test]
    fn lock_sets_flag_and_preserves_content() {
        let l = lk(&base()).unwrap();
        assert!(l.locked);
        let mut back = l.clone();
        back.locked = false;
        assert_eq!(back, base());
    }

    #[test]
    fn lock_refuses_and_lists_every_reason() {
        let mut p = base();
        p.locked = true;
        assert_eq!(lk(&p).unwrap_err(), vec![LockRefusal::AlreadyLocked]);

        let empty = Profile::default();
        let why = lk(&empty).unwrap_err();
        assert!(why.contains(&LockRefusal::EmptyModel));
        assert!(why.contains(&LockRefusal::NoParticipants));
        assert!(why.contains(&LockRefusal::NoWriterTopics));

        let mut p = base();
        p.writer_topics.insert("/arm".into());
        p.writer_topics.insert("/bad".into());
        p.motion_envelopes
            .insert("/arm".into(), Envelope::default());
        p.motion_envelopes.insert(
            "/bad".into(),
            Envelope {
                max_linear_speed: Some(f64::NAN),
                max_joint_speed: Some(-1.0),
                ..Default::default()
            },
        );
        let why = lk(&p).unwrap_err();
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
        assert!(lk(&p).is_ok());
    }

    #[test]
    fn lock_requires_matching_confirmed_signoff() {
        let p = base();
        let so = Signoff::for_profile(&p);
        // Unconfirmed and anonymous.
        let why = lock(&p, &so).unwrap_err();
        assert!(why.contains(&LockRefusal::SignoffNoOperator));
        assert_eq!(
            why.iter()
                .filter(|r| matches!(r, LockRefusal::Unconfirmed { .. }))
                .count(),
            so.items.len()
        );
        // Confirmed, but for another draft.
        let mut other = base();
        other.writer_topics.insert("/odom".into());
        let why = lock(&other, &so.clone().confirm_all("op")).unwrap_err();
        assert_eq!(why, vec![LockRefusal::SignoffDigestMismatch]);
        // Wrong model.
        let mut so2 = so.clone().confirm_all("op");
        so2.model = "arm".into();
        assert!(lock(&p, &so2)
            .unwrap_err()
            .iter()
            .any(|r| matches!(r, LockRefusal::SignoffModelMismatch { .. })));
        // Malformed sign-off.
        let mut so3 = so.clone().confirm_all("op");
        so3.format = "nope".into();
        assert!(matches!(
            lock(&p, &so3).unwrap_err()[0],
            LockRefusal::SignoffInvalid { .. }
        ));
        // Operator of only whitespace.
        let mut so4 = so.clone().confirm_all("op");
        so4.operator = "  ".into();
        assert_eq!(
            lock(&p, &so4).unwrap_err(),
            vec![LockRefusal::SignoffNoOperator]
        );
        // All good.
        assert!(lock(&p, &so.confirm_all("op")).unwrap().locked);
        // Refusals serialise and display.
        let why = lock(&p, &Signoff::for_profile(&p)).unwrap_err();
        serde_json::to_string(&why).unwrap();
        assert!(why.iter().any(|r| r.to_string().contains("not confirmed")));
    }

    #[test]
    fn lock_draft_text_binds_to_bytes_and_parses_strictly() {
        let p = base();
        let text = crate::to_json(&p).unwrap();
        let so = Signoff::for_profile(&p).confirm_all("op");
        assert!(lock_draft_text(&text, &so).unwrap().locked);
        // Same content, different bytes (re-indented by an editor): the
        // sign-off no longer matches.
        let edited = text.replace("  ", "    ");
        assert_eq!(
            lock_draft_text(&edited, &so).unwrap_err(),
            vec![LockRefusal::SignoffDigestMismatch]
        );
        // Partially written draft.
        let why = lock_draft_text(&text[..text.len() / 2], &so).unwrap_err();
        assert!(matches!(why[0], LockRefusal::UnreadableDraft { .. }));
        // A draft with a key removed.
        let cut = text.replace("  \"actions\": [],\n", "");
        assert!(matches!(
            lock_draft_text(&cut, &so).unwrap_err()[0],
            LockRefusal::UnreadableDraft { .. }
        ));
    }

    #[test]
    fn merge_refuses_invalid_inputs() {
        let mut bad = base();
        bad.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_linear_speed = Some(f64::INFINITY);
        let e = merge_profiles(&[base(), bad]).unwrap_err();
        assert!(
            matches!(e, MergeError::InvalidInput { index: 1, .. }),
            "{e}"
        );
        let mut nan = base();
        nan.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_joint_speed = Some(f64::NAN);
        assert!(merge_profiles(&[nan]).is_err());
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
        let mut new = lk(&base()).unwrap();
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
                ..Default::default()
            },
        );
        let mut c = lk(&base()).unwrap();
        c.writer_topics.insert("/arm".into());
        c.motion_envelopes.insert(
            "/arm".into(),
            Envelope {
                max_linear_speed: None,
                max_joint_speed: Some(1.0),
                ..Default::default()
            },
        );
        let m = merge_profiles(&[a.clone(), b.clone(), c.clone()]).unwrap();
        assert!(!m.locked);
        assert_eq!(m.participants.len(), 2);
        assert_eq!(m.writer_topics.len(), 3);
        assert_eq!(
            m.motion_envelopes["/cmd_vel"],
            Envelope {
                max_linear_speed: Some(0.5),
                max_joint_speed: Some(2.0),
                ..Default::default()
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
    fn lock_runs_profile_validate() {
        let mut p = base();
        p.participants.insert("NOT-A-GUID".into());
        p.writer_topics.insert("rt/cmd_vel".into());
        p.services.insert("get_parameters".into());
        p.actions.insert("/".into());
        p.reader_topics.insert("/a b".into());
        p.raw_dds_topics.insert(String::new());
        let why = lk(&p).unwrap_err();
        assert_eq!(why.len(), 6, "{why:#?}");
        assert!(why
            .iter()
            .all(|r| matches!(r, LockRefusal::InvalidProfile { .. })));
        let text: Vec<String> = why.iter().map(ToString::to_string).collect();
        assert!(
            text.iter().any(|t| t.contains("\"rt/cmd_vel\"")),
            "{text:?}"
        );
        let j = serde_json::to_string(&why).unwrap();
        assert!(j.contains("\"reason\":\"invalid_profile\""), "{j}");
        assert!(j.contains("\"error\":\"not_a_ros_name\""), "{j}");

        // A clean profile with the new sets locks.
        let mut q = base();
        q.services.insert("/nav/get_parameters".into());
        q.actions.insert("/dock".into());
        q.raw_dds_topics.insert("ros_discovery_info".into());
        q.reader_topics.insert("/odom".into());
        let l = lk(&q).unwrap();
        assert!(l.locked && l.services.len() == 1);
    }

    #[test]
    fn diff_covers_new_sets_and_reader_enforcement() {
        let mut old = base();
        old.services.insert("/a".into());
        old.raw_dds_topics.insert("r1".into());
        let mut new = base();
        new.services.insert("/b".into());
        new.actions.insert("/dock".into());
        new.raw_dds_topics.insert("r2".into());
        let d = diff(&old, &new);
        assert!(d.services_added.contains("/b") && d.services_removed.contains("/a"));
        assert!(d.actions_added.contains("/dock"));
        assert!(d.raw_dds_topics_added.contains("r2"));
        assert!(d.raw_dds_topics_removed.contains("r1"));
        assert!(d.loosens());
        let s = d.to_string();
        assert!(s.contains("+ service /b   [LOOSENS]"), "{s}");
        assert!(s.contains("- service /a\n"), "{s}");
        assert!(s.contains("+ action /dock   [LOOSENS]"), "{s}");
        assert!(s.contains("+ raw DDS topic \"r2\"   [LOOSENS]"), "{s}");

        // Only removals: not loosening.
        let d = diff(&new, &base());
        assert!(!d.loosens(), "{d}");

        // Reader enforcement off -> on tightens; topics listed without LOOSENS.
        let mut on = base();
        on.reader_topics.insert("/odom".into());
        let d = diff(&base(), &on);
        assert_eq!(d.reader_enforcement, Some((false, true)));
        assert!(!d.loosens());
        let s = d.to_string();
        assert!(s.contains("off -> on   [tightens]"), "{s}");
        assert!(s.contains("+ reader topic /odom\n"), "{s}");
        // on -> off loosens.
        let d = diff(&on, &base());
        assert!(d.loosens());
        assert!(d.to_string().contains("on -> off   [LOOSENS]"));
        // Adding a reader topic while enforcing loosens.
        let mut more = on.clone();
        more.reader_topics.insert("/scan".into());
        let d = diff(&on, &more);
        assert!(d.loosens());
        assert!(d.to_string().contains("+ reader topic /scan   [LOOSENS]"));
        serde_json::to_string(&d).unwrap();
    }

    #[test]
    fn merge_profiles_new_sets_and_reader_mismatch() {
        let mut a = base();
        a.services.insert("/a".into());
        a.raw_dds_topics.insert("r".into());
        let mut b = base();
        b.actions.insert("/dock".into());
        let m = merge_profiles(&[a.clone(), b.clone()]).unwrap();
        assert!(m.services.contains("/a") && m.actions.contains("/dock"));
        assert!(m.raw_dds_topics.contains("r") && m.reader_topics.is_empty());

        let mut ra = a.clone();
        ra.reader_topics.insert("/odom".into());
        assert_eq!(
            merge_profiles(&[a.clone(), ra.clone()]).unwrap_err(),
            MergeError::ReaderEnforcementMismatch
        );
        assert_eq!(
            merge_profiles(&[ra.clone(), b.clone()]).unwrap_err(),
            MergeError::ReaderEnforcementMismatch
        );
        let mut rb = b.clone();
        rb.reader_topics.insert("/scan".into());
        let m = merge_profiles(&[ra, rb]).unwrap();
        assert_eq!(m.reader_topics.len(), 2);
        assert!(MergeError::ReaderEnforcementMismatch
            .to_string()
            .contains("--learn-readers"));
    }

    #[test]
    fn checker_counts_deviations() {
        let p = lk(&base()).unwrap();
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
                angular_speed: None,
                ..Default::default()
            })
        };
        c.observe("x", 3, &mv(0.4));
        c.observe("x", 4, &mv(f64::NAN));
        c.observe("x", 5, &mv(-1.0));
        c.observe("x", 6, &mv(0.6));
        let r = c.finish();
        assert_eq!(r.events, 6);
        // NaN -> core non_finite_command; -1.0 -> |1.0| over envelope plus
        // the commissioning negative-magnitude anomaly; 0.6 -> over envelope.
        assert_eq!(r.deviations_total, 5);
        assert_eq!(r.by_rule["robot.ros2.unknown_participant"], 1);
        assert_eq!(r.by_rule["robot.motion.non_finite_command"], 1);
        assert_eq!(r.by_rule[RULE_ANOMALOUS_SPEED], 1);
        assert_eq!(r.by_rule["robot.motion.linear_over_envelope"], 2);
        assert_eq!(r.findings[0].position, 2);
        let s = r.to_string();
        assert!(
            s.contains("x:2: [High] robot.ros2.unknown_participant"),
            "{s}"
        );
        assert!(s.contains("5 deviation(s) over 6 event(s)"));
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
