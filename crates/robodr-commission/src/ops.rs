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
//! [`lock_signed_draft`] (what the CLI uses) adds the operator signatures
//! of the sign-off (see `signoff`: a valid signature from a key in the
//! operators trust list, the sign-off's `operator` among the signers, and
//! `motion_quorum` distinct operators when the list has motion items).
//! [`lock`] / [`lock_draft_text`] check content and confirmations only:
//! callers that embed the library and authenticate the operator themselves.
//!
//! The CLI then writes the result sealed (see `profile_file`), so the
//! locked file cannot be edited or half-written without `check`, `diff`
//! and `merge` refusing it.
//!
//! # Output manifest (multi-file publish)
//!
//! `learn` writes three files (draft, sign-off list, report) and `signoff`
//! two. Each file is published atomically, but a power loss between two
//! publishes can leave a new draft next to an old sign-off or report (the
//! operator would review a stale report). So the producing command writes a
//! [`Manifest`] **last** (`<draft>.manifest.json`, after removing any old
//! one and after the companion files are fsynced): the draft's SHA-256, the
//! report's SHA-256 and the sign-off's invariant digests (`profile_sha256`,
//! `items_sha256`; `confirmed` / `operator` change on review, so the file
//! hash cannot be recorded). [`verify_manifest`] (used by `lock`, and by
//! `check` on a draft) refuses a draft whose manifest is missing, malformed
//! or does not match the draft, the sign-off or the report. A manifest is
//! not a signature: it detects torn and mixed-up outputs, not forgery
//! (that is the operator signature's job). `lock --no-manifest` skips it
//! for drafts made before manifests existed or edited by hand (their
//! sign-off is then the conservative `signoff` list, which writes a fresh
//! manifest).

use crate::input::{EventSource, InputError};
use crate::learner::{
    DEFAULT_HARD_CAP_JOINT, DEFAULT_HARD_CAP_KP, DEFAULT_HARD_CAP_LINEAR,
    DEFAULT_HARD_CAP_POSITION_STEP, DEFAULT_HARD_CAP_TORQUE,
};
use crate::profile_file::parse_profile_text;
use crate::signoff::{
    draft_digest, motion_items, required_items, satisfies, sha256_hex, verify_signoff_signatures,
    OperatorTrust, Signoff, SignoffSignatures,
};
use robodr_events::profile::{Envelope, EnvelopeField, Profile, ProfileError};
use robodr_events::{Deviation, MotionCommand, RobotEvent, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

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
    /// N·m (`max_joint_torque`).
    pub torque: f64,
    /// `max_joint_kp`.
    pub kp: f64,
    /// rad (`max_joint_position_step`).
    pub position_step: f64,
}

impl Default for HardCaps {
    fn default() -> Self {
        Self {
            linear: DEFAULT_HARD_CAP_LINEAR,
            joint: DEFAULT_HARD_CAP_JOINT,
            torque: DEFAULT_HARD_CAP_TORQUE,
            kp: DEFAULT_HARD_CAP_KP,
            position_step: DEFAULT_HARD_CAP_POSITION_STEP,
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
            ("joint_torque", env.max_joint_torque, caps.torque),
            ("joint_kp", env.max_joint_kp, caps.kp),
            (
                "joint_position_step",
                env.max_joint_position_step,
                caps.position_step,
            ),
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
    /// No valid operator signature over the sign-off.
    OperatorSignatureMissing,
    /// A signature that is malformed, by an unlisted key, or invalid.
    OperatorSignatureInvalid {
        detail: String,
    },
    /// The sign-off's `operator` is not one of the operators who signed it.
    OperatorNotASigner {
        operator: String,
        signers: Vec<String>,
    },
    /// Too few distinct operators signed a sign-off with motion items.
    MotionQuorumNotMet {
        have: usize,
        need: usize,
    },
    /// The draft has no output manifest.
    ManifestMissing {
        path: String,
    },
    /// The manifest is malformed or the draft / sign-off / report do not
    /// match it.
    ManifestMismatch {
        detail: String,
    },
    /// The sign-off is bound to the raw bytes of a draft that is not in
    /// canonical form, so the unit could not verify the attestation the
    /// locked profile carries (see `trust::attestation`).
    SignoffNotCanonical,
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
            LockRefusal::OperatorSignatureMissing => write!(
                f,
                "the sign-off carries no valid operator signature: the operator must sign the \
                 confirmed list (`robodr-commission signoff --signoff <file> --sign-key \
                 <operator.key>`) with a key in the operators trust list"
            ),
            LockRefusal::OperatorSignatureInvalid { detail } => {
                write!(f, "operator signature: {detail}")
            }
            LockRefusal::OperatorNotASigner { operator, signers } => write!(
                f,
                "the sign-off names operator {operator:?}, but the valid signatures are by \
                 {signers:?}: the named operator must sign it"
            ),
            LockRefusal::SignoffNotCanonical => write!(
                f,
                "the sign-off is bound to the draft's raw bytes, which are not the canonical \
                 form the unit verifies the attestation against: regenerate the list with \
                 `robodr-commission signoff --in <draft> --out <signoff>` (binds the content), \
                 confirm and sign it again"
            ),
            LockRefusal::MotionQuorumNotMet { have, need } => write!(
                f,
                "two-person rule: the sign-off has motion items, so {need} distinct operators \
                 must sign it ({have} did)"
            ),
            LockRefusal::ManifestMissing { path } => write!(
                f,
                "no output manifest {path}: the learn/signoff output set is incomplete (power \
                 loss or interrupted write?); re-run the command, or pass --no-manifest for a \
                 draft made before manifests existed"
            ),
            LockRefusal::ManifestMismatch { detail } => write!(f, "manifest: {detail}"),
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
    lock_with_digest(profile, signoff, &[draft_digest(profile)], caps)
}

/// [`lock`] for a draft read from disk: the sign-off is checked against the
/// SHA-256 of `draft_text` itself or of its canonical form
/// ([`draft_digest`] of the parsed draft: the same content), and the text
/// must parse strictly (`profile_file::parse_profile_text`: all keys, no
/// unknown keys).
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
    let digests = [sha256_hex(draft_text.as_bytes()), draft_digest(&profile)];
    lock_with_digest(&profile, signoff, &digests, caps)
}

fn lock_with_digest(
    profile: &Profile,
    signoff: &Signoff,
    digests: &[String],
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
    if !digests.contains(&signoff.profile_sha256) {
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
    for req in required_items(profile) {
        if !signoff.items.iter().any(|i| satisfies(i, &req)) {
            why.push(LockRefusal::RequiredItemMissing {
                subject: req.subject,
                why: req.why,
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

/// Who may sign a sign-off, and the two-person rule ([`lock_signed_draft`]).
#[derive(Debug, Clone, Copy)]
pub struct OperatorPolicy<'a> {
    pub trust: &'a OperatorTrust,
    /// Raise the trust list's `motion_quorum` for this lock (the effective
    /// quorum is the larger of the two; it can never be lowered here).
    pub min_motion_quorum: usize,
}

impl OperatorPolicy<'_> {
    /// Distinct operators required for a sign-off with motion items.
    pub fn motion_quorum(&self) -> usize {
        self.trust
            .motion_quorum()
            .max(self.min_motion_quorum)
            .max(1)
    }
}

/// The operator-signature checks of [`lock_signed_draft`] alone: every
/// signature valid, at least one, `signoff.operator` among the signers,
/// and the motion quorum. `sigs == None`: no signature file.
pub fn signature_refusals(
    signoff: &Signoff,
    signoff_text: &str,
    sigs: Option<&SignoffSignatures>,
    policy: &OperatorPolicy<'_>,
) -> Vec<LockRefusal> {
    let mut why = Vec::new();
    let Some(sigs) = sigs else {
        why.push(LockRefusal::OperatorSignatureMissing);
        return why;
    };
    let v = verify_signoff_signatures(signoff_text.as_bytes(), sigs, policy.trust);
    for detail in v.problems {
        why.push(LockRefusal::OperatorSignatureInvalid { detail });
    }
    if v.signers.is_empty() {
        why.push(LockRefusal::OperatorSignatureMissing);
        return why;
    }
    let operator = signoff.operator.trim();
    if !operator.is_empty() && !v.signers.contains_key(operator) {
        why.push(LockRefusal::OperatorNotASigner {
            operator: operator.to_string(),
            signers: v.signers.keys().cloned().collect(),
        });
    }
    let need = policy.motion_quorum();
    if motion_items(signoff).next().is_some() && v.signers.len() < need {
        why.push(LockRefusal::MotionQuorumNotMet {
            have: v.signers.len(),
            need,
        });
    }
    why
}

/// The full lock the CLI performs: [`lock_draft_text_with_caps`] (content,
/// confirmations, item digest, floor, caps) plus [`signature_refusals`] over
/// the exact sign-off bytes, plus the sign-off bound to the draft's
/// canonical content (so the attestation the CLI embeds,
/// `trust::attestation_for`, verifies on the unit). Every reason is
/// collected. On success returns the locked profile and the parsed
/// sign-off.
pub fn lock_signed_draft(
    draft_text: &str,
    signoff_text: &str,
    sigs: Option<&SignoffSignatures>,
    policy: &OperatorPolicy<'_>,
    caps: &HardCaps,
) -> Result<(Profile, Signoff), Vec<LockRefusal>> {
    let signoff: Signoff = serde_json::from_str(signoff_text).map_err(|e| {
        vec![LockRefusal::SignoffInvalid {
            error: e.to_string(),
        }]
    })?;
    let mut why = Vec::new();
    let locked = match lock_draft_text_with_caps(draft_text, &signoff, caps) {
        Ok(p) => Some(p),
        Err(r) => {
            why.extend(r);
            None
        }
    };
    if let Some(p) = &locked {
        if signoff.profile_sha256 != crate::trust::content_digest(p) {
            why.push(LockRefusal::SignoffNotCanonical);
        }
    }
    why.extend(signature_refusals(&signoff, signoff_text, sigs, policy));
    match locked {
        Some(p) if why.is_empty() => Ok((p, signoff)),
        _ => Err(why),
    }
}

// ------------------------------------------------------------ manifest ---

/// Value of [`Manifest::format`].
pub const MANIFEST_FORMAT: &str = "robodr-commission-manifest/v1";
/// Max manifest size.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
/// Max size of a report the manifest check reads back.
pub const MAX_REPORT_BYTES: u64 = 256 << 20;

/// The manifest path of a draft: the file name with `.manifest.json`
/// appended.
pub fn manifest_path_for(draft: &Path) -> PathBuf {
    let mut s = draft.as_os_str().to_os_string();
    s.push(".manifest.json");
    PathBuf::from(s)
}

/// One file of an output set and the SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    /// Relative to the manifest's directory when in the same directory,
    /// else absolute.
    pub path: String,
    pub sha256: String,
}

/// The sign-off of an output set: its invariant digests (the operator
/// edits `confirmed` and `operator`, so the file hash would not survive
/// review).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignoff {
    pub path: String,
    pub profile_sha256: String,
    pub items_sha256: String,
}

/// The output manifest written last by `learn` and `signoff`; see the
/// module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub model: String,
    pub draft: ManifestFile,
    pub signoff: Option<ManifestSignoff>,
    pub report: Option<ManifestFile>,
}

/// How `file` is recorded in a manifest at `manifest`: its file name when
/// both are in the same directory, else its absolute path.
pub fn manifest_entry_path(manifest: &Path, file: &Path) -> String {
    let dir = |p: &Path| {
        let d = p.parent().filter(|d| !d.as_os_str().is_empty());
        std::fs::canonicalize(d.unwrap_or(Path::new("."))).ok()
    };
    match (dir(manifest), dir(file), file.file_name()) {
        (Some(a), Some(b), Some(n)) if a == b => n.to_string_lossy().into_owned(),
        (_, Some(b), Some(n)) => b.join(n).to_string_lossy().into_owned(),
        _ => file.to_string_lossy().into_owned(),
    }
}

impl Manifest {
    /// The manifest of an output set: `draft` and `report` are
    /// `(path, exact bytes)`.
    pub fn new(
        manifest: &Path,
        model: &str,
        draft: (&Path, &[u8]),
        signoff: Option<(&Path, &Signoff)>,
        report: Option<(&Path, &[u8])>,
    ) -> Self {
        let file = |(p, b): (&Path, &[u8])| ManifestFile {
            path: manifest_entry_path(manifest, p),
            sha256: sha256_hex(b),
        };
        Self {
            format: MANIFEST_FORMAT.into(),
            model: model.into(),
            draft: file(draft),
            signoff: signoff.map(|(p, s)| ManifestSignoff {
                path: manifest_entry_path(manifest, p),
                profile_sha256: s.profile_sha256.clone(),
                items_sha256: s.items_sha256.clone(),
            }),
            report: report.map(file),
        }
    }

    /// Strict parse (unknown / duplicate keys refused, format checked).
    pub fn parse(text: &str) -> Result<Self, String> {
        crate::profile_file::reject_duplicate_keys(text).map_err(|e| e.to_string())?;
        let m: Self = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if m.format != MANIFEST_FORMAT {
            return Err(format!(
                "format {:?}, expected {MANIFEST_FORMAT:?}",
                m.format
            ));
        }
        Ok(m)
    }

    pub fn to_text(&self) -> String {
        crate::to_json(self).unwrap_or_default()
    }

    /// Where a recorded path lives, given the manifest's own path.
    pub fn resolve(manifest: &Path, recorded: &str) -> PathBuf {
        let p = Path::new(recorded);
        if p.is_absolute() {
            return p.to_path_buf();
        }
        manifest
            .parent()
            .map_or_else(|| p.to_path_buf(), |d| d.join(p))
    }

    /// Mismatches between this manifest and the draft bytes, the sign-off
    /// (if given; else the recorded sign-off file is read) and the report
    /// file on disk.
    pub fn problems(
        &self,
        manifest: &Path,
        draft_bytes: &[u8],
        signoff: Option<&Signoff>,
    ) -> Vec<String> {
        let mut out = Vec::new();
        if self.draft.sha256 != sha256_hex(draft_bytes) {
            out.push(format!(
                "the draft does not match the manifest (recorded {}, the file is {}): it was \
                 replaced or edited after the output set was written",
                self.draft.sha256,
                sha256_hex(draft_bytes)
            ));
        }
        if let Some(ms) = &self.signoff {
            let read;
            let so = match signoff {
                Some(s) => Some(s),
                None => {
                    let p = Self::resolve(manifest, &ms.path);
                    read = crate::profile_file::read_regular_file(&p, MAX_MANIFEST_BYTES << 8)
                        .map_err(|e| format!("{}: {e}", p.display()))
                        .and_then(|t| {
                            serde_json::from_str::<Signoff>(&t)
                                .map_err(|e| format!("{}: {e}", p.display()))
                        });
                    match &read {
                        Ok(s) => Some(s),
                        Err(e) => {
                            out.push(format!("recorded sign-off unreadable: {e}"));
                            None
                        }
                    }
                }
            };
            if let Some(so) = so {
                if so.profile_sha256 != ms.profile_sha256 || so.items_sha256 != ms.items_sha256 {
                    out.push(format!(
                        "the sign-off is not the one written with this draft (manifest records \
                         {}); a stale or foreign list",
                        ms.path
                    ));
                }
            }
        }
        if let Some(r) = &self.report {
            let p = Self::resolve(manifest, &r.path);
            match crate::profile_file::read_regular_file(&p, MAX_REPORT_BYTES) {
                Ok(b) if sha256_hex(b.as_bytes()) == r.sha256 => {}
                Ok(_) => out.push(format!(
                    "the report {} does not match the manifest: the operator would review a \
                     stale or edited report",
                    p.display()
                )),
                Err(e) => out.push(format!("the report {} is missing: {e}", p.display())),
            }
        }
        out
    }
}

/// [`Manifest`] checks for a draft at `draft_path`: the manifest
/// (`<draft>.manifest.json`) must exist, parse, and match the draft bytes,
/// the sign-off (when given) and the report. Empty = consistent.
pub fn verify_manifest(
    draft_path: &Path,
    draft_bytes: &[u8],
    signoff: Option<&Signoff>,
) -> Vec<LockRefusal> {
    let mp = manifest_path_for(draft_path);
    let text = match crate::profile_file::read_regular_file(&mp, MAX_MANIFEST_BYTES) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return vec![LockRefusal::ManifestMissing {
                path: mp.display().to_string(),
            }]
        }
        Err(e) => {
            return vec![LockRefusal::ManifestMismatch {
                detail: format!("{}: {e}", mp.display()),
            }]
        }
    };
    match Manifest::parse(&text) {
        Err(e) => vec![LockRefusal::ManifestMismatch {
            detail: format!("{}: {e}", mp.display()),
        }],
        Ok(m) => m
            .problems(&mp, draft_bytes, signoff)
            .into_iter()
            .map(|detail| LockRefusal::ManifestMismatch { detail })
            .collect(),
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
                            EnvelopeField::MaxJointTorque => "joint_torque",
                            EnvelopeField::MaxJointKp => "joint_kp",
                            EnvelopeField::MaxJointPositionStep => "joint_position_step",
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
/// `bound_config` is **not** carried over (nor are participant identities
/// and learned motion types): the merged draft binds no safety
/// configuration until `bind` runs on it, so a unit using it treats the
/// policy and adapters as not OEM-validated (fail closed).
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
            e.max_joint_torque = max_opt(e.max_joint_torque, env.max_joint_torque);
            e.max_joint_kp = max_opt(e.max_joint_kp, env.max_joint_kp);
            e.max_joint_position_step =
                max_opt(e.max_joint_position_step, env.max_joint_position_step);
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
    /// Bound safety configuration (`bound_config`, see
    /// `trust::bound`) that was added, removed or re-bound: role ->
    /// `(old digest, new digest)`. Neither tightens nor loosens by itself
    /// (the file's content decides), so it is shown for review, not in
    /// [`ProfileDiff::loosens`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bound_config_changes: BTreeMap<String, (Option<String>, Option<String>)>,
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
                    ("joint_torque", o.max_joint_torque, env.max_joint_torque),
                    ("joint_kp", o.max_joint_kp, env.max_joint_kp),
                    (
                        "joint_position_step",
                        o.max_joint_position_step,
                        env.max_joint_position_step,
                    ),
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
    let roles: BTreeSet<&String> = old
        .bound_config
        .keys()
        .chain(new.bound_config.keys())
        .collect();
    for role in roles {
        let (a, b) = (old.bound_config.get(role), new.bound_config.get(role));
        if a != b {
            d.bound_config_changes
                .insert(role.clone(), (a.cloned(), b.cloned()));
        }
    }
    d
}

fn bound(v: Option<f64>) -> String {
    v.map_or_else(|| "unbounded".into(), |v| v.to_string())
}

fn env_str(e: &Envelope) -> String {
    let mut s = format!(
        "linear {} m/s, joint {} rad/s",
        bound(e.max_linear_speed),
        bound(e.max_joint_speed)
    );
    // Joint terms only when set (keeps the historic text for other
    // envelopes).
    for (name, v, unit) in [
        ("joint torque", e.max_joint_torque, " N·m"),
        ("joint kp", e.max_joint_kp, ""),
        ("joint position step", e.max_joint_position_step, " rad"),
    ] {
        if let Some(v) = v {
            s.push_str(&format!(", {name} {v}{unit}"));
        }
    }
    s
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
        for (role, (a, b)) in &self.bound_config_changes {
            match (a, b) {
                (None, Some(n)) => writeln!(f, "+ bound {role} {n}   [REVIEW the file]")?,
                (Some(o), None) => writeln!(
                    f,
                    "- bound {role} (was {o}): the unit no longer honours that file's flags"
                )?,
                (Some(o), Some(n)) => {
                    writeln!(f, "~ bound {role}: {o} -> {n}   [REVIEW the file]")?
                }
                (None, None) => {}
            }
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
///
/// Participant identities (`Profile::participant_identities`): a
/// participant whose prefix is not in `participants` but whose source IP and
/// RTPS vendor (the prefix's first two bytes) match an identity is treated
/// as profiled from then on, as the sensor does after a restart. This
/// offline review does not enforce `max_instances` (events carry no lease
/// or dispose); the sensor does.
pub struct Checker<'p> {
    profile: &'p Profile,
    /// `profile` plus the prefixes resolved to an identity so far.
    working: Profile,
    report: CheckReport,
}

impl<'p> Checker<'p> {
    pub fn new(profile: &'p Profile) -> Self {
        Self {
            profile,
            working: profile.clone(),
            report: CheckReport {
                model: profile.model.clone(),
                profile_locked: profile.locked,
                ..Default::default()
            },
        }
    }

    fn resolve_identity(&mut self, event: &RobotEvent) {
        let RobotEvent::Ros2ParticipantDiscovered(p) = event else {
            return;
        };
        if self.working.participants.contains(&p.guid_prefix) || p.guid_prefix.len() != 24 {
            return;
        }
        let ip = p.src_ip.parse::<std::net::IpAddr>().ok();
        let matches = self.profile.participant_identities.values().any(|id| {
            p.guid_prefix.get(..4) == Some(id.vendor.as_str())
                && id
                    .ips
                    .iter()
                    .any(|i| i.parse::<std::net::IpAddr>().ok() == ip && ip.is_some())
        });
        if matches {
            self.working.participants.insert(p.guid_prefix.clone());
        }
    }

    pub fn observe(&mut self, source: &str, position: u64, event: &RobotEvent) {
        self.report.events += 1;
        self.resolve_identity(event);
        for deviation in check_event(&self.working, event) {
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
        // sign-off still matches through the canonical content digest (what
        // the unit verifies the attestation against) ...
        let edited = text.replace("  ", "    ");
        assert!(lock_draft_text(&edited, &so).unwrap().locked);
        // ... and one bound to the edited raw bytes matches those bytes.
        let mut raw = so.clone();
        raw.rebind(sha256_hex(edited.as_bytes()));
        assert!(lock_draft_text(&edited, &raw).unwrap().locked);
        // Other content: no match either way.
        let mut other = p.clone();
        other.writer_topics.insert("/odom".into());
        let other_text = crate::to_json(&other).unwrap();
        assert_eq!(
            lock_draft_text(&other_text, &so).unwrap_err(),
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

    // ------------------------------------------------ signed lock ---

    fn opkey(id: &str, seed: u8) -> robodr_blackbox::Ed25519SigningKey {
        robodr_blackbox::Ed25519SigningKey::from_seed(id, &[seed; 32]).unwrap()
    }

    struct Ops {
        alice: robodr_blackbox::Ed25519SigningKey,
        alice2: robodr_blackbox::Ed25519SigningKey,
        bob: robodr_blackbox::Ed25519SigningKey,
        trust: OperatorTrust,
    }

    fn ops(quorum: usize) -> Ops {
        let (alice, alice2, bob) = (opkey("alice-1", 1), opkey("alice-2", 2), opkey("bob-1", 3));
        let trust = OperatorTrust::new(
            vec![
                ("alice".into(), alice.verifying_key()),
                ("alice".into(), alice2.verifying_key()),
                ("bob".into(), bob.verifying_key()),
            ],
            quorum,
        )
        .unwrap();
        Ops {
            alice,
            alice2,
            bob,
            trust,
        }
    }

    /// Draft text and a confirmed sign-off text (operator alice).
    fn signed_case() -> (String, String) {
        let p = base();
        let draft = crate::to_json(&p).unwrap();
        let so = Signoff::for_profile(&p).confirm_all("alice");
        (draft, crate::to_json(&so).unwrap())
    }

    fn sign(text: &str, keys: &[&robodr_blackbox::Ed25519SigningKey]) -> SignoffSignatures {
        let mut s = SignoffSignatures::new(text.as_bytes());
        for k in keys {
            s.add(text.as_bytes(), *k).unwrap();
        }
        s
    }

    fn signed_lock(
        draft: &str,
        so: &str,
        sigs: Option<&SignoffSignatures>,
        trust: &OperatorTrust,
        min: usize,
    ) -> Result<(Profile, Signoff), Vec<LockRefusal>> {
        let policy = OperatorPolicy {
            trust,
            min_motion_quorum: min,
        };
        lock_signed_draft(draft, so, sigs, &policy, &HardCaps::default())
    }

    #[test]
    fn signed_lock_requires_a_canonically_bound_signoff() {
        let o = ops(1);
        let (draft, _) = signed_case();
        // A hand-edited (re-indented) draft with a sign-off bound to its raw
        // bytes: the unit could not verify the attestation, so the CLI lock
        // path refuses it ...
        let edited = draft.replace("  ", "    ");
        let mut raw = Signoff::for_profile(&base()).confirm_all("alice");
        raw.rebind(sha256_hex(edited.as_bytes()));
        let raw = crate::to_json(&raw).unwrap();
        let why =
            signed_lock(&edited, &raw, Some(&sign(&raw, &[&o.alice])), &o.trust, 1).unwrap_err();
        assert_eq!(why, vec![LockRefusal::SignoffNotCanonical]);
        assert!(why[0].to_string().contains("signoff --in"));
        // ... while a sign-off bound to the content (what `signoff --in`
        // writes) locks the same edited bytes.
        let canon = crate::to_json(&Signoff::for_profile(&base()).confirm_all("alice")).unwrap();
        let (p, _) = signed_lock(
            &edited,
            &canon,
            Some(&sign(&canon, &[&o.alice])),
            &o.trust,
            1,
        )
        .unwrap();
        assert_eq!(
            crate::trust::content_digest(&p),
            Signoff::for_profile(&base()).profile_sha256
        );
    }

    #[test]
    fn signed_lock_requires_a_valid_listed_signature() {
        let o = ops(1);
        let (draft, so) = signed_case();
        let (p, s) = signed_lock(&draft, &so, Some(&sign(&so, &[&o.alice])), &o.trust, 1).unwrap();
        assert!(p.locked);
        assert_eq!(s.operator, "alice");
        // No signature file / empty signature list.
        assert_eq!(
            signed_lock(&draft, &so, None, &o.trust, 1).unwrap_err(),
            vec![LockRefusal::OperatorSignatureMissing]
        );
        assert_eq!(
            signed_lock(&draft, &so, Some(&sign(&so, &[])), &o.trust, 1).unwrap_err(),
            vec![LockRefusal::OperatorSignatureMissing]
        );
        // A key outside the trust list: invalid and missing.
        let stranger = opkey("mallory", 9);
        let why =
            signed_lock(&draft, &so, Some(&sign(&so, &[&stranger])), &o.trust, 1).unwrap_err();
        assert!(matches!(
            why[0],
            LockRefusal::OperatorSignatureInvalid { .. }
        ));
        assert!(why.contains(&LockRefusal::OperatorSignatureMissing));
        // A valid signature plus a bad one: fail closed.
        let mut mixed = sign(&so, &[&o.alice]);
        mixed.add(so.as_bytes(), &stranger).unwrap();
        let why = signed_lock(&draft, &so, Some(&mixed), &o.trust, 1).unwrap_err();
        assert_eq!(why.len(), 1, "{why:?}");
        assert!(why[0]
            .to_string()
            .contains("not in the operators trust list"));
        // Signed by bob, but the list names alice.
        let why = signed_lock(&draft, &so, Some(&sign(&so, &[&o.bob])), &o.trust, 1).unwrap_err();
        assert_eq!(
            why,
            vec![LockRefusal::OperatorNotASigner {
                operator: "alice".into(),
                signers: vec!["bob".into()]
            }]
        );
        // The list was edited after signing (operator renamed): void.
        let edited = so.replace("\"alice\"", "\"bob\"");
        let why =
            signed_lock(&draft, &edited, Some(&sign(&so, &[&o.bob])), &o.trust, 1).unwrap_err();
        assert!(why
            .iter()
            .any(|r| r.to_string().contains("changed after signing")));
        // Content refusals and signature refusals are reported together.
        let unconfirmed = crate::to_json(&{
            let mut s = Signoff::for_profile(&base());
            s.operator = "alice".into();
            s
        })
        .unwrap();
        let why = signed_lock(&draft, &unconfirmed, None, &o.trust, 1).unwrap_err();
        assert!(why
            .iter()
            .any(|r| matches!(r, LockRefusal::Unconfirmed { .. })));
        assert!(why.contains(&LockRefusal::OperatorSignatureMissing));
        // Not a sign-off at all.
        assert!(matches!(
            signed_lock(&draft, "{", None, &o.trust, 1).unwrap_err()[0],
            LockRefusal::SignoffInvalid { .. }
        ));
        for r in &why {
            assert!(!r.to_string().is_empty());
        }
        serde_json::to_string(&why).unwrap();
    }

    #[test]
    fn forged_list_with_recomputed_digests_still_needs_a_signature() {
        // Someone with write access deletes the motion item and recomputes
        // items_sha256: the digest check passes, the floor and the missing
        // signature still refuse.
        let o = ops(1);
        let (draft, so) = signed_case();
        let mut forged: Signoff = serde_json::from_str(&so).unwrap();
        forged.items.retain(|i| i.kind == "participant_unreviewed");
        let digest = forged.profile_sha256.clone();
        forged.rebind(digest);
        assert!(forged.items_intact());
        let text = crate::to_json(&forged).unwrap();
        let why = signed_lock(&draft, &text, None, &o.trust, 1).unwrap_err();
        assert!(why
            .iter()
            .any(|r| matches!(r, LockRefusal::RequiredItemMissing { .. })));
        assert!(why.contains(&LockRefusal::OperatorSignatureMissing));
        // The signatures over the genuine list do not carry over.
        let why =
            signed_lock(&draft, &text, Some(&sign(&so, &[&o.alice])), &o.trust, 1).unwrap_err();
        assert!(why
            .iter()
            .any(|r| r.to_string().contains("changed after signing")));
    }

    #[test]
    fn two_person_rule_counts_distinct_operators() {
        let o = ops(2);
        let (draft, so) = signed_case();
        // The conservative list has a motion item: two operators needed.
        let one = sign(&so, &[&o.alice]);
        assert_eq!(
            signed_lock(&draft, &so, Some(&one), &o.trust, 1).unwrap_err(),
            vec![LockRefusal::MotionQuorumNotMet { have: 1, need: 2 }]
        );
        // Two keys of the same person are one operator.
        let same = sign(&so, &[&o.alice, &o.alice2]);
        assert_eq!(
            signed_lock(&draft, &so, Some(&same), &o.trust, 1).unwrap_err(),
            vec![LockRefusal::MotionQuorumNotMet { have: 1, need: 2 }]
        );
        let two = sign(&so, &[&o.alice, &o.bob]);
        assert!(signed_lock(&draft, &so, Some(&two), &o.trust, 1).is_ok());
        // The per-lock minimum raises a trust list's quorum of 1, never
        // lowers it.
        let o1 = ops(1);
        let one = sign(&so, &[&o1.alice]);
        assert!(signed_lock(&draft, &so, Some(&one), &o1.trust, 1).is_ok());
        assert_eq!(
            signed_lock(&draft, &so, Some(&one), &o1.trust, 2).unwrap_err(),
            vec![LockRefusal::MotionQuorumNotMet { have: 1, need: 2 }]
        );
        let policy = OperatorPolicy {
            trust: &o.trust,
            min_motion_quorum: 0,
        };
        assert_eq!(policy.motion_quorum(), 2);
        // A draft without motion channels has no motion items: one signer.
        let mut p = base();
        p.motion_envelopes.clear();
        let d2 = crate::to_json(&p).unwrap();
        let s2 = crate::to_json(&Signoff::for_profile(&p).confirm_all("bob")).unwrap();
        assert!(signed_lock(&d2, &s2, Some(&sign(&s2, &[&o.bob])), &o.trust, 1).is_ok());
    }

    // ------------------------------------------------------ manifest ---

    fn mdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-manifest-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A learn-like output set in `d`: draft, sign-off, report, manifest.
    fn output_set(d: &Path) -> (PathBuf, String, Signoff) {
        let p = base();
        let draft = d.join("draft.json");
        let text = crate::to_json(&p).unwrap();
        let so = Signoff::for_profile(&p);
        let so_path = d.join("draft.json.signoff.json");
        let report = d.join("report.json");
        std::fs::write(&draft, &text).unwrap();
        std::fs::write(&so_path, crate::to_json(&so).unwrap()).unwrap();
        std::fs::write(&report, "{\"r\": 1}\n").unwrap();
        let mp = manifest_path_for(&draft);
        let m = Manifest::new(
            &mp,
            &p.model,
            (&draft, text.as_bytes()),
            Some((&so_path, &so)),
            Some((&report, b"{\"r\": 1}\n".as_slice())),
        );
        assert_eq!(m.draft.path, "draft.json", "same dir: relative");
        std::fs::write(&mp, m.to_text()).unwrap();
        (draft, text, so)
    }

    #[test]
    fn manifest_binds_the_output_set() {
        let d = mdir("set");
        let (draft, text, so) = output_set(&d);
        assert!(verify_manifest(&draft, text.as_bytes(), Some(&so)).is_empty());
        // Recorded sign-off read from disk when none is given.
        assert!(verify_manifest(&draft, text.as_bytes(), None).is_empty());
        // Confirming does not break the binding.
        let c = so.clone().confirm_all("alice");
        assert!(verify_manifest(&draft, text.as_bytes(), Some(&c)).is_empty());

        // Draft replaced (new learn published, manifest from the old one).
        let other = text.replace("\"ugv\"", "\"ugv2\"");
        let why = verify_manifest(&draft, other.as_bytes(), Some(&so));
        assert!(
            why[0].to_string().contains("draft does not match"),
            "{why:?}"
        );
        // A sign-off of another draft.
        let mut q = base();
        q.writer_topics.insert("/odom".into());
        let foreign = Signoff::for_profile(&q);
        let why = verify_manifest(&draft, text.as_bytes(), Some(&foreign));
        assert!(why[0].to_string().contains("stale or foreign"), "{why:?}");
        // Report edited, then missing.
        std::fs::write(d.join("report.json"), "{}\n").unwrap();
        let why = verify_manifest(&draft, text.as_bytes(), Some(&so));
        assert!(
            why[0].to_string().contains("stale or edited report"),
            "{why:?}"
        );
        std::fs::remove_file(d.join("report.json")).unwrap();
        let why = verify_manifest(&draft, text.as_bytes(), Some(&so));
        assert!(why[0].to_string().contains("missing"), "{why:?}");
        // Recorded sign-off missing (none given).
        std::fs::remove_file(d.join("draft.json.signoff.json")).unwrap();
        let why = verify_manifest(&draft, text.as_bytes(), None);
        assert!(why
            .iter()
            .any(|r| r.to_string().contains("sign-off unreadable")));
        // Malformed / foreign-format / missing manifest.
        let mp = manifest_path_for(&draft);
        std::fs::write(&mp, "{").unwrap();
        assert!(matches!(
            verify_manifest(&draft, text.as_bytes(), Some(&so))[0],
            LockRefusal::ManifestMismatch { .. }
        ));
        std::fs::write(&mp, "{\"format\": \"x\"}").unwrap();
        assert!(Manifest::parse("{\"format\": \"x\"}").is_err());
        std::fs::remove_file(&mp).unwrap();
        let why = verify_manifest(&draft, text.as_bytes(), Some(&so));
        assert!(matches!(why[0], LockRefusal::ManifestMissing { .. }));
        assert!(why[0].to_string().contains("--no-manifest"));
        // A manifest that is a directory.
        std::fs::create_dir(&mp).unwrap();
        assert!(matches!(
            verify_manifest(&draft, text.as_bytes(), Some(&so))[0],
            LockRefusal::ManifestMismatch { .. }
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn manifest_paths_and_strict_parse() {
        let d = mdir("paths");
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let mp = d.join("a.json.manifest.json");
        assert_eq!(manifest_entry_path(&mp, &d.join("a.json")), "a.json");
        let other = manifest_entry_path(&mp, &sub.join("r.json"));
        assert!(Path::new(&other).is_absolute(), "{other}");
        assert_eq!(Manifest::resolve(&mp, &other), PathBuf::from(&other));
        assert_eq!(Manifest::resolve(&mp, "a.json"), d.join("a.json"));
        assert_eq!(
            manifest_path_for(Path::new("x/p.json")),
            PathBuf::from("x/p.json.manifest.json")
        );
        let m = Manifest::new(&mp, "m", (&d.join("a.json"), b"x"), None, None);
        let t = m.to_text();
        assert_eq!(Manifest::parse(&t).unwrap(), m);
        assert!(Manifest::parse(&t.replace("\"model\"", "\"x\": 1, \"model\"")).is_err());
        assert!(Manifest::parse(&t.replace("\"model\"", "\"model\": \"y\", \"model\"")).is_err());
        assert!(Manifest::parse(&t.replace(MANIFEST_FORMAT, "v0")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    // ------------------------------------------- bound configuration ---

    /// T12: a bound file (here without any motion channel) needs its own
    /// confirmed item, and that item is under the motion quorum: one
    /// operator cannot make a response policy enforceable alone.
    #[test]
    fn bound_config_needs_its_item_and_the_motion_quorum() {
        let mut p = base();
        p.motion_envelopes.clear();
        let d = format!("sha256:{}", "a".repeat(64));
        p.bound_config.insert("response_policy".into(), d.clone());
        // A list without the binding item: refused by the floor.
        let mut unbound = p.clone();
        unbound.bound_config.clear();
        let mut so = Signoff::for_profile(&unbound).confirm_all("alice");
        so.rebind(crate::signoff::draft_digest(&p));
        let why = lock(&p, &so).unwrap_err();
        assert!(
            why.iter().any(
                |r| matches!(r, LockRefusal::RequiredItemMissing { subject, .. }
                if subject == &format!("response_policy {d}"))
            ),
            "{why:?}"
        );
        // The conservative list carries it; one signer under quorum 2 fails.
        let draft = crate::to_json(&p).unwrap();
        let so = crate::to_json(&Signoff::for_profile(&p).confirm_all("alice")).unwrap();
        let o = ops(2);
        let one = sign(&so, &[&o.alice]);
        let policy = OperatorPolicy {
            trust: &o.trust,
            min_motion_quorum: 1,
        };
        let why =
            lock_signed_draft(&draft, &so, Some(&one), &policy, &HardCaps::default()).unwrap_err();
        assert!(
            why.iter()
                .any(|r| matches!(r, LockRefusal::MotionQuorumNotMet { have: 1, need: 2 })),
            "{why:?}"
        );
        let two = sign(&so, &[&o.alice, &o.bob]);
        let (locked, _) =
            lock_signed_draft(&draft, &so, Some(&two), &policy, &HardCaps::default()).unwrap();
        assert_eq!(locked.bound_config.get("response_policy"), Some(&d));
    }

    /// Review (WP6): `diff` did not show bound_config changes, so a
    /// re-lock review could not see that the policy, executor motion or
    /// firewall binding changed; `merge` drops the bindings (fail closed,
    /// now documented and tested).
    #[test]
    fn diff_shows_bound_config_and_merge_drops_it() {
        let old = base();
        let mut new = old.clone();
        let (a, b) = (
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        );
        let mut old_b = old.clone();
        old_b
            .bound_config
            .insert("response_policy".into(), a.clone());
        old_b
            .bound_config
            .insert("motion_firewall".into(), a.clone());
        new.bound_config.insert("response_policy".into(), b.clone());
        new.bound_config.insert("executor_motion".into(), b.clone());
        let d = diff(&old_b, &new);
        assert!(!d.is_empty());
        assert!(!d.loosens(), "{d}");
        assert_eq!(
            d.bound_config_changes.get("response_policy"),
            Some(&(Some(a.clone()), Some(b.clone())))
        );
        assert_eq!(
            d.bound_config_changes.get("executor_motion"),
            Some(&(None, Some(b.clone())))
        );
        assert_eq!(
            d.bound_config_changes.get("motion_firewall"),
            Some(&(Some(a.clone()), None))
        );
        let text = d.to_string();
        assert!(
            text.contains(&format!("~ bound response_policy: {a} -> {b}")),
            "{text}"
        );
        assert!(text.contains("+ bound executor_motion"), "{text}");
        assert!(text.contains("- bound motion_firewall"), "{text}");
        let j = serde_json::to_value(&d).unwrap();
        assert!(
            j["bound_config_changes"]["response_policy"].is_array(),
            "{j}"
        );
        // Unchanged bindings: nothing reported (and the JSON omits it).
        let d = diff(&new, &new);
        assert!(d.is_empty());
        assert!(serde_json::to_value(&d)
            .unwrap()
            .get("bound_config_changes")
            .is_none());

        let m = merge_profiles(&[old_b, new]).unwrap();
        assert!(m.bound_config.is_empty());
    }
}
