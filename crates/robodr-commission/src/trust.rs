//! Profile authenticity and anti-rollback: detached signatures, trust
//! anchors and the accepted-version state file.
//!
//! The lock seal (`profile_file`) detects edits but not forgery: anyone can
//! recompute a SHA-256. This module adds what makes a locked profile a
//! *signed, versioned artifact*:
//!
//! 1. **Detached signature** (`<profile>.sig`, [`ProfileSignature`]): an
//!    Ed25519 signature (`robodr_blackbox::Ed25519SigningKey`, through the
//!    blackbox `Signer` / `Verifier` traits) over
//!    [`SIG_DOMAIN`]` || <exact bytes of the sealed profile file>`. The file
//!    also names the signing `key_id` and the `sha256:` digest of the
//!    signed bytes (diagnostics; the signature is what is trusted). Signing
//!    the exact bytes means no canonicalisation question can arise: one
//!    changed byte (a space) invalidates it.
//! 2. **Trust anchors** ([`parse_trust_keys`] / [`load_trust_keys`]): a
//!    `robodr-profile-trust/v1` JSON file of Ed25519 *public* keys. Several
//!    keys may be listed (rotation); a signature must verify under the key
//!    its `key_id` names. The file is not secret but its integrity matters,
//!    so it is refused when it is a symlink, not a regular file, or
//!    writable by group or others.
//! 3. **Verification** ([`verify_profile_text`]): strict parse
//!    ([`crate::parse_profile_text`], seal included), then for a **locked**
//!    profile: metadata present (a locked file without metadata is a legacy
//!    profile and is refused: [`ProfileTrustError::LegacyUnversioned`]),
//!    trust anchors configured, a signature present, well formed, for these
//!    bytes and valid under the named trusted key, and the optional
//!    platform / unit expectations met. A draft (unlocked) profile needs no
//!    signature: it is observe-only by construction.
//! 4. **Anti-rollback** ([`check_rollback`] / [`enforce_rollback`]): a
//!    `robodr-profile-state/v1` state file remembers the last accepted
//!    `profile_version` and file digest. A lower version, the same version
//!    with different bytes (equivocation) or a draft after a locked profile
//!    (downgrade to observe) is refused unless the operator names the exact
//!    file digest in an explicit rollback flag. An accepted change is
//!    persisted atomically (temp file, fsync, rename; see
//!    [`crate::write_file_atomic`]).
//! 5. **Black-box witness** ([`reconcile_with_chain`], [`accepted_note`],
//!    [`accepted_from_note`]): every accepted locked profile is also
//!    recorded in the signed, hash-chained black box (a note carrying a
//!    `profile_accepted` object; agentd writes it at start and in every
//!    heartbeat). At the next start the latest such record is the second
//!    witness: a state file that is **missing** or **behind** it (lower
//!    version, other digest, older revocation serial) means the state was
//!    deleted or rewritten; the chain's record is then the baseline (a lower
//!    version stays refused) and a [`StateAlarm`] is raised (agentd reports
//!    it as a Critical, observe-only finding).
//! 6. **Root-signed trust file and monotonic floor** ([`load_trust_file`]):
//!    whenever **trust roots** are configured ([`load_trust_roots`],
//!    `robodr-trust-roots/v1`), the trust file must be signed by one of them
//!    (`<trust>.sig`, domain [`TRUST_SIG_DOMAIN`]); an unsigned or badly
//!    signed trust file is invalid (fail closed), so whoever can rewrite it
//!    can neither add a profile key nor strip what it carries. It may carry
//!    `min_profile_version`, which is honoured only when root-signed (a
//!    floor without roots is invalid). A locked profile below the floor is
//!    refused and `allow_rollback` cannot override it. The highest floor
//!    ever accepted is also kept in the state file and the black-box record
//!    ([`AcceptedState::trust_floor`]): an older root-signed trust file with
//!    a lower floor (replay) never lowers the effective floor.
//! 7. **Revocation list** ([`revocation`]): a `robodr-profile-revocations/v2`
//!    file bound to one `platform`, of revoked profile digests and revoked
//!    signing keys **by public-key fingerprint** ([`key_fingerprint`]), with
//!    a monotonic `serial` and `issued_at`, signed by a trust root (never by
//!    a profile signing key: roots and profile keys must be disjoint). A
//!    revoked profile, a profile signed by a revoked key (whatever `key_id`
//!    it is listed under) or a list for another platform is refused. The
//!    list itself is anti-rollback protected: its serial and digest are
//!    kept in the state file and the black-box record, and an older serial,
//!    the same serial with other content, or a missing list after one was
//!    accepted is refused. A missing list is otherwise allowed or refused by
//!    [`RevocationPolicy`].
//! 8. **Operator attestation** ([`attestation`]): a locked profile carries
//!    its operator sign-off and the operators' signatures
//!    (`metadata.attestation`, embedded by `lock`); the loader verifies them
//!    against the `operators` (and `motion_quorum`) of the trust file, so
//!    the two-person rule is enforced on the unit, not only by the honest
//!    `lock` path. Required by default whenever trust roots are configured
//!    (`require_attestation` in the root-signed trust file can say
//!    otherwise); an unattested profile is then refused
//!    ([`ProfileTrustError::Unattested`]).
//!
//! The whole decision is [`evaluate_profile_trust`]; every loader (sensor
//! pipeline, agentd, replay, `verify-profile`) calls it.
//!
//! Signing keys use the **one** RoboDR key file format, robodr-blackbox's
//! `KeyFile` (`robodr-blackbox-key/v2`, `"kind": "secret"`,
//! `"algorithm": "ed25519"`, 32-byte seed as `secret_hex` plus
//! `public_hex`), so a key from `robodr-commission keygen` or from
//! `robodr-blackbox keygen` (default Ed25519) signs profiles alike
//! ([`load_signing_key`], [`new_signing_key`]). They are loaded with the
//! blackbox's secret-key checks (no symlink, no group/other access, owner
//! the effective user or root). The matching `.pub` public key file
//! (`"kind": "public"`) is what goes into a trust file
//! ([`verifying_keys_from_public_files`]).
//!
//! # Limits (honest list)
//!
//! * The Ed25519 implementation is robodr-blackbox's std-only one: pinned
//!   to RFC 8032 vectors but **not audited** (see that module's docs).
//! * The state file is plain JSON on the unit. Deleting or rewriting it is
//!   now **detected** through the black-box record, not prevented: root can
//!   also delete the black box (detectable off-unit through the export
//!   chain, not on the unit) and then only the signed trust-file floor
//!   remains. Cyclic retention or export pruning can drop old records;
//!   agentd re-records the accepted profile in every heartbeat so the
//!   newest segment carries it. A hardware monotonic counter (TPM NV index)
//!   is the real fix (Phase 2/3). An unreadable or malformed state file
//!   fails closed (refused), it is never silently reset.
//! * The trust file is protected against forgery, not replay: an older
//!   root-signed trust file verifies (with its older key list). Its floor
//!   cannot be lowered that way (the highest accepted floor is remembered,
//!   see 6.), but a re-added profile key must be revoked through the
//!   revocation list, which carries a serial for that reason.
//! * Trust roots cannot be revoked by the list they sign; replace the roots
//!   file instead. `issued_at` is informational (air-gapped units have no
//!   trusted clock): there is no expiry.
//! * Trust-anchor files are checked for symlinks and group/other write
//!   permission, not for ownership.

use crate::profile_file::{
    parse_profile_text, read_regular_file, write_file_atomic, ProfileFileError,
};
use crate::signoff::sha256_hex;
use robodr_blackbox::crypto::{from_hex, to_hex};
use robodr_blackbox::sign::SignError;
use robodr_blackbox::sign_ed25519::{ED25519, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN};
use robodr_blackbox::{Ed25519SigningKey, Ed25519VerifyingKey, KeyFile, Keyring, Signer, Verifier};
use robodr_events::profile::{is_sha256_digest, Profile};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub mod attestation;
pub mod revocation;

use crate::signoff::{OperatorKeyJson, OperatorTrust};
pub use attestation::{attestation_for, content_digest, verify_attestation, AttestationSummary};
pub use revocation::{
    key_fingerprint, load_revocation_list, RevocationList, RevocationPolicy, RevocationSignature,
    MAX_REVOCATION_BYTES, MAX_REVOKED_ENTRIES, REVOCATION_DOMAIN, REVOCATION_FORMAT,
    REVOCATION_FORMAT_V1,
};

/// Domain separation prefix of the signed message.
pub const SIG_DOMAIN: &[u8] = b"robodr-profile-sig/v1\0";
/// `format` of a signature file.
pub const SIG_FORMAT: &str = "robodr-profile-sig/v1";
/// `format` of a trust-anchor file.
pub const TRUST_FORMAT: &str = "robodr-profile-trust/v1";
/// `format` of a trust-roots file (keys that sign revocation lists and
/// trust-file floors; never profiles).
pub const ROOTS_FORMAT: &str = "robodr-trust-roots/v1";
/// `format` of a trust file's detached signature (`<trust>.sig`).
pub const TRUST_SIG_FORMAT: &str = "robodr-profile-trust-sig/v1";
/// Domain separation prefix of a trust file's signed message.
pub const TRUST_SIG_DOMAIN: &[u8] = b"robodr-profile-trust-sig/v1\0";
/// `kind` of the black-box note recording an accepted profile.
pub const ACCEPTED_NOTE_KIND: &str = "robodr.profile_accepted";
/// Top-level member of a black-box note that carries an [`AcceptedState`]
/// (the [`ACCEPTED_NOTE_KIND`] note and agentd's heartbeats).
pub const ACCEPTED_NOTE_FIELD: &str = "profile_accepted";
/// `format` of the anti-rollback state file.
pub const STATE_FORMAT: &str = "robodr-profile-state/v1";
/// Largest signature file read.
pub const MAX_SIG_BYTES: u64 = 16 * 1024;
/// Largest trust-anchor file read.
pub const MAX_TRUST_BYTES: u64 = 256 * 1024;
/// Most keys in one trust-anchor file.
pub const MAX_TRUST_KEYS: usize = 64;
/// Largest state file read.
pub const MAX_STATE_BYTES: u64 = 64 * 1024;

/// Why a profile is not trusted for enforcement. Every variant means
/// "observe-only + `profile_refused`" for a loader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum ProfileTrustError {
    /// No trusted profile keys are configured: a locked profile cannot be
    /// authenticated, so it is not enforced (fail closed).
    NoTrustAnchors,
    /// The trust-anchor file could not be read or is malformed.
    TrustFile { detail: String },
    /// A locked profile without its detached signature file.
    MissingSignature { path: String },
    /// The signature file is unreadable or malformed.
    MalformedSignature { detail: String },
    /// The signature file is for different bytes (its `profile_digest`
    /// does not match this file).
    DigestMismatch { signed: String, file: String },
    /// The signing key is not in the trust anchors.
    UnknownKey { key_id: String },
    /// The signature does not verify under the named trusted key (forged,
    /// tampered bytes, or the wrong key).
    BadSignature { key_id: String },
    /// A locked profile without metadata (locked before profiles were
    /// versioned). Migrate with `robodr-commission migrate-legacy`.
    LegacyUnversioned,
    /// `metadata.platform` is not the platform this unit expects.
    PlatformMismatch { expected: String, found: String },
    /// `metadata.unit_id` names another unit.
    UnitMismatch {
        expected: String,
        found: Option<String>,
    },
    /// `profile_version` is lower than the last accepted one.
    Rollback {
        accepted_version: u64,
        offered_version: u64,
        offered_digest: String,
    },
    /// Same `profile_version` as the accepted one, different bytes.
    Equivocation {
        version: u64,
        accepted_digest: String,
        offered_digest: String,
    },
    /// A draft (unlocked) profile after a locked one was accepted.
    DowngradeToDraft {
        accepted_version: u64,
        offered_digest: String,
    },
    /// The anti-rollback state file is unreadable, malformed or could not
    /// be written.
    State { detail: String },
    /// The trust-roots file could not be read or is malformed, or a key is
    /// both a root and a profile signing key.
    TrustRoots { detail: String },
    /// The revocation list is unreadable, malformed, not signed by a trust
    /// root, or cannot be checked (no roots configured).
    Revocations { detail: String },
    /// `revocation_policy = "required"` and the list file does not exist.
    RevocationListMissing { path: String },
    /// The profile file's digest is revoked.
    RevokedProfile { digest: String, serial: u64 },
    /// The key that signed the profile is revoked (by fingerprint).
    RevokedKey {
        key_id: String,
        fingerprint: String,
        serial: u64,
    },
    /// The revocation list is for another platform than the profile.
    RevocationPlatformMismatch { list: String, profile: String },
    /// The revocation list is older than the last accepted one.
    RevocationRollback {
        accepted_serial: u64,
        offered_serial: u64,
    },
    /// Same revocation serial as the accepted list, different content.
    RevocationEquivocation { serial: u64 },
    /// A revocation list was accepted before and is now missing.
    RevocationListRemoved { accepted_serial: u64 },
    /// `profile_version` is below the root-signed `min_profile_version` of
    /// the trust file, or below the highest floor accepted before (not
    /// overridable by `allow_rollback`).
    BelowFloor { floor: u64, offered_version: u64 },
    /// Attestation is required and the locked profile carries none (no
    /// operator sign-off evidence: legacy, migrated or hand-made).
    Unattested,
    /// The attestation does not verify (see [`attestation`]).
    BadAttestation { detail: String },
    /// Fewer distinct operators signed than the trust file's
    /// `motion_quorum` (sign-off with motion items).
    AttestationQuorumNotMet { have: usize, need: usize },
}

impl fmt::Display for ProfileTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrustAnchors => write!(
                f,
                "no trusted profile keys configured: a locked profile cannot be authenticated"
            ),
            Self::TrustFile { detail } => write!(f, "trusted profile keys: {detail}"),
            Self::MissingSignature { path } => write!(
                f,
                "locked profile has no signature file {path:?} (sign it with `robodr-commission \
                 lock --sign-key` or `sign`)"
            ),
            Self::MalformedSignature { detail } => write!(f, "signature file: {detail}"),
            Self::DigestMismatch { signed, file } => write!(
                f,
                "signature is for {signed}, the profile file is {file} (edited, or the wrong \
                 .sig file)"
            ),
            Self::UnknownKey { key_id } => {
                write!(
                    f,
                    "signed by {key_id:?}, which is not a trusted profile key"
                )
            }
            Self::BadSignature { key_id } => write!(
                f,
                "signature does not verify under trusted key {key_id:?} (forged or tampered)"
            ),
            Self::LegacyUnversioned => write!(
                f,
                "locked profile has no metadata (legacy, unversioned): migrate it with \
                 `robodr-commission migrate-legacy`"
            ),
            Self::PlatformMismatch { expected, found } => write!(
                f,
                "profile is for platform {found:?}, this unit expects {expected:?}"
            ),
            Self::UnitMismatch { expected, found } => write!(
                f,
                "profile is for unit {found:?}, this unit is {expected:?}"
            ),
            Self::Rollback {
                accepted_version,
                offered_version,
                offered_digest,
            } => write!(
                f,
                "rollback refused: profile_version {offered_version} < last accepted \
                 {accepted_version}; to roll back deliberately, name it: allow_rollback = \
                 {offered_digest:?}"
            ),
            Self::Equivocation {
                version,
                accepted_digest,
                offered_digest,
            } => write!(
                f,
                "profile_version {version} was already accepted as {accepted_digest}; this file \
                 is {offered_digest} (two different profiles with one version)"
            ),
            Self::DowngradeToDraft {
                accepted_version,
                offered_digest,
            } => write!(
                f,
                "an unlocked draft replaces locked profile_version {accepted_version}; to accept \
                 it deliberately, name it: allow_rollback = {offered_digest:?}"
            ),
            Self::State { detail } => write!(f, "anti-rollback state: {detail}"),
            Self::TrustRoots { detail } => write!(f, "trust roots: {detail}"),
            Self::Revocations { detail } => write!(f, "revocation list: {detail}"),
            Self::RevocationListMissing { path } => write!(
                f,
                "revocation list {path:?} is missing and revocation_policy is \"required\""
            ),
            Self::RevokedProfile { digest, serial } => write!(
                f,
                "profile {digest} is revoked (revocation list serial {serial})"
            ),
            Self::RevokedKey {
                key_id,
                fingerprint,
                serial,
            } => write!(
                f,
                "signing key {key_id:?} ({fingerprint}) is revoked (revocation list serial \
                 {serial})"
            ),
            Self::RevocationPlatformMismatch { list, profile } => write!(
                f,
                "revocation list is for platform {list:?}, the profile is for {profile:?}"
            ),
            Self::RevocationRollback {
                accepted_serial,
                offered_serial,
            } => write!(
                f,
                "revocation list rollback refused: serial {offered_serial} < last accepted \
                 {accepted_serial}"
            ),
            Self::RevocationEquivocation { serial } => write!(
                f,
                "revocation list serial {serial} was already accepted with other content"
            ),
            Self::RevocationListRemoved { accepted_serial } => write!(
                f,
                "a revocation list (serial {accepted_serial}) was accepted before and is now \
                 missing; install it (or a newer one)"
            ),
            Self::BelowFloor {
                floor,
                offered_version,
            } => write!(
                f,
                "profile_version {offered_version} is below the signed min_profile_version \
                 {floor} (trust file, or the highest floor accepted before)"
            ),
            Self::Unattested => write!(
                f,
                "locked profile carries no operator sign-off attestation (re-lock it with \
                 `robodr-commission lock`, which embeds the signed sign-off); this unit requires \
                 attestation"
            ),
            Self::BadAttestation { detail } => write!(f, "operator attestation: {detail}"),
            Self::AttestationQuorumNotMet { have, need } => write!(
                f,
                "operator attestation: {have} distinct operator(s) signed a sign-off with motion \
                 items; the trust file's motion_quorum is {need} (two-person rule)"
            ),
        }
    }
}

impl std::error::Error for ProfileTrustError {}

impl From<ProfileTrustError> for ProfileFileError {
    fn from(reason: ProfileTrustError) -> Self {
        ProfileFileError::Untrusted { reason }
    }
}

/// `sha256:<hex>` of exact file bytes (the identity used for signatures,
/// lineage, rollback flags and the state file).
pub fn file_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// The detached signature path of a profile: the file name with `.sig`
/// appended (`locked.json` -> `locked.json.sig`).
pub fn sig_path_for(profile: &Path) -> PathBuf {
    let mut s = profile.as_os_str().to_os_string();
    s.push(".sig");
    PathBuf::from(s)
}

/// The message that is signed: [`SIG_DOMAIN`] followed by the exact bytes.
pub fn signed_message(profile_bytes: &[u8]) -> Vec<u8> {
    signed_message_for(SigKind::Profile, profile_bytes)
}

/// What a detached signature file signs: a profile or a trust file. Each
/// has its own `format` and domain, so one can never stand in for the
/// other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigKind {
    /// `<profile>.sig` ([`SIG_FORMAT`], [`SIG_DOMAIN`]).
    Profile,
    /// `<trust>.sig` ([`TRUST_SIG_FORMAT`], [`TRUST_SIG_DOMAIN`]).
    TrustFile,
}

impl SigKind {
    /// The signature file's `format`.
    pub fn format(self) -> &'static str {
        match self {
            Self::Profile => SIG_FORMAT,
            Self::TrustFile => TRUST_SIG_FORMAT,
        }
    }

    /// The domain prefix of the signed message.
    pub fn domain(self) -> &'static [u8] {
        match self {
            Self::Profile => SIG_DOMAIN,
            Self::TrustFile => TRUST_SIG_DOMAIN,
        }
    }
}

/// `kind.domain() || bytes`.
pub fn signed_message_for(kind: SigKind, bytes: &[u8]) -> Vec<u8> {
    let d = kind.domain();
    let mut m = Vec::with_capacity(d.len() + bytes.len());
    m.extend_from_slice(d);
    m.extend_from_slice(bytes);
    m
}

// ------------------------------------------------------------ signature --

/// A detached signature file: `robodr-profile-sig/v1` for a profile,
/// `robodr-profile-trust-sig/v1` for a trust file ([`SigKind`]).
/// `profile_digest` is the [`file_digest`] of the signed file, whichever
/// kind it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSignature {
    pub format: String,
    pub algorithm: String,
    pub key_id: String,
    /// [`file_digest`] of the signed bytes.
    pub profile_digest: String,
    pub signature_hex: String,
}

impl ProfileSignature {
    /// Sign the exact bytes of a (sealed) profile file.
    pub fn create(profile_bytes: &[u8], signer: &dyn Signer) -> Result<Self, SignError> {
        Self::create_for(SigKind::Profile, profile_bytes, signer)
    }

    /// Sign the exact bytes of a file of `kind`.
    pub fn create_for(
        kind: SigKind,
        profile_bytes: &[u8],
        signer: &dyn Signer,
    ) -> Result<Self, SignError> {
        let sig = signer.sign(&signed_message_for(kind, profile_bytes))?;
        Ok(Self {
            format: kind.format().into(),
            algorithm: signer.algorithm().into(),
            key_id: signer.key_id().into(),
            profile_digest: file_digest(profile_bytes),
            signature_hex: to_hex(&sig),
        })
    }

    /// The `.sig` file text (pretty JSON, trailing newline).
    pub fn to_text(&self) -> String {
        crate::to_json(self).unwrap_or_default()
    }

    /// Parse a profile `.sig` file (unknown keys and duplicate keys
    /// refused).
    pub fn parse(text: &str) -> Result<Self, ProfileTrustError> {
        Self::parse_for(SigKind::Profile, text)
    }

    /// Parse a `.sig` file of `kind` (errors are
    /// [`ProfileTrustError::MalformedSignature`]).
    pub fn parse_for(kind: SigKind, text: &str) -> Result<Self, ProfileTrustError> {
        let bad = |detail: String| ProfileTrustError::MalformedSignature { detail };
        crate::profile_file::reject_duplicate_keys(text).map_err(|e| bad(e.to_string()))?;
        let s: Self = serde_json::from_str(text).map_err(|e| bad(e.to_string()))?;
        if s.format != kind.format() {
            return Err(bad(format!(
                "format {:?}, expected {:?}",
                s.format,
                kind.format()
            )));
        }
        if s.algorithm != ED25519 {
            return Err(bad(format!(
                "algorithm {:?} is not supported (only {ED25519:?})",
                s.algorithm
            )));
        }
        if !is_sha256_digest(&s.profile_digest) {
            return Err(bad("profile_digest is not sha256:<64 hex>".into()));
        }
        match from_hex(&s.signature_hex) {
            Some(b) if b.len() == SIGNATURE_LEN => {}
            _ => {
                return Err(bad(format!(
                    "signature_hex is not {SIGNATURE_LEN} bytes of hex"
                )))
            }
        }
        Ok(s)
    }

    /// Check this signature against `profile_bytes` under the trusted key
    /// it names.
    pub fn verify(&self, profile_bytes: &[u8], anchors: &Keyring) -> Result<(), ProfileTrustError> {
        self.verify_for(SigKind::Profile, profile_bytes, anchors)
    }

    /// Check this signature against the bytes of a file of `kind` under the
    /// key of `anchors` it names.
    pub fn verify_for(
        &self,
        kind: SigKind,
        profile_bytes: &[u8],
        anchors: &Keyring,
    ) -> Result<(), ProfileTrustError> {
        let digest = file_digest(profile_bytes);
        if self.profile_digest != digest {
            return Err(ProfileTrustError::DigestMismatch {
                signed: self.profile_digest.clone(),
                file: digest,
            });
        }
        let Some(key) = anchors.get(&self.key_id) else {
            return Err(ProfileTrustError::UnknownKey {
                key_id: self.key_id.clone(),
            });
        };
        let sig = from_hex(&self.signature_hex).unwrap_or_default();
        if self.format != kind.format()
            || key.algorithm() != self.algorithm
            || !key.verify(&signed_message_for(kind, profile_bytes), &sig)
        {
            return Err(ProfileTrustError::BadSignature {
                key_id: self.key_id.clone(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------- trust keys --

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustKeyJson {
    algorithm: String,
    key_id: String,
    public_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustJson {
    format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min_profile_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    require_attestation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    motion_quorum: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operators: Option<Vec<OperatorKeyJson>>,
    keys: Vec<TrustKeyJson>,
}

/// A parsed key-list file.
struct KeyList {
    keys: Vec<Ed25519VerifyingKey>,
    floor: Option<u64>,
    require_attestation: Option<bool>,
    operators: Option<OperatorTrust>,
}

impl KeyList {
    fn has_trust_file_members(&self) -> bool {
        self.floor.is_some() || self.require_attestation.is_some() || self.operators.is_some()
    }
}

/// Parse a key-list file (`format` must be `expected`): at least one key,
/// at most [`MAX_TRUST_KEYS`], Ed25519 only, canonical non-small-order
/// public keys, no duplicate key id or public key; the optional members
/// (`min_profile_version`, `require_attestation`, `operators` +
/// `motion_quorum`, checked by [`OperatorTrust::from_entries`]).
fn parse_key_list(text: &str, expected: &str) -> Result<KeyList, String> {
    crate::profile_file::reject_duplicate_keys(text).map_err(|e| e.to_string())?;
    let j: TrustJson = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if j.format != expected {
        return Err(format!("format {:?}, expected {expected:?}", j.format));
    }
    if j.keys.is_empty() {
        return Err("no keys".into());
    }
    if j.keys.len() > MAX_TRUST_KEYS {
        return Err(format!("more than {MAX_TRUST_KEYS} keys"));
    }
    let mut out: Vec<Ed25519VerifyingKey> = Vec::with_capacity(j.keys.len());
    for k in j.keys {
        if k.algorithm != ED25519 {
            return Err(format!(
                "key {:?}: algorithm {:?} is not supported (only {ED25519:?})",
                k.key_id, k.algorithm
            ));
        }
        let public: [u8; PUBLIC_KEY_LEN] = from_hex(&k.public_hex)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                format!(
                    "key {:?}: public_hex is not {PUBLIC_KEY_LEN} bytes of hex",
                    k.key_id
                )
            })?;
        let vk = Ed25519VerifyingKey::from_bytes(k.key_id.clone(), &public)
            .map_err(|e| format!("key {:?}: {e}", k.key_id))?;
        if out
            .iter()
            .any(|o| Verifier::key_id(o) == k.key_id || o.as_bytes() == vk.as_bytes())
        {
            return Err(format!("key {:?}: listed twice", k.key_id));
        }
        out.push(vk);
    }
    let operators = match (j.operators, j.motion_quorum) {
        (None, None) => None,
        (None, Some(_)) => return Err("motion_quorum without operators".into()),
        (Some(ops), q) => Some(
            OperatorTrust::from_entries(ops, q.unwrap_or(1))
                .map_err(|e| format!("operators: {e}"))?,
        ),
    };
    if let Some(ops) = &operators {
        if let Some(k) = ops
            .public_keys()
            .find(|o| out.iter().any(|k| k.as_bytes() == o.as_bytes()))
        {
            return Err(format!(
                "operators: key {:?} is also a profile signing key (operators and profile keys \
                 must be distinct: one person would both sign off and sign)",
                Verifier::key_id(k)
            ));
        }
    }
    Ok(KeyList {
        keys: out,
        floor: j.min_profile_version,
        require_attestation: j.require_attestation,
        operators,
    })
}

fn ring_of(keys: &[Ed25519VerifyingKey]) -> Result<Keyring, String> {
    let mut ring = Keyring::new();
    for k in keys {
        ring.add(Box::new(k.clone()))
            .map_err(|e| format!("key {:?}: {e}", Verifier::key_id(k)))?;
    }
    Ok(ring)
}

/// Parse a trust-anchor file's text into a keyring of Ed25519 verifying
/// keys. Refuses an empty list, a duplicate key id, a non-Ed25519 key and
/// an invalid (non-canonical or small-order) public key. A
/// `min_profile_version` is parsed but not returned: use
/// [`parse_trust_file`] / [`load_trust_file`], which also check its
/// signature.
pub fn parse_trust_keys(text: &str) -> Result<Keyring, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::TrustFile { detail };
    let l = parse_key_list(text, TRUST_FORMAT).map_err(bad)?;
    ring_of(&l.keys).map_err(bad)
}

/// Read a trust-anchor file: regular file (not a symlink), not writable by
/// group or others, size-capped; then [`parse_trust_keys`]. Ignores a
/// `min_profile_version` (use [`load_trust_file`] for the full check).
pub fn load_trust_keys(path: &Path) -> Result<Keyring, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::TrustFile {
        detail: format!("{}: {detail}", path.display()),
    };
    let text = read_protected(path, MAX_TRUST_BYTES).map_err(|e| bad(e.to_string()))?;
    parse_trust_keys(&text).map_err(|e| match e {
        ProfileTrustError::TrustFile { detail } => bad(detail),
        other => other,
    })
}

/// The text of a trust-anchor file listing `keys`.
pub fn trust_keys_text(keys: &[Ed25519VerifyingKey]) -> String {
    trust_file_text(keys, None)
}

fn key_list_text(format: &str, keys: &[Ed25519VerifyingKey], opt: &TrustFileOptions<'_>) -> String {
    let j = TrustJson {
        format: format.into(),
        min_profile_version: opt.min_profile_version,
        require_attestation: opt.require_attestation,
        motion_quorum: opt.operators.map(OperatorTrust::motion_quorum),
        operators: opt.operators.map(OperatorTrust::entries),
        keys: keys
            .iter()
            .map(|k| TrustKeyJson {
                algorithm: ED25519.into(),
                key_id: Verifier::key_id(k).into(),
                public_hex: to_hex(k.as_bytes()),
            })
            .collect(),
    };
    crate::to_json(&j).unwrap_or_default()
}

/// The text of a trust-anchor file listing `keys`, with an optional
/// `min_profile_version` floor (which must then be signed by a trust root:
/// [`ProfileSignature::create_for`] with [`SigKind::TrustFile`] over these
/// exact bytes, written to [`sig_path_for`] the trust file).
pub fn trust_file_text(keys: &[Ed25519VerifyingKey], floor: Option<u64>) -> String {
    trust_file_text_with(
        keys,
        &TrustFileOptions {
            min_profile_version: floor,
            ..Default::default()
        },
    )
}

/// Optional members of a trust file ([`trust_file_text_with`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustFileOptions<'a> {
    /// `min_profile_version` (needs a root signature).
    pub min_profile_version: Option<u64>,
    /// `require_attestation` (`None`: required iff trust roots are
    /// configured on the unit).
    pub require_attestation: Option<bool>,
    /// `operators` and `motion_quorum`: who may attest a profile.
    pub operators: Option<&'a OperatorTrust>,
}

/// The text of a trust file listing `keys` with the optional members of
/// `opt`.
pub fn trust_file_text_with(keys: &[Ed25519VerifyingKey], opt: &TrustFileOptions<'_>) -> String {
    key_list_text(TRUST_FORMAT, keys, opt)
}

/// Trust roots: the keys that sign revocation lists and trust-file floors
/// (`robodr-trust-roots/v1`). They never sign profiles.
#[derive(Debug)]
pub struct TrustRoots {
    pub keys: Keyring,
    pub public_keys: Vec<Ed25519VerifyingKey>,
}

impl TrustRoots {
    /// Refuse a profile key that is also a root (same id or same public
    /// key): one key compromise must not defeat both signature and
    /// revocation.
    pub fn check_disjoint(&self, profile_keys: &[Ed25519VerifyingKey]) -> Result<(), String> {
        for p in profile_keys {
            if let Some(r) = self.public_keys.iter().find(|r| {
                Verifier::key_id(*r) == Verifier::key_id(p) || r.as_bytes() == p.as_bytes()
            }) {
                return Err(format!(
                    "profile key {:?} is also trust root {:?}: roots and profile signing keys \
                     must be distinct",
                    Verifier::key_id(p),
                    Verifier::key_id(r)
                ));
            }
        }
        Ok(())
    }
}

/// Parse a trust-roots file (`robodr-trust-roots/v1`, same key-list layout
/// as a trust file, no `min_profile_version`).
pub fn parse_trust_roots(text: &str) -> Result<TrustRoots, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::TrustRoots { detail };
    let l = parse_key_list(text, ROOTS_FORMAT).map_err(bad)?;
    if l.has_trust_file_members() {
        return Err(bad(
            "min_profile_version / require_attestation / operators belong in the trust file".into(),
        ));
    }
    Ok(TrustRoots {
        keys: ring_of(&l.keys).map_err(bad)?,
        public_keys: l.keys,
    })
}

/// Read a trust-roots file with the trust-file protections (no symlink,
/// regular file, not writable by group/others, size cap).
pub fn load_trust_roots(path: &Path) -> Result<TrustRoots, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::TrustRoots {
        detail: format!("{}: {detail}", path.display()),
    };
    let text = read_protected(path, MAX_TRUST_BYTES).map_err(|e| bad(e.to_string()))?;
    parse_trust_roots(&text).map_err(|e| match e {
        ProfileTrustError::TrustRoots { detail } => bad(detail),
        other => other,
    })
}

/// The text of a trust-roots file listing `keys`.
pub fn trust_roots_text(keys: &[Ed25519VerifyingKey]) -> String {
    key_list_text(ROOTS_FORMAT, keys, &TrustFileOptions::default())
}

/// A trust-anchor file with its optional signed members.
#[derive(Debug)]
pub struct TrustFile {
    pub keys: Keyring,
    pub public_keys: Vec<Ed25519VerifyingKey>,
    /// Root-signed `min_profile_version` (`None`: no floor).
    pub min_profile_version: Option<u64>,
    /// Trust root that signed the file (`None`: unsigned, only possible
    /// without trust roots).
    pub signed_by: Option<String>,
    /// Who may attest a locked profile (`operators` + `motion_quorum`).
    pub operators: Option<OperatorTrust>,
    /// Whether a locked profile must carry a valid operator attestation:
    /// `require_attestation` if the file says, else `true` exactly when
    /// trust roots are configured.
    pub require_attestation: bool,
}

/// Parse a trust file and check its detached signature `sig_text` (the
/// `<trust>.sig` content, if any) against `roots`:
///
/// * with roots configured the file **must** be signed by one of them (no
///   signature or a bad one: error, fail closed), and no profile key may be
///   a root ([`TrustRoots::check_disjoint`]) or an operator;
/// * without roots, a `min_profile_version` is refused (it cannot be
///   authenticated);
/// * attestation is required when the file says so, by default when roots
///   are configured; then `operators` must be listed.
pub fn parse_trust_file(
    text: &str,
    sig_text: Option<&str>,
    sig_name: &str,
    roots: Option<&TrustRoots>,
) -> Result<TrustFile, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::TrustFile { detail };
    let l = parse_key_list(text, TRUST_FORMAT).map_err(bad)?;
    if l.floor == Some(0) {
        return Err(bad("min_profile_version must be >= 1".into()));
    }
    if let Some(r) = roots {
        r.check_disjoint(&l.keys).map_err(bad)?;
        if let Some(ops) = &l.operators {
            let ops: Vec<Ed25519VerifyingKey> = ops.public_keys().cloned().collect();
            if let Some(o) = ops
                .iter()
                .find(|o| r.public_keys.iter().any(|k| k.as_bytes() == o.as_bytes()))
            {
                return Err(bad(format!(
                    "operator key {:?} is also a trust root: roots and operator keys must be \
                     distinct",
                    Verifier::key_id(o)
                )));
            }
        }
    }
    let signed_by = match (sig_text, roots) {
        (Some(st), Some(r)) => {
            let sig = ProfileSignature::parse_for(SigKind::TrustFile, st)
                .map_err(|e| bad(format!("{sig_name}: {e}")))?;
            sig.verify_for(SigKind::TrustFile, text.as_bytes(), &r.keys)
                .map_err(|e| bad(format!("{sig_name}: {e} (trust roots)")))?;
            Some(sig.key_id)
        }
        (None, Some(_)) => {
            return Err(bad(format!(
                "trust roots are configured, so the trust file must be signed by one \
                 ({sig_name} is missing; `robodr-commission trust-keys ... --sign-key ROOT.key`)"
            )))
        }
        (_, None) => None,
    };
    if l.floor.is_some() && signed_by.is_none() {
        return Err(bad(format!(
            "min_profile_version is set but the file is not signed by a trust root \
             ({sig_name} missing, or no trust_roots configured)"
        )));
    }
    let require_attestation = l.require_attestation.unwrap_or(roots.is_some());
    if require_attestation && l.operators.is_none() {
        return Err(bad(
            "operator attestation is required (the default with trust roots) but the file lists \
             no operators: add them (`trust-keys --operators operators.json`) or set \
             require_attestation: false"
                .into(),
        ));
    }
    Ok(TrustFile {
        keys: ring_of(&l.keys).map_err(bad)?,
        public_keys: l.keys,
        min_profile_version: l.floor,
        signed_by,
        operators: l.operators,
        require_attestation,
    })
}

/// Read a trust file (protected like [`load_trust_keys`]) and its optional
/// `<trust>.sig`, then [`parse_trust_file`].
pub fn load_trust_file(
    path: &Path,
    roots: Option<&TrustRoots>,
) -> Result<TrustFile, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::TrustFile {
        detail: format!("{}: {detail}", path.display()),
    };
    let text = read_protected(path, MAX_TRUST_BYTES).map_err(|e| bad(e.to_string()))?;
    let sig_path = sig_path_for(path);
    let sig =
        read_optional_sig(&sig_path).map_err(|e| bad(format!("{}: {e}", sig_path.display())))?;
    parse_trust_file(
        &text,
        sig.as_deref(),
        &sig_path.display().to_string(),
        roots,
    )
    .map_err(|e| match e {
        ProfileTrustError::TrustFile { detail } => bad(detail),
        other => other,
    })
}

/// Read a file that others must not be able to modify: no symlink at
/// `path`, a regular file, `mode & 0o022 == 0`, at most `max` bytes.
fn read_protected(path: &Path, max: u64) -> io::Result<String> {
    let lmeta = std::fs::symlink_metadata(path)?;
    if lmeta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "is a symbolic link (refused)",
        ));
    }
    let f = File::open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.ino() != lmeta.ino() || meta.dev() != lmeta.dev() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file changed while opening",
            ));
        }
        let mode = meta.mode() & 0o7777;
        if mode & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("mode {mode:04o} lets group/others modify it; chmod go-w"),
            ));
        }
    }
    let mut s = String::new();
    f.take(max + 1).read_to_string(&mut s)?;
    if s.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("larger than {max} bytes"),
        ));
    }
    Ok(s)
}

// --------------------------------------------------------- signing keys --

/// Load an Ed25519 signing key from a secret key file
/// (`robodr-blackbox-key/v2`, `"kind": "secret"`, `"algorithm": "ed25519"`,
/// as written by `robodr-commission keygen` or `robodr-blackbox keygen`; the
/// older v1 Ed25519 layout is still read). The blackbox's checks apply
/// (`KeyFile::load_secret`: no symlink, mode without group/other bits,
/// owned by the effective user or root). A `.pub` file is refused.
pub fn load_signing_key(path: &Path) -> Result<Ed25519SigningKey, String> {
    let kf = KeyFile::load_secret(path).map_err(|e| format!("{}: {e}", path.display()))?;
    signing_key_from_file(&kf).map_err(|e| format!("{}: {e}", path.display()))
}

/// The Ed25519 signing key held by a key file.
pub fn signing_key_from_file(kf: &KeyFile) -> Result<Ed25519SigningKey, String> {
    if kf.algorithm != ED25519 {
        return Err(format!(
            "key algorithm {:?} cannot sign profiles (need {ED25519:?})",
            kf.algorithm
        ));
    }
    if kf.is_public() {
        return Err("a public key file cannot sign profiles (need the secret key file)".into());
    }
    kf.ed25519_signing_key().map_err(|e| e.to_string())
}

/// A fresh Ed25519 signing key as a blackbox key file (write it with
/// `KeyFile::write_new`: format v2, mode 0600; `KeyFile::to_public` gives
/// the `.pub` file) plus its verifying key for the trust file. Without
/// `key_id` the id is derived from the public key.
pub fn new_signing_key(key_id: Option<&str>) -> Result<(KeyFile, Ed25519VerifyingKey), String> {
    let kf = KeyFile::generate_ed25519(key_id).map_err(|e| e.to_string())?;
    let vk = kf.ed25519_verifying_key().map_err(|e| e.to_string())?;
    Ok((kf, vk))
}

/// The key file for an existing seed (tests, re-imports).
pub fn key_file_for_seed(
    seed: &[u8; SEED_LEN],
    key_id: Option<&str>,
) -> Result<(KeyFile, Ed25519VerifyingKey), String> {
    let kf = KeyFile::ed25519_from_seed(seed, key_id).map_err(|e| e.to_string())?;
    let vk = kf.ed25519_verifying_key().map_err(|e| e.to_string())?;
    Ok((kf, vk))
}

/// Trusted verifying keys from Ed25519 **public** key files (`.pub`,
/// `robodr-blackbox-key/v2` `"kind": "public"`), for [`trust_keys_text`].
/// A file with secret material, an HMAC key or a duplicate key id is
/// refused.
pub fn verifying_keys_from_public_files(
    paths: &[&Path],
) -> Result<Vec<Ed25519VerifyingKey>, String> {
    let mut out: Vec<Ed25519VerifyingKey> = Vec::new();
    for p in paths {
        let kf = KeyFile::load_public(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let vk = kf
            .ed25519_verifying_key()
            .map_err(|e| format!("{}: {e}", p.display()))?;
        if out
            .iter()
            .any(|k| Verifier::key_id(k) == Verifier::key_id(&vk))
        {
            return Err(format!(
                "{}: key id {:?} listed twice",
                p.display(),
                Verifier::key_id(&vk)
            ));
        }
        out.push(vk);
    }
    Ok(out)
}

// --------------------------------------------------------- verification --

/// What a verifier trusts and expects.
#[derive(Debug, Default)]
pub struct TrustPolicy {
    /// Trusted profile signing keys; `None` = none configured (every locked
    /// profile is refused).
    pub anchors: Option<Keyring>,
    /// `metadata.platform` must equal this, if set.
    pub expect_platform: Option<String>,
    /// `metadata.unit_id` must be `None` (fleet-wide) or equal this, if set.
    pub expect_unit_id: Option<String>,
    /// The public keys behind `anchors` (gives
    /// [`VerifiedProfile::signer_fingerprint`], which revocation needs).
    pub anchor_keys: Vec<Ed25519VerifyingKey>,
    /// Require a valid operator attestation on a locked profile, verified
    /// against `operators` (missing operators: every locked profile is
    /// refused).
    pub require_attestation: bool,
    /// Who may attest (the trust file's `operators` / `motion_quorum`).
    pub operators: Option<OperatorTrust>,
}

/// A profile that passed [`verify_profile_text`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedProfile {
    pub profile: Profile,
    /// [`file_digest`] of the exact file bytes.
    pub digest: String,
    /// Key id that signed it (`None` for a draft).
    pub signed_by: Option<String>,
    /// [`key_fingerprint`] of the signing key (`None` for a draft, or when
    /// the policy did not provide the public keys).
    pub signer_fingerprint: Option<String>,
    /// The verified operator attestation (`None` when not required or a
    /// draft).
    pub attestation: Option<AttestationSummary>,
}

impl VerifiedProfile {
    /// `profile_version` of a locked profile, `None` for a draft.
    pub fn version(&self) -> Option<u64> {
        self.profile.metadata.as_ref().map(|m| m.profile_version)
    }
}

/// Verify a profile file's exact text and its detached signature (see the
/// module docs). `sig_text` is the `.sig` file's content, `None` if there
/// is none; `sig_name` names it in errors.
pub fn verify_profile_text(
    text: &str,
    sig_text: Option<&str>,
    sig_name: &str,
    policy: &TrustPolicy,
) -> Result<VerifiedProfile, ProfileFileError> {
    let profile = parse_profile_text(text)?;
    let digest = file_digest(text.as_bytes());
    if !profile.locked {
        return Ok(VerifiedProfile {
            profile,
            digest,
            signed_by: None,
            signer_fingerprint: None,
            attestation: None,
        });
    }
    let Some(meta) = profile.metadata.as_ref() else {
        return Err(ProfileTrustError::LegacyUnversioned.into());
    };
    let anchors = match &policy.anchors {
        Some(a) if !a.is_empty() => a,
        _ => return Err(ProfileTrustError::NoTrustAnchors.into()),
    };
    let sig_text = sig_text.ok_or_else(|| ProfileTrustError::MissingSignature {
        path: sig_name.into(),
    })?;
    let sig = ProfileSignature::parse(sig_text)?;
    sig.verify(text.as_bytes(), anchors)?;
    // Expectations are checked only on authenticated metadata.
    if let Some(p) = &policy.expect_platform {
        if &meta.platform != p {
            return Err(ProfileTrustError::PlatformMismatch {
                expected: p.clone(),
                found: meta.platform.clone(),
            }
            .into());
        }
    }
    if let (Some(u), Some(found)) = (&policy.expect_unit_id, &meta.unit_id) {
        if found != u {
            return Err(ProfileTrustError::UnitMismatch {
                expected: u.clone(),
                found: Some(found.clone()),
            }
            .into());
        }
    }
    let signer_fingerprint = policy
        .anchor_keys
        .iter()
        .find(|k| Verifier::key_id(*k) == sig.key_id)
        .map(|k| key_fingerprint(k.as_bytes()));
    let attestation = if policy.require_attestation {
        let Some(ops) = &policy.operators else {
            return Err(ProfileTrustError::BadAttestation {
                detail: "attestation is required but no operators are configured".into(),
            }
            .into());
        };
        Some(verify_attestation(&profile, ops)?)
    } else {
        None
    };
    Ok(VerifiedProfile {
        profile,
        digest,
        signed_by: Some(sig.key_id),
        signer_fingerprint,
        attestation,
    })
}

/// Read a profile file and its `.sig` ([`sig_path_for`], if any) and
/// verify them. The outer error is an I/O error on the profile itself
/// (unreadable, not a regular file, too large); an unreadable `.sig` of a
/// locked profile is [`ProfileTrustError::MalformedSignature`].
pub fn verify_profile_file(
    path: &Path,
    policy: &TrustPolicy,
) -> io::Result<Result<VerifiedProfile, ProfileFileError>> {
    let text = read_regular_file(path, crate::profile_file::MAX_PROFILE_BYTES)?;
    let sig_path = sig_path_for(path);
    let sig = read_optional_sig(&sig_path);
    let sig_name = sig_path.display().to_string();
    Ok(match sig {
        Ok(s) => verify_profile_text(&text, s.as_deref(), &sig_name, policy),
        // A draft does not need the signature: report the read error only
        // where a signature is required.
        Err(e) => match verify_profile_text(&text, None, &sig_name, policy) {
            Err(ProfileFileError::Untrusted {
                reason: ProfileTrustError::MissingSignature { .. },
            }) => Err(ProfileTrustError::MalformedSignature {
                detail: format!("{sig_name}: {e}"),
            }
            .into()),
            other => other,
        },
    })
}

/// The `.sig` file's text; `Ok(None)` if it does not exist.
pub fn read_optional_sig(path: &Path) -> io::Result<Option<String>> {
    read_optional_text(path, MAX_SIG_BYTES)
}

/// A regular file's text (size-capped); `Ok(None)` if it does not exist.
fn read_optional_text(path: &Path, max: u64) -> io::Result<Option<String>> {
    match read_regular_file(path, max) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The profile-version label carried in findings
/// (`entity_context.profile.version`): the decimal `profile_version` of a
/// locked profile that passed the trust check, `"draft"` for an unlocked
/// profile, `"untrusted"` for a locked profile that did not (its metadata
/// is not authenticated, so it is not repeated), `"unversioned"` for a
/// trusted locked profile without metadata (in-memory profiles only).
pub fn version_label(profile: &Profile, trusted: bool) -> String {
    match (&profile.metadata, profile.locked, trusted) {
        (_, false, _) => "draft".into(),
        (_, true, false) => "untrusted".into(),
        (Some(m), true, true) => m.profile_version.to_string(),
        (None, true, true) => "unversioned".into(),
    }
}

// ------------------------------------------------------- anti-rollback --

/// The anti-rollback state: the last accepted locked profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedState {
    pub format: String,
    pub model: String,
    pub platform: String,
    pub unit_id: Option<String>,
    pub profile_version: u64,
    /// [`file_digest`] of the accepted file.
    pub digest: String,
    /// `serial` of the last accepted revocation list (`None`: none yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_serial: Option<u64>,
    /// [`RevocationList::digest`] of that list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_digest: Option<String>,
    /// The highest root-signed `min_profile_version` accepted so far
    /// (`None`: none). A trust file with a lower floor never lowers it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_floor: Option<u64>,
}

impl AcceptedState {
    /// The state recording `v` (a locked, verified profile), with no
    /// revocation list.
    pub fn of(v: &VerifiedProfile) -> Option<Self> {
        let m = v.profile.metadata.as_ref()?;
        Some(Self {
            format: STATE_FORMAT.into(),
            model: v.profile.model.clone(),
            platform: m.platform.clone(),
            unit_id: m.unit_id.clone(),
            profile_version: m.profile_version,
            digest: v.digest.clone(),
            revocation_serial: None,
            revocation_digest: None,
            trust_floor: None,
        })
    }

    /// Structural check (format, digests, version, revocation pair, floor).
    pub fn validate(&self) -> Result<(), String> {
        if self.format != STATE_FORMAT {
            return Err(format!(
                "format {:?}, expected {STATE_FORMAT:?}",
                self.format
            ));
        }
        if !is_sha256_digest(&self.digest) || self.profile_version == 0 {
            return Err("malformed digest or version".into());
        }
        if self.trust_floor == Some(0) {
            return Err("trust_floor must be >= 1".into());
        }
        match (&self.revocation_serial, &self.revocation_digest) {
            (None, None) => Ok(()),
            (Some(s), Some(d)) if *s >= 1 && is_sha256_digest(d) => Ok(()),
            _ => Err("malformed revocation_serial / revocation_digest".into()),
        }
    }

    fn revocation(&self) -> Option<(u64, &str)> {
        Some((self.revocation_serial?, self.revocation_digest.as_deref()?))
    }
}

/// What [`check_rollback`] decided for an acceptable profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackDecision {
    /// No state yet: first profile (written to the state if locked).
    First,
    /// Exactly the accepted profile again (state unchanged).
    Same,
    /// A higher version (state updated).
    Upgrade,
    /// Lower / equivocating version or a draft, accepted because the
    /// operator named its digest (state updated for a locked profile).
    OperatorRollback,
    /// A draft with no locked profile accepted before (state unchanged).
    Draft,
}

impl RollbackDecision {
    /// Whether the state file must be (re)written for this decision.
    pub fn writes_state(self, v: &VerifiedProfile) -> bool {
        v.profile.locked && matches!(self, Self::First | Self::Upgrade | Self::OperatorRollback)
    }
}

/// `allow_rollback` must be a [`file_digest`].
pub fn validate_rollback_flag(flag: &str) -> Result<(), String> {
    if is_sha256_digest(flag) {
        Ok(())
    } else {
        Err(format!(
            "allow_rollback {flag:?} must be the exact file digest sha256:<64 lower-case hex> \
             (printed by `robodr-commission verify-profile`)"
        ))
    }
}

/// Decide whether `v` may replace `state` (pure; see the module docs).
/// `allow` is the operator's rollback flag: the digest of the one file
/// that may be accepted despite being older (or a draft).
pub fn check_rollback(
    state: Option<&AcceptedState>,
    v: &VerifiedProfile,
    allow: Option<&str>,
) -> Result<RollbackDecision, ProfileTrustError> {
    let named = allow == Some(v.digest.as_str());
    let Some(st) = state else {
        return Ok(if v.profile.locked {
            RollbackDecision::First
        } else {
            RollbackDecision::Draft
        });
    };
    let Some(version) = v.version().filter(|_| v.profile.locked) else {
        return if named {
            Ok(RollbackDecision::OperatorRollback)
        } else {
            Err(ProfileTrustError::DowngradeToDraft {
                accepted_version: st.profile_version,
                offered_digest: v.digest.clone(),
            })
        };
    };
    use std::cmp::Ordering::*;
    match version.cmp(&st.profile_version) {
        Greater => Ok(RollbackDecision::Upgrade),
        Equal if v.digest == st.digest => Ok(RollbackDecision::Same),
        _ if named => Ok(RollbackDecision::OperatorRollback),
        Equal => Err(ProfileTrustError::Equivocation {
            version,
            accepted_digest: st.digest.clone(),
            offered_digest: v.digest.clone(),
        }),
        Less => Err(ProfileTrustError::Rollback {
            accepted_version: st.profile_version,
            offered_version: version,
            offered_digest: v.digest.clone(),
        }),
    }
}

/// Read the state file; `Ok(None)` if it does not exist. Anything else
/// that is not a well-formed state is an error (fail closed).
pub fn load_state(path: &Path) -> Result<Option<AcceptedState>, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::State {
        detail: format!("{}: {detail}", path.display()),
    };
    let text = match read_regular_file(path, MAX_STATE_BYTES) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(bad(e.to_string())),
    };
    crate::profile_file::reject_duplicate_keys(&text).map_err(|e| bad(e.to_string()))?;
    let s: AcceptedState = serde_json::from_str(&text).map_err(|e| bad(e.to_string()))?;
    s.validate().map_err(bad)?;
    Ok(Some(s))
}

/// Persist `state` atomically (temp file + fsync + rename + directory
/// fsync; never through a symlink).
pub fn store_state(path: &Path, state: &AcceptedState) -> Result<(), ProfileTrustError> {
    let text = crate::to_json(state).map_err(|e| ProfileTrustError::State {
        detail: e.to_string(),
    })?;
    write_file_atomic(path, text.as_bytes(), true).map_err(|e| ProfileTrustError::State {
        detail: format!("{}: {e}", path.display()),
    })
}

/// [`load_state`], [`check_rollback`], and [`store_state`] when the
/// decision changes the accepted profile. Nothing is written on refusal.
pub fn enforce_rollback(
    state_path: &Path,
    v: &VerifiedProfile,
    allow: Option<&str>,
) -> Result<RollbackDecision, ProfileTrustError> {
    let state = load_state(state_path)?;
    let d = check_rollback(state.as_ref(), v, allow)?;
    if d.writes_state(v) {
        if let Some(s) = AcceptedState::of(v) {
            store_state(state_path, &s)?;
        }
    }
    Ok(d)
}

// ------------------------------------------------- black-box witness --

/// The black-box note recording an accepted profile ([`ACCEPTED_NOTE_KIND`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedNote {
    pub kind: String,
    /// What was accepted (the same record the state file holds).
    pub profile_accepted: AcceptedState,
    /// Key id that signed the profile.
    pub signed_by: Option<String>,
    /// [`RollbackDecision`] of this load, as text (`None` without
    /// anti-rollback state).
    pub decision: Option<String>,
}

/// The note to append to the black box when `accepted` is enforced.
pub fn accepted_note(
    accepted: &AcceptedState,
    signed_by: Option<&str>,
    decision: Option<RollbackDecision>,
) -> AcceptedNote {
    AcceptedNote {
        kind: ACCEPTED_NOTE_KIND.into(),
        profile_accepted: accepted.clone(),
        signed_by: signed_by.map(str::to_string),
        decision: decision.map(|d| format!("{d:?}")),
    }
}

/// The [`AcceptedState`] a black-box note payload carries in its top-level
/// [`ACCEPTED_NOTE_FIELD`] member (an [`AcceptedNote`] or an agentd
/// heartbeat), if any and well formed. Never panics on hostile bytes.
pub fn accepted_from_note(payload: &[u8]) -> Option<AcceptedState> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let a = v.as_object()?.get(ACCEPTED_NOTE_FIELD)?;
    let s: AcceptedState = serde_json::from_value(a.clone()).ok()?;
    s.validate().ok().map(|()| s)
}

/// Why the state file disagrees with the black box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateAlarmReason {
    /// No state file, but the black box recorded an accepted profile.
    StateMissing,
    /// The state file is older than the black box's record (lower
    /// version, other digest for the same version, an older revocation
    /// list, or a lower trust floor).
    StateBehindChain,
}

/// Evidence that the anti-rollback state was deleted or rewritten (see the
/// module docs). Report it as Critical; it never by itself requests any
/// action on the robot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StateAlarm {
    pub reason: StateAlarmReason,
    /// The state file's content (`None`: missing).
    pub state: Option<AcceptedState>,
    /// The latest black-box record.
    pub chain: AcceptedState,
}

impl fmt::Display for StateAlarm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = &self.chain;
        match (&self.reason, &self.state) {
            (StateAlarmReason::StateMissing, _) | (_, None) => write!(
                f,
                "anti-rollback state file is missing but the black box recorded accepted \
                 profile_version {} ({}): the state was deleted; the recorded version is \
                 enforced as the floor",
                c.profile_version, c.digest
            ),
            (StateAlarmReason::StateBehindChain, Some(s)) => write!(
                f,
                "anti-rollback state (profile_version {}, {}, revocation serial {:?}) is behind \
                 the black box record (profile_version {}, {}, revocation serial {:?}): the \
                 state was rewritten or an operator rollback did not complete; the black-box \
                 record is the baseline",
                s.profile_version,
                s.digest,
                s.revocation_serial,
                c.profile_version,
                c.digest,
                c.revocation_serial
            ),
        }
    }
}

/// Combine the state file with the latest black-box record: the effective
/// anti-rollback baseline and, if they disagree in the state's disfavour,
/// a [`StateAlarm`]. The profile part of the baseline is the chain's when
/// the state is missing or behind it (lower version, or same version and
/// other digest), else the state's; the revocation part is the higher
/// serial (the chain's on a tie with other content); the trust floor is
/// the higher one. A state *ahead* of the chain is normal (accepted, then
/// stopped before the note was written) and raises nothing.
pub fn reconcile_with_chain(
    state: Option<&AcceptedState>,
    chain: Option<&AcceptedState>,
) -> (Option<AcceptedState>, Option<StateAlarm>) {
    let Some(c) = chain else {
        return (state.cloned(), None);
    };
    let Some(s) = state else {
        return (
            Some(c.clone()),
            Some(StateAlarm {
                reason: StateAlarmReason::StateMissing,
                state: None,
                chain: c.clone(),
            }),
        );
    };
    let profile_behind = c.profile_version > s.profile_version
        || (c.profile_version == s.profile_version && c.digest != s.digest);
    let rev_behind = match (s.revocation(), c.revocation()) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some((ss, sd)), Some((cs, cd))) => cs > ss || (cs == ss && cd != sd),
    };
    let floor_behind = c.trust_floor > s.trust_floor;
    let mut base = if profile_behind { c.clone() } else { s.clone() };
    let rev_src = if rev_behind { c } else { s };
    base.revocation_serial = rev_src.revocation_serial;
    base.revocation_digest = rev_src.revocation_digest.clone();
    base.trust_floor = s.trust_floor.max(c.trust_floor);
    let alarm = (profile_behind || rev_behind || floor_behind).then(|| StateAlarm {
        reason: StateAlarmReason::StateBehindChain,
        state: Some(s.clone()),
        chain: c.clone(),
    });
    (Some(base), alarm)
}

// ------------------------------------------------------------ evaluator --

/// Everything [`evaluate_profile_trust`] reads, as configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustInputs<'a> {
    /// `robodr-profile-trust/v1` file (`None`: no locked profile trusted).
    pub trusted_keys: Option<&'a Path>,
    /// `robodr-trust-roots/v1` file (signs revocation lists and floors).
    pub trust_roots: Option<&'a Path>,
    /// `robodr-profile-revocations/v2` file.
    pub revocation_list: Option<&'a Path>,
    /// What a missing revocation list means.
    pub revocation_policy: RevocationPolicy,
    pub expect_platform: Option<&'a str>,
    pub expect_unit_id: Option<&'a str>,
    /// Anti-rollback state file (`None`: no rollback check, the chain is
    /// not consulted either).
    pub state_file: Option<&'a Path>,
    /// Operator rollback flag (exact digest).
    pub allow_rollback: Option<&'a str>,
    /// Latest accepted-profile record from the black box (see
    /// [`reconcile_with_chain`]).
    pub chain: Option<&'a AcceptedState>,
}

/// A profile [`evaluate_profile_trust`] accepts.
#[derive(Debug, Clone, PartialEq)]
pub struct Accepted {
    pub verified: VerifiedProfile,
    /// The rollback decision (`None` without a state file).
    pub decision: Option<RollbackDecision>,
    /// The state file content to persist before enforcing (`None`:
    /// unchanged). A failed write must refuse the profile.
    pub state_write: Option<AcceptedState>,
    /// What to record in the black box once enforcing ([`accepted_note`]);
    /// `Some` for every accepted locked profile.
    pub record: Option<AcceptedState>,
}

/// The outcome of [`evaluate_profile_trust`].
#[derive(Debug, Clone, PartialEq)]
pub struct TrustEvaluation {
    pub result: Result<Accepted, ProfileFileError>,
    /// The state file disagrees with the black box (reported whatever the
    /// result).
    pub alarm: Option<StateAlarm>,
}

/// The full trust decision for the profile at `path` whose exact text is
/// `raw` (the `.sig` is read next to it): strict file check, signature
/// under the trust file's keys, trust roots and the trust file's signed
/// floor, revocation list (validity, freshness, revoked digest / key),
/// platform / unit, and anti-rollback against the state file reconciled
/// with the black-box record. Nothing is written. Drafts need neither
/// signature nor revocation check (they are observe-only); a broken trust
/// configuration matters only for a locked profile.
pub fn evaluate_profile_trust(path: &Path, raw: &str, inp: &TrustInputs<'_>) -> TrustEvaluation {
    let base = inp.state_file.map(|sp| {
        load_state(sp).map(|cur| {
            let (b, a) = reconcile_with_chain(cur.as_ref(), inp.chain);
            (cur, b, a)
        })
    });
    let alarm = match &base {
        Some(Ok((_, _, a))) => a.clone(),
        _ => None,
    };
    TrustEvaluation {
        result: evaluate_inner(path, raw, inp, base),
        alarm,
    }
}

type Baseline = Result<
    (
        Option<AcceptedState>,
        Option<AcceptedState>,
        Option<StateAlarm>,
    ),
    ProfileTrustError,
>;

fn evaluate_inner(
    path: &Path,
    raw: &str,
    inp: &TrustInputs<'_>,
    base: Option<Baseline>,
) -> Result<Accepted, ProfileFileError> {
    let roots = inp.trust_roots.map(load_trust_roots);
    let tf = inp.trusted_keys.map(|p| match &roots {
        // Roots are configured but unusable: the trust file cannot be
        // authenticated (reported as the roots error for a locked profile
        // below).
        Some(Err(e)) => Err(e.clone()),
        Some(Ok(r)) => load_trust_file(p, Some(r)),
        None => load_trust_file(p, None),
    });
    let (policy, floor, setup_err) = match tf {
        None => (TrustPolicy::default(), None, None),
        Some(Ok(tf)) => (
            TrustPolicy {
                anchors: Some(tf.keys),
                anchor_keys: tf.public_keys,
                require_attestation: tf.require_attestation,
                operators: tf.operators,
                ..Default::default()
            },
            tf.min_profile_version,
            None,
        ),
        Some(Err(e)) => (TrustPolicy::default(), None, Some(e)),
    };
    let policy = TrustPolicy {
        expect_platform: inp.expect_platform.map(str::to_string),
        expect_unit_id: inp.expect_unit_id.map(str::to_string),
        ..policy
    };
    let sig_path = sig_path_for(path);
    let sig_name = sig_path.display().to_string();
    let verified = match read_optional_sig(&sig_path) {
        Ok(sig) => verify_profile_text(raw, sig.as_deref(), &sig_name, &policy),
        Err(e) => match verify_profile_text(raw, None, &sig_name, &policy) {
            Err(ProfileFileError::Untrusted {
                reason: ProfileTrustError::MissingSignature { .. },
            }) if policy.anchors.is_some() => Err(ProfileTrustError::MalformedSignature {
                detail: format!("{sig_name}: {e}"),
            }
            .into()),
            other => other,
        },
    };
    let verified = match (verified, setup_err) {
        (
            Err(ProfileFileError::Untrusted {
                reason: ProfileTrustError::NoTrustAnchors,
            }),
            Some(e),
        ) => return Err(e.into()),
        (v, _) => v?,
    };
    let locked = verified.profile.locked;
    // The baseline (state file reconciled with the black box), if any.
    let (current, baseline) = match base {
        None => (None, None),
        Some(b) => {
            let (c, bl, _) = b?;
            (Some(c), Some(bl))
        }
    };
    let remembered_floor = baseline.as_ref().and_then(|b| b.as_ref()?.trust_floor);
    let floor = floor.max(remembered_floor);
    let mut revocation: Option<(u64, String)> = None;
    if locked {
        let roots = match roots {
            None => None,
            Some(Ok(r)) => Some(r),
            Some(Err(e)) => return Err(e.into()),
        };
        match inp.revocation_list {
            Some(p) => {
                let Some(r) = roots.as_ref() else {
                    return Err(ProfileTrustError::Revocations {
                        detail: "no trust_roots configured: the list cannot be authenticated"
                            .into(),
                    }
                    .into());
                };
                match load_revocation_list(p, r)? {
                    Some(list) => {
                        list.check(&verified)?;
                        revocation = Some((list.serial, list.digest()));
                    }
                    None if inp.revocation_policy == RevocationPolicy::Required => {
                        return Err(ProfileTrustError::RevocationListMissing {
                            path: p.display().to_string(),
                        }
                        .into())
                    }
                    None => {}
                }
            }
            None if inp.revocation_policy == RevocationPolicy::Required => {
                return Err(ProfileTrustError::RevocationListMissing {
                    path: "(revocation_list not configured)".into(),
                }
                .into())
            }
            None => {}
        }
        if let (Some(f), Some(v)) = (floor, verified.version()) {
            if v < f {
                return Err(ProfileTrustError::BelowFloor {
                    floor: f,
                    offered_version: v,
                }
                .into());
            }
        }
    }
    let record = AcceptedState::of(&verified)
        .filter(|_| locked)
        .map(|mut s| {
            if let Some((serial, digest)) = &revocation {
                s.revocation_serial = Some(*serial);
                s.revocation_digest = Some(digest.clone());
            }
            s.trust_floor = floor;
            s
        });
    let Some(baseline) = baseline else {
        return Ok(Accepted {
            verified,
            decision: None,
            state_write: None,
            record,
        });
    };
    if locked {
        if let Some((bs, bd)) = baseline.as_ref().and_then(AcceptedState::revocation) {
            match &revocation {
                None => {
                    return Err(ProfileTrustError::RevocationListRemoved {
                        accepted_serial: bs,
                    }
                    .into())
                }
                Some((s, _)) if *s < bs => {
                    return Err(ProfileTrustError::RevocationRollback {
                        accepted_serial: bs,
                        offered_serial: *s,
                    }
                    .into())
                }
                Some((s, d)) if *s == bs && d != bd => {
                    return Err(ProfileTrustError::RevocationEquivocation { serial: bs }.into())
                }
                Some(_) => {}
            }
        }
    }
    let decision = check_rollback(baseline.as_ref(), &verified, inp.allow_rollback)?;
    let current = current.flatten();
    let state_write = match &record {
        Some(r) if current.as_ref() != Some(r) => Some(r.clone()),
        _ => None,
    };
    Ok(Accepted {
        verified,
        decision: Some(decision),
        state_write,
        record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_file::sealed_text;
    use robodr_blackbox::sign_ed25519::derive_key_id;
    use robodr_events::profile::{
        Envelope, ProfileAttestation, ProfileMetadata, PROFILE_SCHEMA_VERSION,
    };

    fn key(n: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed(format!("k{n}"), &[n; 32]).unwrap()
    }

    fn ring(keys: &[&Ed25519SigningKey]) -> Keyring {
        let vks: Vec<_> = keys.iter().map(|k| k.verifying_key()).collect();
        parse_trust_keys(&trust_keys_text(&vks)).unwrap()
    }

    fn policy(keys: &[&Ed25519SigningKey]) -> TrustPolicy {
        TrustPolicy {
            anchors: Some(ring(keys)),
            ..Default::default()
        }
    }

    fn locked(version: u64) -> Profile {
        let mut p = Profile {
            model: "m".into(),
            locked: true,
            metadata: Some(ProfileMetadata {
                schema_version: PROFILE_SCHEMA_VERSION,
                profile_version: version,
                platform: "ugv".into(),
                unit_id: None,
                locked_by: "op".into(),
                locked_at: 1_790_000_000,
                parent_digest: None,
                attestation: None,
            }),
            ..Default::default()
        };
        p.participants.insert("a".repeat(24));
        p.writer_topics.insert("/cmd_vel".into());
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(1.0),
                max_joint_speed: None,
                ..Default::default()
            },
        );
        p
    }

    fn signed(p: &Profile, k: &Ed25519SigningKey) -> (String, String) {
        let text = sealed_text(p).unwrap();
        let sig = ProfileSignature::create(text.as_bytes(), k).unwrap();
        (text, sig.to_text())
    }

    fn untrusted(r: Result<VerifiedProfile, ProfileFileError>) -> ProfileTrustError {
        match r {
            Err(ProfileFileError::Untrusted { reason }) => reason,
            other => panic!("expected untrusted, got {other:?}"),
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let k = key(1);
        let (text, sig) = signed(&locked(1), &k);
        let v = verify_profile_text(&text, Some(&sig), "x.sig", &policy(&[&k])).unwrap();
        assert_eq!(v.profile, locked(1));
        assert_eq!(v.signed_by.as_deref(), Some("k1"));
        assert_eq!(v.digest, file_digest(text.as_bytes()));
        assert_eq!(v.version(), Some(1));
        // A ring with several keys (rotation) still picks the right one.
        let k2 = key(2);
        assert!(verify_profile_text(&text, Some(&sig), "x", &policy(&[&k2, &k])).is_ok());
    }

    #[test]
    fn wrong_key_unknown_key_and_forged_key_id() {
        let k = key(1);
        let other = key(2);
        let (text, sig) = signed(&locked(1), &k);
        assert_eq!(
            untrusted(verify_profile_text(
                &text,
                Some(&sig),
                "x",
                &policy(&[&other])
            )),
            ProfileTrustError::UnknownKey {
                key_id: "k1".into()
            }
        );
        // Attacker signs with their own key but claims the trusted key id.
        let impostor = Ed25519SigningKey::from_seed("k1", &[9; 32]).unwrap();
        let (_, forged) = signed(&locked(1), &impostor);
        assert_eq!(
            untrusted(verify_profile_text(
                &text,
                Some(&forged),
                "x",
                &policy(&[&k])
            )),
            ProfileTrustError::BadSignature {
                key_id: "k1".into()
            }
        );
        // An HMAC signer cannot produce an accepted signature file.
        let h = robodr_blackbox::HmacSha256Key::new("k1", &[7; 32]).unwrap();
        let hs = ProfileSignature::create(text.as_bytes(), &h)
            .unwrap()
            .to_text();
        assert!(matches!(
            untrusted(verify_profile_text(&text, Some(&hs), "x", &policy(&[&k]))),
            ProfileTrustError::MalformedSignature { .. }
        ));
    }

    #[test]
    fn tampered_bytes_are_refused() {
        let k = key(1);
        let (text, sig) = signed(&locked(1), &k);
        // Content edit: the seal catches it first.
        let edited = text.replace("1.0", "9.0");
        assert!(verify_profile_text(&edited, Some(&sig), "x", &policy(&[&k])).is_err());
        // A forger edits and re-seals (recomputes the hash): the signature
        // catches it.
        let mut p = locked(1);
        p.participants.insert("b".repeat(24));
        let resealed = sealed_text(&p).unwrap();
        assert!(matches!(
            untrusted(verify_profile_text(
                &resealed,
                Some(&sig),
                "x",
                &policy(&[&k])
            )),
            ProfileTrustError::DigestMismatch { .. }
        ));
        // Digest field rewritten to match, signature still the old one.
        let mut s = ProfileSignature::parse(&sig).unwrap();
        s.profile_digest = file_digest(resealed.as_bytes());
        assert!(matches!(
            untrusted(verify_profile_text(
                &resealed,
                Some(&s.to_text()),
                "x",
                &policy(&[&k])
            )),
            ProfileTrustError::BadSignature { .. }
        ));
        // Every single-bit flip of the signature is refused.
        let good = ProfileSignature::parse(&sig).unwrap();
        let raw = from_hex(&good.signature_hex).unwrap();
        for i in 0..raw.len() * 8 {
            let mut b = raw.clone();
            b[i / 8] ^= 1 << (i % 8);
            let mut s = good.clone();
            s.signature_hex = to_hex(&b);
            assert!(s.verify(text.as_bytes(), &ring(&[&k])).is_err(), "bit {i}");
        }
    }

    #[test]
    fn missing_or_malformed_signature() {
        let k = key(1);
        let (text, sig) = signed(&locked(1), &k);
        assert_eq!(
            untrusted(verify_profile_text(&text, None, "p.sig", &policy(&[&k]))),
            ProfileTrustError::MissingSignature {
                path: "p.sig".into()
            }
        );
        for bad in [
            "",
            "{}",
            "[]",
            &sig.replace(SIG_FORMAT, "robodr-profile-sig/v9"),
            &sig.replace("\"format\"", "\"format\": \"x\",\n  \"format\""),
            &sig.replace("\"key_id\"", "\"extra\": 1,\n  \"key_id\""),
            &sig.replace("sha256:", "md5:"),
        ] {
            assert!(
                matches!(
                    untrusted(verify_profile_text(&text, Some(bad), "x", &policy(&[&k]))),
                    ProfileTrustError::MalformedSignature { .. }
                ),
                "{bad}"
            );
        }
        // Truncated signature hex.
        let mut s = ProfileSignature::parse(&sig).unwrap();
        s.signature_hex.truncate(10);
        assert!(ProfileSignature::parse(&s.to_text()).is_err());
    }

    #[test]
    fn no_anchors_legacy_and_drafts() {
        let k = key(1);
        let (text, sig) = signed(&locked(1), &k);
        assert_eq!(
            untrusted(verify_profile_text(
                &text,
                Some(&sig),
                "x",
                &TrustPolicy::default()
            )),
            ProfileTrustError::NoTrustAnchors
        );
        let empty = TrustPolicy {
            anchors: Some(Keyring::new()),
            ..Default::default()
        };
        assert_eq!(
            untrusted(verify_profile_text(&text, Some(&sig), "x", &empty)),
            ProfileTrustError::NoTrustAnchors
        );
        // Legacy: sealed, locked, no metadata -> refused even if signed.
        let mut legacy = locked(1);
        legacy.metadata = None;
        let (lt, ls) = signed(&legacy, &k);
        assert_eq!(
            untrusted(verify_profile_text(&lt, Some(&ls), "x", &policy(&[&k]))),
            ProfileTrustError::LegacyUnversioned
        );
        // Draft: no signature needed, no anchors needed.
        let mut draft = locked(1);
        draft.locked = false;
        draft.metadata = None;
        let dt = crate::to_json(&draft).unwrap();
        let v = verify_profile_text(&dt, None, "x", &TrustPolicy::default()).unwrap();
        assert!(v.signed_by.is_none() && v.version().is_none());
    }

    #[test]
    fn platform_and_unit_binding() {
        let k = key(1);
        let mut p = locked(1);
        p.metadata.as_mut().unwrap().unit_id = Some("ugv-007".into());
        let (text, sig) = signed(&p, &k);
        let mut pol = policy(&[&k]);
        pol.expect_platform = Some("ugv".into());
        pol.expect_unit_id = Some("ugv-007".into());
        assert!(verify_profile_text(&text, Some(&sig), "x", &pol).is_ok());
        pol.expect_unit_id = Some("ugv-008".into());
        assert!(matches!(
            untrusted(verify_profile_text(&text, Some(&sig), "x", &pol)),
            ProfileTrustError::UnitMismatch { .. }
        ));
        pol.expect_unit_id = None;
        pol.expect_platform = Some("drone".into());
        assert!(matches!(
            untrusted(verify_profile_text(&text, Some(&sig), "x", &pol)),
            ProfileTrustError::PlatformMismatch { .. }
        ));
        // Fleet-wide profile (unit_id null) is fine for any unit.
        let (t2, s2) = signed(&locked(1), &k);
        let mut pol = policy(&[&k]);
        pol.expect_unit_id = Some("ugv-008".into());
        assert!(verify_profile_text(&t2, Some(&s2), "x", &pol).is_ok());
    }

    #[test]
    fn trust_file_rules() {
        let k = key(1);
        let text = trust_keys_text(&[k.verifying_key()]);
        assert_eq!(parse_trust_keys(&text).unwrap().key_ids(), ["k1"]);
        let dup = trust_keys_text(&[k.verifying_key(), k.verifying_key()]);
        assert!(parse_trust_keys(&dup).is_err());
        assert!(parse_trust_keys(&text.replace(TRUST_FORMAT, "x")).is_err());
        assert!(parse_trust_keys(&text.replace("ed25519\"", "hmac-sha256\"")).is_err());
        assert!(parse_trust_keys(r#"{"format":"robodr-profile-trust/v1","keys":[]}"#).is_err());
        // Small-order public key (the identity point) is refused.
        let mut ident = [0u8; 32];
        ident[0] = 1;
        let bad = text.replace(&to_hex(k.verifying_key().as_bytes()), &to_hex(&ident));
        assert!(parse_trust_keys(&bad).is_err());
        assert!(parse_trust_keys("not json").is_err());
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "robodr-commission-trust-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    #[test]
    fn trust_file_permissions_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("perm");
        let p = d.join("trust.json");
        std::fs::write(&p, trust_keys_text(&[key(1).verifying_key()])).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_trust_keys(&p).is_ok());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(load_trust_keys(&p)
            .unwrap_err()
            .to_string()
            .contains("chmod"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let l = d.join("link.json");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(load_trust_keys(&l).is_err());
        assert!(load_trust_keys(&d).is_err());
        assert!(load_trust_keys(&d.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn signing_key_files() {
        let d = tmpdir("keys");
        let (kf, vk) = key_file_for_seed(&[5; 32], None).unwrap();
        assert_eq!(kf.algorithm, ED25519);
        assert_eq!(kf.key_id, derive_key_id(vk.as_bytes()));
        let p = d.join("sign.key");
        kf.write_new(&p).unwrap();
        let sk = load_signing_key(&p).unwrap();
        assert_eq!(sk.public_key(), *vk.as_bytes());
        // An HMAC key file cannot sign profiles.
        let h = KeyFile::hmac_from_secret(&[1; 32], None).unwrap();
        assert!(signing_key_from_file(&h).is_err());
        let (named, _) = key_file_for_seed(&[5; 32], Some("oem-2026")).unwrap();
        assert_eq!(named.key_id, "oem-2026");
        assert!(key_file_for_seed(&[5; 32], Some("bad id")).is_err());
        let (fresh, fvk) = new_signing_key(None).unwrap();
        assert_eq!(
            signing_key_from_file(&fresh).unwrap().public_key(),
            *fvk.as_bytes()
        );
        // One format: the blackbox KeyFile v2 (secret + .pub).
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.contains(robodr_blackbox::keys::KEY_FILE_FORMAT_V2),
            "{text}"
        );
        let pubp = robodr_blackbox::keys::public_key_path(&p);
        kf.to_public().unwrap().write_new(&pubp).unwrap();
        // A public key file cannot sign...
        let e = load_signing_key(&pubp).unwrap_err();
        assert!(e.contains("secret") || e.contains("no secret"), "{e}");
        assert!(signing_key_from_file(&kf.to_public().unwrap()).is_err());
        // ... but builds a trust file that verifies the secret's signatures.
        let vks = verifying_keys_from_public_files(&[pubp.as_path()]).unwrap();
        assert_eq!(vks[0].as_bytes(), vk.as_bytes());
        let ring = parse_trust_keys(&trust_keys_text(&vks)).unwrap();
        let sig = sk.sign(b"m").unwrap();
        assert!(ring.verify_as(Signer::key_id(&sk), b"m", &sig));
        // Secret files, duplicates and HMAC keys are refused as trust input.
        assert!(verifying_keys_from_public_files(&[p.as_path()]).is_err());
        assert!(verifying_keys_from_public_files(&[pubp.as_path(), pubp.as_path()]).is_err());
        // A key written by the blackbox's own generator signs profiles too.
        let bb = KeyFile::generate_ed25519(Some("bb-key")).unwrap();
        let bbp = d.join("bb.key");
        bb.write_new(&bbp).unwrap();
        assert_eq!(
            load_signing_key(&bbp).unwrap().public_key(),
            bb.public_key().unwrap()
        );
        // Legacy v1 Ed25519 layout (written before KeyFile v2) still loads.
        let v1 = d.join("v1.key");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&v1)
                .unwrap();
            write!(
                f,
                "{{\"format\":\"robodr-blackbox-key/v1\",\"algorithm\":\"ed25519\",\
                 \"key_id\":\"old\",\"secret_hex\":\"{}\"}}",
                to_hex(&[5; 32])
            )
            .unwrap();
        }
        assert_eq!(load_signing_key(&v1).unwrap().public_key(), *vk.as_bytes());
        let _ = std::fs::remove_dir_all(&d);
    }

    fn verified(version: u64, salt: &str) -> VerifiedProfile {
        let mut p = locked(version);
        p.model = format!("m{salt}");
        VerifiedProfile {
            digest: file_digest(format!("{version}{salt}").as_bytes()),
            profile: p,
            signed_by: Some("k1".into()),
            signer_fingerprint: Some(kfp("k1")),
            attestation: None,
        }
    }

    #[test]
    fn hostile_sig_trust_and_state_text_never_panics() {
        let k = key(1);
        let (text, sig) = signed(&locked(1), &k);
        let trust = trust_keys_text(&[k.verifying_key()]);
        let st = crate::to_json(&AcceptedState {
            format: STATE_FORMAT.into(),
            model: "m".into(),
            platform: "p".into(),
            unit_id: None,
            profile_version: 1,
            digest: file_digest(b"x"),
            revocation_serial: None,
            revocation_digest: None,
            trust_floor: Some(2),
        })
        .unwrap();
        let anchors = ring(&[&k]);
        for n in 0..sig.trim_end().len() {
            assert!(
                ProfileSignature::parse(&sig[..n]).is_err(),
                "sig prefix {n}"
            );
        }
        for n in 0..trust.trim_end().len() {
            assert!(parse_trust_keys(&trust[..n]).is_err(), "trust prefix {n}");
        }
        for n in 0..st.trim_end().len() {
            assert!(serde_json::from_str::<AcceptedState>(&st[..n]).is_err());
        }
        // Byte-flipped variants: never panic, never verify.
        let mut x: u32 = 0x9e37_79b9;
        for _ in 0..500 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let mut b = sig.clone().into_bytes();
            let i = x as usize % b.len();
            b[i] = (x >> 8) as u8;
            if let Ok(t) = String::from_utf8(b) {
                if t != sig {
                    if let Ok(s) = ProfileSignature::parse(&t) {
                        let _ = s.verify(text.as_bytes(), &anchors);
                    }
                }
            }
        }
        // Oversized NaN-ish numbers in state.
        let bad = st.replace("\"profile_version\": 1", "\"profile_version\": 1e400");
        assert!(serde_json::from_str::<AcceptedState>(&bad).is_err());
    }

    #[test]
    fn version_labels() {
        let p = locked(42);
        assert_eq!(version_label(&p, true), "42");
        assert_eq!(version_label(&p, false), "untrusted");
        let mut d = p.clone();
        d.locked = false;
        assert_eq!(version_label(&d, true), "draft");
        d.locked = true;
        d.metadata = None;
        assert_eq!(version_label(&d, true), "unversioned");
    }

    #[test]
    fn rollback_rules() {
        let v3 = verified(3, "");
        let st = AcceptedState::of(&v3).unwrap();
        assert_eq!(check_rollback(None, &v3, None), Ok(RollbackDecision::First));
        assert_eq!(
            check_rollback(Some(&st), &v3, None),
            Ok(RollbackDecision::Same)
        );
        assert_eq!(
            check_rollback(Some(&st), &verified(4, ""), None),
            Ok(RollbackDecision::Upgrade)
        );
        let v2 = verified(2, "");
        assert!(matches!(
            check_rollback(Some(&st), &v2, None),
            Err(ProfileTrustError::Rollback {
                accepted_version: 3,
                offered_version: 2,
                ..
            })
        ));
        // The flag must name exactly this file.
        assert!(check_rollback(Some(&st), &v2, Some(&v3.digest)).is_err());
        assert_eq!(
            check_rollback(Some(&st), &v2, Some(&v2.digest)),
            Ok(RollbackDecision::OperatorRollback)
        );
        let eq = verified(3, "other");
        assert!(matches!(
            check_rollback(Some(&st), &eq, None),
            Err(ProfileTrustError::Equivocation { version: 3, .. })
        ));
        assert_eq!(
            check_rollback(Some(&st), &eq, Some(&eq.digest)),
            Ok(RollbackDecision::OperatorRollback)
        );
        let mut draft = verified(1, "d");
        draft.profile.locked = false;
        draft.profile.metadata = None;
        assert!(matches!(
            check_rollback(Some(&st), &draft, None),
            Err(ProfileTrustError::DowngradeToDraft { .. })
        ));
        let d = check_rollback(Some(&st), &draft, Some(&draft.digest)).unwrap();
        assert_eq!(d, RollbackDecision::OperatorRollback);
        assert!(!d.writes_state(&draft));
        assert_eq!(
            check_rollback(None, &draft, None),
            Ok(RollbackDecision::Draft)
        );
        // u64 edges.
        let max = verified(u64::MAX, "");
        assert_eq!(
            check_rollback(Some(&st), &max, None),
            Ok(RollbackDecision::Upgrade)
        );
        assert!(validate_rollback_flag(&v2.digest).is_ok());
        assert!(validate_rollback_flag("2").is_err());
    }

    #[test]
    fn state_persisted_atomically_and_fails_closed() {
        let d = tmpdir("state");
        let sp = d.join("profile-state.json");
        let v3 = verified(3, "");
        assert_eq!(
            enforce_rollback(&sp, &v3, None),
            Ok(RollbackDecision::First)
        );
        assert_eq!(load_state(&sp).unwrap(), AcceptedState::of(&v3));
        // Refusal writes nothing.
        let before = std::fs::read(&sp).unwrap();
        assert!(enforce_rollback(&sp, &verified(2, ""), None).is_err());
        assert_eq!(std::fs::read(&sp).unwrap(), before);
        // Upgrade rewrites; no temp files left behind.
        let v5 = verified(5, "");
        assert_eq!(
            enforce_rollback(&sp, &v5, None),
            Ok(RollbackDecision::Upgrade)
        );
        assert_eq!(load_state(&sp).unwrap().unwrap().profile_version, 5);
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        // Operator rollback to 3 lowers the baseline.
        assert_eq!(
            enforce_rollback(&sp, &v3, Some(&v3.digest)),
            Ok(RollbackDecision::OperatorRollback)
        );
        assert_eq!(load_state(&sp).unwrap().unwrap().profile_version, 3);
        // Corrupt state: refused, not reset.
        for bad in ["", "{}", "garbage", r#"{"format":"x"}"#] {
            std::fs::write(&sp, bad).unwrap();
            assert!(matches!(
                enforce_rollback(&sp, &v5, None),
                Err(ProfileTrustError::State { .. })
            ));
            assert_eq!(std::fs::read(&sp).unwrap(), bad.as_bytes());
        }
        // A directory where the state should be: refused.
        std::fs::remove_file(&sp).unwrap();
        std::fs::create_dir(&sp).unwrap();
        assert!(enforce_rollback(&sp, &v5, None).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn verify_profile_file_reads_sig_next_to_profile() {
        let d = tmpdir("file");
        let k = key(1);
        let (text, sig) = signed(&locked(1), &k);
        let p = d.join("locked.json");
        std::fs::write(&p, &text).unwrap();
        let pol = policy(&[&k]);
        assert!(matches!(
            verify_profile_file(&p, &pol).unwrap(),
            Err(ProfileFileError::Untrusted {
                reason: ProfileTrustError::MissingSignature { .. }
            })
        ));
        std::fs::write(sig_path_for(&p), &sig).unwrap();
        assert!(verify_profile_file(&p, &pol).unwrap().is_ok());
        // A directory at the .sig path: malformed, not "missing".
        std::fs::remove_file(sig_path_for(&p)).unwrap();
        std::fs::create_dir(sig_path_for(&p)).unwrap();
        assert!(matches!(
            verify_profile_file(&p, &pol).unwrap(),
            Err(ProfileFileError::Untrusted {
                reason: ProfileTrustError::MalformedSignature { .. }
            })
        ));
        assert!(verify_profile_file(&d.join("none.json"), &pol).is_err());
        assert_eq!(
            sig_path_for(Path::new("/a/b.json")),
            Path::new("/a/b.json.sig")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    // ------------------------------------------- roots, floor, revocations --

    fn root(n: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed(format!("root{n}"), &[100 + n; 32]).unwrap()
    }

    fn roots(keys: &[&Ed25519SigningKey]) -> TrustRoots {
        let vks: Vec<_> = keys.iter().map(|k| k.verifying_key()).collect();
        parse_trust_roots(&trust_roots_text(&vks)).unwrap()
    }

    /// Fingerprint of test key `kN`.
    fn kfp(id: &str) -> String {
        let n: u8 = id[1..].parse().unwrap();
        key_fingerprint(key(n).verifying_key().as_bytes())
    }

    /// A list for platform "ugv" revoking `digests` and the keys named
    /// `kN` (by fingerprint).
    fn rl(
        serial: u64,
        digests: &[&str],
        key_ids: &[&str],
        k: &Ed25519SigningKey,
    ) -> RevocationList {
        RevocationList::create(
            serial,
            1_790_000_000,
            "ugv",
            digests.iter().map(|s| s.to_string()),
            key_ids.iter().map(|s| kfp(s)),
            k,
        )
        .unwrap()
    }

    #[test]
    fn revocation_list_round_trip_and_tamper() {
        let r = root(1);
        let rs = roots(&[&r]);
        let d = file_digest(b"p");
        let l = rl(3, &[&d, &d], &["k9", "k1"], &r);
        // Sorted and deduplicated.
        assert_eq!(l.revoked_digests, vec![d.clone()]);
        let mut want = vec![kfp("k1"), kfp("k9")];
        want.sort();
        assert_eq!(l.revoked_keys, want);
        assert_eq!(l.platform, "ugv");
        let text = l.to_text();
        let p = RevocationList::parse(&text).unwrap();
        p.verify(&rs).unwrap();
        assert_eq!(p.digest(), l.digest());
        // Whitespace does not change the identity; content does.
        let compact = serde_json::to_string(&p).unwrap();
        assert_eq!(
            RevocationList::parse(&compact).unwrap().digest(),
            l.digest()
        );
        // Tampering with any signed value breaks the signature.
        for edit in [
            text.replace("\"serial\": 3", "\"serial\": 4"),
            text.replace("1790000000", "1790000001"),
            text.replace(&kfp("k9"), &kfp("k8")),
            text.replace(&d, &file_digest(b"q")),
            text.replace("\"platform\": \"ugv\"", "\"platform\": \"ugw\""),
        ] {
            let t = RevocationList::parse(&edit).unwrap();
            assert!(
                matches!(t.verify(&rs), Err(ProfileTrustError::Revocations { .. })),
                "{edit}"
            );
        }
        // Signed by a key that is not a root (e.g. a profile key).
        let forged = rl(3, &[], &[], &key(1));
        assert!(forged
            .verify(&rs)
            .unwrap_err()
            .to_string()
            .contains("not a trust root"));
        // Impostor claiming the root's key id.
        let imp = Ed25519SigningKey::from_seed("root1", &[7; 32]).unwrap();
        assert!(rl(3, &[], &[], &imp).verify(&rs).is_err());
        // HMAC signer refused at creation.
        let h = robodr_blackbox::HmacSha256Key::new("root1", &[7; 32]).unwrap();
        assert!(RevocationList::create(1, 0, "ugv", [], [], &h).is_err());
        assert!(RevocationList::create(0, 0, "ugv", [], [], &r).is_err());
        // A key id (label) where a fingerprint belongs, or a bad platform.
        assert!(RevocationList::create(1, 0, "ugv", [], ["k1".to_string()], &r).is_err());
        assert!(RevocationList::create(1, 0, "u g v", [], [], &r).is_err());
        assert!(RevocationList::create(1, 0, "", [], [], &r).is_err());
        assert_eq!(kfp("k1"), file_digest(key(1).verifying_key().as_bytes()));
    }

    #[test]
    fn revocation_list_malformed_and_hostile() {
        let r = root(1);
        let text = rl(2, &[&file_digest(b"p")], &["k1"], &r).to_text();
        for bad in [
            String::new(),
            "{}".into(),
            "[]".into(),
            text.replace(REVOCATION_FORMAT, "robodr-profile-revocations/v9"),
            text.replace("\"serial\": 2", "\"serial\": 0"),
            text.replace("\"serial\": 2", "\"serial\": -1"),
            text.replace("\"serial\": 2", "\"serial\": 1e400"),
            text.replace("sha256:", "md5:"),
            text.replace(&format!("\"{}\"", kfp("k1")), "\"\""),
            text.replace(&format!("\"{}\"", kfp("k1")), "\"k1\""),
            text.replace(
                &format!("\"{}\"", kfp("k1")),
                &format!("\"{0}\", \"{0}\"", kfp("k1")),
            ),
            text.replace("\"platform\": \"ugv\"", "\"platform\": \"\""),
            text.replace("\"platform\": \"ugv\",", ""),
            // A v1 list (revoked keys by key id) is refused outright.
            text.replace(REVOCATION_FORMAT, REVOCATION_FORMAT_V1),
            text.replace("\"serial\"", "\"extra\": 1,\n  \"serial\""),
            text.replace("\"serial\"", "\"serial\": 5,\n  \"serial\""),
            text.replace("\"ed25519\"", "\"hmac-sha256\""),
        ] {
            assert!(
                matches!(
                    RevocationList::parse(&bad),
                    Err(ProfileTrustError::Revocations { .. })
                ),
                "{bad}"
            );
        }
        for n in 0..text.trim_end().len() {
            assert!(RevocationList::parse(&text[..n]).is_err(), "prefix {n}");
        }
        let many: Vec<String> = (0..=MAX_REVOKED_ENTRIES)
            .map(|i| file_digest(format!("{i}").as_bytes()))
            .collect();
        assert!(RevocationList::create(1, 0, "ugv", [], many, &r).is_err());
        assert!(
            RevocationList::parse(&text.replace(REVOCATION_FORMAT, REVOCATION_FORMAT_V1))
                .unwrap_err()
                .to_string()
                .contains("re-issue")
        );
        // Byte flips never panic.
        let mut x: u32 = 0x1234_5678;
        for _ in 0..500 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let mut b = text.clone().into_bytes();
            let i = x as usize % b.len();
            b[i] = (x >> 8) as u8;
            if let Ok(t) = String::from_utf8(b) {
                if let Ok(l) = RevocationList::parse(&t) {
                    let _ = l.verify(&roots(&[&r]));
                }
            }
        }
    }

    /// Operator keys (distinct from profile keys and roots).
    fn op(n: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed(format!("op{n}"), &[50 + n; 32]).unwrap()
    }

    /// alice (op1) and bob (op2), motion_quorum 2.
    fn operators() -> OperatorTrust {
        OperatorTrust::new(
            vec![
                ("alice".into(), op(1).verifying_key()),
                ("bob".into(), op(2).verifying_key()),
            ],
            2,
        )
        .unwrap()
    }

    /// A trust file with `keys`, `floor` and the [`operators`].
    fn tf_text(keys: &[Ed25519VerifyingKey], floor: Option<u64>) -> String {
        let ops = operators();
        trust_file_text_with(
            keys,
            &TrustFileOptions {
                min_profile_version: floor,
                operators: Some(&ops),
                ..Default::default()
            },
        )
    }

    fn root_sig(text: &str, r: &Ed25519SigningKey) -> String {
        ProfileSignature::create_for(SigKind::TrustFile, text.as_bytes(), r)
            .unwrap()
            .to_text()
    }

    #[test]
    fn trust_file_floor_needs_root_signature() {
        let k = key(1);
        let r = root(1);
        let rs = roots(&[&r]);
        let floored = tf_text(&[k.verifying_key()], Some(5));
        let sig = ProfileSignature::create_for(SigKind::TrustFile, floored.as_bytes(), &r)
            .unwrap()
            .to_text();
        let tf = parse_trust_file(&floored, Some(&sig), "t.sig", Some(&rs)).unwrap();
        assert_eq!(tf.min_profile_version, Some(5));
        assert_eq!(tf.signed_by.as_deref(), Some("root1"));
        // No signature, no roots, or a bad signature: refused.
        assert!(parse_trust_file(&floored, None, "t.sig", Some(&rs)).is_err());
        assert!(parse_trust_file(&floored, Some(&sig), "t.sig", None).is_err());
        let other = ProfileSignature::create_for(SigKind::TrustFile, floored.as_bytes(), &root(2))
            .unwrap()
            .to_text();
        assert!(parse_trust_file(&floored, Some(&other), "t.sig", Some(&rs)).is_err());
        // A profile signature cannot stand in for a trust-file signature.
        let psig = ProfileSignature::create(floored.as_bytes(), &r)
            .unwrap()
            .to_text();
        assert!(parse_trust_file(&floored, Some(&psig), "t.sig", Some(&rs)).is_err());
        // Signature over other bytes (floor lowered after signing).
        let lowered = floored.replace("\"min_profile_version\": 5", "\"min_profile_version\": 1");
        assert!(parse_trust_file(&lowered, Some(&sig), "t.sig", Some(&rs)).is_err());
        // Floor 0, a root among the profile keys, a floor in the roots file.
        let zero = trust_file_text(&[k.verifying_key()], Some(0));
        assert!(parse_trust_file(&zero, None, "t", None).is_err());
        let overlap = tf_text(&[k.verifying_key(), r.verifying_key()], None);
        assert!(
            parse_trust_file(&overlap, Some(&root_sig(&overlap, &r)), "t", Some(&rs))
                .unwrap_err()
                .to_string()
                .contains("distinct")
        );
        let roots_with_floor = trust_roots_text(&[r.verifying_key()])
            .replace("\"keys\"", "\"min_profile_version\": 2,\n  \"keys\"");
        assert!(parse_trust_roots(&roots_with_floor).is_err());
        // The roots file and a trust file are not interchangeable.
        assert!(parse_trust_roots(&trust_keys_text(&[r.verifying_key()])).is_err());
        assert!(parse_trust_keys(&trust_roots_text(&[r.verifying_key()])).is_err());
        // Unsigned, no floor: fine without roots only (see
        // `unsigned_trust_file_cannot_strip_the_signed_floor`).
        let plain = trust_keys_text(&[k.verifying_key()]);
        assert!(parse_trust_file(&plain, None, "t", None).is_ok());
        assert!(
            parse_trust_file(&tf_text(&[k.verifying_key()], None), None, "t", Some(&rs))
                .unwrap_err()
                .to_string()
                .contains("must be signed")
        );
    }

    #[test]
    fn trust_file_operators_and_attestation_requirement() {
        let k = key(1);
        let r = root(1);
        let rs = roots(&[&r]);
        let vk = [k.verifying_key()];
        // With roots, attestation is required by default: operators needed.
        let plain = trust_keys_text(&vk);
        let e = parse_trust_file(&plain, Some(&root_sig(&plain, &r)), "t", Some(&rs)).unwrap_err();
        assert!(e.to_string().contains("no operators"), "{e}");
        let with_ops = tf_text(&vk, None);
        let tf =
            parse_trust_file(&with_ops, Some(&root_sig(&with_ops, &r)), "t", Some(&rs)).unwrap();
        assert!(tf.require_attestation);
        assert_eq!(tf.operators.as_ref().unwrap().motion_quorum(), 2);
        // A root-signed explicit opt-out.
        let opt_out = trust_file_text_with(
            &vk,
            &TrustFileOptions {
                require_attestation: Some(false),
                ..Default::default()
            },
        );
        let tf = parse_trust_file(&opt_out, Some(&root_sig(&opt_out, &r)), "t", Some(&rs)).unwrap();
        assert!(!tf.require_attestation && tf.operators.is_none());
        // Without roots: not required unless the file says so.
        assert!(
            !parse_trust_file(&with_ops, None, "t", None)
                .unwrap()
                .require_attestation
        );
        let req = trust_file_text_with(
            &vk,
            &TrustFileOptions {
                require_attestation: Some(true),
                ..Default::default()
            },
        );
        assert!(
            parse_trust_file(&req, None, "t", None).is_err(),
            "required, no operators"
        );
        // Operators must be distinct from profile keys and from roots.
        let self_op = OperatorTrust::new(vec![("mallory".into(), k.verifying_key())], 1).unwrap();
        let t = trust_file_text_with(
            &vk,
            &TrustFileOptions {
                operators: Some(&self_op),
                ..Default::default()
            },
        );
        assert!(parse_trust_file(&t, None, "t", None)
            .unwrap_err()
            .to_string()
            .contains("also a profile signing key"));
        let root_op = OperatorTrust::new(vec![("rooty".into(), r.verifying_key())], 1).unwrap();
        let t = trust_file_text_with(
            &vk,
            &TrustFileOptions {
                operators: Some(&root_op),
                ..Default::default()
            },
        );
        assert!(
            parse_trust_file(&t, Some(&root_sig(&t, &r)), "t", Some(&rs))
                .unwrap_err()
                .to_string()
                .contains("also a trust root")
        );
        // Malformed operator sections; members that belong to trust files
        // are refused in a roots file.
        for bad in [
            with_ops.replace("\"motion_quorum\": 2", "\"motion_quorum\": 3"),
            with_ops.replace("\"motion_quorum\": 2", "\"motion_quorum\": 0"),
            plain.replace("\"keys\"", "\"motion_quorum\": 1,\n  \"keys\""),
            with_ops.replace("\"alice\"", "\" alice\""),
        ] {
            assert!(parse_trust_file(&bad, None, "t", None).is_err(), "{bad}");
        }
        let roots_with_ops = trust_roots_text(&[r.verifying_key()])
            .replace("\"keys\"", "\"require_attestation\": false,\n  \"keys\"");
        assert!(parse_trust_roots(&roots_with_ops).is_err());
    }

    fn st(version: u64, salt: &str, rev: Option<(u64, &str)>) -> AcceptedState {
        let mut s = AcceptedState::of(&verified(version, salt)).unwrap();
        if let Some((n, d)) = rev {
            s.revocation_serial = Some(n);
            s.revocation_digest = Some(file_digest(d.as_bytes()));
        }
        s
    }

    #[test]
    fn chain_reconciliation() {
        let s3 = st(3, "", None);
        assert_eq!(reconcile_with_chain(None, None), (None, None));
        assert_eq!(
            reconcile_with_chain(Some(&s3), None),
            (Some(s3.clone()), None)
        );
        // State deleted.
        let (b, a) = reconcile_with_chain(None, Some(&s3));
        assert_eq!(b, Some(s3.clone()));
        assert_eq!(a.unwrap().reason, StateAlarmReason::StateMissing);
        // State ahead of the chain (stopped before the note): normal.
        let s4 = st(4, "", None);
        assert_eq!(
            reconcile_with_chain(Some(&s4), Some(&s3)),
            (Some(s4.clone()), None)
        );
        // State behind: lower version, or same version other digest.
        let (b, a) = reconcile_with_chain(Some(&s3), Some(&s4));
        assert_eq!(b, Some(s4.clone()));
        assert_eq!(a.unwrap().reason, StateAlarmReason::StateBehindChain);
        let other3 = st(3, "x", None);
        let (b, a) = reconcile_with_chain(Some(&other3), Some(&s3));
        assert_eq!(b, Some(s3.clone()));
        assert!(a.is_some());
        // Revocation serial behind (profile equal): revocation from chain.
        let s3r1 = st(3, "", Some((1, "a")));
        let s3r2 = st(3, "", Some((2, "b")));
        let (b, a) = reconcile_with_chain(Some(&s3r1), Some(&s3r2));
        assert_eq!(b, Some(s3r2.clone()));
        assert!(a.is_some());
        // Profile ahead in state, revocation ahead in chain: mixed.
        let s4r1 = st(4, "", Some((1, "a")));
        let (b, a) = reconcile_with_chain(Some(&s4r1), Some(&s3r2));
        let b = b.unwrap();
        assert_eq!((b.profile_version, b.revocation_serial), (4, Some(2)));
        assert!(a.unwrap().to_string().contains("behind"));
        // Same everything: nothing.
        assert_eq!(
            reconcile_with_chain(Some(&s3r2), Some(&s3r2)),
            (Some(s3r2.clone()), None)
        );
        // Trust floor: the higher one wins; a lower state floor is behind.
        let mut f5 = s3.clone();
        f5.trust_floor = Some(5);
        let (b, a) = reconcile_with_chain(Some(&s3), Some(&f5));
        assert_eq!(b.unwrap().trust_floor, Some(5));
        assert_eq!(a.unwrap().reason, StateAlarmReason::StateBehindChain);
        let (b, a) = reconcile_with_chain(Some(&f5), Some(&s3));
        assert_eq!(b.unwrap().trust_floor, Some(5));
        assert!(a.is_none(), "state ahead of the chain is normal");
        let mut zero = s3.clone();
        zero.trust_floor = Some(0);
        assert!(zero.validate().is_err());
    }

    #[test]
    fn accepted_notes_round_trip_and_hostile_payloads() {
        let s = st(7, "", Some((2, "x")));
        let n = accepted_note(&s, Some("k1"), Some(RollbackDecision::Upgrade));
        let bytes = serde_json::to_vec(&n).unwrap();
        assert_eq!(accepted_from_note(&bytes), Some(s.clone()));
        // A heartbeat carrying the same member.
        let hb = serde_json::json!({"kind": "robodr.agentd_heartbeat", "profile_accepted": s});
        assert_eq!(
            accepted_from_note(&serde_json::to_vec(&hb).unwrap()),
            Some(s.clone())
        );
        for bad in [
            &b""[..],
            b"null",
            b"[]",
            b"{\"profile_accepted\": 1}",
            b"{\"profile_accepted\": {\"format\": \"x\"}}",
            b"{\"kind\": \"robodr.agentd_heartbeat\"}",
            b"\xff\xfe",
        ] {
            assert_eq!(accepted_from_note(bad), None);
        }
        let mut zero = s.clone();
        zero.profile_version = 0;
        let v = serde_json::json!({ "profile_accepted": zero });
        assert_eq!(accepted_from_note(&serde_json::to_vec(&v).unwrap()), None);
        let mut half = s;
        half.revocation_digest = None;
        let v = serde_json::json!({ "profile_accepted": half });
        assert_eq!(accepted_from_note(&serde_json::to_vec(&v).unwrap()), None);
    }

    /// Files for evaluator tests: trust file, roots, profiles, lists.
    struct Fx {
        dir: PathBuf,
        trust: PathBuf,
        roots: PathBuf,
        revs: PathBuf,
        state: PathBuf,
    }

    /// Embed an operator attestation in locked `p`: a confirmed sign-off
    /// for its content (operator alice, = `locked_by`) signed by `signers`.
    fn attest(p: &mut Profile, signers: &[&Ed25519SigningKey]) {
        let text = signoff_text_for(p, "alice");
        let mut sigs = crate::signoff::SignoffSignatures::new(text.as_bytes());
        for k in signers {
            sigs.add(text.as_bytes(), *k).unwrap();
        }
        let m = p.metadata.as_mut().unwrap();
        m.locked_by = "alice".into();
        m.attestation = Some(attestation_for(&text, &sigs));
    }

    /// The confirmed sign-off text `lock` would have used for `p`.
    fn signoff_text_for(p: &Profile, operator: &str) -> String {
        let mut d = p.clone();
        d.locked = false;
        d.metadata = None;
        crate::to_json(&crate::signoff::Signoff::for_profile(&d).confirm_all(operator)).unwrap()
    }

    /// `locked(version)` attested by alice and bob.
    fn attested(version: u64) -> Profile {
        let mut p = locked(version);
        attest(&mut p, &[&op(1), &op(2)]);
        p
    }

    impl Fx {
        fn new(tag: &str, floor: Option<u64>) -> Self {
            let dir = tmpdir(tag);
            let trust = dir.join("trust.json");
            let text = tf_text(&[key(1).verifying_key(), key(2).verifying_key()], floor);
            std::fs::write(&trust, &text).unwrap();
            std::fs::write(sig_path_for(&trust), root_sig(&text, &root(1))).unwrap();
            let roots = dir.join("roots.json");
            std::fs::write(&roots, trust_roots_text(&[root(1).verifying_key()])).unwrap();
            Self {
                revs: dir.join("revocations.json"),
                state: dir.join("state.json"),
                dir,
                trust,
                roots,
            }
        }

        fn profile(&self, name: &str, version: u64, k: &Ed25519SigningKey) -> (PathBuf, String) {
            self.write(name, &attested(version), k)
        }

        fn write(&self, name: &str, p: &Profile, k: &Ed25519SigningKey) -> (PathBuf, String) {
            let (text, sig) = signed(p, k);
            let p = self.dir.join(name);
            std::fs::write(&p, &text).unwrap();
            std::fs::write(sig_path_for(&p), sig).unwrap();
            (p, text)
        }

        fn list(&self, l: &RevocationList) {
            std::fs::write(&self.revs, l.to_text()).unwrap();
        }

        fn inputs(&self) -> TrustInputs<'_> {
            TrustInputs {
                trusted_keys: Some(&self.trust),
                trust_roots: Some(&self.roots),
                revocation_list: Some(&self.revs),
                state_file: Some(&self.state),
                ..Default::default()
            }
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn refused(e: &TrustEvaluation) -> ProfileTrustError {
        match &e.result {
            Err(ProfileFileError::Untrusted { reason }) => reason.clone(),
            other => panic!("expected a trust refusal, got {other:?}"),
        }
    }

    /// Evaluate and persist the state write (as a loader would).
    fn eval(p: &Path, text: &str, i: &TrustInputs<'_>) -> TrustEvaluation {
        let e = evaluate_profile_trust(p, text, i);
        if let Ok(a) = &e.result {
            if let (Some(w), Some(sp)) = (&a.state_write, i.state_file) {
                store_state(sp, w).unwrap();
            }
        }
        e
    }

    #[test]
    fn evaluator_revocations() {
        let fx = Fx::new("eval-rev", None);
        let (p, text) = fx.profile("p.json", 2, &key(1));
        let digest = file_digest(text.as_bytes());
        // Optional policy, no list: accepted.
        let e = eval(&p, &text, &fx.inputs());
        let a = e.result.unwrap();
        assert_eq!(a.record.as_ref().unwrap().revocation_serial, None);
        assert!(e.alarm.is_none());
        // Required policy, no list: refused.
        let mut req = fx.inputs();
        req.revocation_policy = RevocationPolicy::Required;
        assert!(matches!(
            refused(&evaluate_profile_trust(&p, &text, &req)),
            ProfileTrustError::RevocationListMissing { .. }
        ));
        // Revoked digest.
        fx.list(&rl(1, &[&digest], &[], &root(1)));
        assert_eq!(
            refused(&eval(&p, &text, &fx.inputs())),
            ProfileTrustError::RevokedProfile {
                digest: digest.clone(),
                serial: 1
            }
        );
        // Revoked signing key (the profile itself is not listed).
        fx.list(&rl(2, &[], &["k1"], &root(1)));
        assert_eq!(
            refused(&eval(&p, &text, &fx.inputs())),
            ProfileTrustError::RevokedKey {
                key_id: "k1".into(),
                fingerprint: kfp("k1"),
                serial: 2
            }
        );
        // A profile signed by another, unrevoked key is accepted and the
        // list's serial is recorded in the state.
        let (p2, t2) = fx.profile("p2.json", 3, &key(2));
        let a = eval(&p2, &t2, &fx.inputs()).result.unwrap();
        assert_eq!(a.decision, Some(RollbackDecision::Upgrade));
        let saved = load_state(&fx.state).unwrap().unwrap();
        assert_eq!(saved.revocation_serial, Some(2));
        // An older list is refused (anti-rollback for the list itself).
        let old = rl(1, &[], &[], &root(1));
        fx.list(&old);
        assert_eq!(
            refused(&eval(&p2, &t2, &fx.inputs())),
            ProfileTrustError::RevocationRollback {
                accepted_serial: 2,
                offered_serial: 1
            }
        );
        // Same serial, other content.
        fx.list(&rl(2, &[], &["k1", "k7"], &root(1)));
        assert_eq!(
            refused(&eval(&p2, &t2, &fx.inputs())),
            ProfileTrustError::RevocationEquivocation { serial: 2 }
        );
        // The list deleted after one was accepted (optional policy).
        std::fs::remove_file(&fx.revs).unwrap();
        assert_eq!(
            refused(&eval(&p2, &t2, &fx.inputs())),
            ProfileTrustError::RevocationListRemoved { accepted_serial: 2 }
        );
        // Tampered list (valid JSON, signature broken).
        let good = rl(3, &[], &["k1"], &root(1)).to_text();
        std::fs::write(&fx.revs, good.replace(&kfp("k1"), &kfp("k7"))).unwrap();
        assert!(matches!(
            refused(&eval(&p2, &t2, &fx.inputs())),
            ProfileTrustError::Revocations { .. }
        ));
        // A list signed by a profile key, not a root.
        fx.list(&rl(3, &[], &["k1"], &key(2)));
        assert!(refused(&eval(&p2, &t2, &fx.inputs()))
            .to_string()
            .contains("not a trust root"));
        // Newer valid list: accepted, state advanced (profile unchanged).
        fx.list(&rl(3, &[], &["k1"], &root(1)));
        let a = eval(&p2, &t2, &fx.inputs()).result.unwrap();
        assert_eq!(a.decision, Some(RollbackDecision::Same));
        assert!(a.state_write.is_some());
        assert_eq!(
            load_state(&fx.state).unwrap().unwrap().revocation_serial,
            Some(3)
        );
        // Again: nothing to write.
        assert!(eval(&p2, &t2, &fx.inputs())
            .result
            .unwrap()
            .state_write
            .is_none());
        // A list without roots configured cannot be checked.
        let mut nr = fx.inputs();
        nr.trust_roots = None;
        assert!(matches!(
            refused(&evaluate_profile_trust(&p2, &t2, &nr)),
            ProfileTrustError::Revocations { .. }
        ));
        // Drafts ignore revocation (observe-only anyway) but not rollback.
        let mut d = locked(1);
        d.locked = false;
        d.metadata = None;
        let dt = crate::to_json(&d).unwrap();
        let dp = fx.dir.join("draft.json");
        std::fs::write(&dp, &dt).unwrap();
        let mut ns = fx.inputs();
        ns.state_file = None;
        assert!(evaluate_profile_trust(&dp, &dt, &ns).result.is_ok());
    }

    #[test]
    fn evaluator_state_deleted_but_chain_has_higher_version() {
        let fx = Fx::new("eval-chain", None);
        let (p1, t1) = fx.profile("v1.json", 1, &key(1));
        let (p3, t3) = fx.profile("v3.json", 3, &key(1));
        let rec3 = eval(&p3, &t3, &fx.inputs()).result.unwrap().record.unwrap();
        // The attacker deletes the state and offers v1.
        std::fs::remove_file(&fx.state).unwrap();
        let mut i = fx.inputs();
        i.chain = Some(&rec3);
        let e = eval(&p1, &t1, &i);
        assert!(matches!(
            refused(&e),
            ProfileTrustError::Rollback {
                accepted_version: 3,
                offered_version: 1,
                ..
            }
        ));
        assert_eq!(
            e.alarm.as_ref().unwrap().reason,
            StateAlarmReason::StateMissing
        );
        assert!(!fx.state.exists(), "a refusal writes nothing");
        // The state rewritten to v1 instead of deleted: same outcome.
        let s1 = AcceptedState::of(
            &verify_profile_text(
                &t1,
                Some(&std::fs::read_to_string(sig_path_for(&p1)).unwrap()),
                "x",
                &policy(&[&key(1)]),
            )
            .unwrap(),
        )
        .unwrap();
        store_state(&fx.state, &s1).unwrap();
        let e = eval(&p1, &t1, &i);
        assert!(matches!(refused(&e), ProfileTrustError::Rollback { .. }));
        assert_eq!(
            e.alarm.as_ref().unwrap().reason,
            StateAlarmReason::StateBehindChain
        );
        // The real profile still loads; the alarm is reported and the state
        // repaired from the chain.
        std::fs::remove_file(&fx.state).unwrap();
        let e = eval(&p3, &t3, &i);
        assert!(e.alarm.is_some());
        let a = e.result.unwrap();
        assert_eq!(a.decision, Some(RollbackDecision::Same));
        assert_eq!(a.state_write.as_ref(), Some(&rec3));
        assert_eq!(load_state(&fx.state).unwrap(), Some(rec3.clone()));
        // Consistent again: no alarm.
        assert!(eval(&p3, &t3, &i).alarm.is_none());
        // The operator's explicit rollback flag still works against the
        // chain baseline.
        std::fs::remove_file(&fx.state).unwrap();
        let d1 = file_digest(t1.as_bytes());
        i.allow_rollback = Some(&d1);
        let a = eval(&p1, &t1, &i).result.unwrap();
        assert_eq!(a.decision, Some(RollbackDecision::OperatorRollback));
        // Without a state file configured the chain is not consulted.
        let mut ns = fx.inputs();
        ns.state_file = None;
        ns.chain = Some(&rec3);
        let e = evaluate_profile_trust(&p1, &t1, &ns);
        assert!(e.result.is_ok() && e.alarm.is_none());
    }

    #[test]
    fn evaluator_signed_floor() {
        let fx = Fx::new("eval-floor", Some(3));
        let (p2, t2) = fx.profile("v2.json", 2, &key(1));
        let (p3, t3) = fx.profile("v3.json", 3, &key(1));
        let d2 = file_digest(t2.as_bytes());
        let mut i = fx.inputs();
        i.state_file = None;
        assert_eq!(
            refused(&evaluate_profile_trust(&p2, &t2, &i)),
            ProfileTrustError::BelowFloor {
                floor: 3,
                offered_version: 2
            }
        );
        // allow_rollback cannot lower the floor.
        let mut j = fx.inputs();
        j.allow_rollback = Some(&d2);
        assert!(matches!(
            refused(&evaluate_profile_trust(&p2, &t2, &j)),
            ProfileTrustError::BelowFloor { .. }
        ));
        assert!(evaluate_profile_trust(&p3, &t3, &i).result.is_ok());
        // The floor without its root signature: trust file invalid.
        std::fs::remove_file(sig_path_for(&fx.trust)).unwrap();
        assert!(matches!(
            refused(&evaluate_profile_trust(&p3, &t3, &i)),
            ProfileTrustError::TrustFile { .. }
        ));
        // Floor signed but roots not configured: invalid too.
        let text = std::fs::read_to_string(&fx.trust).unwrap();
        let sig =
            ProfileSignature::create_for(SigKind::TrustFile, text.as_bytes(), &root(1)).unwrap();
        std::fs::write(sig_path_for(&fx.trust), sig.to_text()).unwrap();
        let mut nr = i;
        nr.trust_roots = None;
        nr.revocation_list = None;
        assert!(matches!(
            refused(&evaluate_profile_trust(&p3, &t3, &nr)),
            ProfileTrustError::TrustFile { .. }
        ));
        // A broken roots file refuses locked profiles.
        std::fs::write(&fx.roots, "{").unwrap();
        assert!(evaluate_profile_trust(&p3, &t3, &i).result.is_err());
    }

    // ------------------------------------ security review regressions --
    // Each was a PoC that passed while the weakness existed; they now
    // assert the fixed behaviour.

    /// With trust roots configured an unsigned trust file was accepted, so
    /// whoever could rewrite it stripped the root-signed floor. Now it is
    /// refused, and the highest floor ever accepted is remembered in the
    /// state file and the black-box record, so neither an unsigned file
    /// nor an older root-signed one (replay) lowers it.
    #[test]
    fn unsigned_trust_file_cannot_strip_the_signed_floor() {
        let fx = Fx::new("reg-floor-strip", Some(3));
        let (p2, t2) = fx.profile("v2.json", 2, &key(1));
        let (p3, t3) = fx.profile("v3.json", 3, &key(1));
        let mut i = fx.inputs();
        i.state_file = None;
        assert!(matches!(
            refused(&evaluate_profile_trust(&p2, &t2, &i)),
            ProfileTrustError::BelowFloor { .. }
        ));
        // Accept v3 with state: the floor is recorded.
        let rec = eval(&p3, &t3, &fx.inputs()).result.unwrap().record.unwrap();
        assert_eq!(rec.trust_floor, Some(3));
        assert_eq!(load_state(&fx.state).unwrap().unwrap().trust_floor, Some(3));
        // Attacker: same keys, no floor, no signature.
        let stripped = tf_text(&[key(1).verifying_key(), key(2).verifying_key()], None);
        std::fs::write(&fx.trust, &stripped).unwrap();
        std::fs::remove_file(sig_path_for(&fx.trust)).unwrap();
        let e = evaluate_profile_trust(&p2, &t2, &i);
        assert!(
            matches!(refused(&e), ProfileTrustError::TrustFile { ref detail } if detail.contains("must be signed")),
            "{:?}",
            e.result
        );
        // An older root-signed trust file without the floor (replay): the
        // remembered floor still holds (state) ...
        std::fs::write(sig_path_for(&fx.trust), root_sig(&stripped, &root(1))).unwrap();
        assert!(evaluate_profile_trust(&p3, &t3, &fx.inputs())
            .result
            .is_ok());
        assert_eq!(
            refused(&evaluate_profile_trust(&p2, &t2, &fx.inputs())),
            ProfileTrustError::BelowFloor {
                floor: 3,
                offered_version: 2
            }
        );
        // ... and with the state deleted, the black-box record carries it.
        std::fs::remove_file(&fx.state).unwrap();
        let mut c = fx.inputs();
        c.chain = Some(&rec);
        let e = evaluate_profile_trust(&p2, &t2, &c);
        assert!(matches!(
            refused(&e),
            ProfileTrustError::BelowFloor { floor: 3, .. }
        ));
        assert!(e.alarm.is_some());
        // The accepted record keeps the floor although the file has none.
        let a = evaluate_profile_trust(&p3, &t3, &c).result.unwrap();
        assert_eq!(a.record.unwrap().trust_floor, Some(3));
    }

    /// Key revocation was by `key_id` label, which neither the profile
    /// signature nor the trust file binds to the key: re-listing the
    /// revoked key under another id (and editing the `.sig`'s `key_id`)
    /// loaded a profile signed by it. Now keys are revoked by public-key
    /// fingerprint, and the list is bound to a platform.
    #[test]
    fn key_revocation_survives_renaming_the_key_id() {
        let fx = Fx::new("reg-rev-rename", None);
        let (p, text) = fx.profile("p.json", 2, &key(1));
        fx.list(&rl(1, &[], &["k1"], &root(1)));
        let mut i = fx.inputs();
        i.state_file = None;
        assert!(matches!(
            refused(&evaluate_profile_trust(&p, &text, &i)),
            ProfileTrustError::RevokedKey { .. }
        ));
        // The revoked key re-listed as "k1-reissued" (even in a properly
        // root-signed trust file) and the .sig edited to match.
        let renamed = robodr_blackbox::Ed25519VerifyingKey::from_bytes(
            "k1-reissued",
            key(1).verifying_key().as_bytes(),
        )
        .unwrap();
        let t = tf_text(&[renamed], None);
        std::fs::write(&fx.trust, &t).unwrap();
        std::fs::write(sig_path_for(&fx.trust), root_sig(&t, &root(1))).unwrap();
        let sig = std::fs::read_to_string(sig_path_for(&p))
            .unwrap()
            .replace("\"k1\"", "\"k1-reissued\"");
        std::fs::write(sig_path_for(&p), sig).unwrap();
        assert_eq!(
            refused(&evaluate_profile_trust(&p, &text, &i)),
            ProfileTrustError::RevokedKey {
                key_id: "k1-reissued".into(),
                fingerprint: kfp("k1"),
                serial: 1
            }
        );
        // A list issued for another platform is refused, whatever it holds.
        let other = RevocationList::create(2, 0, "drone", [], [], &root(1)).unwrap();
        fx.list(&other);
        assert_eq!(
            refused(&evaluate_profile_trust(&p, &text, &i)),
            ProfileTrustError::RevocationPlatformMismatch {
                list: "drone".into(),
                profile: "ugv".into()
            }
        );
        // A signed profile whose key's public bytes are unknown to the
        // policy cannot be checked against a list: refused.
        let v = VerifiedProfile {
            signer_fingerprint: None,
            ..verified(2, "")
        };
        assert!(matches!(
            rl(1, &[], &[], &root(1)).check(&v),
            Err(ProfileTrustError::Revocations { .. })
        ));
    }

    /// The unit never saw the operator sign-off: a hand-built locked
    /// profile that one profile-key holder sealed and signed was fully
    /// trusted, so the two-person rule bound only the honest `lock` path.
    /// Now the profile must carry the signed sign-off (attestation) and it
    /// is verified against the trust file's operators and motion quorum.
    #[test]
    fn signed_profile_needs_operator_attestation() {
        let fx = Fx::new("reg-no-signoff", None);
        let mut i = fx.inputs();
        i.state_file = None;
        // Hand-made: no attestation at all.
        let mut p = locked(1);
        p.metadata.as_mut().unwrap().locked_by = "nobody-signed-off".into();
        p.participants.insert("e".repeat(24));
        let (path, text) = fx.write("handmade.json", &p, &key(1));
        assert_eq!(
            refused(&evaluate_profile_trust(&path, &text, &i)),
            ProfileTrustError::Unattested
        );
        // A genuine attestation (of v1) copied onto other content.
        let genuine = attested(1);
        let mut forged = p.clone();
        forged.metadata = genuine.metadata.clone();
        let (path, text) = fx.write("forged.json", &forged, &key(1));
        let e = refused(&evaluate_profile_trust(&path, &text, &i));
        assert!(
            matches!(&e, ProfileTrustError::BadAttestation { detail } if detail.contains("other content")),
            "{e}"
        );
        // One operator signs alone a sign-off with motion items.
        let mut solo = locked(1);
        attest(&mut solo, &[&op(1)]);
        let (path, text) = fx.write("solo.json", &solo, &key(1));
        assert_eq!(
            refused(&evaluate_profile_trust(&path, &text, &i)),
            ProfileTrustError::AttestationQuorumNotMet { have: 1, need: 2 }
        );
        // A signature by a key that is not an operator (e.g. the profile key).
        let mut rogue = locked(1);
        attest(&mut rogue, &[&op(1), &op(2), &key(1)]);
        let (path, text) = fx.write("rogue.json", &rogue, &key(1));
        assert!(matches!(
            refused(&evaluate_profile_trust(&path, &text, &i)),
            ProfileTrustError::BadAttestation { .. }
        ));
        // locked_by is not the sign-off's operator.
        let mut renamed = attested(1);
        renamed.metadata.as_mut().unwrap().locked_by = "bob".into();
        let (path, text) = fx.write("renamed.json", &renamed, &key(1));
        assert!(matches!(
            refused(&evaluate_profile_trust(&path, &text, &i)),
            ProfileTrustError::BadAttestation { detail } if detail.contains("locked_by")
        ));
        // The properly attested profile loads and says who attested.
        let (path, text) = fx.profile("good.json", 1, &key(1));
        let a = evaluate_profile_trust(&path, &text, &i).result.unwrap();
        let att = a.verified.attestation.unwrap();
        assert_eq!(att.operator, "alice");
        assert_eq!(att.signers.len(), 2);
        assert_eq!(att.quorum, 2);
        assert_eq!(a.verified.signer_fingerprint, Some(kfp("k1")));
        // A root-signed opt-out accepts the unattested profile.
        let opt_out = trust_file_text_with(
            &[key(1).verifying_key(), key(2).verifying_key()],
            &TrustFileOptions {
                require_attestation: Some(false),
                ..Default::default()
            },
        );
        std::fs::write(&fx.trust, &opt_out).unwrap();
        std::fs::write(sig_path_for(&fx.trust), root_sig(&opt_out, &root(1))).unwrap();
        let (path, text) = fx.write("handmade2.json", &p, &key(1));
        assert!(evaluate_profile_trust(&path, &text, &i).result.is_ok());
    }

    #[test]
    fn attestation_verification_edge_cases() {
        let ops = operators();
        let good = attested(1);
        assert!(verify_attestation(&good, &ops).is_ok());
        let edit = |f: &dyn Fn(&mut ProfileAttestation)| {
            let mut p = good.clone();
            f(p.metadata.as_mut().unwrap().attestation.as_mut().unwrap());
            verify_attestation(&p, &ops)
        };
        // The sign-off edited after signing (a confirmation flipped).
        assert!(edit(&|a| a.signoff = a.signoff.replacen("true", "false", 1)).is_err());
        // Garbage, truncated and duplicate-key texts.
        assert!(edit(&|a| a.signoff = "{".into()).is_err());
        assert!(edit(&|a| a.signatures = "[]".into()).is_err());
        assert!(edit(&|a| a.signoff = a.signoff[..a.signoff.len() / 2].to_string()).is_err());
        assert!(edit(&|a| {
            a.signoff = a
                .signoff
                .replacen("\"model\"", "\"model\": \"x\", \"model\"", 1)
        })
        .is_err());
        // No signatures at all.
        assert!(edit(&|a| {
            let so = a.signoff.clone();
            a.signatures = crate::signoff::SignoffSignatures::new(so.as_bytes()).to_text();
        })
        .is_err());
        // An unconfirmed list signed by both (honestly signed, still refused).
        let mut p = locked(1);
        let mut d = p.clone();
        d.locked = false;
        d.metadata = None;
        let mut so = crate::signoff::Signoff::for_profile(&d).confirm_all("alice");
        so.items[0].confirmed = false;
        let text = crate::to_json(&so).unwrap();
        let mut sigs = crate::signoff::SignoffSignatures::new(text.as_bytes());
        sigs.add(text.as_bytes(), &op(1)).unwrap();
        sigs.add(text.as_bytes(), &op(2)).unwrap();
        let m = p.metadata.as_mut().unwrap();
        m.locked_by = "alice".into();
        m.attestation = Some(attestation_for(&text, &sigs));
        assert!(verify_attestation(&p, &ops)
            .unwrap_err()
            .to_string()
            .contains("not confirmed"));
        // No motion channel: no quorum, one operator suffices.
        let mut calm = locked(1);
        calm.motion_envelopes.clear();
        attest(&mut calm, &[&op(1)]);
        let s = verify_attestation(&calm, &ops).unwrap();
        assert_eq!((s.motion_items, s.quorum), (0, 0));
        // Unattested and legacy.
        assert_eq!(
            verify_attestation(&locked(1), &ops),
            Err(ProfileTrustError::Unattested)
        );
        let mut legacy = locked(1);
        legacy.metadata = None;
        assert_eq!(
            verify_attestation(&legacy, &ops),
            Err(ProfileTrustError::LegacyUnversioned)
        );
        // Through verify_profile_text: required, operators missing.
        let (t, sig) = signed(&good, &key(1));
        let mut pol = policy(&[&key(1)]);
        pol.require_attestation = true;
        assert!(matches!(
            untrusted(verify_profile_text(&t, Some(&sig), "x", &pol)),
            ProfileTrustError::BadAttestation { .. }
        ));
        pol.operators = Some(ops);
        assert!(verify_profile_text(&t, Some(&sig), "x", &pol).is_ok());
    }
}
