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
//! * The state file is plain JSON on the unit. Anyone who can delete or
//!   rewrite it (root on the unit) resets anti-rollback; a hardware
//!   monotonic counter (TPM NV index) is the real fix (Phase 2/3). An
//!   unreadable or malformed state file fails closed (refused), it is
//!   never silently reset.
//! * Trust-anchor files are checked for symlinks and group/other write
//!   permission, not for ownership.
//! * Revocation is by removing a key from the trust file; there is no
//!   revocation list or expiry.

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

/// Domain separation prefix of the signed message.
pub const SIG_DOMAIN: &[u8] = b"robodr-profile-sig/v1\0";
/// `format` of a signature file.
pub const SIG_FORMAT: &str = "robodr-profile-sig/v1";
/// `format` of a trust-anchor file.
pub const TRUST_FORMAT: &str = "robodr-profile-trust/v1";
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
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + profile_bytes.len());
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(profile_bytes);
    m
}

// ------------------------------------------------------------ signature --

/// A detached profile signature (`robodr-profile-sig/v1`).
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
        let sig = signer.sign(&signed_message(profile_bytes))?;
        Ok(Self {
            format: SIG_FORMAT.into(),
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

    /// Parse a `.sig` file (unknown keys and duplicate keys refused).
    pub fn parse(text: &str) -> Result<Self, ProfileTrustError> {
        let bad = |detail: String| ProfileTrustError::MalformedSignature { detail };
        crate::profile_file::reject_duplicate_keys(text).map_err(|e| bad(e.to_string()))?;
        let s: Self = serde_json::from_str(text).map_err(|e| bad(e.to_string()))?;
        if s.format != SIG_FORMAT {
            return Err(bad(format!(
                "format {:?}, expected {SIG_FORMAT:?}",
                s.format
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
        if key.algorithm() != self.algorithm || !key.verify(&signed_message(profile_bytes), &sig) {
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
    keys: Vec<TrustKeyJson>,
}

/// Parse a trust-anchor file's text into a keyring of Ed25519 verifying
/// keys. Refuses an empty list, a duplicate key id, a non-Ed25519 key and
/// an invalid (non-canonical or small-order) public key.
pub fn parse_trust_keys(text: &str) -> Result<Keyring, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::TrustFile { detail };
    crate::profile_file::reject_duplicate_keys(text).map_err(|e| bad(e.to_string()))?;
    let j: TrustJson = serde_json::from_str(text).map_err(|e| bad(e.to_string()))?;
    if j.format != TRUST_FORMAT {
        return Err(bad(format!(
            "format {:?}, expected {TRUST_FORMAT:?}",
            j.format
        )));
    }
    if j.keys.is_empty() {
        return Err(bad("no keys".into()));
    }
    if j.keys.len() > MAX_TRUST_KEYS {
        return Err(bad(format!("more than {MAX_TRUST_KEYS} keys")));
    }
    let mut ring = Keyring::new();
    for k in j.keys {
        if k.algorithm != ED25519 {
            return Err(bad(format!(
                "key {:?}: algorithm {:?} is not supported (only {ED25519:?})",
                k.key_id, k.algorithm
            )));
        }
        let public: [u8; PUBLIC_KEY_LEN] = from_hex(&k.public_hex)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                bad(format!(
                    "key {:?}: public_hex is not {PUBLIC_KEY_LEN} bytes of hex",
                    k.key_id
                ))
            })?;
        let vk = Ed25519VerifyingKey::from_bytes(k.key_id.clone(), &public)
            .map_err(|e| bad(format!("key {:?}: {e}", k.key_id)))?;
        ring.add(Box::new(vk))
            .map_err(|e| bad(format!("key {:?}: {e}", k.key_id)))?;
    }
    Ok(ring)
}

/// Read a trust-anchor file: regular file (not a symlink), not writable by
/// group or others, size-capped; then [`parse_trust_keys`].
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
    let j = TrustJson {
        format: TRUST_FORMAT.into(),
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
}

/// A profile that passed [`verify_profile_text`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedProfile {
    pub profile: Profile,
    /// [`file_digest`] of the exact file bytes.
    pub digest: String,
    /// Key id that signed it (`None` for a draft).
    pub signed_by: Option<String>,
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
    Ok(VerifiedProfile {
        profile,
        digest,
        signed_by: Some(sig.key_id),
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
    match read_regular_file(path, MAX_SIG_BYTES) {
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
}

impl AcceptedState {
    /// The state recording `v` (a locked, verified profile).
    pub fn of(v: &VerifiedProfile) -> Option<Self> {
        let m = v.profile.metadata.as_ref()?;
        Some(Self {
            format: STATE_FORMAT.into(),
            model: v.profile.model.clone(),
            platform: m.platform.clone(),
            unit_id: m.unit_id.clone(),
            profile_version: m.profile_version,
            digest: v.digest.clone(),
        })
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
    if s.format != STATE_FORMAT {
        return Err(bad(format!(
            "format {:?}, expected {STATE_FORMAT:?}",
            s.format
        )));
    }
    if !is_sha256_digest(&s.digest) || s.profile_version == 0 {
        return Err(bad("malformed digest or version".into()));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_file::sealed_text;
    use robodr_blackbox::sign_ed25519::derive_key_id;
    use robodr_events::profile::{Envelope, ProfileMetadata, PROFILE_SCHEMA_VERSION};

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
}
