//! Signed revocation list (`robodr-profile-revocations/v1`).
//!
//! ```json
//! {
//!   "format": "robodr-profile-revocations/v1",
//!   "serial": 3,
//!   "issued_at": 1790000000,
//!   "revoked_digests": ["sha256:<64 hex>"],
//!   "revoked_key_ids": ["oem-ugv-x1-2025"],
//!   "signature": { "algorithm": "ed25519", "key_id": "root-1", "signature_hex": "<128 hex>" }
//! }
//! ```
//!
//! * The signature is Ed25519 over [`REVOCATION_DOMAIN`] followed by the
//!   compact JSON of the body (every member but `signature`, in the order
//!   above). The body is re-serialised from the parsed values, so
//!   whitespace does not matter but every value does; [`RevocationList::digest`]
//!   is the `sha256:` of that signed message (the list's identity in the
//!   state file and the black box).
//! * It must verify under a **trust root** (`robodr-trust-roots/v1`), never
//!   a profile signing key: the parent module refuses a key that is both.
//! * `serial` (>= 1) is monotonic: the loader refuses a list with a lower
//!   serial than the last accepted one, or the same serial with another
//!   digest (see `evaluate_profile_trust`). `issued_at` (Unix seconds) is
//!   informational only: units have no trusted clock, there is no expiry.
//! * Strict parsing: unknown or duplicate keys, malformed digests, invalid
//!   key ids, duplicate entries and more than [`MAX_REVOKED_ENTRIES`]
//!   entries are refused. [`RevocationList::create`] sorts and dedups.

use super::{file_digest, read_optional_text, ProfileTrustError, TrustRoots, VerifiedProfile};
use robodr_blackbox::crypto::{from_hex, to_hex};
use robodr_blackbox::sign_ed25519::{ED25519, SIGNATURE_LEN};
use robodr_blackbox::Signer;
use robodr_events::profile::is_sha256_digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// `format` of a revocation list.
pub const REVOCATION_FORMAT: &str = "robodr-profile-revocations/v1";
/// Domain separation prefix of the signed message.
pub const REVOCATION_DOMAIN: &[u8] = b"robodr-profile-revocations/v1\0";
/// Largest revocation list read.
pub const MAX_REVOCATION_BYTES: u64 = 1 << 20;
/// Most entries (digests + key ids) in one list.
pub const MAX_REVOKED_ENTRIES: usize = 4096;
/// Longest revoked key id.
const MAX_KEY_ID_LEN: usize = 64;

/// What a **missing** revocation list file means. A list that exists but
/// is invalid is always refused; a list that was accepted before and is
/// now missing is always refused too.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationPolicy {
    /// No list (yet): proceed without revocation (default).
    #[default]
    Optional,
    /// No list: every locked profile is refused.
    Required,
}

/// The embedded signature of a revocation list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationSignature {
    pub algorithm: String,
    pub key_id: String,
    pub signature_hex: String,
}

/// A parsed revocation list (structure checked; [`RevocationList::verify`]
/// checks the signature).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationList {
    pub format: String,
    pub serial: u64,
    pub issued_at: u64,
    pub revoked_digests: Vec<String>,
    pub revoked_key_ids: Vec<String>,
    pub signature: RevocationSignature,
}

#[derive(Serialize)]
struct Body<'a> {
    format: &'a str,
    serial: u64,
    issued_at: u64,
    revoked_digests: &'a [String],
    revoked_key_ids: &'a [String],
}

fn valid_key_id(k: &str) -> bool {
    !k.is_empty() && k.len() <= MAX_KEY_ID_LEN && k.bytes().all(|b| b.is_ascii_graphic())
}

fn check_entries(serial: u64, digests: &[String], key_ids: &[String]) -> Result<(), String> {
    if serial == 0 {
        return Err("serial must be >= 1".into());
    }
    if digests.len() + key_ids.len() > MAX_REVOKED_ENTRIES {
        return Err(format!("more than {MAX_REVOKED_ENTRIES} entries"));
    }
    let mut seen = BTreeSet::new();
    for d in digests {
        if !is_sha256_digest(d) {
            return Err(format!(
                "revoked digest {:?} is not sha256:<64 lower-case hex>",
                d.chars().take(80).collect::<String>()
            ));
        }
        if !seen.insert(d.as_str()) {
            return Err(format!("revoked digest {d} listed twice"));
        }
    }
    let mut seen = BTreeSet::new();
    for k in key_ids {
        if !valid_key_id(k) {
            return Err(format!(
                "revoked key id {:?} is not 1..={MAX_KEY_ID_LEN} printable ASCII characters",
                k.chars().take(80).collect::<String>()
            ));
        }
        if !seen.insert(k.as_str()) {
            return Err(format!("revoked key id {k:?} listed twice"));
        }
    }
    Ok(())
}

impl RevocationList {
    /// The message the signature covers: [`REVOCATION_DOMAIN`] || compact
    /// JSON of the body.
    pub fn signed_message(&self) -> Vec<u8> {
        let body = Body {
            format: &self.format,
            serial: self.serial,
            issued_at: self.issued_at,
            revoked_digests: &self.revoked_digests,
            revoked_key_ids: &self.revoked_key_ids,
        };
        let mut m = REVOCATION_DOMAIN.to_vec();
        // Serialising strings, integers and string arrays cannot fail.
        m.extend_from_slice(&serde_json::to_vec(&body).unwrap_or_default());
        m
    }

    /// `sha256:` of [`RevocationList::signed_message`]: the list's
    /// identity (independent of whitespace and of the signature bytes).
    pub fn digest(&self) -> String {
        file_digest(&self.signed_message())
    }

    /// Build and sign a list (entries sorted and deduplicated).
    pub fn create(
        serial: u64,
        issued_at: u64,
        digests: impl IntoIterator<Item = String>,
        key_ids: impl IntoIterator<Item = String>,
        signer: &dyn Signer,
    ) -> Result<Self, String> {
        if signer.algorithm() != ED25519 {
            return Err(format!(
                "revocation lists are signed with {ED25519}, not {:?}",
                signer.algorithm()
            ));
        }
        let digests: Vec<String> = digests
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let key_ids: Vec<String> = key_ids
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        check_entries(serial, &digests, &key_ids)?;
        let mut l = Self {
            format: REVOCATION_FORMAT.into(),
            serial,
            issued_at,
            revoked_digests: digests,
            revoked_key_ids: key_ids,
            signature: RevocationSignature {
                algorithm: ED25519.into(),
                key_id: signer.key_id().into(),
                signature_hex: String::new(),
            },
        };
        let sig = signer
            .sign(&l.signed_message())
            .map_err(|e| e.to_string())?;
        l.signature.signature_hex = to_hex(&sig);
        Ok(l)
    }

    /// The file text (pretty JSON, trailing newline).
    pub fn to_text(&self) -> String {
        crate::to_json(self).unwrap_or_default()
    }

    /// Strict structural parse (no signature check).
    pub fn parse(text: &str) -> Result<Self, ProfileTrustError> {
        let bad = |detail: String| ProfileTrustError::Revocations { detail };
        crate::profile_file::reject_duplicate_keys(text).map_err(|e| bad(e.to_string()))?;
        let l: Self = serde_json::from_str(text).map_err(|e| bad(e.to_string()))?;
        if l.format != REVOCATION_FORMAT {
            return Err(bad(format!(
                "format {:?}, expected {REVOCATION_FORMAT:?}",
                l.format
            )));
        }
        check_entries(l.serial, &l.revoked_digests, &l.revoked_key_ids).map_err(bad)?;
        if l.signature.algorithm != ED25519 {
            return Err(bad(format!(
                "signature algorithm {:?} is not supported (only {ED25519:?})",
                l.signature.algorithm
            )));
        }
        if !valid_key_id(&l.signature.key_id) {
            return Err(bad("signature key_id is malformed".into()));
        }
        match from_hex(&l.signature.signature_hex) {
            Some(b) if b.len() == SIGNATURE_LEN => {}
            _ => {
                return Err(bad(format!(
                    "signature_hex is not {SIGNATURE_LEN} bytes of hex"
                )))
            }
        }
        Ok(l)
    }

    /// Check the signature under the trust root it names.
    pub fn verify(&self, roots: &TrustRoots) -> Result<(), ProfileTrustError> {
        let bad = |detail: String| ProfileTrustError::Revocations { detail };
        let Some(key) = roots.keys.get(&self.signature.key_id) else {
            return Err(bad(format!(
                "signed by {:?}, which is not a trust root",
                self.signature.key_id
            )));
        };
        let sig = from_hex(&self.signature.signature_hex).unwrap_or_default();
        if key.algorithm() != self.signature.algorithm || !key.verify(&self.signed_message(), &sig)
        {
            return Err(bad(format!(
                "signature does not verify under trust root {:?} (forged or tampered)",
                self.signature.key_id
            )));
        }
        Ok(())
    }

    /// Whether the profile file with this digest is revoked.
    pub fn revokes_digest(&self, digest: &str) -> bool {
        self.revoked_digests.iter().any(|d| d == digest)
    }

    /// Whether this signing key id is revoked.
    pub fn revokes_key(&self, key_id: &str) -> bool {
        self.revoked_key_ids.iter().any(|k| k == key_id)
    }

    /// Refuse `v` if its digest or its signing key is revoked.
    pub fn check(&self, v: &VerifiedProfile) -> Result<(), ProfileTrustError> {
        if self.revokes_digest(&v.digest) {
            return Err(ProfileTrustError::RevokedProfile {
                digest: v.digest.clone(),
                serial: self.serial,
            });
        }
        if let Some(k) = v.signed_by.as_deref().filter(|k| self.revokes_key(k)) {
            return Err(ProfileTrustError::RevokedKey {
                key_id: k.to_string(),
                serial: self.serial,
            });
        }
        Ok(())
    }
}

/// Read, parse and verify the list at `path` under `roots`; `Ok(None)` if
/// the file does not exist (the caller applies [`RevocationPolicy`]).
pub fn load_revocation_list(
    path: &Path,
    roots: &TrustRoots,
) -> Result<Option<RevocationList>, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::Revocations {
        detail: format!("{}: {detail}", path.display()),
    };
    let Some(text) =
        read_optional_text(path, MAX_REVOCATION_BYTES).map_err(|e| bad(e.to_string()))?
    else {
        return Ok(None);
    };
    let l = RevocationList::parse(&text).map_err(|e| match e {
        ProfileTrustError::Revocations { detail } => bad(detail),
        other => other,
    })?;
    l.verify(roots).map_err(|e| match e {
        ProfileTrustError::Revocations { detail } => bad(detail),
        other => other,
    })?;
    Ok(Some(l))
}
