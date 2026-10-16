//! Record authenticity: the [`Signer`] / [`Verifier`] traits and the interim
//! HMAC-SHA256 implementation.
//!
//! # Why traits
//!
//! The recorder signs every record hash through [`Signer`]; the verifier checks
//! through [`Verifier`]. Neither knows the algorithm. A production backend is a
//! drop-in: implement both traits for Ed25519 (from an audited crate) or for a
//! TPM-resident ECDSA key, set `algorithm()` to e.g. `"ed25519"`, and the
//! record format, chain, storage and verification logic stay unchanged
//! (signatures are length-prefixed, up to [`crate::record::MAX_SIG_LEN`] bytes).
//!
//! # Why HMAC is only a placeholder
//!
//! [`HmacSha256Key`] is a *symmetric* MAC: whoever can verify can also forge.
//! On a robot this means: the key must be protected (e.g. sealed to the TPM and
//! unsealed only into the recorder process), and anyone who extracts it (root on
//! the unit plus a successful unseal) can rewrite the whole history with valid
//! tags. A fleet verifier that holds the same key could also forge evidence,
//! which defeats non-repudiation. Asymmetric signatures with a non-exportable
//! private key fix both problems; HMAC is used now only because no audited
//! asymmetric implementation is available offline.

use crate::crypto::{ct_eq, hmac_sha256, sha256, to_hex, wipe};
use std::fmt;

/// Algorithm name recorded in the chain identity for [`HmacSha256Key`].
pub const HMAC_SHA256: &str = "hmac-sha256";
/// Minimum HMAC key length accepted (full 256-bit strength).
pub const MIN_HMAC_KEY_LEN: usize = 32;
/// Maximum key-id length (it is stored in every chain identity).
pub const MAX_KEY_ID_LEN: usize = 128;

const KEY_ID_DOMAIN: &[u8] = b"robodr-blackbox/key-id/v1\0";

/// A signing backend failed (e.g. TPM unavailable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignError(pub String);

impl SignError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signing failed: {}", self.0)
    }
}

impl std::error::Error for SignError {}

/// Produces signatures over record-hash messages.
pub trait Signer: Send {
    /// Algorithm identifier, e.g. `"hmac-sha256"`, `"ed25519"`.
    fn algorithm(&self) -> &str;
    /// Stable identifier of the key, bound into the chain identity.
    fn key_id(&self) -> &str;
    /// Sign `message`. May fail (hardware-backed keys).
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
    /// Check a signature made by this key, if the backend can do so without
    /// a separate [`Verifier`] (HMAC: recompute; Ed25519/ECDSA: the public
    /// half). `None` (the default) means "cannot self-verify"; such a signer
    /// must be opened with [`crate::Recorder::open_with_verifier`].
    ///
    /// The recorder uses this to authenticate the existing log tail and its
    /// own state files before it chains onto them.
    fn verify_own(&self, message: &[u8], signature: &[u8]) -> Option<bool> {
        let _ = (message, signature);
        None
    }
}

/// Checks signatures produced by the matching [`Signer`].
pub trait Verifier {
    fn algorithm(&self) -> &str;
    fn key_id(&self) -> &str;
    /// `true` iff `signature` is valid for `message` under this key.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
    /// `true` iff `signature` is valid for `message` under the key named
    /// `key_id`. The default accepts only this verifier's own key id; a
    /// [`crate::keys::Keyring`] looks the key up instead.
    fn verify_as(&self, key_id: &str, message: &[u8], signature: &[u8]) -> bool {
        self.key_id() == key_id && self.verify(message, signature)
    }
}

/// Why an HMAC key was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    TooShort { len: usize, min: usize },
    BadKeyId,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::TooShort { len, min } => {
                write!(f, "HMAC key is {len} bytes, at least {min} required")
            }
            KeyError::BadKeyId => write!(
                f,
                "key id must be 1..={MAX_KEY_ID_LEN} printable ASCII characters"
            ),
        }
    }
}

impl std::error::Error for KeyError {}

/// Interim shared-key authenticator (HMAC-SHA256). See the module docs for
/// why this must be replaced by an asymmetric signer in production.
pub struct HmacSha256Key {
    key_id: String,
    key: Vec<u8>,
}

impl HmacSha256Key {
    /// Wrap `key` (>= 32 bytes) under an explicit `key_id`.
    pub fn new(key_id: impl Into<String>, key: &[u8]) -> Result<Self, KeyError> {
        let key_id = key_id.into();
        if key_id.is_empty()
            || key_id.len() > MAX_KEY_ID_LEN
            || !key_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(KeyError::BadKeyId);
        }
        if key.len() < MIN_HMAC_KEY_LEN {
            return Err(KeyError::TooShort {
                len: key.len(),
                min: MIN_HMAC_KEY_LEN,
            });
        }
        Ok(Self {
            key_id,
            key: key.to_vec(),
        })
    }

    /// Wrap `key` with a key id derived from it:
    /// `hmac-sha256:` + first 8 bytes of SHA-256(domain || key), in hex.
    /// (A one-way digest of a 256-bit secret does not help an attacker.)
    pub fn with_derived_id(key: &[u8]) -> Result<Self, KeyError> {
        let mut m = KEY_ID_DOMAIN.to_vec();
        m.extend_from_slice(key);
        let d = sha256(&m);
        wipe(&mut m);
        Self::new(format!("{HMAC_SHA256}:{}", to_hex(&d[..8])), key)
    }
}

impl Drop for HmacSha256Key {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

impl fmt::Debug for HmacSha256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacSha256Key")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Signer for HmacSha256Key {
    fn algorithm(&self) -> &str {
        HMAC_SHA256
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(hmac_sha256(&self.key, message).to_vec())
    }
    fn verify_own(&self, message: &[u8], signature: &[u8]) -> Option<bool> {
        Some(ct_eq(&hmac_sha256(&self.key, message), signature))
    }
}

impl Verifier for HmacSha256Key {
    fn algorithm(&self) -> &str {
        HMAC_SHA256
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        ct_eq(&hmac_sha256(&self.key, message), signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_keys_and_bad_ids() {
        assert_eq!(
            HmacSha256Key::new("k", &[1; 31]).unwrap_err(),
            KeyError::TooShort { len: 31, min: 32 }
        );
        assert_eq!(
            HmacSha256Key::new("", &[1; 32]).unwrap_err(),
            KeyError::BadKeyId
        );
        assert_eq!(
            HmacSha256Key::new("has space", &[1; 32]).unwrap_err(),
            KeyError::BadKeyId
        );
        assert_eq!(
            HmacSha256Key::new("x".repeat(129), &[1; 32]).unwrap_err(),
            KeyError::BadKeyId
        );
    }

    #[test]
    fn sign_verify_and_wrong_key() {
        let a = HmacSha256Key::new("a", &[7; 32]).unwrap();
        let b = HmacSha256Key::new("a", &[8; 32]).unwrap();
        let sig = a.sign(b"msg").unwrap();
        assert_eq!(sig.len(), 32);
        assert!(a.verify(b"msg", &sig));
        assert!(!a.verify(b"msh", &sig));
        assert!(!b.verify(b"msg", &sig));
        assert!(!a.verify(b"msg", &sig[..31]));
        assert!(!a.verify(b"msg", &[]));
        assert_eq!(a.verify_own(b"msg", &sig), Some(true));
        assert_eq!(a.verify_own(b"msh", &sig), Some(false));
        assert_eq!(b.verify_own(b"msg", &sig), Some(false));
    }

    #[test]
    fn default_signer_cannot_self_verify() {
        struct Opaque;
        impl Signer for Opaque {
            fn algorithm(&self) -> &str {
                "x"
            }
            fn key_id(&self) -> &str {
                "x"
            }
            fn sign(&self, _: &[u8]) -> Result<Vec<u8>, SignError> {
                Ok(vec![1])
            }
        }
        assert_eq!(Opaque.verify_own(b"m", &[1]), None);
    }

    #[test]
    fn derived_id_is_stable_and_key_specific() {
        let a = HmacSha256Key::with_derived_id(&[1; 32]).unwrap();
        let a2 = HmacSha256Key::with_derived_id(&[1; 32]).unwrap();
        let b = HmacSha256Key::with_derived_id(&[2; 32]).unwrap();
        assert_eq!(Signer::key_id(&a), Signer::key_id(&a2));
        assert_ne!(Signer::key_id(&a), Signer::key_id(&b));
        assert!(Signer::key_id(&a).starts_with("hmac-sha256:"));
    }

    #[test]
    fn debug_redacts_key() {
        let a = HmacSha256Key::new("dbg", &[0x5a; 32]).unwrap();
        let s = format!("{a:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("90")); // 0x5a == 90
    }
}
