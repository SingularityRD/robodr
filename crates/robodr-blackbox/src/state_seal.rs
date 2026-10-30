//! Keys that seal a daemon's **operational state files** (agentd's
//! control-plane journals, the executor's journal) against edits by someone
//! who can write the state directory but does not hold the daemon's key.
//!
//! A [`StateSealKey`] is never a key file of its own: it is derived from a
//! key the daemon already holds (agentd: the black-box key; the executor:
//! its link key), one key per `purpose`:
//!
//! ```text
//! K_purpose = HMAC-SHA256(root secret, "robodr-state-seal/v1\0" || purpose)
//! tag       = HMAC-SHA256(K_purpose, domain || 0x00 || for each part: u32 BE length || part)
//! key id    = "hmac-sha256:" + first 8 bytes of SHA-256(key-id domain || K_purpose), hex
//! ```
//!
//! so the root key never MACs state bytes directly, two purposes never share
//! a key, and the parts of a tag cannot be shifted into each other. The key
//! id (written into every sealed file's header) names the key without
//! revealing it, so a file sealed under another key (a rotated black-box
//! key, another unit's state) is told apart from an edited one.
//!
//! It is the same RFC 2104 HMAC-SHA256 as the legacy black-box signer
//! ([`crate::crypto::hmac_sha256`]) and the same key-id derivation as
//! [`crate::sign::HmacSha256Key::with_derived_id`]: nothing new is built
//! here. HMAC is symmetric, which is fine for state only the daemon itself
//! reads back; the derived key is wiped on drop.
//!
//! A seal makes edits, deletions and reordering **detectable**; it cannot
//! tell an old sealed file from the current one. Rollback and truncation
//! need a head bound to something the attacker cannot rewind (agentd binds
//! its journal heads to signed black-box notes).

use crate::crypto::{ct_eq, hmac_sha256, wipe};
use crate::sign::{HmacSha256Key, KeyError, Verifier, MIN_HMAC_KEY_LEN};
use std::fmt;

/// Domain of the key derivation.
const DERIVE_DOMAIN: &[u8] = b"robodr-state-seal/v1\0";
/// Tag length (bytes).
pub const TAG_LEN: usize = 32;

/// A derived state-sealing key (see the module).
pub struct StateSealKey {
    key: [u8; 32],
    key_id: String,
}

impl Drop for StateSealKey {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

impl fmt::Debug for StateSealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateSealKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl StateSealKey {
    /// Derive the key for `purpose` from `root` (an Ed25519 seed or an HMAC
    /// secret, at least 32 bytes).
    pub fn derive(root: &[u8], purpose: &str) -> Result<Self, KeyError> {
        if root.len() < MIN_HMAC_KEY_LEN {
            return Err(KeyError::TooShort {
                len: root.len(),
                min: MIN_HMAC_KEY_LEN,
            });
        }
        let mut m = DERIVE_DOMAIN.to_vec();
        m.extend_from_slice(purpose.as_bytes());
        let key = hmac_sha256(root, &m);
        let key_id = HmacSha256Key::with_derived_id(&key)?.key_id().to_string();
        Ok(Self { key, key_id })
    }

    /// The derived key's id (`hmac-sha256:<16 hex>`).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The tag of `parts` under `domain` (length-prefixed, see the module).
    pub fn tag(&self, domain: &str, parts: &[&[u8]]) -> [u8; TAG_LEN] {
        let mut m =
            Vec::with_capacity(domain.len() + 1 + parts.iter().map(|p| p.len() + 4).sum::<usize>());
        m.extend_from_slice(domain.as_bytes());
        m.push(0);
        for p in parts {
            m.extend_from_slice(&(p.len() as u32).to_be_bytes());
            m.extend_from_slice(p);
        }
        hmac_sha256(&self.key, &m)
    }

    /// Whether `tag` is the tag of `parts` under `domain` (constant time).
    pub fn check(&self, domain: &str, parts: &[&[u8]], tag: &[u8]) -> bool {
        ct_eq(&self.tag(domain, parts), tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_separates_purposes_and_roots() {
        let a = StateSealKey::derive(&[7; 32], "agentd").unwrap();
        let a2 = StateSealKey::derive(&[7; 32], "agentd").unwrap();
        let b = StateSealKey::derive(&[7; 32], "executor").unwrap();
        let c = StateSealKey::derive(&[8; 32], "agentd").unwrap();
        assert_eq!(a.key_id(), a2.key_id());
        assert_ne!(a.key_id(), b.key_id());
        assert_ne!(a.key_id(), c.key_id());
        assert!(a.key_id().starts_with("hmac-sha256:"));
        let t = a.tag("d", &[b"x", b"y"]);
        assert!(a2.check("d", &[b"x", b"y"], &t));
        assert!(!b.check("d", &[b"x", b"y"], &t), "another purpose");
        assert!(!c.check("d", &[b"x", b"y"], &t), "another root");
        assert!(!a.check("e", &[b"x", b"y"], &t), "another domain");
        // Length prefixes: parts cannot be shifted into each other.
        assert!(!a.check("d", &[b"xy", b""], &t));
        assert!(!a.check("d", &[b"x", b"y"], &t[..31]));
        assert!(StateSealKey::derive(&[7; 31], "agentd").is_err());
        assert!(!format!("{a:?}").contains("key:"), "Debug hides the key");
    }
}
