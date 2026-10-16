//! Ed25519 signatures (RFC 8032, PureEdDSA) and an asymmetric [`Signer`] /
//! [`Verifier`] backend built on them.
//!
//! # Why this exists
//!
//! The interim [`crate::sign::HmacSha256Key`] is symmetric: anyone who can
//! verify can forge. Ed25519 removes that: the robot holds the private seed,
//! fleet verifiers hold only the 32-byte public key and cannot create valid
//! records.
//!
//! # Implementation
//!
//! The curve and scalar arithmetic come from the audited
//! [`ed25519-dalek`](https://docs.rs/ed25519-dalek) 2.x crate (on top of
//! `curve25519-dalek`, constant-time, with the `zeroize` feature so the
//! signing key's seed and expanded secret are wiped on drop). SHA-512 comes
//! from RustCrypto's `sha2`, the same implementation `ed25519-dalek` uses.
//! This module is a thin wrapper that keeps RoboDR's contract stable: the
//! `"ed25519"` algorithm id, the key-id derivation ([`derive_key_id`]), the
//! on-disk formats (32-byte seed, 32-byte public key, 64 raw signature bytes
//! `R || S`) and the strict verification rules below are unchanged from the
//! earlier in-crate implementation, and every RFC 8032 §7.1 vector and the
//! OpenSSL cross-check vectors still pass.
//!
//! The seed comes from [`crate::crypto::fill_random`] (`getrandom(2)`), not
//! from a `rand_core` RNG.
//!
//! # Verification rules
//!
//! [`verify`] is stricter than the minimum RFC 8032 §5.1.7 requires, in the
//! direction of rejecting more. It is `ed25519-dalek`'s `verify_strict` plus
//! an explicit canonicality check on the public key:
//! - signature length must be exactly 64 bytes;
//! - `S` must be canonical (`S < L`), which rules out `S + L` malleability;
//! - `A` and `R` must decode (§5.1.3) and be **canonical**: `y < p`, and
//!   `x = 0` with the sign bit set is rejected (for `R` this follows from
//!   comparing the re-encoded `R`; for `A` it is checked on construction);
//! - `A` and `R` must not be of **small order** (order dividing 8, including
//!   the identity). This defeats the "identity key verifies everything" class
//!   of forgeries and matches libsodium;
//! - the check is the **cofactorless** equation `[S]B = R + [k]A` with
//!   `k = SHA-512(R || A || M) mod L`.
//!
//! Points of mixed order (a large-order point plus a small-order torsion
//! component) are not rejected; for signatures produced by an honest signer
//! that never happens, and cofactorless verification is deterministic about
//! them. Only PureEdDSA (`Ed25519`) is provided, not `Ed25519ctx`/`Ed25519ph`.

use crate::crypto::{fill_random, sha256, to_hex, wipe};
use crate::sign::{SignError, Signer, Verifier, MAX_KEY_ID_LEN};
use ed25519_dalek::Signer as _;
use sha2::Digest as _;
use std::fmt;

/// Algorithm name recorded in the chain identity for Ed25519 keys.
pub const ED25519: &str = "ed25519";
/// Seed (private key) length in bytes.
pub const SEED_LEN: usize = ed25519_dalek::SECRET_KEY_LENGTH;
/// Public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
/// Signature length in bytes (`R || S`).
pub const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

const KEY_ID_DOMAIN: &[u8] = b"robodr-blackbox/ed25519-key-id/v1\0";

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4), via RustCrypto `sha2`
// ---------------------------------------------------------------------------

/// SHA-512 block size in bytes.
pub const SHA512_BLOCK_LEN: usize = 128;
/// SHA-512 digest size in bytes.
pub const SHA512_DIGEST_LEN: usize = 64;

/// Streaming SHA-512 hasher (FIPS 180-4).
#[derive(Clone, Default)]
pub struct Sha512(sha2::Sha512);

impl Sha512 {
    /// A fresh hasher.
    pub fn new() -> Self {
        Self(sha2::Sha512::new())
    }

    /// Absorb `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finish and return the 64-byte digest.
    pub fn finalize(self) -> [u8; SHA512_DIGEST_LEN] {
        self.0.finalize().into()
    }
}

/// One-shot SHA-512.
pub fn sha512(data: &[u8]) -> [u8; SHA512_DIGEST_LEN] {
    sha2::Sha512::digest(data).into()
}

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032 §5.1.5 - §5.1.7), via ed25519-dalek
// ---------------------------------------------------------------------------

/// Strict public-key decoding: the bytes must decode to a curve point, be its
/// canonical encoding (`y < p`, no `x = 0` with the sign bit set) and the
/// point must not be of small order.
fn decode_public_strict(bytes: &[u8; PUBLIC_KEY_LEN]) -> Option<ed25519_dalek::VerifyingKey> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes).ok()?;
    // `from_bytes` accepts non-canonical `y`; re-encoding exposes it.
    if vk.to_edwards().compress().to_bytes() != *bytes || vk.is_weak() {
        return None;
    }
    Some(vk)
}

/// Derive the public key `A = [s]B` from a 32-byte seed (RFC 8032 §5.1.5).
pub fn public_key_from_seed(seed: &[u8; SEED_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// Sign `message` with the key derived from `seed` (RFC 8032 §5.1.6).
/// Deterministic: the same seed and message always give the same signature.
pub fn sign(seed: &[u8; SEED_LEN], message: &[u8]) -> [u8; SIGNATURE_LEN] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .sign(message)
        .to_bytes()
}

fn verify_key(vk: &ed25519_dalek::VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    let Ok(sig) = <&[u8; SIGNATURE_LEN]>::try_from(signature) else {
        return false;
    };
    // `verify_strict` rejects non-canonical `S`, a small-order `R` or `A`,
    // and (by comparing encodings) a non-canonical `R`.
    vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(sig))
        .is_ok()
}

/// Strict, cofactorless Ed25519 verification (see the module docs for the
/// exact rules). Never panics; any malformed input yields `false`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(a_bytes) = <&[u8; PUBLIC_KEY_LEN]>::try_from(public_key) else {
        return false;
    };
    let Some(vk) = decode_public_strict(a_bytes) else {
        return false;
    };
    verify_key(&vk, message, signature)
}

// ---------------------------------------------------------------------------
// Signer / Verifier backend
// ---------------------------------------------------------------------------

/// Why an Ed25519 key could not be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed25519Error {
    /// Key id is empty, longer than [`MAX_KEY_ID_LEN`], or not printable ASCII.
    BadKeyId,
    /// Public key is not a canonical encoding of a point of large order.
    InvalidPublicKey,
    /// The operating-system randomness source failed.
    Rng(String),
}

impl fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ed25519Error::BadKeyId => write!(
                f,
                "key id must be 1..={MAX_KEY_ID_LEN} printable ASCII characters"
            ),
            Ed25519Error::InvalidPublicKey => {
                write!(f, "not a valid (canonical, large-order) Ed25519 public key")
            }
            Ed25519Error::Rng(e) => write!(f, "randomness source failed: {e}"),
        }
    }
}

impl std::error::Error for Ed25519Error {}

fn check_key_id(key_id: &str) -> Result<(), Ed25519Error> {
    if key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_LEN
        || !key_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(Ed25519Error::BadKeyId);
    }
    Ok(())
}

/// `ed25519:` + first 8 bytes of SHA-256(domain || public key), in hex.
/// Signing and verifying halves derive the same id from the public key.
pub fn derive_key_id(public: &[u8; PUBLIC_KEY_LEN]) -> String {
    let mut m = KEY_ID_DOMAIN.to_vec();
    m.extend_from_slice(public);
    format!("{ED25519}:{}", to_hex(&sha256(&m)[..8]))
}

/// A fresh 32-byte seed from the kernel CSPRNG ([`fill_random`]:
/// `getrandom(2)`, `/dev/urandom` only where the syscall is missing). Fails
/// rather than fall back to anything weaker; an all-zero read is treated as
/// a broken source. The caller must wipe the returned seed.
pub fn random_seed() -> Result<[u8; SEED_LEN], Ed25519Error> {
    let mut seed = [0u8; SEED_LEN];
    if let Err(e) = fill_random(&mut seed) {
        wipe(&mut seed);
        return Err(Ed25519Error::Rng(e.to_string()));
    }
    Ok(seed)
}

/// Ed25519 private key (32-byte seed) usable as a recorder [`Signer`].
/// Secret material is wiped on drop (`ed25519-dalek`'s `zeroize`); `Debug`
/// redacts it.
pub struct Ed25519SigningKey {
    key_id: String,
    key: ed25519_dalek::SigningKey,
    public: [u8; PUBLIC_KEY_LEN],
}

impl Ed25519SigningKey {
    /// Key from an existing seed under an explicit key id.
    pub fn from_seed(
        key_id: impl Into<String>,
        seed: &[u8; SEED_LEN],
    ) -> Result<Self, Ed25519Error> {
        let key_id = key_id.into();
        check_key_id(&key_id)?;
        let key = ed25519_dalek::SigningKey::from_bytes(seed);
        let public = key.verifying_key().to_bytes();
        Ok(Self {
            key_id,
            key,
            public,
        })
    }

    /// Key from an existing seed, key id derived from the public key
    /// ([`derive_key_id`]).
    pub fn from_seed_with_derived_id(seed: &[u8; SEED_LEN]) -> Self {
        let public = public_key_from_seed(seed);
        Self::from_seed(derive_key_id(&public), seed).expect("derived key id is valid")
    }

    /// Fresh key from [`random_seed`] under an explicit key id.
    pub fn generate(key_id: impl Into<String>) -> Result<Self, Ed25519Error> {
        let mut seed = random_seed()?;
        let k = Self::from_seed(key_id, &seed);
        wipe(&mut seed);
        k
    }

    /// Fresh key from [`random_seed`] with a derived key id.
    pub fn generate_with_derived_id() -> Result<Self, Ed25519Error> {
        let mut seed = random_seed()?;
        let k = Self::from_seed_with_derived_id(&seed);
        wipe(&mut seed);
        Ok(k)
    }

    /// The 32-byte public key `A`.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// The matching verifier, under the same key id.
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey::from_bytes(self.key_id.clone(), &self.public)
            .expect("public key of a clamped scalar is valid")
    }

    /// **Secret.** The seed, for sealing the key at rest (e.g. to a TPM).
    /// Callers must wipe the returned copy when done.
    pub fn to_seed(&self) -> [u8; SEED_LEN] {
        self.key.to_bytes()
    }

    /// Sign `message`, returning the 64-byte `R || S`.
    pub fn sign_message(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.key.sign(message).to_bytes()
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("key_id", &self.key_id)
            .field("public", &to_hex(&self.public))
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl Signer for Ed25519SigningKey {
    fn algorithm(&self) -> &str {
        ED25519
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.sign_message(message).to_vec())
    }
    fn verify_own(&self, message: &[u8], signature: &[u8]) -> Option<bool> {
        Some(verify(&self.public, message, signature))
    }
}

/// Ed25519 public key usable as a [`Verifier`]. Construction validates the
/// key (canonical, not small order), so a verifier can never be built
/// around a key that would accept forged signatures.
#[derive(Clone)]
pub struct Ed25519VerifyingKey {
    key_id: String,
    public: [u8; PUBLIC_KEY_LEN],
    key: ed25519_dalek::VerifyingKey,
}

impl Ed25519VerifyingKey {
    /// Wrap a 32-byte public key under an explicit key id.
    pub fn from_bytes(
        key_id: impl Into<String>,
        public: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Self, Ed25519Error> {
        let key_id = key_id.into();
        check_key_id(&key_id)?;
        let key = decode_public_strict(public).ok_or(Ed25519Error::InvalidPublicKey)?;
        Ok(Self {
            key_id,
            public: *public,
            key,
        })
    }

    /// Wrap a public key with the derived key id ([`derive_key_id`]).
    pub fn from_bytes_with_derived_id(public: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, Ed25519Error> {
        Self::from_bytes(derive_key_id(public), public)
    }

    /// The 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }
}

impl fmt::Debug for Ed25519VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519VerifyingKey")
            .field("key_id", &self.key_id)
            .field("public", &to_hex(&self.public))
            .finish()
    }
}

impl Verifier for Ed25519VerifyingKey {
    fn algorithm(&self) -> &str {
        ED25519
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        verify_key(&self.key, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::from_hex;

    fn h32(s: &str) -> [u8; 32] {
        from_hex(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn random_seed_reads_urandom() {
        let a = random_seed().unwrap();
        let b = random_seed().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn debug_redacts_seed() {
        let k = Ed25519SigningKey::from_seed("dbg", &[0x5a; 32]).unwrap();
        let s = format!("{k:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("5a5a5a"));
    }

    #[test]
    fn seed_round_trips_through_the_dalek_key() {
        let k = Ed25519SigningKey::from_seed("rt", &[0x11; 32]).unwrap();
        assert_eq!(k.to_seed(), [0x11; 32]);
        assert_eq!(k.public_key(), public_key_from_seed(&[0x11; 32]));
    }

    #[test]
    fn strict_public_decode_rejects_non_canonical_and_small_order() {
        let base = h32("5866666666666666666666666666666666666666666666666666666666666666");
        assert!(decode_public_strict(&base).is_some());
        for bad in [
            // identity, (0,-1), y = p, y = p + 1, x = 0 with the sign bit
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0100000000000000000000000000000000000000000000000000000000000080",
        ] {
            assert!(decode_public_strict(&h32(bad)).is_none(), "{bad}");
        }
        // Non-canonical y for every value in [p, 2^255) that decodes at all:
        // the strict decoder must never accept one, small order or not.
        let p = h32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        for k in 0..19u8 {
            for sign in [0u8, 0x80] {
                let mut b = p;
                b[0] += k;
                b[31] |= sign;
                assert!(
                    decode_public_strict(&b).is_none(),
                    "y = p + {k}, sign {sign}"
                );
            }
        }
    }
}
