//! # robodr-seal
//!
//! Captured-unit software protection for RoboDR's secure delivery
//! (`docs/SECURE-DELIVERY.md` §7, Sprint 13c):
//!
//! * [`chunk`]: the content key `CK` of a sealed RPK and its chunks:
//!   XChaCha20-Poly1305 with keys derived by HKDF-SHA256, a synthetic
//!   nonce per chunk, the chunk's position and the RPK's `seal_id` as
//!   associated data, a key commitment and keyed file digests (§7.2);
//! * [`wrap`]: `wrap(recipient, CK)`: ephemeral-static ECDH (X25519 to a
//!   depot or a unit without a TPM, P-256 to a unit's TPM-resident `UWK`),
//!   HKDF, XChaCha20-Poly1305, bound to what the key is for (§7.1, §7.3);
//! * [`keys`]: key files (X25519 wrapping keys, the P-256 policy authority
//!   key) and fingerprints;
//! * [`policy`]: the **signed PCR policy** (`TPM2_PolicyAuthorize`), its
//!   policy digests computed offline exactly as the TPM does, and the
//!   erase-epoch and policy-floor NV conditions (§7.4, §7.6);
//! * [`tpm`]: the unit side driven through `tpm2-tools` (the approach of
//!   `robodr-blackbox`'s `TpmNvCounterAnchor`): provisioning, the
//!   TPM-resident `UWK`, unwrap under a salted, encrypting policy session,
//!   policy revocation and crypto-erase;
//! * [`luks`]: the LUKS2 runtime volume (`cryptsetup`) and the Clevis/Tang
//!   fallback (`clevis`), §7.4, §7.7;
//! * [`unit`]: a unit's sealing state (`unit.json`, the TPM blobs, the
//!   installed signed policy) and the operations `robodr-deliverd` and the
//!   `robodr-seal` CLI use: unwrap a content key, open the volume, erase;
//! * [`rpk`]: sealed RPKs end to end: seal at release, re-wrap per unit
//!   at the depot, open on the unit;
//! * [`cmd`]: the bounded subprocess runner (cleared environment, stdin,
//!   timeout, captured output wiped after use).
//!
//! Key material is held in [`zeroize::Zeroizing`] buffers and compared in
//! constant time. Nothing here decides *whether* to install or erase: that
//! is `robodr-deliverd`'s (and, for executed erase, `robodr-responder`'s
//! in 14b).

// S10: no unsafe code at all in this crate.
#![forbid(unsafe_code)]
// Review L3 (S10, R9): release builds use `panic = "abort"`; non-test code
// has no unwrap / expect / panic!-family call.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod chunk;
pub mod cli;
pub mod cmd;
pub mod keys;
pub mod luks;
pub mod mounts;
pub mod policy;
pub mod rpk;
pub mod tpm;
pub mod unit;
pub mod wrap;

use std::fmt;

/// Why a sealing operation failed. `kind` is stable (it decides the
/// finding: [`ErrorKind::PolicyRefused`] and [`ErrorKind::Erased`] are
/// `robot.seal.unseal_failed`); `detail` is for humans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealError {
    pub kind: ErrorKind,
    pub detail: String,
}

/// Stable failure classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Malformed input (a wrap, a policy, a key file, an argument).
    Invalid,
    /// Authentication failed: a chunk, a wrap or a key commitment does not
    /// verify (tampered, truncated, reordered, for another unit or RPK, or
    /// the wrong key).
    Unauthentic,
    /// The TPM refused the policy: the boot measurements (PCRs) do not
    /// match the signed policy, the policy was revoked (floor), or its
    /// signature is not the policy authority's.
    PolicyRefused,
    /// The unit's keys were crypto-erased (the epoch moved on, or the key
    /// material is gone).
    Erased,
    /// A tool, the TPM or the Tang server could not be reached or failed.
    Unavailable,
    /// Local file-system failure.
    Io,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Invalid => "invalid",
            ErrorKind::Unauthentic => "unauthentic",
            ErrorKind::PolicyRefused => "policy_refused",
            ErrorKind::Erased => "erased",
            ErrorKind::Unavailable => "unavailable",
            ErrorKind::Io => "io",
        }
    }
}

impl SealError {
    pub fn new(kind: ErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.detail)
    }
}

impl std::error::Error for SealError {}

pub(crate) fn invalid(detail: impl Into<String>) -> SealError {
    SealError::new(ErrorKind::Invalid, detail)
}

pub(crate) fn unauthentic(detail: impl Into<String>) -> SealError {
    SealError::new(ErrorKind::Unauthentic, detail)
}

pub(crate) fn io_err(p: &std::path::Path, e: impl fmt::Display) -> SealError {
    SealError::new(ErrorKind::Io, format!("{}: {e}", p.display()))
}

/// `O_NOFOLLOW` (declared by hand like `robodr-blackbox`'s `store::sys`:
/// no libc crate; its value differs between architectures).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const O_NOFOLLOW: i32 = if cfg!(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc",
    target_arch = "powerpc64"
)) {
    0o100000
} else {
    0o400000
};
/// Elsewhere: no flag (the opened file is still checked to be a regular
/// file; creation is `O_EXCL`, which never follows a final symlink).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) const O_NOFOLLOW: i32 = 0;

/// 32 bytes from the kernel CSPRNG (`robodr-blackbox`'s `getrandom(2)`).
pub(crate) fn random32() -> Result<zeroize::Zeroizing<[u8; 32]>, SealError> {
    let mut b = zeroize::Zeroizing::new([0u8; 32]);
    robodr_blackbox::crypto::fill_random(&mut b[..])
        .map_err(|e| SealError::new(ErrorKind::Unavailable, format!("randomness: {e}")))?;
    Ok(b)
}

/// Lower-case hex.
pub fn to_hex(b: &[u8]) -> String {
    robodr_blackbox::crypto::to_hex(b)
}

/// Strict lower-case hex decode.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    robodr_blackbox::crypto::from_hex(s)
}

/// Constant-time equality (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
