//! # robodr-signer
//!
//! Key providers (`docs/SALES-READINESS.md` T36, T66).
//!
//! ## Commissioning and release keys (T36)
//!
//! [`load`] turns the `--key` / `--sign-key` argument of
//! `robodr-commission` and `robodr-release` into a [`KeySigner`], an
//! Ed25519 [`robodr_blackbox::Signer`] with a known public key. The path
//! names either
//!
//! * a `robodr-blackbox` **secret key file** (what `keygen` writes; the
//!   seed is in the file, [`Backend::File`]), or
//! * a **signer file** (`"format": "robodr-signer/v1"`, no secret in it)
//!   that names an **external signer command** ([`Backend::External`]):
//!   the private key stays in a token or HSM and the command asks it for
//!   each signature. The PKCS#11 adapter shipped in
//!   `crates/robodr-signer/adapters/robodr-signer-pkcs11` (OpenSC
//!   `pkcs11-tool`, `CKM_EDDSA`) drives YubiKey, Nitrokey, SoftHSM and
//!   network HSMs this way.
//!
//! ```json
//! {
//!   "format": "robodr-signer/v1",
//!   "backend": "external",
//!   "key_id": "release-1",
//!   "public_key_hex": "<64 hex: the token key's Ed25519 public key>",
//!   "command": ["/usr/lib/robodr/robodr-signer-pkcs11", "sign",
//!               "--module", "/usr/lib/x86_64-linux-gnu/libykcs11.so",
//!               "--id", "01", "--pin-env", "ROBODR_PKCS11_PIN"],
//!   "pass_env": ["ROBODR_PKCS11_PIN"],
//!   "timeout_ms": 120000
//! }
//! ```
//!
//! ### The external signer protocol (`robodr-signer/v1`)
//!
//! The command is run directly (no shell) with `command[1..]` as its
//! arguments and a **cleared environment**: only `PATH`
//! ([`external::SAFE_PATH`]), `LC_ALL=C`, `ROBODR_SIGNER_PROTOCOL=1`,
//! `ROBODR_SIGNER_ALGORITHM=ed25519`, `ROBODR_SIGNER_KEY_ID` and the
//! variables named in `pass_env` (copied from the caller when set).
//!
//! * **stdin**: exactly the message to sign (raw bytes, then EOF). The
//!   message is what the caller signs (a domain-separated document); the
//!   signer must sign it as pure Ed25519 (RFC 8032, not prehashed), which
//!   is PKCS#11 `CKM_EDDSA` without parameters.
//! * **stdout**: the 64-byte signature, raw or as 128 hex digits
//!   (trailing whitespace allowed), nothing else; at most
//!   [`external::MAX_OUTPUT_BYTES`].
//! * **stderr**: passed through to the operator ("touch your key").
//! * **process group**: the command runs in a process group of its own,
//!   and on a timeout, or when it exits leaving its stdout open, the whole
//!   group is killed (SIGKILL), so a `pkcs11-tool` the adapter started
//!   does not outlive the call. It is therefore not in the terminal's
//!   foreground group and cannot read the terminal: the PIN comes from a
//!   `pass_env` variable or a file, never a prompt. A Ctrl-C at the
//!   terminal stops the caller only; the command then runs on until it
//!   finishes or writes to its closed stdout.
//! * **exit status** 0 on success. Anything else, a timeout
//!   (`timeout_ms`, default [`external::DEFAULT_TIMEOUT_MS`]), or a
//!   signature that does **not verify under `public_key_hex`** is an
//!   error: the caller never receives a signature that was not checked
//!   against the pinned public key, so a wrong slot, a swapped token or a
//!   lying adapter cannot slip a foreign signature into a quorum.
//!
//! The signer file is a trust anchor (whoever edits it chooses what runs
//! with the operator's rights): it must be a regular file, not a symlink,
//! owned by root or the effective user and not group/other-writable. The
//! command must be an absolute path whose resolved file and every parent
//! directory pass the same owner/mode rule (like OpenSSH's `safe_path`).
//!
//! ## Robot-side keys (T66)
//!
//! [`credential`] classifies systemd encrypted credentials
//! (`systemd-creds encrypt`, `LoadCredentialEncrypted=`) by their header:
//! TPM2-sealed, host-key only, or the null key. `robodr-agentd` uses it to
//! report, per private key, whether the key is TPM-protected at rest and
//! to refuse to start when `key_protection.require` is `"tpm2"` and one is
//! not (see `crates/robodr-agentd/src/key_protection.rs`).

// S10: no unsafe code at all in this crate.
#![forbid(unsafe_code)]
// Release builds use `panic = "abort"`; non-test code has no unwrap /
// expect / panic!-family call and no unchecked indexing.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing
    )
)]

pub mod credential;
pub mod external;

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use robodr_blackbox::sign::{key_fingerprint, SignError};
use robodr_blackbox::sign_ed25519::{self, ED25519, PUBLIC_KEY_LEN};
use robodr_blackbox::{Ed25519SigningKey, Ed25519VerifyingKey, KeyFile, KeyFileError, Signer};
use serde::Deserialize;

/// `format` of a signer file.
pub const SIGNER_FORMAT: &str = "robodr-signer/v1";
/// Largest signer file read.
pub const MAX_SIGNER_FILE_BYTES: u64 = 64 * 1024;

/// Where a [`KeySigner`]'s private key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// A `robodr-blackbox` secret key file (the seed is on disk).
    File,
    /// An external signer command (token, HSM): the seed never reaches
    /// this process.
    External,
}

impl Backend {
    /// `"file"` or `"external"` (as printed by the tools).
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::File => "file",
            Backend::External => "external",
        }
    }
}

enum Inner {
    File(Ed25519SigningKey),
    External(external::ExternalSigner),
}

/// An Ed25519 signer with a known public key, whatever holds the private
/// half. Every signature it returns verifies under [`Self::public_key`].
pub struct KeySigner {
    key_id: String,
    public: [u8; PUBLIC_KEY_LEN],
    inner: Inner,
}

impl std::fmt::Debug for KeySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySigner")
            .field("key_id", &self.key_id)
            .field("backend", &self.backend())
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl KeySigner {
    /// A signer over an in-memory key ([`Backend::File`]).
    pub fn from_signing_key(key: Ed25519SigningKey) -> Self {
        Self {
            key_id: Signer::key_id(&key).to_string(),
            public: key.public_key(),
            inner: Inner::File(key),
        }
    }

    /// A signer over an external command ([`Backend::External`]).
    pub fn from_external(signer: external::ExternalSigner) -> Self {
        Self {
            key_id: signer.key_id().to_string(),
            public: signer.public_key(),
            inner: Inner::External(signer),
        }
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// The public key as a verifier under this signer's key id.
    pub fn verifying_key(&self) -> Result<Ed25519VerifyingKey, String> {
        Ed25519VerifyingKey::from_bytes(self.key_id.clone(), &self.public)
            .map_err(|e| e.to_string())
    }

    /// Where the private key lives.
    pub fn backend(&self) -> Backend {
        match self.inner {
            Inner::File(_) => Backend::File,
            Inner::External(_) => Backend::External,
        }
    }

    /// [`key_fingerprint`] of the public key.
    pub fn fingerprint(&self) -> String {
        key_fingerprint(&self.public)
    }
}

impl Signer for KeySigner {
    fn algorithm(&self) -> &str {
        ED25519
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let sig = match &self.inner {
            Inner::File(k) => Signer::sign(k, message)?,
            Inner::External(x) => x.sign(message).map_err(SignError::new)?,
        };
        // Checked for both backends: a signature that does not verify under
        // the pinned public key never leaves this function.
        if !sign_ed25519::verify(&self.public, message, &sig) {
            return Err(SignError::new(format!(
                "the {} signer for key {} returned a signature that does not verify under \
                 its public key (fingerprint {}): wrong token, slot or key",
                self.backend().as_str(),
                self.key_id,
                self.fingerprint()
            )));
        }
        Ok(sig)
    }
    fn verify_own(&self, message: &[u8], signature: &[u8]) -> Option<bool> {
        Some(sign_ed25519::verify(&self.public, message, signature))
    }
    fn public_fingerprint(&self) -> Option<String> {
        Some(self.fingerprint())
    }
}

/// The signer file as written ([`SIGNER_FORMAT`]).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerFile {
    format: String,
    backend: String,
    key_id: String,
    public_key_hex: String,
    command: Vec<String>,
    #[serde(default)]
    pass_env: Vec<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

/// Only the `format` member, to tell a signer file from a key file.
#[derive(Deserialize)]
struct FormatOnly {
    #[serde(default)]
    format: Option<String>,
}

/// Load the signer named by `path`: a `robodr-blackbox` Ed25519 secret key
/// file ([`Backend::File`], the blackbox's file checks apply) or a signer
/// file ([`Backend::External`]; see the crate docs). A public key file, an
/// HMAC key or anything else is refused.
pub fn load(path: &Path) -> Result<KeySigner, String> {
    let at = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    match KeyFile::load_secret(path) {
        Ok(kf) => {
            if kf.algorithm != ED25519 {
                return Err(at(&format!(
                    "key algorithm {:?} cannot sign (need {ED25519:?})",
                    kf.algorithm
                )));
            }
            let k = kf.ed25519_signing_key().map_err(|e| at(&e))?;
            Ok(KeySigner::from_signing_key(k))
        }
        // Not a key file: maybe a signer file (which holds no secret, so
        // reading it here leaves nothing behind).
        Err(KeyFileError::Parse(key_err)) => {
            let text = read_signer_file(path).map_err(|e| at(&e))?;
            let is_signer = serde_json::from_str::<FormatOnly>(&text)
                .ok()
                .and_then(|f| f.format)
                .is_some_and(|f| f == SIGNER_FORMAT);
            if !is_signer {
                return Err(at(&format!(
                    "neither a robodr-blackbox secret key file ({key_err}) nor a \
                     {SIGNER_FORMAT} signer file"
                )));
            }
            let x = parse_signer_file(&text).map_err(|e| at(&e))?;
            Ok(KeySigner::from_external(x))
        }
        Err(e) => Err(at(&e)),
    }
}

/// Parse and check a signer file's text (the command's path is checked
/// on disk too, see [`external::check_trusted_executable`]).
pub fn parse_signer_file(text: &str) -> Result<external::ExternalSigner, String> {
    let f: SignerFile = serde_json::from_str(text).map_err(|e| format!("signer file: {e}"))?;
    if f.format != SIGNER_FORMAT {
        return Err(format!(
            "signer file: format {:?}, expected {SIGNER_FORMAT:?}",
            f.format
        ));
    }
    if f.backend != "external" {
        return Err(format!(
            "signer file: backend {:?} is not supported (only \"external\"; PKCS#11 tokens \
             use the robodr-signer-pkcs11 adapter as the command)",
            f.backend
        ));
    }
    let public = robodr_blackbox::crypto::from_hex(&f.public_key_hex)
        .and_then(|b| <[u8; PUBLIC_KEY_LEN]>::try_from(b.as_slice()).ok())
        .ok_or("signer file: public_key_hex must be 64 hex digits (32 bytes)")?;
    // Validates the key id rule and the key itself (canonical, not small
    // order), so a signer cannot be pinned to a key that accepts forgeries.
    Ed25519VerifyingKey::from_bytes(f.key_id.clone(), &public)
        .map_err(|e| format!("signer file: {e}"))?;
    external::ExternalSigner::new(f.key_id, public, f.command, f.pass_env, f.timeout_ms)
}

/// Read a signer file after the trust-anchor checks: regular file, not a
/// symlink, owned by root or the effective user, not group/other-writable,
/// at most [`MAX_SIGNER_FILE_BYTES`].
fn read_signer_file(path: &Path) -> Result<String, String> {
    let lmd = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !lmd.file_type().is_file() {
        return Err("a signer file must be a regular file (not a symlink)".into());
    }
    let f = File::open(path).map_err(|e| e.to_string())?;
    let md = f.metadata().map_err(|e| e.to_string())?;
    if md.dev() != lmd.dev() || md.ino() != lmd.ino() {
        return Err("the signer file changed while it was opened".into());
    }
    check_owner_mode(md.uid(), md.permissions().mode(), "signer file")?;
    if md.len() > MAX_SIGNER_FILE_BYTES {
        return Err(format!(
            "a signer file is at most {MAX_SIGNER_FILE_BYTES} bytes"
        ));
    }
    let mut s = String::new();
    f.take(MAX_SIGNER_FILE_BYTES + 1)
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    if s.len() as u64 > MAX_SIGNER_FILE_BYTES {
        return Err(format!(
            "a signer file is at most {MAX_SIGNER_FILE_BYTES} bytes"
        ));
    }
    Ok(s)
}

/// Owner root or the effective user; no group/other write bit.
pub(crate) fn check_owner_mode(uid: u32, mode: u32, what: &str) -> Result<(), String> {
    let euid = robodr_blackbox::keys::effective_uid();
    if uid != 0 && uid != euid {
        return Err(format!(
            "{what} is owned by uid {uid} (must be root or the effective user {euid})"
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "{what} is group- or other-writable (mode {:o})",
            mode & 0o7777
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> String {
        robodr_blackbox::crypto::to_hex(&sign_ed25519::public_key_from_seed(&[seed; 32]))
    }

    fn file(cmd: &str, extra: &str) -> String {
        format!(
            r#"{{"format":"robodr-signer/v1","backend":"external","key_id":"rel-1",
               "public_key_hex":"{}","command":["{cmd}"]{extra}}}"#,
            pk(1)
        )
    }

    #[test]
    fn signer_files_are_validated() {
        assert!(parse_signer_file(&file("/bin/true", "")).is_ok());
        // Wrong format / backend / unknown member.
        assert!(
            parse_signer_file(&file("/bin/true", "").replace("signer/v1", "signer/v2")).is_err()
        );
        assert!(
            parse_signer_file(&file("/bin/true", "").replace("\"external\"", "\"pkcs11\""))
                .is_err()
        );
        assert!(parse_signer_file(&file("/bin/true", r#","shell":true"#)).is_err());
        // Relative command, empty command.
        assert!(parse_signer_file(&file("true", "")).is_err());
        assert!(
            parse_signer_file(&file("/bin/true", "").replace(r#"["/bin/true"]"#, "[]")).is_err()
        );
        // Bad public key: short, non-hex, small order (all zero = identity).
        assert!(parse_signer_file(&file("/bin/true", "").replace(&pk(1), "abcd")).is_err());
        assert!(
            parse_signer_file(&file("/bin/true", "").replace(&pk(1), &"zz".repeat(32))).is_err()
        );
        let identity = format!("01{}", "00".repeat(31));
        assert!(parse_signer_file(&file("/bin/true", "").replace(&pk(1), &identity)).is_err());
        // Bad key id.
        assert!(parse_signer_file(&file("/bin/true", "").replace("rel-1", "")).is_err());
    }

    #[test]
    fn pass_env_and_timeout_are_bounded() {
        assert!(parse_signer_file(&file("/bin/true", r#","pass_env":["PIN_X"]"#)).is_ok());
        for bad in [
            "LD_PRELOAD",
            "PATH",
            "ROBODR_SIGNER_KEY_ID",
            "a b",
            "",
            "lower",
        ] {
            let t = file("/bin/true", &format!(r#","pass_env":["{bad}"]"#));
            assert!(parse_signer_file(&t).is_err(), "{bad}");
        }
        assert!(parse_signer_file(&file("/bin/true", r#","timeout_ms":0"#)).is_err());
        assert!(parse_signer_file(&file("/bin/true", r#","timeout_ms":600001"#)).is_err());
        assert!(parse_signer_file(&file("/bin/true", r#","timeout_ms":600000"#)).is_ok());
    }

    #[test]
    fn file_backend_signs_and_self_checks() {
        let k = Ed25519SigningKey::from_seed("k1", &[7; 32]).unwrap();
        let s = KeySigner::from_signing_key(k);
        assert_eq!(s.backend(), Backend::File);
        let sig = Signer::sign(&s, b"m").unwrap();
        assert_eq!(s.verify_own(b"m", &sig), Some(true));
        assert_eq!(s.verify_own(b"x", &sig), Some(false));
        assert!(format!("{s:?}").contains("k1"));
        assert!(!format!("{s:?}").contains(&robodr_blackbox::crypto::to_hex(&[7; 32])));
    }

    #[test]
    fn owner_mode_rule() {
        let me = robodr_blackbox::keys::effective_uid();
        assert!(check_owner_mode(me, 0o100600, "f").is_ok());
        assert!(check_owner_mode(0, 0o100755, "f").is_ok());
        assert!(check_owner_mode(me, 0o100620, "f").is_err());
        assert!(check_owner_mode(me, 0o100602, "f").is_err());
        if me != 0 {
            assert!(check_owner_mode(me + 1, 0o100600, "f").is_err());
        } else {
            assert!(check_owner_mode(4242, 0o100600, "f").is_err());
        }
    }
}
