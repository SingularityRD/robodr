//! Key files.
//!
//! | format | holds | who |
//! |---|---|---|
//! | `robodr-seal-x25519/1` | X25519 secret | a depot wrapping key (§7.1; in its TPM / HSM from 14a), or the UWK of a unit without a TPM (§7.7, on the runtime volume) |
//! | `robodr-seal-x25519-public/1` | X25519 public | what the release wraps content keys to (`build rpk --seal-to`) |
//! | `robodr-seal-policy-key/1` | P-256 ECDSA secret | the **policy authority**: signs PCR policies (§7.4); held offline by the delivery roots |
//! | `robodr-seal-policy-public/1` | P-256 public | pinned into every unit's UWK policy at enrolment |
//!
//! Secret files are written `0600` with `O_EXCL` and read only if they are
//! regular files (not followed through a symlink) that nobody but the
//! owner can read or write. Contents are compact JSON with a lower-case
//! hex member; buffers holding secrets are wiped.

use crate::{from_hex, invalid, io_err, to_hex, SealError};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroizing;

pub const X25519_SECRET_FORMAT: &str = "robodr-seal-x25519/1";
pub const X25519_PUBLIC_FORMAT: &str = "robodr-seal-x25519-public/1";
pub const POLICY_SECRET_FORMAT: &str = "robodr-seal-policy-key/1";
pub const POLICY_PUBLIC_FORMAT: &str = "robodr-seal-policy-public/1";

const MAX_KEY_FILE: u64 = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretFile {
    format: String,
    secret: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicFile {
    format: String,
    public: String,
}

fn write_secret(path: &Path, format: &str, secret: &[u8]) -> Result<(), SealError> {
    let doc = Zeroizing::new(
        serde_json::to_vec(&SecretFile {
            format: format.into(),
            secret: to_hex(secret),
        })
        .map_err(|e| invalid(e.to_string()))?,
    );
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc_nofollow())
        .open(path)
        .map_err(|e| io_err(path, e))?;
    f.write_all(&doc).map_err(|e| io_err(path, e))?;
    f.sync_all().map_err(|e| io_err(path, e))
}

fn write_public(path: &Path, format: &str, public: &[u8]) -> Result<(), SealError> {
    let doc = serde_json::to_vec(&PublicFile {
        format: format.into(),
        public: to_hex(public),
    })
    .map_err(|e| invalid(e.to_string()))?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|e| io_err(path, e))?;
    f.write_all(&doc).map_err(|e| io_err(path, e))?;
    f.sync_all().map_err(|e| io_err(path, e))
}

fn libc_nofollow() -> i32 {
    crate::O_NOFOLLOW
}

pub(crate) fn read_bounded(path: &Path, secret: bool) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc_nofollow())
        .open(path)
        .map_err(|e| io_err(path, e))?;
    let md = f.metadata().map_err(|e| io_err(path, e))?;
    if !md.is_file() {
        return Err(invalid(format!("{}: not a regular file", path.display())));
    }
    if secret {
        // The one secret-file rule of every RoboDR binary
        // (robodr_blackbox::secret_file): owner root or this user, no
        // group/other bits, or a systemd credential only root and this
        // user can read.
        robodr_blackbox::secret_file::check_secret_file(&f, &md).map_err(|e| {
            invalid(format!(
                "{}: a secret key file must not be accessible by group or others: {e}",
                path.display()
            ))
        })?;
    }
    let mut buf = Zeroizing::new(Vec::new());
    Read::by_ref(&mut f)
        .take(MAX_KEY_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io_err(path, e))?;
    if buf.len() as u64 > MAX_KEY_FILE {
        return Err(invalid(format!("{}: key file too large", path.display())));
    }
    Ok(buf)
}

fn read_secret(path: &Path, format: &str, len: usize) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let buf = read_bounded(path, true)?;
    let f: SecretFile =
        serde_json::from_slice(&buf).map_err(|e| invalid(format!("{}: {e}", path.display())))?;
    let secret = Zeroizing::new(f.secret);
    if f.format != format {
        return Err(invalid(format!(
            "{}: not a {format} key file",
            path.display()
        )));
    }
    let b = Zeroizing::new(
        from_hex(&secret).ok_or_else(|| invalid(format!("{}: bad hex", path.display())))?,
    );
    if b.len() != len {
        return Err(invalid(format!("{}: wrong key length", path.display())));
    }
    Ok(b)
}

fn read_public(path: &Path, format: &str, len: usize) -> Result<Vec<u8>, SealError> {
    let buf = read_bounded(path, false)?;
    let f: PublicFile =
        serde_json::from_slice(&buf).map_err(|e| invalid(format!("{}: {e}", path.display())))?;
    if f.format != format {
        return Err(invalid(format!("{}: not a {format} file", path.display())));
    }
    let b = from_hex(&f.public).ok_or_else(|| invalid(format!("{}: bad hex", path.display())))?;
    if b.len() != len {
        return Err(invalid(format!("{}: wrong key length", path.display())));
    }
    Ok(b)
}

/// Write a new X25519 key pair: `path` (secret, 0600) and `pub_path`.
pub fn x25519_generate(
    path: &Path,
    pub_path: &Path,
) -> Result<crate::wrap::X25519Secret, SealError> {
    let k = crate::wrap::X25519Secret::generate()?;
    write_secret(path, X25519_SECRET_FORMAT, k.expose())?;
    if let Err(e) = write_public(pub_path, X25519_PUBLIC_FORMAT, &k.public()) {
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(k)
}

/// Write an existing X25519 secret (fallback enrolment).
pub fn x25519_write(path: &Path, k: &crate::wrap::X25519Secret) -> Result<(), SealError> {
    write_secret(path, X25519_SECRET_FORMAT, k.expose())
}

pub fn x25519_load(path: &Path) -> Result<crate::wrap::X25519Secret, SealError> {
    let b = read_secret(path, X25519_SECRET_FORMAT, 32)?;
    crate::wrap::X25519Secret::from_bytes(&b)
}

pub fn x25519_load_public(path: &Path) -> Result<[u8; 32], SealError> {
    let b = read_public(path, X25519_PUBLIC_FORMAT, 32)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}

/// The policy authority's signing key.
pub struct PolicyKey(p256::ecdsa::SigningKey);

impl std::fmt::Debug for PolicyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PolicyKey(..)")
    }
}

impl PolicyKey {
    pub fn generate() -> Result<Self, SealError> {
        let s = crate::wrap::p256_random()?;
        Ok(Self(p256::ecdsa::SigningKey::from(s)))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, SealError> {
        p256::ecdsa::SigningKey::from_slice(b)
            .map(Self)
            .map_err(|_| invalid("not a P-256 secret scalar"))
    }

    /// SEC1 uncompressed public key.
    pub fn public(&self) -> [u8; 65] {
        crate::wrap::p256_public_bytes(&p256::PublicKey::from(self.0.verifying_key()))
    }

    /// ECDSA-SHA256 (RFC 6979, low-S) over a precomputed SHA-256 digest,
    /// DER-encoded: what `tpm2_verifysignature -f ecdsa` takes.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SealError> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self
            .0
            .sign_prehash(digest)
            .map_err(|_| invalid("ECDSA signing failed"))?;
        let sig = sig.normalize_s();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// Verify a DER ECDSA-SHA256 signature over a digest with a SEC1 public key.
pub fn policy_verify(public: &[u8], digest: &[u8; 32], der: &[u8]) -> Result<(), SealError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| invalid("policy public key is not a P-256 point"))?;
    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|_| crate::unauthentic("policy signature is not DER ECDSA"))?;
    vk.verify_prehash(digest, &sig)
        .map_err(|_| crate::unauthentic("policy signature does not verify"))
}

/// A hex SEC1 P-256 public key (a recorded policy authority).
pub fn policy_verify_key(hex: &str) -> Result<[u8; 65], SealError> {
    let b = from_hex(hex).ok_or_else(|| invalid("bad policy authority hex"))?;
    crate::wrap::Recipient::p256(&b)?;
    let mut a = [0u8; 65];
    a.copy_from_slice(&b);
    Ok(a)
}

pub fn policy_generate(path: &Path, pub_path: &Path) -> Result<PolicyKey, SealError> {
    let k = PolicyKey::generate()?;
    let bytes = Zeroizing::new(k.0.to_bytes().to_vec());
    write_secret(path, POLICY_SECRET_FORMAT, &bytes)?;
    if let Err(e) = write_public(pub_path, POLICY_PUBLIC_FORMAT, &k.public()) {
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(k)
}

pub fn policy_load(path: &Path) -> Result<PolicyKey, SealError> {
    let b = read_secret(path, POLICY_SECRET_FORMAT, 32)?;
    PolicyKey::from_bytes(&b)
}

pub fn policy_load_public(path: &Path) -> Result<[u8; 65], SealError> {
    let b = read_public(path, POLICY_PUBLIC_FORMAT, 65)?;
    crate::wrap::Recipient::p256(&b)?;
    let mut a = [0u8; 65];
    a.copy_from_slice(&b);
    Ok(a)
}

/// DER `SubjectPublicKeyInfo` of a P-256 key (id-ecPublicKey, prime256v1).
pub fn p256_spki_der(public: &[u8; 65]) -> Vec<u8> {
    const PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let mut d = PREFIX.to_vec();
    d.extend_from_slice(public);
    d
}

/// The SEC1 point of a P-256 DER `SubjectPublicKeyInfo` (the fixed form
/// `tpm2_readpublic -f der` writes).
pub fn p256_from_spki_der(der: &[u8]) -> Result<[u8; 65], SealError> {
    if der.len() != 91 {
        return Err(invalid("not a P-256 SubjectPublicKeyInfo"));
    }
    let mut p = [0u8; 65];
    p.copy_from_slice(&der[26..]);
    if p256_spki_der(&p) != der {
        return Err(invalid("not a P-256 SubjectPublicKeyInfo"));
    }
    crate::wrap::Recipient::p256(&p)?;
    Ok(p)
}

/// PEM of [`p256_spki_der`] (what `tpm2_loadexternal -u` reads).
pub fn p256_pem(public: &[u8; 65]) -> String {
    let b64 = base64(&p256_spki_der(public));
    let mut s = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        s.push_str(&String::from_utf8_lossy(line));
        s.push('\n');
    }
    s.push_str("-----END PUBLIC KEY-----\n");
    s
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("robodr-seal-keys-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn key_files_round_trip_and_are_private() {
        let d = dir("rt");
        let k = x25519_generate(&d.join("k"), &d.join("k.pub")).unwrap();
        assert_eq!(x25519_load(&d.join("k")).unwrap().public(), k.public());
        assert_eq!(x25519_load_public(&d.join("k.pub")).unwrap(), k.public());
        // Never overwritten.
        assert!(x25519_generate(&d.join("k"), &d.join("k2.pub")).is_err());
        // Group-readable secret refused.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("k"), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(x25519_load(&d.join("k")).is_err());
        // A symlink is not followed.
        fs::set_permissions(d.join("k"), fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(d.join("k"), d.join("link")).unwrap();
        assert!(x25519_load(&d.join("link")).is_err());
        // Format confusion: a public file is not a secret one.
        assert!(x25519_load(&d.join("k.pub")).is_err());
        let p = policy_generate(&d.join("p"), &d.join("p.pub")).unwrap();
        assert_eq!(policy_load_public(&d.join("p.pub")).unwrap(), p.public());
        assert!(policy_load(&d.join("k")).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn ecdsa_and_spki() {
        let k = PolicyKey::generate().unwrap();
        let d = [5u8; 32];
        let s = k.sign_digest(&d).unwrap();
        policy_verify(&k.public(), &d, &s).unwrap();
        assert!(policy_verify(&k.public(), &[6u8; 32], &s).is_err());
        assert!(policy_verify(&PolicyKey::generate().unwrap().public(), &d, &s).is_err());
        let der = p256_spki_der(&k.public());
        assert_eq!(p256_from_spki_der(&der).unwrap(), k.public());
        let pem = p256_pem(&k.public());
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"));
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"a"), "YQ==");
    }
}
