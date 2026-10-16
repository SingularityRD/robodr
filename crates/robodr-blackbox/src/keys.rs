//! Key files and keyrings.
//!
//! # Key file (`robodr-blackbox-key/v1`)
//!
//! A small JSON document, one key per file:
//!
//! ```json
//! {"format":"robodr-blackbox-key/v1","algorithm":"hmac-sha256",
//!  "key_id":"hmac-sha256:1f2e3d4c5b6a7980","secret_hex":"<64 hex digits>"}
//! ```
//!
//! - `key_id` is bound into every chain identity and every checkpoint, so a
//!   verifier can pick the right key (see [`Keyring`]).
//! - `secret_hex` is the key material. For HMAC this is the *shared* secret:
//!   the file is as sensitive on the verifying side as on the robot.
//! - Unknown fields are rejected, so a typo cannot silently drop data.
//!
//! [`KeyFile::write_new`] creates the file exclusively (`O_CREAT|O_EXCL`,
//! `O_NOFOLLOW`, mode 0600): it never overwrites an existing key and never
//! writes through a symlink. [`KeyFile::load`] refuses a symlink, anything
//! that is not a regular file, and a file readable or writable by group or
//! others (`mode & 0o077 != 0`), with [`KeyFileError::Permissions`].
//!
//! Only `hmac-sha256` is understood here. Other algorithms (Ed25519, TPM
//! handles) are parsed but [`KeyFile::hmac`] refuses them with
//! [`KeyFileError::UnsupportedAlgorithm`]; the backend that implements them
//! converts a [`KeyFile`] itself.
//!
//! # Keyring (`robodr-blackbox-keyring/v1`)
//!
//! [`Keyring`] maps `key_id` to a [`Verifier`]. It is how a log, a directory
//! or a bundle that spans a key rotation ([`crate::Recorder::rotate_key`]) is
//! verified: records before the rotation verify under the old key, records
//! after it under the new one. A keyring file is either a single key file or
//!
//! ```json
//! {"format":"robodr-blackbox-keyring/v1","keys":[ <key file objects> ]}
//! ```
//!
//! and is subject to the same permission check.
//!
//! **Limit:** [`Verifier::verify`] on a keyring accepts a signature made by
//! *any* key in the ring (records do not name their key individually; only
//! chain identities, `SegmentStart` and checkpoints do, and those use
//! [`Verifier::verify_as`]). A keyring should therefore hold only keys of
//! the units whose evidence it verifies.

use crate::crypto::{from_hex, to_hex, wipe};
use crate::sign::{HmacSha256Key, KeyError, Verifier, HMAC_SHA256, MIN_HMAC_KEY_LEN};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// `format` value of a key file.
pub const KEY_FILE_FORMAT: &str = "robodr-blackbox-key/v1";
/// `format` value of a keyring file.
pub const KEYRING_FORMAT: &str = "robodr-blackbox-keyring/v1";
/// Largest key or keyring file accepted.
pub const MAX_KEY_FILE_BYTES: u64 = 256 * 1024;
/// Bytes of key material [`KeyFile::generate_hmac`] draws.
pub const GENERATED_KEY_LEN: usize = 32;

/// Why a key file could not be created, read or used.
#[derive(Debug)]
pub enum KeyFileError {
    Io(io::Error),
    /// The file exists already (never overwritten).
    Exists,
    /// A symlink, directory or other non-regular file.
    NotRegular,
    /// Group or others have access (`mode & 0o077 != 0`).
    Permissions {
        mode: u32,
    },
    TooLarge {
        len: u64,
    },
    Parse(String),
    UnsupportedAlgorithm(String),
    Key(KeyError),
    DuplicateKeyId(String),
    /// No kernel randomness available: a key is never generated without it.
    NoRandomness(io::Error),
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFileError::Io(e) => write!(f, "I/O error: {e}"),
            KeyFileError::Exists => write!(f, "refusing to overwrite an existing file"),
            KeyFileError::NotRegular => {
                write!(f, "not a regular file (symlinks are never followed)")
            }
            KeyFileError::Permissions { mode } => write!(
                f,
                "key file mode {mode:04o} gives group/others access; chmod 600 it"
            ),
            KeyFileError::TooLarge { len } => {
                write!(f, "{len} bytes exceeds {MAX_KEY_FILE_BYTES}")
            }
            KeyFileError::Parse(m) => write!(f, "malformed key file: {m}"),
            KeyFileError::UnsupportedAlgorithm(a) => {
                write!(f, "unsupported key algorithm {a:?}")
            }
            KeyFileError::Key(e) => write!(f, "{e}"),
            KeyFileError::DuplicateKeyId(id) => write!(f, "key id {id:?} appears twice"),
            KeyFileError::NoRandomness(e) => write!(f, "no kernel randomness: {e}"),
        }
    }
}

impl std::error::Error for KeyFileError {}

impl From<io::Error> for KeyFileError {
    fn from(e: io::Error) -> Self {
        KeyFileError::Io(e)
    }
}

impl From<KeyError> for KeyFileError {
    fn from(e: KeyError) -> Self {
        KeyFileError::Key(e)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyJson {
    format: String,
    algorithm: String,
    key_id: String,
    secret_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringJson {
    format: String,
    keys: Vec<KeyJson>,
}

/// One key: algorithm, id and secret. The secret is wiped on drop and never
/// printed by `Debug`.
pub struct KeyFile {
    pub algorithm: String,
    pub key_id: String,
    secret: Vec<u8>,
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFile")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

impl KeyFile {
    /// Wrap existing HMAC key material (checked like [`HmacSha256Key::new`]).
    /// Without `key_id` the id is derived from the key
    /// ([`HmacSha256Key::with_derived_id`]).
    pub fn hmac_from_secret(secret: &[u8], key_id: Option<&str>) -> Result<Self, KeyFileError> {
        let k = match key_id {
            Some(id) => HmacSha256Key::new(id, secret)?,
            None => HmacSha256Key::with_derived_id(secret)?,
        };
        Ok(Self {
            algorithm: HMAC_SHA256.to_string(),
            key_id: crate::sign::Signer::key_id(&k).to_string(),
            secret: secret.to_vec(),
        })
    }

    /// A fresh 256-bit HMAC key from `/dev/urandom`. Fails rather than fall
    /// back to weaker randomness.
    pub fn generate_hmac(key_id: Option<&str>) -> Result<Self, KeyFileError> {
        let mut secret = [0u8; GENERATED_KEY_LEN];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut secret))
            .map_err(KeyFileError::NoRandomness)?;
        if secret.iter().all(|&b| b == 0) {
            return Err(KeyFileError::NoRandomness(io::Error::other(
                "kernel returned all-zero bytes",
            )));
        }
        let k = Self::hmac_from_secret(&secret, key_id);
        wipe(&mut secret);
        k
    }

    /// The key as an HMAC signer/verifier.
    pub fn hmac(&self) -> Result<HmacSha256Key, KeyFileError> {
        if self.algorithm != HMAC_SHA256 {
            return Err(KeyFileError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        Ok(HmacSha256Key::new(self.key_id.clone(), &self.secret)?)
    }

    /// Raw key material (for a backend that implements another algorithm).
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Serialise (contains the secret).
    pub fn to_json(&self) -> String {
        let mut hex = to_hex(&self.secret);
        let s = serde_json::to_string(&KeyJson {
            format: KEY_FILE_FORMAT.into(),
            algorithm: self.algorithm.clone(),
            key_id: self.key_id.clone(),
            secret_hex: hex.clone(),
        })
        .unwrap_or_default();
        wipe_string(&mut hex);
        s + "\n"
    }

    fn from_parsed(j: KeyJson) -> Result<Self, KeyFileError> {
        if j.format != KEY_FILE_FORMAT {
            return Err(KeyFileError::Parse(format!(
                "format {:?}, expected {KEY_FILE_FORMAT:?}",
                j.format
            )));
        }
        if j.key_id.is_empty()
            || j.key_id.len() > crate::sign::MAX_KEY_ID_LEN
            || !j.key_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(KeyFileError::Key(KeyError::BadKeyId));
        }
        if j.algorithm.is_empty() || !j.algorithm.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(KeyFileError::Parse("bad algorithm name".into()));
        }
        let secret = from_hex(j.secret_hex.trim())
            .ok_or_else(|| KeyFileError::Parse("secret_hex is not hex".into()))?;
        if j.algorithm == HMAC_SHA256 && secret.len() < MIN_HMAC_KEY_LEN {
            return Err(KeyFileError::Key(KeyError::TooShort {
                len: secret.len(),
                min: MIN_HMAC_KEY_LEN,
            }));
        }
        Ok(Self {
            algorithm: j.algorithm,
            key_id: j.key_id,
            secret,
        })
    }

    /// Parse a key file's text (no permission check).
    pub fn from_json(s: &str) -> Result<Self, KeyFileError> {
        let j: KeyJson = serde_json::from_str(s).map_err(|e| KeyFileError::Parse(e.to_string()))?;
        Self::from_parsed(j)
    }

    /// Create `path` exclusively, mode 0600, never following a symlink, and
    /// fsync it. An existing file (or symlink, dangling or not) is
    /// [`KeyFileError::Exists`]; nothing is overwritten.
    pub fn write_new(&self, path: &Path) -> Result<(), KeyFileError> {
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        let mut f = match crate::store::private(&mut o).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(KeyFileError::Exists),
            Err(e) => return Err(e.into()),
        };
        let mut text = self.to_json();
        let res = f.write_all(text.as_bytes()).and_then(|()| f.sync_all());
        wipe_string(&mut text);
        if let Err(e) = res {
            drop(f);
            let _ = std::fs::remove_file(path);
            return Err(e.into());
        }
        if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = File::open(dir).and_then(|d| d.sync_all());
        }
        Ok(())
    }

    /// Read and parse a key file after the permission checks described in
    /// the module docs.
    pub fn load(path: &Path) -> Result<Self, KeyFileError> {
        let mut text = read_private(path)?;
        let r = Self::from_json(&text);
        wipe_string(&mut text);
        r
    }
}

/// Best-effort wipe of a string that held key material.
fn wipe_string(s: &mut str) {
    // SAFETY: every byte is overwritten with ASCII '0', so the buffer stays
    // valid UTF-8; `write_volatile` targets a valid, exclusively borrowed byte.
    unsafe {
        for b in s.as_bytes_mut() {
            std::ptr::write_volatile(b, b'0');
        }
    }
}

/// Open without following symlinks, require a regular file with no
/// group/other permission bits, bounded size.
fn read_private(path: &Path) -> Result<String, KeyFileError> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(crate::store::sys::O_NOFOLLOW);
    }
    let f = match o.open(path) {
        Ok(f) => f,
        // ELOOP: the final component is a symlink.
        Err(e) if e.raw_os_error() == Some(40) || e.raw_os_error() == Some(62) => {
            return Err(KeyFileError::NotRegular)
        }
        Err(e) => return Err(e.into()),
    };
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(KeyFileError::NotRegular);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(KeyFileError::Permissions { mode });
        }
    }
    if md.len() > MAX_KEY_FILE_BYTES {
        return Err(KeyFileError::TooLarge { len: md.len() });
    }
    let mut s = String::new();
    f.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_string(&mut s)
        .map_err(|e| KeyFileError::Parse(e.to_string()))?;
    Ok(s)
}

/// Verifiers by key id. See the module docs.
#[derive(Default)]
pub struct Keyring {
    keys: BTreeMap<String, Box<dyn Verifier>>,
    label: String,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("key_ids", &self.key_ids())
            .finish()
    }
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a verifier under its own key id. A second key with the same id is
    /// [`KeyFileError::DuplicateKeyId`] (ambiguous, never silently replaced).
    pub fn add(&mut self, v: Box<dyn Verifier>) -> Result<(), KeyFileError> {
        let id = v.key_id().to_string();
        if self.keys.contains_key(&id) {
            return Err(KeyFileError::DuplicateKeyId(id));
        }
        self.keys.insert(id, v);
        self.label = format!(
            "keyring[{}]",
            self.keys.keys().cloned().collect::<Vec<_>>().join(",")
        );
        Ok(())
    }

    /// Add the key in `k` (HMAC only; see [`KeyFile::hmac`]).
    pub fn add_key_file(&mut self, k: &KeyFile) -> Result<(), KeyFileError> {
        self.add(Box::new(k.hmac()?))
    }

    /// Load a key file or keyring file (permission-checked) into this ring.
    pub fn load_file(&mut self, path: &Path) -> Result<(), KeyFileError> {
        let mut text = read_private(path)?;
        let r = self.add_json(&text);
        wipe_string(&mut text);
        r
    }

    /// Parse key file or keyring file text into this ring.
    pub fn add_json(&mut self, text: &str) -> Result<(), KeyFileError> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|e| KeyFileError::Parse(e.to_string()))?;
        match v.get("format").and_then(|f| f.as_str()) {
            Some(KEYRING_FORMAT) => {
                let j: KeyringJson =
                    serde_json::from_value(v).map_err(|e| KeyFileError::Parse(e.to_string()))?;
                debug_assert_eq!(j.format, KEYRING_FORMAT);
                if j.keys.is_empty() {
                    return Err(KeyFileError::Parse("keyring holds no keys".into()));
                }
                for k in j.keys {
                    self.add_key_file(&KeyFile::from_parsed(k)?)?;
                }
                Ok(())
            }
            _ => {
                let j: KeyJson =
                    serde_json::from_value(v).map_err(|e| KeyFileError::Parse(e.to_string()))?;
                self.add_key_file(&KeyFile::from_parsed(j)?)
            }
        }
    }

    /// The verifier for `key_id`.
    pub fn get(&self, key_id: &str) -> Option<&dyn Verifier> {
        self.keys.get(key_id).map(|b| &**b)
    }

    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Verifier for Keyring {
    fn algorithm(&self) -> &str {
        "keyring"
    }
    fn key_id(&self) -> &str {
        &self.label
    }
    /// Valid under *any* key of the ring (see the module docs).
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.keys.values().any(|v| v.verify(message, signature))
    }
    fn verify_as(&self, key_id: &str, message: &[u8], signature: &[u8]) -> bool {
        self.keys
            .get(key_id)
            .is_some_and(|v| v.verify(message, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Signer;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let d = std::env::temp_dir().join(format!(
            "robodr-bb-keys-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn generate_write_load_round_trip() {
        let d = tmp("rt");
        let p = d.join("k.json");
        let k = KeyFile::generate_hmac(None).unwrap();
        assert!(k.key_id.starts_with("hmac-sha256:"));
        k.write_new(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
        let l = KeyFile::load(&p).unwrap();
        assert_eq!(l.key_id, k.key_id);
        assert_eq!(l.secret(), k.secret());
        let s = l.hmac().unwrap();
        let sig = s.sign(b"m").unwrap();
        assert!(k.hmac().unwrap().verify(b"m", &sig));
        // Never overwritten.
        assert!(matches!(k.write_new(&p), Err(KeyFileError::Exists)));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn two_generated_keys_differ() {
        let a = KeyFile::generate_hmac(None).unwrap();
        let b = KeyFile::generate_hmac(None).unwrap();
        assert_ne!(a.secret(), b.secret());
        assert_ne!(a.key_id, b.key_id);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_open_permissions_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("perm");
        let p = d.join("k.json");
        KeyFile::generate_hmac(Some("unit-a"))
            .unwrap()
            .write_new(&p)
            .unwrap();
        for mode in [0o640, 0o604, 0o660, 0o644] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            match KeyFile::load(&p) {
                Err(KeyFileError::Permissions { mode: m }) => assert_eq!(m, mode),
                other => panic!("mode {mode:o}: {other:?}"),
            }
            assert!(matches!(
                Keyring::new().load_file(&p),
                Err(KeyFileError::Permissions { .. })
            ));
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(KeyFile::load(&p).is_ok());
        let link = d.join("link.json");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(matches!(
            KeyFile::load(&link),
            Err(KeyFileError::NotRegular)
        ));
        // write_new never writes through a symlink, dangling or not.
        let dangling = d.join("dangling.json");
        std::os::unix::fs::symlink(d.join("nowhere"), &dangling).unwrap();
        let k = KeyFile::generate_hmac(None).unwrap();
        assert!(matches!(k.write_new(&dangling), Err(KeyFileError::Exists)));
        assert!(!d.join("nowhere").exists());
        assert!(matches!(KeyFile::load(&d), Err(KeyFileError::NotRegular)));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rejects_malformed_key_files() {
        let good = KeyFile::hmac_from_secret(&[7; 32], Some("u"))
            .unwrap()
            .to_json();
        assert!(KeyFile::from_json(&good).is_ok());
        for bad in [
            "",
            "{}",
            "not json",
            r#"{"format":"x","algorithm":"hmac-sha256","key_id":"u","secret_hex":"00"}"#,
            &good.replace("\"u\"", "\"\""),
            &good.replace("\"u\"", "\"has space\""),
            &good.replace("hmac-sha256\"", "hmac sha\""),
            &good.replace("07070707", "zz070707"),
            &good.replace("}", ",\"extra\":1}"),
            r#"{"format":"robodr-blackbox-key/v1","algorithm":"hmac-sha256","key_id":"u","secret_hex":"0011"}"#,
        ] {
            assert!(KeyFile::from_json(bad).is_err(), "{bad}");
        }
        let ed = good.replace("\"hmac-sha256\"", "\"ed25519\"");
        let k = KeyFile::from_json(&ed).unwrap();
        assert!(matches!(
            k.hmac(),
            Err(KeyFileError::UnsupportedAlgorithm(_))
        ));
        assert!(format!("{k:?}").contains("redacted"));
        assert!(!format!("{k:?}").contains("0707"));
    }

    #[test]
    fn keyring_maps_ids_and_refuses_duplicates() {
        let a = KeyFile::hmac_from_secret(&[1; 32], Some("a")).unwrap();
        let b = KeyFile::hmac_from_secret(&[2; 32], Some("b")).unwrap();
        let ring_json = format!(
            "{{\"format\":\"{KEYRING_FORMAT}\",\"keys\":[{},{}]}}",
            a.to_json().trim(),
            b.to_json().trim()
        );
        let mut ring = Keyring::new();
        ring.add_json(&ring_json).unwrap();
        assert_eq!(ring.key_ids(), vec!["a", "b"]);
        assert_eq!(ring.len(), 2);
        let sa = a.hmac().unwrap().sign(b"m").unwrap();
        let sb = b.hmac().unwrap().sign(b"m").unwrap();
        assert!(ring.verify(b"m", &sa) && ring.verify(b"m", &sb));
        assert!(ring.verify_as("a", b"m", &sa));
        assert!(!ring.verify_as("a", b"m", &sb));
        assert!(!ring.verify_as("c", b"m", &sa));
        assert!(!ring.verify(b"x", &sa));
        assert!(ring.get("b").is_some() && ring.get("c").is_none());
        assert!(matches!(
            ring.add_key_file(&a),
            Err(KeyFileError::DuplicateKeyId(_))
        ));
        assert!(Keyring::new()
            .add_json(&format!("{{\"format\":\"{KEYRING_FORMAT}\",\"keys\":[]}}"))
            .is_err());
        assert!(ring.key_id().contains("a,b"));
    }

    #[test]
    fn plain_verifier_verify_as_requires_its_own_id() {
        let k = HmacSha256Key::new("a", &[1; 32]).unwrap();
        let s = k.sign(b"m").unwrap();
        assert!(k.verify_as("a", b"m", &s));
        assert!(!k.verify_as("b", b"m", &s));
    }
}
