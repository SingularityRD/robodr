//! Key files and keyrings.
//!
//! # Key file, format v2 (`robodr-blackbox-key/v2`)
//!
//! A small JSON document, one key per file. Ed25519 (the production
//! algorithm) comes as a **pair** of files:
//!
//! ```json
//! {"format":"robodr-blackbox-key/v2","kind":"secret","algorithm":"ed25519",
//!  "key_id":"ed25519:1f2e3d4c5b6a7980","public_hex":"<64 hex>","secret_hex":"<64 hex seed>"}
//! {"format":"robodr-blackbox-key/v2","kind":"public","algorithm":"ed25519",
//!  "key_id":"ed25519:1f2e3d4c5b6a7980","public_hex":"<64 hex>"}
//! ```
//!
//! - The **secret** file holds the 32-byte RFC 8032 seed (and, as a
//!   consistency check, the public key derived from it; a mismatch is
//!   refused). It stays on the signing unit, mode 0600.
//! - The **public** file (conventionally `<secret file>.pub`, see
//!   [`PUBLIC_KEY_SUFFIX`]) holds only the 32-byte public key. It can verify
//!   but never sign, so it is safe to distribute to the fleet console, the
//!   SOC importer and auditors. It is loaded whatever its permissions.
//! - `key_id` is bound into every chain identity and every checkpoint, so a
//!   verifier can pick the right key (see [`Keyring`]). Without an explicit
//!   id it is derived from the public key
//!   ([`crate::sign_ed25519::derive_key_id`], `ed25519:<16 hex>`).
//! - Optional `"device_id"` (any key file, v1 or v2) binds the key to one
//!   unit: a [`Keyring`] then lets it verify only chains whose identity
//!   names that device (see *Keyring* below). It is copied into the public
//!   file by [`KeyFile::to_public`]; set it with [`KeyFile::with_device_id`]
//!   (`robodr-blackbox keygen --device ID`).
//! - Unknown fields are rejected, so a typo cannot silently drop data.
//!
//! # Legacy HMAC (`hmac-sha256`)
//!
//! ```json
//! {"format":"robodr-blackbox-key/v1","algorithm":"hmac-sha256",
//!  "key_id":"hmac-sha256:1f2e3d4c5b6a7980","secret_hex":"<64 hex digits>"}
//! ```
//!
//! HMAC is the symmetric placeholder: the *same* secret signs and verifies,
//! so every verifier can also forge. It has no public half
//! ([`KeyFile::to_public`] refuses it). HMAC key files are still written in
//! format v1 (byte-for-byte what earlier releases wrote and read); v2 with
//! `"kind":"secret","algorithm":"hmac-sha256"` is read too. A v1 file with
//! `"algorithm":"ed25519"` and a 32-byte `secret_hex` is read as an Ed25519
//! seed. Other algorithm names are parsed from v1 files but cannot be used
//! as a signer or verifier ([`KeyFileError::UnsupportedAlgorithm`]); v2
//! accepts only `ed25519` and `hmac-sha256`.
//!
//! # File safety
//!
//! [`KeyFile::write_new`] creates the file exclusively (`O_CREAT|O_EXCL`,
//! `O_NOFOLLOW`; mode 0600 for a file with secret material, 0644 for a
//! public key file): it never overwrites an existing key and never writes
//! through a symlink. Every load refuses a symlink, anything that is not a
//! regular file, and files over [`MAX_KEY_FILE_BYTES`]. A file that contains
//! **secret** material (any HMAC key, an Ed25519 seed, a keyring holding
//! either) is additionally refused, with [`KeyFileError::Permissions`], when
//! group or others have any access (`mode & 0o077 != 0`), and with
//! [`KeyFileError::Owner`] when it is owned by neither the effective user
//! nor root. The one exception is a systemd `LoadCredential=` file that
//! only root and this user can read through its POSIX ACL (the shared rule
//! in [`crate::secret_file`]); a credential that fails that rule is
//! [`KeyFileError::Credential`]. A file with only public keys passes
//! whatever its mode.
//!
//! # Keyring (`robodr-blackbox-keyring/v1`)
//!
//! [`Keyring`] maps `key_id` to a [`Verifier`]. It is how a log, a directory
//! or a bundle that spans a key rotation ([`crate::Recorder::rotate_key`]) is
//! verified: records before the rotation verify under the old key, records
//! after it under the new one. A keyring file is either a single key file
//! (secret or public) or
//!
//! ```json
//! {"format":"robodr-blackbox-keyring/v1","keys":[ <key file objects> ]}
//! ```
//!
//! and is subject to the same permission rule (strict only if it holds a
//! secret). [`Keyring::load_public_file`] refuses any secret, for verifiers
//! that must never hold signing material.
//!
//! ## Which key may vouch for what
//!
//! A keyring never answers "does *any* key accept this?" for evidence:
//!
//! - [`Verifier::verify_key`] checks under exactly the key the evidence
//!   names, and only if that key's algorithm is the named one. Record
//!   verification ([`crate::verify::verify_segments`]) uses it with the key
//!   the chain identity names (switched only by an authenticated
//!   `KeyRotation`, or by a `SegmentStart` hint, see that module), so a
//!   keyring holding unit B's key does not authenticate a log whose
//!   identity says unit A, and an HMAC key never vouches for an `ed25519`
//!   chain.
//! - [`Verifier::verify_as`] (checkpoints) looks the named key up.
//! - [`Verifier::verify`] (no key named) is accepted only when the ring
//!   holds exactly one key, i.e. when it is unambiguous.
//! - A key with a `device_id` is reported by [`Verifier::key_device`]; the
//!   verifier refuses it for a chain of another device. Unbound keys are
//!   attributed only by key id; bind fleet keys to their units.
//! - Mixing symmetric (HMAC) and asymmetric (Ed25519) keys in one ring is
//!   refused ([`KeyFileError::MixedAlgorithms`]) unless explicitly allowed
//!   with [`Keyring::set_allow_mixed_algorithms`] (e.g. to verify a log
//!   that rotated from a legacy HMAC key to Ed25519): a verifier that holds
//!   an HMAC key can forge whatever that key is allowed to vouch for.
//!
//! ## Legacy HMAC policy (refused by default at every tool boundary)
//!
//! The library still parses and uses HMAC keys (existing logs must stay
//! verifiable), but every place that loads a black-box key for an operator
//! refuses one unless explicitly allowed: [`KeyFile::check_hmac_policy`]
//! for a single key, [`Keyring::set_refuse_hmac`] for a ring (both fail
//! with [`KeyFileError::LegacyHmac`]). `robodr-blackbox` takes
//! `--allow-hmac`, `robodr-agentd` `blackbox.allow_hmac`, the diode tools
//! `--allow-hmac`; profile and trust keys are Ed25519-only regardless.
//!
//! [`Keyring::verify_any`] (the recorder's own `previous_keys`, a trusted
//! local input) is the one place where "any key in the ring" is accepted.

use crate::crypto::{fill_random, from_hex, to_hex, wipe};
use crate::sign::{HmacSha256Key, KeyError, Signer, Verifier, HMAC_SHA256, MIN_HMAC_KEY_LEN};
use crate::sign_ed25519::{
    derive_key_id, public_key_from_seed, random_seed, Ed25519Error, Ed25519SigningKey,
    Ed25519VerifyingKey, ED25519, PUBLIC_KEY_LEN, SEED_LEN,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// `format` value of a v1 key file (legacy; still written for HMAC keys).
pub const KEY_FILE_FORMAT: &str = "robodr-blackbox-key/v1";
/// `format` value of a v2 key file (secret or public; written for Ed25519).
pub const KEY_FILE_FORMAT_V2: &str = "robodr-blackbox-key/v2";
/// `format` value of a keyring file.
pub const KEYRING_FORMAT: &str = "robodr-blackbox-keyring/v1";
/// Largest key or keyring file accepted.
pub const MAX_KEY_FILE_BYTES: u64 = 256 * 1024;
/// Bytes of key material [`KeyFile::generate_hmac`] draws.
pub const GENERATED_KEY_LEN: usize = 32;
/// Suffix appended to a secret key file's path for its public key file.
pub const PUBLIC_KEY_SUFFIX: &str = ".pub";
/// Algorithm [`KeyFile::generate`] uses when none is named.
pub const DEFAULT_ALGORITHM: &str = ED25519;

/// Why a key file could not be created, read or used.
#[derive(Debug)]
pub enum KeyFileError {
    Io(io::Error),
    /// The file exists already (never overwritten).
    Exists,
    /// A symlink, directory or other non-regular file.
    NotRegular,
    /// Group or others have access (`mode & 0o077 != 0`) to secret material
    /// (and it is not an acceptable systemd credential).
    Permissions {
        mode: u32,
    },
    /// A file in a systemd credential directory that fails the credential
    /// rule ([`crate::secret_file`]); the error says why.
    Credential(crate::secret_file::SecretFileError),
    TooLarge {
        len: u64,
    },
    Parse(String),
    UnsupportedAlgorithm(String),
    Key(KeyError),
    DuplicateKeyId(String),
    /// No kernel randomness available: a key is never generated without it.
    NoRandomness(io::Error),
    /// A file with secret material owned by neither the effective user nor
    /// root.
    Owner {
        uid: u32,
    },
    /// An Ed25519 key was rejected (bad id, invalid public key).
    Ed25519(Ed25519Error),
    /// The secret file's `public_hex` is not the public key of its seed.
    PublicKeyMismatch,
    /// The algorithm has no public half (HMAC is symmetric).
    NoPublicKey(String),
    /// A public key file where a secret (signing) key is needed.
    NoSecret,
    /// Secret material where only public keys are allowed.
    NotPublic(String),
    /// A keyring would mix key algorithms (e.g. HMAC next to Ed25519)
    /// without [`Keyring::set_allow_mixed_algorithms`].
    MixedAlgorithms {
        existing: String,
        added: String,
    },
    /// `device_id` is empty, too long or not printable ASCII.
    BadDeviceId,
    /// A legacy HMAC key where the caller's policy refuses them
    /// ([`KeyFile::check_hmac_policy`], [`Keyring::set_refuse_hmac`]).
    LegacyHmac(String),
    /// A file used as a trust anchor (public keys that decide what
    /// verifies: keyrings, `previous_keys`) that another user could have
    /// written: owned by neither root nor the effective user, or group- or
    /// world-writable (`mode & 0o022 != 0`).
    UntrustedFile {
        uid: u32,
        mode: u32,
    },
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
                "key file mode {mode:04o} gives group/others access to secret key material; chmod 600 it \
                 (a systemd LoadCredential= file is accepted when only root and this user can read it)"
            ),
            KeyFileError::Credential(e) => write!(f, "secret key file: {e}"),
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
            KeyFileError::UntrustedFile { uid, mode } => write!(
                f,
                "key file used as a trust anchor is owned by uid {uid} with mode {mode:04o}: it \
                 must be owned by root or this user and not group/world-writable (chown it, \
                 chmod go-w)"
            ),
            KeyFileError::Owner { uid } => write!(
                f,
                "secret key file is owned by uid {uid}, not by this user or root"
            ),
            KeyFileError::Ed25519(e) => write!(f, "{e}"),
            KeyFileError::PublicKeyMismatch => {
                write!(f, "public_hex does not match the secret seed")
            }
            KeyFileError::NoPublicKey(a) => write!(
                f,
                "{a} is symmetric and has no public key; use an ed25519 key"
            ),
            KeyFileError::NoSecret => write!(
                f,
                "this is a public key file; signing needs the secret key file"
            ),
            KeyFileError::NotPublic(id) => write!(
                f,
                "key {id:?} contains secret material where only public keys are allowed \
                 (use `robodr-blackbox export-pub`)"
            ),
            KeyFileError::MixedAlgorithms { existing, added } => write!(
                f,
                "keyring holds {existing} keys; refusing to add a {added} key without an \
                 explicit opt-in (mixed algorithms)"
            ),
            KeyFileError::BadDeviceId => write!(
                f,
                "device id must be 1..={} printable ASCII characters",
                crate::sign::MAX_KEY_ID_LEN
            ),
            KeyFileError::LegacyHmac(id) => write!(
                f,
                "key {id:?} is a legacy hmac-sha256 key, refused by default (symmetric: whoever \
                 can verify can also forge); migrate to ed25519 (OPERATIONS 4.3), or accept it \
                 knowingly with --allow-hmac (robodr-agentd: blackbox.allow_hmac)"
            ),
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

impl From<Ed25519Error> for KeyFileError {
    fn from(e: Ed25519Error) -> Self {
        match e {
            Ed25519Error::BadKeyId => KeyFileError::Key(KeyError::BadKeyId),
            Ed25519Error::Rng(m) => KeyFileError::NoRandomness(io::Error::other(m)),
            e => KeyFileError::Ed25519(e),
        }
    }
}

/// Whether a key file holds signing material or only a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Secret,
    Public,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyJson {
    format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    algorithm: String,
    key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

impl Drop for KeyJson {
    fn drop(&mut self) {
        if let Some(s) = self.secret_hex.as_mut() {
            wipe_string(s);
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringJson {
    format: String,
    keys: Vec<KeyJson>,
}

/// Only the `format` field; everything else is skipped without being
/// copied (unlike a `serde_json::Value`, which would duplicate secrets).
#[derive(Deserialize)]
struct FormatProbe {
    #[serde(default)]
    format: Option<String>,
}

/// One key: algorithm, id, and either secret material (HMAC key, Ed25519
/// seed) or only an Ed25519 public key. The secret is wiped on drop and
/// never printed by `Debug`.
pub struct KeyFile {
    pub algorithm: String,
    pub key_id: String,
    /// The unit this key belongs to, if bound (see the module docs).
    pub device_id: Option<String>,
    secret: Vec<u8>,
    public: Option<[u8; PUBLIC_KEY_LEN]>,
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFile")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("device_id", &self.device_id)
            .field("kind", &self.kind())
            .field("public", &self.public.as_ref().map(|p| to_hex(p)))
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

fn ok_name(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= crate::sign::MAX_KEY_ID_LEN
        && id.bytes().all(|b| b.is_ascii_graphic())
}

fn check_key_id(id: &str) -> Result<(), KeyFileError> {
    if !ok_name(id) {
        return Err(KeyFileError::Key(KeyError::BadKeyId));
    }
    Ok(())
}

fn check_device_id(id: &str) -> Result<(), KeyFileError> {
    if !ok_name(id) {
        return Err(KeyFileError::BadDeviceId);
    }
    Ok(())
}

fn hex32(field: &str, s: &str) -> Result<[u8; 32], KeyFileError> {
    let mut v =
        from_hex(s.trim()).ok_or_else(|| KeyFileError::Parse(format!("{field} is not hex")))?;
    let r = <[u8; 32]>::try_from(v.as_slice())
        .map_err(|_| KeyFileError::Parse(format!("{field} must be 32 bytes, got {}", v.len())));
    wipe(&mut v);
    r
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
            key_id: Signer::key_id(&k).to_string(),
            device_id: None,
            secret: secret.to_vec(),
            public: None,
        })
    }

    /// A fresh 256-bit HMAC key from the kernel CSPRNG
    /// ([`crate::crypto::fill_random`]). Fails rather than fall back to
    /// weaker randomness. Legacy: prefer [`KeyFile::generate_ed25519`].
    pub fn generate_hmac(key_id: Option<&str>) -> Result<Self, KeyFileError> {
        let mut secret = [0u8; GENERATED_KEY_LEN];
        if let Err(e) = fill_random(&mut secret) {
            wipe(&mut secret);
            return Err(KeyFileError::NoRandomness(e));
        }
        let k = Self::hmac_from_secret(&secret, key_id);
        wipe(&mut secret);
        k
    }

    /// Wrap an Ed25519 seed. Without `key_id` the id is derived from the
    /// public key ([`derive_key_id`]).
    pub fn ed25519_from_seed(
        seed: &[u8; SEED_LEN],
        key_id: Option<&str>,
    ) -> Result<Self, KeyFileError> {
        let public = public_key_from_seed(seed);
        let key_id = match key_id {
            Some(id) => {
                check_key_id(id)?;
                id.to_string()
            }
            None => derive_key_id(&public),
        };
        Ok(Self {
            algorithm: ED25519.to_string(),
            key_id,
            device_id: None,
            secret: seed.to_vec(),
            public: Some(public),
        })
    }

    /// A fresh Ed25519 key (seed from `/dev/urandom`, see
    /// [`crate::sign_ed25519::random_seed`]).
    pub fn generate_ed25519(key_id: Option<&str>) -> Result<Self, KeyFileError> {
        if let Some(id) = key_id {
            check_key_id(id)?;
        }
        let mut seed = random_seed()?;
        let k = Self::ed25519_from_seed(&seed, key_id);
        wipe(&mut seed);
        k
    }

    /// A fresh key of `algorithm` (`"ed25519"` or `"hmac-sha256"`; `"hmac"`
    /// is accepted as an alias).
    pub fn generate(algorithm: &str, key_id: Option<&str>) -> Result<Self, KeyFileError> {
        match algorithm {
            ED25519 => Self::generate_ed25519(key_id),
            HMAC_SHA256 | "hmac" => Self::generate_hmac(key_id),
            a => Err(KeyFileError::UnsupportedAlgorithm(a.to_string())),
        }
    }

    /// An Ed25519 public key file for `public` (validated: canonical, not of
    /// small order). Without `key_id` the id is derived.
    pub fn ed25519_public(
        public: &[u8; PUBLIC_KEY_LEN],
        key_id: Option<&str>,
    ) -> Result<Self, KeyFileError> {
        let id = match key_id {
            Some(id) => id.to_string(),
            None => derive_key_id(public),
        };
        Ed25519VerifyingKey::from_bytes(id.clone(), public)?;
        Ok(Self {
            algorithm: ED25519.to_string(),
            key_id: id,
            device_id: None,
            secret: Vec::new(),
            public: Some(*public),
        })
    }

    /// Bind this key to one unit (see the module docs); `None` unbinds.
    pub fn with_device_id(mut self, device_id: Option<&str>) -> Result<Self, KeyFileError> {
        if let Some(d) = device_id {
            check_device_id(d)?;
        }
        self.device_id = device_id.map(str::to_string);
        Ok(self)
    }

    /// Secret (signing material present) or public (verify only).
    pub fn kind(&self) -> KeyKind {
        if self.secret.is_empty() {
            KeyKind::Public
        } else {
            KeyKind::Secret
        }
    }

    /// `true` for a public key file (no signing material).
    pub fn is_public(&self) -> bool {
        self.kind() == KeyKind::Public
    }

    /// `true` for a symmetric key (HMAC): whoever can verify can also sign.
    pub fn is_symmetric(&self) -> bool {
        self.algorithm == HMAC_SHA256
    }

    /// The legacy-HMAC policy every tool applies at its boundary: a
    /// symmetric key is [`KeyFileError::LegacyHmac`] unless `allow_hmac`
    /// (the operator's explicit `--allow-hmac` / `blackbox.allow_hmac`).
    /// Library constructors stay algorithm-agnostic; see the module docs.
    pub fn check_hmac_policy(&self, allow_hmac: bool) -> Result<(), KeyFileError> {
        if self.is_symmetric() && !allow_hmac {
            return Err(KeyFileError::LegacyHmac(self.key_id.clone()));
        }
        Ok(())
    }

    /// The Ed25519 public key, if this is an Ed25519 key.
    pub fn public_key(&self) -> Option<[u8; PUBLIC_KEY_LEN]> {
        self.public
    }

    /// The public half as its own key file (same id), safe to distribute.
    /// HMAC has none: [`KeyFileError::NoPublicKey`].
    pub fn to_public(&self) -> Result<Self, KeyFileError> {
        match (&self.public, self.algorithm.as_str()) {
            (Some(p), ED25519) => Self::ed25519_public(p, Some(&self.key_id))?
                .with_device_id(self.device_id.as_deref()),
            (_, ED25519) => Err(KeyFileError::Parse("ed25519 key without public key".into())),
            (_, a) if a == HMAC_SHA256 => Err(KeyFileError::NoPublicKey(a.to_string())),
            (_, a) => Err(KeyFileError::UnsupportedAlgorithm(a.to_string())),
        }
    }

    /// The key as an HMAC signer/verifier.
    pub fn hmac(&self) -> Result<HmacSha256Key, KeyFileError> {
        if self.algorithm != HMAC_SHA256 {
            return Err(KeyFileError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        Ok(HmacSha256Key::new(self.key_id.clone(), &self.secret)?)
    }

    /// The key as an Ed25519 signer (secret key files only).
    pub fn ed25519_signing_key(&self) -> Result<Ed25519SigningKey, KeyFileError> {
        if self.algorithm != ED25519 {
            return Err(KeyFileError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        let mut seed: [u8; SEED_LEN] = self
            .secret
            .as_slice()
            .try_into()
            .map_err(|_| KeyFileError::NoSecret)?;
        let k = Ed25519SigningKey::from_seed(self.key_id.clone(), &seed);
        wipe(&mut seed);
        Ok(k?)
    }

    /// The key as an Ed25519 verifier (secret or public key files).
    pub fn ed25519_verifying_key(&self) -> Result<Ed25519VerifyingKey, KeyFileError> {
        match (&self.public, self.algorithm.as_str()) {
            (Some(p), ED25519) => Ok(Ed25519VerifyingKey::from_bytes(self.key_id.clone(), p)?),
            _ => Err(KeyFileError::UnsupportedAlgorithm(self.algorithm.clone())),
        }
    }

    /// A recorder [`Signer`] for this key (Ed25519 or HMAC secret files).
    pub fn signer(&self) -> Result<Box<dyn Signer>, KeyFileError> {
        if self.is_public() {
            return Err(KeyFileError::NoSecret);
        }
        match self.algorithm.as_str() {
            ED25519 => Ok(Box::new(self.ed25519_signing_key()?)),
            HMAC_SHA256 => Ok(Box::new(self.hmac()?)),
            a => Err(KeyFileError::UnsupportedAlgorithm(a.to_string())),
        }
    }

    /// A [`Verifier`] for this key (Ed25519 secret or public, HMAC secret).
    pub fn verifier(&self) -> Result<Box<dyn Verifier>, KeyFileError> {
        match self.algorithm.as_str() {
            ED25519 => Ok(Box::new(self.ed25519_verifying_key()?)),
            HMAC_SHA256 => Ok(Box::new(self.hmac()?)),
            a => Err(KeyFileError::UnsupportedAlgorithm(a.to_string())),
        }
    }

    /// Raw secret material (HMAC key or Ed25519 seed; empty for a public key
    /// file), for a backend that implements another algorithm.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Serialise. Contains the secret unless this is a public key file.
    /// HMAC (and other legacy) secrets are written as format v1, Ed25519
    /// keys as format v2.
    pub fn to_json(&self) -> String {
        let j = if self.algorithm == ED25519 {
            KeyJson {
                format: KEY_FILE_FORMAT_V2.into(),
                kind: Some(
                    match self.kind() {
                        KeyKind::Secret => "secret",
                        KeyKind::Public => "public",
                    }
                    .into(),
                ),
                algorithm: self.algorithm.clone(),
                key_id: self.key_id.clone(),
                public_hex: self.public.as_ref().map(|p| to_hex(p)),
                secret_hex: (!self.secret.is_empty()).then(|| to_hex(&self.secret)),
                device_id: self.device_id.clone(),
            }
        } else {
            KeyJson {
                format: KEY_FILE_FORMAT.into(),
                kind: None,
                algorithm: self.algorithm.clone(),
                key_id: self.key_id.clone(),
                public_hex: None,
                secret_hex: Some(to_hex(&self.secret)),
                device_id: self.device_id.clone(),
            }
        };
        // One allocation of ample size, so the serialised secret is never
        // left behind in a buffer the Vec grew out of; on the (impossible)
        // error path the partial output is wiped.
        let mut out = Vec::with_capacity(1024 + 2 * self.secret.len());
        if serde_json::to_writer(&mut out, &j).is_err() {
            wipe(&mut out);
            return String::new();
        }
        out.push(b'\n');
        String::from_utf8(out).unwrap_or_else(|e| {
            let mut b = e.into_bytes();
            wipe(&mut b);
            String::new()
        })
    }

    fn from_parsed(j: &KeyJson) -> Result<Self, KeyFileError> {
        check_key_id(&j.key_id)?;
        if j.algorithm.is_empty() || !j.algorithm.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(KeyFileError::Parse("bad algorithm name".into()));
        }
        if let Some(d) = &j.device_id {
            check_device_id(d)?;
        }
        let k = match j.format.as_str() {
            KEY_FILE_FORMAT => Self::from_v1(j),
            KEY_FILE_FORMAT_V2 => Self::from_v2(j),
            f => Err(KeyFileError::Parse(format!(
                "format {f:?}, expected {KEY_FILE_FORMAT_V2:?} or {KEY_FILE_FORMAT:?}"
            ))),
        }?;
        k.with_device_id(j.device_id.as_deref())
    }

    fn from_v1(j: &KeyJson) -> Result<Self, KeyFileError> {
        if j.kind.is_some() || j.public_hex.is_some() {
            return Err(KeyFileError::Parse(
                "kind/public_hex need format robodr-blackbox-key/v2".into(),
            ));
        }
        let hex = j
            .secret_hex
            .as_deref()
            .ok_or_else(|| KeyFileError::Parse("missing secret_hex".into()))?;
        if j.algorithm == ED25519 {
            let mut seed = hex32("secret_hex", hex)?;
            let k = Self::ed25519_from_seed(&seed, Some(&j.key_id));
            wipe(&mut seed);
            return k;
        }
        let mut secret = from_hex(hex.trim())
            .ok_or_else(|| KeyFileError::Parse("secret_hex is not hex".into()))?;
        if j.algorithm == HMAC_SHA256 && secret.len() < MIN_HMAC_KEY_LEN {
            let len = secret.len();
            wipe(&mut secret);
            return Err(KeyFileError::Key(KeyError::TooShort {
                len,
                min: MIN_HMAC_KEY_LEN,
            }));
        }
        Ok(Self {
            algorithm: j.algorithm.clone(),
            key_id: j.key_id.clone(),
            device_id: None,
            secret,
            public: None,
        })
    }

    fn from_v2(j: &KeyJson) -> Result<Self, KeyFileError> {
        let kind = match j.kind.as_deref() {
            Some("secret") => KeyKind::Secret,
            Some("public") => KeyKind::Public,
            Some(k) => return Err(KeyFileError::Parse(format!("unknown kind {k:?}"))),
            None => return Err(KeyFileError::Parse("missing kind".into())),
        };
        match (j.algorithm.as_str(), kind) {
            (ED25519, KeyKind::Secret) => {
                let hex = j
                    .secret_hex
                    .as_deref()
                    .ok_or_else(|| KeyFileError::Parse("missing secret_hex".into()))?;
                let mut seed = hex32("secret_hex", hex)?;
                let k = Self::ed25519_from_seed(&seed, Some(&j.key_id));
                wipe(&mut seed);
                let k = k?;
                if let Some(p) = &j.public_hex {
                    if Some(hex32("public_hex", p)?) != k.public {
                        return Err(KeyFileError::PublicKeyMismatch);
                    }
                }
                Ok(k)
            }
            (ED25519, KeyKind::Public) => {
                if j.secret_hex.is_some() {
                    return Err(KeyFileError::Parse(
                        "a public key file must not contain secret_hex".into(),
                    ));
                }
                let p = j
                    .public_hex
                    .as_deref()
                    .ok_or_else(|| KeyFileError::Parse("missing public_hex".into()))?;
                Self::ed25519_public(&hex32("public_hex", p)?, Some(&j.key_id))
            }
            (HMAC_SHA256, KeyKind::Secret) => {
                if j.public_hex.is_some() {
                    return Err(KeyFileError::Parse("HMAC keys have no public_hex".into()));
                }
                let hex = j
                    .secret_hex
                    .as_deref()
                    .ok_or_else(|| KeyFileError::Parse("missing secret_hex".into()))?;
                let mut secret = from_hex(hex.trim())
                    .ok_or_else(|| KeyFileError::Parse("secret_hex is not hex".into()))?;
                let k = Self::hmac_from_secret(&secret, Some(&j.key_id));
                wipe(&mut secret);
                k
            }
            (HMAC_SHA256, KeyKind::Public) => {
                Err(KeyFileError::NoPublicKey(HMAC_SHA256.to_string()))
            }
            (a, _) => Err(KeyFileError::UnsupportedAlgorithm(a.to_string())),
        }
    }

    /// Parse a key file's text (no permission check).
    pub fn from_json(s: &str) -> Result<Self, KeyFileError> {
        let j: KeyJson = serde_json::from_str(s).map_err(|e| KeyFileError::Parse(e.to_string()))?;
        Self::from_parsed(&j)
    }

    /// Create `path` exclusively, never following a symlink, and fsync it.
    /// Mode 0600 for a key with secret material, 0644 for a public key
    /// file. An existing file (or symlink, dangling or not) is
    /// [`KeyFileError::Exists`]; nothing is overwritten.
    pub fn write_new(&self, path: &Path) -> Result<(), KeyFileError> {
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        crate::store::private(&mut o);
        #[cfg(unix)]
        if self.is_public() {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o644);
        }
        let mut f = match o.open(path) {
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

    /// Read and parse a key file (secret or public) after the checks
    /// described in the module docs: the permission/owner rule applies only
    /// if the file holds secret material.
    pub fn load(path: &Path) -> Result<Self, KeyFileError> {
        let (mut text, md, f) = read_key_text(path)?;
        let r = Self::from_json(&text);
        wipe_string(&mut text);
        let k = r?;
        if !k.is_public() {
            check_secret_access(&f, &md)?;
        }
        Ok(k)
    }

    /// Load a key file that must be a **public** key file; a file with
    /// secret material is [`KeyFileError::NotPublic`] (whatever its mode).
    pub fn load_public(path: &Path) -> Result<Self, KeyFileError> {
        let (mut text, _, _) = read_key_text(path)?;
        let r = Self::from_json(&text);
        wipe_string(&mut text);
        let k = r?;
        if !k.is_public() {
            return Err(KeyFileError::NotPublic(k.key_id.clone()));
        }
        Ok(k)
    }

    /// Load a key file that must hold a secret (a signer). A public key
    /// file is [`KeyFileError::NoSecret`].
    pub fn load_secret(path: &Path) -> Result<Self, KeyFileError> {
        let k = Self::load(path)?;
        if k.is_public() {
            return Err(KeyFileError::NoSecret);
        }
        Ok(k)
    }
}

/// `<secret path>.pub`: where `robodr-blackbox keygen` puts the public key.
pub fn public_key_path(secret_path: &Path) -> PathBuf {
    let mut s = secret_path.as_os_str().to_os_string();
    s.push(PUBLIC_KEY_SUFFIX);
    PathBuf::from(s)
}

/// Best-effort wipe of a string that held key material (`zeroize`: volatile
/// writes of NUL, which keep it valid UTF-8, and a compiler fence, like
/// [`crate::crypto::wipe`]).
fn wipe_string(s: &mut str) {
    zeroize::Zeroize::zeroize(s);
}

#[cfg(unix)]
extern "C" {
    fn geteuid() -> u32;
}

/// The effective uid of this process.
#[cfg(unix)]
#[allow(unsafe_code)] // FFI: no std API for the effective uid.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
    unsafe { geteuid() }
}

/// The rule for files holding secret material ([`crate::secret_file`]):
/// owned by the effective user or root, and either no group/other access
/// or a systemd credential only root and this user can read.
fn check_secret_access(f: &File, md: &Metadata) -> Result<(), KeyFileError> {
    use crate::secret_file::{check_secret_file, SecretFileError};
    match check_secret_file(f, md) {
        Ok(_) => Ok(()),
        Err(SecretFileError::Mode { mode }) => Err(KeyFileError::Permissions { mode }),
        Err(SecretFileError::Owner { uid, .. }) => Err(KeyFileError::Owner { uid }),
        Err(SecretFileError::NotRegular) => Err(KeyFileError::NotRegular),
        Err(e) => Err(KeyFileError::Credential(e)),
    }
}

/// The rule for files used as trust anchors (keyrings, previous keys, even
/// public-only): owned by root or the effective user, and writable by
/// nobody else (`mode & 0o022 == 0`). Whoever can write such a file
/// decides which signatures verify.
fn check_trust_access(md: &Metadata) -> Result<(), KeyFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = md.permissions().mode() & 0o7777;
        let uid = md.uid();
        if mode & 0o022 != 0 || (uid != 0 && uid != effective_uid()) {
            return Err(KeyFileError::UntrustedFile { uid, mode });
        }
    }
    #[cfg(not(unix))]
    let _ = md;
    Ok(())
}

/// Open without following symlinks, require a regular file of bounded
/// size, read it. Returns the text and the opened file's metadata (the
/// permission rule is applied by the caller once it knows whether the file
/// holds secrets).
fn read_key_text(path: &Path) -> Result<(String, Metadata, File), KeyFileError> {
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
    if md.len() > MAX_KEY_FILE_BYTES {
        return Err(KeyFileError::TooLarge { len: md.len() });
    }
    // Sized up front: a String that grows while reading would leave copies
    // of the key text in the buffers it outgrew.
    let mut s = String::with_capacity(md.len() as usize + 64);
    (&f).take(MAX_KEY_FILE_BYTES + 1)
        .read_to_string(&mut s)
        .map_err(|e| KeyFileError::Parse(e.to_string()))?;
    if s.len() as u64 > MAX_KEY_FILE_BYTES {
        let len = s.len() as u64;
        wipe_string(&mut s);
        return Err(KeyFileError::TooLarge { len });
    }
    Ok((s, md, f))
}

/// Parse key file or keyring file text into key files. The text is parsed
/// straight into [`KeyJson`] (whose `Drop` wipes the secret); no
/// intermediate `serde_json::Value` copy of the secret is made.
fn parse_key_files(text: &str) -> Result<Vec<KeyFile>, KeyFileError> {
    let probe: FormatProbe =
        serde_json::from_str(text).map_err(|e| KeyFileError::Parse(e.to_string()))?;
    match probe.format.as_deref() {
        Some(KEYRING_FORMAT) => {
            let j: KeyringJson =
                serde_json::from_str(text).map_err(|e| KeyFileError::Parse(e.to_string()))?;
            debug_assert_eq!(j.format, KEYRING_FORMAT);
            if j.keys.is_empty() {
                return Err(KeyFileError::Parse("keyring holds no keys".into()));
            }
            j.keys.iter().map(KeyFile::from_parsed).collect()
        }
        _ => {
            let j: KeyJson =
                serde_json::from_str(text).map_err(|e| KeyFileError::Parse(e.to_string()))?;
            Ok(vec![KeyFile::from_parsed(&j)?])
        }
    }
}

/// One keyring entry: the verifier and, if the key is bound, its unit.
struct Entry {
    verifier: Box<dyn Verifier>,
    device_id: Option<String>,
}

/// Verifiers by key id. See the module docs.
#[derive(Default)]
pub struct Keyring {
    keys: BTreeMap<String, Entry>,
    label: String,
    allow_mixed: bool,
    refuse_hmac: bool,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("key_ids", &self.key_ids())
            .field("allow_mixed_algorithms", &self.allow_mixed)
            .field("refuse_hmac", &self.refuse_hmac)
            .finish()
    }
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow keys of different algorithms (HMAC next to Ed25519) in this
    /// ring. Off by default; see the module docs for why.
    pub fn set_allow_mixed_algorithms(&mut self, allow: bool) -> &mut Self {
        self.allow_mixed = allow;
        self
    }

    /// Refuse every HMAC key added to this ring from now on
    /// ([`KeyFileError::LegacyHmac`]; nothing of a refused file is added).
    /// Off for a plain [`Keyring::new`] (library compatibility); the
    /// `robodr-blackbox` tool and `robodr-agentd` turn it on unless the
    /// operator passes `--allow-hmac` / sets `blackbox.allow_hmac`.
    pub fn set_refuse_hmac(&mut self, refuse: bool) -> &mut Self {
        self.refuse_hmac = refuse;
        self
    }

    fn check_add(&self, id: &str, algorithm: &str) -> Result<(), KeyFileError> {
        if self.keys.contains_key(id) {
            return Err(KeyFileError::DuplicateKeyId(id.to_string()));
        }
        if self.refuse_hmac && algorithm == HMAC_SHA256 {
            return Err(KeyFileError::LegacyHmac(id.to_string()));
        }
        if !self.allow_mixed {
            if let Some(e) = self
                .keys
                .values()
                .find(|e| e.verifier.algorithm() != algorithm)
            {
                return Err(KeyFileError::MixedAlgorithms {
                    existing: e.verifier.algorithm().to_string(),
                    added: algorithm.to_string(),
                });
            }
        }
        Ok(())
    }

    fn insert(&mut self, v: Box<dyn Verifier>, device_id: Option<String>) {
        self.keys.insert(
            v.key_id().to_string(),
            Entry {
                verifier: v,
                device_id,
            },
        );
        self.label = format!(
            "keyring[{}]",
            self.keys.keys().cloned().collect::<Vec<_>>().join(",")
        );
    }

    /// Add a verifier under its own key id, not bound to a device. A second
    /// key with the same id is [`KeyFileError::DuplicateKeyId`] (ambiguous,
    /// never silently replaced); a key of another algorithm than the ring's
    /// is [`KeyFileError::MixedAlgorithms`] unless allowed.
    pub fn add(&mut self, v: Box<dyn Verifier>) -> Result<(), KeyFileError> {
        self.add_bound(v, None)
    }

    /// [`Keyring::add`], binding the key to `device_id` (if `Some`): it then
    /// verifies only chains of that device.
    pub fn add_bound(
        &mut self,
        v: Box<dyn Verifier>,
        device_id: Option<&str>,
    ) -> Result<(), KeyFileError> {
        if let Some(d) = device_id {
            check_device_id(d)?;
        }
        self.check_add(v.key_id(), v.algorithm())?;
        self.insert(v, device_id.map(str::to_string));
        Ok(())
    }

    /// Add the key in `k` (Ed25519 secret or public, HMAC; see
    /// [`KeyFile::verifier`]), with its `device_id` binding.
    pub fn add_key_file(&mut self, k: &KeyFile) -> Result<(), KeyFileError> {
        self.add_bound(k.verifier()?, k.device_id.as_deref())
    }

    fn add_all(&mut self, keys: &[KeyFile]) -> Result<(), KeyFileError> {
        // Validate the whole batch first: nothing is added unless all are.
        let mut alg: Option<String> = self
            .keys
            .values()
            .next()
            .map(|e| e.verifier.algorithm().to_string());
        let mut seen = std::collections::BTreeSet::new();
        let mut verifiers = Vec::with_capacity(keys.len());
        for k in keys {
            if self.keys.contains_key(&k.key_id) || !seen.insert(k.key_id.as_str()) {
                return Err(KeyFileError::DuplicateKeyId(k.key_id.clone()));
            }
            k.check_hmac_policy(!self.refuse_hmac)?;
            let v = k.verifier()?;
            match &alg {
                Some(a) if !self.allow_mixed && a != v.algorithm() => {
                    return Err(KeyFileError::MixedAlgorithms {
                        existing: a.clone(),
                        added: v.algorithm().to_string(),
                    })
                }
                Some(_) => {}
                None => alg = Some(v.algorithm().to_string()),
            }
            verifiers.push((v, k.device_id.clone()));
        }
        for (v, d) in verifiers {
            self.insert(v, d);
        }
        Ok(())
    }

    /// Load a key file or keyring file into this ring. A file holding any
    /// secret must pass the permission/owner rule; a public-only file the
    /// trust-anchor rule (owned by root or this user, not group/world-
    /// writable: [`KeyFileError::UntrustedFile`]). Nothing is added unless
    /// every key in the file is usable.
    pub fn load_file(&mut self, path: &Path) -> Result<(), KeyFileError> {
        let keys = load_key_files(path)?;
        self.add_all(&keys)
    }

    /// Like [`Keyring::load_file`], but every key must be a public key:
    /// secret material is [`KeyFileError::NotPublic`] (for verifiers that
    /// must never hold signing keys).
    ///
    /// The file must pass the trust-anchor rule (owned by root or this
    /// user, not group/world-writable: [`KeyFileError::UntrustedFile`]).
    pub fn load_public_file(&mut self, path: &Path) -> Result<(), KeyFileError> {
        let (mut text, md, _) = read_key_text(path)?;
        let r = parse_key_files(&text);
        wipe_string(&mut text);
        let keys = r?;
        if let Some(k) = keys.iter().find(|k| !k.is_public()) {
            return Err(KeyFileError::NotPublic(k.key_id.clone()));
        }
        check_trust_access(&md)?;
        self.add_all(&keys)
    }

    /// Parse key file or keyring file text into this ring (no permission
    /// check).
    pub fn add_json(&mut self, text: &str) -> Result<(), KeyFileError> {
        self.add_all(&parse_key_files(text)?)
    }

    /// The verifier for `key_id`.
    pub fn get(&self, key_id: &str) -> Option<&dyn Verifier> {
        self.keys.get(key_id).map(|e| &*e.verifier)
    }

    /// The device `key_id` is bound to, if any.
    pub fn device_of(&self, key_id: &str) -> Option<&str> {
        self.keys.get(key_id).and_then(|e| e.device_id.as_deref())
    }

    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }

    /// Key ids of symmetric (HMAC) keys: their holder can also forge.
    pub fn symmetric_key_ids(&self) -> Vec<&str> {
        self.keys
            .iter()
            .filter(|(_, e)| e.verifier.algorithm() == HMAC_SHA256)
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// Distinct algorithms of the keys in the ring.
    pub fn algorithms(&self) -> Vec<&str> {
        let mut a: Vec<&str> = self.keys.values().map(|e| e.verifier.algorithm()).collect();
        a.sort_unstable();
        a.dedup();
        a
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
    /// No key is named: accepted only if the ring holds exactly one key
    /// (unambiguous). Evidence verification names its key
    /// ([`Verifier::verify_key`]); see the module docs.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let mut it = self.keys.values();
        match (it.next(), it.next()) {
            (Some(e), None) => e.verifier.verify(message, signature),
            _ => false,
        }
    }
    fn verify_as(&self, key_id: &str, message: &[u8], signature: &[u8]) -> bool {
        self.keys
            .get(key_id)
            .is_some_and(|e| e.verifier.verify(message, signature))
    }
    fn verify_key(&self, key_id: &str, algorithm: &str, message: &[u8], signature: &[u8]) -> bool {
        self.keys.get(key_id).is_some_and(|e| {
            e.verifier.algorithm() == algorithm && e.verifier.verify(message, signature)
        })
    }
    fn key_device(&self, key_id: &str) -> Option<&str> {
        self.device_of(key_id)
    }
    fn key_fingerprint(&self, key_id: &str) -> Option<String> {
        self.keys
            .get(key_id)
            .and_then(|e| e.verifier.key_fingerprint(key_id))
    }
    fn verify_any(&self, message: &[u8], signature: &[u8]) -> bool {
        self.keys
            .values()
            .any(|e| e.verifier.verify_any(message, signature))
    }
}

/// Load every key in a key file or keyring file, with the checks of
/// [`Keyring::load_file`] (a file holding any secret must pass the
/// permission/owner rule, a public-only file the trust-anchor rule: owned
/// by root or this user, not group/world-writable).
pub fn load_key_files(path: &Path) -> Result<Vec<KeyFile>, KeyFileError> {
    let (mut text, md, f) = read_key_text(path)?;
    let r = parse_key_files(&text);
    wipe_string(&mut text);
    let keys = r?;
    if keys.iter().any(|k| !k.is_public()) {
        check_secret_access(&f, &md)?;
    } else {
        check_trust_access(&md)?;
    }
    Ok(keys)
}

/// Load a recorder's retired keys from `paths` (public key or keyring
/// files, [`load_key_files`]) with the checks both `robodr-agentd`
/// (`blackbox.previous_keys`) and `robodr-blackbox rotate
/// --previous-keys` apply: an Ed25519 secret key file is refused (its
/// `.pub` suffices: a retired signing key has no business on the unit), an
/// HMAC key needs `allow_hmac` (and adds a warning), no key may carry an
/// id in `exclude` (`(key id, why)`: the current or new key), and a key
/// bound to a device must be bound to `device_id`. Ids are distinct;
/// algorithms are mixed only with `allow_hmac` (the way off HMAC). Errors
/// name the file under `label`.
pub fn load_previous_keys(
    label: &str,
    paths: &[&Path],
    device_id: &str,
    exclude: &[(&str, &str)],
    allow_hmac: bool,
    warnings: &mut Vec<String>,
) -> Result<PreviousKeys, String> {
    let mut all = Vec::new();
    for p in paths {
        let shown = p.display();
        let keys = load_key_files(p).map_err(|e| format!("{label} {shown}: {e}"))?;
        for k in keys {
            let id = k.key_id.escape_debug().to_string();
            k.check_hmac_policy(allow_hmac)
                .map_err(|e| format!("{label} {shown}: {e}"))?;
            if !k.is_symmetric() && !k.is_public() {
                return Err(format!(
                    "{label} {shown}: key \"{id}\" is a secret key file; a retired ed25519 key \
                     is listed by its public file (robodr-blackbox export-pub)"
                ));
            }
            if let Some((_, why)) = exclude.iter().find(|(x, _)| *x == k.key_id) {
                return Err(format!("{label} {shown}: key \"{id}\" is {why}"));
            }
            if let Some(d) = k.device_id.as_deref() {
                if d != device_id {
                    return Err(format!(
                        "{label} {shown}: key \"{id}\" is bound to device \"{}\", not \"{}\"",
                        d.escape_debug(),
                        device_id.escape_debug()
                    ));
                }
            }
            if k.is_symmetric() {
                warnings.push(format!(
                    "{label}: {id} is a legacy hmac-sha256 key: whoever holds it can forge \
                     the records it signed"
                ));
            }
            all.push(k);
        }
    }
    PreviousKeys::from_key_files(&all, allow_hmac).map_err(|e| format!("{label}: {e}"))
}

/// A recorder's **previous** (retired) keys after a key rotation, as a
/// `Send + Sync`, cheaply cloned set: what [`crate::Recorder::open_with_keys`]
/// needs on every (re)open of a log whose older records are signed by keys
/// the unit no longer signs with, and what
/// [`crate::TpmNvCounterAnchor::with_previous_keys`] needs for a sidecar
/// written before the rotation. Unlike a [`Keyring`] it can be shared
/// between threads and reopens.
///
/// Keys are distinct by id and of one algorithm unless `allow_mixed` (an
/// HMAC-to-Ed25519 migration has one HMAC key here and the Ed25519 signer
/// outside, which is not mixing). Legacy-HMAC policy is the caller's
/// ([`KeyFile::check_hmac_policy`]). [`Verifier::verify`] (no key named)
/// accepts only with exactly one key; [`Verifier::verify_any`] is the
/// recorder's trusted-local use (put only this unit's own keys here).
#[derive(Clone, Default)]
pub struct PreviousKeys {
    keys: std::sync::Arc<Vec<(SyncVerifier, Option<String>)>>,
    label: String,
}

type SyncVerifier = std::sync::Arc<dyn Verifier + Send + Sync>;

impl fmt::Debug for PreviousKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreviousKeys")
            .field("key_ids", &self.key_ids())
            .finish()
    }
}

impl PreviousKeys {
    /// The verifying halves of `files` (Ed25519 secret or public, HMAC),
    /// with their `device_id` bindings. Refuses duplicate ids
    /// ([`KeyFileError::DuplicateKeyId`]) and, unless `allow_mixed`, keys
    /// of different algorithms ([`KeyFileError::MixedAlgorithms`]).
    pub fn from_key_files(files: &[KeyFile], allow_mixed: bool) -> Result<Self, KeyFileError> {
        let mut keys: Vec<(SyncVerifier, Option<String>)> = Vec::with_capacity(files.len());
        for k in files {
            if keys.iter().any(|(v, _)| v.key_id() == k.key_id) {
                return Err(KeyFileError::DuplicateKeyId(k.key_id.clone()));
            }
            if let Some((v, _)) = keys.first() {
                if !allow_mixed && v.algorithm() != k.algorithm {
                    return Err(KeyFileError::MixedAlgorithms {
                        existing: v.algorithm().to_string(),
                        added: k.algorithm.clone(),
                    });
                }
            }
            let v: SyncVerifier = match k.algorithm.as_str() {
                ED25519 => std::sync::Arc::new(k.ed25519_verifying_key()?),
                HMAC_SHA256 => std::sync::Arc::new(k.hmac()?),
                a => return Err(KeyFileError::UnsupportedAlgorithm(a.to_string())),
            };
            keys.push((v, k.device_id.clone()));
        }
        let label = format!(
            "previous[{}]",
            keys.iter()
                .map(|(v, _)| v.key_id())
                .collect::<Vec<_>>()
                .join(",")
        );
        Ok(Self {
            keys: std::sync::Arc::new(keys),
            label,
        })
    }

    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.iter().map(|(v, _)| v.key_id()).collect()
    }

    /// `(key_id, algorithm, device_id)` of every key.
    pub fn entries(&self) -> Vec<(&str, &str, Option<&str>)> {
        self.keys
            .iter()
            .map(|(v, d)| (v.key_id(), v.algorithm(), d.as_deref()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn find(&self, key_id: &str) -> Option<&(SyncVerifier, Option<String>)> {
        self.keys.iter().find(|(v, _)| v.key_id() == key_id)
    }
}

impl Verifier for PreviousKeys {
    fn algorithm(&self) -> &str {
        "keyring"
    }
    fn key_id(&self) -> &str {
        &self.label
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self.keys.as_slice() {
            [(v, _)] => v.verify(message, signature),
            _ => false,
        }
    }
    fn verify_as(&self, key_id: &str, message: &[u8], signature: &[u8]) -> bool {
        self.find(key_id)
            .is_some_and(|(v, _)| v.verify(message, signature))
    }
    fn verify_key(&self, key_id: &str, algorithm: &str, message: &[u8], signature: &[u8]) -> bool {
        self.find(key_id)
            .is_some_and(|(v, _)| v.algorithm() == algorithm && v.verify(message, signature))
    }
    fn key_device(&self, key_id: &str) -> Option<&str> {
        self.find(key_id).and_then(|(_, d)| d.as_deref())
    }
    fn key_fingerprint(&self, key_id: &str) -> Option<String> {
        self.find(key_id)
            .and_then(|(v, _)| v.key_fingerprint(key_id))
    }
    fn verify_any(&self, message: &[u8], signature: &[u8]) -> bool {
        self.keys.iter().any(|(v, _)| v.verify(message, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Signer;

    #[test]
    fn wipe_string_zeroes_every_byte_and_keeps_the_length() {
        let mut s = String::from("{\"secret_hex\":\"00ff\"}é");
        let len = s.len();
        wipe_string(&mut s);
        assert_eq!(s.len(), len);
        assert!(s.bytes().all(|b| b == 0));
        let mut empty = String::new();
        wipe_string(&mut empty);
    }

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
        // No key named and two keys: ambiguous, refused (K1).
        assert!(!ring.verify(b"m", &sa) && !ring.verify(b"m", &sb));
        assert!(!ring.verify_any(b"x", &sa));
        assert!(ring.verify_any(b"m", &sa) && ring.verify_any(b"m", &sb));
        assert!(ring.verify_key("a", "hmac-sha256", b"m", &sa));
        assert!(!ring.verify_key("a", "ed25519", b"m", &sa));
        assert!(!ring.verify_key("b", "hmac-sha256", b"m", &sa));
        let mut one = Keyring::new();
        one.add_key_file(&a).unwrap();
        assert!(one.verify(b"m", &sa) && !one.verify(b"m", &sb));
        assert!(!Keyring::new().verify(b"m", &sa));
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

    fn mode(p: &Path, m: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = (p, m);
    }

    #[test]
    fn ed25519_generate_write_load_sign_verify() {
        let d = tmp("ed");
        let sp = d.join("unit.key");
        let pp = public_key_path(&sp);
        assert_eq!(pp, d.join("unit.key.pub"));
        let k = KeyFile::generate_ed25519(None).unwrap();
        assert_eq!(k.algorithm, "ed25519");
        assert!(k.key_id.starts_with("ed25519:"));
        assert_eq!(k.kind(), KeyKind::Secret);
        assert!(!k.is_symmetric());
        k.write_new(&sp).unwrap();
        let pubk = k.to_public().unwrap();
        assert!(pubk.is_public() && pubk.secret().is_empty());
        assert_eq!(pubk.key_id, k.key_id);
        pubk.write_new(&pp).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(m(&sp), 0o600);
            assert_eq!(m(&pp), 0o644);
        }
        // The public file never contains the seed.
        let pub_text = std::fs::read_to_string(&pp).unwrap();
        assert!(!pub_text.contains(&to_hex(k.secret())));
        assert!(pub_text.contains("\"kind\":\"public\""));
        assert!(!pub_text.contains("secret_hex"));

        let ls = KeyFile::load(&sp).unwrap();
        assert_eq!(ls.secret(), k.secret());
        assert_eq!(ls.public_key(), k.public_key());
        let signer = ls.signer().unwrap();
        assert_eq!(signer.algorithm(), "ed25519");
        let sig = signer.sign(b"m").unwrap();
        assert_eq!(sig.len(), 64);
        let lp = KeyFile::load(&pp).unwrap();
        assert!(lp.verifier().unwrap().verify(b"m", &sig));
        assert!(!lp.verifier().unwrap().verify(b"x", &sig));
        assert!(matches!(lp.signer(), Err(KeyFileError::NoSecret)));
        assert!(matches!(
            KeyFile::load_secret(&pp),
            Err(KeyFileError::NoSecret)
        ));
        assert!(KeyFile::load_public(&pp).is_ok());
        assert!(matches!(
            KeyFile::load_public(&sp),
            Err(KeyFileError::NotPublic(_))
        ));
        // Ed25519SigningKey / VerifyingKey interop (the public API others use).
        let sk = ls.ed25519_signing_key().unwrap();
        assert_eq!(sk.public_key(), lp.public_key().unwrap());
        assert!(lp
            .ed25519_verifying_key()
            .unwrap()
            .verify(b"n", &sk.sign_message(b"n")));
        assert!(matches!(
            lp.ed25519_signing_key(),
            Err(KeyFileError::NoSecret)
        ));
        // Both files are never overwritten.
        assert!(matches!(k.write_new(&sp), Err(KeyFileError::Exists)));
        assert!(matches!(pubk.write_new(&pp), Err(KeyFileError::Exists)));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn ed25519_seed_and_explicit_id_are_deterministic() {
        let a = KeyFile::ed25519_from_seed(&[9; 32], Some("ugv-01-bb")).unwrap();
        let b = KeyFile::from_json(&a.to_json()).unwrap();
        assert_eq!(b.key_id, "ugv-01-bb");
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(
            a.public_key().unwrap(),
            crate::sign_ed25519::public_key_from_seed(&[9; 32])
        );
        let derived = KeyFile::ed25519_from_seed(&[9; 32], None).unwrap();
        assert_eq!(
            derived.key_id,
            derive_key_id(&derived.public_key().unwrap())
        );
        assert!(KeyFile::ed25519_from_seed(&[9; 32], Some("")).is_err());
        assert!(KeyFile::generate_ed25519(Some("has space")).is_err());
        assert!(KeyFile::generate("ed25519", None)
            .unwrap()
            .key_id
            .starts_with("ed25519:"));
        assert!(KeyFile::generate("hmac", None).unwrap().is_symmetric());
        assert!(KeyFile::generate("hmac-sha256", None)
            .unwrap()
            .is_symmetric());
        assert!(matches!(
            KeyFile::generate("rsa", None),
            Err(KeyFileError::UnsupportedAlgorithm(_))
        ));
        let g1 = KeyFile::generate_ed25519(None).unwrap();
        let g2 = KeyFile::generate_ed25519(None).unwrap();
        assert_ne!(g1.secret(), g2.secret());
        assert_ne!(g1.key_id, g2.key_id);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("redacted") && !dbg.contains(&to_hex(&[9; 32])));
    }

    #[test]
    fn hmac_has_no_public_half_and_keeps_v1_format() {
        let h = KeyFile::hmac_from_secret(&[3; 32], Some("h")).unwrap();
        assert!(matches!(h.to_public(), Err(KeyFileError::NoPublicKey(_))));
        assert_eq!(h.public_key(), None);
        // Byte-for-byte the legacy v1 layout.
        assert_eq!(
            h.to_json(),
            format!(
                "{{\"format\":\"robodr-blackbox-key/v1\",\"algorithm\":\"hmac-sha256\",\
                 \"key_id\":\"h\",\"secret_hex\":\"{}\"}}\n",
                "03".repeat(32)
            )
        );
        let sig = h.signer().unwrap().sign(b"m").unwrap();
        assert!(h.verifier().unwrap().verify(b"m", &sig));
        // v2 HMAC secret is read too.
        let v2 = format!(
            "{{\"format\":\"{KEY_FILE_FORMAT_V2}\",\"kind\":\"secret\",\"algorithm\":\"hmac-sha256\",\
             \"key_id\":\"h\",\"secret_hex\":\"{}\"}}",
            "03".repeat(32)
        );
        assert_eq!(KeyFile::from_json(&v2).unwrap().secret(), h.secret());
        // ...but not as a "public" key, and not with a public_hex.
        for bad in [
            v2.replace("\"secret\"", "\"public\""),
            v2.replace(
                "\"key_id\"",
                &format!("\"public_hex\":\"{}\",\"key_id\"", "00".repeat(32)),
            ),
            v2.replace(&"03".repeat(32), &"03".repeat(8)),
        ] {
            assert!(KeyFile::from_json(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_malformed_v2_files() {
        let k = KeyFile::ed25519_from_seed(&[5; 32], Some("e")).unwrap();
        let sec = k.to_json();
        let pubj = k.to_public().unwrap().to_json();
        assert!(KeyFile::from_json(&sec).is_ok());
        assert!(KeyFile::from_json(&pubj).is_ok());
        let pub_hex = to_hex(&k.public_key().unwrap());
        let other_pub = to_hex(&public_key_from_seed(&[6; 32]));
        let mut bad_inputs = vec![
            sec.replace("\"kind\":\"secret\",", ""),
            sec.replace("\"secret\"", "\"private\""),
            sec.replace(&pub_hex, &other_pub),
            sec.replace(&"05".repeat(32), &"05".repeat(31)),
            sec.replace(&"05".repeat(32), &format!("zz{}", "05".repeat(31))),
            sec.replace("ed25519", "ed448"),
            sec.replace("}", ",\"extra\":1}"),
            pubj.replace("\"kind\":\"public\"", "\"kind\":\"secret\""),
            pubj.replace(&pub_hex, &pub_hex[..62]),
            pubj.replace(&pub_hex, &"00".repeat(32)),
            // Identity point: small order, refused.
            pubj.replace(&pub_hex, &format!("01{}", "00".repeat(31))),
            pubj.replace(
                "\"key_id\"",
                &format!("\"secret_hex\":\"{}\",\"key_id\"", "05".repeat(32)),
            ),
            pubj.replace("robodr-blackbox-key/v2", "robodr-blackbox-key/v1"),
            pubj.replace("robodr-blackbox-key/v2", "robodr-blackbox-key/v3"),
        ];
        bad_inputs.push(pubj.replace(",\"public_hex\"", ",\"x\""));
        for bad in &bad_inputs {
            assert!(KeyFile::from_json(bad).is_err(), "{bad}");
        }
        assert!(matches!(
            KeyFile::from_json(&sec.replace(&pub_hex, &other_pub)),
            Err(KeyFileError::PublicKeyMismatch)
        ));
        // public_hex is optional in a secret file (derived from the seed).
        let no_pub = sec.replace(&format!("\"public_hex\":\"{pub_hex}\","), "");
        assert_eq!(
            KeyFile::from_json(&no_pub).unwrap().public_key(),
            k.public_key()
        );
    }

    #[cfg(unix)]
    #[test]
    fn public_files_load_with_any_mode_secrets_never() {
        let d = tmp("pubperm");
        let k = KeyFile::generate_ed25519(Some("unit-e")).unwrap();
        let sp = d.join("e.key");
        let pp = public_key_path(&sp);
        k.write_new(&sp).unwrap();
        k.to_public().unwrap().write_new(&pp).unwrap();
        // Readable by anyone is fine for a public key ...
        for m in [0o644, 0o604, 0o400, 0o444] {
            mode(&pp, m);
            assert!(KeyFile::load(&pp).is_ok(), "{m:o}");
            assert!(Keyring::new().load_file(&pp).is_ok(), "{m:o}");
            assert!(Keyring::new().load_public_file(&pp).is_ok(), "{m:o}");
            assert!(load_key_files(&pp).is_ok(), "{m:o}");
        }
        // ... but a file used as a trust anchor (keyring, previous keys)
        // that another user can write decides what verifies: refused.
        for m in [0o666, 0o664, 0o646, 0o620] {
            mode(&pp, m);
            assert!(
                matches!(
                    Keyring::new().load_file(&pp),
                    Err(KeyFileError::UntrustedFile { .. })
                ),
                "{m:o}"
            );
            assert!(
                matches!(
                    Keyring::new().load_public_file(&pp),
                    Err(KeyFileError::UntrustedFile { .. })
                ),
                "{m:o}"
            );
            let e = load_key_files(&pp).unwrap_err();
            assert!(e.to_string().contains("trust anchor"), "{e}");
        }
        mode(&pp, 0o644);
        #[cfg(unix)]
        if effective_uid() == 0 {
            std::os::unix::fs::chown(&pp, Some(4321), None).unwrap();
            assert!(matches!(
                load_key_files(&pp),
                Err(KeyFileError::UntrustedFile { uid: 4321, .. })
            ));
            std::os::unix::fs::chown(&pp, Some(0), None).unwrap();
        }
        for m in [0o640, 0o604, 0o644, 0o660] {
            mode(&sp, m);
            assert!(matches!(
                KeyFile::load(&sp),
                Err(KeyFileError::Permissions { .. })
            ));
            assert!(matches!(
                Keyring::new().load_file(&sp),
                Err(KeyFileError::Permissions { .. })
            ));
            // A secret is refused as a "public" key whatever its mode.
            assert!(matches!(
                Keyring::new().load_public_file(&sp),
                Err(KeyFileError::NotPublic(_))
            ));
        }
        mode(&sp, 0o600);
        assert!(KeyFile::load(&sp).is_ok());
        // Symlinked public key files are refused like any key file.
        let link = d.join("link.pub");
        std::os::unix::fs::symlink(&pp, &link).unwrap();
        assert!(matches!(
            KeyFile::load(&link),
            Err(KeyFileError::NotRegular)
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secret_owner_rule() {
        use std::os::unix::fs::MetadataExt;
        let d = tmp("owner");
        let p = d.join("k");
        KeyFile::generate_ed25519(None)
            .unwrap()
            .write_new(&p)
            .unwrap();
        let md = std::fs::metadata(&p).unwrap();
        let f = File::open(&p).unwrap();
        assert!(check_secret_access(&f, &md).is_ok());
        assert!(md.uid() == effective_uid() || md.uid() == 0);
        // Changing ownership needs root; when we have it, check a foreign
        // owner is refused (and root ownership is accepted).
        if effective_uid() == 0 {
            std::os::unix::fs::chown(&p, Some(4242), Some(4242)).unwrap();
            assert!(matches!(
                KeyFile::load(&p),
                Err(KeyFileError::Owner { uid: 4242 })
            ));
            // The public half of a foreign-owned key file is still fine.
            let pp = d.join("k.pub");
            KeyFile::load_public(&p).unwrap_err();
            KeyFile::generate_ed25519(None)
                .unwrap()
                .to_public()
                .unwrap()
                .write_new(&pp)
                .unwrap();
            std::os::unix::fs::chown(&pp, Some(4242), Some(4242)).unwrap();
            assert!(KeyFile::load(&pp).is_ok());
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn mixed_keyring_verifies_ed25519_and_hmac() {
        let e = KeyFile::ed25519_from_seed(&[1; 32], Some("e")).unwrap();
        let h = KeyFile::hmac_from_secret(&[2; 32], Some("h")).unwrap();
        let ring_json = format!(
            "{{\"format\":\"{KEYRING_FORMAT}\",\"keys\":[{},{}]}}",
            e.to_public().unwrap().to_json().trim(),
            h.to_json().trim()
        );
        // Mixing HMAC and Ed25519 needs an explicit opt-in; nothing is
        // added by the refused attempt.
        let mut ring = Keyring::new();
        assert!(matches!(
            ring.add_json(&ring_json),
            Err(KeyFileError::MixedAlgorithms { .. })
        ));
        assert!(ring.is_empty());
        ring.add_key_file(&e).unwrap();
        assert!(matches!(
            ring.add_key_file(&h),
            Err(KeyFileError::MixedAlgorithms { .. })
        ));
        let mut ring = Keyring::new();
        ring.set_allow_mixed_algorithms(true);
        ring.add_json(&ring_json).unwrap();
        assert_eq!(ring.key_ids(), vec!["e", "h"]);
        assert_eq!(ring.algorithms(), vec!["ed25519", "hmac-sha256"]);
        assert_eq!(ring.symmetric_key_ids(), vec!["h"]);
        let se = e.signer().unwrap().sign(b"m").unwrap();
        let sh = h.signer().unwrap().sign(b"m").unwrap();
        assert!(ring.verify_as("e", b"m", &se));
        assert!(ring.verify_as("h", b"m", &sh));
        assert!(!ring.verify_as("e", b"m", &sh));
        // The algorithm must match the key's: an HMAC key never answers
        // for an ed25519 key id, even in a mixed ring.
        assert!(ring.verify_key("h", "hmac-sha256", b"m", &sh));
        assert!(!ring.verify_key("h", "ed25519", b"m", &sh));
        // A public-only ring has no symmetric keys.
        let mut pr = Keyring::new();
        pr.add_json(&e.to_public().unwrap().to_json()).unwrap();
        assert!(pr.symmetric_key_ids().is_empty());
        // Duplicate ids inside one file: nothing is added.
        let dup = format!(
            "{{\"format\":\"{KEYRING_FORMAT}\",\"keys\":[{},{}]}}",
            e.to_public().unwrap().to_json().trim(),
            e.to_json().trim()
        );
        let mut r = Keyring::new();
        assert!(matches!(
            r.add_json(&dup),
            Err(KeyFileError::DuplicateKeyId(_))
        ));
        assert!(r.is_empty());
    }

    #[test]
    fn device_binding_round_trips_and_reaches_the_keyring() {
        let k = KeyFile::ed25519_from_seed(&[8; 32], Some("u1"))
            .unwrap()
            .with_device_id(Some("ugv-01"))
            .unwrap();
        let sec = k.to_json();
        assert!(sec.contains("\"device_id\":\"ugv-01\""));
        let p = k.to_public().unwrap();
        assert_eq!(p.device_id.as_deref(), Some("ugv-01"));
        let back = KeyFile::from_json(&p.to_json()).unwrap();
        assert_eq!(back.device_id.as_deref(), Some("ugv-01"));
        assert_eq!(KeyFile::from_json(&sec).unwrap().device_id, k.device_id);
        let mut ring = Keyring::new();
        ring.add_json(&p.to_json()).unwrap();
        assert_eq!(ring.key_device("u1"), Some("ugv-01"));
        assert_eq!(ring.key_device("nope"), None);
        // HMAC v1 files may carry it too; without it they stay byte-for-byte v1.
        let h = KeyFile::hmac_from_secret(&[3; 32], Some("h"))
            .unwrap()
            .with_device_id(Some("ugv-02"))
            .unwrap();
        let hj = h.to_json();
        assert!(hj.starts_with("{\"format\":\"robodr-blackbox-key/v1\""));
        assert_eq!(
            KeyFile::from_json(&hj).unwrap().device_id.as_deref(),
            Some("ugv-02")
        );
        // Bad device ids are refused, in files and in the API.
        for bad in ["", "has space", &"x".repeat(129)] {
            assert!(matches!(
                KeyFile::hmac_from_secret(&[3; 32], None)
                    .unwrap()
                    .with_device_id(Some(bad)),
                Err(KeyFileError::BadDeviceId)
            ));
            let j = hj.replace("ugv-02", bad);
            assert!(KeyFile::from_json(&j).is_err(), "{j}");
            assert!(Keyring::new()
                .add_bound(Box::new(h.hmac().unwrap()), Some(bad))
                .is_err());
        }
    }

    /// K2 (rev4): Ed25519 key files work through the keyring, and their
    /// lengths are exact: a 32-byte seed, a 32-byte public key.
    #[test]
    fn ed25519_key_files_verify_via_keyring_and_lengths_are_exact() {
        let pk = to_hex(&public_key_from_seed(&[7; 32]));
        let v1 = format!(
            r#"{{"format":"robodr-blackbox-key/v1","algorithm":"ed25519","key_id":"unit-a","secret_hex":"{}"}}"#,
            "07".repeat(32)
        );
        let mut ring = Keyring::new();
        ring.add_json(&v1).unwrap();
        let sk = KeyFile::from_json(&v1).unwrap();
        assert_eq!(sk.secret().len(), SEED_LEN);
        assert_eq!(sk.public_key().map(|p| to_hex(&p)), Some(pk.clone()));
        let sig = sk.signer().unwrap().sign(b"m").unwrap();
        assert!(ring.verify_key("unit-a", "ed25519", b"m", &sig));
        for n in [0usize, 1, 16, 31, 33, 64] {
            let tiny = v1.replace(&"07".repeat(32), &"07".repeat(n));
            assert!(KeyFile::from_json(&tiny).is_err(), "seed of {n} bytes");
            assert!(Keyring::new().add_json(&tiny).is_err());
            let pubj = sk
                .to_public()
                .unwrap()
                .to_json()
                .replace(&pk, &pk[..(2 * n).min(pk.len())]);
            if n < 32 {
                assert!(KeyFile::from_json(&pubj).is_err(), "public of {n} bytes");
            }
        }
        let long_pub = sk
            .to_public()
            .unwrap()
            .to_json()
            .replace(&pk, &format!("{pk}00"));
        assert!(KeyFile::from_json(&long_pub).is_err());
    }

    #[test]
    fn key_text_is_parsed_without_value_copies_and_rejects_non_objects() {
        for bad in ["[]", "1", "\"x\"", "null", "{\"format\":1}"] {
            assert!(Keyring::new().add_json(bad).is_err(), "{bad}");
            assert!(KeyFile::from_json(bad).is_err(), "{bad}");
        }
        let k = KeyFile::hmac_from_secret(&[9; 32], Some("z")).unwrap();
        assert!(k.to_json().ends_with("}\n"));
        assert_eq!(KeyFile::from_json(&k.to_json()).unwrap().secret(), &[9; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn keyring_file_with_a_secret_is_permission_checked() {
        let d = tmp("ringperm");
        let e = KeyFile::ed25519_from_seed(&[1; 32], Some("e")).unwrap();
        let f = KeyFile::ed25519_from_seed(&[4; 32], Some("f")).unwrap();
        let only_pub = d.join("pub.ring");
        std::fs::write(
            &only_pub,
            format!(
                "{{\"format\":\"{KEYRING_FORMAT}\",\"keys\":[{},{}]}}",
                e.to_public().unwrap().to_json().trim(),
                f.to_public().unwrap().to_json().trim()
            ),
        )
        .unwrap();
        mode(&only_pub, 0o644);
        let mut r = Keyring::new();
        r.load_public_file(&only_pub).unwrap();
        assert_eq!(r.len(), 2);
        let with_secret = d.join("sec.ring");
        std::fs::write(
            &with_secret,
            format!(
                "{{\"format\":\"{KEYRING_FORMAT}\",\"keys\":[{},{}]}}",
                e.to_public().unwrap().to_json().trim(),
                f.to_json().trim()
            ),
        )
        .unwrap();
        mode(&with_secret, 0o644);
        assert!(matches!(
            Keyring::new().load_file(&with_secret),
            Err(KeyFileError::Permissions { .. })
        ));
        mode(&with_secret, 0o600);
        assert!(Keyring::new().load_file(&with_secret).is_ok());
        assert!(matches!(
            Keyring::new().load_public_file(&with_secret),
            Err(KeyFileError::NotPublic(id)) if id == "f"
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    // Legacy HMAC policy: refused unless explicitly allowed, for a single
    // key file and for a keyring (a refused ring file adds nothing).
    #[test]
    fn legacy_hmac_is_refused_unless_allowed() {
        let h = KeyFile::hmac_from_secret(&[3; 32], Some("old-hmac")).unwrap();
        let e = KeyFile::ed25519_from_seed(&[1; 32], Some("e")).unwrap();
        assert!(matches!(
            h.check_hmac_policy(false),
            Err(KeyFileError::LegacyHmac(id)) if id == "old-hmac"
        ));
        assert!(h.check_hmac_policy(true).is_ok());
        assert!(e.check_hmac_policy(false).is_ok());
        let msg = h.check_hmac_policy(false).unwrap_err().to_string();
        assert!(
            msg.contains("--allow-hmac") && msg.contains("forge"),
            "{msg}"
        );

        let mut strict = Keyring::new();
        strict.set_refuse_hmac(true);
        assert!(matches!(
            strict.add_key_file(&h),
            Err(KeyFileError::LegacyHmac(_))
        ));
        assert!(matches!(
            strict.add_json(&h.to_json()),
            Err(KeyFileError::LegacyHmac(_))
        ));
        assert!(strict.is_empty());
        strict.add_key_file(&e).unwrap();
        // Opted in: the same key verifies again (existing logs stay
        // verifiable); a plain ring is unchanged (library compatibility).
        let mut allowed = Keyring::new();
        allowed.set_refuse_hmac(false);
        allowed.add_json(&h.to_json()).unwrap();
        assert_eq!(allowed.symmetric_key_ids(), vec!["old-hmac"]);
        Keyring::new().add_key_file(&h).unwrap();
    }

    // `rotate --previous-keys` and agentd's `blackbox.previous_keys`: one
    // set of checks.
    #[test]
    fn previous_keys_loader_applies_the_retired_key_checks() {
        let d = tmp("prevload");
        let k = KeyFile::generate_ed25519(Some("old")).unwrap();
        let sp = d.join("old.key");
        let pp = public_key_path(&sp);
        k.write_new(&sp).unwrap();
        k.to_public().unwrap().write_new(&pp).unwrap();
        let mut w = Vec::new();
        let load = |p: &Path, dev: &str, ex: &[(&str, &str)], hmac: bool, w: &mut Vec<String>| {
            load_previous_keys("--previous-keys", &[p], dev, ex, hmac, w)
        };
        assert_eq!(
            load(&pp, "ugv-1", &[], false, &mut w).unwrap().key_ids(),
            ["old"]
        );
        // A secret key file (the retired signing key itself) is refused.
        let e = load(&sp, "ugv-1", &[], false, &mut w).unwrap_err();
        assert!(e.contains("secret key file"), "{e}");
        // Neither the current nor the new key.
        let e = load(&pp, "ugv-1", &[("old", "the new key id")], false, &mut w).unwrap_err();
        assert!(e.contains("the new key id"), "{e}");
        // A key bound to another device.
        let mut b = KeyFile::generate_ed25519(Some("foreign")).unwrap();
        b.device_id = Some("ugv-9".into());
        let bp = d.join("foreign.pub");
        b.to_public().unwrap().write_new(&bp).unwrap();
        let e = load(&bp, "ugv-1", &[], false, &mut w).unwrap_err();
        assert!(e.contains("bound to device"), "{e}");
        assert!(load(&bp, "ugv-9", &[], false, &mut w).is_ok());
        // HMAC only with the opt-in (and then with a warning).
        let h = KeyFile::hmac_from_secret(&[3; 32], Some("legacy")).unwrap();
        let hp = d.join("legacy.key");
        h.write_new(&hp).unwrap();
        assert!(load(&hp, "ugv-1", &[], false, &mut w).is_err());
        assert!(w.is_empty());
        assert!(load(&hp, "ugv-1", &[], true, &mut w).is_ok());
        assert_eq!(w.len(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
