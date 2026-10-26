//! Profile files on disk: strict parsing, the lock seal, and safe writes.
//!
//! # Strict parsing ([`parse_profile_text`])
//!
//! `Profile` deserialisation in robodr-events is lenient (every set has
//! `#[serde(default)]`, unknown keys are ignored), which is right for the
//! sensor's forward compatibility but wrong for a file an operator is about
//! to lock or enforce: a half-written file that happens to be valid JSON, a
//! typo (`"locked ": true`), or a dropped key would load as a *different*
//! profile without complaint. The commissioning tool therefore requires
//! every `Profile` key to be present, rejects unknown keys (top level and in
//! envelopes; the per-axis envelope keys `max_lateral_speed`,
//! `max_vertical_speed`, `max_roll_pitch_rate` and the boolean `holonomic`
//! are optional, see `robodr_events::profile::Envelope`), rejects duplicate keys **at every depth** (compared after JSON
//! unescaping, so `"/cmd_vel"` and `"/cmd\u005fvel"` are the same key: two
//! entries for one motion channel, where a reviewer sees the first and the
//! parser keeps the last, are refused), and runs `Profile::validate` on
//! every locked profile.
//!
//! # The seal
//!
//! `lock` writes the locked profile as the canonical JSON of the profile
//! with one extra first member, `"seal": "sha256:<hex>"`, the SHA-256 of the
//! file *without* that line. Loading a profile with `"locked": true`
//! requires a valid seal, so a locked file that was edited (a participant
//! added, `locked` flipped by hand, a partial write) is refused, and a seal
//! on an unlocked file is refused too. The sensor ignores the extra key
//! (robodr-events tolerates unknown keys). The seal is a plain hash, not a
//! signature: it detects edits and corruption, not a deliberate forger who
//! recomputes it. Authenticity comes from the detached Ed25519 signature
//! over the exact sealed bytes, checked by the loaders (see [`crate::trust`]).
//!
//! # Metadata
//!
//! The optional top-level `metadata` member (`ProfileMetadata`: schema and
//! profile version, platform / unit, locked_by / locked_at, parent digest)
//! is written by `lock`. When present it must be an object with exactly
//! [`METADATA_KEYS`] (all present, nothing else but the optional
//! [`OPTIONAL_METADATA_KEYS`] `attestation`), and it is only allowed on
//! a locked profile ([`ProfileFileError::MetadataOnDraft`]): a draft has
//! not been locked by anyone. A locked file *without* metadata is a legacy
//! (pre-versioning) profile: it still parses here, so `check`, `diff` and
//! `merge` work on it, but the loaders refuse to enforce it
//! ([`crate::trust::ProfileTrustError::LegacyUnversioned`]); migrate it with
//! `robodr-commission migrate-legacy`.
//!
//! # Safe writes ([`write_file_atomic`])
//!
//! Output is written to a fresh temp file in the destination directory
//! (`O_CREAT|O_EXCL`, so a planted symlink at the temp name is never
//! followed), fsynced, then published atomically: with `hard_link` when the
//! destination must not exist (fails atomically with `EEXIST`, no
//! check-then-write race) or with `rename` when overwriting is allowed. A
//! symlink at the destination is refused in both modes, and only regular
//! files may be overwritten.
//!
//! [`write_files_atomic`] does the same for a set of files that belong
//! together (draft + sign-off + report): every destination is checked
//! first, every temp file is written and fsynced, and only then is anything
//! published. If a publish fails, the files already published by this call
//! are rolled back (removed, or restored from a hard-link backup when
//! overwriting), and all temps are removed. Limits: a crash (power loss)
//! during the publish phase can leave a subset published, and rollback
//! cannot undo a concurrent writer's change to the same paths.

use crate::signoff::sha256_hex;
use crate::to_json;
use robodr_events::profile::{Profile, ProfileError};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// Every key `Profile` serialises; all must be present in a profile file.
pub const PROFILE_KEYS: [&str; 9] = [
    "model",
    "locked",
    "participants",
    "writer_topics",
    "motion_envelopes",
    "services",
    "actions",
    "reader_topics",
    "raw_dds_topics",
];
/// Optional top-level keys (`metadata` is written by `lock`;
/// `participant_identities` and `motion_types` by `learn`, omitted when
/// empty).
pub const OPTIONAL_PROFILE_KEYS: [&str; 3] = ["metadata", "participant_identities", "motion_types"];
/// Keys of one `participant_identities` entry; `ips` and `vendor` are
/// required, the rest optional.
pub const IDENTITY_KEYS: [&str; 5] = ["ips", "vendor", "enclave", "nodes", "max_instances"];
/// Keys of the `metadata` object; all must be present.
pub const METADATA_KEYS: [&str; 7] = [
    "schema_version",
    "profile_version",
    "platform",
    "unit_id",
    "locked_by",
    "locked_at",
    "parent_digest",
];
/// Optional key of the `metadata` object (the operator sign-off evidence,
/// `{"signoff": "<text>", "signatures": "<text>"}`, written by `lock`).
pub const OPTIONAL_METADATA_KEYS: [&str; 1] = ["attestation"];
/// Keys of one envelope object; both must be present.
pub const ENVELOPE_KEYS: [&str; 2] = ["max_linear_speed", "max_joint_speed"];
/// Optional per-axis and joint-term limit keys of an envelope (number or
/// null when present). Absent = `None`; `Envelope` does not serialise them when
/// `None`, so files written before they existed are byte-identical.
pub const OPTIONAL_ENVELOPE_LIMIT_KEYS: [&str; 6] = [
    "max_lateral_speed",
    "max_vertical_speed",
    "max_roll_pitch_rate",
    "max_joint_torque",
    "max_joint_kp",
    "max_joint_position_step",
];
/// Optional boolean key of an envelope (absent = `false`).
pub const ENVELOPE_HOLONOMIC_KEY: &str = "holonomic";
/// The seal member written by `lock`.
pub const SEAL_KEY: &str = "seal";
const SEAL_PREFIX: &str = "{\n  \"seal\": \"sha256:";
const SEAL_SUFFIX: &str = "\",\n";

/// Largest profile file we are willing to load.
pub const MAX_PROFILE_BYTES: u64 = 64 << 20;

/// Why a profile file is refused.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ProfileFileError {
    Json {
        message: String,
    },
    NotAnObject,
    MissingKey {
        key: String,
    },
    UnknownKey {
        key: String,
    },
    BadEnvelope {
        channel: String,
        detail: String,
    },
    /// `"locked": true` without a seal: not produced by `lock`, or the seal
    /// line was removed.
    LockedWithoutSeal,
    /// The seal does not match the content: edited or partially written.
    SealMismatch,
    /// A `seal` member that is malformed or not where `lock` puts it.
    MalformedSeal,
    /// A seal on an unlocked profile (someone flipped `locked` by hand).
    SealOnDraft,
    /// A locked profile that fails `Profile::validate`.
    Invalid {
        errors: Vec<ProfileError>,
    },
    /// The `metadata` member is not an object with exactly
    /// [`METADATA_KEYS`].
    BadMetadata {
        detail: String,
    },
    /// A `participant_identities` entry has unknown or missing keys
    /// ([`IDENTITY_KEYS`]); its values are checked by `Profile::validate`.
    BadIdentity {
        name: String,
        detail: String,
    },
    /// `metadata` on an unlocked profile (only `lock` writes it).
    MetadataOnDraft,
    /// The file is well formed but not trusted for enforcement: signature,
    /// trust anchors, platform/unit binding or anti-rollback (see
    /// [`crate::trust`]). Only the trust-checking loaders produce this.
    Untrusted {
        reason: crate::trust::ProfileTrustError,
    },
}

impl fmt::Display for ProfileFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json { message } => write!(f, "not a profile: {message}"),
            Self::NotAnObject => write!(f, "not a profile: top level is not a JSON object"),
            Self::MissingKey { key } => write!(
                f,
                "missing key {key:?} (partially written or hand-trimmed profile)"
            ),
            Self::UnknownKey { key } => write!(f, "unknown key {key:?} (typo or edited profile)"),
            Self::BadEnvelope { channel, detail } => {
                write!(f, "motion envelope {channel:?}: {detail}")
            }
            Self::LockedWithoutSeal => write!(
                f,
                "\"locked\": true but no seal: a locked profile must come from `lock` unmodified"
            ),
            Self::SealMismatch => write!(
                f,
                "seal does not match content: the locked profile was edited or is incomplete"
            ),
            Self::MalformedSeal => write!(f, "malformed or misplaced seal"),
            Self::SealOnDraft => write!(
                f,
                "sealed file has \"locked\": false (edited after locking)"
            ),
            Self::BadMetadata { detail } => write!(f, "metadata: {detail}"),
            Self::BadIdentity { name, detail } => {
                write!(f, "participant_identities {name:?}: {detail}")
            }
            Self::MetadataOnDraft => write!(
                f,
                "\"metadata\" on an unlocked profile: only `lock` writes it; remove it from \
                 the draft"
            ),
            Self::Untrusted { reason } => write!(f, "not trusted for enforcement: {reason}"),
            Self::Invalid { errors } => {
                write!(f, "locked profile fails validation:")?;
                for e in errors {
                    write!(f, "\n  - {e}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ProfileFileError {}

/// A JSON value walker that fails on a duplicate object key at any depth.
/// Keys arrive unescaped from serde_json, so escape spellings of one key
/// collide. Depth is bounded by serde_json's recursion limit.
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        while a.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        let mut seen = HashSet::new();
        while let Some(k) = a.next_key::<String>()? {
            if !seen.insert(k.clone()) {
                let shown: String = k.chars().take(128).collect();
                return Err(de::Error::custom(format!("duplicate key {shown:?}")));
            }
            a.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

/// Refuse JSON text with a duplicate object key at any depth.
pub fn reject_duplicate_keys(text: &str) -> Result<(), serde_json::Error> {
    serde_json::from_str::<NoDuplicateKeys>(text).map(|_| ())
}

/// Split a sealed text into `(seal hex, body)`; `None` if not sealed in the
/// canonical position.
fn split_seal(text: &str) -> Option<(&str, String)> {
    let rest = text.strip_prefix(SEAL_PREFIX)?;
    let hex = rest.get(..64)?;
    let after = rest.get(64..)?.strip_prefix(SEAL_SUFFIX)?;
    Some((hex, format!("{{\n{after}")))
}

/// Strictly parse a profile file's text. See the module docs.
pub fn parse_profile_text(text: &str) -> Result<Profile, ProfileFileError> {
    let json_err = |e: serde_json::Error| ProfileFileError::Json {
        message: e.to_string(),
    };
    // Duplicate keys first: the `Value` pass below and the typed maps
    // (`motion_envelopes`) would silently keep only the last one.
    reject_duplicate_keys(text).map_err(json_err)?;
    let value: serde_json::Value = serde_json::from_str(text).map_err(json_err)?;
    let obj = value.as_object().ok_or(ProfileFileError::NotAnObject)?;
    for k in obj.keys() {
        if !PROFILE_KEYS.contains(&k.as_str())
            && !OPTIONAL_PROFILE_KEYS.contains(&k.as_str())
            && k != SEAL_KEY
        {
            return Err(ProfileFileError::UnknownKey { key: k.clone() });
        }
    }
    for k in PROFILE_KEYS {
        if !obj.contains_key(k) {
            return Err(ProfileFileError::MissingKey { key: k.into() });
        }
    }
    if let Some(envs) = obj.get("motion_envelopes").and_then(|v| v.as_object()) {
        for (ch, env) in envs {
            let bad = |detail: String| ProfileFileError::BadEnvelope {
                channel: ch.clone(),
                detail,
            };
            let e = env.as_object().ok_or_else(|| bad("not an object".into()))?;
            for k in e.keys() {
                if !ENVELOPE_KEYS.contains(&k.as_str())
                    && !OPTIONAL_ENVELOPE_LIMIT_KEYS.contains(&k.as_str())
                    && k != ENVELOPE_HOLONOMIC_KEY
                {
                    return Err(bad(format!("unknown key {k:?}")));
                }
            }
            for k in OPTIONAL_ENVELOPE_LIMIT_KEYS {
                if let Some(v) = e.get(k) {
                    if !(v.is_null() || v.is_number()) {
                        return Err(bad(format!("{k} is not a number or null")));
                    }
                }
            }
            if let Some(v) = e.get(ENVELOPE_HOLONOMIC_KEY) {
                if !v.is_boolean() {
                    return Err(bad(format!("{ENVELOPE_HOLONOMIC_KEY} is not a boolean")));
                }
            }
            for k in ENVELOPE_KEYS {
                match e.get(k) {
                    None => return Err(bad(format!("missing key {k:?}"))),
                    Some(v) if !(v.is_null() || v.is_number()) => {
                        return Err(bad(format!("{k} is not a number or null")))
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(t) = obj.get("motion_types") {
        let t = t.as_object().ok_or_else(|| ProfileFileError::BadEnvelope {
            channel: String::new(),
            detail: "motion_types is not an object".into(),
        })?;
        for (channel, v) in t {
            if !v.is_string() {
                return Err(ProfileFileError::BadEnvelope {
                    channel: channel.clone(),
                    detail: "motion_types value is not a string".into(),
                });
            }
        }
    }
    if let Some(ids) = obj.get("participant_identities") {
        let ids = ids
            .as_object()
            .ok_or_else(|| ProfileFileError::BadIdentity {
                name: String::new(),
                detail: "participant_identities is not an object".into(),
            })?;
        for (name, id) in ids {
            let bad = |detail: String| ProfileFileError::BadIdentity {
                name: name.clone(),
                detail,
            };
            let o = id.as_object().ok_or_else(|| bad("not an object".into()))?;
            for k in o.keys() {
                if !IDENTITY_KEYS.contains(&k.as_str()) {
                    return Err(bad(format!("unknown key {k:?}")));
                }
            }
            for k in ["ips", "vendor"] {
                if !o.contains_key(k) {
                    return Err(bad(format!("missing key {k:?}")));
                }
            }
        }
    }
    if let Some(meta) = obj.get("metadata") {
        let bad = |detail: String| ProfileFileError::BadMetadata { detail };
        let m = meta
            .as_object()
            .ok_or_else(|| bad("not an object".into()))?;
        for k in m.keys() {
            if !METADATA_KEYS.contains(&k.as_str()) && !OPTIONAL_METADATA_KEYS.contains(&k.as_str())
            {
                return Err(bad(format!("unknown key {k:?}")));
            }
        }
        for k in METADATA_KEYS {
            if !m.contains_key(k) {
                return Err(bad(format!("missing key {k:?}")));
            }
        }
        if let Some(a) = m.get("attestation") {
            let a = a
                .as_object()
                .ok_or_else(|| bad("attestation is not an object".into()))?;
            for k in a.keys() {
                if k != "signoff" && k != "signatures" {
                    return Err(bad(format!("attestation: unknown key {k:?}")));
                }
            }
            for k in ["signoff", "signatures"] {
                if !a.get(k).is_some_and(serde_json::Value::is_string) {
                    return Err(bad(format!("attestation: {k:?} missing or not a string")));
                }
            }
        }
    }
    // Typed parse straight from the text (duplicates were refused above).
    let profile: Profile = serde_json::from_str(text).map_err(json_err)?;

    let sealed = obj.contains_key(SEAL_KEY);
    if sealed {
        let (hex, body) = split_seal(text).ok_or(ProfileFileError::MalformedSeal)?;
        if sha256_hex(body.as_bytes()) != hex {
            return Err(ProfileFileError::SealMismatch);
        }
        if !profile.locked {
            return Err(ProfileFileError::SealOnDraft);
        }
    } else if profile.locked {
        return Err(ProfileFileError::LockedWithoutSeal);
    }
    if !profile.locked && profile.metadata.is_some() {
        return Err(ProfileFileError::MetadataOnDraft);
    }
    if profile.locked {
        profile
            .validate()
            .map_err(|errors| ProfileFileError::Invalid { errors })?;
    }
    Ok(profile)
}

/// The file text for a locked profile: canonical JSON plus the seal.
pub fn sealed_text(profile: &Profile) -> Result<String, serde_json::Error> {
    let body = to_json(profile)?;
    let digest = sha256_hex(body.as_bytes());
    // serde_json's pretty output of a struct always starts with "{\n";
    // refuse rather than abort if that ever changes.
    let rest = body.strip_prefix("{\n").ok_or_else(|| {
        <serde_json::Error as serde::ser::Error>::custom(
            "canonical profile JSON does not start with \"{\\n\"",
        )
    })?;
    Ok(format!("{SEAL_PREFIX}{digest}{SEAL_SUFFIX}{rest}"))
}

/// Read a whole file that must be a regular file no larger than `max`
/// bytes (a FIFO or device such as `/dev/zero` is refused, not read).
pub fn read_regular_file(path: &Path, max: u64) -> io::Result<String> {
    let f = File::open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
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

/// Write `contents` to `path` atomically, never through a symlink, and
/// without clobbering an existing file unless `overwrite`. See the module
/// docs.
pub fn write_file_atomic(path: &Path, contents: &[u8], overwrite: bool) -> io::Result<()> {
    write_files_atomic(&[(path, contents)], overwrite)
}

fn split_path(path: &Path) -> io::Result<(&Path, &std::ffi::OsStr)> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a file path"))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    Ok((dir, name))
}

/// Create a fresh `.<name>.<tag>-<pid>-<n>` file next to `path`
/// (`O_CREAT|O_EXCL`: never follows a planted symlink).
fn fresh_sibling(path: &Path, tag: &str) -> io::Result<(std::path::PathBuf, File)> {
    let (dir, name) = split_path(path)?;
    for n in 0..1000u32 {
        let mut tn = std::ffi::OsString::from(".");
        tn.push(name);
        tn.push(format!(".{tag}-{}-{n}", std::process::id()));
        let candidate = dir.join(tn);
        let mut oo = OpenOptions::new();
        oo.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            oo.mode(0o644);
        }
        match oo.open(&candidate) {
            Ok(f) => return Ok((candidate, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a temp file",
    ))
}

/// A free sibling name for a hard-link backup (`hard_link` refuses to
/// replace, so a racing file at the name only makes us try the next one).
fn backup_link(path: &Path) -> io::Result<std::path::PathBuf> {
    let (dir, name) = split_path(path)?;
    for n in 0..1000u32 {
        let mut tn = std::ffi::OsString::from(".");
        tn.push(name);
        tn.push(format!(".bak-{}-{n}", std::process::id()));
        let candidate = dir.join(tn);
        match fs::hard_link(path, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a backup link",
    ))
}

/// Publish one written temp file at `path` (see the module docs).
fn publish(tmp_path: &Path, path: &Path, overwrite: bool) -> io::Result<()> {
    if overwrite {
        // Re-check right before publishing; rename replaces a symlink
        // itself (never writes through it), so a racing symlink cannot
        // redirect the write either way.
        check_destination(path, true)?;
        fs::rename(tmp_path, path)
    } else {
        match fs::hard_link(tmp_path, path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "already exists (refusing to overwrite)",
            )),
            // Filesystems without hard links: best effort, re-check and
            // rename (a narrow race remains; documented).
            Err(_) => {
                check_destination(path, false)?;
                fs::rename(tmp_path, path)
            }
        }
    }
}

/// Write several files as one unit: all destinations are checked, all
/// temps written and fsynced, then all are published; on any failure
/// nothing this call published remains (see the module docs). Errors name
/// the failing path.
pub fn write_files_atomic(files: &[(&Path, &[u8])], overwrite: bool) -> io::Result<()> {
    let named = |p: &Path, e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", p.display()));
    // 1. Every destination first: nothing is created if one is refused.
    for (i, (p, _)) in files.iter().enumerate() {
        split_path(p).map_err(|e| named(p, e))?;
        if files[..i].iter().any(|(q, _)| q == p) {
            return Err(named(
                p,
                io::Error::new(io::ErrorKind::InvalidInput, "named twice"),
            ));
        }
        check_destination(p, overwrite).map_err(|e| named(p, e))?;
    }
    // 2. All temps, written and fsynced.
    let mut temps: Vec<std::path::PathBuf> = Vec::new();
    let mut backups: Vec<Option<std::path::PathBuf>> = Vec::new();
    let cleanup = |temps: &[std::path::PathBuf], backups: &[Option<std::path::PathBuf>]| {
        for t in temps.iter().chain(backups.iter().flatten()) {
            let _ = fs::remove_file(t);
        }
    };
    for (p, contents) in files {
        let r = fresh_sibling(p, "tmp").and_then(|(tp, mut f)| {
            temps.push(tp);
            f.write_all(contents)?;
            f.sync_all()
        });
        if let Err(e) = r {
            cleanup(&temps, &backups);
            return Err(named(p, e));
        }
    }
    // 3. Overwrite mode: hard-link backups of existing destinations, so a
    //    failed publish can be undone.
    if overwrite {
        for (p, _) in files {
            let b = match fs::symlink_metadata(p) {
                Ok(m) if m.is_file() => match backup_link(p) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        cleanup(&temps, &backups);
                        return Err(named(p, e));
                    }
                },
                _ => None,
            };
            backups.push(b);
        }
    } else {
        backups.resize(files.len(), None);
    }
    // 4. Publish; roll back on the first failure.
    for (i, ((p, _), tp)) in files.iter().zip(&temps).enumerate() {
        if let Err(e) = publish(tp, p, overwrite) {
            for ((q, _), b) in files[..i].iter().zip(&backups) {
                match b {
                    Some(b) => {
                        let _ = fs::rename(b, q);
                    }
                    None => {
                        let _ = fs::remove_file(q);
                    }
                }
            }
            cleanup(&temps, &backups);
            return Err(named(p, e));
        }
    }
    cleanup(&temps, &backups);
    // Make the new directory entries durable too (best effort).
    let mut dirs: Vec<&Path> = files
        .iter()
        .filter_map(|(p, _)| split_path(p).ok().map(|(d, _)| d))
        .collect();
    dirs.dedup();
    for d in dirs {
        if let Ok(d) = File::open(d) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Would [`write_file_atomic`] accept `path` as a destination right now
/// (not a symlink; absent, or a regular file and `overwrite`)? For callers
/// that want to fail before doing expensive work; the write re-checks.
pub fn check_destination(path: &Path, overwrite: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "is a symbolic link (refusing to write through it)",
        )),
        Ok(_) if !overwrite => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "already exists (refusing to overwrite; pass --force to replace it)",
        )),
        Ok(m) if !m.is_file() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exists and is not a regular file",
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::profile::Envelope;

    fn prof(locked: bool) -> Profile {
        let mut p = Profile {
            model: "m".into(),
            locked,
            ..Default::default()
        };
        p.participants.insert("a".repeat(24));
        p.writer_topics.insert("/cmd_vel".into());
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(0.429),
                max_joint_speed: None,
                ..Default::default()
            },
        );
        p
    }

    #[test]
    fn draft_roundtrips_strictly() {
        let text = to_json(&prof(false)).unwrap();
        assert_eq!(parse_profile_text(&text).unwrap(), prof(false));
    }

    #[test]
    fn holonomic_envelope_keys_are_optional_but_typed() {
        // A legacy (non-holonomic) draft is written without the new keys.
        let text = to_json(&prof(false)).unwrap();
        assert!(!text.contains("holonomic") && !text.contains("max_lateral_speed"));
        // A holonomic envelope round-trips strictly.
        let mut p = prof(false);
        {
            let e = p.motion_envelopes.get_mut("/cmd_vel").unwrap();
            e.holonomic = true;
            e.max_lateral_speed = Some(0.3);
            e.max_vertical_speed = Some(0.0);
            e.max_roll_pitch_rate = Some(0.0);
        }
        let text = to_json(&p).unwrap();
        assert_eq!(parse_profile_text(&text).unwrap(), p);
        // Wrong types and typos in the new keys are refused.
        for (from, to) in [
            ("\"holonomic\": true", "\"holonomic\": 1"),
            ("\"holonomic\": true", "\"holonomik\": true"),
            (
                "\"max_lateral_speed\": 0.3",
                "\"max_lateral_speed\": \"0.3\"",
            ),
            ("\"max_lateral_speed\": 0.3", "\"max_lateral_sped\": 0.3"),
        ] {
            assert!(text.contains(from), "{text}");
            let bad = text.replace(from, to);
            assert!(
                matches!(
                    parse_profile_text(&bad).unwrap_err(),
                    ProfileFileError::BadEnvelope { .. }
                ),
                "{to}"
            );
        }
        // null for an optional limit is accepted (= None).
        let null = text.replace("\"max_lateral_speed\": 0.3", "\"max_lateral_speed\": null");
        let q = parse_profile_text(&null).unwrap();
        assert_eq!(q.motion_envelopes["/cmd_vel"].max_lateral_speed, None);
    }

    #[test]
    fn missing_unknown_and_duplicate_keys_are_refused() {
        let text = to_json(&prof(false)).unwrap();
        let cut = text.replace("  \"services\": [],\n", "");
        assert_eq!(
            parse_profile_text(&cut).unwrap_err(),
            ProfileFileError::MissingKey {
                key: "services".into()
            }
        );
        let typo = text.replace("\"locked\"", "\"locked \"");
        assert!(matches!(
            parse_profile_text(&typo).unwrap_err(),
            ProfileFileError::UnknownKey { .. }
        ));
        let dup = text.replace(
            "\"locked\": false,",
            "\"locked\": false,\n  \"locked\": false,",
        );
        assert!(matches!(
            parse_profile_text(&dup).unwrap_err(),
            ProfileFileError::Json { .. }
        ));
        let env = text.replace("\"max_joint_speed\": null", "\"max_joint_sped\": null");
        assert!(matches!(
            parse_profile_text(&env).unwrap_err(),
            ProfileFileError::BadEnvelope { .. }
        ));
        let env = text.replace("\"max_joint_speed\": null", "\"max_joint_speed\": \"1\"");
        assert!(parse_profile_text(&env).is_err());
        assert_eq!(
            parse_profile_text("[]").unwrap_err(),
            ProfileFileError::NotAnObject
        );
        // Every truncation of a valid file is refused.
        for n in 0..text.trim_end().len() {
            assert!(parse_profile_text(&text[..n]).is_err(), "prefix {n}");
        }
    }

    #[test]
    fn seal_rules() {
        let sealed = sealed_text(&prof(true)).unwrap();
        assert!(sealed.starts_with("{\n  \"seal\": \"sha256:"));
        assert_eq!(parse_profile_text(&sealed).unwrap(), prof(true));
        // The sensor's lenient loader still reads it.
        let lenient: Profile = serde_json::from_str(&sealed).unwrap();
        assert_eq!(lenient, prof(true));

        // Locked without a seal.
        let bare = to_json(&prof(true)).unwrap();
        assert_eq!(
            parse_profile_text(&bare).unwrap_err(),
            ProfileFileError::LockedWithoutSeal
        );
        // Edited after sealing: a new participant, a looser envelope.
        let edited = sealed.replace("0.429", "9.0");
        assert_eq!(
            parse_profile_text(&edited).unwrap_err(),
            ProfileFileError::SealMismatch
        );
        // Flipped to draft by hand.
        let flipped = sealed.replace("\"locked\": true", "\"locked\": false");
        assert_eq!(
            parse_profile_text(&flipped).unwrap_err(),
            ProfileFileError::SealMismatch
        );
        // Seal moved elsewhere.
        let moved = bare.replace("\"model\"", "\"seal\": \"x\",\n  \"model\"");
        assert_eq!(
            parse_profile_text(&moved).unwrap_err(),
            ProfileFileError::MalformedSeal
        );
        // A validly sealed draft (someone sealed a draft): refused.
        let draft_sealed = {
            let body = to_json(&prof(false)).unwrap();
            let d = sha256_hex(body.as_bytes());
            format!("{SEAL_PREFIX}{d}{SEAL_SUFFIX}{}", &body[2..])
        };
        assert_eq!(
            parse_profile_text(&draft_sealed).unwrap_err(),
            ProfileFileError::SealOnDraft
        );
        // A sealed but invalid locked profile.
        let mut bad = prof(true);
        bad.participants.insert("NOT-HEX".into());
        assert!(matches!(
            parse_profile_text(&sealed_text(&bad).unwrap()).unwrap_err(),
            ProfileFileError::Invalid { .. }
        ));
    }

    fn meta() -> robodr_events::profile::ProfileMetadata {
        robodr_events::profile::ProfileMetadata {
            schema_version: robodr_events::profile::PROFILE_SCHEMA_VERSION,
            profile_version: 2,
            platform: "ugv".into(),
            unit_id: None,
            locked_by: "op".into(),
            locked_at: 1_790_000_000,
            parent_digest: None,
            attestation: None,
        }
    }

    #[test]
    fn metadata_rules() {
        let mut p = prof(true);
        p.metadata = Some(meta());
        let sealed = sealed_text(&p).unwrap();
        assert_eq!(parse_profile_text(&sealed).unwrap(), p);
        // Legacy locked profile (no metadata) still parses here.
        assert!(parse_profile_text(&sealed_text(&prof(true)).unwrap()).is_ok());
        let reseal = |p: &Profile, edit: &dyn Fn(&str) -> String| {
            let body = edit(&to_json(p).unwrap());
            let d = sha256_hex(body.as_bytes());
            format!("{SEAL_PREFIX}{d}{SEAL_SUFFIX}{}", &body[2..])
        };
        for (edit, what) in [
            (
                &(|t: &str| t.replace("\"unit_id\": null,\n", "")) as &dyn Fn(&str) -> String,
                "missing key",
            ),
            (
                &|t: &str| t.replace("\"unit_id\": null", "\"unit_id\": null, \"x\": 1"),
                "unknown key",
            ),
        ] {
            let e = parse_profile_text(&reseal(&p, edit)).unwrap_err();
            assert!(
                matches!(&e, ProfileFileError::BadMetadata { detail } if detail.contains(what)),
                "{e:?}"
            );
        }
        // Not an object / null.
        let mut v: serde_json::Value = serde_json::from_str(&to_json(&p).unwrap()).unwrap();
        for bad in [
            serde_json::Value::Null,
            serde_json::json!(3),
            serde_json::json!([]),
        ] {
            v["metadata"] = bad;
            let body = to_json(&v).unwrap();
            assert!(matches!(
                parse_profile_text(&body).unwrap_err(),
                ProfileFileError::BadMetadata { .. }
            ));
        }
        // Wrong type inside: a JSON error.
        let e = parse_profile_text(&reseal(&p, &|t: &str| {
            t.replace("\"profile_version\": 2", "\"profile_version\": \"2\"")
        }))
        .unwrap_err();
        assert!(matches!(e, ProfileFileError::Json { .. }), "{e:?}");
        // Negative / overflowing version.
        for bad in ["-1", "18446744073709551616", "1.5"] {
            let e = parse_profile_text(&reseal(&p, &|t: &str| {
                t.replace(
                    "\"profile_version\": 2",
                    &format!("\"profile_version\": {bad}"),
                )
            }));
            assert!(e.is_err(), "{bad}");
        }
        // The optional attestation: round-trips; strict shape when present.
        let mut att = p.clone();
        att.metadata.as_mut().unwrap().attestation =
            Some(robodr_events::profile::ProfileAttestation {
                signoff: "so\n".into(),
                signatures: "sigs".into(),
            });
        let t = sealed_text(&att).unwrap();
        assert_eq!(parse_profile_text(&t).unwrap(), att);
        for (from, to, what) in [
            (
                "\"signatures\": \"sigs\"",
                "\"signatures\": 3",
                "not a string",
            ),
            (
                "\"signatures\": \"sigs\"",
                "\"signatures\": \"sigs\", \"x\": \"y\"",
                "unknown key",
            ),
            ("\"signatures\": \"sigs\"", "\"z\": \"sigs\"", "unknown key"),
        ] {
            let e = parse_profile_text(&reseal(&att, &|t: &str| t.replace(from, to))).unwrap_err();
            assert!(
                matches!(&e, ProfileFileError::BadMetadata { detail } if detail.contains(what)),
                "{e:?}"
            );
        }
        let e = parse_profile_text(&reseal(&att, &|t: &str| {
            let i = t.find("\"attestation\": {").unwrap();
            let j = i + t[i..].find('}').unwrap() + 1;
            format!("{}\"attestation\": []{}", &t[..i], &t[j..])
        }))
        .unwrap_err();
        assert!(matches!(e, ProfileFileError::BadMetadata { .. }), "{e:?}");
        // Invalid metadata on a locked profile: refused by validate.
        let mut bad = p.clone();
        bad.metadata.as_mut().unwrap().profile_version = 0;
        assert!(matches!(
            parse_profile_text(&sealed_text(&bad).unwrap()).unwrap_err(),
            ProfileFileError::Invalid { .. }
        ));
        // Metadata on a draft.
        let mut draft = prof(false);
        draft.metadata = Some(meta());
        assert_eq!(
            parse_profile_text(&to_json(&draft).unwrap()).unwrap_err(),
            ProfileFileError::MetadataOnDraft
        );
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("robodr-commission-pf-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_write_no_clobber_no_symlink() {
        let d = tmpdir("w");
        let p = d.join("out.json");
        write_file_atomic(&p, b"one", false).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"one");
        let e = write_file_atomic(&p, b"two", false).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&p).unwrap(), b"one");
        write_file_atomic(&p, b"two", true).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        // No temp files left behind.
        let names: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        #[cfg(unix)]
        {
            let target = d.join("victim");
            fs::write(&target, b"keep").unwrap();
            let link = d.join("link.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            for force in [false, true] {
                let e = write_file_atomic(&link, b"evil", force).unwrap_err();
                assert!(e.to_string().contains("symbolic link"), "{e}");
            }
            assert_eq!(fs::read(&target).unwrap(), b"keep");
            // A dangling symlink is refused too.
            let dangling = d.join("dangling.json");
            std::os::unix::fs::symlink(d.join("nowhere"), &dangling).unwrap();
            assert!(write_file_atomic(&dangling, b"x", false).is_err());
            assert!(!d.join("nowhere").exists());
        }
        // A directory is not overwritten.
        let sub = d.join("dir");
        fs::create_dir(&sub).unwrap();
        assert!(write_file_atomic(&sub, b"x", true).is_err());
        assert!(write_file_atomic(Path::new("/"), b"x", true).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn read_regular_file_refuses_devices_and_huge_files() {
        #[cfg(unix)]
        assert!(read_regular_file(Path::new("/dev/zero"), 10).is_err());
        let d = tmpdir("r");
        let p = d.join("big");
        fs::write(&p, vec![b'x'; 100]).unwrap();
        assert!(read_regular_file(&p, 99).is_err());
        assert_eq!(read_regular_file(&p, 100).unwrap().len(), 100);
        assert!(read_regular_file(&d, 100).is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
