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
//! envelopes), rejects duplicate keys, and runs `Profile::validate` on every
//! locked profile.
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
//! recomputes it. Authenticity needs a signing key (follow-up).
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

use crate::signoff::sha256_hex;
use crate::to_json;
use robodr_events::profile::{Profile, ProfileError};
use serde::Serialize;
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
/// Keys of one envelope object; both must be present.
pub const ENVELOPE_KEYS: [&str; 2] = ["max_linear_speed", "max_joint_speed"];
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
    let value: serde_json::Value = serde_json::from_str(text).map_err(json_err)?;
    let obj = value.as_object().ok_or(ProfileFileError::NotAnObject)?;
    for k in obj.keys() {
        if !PROFILE_KEYS.contains(&k.as_str()) && k != SEAL_KEY {
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
                if !ENVELOPE_KEYS.contains(&k.as_str()) {
                    return Err(bad(format!("unknown key {k:?}")));
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
    // Typed parse straight from the text: serde's derive rejects duplicate
    // fields, which the `Value` pass above silently collapses.
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
    let rest = body
        .strip_prefix("{\n")
        .expect("serde_json pretty output of a struct starts with \"{\\n\"");
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
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a file path"))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    check_destination(path, overwrite)?;

    // Fresh temp file next to the destination (same filesystem).
    let mut tmp = None;
    for n in 0..1000u32 {
        let mut tn = std::ffi::OsString::from(".");
        tn.push(name);
        tn.push(format!(".tmp-{}-{n}", std::process::id()));
        let candidate = dir.join(tn);
        let mut oo = OpenOptions::new();
        oo.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            oo.mode(0o644);
        }
        match oo.open(&candidate) {
            Ok(f) => {
                tmp = Some((candidate, f));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let (tmp_path, mut f) = tmp.ok_or_else(|| {
        io::Error::new(io::ErrorKind::AlreadyExists, "could not create a temp file")
    })?;
    let result = (|| {
        f.write_all(contents)?;
        f.sync_all()?;
        drop(f);
        if overwrite {
            // Re-check right before publishing; rename replaces a symlink
            // itself (never writes through it), so a racing symlink cannot
            // redirect the write either way.
            check_destination(path, true)?;
            fs::rename(&tmp_path, path)
        } else {
            match fs::hard_link(&tmp_path, path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "already exists (refusing to overwrite)",
                )),
                // Filesystems without hard links: best effort, re-check and
                // rename (a narrow race remains; documented).
                Err(_) => {
                    check_destination(path, false)?;
                    fs::rename(&tmp_path, path)
                }
            }
        }
    })();
    let _ = fs::remove_file(&tmp_path);
    result?;
    // Make the new directory entry durable too (best effort).
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn check_destination(path: &Path, overwrite: bool) -> io::Result<()> {
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
