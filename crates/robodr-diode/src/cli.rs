//! Helpers shared by the `robodr-diode-pack` / `robodr-diode-unpack` binaries:
//! a tiny `--flag value` parser and key/keyring loading. Not a stable API.

use crate::fsutil::{self, ReadError};
use crate::unpack::Keyring;
use robodr_blackbox::crypto::from_hex;
use robodr_blackbox::HmacSha256Key;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const MAX_KEY_FILE: u64 = 4096;
const MAX_KEYRING_FILE: u64 = 1024 * 1024;
/// Largest findings input file the pack CLI reads (1 GiB).
pub const MAX_INPUT_FILE: u64 = 1024 * 1024 * 1024;

/// Parsed `--flag value` arguments.
#[derive(Debug, Default)]
pub struct Args {
    pairs: Vec<(String, String)>,
}

/// Parse `--flag value` pairs; every flag must be in `known`.
/// `--help`/`-h` yields `Err("help")`.
pub fn parse_args(args: impl IntoIterator<Item = String>, known: &[&str]) -> Result<Args, String> {
    let mut it = args.into_iter();
    let mut out = Args::default();
    while let Some(a) = it.next() {
        if a == "--help" || a == "-h" {
            return Err("help".into());
        }
        let Some(flag) = a.strip_prefix("--") else {
            return Err(format!("unexpected argument {a:?}"));
        };
        if !known.contains(&flag) {
            return Err(format!("unknown flag --{flag}"));
        }
        let v = it.next().ok_or_else(|| format!("--{flag} needs a value"))?;
        out.pairs.push((flag.to_string(), v));
    }
    Ok(out)
}

impl Args {
    /// The single value of `flag` (error if given twice).
    pub fn one(&self, flag: &str) -> Result<Option<&str>, String> {
        let v = self.all(flag);
        match v.len() {
            0 => Ok(None),
            1 => Ok(Some(v[0])),
            _ => Err(format!("--{flag} given more than once")),
        }
    }

    pub fn req(&self, flag: &str) -> Result<&str, String> {
        self.one(flag)?
            .ok_or_else(|| format!("--{flag} is required"))
    }

    pub fn all(&self, flag: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(k, _)| k == flag)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn num<T: FromStr>(&self, flag: &str) -> Result<Option<T>, String> {
        self.one(flag)?
            .map(|v| {
                v.parse()
                    .map_err(|_| format!("--{flag}: not a number: {v:?}"))
            })
            .transpose()
    }
}

/// Load an HMAC key (hex, >= 32 bytes, whitespace ignored) from `path`.
pub fn load_hmac_key(key_id: &str, path: &Path) -> Result<HmacSha256Key, String> {
    let bytes = fsutil::read_capped(path, MAX_KEY_FILE)
        .map_err(|e| format!("key file {}: {}", path.display(), read_err(e)))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "key file is not UTF-8".to_string())?;
    let hex: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let mut key = from_hex(&hex).ok_or_else(|| "key file is not hex".to_string())?;
    let k = HmacSha256Key::new(key_id, &key).map_err(|e| e.to_string());
    key.iter_mut().for_each(|b| *b = 0);
    k
}

/// A warning if `path` is readable by group or others.
pub fn key_file_mode_warning(path: &Path) -> Option<String> {
    let m = std::fs::metadata(path).ok()?;
    (m.permissions().mode() & 0o077 != 0).then(|| {
        format!(
            "warning: key file {} is accessible by group/others (mode {:o})",
            path.display(),
            m.permissions().mode() & 0o777
        )
    })
}

/// Keyring file: one `<unit_id> <key_id> <key-file>` per line; `#` comments.
/// Relative key-file paths are resolved against the keyring's directory.
pub fn load_keyring(path: &Path) -> Result<(Keyring, Vec<String>), String> {
    let bytes = fsutil::read_capped(path, MAX_KEYRING_FILE)
        .map_err(|e| format!("keyring {}: {}", path.display(), read_err(e)))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "keyring is not UTF-8".to_string())?;
    let base = path.parent().unwrap_or(Path::new("."));
    let mut ring = Keyring::new();
    let mut warnings = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 3 {
            return Err(format!(
                "keyring line {}: expected `<unit_id> <key_id> <key-file>`",
                i + 1
            ));
        }
        let kp = resolve(base, f[2]);
        if let Some(w) = key_file_mode_warning(&kp) {
            warnings.push(w);
        }
        let key = load_hmac_key(f[1], &kp).map_err(|e| format!("keyring line {}: {e}", i + 1))?;
        ring.add(f[0], Box::new(key))
            .map_err(|e| format!("keyring line {}: {e}", i + 1))?;
    }
    Ok((ring, warnings))
}

fn resolve(base: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// `unit:seq`.
pub fn parse_unit_seq(s: &str) -> Result<(String, u64), String> {
    let (u, q) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("expected <unit>:<seq>, got {s:?}"))?;
    let seq = q.parse().map_err(|_| format!("bad seq in {s:?}"))?;
    if !robodr_ocsf::validate::is_valid_robot_id(u) || seq == 0 {
        return Err(format!("bad <unit>:<seq> {s:?}"));
    }
    Ok((u.to_string(), seq))
}

/// Read a capped regular file.
pub fn read_file(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    fsutil::read_capped(path, max).map_err(|e| format!("{}: {}", path.display(), read_err(e)))
}

/// Wall-clock milliseconds since the epoch (0 if the clock is before 1970).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn read_err(e: ReadError) -> String {
    match e {
        ReadError::Missing => "not found".into(),
        ReadError::NotRegular => "not a regular file (symlink?)".into(),
        ReadError::TooLarge(n) => format!("too large ({n} bytes)"),
        ReadError::Io(e) => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn args() {
        let a = parse_args(s(&["--a", "1", "--b", "x", "--b", "y"]), &["a", "b"]).unwrap();
        assert_eq!(a.num::<u64>("a").unwrap(), Some(1));
        assert_eq!(a.all("b"), vec!["x", "y"]);
        assert!(a.one("b").is_err());
        assert!(a.req("c").is_err());
        assert!(parse_args(s(&["--z", "1"]), &["a"]).is_err());
        assert!(parse_args(s(&["--a"]), &["a"]).is_err());
        assert!(parse_args(s(&["pos"]), &["a"]).is_err());
        assert_eq!(parse_args(s(&["-h"]), &["a"]).unwrap_err(), "help");
    }

    #[test]
    fn unit_seq() {
        assert_eq!(parse_unit_seq("ugv-1:7").unwrap(), ("ugv-1".into(), 7));
        assert!(parse_unit_seq("ugv-1:0").is_err());
        assert!(parse_unit_seq("a/b:1").is_err());
        assert!(parse_unit_seq("x").is_err());
    }
}
