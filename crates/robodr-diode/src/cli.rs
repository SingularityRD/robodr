//! Helpers shared by the `robodr-diode-pack` / `robodr-diode-unpack` binaries:
//! a tiny `--flag value` parser and key/keyring loading. Not a stable API.
//!
//! # Keys
//!
//! All keys are `robodr-blackbox` key files ([`robodr_blackbox::KeyFile`],
//! made with `robodr-blackbox keygen`), loaded with its checks: symlinks and
//! non-regular files are refused, and a file holding **secret** material is
//! refused (not merely warned about) when group or others can access it or
//! when it is owned by another user (root excepted).
//!
//! * The packer signs with an **Ed25519 secret** key file.
//! * The importer verifies with **Ed25519 public** key files only: an
//!   Ed25519 secret key file in the importer keyring is refused, so the SOC
//!   never holds a key that can sign batches.
//! * Legacy symmetric HMAC-SHA256 key files are accepted on either side only
//!   with an explicit `--allow-hmac`, and each use prints a warning: with
//!   HMAC the importer's key can forge batches.

use crate::fsutil::{self, ReadError};
use crate::unpack::Keyring;
use robodr_blackbox::{KeyFile, Signer, Verifier};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const MAX_KEYRING_FILE: u64 = 1024 * 1024;
/// Largest findings input file the pack CLI reads (1 GiB).
pub const MAX_INPUT_FILE: u64 = 1024 * 1024 * 1024;

/// Parsed `--flag value` arguments.
#[derive(Debug, Default)]
pub struct Args {
    pairs: Vec<(String, String)>,
    switches: Vec<String>,
}

/// Parse `--flag value` pairs; every flag must be in `known`.
/// `--help`/`-h` yields `Err("help")`.
/// The process arguments (without the program name) as UTF-8 strings. An
/// argument that is not valid UTF-8 is an error (a usage error for the
/// binaries), never a panic as with `std::env::args()`.
pub fn argv() -> Result<Vec<String>, String> {
    std::env::args_os()
        .skip(1)
        .map(|a| {
            a.into_string()
                .map_err(|a| format!("argument {a:?} is not valid UTF-8"))
        })
        .collect()
}

pub fn parse_args(args: impl IntoIterator<Item = String>, known: &[&str]) -> Result<Args, String> {
    parse_args_with_switches(args, known, &[])
}

/// [`parse_args`] plus value-less `--switch`es (each at most once).
pub fn parse_args_with_switches(
    args: impl IntoIterator<Item = String>,
    known: &[&str],
    switches: &[&str],
) -> Result<Args, String> {
    let mut it = args.into_iter();
    let mut out = Args::default();
    while let Some(a) = it.next() {
        if a == "--help" || a == "-h" {
            return Err("help".into());
        }
        let Some(flag) = a.strip_prefix("--") else {
            return Err(format!("unexpected argument {a:?}"));
        };
        if switches.contains(&flag) {
            if out.switches.iter().any(|s| s == flag) {
                return Err(format!("--{flag} given more than once"));
            }
            out.switches.push(flag.to_string());
            continue;
        }
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

    /// `true` if the value-less `--flag` was given.
    pub fn flag(&self, flag: &str) -> bool {
        self.switches.iter().any(|s| s == flag)
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

/// Warning printed whenever an HMAC key is used.
pub const HMAC_WARNING: &str = "warning: hmac-sha256 key in use (allowed by --allow-hmac): it is \
symmetric, so whoever can verify these batches can also forge them. Migrate to ed25519 \
(`robodr-blackbox keygen`).";

fn hmac_gate(kf: &KeyFile, path: &Path, allow_hmac: bool) -> Result<Option<String>, String> {
    if !kf.is_symmetric() {
        return Ok(None);
    }
    if !allow_hmac {
        return Err(format!(
            "key file {}: hmac-sha256 key refused (symmetric: the verifying side could forge); \
             use an ed25519 key, or pass --allow-hmac to accept it knowingly",
            path.display()
        ));
    }
    Ok(Some(format!("{HMAC_WARNING} [{}]", path.display())))
}

/// Load the packer's signing key: a secret key file (Ed25519; HMAC only
/// with `allow_hmac`). `expected_key_id`, if given, must equal the file's.
/// Returns the signer and any warning to print.
pub fn load_signer(
    path: &Path,
    expected_key_id: Option<&str>,
    allow_hmac: bool,
) -> Result<(Box<dyn Signer>, Option<String>), String> {
    let kf = KeyFile::load_secret(path).map_err(|e| format!("key file {}: {e}", path.display()))?;
    if let Some(id) = expected_key_id {
        if id != kf.key_id {
            return Err(format!(
                "key file {}: --key-id {id:?} contradicts the file's key id {:?}",
                path.display(),
                kf.key_id
            ));
        }
    }
    let warning = hmac_gate(&kf, path, allow_hmac)?;
    let signer = kf
        .signer()
        .map_err(|e| format!("key file {}: {e}", path.display()))?;
    Ok((signer, warning))
}

/// Load a verifying key for the importer: an Ed25519 **public** key file
/// (any mode), or a legacy HMAC key file with `allow_hmac`. An Ed25519
/// secret key file is refused: the high side must not hold signing keys.
pub fn load_verifier(
    path: &Path,
    allow_hmac: bool,
) -> Result<(Box<dyn Verifier>, Option<String>), String> {
    let kf = KeyFile::load(path).map_err(|e| format!("key file {}: {e}", path.display()))?;
    let warning = hmac_gate(&kf, path, allow_hmac)?;
    if !kf.is_symmetric() && !kf.is_public() {
        return Err(format!(
            "key file {}: contains the secret signing key {:?}; the importer needs only the \
             public key (`robodr-blackbox export-pub`) and refuses to hold the secret",
            path.display(),
            kf.key_id
        ));
    }
    let v = kf
        .verifier()
        .map_err(|e| format!("key file {}: {e}", path.display()))?;
    Ok((v, warning))
}

/// Keyring file: one `<unit_id> <key-file>` (or the older
/// `<unit_id> <key_id> <key-file>`, where the key id must equal the
/// file's) per line; `#` comments. Relative key-file paths are resolved
/// against the keyring's directory. Each key file is loaded with
/// [`load_verifier`]. Returns the keyring and warnings to print.
pub fn load_keyring(path: &Path, allow_hmac: bool) -> Result<(Keyring, Vec<String>), String> {
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
        let (unit, key_id, file) = match f.as_slice() {
            [u, file] => (*u, None, *file),
            [u, id, file] => (*u, Some(*id), *file),
            _ => {
                return Err(format!(
                    "keyring line {}: expected `<unit_id> <key-file>`",
                    i + 1
                ))
            }
        };
        let kp = resolve(base, file);
        let (v, w) =
            load_verifier(&kp, allow_hmac).map_err(|e| format!("keyring line {}: {e}", i + 1))?;
        if let Some(id) = key_id {
            if id != v.key_id() {
                return Err(format!(
                    "keyring line {}: key id {id:?} contradicts the file's key id {:?}",
                    i + 1,
                    v.key_id()
                ));
            }
        }
        warnings.extend(w);
        ring.add(unit, v)
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
        // Switches take no value and appear at most once.
        let a = parse_args_with_switches(s(&["--x", "--a", "1"]), &["a"], &["x"]).unwrap();
        assert!(a.flag("x") && !a.flag("a"));
        assert_eq!(a.one("a").unwrap(), Some("1"));
        assert!(parse_args_with_switches(s(&["--x", "--x"]), &["a"], &["x"]).is_err());
        assert!(!parse_args(s(&["--a", "1"]), &["a"]).unwrap().flag("x"));
        assert!(parse_args(s(&["--x"]), &["a"]).is_err());
    }

    #[test]
    fn unit_seq() {
        assert_eq!(parse_unit_seq("ugv-1:7").unwrap(), ("ugv-1".into(), 7));
        assert!(parse_unit_seq("ugv-1:0").is_err());
        assert!(parse_unit_seq("a/b:1").is_err());
        assert!(parse_unit_seq("x").is_err());
    }
}
