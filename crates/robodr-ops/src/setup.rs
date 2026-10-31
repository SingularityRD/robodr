//! First-boot setup (`robodr-setup`, sales-readiness T68): roles, key
//! generation, the role's `agentd.json`, key fingerprints.
//!
//! Nothing here overwrites a file: an existing key or configuration is
//! kept (and reported), so re-running the setup is safe and can never
//! replace a key the SOC already trusts. Secret keys are written 0600 by
//! `robodr_blackbox::KeyFile::write_new` (exclusive create, no symlink
//! following, fsync), exactly as `robodr-blackbox keygen` writes them; the
//! secret is never printed.

use crate::rooted;
use robodr_blackbox::keys::{public_key_path, KeyFile};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Where a RoboDR unit sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// On-robot agent on a ROS 2 companion computer.
    Robot,
    /// Unitree EDU development computer (on-robot agent).
    UnitreeEdu,
    /// Passive sensor box on a tap / mirror port of a Unitree robot.
    UnitreeSensorBox,
    /// SOC-side relay of an air-gapped site (`robodr-diode-unpack` +
    /// `robodr-uplink` under a `relay` key): no agent, no configuration.
    SocRelay,
}

impl Role {
    pub const ALL: [Role; 4] = [
        Role::Robot,
        Role::UnitreeEdu,
        Role::UnitreeSensorBox,
        Role::SocRelay,
    ];

    pub fn parse(s: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|r| r.name() == s)
            .ok_or_else(|| {
                format!(
                    "--role {s:?}: expected one of {}",
                    Self::ALL.map(Role::name).join(", ")
                )
            })
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::Robot => "robot",
            Role::UnitreeEdu => "unitree-edu",
            Role::UnitreeSensorBox => "unitree-sensor-box",
            Role::SocRelay => "soc-relay",
        }
    }

    /// The shipped `robodr-agentd` example the role starts from.
    pub fn agentd_example(self) -> Option<&'static str> {
        match self {
            Role::Robot => Some("agentd.example.json"),
            Role::UnitreeEdu => Some("agentd.unitree-edu.example.json"),
            Role::UnitreeSensorBox => Some("agentd.unitree-sensor-box.example.json"),
            Role::SocRelay => None,
        }
    }
}

/// A key the setup can generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    /// The black box's signing key (`robodr-agentd.service`
    /// `LoadCredential=blackbox.key`), bound to the unit.
    Blackbox,
    /// Finding signatures (`20-finding-key.conf.example`).
    Finding,
    /// `robodr-uplink`'s batch signing key (connected site; on a SOC relay,
    /// the `relay` key).
    Uplink,
    /// `robodr-spool-export`'s diode batch signing key (air-gapped site).
    Diode,
}

impl KeyKind {
    pub const ALL: [KeyKind; 4] = [
        KeyKind::Blackbox,
        KeyKind::Finding,
        KeyKind::Uplink,
        KeyKind::Diode,
    ];

    pub fn parse(s: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or_else(|| {
                format!(
                    "key {s:?}: expected one of {}",
                    Self::ALL.map(KeyKind::name).join(", ")
                )
            })
    }

    pub fn name(self) -> &'static str {
        match self {
            KeyKind::Blackbox => "blackbox",
            KeyKind::Finding => "finding",
            KeyKind::Uplink => "uplink",
            KeyKind::Diode => "diode",
        }
    }

    /// File name in `/etc/robodr/keys` (what the units' `LoadCredential=`
    /// lines name).
    pub fn file(self) -> &'static str {
        match self {
            KeyKind::Blackbox => "agentd-blackbox.key",
            KeyKind::Finding => "agentd-finding.key",
            KeyKind::Uplink => "uplink.key",
            KeyKind::Diode => "diode.key",
        }
    }

    /// Bound to the unit (`device_id`): verifiers accept it only for that
    /// unit's chains. Only the black-box key: agentd requires its key's
    /// binding to equal `robot.id`, and a relay key serves many units.
    fn bound(self) -> bool {
        self == KeyKind::Blackbox
    }
}

/// The keys a role needs by default (more with `--key`).
pub fn default_keys(role: Role) -> Vec<KeyKind> {
    match role {
        Role::SocRelay => vec![KeyKind::Uplink],
        _ => vec![KeyKind::Blackbox],
    }
}

/// A unit id: 1-64 of `[A-Za-z0-9._-]`, starting with a letter or digit
/// (it ends up in key ids, file names, finding fields and SOC records).
pub fn check_unit_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "unit id {id:?}: 1-64 characters of A-Z a-z 0-9 . _ -, starting with a letter or digit"
        ))
    }
}

/// What happened to one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyOutcome {
    pub kind: KeyKind,
    pub path: String,
    /// `created` or `kept` (it already existed; never overwritten).
    pub action: &'static str,
    pub key_id: String,
}

/// Generate the `kinds` keys in `keys_dir` (absolute, under `root`).
/// Existing keys are kept and reported.
pub fn generate_keys(
    root: &Path,
    keys_dir: &str,
    kinds: &[KeyKind],
    unit_id: &str,
) -> Result<Vec<KeyOutcome>, String> {
    check_unit_id(unit_id)?;
    let dir = rooted(root, keys_dir);
    let md = std::fs::symlink_metadata(&dir).map_err(|e| {
        format!(
            "{keys_dir}: {e} (install the package first; systemd-tmpfiles creates it 0700 root)"
        )
    })?;
    if !md.is_dir() || md.mode() & 0o077 != 0 {
        return Err(format!(
            "{keys_dir}: must be a directory without group/other access (mode {:04o}); \
             refusing to write secret keys into it",
            md.mode() & 0o7777
        ));
    }
    let mut out = Vec::new();
    for &kind in kinds {
        let path = dir.join(kind.file());
        let shown = format!("{}/{}", keys_dir.trim_end_matches('/'), kind.file());
        if std::fs::symlink_metadata(&path).is_ok() {
            let k = KeyFile::load(&path).map_err(|e| format!("{shown}: exists but {e}"))?;
            out.push(KeyOutcome {
                kind,
                path: shown,
                action: "kept",
                key_id: k.key_id.clone(),
            });
            continue;
        }
        let pub_path = public_key_path(&path);
        if std::fs::symlink_metadata(&pub_path).is_ok() {
            return Err(format!(
                "{}: a public key exists without its secret {shown}; move it away first",
                pub_path.display()
            ));
        }
        let device = kind.bound().then_some(unit_id);
        let key = KeyFile::generate("ed25519", None)
            .and_then(|k| k.with_device_id(device))
            .map_err(|e| e.to_string())?;
        key.write_new(&path).map_err(|e| format!("{shown}: {e}"))?;
        if let Err(e) = key.to_public().and_then(|p| p.write_new(&pub_path)) {
            // Never leave a secret without its public half.
            let _ = std::fs::remove_file(&path);
            return Err(format!("{}: {e}", pub_path.display()));
        }
        out.push(KeyOutcome {
            kind,
            path: shown,
            action: "created",
            key_id: key.key_id.clone(),
        });
    }
    Ok(out)
}

/// The fingerprint of a public key file, for registration with the SOC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fingerprint {
    pub file: String,
    pub key_id: String,
    pub algorithm: String,
    pub device_id: Option<String>,
    /// `sha256:<hex>` of the 32 raw public key bytes: the same value as
    /// `robodr-commission`'s key fingerprint (revocation lists).
    pub key_sha256: String,
    /// SHA-256 of the `.pub` file as written (compare after copying it).
    pub file_sha256: String,
}

/// Fingerprints of every `*.pub` in `keys_dir` (sorted by name). Secret
/// key files are never opened.
pub fn fingerprints(root: &Path, keys_dir: &str) -> Result<Vec<Fingerprint>, String> {
    let dir = rooted(root, keys_dir);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{keys_dir}: {e}"))?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".pub"))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for n in names {
        let p = dir.join(&n);
        let shown = format!("{}/{n}", keys_dir.trim_end_matches('/'));
        let bytes = std::fs::read(&p).map_err(|e| format!("{shown}: {e}"))?;
        let k = KeyFile::load_public(&p).map_err(|e| format!("{shown}: {e}"))?;
        let raw = k
            .public_key()
            .ok_or_else(|| format!("{shown}: no Ed25519 public key"))?;
        out.push(Fingerprint {
            file: shown,
            key_id: k.key_id.clone(),
            algorithm: k.algorithm.clone(),
            device_id: k.device_id.clone(),
            key_sha256: format!("sha256:{}", crate::hex(&Sha256::digest(raw))),
            file_sha256: crate::sha256_hex(&bytes),
        });
    }
    Ok(out)
}

/// Settings of the role configuration.
#[derive(Debug, Clone)]
pub struct ConfigRequest {
    pub role: Role,
    pub unit_id: String,
    pub site: Option<String>,
    /// Capture interfaces (replace the example's).
    pub interfaces: Vec<String>,
}

/// The role's `robodr-agentd` configuration from the shipped example text:
/// the unit id in `robot.id` and `sensor.profile_trust.expect_unit_id`, the
/// site and capture interfaces when given. Validated by robodr-agentd's own
/// parser. Returns the configuration and the JSON pointers of values the
/// operator still has to review (the examples mark them `EXAMPLE` /
/// `replace`).
pub fn render_config(example: &str, req: &ConfigRequest) -> Result<(Value, Vec<String>), String> {
    check_unit_id(&req.unit_id)?;
    for i in &req.interfaces {
        let ok = !i.is_empty()
            && i.len() <= 15
            && i.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
        if !ok {
            return Err(format!("--interface {i:?}: not a network interface name"));
        }
    }
    let mut v: Value =
        serde_json::from_str(example).map_err(|e| format!("example configuration: {e}"))?;
    let robot = v
        .get_mut("robot")
        .and_then(Value::as_object_mut)
        .ok_or("example configuration has no robot object")?;
    robot.insert("id".into(), Value::String(req.unit_id.clone()));
    if let Some(site) = &req.site {
        check_unit_id(site).map_err(|e| e.replace("unit id", "site"))?;
        robot.insert("site".into(), Value::String(site.clone()));
    }
    if let Some(pt) = v
        .pointer_mut("/sensor/profile_trust")
        .and_then(Value::as_object_mut)
    {
        pt.insert("expect_unit_id".into(), Value::String(req.unit_id.clone()));
    }
    if !req.interfaces.is_empty() {
        let cap = v
            .pointer_mut("/sensor/capture")
            .and_then(Value::as_object_mut)
            .ok_or("this role's example has no sensor.capture section")?;
        cap.insert(
            "interfaces".into(),
            Value::Array(req.interfaces.iter().cloned().map(Value::String).collect()),
        );
    }
    let text = serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?;
    robodr_agentd::config::parse(&text)
        .map_err(|e| format!("rendered configuration refused by robodr-agentd: {e}"))?;
    let mut review = Vec::new();
    placeholders(&v, String::new(), &mut review);
    Ok((v, review))
}

/// JSON pointers of string values that still read like an example.
fn placeholders(v: &Value, at: String, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            let l = s.to_ascii_lowercase();
            if l.contains("example") || l.contains("replace") {
                out.push(at);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                placeholders(x, format!("{at}/{i}"), out);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                placeholders(
                    x,
                    format!("{at}/{}", k.replace('~', "~0").replace('/', "~1")),
                    out,
                );
            }
        }
        _ => {}
    }
}

/// The gid of `group` in `<root>/etc/group`.
pub fn group_gid(root: &Path, group: &str) -> Option<u32> {
    std::fs::read_to_string(rooted(root, "/etc/group"))
        .ok()?
        .lines()
        .find_map(|l| {
            let mut f = l.split(':');
            (f.next()? == group)
                .then(|| f.nth(1)?.parse().ok())
                .flatten()
        })
}

/// Write `text` to `path` (under `root`) as a new file, mode 0640, group
/// `robodr` when running as root (robodr-agentd reads it through that
/// group). An existing file is never replaced: `Ok(false)`.
pub fn write_config(root: &Path, path: &str, text: &str) -> Result<bool, String> {
    let p: PathBuf = rooted(root, path);
    if std::fs::symlink_metadata(&p).is_ok() {
        return Ok(false);
    }
    // Resolved before anything is created: no half-configured file.
    let gid = if robodr_blackbox::keys::effective_uid() == 0 {
        Some(
            group_gid(root, "robodr")
                .ok_or("group robodr not found (systemd-sysusers creates it with the package)")?,
        )
    } else {
        None
    };
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(&p)
        .map_err(|e| format!("{path}: {e}"))?;
    let res = f
        .write_all(text.as_bytes())
        .and_then(|()| f.write_all(b"\n"))
        .and_then(|()| f.sync_all());
    if let Err(e) = res {
        drop(f);
        let _ = std::fs::remove_file(&p);
        return Err(format!("{path}: {e}"));
    }
    if let Some(gid) = gid {
        if let Err(e) = std::os::unix::fs::chown(&p, Some(0), Some(gid)) {
            let _ = std::fs::remove_file(&p);
            return Err(format!("{path}: {e}"));
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_ids() {
        for ok in ["ugv-007", "G1.edu_01", "a"] {
            assert!(check_unit_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-x", "a b", "a/b", "ä", &"x".repeat(65), "a\nb", "../x"] {
            assert!(check_unit_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn roles_and_keys_parse() {
        for r in Role::ALL {
            assert_eq!(Role::parse(r.name()).unwrap(), r);
        }
        for k in KeyKind::ALL {
            assert_eq!(KeyKind::parse(k.name()).unwrap(), k);
        }
        assert!(Role::parse("drone").is_err());
    }
}
