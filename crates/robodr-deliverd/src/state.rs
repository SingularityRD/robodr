//! The agent's durable state (`robodr-deliverd-state/1`): installed
//! versions, rollback targets kept in the store, anti-rollback floors, the
//! accepted deployment and bundle chain heads, the monotonic time floor and
//! the write-ahead intent of the switch in progress.
//!
//! # Crash safety
//!
//! The file is replaced atomically (temporary sibling, `fsync`, `rename`,
//! `fsync` of the directory), so a crash leaves either the old or the new
//! state, never a mix. Every switch is preceded by an intent ([`Txn`]) and
//! the floor raise, written **before** anything on the robot changes; after
//! a crash the engine reads what is actually active and finishes or undoes
//! the switch (`engine`, recovery).
//!
//! # Monotonic floors
//!
//! [`StateFile::save`] refuses to write a state whose floor for any
//! package is lower than in the state it last wrote or read, so no code
//! path can lower a floor. Root can still delete or replace the file (the
//! same honest limit as `robodr-commission`'s state); the engine then
//! takes the floors recorded in the black box as the baseline and reports
//! it (`engine`, `robodr.deliver.state_restored`).

use crate::fault;
use crate::fsx;
use robodr_pkg::bundle::ChainState;
use robodr_pkg::common::{is_hex64, is_label, is_pkg_name};
use robodr_pkg::deployment::MaintenanceWindow;
use robodr_pkg::rpk::Kind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `format` of the state file.
pub const STATE_FORMAT: &str = "robodr-deliverd-state/1";
/// Largest state file read.
pub const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
/// Most packages tracked.
pub const MAX_PACKAGES: usize = 1024;
/// Most versions kept per package.
pub const MAX_KEPT: usize = 8;
/// Most media entries remembered as handled.
pub const MAX_SEEN_MEDIA: usize = 64;
/// Most bundle chains tracked.
pub const MAX_CHAINS: usize = 64;

/// A `dpkg` package and version (kind `deb`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebInfo {
    pub package: String,
    pub version: String,
}

/// One version of a package that is (or was) installed and is in the
/// store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ver {
    pub serial: u64,
    /// RPK digest (`robodr-pkg/digest/v1`).
    pub digest: String,
    pub kind: Kind,
    pub deb: Option<DebInfo>,
    /// Probe users resolved at staging: name -> `[uid, gid]`. A name that
    /// resolves differently at probe time fails the probe.
    pub probe_users: BTreeMap<String, [u32; 2]>,
}

/// The installed version of a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    pub ver: Ver,
    /// `false`: it failed its health gate and no rollback target at or
    /// above the floor existed (`robot.deliver.rollback_blocked_floor`).
    pub healthy: bool,
}

/// What became of a deployment item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Pending,
    Installed,
    /// Health gate failed (rolled back, or blocked by the floor).
    Failed,
    /// Refused before anything changed (reason in the black box).
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub name: String,
    pub serial: u64,
    pub digest: String,
    pub status: ItemStatus,
    /// Deferrals so far (safety state, window, confirmation).
    pub deferrals: u32,
    /// The last deferral reason recorded (so a long wait is one note per
    /// change, not one per loop).
    pub last_deferral: Option<String>,
    /// The staged version (set once it is prepared).
    pub ver: Option<Ver>,
}

/// The accepted deployment being worked on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDeployment {
    pub id: String,
    pub seq: u64,
    pub digest: String,
    /// Directory name of the imported (verified) pack under `packs/`.
    pub pack: String,
    pub ring: String,
    pub expires_at: u64,
    pub maintenance_window: Option<MaintenanceWindow>,
    pub items: Vec<Item>,
}

/// Phase of the switch in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Floor raised, the switch to `to` may or may not have happened.
    Activating,
    /// `to` is active; its health gate is being judged.
    Health,
    /// `to` failed; switching back to `from`.
    RollingBack,
}

/// The write-ahead intent of a switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Txn {
    pub name: String,
    pub from: Option<Ver>,
    pub to: Ver,
    pub phase: Phase,
    /// Why the health gate failed (set when entering `rolling_back`).
    pub failure: Option<String>,
}

/// The accepted deployment's sequence number and digest (anti-replay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastDeployment {
    pub seq: u64,
    pub digest: String,
    pub expires_at: u64,
}

/// Staleness reported (`robot.deliver.stale`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stale {
    pub since: u64,
    pub high: bool,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub format: String,
    pub site: String,
    pub unit: String,
    /// Newest depot-signed time accepted (Unix seconds); never decreases.
    pub time_floor: u64,
    pub last_deployment: Option<LastDeployment>,
    /// Bundle chain heads, one per programme (sorted by programme).
    pub chains: Vec<ChainState>,
    /// Anti-rollback floors (highest `security_floor` of an installed
    /// release, per package); only ever raised.
    pub floors: BTreeMap<String, u64>,
    pub installed: BTreeMap<String, Installed>,
    /// Earlier versions still in the store (rollback targets), newest
    /// first.
    pub kept: BTreeMap<String, Vec<Ver>>,
    pub deployment: Option<ActiveDeployment>,
    pub txn: Option<Txn>,
    pub stale: Option<Stale>,
    /// Media entries already handled: entry name -> SHA-256 of its
    /// `deployment.json` bytes (imported, already accepted or refused), so
    /// a refusal is reported once, not every loop.
    pub seen_media: BTreeMap<String, String>,
}

impl State {
    /// The empty state of a freshly enrolled unit.
    pub fn new(site: &str, unit: &str) -> Self {
        Self {
            format: STATE_FORMAT.into(),
            site: site.into(),
            unit: unit.into(),
            time_floor: 0,
            last_deployment: None,
            chains: Vec::new(),
            floors: BTreeMap::new(),
            installed: BTreeMap::new(),
            kept: BTreeMap::new(),
            deployment: None,
            txn: None,
            stale: None,
            seen_media: BTreeMap::new(),
        }
    }

    /// The unit's floor for `name` (0 = none).
    pub fn floor(&self, name: &str) -> u64 {
        self.floors.get(name).copied().unwrap_or(0)
    }

    /// Raise the floor of `name` to at least `f`; returns the old floor
    /// when it moved.
    pub fn raise_floor(&mut self, name: &str, f: u64) -> Option<u64> {
        let old = self.floor(name);
        if f > old {
            self.floors.insert(name.to_string(), f);
            Some(old)
        } else {
            None
        }
    }

    /// The chain head of `programme`.
    pub fn chain(&self, programme: &str) -> Option<&ChainState> {
        self.chains.iter().find(|c| c.programme == programme)
    }

    /// Replace or add the chain head of its programme.
    pub fn set_chain(&mut self, c: ChainState) {
        self.chains.retain(|x| x.programme != c.programme);
        self.chains.push(c);
        self.chains.sort_by(|a, b| a.programme.cmp(&b.programme));
    }

    /// Remember a handled media entry (bounded: the oldest names go).
    pub fn see_media(&mut self, name: &str, sha: &str) {
        self.seen_media.insert(name.to_string(), sha.to_string());
        while self.seen_media.len() > MAX_SEEN_MEDIA {
            let Some(k) = self.seen_media.keys().next().cloned() else {
                break;
            };
            self.seen_media.remove(&k);
        }
    }

    /// Structural checks of a parsed state (labels, digests, bounds).
    pub fn validate(&self) -> Result<(), String> {
        let bad = |w: &str| Err(format!("state: bad {w}"));
        if self.format != STATE_FORMAT || !is_label(&self.site) || !is_label(&self.unit) {
            return bad("format, site or unit");
        }
        let ver_ok = |v: &Ver| {
            v.serial >= 1
                && v.serial <= robodr_pkg::MAX_SAFE_INTEGER
                && is_hex64(&v.digest)
                && v.probe_users.len() <= 16
                && v.deb.as_ref().is_none_or(|d| {
                    d.package.len() <= 128 && d.version.len() <= 128 && !d.package.is_empty()
                })
        };
        if self.floors.len() > MAX_PACKAGES
            || self.installed.len() > MAX_PACKAGES
            || self.kept.len() > MAX_PACKAGES
            || self.chains.len() > MAX_CHAINS
            || self.seen_media.len() > MAX_SEEN_MEDIA
        {
            return bad("bounds");
        }
        if !self.floors.keys().all(|k| is_pkg_name(k)) {
            return bad("floor name");
        }
        for (k, i) in &self.installed {
            if !is_pkg_name(k) || !ver_ok(&i.ver) {
                return bad("installed entry");
            }
        }
        for (k, v) in &self.kept {
            if !is_pkg_name(k) || v.len() > MAX_KEPT || !v.iter().all(ver_ok) {
                return bad("kept entry");
            }
        }
        if let Some(d) = &self.deployment {
            if !is_label(&d.id)
                || !is_hex64(&d.digest)
                || d.items.len() > robodr_pkg::deployment::MAX_ITEMS
                || !d
                    .items
                    .iter()
                    .all(|i| is_pkg_name(&i.name) && is_hex64(&i.digest))
                || d.pack.is_empty()
                || d.pack.len() > 128
                || !d
                    .pack
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return bad("deployment");
            }
        }
        if let Some(t) = &self.txn {
            if !is_pkg_name(&t.name)
                || !ver_ok(&t.to)
                || t.from.as_ref().is_some_and(|f| !ver_ok(f))
            {
                return bad("txn");
            }
        }
        if let Some(l) = &self.last_deployment {
            if !is_hex64(&l.digest) {
                return bad("last_deployment");
            }
        }
        for c in &self.chains {
            ChainState::parse(&serde_json::to_vec(c).map_err(|e| e.to_string())?)
                .map_err(|e| format!("state: chain: {e}"))?;
        }
        Ok(())
    }

    /// Parse state bytes strictly.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err("state: too large".into());
        }
        let s: State = serde_json::from_slice(bytes)
            .map_err(|e| format!("state: {}", robodr_pkg::common::trunc(&e.to_string())))?;
        s.validate()?;
        Ok(s)
    }
}

/// The state file on disk, with the floors it last wrote or read.
#[derive(Debug)]
pub struct StateFile {
    path: PathBuf,
    floors: BTreeMap<String, u64>,
}

impl StateFile {
    /// `path` (`<state_dir>/state.json`).
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            floors: BTreeMap::new(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the state; `Ok(None)` when the file does not exist.
    pub fn load(&mut self) -> Result<Option<State>, String> {
        let Some(b) = fsx::read_optional(&self.path, MAX_STATE_BYTES)
            .map_err(|e| format!("{}: {e}", self.path.display()))?
        else {
            return Ok(None);
        };
        let s = State::parse(&b)?;
        self.floors = s.floors.clone();
        Ok(Some(s))
    }

    /// Write `s` atomically. Refuses (and writes nothing) if any floor is
    /// lower than in the last state written or read.
    pub fn save(&mut self, s: &State) -> Result<(), String> {
        for (name, f) in &self.floors {
            if s.floor(name) < *f {
                return Err(format!(
                    "state: refusing to lower the floor of {name} from {f} to {}",
                    s.floor(name)
                ));
            }
        }
        s.validate()?;
        let bytes = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
        let tmp = fsx::temp_sibling(&self.path, "new");
        fsx::write_new(&tmp, &bytes, 0o600).map_err(|e| format!("{}: {e}", tmp.display()))?;
        // A crash here leaves the old state and a stray temporary file.
        if let Err(c) = fault::hit("state.after_tmp") {
            return Err(c.to_string());
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{}: {e}", self.path.display())
        })?;
        if let Some(d) = self.path.parent() {
            fsx::sync_dir(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        self.floors = s.floors.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ver(serial: u64) -> Ver {
        Ver {
            serial,
            digest: "ab".repeat(32),
            kind: Kind::Files,
            deb: None,
            probe_users: BTreeMap::new(),
        }
    }

    #[test]
    fn floors_never_go_down_through_save() {
        let d = std::env::temp_dir().join(format!("deliverd-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut f = StateFile::new(&d.join("state.json"));
        assert!(f.load().unwrap().is_none());
        let mut s = State::new("site-a", "ugv-07");
        assert_eq!(s.raise_floor("nav", 5), Some(0));
        assert_eq!(s.raise_floor("nav", 3), None);
        assert_eq!(s.floor("nav"), 5);
        f.save(&s).unwrap();
        let mut lower = s.clone();
        lower.floors.insert("nav".into(), 4);
        assert!(f.save(&lower).unwrap_err().contains("lower the floor"));
        lower.floors.remove("nav");
        assert!(f.save(&lower).is_err());
        // A fresh handle learns the floors from the file.
        let mut g = StateFile::new(&d.join("state.json"));
        let back = g.load().unwrap().unwrap();
        assert_eq!(back, s);
        assert!(g.save(&lower).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn crash_before_rename_keeps_the_old_state() {
        let d = std::env::temp_dir().join(format!("deliverd-state-c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut f = StateFile::new(&d.join("state.json"));
        let mut s = State::new("site-a", "ugv-07");
        f.save(&s).unwrap();
        s.installed.insert(
            "nav".into(),
            Installed {
                ver: ver(3),
                healthy: true,
            },
        );
        fault::arm("state.after_tmp");
        assert!(f.save(&s).is_err());
        fault::disarm();
        let back = StateFile::new(&d.join("state.json"))
            .load()
            .unwrap()
            .unwrap();
        assert!(back.installed.is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn hostile_state_is_refused() {
        let s = State::new("site-a", "ugv-07");
        let good = serde_json::to_value(&s).unwrap();
        let cases: Vec<fn(&mut serde_json::Value)> = vec![
            |v| v["extra"] = 1.into(),
            |v| v["format"] = "x".into(),
            |v| v["unit"] = "../x".into(),
            |v| v["floors"] = serde_json::json!({"A B": 1}),
            |v| {
                v["installed"] = serde_json::json!({"nav": {"ver": {"serial": 0, "digest": "x",
                    "kind": "files", "deb": null, "probe_users": {}}, "healthy": true}})
            },
            |v| v["time_floor"] = (-1).into(),
        ];
        for m in cases {
            let mut v = good.clone();
            m(&mut v);
            assert!(
                State::parse(&serde_json::to_vec(&v).unwrap()).is_err(),
                "{v}"
            );
        }
        assert!(State::parse(&serde_json::to_vec(&good).unwrap()).is_ok());
    }
}
