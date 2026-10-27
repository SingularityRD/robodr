//! The fleet state directory (`/var/lib/robodr/fleet`, 0700 root) and the
//! context every operation runs in.
//!
//! ```text
//! fleet.lock               single-instance flock
//! enroll-pending.json      an enrollment request not yet answered
//! enrollment.json          the confirmed enrollment (robot, workspace, keys)
//! tokens-used.json         token ids this unit has consumed (local replay guard)
//! rotation-<role>.json     an unfinished key rotation (its journal)
//! revocations-state.json   last accepted revocation list per platform (serial, digest)
//! approvals-used.json      approval ids this unit has consumed
//! ring.json                last accepted ring information (serial)
//! profile/                 the staged profile, its .sig, staged-meta.json, backups
//! journal/                 the fleet journal (robodr-blackbox recorder)
//! ```
//!
//! Every file is written atomically (temp + fsync + rename + directory
//! fsync); a malformed state file is an error, never silently reset.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::config::{AgentdFacts, Config};
use crate::fsx;
use crate::journal::Journal;
use crate::wire::KeyRef;

const MAX_STATE_BYTES: u64 = 1024 * 1024;
/// Most ids kept in a replay-guard list (oldest dropped first).
pub const MAX_USED_IDS: usize = 4096;

pub const ENROLLMENT_FORMAT: &str = "robodr-fleet-enrollment/v1";
pub const PENDING_FORMAT: &str = "robodr-fleet-enroll-pending/v1";
pub const ROTATION_FORMAT: &str = "robodr-fleet-rotation/v1";

/// The confirmed enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub format: String,
    pub workspace: String,
    pub robot_id: String,
    pub site: Option<String>,
    pub token_id: String,
    pub request_id: String,
    pub request_digest: String,
    /// The SOC key that signed the answer.
    pub soc_key_id: String,
    /// The registered keys (updated by every finished rotation).
    pub keys: Vec<KeyRef>,
    pub enrolled_at_ms: u64,
}

impl Enrollment {
    pub fn key(&self, role: &str) -> Option<&KeyRef> {
        self.keys.iter().find(|k| k.role == role)
    }
}

/// An enrollment request that was produced but not yet answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingEnroll {
    pub format: String,
    pub token_id: String,
    pub request_id: String,
    pub request_digest: String,
    pub workspace: String,
    pub robot_id: String,
    pub site: Option<String>,
    pub keys: Vec<KeyRef>,
    /// The exact request envelope (resent byte-identical on retry).
    pub envelope: String,
    pub created_at_ms: u64,
}

/// Phase of a key rotation (contract §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// New key generated at `<key>.next`, request built; not yet confirmed.
    Prepared,
    /// The SOC confirmed the new key (both keys valid: overlap).
    Registered,
    /// The new key is the active key file; the old one is in `retired/`.
    Swapped,
}

/// The journal of one unfinished rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub format: String,
    pub rotation_id: String,
    pub role: String,
    pub workspace: String,
    pub robot_id: String,
    pub phase: Phase,
    pub old_key_id: String,
    pub old_fingerprint: String,
    pub new_key_id: String,
    pub new_fingerprint: String,
    /// The exact rotate request envelope.
    pub request: String,
    pub request_digest: String,
    /// The rotate request may have reached the SOC: it was submitted (set
    /// **before** the first submit) or written out for the air-gapped
    /// flow. From then on the rotation is never abandoned locally: it is
    /// resent (the SOC answers with its stored answer) or cancelled at the
    /// SOC (§5.5). Missing in a journal: assumed sent.
    #[serde(default = "assume_sent")]
    pub sent: bool,
    /// The exact cancel request envelope, once built (§5.5).
    #[serde(default)]
    pub cancel_request: Option<String>,
    /// The exact retire request envelope, once built.
    pub retire_request: Option<String>,
    pub started_at_ms: u64,
}

fn assume_sent() -> bool {
    true
}

/// Last accepted revocation list of a platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationMark {
    pub platform: String,
    pub serial: u64,
    pub digest: String,
}

/// Last accepted ring information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingMark {
    pub serial: u64,
    /// The exact envelope.
    pub envelope: String,
}

/// The staged (verified, not enforced) profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedMeta {
    pub digest: String,
    pub profile_version: u64,
    pub platform: String,
    pub unit_id: Option<String>,
    pub signed_by: Option<String>,
    pub staged_at_ms: u64,
}

/// Wall clock in ms (overridable for tests).
pub type Clock = Box<dyn Fn() -> u64>;

pub fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Everything an operation needs: the configuration, the facts read from
/// agentd's configuration, the locked state directory and a clock.
pub struct Ctx {
    pub cfg: Config,
    pub facts: AgentdFacts,
    pub clock: Clock,
    _lock: fsx::DirLock,
}

impl Ctx {
    /// Lock the state directory (created 0700 if missing).
    pub fn open(cfg: Config, facts: AgentdFacts, clock: Clock) -> Result<Self, String> {
        fsx::ensure_private_dir(&cfg.state_dir)
            .map_err(|e| format!("state dir {}: {e}", cfg.state_dir.display()))?;
        let lock = fsx::DirLock::acquire(&cfg.state_dir).map_err(|e| e.to_string())?;
        Ok(Self {
            cfg,
            facts,
            clock,
            _lock: lock,
        })
    }

    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.cfg.state_dir.join(name)
    }

    pub fn profile_dir(&self) -> Result<PathBuf, String> {
        let d = self.path("profile");
        fsx::ensure_private_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        Ok(d)
    }

    pub fn load<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, String> {
        load_json(&self.path(name))
    }

    pub fn store<T: Serialize>(&self, name: &str, v: &T) -> Result<(), String> {
        store_json(&self.path(name), v)
    }

    pub fn remove(&self, name: &str) -> Result<(), String> {
        let p = self.path(name);
        match std::fs::remove_file(&p) {
            Ok(()) => fsx::sync_parent(&p).map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", p.display())),
        }
    }

    pub fn enrollment(&self) -> Result<Enrollment, String> {
        self.load::<Enrollment>("enrollment.json")?.ok_or_else(|| {
            "this unit is not enrolled (run robodr-enroll --token ... first)".to_string()
        })
    }

    /// Open the fleet journal for `robot_id`.
    pub fn journal(&self, robot_id: &str) -> Result<Journal, String> {
        let d = self.path("journal");
        fsx::ensure_private_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        Journal::open(&d, robot_id, &self.cfg.blackbox_key)
    }

    /// Whether `id` is in the replay-guard list `name`.
    pub fn used(&self, name: &str, id: &str) -> Result<bool, String> {
        Ok(self
            .load::<Vec<String>>(name)?
            .unwrap_or_default()
            .iter()
            .any(|x| x == id))
    }

    /// Add `id` to the replay-guard list `name`.
    pub fn mark_used(&self, name: &str, id: &str) -> Result<(), String> {
        let mut v = self.load::<Vec<String>>(name)?.unwrap_or_default();
        if !v.iter().any(|x| x == id) {
            v.push(id.to_string());
        }
        if v.len() > MAX_USED_IDS {
            let n = v.len() - MAX_USED_IDS;
            v.drain(..n);
        }
        self.store(name, &v)
    }
}

/// Read a JSON state file (`Ok(None)` if missing; malformed is an error).
pub fn load_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    match fsx::read_optional(path, MAX_STATE_BYTES) {
        Ok(None) => Ok(None),
        Ok(Some(b)) => {
            let t =
                std::str::from_utf8(&b).map_err(|_| format!("{}: not UTF-8", path.display()))?;
            robodr_commission::profile_file::reject_duplicate_keys(t)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            serde_json::from_str(t)
                .map(Some)
                .map_err(|e| format!("{}: malformed state file ({e})", path.display()))
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Write a JSON state file atomically (pretty, trailing newline, 0600).
pub fn store_json<T: Serialize>(path: &Path, v: &T) -> Result<(), String> {
    let mut s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    s.push('\n');
    fsx::write_atomic(path, s.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
}
