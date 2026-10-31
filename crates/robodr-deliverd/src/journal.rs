//! Delivery evidence (`docs/SECURE-DELIVERY.md` §6.6): a `robodr-blackbox`
//! chain of the agent's own (`/var/lib/robodr/blackbox/deliverd`), signed
//! with the unit's black-box key, like `robodr-fleet`'s journal: the
//! recorder is single-writer (`flock`) and agentd holds its directory.
//! Both chains verify with the same key (`robodr-blackbox verify
//! /var/lib/robodr/blackbox/deliverd --keyring <unit key>.pub`).
//!
//! Every step is a **critical** (fsynced) note `{"kind":
//! "robodr.deliver.<step>", ...}`; the lock also keeps a second agent off
//! the same state. A note that cannot be written stops the step before
//! anything on the robot changes (no unrecorded install).

use robodr_blackbox::{
    AppendOutcome, FsyncPolicy, KeyFile, Recorder, RecorderConfig, RetentionMode, Signer,
    SystemClock, TimeSource,
};
use robodr_ocsf::BlackBoxRef;
use serde_json::{Map, Value};
use std::path::Path;

/// Note kinds (the `kind` member).
pub mod kinds {
    pub const STARTED: &str = "robodr.deliver.started";
    pub const PACK_IMPORTED: &str = "robodr.deliver.pack_imported";
    pub const REFUSED: &str = "robodr.deliver.refused";
    pub const CHAIN: &str = "robodr.deliver.chain";
    pub const STAGED: &str = "robodr.deliver.staged";
    pub const DEFERRED: &str = "robodr.deliver.deferred";
    pub const CONFIRMED: &str = "robodr.deliver.operator_confirmed";
    pub const ACTIVATING: &str = "robodr.deliver.activating";
    pub const FLOOR_RAISED: &str = "robodr.deliver.floor_raised";
    pub const SWITCHED: &str = "robodr.deliver.switched";
    pub const HEALTH: &str = "robodr.deliver.health";
    pub const INSTALLED: &str = "robodr.deliver.installed";
    pub const ROLLBACK: &str = "robodr.deliver.rollback";
    pub const ROLLBACK_BLOCKED: &str = "robodr.deliver.rollback_blocked";
    pub const RECOVERED: &str = "robodr.deliver.recovered";
    pub const STALE: &str = "robodr.deliver.stale";
    pub const STATE_RESTORED: &str = "robodr.deliver.state_restored";
    pub const TRUST_ROTATED: &str = "robodr.deliver.trust_rotated";
    pub const REANCHORED: &str = "robodr.deliver.reanchored";
    /// The high-water record was written (review M-A, M-B): its
    /// generation, digest and baseline (deployment, chain heads, time
    /// floor).
    pub const HIGHWATER: &str = "robodr.deliver.highwater";
    /// The first note of a journal started by `robodr-deliverd rekey`
    /// (review L-R3-3): the baseline the archived journal held (floors,
    /// generation, trust version, deployment, chain heads, time floor),
    /// carried over under the new key.
    pub const REKEYED: &str = "robodr.deliver.rekeyed";
    /// Sealing (13c): a sealed item's key could not be unsealed.
    pub const UNSEAL_FAILED: &str = "robodr.seal.unseal_failed";
    /// Sealing (13c): an erase trigger reported tamper.
    pub const TAMPER: &str = "robodr.seal.tamper";
    /// Sealing (13c): crypto-erase executed.
    pub const ERASED: &str = "robodr.seal.erased";
    /// Sprint 14b: the high-water record is anchored in the TPM NV counter.
    pub const ANCHOR_MIGRATED: &str = "robodr.deliver.anchor_migrated";
    /// Sprint 14b: the responder planned a crypto-erase for a trigger.
    pub const ERASE_PLANNED: &str = "robodr.seal.erase_planned";
    /// Sprint 14b: the planned erase was deferred by the safety state.
    pub const ERASE_DEFERRED: &str = "robodr.seal.erase_deferred";
    /// Sprint 14b: the erase is about to run (written before it).
    pub const ERASE_INTENT: &str = "robodr.seal.erase_intent";
    /// A deferred erase lockdown ran (services stopped, runtime volume
    /// unmounted and closed or suspended) after the keys were destroyed.
    pub const ERASE_LOCKDOWN: &str = "robodr.seal.erase_lockdown";
    /// Sprint 14b: a site lease was installed.
    pub const LEASE_INSTALLED: &str = "robodr.seal.lease_installed";
    /// Sprint 14b: a sealed item waits for a site lease.
    pub const LEASE_EXPIRED: &str = "robodr.seal.lease_expired";
}

/// What the notes still in the journal say about the unit's history
/// ([`Journal::history`]): the baseline `reanchor` rebuilds (review L-A)
/// and the generation a high-water record must not be older than (review
/// M-B).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    /// Highest high-water record generation noted.
    pub hw_generation: u64,
    /// Highest site trust file version noted (anchor at start, rotation,
    /// pack import, re-anchoring).
    pub trust_version: u64,
    /// The newest accepted deployment noted.
    pub last_deployment: Option<crate::state::LastDeployment>,
    /// The newest chain head per programme noted.
    pub chains: Vec<robodr_pkg::bundle::ChainState>,
    /// Highest time floor noted.
    pub time_floor: u64,
    /// Floors of the `floor_raised` notes.
    pub floors: std::collections::BTreeMap<String, u64>,
}

impl History {
    fn deployment(&mut self, d: crate::state::LastDeployment) {
        if self.last_deployment.as_ref().is_none_or(|x| x.seq < d.seq) {
            self.last_deployment = Some(d);
        }
    }

    fn chain(&mut self, c: robodr_pkg::bundle::ChainState) {
        let full = self.chains.len() >= crate::state::MAX_CHAINS;
        match self.chains.iter_mut().find(|x| x.programme == c.programme) {
            Some(x) if x.bundle_seq < c.bundle_seq => *x = c,
            Some(_) => {}
            None if !full => self.chains.push(c),
            None => {}
        }
    }

    fn note(&mut self, v: &Value) {
        let u = |k: &str| v[k].as_u64();
        let kind = v["kind"].as_str().unwrap_or("");
        match kind {
            kinds::FLOOR_RAISED => {
                if let (Some(n), Some(f)) = (v["name"].as_str(), u("to")) {
                    if robodr_pkg::common::is_pkg_name(n) {
                        let e = self.floors.entry(n.to_string()).or_insert(0);
                        *e = (*e).max(f);
                    }
                }
            }
            kinds::HIGHWATER => {
                self.hw_generation = self.hw_generation.max(u("generation").unwrap_or(0));
                self.time_floor = self.time_floor.max(u("time_floor").unwrap_or(0));
                if let Ok(d) = serde_json::from_value(v["last_deployment"].clone()) {
                    self.deployment(d);
                }
                if let Ok(cs) = serde_json::from_value::<Vec<robodr_pkg::bundle::ChainState>>(
                    v["chains"].clone(),
                ) {
                    for c in cs {
                        self.chain(c);
                    }
                }
            }
            kinds::REKEYED => {
                self.hw_generation = self.hw_generation.max(u("generation").unwrap_or(0));
                self.trust_version = self.trust_version.max(u("trust_version").unwrap_or(0));
                self.time_floor = self.time_floor.max(u("time_floor").unwrap_or(0));
                if let Some(m) = v["floors"].as_object() {
                    for (n, f) in m {
                        if let (true, Some(f)) = (robodr_pkg::common::is_pkg_name(n), f.as_u64()) {
                            let e = self.floors.entry(n.clone()).or_insert(0);
                            *e = (*e).max(f);
                        }
                    }
                }
                if let Ok(d) = serde_json::from_value(v["last_deployment"].clone()) {
                    self.deployment(d);
                }
                if let Ok(cs) = serde_json::from_value::<Vec<robodr_pkg::bundle::ChainState>>(
                    v["chains"].clone(),
                ) {
                    for c in cs {
                        self.chain(c);
                    }
                }
            }
            kinds::STARTED | kinds::REANCHORED => {
                self.hw_generation = self.hw_generation.max(u("hw_generation").unwrap_or(0));
                self.trust_version = self.trust_version.max(u("trust_version").unwrap_or(0));
            }
            kinds::TRUST_ROTATED => {
                self.trust_version = self.trust_version.max(u("version").unwrap_or(0));
            }
            kinds::PACK_IMPORTED => {
                self.trust_version = self.trust_version.max(u("trust_version").unwrap_or(0));
                if let (Some(seq), Some(digest), Some(expires_at)) = (
                    u("deployment_seq"),
                    v["deployment_digest"].as_str(),
                    u("expires_at"),
                ) {
                    if robodr_pkg::common::is_hex64(digest) {
                        self.deployment(crate::state::LastDeployment {
                            seq,
                            digest: digest.to_string(),
                            expires_at,
                        });
                    }
                }
                if let Ok(cs) = serde_json::from_value::<Vec<robodr_pkg::bundle::ChainState>>(
                    v["heads"].clone(),
                ) {
                    for c in cs {
                        self.chain(c);
                    }
                }
            }
            _ => {}
        }
    }
}

/// The open journal.
pub struct Journal {
    rec: Recorder,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("dir", &self.rec.dir())
            .finish()
    }
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control))
        .unwrap_or_else(|| "unknown-boot".into())
}

/// Load a black-box secret key file (`what` names it in errors) under the
/// legacy-HMAC policy: an HMAC key is refused unless `allow_hmac`
/// (`blackbox.allow_hmac`).
pub fn load_blackbox_key(key: &Path, allow_hmac: bool, what: &str) -> Result<KeyFile, String> {
    let kf = KeyFile::load_secret(key).map_err(|e| format!("{what} {}: {e}", key.display()))?;
    kf.check_hmac_policy(allow_hmac).map_err(|e| {
        format!(
            "{what} {}: {}",
            key.display(),
            e.to_string().replace(
                "--allow-hmac (robodr-agentd: blackbox.allow_hmac)",
                "blackbox.allow_hmac"
            )
        )
    })?;
    Ok(kf)
}

impl Journal {
    /// Open (or create) the journal in `dir` for `unit`, signed with the
    /// black-box secret key file `key`. A legacy HMAC key is refused; see
    /// [`Journal::open_with`].
    pub fn open(dir: &Path, unit: &str, key: &Path) -> Result<Self, String> {
        Self::open_with(dir, unit, key, false)
    }

    /// [`Journal::open`], accepting a legacy HMAC key if `allow_hmac`.
    pub fn open_with(dir: &Path, unit: &str, key: &Path, allow_hmac: bool) -> Result<Self, String> {
        let kf = load_blackbox_key(key, allow_hmac, "black-box key")?;
        let signer = kf
            .signer()
            .map_err(|e| format!("black-box key {}: {e}", key.display()))?;
        crate::fsx::ensure_dir(dir, 0o750).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut cfg = RecorderConfig::new(dir, unit, boot_id());
        cfg.mode = RetentionMode::Cyclic { max_segments: 16 };
        cfg.max_segment_bytes = 1024 * 1024;
        cfg.fsync = FsyncPolicy::Every(1);
        let rec = Recorder::open(cfg, signer, Box::new(SystemClock::new(TimeSource::Rtc)))
            .map_err(|e| format!("delivery journal {}: {e}", dir.display()))?;
        Ok(Self { rec })
    }

    /// Append a critical note `{"kind": kind, ...body}`; the reference of
    /// the record for findings.
    pub fn note(&mut self, kind: &str, body: Value) -> Result<BlackBoxRef, String> {
        let mut m = Map::new();
        m.insert("kind".into(), Value::String(kind.into()));
        if let Value::Object(b) = body {
            for (k, v) in b {
                if k != "kind" {
                    m.insert(k, v);
                }
            }
        }
        match self.rec.append_note(&Value::Object(m), true) {
            Ok(AppendOutcome::Recorded { seq, hash }) => Ok(BlackBoxRef {
                segment: self.rec.segments().last().copied().unwrap_or(0),
                seq,
                sha256: robodr_blackbox::crypto::to_hex(&hash),
            }),
            Ok(AppendOutcome::Refused(r)) => Err(format!("delivery journal refused a note: {r:?}")),
            Err(e) => Err(format!("delivery journal: {e}")),
        }
    }

    /// Seal (checkpoint) and close.
    pub fn close(self) -> Result<(), String> {
        self.rec
            .close()
            .map(|_| ())
            .map_err(|e| format!("delivery journal close: {e}"))
    }

    /// Floors recorded by `floor_raised` notes still in the journal
    /// (the baseline when the state file is missing or behind) that
    /// verify with `key`.
    pub fn recorded_floors(
        dir: &Path,
        key: &dyn Signer,
    ) -> std::collections::BTreeMap<String, u64> {
        Self::history(dir, key).floors
    }

    /// What the notes still in the journal in `dir` say ([`History`]).
    /// Only records whose hash is right and whose signature verifies with
    /// `key` (the unit's black-box key) count (Info of review 3): a note
    /// written into the directory by anyone without the key is ignored.
    /// Chain linkage is not required (the journal is cyclic: evicted
    /// segments leave gaps).
    pub fn history(dir: &Path, key: &dyn Signer) -> History {
        let mut h = History::default();
        let Ok(segs) = robodr_blackbox::verify::read_segments(dir) else {
            return h;
        };
        for seg in segs {
            for item in robodr_blackbox::record::scan_frames(&seg.bytes).items {
                let robodr_blackbox::record::ScanItem::Record(r) = item else {
                    continue;
                };
                let rec = &r.record;
                let authentic = rec.compute_hash() == rec.hash
                    && key.verify_own(
                        &robodr_blackbox::record::signing_message(&rec.hash),
                        &rec.sig,
                    ) == Some(true);
                if !authentic {
                    continue;
                }
                if let Ok(v) = serde_json::from_slice::<Value>(&rec.payload) {
                    h.note(&v);
                }
            }
        }
        h
    }

    /// Whether the journal directory already holds segments.
    pub fn has_records(dir: &Path) -> bool {
        robodr_blackbox::store::list_segments(dir).is_ok_and(|s| !s.is_empty())
    }
}
