//! The depot's database (`state_dir/depot.json`, `robodr-depot-db/1`):
//! the fleet inventory (§4.3), imported RPKs and bundle chains, enrolment
//! state, rollouts and the deployment sequence.
//!
//! # Rollback (Sprint 14b)
//!
//! The file is replaced atomically and carries a `generation`. With an
//! `anchor` configured it also carries `nv`, the value of an NV counter in
//! the depot's TPM ([`robodr_seal::nvcounter`]): each save writes
//! `nv = T + 1`, then increments the counter. A database restored from a
//! backup or an older disk image is refused at open (the depot is then
//! **locked**: it signs, serves and imports nothing until an operator
//! re-anchors it, `robodr-depot reanchor`), as is a database whose counter
//! was undefined and defined again. Without a TPM there is no such
//! anchor; the units still refuse a rolled-back depot's reused deployment
//! sequence numbers (equivocation, `robodr-deliverd`), and the black box
//! of the depot host records every deployment it signed.

use crate::{err, DepotError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const DB_FORMAT: &str = "robodr-depot-db/1";
pub const DB_FILE: &str = "depot.json";
pub const MAX_DB_BYTES: usize = 64 * 1024 * 1024;

/// One imported RPK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rpk {
    pub name: String,
    pub serial: u64,
    pub arch: String,
    pub platform: String,
    pub kind: String,
    pub sealed: bool,
    /// The bundle label (`<programme>-<seq>`) it came in.
    pub bundle: String,
    /// Its directory name inside that bundle.
    pub dir: String,
}

/// One imported bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub programme: String,
    pub seq: u64,
    pub hash: String,
    /// Digest of the entry report it was imported with.
    pub entry_report: String,
    pub station: String,
    pub imported_at: u64,
}

/// Where a unit's enrolment stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrolState {
    /// A nonce was issued.
    Begun,
    /// The request verified; a credential challenge was issued.
    Challenged,
    /// The TPM answered the challenge; waiting for operators.
    Activated,
    /// Operator quorum reached: the depot serves and wraps for it.
    Enrolled,
    /// Revoked (or erased): nothing more for it.
    Revoked,
}

/// Attestation state of a unit (§4.3; the trust states of Sprint 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attestation {
    Verified,
    Deviation,
    Unknown,
}

/// The newest report accepted from a unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastReport {
    pub received_at: u64,
    pub tpm_resets: u32,
    pub tpm_clock: u64,
    pub reported_at: u64,
    pub deployment_seq: u64,
    pub report: robodr_seal::report::UnitReport,
}

/// One unit of the fleet inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    pub unit: String,
    /// The ring the trust file assigns it to.
    pub ring: String,
    pub state: EnrolState,
    pub attestation: Attestation,
    /// The depot's current nonce (hex) while enrolling.
    pub nonce: Option<String>,
    /// SHA-256 (hex) of the credential secret while challenged.
    pub secret_sha256: Option<String>,
    /// The enrolment record, as verified.
    pub record: Option<robodr_seal::unit::UnitRecord>,
    pub platform: Option<String>,
    /// SEC1 P-256 hex of the unit identity key (TLS, reports).
    pub identity_public: Option<String>,
    pub ak_name: Option<String>,
    /// The AK's TPM2B_PUBLIC (hex), checked against `ak_name` at
    /// enrolment: verifies the TPM time attestation of reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ak_public: Option<String>,
    /// SHA-256 (hex) of the EK public area.
    pub ek: Option<String>,
    pub policy_version: Option<u32>,
    /// Operator approvals of the enrolment (`robodr-sigset/1`, hex of its
    /// canonical bytes), over [`crate::depot::enrolment_digest`].
    pub approvals: Option<String>,
    pub enrolled_at: Option<u64>,
    pub cert_serial: Option<u64>,
    pub last_report: Option<LastReport>,
    pub erased: bool,
    pub lease_seq: u64,
}

/// Status of a deployment the depot made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployState {
    /// Signed by the depot, waiting for the operator quorum.
    AwaitingApproval,
    /// Quorum reached: served to its units.
    Active,
    /// Its rollout halted: no longer served.
    Halted,
    /// No longer served (kept for evidence).
    Superseded,
}

/// One deployment (stage of a rollout).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub seq: u64,
    pub id: String,
    pub rollout: String,
    pub ring: String,
    pub units: Vec<String>,
    pub state: DeployState,
    pub created_at: u64,
    pub activated_at: Option<u64>,
    /// Digest of the deployment document.
    pub digest: String,
}

/// Rollout state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutState {
    Running,
    Halted,
    Completed,
    Aborted,
}

/// A staged rollout (§6.2): the same items, ring after ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollout {
    pub id: String,
    /// RPK digests.
    pub items: Vec<String>,
    /// Rings in order (`lab`, `canary`, `ring-<n>`, ascending).
    pub stages: Vec<String>,
    /// Index of the current stage.
    pub stage: usize,
    pub state: RolloutState,
    pub batch_size: u32,
    pub soak_s: u32,
    pub max_failures: u32,
    pub validity_s: u64,
    pub maintenance_window: Option<robodr_pkg::deployment::MaintenanceWindow>,
    /// Least distribution: only these units (`None`: every unit).
    #[serde(default)]
    pub units: Option<Vec<String>>,
    /// Deployment sequence numbers of its stages, in order.
    pub deployments: Vec<u64>,
    /// Units that failed in the current stage, with the reason.
    pub failures: BTreeMap<String, String>,
    pub halted_reason: Option<String>,
    pub created_at: u64,
}

/// The database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Db {
    pub format: String,
    pub site: String,
    pub generation: u64,
    /// NV counter value this generation belongs to (with an anchor).
    pub nv: Option<u64>,
    /// Locked by an anchor failure: the reason.
    pub locked: Option<String>,
    pub deployment_seq: u64,
    pub cert_serial: u64,
    pub rpks: BTreeMap<String, Rpk>,
    pub bundles: BTreeMap<String, Bundle>,
    pub units: BTreeMap<String, Unit>,
    pub deployments: BTreeMap<u64, Deployment>,
    pub rollouts: BTreeMap<String, Rollout>,
}

impl Db {
    pub fn new(site: &str) -> Self {
        Self {
            format: DB_FORMAT.into(),
            site: site.into(),
            generation: 0,
            nv: None,
            locked: None,
            deployment_seq: 0,
            cert_serial: 1,
            rpks: BTreeMap::new(),
            bundles: BTreeMap::new(),
            units: BTreeMap::new(),
            deployments: BTreeMap::new(),
            rollouts: BTreeMap::new(),
        }
    }
}

/// The database anchor: an NV counter of the depot's TPM.
pub struct Anchor {
    pub tpm: robodr_seal::tpm::Tpm,
    pub index: u32,
}

impl std::fmt::Debug for Anchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Anchor(0x{:08x})", self.index)
    }
}

/// The database on disk.
#[derive(Debug)]
pub struct Store {
    pub path: PathBuf,
    pub anchor: Option<Anchor>,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), DepotError> {
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| err(format!("{}: {e}", tmp.display())))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| err(format!("{}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path).map_err(|e| err(format!("{}: {e}", path.display())))?;
    if let Some(d) = path.parent() {
        if let Ok(d) = std::fs::File::open(d) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

impl Store {
    /// Load (or create) the database and judge it against the anchor. A
    /// database the anchor refuses is returned **locked**; the flag says
    /// whether the lock is new (not yet in the file).
    pub fn open(&self, site: &str) -> Result<(Db, bool), DepotError> {
        let mut db = match std::fs::read(&self.path) {
            Ok(b) => {
                if b.len() > MAX_DB_BYTES {
                    return Err(err("depot database too large"));
                }
                let d: Db =
                    serde_json::from_slice(&b).map_err(|e| err(format!("depot database: {e}")))?;
                if d.format != DB_FORMAT || d.site != site {
                    return Err(err("depot database of another format or site"));
                }
                d
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Db::new(site),
            Err(e) => return Err(err(format!("{}: {e}", self.path.display()))),
        };
        let was_locked = db.locked.is_some();
        if let Some(a) = &self.anchor {
            use robodr_seal::nvcounter::{judge, Verdict};
            let c = a.tpm.counter(a.index).map_err(|e| err(e.to_string()))?;
            let fresh = db.generation == 0 && db.nv.is_none();
            match judge(db.nv, c) {
                Verdict::Current | Verdict::Migrate => {}
                Verdict::CompleteIncrement => {
                    a.tpm
                        .increment_counter(a.index)
                        .map_err(|e| err(e.to_string()))?;
                }
                Verdict::Locked(why) if fresh => {
                    // No database at all next to a used counter: a deleted
                    // database is a rollback too.
                    db.locked = Some(format!("no database while {why}"));
                }
                Verdict::Locked(why) => db.locked = Some(why),
            }
        }
        let fresh_lock = !was_locked && db.locked.is_some();
        Ok((db, fresh_lock))
    }

    /// Save the next generation (anchored: `nv = T + 1`, then increment).
    pub fn save(&self, db: &mut Db) -> Result<(), DepotError> {
        db.generation += 1;
        match &self.anchor {
            None => write_atomic(
                &self.path,
                &serde_json::to_vec_pretty(db).map_err(|e| err(e.to_string()))?,
            ),
            Some(a) => {
                use robodr_seal::tpm_ident::Counter;
                let c = a.tpm.counter(a.index).map_err(|e| err(e.to_string()))?;
                match c {
                    Counter::Value(t) => {
                        db.nv = Some(t + 1);
                        write_atomic(
                            &self.path,
                            &serde_json::to_vec_pretty(db).map_err(|e| err(e.to_string()))?,
                        )?;
                        a.tpm
                            .increment_counter(a.index)
                            .map_err(|e| err(e.to_string()))
                    }
                    Counter::Unwritten => {
                        // First anchored write (nvcounter: a crash between
                        // the increment and this write locks the depot).
                        a.tpm
                            .increment_counter(a.index)
                            .map_err(|e| err(e.to_string()))?;
                        match a.tpm.counter(a.index).map_err(|e| err(e.to_string()))? {
                            Counter::Value(v) => db.nv = Some(v),
                            _ => return Err(err("NV counter unreadable after its first increment")),
                        }
                        write_atomic(
                            &self.path,
                            &serde_json::to_vec_pretty(db).map_err(|e| err(e.to_string()))?,
                        )
                    }
                    Counter::Undefined => Err(err(
                        "the database anchor NV counter is not defined (robodr-seal counter define)",
                    )),
                }
            }
        }
    }
}
