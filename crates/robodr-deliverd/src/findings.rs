//! The §9 `robot.deliver.*` findings (`docs/SECURE-DELIVERY.md` §9,
//! contract `robodr.findings` 2.2): built and validated with `robodr-ocsf`
//! from the trusted catalog (title and description never come from
//! untrusted text; the reason travels as the tainted `detail`) and written
//! into **agentd's findings spool** (`robodr.spool/v1`), so the existing
//! exporters (`robodr-spool-export`, `robodr-kafka-publish`,
//! `robodr-uplink`) carry them out with agentd's own findings.
//!
//! # Sharing the spool
//!
//! agentd numbers its records itself. Both producers therefore claim a
//! record name with a **no-replace** hard link (`link(2)` fails if the name
//! exists): this agent writes the record into its own `tmp.deliverd/`
//! directory inside the spool (same file system), `fsync`s it and links it
//! to `ready/<seq:020>.json`, moving on to the next number when the name is
//! taken; agentd does the same since 13b (`robodr_agentd::spool`). Neither
//! can overwrite the other's record. The record file is owned by the owner
//! of `ready/` (agentd's user), mode 0640, so the exporters can read and
//! rename it.
//!
//! `entity_context.profile` of these findings names the **delivery trust
//! file** they were judged under (`delivery-trust-<version>` and its
//! digest), not a model profile.

use crate::config::FindingsCfg;
use robodr_agentd::spool::{SpoolRecord, SPOOL_SCHEMA};
use robodr_events::{Deviation, Severity};
use robodr_ocsf::{
    AttestationStatus, BlackBoxRef, FindingBuilder, Mode, PlatformFamily, ProfileRef, RobotContext,
    RobotInfo,
};
use robodr_responder::SafetyState;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Rule ids (catalog entries in `robodr-ocsf`, contract 2.2).
pub mod rules {
    /// RPK installed and healthy (§9 "Info"; the contract's lowest
    /// severity is Low).
    pub const INSTALLED: &str = "robot.deliver.installed";
    /// Install deferred by the safety state (or window / confirmation).
    pub const DEFERRED_SAFETY: &str = "robot.deliver.deferred_safety";
    /// Health gate failed; automatic rollback taken.
    pub const HEALTH_FAILED: &str = "robot.deliver.health_failed";
    /// Failing version, no rollback target at or above the floor.
    pub const ROLLBACK_BLOCKED_FLOOR: &str = "robot.deliver.rollback_blocked_floor";
    /// Signature, quorum, revocation, floor, scope, platform or hash check
    /// failed.
    pub const REFUSED: &str = "robot.deliver.refused";
    /// No unexpired deployment / trust file within the freshness window.
    pub const STALE: &str = "robot.deliver.stale";
    /// Bundle sequence gap, replay or equivocation.
    pub const CHAIN_GAP: &str = "robot.deliver.chain_gap";
    /// Every id above.
    pub const ALL: [&str; 7] = [
        INSTALLED,
        DEFERRED_SAFETY,
        HEALTH_FAILED,
        ROLLBACK_BLOCKED_FLOOR,
        REFUSED,
        STALE,
        CHAIN_GAP,
    ];
}

/// The OCSF safety-state of a responder state (as agentd maps it).
pub fn ocsf_safety(s: SafetyState) -> robodr_ocsf::SafetyState {
    robodr_agent_like::map(s)
}

mod robodr_agent_like {
    use robodr_ocsf::{HumanProximity, MotionState};
    use robodr_responder::SafetyState;

    pub fn map(s: SafetyState) -> robodr_ocsf::SafetyState {
        let (motion, human) = match s {
            SafetyState::Idle | SafetyState::EStopActive | SafetyState::SafeStateActive => {
                (MotionState::Stationary, HumanProximity::Unknown)
            }
            SafetyState::MovingSlow | SafetyState::MovingFast => {
                (MotionState::Moving, HumanProximity::Unknown)
            }
            SafetyState::CollaborativeHumanNearby => {
                (MotionState::Unknown, HumanProximity::Detected)
            }
            SafetyState::Unknown => (MotionState::Unknown, HumanProximity::Unknown),
        };
        robodr_ocsf::SafetyState {
            motion,
            human_proximity: human,
        }
    }
}

/// Counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub spooled: u64,
    /// Not spooled: the spool held `max_ready_files` unexported records.
    pub dropped_full: u64,
    /// Not built or not written (the black box still has the step).
    pub errors: u64,
}

/// One finding to emit.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub detail: String,
    pub safety: SafetyState,
    pub evidence: Option<BlackBoxRef>,
}

/// Builds and spools findings.
pub struct Findings {
    cfg: FindingsCfg,
    robot: RobotInfo,
    signer: Option<Box<dyn robodr_blackbox::Signer>>,
    seen: HashMap<String, (u64, u64)>,
    pub stats: Stats,
}

impl std::fmt::Debug for Findings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Findings")
            .field("spool", &self.cfg.spool)
            .field("stats", &self.stats)
            .finish()
    }
}

impl Findings {
    /// For unit `id` (`model`, `site`).
    pub fn new(
        cfg: &FindingsCfg,
        id: &str,
        model: &str,
        site: &str,
        signer: Option<Box<dyn robodr_blackbox::Signer>>,
    ) -> Self {
        Self {
            cfg: cfg.clone(),
            robot: RobotInfo {
                id: id.into(),
                model: model.into(),
                platform_family: PlatformFamily::LinuxRos2,
                site: site.into(),
                firmware: None,
            },
            signer,
            seen: HashMap::new(),
            stats: Stats::default(),
        }
    }

    /// Build, validate and spool `f`, judged under trust file
    /// `(version, digest)` (None before any trust file was accepted).
    pub fn emit(
        &mut self,
        f: &Finding,
        trust: Option<(u64, &str)>,
        now_ms: u64,
    ) -> Result<PathBuf, String> {
        let r = self.build_and_spool(f, trust, now_ms);
        match &r {
            Ok(_) => self.stats.spooled += 1,
            Err(e) if e == FULL => self.stats.dropped_full += 1,
            Err(_) => self.stats.errors += 1,
        }
        r
    }

    fn build_and_spool(
        &mut self,
        f: &Finding,
        trust: Option<(u64, &str)>,
        now_ms: u64,
    ) -> Result<PathBuf, String> {
        let profile = match trust {
            Some((v, d)) => ProfileRef {
                version: format!("delivery-trust-{v}"),
                sha256: d.to_string(),
            },
            None => ProfileRef {
                version: "delivery-trust-none".into(),
                sha256: "0".repeat(64),
            },
        };
        let mut ctx = RobotContext::new(self.robot.clone(), profile, Mode::Enforce);
        ctx.data_source = self.cfg.data_source.clone();
        ctx.topic = self.cfg.topic.clone();
        let dev = Deviation::new(f.rule, f.severity, f.detail.clone());
        let mut b = FindingBuilder::from_deviation(&dev, &ctx)
            .safety_state(ocsf_safety(f.safety))
            .attestation(AttestationStatus::Unknown);
        let uid = b.finding_uid();
        let (first, count) = {
            let e = self.seen.entry(uid).or_insert((now_ms, 0));
            e.1 = e.1.saturating_add(1);
            (e.0.min(now_ms), e.1)
        };
        if self.seen.len() > 4096 {
            self.seen.clear();
        }
        b = b.seen(first, now_ms).occurrences(count);
        if let Some(r) = &f.evidence {
            b = b.evidence(r.clone());
        }
        let env = b.build().map_err(|e| {
            format!(
                "finding {} invalid: {}",
                f.rule,
                e.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })?;
        let mut rec = robodr_ocsf::record(&env, None).map_err(|e| {
            format!(
                "finding {} record: {}",
                f.rule,
                e.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })?;
        if let Some(s) = &self.signer {
            robodr_ocsf::sign_record(&mut rec, s.as_ref())
                .map_err(|e| format!("finding signature: {e}"))?;
        }
        let headers: Vec<(String, String)> = rec
            .headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        spool_write(
            &self.cfg.spool,
            self.cfg.max_ready_files,
            &rec.topic,
            &rec.key,
            &headers,
            &rec.value,
        )
    }
}

/// The error string of a full spool.
pub const FULL: &str = "spool full of unexported records";

fn record_seq(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".json")?;
    if stem.len() != 20 || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    stem.parse().ok()
}

fn scan(dir: &Path) -> io::Result<(u64, u64)> {
    let mut max = 0;
    let mut n = 0;
    for e in fs::read_dir(dir)? {
        let e = e?;
        if let Some(s) = e.file_name().to_str().and_then(record_seq) {
            max = max.max(s);
            n += 1;
        }
    }
    Ok((max, n))
}

/// Write one spool record into `spool/ready/` with a no-replace link (see
/// the module docs). Returns the record's path.
pub fn spool_write(
    spool: &Path,
    max_ready: u64,
    topic: &str,
    key: &str,
    headers: &[(String, String)],
    value: &str,
) -> Result<PathBuf, String> {
    let io_e = |p: &Path, e: io::Error| format!("{}: {e}", p.display());
    let ready = spool.join("ready");
    let acked = spool.join("acked");
    if !crate::fsx::is_real_dir(&ready) || !crate::fsx::is_real_dir(&acked) {
        return Err(format!(
            "{}: not an agentd spool (no ready/ and acked/ directories)",
            spool.display()
        ));
    }
    let owner = fs::metadata(&ready).map_err(|e| io_e(&ready, e))?;
    let tmpdir = spool.join("tmp.deliverd");
    crate::fsx::ensure_dir(&tmpdir, 0o700).map_err(|e| io_e(&tmpdir, e))?;
    let (rmax, rn) = scan(&ready).map_err(|e| io_e(&ready, e))?;
    if rn >= max_ready {
        return Err(FULL.into());
    }
    let (amax, _) = scan(&acked).map_err(|e| io_e(&acked, e))?;
    let mut seq = rmax.max(amax).saturating_add(1);
    for _ in 0..64 {
        let rec = SpoolRecord {
            schema: SPOOL_SCHEMA.into(),
            seq,
            topic: topic.into(),
            key: key.into(),
            partition: None,
            headers: headers.to_vec(),
            value: value.into(),
        };
        let bytes = serde_json::to_vec(&rec).map_err(|e| e.to_string())?;
        let name = format!("{seq:020}.json");
        let tmp = tmpdir.join(format!("{name}.{}", std::process::id()));
        let _ = fs::remove_file(&tmp);
        {
            let mut f: File = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o640)
                .open(&tmp)
                .map_err(|e| io_e(&tmp, e))?;
            f.write_all(&bytes).map_err(|e| io_e(&tmp, e))?;
            // Owned like the spool's own records, readable by its group.
            std::os::unix::fs::fchown(&f, Some(owner.uid()), Some(owner.gid()))
                .map_err(|e| io_e(&tmp, e))?;
            f.set_permissions(fs::Permissions::from_mode(0o640))
                .map_err(|e| io_e(&tmp, e))?;
            f.sync_all().map_err(|e| io_e(&tmp, e))?;
        }
        let dst = ready.join(&name);
        let linked = fs::hard_link(&tmp, &dst);
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                crate::fsx::sync_dir(&ready).map_err(|e| io_e(&ready, e))?;
                return Ok(dst);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                seq = seq.saturating_add(1);
            }
            Err(e) => return Err(io_e(&dst, e)),
        }
    }
    Err("spool: no free record name after 64 attempts".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_never_overwritten() {
        let d = std::env::temp_dir().join(format!("deliverd-spool-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for s in ["ready", "acked"] {
            fs::create_dir_all(d.join(s)).unwrap();
        }
        fs::write(d.join("ready").join(format!("{:020}.json", 7)), b"agentd").unwrap();
        fs::write(d.join("acked").join(format!("{:020}.json", 9)), b"acked").unwrap();
        let p = spool_write(&d, 100, "robodr.findings", "k", &[], "{}").unwrap();
        assert_eq!(p.file_name().unwrap(), format!("{:020}.json", 10).as_str());
        // A concurrent producer took 11 meanwhile: 12 is used, 11 untouched.
        fs::write(d.join("ready").join(format!("{:020}.json", 11)), b"other").unwrap();
        fs::remove_file(d.join("acked").join(format!("{:020}.json", 9))).unwrap();
        let p2 = spool_write(&d, 100, "robodr.findings", "k", &[], "{}").unwrap();
        assert_eq!(p2.file_name().unwrap(), format!("{:020}.json", 12).as_str());
        assert_eq!(
            fs::read(d.join("ready").join(format!("{:020}.json", 11))).unwrap(),
            b"other"
        );
        let rec: SpoolRecord = serde_json::from_slice(&fs::read(&p2).unwrap()).unwrap();
        assert_eq!(rec.seq, 12);
        assert_eq!(
            fs::metadata(&p2).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(spool_write(&d, 3, "t", "k", &[], "{}").unwrap_err(), FULL);
        assert!(spool_write(&d.join("nope"), 3, "t", "k", &[], "{}").is_err());
        fs::remove_dir_all(&d).unwrap();
    }
}
