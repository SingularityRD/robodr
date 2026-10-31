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
//! exists), moving on to the next number when the name is taken; agentd
//! does the same since 13b (`robodr_agentd::spool`). Neither can overwrite
//! the other's record. The record file is owned by the owner of `ready/`
//! (agentd's user), mode 0640, so the exporters can read and rename it.
//!
//! # Root in a directory another user owns (review M2)
//!
//! The spool belongs to agentd's user, who can rename, replace or symlink
//! anything in it at any moment. This agent (root) therefore never acts on
//! a path there: it opens the spool and `ready/` as directory descriptors
//! (`O_NOFOLLOW`), writes the record into an **unnamed** file in `ready/`
//! (`O_TMPFILE`), `fchown`s and `fsync`s it through its descriptor, and
//! gives it its name with `linkat` from that descriptor (no-replace). No
//! name is created, linked or removed through a directory that could have
//! been swapped, and no temporary name exists for anyone to replace.
//! Where `O_TMPFILE` is not available the file is created exclusively
//! (`O_EXCL|O_NOFOLLOW`) under a hidden name in `ready/`, linked from its
//! descriptor, and that name is unlinked relative to the held `ready/`
//! descriptor ([`crate::fdio`]). The `tmp.deliverd/` directory of earlier
//! versions is no longer used.
//!
//! # Critical findings first (agentd's spool shares)
//!
//! The records go through agentd's class logic ([`class_of`]): a finding
//! below Critical is not written once `ready/` holds `max_ready_files -
//! max_ready_files / 8` records (the last eighth is the Critical share,
//! `robodr_agentd::spool::reserve_files_for`), so a run of refusals or
//! deferrals can never take the room a Critical finding of agentd's or of
//! this agent needs. A Critical finding (`robot.deliver.rollback_blocked_floor`
//! always, any other at Critical severity) may use the whole bound, but this
//! agent, one source, holds at most
//! `robodr_agentd::spool::source_cap_for` records of the share, and none of
//! its last part once it holds one (as agentd's per-source cap).
//!
//! `entity_context.profile` of these findings names the **delivery trust
//! file** they were judged under (`delivery-trust-<version>` and its
//! digest), not a model profile.

use crate::config::FindingsCfg;
use robodr_agentd::spool::{
    reserve_files_for, source_cap_for, SpoolClass, SpoolRecord, SPOOL_SCHEMA,
};
use robodr_events::{Deviation, Severity};
use robodr_ocsf::{
    AttestationStatus, BlackBoxRef, FindingBuilder, Mode, PlatformFamily, ProfileRef, RobotContext,
    RobotInfo,
};
use robodr_responder::SafetyState;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
    /// Every `robot.deliver.*` id above.
    pub const ALL: [&str; 7] = [
        INSTALLED,
        DEFERRED_SAFETY,
        HEALTH_FAILED,
        ROLLBACK_BLOCKED_FLOOR,
        REFUSED,
        STALE,
        CHAIN_GAP,
    ];
    /// Sealing (13c, contract 2.3): the TPM refused to unseal (policy
    /// mismatch, revoked policy) or the unit's keys were erased.
    pub const SEAL_UNSEAL_FAILED: &str = "robot.seal.unseal_failed";
    /// Lease expired (§7.5; catalogued, emitted from 14b).
    pub const SEAL_LEASE_EXPIRED: &str = "robot.seal.lease_expired";
    /// Crypto-erase executed, with its trigger.
    pub const SEAL_ERASED: &str = "robot.seal.erased";
    /// Enclosure tamper or erase trigger fired.
    pub const SEAL_TAMPER: &str = "robot.seal.tamper";
    /// Sprint 14b (contract 2.3, `catalog_2_3_depot`): an executed erase
    /// deferred by the safety state.
    pub const SEAL_ERASE_DEFERRED: &str = "robot.seal.erase_deferred";
    /// Every `robot.seal.*` id.
    pub const SEAL_ALL: [&str; 4] = [
        SEAL_UNSEAL_FAILED,
        SEAL_LEASE_EXPIRED,
        SEAL_ERASED,
        SEAL_TAMPER,
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
    /// Records of this agent in the Critical share since `ready/` was last
    /// below the lesser share (module docs).
    reserve_held: u64,
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
            reserve_held: 0,
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
        ctx.max_contract_minor = self.cfg.max_contract_minor;
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
            class_of(f),
            &mut self.reserve_held,
            &rec.topic,
            &rec.key,
            &headers,
            &rec.value,
        )
    }
}

/// The spool share of `f` (module docs): Critical for
/// `robot.deliver.rollback_blocked_floor` (whatever its severity) and for
/// any finding at Critical severity, Normal otherwise. Never Health: the
/// health reserve is agentd's own.
pub fn class_of(f: &Finding) -> SpoolClass {
    if f.rule == rules::ROLLBACK_BLOCKED_FLOOR || f.severity >= Severity::Critical {
        SpoolClass::Critical
    } else {
        SpoolClass::Normal
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

fn scan(dir: &File) -> io::Result<(u64, u64)> {
    let mut max = 0;
    let mut n = 0;
    // Listed through the held descriptor (the magic link names exactly
    // the directory that was opened).
    for e in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        let e = e?;
        if let Some(s) = e.file_name().to_str().and_then(record_seq) {
            max = max.max(s);
            n += 1;
        }
    }
    Ok((max, n))
}

/// Test seam of [`spool_write`] (review M2): a hook called on this thread
/// at each step (`"opened"`: the directories are held; `"written"`: the
/// record is written and synced, not yet named), so a test can change the
/// spool under the writer at exactly those points, and a switch that forces
/// the named-temporary fallback. Unset (and never set) in production.
#[doc(hidden)]
pub mod seam {
    use std::cell::{Cell, RefCell};

    type Hook = Box<dyn FnMut(&str)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static NAMED: Cell<bool> = const { Cell::new(false) };
    }

    /// Install (or clear) the hook on this thread.
    pub fn set_hook(h: Option<Hook>) {
        HOOK.with(|x| *x.borrow_mut() = h);
    }

    /// Force the named-temporary fallback on this thread.
    pub fn force_named_temp(on: bool) {
        NAMED.with(|x| x.set(on));
    }

    pub(crate) fn named_temp() -> bool {
        NAMED.with(Cell::get)
    }

    pub(crate) fn hit(step: &str) {
        HOOK.with(|x| {
            if let Some(h) = x.borrow_mut().as_mut() {
                h(step);
            }
        });
    }
}

/// The record file, unnamed when the kernel and file system allow it.
fn new_record_file(ready: &File, seq: u64) -> io::Result<(File, Option<String>)> {
    if !seam::named_temp() {
        match crate::fdio::tmpfile_in(ready, 0o640) {
            Ok(f) => return Ok((f, None)),
            // No O_TMPFILE here (EISDIR: old kernel; EOPNOTSUPP: file
            // system; EINVAL): fall back to a named temporary.
            Err(e) if matches!(e.raw_os_error(), Some(21 | 95 | 22)) => {}
            Err(e) => return Err(e),
        }
    }
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let name = format!(
        ".deliverd-{}-{seq}-{}.tmp",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    );
    let f = crate::fdio::create_at(ready, &name, 0o600)?;
    Ok((f, Some(name)))
}

/// Write one spool record into `spool/ready/` with a no-replace link (see
/// the module docs) within the share of `class` of a spool bounded to
/// `max_ready` ready records; `reserve_held` is this writer's count of
/// records in the Critical share (updated). Returns the record's path.
#[allow(clippy::too_many_arguments)]
pub fn spool_write(
    spool: &Path,
    max_ready: u64,
    class: SpoolClass,
    reserve_held: &mut u64,
    topic: &str,
    key: &str,
    headers: &[(String, String)],
    value: &str,
) -> Result<PathBuf, String> {
    let io_e = |p: &Path, e: io::Error| format!("{}: {e}", p.display());
    let not_spool = |e: io::Error| {
        format!(
            "{}: not an agentd spool (no ready/ and acked/ directories): {e}",
            spool.display()
        )
    };
    let root = crate::fdio::open_dir(spool).map_err(not_spool)?;
    let ready = crate::fdio::open_dir_at(&root, "ready").map_err(not_spool)?;
    let acked = crate::fdio::open_dir_at(&root, "acked").map_err(not_spool)?;
    let ready_path = spool.join("ready");
    let owner = ready.metadata().map_err(|e| io_e(&ready_path, e))?;
    seam::hit("opened");
    let (rmax, rn) = scan(&ready).map_err(|e| io_e(&ready_path, e))?;
    // agentd's shares (module docs): below Critical, never into the last
    // eighth; Critical, the whole bound but one source's cap of the share
    // and nothing of its last part once this writer holds a record there.
    // Health is agentd's own reserve: treated as Normal here.
    let normal = max_ready.saturating_sub(reserve_files_for(max_ready));
    let in_reserve = rn.saturating_add(1) > normal;
    match class {
        SpoolClass::Critical => {
            if rn >= max_ready {
                return Err(FULL.into());
            }
            if !in_reserve {
                *reserve_held = 0;
            } else {
                let cap = source_cap_for(max_ready);
                let in_fresh = rn.saturating_add(1) > max_ready.saturating_sub(cap);
                if *reserve_held >= cap || (in_fresh && *reserve_held > 0) {
                    return Err(FULL.into());
                }
            }
        }
        SpoolClass::Normal | SpoolClass::Health => {
            if in_reserve {
                return Err(FULL.into());
            }
            *reserve_held = 0;
        }
    }
    let (amax, _) = scan(&acked).map_err(|e| io_e(&spool.join("acked"), e))?;
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
        let (mut f, tmp_name) = new_record_file(&ready, seq).map_err(|e| io_e(&ready_path, e))?;
        let written = (|| -> io::Result<()> {
            f.write_all(&bytes)?;
            // Owned like the spool's own records, readable by its group.
            std::os::unix::fs::fchown(&f, Some(owner.uid()), Some(owner.gid()))?;
            f.set_permissions(fs::Permissions::from_mode(0o640))?;
            f.sync_all()
        })();
        seam::hit("written");
        let linked = written.and_then(|()| crate::fdio::link_fd_at(&f, &ready, &name));
        if let Some(t) = &tmp_name {
            // Relative to the held ready/ descriptor: at worst removes
            // whatever the spool's owner put under that hidden name there.
            let _ = crate::fdio::unlink_at(&ready, t);
        }
        match linked {
            Ok(()) => {
                if in_reserve && class == SpoolClass::Critical {
                    *reserve_held = reserve_held.saturating_add(1);
                }
                ready.sync_all().map_err(|e| io_e(&ready_path, e))?;
                return Ok(ready_path.join(&name));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                seq = seq.saturating_add(1);
            }
            Err(e) => return Err(io_e(&ready_path.join(&name), e)),
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
        let p = spool_write(
            &d,
            100,
            SpoolClass::Normal,
            &mut 0,
            "robodr.findings",
            "k",
            &[],
            "{}",
        )
        .unwrap();
        assert_eq!(p.file_name().unwrap(), format!("{:020}.json", 10).as_str());
        // A concurrent producer took 11 meanwhile: 12 is used, 11 untouched.
        fs::write(d.join("ready").join(format!("{:020}.json", 11)), b"other").unwrap();
        fs::remove_file(d.join("acked").join(format!("{:020}.json", 9))).unwrap();
        let p2 = spool_write(
            &d,
            100,
            SpoolClass::Normal,
            &mut 0,
            "robodr.findings",
            "k",
            &[],
            "{}",
        )
        .unwrap();
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
        assert_eq!(
            spool_write(&d, 3, SpoolClass::Critical, &mut 0, "t", "k", &[], "{}").unwrap_err(),
            FULL
        );
        assert!(spool_write(
            &d.join("nope"),
            3,
            SpoolClass::Normal,
            &mut 0,
            "t",
            "k",
            &[],
            "{}"
        )
        .is_err());
        fs::remove_dir_all(&d).unwrap();
    }

    /// T38: `findings.max_contract_minor` caps deliverd's findings like
    /// agentd's (they share the spool and the SOC's validators).
    #[test]
    fn producer_cap_labels_the_older_contract() {
        let d = std::env::temp_dir().join(format!("deliverd-cap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for s in ["ready", "acked"] {
            fs::create_dir_all(d.join(s)).unwrap();
        }
        let emit = |cap: Option<u64>| {
            let cfg = FindingsCfg {
                spool: d.clone(),
                max_contract_minor: cap,
                ..FindingsCfg::default()
            };
            let mut f = Findings::new(&cfg, "ugv-007", "test", "lab", None);
            let p = f
                .emit(
                    &finding(rules::ROLLBACK_BLOCKED_FLOOR, Severity::High),
                    None,
                    1_790_000_000_000,
                )
                .unwrap();
            let rec: SpoolRecord = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
            robodr_ocsf::parse_and_validate(&rec.value).unwrap()
        };
        assert_eq!(emit(None).contract_version, robodr_ocsf::CONTRACT_VERSION);
        let capped = emit(Some(3));
        assert_eq!(capped.contract_version, "2.3.0");
        assert_eq!(capped.entity_context.rule_id, rules::ROLLBACK_BLOCKED_FLOOR);
        fs::remove_dir_all(&d).unwrap();
    }

    fn finding(rule: &'static str, severity: Severity) -> Finding {
        Finding {
            rule,
            severity,
            detail: String::new(),
            safety: SafetyState::Unknown,
            evidence: None,
        }
    }

    #[test]
    fn rollback_blocked_floor_is_critical_others_by_severity() {
        assert_eq!(
            class_of(&finding(rules::ROLLBACK_BLOCKED_FLOOR, Severity::High)),
            SpoolClass::Critical
        );
        assert_eq!(
            class_of(&finding(rules::ROLLBACK_BLOCKED_FLOOR, Severity::Critical)),
            SpoolClass::Critical
        );
        for r in rules::ALL {
            if r != rules::ROLLBACK_BLOCKED_FLOOR {
                assert_eq!(class_of(&finding(r, Severity::High)), SpoolClass::Normal);
                assert_eq!(
                    class_of(&finding(r, Severity::Critical)),
                    SpoolClass::Critical
                );
            }
        }
    }

    /// agentd's Critical share (merge of red team F1 with 13b): lesser
    /// findings leave the last eighth of the bound free; this agent's
    /// Critical findings may use it, up to one source's cap.
    #[test]
    fn lesser_findings_leave_the_critical_share_free() {
        let d = std::env::temp_dir().join(format!("deliverd-share-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for s in ["ready", "acked"] {
            fs::create_dir_all(d.join(s)).unwrap();
        }
        // Bound 64: reserve 8, Normal up to 56, one source's cap 2.
        let max = 64;
        assert_eq!(reserve_files_for(max), 8);
        assert_eq!(source_cap_for(max), 2);
        let mut held = 0;
        let w = |class, held: &mut u64| spool_write(&d, max, class, held, "t", "k", &[], "{}");
        for _ in 0..56 {
            w(SpoolClass::Normal, &mut held).unwrap();
        }
        assert_eq!(w(SpoolClass::Normal, &mut held).unwrap_err(), FULL);
        assert_eq!(w(SpoolClass::Health, &mut held).unwrap_err(), FULL);
        w(SpoolClass::Critical, &mut held).unwrap();
        w(SpoolClass::Critical, &mut held).unwrap();
        assert_eq!(held, 2);
        // The cap: the rest of the share stays for other sources (agentd's).
        assert_eq!(w(SpoolClass::Critical, &mut held).unwrap_err(), FULL);
        // Drained below the lesser share: the count starts again.
        for e in fs::read_dir(d.join("ready")).unwrap().take(10) {
            let p = e.unwrap().path();
            fs::rename(&p, d.join("acked").join(p.file_name().unwrap())).unwrap();
        }
        w(SpoolClass::Normal, &mut held).unwrap();
        assert_eq!(held, 0);
        fs::remove_dir_all(&d).unwrap();
    }
}
