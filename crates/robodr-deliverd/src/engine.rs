//! The reconcile loop: media packs in, one item at a time through stage →
//! gate → intent + floor → switch → health → install or rollback, with
//! every step in the black box and the §9 findings in the spool.
//!
//! # One step at a time, crash-safe
//!
//! [`Engine::tick`] does at most one switch. Before anything on the robot
//! changes, the intent ([`Txn`], phase `activating`) and the raised floor
//! are written to the state file; the phase moves to `health` after the
//! switch, to `rolling_back` after a failed gate. When a process dies at
//! any point, the next [`Engine::tick`] first resumes the intent:
//!
//! | phase at crash | what is active | recovery |
//! |---|---|---|
//! | `activating` | the old version | intent dropped, item retried through the gate |
//! | `activating` | the new version | phase `health`, gate judged again |
//! | `activating` | neither (half-done `dpkg`) | rolled back to the old version |
//! | `health` | the new version | gate judged again |
//! | `rolling_back` | either | rollback (idempotent) finished |
//!
//! Floors are raised in the intent's write, so they can only be at or
//! above what was installed, never behind (`state`).
//!
//! # Rollback and the floor
//!
//! A failed health gate rolls back to the previous installed version if
//! it is at or above the package's floor **after** the new release raised
//! it (§6.4) and still in the store. Otherwise the unit stays on the
//! failing version and raises `robot.deliver.rollback_blocked_floor`
//! (Critical); an operator decides. Rollbacks pass the safety gate too.

use crate::clock::{effective_now, in_window, window_time, Clock};
use crate::config::Config;
use crate::fault;
use crate::findings::{rules, Finding, Findings};
use crate::health;
use crate::highwater::{self, HighWater};
use crate::install::{Installer, PrepError};
use crate::journal::{kinds, Journal};
use crate::media::{self, Outcome};
use crate::safety::{self, state_name, Observed};
use crate::state::{
    ActiveDeployment, Installed, Item, ItemStatus, LastDeployment, Locked, Phase, Stale, State,
    StateFile, Txn, Ver,
};
use crate::store::Store;
use robodr_events::Severity;
use robodr_ocsf::BlackBoxRef;
use robodr_pkg::rpk::Manifest;
use robodr_pkg::trust::{verify_trust_anchor, VerifiedTrust};
use robodr_responder::SafetyState;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// What one tick did (tests, `once`, logs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    pub imported: Vec<String>,
    pub refused: Vec<String>,
    pub installed: Vec<String>,
    pub deferred: Option<String>,
    pub rolled_back: Vec<String>,
    pub blocked: Vec<String>,
    pub recovered: Vec<String>,
    pub stale: Option<String>,
}

/// An engine error: an I/O or evidence problem, or a simulated crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError(pub String);

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for EngineError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<fault::Crash> for EngineError {
    fn from(c: fault::Crash) -> Self {
        Self(c.to_string())
    }
}

type R<T> = Result<T, EngineError>;

/// The agent.
pub struct Engine {
    cfg: Config,
    clock: Box<dyn Clock>,
    file: StateFile,
    state: State,
    store: Store,
    journal: Journal,
    findings: Findings,
    /// The trust anchor as last loaded (floors, revocations, findings'
    /// profile reference).
    anchor: Option<VerifiedTrust>,
    /// Transient import problems already recorded this run.
    reported: BTreeSet<String>,
    /// Media entry name -> (tree stamp, content digest) of the last pass,
    /// so an unchanged pack is not hashed again (review L4).
    media_cache: std::collections::BTreeMap<String, (String, String)>,
    /// The black-box key, which signs the high-water record.
    hw_key: Box<dyn robodr_blackbox::Signer>,
    /// The high-water record as last written or read.
    hw_written: Option<HighWater>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("unit", &self.cfg.unit.id)
            .finish()
    }
}

fn ver_json(v: &Option<Ver>) -> serde_json::Value {
    v.as_ref().map_or(
        serde_json::Value::Null,
        |v| json!({"serial": v.serial, "digest": v.digest}),
    )
}

impl Engine {
    /// Open the agent: state, store, journal (single-writer lock), anchor,
    /// and the high-water record ([`crate::highwater`], review M1).
    ///
    /// | state file | high-water record | journal | result |
    /// |---|---|---|---|
    /// | present | valid | any | state raised to the record (if behind) |
    /// | present | missing / invalid | any | state kept; record rewritten from it |
    /// | missing | valid | any | floors, deployment sequence, time floor, chain heads restored (High finding) |
    /// | missing | missing / invalid | has records | **locked** until `reanchor` (High finding) |
    /// | missing | missing | empty | a freshly enrolled unit |
    ///
    /// The `floor_raised` notes still in the journal raise the floors in
    /// every case.
    pub fn open(cfg: Config, clock: Box<dyn Clock>) -> R<Self> {
        crate::fsx::ensure_dir(&cfg.state_dir, 0o700)
            .map_err(|e| format!("{}: {e}", cfg.state_dir.display()))?;
        let had_records = Journal::has_records(&cfg.blackbox.dir);
        let journal = Journal::open(&cfg.blackbox.dir, &cfg.unit.id, &cfg.blackbox.key)?;
        let hw_key = robodr_blackbox::KeyFile::load_secret(&cfg.blackbox.key)
            .and_then(|k| k.signer())
            .map_err(|e| format!("black-box key {}: {e}", cfg.blackbox.key.display()))?;
        let signer = match &cfg.findings.finding_key {
            Some(p) => Some(
                robodr_blackbox::KeyFile::load_secret(p)
                    .and_then(|k| k.signer())
                    .map_err(|e| format!("finding key {}: {e}", p.display()))?,
            ),
            None => None,
        };
        let findings = Findings::new(
            &cfg.findings,
            &cfg.unit.id,
            &cfg.unit.model,
            &cfg.unit.site,
            signer,
        );
        let mut file = StateFile::new(&cfg.state_path());
        let recorded = Journal::recorded_floors(&cfg.blackbox.dir);
        let hw = match highwater::load(&cfg.blackbox.dir, hw_key.as_ref()) {
            Ok(Some(h)) if h.site != cfg.unit.site || h.unit != cfg.unit.id => Err(format!(
                "high-water record of unit {} at site {}, this is {} at {}",
                h.unit, h.site, cfg.unit.id, cfg.unit.site
            )),
            other => other,
        };
        let now = clock.now_s().unwrap_or(0);
        let mut restored: Option<&str> = None;
        let mut lock: Option<String> = None;
        let mut state = match file.load()? {
            Some(s) => {
                if s.site != cfg.unit.site || s.unit != cfg.unit.id {
                    return Err(EngineError(format!(
                        "{}: state of unit {} at site {}, this is {} at {}",
                        file.path().display(),
                        s.unit,
                        s.site,
                        cfg.unit.id,
                        cfg.unit.site
                    )));
                }
                s
            }
            None => {
                match &hw {
                    Ok(Some(_)) => {
                        restored = Some(
                            "the state file is missing; floors, deployment sequence, time floor \
                             and chain heads restored from the signed high-water record",
                        );
                    }
                    Ok(None) if !had_records => {}
                    Ok(None) => {
                        lock = Some(
                            "the state file and the high-water record are missing but the \
                             delivery journal has records: the floors and the deployment \
                             sequence cannot be restored completely"
                                .into(),
                        );
                    }
                    Err(e) => {
                        lock = Some(format!(
                            "the state file is missing and the high-water record is not usable \
                             ({e})"
                        ));
                    }
                }
                State::new(&cfg.unit.site, &cfg.unit.id)
            }
        };
        // Legacy (before review L4): name-keyed media entries.
        state.seen_media.clear();
        let mut behind: Vec<serde_json::Value> = Vec::new();
        if let Ok(Some(h)) = &hw {
            behind.extend(h.raise(&mut state));
        }
        for (name, f) in &recorded {
            if let Some(old) = state.raise_floor(name, *f) {
                behind.push(json!({"floor": name, "state": old, "black_box": f}));
            }
        }
        if let Some(why) = &lock {
            if state.locked.is_none() {
                state.locked = Some(Locked {
                    since: now,
                    why: why.clone(),
                });
            }
        }
        let store = Store::open(&cfg.state_dir)?;
        let mut e = Self {
            cfg,
            clock,
            file,
            state,
            store,
            journal,
            findings,
            anchor: None,
            reported: BTreeSet::new(),
            media_cache: std::collections::BTreeMap::new(),
            hw_key,
            hw_written: None,
        };
        e.load_anchor();
        e.journal.note(
            kinds::STARTED,
            json!({"version": env!("CARGO_PKG_VERSION"), "unit": e.cfg.unit.id,
                   "site": e.cfg.unit.site, "trust_version": e.anchor.as_ref().map(|a| a.file().version)}),
        )?;
        match &hw {
            Ok(Some(h)) => e.hw_written = Some(h.clone()),
            Ok(None) => {}
            Err(err) => {
                let r = e.journal.note(
                    kinds::STATE_RESTORED,
                    json!({"why": "the high-water record is not usable", "detail": err}),
                )?;
                e.finding(
                    rules::REFUSED,
                    Severity::High,
                    format!("highwater_invalid: {err}; it is rewritten from the state"),
                    Some(r),
                );
            }
        }
        if let Some(why) = &lock {
            let r = e.journal.note(
                kinds::STATE_RESTORED,
                json!({"why": why, "locked": true, "restored": behind}),
            )?;
            e.finding(
                rules::REFUSED,
                Severity::High,
                format!(
                    "state_lost: {why}; the unit refuses imports and installs until an operator \
                     re-anchors it (robodr-deliverd reanchor)"
                ),
                Some(r),
            );
            e.save()?;
        } else if restored.is_some() || !behind.is_empty() {
            let why = restored.unwrap_or(
                "the state file is behind the high-water record or the delivery journal",
            );
            let r = e.journal.note(
                kinds::STATE_RESTORED,
                json!({"why": why, "restored": behind}),
            )?;
            e.finding(
                rules::REFUSED,
                Severity::High,
                format!("state_restored: {why}"),
                Some(r),
            );
            e.save()?;
        }
        if !e.file.path().exists() || e.hw_written.is_none() {
            e.save()?;
        }
        e.cleanup();
        Ok(e)
    }

    /// Operator re-anchoring after a lost state (review M1): accept the
    /// presented site trust file under the pinned roots and site (as the
    /// unit's anchor, a rotation of it, or a new anchor when none is
    /// left), take its signed `issued_at` as a time floor and its site
    /// floors as they apply at every install, and lift the lock. The
    /// daemon must be stopped (the journal is single-writer).
    pub fn reanchor(&mut self, trust: &std::path::Path) -> R<serde_json::Value> {
        let now = self.sys_now()?;
        let anchor = self.cfg.anchor_path();
        let t = if std::fs::symlink_metadata(&anchor).is_ok() {
            let st = robodr_release::ops::SiteTrust::anchored(
                trust,
                &anchor,
                &self.cfg.trust.roots,
                &self.cfg.unit.site,
                now,
            )
            .map_err(|e| e.to_string())?;
            robodr_release::ops::commit_anchor(&st).map_err(|e| e.to_string())?;
            st.trust
        } else {
            robodr_release::ops::init_anchor(
                trust,
                &anchor,
                &self.cfg.trust.roots,
                &self.cfg.unit.site,
                now,
            )
            .map_err(|e| e.to_string())?
        };
        self.load_anchor();
        let was = self.state.locked.take();
        self.state.time_floor = self.state.time_floor.max(t.file().issued_at);
        self.save()?;
        let v = json!({"trust_version": t.file().version, "trust_digest": t.digest,
                       "was_locked": was.as_ref().map(|l| l.why.clone()),
                       "time_floor": self.state.time_floor,
                       "site_floors": t.file().floors.iter().map(|f| json!({"name": f.name, "min_serial": f.min_serial})).collect::<Vec<_>>()});
        self.journal.note(kinds::REANCHORED, v.clone())?;
        Ok(v)
    }

    fn load_anchor(&mut self) {
        let a = self.cfg.anchor_path();
        let sig = robodr_release::ops::sig_path(&a);
        let doc = robodr_release::fsio::read_capped(&a, robodr_pkg::trust::MAX_TRUST_BYTES);
        let s = robodr_release::fsio::read_capped(&sig, robodr_pkg::sig::MAX_SIGSET_BYTES);
        self.anchor = match (doc, s) {
            (Ok(d), Ok(s)) => {
                verify_trust_anchor(&d, &s, &self.cfg.trust.roots, &self.cfg.unit.site).ok()
            }
            _ => None,
        };
    }

    /// The state (read only).
    pub fn state(&self) -> &State {
        &self.state
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Findings counters.
    pub fn findings_stats(&self) -> crate::findings::Stats {
        self.findings.stats
    }

    /// Close the journal (seal).
    pub fn close(self) -> R<()> {
        Ok(self.journal.close()?)
    }

    /// Write the state; the high-water record first when the baseline
    /// moved, so the record is never behind the state file (review M1).
    fn save(&mut self) -> R<()> {
        let hw = HighWater::of(&self.state);
        if self.hw_written.as_ref() != Some(&hw) {
            highwater::store(&self.cfg.blackbox.dir, &hw, self.hw_key.as_ref())?;
            self.hw_written = Some(hw);
        }
        Ok(self.file.save(&self.state)?)
    }

    fn sys_now(&self) -> R<u64> {
        Ok(self.clock.now_s()?)
    }

    fn eff_now(&self, sys: u64) -> u64 {
        effective_now(self.cfg.trust.clock, sys, self.state.time_floor)
    }

    fn finding(
        &mut self,
        rule: &'static str,
        severity: Severity,
        detail: String,
        evidence: Option<BlackBoxRef>,
    ) {
        self.finding_in(rule, severity, detail, evidence, SafetyState::Unknown);
    }

    fn finding_in(
        &mut self,
        rule: &'static str,
        severity: Severity,
        detail: String,
        evidence: Option<BlackBoxRef>,
        safety: SafetyState,
    ) {
        let now_ms = self.clock.now_ms().unwrap_or(0);
        let trust = self
            .anchor
            .as_ref()
            .map(|a| (a.file().version, a.digest.clone()));
        let f = Finding {
            rule,
            severity,
            detail,
            safety,
            evidence,
        };
        // A finding that cannot be spooled is still in the black box
        // (the note it references); the counters show the loss.
        let _ = self
            .findings
            .emit(&f, trust.as_ref().map(|(v, d)| (*v, d.as_str())), now_ms);
    }

    fn installer(&self) -> Installer<'_> {
        Installer {
            cfg: &self.cfg,
            store: &self.store,
        }
    }

    /// Remove import leftovers and packs no deployment refers to.
    fn cleanup(&mut self) {
        let _ = crate::fsx::remove_any(&self.cfg.state_dir.join("import"));
        let keep = self.state.deployment.as_ref().map(|d| d.pack.clone());
        if let Ok(rd) = std::fs::read_dir(self.cfg.state_dir.join("packs")) {
            for e in rd.flatten() {
                if Some(e.file_name().to_string_lossy().into_owned()) != keep {
                    let _ = crate::fsx::remove_any(&e.path());
                }
            }
        }
    }

    /// One reconcile pass (see the module docs).
    pub fn tick(&mut self) -> R<TickReport> {
        let mut rep = TickReport::default();
        let sys = self.sys_now()?;
        if let Some(l) = &self.state.locked {
            // Fail closed (review M1): nothing is imported, installed or
            // rolled back until an operator re-anchors the unit.
            rep.deferred = Some(format!("locked: {} (robodr-deliverd reanchor)", l.why));
            self.check_stale(sys, &mut rep)?;
            return Ok(rep);
        }
        if let Some(t) = self.state.txn.clone() {
            self.resume(t, &mut rep)?;
            return Ok(rep);
        }
        self.scan_media(sys, &mut rep)?;
        self.work(sys, &mut rep)?;
        self.check_stale(sys, &mut rep)?;
        Ok(rep)
    }

    // ------------------------------------------------------------ media --

    /// The content digest of the pack at `path` (review L4), recomputed
    /// only when its tree stamp changed since the last pass. `None`: not
    /// readable now (looked at again next pass).
    fn pack_key(&mut self, name: &str, path: &std::path::Path) -> Option<String> {
        let stamp = media::pack_stamp(path)?;
        if let Some((s, d)) = self.media_cache.get(name) {
            if *s == stamp {
                return Some(d.clone());
            }
        }
        // A pack beyond the walk's bounds is keyed by its stamp: the
        // import refuses its layout anyway.
        let digest = media::pack_digest(path).unwrap_or_else(|| stamp.clone());
        if self.media_cache.len() >= 4 * crate::state::MAX_SEEN_MEDIA {
            self.media_cache.clear();
        }
        self.media_cache
            .insert(name.to_string(), (stamp, digest.clone()));
        Some(digest)
    }

    fn scan_media(&mut self, sys: u64, rep: &mut TickReport) -> R<()> {
        for (name, path) in media::list_media(&self.cfg.media_dir) {
            let Some(key) = self.pack_key(&name, &path) else {
                continue;
            };
            if self.state.seen_pack(&key) {
                continue;
            }
            match media::import(&self.cfg, &self.state, &path, sys) {
                Ok(Outcome::AlreadyAccepted) => {
                    self.state.see_pack(&key, &name);
                    self.save()?;
                }
                Ok(Outcome::Imported(imp)) => self.accept_pack(&name, &key, *imp, rep)?,
                Err(r) if r.transient => {
                    let k = format!("{name}:{}", r.detail);
                    if self.reported.insert(k) {
                        self.journal.note(
                            kinds::REFUSED,
                            json!({"stage": "import", "media": name, "transient": true,
                                   "code": r.code.as_str(), "detail": r.detail}),
                        )?;
                    }
                }
                Err(r) => {
                    let ev = self.journal.note(
                        kinds::REFUSED,
                        json!({"stage": "import", "media": name, "code": r.code.as_str(),
                               "detail": r.detail}),
                    )?;
                    let (rule, sev) = if r.stale {
                        (rules::STALE, Severity::High)
                    } else if r.chain {
                        (rules::CHAIN_GAP, Severity::High)
                    } else {
                        (rules::REFUSED, Severity::High)
                    };
                    self.finding(
                        rule,
                        sev,
                        format!("{}: {}", r.code.as_str(), r.detail),
                        Some(ev),
                    );
                    rep.refused.push(format!("{name}: {r}"));
                    self.state.see_pack(&key, &name);
                    self.save()?;
                }
            }
        }
        Ok(())
    }

    fn accept_pack(
        &mut self,
        media_name: &str,
        pack_key: &str,
        imp: media::Imported,
        rep: &mut TickReport,
    ) -> R<()> {
        if robodr_release::ops::commit_anchor(&imp.trust).map_err(|e| e.to_string())? {
            let a = &imp.trust.trust;
            self.journal.note(
                kinds::TRUST_ROTATED,
                json!({"version": a.file().version, "digest": a.digest}),
            )?;
        }
        self.load_anchor();
        let d = &imp.deployment.deployment;
        let old_pack = self.state.deployment.as_ref().map(|x| x.pack.clone());
        self.state.last_deployment = Some(LastDeployment {
            seq: d.deployment_seq,
            digest: imp.deployment.digest.clone(),
            expires_at: d.expires_at,
        });
        for h in &imp.heads {
            self.state.set_chain(h.clone());
        }
        self.state.time_floor = self.state.time_floor.max(imp.time_floor);
        self.state.deployment = Some(ActiveDeployment {
            id: d.deployment_id.clone(),
            seq: d.deployment_seq,
            digest: imp.deployment.digest.clone(),
            pack: imp.pack.clone(),
            ring: imp.ring.clone(),
            expires_at: d.expires_at,
            maintenance_window: d.maintenance_window.clone(),
            items: d
                .items
                .iter()
                .map(|i| Item {
                    name: i.name.clone(),
                    serial: i.serial,
                    digest: i.rpk_digest.clone(),
                    status: ItemStatus::Pending,
                    deferrals: 0,
                    last_deferral: None,
                    ver: None,
                })
                .collect(),
        });
        self.state.see_pack(pack_key, media_name);
        if self.state.stale.is_some() && self.eff_now(self.sys_now()?) < d.expires_at {
            self.state.stale = None;
        }
        self.save()?;
        if let Some(p) = old_pack.filter(|p| p != &imp.pack) {
            let _ = crate::fsx::remove_any(&self.cfg.state_dir.join("packs").join(p));
        }
        let ev = self.journal.note(
            kinds::PACK_IMPORTED,
            json!({"media": media_name, "pack": imp.pack, "deployment_id": d.deployment_id,
                   "deployment_seq": d.deployment_seq, "deployment_digest": imp.deployment.digest,
                   "ring": imp.ring, "judged_at": imp.now,
                   "signers": imp.deployment.signers.0.iter().map(|(r, f)| format!("{}:{f}", r.as_str())).collect::<Vec<_>>(),
                   "trust_version": imp.trust.trust.file().version,
                   "items": d.items.iter().map(|i| json!({"name": i.name, "serial": i.serial, "digest": i.rpk_digest})).collect::<Vec<_>>(),
                   "bundles": imp.bundles}),
        )?;
        for b in imp.bundles.iter().filter(|b| b.step == "gap") {
            let ev2 = self.journal.note(
                kinds::CHAIN,
                json!({"programme": b.programme, "gap_after": b.after, "seq": b.seq}),
            )?;
            self.finding(
                rules::CHAIN_GAP,
                Severity::High,
                format!(
                    "chain_gap: bundle {} of {} after {}: bundles in between were never seen here",
                    b.seq,
                    b.programme,
                    b.after.unwrap_or(0)
                ),
                Some(ev2),
            );
        }
        let _ = ev;
        rep.imported.push(imp.pack);
        Ok(())
    }

    // ------------------------------------------------------------- items --

    fn work(&mut self, sys: u64, rep: &mut TickReport) -> R<()> {
        let Some(dep) = self.state.deployment.clone() else {
            return Ok(());
        };
        let now = self.eff_now(sys);
        if now >= dep.expires_at {
            let mut changed = false;
            for i in 0..dep.items.len() {
                if dep.items[i].status == ItemStatus::Pending {
                    if let Some(d) = self.state.deployment.as_mut() {
                        d.items[i].status = ItemStatus::Refused;
                        changed = true;
                    }
                    let ev = self.journal.note(
                        kinds::REFUSED,
                        json!({"stage": "install", "name": dep.items[i].name, "serial": dep.items[i].serial,
                               "code": "expired", "detail": "the deployment expired before the item was installed"}),
                    )?;
                    self.finding(
                        rules::REFUSED,
                        Severity::High,
                        format!(
                            "expired: {} {}: the deployment expired before it was installed",
                            dep.items[i].name, dep.items[i].serial
                        ),
                        Some(ev),
                    );
                }
            }
            if changed {
                self.save()?;
            }
            return Ok(());
        }
        let pending: Vec<usize> = (0..dep.items.len())
            .filter(|i| dep.items[*i].status == ItemStatus::Pending)
            .collect();
        let Some(&idx) = pending.first() else {
            return Ok(());
        };
        // Dependencies first: an item whose requirement is another pending
        // item of this deployment waits for it.
        let mut order = pending.clone();
        let deps_pending = |i: usize, e: &Self| -> bool {
            let Some(m) = e.store.manifest(&dep.items[i].digest).ok() else {
                return false;
            };
            m.requires.iter().any(|r| {
                pending
                    .iter()
                    .any(|j| *j != i && dep.items[*j].name == r.name)
            })
        };
        order.sort_by_key(|i| deps_pending(*i, self));
        let pick = order.first().copied().unwrap_or(idx);
        self.item(pick, sys, rep)
    }

    fn set_item<F: FnOnce(&mut Item)>(&mut self, idx: usize, f: F) {
        if let Some(d) = self.state.deployment.as_mut() {
            if let Some(i) = d.items.get_mut(idx) {
                f(i);
            }
        }
    }

    fn refuse_item(
        &mut self,
        idx: usize,
        code: &str,
        detail: String,
        rep: &mut TickReport,
    ) -> R<()> {
        let (name, serial) = self
            .state
            .deployment
            .as_ref()
            .and_then(|d| d.items.get(idx))
            .map(|i| (i.name.clone(), i.serial))
            .unwrap_or_default();
        self.set_item(idx, |i| i.status = ItemStatus::Refused);
        self.save()?;
        let ev = self.journal.note(
            kinds::REFUSED,
            json!({"stage": "install", "name": name, "serial": serial, "code": code, "detail": detail}),
        )?;
        self.finding(
            rules::REFUSED,
            Severity::High,
            format!("{code}: {name} {serial}: {detail}"),
            Some(ev),
        );
        rep.refused
            .push(format!("{name} {serial}: {code}: {detail}"));
        Ok(())
    }

    fn item(&mut self, idx: usize, sys: u64, rep: &mut TickReport) -> R<()> {
        let Some(dep) = self.state.deployment.clone() else {
            return Ok(());
        };
        let Some(it) = dep.items.get(idx).cloned() else {
            return Ok(());
        };
        let pack_dir = self.cfg.state_dir.join("packs").join(&dep.pack);
        // 1. Into the store, from the verified copy.
        let m = if self.store.has_rpk(&it.digest) {
            self.store.manifest(&it.digest)?
        } else {
            let Some(src) = media::find_rpk(&pack_dir, &it.digest) else {
                return self.refuse_item(
                    idx,
                    "missing_file",
                    "the RPK is no longer in the imported pack".into(),
                    rep,
                );
            };
            match self.store.put_rpk(&src, &it.digest) {
                Ok(m) => m,
                Err(e) => return self.refuse_item(idx, "file_mismatch", e, rep),
            }
        };
        // Already the installed, healthy version.
        if self
            .state
            .installed
            .get(&it.name)
            .is_some_and(|i| i.ver.digest == it.digest && i.healthy)
        {
            self.set_item(idx, |i| i.status = ItemStatus::Installed);
            self.save()?;
            return Ok(());
        }
        // The same serial with other content (a release re-signed into
        // another manifest): refused while a version of that serial is
        // installed, kept as a rollback target (review M4) or part of a
        // switch, so a serial always names one content on this unit.
        if let Some(role) = self.serial_taken(&it.name, m.version.serial, &it.digest) {
            return self.refuse_item(
                idx,
                "equivocation",
                format!("serial {} is {role} with other content", m.version.serial),
                rep,
            );
        }
        // 2. Policy at the moment of use: floors (unit and site),
        // revocations, the unit checks.
        if let Some(a) = &self.anchor {
            if a.is_rpk_revoked(&it.digest) || a.is_serial_revoked(&m.name, m.version.serial) {
                return self.refuse_item(
                    idx,
                    "revoked_rpk",
                    "revoked by the site trust file".into(),
                    rep,
                );
            }
            if m.version.serial < a.floor(&m.name) {
                return self.refuse_item(
                    idx,
                    "below_floor",
                    format!("below the site floor {}", a.floor(&m.name)),
                    rep,
                );
            }
        }
        let others: Vec<(String, u64)> = dep
            .items
            .iter()
            .filter(|x| {
                x.name != it.name
                    && x.status != ItemStatus::Refused
                    && x.status != ItemStatus::Failed
            })
            .map(|x| (x.name.clone(), x.serial))
            .collect();
        if let Err(r) = media::check_item(&self.cfg, &self.state, &m, &others) {
            return self.refuse_item(idx, r.code.as_str(), r.detail, rep);
        }
        // 3. Stage (once).
        let ver = match it.ver.clone() {
            Some(v) if self.prepared(&it.name, &v) => v,
            _ => {
                let mut v = Ver {
                    serial: m.version.serial,
                    digest: it.digest.clone(),
                    kind: m.kind,
                    deb: None,
                    probe_users: Default::default(),
                };
                for h in &m.health {
                    if let robodr_pkg::rpk::HealthCheck::Probe { user, .. } = h {
                        match crate::users::resolve(&self.cfg, user) {
                            Ok(ids) => {
                                v.probe_users.insert(user.clone(), [ids.uid, ids.gid]);
                            }
                            Err(e) => {
                                return self.refuse_item(
                                    idx,
                                    "invalid",
                                    format!("probe user: {e}"),
                                    rep,
                                )
                            }
                        }
                    }
                }
                match self.installer().prepare(&m, &mut v) {
                    Ok(()) => {}
                    Err(PrepError::Refused(e)) => return self.refuse_item(idx, "invalid", e, rep),
                    Err(PrepError::Io(e)) => {
                        let k = format!("prepare:{}:{e}", it.name);
                        if self.reported.insert(k) {
                            self.journal.note(
                                kinds::REFUSED,
                                json!({"stage": "stage", "name": it.name, "transient": true, "detail": e}),
                            )?;
                        }
                        return Ok(());
                    }
                }
                self.journal.note(
                    kinds::STAGED,
                    json!({"name": it.name, "serial": v.serial, "digest": v.digest,
                           "kind": format!("{:?}", v.kind), "deb": v.deb,
                           "maintainer_scripts_allowed": m.install.allow_maintainer_scripts,
                           "requires_operator_present": m.install.requires_operator_present,
                           "probe_users": v.probe_users}),
                )?;
                let vv = v.clone();
                self.set_item(idx, |i| i.ver = Some(vv));
                self.save()?;
                fault::hit("after_stage")?;
                v
            }
        };
        // 3b. The dpkg identity of a deb (review H2).
        if let Some(d) = &ver.deb {
            if let Some(why) = self.deb_conflict(&it.name, &it.digest, &pack_dir, &ver, d) {
                return self.refuse_item(idx, "invalid", why, rep);
            }
        }
        // 4. The gate. A window is judged only on a time nobody local can
        // set (review L3): with an untrusted clock and no signed time it
        // stays closed.
        if let Some(w) = &dep.maintenance_window {
            match window_time(self.cfg.trust.clock, sys, self.clock.signed_now_s()) {
                None => {
                    return self.defer(idx, "maintenance_window:no_trusted_time".into(), None, rep)
                }
                Some(t) if !in_window(w, t) => {
                    return self.defer(idx, "maintenance_window".into(), None, rep)
                }
                Some(_) => {}
            }
        }
        let confirm = self.confirm_path(&dep.digest, &it.name);
        if m.install.requires_operator_present && !confirm.is_file() {
            return self.defer(idx, "operator_confirmation".into(), None, rep);
        }
        let seen = safety::observe(&self.cfg.safety);
        if !seen.allows_install() {
            return self.defer(
                idx,
                format!("safety_state:{}", state_name(seen.state)),
                Some(seen),
                rep,
            );
        }
        // 5. Re-check immediately before the switch.
        let seen = safety::observe(&self.cfg.safety);
        if !seen.allows_install() {
            return self.defer(
                idx,
                format!("safety_state:{}", state_name(seen.state)),
                Some(seen),
                rep,
            );
        }
        // 6. Intent and floor, durable before anything changes.
        let from = self.state.installed.get(&it.name).map(|i| i.ver.clone());
        let old_floor = self.state.raise_floor(&it.name, m.security_floor);
        self.state.txn = Some(Txn {
            name: it.name.clone(),
            from: from.clone(),
            to: ver.clone(),
            phase: Phase::Activating,
            failure: None,
        });
        self.save()?;
        fault::hit("after_intent")?;
        self.journal.note(
            kinds::ACTIVATING,
            json!({"name": it.name, "from": ver_json(&from), "to": ver_json(&Some(ver.clone())),
                   "deployment": dep.digest, "safety_state": state_name(seen.state),
                   "maintainer_scripts_allowed": m.install.allow_maintainer_scripts}),
        )?;
        if let Some(old) = old_floor {
            self.journal.note(
                kinds::FLOOR_RAISED,
                json!({"name": it.name, "from": old, "to": m.security_floor}),
            )?;
        }
        if m.install.requires_operator_present {
            let _ = std::fs::remove_file(&confirm);
            self.journal.note(
                kinds::CONFIRMED,
                json!({"name": it.name, "deployment": dep.digest}),
            )?;
        }
        // 7. Switch.
        let switched = self.installer().activate(&it.name, &ver, &m);
        fault::hit("after_switch")?;
        let txn = Txn {
            name: it.name.clone(),
            from,
            to: ver,
            phase: Phase::Health,
            failure: None,
        };
        match switched {
            Ok(()) => {
                self.journal.note(
                    kinds::SWITCHED,
                    json!({"name": txn.name, "serial": txn.to.serial}),
                )?;
                self.state.txn = Some(txn.clone());
                self.save()?;
                fault::hit("after_health_intent")?;
                self.judge(txn, &m, seen.state, rep)
            }
            Err(e) => self.failed(txn, format!("switch failed: {e}"), seen.state, rep),
        }
    }

    /// Where serial `serial` of `name` is already on this unit with
    /// another digest than `digest` (installed, kept, or in the intent).
    fn serial_taken(&self, name: &str, serial: u64, digest: &str) -> Option<&'static str> {
        let other = |v: &Ver| v.serial == serial && v.digest != digest;
        if self
            .state
            .installed
            .get(name)
            .is_some_and(|i| other(&i.ver))
        {
            return Some("installed");
        }
        if self
            .state
            .kept
            .get(name)
            .is_some_and(|k| k.iter().any(other))
        {
            return Some("kept as a rollback target");
        }
        if self
            .state
            .txn
            .as_ref()
            .is_some_and(|t| t.name == name && (other(&t.to) || t.from.as_ref().is_some_and(other)))
        {
            return Some("being switched");
        }
        None
    }

    /// Why the staged `.deb` `d` of `name` (RPK `digest`, version `ver`)
    /// may not be installed (review H2), or `None`.
    fn deb_conflict(
        &self,
        name: &str,
        digest: &str,
        pack_dir: &std::path::Path,
        ver: &Ver,
        d: &crate::state::DebInfo,
    ) -> Option<String> {
        // Another RPK name already owns this dpkg package.
        let owned = |v: &Ver| v.deb.as_ref().is_some_and(|x| x.package == d.package);
        if let Some(other) = self
            .state
            .installed
            .iter()
            .find(|(n, i)| n.as_str() != name && owned(&i.ver))
            .map(|(n, _)| n.clone())
            .or_else(|| {
                self.state
                    .kept
                    .iter()
                    .find(|(n, k)| n.as_str() != name && k.iter().any(owned))
                    .map(|(n, _)| n.clone())
            })
        {
            return Some(format!(
                "dpkg package {} belongs to RPK {other} on this unit",
                d.package
            ));
        }
        // Floors apply to the dpkg identity too.
        let floor = self.state.floor(&d.package);
        if ver.serial < floor {
            return Some(format!(
                "dpkg package {} has the floor {floor}; serial {} is below it",
                d.package, ver.serial
            ));
        }
        // A higher serial never carries a lower dpkg version.
        if let Some(i) = self.state.installed.get(name) {
            if let Some(cur) = i.ver.deb.as_ref().filter(|_| ver.serial > i.ver.serial) {
                match self.installer().deb_version_lt(&d.version, &cur.version) {
                    Ok(false) => {}
                    Ok(true) => {
                        return Some(format!(
                            "serial {} carries dpkg version {}, lower than the installed {} \
                             (serial {})",
                            ver.serial, d.version, cur.version, i.ver.serial
                        ))
                    }
                    Err(e) => return Some(e),
                }
            }
        }
        // RoboDR's own packages: only from the designated programme.
        let touched: Vec<&str> = crate::install::ROBODR_PACKAGES
            .iter()
            .copied()
            .filter(|p| d.package == *p || d.relations.iter().any(|r| r == p))
            .collect();
        if !touched.is_empty() {
            let programme = media::programme_of(pack_dir, digest);
            let designated = self.cfg.install.robodr_programme.as_deref();
            if designated.is_none() || programme.as_deref() != designated {
                return Some(format!(
                    "the .deb is, conflicts with, breaks, replaces or provides RoboDR's own \
                     package(s) {} and its bundle's programme ({}) is not the designated RoboDR \
                     programme ({})",
                    touched.join(", "),
                    programme.as_deref().unwrap_or("unknown"),
                    designated.unwrap_or("none configured")
                ));
            }
        }
        None
    }

    fn prepared(&self, name: &str, v: &Ver) -> bool {
        match v.kind {
            robodr_pkg::rpk::Kind::Deb => v.deb.is_some() && self.store.has_rpk(&v.digest),
            k => {
                crate::fsx::is_real_dir(&self.installer().version_dir(k, name, v.serial, &v.digest))
            }
        }
    }

    /// Where `robodr-deliverd confirm` drops an operator confirmation.
    pub fn confirm_path(&self, deployment_digest: &str, name: &str) -> PathBuf {
        confirm_path(&self.cfg, deployment_digest, name)
    }

    fn defer(
        &mut self,
        idx: usize,
        reason: String,
        seen: Option<Observed>,
        rep: &mut TickReport,
    ) -> R<()> {
        let Some(it) = self
            .state
            .deployment
            .as_ref()
            .and_then(|d| d.items.get(idx))
            .cloned()
        else {
            return Ok(());
        };
        let n = it.deferrals.saturating_add(1);
        let changed = it.last_deferral.as_deref() != Some(reason.as_str());
        let r2 = reason.clone();
        self.set_item(idx, |i| {
            i.deferrals = n;
            i.last_deferral = Some(r2);
        });
        self.save()?;
        rep.deferred = Some(format!("{} {}: {reason}", it.name, it.serial));
        let safety_state = seen.as_ref().map_or(SafetyState::Unknown, |s| s.state);
        let ev = if changed {
            Some(self.journal.note(
                kinds::DEFERRED,
                json!({"name": it.name, "serial": it.serial, "reason": reason, "deferrals": n,
                       "safety_state": state_name(safety_state),
                       "why": seen.as_ref().and_then(|s| s.why.clone())}),
            )?)
        } else {
            None
        };
        if seen.is_some() {
            let medium = self.cfg.findings.deferral_medium_after;
            let first_safety = changed;
            if first_safety || n == medium {
                let sev = if n >= medium {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                self.finding_in(
                    rules::DEFERRED_SAFETY,
                    sev,
                    format!(
                        "{} {}: install deferred ({reason}), {n} deferral(s)",
                        it.name, it.serial
                    ),
                    ev,
                    safety_state,
                );
            }
        }
        Ok(())
    }

    fn judge(
        &mut self,
        txn: Txn,
        m: &Manifest,
        safety: SafetyState,
        rep: &mut TickReport,
    ) -> R<()> {
        let report = health::run(&self.cfg, &m.health, &txn.to);
        let ev = self.journal.note(
            kinds::HEALTH,
            json!({"name": txn.name, "serial": txn.to.serial, "passed": report.passed,
                   "checks": report.checks}),
        )?;
        fault::hit("after_health")?;
        if report.passed {
            return self.finish(txn, ev, safety, rep);
        }
        self.failed(txn, report.first_failure(), safety, rep)
    }

    fn finish(
        &mut self,
        txn: Txn,
        ev: BlackBoxRef,
        safety: SafetyState,
        rep: &mut TickReport,
    ) -> R<()> {
        let name = txn.name.clone();
        if let Some(from) = txn.from.clone() {
            if from.digest != txn.to.digest {
                let kept = self.state.kept.entry(name.clone()).or_default();
                kept.retain(|k| k.digest != from.digest && k.digest != txn.to.digest);
                kept.insert(0, from);
            }
        }
        if let Some(k) = self.state.kept.get_mut(&name) {
            k.retain(|x| x.digest != txn.to.digest);
        }
        self.state.installed.insert(
            name.clone(),
            Installed {
                ver: txn.to.clone(),
                healthy: true,
            },
        );
        let dropped = self.trim_kept(&name);
        self.mark_item(&name, &txn.to.digest, ItemStatus::Installed);
        self.state.txn = None;
        self.save()?;
        let ev2 = self.journal.note(
            kinds::INSTALLED,
            json!({"name": name, "serial": txn.to.serial, "digest": txn.to.digest, "health": ev.seq}),
        )?;
        self.finding_in(
            rules::INSTALLED,
            Severity::Low,
            format!("{name} {} installed and healthy", txn.to.serial),
            Some(ev2),
            safety,
        );
        self.drop_versions(&name, dropped);
        rep.installed.push(format!("{name} {}", txn.to.serial));
        Ok(())
    }

    fn trim_kept(&mut self, name: &str) -> Vec<Ver> {
        let keep = self.cfg.install.keep_versions as usize;
        let floor = self.state.floor(name);
        let Some(k) = self.state.kept.get_mut(name) else {
            return Vec::new();
        };
        // Versions below the floor can never run again: not kept.
        let mut dropped: Vec<Ver> = Vec::new();
        let mut i = 0;
        while i < k.len() {
            if k[i].serial < floor || i >= keep {
                dropped.push(k.remove(i));
            } else {
                i += 1;
            }
        }
        dropped
    }

    fn drop_versions(&mut self, name: &str, dropped: Vec<Ver>) {
        for v in &dropped {
            let _ = self.installer().remove(name, v);
        }
        self.gc();
    }

    fn gc(&mut self) {
        let mut keep: BTreeSet<String> = BTreeSet::new();
        for i in self.state.installed.values() {
            keep.insert(i.ver.digest.clone());
        }
        for v in self.state.kept.values().flatten() {
            keep.insert(v.digest.clone());
        }
        if let Some(t) = &self.state.txn {
            keep.insert(t.to.digest.clone());
            if let Some(f) = &t.from {
                keep.insert(f.digest.clone());
            }
        }
        if let Some(d) = &self.state.deployment {
            for i in d.items.iter().filter(|i| i.status == ItemStatus::Pending) {
                keep.insert(i.digest.clone());
            }
        }
        let _ = self.store.gc(&keep);
    }

    fn mark_item(&mut self, name: &str, digest: &str, s: ItemStatus) {
        if let Some(d) = self.state.deployment.as_mut() {
            for i in d.items.iter_mut() {
                if i.name == name && i.digest == digest {
                    i.status = s;
                }
            }
        }
    }

    /// The health gate (or the switch) failed for `txn.to`.
    fn failed(
        &mut self,
        mut txn: Txn,
        why: String,
        safety: SafetyState,
        rep: &mut TickReport,
    ) -> R<()> {
        let floor = self.state.floor(&txn.name);
        let target = txn
            .from
            .clone()
            .filter(|f| f.serial >= floor && self.store.has_rpk(&f.digest));
        let Some(from) = target else {
            let reason = match &txn.from {
                None => "no earlier version on this unit".to_string(),
                Some(f) if f.serial < floor => {
                    format!(
                        "the previous serial {} is below the floor {floor}",
                        f.serial
                    )
                }
                Some(_) => "the previous version is no longer in the store".to_string(),
            };
            self.state.installed.insert(
                txn.name.clone(),
                Installed {
                    ver: txn.to.clone(),
                    healthy: false,
                },
            );
            self.mark_item(&txn.name, &txn.to.digest, ItemStatus::Failed);
            self.state.txn = None;
            self.save()?;
            let ev = self.journal.note(
                kinds::ROLLBACK_BLOCKED,
                json!({"name": txn.name, "serial": txn.to.serial, "floor": floor,
                       "failure": why, "reason": reason}),
            )?;
            self.finding_in(
                rules::ROLLBACK_BLOCKED_FLOOR,
                Severity::Critical,
                format!(
                    "{} {} failed its health gate ({why}); no rollback: {reason}; the unit stays on it until an operator acts",
                    txn.name, txn.to.serial
                ),
                Some(ev),
                safety,
            );
            rep.blocked.push(format!("{} {}", txn.name, txn.to.serial));
            return Ok(());
        };
        txn.phase = Phase::RollingBack;
        txn.failure = Some(why.clone());
        self.state.txn = Some(txn.clone());
        self.save()?;
        let ev = self.journal.note(
            kinds::ROLLBACK,
            json!({"name": txn.name, "phase": "start", "from": txn.to.serial, "to": from.serial,
                   "failure": why}),
        )?;
        self.finding_in(
            rules::HEALTH_FAILED,
            Severity::High,
            format!(
                "{} {} failed its health gate ({why}); automatic rollback to {}",
                txn.name, txn.to.serial, from.serial
            ),
            Some(ev),
            safety,
        );
        fault::hit("after_rollback_intent")?;
        self.rollback(txn, rep)
    }

    fn rollback(&mut self, txn: Txn, rep: &mut TickReport) -> R<()> {
        let Some(from) = txn.from.clone() else {
            return Err(EngineError("rollback without a target".into()));
        };
        let seen = safety::observe(&self.cfg.safety);
        if !seen.allows_install() {
            rep.deferred = Some(format!(
                "rollback of {}: safety_state:{}",
                txn.name,
                state_name(seen.state)
            ));
            let k = format!("rollback-defer:{}:{}", txn.name, state_name(seen.state));
            if self.reported.insert(k) {
                let ev = self.journal.note(
                    kinds::DEFERRED,
                    json!({"name": txn.name, "serial": from.serial, "reason": format!("rollback safety_state:{}", state_name(seen.state)),
                           "safety_state": state_name(seen.state), "why": seen.why}),
                )?;
                self.finding_in(
                    rules::DEFERRED_SAFETY,
                    Severity::Medium,
                    format!(
                        "rollback of {} to {} deferred by the safety state",
                        txn.name, from.serial
                    ),
                    Some(ev),
                    seen.state,
                );
            }
            return Ok(());
        }
        let m = self.store.manifest(&from.digest)?;
        let mut v = from.clone();
        if !self.prepared(&txn.name, &v) {
            if let Err(e) = self.installer().prepare(&m, &mut v) {
                return self.rollback_failed(
                    txn,
                    format!("preparing the rollback target: {e}"),
                    rep,
                );
            }
        }
        if let Err(e) = self.installer().activate(&txn.name, &v, &m) {
            return self.rollback_failed(txn, e, rep);
        }
        fault::hit("after_rollback_switch")?;
        let report = health::run(&self.cfg, &m.health, &v);
        self.state.installed.insert(
            txn.name.clone(),
            Installed {
                ver: v.clone(),
                healthy: report.passed,
            },
        );
        if let Some(k) = self.state.kept.get_mut(&txn.name) {
            k.retain(|x| x.digest != v.digest);
        }
        self.mark_item(&txn.name, &txn.to.digest, ItemStatus::Failed);
        self.state.txn = None;
        self.save()?;
        self.journal.note(
            kinds::ROLLBACK,
            json!({"name": txn.name, "phase": "done", "from": txn.to.serial, "to": v.serial,
                   "health_after": report.passed, "checks": report.checks, "failure": txn.failure}),
        )?;
        // The failed version is not kept.
        let failed = txn.to.clone();
        if failed.digest != v.digest {
            let _ = self.installer().remove(&txn.name, &failed);
        }
        self.gc();
        rep.rolled_back
            .push(format!("{} {} -> {}", txn.name, txn.to.serial, v.serial));
        Ok(())
    }

    fn rollback_failed(&mut self, txn: Txn, why: String, rep: &mut TickReport) -> R<()> {
        self.state.installed.insert(
            txn.name.clone(),
            Installed {
                ver: txn.to.clone(),
                healthy: false,
            },
        );
        self.mark_item(&txn.name, &txn.to.digest, ItemStatus::Failed);
        self.state.txn = None;
        self.save()?;
        let ev = self.journal.note(
            kinds::ROLLBACK_BLOCKED,
            json!({"name": txn.name, "serial": txn.to.serial, "reason": format!("rollback failed: {why}"),
                   "failure": txn.failure}),
        )?;
        self.finding(
            rules::ROLLBACK_BLOCKED_FLOOR,
            Severity::Critical,
            format!(
                "{} {}: rollback failed ({why}); the unit stays on the failing version",
                txn.name, txn.to.serial
            ),
            Some(ev),
        );
        rep.blocked.push(format!("{} {}", txn.name, txn.to.serial));
        Ok(())
    }

    /// Resume an intent left by a crash (or a deferred rollback).
    fn resume(&mut self, mut txn: Txn, rep: &mut TickReport) -> R<()> {
        match txn.phase {
            Phase::RollingBack => {
                if !self.reported.contains(&format!("resumed:{}", txn.name)) {
                    self.reported.insert(format!("resumed:{}", txn.name));
                    self.journal.note(
                        kinds::RECOVERED,
                        json!({"name": txn.name, "phase": "rolling_back", "action": "finish the rollback"}),
                    )?;
                    rep.recovered.push(format!("{} rolling_back", txn.name));
                }
                self.rollback(txn, rep)
            }
            Phase::Health => {
                self.journal.note(
                    kinds::RECOVERED,
                    json!({"name": txn.name, "phase": "health", "action": "judge the health gate again"}),
                )?;
                rep.recovered.push(format!("{} health", txn.name));
                let m = self.store.manifest(&txn.to.digest)?;
                self.judge(txn, &m, SafetyState::Unknown, rep)
            }
            Phase::Activating => {
                let known: Vec<&Ver> = txn.from.iter().chain(std::iter::once(&txn.to)).collect();
                let active = self.installer().active_of(&txn.name, txn.to.kind, &known);
                let from_serial = txn.from.as_ref().map(|f| f.serial);
                match active {
                    Ok(Some(s)) if s == txn.to.serial => {
                        self.journal.note(
                            kinds::RECOVERED,
                            json!({"name": txn.name, "phase": "activating", "observed": s,
                                   "action": "switched before the crash: judge the health gate"}),
                        )?;
                        rep.recovered
                            .push(format!("{} activating->health", txn.name));
                        txn.phase = Phase::Health;
                        self.state.txn = Some(txn.clone());
                        self.save()?;
                        let m = self.store.manifest(&txn.to.digest)?;
                        self.judge(txn, &m, SafetyState::Unknown, rep)
                    }
                    Ok(s) if s == from_serial => {
                        self.state.txn = None;
                        self.save()?;
                        self.journal.note(
                            kinds::RECOVERED,
                            json!({"name": txn.name, "phase": "activating", "observed": s,
                                   "action": "not switched before the crash: retried through the gate"}),
                        )?;
                        rep.recovered
                            .push(format!("{} activating->retry", txn.name));
                        Ok(())
                    }
                    other => {
                        let why = format!(
                            "inconsistent after a crash during the switch (active: {other:?})"
                        );
                        self.journal.note(
                            kinds::RECOVERED,
                            json!({"name": txn.name, "phase": "activating", "observed": format!("{other:?}"),
                                   "action": "roll back"}),
                        )?;
                        rep.recovered
                            .push(format!("{} activating->rollback", txn.name));
                        self.failed(txn, why, SafetyState::Unknown, rep)
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------- stale --

    fn check_stale(&mut self, sys: u64, rep: &mut TickReport) -> R<()> {
        let now = self.eff_now(sys);
        let mut why: Option<String> = None;
        if let Some(a) = &self.anchor {
            if now >= a.file().expires_at {
                why = Some(format!(
                    "the site trust file (version {}) expired at {}: a newer one is due",
                    a.file().version,
                    a.file().expires_at
                ));
            }
        }
        if why.is_none() {
            if let Some(l) = &self.state.last_deployment {
                if now >= l.expires_at {
                    why = Some(format!(
                        "the newest deployment (seq {}) expired at {}: no fresh deployment arrived",
                        l.seq, l.expires_at
                    ));
                }
            }
        }
        let Some(why) = why else {
            if self.state.stale.take().is_some() {
                self.save()?;
                self.journal.note(kinds::STALE, json!({"stale": false}))?;
            }
            return Ok(());
        };
        rep.stale = Some(why.clone());
        let grace = self.cfg.findings.stale_grace_s;
        match self.state.stale.clone() {
            None => {
                self.state.stale = Some(Stale {
                    since: now,
                    high: false,
                    why: why.clone(),
                });
                self.save()?;
                let ev = self.journal.note(
                    kinds::STALE,
                    json!({"stale": true, "why": why, "level": "medium"}),
                )?;
                self.finding(rules::STALE, Severity::Medium, why, Some(ev));
            }
            Some(s) if !s.high && now >= s.since.saturating_add(grace) => {
                self.state.stale = Some(Stale { high: true, ..s });
                self.save()?;
                let ev = self.journal.note(
                    kinds::STALE,
                    json!({"stale": true, "why": why, "level": "high"}),
                )?;
                self.finding(
                    rules::STALE,
                    Severity::High,
                    format!("{why} (for more than {grace} s)"),
                    Some(ev),
                );
            }
            Some(_) => {}
        }
        Ok(())
    }
}

/// Where `robodr-deliverd confirm` drops an operator confirmation for
/// `name` of the deployment `deployment_digest`.
pub fn confirm_path(cfg: &Config, deployment_digest: &str, name: &str) -> PathBuf {
    cfg.state_dir.join("confirm").join(format!(
        "{}-{name}",
        &deployment_digest[..deployment_digest.len().min(64)]
    ))
}
