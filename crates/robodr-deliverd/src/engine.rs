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
use robodr_pkg::trust::VerifiedTrust;
use robodr_responder::SafetyState;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// What one tick did (tests, `once`, logs).
/// `reported` key of the missing-anchor lock (one finding per episode).
const ANCHOR_LOCK: &str = "anchor:locked";

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
    /// SHA-256 of the lease files of media packs already tried this run
    /// (Sprint 14b): a renewed lease in a pack whose deployment is
    /// unchanged is still installed, an unchanged one is not re-read.
    pub(crate) leases_tried: BTreeSet<String>,
    /// Media entry name -> (tree stamp, content digest) of the last pass,
    /// so an unchanged pack is not hashed again (review L4).
    media_cache: std::collections::BTreeMap<String, (String, String)>,
    /// The black-box key, which signs the high-water record.
    hw_key: Box<dyn robodr_blackbox::Signer>,
    /// The high-water record as last written or read.
    hw_written: Option<HighWater>,
    /// The highest record generation known (record, state, journal): the
    /// next write takes the one after it (review M-B).
    hw_gen: u64,
    /// Sealing (13c), when configured.
    sealing: Option<crate::sealing::Sealing>,
    /// Sprint 14b: the TPM NV counter anchoring the high-water record.
    nv: Option<(robodr_seal::tpm::Tpm, u32)>,
    /// The LUKS front end erase uses (`None`: the system's tools).
    luks: Option<std::sync::Arc<robodr_seal::luks::Luks>>,
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
    /// and the high-water record ([`crate::highwater`], reviews M1, M-A,
    /// M-B).
    ///
    /// | state file | high-water record | journal | result |
    /// |---|---|---|---|
    /// | present | valid, current | any | state raised to the record (if behind) |
    /// | present | missing / invalid | has records | **locked** until `reanchor` (High finding) |
    /// | present | missing / invalid | empty | **locked** (an invalid record); a missing one is rewritten |
    /// | missing | valid, current | any | floors, deployment sequence, time floor, chain heads restored (High finding) |
    /// | missing | missing / invalid | has records | **locked** |
    /// | missing | missing | empty | a freshly enrolled unit |
    /// | any | older than the journal's or the state's generation | any | **locked** |
    /// | any | locked | any | **locked** (the lock is part of the signed record) |
    ///
    /// The `floor_raised` notes still in the journal raise the floors in
    /// every case. A locked start writes a record that is locked too, so
    /// deleting the state file again does not lift the lock.
    pub fn open(cfg: Config, clock: Box<dyn Clock>) -> R<Self> {
        crate::fsx::ensure_dir(&cfg.state_dir, 0o700)
            .map_err(|e| format!("{}: {e}", cfg.state_dir.display()))?;
        let had_records = Journal::has_records(&cfg.blackbox.dir);
        let allow_hmac = cfg.blackbox.allow_hmac;
        let hw_kf =
            crate::journal::load_blackbox_key(&cfg.blackbox.key, allow_hmac, "black-box key")?;
        if hw_kf.is_symmetric() {
            eprintln!(
                "robodr-deliverd: warning: black-box key {} is a legacy hmac-sha256 key \
                 (allowed by blackbox.allow_hmac; whoever can verify can also forge): \
                 migrate to ed25519 (OPERATIONS 4.3)",
                cfg.blackbox.key.display()
            );
        }
        let hw_key = hw_kf
            .signer()
            .map_err(|e| format!("black-box key {}: {e}", cfg.blackbox.key.display()))?;
        let history = Journal::history(&cfg.blackbox.dir, hw_key.as_ref());
        let journal = Journal::open_with(
            &cfg.blackbox.dir,
            &cfg.unit.id,
            &cfg.blackbox.key,
            allow_hmac,
        )?;
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
        let loaded = file.load()?;
        let state_present = loaded.is_some();
        let mut state = match loaded {
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
            None => State::new(&cfg.unit.site, &cfg.unit.id),
        };
        let state_gen = state.hw_generation;
        match &hw {
            Ok(Some(h)) => {
                // Review M-B: an older copy of the record put back.
                let newest = history.hw_generation.max(state_gen);
                if h.generation < newest {
                    lock = Some(format!(
                        "the high-water record is generation {}, older than the generation {} \
                         the {} recorded: an older copy was put back",
                        h.generation,
                        newest,
                        if history.hw_generation >= state_gen {
                            "delivery journal"
                        } else {
                            "state file"
                        }
                    ));
                } else if let Some(l) = &h.locked {
                    // Review M-A: the lock is part of the signed record.
                    lock = Some(l.why.clone());
                } else if !state_present {
                    restored = Some(
                        "the state file is missing; floors, deployment sequence, time floor \
                         and chain heads restored from the signed high-water record",
                    );
                }
            }
            Ok(None) if !had_records && !state_present => {}
            Ok(None) if !had_records => {
                // A state file with no journal at all: the record is
                // written from it (a unit set up before the record).
            }
            Ok(None) => {
                lock = Some(if state_present {
                    "the high-water record is missing while the state file and the delivery \
                     journal exist: the state file cannot be shown to be current"
                        .into()
                } else {
                    "the state file and the high-water record are missing but the delivery \
                     journal has records: the floors and the deployment sequence cannot be \
                     restored completely"
                        .into()
                });
            }
            Err(e) => {
                lock = Some(format!(
                    "the high-water record is not usable ({}); the {} cannot be shown to be \
                     current",
                    robodr_pkg::common::trunc(e),
                    if state_present {
                        "state file"
                    } else {
                        "baseline"
                    }
                ));
            }
        }
        // Sprint 14b: the high-water record against the TPM NV counter.
        let nv = match cfg
            .seal
            .as_ref()
            .and_then(|s| s.anti_rollback_nv.as_ref().map(|i| (s, i)))
        {
            None => None,
            Some((s, i)) => {
                let t = s
                    .tpm
                    .as_ref()
                    .ok_or_else(|| EngineError("seal.anti_rollback_nv needs seal.tpm".into()))?;
                let tpm = robodr_seal::tpm::Tpm::new(
                    t.tpm_config().map_err(EngineError)?,
                    Box::new(robodr_seal::cmd::System),
                )
                .map_err(|e| EngineError(e.to_string()))?;
                let idx = robodr_seal::unit::parse_handle(i, 0x01)
                    .map_err(|e| EngineError(e.to_string()))?;
                Some((tpm, idx))
            }
        };
        let mut migrate = false;
        if let Some((tpm, idx)) = &nv {
            use robodr_seal::nvcounter::{judge, Verdict};
            let rec_nv = hw.as_ref().ok().and_then(Option::as_ref).and_then(|h| h.nv);
            let why = match tpm.counter(*idx) {
                Err(e) => Some(format!("the anti-rollback NV counter is unreadable: {e}")),
                Ok(c) => match judge(rec_nv, c) {
                    Verdict::Current => None,
                    Verdict::Migrate => {
                        migrate = true;
                        None
                    }
                    Verdict::CompleteIncrement => tpm
                        .increment_counter(*idx)
                        .err()
                        .map(|e| format!("the anti-rollback NV counter: {e}")),
                    Verdict::Locked(w) => Some(format!("anti-rollback NV counter: {w}")),
                },
            };
            if let Some(w) = why {
                lock.get_or_insert(w);
            }
        }
        // Legacy (before review L4): name-keyed media entries.
        state.seen_media.clear();
        let mut behind: Vec<serde_json::Value> = Vec::new();
        if let Ok(Some(h)) = &hw {
            behind.extend(h.raise(&mut state));
        }
        for (name, f) in &history.floors {
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
        let hw_gen = history.hw_generation.max(state_gen).max(
            hw.as_ref()
                .ok()
                .and_then(Option::as_ref)
                .map_or(0, |h| h.generation),
        );
        let store = Store::open(&cfg.state_dir)?;
        let cfg_seal = cfg
            .seal
            .as_ref()
            .map(|s| crate::sealing::Sealing::new(s, &cfg.unit.id));
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
            leases_tried: BTreeSet::new(),
            media_cache: std::collections::BTreeMap::new(),
            sealing: cfg_seal,
            hw_key,
            hw_written: None,
            hw_gen,
            nv,
            luks: None,
        };
        e.load_anchor();
        e.journal.note(
            kinds::STARTED,
            json!({"version": env!("CARGO_PKG_VERSION"), "unit": e.cfg.unit.id,
                   "site": e.cfg.unit.site, "trust_version": e.anchor.as_ref().map(|a| a.file().version),
                   "hw_generation": hw.as_ref().ok().and_then(Option::as_ref).map(|h| h.generation)}),
        )?;
        match &hw {
            Ok(Some(h)) if lock.is_none() && !migrate => e.hw_written = Some(h.clone()),
            Ok(_) => {}
            Err(err) => {
                e.journal.note(
                    kinds::STATE_RESTORED,
                    json!({"why": "the high-water record is not usable", "detail": err}),
                )?;
            }
        }
        if let Some(why) = &lock {
            let r = e.journal.note(
                kinds::STATE_RESTORED,
                json!({"why": why, "locked": true, "restored": behind,
                       "hw_generation": hw.as_ref().ok().and_then(Option::as_ref).map(|h| h.generation),
                       "journal_hw_generation": history.hw_generation,
                       "state_hw_generation": state_gen}),
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
            // The record written now is locked as well (review M-A).
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
        if migrate && lock.is_none() && e.nv.is_some() {
            e.journal.note(
                kinds::ANCHOR_MIGRATED,
                json!({"why": "the high-water record is anchored in the TPM NV counter from now on",
                       "hw_generation": hw.as_ref().ok().and_then(Option::as_ref).map(|h| h.generation)}),
            )?;
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
    ///
    /// Review L-A: the trust file must not be older than the newest
    /// version the delivery journal has seen, and the anti-replay baseline
    /// (the newest accepted deployment, the bundle chain heads, the time
    /// floor) is rebuilt from the journal's notes before the lock is
    /// lifted; it is only ever raised.
    pub fn reanchor(&mut self, trust: &std::path::Path) -> R<serde_json::Value> {
        let now = self.sys_now()?;
        let history = Journal::history(&self.cfg.blackbox.dir, self.hw_key.as_ref());
        let anchor = self.cfg.anchor_path();
        // With an anchor: the presented file must be it or an accepted
        // rotation of it (also across a root-set rotation the anchor
        // recorded); without one: accepted under the pinned roots.
        let (st, pinned_version) = if robodr_release::ops::anchor_exists(&anchor) {
            (
                Some(
                    robodr_release::ops::SiteTrust::anchored(
                        trust,
                        &anchor,
                        &self.cfg.trust.roots,
                        &self.cfg.unit.site,
                        now,
                    )
                    .map_err(|e| format!("{}: {e}", trust.display()))?,
                ),
                0,
            )
        } else {
            let (doc, sig) =
                robodr_release::ops::read_trust_files(trust).map_err(|e| e.to_string())?;
            robodr_pkg::trust::verify_trust_pinned(
                &doc,
                &sig,
                &self.cfg.trust.roots,
                &self.cfg.unit.site,
                now,
            )
            .map_err(|e| format!("{}: {e}", trust.display()))
            .map(|v| (None, v.file().version))?
        };
        let presented_version = st
            .as_ref()
            .map_or(pinned_version, |s| s.trust.file().version);
        if presented_version < history.trust_version {
            return Err(EngineError(format!(
                "{}: trust file version {} is older than version {} the delivery journal has \
                 seen; present the site's current trust file",
                trust.display(),
                presented_version,
                history.trust_version
            )));
        }
        let t = match st {
            Some(st) => {
                robodr_release::ops::commit_anchor(&st).map_err(|e| e.to_string())?;
                st.trust
            }
            None => robodr_release::ops::init_anchor(
                trust,
                &anchor,
                &self.cfg.trust.roots,
                &self.cfg.unit.site,
                now,
            )
            .map_err(|e| e.to_string())?,
        };
        self.load_anchor();
        // Rebuild the anti-replay baseline from the journal (only raises).
        let mut rebuilt = Vec::new();
        if let Some(l) = &history.last_deployment {
            if self
                .state
                .last_deployment
                .as_ref()
                .is_none_or(|x| x.seq < l.seq)
            {
                rebuilt.push(json!({"deployment_seq": l.seq}));
                self.state.last_deployment = Some(l.clone());
            }
        }
        for c in &history.chains {
            if self
                .state
                .chain(&c.programme)
                .is_none_or(|x| x.bundle_seq < c.bundle_seq)
            {
                rebuilt.push(json!({"chain": c.programme, "bundle_seq": c.bundle_seq}));
                self.state.set_chain(c.clone());
            }
        }
        for (name, f) in &history.floors {
            if let Some(old) = self.state.raise_floor(name, *f) {
                rebuilt.push(json!({"floor": name, "state": old, "black_box": f}));
            }
        }
        if history.time_floor > self.state.time_floor {
            rebuilt.push(json!({"time_floor": history.time_floor}));
        }
        let was = self.state.locked.take();
        self.state.time_floor = self
            .state
            .time_floor
            .max(t.file().issued_at)
            .max(history.time_floor);
        self.save()?;
        let v = json!({"trust_version": t.file().version, "trust_digest": t.digest,
                       "was_locked": was.as_ref().map(|l| l.why.clone()),
                       "time_floor": self.state.time_floor,
                       "rebuilt": rebuilt,
                       "last_deployment_seq": self.state.last_deployment.as_ref().map(|l| l.seq),
                       "hw_generation": self.hw_gen,
                       "site_floors": t.file().floors.iter().map(|f| json!({"name": f.name, "min_serial": f.min_serial})).collect::<Vec<_>>()});
        self.journal.note(kinds::REANCHORED, v.clone())?;
        Ok(v)
    }

    /// Load the trust anchor (through the root-set rotations it recorded,
    /// `robodr_release::ops::read_anchor`). `None` when it is missing or
    /// does not verify: the unit is then locked for imports and installs
    /// ([`Engine::tick`], a High finding) until it loads again.
    fn load_anchor(&mut self) {
        self.anchor = robodr_release::ops::read_anchor(
            &self.cfg.anchor_path(),
            &self.cfg.trust.roots,
            &self.cfg.unit.site,
        )
        .ok();
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
    ///
    /// Every record write takes the next generation and is noted in the
    /// journal (`robodr.deliver.highwater`, with the baseline) right after
    /// it, and the state file carries that generation (review M-B): a crash
    /// in between leaves a record newer than the note or the state, which
    /// is accepted; never an older one.
    fn save(&mut self) -> R<()> {
        let mut hw = HighWater::of(&self.state);
        if !self
            .hw_written
            .as_ref()
            .is_some_and(|w| w.same_baseline(&hw))
        {
            hw.generation = self.hw_gen.saturating_add(1);
            self.store_anchored(&mut hw)?;
            self.hw_gen = hw.generation;
            self.journal.note(
                kinds::HIGHWATER,
                json!({"generation": hw.generation, "digest": hw.digest()?,
                       "locked": hw.locked.is_some(),
                       "last_deployment": hw.last_deployment, "time_floor": hw.time_floor,
                       "chains": hw.chains}),
            )?;
            self.hw_written = Some(hw);
        }
        self.state.hw_generation = self.hw_gen;
        Ok(self.file.save(&self.state)?)
    }

    /// Write the record; with the NV anchor, `nv = T + 1` first and then
    /// the increment ([`robodr_seal::nvcounter`]).
    fn store_anchored(&mut self, hw: &mut HighWater) -> R<()> {
        use robodr_seal::tpm_ident::Counter;
        let Some((tpm, idx)) = &self.nv else {
            return Ok(highwater::store(
                &self.cfg.blackbox.dir,
                hw,
                self.hw_key.as_ref(),
            )?);
        };
        let e = |x: robodr_seal::SealError| EngineError(format!("anti-rollback NV counter: {x}"));
        match tpm.counter(*idx).map_err(e)? {
            Counter::Value(t) => {
                hw.nv = Some(t.saturating_add(1));
                highwater::store(&self.cfg.blackbox.dir, hw, self.hw_key.as_ref())?;
                tpm.increment_counter(*idx).map_err(e)
            }
            Counter::Unwritten => {
                tpm.increment_counter(*idx).map_err(e)?;
                match tpm.counter(*idx).map_err(e)? {
                    Counter::Value(v) => hw.nv = Some(v),
                    _ => {
                        return Err(EngineError(
                            "NV counter unreadable after an increment".into(),
                        ))
                    }
                }
                Ok(highwater::store(
                    &self.cfg.blackbox.dir,
                    hw,
                    self.hw_key.as_ref(),
                )?)
            }
            Counter::Undefined => Err(EngineError(
                "the anti-rollback NV counter is not defined (robodr-seal counter define)".into(),
            )),
        }
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
            sealing: self.sealing.as_ref(),
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
        // Sprint 14b: a pending crypto-erase runs first, locked or not.
        // Until all of it is done (the keys at once; the lockdown when the
        // safety state allows) nothing is imported, stored, unwrapped or
        // installed: no plaintext is produced under keys slated for
        // destruction, nor written into a volume about to be closed.
        if self.state.erase_pending.is_some() {
            self.erase_pending(sys, &mut rep)?;
            if self.state.erase_pending.is_some() {
                rep.deferred
                    .get_or_insert_with(|| "crypto-erase pending".into());
                return Ok(rep);
            }
        }
        if let Some(l) = &self.state.locked {
            // Fail closed (review M1): nothing is imported, installed or
            // rolled back until an operator re-anchors the unit.
            rep.deferred = Some(format!("locked: {} (robodr-deliverd reanchor)", l.why));
            self.check_stale(sys, &mut rep)?;
            return Ok(rep);
        }
        // Review finding (MED): a missing or unverifiable trust anchor
        // used to skip the site's revocations, floors and trust expiry at
        // install. It is a locked state now: nothing is imported, resumed
        // or installed until the anchor loads again (High finding once).
        if self.anchor.is_none() {
            self.load_anchor();
        }
        if self.anchor.is_none() {
            let why = "the site trust anchor is missing or does not verify under the pinned \
                       roots";
            rep.deferred = Some(format!(
                "locked: {why} (robodr-deliverd init-anchor or reanchor)"
            ));
            if self.reported.insert(ANCHOR_LOCK.into()) {
                let ev = self.journal.note(
                    kinds::REFUSED,
                    json!({"stage": "trust_anchor", "detail": why,
                           "anchor": self.cfg.anchor_path()}),
                )?;
                self.finding(
                    rules::REFUSED,
                    Severity::High,
                    format!(
                        "trust_anchor: {why}; the unit refuses imports and installs until it is \
                         restored"
                    ),
                    Some(ev),
                );
            }
            return Ok(rep);
        }
        self.reported.remove(ANCHOR_LOCK);
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
        let max = self.cfg.pack_digest_max_mb.saturating_mul(1024 * 1024);
        let digest = media::pack_digest(path, max).unwrap_or_else(|| stamp.clone());
        if self.media_cache.len() >= 4 * crate::state::MAX_SEEN_MEDIA {
            self.media_cache.clear();
        }
        self.media_cache
            .insert(name.to_string(), (stamp, digest.clone()));
        Some(digest)
    }

    fn scan_media(&mut self, sys: u64, rep: &mut TickReport) -> R<()> {
        for (name, path) in media::list_media(&self.cfg.media_dir) {
            // Sprint 14b: a lease in the pack (whatever the deployment,
            // also in a pack whose deployment was already seen: a lease
            // renewal may come with an unchanged deployment).
            if self.sealing.is_some() {
                if let Err(e) = crate::lan::lease_from_pack(self, &path) {
                    let k = format!("lease-media:{name}:{e}");
                    if self.reported.insert(k) {
                        self.journal.note(
                            kinds::REFUSED,
                            json!({"stage": "lease", "media": name, "detail": e}),
                        )?;
                    }
                }
            }
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
        self.erase_guard()?;
        if robodr_release::ops::commit_anchor(&imp.trust).map_err(|e| e.to_string())? {
            let a = &imp.trust.trust;
            self.journal.note(
                kinds::TRUST_ROTATED,
                json!({"version": a.file().version, "digest": a.digest}),
            )?;
        }
        self.load_anchor();
        let d = &imp.deployment.deployment;
        // This unit's content-key wraps of sealed items (§7.3): kept with
        // the store; another unit's entries are not this unit's business.
        for w in d.wrapped_keys.iter().filter(|w| w.unit == self.cfg.unit.id) {
            if let Some(b) = robodr_seal::from_hex(&w.wrap) {
                self.store.put_wrap(&w.rpk_digest, &b)?;
            }
        }
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
                   "expires_at": d.expires_at, "heads": imp.heads,
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
            for (i, item) in dep.items.iter().enumerate() {
                if item.status == ItemStatus::Pending {
                    let live = self.state.deployment.as_mut();
                    if let Some(x) = live.and_then(|d| d.items.get_mut(i)) {
                        x.status = ItemStatus::Refused;
                        changed = true;
                    }
                    let ev = self.journal.note(
                        kinds::REFUSED,
                        json!({"stage": "install", "name": item.name, "serial": item.serial,
                               "code": "expired", "detail": "the deployment expired before the item was installed"}),
                    )?;
                    self.finding(
                        rules::REFUSED,
                        Severity::High,
                        format!(
                            "expired: {} {}: the deployment expired before it was installed",
                            item.name, item.serial
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
        let pending: Vec<usize> = dep
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.status == ItemStatus::Pending)
            .map(|(i, _)| i)
            .collect();
        let Some(&idx) = pending.first() else {
            return Ok(());
        };
        // Dependencies first: an item whose requirement is another pending
        // item of this deployment waits for it.
        let mut order = pending.clone();
        let deps_pending = |i: usize, e: &Self| -> bool {
            let Some(m) = dep
                .items
                .get(i)
                .and_then(|item| e.store.manifest(&item.digest).ok())
            else {
                return false;
            };
            m.requires.iter().any(|r| {
                pending
                    .iter()
                    .any(|j| *j != i && dep.items.get(*j).is_some_and(|x| x.name == r.name))
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

    /// A sealed item whose content key could not be unwrapped. The TPM
    /// refusing the policy (changed boot measurements, revoked policy) or
    /// an erased unit is `robot.seal.unseal_failed` and refuses the item;
    /// a wrap that does not authenticate is a delivery refusal; an
    /// unreachable TPM is retried.
    fn unseal_failed(
        &mut self,
        idx: usize,
        it: &Item,
        e: robodr_seal::SealError,
        rep: &mut TickReport,
    ) -> R<()> {
        use robodr_seal::ErrorKind as K;
        match e.kind {
            K::PolicyRefused | K::Erased => {
                self.set_item(idx, |i| i.status = ItemStatus::Refused);
                self.save()?;
                let ev = self.journal.note(
                    kinds::UNSEAL_FAILED,
                    json!({"name": it.name, "serial": it.serial, "digest": it.digest,
                           "reason": e.kind.as_str(), "detail": e.detail}),
                )?;
                self.finding(
                    rules::SEAL_UNSEAL_FAILED,
                    Severity::High,
                    format!(
                        "{}: {} {}: the unit could not unseal its content key: {}",
                        e.kind.as_str(),
                        it.name,
                        it.serial,
                        e.detail
                    ),
                    Some(ev),
                );
                rep.refused.push(format!(
                    "{} {}: {}: {}",
                    it.name,
                    it.serial,
                    e.kind.as_str(),
                    e.detail
                ));
                Ok(())
            }
            K::LeaseExpired => {
                // Sprint 14b: the item waits for a lease (the depot renews
                // it over the LAN or in a media pack); reported once per
                // reason.
                let k = format!("lease:{}", e.detail);
                if self.reported.insert(k) {
                    let ev = self.journal.note(
                        kinds::LEASE_EXPIRED,
                        json!({"name": it.name, "serial": it.serial, "detail": e.detail}),
                    )?;
                    self.finding(
                        rules::SEAL_LEASE_EXPIRED,
                        Severity::Medium,
                        format!(
                            "lease_expired: {} {}: sealed payloads are unavailable until the \
                             depot renews the site lease: {}",
                            it.name, it.serial, e.detail
                        ),
                        Some(ev),
                    );
                }
                rep.deferred = Some(format!("{} {}: lease_expired", it.name, it.serial));
                Ok(())
            }
            K::Unauthentic | K::Invalid => self.refuse_item(idx, "unauthentic_key", e.detail, rep),
            K::Unavailable | K::Io => {
                let k = format!("unseal:{}:{}", it.name, e.detail);
                if self.reported.insert(k) {
                    self.journal.note(
                        kinds::REFUSED,
                        json!({"stage": "unseal", "name": it.name, "transient": true, "detail": e.detail}),
                    )?;
                }
                Ok(())
            }
        }
    }

    /// Crypto-erase this unit's sealing keys (§7.6, `robodr-seal`'s
    /// `Unit::erase`): with a TPM the erase epoch moves on (every key
    /// sealed to the unit is dead); without one the runtime volume's
    /// LUKS2 keyslots are wiped (`seal.device`, or `device`). Then the
    /// open runtime volume is locked down (`seal.stop_units` stopped,
    /// `runtime_root` unmounted, `seal.mapper_name` closed or suspended).
    /// Noted in the journal; `robot.seal.erased` (Critical) says exactly
    /// what was destroyed and what was not, and `robot.seal.tamper`
    /// (Critical) comes first when the trigger is a tamper input. An erase
    /// whose essential step failed reports nothing as erased. This is the
    /// operator's direct erase (`robodr-deliverd erase`), not gated here;
    /// triggers go through [`Engine::erase_trigger`] and the responder's
    /// plan.
    pub fn erase(
        &mut self,
        trigger: &str,
        device: Option<&std::path::Path>,
    ) -> R<serde_json::Value> {
        self.erase_with(trigger, device, true, false)
    }

    /// The LUKS front end erase uses ([`Engine::set_luks`], or the
    /// system's `cryptsetup` / `systemctl` / `umount`).
    fn luks(&self) -> std::sync::Arc<robodr_seal::luks::Luks> {
        self.luks
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(robodr_seal::luks::Luks::system()))
    }

    /// Replace the LUKS front end (`cryptsetup`, `systemctl`, `umount`
    /// runner) erase uses: labs and tests without device-mapper.
    pub fn set_luks(&mut self, luks: robodr_seal::luks::Luks) {
        self.luks = Some(std::sync::Arc::new(luks));
    }

    /// The runtime root, if it is a mount point now.
    fn runtime_mount(s: &crate::sealing::Sealing) -> Option<&std::path::Path> {
        robodr_seal::mounts::is_mount_point(&s.cfg.runtime_root)
            .then_some(s.cfg.runtime_root.as_path())
    }

    /// Whether erase has a lockdown to do at all (services to stop, a
    /// mapping to close, a mounted runtime root).
    fn lockdown_configured(s: &crate::sealing::Sealing) -> bool {
        s.cfg.mapper_name.is_some()
            || !s.cfg.stop_units.is_empty()
            || Self::runtime_mount(s).is_some()
    }

    fn erase_with(
        &mut self,
        trigger: &str,
        device: Option<&std::path::Path>,
        announce: bool,
        defer_lockdown: bool,
    ) -> R<serde_json::Value> {
        let s = self
            .sealing
            .clone()
            .ok_or_else(|| EngineError("no seal configuration: nothing to erase".into()))?;
        if trigger == "tamper" && announce {
            let ev = self
                .journal
                .note(kinds::TAMPER, json!({"trigger": trigger}))?;
            self.finding(
                rules::SEAL_TAMPER,
                Severity::Critical,
                "tamper: an enclosure tamper input fired; crypto-erase follows".into(),
                Some(ev),
            );
        }
        let unit = s.unit().map_err(|e| EngineError(e.to_string()))?;
        let device = device.or(s.cfg.device.as_deref());
        let target = robodr_seal::unit::EraseTarget {
            device,
            mapper: s.cfg.mapper_name.as_deref(),
            mount: Self::runtime_mount(&s),
            stop_units: &s.cfg.stop_units,
            defer_lockdown,
        };
        let rep = unit
            .erase(trigger, &self.luks(), &target)
            .map_err(|e| EngineError(format!("erase failed: {e}")))?;
        let v = serde_json::to_value(&rep).map_err(|e| EngineError(e.to_string()))?;
        let ev = self.journal.note(kinds::ERASED, v.clone())?;
        self.finding(
            rules::SEAL_ERASED,
            Severity::Critical,
            erase_summary(&rep),
            Some(ev),
        );
        Ok(v)
    }

    // ----------------------------------------------- executed erase (14b) --

    /// An authenticated erase trigger (the platform's trigger socket,
    /// [`crate::erasex`], or an operator): recorded and planned by the
    /// responder ([`robodr_responder::erase`]). The keys are destroyed now
    /// in every safety state (no actuator is involved); the lockdown of
    /// the runtime volume (stop services, unmount, close) runs now when
    /// the live safety state allows it, otherwise it stays pending (also
    /// across a restart) and a later tick runs it. While anything of the
    /// erase is pending the agent imports, stores and unwraps nothing.
    /// `approvers`: distinct people who approved (0 for a platform input).
    /// Returns what happened.
    pub fn erase_trigger(
        &mut self,
        trigger: robodr_responder::erase::EraseTrigger,
        approvers: u8,
    ) -> R<String> {
        use robodr_responder::erase::{plan_erase, EraseDecision};
        let sys = self.sys_now()?;
        if self.sealing.is_none() {
            return Err(EngineError(
                "no seal configuration: nothing to erase".into(),
            ));
        }
        let seen = safety::observe(&self.cfg.safety);
        let plan = plan_erase(trigger, seen.state, approvers);
        let ev = self.journal.note(
            kinds::ERASE_PLANNED,
            json!({"trigger": trigger.as_str(), "plan": plan, "why_unknown": seen.why}),
        )?;
        if trigger == robodr_responder::erase::EraseTrigger::Tamper {
            self.finding_in(
                rules::SEAL_TAMPER,
                Severity::Critical,
                "tamper: an enclosure tamper input fired; crypto-erase is planned".into(),
                Some(ev),
                seen.state,
            );
        }
        if let EraseDecision::AwaitApproval { persons } = plan.decision {
            return Ok(format!(
                "awaiting the approval of {persons} different people"
            ));
        }
        if self.state.erase_pending.is_none() {
            self.state.erase_pending = Some(crate::state::PendingErase {
                trigger: trigger.as_str().into(),
                since: sys,
                deferrals: 0,
                last_state: String::new(),
                keys_destroyed: None,
                escalated: false,
            });
            self.save()?;
        }
        let mut rep = TickReport::default();
        self.erase_pending(sys, &mut rep)?;
        Ok(match &self.state.erase_pending {
            None => "erased".into(),
            Some(p) if p.keys_destroyed.is_some() => {
                format!("keys destroyed; lockdown deferred ({})", p.last_state)
            }
            Some(p) => format!("pending ({})", p.last_state),
        })
    }

    /// Refuse while a crypto-erase is pending (imports, wrap stores,
    /// unwraps): nothing new is decrypted under keys slated for
    /// destruction, nor written into the volume about to be closed.
    fn erase_guard(&self) -> R<()> {
        match &self.state.erase_pending {
            None => Ok(()),
            Some(p) => Err(EngineError(format!(
                "a crypto-erase ({}) is pending: nothing is imported, stored or unwrapped",
                p.trigger
            ))),
        }
    }

    /// Run a pending erase: the keys at once, in every safety state; the
    /// lockdown if the responder's plan says so in the live safety state,
    /// re-read immediately before acting (executor rule 4). A lockdown
    /// deferred past `erase.max_lockdown_deferral_s` escalates once (High).
    fn erase_pending(&mut self, sys: u64, rep: &mut TickReport) -> R<()> {
        use robodr_responder::erase::{lockdown_overdue, plan_erase, EraseDecision, EraseTrigger};
        let Some(p) = self.state.erase_pending.clone() else {
            return Ok(());
        };
        let Some(trigger) = EraseTrigger::parse(&p.trigger) else {
            self.state.erase_pending = None;
            return self.save();
        };
        let Some(s) = self.sealing.clone() else {
            rep.deferred = Some("erase pending: no seal configuration".into());
            return Ok(());
        };
        // The pending erase was approved when it was recorded.
        let approvers = if trigger.needs_two_persons() { 2 } else { 0 };
        let seen = safety::observe(&self.cfg.safety);
        let plan = plan_erase(trigger, seen.state, approvers);
        let st = state_name(seen.state).to_string();
        let lockdown_now = plan.decision == EraseDecision::Execute;
        // 1. The keys: no actuator involved, in every safety state.
        if p.keys_destroyed.is_none() {
            self.journal.note(
                kinds::ERASE_INTENT,
                json!({"trigger": p.trigger, "state": st, "since": p.since, "at": sys,
                       "lockdown": if lockdown_now { "now" } else { "deferred" }}),
            )?;
            let v = self.erase_with(&p.trigger, None, false, !lockdown_now)?;
            // Read back: the epoch moved on (TPM), or the keyslots are gone.
            let destroyed = v
                .get("destroyed")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            if destroyed == 0 {
                rep.deferred = Some("erase: nothing destroyed; tried again".into());
                return Err(EngineError("erase destroyed nothing".into()));
            }
            if lockdown_now || !Self::lockdown_configured(&s) {
                self.state.erase_pending = None;
                return self.save();
            }
            if let Some(x) = self.state.erase_pending.as_mut() {
                x.keys_destroyed = Some(sys);
            }
            self.save()?;
        } else if lockdown_now {
            // 2. The deferred lockdown. Executor rule 4: the state again,
            // immediately before acting.
            let again = safety::observe(&self.cfg.safety);
            if again.state != seen.state {
                rep.deferred =
                    Some("erase lockdown: the safety state changed; judged again".into());
                return Ok(());
            }
            self.journal.note(
                kinds::ERASE_INTENT,
                json!({"trigger": p.trigger, "state": state_name(again.state), "since": p.since,
                       "at": sys, "lockdown": "now"}),
            )?;
            let l = self.luks().lockdown(
                &s.cfg.stop_units,
                Self::runtime_mount(&s),
                s.cfg.mapper_name.as_deref(),
            );
            self.journal.note(
                kinds::ERASE_LOCKDOWN,
                json!({"trigger": p.trigger, "lockdown": l, "keys_destroyed": p.keys_destroyed,
                       "volume_locked": l.volume_locked()}),
            )?;
            self.state.erase_pending = None;
            return self.save();
        }
        // 3. The lockdown waits: noted once per state, escalated once.
        let until = match &plan.decision {
            EraseDecision::DestroyKeysDeferLockdown { until } => until.clone(),
            _ => String::new(),
        };
        let p = self.state.erase_pending.clone().unwrap_or(p);
        if p.last_state != st {
            let ev = self.journal.note(
                kinds::ERASE_DEFERRED,
                json!({"trigger": p.trigger, "state": st, "until": until,
                       "why_unknown": seen.why, "since": p.since,
                       "keys_destroyed": p.keys_destroyed}),
            )?;
            self.finding_in(
                rules::SEAL_ERASE_DEFERRED,
                Severity::Medium,
                format!(
                    "erase_deferred: crypto-erase ({}): keys destroyed; the lockdown of the \
                     runtime volume (stop services, unmount, close) is deferred in safety state \
                     {st}: it runs as soon as the state is {until}",
                    p.trigger
                ),
                Some(ev),
                seen.state,
            );
            if let Some(x) = self.state.erase_pending.as_mut() {
                x.last_state = st.clone();
                x.deferrals = x.deferrals.saturating_add(1);
            }
            self.save()?;
        }
        let max = self.cfg.erase.as_ref().map_or(
            robodr_responder::erase::DEFAULT_MAX_LOCKDOWN_DEFERRAL_S,
            |e| e.max_lockdown_deferral_s,
        );
        let waited = sys.saturating_sub(p.keys_destroyed.unwrap_or(sys));
        if !p.escalated && lockdown_overdue(waited, max) {
            let ev = self.journal.note(
                kinds::ERASE_DEFERRED,
                json!({"trigger": p.trigger, "state": st, "until": until, "overdue": true,
                       "waited_s": waited, "max_s": max}),
            )?;
            self.finding_in(
                rules::SEAL_ERASE_DEFERRED,
                Severity::High,
                format!(
                    "erase_deferred: crypto-erase ({}): the runtime volume lockdown has waited \
                     {waited} s (cap {max} s) in safety state {st}; the keys are destroyed but \
                     the open volume's plaintext stays readable until the robot is {until}",
                    p.trigger
                ),
                Some(ev),
                seen.state,
            );
            if let Some(x) = self.state.erase_pending.as_mut() {
                x.escalated = true;
            }
            self.save()?;
        }
        rep.deferred = Some(format!("erase lockdown deferred: {st}"));
        Ok(())
    }

    /// A refused erase trigger (not a feeder, malformed): noted, nothing
    /// planned.
    pub fn note_refused_trigger(&mut self, uid: Option<u32>, why: &str) {
        let _ = self.journal.note(
            kinds::REFUSED,
            json!({"stage": "erase_trigger", "uid": uid, "detail": why}),
        );
    }

    // --------------------------------------------- reports, leases (14a) --

    /// This unit's install report (Sprint 14a), signed by its identity key
    /// (TPM-resident for a TPM unit, [`robodr_seal::report`]).
    pub fn unit_report(&self) -> R<Vec<u8>> {
        use robodr_seal::report::*;
        let s = self
            .sealing
            .as_ref()
            .ok_or_else(|| EngineError("reports need the seal configuration".into()))?;
        let u = s.unit().map_err(|e| EngineError(e.to_string()))?;
        let (resets, clock) = match u.record().mode {
            robodr_seal::unit::Mode::Tpm => {
                let t = u.tpm_time().map_err(|e| EngineError(e.to_string()))?;
                (t.reset_count, t.clock)
            }
            robodr_seal::unit::Mode::Fallback => (0, 0),
        };
        let d = self.state.deployment.as_ref();
        let mut items: Vec<ReportItem> = d
            .map(|d| {
                d.items
                    .iter()
                    .map(|i| ReportItem {
                        name: i.name.clone(),
                        serial: i.serial,
                        rpk_digest: i.digest.clone(),
                        status: match i.status {
                            ItemStatus::Pending => ItemState::Pending,
                            ItemStatus::Installed => ItemState::Installed,
                            ItemStatus::Failed => ItemState::Failed,
                            ItemStatus::Refused => ItemState::Refused,
                        },
                        deferrals: i.deferrals,
                    })
                    .collect()
            })
            .unwrap_or_default();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        let installed = self
            .state
            .installed
            .iter()
            .map(|(n, i)| InstalledItem {
                name: n.clone(),
                serial: i.ver.serial,
                rpk_digest: i.ver.digest.clone(),
                healthy: i.healthy,
            })
            .collect();
        let mut r = UnitReport {
            format: REPORT_FORMAT.into(),
            site: self.cfg.unit.site.clone(),
            unit: self.cfg.unit.id.clone(),
            reported_at: self.sys_now()?,
            tpm_resets: resets,
            tpm_clock: clock,
            deployment_id: d.map(|d| d.id.clone()),
            deployment_seq: d.map_or(0, |d| d.seq),
            deployment_digest: d.map(|d| d.digest.clone()),
            items,
            installed,
            erased: u.is_erased(),
            time: None,
        };
        // TPM units: the TPM's own attestation of its time, for this
        // report (the depot bases leases on it; 14b review). Also after an
        // erase: the AK is intact, and the depot accepts no TPM unit's
        // report, erased or not, without it.
        if u.record().mode == robodr_seal::unit::Mode::Tpm {
            let d = r.time_digest().map_err(|e| EngineError(e.to_string()))?;
            r.time = Some(u.time_attest(&d).map_err(|e| EngineError(e.to_string()))?);
        }
        r.sign(&|dg| u.sign_digest(dg))
            .map_err(|e| EngineError(e.to_string()))
    }

    /// Install a site lease from the depot (Sprint 14b): verified by the
    /// seal directory against the enrolled lease key; noted.
    pub fn install_lease(&mut self, bytes: &[u8]) -> R<()> {
        let s = self
            .sealing
            .as_ref()
            .ok_or_else(|| EngineError("no seal configuration".into()))?;
        let u = s.unit().map_err(|e| EngineError(e.to_string()))?;
        match u.install_lease(bytes) {
            Ok(l) => {
                self.journal.note(
                    kinds::LEASE_INSTALLED,
                    json!({"lease_seq": l.lease_seq, "clock_before": l.clock_before,
                           "resets_max": l.resets_max}),
                )?;
                // Sealed items waiting for a lease are tried again.
                self.reported.retain(|k| !k.starts_with("lease:"));
                Ok(())
            }
            Err(e) => {
                self.journal.note(
                    kinds::REFUSED,
                    json!({"stage": "lease", "detail": e.to_string()}),
                )?;
                Err(EngineError(format!("lease refused: {e}")))
            }
        }
    }

    fn item(&mut self, idx: usize, sys: u64, rep: &mut TickReport) -> R<()> {
        self.erase_guard()?;
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
        // revocations, the unit checks. Never without the anchor (the
        // tick is locked then; this is the backstop).
        let Some(a) = self.anchor.as_ref() else {
            return Err(EngineError(
                "no verified trust anchor: the site's revocations and floors cannot be checked"
                    .into(),
            ));
        };
        let floor = a.floor(&m.name);
        if a.is_rpk_revoked(&it.digest) || a.is_serial_revoked(&m.name, m.version.serial) {
            return self.refuse_item(
                idx,
                "revoked_rpk",
                "revoked by the site trust file".into(),
                rep,
            );
        }
        if m.version.serial < floor {
            return self.refuse_item(
                idx,
                "below_floor",
                format!("below the site floor {floor}"),
                rep,
            );
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
                    sealed: m.is_sealed(),
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
                    Err(PrepError::Unseal(e)) => return self.unseal_failed(idx, &it, e, rep),
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
        // 5b. A deb (review H-R3-1, Info of review 3), right before the
        // switch: every other recorded package must be as the agent left
        // it (one changed outside the agent, e.g. updated by apt, is
        // reported and blocks deb installs: the agent never downgrades it
        // on its own), and no path of the .deb may land on another
        // package's file or a protected path.
        if ver.kind == robodr_pkg::rpk::Kind::Deb {
            let outside = self.deb_damage(&it.name, &ver);
            if !outside.is_empty() {
                return self.changed_outside(idx, &outside, seen.state, rep);
            }
            let own = ver
                .deb
                .as_ref()
                .is_some_and(|d| crate::install::ROBODR_PACKAGES.contains(&d.package.as_str()));
            match self.installer().check_deb_paths(&m, &ver, own) {
                Ok(()) => {}
                Err(PrepError::Refused(e)) => return self.refuse_item(idx, "invalid", e, rep),
                // A deb is never sealed.
                Err(PrepError::Unseal(e)) => {
                    return self.refuse_item(idx, "invalid", e.to_string(), rep)
                }
                Err(PrepError::Io(e)) => {
                    let k = format!("paths:{}:{e}", it.name);
                    if self.reported.insert(k) {
                        self.journal.note(
                            kinds::REFUSED,
                            json!({"stage": "paths", "name": it.name, "transient": true, "detail": e}),
                        )?;
                    }
                    rep.deferred = Some(format!("{} {}: {e}", it.name, it.serial));
                    return Ok(());
                }
            }
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
        // Relations (review H-A): `Conflicts`, `Breaks`, `Replaces` and
        // `Provides` may name only the RPK's own package. One naming another
        // package lets `dpkg --install` take over that package's files or
        // remove it (a floored package, another programme's package) while
        // the state still records it. The one exception is RoboDR's own
        // pair (`robodr` <-> `robodr-focal`), and only for a RoboDR package
        // from the designated programme (checked below).
        let own_robodr = crate::install::ROBODR_PACKAGES.contains(&d.package.as_str());
        let foreign: Vec<&str> = d
            .relations
            .iter()
            .map(String::as_str)
            .filter(|r| {
                *r != d.package && !(own_robodr && crate::install::ROBODR_PACKAGES.contains(r))
            })
            .collect();
        if !foreign.is_empty() {
            return Some(format!(
                "the .deb conflicts with, breaks, replaces or provides {}: a deb RPK may name only \
                 its own package ({}) in these fields",
                foreign
                    .iter()
                    .take(8)
                    .map(|r| robodr_pkg::common::trunc(r))
                    .collect::<Vec<_>>()
                    .join(", "),
                d.package
            ));
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

    /// Why the recorded deb package `d` is not as the agent installed it
    /// (review H-A, H-R3-1 (c)), or `None`: dpkg must have it installed at
    /// the recorded version, and `dpkg --verify` (conffiles aside) and its
    /// file list must say what they said right after its install.
    fn deb_intact(&self, d: &crate::state::DebInfo) -> Option<String> {
        let inst = self.installer();
        match inst.deb_state(&d.package) {
            Some((st, v)) if st == "installed" && v == d.version => {}
            seen => {
                return Some(seen.map_or_else(
                    || "unknown to dpkg".to_string(),
                    |(st, v)| format!("{st} {v}"),
                ))
            }
        }
        // Compared with what `dpkg --verify` said right after its install
        // (files left out by a `path-exclude` show as `missing` from the
        // start); a package recorded before that baseline is checked for
        // its file list only until the next install records it.
        match inst.deb_verify(&d.package) {
            Ok(lines) if d.verify.as_ref().is_none_or(|b| *b == lines_digest(&lines)) => {}
            Ok(lines) => {
                return Some(format!(
                    "installed {}: dpkg --verify: {}",
                    d.version,
                    lines
                        .iter()
                        .take(4)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" | ")
                ))
            }
            Err(e) => return Some(format!("installed {}: {e}", d.version)),
        }
        if let Some(want) = &d.files {
            match inst.deb_files_digest(&d.package) {
                Ok(got) if got == *want => {}
                Ok(_) => {
                    return Some(format!(
                        "installed {}: its file list changed since its install",
                        d.version
                    ))
                }
                Err(e) => return Some(format!("installed {}: {e}", d.version)),
            }
        }
        None
    }

    /// Defer item `idx` because recorded deb packages were changed outside
    /// the agent (Info of review 3: apt, unattended-upgrades, an operator):
    /// reported once per change (`robot.deliver.refused`, High), never
    /// "restored" (downgraded) on the agent's own. Deb installs wait until
    /// the package is back at its recorded version (by the operator) or a
    /// release of that package is delivered.
    fn changed_outside(
        &mut self,
        idx: usize,
        outside: &[(String, String, String, String)],
        safety: SafetyState,
        rep: &mut TickReport,
    ) -> R<()> {
        let what = describe_damage(outside);
        let k = format!("outside:{what}");
        if self.reported.insert(k) {
            let ev = self.journal.note(
                kinds::REFUSED,
                json!({"stage": "switch", "code": "changed_outside", "transient": true,
                       "detail": format!("recorded packages changed outside the agent: {what}")}),
            )?;
            self.finding_in(
                rules::REFUSED,
                Severity::High,
                format!(
                    "changed_outside: recorded deb packages were changed outside the agent \
                     ({what}); deb installs wait until they are back at their recorded version \
                     or a release of them is delivered"
                ),
                Some(ev),
                safety,
            );
        }
        self.defer(idx, format!("deb_changed_outside: {what}"), None, rep)
    }

    /// Recorded deb packages other than `name` that are not as the agent
    /// installed them ([`Self::deb_intact`]): `(RPK name, package,
    /// recorded version, what dpkg says)`. When `to` is one of RoboDR's
    /// own packages, the other one it may replace is not checked.
    fn deb_damage(&self, name: &str, to: &Ver) -> Vec<(String, String, String, String)> {
        let robodr = crate::install::ROBODR_PACKAGES;
        let skip: Vec<&str> = to
            .deb
            .iter()
            .filter(|d| robodr.contains(&d.package.as_str()))
            .flat_map(|d| d.relations.iter().map(String::as_str))
            .filter(|r| robodr.contains(r))
            .collect();
        let mut out = Vec::new();
        for (n, i) in &self.state.installed {
            let Some(d) = &i.ver.deb else { continue };
            if n == name || d.package == name || skip.contains(&d.package.as_str()) {
                continue;
            }
            if let Some(seen) = self.deb_intact(d) {
                out.push((n.clone(), d.package.clone(), d.version.clone(), seen));
            }
        }
        out
    }

    /// Reinstall the recorded version of every damaged package
    /// ([`Self::deb_damage`]); those that could not be restored are marked
    /// unhealthy and raise `robot.deliver.rollback_blocked_floor`
    /// (Critical). Returns them.
    fn restore_debs(
        &mut self,
        damage: &[(String, String, String, String)],
        safety: SafetyState,
    ) -> R<Vec<String>> {
        let mut failed = Vec::new();
        for (n, pkg, version, seen) in damage {
            let Some(i) = self.state.installed.get(n).cloned() else {
                continue;
            };
            let res = self.store.manifest(&i.ver.digest).and_then(|m| {
                let mut v = i.ver.clone();
                if !self.prepared(n, &v) {
                    self.installer()
                        .prepare(&m, &mut v)
                        .map_err(|e| e.to_string())?;
                }
                self.installer().activate(n, &v, &m)
            });
            let ok = res.is_ok()
                && i.ver
                    .deb
                    .as_ref()
                    .is_some_and(|d| self.deb_intact(d).is_none());
            let ev = self.journal.note(
                kinds::ROLLBACK,
                json!({"name": n, "phase": "restore", "package": pkg, "version": version,
                       "observed": seen, "restored": ok,
                       "error": res.as_ref().err()}),
            )?;
            if ok {
                continue;
            }
            failed.push(format!("{pkg} {version}"));
            if let Some(x) = self.state.installed.get_mut(n) {
                x.healthy = false;
            }
            self.save()?;
            self.finding_in(
                rules::ROLLBACK_BLOCKED_FLOOR,
                Severity::Critical,
                format!(
                    "{n} {}: dpkg changed it during another package's install ({seen}) and it \
                     could not be restored{}",
                    i.ver.serial,
                    res.err().map(|e| format!(": {e}")).unwrap_or_default()
                ),
                Some(ev),
                safety,
            );
        }
        Ok(failed)
    }

    fn prepared(&self, name: &str, v: &Ver) -> bool {
        match v.kind {
            robodr_pkg::rpk::Kind::Deb => v.deb.is_some() && self.store.has_rpk(&v.digest),
            k => crate::fsx::is_real_dir(
                &self
                    .installer()
                    .version_dir(k, v.sealed, name, v.serial, &v.digest),
            ),
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
        mut txn: Txn,
        m: &Manifest,
        safety: SafetyState,
        rep: &mut TickReport,
    ) -> R<()> {
        // Review H-A: a `dpkg --install` must leave every other deb package
        // the state records installed at its recorded version. One it
        // changed anyway is restored, and the switch counts as failed.
        if txn.to.kind == robodr_pkg::rpk::Kind::Deb {
            let damage = self.deb_damage(&txn.name, &txn.to);
            if !damage.is_empty() {
                let what = describe_damage(&damage);
                let seen = safety::observe(&self.cfg.safety);
                if !seen.allows_install() {
                    // Still in phase `health`: judged (and restored) again
                    // at the next pass.
                    rep.deferred = Some(format!(
                        "restoring {what}: safety_state:{}",
                        state_name(seen.state)
                    ));
                    return Ok(());
                }
                let not_restored = self.restore_debs(&damage, seen.state)?;
                self.journal.note(
                    kinds::REFUSED,
                    json!({"stage": "switch", "name": txn.name, "serial": txn.to.serial,
                           "code": "collateral",
                           "detail": format!("dpkg --install changed other recorded packages: {what}"),
                           "not_restored": not_restored}),
                )?;
                return self.failed(
                    txn,
                    format!("dpkg --install changed other recorded packages: {what}"),
                    safety,
                    rep,
                );
            }
            // Review H-R3-1 (c): the file list it was installed with, and
            // that of recorded packages from before it was recorded.
            self.record_files(&mut txn.to);
            self.state.txn = Some(txn.clone());
            let names: Vec<String> = self.state.installed.keys().cloned().collect();
            for n in names {
                let Some(mut v) = self
                    .state
                    .installed
                    .get(&n)
                    .map(|i| i.ver.clone())
                    .filter(|v| {
                        v.deb
                            .as_ref()
                            .is_some_and(|d| d.files.is_none() || d.verify.is_none())
                    })
                else {
                    continue;
                };
                self.record_files(&mut v);
                if let Some(i) = self.state.installed.get_mut(&n) {
                    i.ver = v;
                }
            }
            self.save()?;
        }
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

    /// Record the baseline of the deb `v` in it (review H-R3-1): its file
    /// list and what `dpkg --verify` says, right after its install.
    fn record_files(&self, v: &mut Ver) {
        if let Some(d) = v.deb.as_mut() {
            if let Ok(f) = self.installer().deb_files_digest(&d.package) {
                d.files = Some(f);
            }
            if let Ok(lines) = self.installer().deb_verify(&d.package) {
                d.verify = Some(lines_digest(&lines));
            }
        }
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
            if i >= keep || k.get(i).is_some_and(|v| v.serial < floor) {
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
        if v.kind == robodr_pkg::rpk::Kind::Deb {
            let damage = self.deb_damage(&txn.name, &v);
            if !damage.is_empty() {
                let what = describe_damage(&damage);
                let not_restored = self.restore_debs(&damage, seen.state)?;
                if !not_restored.is_empty() {
                    return self.rollback_failed(
                        txn,
                        format!(
                            "the rollback changed other recorded packages ({what}); not restored: {}",
                            not_restored.join("; ")
                        ),
                        rep,
                    );
                }
            }
        }
        if v.deb
            .as_ref()
            .is_some_and(|d| d.files.is_none() || d.verify.is_none())
        {
            self.record_files(&mut v);
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
                let active =
                    self.installer()
                        .active_of(&txn.name, txn.to.kind, txn.to.sealed, &known);
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

/// SHA-256 (hex) of `dpkg --verify` lines, sorted (review H-R3-1).
fn lines_digest(lines: &[String]) -> String {
    let mut v: Vec<&str> = lines.iter().map(String::as_str).collect();
    v.sort_unstable();
    let mut h = robodr_blackbox::crypto::Sha256::new();
    for l in v {
        h.update(l.as_bytes());
        h.update(b"\n");
    }
    robodr_blackbox::crypto::to_hex(&h.finalize())
}

/// `"<package> <recorded version> -> <what dpkg says>"`, joined.
fn describe_damage(d: &[(String, String, String, String)]) -> String {
    d.iter()
        .map(|(_, p, v, seen)| format!("{p} {v} -> {seen}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Where `robodr-deliverd confirm` drops an operator confirmation for
/// `name` of the deployment `deployment_digest`.
pub fn confirm_path(cfg: &Config, deployment_digest: &str, name: &str) -> PathBuf {
    cfg.state_dir.join("confirm").join(format!(
        "{}-{name}",
        &deployment_digest[..deployment_digest.len().min(64)]
    ))
}

/// The `robot.seal.erased` text: what was destroyed, and what was not.
pub fn erase_summary(rep: &robodr_seal::unit::EraseReport) -> String {
    use robodr_seal::unit as u;
    let what: Vec<String> = rep
        .destroyed
        .iter()
        .map(|d| match d.as_str() {
            u::DESTROYED_EPOCH => match (rep.epoch_before, rep.epoch_after) {
                (Some(b), Some(a)) => format!("TPM erase epoch moved {b} -> {a}"),
                _ => "TPM erase epoch incremented".into(),
            },
            u::DESTROYED_UWK_BLOBS => "UWK blobs deleted".into(),
            u::DESTROYED_VOLUME_WRAP => "volume key wrap deleted".into(),
            u::DESTROYED_FALLBACK_UWK => "UWK file destroyed".into(),
            u::DESTROYED_KEYSLOTS => "runtime volume keyslots wiped".into(),
            other => other.to_string(),
        })
        .collect();
    let volume = match &rep.lockdown {
        Some(l) if l.closed => "runtime volume closed".to_string(),
        Some(l) if l.suspended => {
            "runtime volume suspended (busy: not closed; its key is out of the kernel)".into()
        }
        Some(_) => "runtime volume STILL OPEN: its plaintext is readable until power-off".into(),
        None => "runtime volume not closed (no seal.mapper_name)".into(),
    };
    let mut t = format!(
        "erased: trigger {}: {}; {volume}",
        rep.trigger,
        what.join(", ")
    );
    if !rep.incomplete.is_empty() {
        t.push_str(&format!("; not done: {}", rep.incomplete.join("; ")));
    }
    t
}
