//! The executor core: one action at a time, precheck → safety re-check →
//! journal intent → apply → read-back verify → commit, and revert, TTL
//! expiry, periodic verification and restart reconciliation.
//!
//! The engine is single-threaded and owns the table `inet robodr`: its
//! content is always [`nft::render`] of the journal's `active` entries (plus
//! the one `applying` entry while it is being installed). Every function
//! takes the wall clock (`now_ms`, Unix ms) from its caller.

use robodr_responder::{ActionId, ResponsePolicy};
use serde::{Deserialize, Serialize};

use crate::config::Resolved;
use crate::decision::{self, codes, Current, Effect, Refusal};
use crate::journal::{Entry, EventKind, Final, Finished, Journal, Loaded, Phase, State};
use crate::nft::{self, Active, Nft, Rendered};
use crate::order::Order;

/// Where the engine gets the platform's current safety state from,
/// immediately before it applies anything.
pub trait SafetyOracle {
    fn current(&mut self) -> Result<Current, String>;
}

/// An oracle that always answers the same (tests, tools).
#[derive(Debug, Clone, Copy)]
pub struct FixedSafety(pub Current);

impl SafetyOracle for FixedSafety {
    fn current(&mut self) -> Result<Current, String> {
        Ok(self.0)
    }
}

/// An action's state as reported to agentd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Applied and the read-back matched (the rules are in force).
    Verified,
    /// Being installed (only seen if asked mid-transaction).
    Applying,
    /// A revert is in progress or failed and is being retried.
    Reverting,
    /// Removed (by request, TTL or reconciliation).
    Reverted,
    /// Refused before anything was applied.
    Refused,
    /// The apply failed and was rolled back (or could not be committed).
    Failed,
    /// Recorded only (v1 `restrict_motion`).
    Advisory,
    /// Removed from outside (`nft delete table inet robodr`).
    RemovedExternally,
    /// No action with this id.
    Unknown,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Verified => "verified",
            Status::Applying => "applying",
            Status::Reverting => "reverting",
            Status::Reverted => "reverted",
            Status::Refused => "refused",
            Status::Failed => "failed",
            Status::Advisory => "advisory",
            Status::RemovedExternally => "removed_externally",
            Status::Unknown => "unknown",
        }
    }
}

/// The answer for one action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub id: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// A resubmission of an order already known (not executed again).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub duplicate: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Outcome {
    fn bare(id: &str, status: Status) -> Self {
        Self {
            id: id.into(),
            status,
            action: None,
            refusal: None,
            error: None,
            applied_ms: None,
            deadline_ms: None,
            duplicate: false,
            note: None,
        }
    }
}

/// The executor core.
pub struct Engine {
    cfg: Resolved,
    policy: ResponsePolicy,
    nft: Box<dyn Nft + Send>,
    journal: Journal,
    state: State,
    boot_id: String,
    last_verify_ms: u64,
    /// The last journal write failed (reported in status).
    pub journal_errors: u64,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("active", &self.state.entries.len())
            .field("boot_id", &self.boot_id)
            .finish()
    }
}

/// A crash point was hit (fault-injection builds only): stop like a dead
/// process.
#[cfg(feature = "fault-injection")]
macro_rules! crash_point {
    ($p:expr, $id:expr) => {
        if crate::fault::hit($p) {
            let mut o = Outcome::bare($id, Status::Failed);
            o.error = Some(format!("fault injected: crashed at {:?}", $p));
            return o;
        }
    };
}
#[cfg(not(feature = "fault-injection"))]
macro_rules! crash_point {
    ($p:expr, $id:expr) => {};
}

impl Engine {
    /// Open the journal in `cfg.state_dir` and reconcile the table with it
    /// (see [`crate::journal`]): `applying` / `reverting` entries are
    /// dropped, expired ones reverted, the rest re-applied and verified; a
    /// table that vanished during this boot while actions were active was
    /// removed by an operator and is not re-installed.
    pub fn open(
        cfg: Resolved,
        policy: ResponsePolicy,
        nft: Box<dyn Nft + Send>,
        boot_id: &str,
        now_ms: u64,
    ) -> Result<Self, String> {
        let journal = Journal::new(&cfg.config.state_dir);
        let mut e = Engine {
            state: State::empty(boot_id),
            cfg,
            policy,
            nft,
            journal,
            boot_id: boot_id.to_string(),
            last_verify_ms: now_ms,
            journal_errors: 0,
        };
        match e.journal.load() {
            Loaded::Fresh => {
                let leftover = nft::table_exists(e.nft.as_mut())?;
                if leftover {
                    nft::delete_table(e.nft.as_mut())?;
                    e.state.event(
                        now_ms,
                        EventKind::Reconciled,
                        None,
                        None,
                        "no journal: a leftover table inet robodr was removed",
                    );
                }
            }
            Loaded::Corrupt(why) => {
                nft::delete_table(e.nft.as_mut())?;
                e.state.event(
                    now_ms,
                    EventKind::JournalReset,
                    None,
                    None,
                    format!(
                        "the journal was unreadable ({why}): table inet robodr deleted, every \
                         action reverted, starting empty"
                    ),
                );
            }
            Loaded::State(s) => {
                e.state = s;
                e.reconcile(now_ms)?;
            }
        }
        e.state.boot_id = boot_id.to_string();
        e.journal.save(&e.state)?;
        Ok(e)
    }

    fn reconcile(&mut self, now_ms: u64) -> Result<(), String> {
        let same_boot = self.state.boot_id == self.boot_id;
        let max_ms = self.cfg.config.ttl.max_s.saturating_mul(1000);
        let mut summary = Vec::new();
        let entries = std::mem::take(&mut self.state.entries);
        let mut keep = Vec::new();
        for en in entries {
            match en.phase {
                Phase::Applying => {
                    self.finish(
                        &en,
                        Final::Failed,
                        now_ms,
                        "interrupted between apply and commit (crash or stop): reverted at restart",
                    );
                    self.state.event(
                        now_ms,
                        EventKind::Failed,
                        Some(&en.id),
                        Some(en.action),
                        "interrupted between apply and commit: reverted at restart",
                    );
                    summary.push(format!("{} interrupted apply reverted", en.id));
                }
                Phase::Reverting => {
                    self.finish(&en, Final::Reverted, now_ms, "revert completed at restart");
                    self.state.event(
                        now_ms,
                        EventKind::Reverted,
                        Some(&en.id),
                        Some(en.action),
                        "revert completed at restart",
                    );
                    summary.push(format!("{} revert completed", en.id));
                }
                Phase::Active
                    if en.deadline_ms <= now_ms
                        || en.deadline_ms.saturating_sub(now_ms) > max_ms =>
                {
                    self.state.event(
                        now_ms,
                        EventKind::Expired,
                        Some(&en.id),
                        Some(en.action),
                        "TTL expired while the executor was down (or the clock moved back)",
                    );
                    self.finish(&en, Final::Reverted, now_ms, "TTL expired (at restart)");
                    self.state.event(
                        now_ms,
                        EventKind::Reverted,
                        Some(&en.id),
                        Some(en.action),
                        "reverted at restart: TTL expired",
                    );
                    summary.push(format!("{} expired", en.id));
                }
                Phase::Active => keep.push(en),
            }
        }
        if !keep.is_empty() && same_boot && !nft::table_exists(self.nft.as_mut())? {
            for en in &keep {
                self.finish(
                    en,
                    Final::RemovedExternally,
                    now_ms,
                    "table inet robodr was removed while the executor was down (same boot): \
                     operator emergency disable honoured, not re-applied",
                );
                self.state.event(
                    now_ms,
                    EventKind::RemovedExternally,
                    Some(&en.id),
                    Some(en.action),
                    "table removed from outside during this boot: not re-applied",
                );
            }
            summary.push(format!("{} removed externally", keep.len()));
            keep.clear();
        }
        self.state.entries = keep;
        let r = self.rendered();
        let ok = nft::apply(self.nft.as_mut(), &r).and_then(|()| self.read_verify(&r));
        if let Err(err) = ok {
            // Cannot re-establish the journalled state: fail towards doing
            // nothing on the robot.
            let entries = std::mem::take(&mut self.state.entries);
            let del = nft::delete_table(self.nft.as_mut())
                .and_then(|()| self.read_verify(&Rendered { chains: None }));
            for en in &entries {
                self.finish(
                    en,
                    Final::Reverted,
                    now_ms,
                    &format!("could not be re-applied at restart ({err}): reverted"),
                );
                self.state.event(
                    now_ms,
                    EventKind::Reverted,
                    Some(&en.id),
                    Some(en.action),
                    format!("could not be re-applied at restart ({err}): reverted"),
                );
            }
            if let Err(e2) = del {
                self.state.event(
                    now_ms,
                    EventKind::RevertFailed,
                    None,
                    None,
                    format!(
                        "restart: re-apply failed ({err}) and deleting the table failed ({e2})"
                    ),
                );
            }
            summary.push(format!("re-apply failed: {err}"));
        } else if !self.state.entries.is_empty() {
            summary.push(format!(
                "{} active action(s) re-applied and verified{}",
                self.state.entries.len(),
                if same_boot { "" } else { " after a reboot" }
            ));
        }
        self.state.event(
            now_ms,
            EventKind::Reconciled,
            None,
            None,
            if summary.is_empty() {
                "nothing to do".to_string()
            } else {
                summary.join("; ")
            },
        );
        Ok(())
    }

    fn finish(&mut self, en: &Entry, result: Final, at_ms: u64, detail: &str) {
        self.state.finish(Finished {
            id: en.id.clone(),
            digest: en.digest.clone(),
            action: en.action,
            result,
            at_ms,
            refusal: None,
            detail: Some(detail.to_string()),
        });
    }

    fn save(&mut self) -> Result<(), String> {
        let r = self.journal.save(&self.state);
        if r.is_err() {
            self.journal_errors = self.journal_errors.saturating_add(1);
        }
        r
    }

    /// The rendering of the current journal: `active` and `applying`
    /// entries.
    pub fn rendered(&self) -> Rendered {
        let act: Vec<Active<'_>> = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase != Phase::Reverting)
            .map(|e| Active {
                id: &e.id,
                effect: &e.effect,
            })
            .collect();
        nft::render(&act)
    }

    fn read_verify(&mut self, r: &Rendered) -> Result<(), String> {
        let listed = nft::read_table(self.nft.as_mut())?;
        nft::verify(listed.as_deref(), r)
    }

    fn install(&mut self) -> Result<(), String> {
        let r = self.rendered();
        nft::apply(self.nft.as_mut(), &r)?;
        self.read_verify(&r)
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn policy(&self) -> &ResponsePolicy {
        &self.policy
    }

    /// Execute one order (see the module docs). Never panics; every path
    /// ends in an outcome and, unless refused before anything happened, an
    /// event.
    pub fn submit(&mut self, order: &Order, oracle: &mut dyn SafetyOracle, now_ms: u64) -> Outcome {
        let digest = order.digest();
        if let Some(en) = self.state.entry(&order.id) {
            if en.digest == digest {
                let mut o = self.status(&order.id);
                o.duplicate = true;
                return o;
            }
            return self.refused_conflict(order);
        }
        if let Some(f) = self.state.finished(&order.id) {
            if f.digest == digest {
                let mut o = self.status(&order.id);
                o.duplicate = true;
                return o;
            }
            return self.refused_conflict(order);
        }
        let planned = match decision::precheck(order, &self.policy, &self.cfg) {
            Ok(p) => p,
            Err(r) => return self.refuse(order, &digest, r, now_ms),
        };
        let ttl = match planned.effect {
            Effect::Evidence => {
                return self.refuse(
                    order,
                    &digest,
                    Refusal::new(
                        codes::EVIDENCE_ELSEWHERE,
                        "record_evidence is carried out by agentd (it owns the black box), \
                         not by the executor process",
                    ),
                    now_ms,
                )
            }
            Effect::Advisory { ref note } => {
                let note = note.clone();
                self.state.finish(Finished {
                    id: order.id.clone(),
                    digest,
                    action: order.action,
                    result: Final::Advisory,
                    at_ms: now_ms,
                    refusal: None,
                    detail: Some(note.clone()),
                });
                self.state.event(
                    now_ms,
                    EventKind::Advisory,
                    Some(&order.id),
                    Some(order.action),
                    note.clone(),
                );
                let _ = self.save();
                let mut o = Outcome::bare(&order.id, Status::Advisory);
                o.action = Some(order.action);
                o.note = Some(note);
                return o;
            }
            _ => planned.ttl_s.unwrap_or(self.cfg.config.ttl.default_s),
        };
        // One isolation at a time; one quarantine per participant.
        let clash = self
            .state
            .entries
            .iter()
            .find(|e| match (&e.effect, &planned.effect) {
                (Effect::Isolate(_), Effect::Isolate(_)) => true,
                (Effect::Quarantine(a), Effect::Quarantine(b)) => a.guid_prefix == b.guid_prefix,
                _ => false,
            });
        if let Some(c) = clash {
            let r = Refusal::new(
                codes::ALREADY_ACTIVE,
                format!(
                    "{} is already in force for this target (request {}): revert it first",
                    order.action.as_str(),
                    c.id
                ),
            );
            return self.refuse(order, &digest, r, now_ms);
        }
        // Immediately before apply: the platform's safety state now.
        let current = oracle.current();
        if let Err(r) = decision::recheck_safety(order, current, self.cfg.config.max_safety_age_ms)
        {
            return self.refuse(order, &digest, r, now_ms);
        }
        let deadline = now_ms.saturating_add(ttl.saturating_mul(1000));
        self.state.entries.push(Entry {
            id: order.id.clone(),
            digest: digest.clone(),
            action: order.action,
            origin: order.origin.clone(),
            effect: planned.effect.clone(),
            phase: Phase::Applying,
            ttl_s: ttl,
            applied_ms: now_ms,
            deadline_ms: deadline,
        });
        if let Err(e) = self.save() {
            self.state.entries.retain(|en| en.id != order.id);
            let mut o = Outcome::bare(&order.id, Status::Failed);
            o.action = Some(order.action);
            o.error = Some(format!("journal write failed, nothing applied: {e}"));
            self.state.event(
                now_ms,
                EventKind::Failed,
                Some(&order.id),
                Some(order.action),
                o.error.clone().unwrap_or_default(),
            );
            return o;
        }
        crash_point!(crate::fault::Point::AfterIntent, &order.id);
        let r = self.rendered();
        if let Err(e) = nft::apply(self.nft.as_mut(), &r) {
            return self.rollback(order, &format!("nft apply failed: {e}"), now_ms);
        }
        crash_point!(crate::fault::Point::AfterApply, &order.id);
        if let Err(e) = self.read_verify(&r) {
            return self.rollback(order, &format!("read-back did not match: {e}"), now_ms);
        }
        if let Some(en) = self.state.entries.iter_mut().find(|en| en.id == order.id) {
            en.phase = Phase::Active;
        }
        if let Err(e) = self.save() {
            return self.rollback(order, &format!("journal commit failed: {e}"), now_ms);
        }
        self.state.event(
            now_ms,
            EventKind::Applied,
            Some(&order.id),
            Some(order.action),
            format!("installed in table inet robodr, ttl {ttl} s"),
        );
        self.state.event(
            now_ms,
            EventKind::Verified,
            Some(&order.id),
            Some(order.action),
            "read-back matches the rendered rules",
        );
        self.last_verify_ms = now_ms;
        let _ = self.save();
        self.status(&order.id)
    }

    fn refused_conflict(&mut self, order: &Order) -> Outcome {
        let mut o = Outcome::bare(&order.id, Status::Refused);
        o.action = Some(order.action);
        o.refusal = Some(Refusal::new(
            codes::ID_CONFLICT,
            "this id was already used for another action, target or ttl",
        ));
        o
    }

    fn refuse(&mut self, order: &Order, digest: &str, r: Refusal, now_ms: u64) -> Outcome {
        self.state.event(
            now_ms,
            EventKind::Refused,
            Some(&order.id),
            Some(order.action),
            format!("{}: {}", r.code, r.reason),
        );
        self.state.finish(Finished {
            id: order.id.clone(),
            digest: digest.to_string(),
            action: order.action,
            result: Final::Refused,
            at_ms: now_ms,
            refusal: Some(r.clone()),
            detail: None,
        });
        let _ = self.save();
        let mut o = Outcome::bare(&order.id, Status::Refused);
        o.action = Some(order.action);
        o.refusal = Some(r);
        o
    }

    /// Undo a failed apply: drop the entry and re-render without it.
    fn rollback(&mut self, order: &Order, why: &str, now_ms: u64) -> Outcome {
        let en = self
            .state
            .entries
            .iter()
            .position(|e| e.id == order.id)
            .map(|i| self.state.entries.remove(i));
        let undo = self.install();
        if let Some(en) = &en {
            self.finish(en, Final::Failed, now_ms, why);
        }
        self.state.event(
            now_ms,
            EventKind::Failed,
            Some(&order.id),
            Some(order.action),
            why.to_string(),
        );
        if let Err(e) = &undo {
            self.state.event(
                now_ms,
                EventKind::RevertFailed,
                Some(&order.id),
                Some(order.action),
                format!(
                    "rolling back the failed apply did not verify ({e}); the periodic \
                         check retries"
                ),
            );
        }
        let _ = self.save();
        let mut o = Outcome::bare(&order.id, Status::Failed);
        o.action = Some(order.action);
        o.error = Some(match undo {
            Ok(()) => format!("{why}; rolled back"),
            Err(e) => format!("{why}; rollback did not verify: {e}"),
        });
        o
    }

    /// Revert one action (request, TTL, operator). Idempotent: an action
    /// already finished answers its final status.
    pub fn revert(&mut self, id: &str, reason: &str, now_ms: u64) -> Outcome {
        let Some(pos) = self.state.entries.iter().position(|e| e.id == id) else {
            return self.status(id);
        };
        self.state.entries[pos].phase = Phase::Reverting;
        let _ = self.save();
        crash_point!(crate::fault::Point::AfterRevertIntent, id);
        self.finish_revert(id, reason, now_ms)
    }

    fn finish_revert(&mut self, id: &str, reason: &str, now_ms: u64) -> Outcome {
        let Some(en) = self.state.entry(id).cloned() else {
            return self.status(id);
        };
        match self.install() {
            Ok(()) => {
                self.state.entries.retain(|e| e.id != id);
                self.finish(&en, Final::Reverted, now_ms, reason);
                self.state.event(
                    now_ms,
                    EventKind::Reverted,
                    Some(id),
                    Some(en.action),
                    reason.to_string(),
                );
                let _ = self.save();
                self.status(id)
            }
            Err(e) => {
                self.state.event(
                    now_ms,
                    EventKind::RevertFailed,
                    Some(id),
                    Some(en.action),
                    format!("{reason}: revert did not verify ({e}); retried every tick"),
                );
                let _ = self.save();
                let mut o = self.status(id);
                o.error = Some(format!("revert did not verify: {e}"));
                o
            }
        }
    }

    /// Housekeeping, every second or so: retry failed reverts, revert
    /// expired actions, and every `verify_interval_s` read the table back.
    pub fn tick(&mut self, now_ms: u64) {
        let reverting: Vec<String> = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase == Phase::Reverting)
            .map(|e| e.id.clone())
            .collect();
        for id in reverting {
            self.finish_revert(&id, "revert retried", now_ms);
        }
        let max_ms = self.cfg.config.ttl.max_s.saturating_mul(1000);
        let expired: Vec<(String, ActionId)> = self
            .state
            .entries
            .iter()
            .filter(|e| {
                e.phase == Phase::Active
                    && (e.deadline_ms <= now_ms || e.deadline_ms.saturating_sub(now_ms) > max_ms)
            })
            .map(|e| (e.id.clone(), e.action))
            .collect();
        for (id, action) in expired {
            self.state.event(
                now_ms,
                EventKind::Expired,
                Some(&id),
                Some(action),
                "TTL expired",
            );
            self.revert(&id, "TTL expired: automatic revert", now_ms);
        }
        let every = self.cfg.config.verify_interval_s.saturating_mul(1000);
        if now_ms.saturating_sub(self.last_verify_ms) >= every {
            self.last_verify_ms = now_ms;
            self.periodic_verify(now_ms);
        }
    }

    /// Read the table back and compare. A table that disappeared while
    /// actions were active is an operator's emergency disable: every action
    /// is dropped and nothing is re-applied. Any other difference is
    /// drift: the rendering is re-applied.
    pub fn periodic_verify(&mut self, now_ms: u64) {
        let r = self.rendered();
        let listed = match nft::read_table(self.nft.as_mut()) {
            Ok(l) => l,
            Err(e) => {
                self.state.event(
                    now_ms,
                    EventKind::Drift,
                    None,
                    None,
                    format!("could not read table inet robodr: {e}"),
                );
                let _ = self.save();
                return;
            }
        };
        if listed.is_none() && r.chains.is_some() {
            let entries = std::mem::take(&mut self.state.entries);
            for en in &entries {
                self.finish(
                    en,
                    Final::RemovedExternally,
                    now_ms,
                    "table inet robodr was removed from outside (emergency disable): not \
                     re-applied",
                );
                self.state.event(
                    now_ms,
                    EventKind::RemovedExternally,
                    Some(&en.id),
                    Some(en.action),
                    "table inet robodr was removed from outside: action dropped, not re-applied",
                );
            }
            let _ = self.save();
            return;
        }
        if let Err(diff) = nft::verify(listed.as_deref(), &r) {
            let fixed = self.install();
            self.state.event(
                now_ms,
                EventKind::Drift,
                None,
                None,
                match &fixed {
                    Ok(()) => format!("table differed from the rendering ({diff}): re-applied"),
                    Err(e) => format!("table differed ({diff}); re-applying failed: {e}"),
                },
            );
            let _ = self.save();
        }
    }

    /// Remove every action (operator `revert-all`).
    pub fn revert_all(&mut self, reason: &str, now_ms: u64) -> Result<usize, String> {
        let entries = std::mem::take(&mut self.state.entries);
        nft::delete_table(self.nft.as_mut())?;
        self.read_verify(&Rendered { chains: None })?;
        for en in &entries {
            self.finish(en, Final::Reverted, now_ms, reason);
            self.state.event(
                now_ms,
                EventKind::Reverted,
                Some(&en.id),
                Some(en.action),
                reason.to_string(),
            );
        }
        self.save()?;
        Ok(entries.len())
    }

    /// The state of action `id`.
    pub fn status(&self, id: &str) -> Outcome {
        if let Some(en) = self.state.entry(id) {
            let mut o = Outcome::bare(
                id,
                match en.phase {
                    Phase::Applying => Status::Applying,
                    Phase::Active => Status::Verified,
                    Phase::Reverting => Status::Reverting,
                },
            );
            o.action = Some(en.action);
            o.applied_ms = Some(en.applied_ms);
            o.deadline_ms = Some(en.deadline_ms);
            return o;
        }
        if let Some(f) = self.state.finished(id) {
            let mut o = Outcome::bare(
                id,
                match f.result {
                    Final::Reverted => Status::Reverted,
                    Final::Failed => Status::Failed,
                    Final::Refused => Status::Refused,
                    Final::Advisory => Status::Advisory,
                    Final::RemovedExternally => Status::RemovedExternally,
                },
            );
            o.action = Some(f.action);
            o.refusal = f.refusal.clone();
            o.note = f.detail.clone();
            return o;
        }
        Outcome::bare(id, Status::Unknown)
    }

    /// Events with `seq > since`, at most `max`.
    pub fn events_since(&self, since: u64, max: usize) -> Vec<crate::journal::Event> {
        self.state
            .events
            .iter()
            .filter(|e| e.seq > since)
            .take(max)
            .cloned()
            .collect()
    }
}
