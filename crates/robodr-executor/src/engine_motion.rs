//! The engine's motion actions (Sprint 8, [`crate::motion`]): submit
//! (journal intent → adapter apply + read back → commit), undo on revert /
//! TTL / restart / operator disable, re-arm after a reboot and the
//! periodic read-back. A child module of [`crate::engine`].

use super::*;
use crate::motion::MotionSpec;

impl Engine {
    /// Inject other motion ports (tests with fakes; the default talks to
    /// the configured endpoints).
    pub fn with_motion_ports(mut self, p: Box<dyn crate::motion::MotionPorts + Send>) -> Self {
        self.motion = p;
        self
    }

    fn motion_cfg(&self) -> crate::motion::MotionSection {
        self.cfg.config.motion.clone().unwrap_or_default()
    }

    /// Submit an order whose precheck planned [`Effect::Motion`].
    pub(super) fn submit_motion(
        &mut self,
        order: &Order,
        digest: String,
        planned: decision::Planned,
        oracle: &mut dyn SafetyOracle,
        now: Now,
    ) -> Outcome {
        let now_ms = now.wall_ms;
        let Effect::Motion(mut spec) = planned.effect else {
            return self.refuse(
                order,
                &digest,
                Refusal::new(codes::INVALID_ORDER, "not a motion action"),
                now_ms,
            );
        };
        let m = self.motion_cfg();
        let clash = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase != Phase::Held)
            .find(|e| matches!(&e.effect, Effect::Motion(x) if x.action == spec.action))
            .map(|e| e.id.clone());
        if let Some(c) = clash {
            let r = Refusal::new(
                codes::ALREADY_ACTIVE,
                format!(
                    "{} is already in force (request {c}): revert it first",
                    order.action.as_str()
                ),
            );
            return self.refuse(order, &digest, r, now_ms);
        }
        // Immediately before apply: the platform's safety state now, and
        // the adapters' own allowed states with it.
        let current = oracle.current();
        if let Err(r) =
            decision::recheck_safety(order, current.clone(), self.cfg.config.max_safety_age_ms)
        {
            return self.refuse(order, &digest, r, now_ms);
        }
        if let Ok(c) = &current {
            if !spec.allowed(&m, c.state) {
                let r = Refusal::new(
                    codes::SAFETY_STATE_NOT_ALLOWED,
                    format!(
                        "{} is not allowed in safety state {} by its adapter(s)",
                        order.action.as_str(),
                        crate::motion::state_name(c.state)
                    ),
                );
                return self.refuse(order, &digest, r, now_ms);
            }
        }
        let superseded: Vec<Entry> = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase == Phase::Held && clashes(&e.effect, &Effect::Motion(spec.clone())))
            .cloned()
            .collect();
        for en in &superseded {
            self.state.entries.retain(|e| e.id != en.id);
            let why = format!("held after a reboot, superseded by request {}", order.id);
            self.finish(en, Final::Reverted, now_ms, &why);
            self.state.event(
                now_ms,
                EventKind::Reverted,
                Some(&en.id),
                Some(en.action),
                why,
            );
        }
        let adapters: Vec<&str> = spec.adapters.iter().map(|a| a.as_str()).collect();
        let adapters = adapters.join(", ");
        if !spec.reversible {
            // Not reversible: the intent is journalled as an event first (a
            // crash between apply and commit leaves it there), then the
            // result is final.
            self.state.event(
                now_ms,
                EventKind::Applied,
                Some(&order.id),
                Some(order.action),
                format!("sending to adapter(s) {adapters} (not reversible)"),
            );
            if let Err(e) = self.save() {
                let mut o = Outcome::bare(&order.id, Status::Failed);
                o.action = Some(order.action);
                o.error = Some(format!("journal write failed, nothing sent: {e}"));
                return o;
            }
            let res = self.motion.apply(&m, &spec);
            let (result, status, detail) = match &res {
                Ok(n) => (
                    Final::Applied,
                    Status::Applied,
                    format!("applied through {adapters}: {n}"),
                ),
                Err(e) => (Final::Failed, Status::Failed, format!("{adapters}: {e}")),
            };
            self.state.finish(Finished {
                id: order.id.clone(),
                digest,
                action: order.action,
                result,
                at_ms: now_ms,
                refusal: None,
                detail: Some(detail.clone()),
            });
            self.state.event(
                now_ms,
                if res.is_ok() {
                    EventKind::Verified
                } else {
                    EventKind::Failed
                },
                Some(&order.id),
                Some(order.action),
                detail.clone(),
            );
            let _ = self.save();
            let mut o = Outcome::bare(&order.id, status);
            o.action = Some(order.action);
            if res.is_ok() {
                o.applied_ms = Some(now_ms);
                o.note = Some(detail);
            } else {
                o.error = Some(detail);
            }
            return o;
        }
        let ttl = planned.ttl_s.unwrap_or(self.cfg.config.ttl.default_s);
        let deadline = now_ms.saturating_add(ttl.saturating_mul(1000));
        spec.deadline_ms = deadline;
        self.state.entries.push(Entry {
            id: order.id.clone(),
            digest,
            action: order.action,
            origin: order.origin.clone(),
            effect: Effect::Motion(spec.clone()),
            phase: Phase::Applying,
            ttl_s: ttl,
            applied_ms: now_ms,
            deadline_ms: deadline,
            boot_deadline_ms: now
                .boot_ms
                .map(|b| b.saturating_add(ttl.saturating_mul(1000))),
            order: Some(order.clone()),
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
        let applied = self.motion.apply(&m, &spec);
        let note = match applied {
            Ok(n) => n,
            Err(e) => {
                // Undo whatever may have reached the platform (the
                // adapters undo a partial multi-adapter apply themselves).
                let undo = self.motion.revert(&m, &spec);
                let en = self
                    .state
                    .entries
                    .iter()
                    .position(|x| x.id == order.id)
                    .map(|i| self.state.entries.remove(i));
                let why = match undo {
                    Ok(_) => format!("{adapters}: {e}; undone"),
                    Err(u) => format!("{adapters}: {e}; undo failed: {u}"),
                };
                if let Some(en) = &en {
                    self.finish(en, Final::Failed, now_ms, &why);
                }
                self.state.event(
                    now_ms,
                    EventKind::Failed,
                    Some(&order.id),
                    Some(order.action),
                    why.clone(),
                );
                let _ = self.save();
                let mut o = Outcome::bare(&order.id, Status::Failed);
                o.action = Some(order.action);
                o.error = Some(why);
                return o;
            }
        };
        if let Some(en) = self.state.entries.iter_mut().find(|en| en.id == order.id) {
            en.phase = Phase::Active;
        }
        if let Err(e) = self.save() {
            let _ = self.motion.revert(&m, &spec);
            self.state.entries.retain(|en| en.id != order.id);
            let mut o = Outcome::bare(&order.id, Status::Failed);
            o.action = Some(order.action);
            o.error = Some(format!("journal commit failed ({e}): undone"));
            return o;
        }
        self.state.event(
            now_ms,
            EventKind::Applied,
            Some(&order.id),
            Some(order.action),
            format!("applied through {adapters}, ttl {ttl} s"),
        );
        self.state.event(
            now_ms,
            EventKind::Verified,
            Some(&order.id),
            Some(order.action),
            note.clone(),
        );
        let _ = self.save();
        let mut o = self.status(&order.id);
        o.note = Some(note);
        o
    }

    /// Undo a motion entry before it is finished as reverted. `Err` with
    /// the answer when the adapter failed (the entry stays `reverting`
    /// and the revert is retried every tick).
    pub(super) fn motion_undo(
        &mut self,
        en: &Entry,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), Box<Outcome>> {
        let Effect::Motion(spec) = &en.effect else {
            return Ok(());
        };
        let m = self.motion_cfg();
        match self.motion.revert(&m, spec) {
            Ok(n) => {
                self.state.event(
                    now_ms,
                    EventKind::Reverted,
                    Some(&en.id),
                    Some(en.action),
                    format!("adapter undo: {n}"),
                );
                Ok(())
            }
            Err(e) => {
                self.state.event(
                    now_ms,
                    EventKind::RevertFailed,
                    Some(&en.id),
                    Some(en.action),
                    format!("{reason}: adapter undo failed ({e}); retried every tick"),
                );
                let _ = self.save();
                let mut o = self.status(&en.id);
                o.error = Some(format!("adapter undo failed: {e}"));
                Err(Box::new(o))
            }
        }
    }

    /// Restart reconciliation: undo a motion entry; `false` when the
    /// adapter failed (the caller keeps it `reverting`).
    pub(super) fn motion_settled(&mut self, en: &Entry, now_ms: u64) -> bool {
        self.motion_undo(en, "at restart", now_ms).is_ok()
    }

    /// Undo without retry (interrupted apply, operator disable): failures
    /// are recorded.
    pub(super) fn motion_best_effort(&mut self, en: &Entry, now_ms: u64, why: &str) {
        let Effect::Motion(spec) = &en.effect else {
            return;
        };
        let m = self.motion_cfg();
        let detail = match self.motion.revert(&m, spec) {
            Ok(n) => format!("{why}: adapter undo: {n}"),
            Err(e) => format!("{why}: adapter undo FAILED ({e}): check the platform"),
        };
        self.state.event(
            now_ms,
            EventKind::Reverted,
            Some(&en.id),
            Some(en.action),
            detail,
        );
    }

    /// After a reboot: apply the motion entries just re-armed (their nft
    /// part, if any, is already installed). A failure reverts the entry.
    pub(super) fn motion_rearmed(&mut self, armed: &[String], now_ms: u64) {
        let m = self.motion_cfg();
        for id in armed {
            let Some(pos) = self.state.entries.iter().position(|x| &x.id == id) else {
                continue;
            };
            let en = self.state.entries[pos].clone();
            let Effect::Motion(mut spec) = en.effect.clone() else {
                continue;
            };
            spec.deadline_ms = en.deadline_ms;
            match self.motion.apply(&m, &spec) {
                Ok(n) => {
                    if let Some(x) = self.state.entries.get_mut(pos) {
                        x.effect = Effect::Motion(spec);
                        x.phase = Phase::Active;
                    }
                    self.state.event(
                        now_ms,
                        EventKind::Verified,
                        Some(id),
                        Some(en.action),
                        format!("re-armed after a reboot: {n}"),
                    );
                }
                Err(e) => {
                    let en = self.state.entries.remove(pos);
                    let why = format!("could not be re-armed after a reboot ({e}): reverted");
                    let _ = self.motion.revert(&m, &spec);
                    self.finish(&en, Final::Reverted, now_ms, &why);
                    self.state
                        .event(now_ms, EventKind::Reverted, Some(id), Some(en.action), why);
                }
            }
        }
    }

    /// Periodic read-back of active, reversible motion actions; a
    /// restriction the gateway no longer reports is written again.
    pub(super) fn motion_verify(&mut self, now_ms: u64) {
        let m = self.motion_cfg();
        let active: Vec<(String, ActionId, MotionSpec)> = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase == Phase::Active)
            .filter_map(|e| match &e.effect {
                Effect::Motion(s) => Some((e.id.clone(), e.action, s.clone())),
                _ => None,
            })
            .collect();
        for (id, action, spec) in active {
            if let Err(diff) = self.motion.verify(&m, &spec) {
                let fixed = self.motion.apply(&m, &spec);
                self.state.event(
                    now_ms,
                    EventKind::Drift,
                    Some(&id),
                    Some(action),
                    match fixed {
                        Ok(_) => format!("motion action not in force ({diff}): re-applied"),
                        Err(e) => {
                            format!("motion action not in force ({diff}); re-applying failed: {e}")
                        }
                    },
                );
                let _ = self.save();
            }
        }
    }
}
