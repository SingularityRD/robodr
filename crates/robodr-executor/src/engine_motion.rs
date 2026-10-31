//! The engine's motion actions (Sprint 8, [`crate::motion`]): submit
//! (journal intent → adapter apply + read back → commit), undo on revert /
//! TTL / restart / operator disable, re-arm after a reboot and the
//! periodic read-back. A child module of [`crate::engine`].
//!
//! Review finding 1 (ADR-0006): a `safe_pause`
//! ([`MotionSpec::lift_needs_people`]) is **never undone automatically**.
//! Its TTL is reported (`expired`, `HIGH: ...`) and the pause stays in
//! force; a restart, an operator's emergency disable, a failed apply,
//! commit or re-arm leave the platform paused and say so. Only
//! [`Engine::revert_request`] lifts it: the SOC's two-person signed revert,
//! then the safety state now (known, fresh, not engaged, allowed by the
//! pause's adapters).

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
                // adapters undo a partial multi-adapter apply themselves);
                // never a pause (review finding 1): its undo may set the
                // robot moving.
                let undo = if spec.lift_needs_people() {
                    Err(
                        "a pause is never undone automatically: check the platform, it may \
                         be paused"
                            .to_string(),
                    )
                } else {
                    self.motion.revert(&m, &spec)
                };
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
            self.state.entries.retain(|en| en.id != order.id);
            let mut o = Outcome::bare(&order.id, Status::Failed);
            o.action = Some(order.action);
            if spec.lift_needs_people() {
                // Review finding 1: left paused (the safe direction).
                o.error = Some(format!(
                    "journal commit failed ({e}): the pause is in force on the platform and \
                     is not undone automatically; an operator restores the robot"
                ));
            } else {
                let _ = self.motion.revert(&m, &spec);
                o.error = Some(format!("journal commit failed ({e}): undone"));
            }
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
    ///
    /// A pause ([`MotionSpec::lift_needs_people`]) is undone only with
    /// `lift` ([`Engine::revert_request`] checked the two-person revert
    /// and the safety state); otherwise, and when its undo fails, it goes
    /// back to `active` (still paused) and `Err` answers why.
    pub(super) fn motion_undo(
        &mut self,
        en: &Entry,
        reason: &str,
        now_ms: u64,
        lift: bool,
    ) -> Result<(), Box<Outcome>> {
        let Effect::Motion(spec) = &en.effect else {
            return Ok(());
        };
        if spec.lift_needs_people() && !lift {
            return Err(self.pause_kept(
                en,
                now_ms,
                format!(
                    "{reason}: a safe_pause is never lifted automatically (ADR-0006): left in \
                     force; lift it with the SOC's two-person signed revert"
                ),
            ));
        }
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
            Err(e) if spec.lift_needs_people() => Err(self.pause_kept(
                en,
                now_ms,
                format!(
                    "{reason}: adapter undo failed ({e}): the pause stays in force (not \
                     retried: a new signed revert re-checks the safety state)"
                ),
            )),
            Err(e) => {
                self.state.event(
                    now_ms,
                    EventKind::RevertFailed,
                    Some(&en.id),
                    Some(en.action),
                    format!(
                        "{reason}: adapter undo failed ({e}); retried every tick (ttl {}s, \
                         deadline {} ms)",
                        en.ttl_s, en.deadline_ms
                    ),
                );
                let _ = self.save();
                let mut o = self.status(&en.id);
                o.error = Some(format!("adapter undo failed: {e}"));
                Err(Box::new(o))
            }
        }
    }

    /// A pause left in force (review finding 1): back to `active` when it
    /// is still an entry, a `HIGH` event, and the answer.
    fn pause_kept(&mut self, en: &Entry, now_ms: u64, why: String) -> Box<Outcome> {
        if let Some(x) = self.state.entries.iter_mut().find(|x| x.id == en.id) {
            x.phase = Phase::Active;
        }
        let why = format!("HIGH: {why}");
        self.state.event(
            now_ms,
            EventKind::Refused,
            Some(&en.id),
            Some(en.action),
            why.clone(),
        );
        let _ = self.save();
        let mut o = self.status(&en.id);
        o.error = Some(why);
        Box::new(o)
    }

    /// The safety state now allows lifting `spec` (a pause): known, fresh,
    /// not engaged ([`decision::recheck_rearm`]) and one its adapters
    /// allow ([`MotionSpec::allowed`]).
    pub(super) fn lift_safety_ok(
        &self,
        spec: &MotionSpec,
        oracle: &mut dyn SafetyOracle,
    ) -> Result<(), Refusal> {
        let current = oracle.current();
        let state = current.as_ref().ok().map(|c| c.state);
        decision::recheck_rearm(current, self.cfg.config.max_safety_age_ms).map_err(|mut r| {
            r.reason = format!("{}: the pause stays in force", r.reason);
            r
        })?;
        match state {
            Some(s) if spec.allowed(&self.motion_cfg(), s) => Ok(()),
            s => Err(Refusal::new(
                codes::SAFETY_STATE_NOT_ALLOWED,
                format!(
                    "lifting {} is not allowed in safety state {} by its adapter(s): the pause \
                     stays in force",
                    spec.action.as_str(),
                    s.map(crate::motion::state_name).unwrap_or_default()
                ),
            )),
        }
    }

    /// TTL expiry of a pause (review finding 1): reported once, never
    /// lifted. `true` when `id` is such a pause (the caller leaves it).
    pub(super) fn pause_outlives_ttl(&mut self, id: &str, now_ms: u64) -> bool {
        let Some(en) = self.state.entry(id) else {
            return false;
        };
        let pause = en.phase == Phase::Active
            && matches!(&en.effect, Effect::Motion(s) if s.lift_needs_people());
        if !pause {
            return false;
        }
        let action = en.action;
        let reported = self
            .state
            .events
            .iter()
            .any(|ev| ev.kind == EventKind::Expired && ev.id.as_deref() == Some(id));
        if !reported {
            self.state.event(
                now_ms,
                EventKind::Expired,
                Some(id),
                Some(action),
                "HIGH: safe_pause reached motion.safe_pause_ttl_s: left in force (a pause is \
                 never lifted automatically, ADR-0006); lift it with the SOC's two-person \
                 signed revert once the robot is safe to move",
            );
            let _ = self.save();
        }
        true
    }

    /// Restart reconciliation: undo a motion entry; `false` when the
    /// adapter failed (the caller keeps it `reverting`). A pause is never
    /// undone here (`false`: the next tick puts it back to `active`).
    pub(super) fn motion_settled(&mut self, en: &Entry, now_ms: u64) -> bool {
        self.motion_undo(en, "at restart", now_ms, false).is_ok()
    }

    /// Undo without retry (interrupted apply, operator disable): failures
    /// are recorded. A pause is left in force (review finding 1).
    pub(super) fn motion_best_effort(&mut self, en: &Entry, now_ms: u64, why: &str) {
        let Effect::Motion(spec) = &en.effect else {
            return;
        };
        if spec.lift_needs_people() {
            self.state.event(
                now_ms,
                EventKind::Refused,
                Some(&en.id),
                Some(en.action),
                format!(
                    "HIGH: {why}: the safe_pause is not undone (never automatically, \
                     ADR-0006): the platform may still be paused; an operator restores it"
                ),
            );
            return;
        }
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
    /// Review F7: a held motion action is re-armed only in a safety state
    /// its adapters allow ([`crate::motion::MotionSpec::allowed`], the
    /// same gate as a fresh submit); `Some(why)` keeps it held.
    pub(super) fn motion_rearm_blocked(
        &self,
        effect: &Effect,
        s: robodr_responder::SafetyState,
    ) -> Option<String> {
        let Effect::Motion(spec) = effect else {
            return None;
        };
        (!spec.allowed(&self.motion_cfg(), s)).then(|| {
            format!(
                "{}: the {} adapter(s) do not allow {} in safety state {}",
                codes::SAFETY_STATE_NOT_ALLOWED,
                spec.adapters
                    .iter()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join("+"),
                spec.action.as_str(),
                crate::motion::state_name(s)
            )
        })
    }

    pub(super) fn motion_rearmed(&mut self, armed: &[String], now_ms: u64) {
        let m = self.motion_cfg();
        for id in armed {
            let Some(pos) = self.state.entries.iter().position(|x| &x.id == id) else {
                continue;
            };
            let Some(en) = self.state.entries.get(pos).cloned() else {
                continue;
            };
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
                    let why = if spec.lift_needs_people() {
                        format!(
                            "HIGH: could not be re-armed after a reboot ({e}): dropped, not \
                             undone (a pause never is automatically): check the platform"
                        )
                    } else {
                        let _ = self.motion.revert(&m, &spec);
                        format!("could not be re-armed after a reboot ({e}): reverted")
                    };
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

    /// The safe_pause latch (sales-readiness T42): every
    /// `motion.safe_pause_latch_s` each pause in force is re-asserted
    /// through its adapter ([`crate::motion::MotionPorts::latch`]). What
    /// someone did to move the robot while paused is an `overridden`
    /// event with a `HIGH:` detail (agentd: a High finding): per pause and
    /// [`crate::engine::LATCH_REPEAT_REPORT_MS`] window the first
    /// [`crate::engine::LATCH_KINDS_PER_WINDOW`] distinct kinds are
    /// reported at once, every further override (the same kind again, or
    /// kinds beyond that budget) is counted and summarised with its count
    /// once the window has passed. A
    /// platform that cannot be read is a `drift` event, once per change of
    /// the error.
    ///
    /// The adapter calls are synchronous: while a run lasts the engine
    /// handles nothing else (reverts, new orders and TTL expiries wait).
    /// One run takes at most the adapter's configured worst case
    /// ([`crate::motion::MotionSection::worst_case_ms`], at most
    /// [`crate::motion::MOTION_BUDGET_MS`] for `nav2`); for `px4` a mode
    /// read plus, when the mode changed, setting hold again: up to twice
    /// `timeout_ms`. The interval is counted from the end of the previous
    /// run, which bounds the share of time a peer that does not answer can
    /// take, not the length of one run.
    pub(super) fn motion_latch(&mut self, now: Now) {
        let now_ms = now.wall_ms;
        let m = self.motion_cfg();
        let mono = now.boot_ms.unwrap_or(now_ms);
        let every = m.safe_pause_latch_s.saturating_mul(1000);
        if mono.abs_diff(self.last_latch_boot_ms) < every {
            return;
        }
        let pauses: Vec<(String, ActionId, MotionSpec)> = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase == Phase::Active)
            .filter_map(|e| match &e.effect {
                Effect::Motion(s) if s.lift_needs_people() => {
                    Some((e.id.clone(), e.action, s.clone()))
                }
                _ => None,
            })
            .collect();
        self.latch_errors
            .retain(|id, _| pauses.iter().any(|(p, _, _)| p == id));
        self.latch_overrides
            .retain(|id, _| pauses.iter().any(|(p, _, _)| p == id));
        const REPEAT: u64 = crate::engine::LATCH_REPEAT_REPORT_MS;
        const KINDS: usize = crate::engine::LATCH_KINDS_PER_WINDOW;
        if pauses.is_empty() {
            self.last_latch_boot_ms = mono;
            return;
        }
        let started = std::time::Instant::now();
        for (id, action, spec) in pauses {
            match self.motion.latch(&m, &spec) {
                Ok(crate::motion::Latch::Held(_)) => {
                    if self.latch_errors.remove(&id).is_some() {
                        self.state.event(
                            now_ms,
                            EventKind::Verified,
                            Some(&id),
                            Some(action),
                            "safe_pause latch: the platform answers again and is paused",
                        );
                        let _ = self.save();
                    }
                }
                Ok(crate::motion::Latch::Overridden { kind, note }) => {
                    self.latch_errors.remove(&id);
                    // Review (T42): per pause and report window, the first
                    // LATCH_KINDS_PER_WINDOW distinct kinds are reported;
                    // the same kind again, or any kind beyond that budget
                    // (alternating modes), is counted, not reported (it
                    // was cancelled / set back to hold all the same).
                    let s = self.latch_overrides.entry(id.clone()).or_insert_with(|| {
                        crate::engine::OverrideSeen {
                            window_ms: mono,
                            ..Default::default()
                        }
                    });
                    if mono.saturating_sub(s.window_ms) >= REPEAT {
                        s.window_ms = mono;
                        s.reported.clear();
                    }
                    if s.reported.contains(&kind) || s.reported.len() >= KINDS {
                        s.count(kind, note);
                    } else {
                        let earlier = match s.take_unreported() {
                            Some((n, kinds, last)) => format!(
                                " (before it: {n} further override(s) of kind(s) {kinds} not \
                                 reported separately, the last: {last})"
                            ),
                            None => String::new(),
                        };
                        s.reported.push(kind);
                        self.state.event(
                            now_ms,
                            EventKind::Overridden,
                            Some(&id),
                            Some(action),
                            format!(
                                "HIGH: the robot was set moving while safe_pause {id} is in \
                                 force: {note}; the pause stays in force until the SOC's \
                                 two-person signed revert; at most {KINDS} kinds of override \
                                 are reported at once per {} s, further ones are counted{earlier}",
                                REPEAT / 1000
                            ),
                        );
                        let _ = self.save();
                    }
                }
                Err(e) => {
                    if self.latch_errors.get(&id) != Some(&e) {
                        self.state.event(
                            now_ms,
                            EventKind::Drift,
                            Some(&id),
                            Some(action),
                            format!(
                                "safe_pause latch could not read the platform ({e}): a goal or \
                                 mode change made meanwhile is not cancelled; retried every \
                                 {} s",
                                m.safe_pause_latch_s
                            ),
                        );
                        let _ = self.save();
                        self.latch_errors.insert(id.clone(), e);
                    }
                }
            }
            // Overrides counted and not reported: summarised once the
            // window has passed, even if none follows. The summary opens
            // the next window with the kinds it named as reported, so a
            // steady repeat is one event per window.
            let due = self.latch_overrides.get_mut(&id).and_then(|s| {
                if s.unreported == 0 || mono.saturating_sub(s.window_ms) < REPEAT {
                    return None;
                }
                let kinds_now = s.unreported_kinds.clone();
                let (n, kinds, last) = s.take_unreported()?;
                s.window_ms = mono;
                s.reported = kinds_now.into_iter().take(KINDS).collect();
                Some(format!(
                    "HIGH: the robot was set moving again while safe_pause {id} is in force: \
                     {n} further override(s) of kind(s) {kinds} since the last report, each \
                     cancelled / set back to hold, the last: {last}; the pause stays in force \
                     until the SOC's two-person signed revert"
                ))
            });
            if let Some(detail) = due {
                self.state.event(
                    now_ms,
                    EventKind::Overridden,
                    Some(&id),
                    Some(action),
                    detail,
                );
                let _ = self.save();
            }
        }
        let took = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_latch_boot_ms = mono.saturating_add(took);
    }
}
