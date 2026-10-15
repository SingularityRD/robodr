//! Stateful responder: escalation, hysteresis and rate limiting on top of the
//! pure planner, with fixed memory bounds.
//!
//! * **Escalation.** Each source (participant GUID, process, link... — the
//!   caller chooses the key) keeps the timestamps of its recent deviations.
//!   When `threshold` of them fall inside `window_ms`, the source's escalation
//!   level rises by one (up to `max_escalation_steps`, itself <= 2) and the
//!   counter restarts, so each further rung needs another full burst.
//! * **Hysteresis.** A source's planned step never goes down on its own: it is
//!   held until an operator calls [`Responder::acknowledge`] or the source is
//!   quiet for `quiet_period_ms`, which resets it completely.
//! * **Observe-mode deviations** ([`Deviation::is_observe_only`]) are
//!   informational: they are planned (Record only, with `would_have`) from the
//!   source's current state but change no state at all — no source entry, no
//!   escalation hit, no hold, no rate-limit memory.
//! * **Rate limiting, per (source, rule).** Only plans that are
//!   *auto-executable* (above Record, no human approval, not observe-only)
//!   are remembered as issued. A later auto-executable plan for the **same**
//!   source key and rule, not higher than the remembered step and arriving
//!   within `min_reissue_interval_ms`, is reduced to Record
//!   (`suppressed = true`). Escalations are never delayed. Plans awaiting
//!   approval are never suppressed and never suppress anything; another
//!   source's activity never sets `suppressed`.
//! * **Robot-wide motion guard.** Against oscillation/re-spamming of the
//!   Motion Firewall and mission executive, an auto-executable
//!   motion-affecting plan whose step *and* severity are both not higher than
//!   the motion-affecting auto step issued robot-wide within
//!   `min_reissue_interval_ms` has only its motion-affecting actions dropped
//!   (`Reason::MotionAlreadyRequested`): that step is already requested and
//!   plans never relax. Its Record and Restrict actions, which concern its own
//!   source, are kept, so the plan is not `suppressed`. A plan of higher
//!   severity or higher step always passes and becomes the new reference.
//!   Combined with the hold, the requested motion response is monotone within
//!   the interval.
//! * **Bounded memory.** At most [`MAX_SOURCES`] tracked sources, each with at
//!   most [`MAX_HITS`] timestamps and a key of at most [`MAX_SOURCE_KEY_LEN`]
//!   bytes. When the table is full, further new sources share one overflow
//!   bucket (which escalates like any source), so flooding fresh source ids
//!   neither grows memory nor evicts the escalation state of real offenders.
//!   The rate-limit memory holds at most [`MAX_REISSUE_KEYS`] (source, rule)
//!   entries, keyed by the real (truncated) source key even for overflow
//!   sources; entries expire after `min_reissue_interval_ms`; when full the
//!   oldest is evicted. Eviction can only cause a redundant re-issue, never a
//!   suppression.
//!
//! # What a flood of decoys can and cannot do
//!
//! An attacker who can raise deviations under arbitrary fresh source keys:
//! * cannot get a different source's plan `suppressed` (rate limit is per
//!   (source, rule) key);
//! * cannot downgrade a plan of higher severity or higher step (motion guard
//!   only drops a motion request already in force at the same or a higher
//!   rung, raised by a plan of the same or higher severity — i.e. the decoys
//!   must themselves have triggered at least that motion response, and keep
//!   doing so at least once per interval);
//! * cannot keep a real source from being restricted (Restrict is never
//!   dropped by the motion guard);
//! * can flood the console with approval requests (one per decoy); these are
//!   not deduplicated here — the console should aggregate them, and the flood
//!   is itself evidence;
//! * can push new real sources into the shared overflow escalation bucket
//!   (more active, never less) and churn the bounded rate-limit memory
//!   (redundant re-issues, never fewer responses).
//!
//! Time is the caller's monotonic clock in milliseconds. A clock that steps
//! backwards is treated as "no time elapsed" (never as a reset).

use robodr_events::Deviation;

use robodr_events::Severity;

use crate::action::{Reason, ResponseAction, ResponsePlan, Step};
use crate::planner::{enforce, plan_with};
use crate::policy::{PolicyError, ResponsePolicy, MAX_ESCALATION_THRESHOLD};
use crate::state::{OperationalContext, SafetyState};

/// Maximum number of individually tracked sources.
pub const MAX_SOURCES: usize = 64;
/// Maximum timestamps kept per source (>= any valid threshold).
pub const MAX_HITS: usize = MAX_ESCALATION_THRESHOLD as usize;
/// Source keys longer than this are truncated (at a char boundary).
pub const MAX_SOURCE_KEY_LEN: usize = 128;
/// Key of the shared overflow bucket.
pub const OVERFLOW_SOURCE: &str = "<overflow>";
/// Maximum (source, rule) entries remembered by the rate limiter.
pub const MAX_REISSUE_KEYS: usize = 256;

/// An auto-executable plan issued for one (source, rule).
#[derive(Debug, Clone)]
struct Issued {
    source: String,
    rule: String,
    step: Step,
    at: u64,
}

/// The highest auto-executable motion-affecting request issued robot-wide
/// within the current re-issue interval.
#[derive(Debug, Clone, Copy)]
struct MotionIssued {
    step: Step,
    severity: Severity,
    at: u64,
}

#[derive(Debug, Clone)]
struct SourceState {
    key: String,
    hits: Vec<u64>,
    level: u8,
    held: Step,
    last_seen: u64,
}

impl SourceState {
    fn new(key: String, now: u64) -> Self {
        SourceState {
            key,
            hits: Vec::with_capacity(4),
            level: 0,
            held: Step::Record,
            last_seen: now,
        }
    }

    fn reset(&mut self) {
        self.hits.clear();
        self.level = 0;
        self.held = Step::Record;
    }
}

/// The stateful Cyber-Jidoka responder for one robot.
#[derive(Debug, Clone)]
pub struct Responder {
    policy: ResponsePolicy,
    sources: Vec<SourceState>,
    overflow: Option<SourceState>,
    /// Per-(source, rule) memory of auto-executable plans (rate limit).
    issued: Vec<Issued>,
    /// Robot-wide motion guard reference.
    motion: Option<MotionIssued>,
    now: u64,
}

impl Responder {
    /// Build a responder. The policy is validated; an invalid policy is
    /// refused rather than silently corrected.
    pub fn new(policy: ResponsePolicy) -> Result<Self, PolicyError> {
        policy.validate()?;
        Ok(Responder {
            policy,
            sources: Vec::new(),
            overflow: None,
            issued: Vec::new(),
            motion: None,
            now: 0,
        })
    }

    pub fn policy(&self) -> &ResponsePolicy {
        &self.policy
    }

    /// Number of individually tracked sources (excluding overflow).
    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }

    /// Current escalation level of a source (0 if untracked).
    pub fn escalation_level(&self, source: &str) -> u8 {
        let key = truncate_key(source);
        self.sources
            .iter()
            .chain(self.overflow.iter())
            .find(|s| s.key == key)
            .map_or(0, |s| s.level)
    }

    /// Number of (source, rule) entries in the rate-limit memory
    /// (<= [`MAX_REISSUE_KEYS`]).
    pub fn rate_limit_entries(&self) -> usize {
        self.issued.len()
    }

    /// Plan the response to `deviation` from `source` at time `now_ms`.
    pub fn plan(
        &mut self,
        deviation: &Deviation,
        source: &str,
        state: SafetyState,
        ctx: &OperationalContext,
        now_ms: u64,
    ) -> ResponsePlan {
        let now = self.advance(now_ms);
        let esc = self.policy.escalation;
        let key = truncate_key(source);

        // Observe-mode deviation: informational only. Plan from the current
        // state (for an accurate `would_have`) without changing any of it.
        if deviation.is_observe_only() {
            let (level, held) = self
                .sources
                .iter()
                .find(|s| s.key == key && now.saturating_sub(s.last_seen) < esc.quiet_period_ms)
                .map_or((0, Step::Record), |s| (s.level, s.held));
            return plan_with(&self.policy, deviation, key, state, ctx, level, held).0;
        }

        // Rate-limit memory only matters within the re-issue interval.
        let interval = esc.min_reissue_interval_ms;
        self.issued.retain(|e| now.saturating_sub(e.at) < interval);
        if self
            .motion
            .is_some_and(|m| now.saturating_sub(m.at) >= interval)
        {
            self.motion = None;
        }

        // Per-source quiet period: drop (= fully de-escalate) stale sources.
        self.sources
            .retain(|s| now.saturating_sub(s.last_seen) < esc.quiet_period_ms);
        if self
            .overflow
            .as_ref()
            .is_some_and(|s| now.saturating_sub(s.last_seen) >= esc.quiet_period_ms)
        {
            self.overflow = None;
        }

        let src = self.source_mut(key, now);

        // Escalation bookkeeping.
        src.hits.retain(|&t| now.saturating_sub(t) < esc.window_ms);
        if src.hits.len() >= MAX_HITS {
            src.hits.remove(0);
        }
        src.hits.push(now);
        if src.hits.len() >= esc.threshold as usize {
            if src.level < esc.max_escalation_steps {
                src.level += 1;
            }
            src.hits.clear();
        }
        src.last_seen = now;
        let (level, held, src_key) = (src.level, src.held, src.key.clone());

        let (mut plan, desired) = plan_with(&self.policy, deviation, key, state, ctx, level, held);
        if let Some(s) = self.find_mut(&src_key) {
            s.held = s.held.max(desired);
        }

        // Rate limiting applies only to auto-executable plans; plans awaiting
        // approval execute nothing on their own and are never counted.
        let auto =
            plan.max_step > Step::Record && !plan.requires_human_approval && !plan.observe_only;
        if auto {
            let rule = truncate_key(deviation.rule_str());
            let prior = self
                .issued
                .iter()
                .position(|e| e.source == key && e.rule == rule);
            match prior.map(|i| &self.issued[i]) {
                // 1. Same (source, rule) repeat: reduce to Record.
                Some(e) if plan.max_step <= e.step => {
                    plan.rationale.push(Reason::RateLimited {
                        since_ms: now.saturating_sub(e.at),
                    });
                    plan.actions = vec![ResponseAction::Record];
                    plan.max_step = Step::Record;
                    plan.requires_human_approval = false;
                    plan.suppressed = true;
                }
                _ => {
                    let issued_step = plan.max_step;
                    // 2. Robot-wide motion guard.
                    if issued_step.is_motion_affecting() {
                        match self.motion {
                            Some(m) if issued_step <= m.step && plan.severity <= m.severity => {
                                plan.actions.retain(|a| !a.step().is_motion_affecting());
                                plan.max_step = plan
                                    .actions
                                    .iter()
                                    .map(|a| a.step())
                                    .max()
                                    .unwrap_or(Step::Record);
                                plan.rationale.push(Reason::MotionAlreadyRequested {
                                    step: m.step,
                                    since_ms: now.saturating_sub(m.at),
                                });
                            }
                            prev => {
                                self.motion = Some(MotionIssued {
                                    step: prev.map_or(issued_step, |m| m.step.max(issued_step)),
                                    severity: prev
                                        .map_or(plan.severity, |m| m.severity.max(plan.severity)),
                                    at: now,
                                });
                            }
                        }
                    }
                    // Remember what this (source, rule) asked for (before the
                    // motion guard: the motion part is in force either way).
                    let entry = Issued {
                        source: key.to_string(),
                        rule: rule.to_string(),
                        step: issued_step,
                        at: now,
                    };
                    match prior {
                        Some(i) => self.issued[i] = entry,
                        None => {
                            if self.issued.len() >= MAX_REISSUE_KEYS {
                                if let Some(oldest) = self
                                    .issued
                                    .iter()
                                    .enumerate()
                                    .min_by_key(|(_, e)| e.at)
                                    .map(|(i, _)| i)
                                {
                                    self.issued.swap_remove(oldest);
                                }
                            }
                            self.issued.push(entry);
                        }
                    }
                }
            }
        }
        enforce(plan, deviation, state, ctx)
    }

    /// Operator acknowledgement: the only explicit de-escalation. With
    /// `Some(source)` that source's escalation, hold and rate-limit memory are
    /// reset; with `None` every source, the rate limiter and the robot-wide
    /// motion guard are reset. Returns whether anything was reset.
    ///
    /// This only clears the responder's memory; lifting restrictions already
    /// applied on the platform is a separate operator action.
    pub fn acknowledge(&mut self, source: Option<&str>, now_ms: u64) -> bool {
        self.advance(now_ms);
        match source {
            Some(src) => {
                let key = truncate_key(src);
                let before = self.issued.len();
                self.issued.retain(|e| e.source != key);
                let dropped = self.issued.len() != before;
                match self.find_mut(key) {
                    Some(s) => {
                        s.reset();
                        true
                    }
                    None => dropped,
                }
            }
            None => {
                let any = !self.sources.is_empty()
                    || self.overflow.is_some()
                    || !self.issued.is_empty()
                    || self.motion.is_some();
                self.sources.clear();
                self.overflow = None;
                self.issued.clear();
                self.motion = None;
                any
            }
        }
    }

    fn advance(&mut self, now_ms: u64) -> u64 {
        self.now = self.now.max(now_ms);
        self.now
    }

    fn find_mut(&mut self, key: &str) -> Option<&mut SourceState> {
        if let Some(i) = self.sources.iter().position(|s| s.key == key) {
            return self.sources.get_mut(i);
        }
        self.overflow.as_mut().filter(|s| s.key == key)
    }

    fn source_mut(&mut self, key: &str, now: u64) -> &mut SourceState {
        if let Some(i) = self.sources.iter().position(|s| s.key == key) {
            return &mut self.sources[i];
        }
        if self.sources.len() < MAX_SOURCES && key != OVERFLOW_SOURCE {
            self.sources.push(SourceState::new(key.to_string(), now));
            let last = self.sources.len() - 1;
            return &mut self.sources[last];
        }
        self.overflow
            .get_or_insert_with(|| SourceState::new(OVERFLOW_SOURCE.to_string(), now))
    }
}

fn truncate_key(s: &str) -> &str {
    if s.len() <= MAX_SOURCE_KEY_LEN {
        return s;
    }
    let mut end = MAX_SOURCE_KEY_LEN;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}
