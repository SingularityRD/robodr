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
//! * **Rate limiting.** Robot-wide, a plan whose step is not higher than the
//!   last issued one, arriving within `min_reissue_interval_ms`, is reduced to
//!   Record (`suppressed = true`). Escalations are never delayed; repeats are.
//!   Combined with the hold, the requested response is monotone between
//!   acknowledgements, so a deviation storm cannot make the robot oscillate.
//! * **Bounded memory.** At most [`MAX_SOURCES`] tracked sources, each with at
//!   most [`MAX_HITS`] timestamps and a key of at most [`MAX_SOURCE_KEY_LEN`]
//!   bytes. When the table is full, further new sources share one overflow
//!   bucket (which escalates like any source), so flooding fresh source ids
//!   neither grows memory nor evicts the escalation state of real offenders.
//!
//! Time is the caller's monotonic clock in milliseconds. A clock that steps
//! backwards is treated as "no time elapsed" (never as a reset).

use robodr_events::Deviation;

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
    /// Highest step issued robot-wide since the last reset.
    issued_step: Step,
    last_issue: Option<u64>,
    last_any: Option<u64>,
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
            issued_step: Step::Record,
            last_issue: None,
            last_any: None,
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

        // Robot-wide quiet period resets the rate limiter's memory.
        if self
            .last_any
            .is_some_and(|t| now.saturating_sub(t) >= esc.quiet_period_ms)
        {
            self.issued_step = Step::Record;
            self.last_issue = None;
        }
        self.last_any = Some(now);

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

        let key = truncate_key(source);
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

        // Rate limiting: only repeats are delayed, never escalations.
        if plan.max_step > Step::Record {
            let recent = self
                .last_issue
                .map(|t| now.saturating_sub(t))
                .filter(|&d| d < esc.min_reissue_interval_ms);
            match recent {
                Some(since) if plan.max_step <= self.issued_step => {
                    plan.rationale.push(Reason::RateLimited { since_ms: since });
                    plan.actions = vec![ResponseAction::Record];
                    plan.max_step = Step::Record;
                    plan.requires_human_approval = false;
                    plan.suppressed = true;
                }
                _ => {
                    self.issued_step = self.issued_step.max(plan.max_step);
                    self.last_issue = Some(now);
                }
            }
        }
        enforce(plan, state, ctx)
    }

    /// Operator acknowledgement: the only explicit de-escalation. With
    /// `Some(source)` that source is reset; with `None` every source and the
    /// robot-wide rate limiter are reset. Returns whether anything was reset.
    ///
    /// This only clears the responder's memory; lifting restrictions already
    /// applied on the platform is a separate operator action.
    pub fn acknowledge(&mut self, source: Option<&str>, now_ms: u64) -> bool {
        self.advance(now_ms);
        match source {
            Some(src) => {
                let key = truncate_key(src);
                match self.find_mut(key) {
                    Some(s) => {
                        s.reset();
                        true
                    }
                    None => false,
                }
            }
            None => {
                let any = !self.sources.is_empty()
                    || self.overflow.is_some()
                    || self.last_issue.is_some();
                self.sources.clear();
                self.overflow = None;
                self.issued_step = Step::Record;
                self.last_issue = None;
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
