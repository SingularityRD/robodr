//! The correlation engine: per-rule, per-group bounded state machines.
//!
//! # Time
//!
//! Signals carry a monotonic timestamp. The engine keeps the largest time
//! seen (`now`). A signal whose time is *smaller* than `now` (clock stepped
//! back, producers with skewed clocks, reordering) is processed at `now`
//! and counted in [`Stats::clock_regressions`]: state never moves backwards,
//! a window never grows because of a regression and nothing panics. The
//! signal's own time is kept in the evidence ([`Contribution::t_ns`]) next
//! to the time it was processed at ([`Contribution::at_ns`]). A bogus jump
//! *forward* expires all pending state (fail-open towards the individual
//! findings, which were already reported on their own).
//!
//! Windows are inclusive: two signals exactly `window` apart correlate,
//! `window + 1 ns` apart do not.
//!
//! # Memory
//!
//! * Per group: a sequence keeps one partial match per prefix length
//!   (at most `steps - 1`, each at most `steps` signals); a co-occurrence /
//!   threshold keeps at most `count` signals per slot; distinct-sources at
//!   most `count - 1` values. Validation caps all of these
//!   ([`crate::rules::MAX_REQUIRED_SIGNALS`]).
//! * Per rule: at most [`Limits::max_groups_per_rule`] groups.
//! * Per signal: at most [`Limits::max_entities_per_signal`] entities, each
//!   value and the evidence ref at most [`Limits::max_value_len`] bytes.
//!
//! # Eviction and fairness
//!
//! Every group gets a **protection tier** when it is created:
//!
//! * **2, known**: its group entity is a *known* one, i.e. the integrator
//!   registered it with [`Correlator::set_known_entities`] (agentd: the
//!   profile's participants and the IPs bound to them);
//! * **1, severe**: the signal that started it (step 0) is High or
//!   Critical;
//! * **0**: anything else (an unknown entity, Low / Medium).
//!
//! Tiers 1 and 2 are *protected*. Each rule reserves
//! [`Limits::protected_reserve_pct`] percent of its table for protected
//! groups: unprotected groups may hold at most the rest.
//!
//! When a signal needs a new group and the table (or, for an unprotected
//! newcomer, the unprotected share) is full, the engine first drops expired
//! state, then evicts the first group in the order (tier, progress, least
//! recently touched) that holds at most one signal (no more evidence than
//! the newcomer would) and whose tier is not above the newcomer's. So
//! unknown-entity, low-severity groups go first, and an unprotected
//! newcomer can never displace a protected group. Without such a victim
//! the newcomer is refused ([`Stats::groups_refused`]). Consequence: a
//! flood of fresh entities churns only single-signal groups of its own
//! tier or below; a group that has accumulated two or more signals can
//! only be removed by expiry or by firing.
//!
//! Evictions are counted globally ([`Stats::groups_evicted`]) and per rule
//! ([`Correlator::evictions_of`]). Evicting a group that held evidence also
//! queues an observe-only notice, `robot.correlate.correlation_state_evicted`
//! ([`EVICTED_RULE_ID`], Medium), naming the rule and citing the evicted
//! evidence, at most once per rule per rule window; the integrator collects
//! notices with [`Correlator::take_notices`] and reports them like
//! findings. (A flood of the *same* tier, e.g. High-severity mismatches from
//! fresh spoofed IPs against a group whose entity is not known, can still
//! evict it; the notice makes that visible instead of silent.)
//!
//! # Cooldown
//!
//! After a rule fires for a group, its state is cleared and the group
//! ignores matching signals for `cooldown` ([`Stats::suppressed_cooldown`]).
//! A group in cooldown holds no evidence, so it is the first candidate for
//! eviction; losing it can only cause an *extra* finding, never a missed
//! one.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use robodr_events::{Deviation, Mode, Severity};
use serde::Serialize;

use crate::rules::{Pattern, Rule, RuleSet, MAX_ID_LEN, RULE_ID_PREFIX};
use crate::signal::{bounded_entities, truncate_in_place, Domain, Entity, EntityKind, Signal};

/// Engine-wide memory bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most live groups per rule (>= 1; 0 is treated as 1).
    pub max_groups_per_rule: usize,
    /// Most entities kept from one signal (extra are dropped and counted).
    pub max_entities_per_signal: usize,
    /// Longest entity value / evidence ref kept, bytes.
    pub max_value_len: usize,
    /// Percent (0..=100, larger is clamped) of each rule's group table that
    /// unprotected groups cannot use (module docs, "Eviction and
    /// fairness"). Always leaves at least one unprotected slot.
    pub protected_reserve_pct: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_groups_per_rule: 256,
            max_entities_per_signal: 8,
            max_value_len: 256,
            protected_reserve_pct: 25,
        }
    }
}

impl Limits {
    /// Slots of a rule's table reserved for protected groups.
    pub fn protected_reserve(&self) -> usize {
        let cap = self.max_groups_per_rule.max(1);
        (cap * usize::from(self.protected_reserve_pct.min(100)) / 100).min(cap - 1)
    }
}

/// Rule id of the eviction notice ([`Correlator::take_notices`]).
pub const EVICTED_RULE_ID: &str = "robot.correlate.correlation_state_evicted";
/// Most known entities per [`EntityKind`] ([`Correlator::set_known_entities`]).
pub const MAX_KNOWN_ENTITIES: usize = 4096;
/// Most notices queued between two [`Correlator::take_notices`] calls.
pub const MAX_PENDING_NOTICES: usize = 64;

/// Counters. All saturating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    /// Signals passed to [`Correlator::observe`].
    pub signals: u64,
    /// Signals with a `robot.correlate.*` rule id (ignored: no feedback).
    pub ignored_correlation_inputs: u64,
    /// Signals (or ticks) whose time was before the latest time seen.
    pub clock_regressions: u64,
    /// Entities beyond `max_entities_per_signal`, dropped.
    pub entities_dropped: u64,
    /// Entity values / evidence refs / rule ids cut to the length limit.
    pub values_truncated: u64,
    /// A signal matched a grouped rule but carried no entity of the
    /// rule's `group_by` kind.
    pub missing_group_entity: u64,
    /// Correlated findings emitted.
    pub findings: u64,
    pub groups_created: u64,
    /// Groups removed because all their state expired.
    pub groups_expired: u64,
    /// Groups with pending state evicted to make room (LRU, lowest progress).
    pub groups_evicted: u64,
    /// New groups refused because every live group held more evidence (or
    /// was better protected).
    pub groups_refused: u64,
    /// Eviction notices queued ([`Correlator::take_notices`]).
    pub eviction_notices: u64,
    /// Eviction notices not queued: rate limit (one per rule per window)
    /// or a full queue.
    pub eviction_notices_suppressed: u64,
    /// Known-entity values beyond [`MAX_KNOWN_ENTITIES`], ignored.
    pub known_entities_dropped: u64,
    /// Matching signals ignored because the group was in cooldown.
    pub suppressed_cooldown: u64,
}

/// One input signal as cited by a finding.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Contribution {
    /// Engine-assigned sequence number of the signal: its 1-based position
    /// among all signals passed to [`Correlator::observe`] (ignored ones
    /// included). Lets a consumer match citations to its own input log.
    pub seq: u64,
    pub rule: String,
    pub severity: Severity,
    pub mode: Mode,
    pub domain: Domain,
    /// The signal's own timestamp.
    pub t_ns: u64,
    /// The time it was processed at (differs from `t_ns` only after a clock
    /// regression).
    pub at_ns: u64,
    pub entities: Vec<Entity>,
    pub evidence_ref: Option<String>,
}

/// A finding produced by combining several signals.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CorrelatedFinding {
    /// The correlation rule id (`robot.correlate.*`).
    pub rule: String,
    pub title: String,
    pub severity: Severity,
    /// `observe` if any contributor was observe-only.
    pub mode: Mode,
    /// Engine time at which the rule fired.
    pub at_ns: u64,
    /// The group the rule fired for (`None` for unit-scoped rules).
    pub group: Option<Entity>,
    pub window_ns: u64,
    /// Every contributing signal, by `seq`.
    pub contributors: Vec<Contribution>,
    /// One-line summary built only from trusted text (rule title, counts,
    /// contributing rule ids): no entity values.
    pub detail: String,
}

impl CorrelatedFinding {
    /// The finding as a [`Deviation`] for `Agent::handle_external`.
    pub fn to_deviation(&self) -> Deviation {
        Deviation::new(self.rule.clone(), self.severity, self.detail.clone()).with_mode(self.mode)
    }
}

#[derive(Debug, Clone)]
struct Partial {
    start: u64,
    contribs: Vec<Arc<Contribution>>,
}

#[derive(Debug, Clone)]
enum GroupState {
    /// `partials[k]` = best match of steps `0..=k` (latest start).
    Seq(Vec<Option<Partial>>),
    Slots(Vec<VecDeque<Arc<Contribution>>>),
    Distinct(BTreeMap<String, Arc<Contribution>>),
}

impl GroupState {
    fn new(p: &Pattern) -> Self {
        match p {
            Pattern::Sequence(ms) => GroupState::Seq(vec![None; ms.len().saturating_sub(1)]),
            Pattern::Slots(ms) => GroupState::Slots(vec![VecDeque::new(); ms.len()]),
            Pattern::Distinct { .. } => GroupState::Distinct(BTreeMap::new()),
        }
    }

    fn progress(&self) -> usize {
        match self {
            GroupState::Seq(ps) => ps
                .iter()
                .flatten()
                .map(|p| p.contribs.len())
                .max()
                .unwrap_or(0),
            GroupState::Slots(ss) => ss.iter().map(VecDeque::len).sum(),
            GroupState::Distinct(m) => m.len(),
        }
    }

    /// Every held contribution, by `seq`, without duplicates.
    fn contributions(&self) -> Vec<Arc<Contribution>> {
        let mut all: Vec<Arc<Contribution>> = match self {
            GroupState::Seq(ps) => ps
                .iter()
                .flatten()
                .flat_map(|p| p.contribs.iter().cloned())
                .collect(),
            GroupState::Slots(ss) => ss.iter().flat_map(|s| s.iter().cloned()).collect(),
            GroupState::Distinct(m) => m.values().cloned().collect(),
        };
        all.sort_by_key(|c| c.seq);
        all.dedup_by_key(|c| c.seq);
        all
    }

    /// Drop everything older than `window` before `now`.
    fn expire(&mut self, now: u64, window: u64) {
        let live = |t: u64| now.saturating_sub(t) <= window;
        match self {
            GroupState::Seq(ps) => {
                for p in ps.iter_mut() {
                    if p.as_ref().is_some_and(|x| !live(x.start)) {
                        *p = None;
                    }
                }
            }
            GroupState::Slots(ss) => {
                for s in ss.iter_mut() {
                    while s.front().is_some_and(|c| !live(c.at_ns)) {
                        s.pop_front();
                    }
                }
            }
            GroupState::Distinct(m) => m.retain(|_, c| live(c.at_ns)),
        }
    }

    fn clear(&mut self) {
        match self {
            GroupState::Seq(ps) => ps.iter_mut().for_each(|p| *p = None),
            GroupState::Slots(ss) => ss.iter_mut().for_each(VecDeque::clear),
            GroupState::Distinct(m) => m.clear(),
        }
    }
}

#[derive(Debug, Clone)]
struct Group {
    state: GroupState,
    cooldown_until: Option<u64>,
    touch: u64,
    /// Protection tier (module docs): 0 unprotected, 1 severe, 2 known.
    tier: u8,
    /// `(progress, touch)` as currently stored in the rule's index.
    indexed: (usize, u64),
}

impl Group {
    fn expire(&mut self, now: u64, window: u64) {
        self.state.expire(now, window);
        if self.cooldown_until.is_some_and(|u| u <= now) {
            self.cooldown_until = None;
        }
    }

    fn dead(&self) -> bool {
        self.cooldown_until.is_none() && self.state.progress() == 0
    }
}

#[derive(Debug, Clone, Default)]
struct RuleState {
    groups: BTreeMap<String, Group>,
    /// `(tier, progress, touch, key)` for eviction order.
    index: BTreeSet<(u8, usize, u64, String)>,
    /// Live groups of tier 0.
    unprotected: usize,
    /// Groups of this rule evicted so far.
    evictions: u64,
    /// When an eviction notice was last queued for this rule.
    notice_at: Option<u64>,
}

impl RuleState {
    fn insert(&mut self, key: &str, g: Group) {
        self.index
            .insert((g.tier, g.indexed.0, g.indexed.1, key.to_string()));
        if g.tier == 0 {
            self.unprotected += 1;
        }
        if let Some(old) = self.groups.insert(key.to_string(), g) {
            // Not reached (callers insert new keys only); keep the counts
            // right anyway.
            self.index
                .remove(&(old.tier, old.indexed.0, old.indexed.1, key.to_string()));
            if old.tier == 0 {
                self.unprotected = self.unprotected.saturating_sub(1);
            }
        }
    }

    fn sync(&mut self, key: &str) {
        if let Some(g) = self.groups.get_mut(key) {
            let now_idx = (g.state.progress(), g.touch);
            if now_idx != g.indexed {
                self.index
                    .remove(&(g.tier, g.indexed.0, g.indexed.1, key.to_string()));
                self.index
                    .insert((g.tier, now_idx.0, now_idx.1, key.to_string()));
                g.indexed = now_idx;
            }
        }
    }

    fn remove(&mut self, key: &str) -> Option<Group> {
        let g = self.groups.remove(key)?;
        self.index
            .remove(&(g.tier, g.indexed.0, g.indexed.1, key.to_string()));
        if g.tier == 0 {
            self.unprotected = self.unprotected.saturating_sub(1);
        }
        Some(g)
    }

    /// Expire every group; remove dead ones. Returns how many were removed.
    fn sweep(&mut self, now: u64, window: u64) -> u64 {
        let mut dead = Vec::new();
        let keys: Vec<String> = self.groups.keys().cloned().collect();
        for k in keys {
            if let Some(g) = self.groups.get_mut(&k) {
                g.expire(now, window);
                if g.dead() {
                    dead.push(k.clone());
                }
            }
            self.sync(&k);
        }
        let n = dead.len() as u64;
        for k in dead {
            self.remove(&k);
        }
        n
    }
}

/// The correlation engine for one robot (or one feed). Single-threaded,
/// deterministic: the same signals in the same order give the same findings.
#[derive(Debug, Clone)]
pub struct Correlator {
    rules: Vec<Rule>,
    states: Vec<RuleState>,
    limits: Limits,
    stats: Stats,
    now: Option<u64>,
    seq: u64,
    touch: u64,
    /// Known entity values per kind (tier 2).
    known: BTreeMap<EntityKind, BTreeSet<String>>,
    /// Eviction notices not yet taken.
    notices: Vec<CorrelatedFinding>,
}

enum Applied {
    Nothing,
    Progress,
    Fire(Vec<Arc<Contribution>>),
}

impl Correlator {
    pub fn new(rules: RuleSet, limits: Limits) -> Self {
        let limits = Limits {
            max_groups_per_rule: limits.max_groups_per_rule.max(1),
            ..limits
        };
        let states = vec![RuleState::default(); rules.rules.len()];
        Correlator {
            rules: rules.rules,
            states,
            limits,
            stats: Stats::default(),
            now: None,
            seq: 0,
            touch: 0,
            known: BTreeMap::new(),
            notices: Vec::new(),
        }
    }

    /// The shipped default rules with default limits.
    pub fn with_defaults() -> Self {
        Correlator::new(RuleSet::default_rules(), Limits::default())
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Latest engine time (`None` before the first signal / tick).
    pub fn now(&self) -> Option<u64> {
        self.now
    }

    /// Live groups across all rules.
    pub fn pending_groups(&self) -> usize {
        self.states.iter().map(|s| s.groups.len()).sum()
    }

    /// Live groups of rule `id` (0 if unknown).
    pub fn groups_of(&self, id: &str) -> usize {
        self.rules
            .iter()
            .position(|r| r.id == id)
            .map_or(0, |i| self.states[i].groups.len())
    }

    /// Replace the set of *known* values of entity `kind` (module docs,
    /// "Eviction and fairness"): groups created for them are best
    /// protected. At most [`MAX_KNOWN_ENTITIES`] values are kept (the rest
    /// are counted in [`Stats::known_entities_dropped`]); values are
    /// compared exactly as signals carry them. Existing groups keep the tier
    /// they were created with.
    pub fn set_known_entities<I, V>(&mut self, kind: EntityKind, values: I)
    where
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        let mut set = BTreeSet::new();
        let mut dropped = 0u64;
        for v in values {
            let v: String = v.into();
            if set.len() >= MAX_KNOWN_ENTITIES && !set.contains(&v) {
                dropped += 1;
                continue;
            }
            set.insert(v);
        }
        self.stats.known_entities_dropped =
            self.stats.known_entities_dropped.saturating_add(dropped);
        if set.is_empty() {
            self.known.remove(&kind);
        } else {
            self.known.insert(kind, set);
        }
    }

    /// Is `value` a known entity of `kind`?
    pub fn is_known(&self, kind: EntityKind, value: &str) -> bool {
        self.known.get(&kind).is_some_and(|s| s.contains(value))
    }

    /// Groups of rule `id` evicted so far (0 if unknown).
    pub fn evictions_of(&self, id: &str) -> u64 {
        self.rules
            .iter()
            .position(|r| r.id == id)
            .map_or(0, |i| self.states[i].evictions)
    }

    /// Take the queued eviction notices (`robot.correlate.correlation_state_evicted`,
    /// observe-only; see the module docs). Each names the rule whose pending
    /// state was evicted and cites the evicted evidence.
    pub fn take_notices(&mut self) -> Vec<CorrelatedFinding> {
        std::mem::take(&mut self.notices)
    }

    /// Does rule `id` hold pending state for group key `key` (`""` for a
    /// unit-scoped rule)?
    pub fn has_group(&self, id: &str, key: &str) -> bool {
        self.rules
            .iter()
            .position(|r| r.id == id)
            .is_some_and(|i| self.states[i].groups.contains_key(key))
    }

    fn advance(&mut self, t: u64) -> u64 {
        match self.now {
            Some(n) if t < n => {
                self.stats.clock_regressions = self.stats.clock_regressions.saturating_add(1);
                n
            }
            _ => {
                self.now = Some(t);
                t
            }
        }
    }

    /// Advance time without a signal and drop expired state.
    pub fn tick(&mut self, t_ns: u64) {
        let now = self.advance(t_ns);
        for (i, st) in self.states.iter_mut().enumerate() {
            let n = st.sweep(now, self.rules[i].window_ns);
            self.stats.groups_expired = self.stats.groups_expired.saturating_add(n);
        }
    }

    /// Feed one signal; returns the correlated findings it completes (rule
    /// order, then group key order). Never panics.
    pub fn observe(&mut self, sig: &Signal) -> Vec<CorrelatedFinding> {
        self.stats.signals = self.stats.signals.saturating_add(1);
        self.seq = self.seq.saturating_add(1);
        if sig.rule.starts_with(RULE_ID_PREFIX) {
            self.stats.ignored_correlation_inputs =
                self.stats.ignored_correlation_inputs.saturating_add(1);
            return Vec::new();
        }
        let now = self.advance(sig.t_ns);

        // Quick reject before building the contribution.
        let interested: Vec<usize> = (0..self.rules.len())
            .filter(|&i| self.rules[i].any_matcher(&sig.rule, sig.domain, sig.severity))
            .collect();
        if interested.is_empty() {
            return Vec::new();
        }

        let (entities, dropped, mut truncated) = bounded_entities(sig, &self.limits);
        self.stats.entities_dropped = self.stats.entities_dropped.saturating_add(dropped);
        let mut rule = sig.rule.clone();
        if truncate_in_place(&mut rule, MAX_ID_LEN) {
            truncated += 1;
        }
        let evidence_ref = sig.evidence_ref.clone().map(|mut r| {
            if truncate_in_place(&mut r, self.limits.max_value_len) {
                truncated += 1;
            }
            r
        });
        self.stats.values_truncated = self.stats.values_truncated.saturating_add(truncated);
        let contrib = Arc::new(Contribution {
            seq: self.seq,
            rule,
            severity: sig.severity,
            mode: sig.mode,
            domain: sig.domain,
            t_ns: sig.t_ns,
            at_ns: now,
            entities,
            evidence_ref,
        });

        let mut out = Vec::new();
        for i in interested {
            self.observe_rule(i, &sig.rule, &contrib, now, &mut out);
        }
        out
    }

    fn observe_rule(
        &mut self,
        ri: usize,
        full_rule: &str,
        c: &Arc<Contribution>,
        now: u64,
        out: &mut Vec<CorrelatedFinding>,
    ) {
        let rule = &self.rules[ri];
        let keys: Vec<String> = match rule.group_by {
            None => vec![String::new()],
            Some(kind) => c
                .entities
                .iter()
                .filter(|e| e.kind == kind)
                .map(|e| e.value.clone())
                .collect(),
        };
        if keys.is_empty() {
            self.stats.missing_group_entity = self.stats.missing_group_entity.saturating_add(1);
            return;
        }
        for key in keys {
            self.observe_group(ri, &key, full_rule, c, now, out);
        }
    }

    /// Would this signal put anything into an empty group of rule `ri`?
    fn starts_state(rule: &Rule, full_rule: &str, c: &Contribution) -> bool {
        match &rule.pattern {
            Pattern::Sequence(ms) => ms
                .first()
                .is_some_and(|m| m.matches(full_rule, c.domain, c.severity)),
            Pattern::Slots(ms) => ms
                .iter()
                .any(|m| m.matches(full_rule, c.domain, c.severity)),
            Pattern::Distinct { matcher, by, .. } => {
                matcher.matches(full_rule, c.domain, c.severity)
                    && c.entities.iter().any(|e| e.kind == *by)
            }
        }
    }

    fn observe_group(
        &mut self,
        ri: usize,
        key: &str,
        full_rule: &str,
        c: &Arc<Contribution>,
        now: u64,
        out: &mut Vec<CorrelatedFinding>,
    ) {
        let window = self.rules[ri].window_ns;
        if let Some(g) = self.states[ri].groups.get_mut(key) {
            g.expire(now, window);
        } else {
            if !Self::starts_state(&self.rules[ri], full_rule, c) {
                return;
            }
            let known = self.rules[ri]
                .group_by
                .is_some_and(|kind| self.is_known(kind, key));
            let tier = if known {
                2
            } else if c.severity >= Severity::High {
                1
            } else {
                0
            };
            if !self.make_room(ri, now, tier) {
                return;
            }
            let g = Group {
                state: GroupState::new(&self.rules[ri].pattern),
                cooldown_until: None,
                touch: 0,
                tier,
                indexed: (0, 0),
            };
            self.states[ri].insert(key, g);
            self.stats.groups_created = self.stats.groups_created.saturating_add(1);
        }

        self.touch = self.touch.saturating_add(1);
        let touch = self.touch;
        let rule = &self.rules[ri];
        let st = &mut self.states[ri];
        let Some(g) = st.groups.get_mut(key) else {
            return;
        };
        g.touch = touch;
        let applied = if g.cooldown_until.is_some_and(|u| u > now) {
            self.stats.suppressed_cooldown = self.stats.suppressed_cooldown.saturating_add(1);
            Applied::Nothing
        } else {
            apply(rule, &mut g.state, full_rule, c, now)
        };
        if let Applied::Fire(contribs) = applied {
            g.state.clear();
            g.cooldown_until = (rule.cooldown_ns > 0).then(|| now.saturating_add(rule.cooldown_ns));
            out.push(build_finding(rule, key, contribs, now));
            self.stats.findings = self.stats.findings.saturating_add(1);
        }
        let dead = g.dead();
        st.sync(key);
        if dead {
            st.remove(key);
        }
    }

    /// Make room for one new group of protection `tier` in rule `ri`
    /// (module docs, "Eviction and fairness"). Returns false (and counts a
    /// refusal) if the newcomer must be refused.
    fn make_room(&mut self, ri: usize, now: u64, tier: u8) -> bool {
        let cap = self.limits.max_groups_per_rule;
        let unprotected_cap = cap - self.limits.protected_reserve();
        let window = self.rules[ri].window_ns;
        let full = |st: &RuleState| {
            st.groups.len() >= cap || (tier == 0 && st.unprotected >= unprotected_cap)
        };
        let st = &mut self.states[ri];
        if !full(st) {
            return true;
        }
        let n = st.sweep(now, window);
        self.stats.groups_expired = self.stats.groups_expired.saturating_add(n);
        if !full(st) {
            return true;
        }
        // Lowest tier, least progress, least recently touched first; never
        // above the newcomer's tier, never more evidence than it brings.
        let victim = st
            .index
            .iter()
            .find(|(t, progress, _, _)| *t <= tier && *progress <= 1)
            .map(|(_, _, _, k)| k.clone());
        let Some(key) = victim else {
            self.stats.groups_refused = self.stats.groups_refused.saturating_add(1);
            return false;
        };
        let evicted = st.remove(&key);
        st.evictions = st.evictions.saturating_add(1);
        self.stats.groups_evicted = self.stats.groups_evicted.saturating_add(1);
        if let Some(g) = evicted {
            self.eviction_notice(ri, &key, &g, now);
        }
        true
    }

    /// Queue an eviction notice for rule `ri` (rate-limited).
    fn eviction_notice(&mut self, ri: usize, key: &str, g: &Group, now: u64) {
        let contribs = g.state.contributions();
        if contribs.is_empty() {
            // A group in cooldown held no evidence: nothing was lost.
            return;
        }
        let rule = &self.rules[ri];
        let st = &mut self.states[ri];
        let due = st
            .notice_at
            .is_none_or(|t| now.saturating_sub(t) > rule.window_ns);
        if !due || self.notices.len() >= MAX_PENDING_NOTICES {
            self.stats.eviction_notices_suppressed =
                self.stats.eviction_notices_suppressed.saturating_add(1);
            return;
        }
        st.notice_at = Some(now);
        let observe_only = Mode::Observe;
        let detail = format!(
            "pending state of correlation rule {} ({} held signal(s)) was evicted to make room \
             for a new group; {} group(s) of this rule evicted so far: many fresh entities \
             within its window, possibly a flood aimed at hiding a correlation",
            rule.id,
            contribs.len(),
            st.evictions
        );
        self.notices.push(CorrelatedFinding {
            rule: EVICTED_RULE_ID.to_string(),
            title: "Pending correlation state evicted".to_string(),
            severity: Severity::Medium,
            mode: observe_only,
            at_ns: now,
            group: rule.group_by.map(|kind| Entity {
                kind,
                value: key.to_string(),
            }),
            window_ns: rule.window_ns,
            contributors: contribs.iter().map(|c| (**c).clone()).collect(),
            detail,
        });
        self.stats.eviction_notices = self.stats.eviction_notices.saturating_add(1);
    }
}

fn apply(
    rule: &Rule,
    state: &mut GroupState,
    full_rule: &str,
    c: &Arc<Contribution>,
    now: u64,
) -> Applied {
    let window = rule.window_ns;
    match (&rule.pattern, state) {
        (Pattern::Sequence(ms), GroupState::Seq(partials)) => {
            let steps = ms.len();
            let mut any = false;
            // Descending, so one signal never fills two consecutive steps.
            for j in (0..steps).rev() {
                if !ms[j].matches(full_rule, c.domain, c.severity) {
                    continue;
                }
                if j == 0 {
                    if let Some(slot) = partials.get_mut(0) {
                        *slot = Some(Partial {
                            start: now,
                            contribs: vec![Arc::clone(c)],
                        });
                        any = true;
                    }
                    continue;
                }
                let Some(prev) = partials.get(j - 1).and_then(Option::as_ref) else {
                    continue;
                };
                if now.saturating_sub(prev.start) > window {
                    continue;
                }
                let mut contribs = prev.contribs.clone();
                contribs.push(Arc::clone(c));
                if j == steps - 1 {
                    return Applied::Fire(contribs);
                }
                let start = prev.start;
                if let Some(slot) = partials.get_mut(j) {
                    if slot.as_ref().is_none_or(|p| start >= p.start) {
                        *slot = Some(Partial { start, contribs });
                        any = true;
                    }
                }
            }
            if any {
                Applied::Progress
            } else {
                Applied::Nothing
            }
        }
        (Pattern::Slots(ms), GroupState::Slots(slots)) => {
            // Pick one slot: the first unsatisfied matching slot, else the
            // matching slot whose oldest entry is oldest.
            let mut pick: Option<usize> = None;
            for (i, m) in ms.iter().enumerate() {
                if !m.matches(full_rule, c.domain, c.severity) {
                    continue;
                }
                let len = slots.get(i).map_or(0, VecDeque::len);
                if len < m.count {
                    pick = Some(i);
                    break;
                }
                let oldest = slots.get(i).and_then(|s| s.front()).map(|x| x.at_ns);
                let better = match pick {
                    None => true,
                    Some(p) => {
                        let po = slots.get(p).and_then(|s| s.front()).map(|x| x.at_ns);
                        oldest < po
                    }
                };
                if better {
                    pick = Some(i);
                }
            }
            let Some(i) = pick else {
                return Applied::Nothing;
            };
            let cap = ms[i].count;
            if let Some(s) = slots.get_mut(i) {
                s.push_back(Arc::clone(c));
                while s.len() > cap {
                    s.pop_front();
                }
            }
            let done = ms.iter().zip(slots.iter()).all(|(m, s)| s.len() >= m.count);
            if done {
                let mut all: Vec<Arc<Contribution>> =
                    slots.iter().flat_map(|s| s.iter().cloned()).collect();
                all.sort_by_key(|x| x.seq);
                Applied::Fire(all)
            } else {
                Applied::Progress
            }
        }
        (
            Pattern::Distinct {
                matcher, by, count, ..
            },
            GroupState::Distinct(map),
        ) => {
            if !matcher.matches(full_rule, c.domain, c.severity) {
                return Applied::Nothing;
            }
            let Some(v) = c.entities.iter().find(|e| e.kind == *by) else {
                return Applied::Nothing;
            };
            map.insert(v.value.clone(), Arc::clone(c));
            // Defensive: never hold more than `count` (cannot happen, since
            // reaching `count` fires and clears).
            while map.len() > *count {
                let oldest = map
                    .iter()
                    .min_by_key(|(_, x)| (x.at_ns, x.seq))
                    .map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => {
                        map.remove(&k);
                    }
                    None => break,
                }
            }
            if map.len() >= *count {
                let mut all: Vec<Arc<Contribution>> = map.values().cloned().collect();
                all.sort_by_key(|x| x.seq);
                Applied::Fire(all)
            } else {
                Applied::Progress
            }
        }
        // Pattern and state are created together; a mismatch is impossible.
        _ => {
            let _ = window;
            Applied::Nothing
        }
    }
}

fn build_finding(
    rule: &Rule,
    key: &str,
    contribs: Vec<Arc<Contribution>>,
    now: u64,
) -> CorrelatedFinding {
    let max_in = contribs
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(Severity::Low);
    let observe = contribs.iter().any(|c| c.mode == Mode::Observe);
    let first = contribs.iter().map(|c| c.at_ns).min().unwrap_or(now);
    let mut ids: Vec<&str> = Vec::new();
    for c in &contribs {
        if !ids.contains(&c.rule.as_str()) {
            ids.push(&c.rule);
        }
    }
    let span = now.saturating_sub(first);
    let detail = format!(
        "{}: {} correlated signals within {}.{:03} s [{}]",
        rule.title,
        contribs.len(),
        span / 1_000_000_000,
        (span % 1_000_000_000) / 1_000_000,
        ids.join(", ")
    );
    CorrelatedFinding {
        rule: rule.id.clone(),
        title: rule.title.clone(),
        severity: rule.output_severity(max_in),
        mode: if observe {
            Mode::Observe
        } else {
            Mode::Enforce
        },
        at_ns: now,
        group: rule.group_by.map(|kind| Entity {
            kind,
            value: key.to_string(),
        }),
        window_ns: rule.window_ns,
        contributors: contribs.iter().map(|c| (**c).clone()).collect(),
        detail,
    }
}
