//! The hot path: [`Firewall::check`].
//!
//! Constraints this module is written to (and that the tests check):
//! - **No heap allocation** after [`Firewall::new`]: all state is in vectors
//!   sized at construction; events go to a fixed-capacity buffer.
//! - **No panics**: no `unwrap`/`expect`, no slice indexing (only `get`,
//!   iterators and array destructuring), saturating/checked integer maths.
//! - **Bounded work**: every loop is over at most [`MAX_JOINTS`] elements or a
//!   constant number of iterations, except recording an event, which scans
//!   the fixed-capacity event buffer once (coalesce / evict, at most
//!   `event_capacity` entries); no recursion, no search over sources.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::command::{
    ChannelId, Command, JointVelocities, Motion, SourceId, Twist, Vec3, MAX_JOINTS,
};
use crate::config::{ChannelKind, FailBehaviour, FaultPolicy, ForeignSourceAction, Limits, Policy};
use crate::events::{policy_mode, reject_rule, rules, EventAction, EventBuffer, FirewallEvent};
use crate::joint_engine::JointChanState;
use crate::verdict::{LimitReasons, RejectReason, Substitute, SubstituteKind, Verdict, WouldHave};
use robodr_events::{Deviation, Severity};

type Raw = [f64; MAX_JOINTS];
const ZERO_RAW: Raw = [0.0; MAX_JOINTS];

/// Relative tolerance of the internal post-condition check.
const POST_CHECK_TOL: f64 = 1e-9;

/// Counters since construction (never reset; saturating), plus one gauge
/// (`joint_hold_age_ns`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub checked: u64,
    pub passed: u64,
    pub limited: u64,
    pub rejected: u64,
    /// Passed with a would-have verdict (observe / pass-through / fail-open).
    pub would_have: u64,
    pub faults: u64,
    /// Low-level joint channels: hold episodes started. An episode is a run
    /// of hold substitutes on one channel between two accepted frames (or
    /// until a damping substitute).
    pub joint_hold_episodes: u64,
    /// Humanoid joint channels: hold episodes that outlived `max_hold_ns`
    /// (each also raised one `joint_hold_exceeded` event).
    pub joint_holds_exceeded: u64,
    /// Gauge: age (`now` − acceptance of the held frame, ns) of the most
    /// recent hold substitute on any joint channel; back to 0 when that
    /// channel accepts a frame (or damps).
    pub joint_hold_age_ns: u64,
}

#[derive(Debug, Clone, Copy)]
struct ChanState {
    /// Last motion emitted downstream (accepted output or substitute).
    last_out: Raw,
    last_out_at: Option<u64>,
    /// Acceleration magnitude of the last emitted step, per group.
    a_prev: [f64; 2],
    /// Last *accepted* output and when (for `HoldLast`).
    accepted: Option<(Raw, u64)>,
    /// When the last foreign-source-triggered substitute was emitted (to
    /// bound them under `ForeignSourceAction::Substitute`).
    last_foreign_sub_at: Option<u64>,
}

impl ChanState {
    const INIT: ChanState = ChanState {
        last_out: ZERO_RAW,
        last_out_at: None,
        a_prev: [0.0; 2],
        accepted: None,
        last_foreign_sub_at: None,
    };
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PairState {
    rate_init: bool,
    credit_ns: u64,
    refill_at: u64,
    pub(crate) last_stamp: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct Rejection {
    reason: RejectReason,
    value: f64,
    limit: f64,
}

impl Rejection {
    fn new(reason: RejectReason) -> Self {
        Self {
            reason,
            value: f64::NAN,
            limit: f64::NAN,
        }
    }
    fn with(reason: RejectReason, value: f64, limit: f64) -> Self {
        Self {
            reason,
            value,
            limit,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Accepted {
    out: Raw,
    reasons: LimitReasons,
    /// (value, limit) for each limit that applied.
    speed: (f64, f64),
    accel: (f64, f64),
    jerk: (f64, f64),
    a_new: [f64; 2],
    /// Index and updated state of the (channel, source) pair (rate credit,
    /// last stamp). Written back only once the command is accepted, so a
    /// rejected command never changes it.
    pair_idx: usize,
    pair_new: PairState,
}

/// The Motion Firewall. See the crate docs for the decision semantics.
#[derive(Debug)]
pub struct Firewall {
    pub(crate) policy: Policy,
    pub(crate) observe: bool,
    chans: Vec<ChanState>,
    /// Per low-level joint channel (index = joint index, see
    /// `Policy::joint_index`).
    pub(crate) jchans: Vec<JointChanState>,
    /// Per (channel, source) over **all** channel ids (both kinds).
    pub(crate) pairs: Vec<PairState>,
    pub(crate) nsrc: usize,
    pub(crate) last_now: Option<u64>,
    events: EventBuffer,
    pub(crate) stats: Stats,
    #[cfg(test)]
    pub(crate) inject_fault: bool,
}

// ---------------------------------------------------------------- vector maths

fn ratio(allowance: f64, magnitude: f64) -> f64 {
    // `allowance` is never NaN (validated / guarded); `magnitude` never NaN.
    if magnitude > allowance {
        allowance / magnitude
    } else {
        1.0
    }
}

/// `rate × dt` without producing NaN for `inf × 0`.
fn allow(rate: f64, dt: f64) -> f64 {
    if rate.is_infinite() {
        f64::INFINITY
    } else {
        rate * dt
    }
}

/// Euclidean norm, overflow-safe; `inf` if any element is infinite.
fn norm<'a>(xs: impl Iterator<Item = &'a f64> + Clone) -> f64 {
    let m = max_abs(xs.clone());
    if m == 0.0 || !m.is_finite() {
        return m;
    }
    let s: f64 = xs.map(|x| (x / m) * (x / m)).sum();
    m * s.sqrt()
}

fn max_abs<'a>(xs: impl Iterator<Item = &'a f64>) -> f64 {
    xs.fold(0.0_f64, |m, x| {
        let a = x.abs();
        if a > m {
            a
        } else {
            m
        }
    })
}

fn width(kind: ChannelKind) -> usize {
    match kind {
        ChannelKind::Twist => 6,
        ChannelKind::Joints { count } => count.min(MAX_JOINTS),
    }
}

/// Group magnitudes: twist → (|linear|₂, |angular|₂); joints → (max |q̇ᵢ|, 0).
fn mags(kind: ChannelKind, v: &Raw) -> [f64; 2] {
    match kind {
        ChannelKind::Twist => [norm(v.iter().take(3)), norm(v.iter().skip(3).take(3))],
        ChannelKind::Joints { count } => [max_abs(v.iter().take(count)), 0.0],
    }
}

fn speed_limits(kind: ChannelKind, l: &Limits) -> [f64; 2] {
    match kind {
        ChannelKind::Twist => [l.lin, l.ang],
        ChannelKind::Joints { .. } => [l.joint, f64::INFINITY],
    }
}

fn accel_limits(kind: ChannelKind, l: &Limits) -> [f64; 2] {
    match kind {
        ChannelKind::Twist => [l.lin_acc, l.ang_acc],
        ChannelKind::Joints { .. } => [l.joint_acc, f64::INFINITY],
    }
}

fn jerk_limits(kind: ChannelKind, l: &Limits) -> [f64; 2] {
    match kind {
        ChannelKind::Twist => [l.lin_jerk, l.ang_jerk],
        ChannelKind::Joints { .. } => [l.joint_jerk, f64::INFINITY],
    }
}

fn scale(v: &mut Raw, len: usize, s: f64) {
    for x in v.iter_mut().take(len) {
        *x *= s;
    }
}

fn sub(a: &Raw, b: &Raw, len: usize) -> Raw {
    let mut d = ZERO_RAW;
    for ((d, a), b) in d.iter_mut().zip(a).zip(b).take(len) {
        *d = a - b;
    }
    d
}

/// Uniformly scale `v` so every group is within its speed limit (direction
/// preserved). Returns the factor applied (1.0 if none). The margin of a few
/// ulps makes the post-condition hold despite rounding; bounded to 4 rounds.
fn clamp_speed(kind: ChannelKind, v: &mut Raw, lim: [f64; 2]) -> f64 {
    let len = width(kind);
    let mut total = 1.0;
    for _ in 0..4 {
        let [m0, m1] = mags(kind, v);
        let [l0, l1] = lim;
        let s = ratio(l0, m0).min(ratio(l1, m1));
        if s >= 1.0 {
            break;
        }
        let s = s * (1.0 - 8.0 * f64::EPSILON);
        scale(v, len, s);
        total *= s;
    }
    total
}

/// `true` if every component moves toward zero without crossing it.
fn only_decelerates(prev: &Raw, target: &Raw, len: usize) -> bool {
    prev.iter()
        .zip(target)
        .take(len)
        .all(|(p, t)| *t == 0.0 || (p * t > 0.0 && t.abs() <= p.abs()))
}

fn sanitize_accel(a: f64) -> f64 {
    if a.is_finite() {
        a
    } else {
        f64::MAX
    }
}

fn to_raw(m: &Motion) -> Raw {
    match m {
        Motion::Twist(t) => {
            let [a, b, c] = t.linear.to_array();
            let [d, e, f] = t.angular.to_array();
            let mut r = ZERO_RAW;
            for (dst, src) in r.iter_mut().zip([a, b, c, d, e, f]) {
                *dst = src;
            }
            r
        }
        Motion::Joints(j) => *j.raw(),
    }
}

fn from_raw(kind: ChannelKind, r: &Raw) -> Motion {
    match kind {
        ChannelKind::Twist => {
            let mut it = r.iter().copied();
            let mut next = || it.next().unwrap_or(0.0);
            let l = [next(), next(), next()];
            let a = [next(), next(), next()];
            Motion::Twist(Twist::new(Vec3::from_array(l), Vec3::from_array(a)))
        }
        ChannelKind::Joints { count } => Motion::Joints(JointVelocities::from_raw(count, *r)),
    }
}

fn kind_matches(kind: ChannelKind, m: &Motion) -> bool {
    match (kind, m) {
        (ChannelKind::Twist, Motion::Twist(_)) => true,
        (ChannelKind::Joints { count }, Motion::Joints(j)) => j.len() == count,
        _ => false,
    }
}

fn ns_to_s(ns: u64) -> f64 {
    ns as f64 * 1e-9
}

// ---------------------------------------------------------------- firewall

impl Firewall {
    /// Build a firewall from a compiled policy. This is the only place the
    /// firewall allocates (state tables and the event buffer).
    pub fn new(policy: Policy) -> Self {
        let nsrc = policy.sources.len();
        let nch = policy.channels.len();
        let observe = policy.is_observe_only();
        let events = EventBuffer::with_capacity(policy.platform.event_capacity);
        Self {
            observe,
            chans: vec![ChanState::INIT; nch],
            jchans: vec![JointChanState::INIT; policy.joint_channels.len()],
            pairs: vec![PairState::default(); policy.channel_count().saturating_mul(nsrc)],
            nsrc,
            last_now: None,
            events,
            stats: Stats::default(),
            policy,
            #[cfg(test)]
            inject_fault: false,
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// `true` when verdicts are enforced (profile locked and platform not
    /// pass-through). When `false` every verdict is `Passed`.
    pub fn is_enforcing(&self) -> bool {
        !self.observe
    }

    pub fn source_id(&self, guid: &str) -> Option<SourceId> {
        self.policy.source_id(guid)
    }

    pub fn channel_id(&self, name: &str) -> Option<ChannelId> {
        self.policy.channel_id(name)
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Pending events (read-only view).
    pub fn events(&self) -> &EventBuffer {
        &self.events
    }

    /// Visit and clear pending events without allocating. Returns how many
    /// events were dropped because the buffer was full.
    pub fn drain_events(&mut self, f: impl FnMut(&FirewallEvent)) -> u64 {
        self.events.drain_with(f)
    }

    /// Drain pending events as [`Deviation`]s (allocates — call outside the
    /// control loop). If events were dropped, a final
    /// `robot.firewall.events_dropped` deviation reports how many.
    pub fn drain_deviations(&mut self) -> Vec<Deviation> {
        let mut out = Vec::with_capacity(self.events.len().saturating_add(1));
        let policy = &self.policy;
        // Severity of the drop report: at least Medium, and as high as the
        // most severe event that was lost.
        let sev = self
            .events
            .dropped_max_severity()
            .map_or(Severity::Medium, |s| s.max(Severity::Medium));
        let dropped = self.events.drain_with(|e| out.push(e.to_deviation(policy)));
        if dropped > 0 {
            out.push(
                Deviation::new(
                    rules::EVENTS_DROPPED,
                    sev,
                    format!("{dropped} firewall events dropped: output buffer full"),
                )
                .with_mode(policy_mode(policy)),
            );
        }
        out
    }

    /// The verdict to apply when the firewall **cannot evaluate** a command
    /// (gateway watchdog / deadline miss, or an internal fault), according to
    /// the platform's [`FaultPolicy`]. Recorded as `robot.firewall.internal_fault`.
    pub fn fault_verdict(&mut self, cmd: &Command, now: u64) -> Verdict {
        self.stats.checked = self.stats.checked.saturating_add(1);
        self.fault(cmd, now)
    }

    /// Source, rate and timestamp check of a request that commands **no
    /// motion** on a twist channel (a query, an allowlisted non-velocity
    /// call): stages 0-6 of [`Self::check`] for `cmd` (its motion should be
    /// a zero twist), with the channel's **motion state left as it was**
    /// (last output, acceleration, hold value): such a request says nothing
    /// about the robot's velocity, so it must neither reset the reference
    /// the next velocity command is ramped from nor count as a stop.
    /// Accepted: the (channel, source) rate credit and stamp are stored,
    /// `true`. Refused: the rejection event is recorded (no substitute:
    /// the request carries none), `false`. Observe mode: recorded as
    /// would-have, `true`.
    pub fn check_access(&mut self, cmd: &Command, now: u64) -> bool {
        self.stats.checked = self.stats.checked.saturating_add(1);
        let ch_idx = usize::from(cmd.channel.0);
        match self.evaluate(cmd, now, ch_idx) {
            Ok(acc) => {
                if let Some(p) = self.pairs.get_mut(acc.pair_idx) {
                    *p = acc.pair_new;
                }
                self.stats.passed = self.stats.passed.saturating_add(1);
                true
            }
            Err(rej) => {
                let (rule, sev) = reject_rule(rej.reason);
                if self.observe {
                    self.push_event(
                        rule,
                        sev,
                        cmd,
                        now,
                        EventAction::ObservedOnly,
                        rej.value,
                        rej.limit,
                    );
                    self.stats.passed = self.stats.passed.saturating_add(1);
                    self.stats.would_have = self.stats.would_have.saturating_add(1);
                    return true;
                }
                self.push_event(
                    rule,
                    sev,
                    cmd,
                    now,
                    EventAction::Rejected(None),
                    rej.value,
                    rej.limit,
                );
                self.stats.rejected = self.stats.rejected.saturating_add(1);
                false
            }
        }
    }

    /// The platform is known to be at rest on twist channel `channel` as of
    /// `now` (a velocity command whose duration ended: the robot stopped on
    /// its own). The next command is acceleration limited from zero, and a
    /// hold can no longer hold the earlier velocity. No-op for an unknown
    /// channel.
    pub fn twist_at_rest(&mut self, channel: ChannelId, now: u64) {
        if let Some(st) = self.chans.get_mut(usize::from(channel.0)) {
            st.last_out = ZERO_RAW;
            st.last_out_at = Some(now);
            st.a_prev = [0.0; 2];
            st.accepted = None;
        }
    }

    /// Check one command. Never allocates, never panics, bounded time.
    ///
    /// `now` is the gateway's monotonic clock in nanoseconds, in the same
    /// domain as `cmd.stamp_ns`.
    pub fn check(&mut self, cmd: &Command, now: u64) -> Verdict {
        self.stats.checked = self.stats.checked.saturating_add(1);
        let ch_idx = usize::from(cmd.channel.0);

        let result = self.evaluate(cmd, now, ch_idx);

        #[cfg(test)]
        let result = match result {
            Ok(mut a) if self.inject_fault => {
                a.out = [f64::NAN; MAX_JOINTS];
                Ok(a)
            }
            r => r,
        };

        match result {
            Err(rej) => self.reject(cmd, now, ch_idx, rej),
            Ok(acc) => {
                let Some(ch) = self.policy.channels.get(ch_idx) else {
                    // evaluate() only accepts known channels.
                    return self.fault(cmd, now);
                };
                // Defensive post-condition: finite and within speed limits.
                let lim = speed_limits(ch.kind, &ch.limits);
                let [m0, m1] = mags(ch.kind, &acc.out);
                let [l0, l1] = lim;
                let finite = acc.out.iter().all(|x| x.is_finite());
                let within = m0 <= l0 * (1.0 + POST_CHECK_TOL) && m1 <= l1 * (1.0 + POST_CHECK_TOL);
                if !(finite && within) {
                    return self.fault(cmd, now);
                }
                if let Some(p) = self.pairs.get_mut(acc.pair_idx) {
                    *p = acc.pair_new;
                }
                self.accept(cmd, now, ch_idx, acc)
            }
        }
    }

    /// Stages 0–8 of the decision table. Only the gateway clock is updated
    /// here; the (channel, source) rate credit and last stamp are returned in
    /// [`Accepted`] and stored by `check` for accepted commands only.
    fn evaluate(&mut self, cmd: &Command, now: u64, ch_idx: usize) -> Result<Accepted, Rejection> {
        // 0. Gateway clock must be monotonic.
        if let Some(last) = self.last_now {
            if now < last {
                return Err(Rejection::with(
                    RejectReason::ClockRegression,
                    now as f64,
                    last as f64,
                ));
            }
        }
        self.last_now = Some(now);

        // 1. Channel. A low-level joint channel is checked by
        //    `check_joint`; a `Command` on it is a kind mismatch (after the
        //    source checks, so a foreign source is still reported as such).
        let Some(ch) = self.policy.channels.get(ch_idx) else {
            if self.policy.is_joint_channel(cmd.channel) {
                let src_idx = usize::from(cmd.source.0);
                if cmd.source == SourceId::UNKNOWN || src_idx >= self.nsrc {
                    return Err(Rejection::new(RejectReason::UnknownSource));
                }
                if !self.policy.allows(cmd.channel, cmd.source) {
                    return Err(Rejection::new(RejectReason::UnauthorizedSource));
                }
                return Err(Rejection::new(RejectReason::KindMismatch));
            }
            return Err(Rejection::new(RejectReason::UnknownChannel));
        };

        // 2. Source identity (integer compare / bit test only).
        let src_idx = usize::from(cmd.source.0);
        if cmd.source == SourceId::UNKNOWN || src_idx >= self.nsrc {
            return Err(Rejection::new(RejectReason::UnknownSource));
        }
        if !ch.allows(cmd.source) {
            return Err(Rejection::new(RejectReason::UnauthorizedSource));
        }
        let pair_idx = ch_idx
            .checked_mul(self.nsrc)
            .and_then(|x| x.checked_add(src_idx));
        let Some((pair_idx, pair)) = pair_idx.and_then(|i| self.pairs.get(i).map(|p| (i, *p)))
        else {
            return Err(Rejection::new(RejectReason::UnknownSource));
        };
        // Per-(channel, source) state is only *computed* here; `check` stores
        // it when the command is accepted (see `Accepted::pair_new`).
        let mut pair_new = pair;

        // 3. Rate limit (token bucket in ns of credit).
        if let Some((cost, cap)) = ch.rate {
            let credit = if pair.rate_init {
                pair.credit_ns
                    .saturating_add(now.saturating_sub(pair.refill_at))
                    .min(cap)
            } else {
                cap
            };
            if credit < cost {
                return Err(Rejection::new(RejectReason::RateLimited));
            }
            pair_new.rate_init = true;
            pair_new.refill_at = now;
            pair_new.credit_ns = credit.saturating_sub(cost);
        }

        // 4. Kind and shape.
        if !kind_matches(ch.kind, &cmd.motion) {
            return Err(Rejection::new(RejectReason::KindMismatch));
        }

        // 5. Finite values.
        if !cmd.motion.is_finite() {
            return Err(Rejection::new(RejectReason::NonFinite));
        }

        // 6. Timestamps.
        if cmd.stamp_ns > now.saturating_add(ch.max_future_ns) {
            return Err(Rejection::with(
                RejectReason::FutureTimestamp,
                cmd.stamp_ns.saturating_sub(now) as f64,
                ch.max_future_ns as f64,
            ));
        }
        let age = now.saturating_sub(cmd.stamp_ns);
        if age > ch.max_age_ns {
            return Err(Rejection::with(
                RejectReason::Stale,
                age as f64,
                ch.max_age_ns as f64,
            ));
        }
        if let Some(last) = pair.last_stamp {
            if cmd.stamp_ns <= last {
                return Err(Rejection::with(
                    RejectReason::OutOfOrder,
                    cmd.stamp_ns as f64,
                    last as f64,
                ));
            }
        }
        pair_new.last_stamp = Some(cmd.stamp_ns);

        // 7. Hard limit: far over the envelope is not a typo, it is a reject.
        let kind = ch.kind;
        let len = width(kind);
        let mut target = to_raw(&cmd.motion);
        let lim = speed_limits(kind, &ch.limits);
        let m = mags(kind, &target);
        for (mi, li) in m.iter().zip(lim.iter()) {
            let hard = li * ch.hard_factor;
            if *mi > hard {
                return Err(Rejection::with(RejectReason::OverHardLimit, *mi, hard));
            }
        }

        // 8a. Speed: uniform scaling of the whole command (direction and the
        //     linear/angular ratio — i.e. path curvature — preserved).
        let mut reasons = LimitReasons::NONE;
        let mut speed = (f64::NAN, f64::NAN);
        if clamp_speed(kind, &mut target, lim) < 1.0 {
            reasons.insert(LimitReasons::SPEED);
            let [m0, m1] = m;
            let [l0, l1] = lim;
            speed = if m0 > l0 { (m0, l0) } else { (m1, l1) };
        }

        // 8b. Acceleration / jerk: out = prev + λ·(target − prev), λ ∈ [0, 1].
        let st = self.chans.get(ch_idx).copied().unwrap_or(ChanState::INIT);
        let gap = st.last_out_at.map(|t| now.saturating_sub(t));
        let fresh = matches!(gap, Some(g) if g <= ch.reset_after_ns);
        let (prev, a_prev) = if fresh {
            (st.last_out, st.a_prev)
        } else {
            // Nothing emitted recently: assume the platform is at rest.
            (ZERO_RAW, [0.0; 2])
        };
        let dt_ns = gap.unwrap_or(ch.dt_cap_ns).min(ch.dt_cap_ns);
        let dt = ns_to_s(dt_ns);

        let mut accel = (f64::NAN, f64::NAN);
        let mut jerk = (f64::NAN, f64::NAN);
        let out;
        let a_new;
        if !ch.limit_deceleration && only_decelerates(&prev, &target, len) {
            // Never delay a stop. Next ramp-up starts from zero acceleration.
            out = target;
            a_new = [0.0; 2];
        } else {
            let d = sub(&target, &prev, len);
            let dm = mags(kind, &d);
            let al = accel_limits(kind, &ch.limits);
            let jl = jerk_limits(kind, &ch.limits);
            let mut lam_acc = 1.0_f64;
            let mut lam_jerk = 1.0_f64;
            for i in 0..2 {
                let dmi = dm.get(i).copied().unwrap_or(0.0);
                let ali = al.get(i).copied().unwrap_or(f64::INFINITY);
                let jli = jl.get(i).copied().unwrap_or(f64::INFINITY);
                let api = a_prev.get(i).copied().unwrap_or(0.0);
                let ra = ratio(allow(ali, dt), dmi);
                if ra < lam_acc {
                    lam_acc = ra;
                    accel = (if dt > 0.0 { dmi / dt } else { f64::INFINITY }, ali);
                }
                let a_allowed = if jli.is_infinite() {
                    f64::INFINITY
                } else {
                    api + jli * dt
                };
                let rj = ratio(allow(a_allowed, dt), dmi);
                if rj < lam_jerk {
                    lam_jerk = rj;
                    jerk = (if dt > 0.0 { dmi / dt } else { f64::INFINITY }, a_allowed);
                }
            }
            let lam = lam_acc.min(lam_jerk).clamp(0.0, 1.0);
            if lam_acc < 1.0 && lam_acc <= lam_jerk {
                reasons.insert(LimitReasons::ACCELERATION);
            }
            if lam_jerk < 1.0 && lam_jerk <= lam_acc {
                reasons.insert(LimitReasons::JERK);
            }
            let mut o = target;
            if lam < 1.0 {
                // Convex combination: cannot overflow, stays on the segment.
                for ((o, p), t) in o.iter_mut().zip(&prev).zip(&target).take(len) {
                    *o = (1.0 - lam) * p + lam * t;
                }
            }
            // Rounding guard only (segment of two in-limit points is in-limit).
            clamp_speed(kind, &mut o, lim);
            let step = mags(kind, &sub(&o, &prev, len));
            a_new = if dt > 0.0 {
                [sanitize_accel(step[0] / dt), sanitize_accel(step[1] / dt)]
            } else {
                [0.0; 2]
            };
            out = o;
        }

        Ok(Accepted {
            out,
            reasons,
            speed,
            accel,
            jerk,
            a_new,
            pair_idx,
            pair_new,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn push_event(
        &mut self,
        rule: &'static str,
        sev: Severity,
        cmd: &Command,
        now: u64,
        action: EventAction,
        value: f64,
        limit: f64,
    ) {
        self.record(
            rule,
            sev,
            (cmd.channel, cmd.source),
            now,
            action,
            (value, limit),
            None,
        );
    }

    /// Record one event (shared by both command kinds).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record(
        &mut self,
        rule: &'static str,
        sev: Severity,
        (channel, source): (ChannelId, SourceId),
        now: u64,
        action: EventAction,
        (value, limit): (f64, f64),
        slot: Option<u8>,
    ) {
        let authorised = source != SourceId::UNKNOWN
            && usize::from(source.0) < self.nsrc
            && self.policy.allows(channel, source);
        self.events.push(FirewallEvent {
            rule,
            severity: sev,
            at_ns: now,
            channel,
            source,
            action,
            value,
            limit,
            authorised,
            count: 1,
            last_at_ns: now,
            slot,
        });
    }

    /// Record what was emitted downstream on a channel.
    fn commit(&mut self, ch_idx: usize, out: Raw, now: u64, a: [f64; 2], accepted: bool) {
        if let Some(st) = self.chans.get_mut(ch_idx) {
            st.last_out = out;
            st.last_out_at = Some(now);
            st.a_prev = a;
            if accepted {
                st.accepted = Some((out, now));
            }
        }
    }

    /// Observe-mode bookkeeping: the original command was forwarded.
    fn commit_forwarded(&mut self, cmd: &Command, now: u64, ch_idx: usize) {
        let Some(ch) = self.policy.channels.get(ch_idx) else {
            return;
        };
        if !kind_matches(ch.kind, &cmd.motion) || !cmd.motion.is_finite() {
            return;
        }
        let kind = ch.kind;
        let len = width(kind);
        let raw = to_raw(&cmd.motion);
        let a = match self.chans.get(ch_idx) {
            Some(st) => match st.last_out_at {
                Some(t) if now > t => {
                    let dt = ns_to_s(now.saturating_sub(t).min(ch.dt_cap_ns));
                    let step = mags(kind, &sub(&raw, &st.last_out, len));
                    [sanitize_accel(step[0] / dt), sanitize_accel(step[1] / dt)]
                }
                _ => [0.0; 2],
            },
            None => [0.0; 2],
        };
        self.commit(ch_idx, raw, now, a, true);
    }

    fn accept(&mut self, cmd: &Command, now: u64, ch_idx: usize, acc: Accepted) -> Verdict {
        let Some(kind) = self.policy.channels.get(ch_idx).map(|c| c.kind) else {
            return self.fault(cmd, now);
        };
        let action = if self.observe {
            EventAction::ObservedOnly
        } else {
            EventAction::Limited
        };
        if acc.reasons.contains(LimitReasons::SPEED) {
            self.push_event(
                rules::LIMITED_SPEED,
                Severity::High,
                cmd,
                now,
                action,
                acc.speed.0,
                acc.speed.1,
            );
        }
        if acc.reasons.contains(LimitReasons::ACCELERATION) {
            self.push_event(
                rules::LIMITED_ACCELERATION,
                Severity::Medium,
                cmd,
                now,
                action,
                acc.accel.0,
                acc.accel.1,
            );
        }
        if acc.reasons.contains(LimitReasons::JERK) {
            self.push_event(
                rules::LIMITED_JERK,
                Severity::Medium,
                cmd,
                now,
                action,
                acc.jerk.0,
                acc.jerk.1,
            );
        }

        let limited_cmd = Command {
            motion: from_raw(kind, &acc.out),
            ..*cmd
        };
        if self.observe {
            self.commit_forwarded(cmd, now, ch_idx);
            self.stats.passed = self.stats.passed.saturating_add(1);
            let would_have = if acc.reasons.is_empty() {
                None
            } else {
                self.stats.would_have = self.stats.would_have.saturating_add(1);
                Some(WouldHave::Limited {
                    cmd: limited_cmd,
                    reasons: acc.reasons,
                })
            };
            return Verdict::Passed {
                cmd: *cmd,
                would_have,
            };
        }

        self.commit(ch_idx, acc.out, now, acc.a_new, true);
        if acc.reasons.is_empty() {
            self.stats.passed = self.stats.passed.saturating_add(1);
            // Bit-exact passthrough when nothing was limited.
            Verdict::Passed {
                cmd: *cmd,
                would_have: None,
            }
        } else {
            self.stats.limited = self.stats.limited.saturating_add(1);
            Verdict::Limited {
                cmd: limited_cmd,
                reasons: acc.reasons,
            }
        }
    }

    /// The value a `HoldLast` substitute may hold on channel `ch_idx` at
    /// `now`, or `None` when only zero is safe.
    ///
    /// The hold must never cause more motion than what was **last emitted**
    /// downstream (an earlier substitute may already have stopped the
    /// platform), nor more than the last **accepted** output. The result is
    /// `s·v` — the last accepted output `v` uniformly scaled (direction and
    /// curvature preserved) by the largest `s ∈ (0, 1]` that makes it a
    /// component-wise deceleration of the last emitted output. Being a pure
    /// deceleration from the last emitted output, it is subject to exactly
    /// the treatment the acceleration stage gives any stop: it can never step
    /// the output *up* (e.g. 0 → 0.9 m/s after a zero substitute).
    ///
    /// `None` ("if in doubt, emit zero") when: nothing was accepted; the
    /// accepted output is older than `max_hold_ns`; `now` is before the last
    /// acceptance or emission (clock regression: the age cannot be trusted);
    /// the last emission is older than the channel's reset gap (the platform
    /// may have stopped on its own); a component of the last emitted output
    /// is zero or of opposite sign where the accepted one is not; or the
    /// rounding guard fails.
    fn hold_value(&self, ch_idx: usize, now: u64, max_hold_ns: u64) -> Option<Raw> {
        let ch = self.policy.channels.get(ch_idx)?;
        let st = self.chans.get(ch_idx)?;
        let (v, at) = st.accepted?;
        if now.checked_sub(at)? > max_hold_ns {
            return None;
        }
        if now.checked_sub(st.last_out_at?)? > ch.reset_after_ns {
            return None;
        }
        let len = width(ch.kind);
        let o = &st.last_out;
        let mut s = 1.0_f64;
        for (vi, oi) in v.iter().zip(o).take(len) {
            if *vi == 0.0 {
                continue;
            }
            let p = vi * oi;
            if p.is_nan() || p <= 0.0 {
                return None;
            }
            let r = oi / vi;
            if r < s {
                s = r;
            }
        }
        if !s.is_finite() || s <= 0.0 {
            return None;
        }
        let mut h = v;
        if s < 1.0 {
            // Few-ulp margin so the deceleration check holds after rounding.
            scale(&mut h, len, s * (1.0 - 8.0 * f64::EPSILON));
        }
        let nonzero = h.iter().take(len).any(|x| *x != 0.0);
        let safe = h.iter().all(|x| x.is_finite())
            && only_decelerates(o, &h, len)
            && only_decelerates(&v, &h, len);
        (nonzero && safe).then_some(h)
    }

    /// The substitute for a rejected `cmd`.
    ///
    /// `HoldLast` rule — a rejected command must never cause more motion
    /// than a stop would. A hold is granted only if `allow_hold` (not an
    /// internal fault, not a gateway clock regression) and the rejected
    /// command is **readable intent of an authorised source**
    /// (`trust_content`, source allowed on the channel, right kind, finite);
    /// the held value is [`Self::hold_value`] (never more than the last
    /// emitted *or* the last accepted output) and must be a component-wise
    /// deceleration of the rejected command (each component zero, or same
    /// sign and magnitude ≤ requested). In every other case — a stop or
    /// slow-down rejected as rate-limited, stale, out of order or in the
    /// future; a reversal; NaN/kind-mismatch content whose intent is
    /// unknown; a foreign source; a channel already stopped by an earlier
    /// substitute — zero is emitted instead.
    fn substitute(
        &self,
        cmd: &Command,
        now: u64,
        ch_idx: usize,
        allow_hold: bool,
        trust_content: bool,
    ) -> Option<(Substitute, Raw)> {
        let ch = self.policy.channels.get(ch_idx)?;
        let hold_ok = |held: &Raw| {
            trust_content
                && cmd.source != SourceId::UNKNOWN
                && usize::from(cmd.source.0) < self.nsrc
                && ch.allows(cmd.source)
                && kind_matches(ch.kind, &cmd.motion)
                && cmd.motion.is_finite()
                && only_decelerates(&to_raw(&cmd.motion), held, width(ch.kind))
        };
        let (kind, raw) = match self.policy.platform.fail_behaviour {
            FailBehaviour::HoldLast { max_hold_ns } if allow_hold => {
                match self.hold_value(ch_idx, now, max_hold_ns) {
                    Some(h) if hold_ok(&h) => (SubstituteKind::HoldLast, h),
                    _ => (SubstituteKind::Zero, ZERO_RAW),
                }
            }
            _ => (SubstituteKind::Zero, ZERO_RAW),
        };
        Some((
            Substitute {
                kind,
                cmd: Command {
                    source: SourceId::FIREWALL,
                    channel: cmd.channel,
                    stamp_ns: now,
                    motion: from_raw(ch.kind, &raw),
                },
            },
            raw,
        ))
    }

    fn reject(&mut self, cmd: &Command, now: u64, ch_idx: usize, rej: Rejection) -> Verdict {
        let (rule, sev) = reject_rule(rej.reason);
        if self.observe {
            self.push_event(
                rule,
                sev,
                cmd,
                now,
                EventAction::ObservedOnly,
                rej.value,
                rej.limit,
            );
            self.commit_forwarded(cmd, now, ch_idx);
            self.stats.passed = self.stats.passed.saturating_add(1);
            self.stats.would_have = self.stats.would_have.saturating_add(1);
            return Verdict::Passed {
                cmd: *cmd,
                would_have: Some(WouldHave::Rejected { reason: rej.reason }),
            };
        }

        let foreign = rej.reason.is_foreign_source();
        let sub = if foreign {
            let platform = &self.policy.platform;
            let window_open = match self.chans.get(ch_idx).and_then(|st| st.last_foreign_sub_at) {
                Some(t) => now.saturating_sub(t) >= platform.foreign_substitute_min_interval_ns,
                None => true,
            };
            match platform.foreign_source_action {
                ForeignSourceAction::Substitute if window_open => {
                    self.substitute(cmd, now, ch_idx, true, false)
                }
                _ => None,
            }
        } else {
            // Under a gateway clock regression the hold age cannot be
            // measured, so never hold (F2): zero only.
            let allow_hold = rej.reason != RejectReason::ClockRegression;
            self.substitute(cmd, now, ch_idx, allow_hold, true)
        };
        if let Some((s, raw)) = sub {
            if foreign {
                if let Some(st) = self.chans.get_mut(ch_idx) {
                    st.last_foreign_sub_at = Some(now);
                }
            }
            // What was emitted downstream is the channel's previous output,
            // whoever triggered it: the next accepted command is acceleration
            // limited from it, so the emitted stream never violates the
            // limits. (This is why foreign substitutes are opt-in and
            // interval-bounded: under `Substitute` a spoofer can force at
            // most one stop + ramp-up per interval.)
            self.commit(ch_idx, raw, now, [0.0; 2], false);
            self.push_event(
                rule,
                sev,
                cmd,
                now,
                EventAction::Rejected(Some(s.kind)),
                rej.value,
                rej.limit,
            );
        } else {
            self.push_event(
                rule,
                sev,
                cmd,
                now,
                EventAction::Rejected(None),
                rej.value,
                rej.limit,
            );
        }
        self.stats.rejected = self.stats.rejected.saturating_add(1);
        Verdict::Rejected {
            reason: rej.reason,
            substitute: sub.map(|(s, _)| s),
        }
    }

    /// Internal fault handling per [`FaultPolicy`].
    fn fault(&mut self, cmd: &Command, now: u64) -> Verdict {
        self.stats.faults = self.stats.faults.saturating_add(1);
        let ch_idx = usize::from(cmd.channel.0);
        let (rule, sev) = reject_rule(RejectReason::InternalFault);
        let fail_open = self.observe || self.policy.platform.fault_policy == FaultPolicy::FailOpen;
        if fail_open {
            self.push_event(
                rule,
                sev,
                cmd,
                now,
                EventAction::ObservedOnly,
                f64::NAN,
                f64::NAN,
            );
            self.commit_forwarded(cmd, now, ch_idx);
            self.stats.passed = self.stats.passed.saturating_add(1);
            self.stats.would_have = self.stats.would_have.saturating_add(1);
            return Verdict::Passed {
                cmd: *cmd,
                would_have: Some(WouldHave::Rejected {
                    reason: RejectReason::InternalFault,
                }),
            };
        }
        // Fail-safe: zero only — state may be corrupt, so never hold.
        let sub = self.substitute(cmd, now, ch_idx, false, false);
        if let Some((_, raw)) = sub {
            self.commit(ch_idx, raw, now, [0.0; 2], false);
        }
        self.push_event(
            rule,
            sev,
            cmd,
            now,
            EventAction::Rejected(sub.map(|(s, _)| s.kind)),
            f64::NAN,
            f64::NAN,
        );
        self.stats.rejected = self.stats.rejected.saturating_add(1);
        Verdict::Rejected {
            reason: RejectReason::InternalFault,
            substitute: sub.map(|(s, _)| s),
        }
    }
}
