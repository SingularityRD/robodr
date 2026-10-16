//! The response model and the bounded command history.
//!
//! Both are allocation-free after construction and fully deterministic: no
//! clocks, no randomness, no hashing.

/// Advance a rate-limited first-order response by `dt_s` seconds.
///
/// Solves `de/dt = clamp((u - e) / tau, -a, a)` exactly for a constant input
/// `u`: a linear ramp at the acceleration limit `a` while the first-order
/// slope would exceed it, then an exponential approach with time constant
/// `tau`. `tau_s <= 0` means "instantaneous apart from the rate limit";
/// `max_rate = None` means "no rate limit".
///
/// Inputs are expected finite (the monitor sanitises them); non-positive or
/// non-finite `dt_s` returns `e` unchanged.
pub fn first_order_step(e: f64, u: f64, dt_s: f64, tau_s: f64, max_rate: Option<f64>) -> f64 {
    // `is_finite` also rejects NaN.
    if !dt_s.is_finite() || dt_s <= 0.0 {
        return e;
    }
    let d = u - e;
    if d == 0.0 {
        return e;
    }
    let sign = d.signum();
    let ad = d.abs();
    match max_rate {
        Some(a) if a > 0.0 && a.is_finite() => {
            if tau_s <= 0.0 {
                let step = a * dt_s;
                return if step >= ad { u } else { e + sign * step };
            }
            let knee = a * tau_s; // |u - e| at which the first-order slope equals `a`
            let (mut ad, mut dt) = (ad, dt_s);
            if ad > knee {
                let t_ramp = (ad - knee) / a;
                if dt <= t_ramp {
                    return e + sign * a * dt;
                }
                dt -= t_ramp;
                ad = knee;
            }
            u - sign * ad * (-dt / tau_s).exp()
        }
        _ => {
            if tau_s <= 0.0 {
                u
            } else {
                u - d * (-dt_s / tau_s).exp()
            }
        }
    }
}

/// One recorded command: observer time and per-axis value (`None` =
/// unspecified axis). Values are already sanitised (finite), and are
/// magnitudes when `signed` is `false`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct CmdRec {
    pub t: u64,
    pub v: [Option<f64>; 3],
    pub signed: bool,
}

/// Fixed-capacity ring of commands, oldest first, sorted by `t` (the monitor
/// guarantees non-decreasing push times).
///
/// The buffer is allocated once with `vec![_; cap]` and only ever written by
/// index, so its capacity never changes. The most recently evicted record is
/// kept as `floor`: it is exactly "the latest command before the oldest
/// retained one", so lookups stay exact for any time at or after it.
#[derive(Debug, Clone)]
pub(crate) struct CommandRing {
    buf: Vec<CmdRec>,
    head: usize,
    len: usize,
    floor: Option<CmdRec>,
}

impl CommandRing {
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        CommandRing {
            buf: vec![CmdRec::default(); cap],
            head: 0,
            len: 0,
            floor: None,
        }
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.len
    }

    fn get(&self, i: usize) -> CmdRec {
        self.buf[(self.head + i) % self.buf.len()]
    }

    /// Push a record; returns the evicted one when full.
    pub fn push(&mut self, rec: CmdRec) -> Option<CmdRec> {
        let cap = self.buf.len();
        if self.len < cap {
            let idx = (self.head + self.len) % cap;
            self.buf[idx] = rec;
            self.len += 1;
            None
        } else {
            let ev = self.buf[self.head];
            self.buf[self.head] = rec;
            self.head = (self.head + 1) % cap;
            self.floor = Some(ev);
            Some(ev)
        }
    }

    /// The command in effect at time `t`: the latest record with
    /// `rec.t <= t`. If `t` predates everything retained, the floor record
    /// is returned as a best-effort approximation (the monitor counts this
    /// as a history underrun at eviction time). `None` only if no command was
    /// ever pushed.
    pub fn at(&self, t: u64) -> Option<CmdRec> {
        for i in (0..self.len).rev() {
            let r = self.get(i);
            if r.t <= t {
                return Some(r);
            }
        }
        self.floor
    }

    /// The earliest `rec.t + lat` strictly after `t`, over floor and ring.
    pub fn next_effect_after(&self, t: u64, lat: u64) -> Option<u64> {
        if let Some(f) = self.floor {
            let cp = f.t.saturating_add(lat);
            if cp > t {
                return Some(cp);
            }
        }
        for i in 0..self.len {
            let cp = self.get(i).t.saturating_add(lat);
            if cp > t {
                return Some(cp);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() <= eps
    }

    /// Reference: explicit Euler with a tiny step.
    fn euler(mut e: f64, u: f64, dt: f64, tau: f64, a: Option<f64>) -> f64 {
        let n = 200_000;
        let h = dt / n as f64;
        for _ in 0..n {
            let mut slope = if tau > 0.0 { (u - e) / tau } else { 0.0 };
            if let Some(a) = a {
                slope = slope.clamp(-a, a);
            }
            e += slope * h;
        }
        e
    }

    #[test]
    fn pure_first_order_matches_closed_form() {
        let e = first_order_step(0.0, 1.0, 0.2, 0.2, None);
        assert!(close(e, 1.0 - (-1.0f64).exp(), 1e-12));
    }

    #[test]
    fn rate_limited_matches_numerical_integration() {
        for &(e0, u, dt, tau, a) in &[
            (0.0, 1.0, 0.3, 0.25, 2.0),
            (0.0, 1.0, 1.5, 0.25, 2.0),
            (1.5, -1.0, 0.7, 0.1, 3.0),
            (0.2, 0.3, 0.5, 0.25, 2.0),  // never hits the limit
            (0.0, 2.0, 0.05, 0.25, 2.0), // pure ramp phase
        ] {
            let exact = first_order_step(e0, u, dt, tau, Some(a));
            let reference = euler(e0, u, dt, tau, Some(a));
            assert!(
                close(exact, reference, 1e-4),
                "e0={e0} u={u} dt={dt}: {exact} vs {reference}"
            );
        }
    }

    #[test]
    fn pure_rate_limit_and_degenerate_inputs() {
        assert_eq!(first_order_step(0.0, 1.0, 0.1, 0.0, Some(2.0)), 0.2);
        assert_eq!(first_order_step(0.0, 1.0, 1.0, 0.0, Some(2.0)), 1.0);
        assert_eq!(first_order_step(0.0, 1.0, 0.1, 0.0, None), 1.0);
        assert_eq!(first_order_step(0.3, 1.0, 0.0, 0.2, None), 0.3);
        assert_eq!(first_order_step(0.3, 1.0, -1.0, 0.2, None), 0.3);
        assert_eq!(first_order_step(0.3, 1.0, f64::NAN, 0.2, None), 0.3);
        assert_eq!(first_order_step(0.3, 1.0, f64::INFINITY, 0.2, None), 0.3);
        // Huge dt converges without overflow.
        assert!(close(
            first_order_step(0.0, 1.0, 1e9, 0.2, Some(2.0)),
            1.0,
            1e-12
        ));
    }

    #[test]
    fn monotone_never_overshoots() {
        let mut e = 0.0;
        for _ in 0..1000 {
            e = first_order_step(e, 1.0, 0.01, 0.2, Some(2.0));
            assert!(e <= 1.0);
        }
        assert!(close(e, 1.0, 1e-9));
    }

    #[test]
    fn ring_lookup_and_eviction_floor() {
        let mut r = CommandRing::new(3);
        assert_eq!(r.at(100), None);
        for t in [10u64, 20, 30, 40, 50] {
            r.push(CmdRec {
                t,
                v: [Some(t as f64), None, None],
                signed: true,
            });
        }
        assert_eq!(r.len(), 3);
        assert_eq!(r.capacity(), 3);
        assert_eq!(r.at(35).unwrap().t, 30);
        assert_eq!(r.at(29).unwrap().t, 20); // the floor: exact
        assert_eq!(r.at(5).unwrap().t, 20); // underrun: best effort
        assert_eq!(r.at(1000).unwrap().t, 50);
        assert_eq!(r.next_effect_after(25, 0), Some(30));
        assert_eq!(r.next_effect_after(0, 5), Some(25));
        assert_eq!(r.next_effect_after(55, 0), None);
        assert_eq!(r.next_effect_after(u64::MAX - 1, u64::MAX), Some(u64::MAX));
    }
}
