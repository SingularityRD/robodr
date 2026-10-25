//! Latency / jitter / allocation harness for `Firewall::check_joint`
//! (low-level joint frames, Unitree `LowCmd` style), std only.
//!
//! Run with:
//! `cargo run --release -p robodr-firewall --example joint_latency -- [SECONDS] [--fast] [budgets]`
//! - `SECONDS`: length of each scenario (default 2).
//! - `--fast`: do not pace in real time; feed frames back to back on a
//!   simulated clock (same `now` sequence, warmer caches, much quicker).
//! - Budgets (optional, ns; also from the environment as
//!   `ROBODR_FW_JOINT_BUDGET_P50_NS`, `..._P99_NS`, `..._MAX_NS`,
//!   `..._JITTER_NS`; flags win): `--budget-p50-ns X`, `--budget-p99-ns X`,
//!   `--budget-max-ns X`, `--budget-jitter-ns X` (jitter = p99 − p50),
//!   applied to every scenario.
//!
//! Scenarios: a 35-slot humanoid frame (29 actuated, G1 / H1-2 layout) and a
//! 12-slot quadruped frame (Go1 / A1 layout), each at 1 kHz and at 500 Hz.
//! By default each runs **paced in real time** at its rate (sleep, then spin
//! to the deadline), so every `check_joint` call sees the caches a real
//! control loop sees between ticks. The frame mix: smooth trajectories, ~3 %
//! frames with a stepped position target and a clamped torque, ~1.5 %
//! rejected (CRC invalid, NaN, an unused slot energised, a torque beyond the
//! hard bound).
//!
//! Prints, per scenario, decision-time p50 / p99 / p99.9 / max / mean,
//! jitter, the verdict mix and the number of heap allocations made on this
//! thread during the timed loop (a counting global allocator). Exit code
//! **1** if any allocation happened in a timed loop or a configured budget
//! is exceeded, **2** on a usage error, 0 otherwise. Latency budgets follow
//! the crate's report-only policy (see the README); the allocation check is
//! a hard failure.

use robodr_events::profile::{Envelope, Profile};
use robodr_firewall::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

// ------------------------------------------------------ counting allocator

struct Counting;

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

fn bump() {
    let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        bump();
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocs() -> u64 {
    ALLOCS.with(|c| c.get())
}

// ------------------------------------------------------------------ setup

const P: &str = "0123456789abcdef01234567";
const MS: u64 = 1_000_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn f(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * ((self.next() >> 11) as f64 / (1u64 << 53) as f64)
    }
}

struct Scenario {
    name: &'static str,
    slots: usize,
    active: usize,
    hz: f64,
    humanoid: bool,
}

const Q: (f64, f64) = (-1.5, 1.5);
const DQ: f64 = 20.0;
const TAU: f64 = 60.0;
const KP: f64 = 200.0;
const KD: f64 = 8.0;
/// Per-frame position step bound (rad); the trajectories move ~2 mrad per
/// tick, the "clamp" frames 70 mrad (stepped, within the hard factor).
const STEP: f64 = 0.05;

fn firewall(sc: &Scenario) -> Firewall {
    let mut p = Profile {
        model: "bench-legged".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert(P.into());
    p.writer_topics.insert("/lowcmd".into());
    p.motion_envelopes.insert(
        "/lowcmd".into(),
        Envelope {
            max_joint_speed: Some(30.0),
            ..Default::default()
        },
    );
    let motors = (0..sc.slots)
        .map(|i| {
            if i < sc.active {
                MotorLimits {
                    kp_min: if sc.humanoid { 5.0 } else { 0.0 },
                    max_dq_step: Some(STEP),
                    tau_pd_max: Some(TAU),
                    ..MotorLimits::enabled(Q, DQ, TAU, KP, KD)
                }
            } else {
                MotorLimits::disabled()
            }
        })
        .collect();
    let spec = JointChannelSpec {
        allowed_sources: vec![format!("{P}00000103")],
        motors,
        rate: Some(JointRate::around(sc.hz)),
        damping_kd: 2.0,
        ..Default::default()
    };
    let platform = if sc.humanoid {
        PlatformConfig {
            morphology: Morphology::Humanoid,
            fail_behaviour: FailBehaviour::HoldLast {
                max_hold_ns: 200 * MS,
            },
            fault_policy: FaultPolicy::FailHold,
            event_capacity: 1024,
            ..Default::default()
        }
    } else {
        PlatformConfig {
            morphology: Morphology::Quadruped,
            fail_behaviour: FailBehaviour::HoldLast {
                max_hold_ns: 100 * MS,
            },
            event_capacity: 1024,
            ..Default::default()
        }
    };
    Firewall::new(
        Policy::compile_with_joints(
            &p,
            platform,
            &BTreeMap::new(),
            &BTreeMap::from([("/lowcmd".to_string(), spec)]),
        )
        .expect("policy"),
    )
}

/// Pre-generated `(cmd, now)` stream for one scenario.
fn work(sc: &Scenario, fw: &Firewall, n: usize, seed: u64) -> Vec<(JointCommand, u64)> {
    let src = fw.source_id(&format!("{P}00000103")).expect("src");
    let ch = fw.channel_id("/lowcmd").expect("ch");
    let period = (1e9 / sc.hz) as u64;
    let mut r = Rng(seed);
    let phase: Vec<f64> = (0..sc.slots)
        .map(|_| r.f(0.0, std::f64::consts::TAU))
        .collect();
    let mut out = Vec::with_capacity(n);
    let mut now = 1_000 * MS;
    for k in 0..n {
        // Period with +-2 % jitter.
        now += period - period / 50 + r.next() % (period / 25).max(1);
        let stamp = now - r.next() % (period / 2).max(1);
        let t = k as f64 / sc.hz;
        let mut frame = JointFrame::new(sc.slots, Some(true)).expect("slots");
        for (i, &ph) in phase.iter().enumerate().take(sc.active) {
            let m = frame.motor_mut(i).expect("slot");
            *m = MotorCmd::enabled(
                1.2 * (t * 1.3 + ph).sin(),
                1.5 * (t * 1.3 + ph).cos(),
                10.0 * (t * 0.7 + ph).sin(),
                60.0,
                2.0,
            );
        }
        let roll = r.next() % 1000;
        let slot = (r.next() as usize) % sc.active;
        match roll {
            0..=29 => {
                // Clamp: a position nudge past the step bound and a torque
                // past its bound (both limited, neither rejected).
                let m = frame.motor_mut(slot).expect("slot");
                m.q += 0.07;
                m.tau = 1.5 * TAU;
            }
            30..=32 => frame.crc_ok = Some(false),
            33..=35 => frame.motor_mut(slot).expect("slot").dq = f64::NAN,
            36..=38 if sc.slots > sc.active => {
                *frame.motor_mut(sc.slots - 1).expect("slot") =
                    MotorCmd::enabled(0.0, 0.0, 1.0, 0.0, 0.0)
            }
            39..=44 => frame.motor_mut(slot).expect("slot").tau = 5.0 * TAU,
            _ => {}
        }
        out.push((JointCommand::new(src, ch, stamp, frame), now));
    }
    out
}

#[derive(Default)]
struct Budgets {
    p50: Option<u64>,
    p99: Option<u64>,
    max: Option<u64>,
    jitter: Option<u64>,
}

fn parse_args() -> Result<(f64, bool, Budgets), String> {
    let env = |k: &str| -> Result<Option<u64>, String> {
        match std::env::var(k) {
            Ok(v) => v
                .parse()
                .map(Some)
                .map_err(|_| format!("{k}={v}: not an integer")),
            Err(_) => Ok(None),
        }
    };
    let mut b = Budgets {
        p50: env("ROBODR_FW_JOINT_BUDGET_P50_NS")?,
        p99: env("ROBODR_FW_JOINT_BUDGET_P99_NS")?,
        max: env("ROBODR_FW_JOINT_BUDGET_MAX_NS")?,
        jitter: env("ROBODR_FW_JOINT_BUDGET_JITTER_NS")?,
    };
    let mut secs = 2.0f64;
    let mut fast = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let slot = match a.as_str() {
            "--fast" => {
                fast = true;
                continue;
            }
            "--budget-p50-ns" => &mut b.p50,
            "--budget-p99-ns" => &mut b.p99,
            "--budget-max-ns" => &mut b.max,
            "--budget-jitter-ns" => &mut b.jitter,
            _ => {
                secs = a.parse().map_err(|_| format!("unknown argument {a:?}"))?;
                if !(secs.is_finite() && secs > 0.0) {
                    return Err("SECONDS must be > 0".into());
                }
                continue;
            }
        };
        let v = args.next().ok_or_else(|| format!("{a} needs a value"))?;
        *slot = Some(v.parse().map_err(|_| format!("{a} {v}: not an integer"))?);
    }
    Ok((secs, fast, b))
}

/// Wait until `deadline`: sleep while far away, then spin.
fn wait_until(deadline: Instant) {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let left = deadline - now;
        if left > Duration::from_micros(300) {
            std::thread::sleep(left - Duration::from_micros(200));
        } else {
            std::hint::spin_loop();
        }
    }
}

fn pct(v: &[u64], p: f64) -> u64 {
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn main() {
    let (secs, fast, budgets) = match parse_args() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("joint_latency: {e}");
            std::process::exit(2);
        }
    };
    let scenarios = [
        Scenario {
            name: "humanoid 35 slots (29 actuated) @ 1 kHz",
            slots: 35,
            active: 29,
            hz: 1000.0,
            humanoid: true,
        },
        Scenario {
            name: "humanoid 35 slots (29 actuated) @ 500 Hz",
            slots: 35,
            active: 29,
            hz: 500.0,
            humanoid: true,
        },
        Scenario {
            name: "quadruped 12 slots @ 1 kHz",
            slots: 12,
            active: 12,
            hz: 1000.0,
            humanoid: false,
        },
        Scenario {
            name: "quadruped 12 slots @ 500 Hz",
            slots: 12,
            active: 12,
            hz: 500.0,
            humanoid: false,
        },
    ];

    // Timer overhead.
    let mut overhead = Vec::with_capacity(100_000);
    for _ in 0..100_000 {
        let t0 = Instant::now();
        let t1 = Instant::now();
        overhead.push((t1 - t0).as_nanos() as u64);
    }
    overhead.sort_unstable();
    println!(
        "robodr-firewall check_joint() latency, {secs} s per scenario, {} (timer overhead p50 {} ns, p99 {} ns)",
        if fast {
            "back to back (--fast)"
        } else {
            "paced in real time"
        },
        pct(&overhead, 0.5),
        pct(&overhead, 0.99)
    );
    println!(
        "{:<44} {:>7} {:>7} {:>7} {:>7} {:>8} {:>8} {:>9} {:>8} | {:>6} {:>6} {:>6} {:>6}",
        "scenario",
        "frames",
        "p50",
        "p99",
        "p99.9",
        "max",
        "mean",
        "jitter",
        "allocs",
        "pass",
        "limit",
        "reject",
        "hold"
    );

    let mut failed = false;
    for (si, sc) in scenarios.iter().enumerate() {
        let n = ((secs * sc.hz) as usize).max(1);
        let mut fw = firewall(sc);
        let stream = work(sc, &fw, n, 0xC0FF_EE00_1234_5678 ^ si as u64);
        // Warm-up on a separate firewall (caches, branch predictors).
        let mut warm = firewall(sc);
        for (c, t) in stream.iter().take(2_000) {
            black_box(warm.check_joint(c, *t));
        }
        let mut lat = vec![0u64; n];
        let mut holds = 0u64;
        let t0_sim = stream.first().map_or(0, |(_, t)| *t);
        let start = Instant::now() + Duration::from_millis(5);
        let a0 = allocs();
        for (i, (c, t)) in stream.iter().enumerate() {
            if !fast {
                wait_until(start + Duration::from_nanos(t - t0_sim));
            }
            let t0 = Instant::now();
            let v = fw.check_joint(black_box(c), *t);
            let t1 = Instant::now();
            holds += u64::from(black_box(&v).substitute_kind() == Some(SubstituteKind::HoldLast));
            if let Some(slot) = lat.get_mut(i) {
                *slot = (t1 - t0).as_nanos() as u64;
            }
            if i % 100 == 99 {
                fw.drain_events(|e| {
                    black_box(e);
                });
            }
        }
        let a1 = allocs();
        let alloc_count = a1 - a0;
        lat.sort_unstable();
        let (p50, p99, p999, max) = (
            pct(&lat, 0.5),
            pct(&lat, 0.99),
            pct(&lat, 0.999),
            lat[lat.len() - 1],
        );
        let mean = lat.iter().sum::<u64>() as f64 / n as f64;
        let jitter = p99.saturating_sub(p50);
        let s = fw.stats();
        println!(
            "{:<44} {:>7} {:>5}ns {:>5}ns {:>5}ns {:>6}ns {:>6.0}ns {:>7}ns {:>8} | {:>6} {:>6} {:>6} {:>6}",
            sc.name, n, p50, p99, p999, max, mean, jitter, alloc_count, s.passed, s.limited,
            s.rejected, holds
        );
        if alloc_count != 0 {
            eprintln!(
                "joint_latency: {}: {alloc_count} heap allocations in the timed loop",
                sc.name
            );
            failed = true;
        }
        for (name, got, budget) in [
            ("p50", p50, budgets.p50),
            ("p99", p99, budgets.p99),
            ("max", max, budgets.max),
            ("jitter", jitter, budgets.jitter),
        ] {
            if let Some(b) = budget {
                let ok = got <= b;
                failed |= !ok;
                println!(
                    "BUDGET: {} {name} {got} ns <= {b} ns: {}",
                    sc.name,
                    if ok { "ok" } else { "OVER" }
                );
            }
        }
    }
    if failed {
        eprintln!("joint_latency: allocation check failed or budget exceeded");
        std::process::exit(1);
    }
}
