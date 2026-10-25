//! Test-level latency gate for `check_joint` (35- and 12-slot frames).
//!
//! Follows the crate's latency policy (README, "Latency and jitter
//! harness"): numbers from shared CI runners are not a budget, so this is
//! **report-only in debug builds** (what `cargo test` runs). In a release
//! build (`cargo test --release`) it also enforces a deliberately generous
//! bound, p99 < 50 µs per decision — about 50x the p99 measured on the
//! development VM — which only a pathological regression (an allocation, an
//! unbounded loop) can trip. The hard zero-allocation check lives in
//! `tests/alloc_free.rs`; the full harness is `examples/joint_latency.rs`.

mod common;
use common::*;
use robodr_firewall::*;
use std::hint::black_box;
use std::time::Instant;

const FRAMES: usize = 20_000;
const RELEASE_P99_BOUND_NS: u64 = 50_000;

fn measure(slots: usize, active: usize, platform: PlatformConfig) -> (u64, u64, u64) {
    let mut f = build_joint(platform, true, slots, active, |s| {
        s.rate = Some(JointRate::around(1000.0));
    });
    let mut r = Rng(0xDEC0_DE00 ^ slots as u64);
    let mut work = Vec::with_capacity(FRAMES);
    let mut now = T0;
    for k in 0..FRAMES {
        now += 980_000 + r.below(40_000);
        let t = k as f64 * 1e-3;
        let mut c = JointCommand::new(
            f.ctl,
            f.low,
            now - r.below(100_000),
            jframe(slots, active, |i| {
                MotorCmd::enabled(0.8 * (t + i as f64).sin(), 0.5, 2.0, 50.0, 1.0)
            }),
        );
        match r.below(100) {
            0..=2 => c.frame.motor_mut(0).unwrap().q = 1.4, // clamp
            3 => c.frame.crc_ok = Some(false),              // reject
            _ => {}
        }
        work.push((c, now));
    }
    let mut lat = Vec::with_capacity(FRAMES);
    for (c, t) in &work {
        let t0 = Instant::now();
        let v = f.fw.check_joint(black_box(c), *t);
        lat.push(t0.elapsed().as_nanos() as u64);
        black_box(v);
    }
    let s = f.fw.stats();
    assert!(s.passed > 0 && s.limited > 0 && s.rejected > 0, "{s:?}");
    lat.sort_unstable();
    let pct = |p: f64| lat[((lat.len() as f64 - 1.0) * p).round() as usize];
    (pct(0.5), pct(0.99), lat[lat.len() - 1])
}

#[test]
fn joint_decision_latency_report_and_generous_release_gate() {
    for (name, slots, active, platform) in [
        ("humanoid 35/29", 35, 29, humanoid()),
        (
            "quadruped 12/12",
            12,
            12,
            quadruped(FailBehaviour::HoldLast {
                max_hold_ns: 100 * MS,
            }),
        ),
    ] {
        let (p50, p99, max) = measure(slots, active, platform);
        let build = if cfg!(debug_assertions) {
            "debug, report only"
        } else {
            "release, gated"
        };
        eprintln!(
            "check_joint {name}: p50 {p50} ns, p99 {p99} ns, max {max} ns ({FRAMES} frames, {build})"
        );
        if !cfg!(debug_assertions) {
            assert!(
                p99 < RELEASE_P99_BOUND_NS,
                "{name}: p99 {p99} ns >= {RELEASE_P99_BOUND_NS} ns"
            );
        }
    }
}
