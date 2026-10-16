//! Latency / jitter harness for `Firewall::check` (std only).
//!
//! Run with: `cargo run --release -p robodr-firewall --example latency -- [N] [budgets]`
//! - `N`: number of commands (default 1_000_000).
//! - Budgets (all optional, nanoseconds; also read from the environment as
//!   `ROBODR_FW_BUDGET_P50_NS`, `..._P99_NS`, `..._MAX_NS`, `..._JITTER_NS`,
//!   flags win): `--budget-p50-ns X`, `--budget-p99-ns X`,
//!   `--budget-max-ns X`, `--budget-jitter-ns X` (jitter = p99 - p50).
//!
//! Prints p50 / p99 / p99.9 / max / jitter and a histogram, then a
//! `BUDGET:` line per configured budget. Exits with code **1** if any
//! configured budget is exceeded, **2** on a usage error, 0 otherwise. With
//! no budget configured it is a pure report. See the crate README: this is
//! a report-only gate until it runs on the target controller.
//!
//! Commands are pre-generated (so generation and allocation are outside the
//! timed region) as a realistic mix on a twist and a 6-joint channel: mostly
//! in-envelope, with speed/acceleration limiting, plus ~10% rejections
//! (unknown source, NaN, stale, over-hard). Each call is timed individually
//! with `Instant`; the timer's own overhead is measured and printed so it can
//! be subtracted mentally. Numbers depend heavily on the machine, CPU
//! frequency scaling, and scheduling — see the README caveats.

use robodr_events::profile::{Envelope, Profile};
use robodr_firewall::*;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;

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

fn firewall() -> Firewall {
    let mut p = Profile {
        model: "bench-ugv".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert(P.into());
    p.writer_topics.insert("/cmd_vel".into());
    p.writer_topics.insert("/arm/cmd".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(1.0),
            max_joint_speed: None,
        },
    );
    p.motion_envelopes.insert(
        "/arm/cmd".into(),
        Envelope {
            max_linear_speed: None,
            max_joint_speed: Some(1.5),
        },
    );
    let base = ChannelSpec {
        allowed_sources: vec![format!("{P}00000103")],
        max_angular_speed: Some(2.0),
        max_linear_accel: Some(2.0),
        max_angular_accel: Some(4.0),
        max_linear_jerk: Some(400.0),
        rate_limit: Some(RateLimit {
            per_second: 1_000_000,
            burst: 1_000,
        }),
        max_age_ns: u64::MAX / 4,
        ..Default::default()
    };
    let arm = ChannelSpec {
        kind: ChannelKind::Joints { count: 6 },
        allowed_sources: vec![format!("{P}00000303")],
        max_joint_accel: Some(5.0),
        max_age_ns: u64::MAX / 4,
        ..Default::default()
    };
    let specs = BTreeMap::from([
        ("/cmd_vel".to_string(), base),
        ("/arm/cmd".to_string(), arm),
    ]);
    let platform = PlatformConfig {
        fail_behaviour: FailBehaviour::HoldLast {
            max_hold_ns: 200 * MS,
        },
        event_capacity: 1024,
        ..Default::default()
    };
    Firewall::new(Policy::compile(&p, platform, &specs).expect("policy"))
}

/// Latency budgets in ns; `None` = not gated.
#[derive(Default)]
struct Budgets {
    p50: Option<u64>,
    p99: Option<u64>,
    max: Option<u64>,
    jitter: Option<u64>,
}

fn parse_args() -> Result<(usize, Budgets), String> {
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
        p50: env("ROBODR_FW_BUDGET_P50_NS")?,
        p99: env("ROBODR_FW_BUDGET_P99_NS")?,
        max: env("ROBODR_FW_BUDGET_MAX_NS")?,
        jitter: env("ROBODR_FW_BUDGET_JITTER_NS")?,
    };
    let mut n = 1_000_000usize;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let slot = match a.as_str() {
            "--budget-p50-ns" => &mut b.p50,
            "--budget-p99-ns" => &mut b.p99,
            "--budget-max-ns" => &mut b.max,
            "--budget-jitter-ns" => &mut b.jitter,
            _ => {
                n = a.parse().map_err(|_| format!("unknown argument {a:?}"))?;
                if n == 0 {
                    return Err("N must be >= 1".into());
                }
                continue;
            }
        };
        let v = args.next().ok_or_else(|| format!("{a} needs a value"))?;
        *slot = Some(v.parse().map_err(|_| format!("{a} {v}: not an integer"))?);
    }
    Ok((n, b))
}

fn main() {
    let (n, budgets) = match parse_args() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("latency: {e}");
            std::process::exit(2);
        }
    };
    let mut fw = firewall();
    let nav = fw.source_id(&format!("{P}00000103")).expect("nav");
    let arm_src = fw.source_id(&format!("{P}00000303")).expect("arm");
    let base = fw.channel_id("/cmd_vel").expect("base");
    let arm = fw.channel_id("/arm/cmd").expect("arm");

    // Pre-generate (cmd, now) pairs.
    let mut r = Rng(0xC0FF_EE00_1234_5678);
    let mut work = Vec::with_capacity(n);
    let mut now = 1_000 * MS;
    // Smooth random walks (a planner's output), occasionally jumping to a
    // fresh random target so the limiting paths run too.
    let (mut vx, mut wz) = (0.0f64, 0.0f64);
    let mut q = [0.0f64; 6];
    for i in 0..n {
        now += 950_000 + r.next() % 100_000; // 1 kHz +- 50 us jitter
        let stamp = now - r.next() % MS;
        let roll = r.next() % 100;
        let cmd = if i % 3 == 0 {
            for x in &mut q {
                *x = if r.next().is_multiple_of(2000) {
                    r.f(-2.0, 2.0)
                } else {
                    (*x + r.f(-0.0005, 0.0005)).clamp(-1.4, 1.4)
                };
            }
            let mut j = q;
            if roll < 3 {
                j[0] = f64::NAN;
            }
            let src = if roll == 5 {
                SourceId::UNKNOWN
            } else {
                arm_src
            };
            Command::joints(src, arm, stamp, JointVelocities::from_slice(&j).expect("6"))
        } else {
            if r.next().is_multiple_of(2000) {
                vx = r.f(-1.3, 1.3);
                wz = r.f(-2.5, 2.5);
            } else {
                vx = (vx + r.f(-0.0002, 0.0002)).clamp(-0.9, 0.9);
                wz = (wz + r.f(-0.0004, 0.0004)).clamp(-1.8, 1.8);
            }
            let mut t = Twist::new(Vec3::new(vx, 0.0, 0.0), Vec3::new(0.0, 0.0, wz));
            let src = match roll {
                0..=2 => SourceId::UNKNOWN,
                3..=4 => {
                    t.linear.x = f64::NAN;
                    nav
                }
                5..=6 => {
                    t.linear.x = 5.0;
                    nav
                }
                _ => nav,
            };
            let stamp = if roll == 7 { 0 } else { stamp };
            Command::twist(src, base, stamp, t)
        };
        work.push((cmd, now));
    }

    // Timer overhead.
    let mut overhead = Vec::with_capacity(100_000);
    for _ in 0..100_000 {
        let t0 = Instant::now();
        let t1 = Instant::now();
        overhead.push((t1 - t0).as_nanos() as u64);
    }
    overhead.sort_unstable();

    // Warm-up (caches, branch predictors), not recorded.
    let mut warm = firewall();
    for (c, t) in work.iter().take(10_000) {
        black_box(warm.check(c, *t));
    }

    let mut lat = vec![0u64; n];
    let mut sink = 0usize;
    let wall = Instant::now();
    for (i, (c, t)) in work.iter().enumerate() {
        let t0 = Instant::now();
        let v = fw.check(black_box(c), *t);
        let t1 = Instant::now();
        sink += usize::from(black_box(&v).is_rejected());
        if let Some(slot) = lat.get_mut(i) {
            *slot = (t1 - t0).as_nanos() as u64;
        }
        if i % 512 == 511 {
            fw.drain_events(|e| {
                black_box(e);
            });
        }
    }
    let wall = wall.elapsed();
    lat.sort_unstable();

    let pct = |v: &[u64], p: f64| v[((v.len() as f64 - 1.0) * p).round() as usize];
    let s = fw.stats();
    println!("robodr-firewall check() latency, {n} commands");
    println!(
        "verdicts: passed {} limited {} rejected {} (sink {sink})",
        s.passed, s.limited, s.rejected
    );
    println!(
        "timer overhead (Instant pair): p50 {} ns, p99 {} ns",
        pct(&overhead, 0.5),
        pct(&overhead, 0.99)
    );
    println!(
        "check (incl. timer): p50 {} ns | p99 {} ns | p99.9 {} ns | max {} ns | mean {:.1} ns (wall incl. loop {:.1} ns/cmd)",
        pct(&lat, 0.5),
        pct(&lat, 0.99),
        pct(&lat, 0.999),
        lat[lat.len() - 1],
        lat.iter().sum::<u64>() as f64 / n as f64,
        wall.as_nanos() as f64 / n as f64
    );

    let (p50, p99, max) = (pct(&lat, 0.5), pct(&lat, 0.99), lat[lat.len() - 1]);
    let jitter = p99.saturating_sub(p50);
    println!("jitter (p99 - p50): {jitter} ns");

    // Log2 histogram.
    let mut buckets = [0usize; 24];
    for &x in &lat {
        let b = (64 - x.max(1).leading_zeros()) as usize;
        buckets[b.min(23)] += 1;
    }
    let maxc = *buckets.iter().max().unwrap_or(&1);
    println!("histogram (ns, log2 buckets):");
    for (b, &c) in buckets.iter().enumerate() {
        if c == 0 {
            continue;
        }
        let lo = if b == 0 { 0 } else { 1u64 << (b - 1) };
        let hi = (1u64 << b) - 1;
        let bar = "#".repeat((c * 50).div_ceil(maxc));
        println!(
            "  {:>8}..{:<8} {:>9} {:>7.3}% {bar}",
            lo,
            hi,
            c,
            100.0 * c as f64 / n as f64
        );
    }

    // Budget gate (report-only until measured on the target controller).
    let mut over = false;
    for (name, got, budget) in [
        ("p50", p50, budgets.p50),
        ("p99", p99, budgets.p99),
        ("max", max, budgets.max),
        ("jitter", jitter, budgets.jitter),
    ] {
        if let Some(b) = budget {
            let ok = got <= b;
            over |= !ok;
            println!(
                "BUDGET: {name} {got} ns <= {b} ns: {}",
                if ok { "ok" } else { "OVER" }
            );
        }
    }
    if over {
        eprintln!("latency: budget exceeded");
        std::process::exit(1);
    }
}
