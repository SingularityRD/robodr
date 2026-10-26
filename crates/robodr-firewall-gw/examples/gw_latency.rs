//! Latency harness for the gateway's decision path: one queued IPv4 packet
//! in (bytes), verdict out (`Gateway::process`: IP / UDP checks, strict RTPS
//! walk, strict CDR decode + canonical re-encode, firewall `check_joint`,
//! in-place rewrite with CRC + verification, UDP checksum). The kernel's
//! NFQUEUE round trip is measured separately by `tests/netns_e2e.rs`.
//!
//! ```text
//! cargo run --release -p robodr-firewall-gw --example gw_latency -- [SECONDS] [--fast] \
//!     [--budget-p99-ns X] [--budget-max-ns X]
//! ```
//!
//! Scenarios (each `SECONDS`, default 2): G1 (35 slots, hg `LowCmd_`,
//! humanoid) and Go2 (20 slots, go `LowCmd_`, quadruped) at 1 kHz and
//! 500 Hz, paced in real time (±2 % jitter) unless `--fast`. Mix: smooth
//! trajectories, about 3 % frames with a torque over `tau_max` (limited:
//! rewritten), about 1 % violating hard (rejected: hold rewritten in
//! place), about 1 % from a foreign writer (suppressed). Prints p50, p99,
//! p99.9, max per scenario and the heap allocations made inside the timed
//! calls (counting global allocator). Exit 1 if a configured budget is
//! exceeded, 2 on a usage error. Budgets are report-only until measured on
//! the target hardware (see the crate README).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use robodr_cdr::Representation;
use robodr_firewall_gw::lowcmd::WireMotor;
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{PacketMeta, Verdict};

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarded to the system allocator with the same layout.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: forwarded to the system allocator with the same layout.
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn main() {
    let mut secs = 2.0f64;
    let mut fast = false;
    let mut budget_p99: Option<u64> = None;
    let mut budget_max: Option<u64> = None;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--fast" => fast = true,
            "--budget-p99-ns" | "--budget-max-ns" => {
                let Some(v) = args.get(i + 1).and_then(|v| v.parse().ok()) else {
                    eprintln!("{} needs a number", args[i]);
                    std::process::exit(2);
                };
                if args[i] == "--budget-p99-ns" {
                    budget_p99 = Some(v);
                } else {
                    budget_max = Some(v);
                }
                i += 1;
            }
            s => match s.parse() {
                Ok(v) => secs = v,
                Err(_) => {
                    eprintln!("usage: gw_latency [SECONDS] [--fast] [--budget-p99-ns X] [--budget-max-ns X]");
                    std::process::exit(2);
                }
            },
        }
        i += 1;
    }
    let mut failed = false;
    println!(
        "{:<26} {:>6} {:>9} {:>9} {:>9} {:>10} {:>8} {:>8} {:>7}",
        "scenario",
        "frames",
        "p50 ns",
        "p99 ns",
        "p99.9 ns",
        "max ns",
        "modified",
        "dropped",
        "allocs"
    );
    for (fx, hz) in [
        (Fixture::G1, 1000.0),
        (Fixture::G1, 500.0),
        (Fixture::Go2, 1000.0),
        (Fixture::Go2, 500.0),
    ] {
        let r = scenario(fx, hz, secs, fast);
        let name = format!(
            "{} {} slots @ {} Hz",
            if fx == Fixture::G1 { "G1" } else { "Go2" },
            if fx == Fixture::G1 { 35 } else { 20 },
            hz
        );
        println!(
            "{name:<26} {:>6} {:>9} {:>9} {:>9} {:>10} {:>8} {:>8} {:>7}",
            r.n, r.p50, r.p99, r.p999, r.max, r.modified, r.dropped, r.allocs
        );
        if budget_p99.is_some_and(|b| r.p99 > b) {
            println!(
                "BUDGET: {name}: p99 {} ns > {} ns",
                r.p99,
                budget_p99.unwrap_or(0)
            );
            failed = true;
        }
        if budget_max.is_some_and(|b| r.max > b) {
            println!(
                "BUDGET: {name}: max {} ns > {} ns",
                r.max,
                budget_max.unwrap_or(0)
            );
            failed = true;
        }
    }
    if failed {
        std::process::exit(1);
    }
}

struct Report {
    n: usize,
    p50: u64,
    p99: u64,
    p999: u64,
    max: u64,
    modified: u64,
    dropped: u64,
    allocs: u64,
}

fn scenario(fx: Fixture, hz: f64, secs: f64, fast: bool) -> Report {
    let mut cfg = gateway_config(fx);
    cfg.channels.truncate(1);
    let mut fwc = firewall(fx);
    if let Some(j) = fwc.joint_channels.get_mut("/lowcmd") {
        j.rate = Some(robodr_firewall::JointRate {
            expected_hz: hz,
            min_interval_ns: (0.4e9 / hz) as u64,
            max_interval_ns: (4.0e9 / hz) as u64,
        });
    }
    let mut gw = robodr_firewall_gw::Gateway::new(&cfg, &profile(fx), &fwc).expect("gateway");
    let spec = lowcmd_spec(fx);
    let pins = (spec.pinned_mode_pr, spec.pinned_mode_machine);
    let enabled: Vec<usize> = spec
        .motors
        .iter()
        .enumerate()
        .filter(|(_, m)| m.enabled)
        .map(|(i, _)| i)
        .collect();
    let n = (secs * hz) as usize;
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed >> 11) as f64 / (1u64 << 53) as f64
    };
    // Pre-generate every packet (no allocation or encoding in the timed loop).
    let mut packets: Vec<Vec<u8>> = Vec::with_capacity(n);
    for k in 0..n {
        let mut f = mid_frame(codec(fx), &spec.motors, k as f64 / hz * 3.0, pins);
        let r = rnd();
        let slot = enabled[(rnd() * enabled.len() as f64) as usize % enabled.len()];
        let mut prefix = PREFIX;
        if r < 0.03 {
            let mut w: WireMotor = f.motor(slot).unwrap_or_default();
            w.tau = (spec.motors[slot].tau_max.unwrap_or(1.0) * 1.4) as f32;
            f.set_motor(slot, w);
        } else if r < 0.04 {
            let mut w: WireMotor = f.motor(slot).unwrap_or_default();
            w.tau = 1e5;
            f.set_motor(slot, w);
        } else if r < 0.05 {
            prefix = FOREIGN;
        }
        f.seal();
        let d = lowcmd_datagram(prefix, WRITER, k as i64 + 1, &f, Representation::CdrLe);
        packets.push(packet(CONTROLLER_IP, DDS_PORT, &d));
    }
    let period = Duration::from_secs_f64(1.0 / hz);
    let mut lat = Vec::with_capacity(n);
    let mut work: Vec<u8> = Vec::with_capacity(2048);
    let (mut modified, mut dropped) = (0u64, 0u64);
    let mut allocs = 0u64;
    let start = Instant::now();
    let mut now_ns = 1_000_000_000u64;
    for (k, p) in packets.iter().enumerate() {
        let jitter = 1.0 + (rnd() - 0.5) * 0.04;
        if !fast {
            let target = start + period.mul_f64(k as f64 + (jitter - 1.0).max(0.0));
            while Instant::now() < target {
                std::hint::spin_loop();
            }
        }
        now_ns += (period.as_nanos() as f64 * jitter) as u64;
        work.clear();
        work.extend_from_slice(p);
        let meta = PacketMeta {
            now_ns,
            queue_delay_ns: None,
            instant: start,
            src_mac: None,
        };
        let a0 = ALLOCS.load(Ordering::Relaxed);
        let t0 = Instant::now();
        let v = gw.process(&mut work, meta);
        let dt = t0.elapsed().as_nanos() as u64;
        allocs += ALLOCS.load(Ordering::Relaxed) - a0;
        lat.push(dt);
        match v {
            Verdict::AcceptModified => modified += 1,
            Verdict::Drop => dropped += 1,
            Verdict::Accept => {}
        }
    }
    lat.sort_unstable();
    let q = |p: f64| lat[((lat.len() as f64 * p).ceil() as usize).clamp(1, lat.len()) - 1];
    Report {
        n: lat.len(),
        p50: q(0.5),
        p99: q(0.99),
        p999: q(0.999),
        max: *lat.last().unwrap_or(&0),
        modified,
        dropped,
        allocs,
    }
}
