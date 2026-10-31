//! Fleet capacity harness, in process (sales-readiness T71): N units, each
//! with its own key directory, state directory and fleet journal, run
//! concurrently against one reference SOC (`tests/common/soc.rs`):
//! enroll, uplink rotation (overlap, swap, retire), finding rotation
//! cancelled at the SOC, decommission. Afterwards the SOC's invariants must
//! hold: every unit enrolled and decommissioned, every key registered once
//! (3 per enrollment + 1 per rotation), none left active, no rotation open,
//! and every unit's fleet journal verifies.
//!
//! `ROBODR_FLEET_SIM_UNITS` (default 8) and `ROBODR_FLEET_SIM_THREADS`
//! (default 4) size it: 50 and 500 are the documented capacity runs
//! (`tools/fleet-sim/README.md`); the real-binary, one-netns-per-unit run
//! is `tools/fleet-sim/run.sh --netns`.

mod common;

use common::soc::{Soc, BASE};
use common::*;
use robodr_fleet::client::{HttpResponse, SocTransport, TransportError};
use robodr_fleet::{decommission, enroll, rotate};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The reference SOC behind a lock: one SOC, many unit threads.
#[derive(Clone)]
struct Shared(Arc<Mutex<Soc>>);

impl SocTransport for Shared {
    fn send(
        &mut self,
        method: &str,
        target: &str,
        headers: Vec<(&'static str, String)>,
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let h: Vec<(String, String)> = headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let r = self.0.lock().unwrap().handle(method, target, &h, body);
        Ok(HttpResponse {
            status: r.status,
            retry_after: None,
            body: r.body,
        })
    }

    fn base_path(&self) -> String {
        BASE.into()
    }
}

fn env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// One unit's whole lifecycle; per-step durations.
fn lifecycle(i: usize, soc: &Shared, token: &str) -> Result<[Duration; 5], String> {
    let robot = format!("ugv-{i:04}");
    let u = Unit::new_robot(&format!("cap-{i}"), &robot);
    let ctx = u.ctx();
    let mut t = soc.clone();
    let mut d = [Duration::ZERO; 5];
    let mut timed = |k: usize, f: &mut dyn FnMut() -> Result<(), String>| {
        let t0 = Instant::now();
        let r = f();
        d[k] = t0.elapsed();
        r.map_err(|e| format!("{robot} step {k}: {e}"))
    };
    timed(0, &mut || {
        enroll::prepare(&ctx, token, &Default::default())?;
        enroll::submit(&ctx, &mut t).map(|_| ())
    })?;
    timed(1, &mut || {
        rotate::prepare(&ctx, "uplink", &rotate::no_crash)?;
        rotate::submit_rotate(&ctx, &mut t, "uplink")?;
        rotate::swap(&ctx, "uplink", &rotate::no_crash).map(|_| ())
    })?;
    timed(2, &mut || {
        rotate::submit_retire(&ctx, &mut t, "uplink", &rotate::no_crash).map(|_| ())
    })?;
    // A finding-key rotation that is sent, then cancelled at the SOC.
    timed(3, &mut || {
        rotate::prepare(&ctx, "finding", &rotate::no_crash)?;
        rotate::submit_rotate(&ctx, &mut t, "finding")?;
        rotate::submit_cancel(&ctx, &mut t, "finding")
    })?;
    timed(4, &mut || {
        decommission::prepare(&ctx, "end_of_life")?;
        decommission::submit(&ctx, &mut t).map(|_| ())
    })?;
    // The unit's journal still verifies under its black-box key.
    let kf = robodr_blackbox::KeyFile::load_secret(&u.cfg.blackbox_key).unwrap();
    let v = kf.verifier().unwrap();
    let rep = robodr_blackbox::verify::verify_dir(
        &u.cfg.state_dir.join("journal"),
        v.as_ref(),
        &Default::default(),
    )
    .map_err(|e| format!("{robot}: journal: {e}"))?;
    if !rep.is_intact() {
        return Err(format!("{robot}: journal not intact: {:?}", rep.findings));
    }
    Ok(d)
}

fn pct(v: &mut [Duration], p: f64) -> u128 {
    v.sort_unstable();
    let i = ((v.len().saturating_sub(1)) as f64 * p) as usize;
    v.get(i).map_or(0, Duration::as_millis)
}

#[test]
fn fleet_of_units_enrolls_rotates_and_decommissions_concurrently() {
    let units = env("ROBODR_FLEET_SIM_UNITS", 8).clamp(1, 5000);
    let threads = env("ROBODR_FLEET_SIM_THREADS", 4).clamp(1, 256);
    let mut soc = Soc::new(soc_key(), approval_key(), WORKSPACE, T0);
    // Bulk token issue: one per unit.
    let tokens: Vec<String> = (0..units)
        .map(|i| {
            let mut n = [0u8; 32];
            n[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            soc.issue_token(
                &format!("tok-{i:04}"),
                &format!("ugv-{i:04}"),
                Some(SITE),
                3_600_000,
                n,
            )
        })
        .collect();
    let soc = Shared(Arc::new(Mutex::new(soc)));
    let next = Arc::new(AtomicUsize::new(0));
    let tokens = Arc::new(tokens);
    let started = Instant::now();
    let results: Vec<Result<[Duration; 5], String>> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|_| {
                let (soc, next, tokens) = (soc.clone(), next.clone(), tokens.clone());
                s.spawn(move || {
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::SeqCst);
                        if i >= units {
                            return out;
                        }
                        out.push(lifecycle(i, &soc, &tokens[i]));
                    }
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    let wall = started.elapsed();
    let failures: Vec<&String> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    assert!(
        failures.is_empty(),
        "{} units failed: {failures:?}",
        failures.len()
    );

    let g = soc.0.lock().unwrap();
    assert_eq!(
        g.tokens.values().filter(|t| t.consumed.is_some()).count(),
        units
    );
    assert_eq!(g.decommissions.len(), units);
    // 3 keys per enrollment, 1 per uplink rotation, 1 per cancelled finding
    // rotation: all distinct, none active.
    assert_eq!(g.keys.len(), units * 5);
    let fprs: std::collections::BTreeSet<&str> =
        g.keys.values().map(|k| k.fingerprint.as_str()).collect();
    assert_eq!(fprs.len(), units * 5, "a key registered twice");
    assert!(g.keys.values().all(|k| k.retired_at.is_some()));
    assert_eq!(g.rotations.len(), units * 2);
    assert!(g.rotations.values().all(|r| !r.open()));

    let names = ["enroll", "rotate", "retire", "cancel", "decommission"];
    for (k, name) in names.iter().enumerate() {
        let mut v: Vec<Duration> = results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|d| d[k])
            .collect();
        println!(
            "{name:<13} p50 {:>6} ms  p95 {:>6} ms  max {:>6} ms",
            pct(&mut v, 0.50),
            pct(&mut v, 0.95),
            pct(&mut v, 1.0)
        );
    }
    println!(
        "{units} units, {threads} threads: {} ms wall",
        wall.as_millis()
    );
}
