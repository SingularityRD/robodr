//! W2-4 review PoCs against robodr_blackbox::admission (public API, real time).
use robodr_blackbox::admission::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// agentd control-plane defaults: 4 slots, 2/source, 3/subnet, 100/s.
fn agentd_default() -> AdmissionConfig {
    let mut c = AdmissionConfig::simple(4, 2);
    c.max_per_subnet = 3;
    c.rate_per_s = 100;
    c
}

/// F1: once the server answered, the floor is cumulative from accept: a
/// 640 B ClientHello buys the whole 5 s READ_DEADLINE, 4 KiB buys 33 s.
#[test]
fn f1_floor_is_bypassed_by_one_complete_hello() {
    let t0 = Instant::now();
    for (hello, want_ms) in [(220u64, 2718u64), (640, 6000), (1400, 11937), (4096, 33000)] {
        let p = Progress::new(ProgressPolicy::default(), t0);
        p.on_read(hello as usize);
        p.on_write();
        let d = p.deadline().unwrap() - t0;
        println!("ClientHello {hello} B -> progress deadline {d:?} after accept (no further byte)");
        assert!(d >= Duration::from_millis(want_ms - 1));
    }
}

/// F2: unlisted SOC with an answered handshake (ClientHello 517 B, waiting
/// one RTT for its certificate flight) is evicted by attacker churn of
/// padded ClientHellos from two other /24s within the agentd rate limit.
#[test]
fn f2_padded_hello_churn_evicts_answered_soc() {
    let mut evicted_runs = 0;
    for rtt_ms in [5u64, 20, 50] {
        let a = Admission::new(agentd_default());
        let mut held = Vec::new();
        // Fill the pool with answered padded attackers.
        let mut n = 0u32;
        let mut attack = |held: &mut Vec<Ticket>| {
            n += 1;
            let ip = v4(10, 1 + (n % 2) as u8, (n / 256 % 256) as u8, (n % 250) as u8 + 1);
            if let Ok(t) = a.admit_seen(ip, None, 2048) {
                t.progress().on_read(4096);
                t.progress().on_write();
                held.push(t);
            }
        };
        for _ in 0..4 {
            attack(&mut held);
        }
        let soc = a.admit_seen(v4(192, 168, 5, 10), None, 517).unwrap();
        soc.progress().on_read(517);
        soc.progress().on_write(); // ServerHello..Finished sent; waiting 1 RTT
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_millis(rtt_ms) && !soc.evicted() {
            sleep(Duration::from_millis(10)); // 100 conn/s: the global rate
            attack(&mut held);
            held.retain(|t| !t.evicted());
        }
        println!("rtt {rtt_ms} ms: soc evicted={} after {:?}", soc.evicted(), t0.elapsed());
        if soc.evicted() {
            evicted_runs += 1;
        }
    }
    assert!(evicted_runs >= 2);
}

/// F2b: an unanswered SOC accepted before its ClientHello was queued
/// (seen = 0) is the global worst: the next attacker newcomer evicts it.
#[test]
fn f2b_unqueued_soc_is_first_victim() {
    let a = Admission::new(agentd_default());
    let mut held = Vec::new();
    for i in 0..3u8 {
        let t = a.admit_seen(v4(10, 1 + i % 2, 0, i + 1), None, 2048).unwrap();
        held.push(t);
    }
    let soc = a.admit_seen(v4(192, 168, 5, 10), None, 0).unwrap();
    held.push(a.admit_seen(v4(10, 3, 0, 1), None, 2048).unwrap());
    println!("soc evicted at once: {}", soc.evicted());
    assert!(soc.evicted());
}

/// F3: the quiet-source exemption makes the global bucket moot for a
/// multi-source (IPv6 /48 or botnet) attacker: admissions scale with sources.
#[test]
fn f3_quiet_exemption_scales_with_sources() {
    let a = Admission::new(agentd_default());
    let mut held = Vec::new();
    let t0 = Instant::now();
    let mut ok = 0u64;
    let mut tried = 0u64;
    // 2000 /64s, each connecting once per ~1.05 s, for ~3.2 s.
    for round in 0..3u16 {
        for i in 0..2000u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x77, i, 0, 0, 0, 1));
            tried += 1;
            if let Ok(t) = a.admit(ip, None) {
                ok += 1;
                held.push(t);
                if held.len() > 64 {
                    held.remove(0);
                }
            }
        }
        let _ = round;
        sleep(Duration::from_millis(1050));
    }
    let el = t0.elapsed().as_secs_f64();
    let st = a.stats();
    println!(
        "{tried} tried, {ok} admitted in {el:.2}s = {:.0}/s vs configured 100/s (burst 200); admitted_quiet {} evicted {}",
        ok as f64 / el,
        st.admitted_quiet,
        st.evicted
    );
    assert!(ok > 5000);
}

/// F4: >MAX_SOURCE_BUCKETS busy sources leave a new (or idle-dropped) SOC
/// source without a bucket of its own: it is never "quiet", and with the
/// global bucket kept empty by one hammering pair it is refused at accept.
#[test]
fn f4_source_map_saturation_refuses_unlisted_soc() {
    let a = Admission::new(agentd_default());
    let soc = v4(192, 168, 5, 10);
    // The SOC connected earlier (it has a bucket), then is idle.
    drop(a.admit(soc, None).unwrap());
    let t0 = Instant::now();
    let mut soc_ok = 0;
    let mut soc_tries = 0;
    let mut next_soc = t0 + Duration::from_millis(1500);
    let mut round = 0u32;
    while t0.elapsed() < Duration::from_secs(8) {
        let r0 = Instant::now();
        // 4200 IPv6 /64s, each once per ~second: admitted as quiet sources.
        for i in 0..4200u32 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, (i >> 16) as u16, i as u16, 0, 0, 0, 1));
            let _ = a.admit(ip, None);
        }
        // Two hammering sources keep the global bucket empty.
        for _ in 0..200 {
            let _ = a.admit(v4(10, 9, 0, 1), None);
            let _ = a.admit(v4(10, 9, 1, 1), None);
        }
        if Instant::now() >= next_soc {
            soc_tries += 1;
            if a.admit(soc, None).is_ok() {
                soc_ok += 1;
            }
            next_soc += Duration::from_secs(2);
        }
        round += 1;
        let el = r0.elapsed();
        if el < Duration::from_millis(1000) {
            sleep(Duration::from_millis(1000) - el);
        }
    }
    let st = a.stats();
    println!("rounds {round}: SOC (1 conn / 2 s) admitted {soc_ok}/{soc_tries}; stats {st:?}");
    assert_eq!(soc_ok, 0);
}
