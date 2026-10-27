//! Regressions of the adversarial review of the red-team fixes (branch
//! `wt/redfix`, findings H1, H2, M5, M6; `tools/e2e/REDTEAM.md`, "Review of
//! the F1 / F3 fixes"). Each test replays the reviewer's proof of concept
//! on the pipeline and asserts the attack no longer works: the locators
//! agentd hands the executor for a quarantine
//! ([`BindingTable::quarantine_locators`]) never include another
//! participant's addresses and cannot be emptied or poisoned by the rogue.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use common::*;
use robodr_ros2_pipeline::{rules, Finding, Ingress, Pipeline, PipelineOptions, Severity};

const LEGIT_IP: Ipv4Addr = ROBOT_IP; // 192.168.50.10, the profiled LEGIT
const DECOY: [u8; 12] = [0xc7; 12];
const OTHER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 67);
const SPRAY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 77);
const AWAY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 50);
const AWAY: [u8; 12] = [0x50; 12];

struct Bus {
    p: Pipeline,
    now: Instant,
}

impl Bus {
    fn new() -> Self {
        Self {
            p: Pipeline::new(robot_profile(true), PipelineOptions::default()),
            now: Instant::now(),
        }
    }

    fn send(&mut self, src: Ipv4Addr, d: &[u8]) -> Vec<Finding> {
        self.now += Duration::from_millis(1);
        self.p
            .process_from_at(d, &src.to_string(), Ingress::Unknown, self.now)
    }

    /// SPDP for `prefix` sent from `src`, announcing unicast locators on
    /// every `ips` (ports 7410 and 7411 each).
    fn spdp(&mut self, src: Ipv4Addr, prefix: [u8; 12], ips: &[Ipv4Addr]) -> Vec<Finding> {
        self.send(src, &datagram(prefix, &[spdp_sub(prefix, ips)]))
    }

    fn writer(&mut self, src: Ipv4Addr, prefix: [u8; 12], topic: &str) -> Vec<Finding> {
        self.send(src, &sedp_datagram(prefix, topic, TWIST))
    }

    fn advance(&mut self, s: u64) {
        self.now += Duration::from_secs(s);
    }

    fn q(&self, prefix: &[u8; 12]) -> Vec<SocketAddr> {
        self.p.binding().quarantine_locators(prefix, self.now)
    }
}

fn at(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(ip.into(), port)
}

fn own(ip: Ipv4Addr) -> Vec<SocketAddr> {
    vec![at(ip, 7410), at(ip, 7411)]
}

fn rules_of(f: &[Finding]) -> Vec<(String, Severity)> {
    f.iter()
        .map(|x| (x.deviation.rule_str().to_string(), x.deviation.severity))
        .collect()
}

/// H1: one SPDP for the profiled prefix after its lease ran out, from a
/// foreign host, used to overwrite its remembered ("protected") locators
/// silently; a decoy announcing the robot's address was then handed it.
#[test]
fn h1_a_foreign_host_never_overwrites_a_profiled_prefixs_locators() {
    let mut b = Bus::new();
    assert!(b.spdp(LEGIT_IP, LEGIT, &[LEGIT_IP]).is_empty());
    b.advance(120); // LEGIT's lease (100 s) ran out
    let f = b.spdp(ROGUE_IP, LEGIT, &[ROGUE_IP]);
    // The re-bind attempt is a finding (it was silent), and the prefix is
    // contested: nobody's source is trusted for it any more.
    assert!(
        f.iter().any(
            |x| x.deviation.rule_str() == rules::PARTICIPANT_SOURCE_MISMATCH
                && x.src_ip == ROGUE_IP.to_string()
                && x.deviation.severity == Severity::Critical
        ),
        "{:?}",
        rules_of(&f)
    );
    assert!(b.p.binding().is_contested(&LEGIT));
    assert!(b.q(&LEGIT).is_empty(), "contested: none");
    // The decoy announcing the robot's address next to its own.
    b.spdp(ROGUE_IP, DECOY, &[ROGUE_IP, LEGIT_IP]);
    let q = b.q(&DECOY);
    assert!(
        q.iter().all(|l| l.ip() != std::net::IpAddr::from(LEGIT_IP)),
        "the robot participant's address handed out: {q:?}"
    );
    assert_eq!(q, own(ROGUE_IP));
    // Long after (lease, retention of the decoy irrelevant): still never.
    b.advance(3600);
    assert!(b
        .q(&DECOY)
        .iter()
        .all(|l| l.ip() != std::net::IpAddr::from(LEGIT_IP)));
}

/// H2a: a decoy prefix announcing the rogue's locators (from its own
/// address) made every locator of the rogue "claimed by another live
/// participant": the set was empty and the executor refused.
#[test]
fn h2a_a_decoy_copying_the_rogues_locators_does_not_empty_its_set() {
    let mut b = Bus::new();
    b.spdp(ROGUE_IP, ROGUE, &[ROGUE_IP]);
    b.writer(ROGUE_IP, ROGUE, "rt/cmd_vel");
    assert_eq!(b.q(&ROGUE), own(ROGUE_IP));
    b.spdp(OTHER_IP, DECOY, &[ROGUE_IP]);
    assert_eq!(b.q(&ROGUE), own(ROGUE_IP), "decoy live");
    // The decoy never gets the rogue's address either (it never sent from
    // there).
    assert!(b.q(&DECOY).is_empty(), "{:?}", b.q(&DECOY));
    // The rogue leaves; the decoy is kept alive.
    b.advance(150);
    b.spdp(OTHER_IP, DECOY, &[ROGUE_IP]);
    assert_eq!(b.q(&ROGUE), own(ROGUE_IP), "rogue gone, decoy refreshed");
}

/// H2b: one bad locator in the rogue's own SPDP (loopback, outside the
/// quarantine scope) used to reach the executor, which refused the whole
/// order. Locators the participant was never seen sending from, and
/// loopback ones, are left out instead.
#[test]
fn h2b_poison_locators_are_left_out_of_the_rogues_set() {
    let mut b = Bus::new();
    let lo = Ipv4Addr::LOCALHOST;
    let far = Ipv4Addr::new(10, 99, 0, 1);
    b.spdp(ROGUE_IP, ROGUE, &[ROGUE_IP, lo, far]);
    assert_eq!(b.q(&ROGUE), own(ROGUE_IP));
}

/// M5: a legitimate unprofiled participant that is briefly away had no
/// protection: the rogue announcing its address got it handed out.
#[test]
fn m5_an_absent_participants_address_is_not_in_a_rogues_set() {
    let mut b = Bus::new();
    b.spdp(AWAY_IP, AWAY, &[AWAY_IP]);
    b.advance(120); // away (restart, sleep): its lease ran out
    b.spdp(ROGUE_IP, ROGUE, &[ROGUE_IP, AWAY_IP]);
    assert_eq!(b.q(&ROGUE), own(ROGUE_IP));
}

/// M6: 1100 *active* prefixes (SPDP plus one SEDP each, about 2 s) evicted
/// the remembered locators of a rogue that had announced a motion writer.
#[test]
fn m6_an_active_spray_does_not_evict_a_rogue_that_raised_a_critical_finding() {
    let mut b = Bus::new();
    b.spdp(ROGUE_IP, ROGUE, &[ROGUE_IP]);
    let f = b.writer(ROGUE_IP, ROGUE, "rt/cmd_vel");
    assert!(
        f.iter()
            .any(|x| x.deviation.severity == Severity::Critical && x.src_ip == ROGUE_IP.to_string()),
        "{:?}",
        rules_of(&f)
    );
    for i in 0..1100u32 {
        let mut g = [0xd2; 12];
        g[8..12].copy_from_slice(&i.to_be_bytes());
        b.spdp(SPRAY_IP, g, &[SPRAY_IP]);
        b.writer(SPRAY_IP, g, "rt/chatter");
    }
    assert_eq!(b.q(&ROGUE), own(ROGUE_IP), "{:?}", b.p.binding().stats());
}

// --- Second review of the red-team fixes (R2-3, R2-4, R2-5) ------------------

fn target(b: &Bus, prefix: &[u8; 12]) -> robodr_ros2_pipeline::QuarantineTarget {
    b.p.binding().quarantine_target(prefix, b.now)
}

/// R2-3 (a): the rogue announces a second prefix from its own address with
/// its own locators (no spoofing). Each prefix used to contest the other's
/// ip:port, so the rogue's quarantine was by GUID prefix only. Two prefixes
/// seen at the same address claiming one ip:port share a host: both get it.
#[test]
fn r2_3a_a_self_decoy_does_not_reduce_the_rogue_to_guid_only() {
    let mut b = Bus::new();
    b.spdp(ROGUE_IP, ROGUE, &[ROGUE_IP]);
    b.writer(ROGUE_IP, ROGUE, "rt/cmd_vel");
    b.spdp(ROGUE_IP, DECOY, &[ROGUE_IP]);
    let t = target(&b, &ROGUE);
    assert_eq!(t.locators, own(ROGUE_IP), "decoy live: {t:?}");
    // Also once the rogue left and only the decoy is kept alive.
    b.advance(150);
    b.spdp(ROGUE_IP, DECOY, &[ROGUE_IP]);
    let t = target(&b, &ROGUE);
    assert_eq!(t.locators, own(ROGUE_IP), "rogue gone, decoy live: {t:?}");
    assert_eq!(b.q(&DECOY), own(ROGUE_IP), "the decoy is the same host");
}

/// R2-3 (c): after the SOC named the rogue, it let its lease run out and
/// re-announced its own prefix from a second address it owns. The fresh
/// re-bind replaced its evidence and rank: the quarantine then cut only the
/// second address, and the rank dropped from SocReferenced to High. A
/// prefix ranked High or above keeps its history and rank (merged).
#[test]
fn r2_3c_a_reannounce_from_a_new_address_keeps_the_named_rogues_history() {
    let mut b = Bus::new();
    b.spdp(ROGUE_IP, ROGUE, &[ROGUE_IP]);
    b.writer(ROGUE_IP, ROGUE, "rt/cmd_vel");
    b.p.note_soc_reference(&ROGUE);
    let rank = |b: &Bus| b.p.binding().locator_rank(&ROGUE);
    assert_eq!(
        rank(&b),
        Some(robodr_ros2_pipeline::binding::Rank::SocReferenced)
    );
    b.advance(120); // its lease (100 s) ran out
    b.spdp(OTHER_IP, ROGUE, &[OTHER_IP]);
    assert_eq!(
        rank(&b),
        Some(robodr_ros2_pipeline::binding::Rank::SocReferenced)
    );
    let q = b.q(&ROGUE);
    for l in own(ROGUE_IP).into_iter().chain(own(OTHER_IP)) {
        assert!(q.contains(&l), "{l} missing: {q:?}");
    }
}

/// R2-4: 1100 prefixes from 10 addresses, each with SPDP and one
/// `rt/cmd_vel` writer (every one ranked Critical), evicted a departed
/// rogue ranked Critical: `known: false`, and the executor refused with
/// `locators_required`. Under global pressure the fullest per-source
/// bucket is evicted first.
#[test]
fn r2_4_a_multi_address_critical_spray_does_not_evict_the_rogue() {
    let mut b = Bus::new();
    b.spdp(ROGUE_IP, ROGUE, &[ROGUE_IP]);
    b.writer(ROGUE_IP, ROGUE, "rt/cmd_vel");
    assert_eq!(
        b.p.binding().locator_rank(&ROGUE),
        Some(robodr_ros2_pipeline::binding::Rank::Critical)
    );
    b.advance(150); // the rogue left
    for i in 0..1100u32 {
        let src = Ipv4Addr::new(10, 70, 0, (i % 10) as u8 + 1);
        let mut g = [0xd3; 12];
        g[8..12].copy_from_slice(&i.to_be_bytes());
        b.spdp(src, g, &[src]);
        b.writer(src, g, "rt/cmd_vel");
    }
    let t = target(&b, &ROGUE);
    assert!(t.known, "{t:?} {:?}", b.p.binding().stats());
    assert_eq!(t.locators, own(ROGUE_IP), "{t:?}");
    // A SOC-named prefix is never evicted for spray entries either.
    b.p.note_soc_reference(&ROGUE);
    for i in 0..2200u32 {
        let src = Ipv4Addr::new(10, 71, (i / 250) as u8, (i % 250) as u8 + 1);
        let mut g = [0xd4; 12];
        g[8..12].copy_from_slice(&i.to_be_bytes());
        b.spdp(src, g, &[src]);
        b.writer(src, g, "rt/cmd_vel");
    }
    assert_eq!(b.q(&ROGUE), own(ROGUE_IP));
}

/// R2-5: the profiled LEGIT is live at 192.168.50.10:7410/7411; another
/// (unprofiled) participant on the robot computer uses 7412/7413. A decoy
/// whose SPDP source is spoofed to the robot computer's address announces
/// 7410, 7412 and 7413: the ports LEGIT does not announce were handed out.
/// Every port of the robot's own computer is protected: since review R3-6
/// that is an address no SPDP can claim (this host's, or pinned to a
/// profiled participant). An address LEGIT was only *learned* at
/// (first-come, possibly an attacker's) is never cut whole, but the
/// decoy's own ports there are handed out.
#[test]
fn r2_5_a_spoofed_decoy_never_gets_any_port_of_the_profiled_host() {
    let decoy = |b: &mut Bus| {
        assert!(b.spdp(LEGIT_IP, LEGIT, &[LEGIT_IP]).is_empty());
        let mut ports = Vec::new();
        for port in [7410u32, 7412, 7413] {
            ports.push(param(0x0032, &locator_v4(LEGIT_IP, port)));
        }
        let mut params = vec![
            param(0x0015, &[2, 3, 0, 0]),
            param(0x0016, &[0x01, 0x0f, 0, 0]),
            param(0x0050, &guid(DECOY, [0, 0, 1, 0xc1])),
        ];
        params.extend(ports);
        let spdp = datagram(DECOY, &[data(ENTITY_SPDP_WRITER, 1, &pl_payload(&params))]);
        b.send(LEGIT_IP, &spdp);
        target(b, &DECOY)
    };
    let with = |binding: robodr_ros2_pipeline::BindingOptions| Bus {
        p: Pipeline::new(
            robot_profile(true),
            PipelineOptions {
                binding,
                ..PipelineOptions::default()
            },
        ),
        now: Instant::now(),
    };
    // This host's address.
    let mut b = with(robodr_ros2_pipeline::BindingOptions {
        local_addresses: vec![LEGIT_IP.into()],
        ..Default::default()
    });
    let t = decoy(&mut b);
    assert!(t.locators.is_empty(), "the robot computer's ports: {t:?}");
    assert_eq!(t.excluded.len(), 3, "{t:?}");
    assert!(t.addresses.is_empty(), "{t:?}");
    // Pinned to the profiled participant.
    let mut b = with(robodr_ros2_pipeline::BindingOptions {
        participant_ips: [(LEGIT, vec![LEGIT_IP.into()])].into_iter().collect(),
        ..Default::default()
    });
    let t = decoy(&mut b);
    assert!(t.locators.is_empty(), "the robot computer's ports: {t:?}");
    assert_eq!(t.excluded.len(), 3, "{t:?}");
    assert!(t.addresses.is_empty(), "{t:?}");
    // Learned only: LEGIT's own port stays out, the address is never cut
    // whole, the decoy's other ports are handed out.
    let mut b = Bus::new();
    let t = decoy(&mut b);
    assert_eq!(t.excluded.len(), 1, "{t:?}");
    assert_eq!(t.locators.len(), 2, "{t:?}");
    assert!(t.addresses.is_empty(), "{t:?}");
    assert_eq!(t.excluded_addresses.len(), 1, "{t:?}");
}
