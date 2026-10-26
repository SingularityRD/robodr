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
