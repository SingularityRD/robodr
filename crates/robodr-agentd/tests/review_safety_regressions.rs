//! Regression tests for the security review of the live safety-state feed
//! (`safety.rs`), the participant binding it relies on and the correlation
//! engine as wired into agentd. Each test is the review's PoC
//! (`review_safety_poc.rs`) turned around: it asserts the **fixed**
//! behaviour.
//!
//! Synthetic RTPS + CDR only (same builders as `safety_feed.rs`).

mod common;

#[path = "../../robodr-cdr/tests/common/mod.rs"]
mod cdrenc;

use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::pcap::*;
use common::*;
use robodr_agentd::safety::{rules, FeedFinding, SafetyFeed, SafetyFeedSection, SafetyReport};
use robodr_correlate::{Correlator, EntityKind, Signal};
use robodr_events::profile::Profile;
use robodr_events::Severity;
use robodr_responder::SafetyState as S;
use robodr_ros2_pipeline::{Datagram, Pipeline, PipelineOptions};

const ESTOP_W: [u8; 4] = [0, 0, 0x20, 0x03];
const MODE_W: [u8; 4] = [0, 0, 0x21, 0x03];
const BOOL: &str = "std_msgs::msg::dds_::Bool_";
const U8: &str = "std_msgs::msg::dds_::UInt8_";

/// A second, *profiled* participant on the robot (e.g. a perception node),
/// with its own legitimate IP.
const NAV: [u8; 12] = [0xbb; 12];
const NAV_HEX: &str = "bbbbbbbbbbbbbbbbbbbbbbbb";
const NAV_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 20);

fn bool_cdr(v: u8) -> Vec<u8> {
    vec![0, 1, 0, 0, v, 0, 0, 0]
}

fn u8_cdr(v: u8) -> Vec<u8> {
    vec![0, 1, 0, 0, v, 0, 0, 0]
}

fn odom(lin: [f64; 3], ang: [f64; 3]) -> Vec<u8> {
    cdrenc::odometry(
        robodr_cdr::Representation::CdrLe,
        &cdrenc::OdomSpec {
            frame: b"odom",
            child: b"base_link",
            position: [0.0; 3],
            orientation: [0.0, 0.0, 0.0, 1.0],
            pose_cov: [0.0; 36],
            lin,
            ang,
            twist_cov: [0.0; 36],
        },
    )
}

fn profile() -> Profile {
    let mut p = robot_profile(false);
    p.participants.insert(NAV_HEX.into());
    for t in ["/estop", "/robot_mode"] {
        p.writer_topics.insert(t.into());
    }
    p
}

struct Bus {
    pipeline: Pipeline,
    feed: SafetyFeed,
}

impl Bus {
    /// No discovery is sent: the caller decides what the bus has seen.
    fn bare(feed: serde_json::Value) -> Self {
        Self::with_options(feed, PipelineOptions::default())
    }

    fn with_options(feed: serde_json::Value, opts: PipelineOptions) -> Self {
        let p = profile();
        let sec: SafetyFeedSection = serde_json::from_value(feed).unwrap();
        let (spec, _) = sec.resolve(&p).unwrap();
        Bus {
            pipeline: Pipeline::new(p, opts),
            feed: SafetyFeed::new(spec),
        }
    }

    fn raw(&mut self, ip: Ipv4Addr, payload: Vec<u8>, now: u64) -> Vec<FeedFinding> {
        let d = Datagram::new(payload, ip.to_string());
        self.pipeline.process_datagram_with_motion(&d, 0);
        self.feed
            .observe_datagram(&d, self.pipeline.profile(), self.pipeline.binding(), now)
    }

    fn state(&mut self, now: u64) -> S {
        self.feed.evaluate(now);
        self.feed.state()
    }
}

fn sample(prefix: [u8; 12], writer: [u8; 4], sn: u32, payload: &[u8]) -> Vec<u8> {
    datagram(prefix, &[user_data(writer, [0; 4], sn, payload, true)])
}

fn estop_feed(writers: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "stale_after_ms": 1000,
        "topics": [
            {"topic": "/estop", "type": "std_msgs/msg/Bool",
             "values": {"true": "estop_active", "false": "none"}, "writers": writers},
            {"topic": "/robot_mode", "type": "std_msgs/msg/UInt8", "values": {"0": "idle"},
             "writers": [LEGIT_HEX]}
        ]
    })
}

/// Legit discovery and an engaged e-stop + idle mode, at t = 0.
fn engaged(b: &mut Bus) {
    let disc = datagram(
        LEGIT,
        &[
            spdp_sub(LEGIT, &[ROBOT_IP]),
            sedp_writer_sub(LEGIT, ESTOP_W, "rt/estop", BOOL),
            sedp_writer_sub(LEGIT, MODE_W, "rt/robot_mode", U8),
        ],
    );
    b.raw(ROBOT_IP, disc, 0);
    b.raw(ROBOT_IP, sample(LEGIT, ESTOP_W, 1, &bool_cdr(1)), 0);
    b.raw(ROBOT_IP, sample(LEGIT, MODE_W, 1, &u8_cdr(0)), 0);
    assert_eq!(b.state(0), S::EStopActive);
}

/// NAV announces 8 /estop writers from its own bound IP and publishes
/// "false" on each. Findings.
fn nav_flood(b: &mut Bus) -> Vec<FeedFinding> {
    let mut subs = vec![spdp_sub(NAV, &[NAV_IP])];
    for i in 0..8u8 {
        subs.push(sedp_writer_sub(
            NAV,
            [0, 0, 0x40 + i, 0x03],
            "rt/estop",
            BOOL,
        ));
    }
    b.raw(NAV_IP, datagram(NAV, &subs), 10);
    let mut out = Vec::new();
    for i in 0..8u8 {
        out.extend(b.raw(
            NAV_IP,
            sample(NAV, [0, 0, 0x40 + i, 0x03], 1, &bool_cdr(0)),
            10,
        ));
    }
    out
}

/// F1 (allowlist): a profiled participant that is not a commissioned
/// writer of /estop is not trusted on it, so it cannot touch the e-stop
/// reading at all.
#[test]
fn f1_uncommissioned_profiled_writer_is_not_trusted() {
    let mut b = Bus::bare(estop_feed(&[LEGIT_HEX]));
    engaged(&mut b);
    let f = nav_flood(&mut b);
    assert_eq!(f.len(), 8, "one finding per writer: {f:?}");
    assert!(f
        .iter()
        .all(|f| f.deviation.rule_str() == rules::UNTRUSTED_SOURCE
            && f.deviation.detail.contains("allowlist")));
    assert_eq!(b.feed.stats().untrusted, 8);
    let st = b.feed.status(10);
    let estop = st.sources.iter().find(|s| s.name == "/estop").unwrap();
    assert_eq!(estop.writers, 1);
    assert_eq!(b.state(10), S::EStopActive, "the e-stop stays engaged");
}

/// F1 (eviction): even when the other participant *is* commissioned, an
/// overflow of fresh writers never evicts the more conservative fresh
/// e-stop reading; the overflow is reported and reads at least unknown.
#[test]
fn f1_writer_overflow_never_drops_a_fresh_estop() {
    let mut b = Bus::bare(estop_feed(&[LEGIT_HEX, NAV_HEX]));
    engaged(&mut b);
    let f = nav_flood(&mut b);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].deviation.rule_str(), rules::WRITER_OVERFLOW);
    assert_eq!(f[0].deviation.severity, Severity::High);
    assert_eq!(f[0].src_ip, NAV_IP.to_string());
    let st = b.feed.status(10);
    let estop = st.sources.iter().find(|s| s.name == "/estop").unwrap();
    assert_eq!(estop.writers, 8);
    assert!(estop.overflow);
    assert_eq!(b.state(10), S::EStopActive, "e-stop engaged and graded so");
    // E-stop released by its real writer while the overflow is fresh: at
    // least unknown, never idle.
    b.raw(ROBOT_IP, sample(LEGIT, ESTOP_W, 2, &bool_cdr(0)), 20);
    b.raw(ROBOT_IP, sample(LEGIT, MODE_W, 2, &u8_cdr(0)), 20);
    assert_eq!(b.state(20), S::Unknown);
    // Once the overflow and the flood are stale, the real readings rule.
    b.raw(ROBOT_IP, sample(LEGIT, ESTOP_W, 3, &bool_cdr(0)), 1100);
    b.raw(ROBOT_IP, sample(LEGIT, MODE_W, 3, &u8_cdr(0)), 1100);
    assert_eq!(b.state(1100), S::Idle);
}

/// F2: a profiled participant whose SPDP has not been seen has no binding;
/// a writer under its prefix (from any IP) is no longer trusted.
#[test]
fn f2_unbound_profiled_prefix_is_not_trusted() {
    let mut b = Bus::bare(serde_json::json!({
        "topics": [
            {"topic": "/robot_mode", "type": "std_msgs/msg/UInt8", "values": {"0": "idle"},
             "writers": [LEGIT_HEX]}
        ]
    }));
    let disc = datagram(
        LEGIT,
        &[sedp_writer_sub(LEGIT, MODE_W, "rt/robot_mode", U8)],
    );
    b.raw(ROGUE_IP, disc, 0);
    let f = b.raw(ROGUE_IP, sample(LEGIT, MODE_W, 1, &u8_cdr(0)), 0);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].deviation.rule_str(), rules::UNTRUSTED_SOURCE);
    assert!(f[0].deviation.detail.contains("no binding"), "{f:?}");
    assert_eq!(b.feed.stats().untrusted, 1);
    assert_eq!(b.state(0), S::Unknown, "spoofed idle refused");
    // The same writer from the robot's IP is trusted once its SPDP is seen.
    b.raw(
        ROBOT_IP,
        datagram(LEGIT, &[spdp_sub(LEGIT, &[ROBOT_IP])]),
        1,
    );
    assert!(b
        .raw(ROBOT_IP, sample(LEGIT, MODE_W, 2, &u8_cdr(0)), 1)
        .is_empty());
    assert_eq!(b.state(1), S::Idle);
    // A source IP that does not parse is untrusted too.
    let d = Datagram::new(
        sample(LEGIT, MODE_W, 3, &u8_cdr(0)),
        "not-an-ip".to_string(),
    );
    let f = b
        .feed
        .observe_datagram(&d, b.pipeline.profile(), b.pipeline.binding(), 2);
    assert!(
        f[0].deviation.detail.contains("could not be parsed"),
        "{f:?}"
    );
}

/// F2b: the attacker's SPDP for the profiled prefix arrives first, the real
/// one second. The prefix is contested (Critical in the pipeline) and
/// neither IP is trusted for safety until the operator pins it.
#[test]
fn f2b_first_come_spdp_no_longer_keeps_rogue_trusted() {
    let feed = serde_json::json!({
        "topics": [
            {"topic": "/robot_mode", "type": "std_msgs/msg/UInt8", "values": {"0": "idle"},
             "writers": [LEGIT_HEX]}
        ]
    });
    let mut b = Bus::bare(feed.clone());
    let fake = datagram(
        LEGIT,
        &[
            spdp_sub(LEGIT, &[ROGUE_IP]),
            sedp_writer_sub(LEGIT, MODE_W, "rt/robot_mode", U8),
        ],
    );
    b.raw(ROGUE_IP, fake, 0);
    let real = Datagram::new(
        datagram(LEGIT, &[spdp_sub(LEGIT, &[ROBOT_IP])]),
        ROBOT_IP.to_string(),
    );
    let out = b.pipeline.process_datagram_with_motion(&real, 0);
    let contested: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.deviation.rule_str() == "robot.ros2.participant_source_mismatch")
        .collect();
    assert_eq!(contested.len(), 1, "{:?}", out.findings);
    assert_eq!(contested[0].deviation.severity, Severity::Critical);
    assert!(b.pipeline.binding().is_contested(&LEGIT));
    // The rogue's sample: untrusted.
    let f = b.raw(ROGUE_IP, sample(LEGIT, MODE_W, 1, &u8_cdr(0)), 2);
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].deviation.detail.contains("contested"), "{f:?}");
    assert_eq!(b.state(2), S::Unknown);
    // The real participant's sample: untrusted too (cannot tell them apart).
    b.raw(ROBOT_IP, sample(LEGIT, MODE_W, 2, &u8_cdr(0)), 3);
    assert_eq!(b.state(3), S::Unknown);

    // Operator pins the prefix: the real one is trusted, the rogue is not.
    let mut opts = PipelineOptions::default();
    opts.binding
        .participant_ips
        .insert(LEGIT, vec![ROBOT_IP.into()]);
    let mut b = Bus::with_options(feed, opts);
    let fake = datagram(
        LEGIT,
        &[
            spdp_sub(LEGIT, &[ROGUE_IP]),
            sedp_writer_sub(LEGIT, MODE_W, "rt/robot_mode", U8),
        ],
    );
    b.raw(ROGUE_IP, fake, 0);
    b.raw(
        ROBOT_IP,
        datagram(LEGIT, &[spdp_sub(LEGIT, &[ROBOT_IP])]),
        1,
    );
    assert!(!b.pipeline.binding().is_contested(&LEGIT));
    let f = b.raw(ROGUE_IP, sample(LEGIT, MODE_W, 1, &u8_cdr(0)), 2);
    assert!(f[0].deviation.detail.contains("not bound"), "{f:?}");
    assert_eq!(b.state(2), S::Unknown);
    assert!(b
        .raw(ROBOT_IP, sample(LEGIT, MODE_W, 2, &u8_cdr(0)), 3)
        .is_empty());
    assert_eq!(b.state(3), S::Idle);
}

/// F3: socket connections are separate writers; a fresh e-stop from one
/// gateway is never overwritten by idle from the other.
#[test]
fn f3_socket_connections_combine_most_conservative() {
    let sec: SafetyFeedSection = serde_json::from_value(serde_json::json!({
        "socket": {"path": "/run/robodr-agentd/safety.sock", "stale_after_ms": 500}
    }))
    .unwrap();
    let (spec, _) = sec.resolve(&Profile::default()).unwrap();
    assert_eq!(spec.socket.as_ref().unwrap().max_connections, 2);
    let mut f = SafetyFeed::new(spec);
    f.observe_report_from(
        1,
        SafetyReport {
            state: S::EStopActive,
        },
        0,
    );
    f.observe_report_from(2, SafetyReport { state: S::Idle }, 1);
    f.evaluate(1);
    assert_eq!(f.state(), S::EStopActive, "fresh e-stop claim kept");
    // Gateway A keeps saying estop, B idle: still estop.
    f.observe_report_from(
        1,
        SafetyReport {
            state: S::EStopActive,
        },
        400,
    );
    f.observe_report_from(2, SafetyReport { state: S::Idle }, 450);
    f.evaluate(450);
    assert_eq!(f.state(), S::EStopActive);
    // A releases.
    f.observe_report_from(1, SafetyReport { state: S::Idle }, 460);
    f.evaluate(460);
    assert_eq!(f.state(), S::Idle);
    // Every connection silent: unknown.
    f.evaluate(2000);
    assert_eq!(f.state(), S::Unknown);
}

/// F4: without an explicit angular threshold, spinning in place at 2 rad/s
/// is moving, not idle.
#[test]
fn f4_spin_in_place_is_moving_by_default() {
    let mut b = Bus::bare(serde_json::json!({
        "topics": [
            {"topic": "/odom", "type": "nav_msgs/msg/Odometry",
             "motion": {"moving_above": 0.05, "fast_above": 1.0},
             "writers": [LEGIT_HEX]}
        ]
    }));
    let disc = datagram(
        LEGIT,
        &[
            spdp_sub(LEGIT, &[ROBOT_IP]),
            sedp_writer_sub(LEGIT, ODOM_WRITER, "rt/odom", ODOM),
        ],
    );
    b.raw(ROBOT_IP, disc, 0);
    b.raw(
        ROBOT_IP,
        sample(LEGIT, ODOM_WRITER, 1, &odom([0.0; 3], [0.0, 0.0, 2.0])),
        0,
    );
    assert_eq!(b.state(0), S::MovingSlow);
    // Slow rotation below the default 0.1 rad/s is idle.
    b.raw(
        ROBOT_IP,
        sample(LEGIT, ODOM_WRITER, 2, &odom([0.0; 3], [0.0, 0.0, 0.01])),
        1,
    );
    assert_eq!(b.state(1), S::Idle);
}

/// F5 as in the PoC (same-tier flood against an unknown IP): eviction is
/// no longer silent. With A's IP known (bound to a profiled participant,
/// as agentd registers it), the flood cannot evict it and the sequence
/// fires.
#[test]
fn f5_flood_eviction_is_reported_or_prevented() {
    let a = "192.168.50.66";
    let sig = |t: u64, rule: &str, ip: &str| {
        Signal::new(t, rule, Severity::High).with_entity(EntityKind::Ip, ip)
    };
    let flood = |c: &mut Correlator| {
        for i in 0..256u32 {
            let ip = format!("10.{}.{}.1", i / 256, i % 256);
            c.observe(&sig(2, "robot.ros2.endpoint_source_mismatch", &ip));
        }
    };
    let rule = "robot.correlate.spoofed_motion_source";
    // Unknown A: evicted, but reported per rule with the lost evidence.
    let mut c = Correlator::with_defaults();
    c.observe(&sig(1, "robot.ros2.participant_source_mismatch", a));
    flood(&mut c);
    assert!(!c.has_group(rule, a));
    assert_eq!(c.evictions_of(rule), 1);
    let n = c.take_notices();
    assert_eq!(n.len(), 1);
    assert_eq!(n[0].rule, robodr_correlate::EVICTED_RULE_ID);
    assert_eq!(n[0].mode, robodr_events::Mode::Observe);
    assert!(n[0].detail.contains(rule));
    // Known A: kept, the sequence fires.
    let mut c = Correlator::with_defaults();
    c.set_known_entities(EntityKind::Ip, [a]);
    c.observe(&sig(1, "robot.ros2.participant_source_mismatch", a));
    flood(&mut c);
    assert!(c.has_group(rule, a));
    let f = c.observe(&sig(3, "robot.ros2.unauthorized_motion_writer", a));
    assert!(f.iter().any(|f| f.rule == rule), "{f:?}");
}

#[test]
fn verified_ok_socket_duplicate_key_refused() {
    let r: Result<SafetyReport, _> =
        serde_json::from_str(r#"{"state":"estop_active","state":"idle"}"#);
    assert!(r.is_err());
}

/// F3 end to end: two gateway connections to the daemon's safety socket;
/// the second one's idle does not override the first one's e-stop.
#[test]
fn f3_two_gateways_through_the_daemon() {
    let s = setup("rsr-two-gw", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let safety = s.dir.join("safety.sock");
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": events}]),
        serde_json::json!({}),
    );
    cfg["context"] = serde_json::json!({});
    cfg["safety_feed"] = serde_json::json!({
        "socket": {"path": safety, "stale_after_ms": 60000}
    });
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    let mut a = wait_for(5, "safety socket", || UnixStream::connect(&safety).ok());
    writeln!(a, "{{\"state\":\"estop_active\"}}").unwrap();
    a.flush().unwrap();
    wait_for(5, "estop applied", || {
        let st = status(&s.spool)?;
        (st["safety_state"] == "estop_active").then_some(())
    });
    let mut b = UnixStream::connect(&safety).unwrap();
    writeln!(b, "{{\"state\":\"idle\"}}").unwrap();
    b.flush().unwrap();
    wait_for(5, "second report applied", || {
        let st = status(&s.spool)?;
        (st["safety_feed"]["stats"]["socket_reports"].as_u64()? >= 2).then_some(())
    });
    let st = status(&s.spool).unwrap();
    assert_eq!(st["safety_state"], "estop_active", "{st}");
    assert_eq!(st["safety_feed"]["sources"][0]["writers"], 2, "{st}");
    // Gateway A releases: now idle.
    writeln!(a, "{{\"state\":\"idle\"}}").unwrap();
    a.flush().unwrap();
    wait_for(5, "released", || {
        let st = status(&s.spool)?;
        (st["safety_state"] == "idle").then_some(())
    });
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    res.unwrap_or_else(|e| panic!("{e}\n{log}"));
}
