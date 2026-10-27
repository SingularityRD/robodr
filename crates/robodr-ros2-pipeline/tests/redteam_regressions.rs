//! Regressions of the S11-lite red team (`tools/e2e/REDTEAM.md`).
//!
//! F3 (row R6e): a valid SOC `quarantine_node` of the rogue participant was
//! refused by the executor with `locators_required`, both while the rogue
//! was live and after it left: agentd hands the executor the locators the
//! binding table gives for the rogue's GUID prefix, and the table gave
//! none. Replayed here on the lab capture the red team used
//! (`fastrtps_gz_rogue_cmd_vel.pcap`), with the rogue's address inside its
//! identity's addresses so it raises `identity_instances_exceeded`, as in
//! the red team.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use robodr_capture::{CaptureFile, RtpsPortMap};
use robodr_commission::{LearnConfig, Learner, PcapSource};
use robodr_ros2_pipeline::{
    rules, BindingTable, CaptureDatagramSource, DatagramSource, Finding, Ingress, Pipeline,
    PipelineOptions,
};
use robodr_rtps::GuidPrefix;

const ROBOT_IP: &str = "10.77.10.10";
const ROGUE_IP: &str = "10.77.10.66";
/// The rogue `/debug_tool` of `fastrtps_gz_rogue_cmd_vel.pcap` (the
/// capture is pinned by its SHA-256 in the fixture README).
const ROGUE: GuidPrefix = [
    0x01, 0x0f, 0xf3, 0xa0, 0x01, 0x00, 0xc3, 0x85, 0x00, 0x00, 0x00, 0x00,
];
/// The robot's `gz_bridge` participant in that capture (it holds the
/// identity the rogue matches; it publishes `/odom`, subscribes `/cmd_vel`).
const ROBOT: GuidPrefix = [
    0x01, 0x0f, 0xbe, 0x18, 0x1b, 0x00, 0xda, 0xa5, 0x00, 0x00, 0x00, 0x00,
];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/captures/ros2-jazzy")
        .join(name)
}

/// The locators agentd hands the executor for a quarantine of `prefix`.
fn quarantine_locators(b: &BindingTable, prefix: &GuidPrefix, now: Instant) -> Vec<SocketAddr> {
    b.quarantine_locators(prefix, now)
}

fn sa(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), port)
}

struct Run {
    p: Pipeline,
    findings: Vec<Finding>,
    /// Pipeline time of the last packet.
    end: Instant,
    /// The robot's SPDP datagram (template of the GUID spray).
    robot_spdp: Vec<u8>,
    /// The rogue's quarantine locators while it was live.
    live: Vec<SocketAddr>,
}

/// Learn the profile from the baseline run, put the rogue's address into
/// every identity's addresses, then replay the rogue run on its packet
/// timeline.
fn replay_rogue_run() -> Run {
    let mut l = Learner::new(LearnConfig {
        model: "lab-ugv".into(),
        ..LearnConfig::default()
    })
    .unwrap();
    l.ingest(&mut PcapSource::open(&fixture("fastrtps_gz_baseline.pcap")).unwrap())
        .unwrap();
    let mut profile = l.finish().profile;
    for id in profile.participant_identities.values_mut() {
        id.ips.insert(ROGUE_IP.into());
    }
    let bytes = std::fs::read(fixture("fastrtps_gz_rogue_cmd_vel.pcap")).unwrap();
    let mut src = CaptureDatagramSource::new(
        CaptureFile::new(&bytes[..]).unwrap(),
        robodr_ros2_pipeline::source::rtps_filter(RtpsPortMap::ros2_default()),
    );
    let mut p = Pipeline::new(profile, PipelineOptions::default());
    let t0 = Instant::now();
    let mut c0 = None;
    let mut end = t0;
    let mut findings = p.status_findings();
    let mut robot_spdp = None;
    let mut live = Vec::new();
    while let Some(d) = src.recv().unwrap() {
        let at = d.captured_at.unwrap();
        let now = t0 + (at - *c0.get_or_insert(at));
        end = now;
        if robot_spdp.is_none() && d.src_ip == ROBOT_IP && d.payload.get(8..20) == Some(&ROBOT[..])
        {
            let has_spdp = d.payload.windows(4).any(|w| w == [0x00, 0x01, 0x00, 0xc2]);
            if has_spdp {
                robot_spdp = Some(d.payload.clone());
            }
        }
        findings.extend(p.process_from_at(&d.payload, &d.src_ip, d.ingress, now));
        if live.is_empty() {
            live = quarantine_locators(p.binding(), &ROGUE, now);
        }
    }
    Run {
        p,
        findings,
        end,
        robot_spdp: robot_spdp.expect("robot SPDP in the capture"),
        live,
    }
}

fn has(f: &[Finding], rule: &str, ip: &str) -> bool {
    f.iter()
        .any(|x| x.deviation.rule_str() == rule && x.src_ip == ip)
}

/// The red team's scenario: the rogue matched its identity (whose single
/// instance the robot holds), and later left (it disposed itself).
#[test]
fn a_departed_rogue_keeps_its_own_locators_for_a_quarantine() {
    let r = replay_rogue_run();
    let b = r.p.binding();
    assert!(has(
        &r.findings,
        rules::IDENTITY_INSTANCES_EXCEEDED,
        ROGUE_IP
    ));
    assert!(has(
        &r.findings,
        "robot.ros2.unauthorized_motion_writer",
        ROGUE_IP
    ));
    // Not the contested-prefix case: nobody else claimed its prefix.
    assert!(!b.is_contested(&ROGUE));
    assert!(b.contested().next().is_none());
    // While live, its own announced locators.
    let rogue_locs = vec![sa(ROGUE_IP, 7410), sa(ROGUE_IP, 7411)];
    assert_eq!(r.live, rogue_locs);
    // It left (SPDP dispose): no live binding any more...
    assert!(!b.is_bound(&ROGUE));
    // ...but a SOC's quarantine order, minutes later, still gets the
    // locators last observed for that prefix.
    for later in [
        Duration::ZERO,
        Duration::from_secs(300),
        Duration::from_secs(3600),
    ] {
        assert_eq!(
            quarantine_locators(b, &ROGUE, r.end + later),
            rogue_locs,
            "{later:?} after the capture"
        );
    }
    // Never the robot's: they are not the rogue's.
    assert!(rogue_locs
        .iter()
        .all(|l| l.ip() != ROBOT_IP.parse::<IpAddr>().unwrap()));
}

/// The red team ran the GUID spray (R2) between the rogue run and the
/// quarantine: 3000 random prefixes evicted the rogue from the binding
/// table. The rogue's locators survive it, and a sprayed prefix announcing
/// the robot's own locators never gets them.
#[test]
fn a_guid_spray_neither_evicts_the_rogue_nor_lends_the_robot_locators() {
    let mut r = replay_rogue_run();
    let robot_locs = quarantine_locators(r.p.binding(), &ROBOT, r.end);
    assert!(!robot_locs.is_empty(), "robot is live at the end");
    let mut now = r.end;
    let mut sprayed = Vec::new();
    for i in 0..3000u32 {
        let mut g = ROBOT;
        g[4..8].copy_from_slice(&i.to_be_bytes());
        g[8] = 0x5a;
        let d = replace_all(&r.robot_spdp, &ROBOT, &g);
        now += Duration::from_millis(1);
        r.p.process_from_at(&d, ROBOT_IP, Ingress::Unknown, now);
        sprayed.push(g);
    }
    let b = r.p.binding();
    assert!(b.stats().evicted > 0, "{:?}", b.stats());
    assert_eq!(
        quarantine_locators(b, &ROGUE, now),
        vec![sa(ROGUE_IP, 7410), sa(ROGUE_IP, 7411)]
    );
    // A sprayed prefix announced the robot's locators: a quarantine of it
    // must not cut the robot (no locators: the executor refuses).
    for g in [sprayed[0], sprayed[2999]] {
        let l = quarantine_locators(b, &g, now);
        assert!(l.iter().all(|x| !robot_locs.contains(x)), "{l:?}");
    }
    // A quarantine of the robot itself gets at most its own locators.
    let l = quarantine_locators(b, &ROBOT, now);
    assert!(l.iter().all(|x| robot_locs.contains(x)), "{l:?}");
}

fn replace_all(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = hay.to_vec();
    let mut i = 0;
    while i + from.len() <= out.len() {
        if &out[i..i + from.len()] == from {
            out[i..i + from.len()].copy_from_slice(to);
            i += from.len();
        } else {
            i += 1;
        }
    }
    out
}
