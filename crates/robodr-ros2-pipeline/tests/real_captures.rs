//! Real ROS 2 Jazzy captures (Fast DDS and Cyclone DDS), see
//! `fixtures/captures/ros2-jazzy/README.md`: learn a profile from one run,
//! then replay another run (every process has a new GUID prefix there).

use robodr_capture::{CaptureFile, RtpsPortMap};
use robodr_commission::{LearnConfig, Learner, PcapSource};
use robodr_events::profile::Profile;
use robodr_events::Severity;
use robodr_ros2_pipeline::{
    rules, CaptureDatagramSource, DatagramSource, Finding, Pipeline, PipelineOptions,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

const VENDORS: [&str; 2] = ["fastrtps", "cyclonedds"];
const ROBOT_IP: &str = "10.77.10.10";
const TELEOP_IP: &str = "10.77.10.21";
const ROGUE_IP: &str = "10.77.10.66";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/captures/ros2-jazzy")
        .join(name)
}

fn learn(vendor: &str) -> Profile {
    let cfg = LearnConfig {
        model: "lab-ugv".into(),
        ..LearnConfig::default()
    };
    let mut l = Learner::new(cfg).unwrap();
    let path = fixture(&format!("{vendor}_baseline.pcap"));
    l.ingest(&mut PcapSource::open(&path).unwrap()).unwrap();
    l.finish().profile
}

fn replay(profile: Profile, file: &str) -> (Vec<Finding>, Pipeline) {
    let bytes = std::fs::read(fixture(file)).unwrap();
    let mut src = CaptureDatagramSource::new(
        CaptureFile::new(&bytes[..]).unwrap(),
        robodr_ros2_pipeline::source::rtps_filter(RtpsPortMap::ros2_default()),
    );
    let mut p = Pipeline::new(profile, PipelineOptions::default());
    let mut out = p.status_findings();
    while let Some(d) = src.recv().unwrap() {
        out.extend(p.process_datagram(&d));
    }
    out.extend(p.finish());
    (out, p)
}

/// Findings of Medium severity or more, as (rule, source IP).
fn notable(f: &[Finding]) -> BTreeSet<(String, String)> {
    f.iter()
        .filter(|x| x.deviation.severity >= Severity::Medium)
        .map(|x| (x.deviation.rule.to_string(), x.src_ip.clone()))
        .collect()
}

#[test]
fn learn_from_a_capture_yields_identities_and_a_cmd_vel_envelope() {
    for v in VENDORS {
        let p = learn(v);
        assert!(p.validate().is_ok(), "{v}: {:?}", p.validate());
        let ids = &p.participant_identities;
        assert_eq!(
            ids.keys().cloned().collect::<Vec<_>>(),
            ["base_controller", "teleop_twist"],
            "{v}"
        );
        let vendor = if v == "fastrtps" { "010f" } else { "0110" };
        assert_eq!(ids["base_controller"].vendor, vendor);
        assert!(ids["base_controller"].ips.contains(ROBOT_IP));
        assert!(ids["teleop_twist"].ips.contains(TELEOP_IP));
        assert!(ids["teleop_twist"].nodes.contains("/teleop_twist"));
        // 0.3 m/s observed -> an envelope above it, far below the rogue 3.0.
        let env = &p.motion_envelopes["/cmd_vel"];
        let max = env.max_linear_speed.unwrap();
        assert!((0.3..1.0).contains(&max), "{v}: {max}");
    }
}

#[test]
fn the_learned_run_replays_clean() {
    // Nothing notable except the teleop leaving at the end of the capture.
    for v in VENDORS {
        let (f, p) = replay(learn(v), &format!("{v}_baseline.pcap"));
        let n = notable(&f);
        assert_eq!(
            n,
            [(
                rules::PARTICIPANT_REMOVED.to_string(),
                TELEOP_IP.to_string()
            )]
            .into(),
            "{v}: {f:#?}"
        );
        assert_eq!(p.stats().identity.pool_full, 0);
    }
}

#[test]
fn rogue_publisher_is_caught_after_the_robot_restarted() {
    for v in VENDORS {
        let profile = learn(v);
        let learned: BTreeSet<String> = profile.participants.clone();
        let (f, p) = replay(profile, &format!("{v}_rogue_cmd_vel.pcap"));
        let n = notable(&f);
        // The robot and the teleop restarted (new prefixes) and were
        // resolved to their identities: nothing from their IPs except the
        // teleop leaving.
        for (rule, ip) in &n {
            if ip == ROBOT_IP || ip == TELEOP_IP {
                assert_eq!(rule, rules::PARTICIPANT_REMOVED, "{v}: {rule} from {ip}");
            }
        }
        let resolved: BTreeSet<String> = p
            .identity_holders()
            .into_iter()
            .map(|(g, _)| robodr_rtps::hex12(&g))
            .collect();
        assert!(resolved.is_disjoint(&learned), "{v}: prefixes must be new");
        assert!(
            p.stats().identity.resolved >= 2,
            "{v}: {:?}",
            p.stats().identity
        );
        // Each holding was confirmed by its node's parameter service. The
        // teleop disposed itself before the end of the capture, so only the
        // robot's controller still holds its identity.
        let names: BTreeSet<String> = p.identity_holders().into_iter().map(|(_, n)| n).collect();
        assert_eq!(names, ["base_controller".to_string()].into(), "{v}");
        assert!(
            p.stats().identity.confirmed >= 2,
            "{v}: {:?}",
            p.stats().identity
        );
        // The rogue: unknown participant, Critical motion writer, Critical
        // over-envelope command.
        for rule in [
            "robot.ros2.unknown_participant",
            "robot.ros2.unauthorized_motion_writer",
            "robot.motion.linear_over_envelope",
        ] {
            assert!(
                n.contains(&(rule.to_string(), ROGUE_IP.to_string())),
                "{v}: {rule} missing: {f:#?}"
            );
        }
        let critical: Vec<&Finding> = f
            .iter()
            .filter(|x| x.deviation.severity == Severity::Critical)
            .collect();
        assert!(
            critical.iter().all(|x| x.src_ip == ROGUE_IP),
            "{v}: {critical:#?}"
        );
    }
}

#[test]
fn a_second_process_claiming_a_held_identity_is_refused() {
    // Pretend the rogue host were one of the teleop identity's addresses:
    // the teleop holds its single instance, so the rogue still is unknown
    // and the instance cap is reported.
    for v in VENDORS {
        let mut profile = learn(v);
        profile
            .participant_identities
            .get_mut("teleop_twist")
            .unwrap()
            .ips
            .insert(ROGUE_IP.into());
        let (f, p) = replay(profile, &format!("{v}_rogue_cmd_vel.pcap"));
        let n = notable(&f);
        for rule in [
            rules::IDENTITY_INSTANCES_EXCEEDED,
            "robot.ros2.unknown_participant",
            "robot.ros2.unauthorized_motion_writer",
        ] {
            assert!(
                n.contains(&(rule.to_string(), ROGUE_IP.to_string())),
                "{v}: {rule} missing: {f:#?}"
            );
        }
        assert!(p.stats().identity.pool_full >= 1);
    }
}

#[test]
fn without_identities_the_restarted_robot_is_unknown() {
    // The failure the identities fix, kept as evidence: GUID-only matching.
    for v in VENDORS {
        let mut profile = learn(v);
        profile.participant_identities.clear();
        let (f, _) = replay(profile, &format!("{v}_rogue_cmd_vel.pcap"));
        assert!(
            notable(&f).contains(&(
                "robot.ros2.unknown_participant".to_string(),
                ROBOT_IP.to_string()
            )),
            "{v}"
        );
    }
}
