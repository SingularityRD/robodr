//! Real ROS 2 Humble captures (Fast DDS 2.6, `rmw_fastrtps_cpp`), see
//! `fixtures/captures/ros2-humble/README.md`.

use robodr_capture::{CaptureFile, RtpsPortMap};
use robodr_commission::{Commissioning, LearnConfig, Learner, PcapSource};
use robodr_events::profile::Profile;
use robodr_events::Severity;
use robodr_ros2_pipeline::{
    rules, CaptureDatagramSource, DatagramSource, Finding, MotionSample, Pipeline, PipelineOptions,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/captures/ros2-humble")
        .join(name)
}

fn commission(file: &str) -> Commissioning {
    let mut l = Learner::new(LearnConfig {
        model: "lab-ugv".into(),
        ..LearnConfig::default()
    })
    .unwrap();
    l.ingest(&mut PcapSource::open(&fixture(file)).unwrap())
        .unwrap();
    l.finish()
}

struct Replay {
    findings: Vec<Finding>,
    motion: Vec<MotionSample>,
    pipeline: Pipeline,
}

fn replay(profile: Profile, file: &str) -> Replay {
    let bytes = std::fs::read(fixture(file)).unwrap();
    let mut src = CaptureDatagramSource::new(
        CaptureFile::new(&bytes[..]).unwrap(),
        robodr_ros2_pipeline::source::rtps_filter(RtpsPortMap::ros2_default()),
    );
    let mut p = Pipeline::new(profile, PipelineOptions::default());
    let mut findings = p.status_findings();
    let mut motion = Vec::new();
    let mut n = 0u64;
    while let Some(d) = src.recv().unwrap() {
        n += 1;
        let o = p.process_datagram_with_motion(&d, n * 1_000_000);
        findings.extend(o.findings);
        motion.extend(o.motion);
    }
    findings.extend(p.capture_findings(&src.capture_health().unwrap()));
    findings.extend(p.finish());
    Replay {
        findings,
        motion,
        pipeline: p,
    }
}

fn notable(f: &[Finding]) -> BTreeSet<(String, String)> {
    f.iter()
        .filter(|x| x.deviation.severity >= Severity::Medium)
        .map(|x| (x.deviation.rule.to_string(), x.src_ip.clone()))
        .collect()
}
const ROBOT_IP: &str = "10.77.10.10";
const TELEOP_IP: &str = "10.77.10.21";
const ROGUE_IP: &str = "10.77.10.66";

fn learn(file: &str) -> Profile {
    commission(file).profile
}

fn teleop_left() -> BTreeSet<(String, String)> {
    [(
        rules::PARTICIPANT_REMOVED.to_string(),
        TELEOP_IP.to_string(),
    )]
    .into()
}

fn rule_ips(f: &[Finding], rule: &str) -> BTreeSet<String> {
    f.iter()
        .filter(|x| x.deviation.rule == rule)
        .map(|x| x.src_ip.clone())
        .collect()
}

// --- T33: Humble behaves like Jazzy -----------------------------------------

#[test]
fn humble_learn_yields_identities_and_a_cmd_vel_envelope() {
    let p = learn("fastrtps_baseline.pcap");
    assert!(p.validate().is_ok(), "{:?}", p.validate());
    let ids = &p.participant_identities;
    assert_eq!(
        ids.keys().cloned().collect::<Vec<_>>(),
        ["base_controller", "teleop_twist"]
    );
    assert_eq!(ids["base_controller"].vendor, "010f");
    assert!(ids["base_controller"].ips.contains(ROBOT_IP));
    assert!(ids["teleop_twist"].nodes.contains("/teleop_twist"));
    let lin = p.motion_envelopes["/cmd_vel"].max_linear_speed.unwrap();
    assert!((0.3..1.0).contains(&lin), "{lin}");
}

#[test]
fn humble_learned_run_replays_clean() {
    let r = replay(learn("fastrtps_baseline.pcap"), "fastrtps_baseline.pcap");
    assert_eq!(notable(&r.findings), teleop_left(), "{:#?}", r.findings);
    // UDP-only transports (fastdds_udp_only.xml): no transport blind spot.
    assert!(rule_ips(&r.findings, rules::CAPTURE_UNSUPPORTED_TRANSPORT).is_empty());
}

#[test]
fn humble_rogue_publisher_is_caught_after_the_robot_restarted() {
    let r = replay(
        learn("fastrtps_baseline.pcap"),
        "fastrtps_rogue_cmd_vel.pcap",
    );
    let n = notable(&r.findings);
    for (rule, ip) in &n {
        if ip == ROBOT_IP || ip == TELEOP_IP {
            assert_eq!(rule, rules::PARTICIPANT_REMOVED, "{rule} from {ip}");
        }
    }
    for rule in [
        "robot.ros2.unknown_participant",
        "robot.ros2.unauthorized_motion_writer",
        "robot.motion.linear_over_envelope",
    ] {
        assert!(
            n.contains(&(rule.to_string(), ROGUE_IP.to_string())),
            "{rule} missing: {n:#?}"
        );
    }
    let critical: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|x| x.deviation.severity == Severity::Critical)
        .collect();
    assert!(!critical.is_empty());
    assert!(
        critical.iter().all(|x| x.src_ip == ROGUE_IP),
        "{critical:#?}"
    );
    assert!(r.pipeline.stats().identity.confirmed >= 2);
}

#[test]
fn humble_several_processes_on_one_host_each_get_their_own_identity() {
    let profile = learn("fastrtps_multi_run1.pcap");
    let robot: BTreeSet<String> = profile
        .participant_identities
        .iter()
        .filter(|(_, id)| id.ips.contains(ROBOT_IP))
        .map(|(n, _)| n.clone())
        .collect();
    assert_eq!(
        robot,
        [
            "add_two_ints_server",
            "base_controller",
            "fibonacci_action_server"
        ]
        .map(String::from)
        .into()
    );
    // Run 2 starts them in reverse order.
    let r = replay(profile, "fastrtps_multi_run2.pcap");
    assert_eq!(notable(&r.findings), teleop_left(), "{:#?}", r.findings);
    let held: BTreeSet<String> = r
        .pipeline
        .identity_holders()
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert_eq!(held, robot);
    assert!(r.pipeline.stats().identity.moved >= 1);
}

#[test]
fn humble_fragmented_discovery_is_learned_and_replays_clean() {
    let c = commission("fastrtps_frag_run1.pcap");
    let d = c.report.runs[0].capture.clone().unwrap();
    assert!(d.discovery_data_frag > 100, "{d:?}");
    assert_eq!(
        (
            d.discovery_frag_rejected,
            d.discovery_frag_evicted,
            d.discovery_frag_incomplete
        ),
        (0, 0, 0),
        "{d:?}"
    );
    assert_eq!(
        c.profile
            .participant_identities
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        [
            "arm_driver",
            "arm_teleop",
            "base_controller",
            "teleop_twist"
        ]
    );
    let r = replay(c.profile, "fastrtps_frag_run2.pcap");
    assert!(
        notable(&r.findings).is_subset(&teleop_left()),
        "{:#?}",
        r.findings
    );
    assert_eq!(
        rule_ips(&r.findings, rules::FRAGMENTED_DISCOVERY),
        [ROBOT_IP, TELEOP_IP].map(String::from).into()
    );
    assert_eq!(r.pipeline.stats().fragments_rejected, 0);
    let arm = r
        .motion
        .iter()
        .filter(|s| s.topic == "rt/arm_controller/joint_trajectory")
        .count();
    assert!(arm >= 15, "{arm}");
}

// --- T14: shared-memory transports -----------------------------------------

#[test]
fn humble_default_shared_memory_transport_is_reported_per_host() {
    // Fast DDS 2.6 default transports (UDPv4 + SHM): every participant
    // advertises shared-memory locators; on the robot host a local planner
    // publishes /cmd_vel to the controller over shared memory, which never
    // reaches the wire.
    let profile = learn("fastrtps_shm_default.pcap");
    assert!(profile.participant_identities.contains_key("local_planner"));
    let r = replay(profile, "fastrtps_shm_default.pcap");
    let shm: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|x| x.deviation.rule == rules::CAPTURE_UNSUPPORTED_TRANSPORT)
        .collect();
    // One per host (dedup on the host + transport detail), Medium.
    assert_eq!(
        shm.iter().map(|x| x.src_ip.clone()).collect::<Vec<_>>(),
        [ROBOT_IP, TELEOP_IP]
    );
    for f in &shm {
        assert_eq!(f.deviation.severity, Severity::Medium);
        assert!(f.deviation.detail.contains("shared memory (shm)"), "{f:?}");
        assert!(f.deviation.detail.contains("docs/DDS-TRANSPORTS.md"));
    }
    // The planner's /cmd_vel never crossed the wire: only the remote
    // teleop's commands were decoded. This is the blind spot reported.
    let senders: BTreeSet<String> = r
        .motion
        .iter()
        .filter(|s| s.topic == "rt/cmd_vel")
        .map(|s| s.src_ip.clone())
        .collect();
    assert_eq!(senders, [TELEOP_IP.to_string()].into());
    // Nothing else but the teleop leaving.
    let mut rest = notable(&r.findings);
    rest.retain(|(rule, _)| rule != rules::CAPTURE_UNSUPPORTED_TRANSPORT);
    assert_eq!(rest, teleop_left(), "{:#?}", r.findings);
}

// --- T78: SROS 2 (DDS-Security, Enforce) -----------------------------------

const FOREIGN_CA_IP: &str = "10.77.10.67";

fn keystore() -> std::sync::Arc<robodr_ros2_pipeline::sros2::Sros2Policy> {
    std::sync::Arc::new(robodr_ros2_pipeline::sros2::Sros2Policy::load(&fixture("sros2")).unwrap())
}

fn replay_opts(profile: Profile, file: &str, opts: PipelineOptions) -> Replay {
    let bytes = std::fs::read(fixture(file)).unwrap();
    let mut src = CaptureDatagramSource::new(
        CaptureFile::new(&bytes[..]).unwrap(),
        robodr_ros2_pipeline::source::rtps_filter(RtpsPortMap::ros2_default()),
    );
    let mut p = Pipeline::new(profile, opts);
    let mut findings = p.status_findings();
    let mut n = 0u64;
    while let Some(d) = src.recv().unwrap() {
        n += 1;
        findings.extend(p.process_datagram_with_motion(&d, n * 1_000_000).findings);
    }
    findings.extend(p.finish());
    Replay {
        findings,
        motion: Vec::new(),
        pipeline: p,
    }
}

#[test]
fn sros2_spdp_carries_the_certificate_subjects_in_clear() {
    let bytes = std::fs::read(fixture("fastrtps_sros2_rogue.pcap")).unwrap();
    let mut src = CaptureDatagramSource::new(
        CaptureFile::new(&bytes[..]).unwrap(),
        robodr_ros2_pipeline::source::rtps_filter(RtpsPortMap::ros2_default()),
    );
    let mut seen: BTreeSet<(String, Option<String>, Option<String>)> = BTreeSet::new();
    while let Some(d) = src.recv().unwrap() {
        if let Some(r) = robodr_rtps::parse_datagram_detailed(&d.payload) {
            for p in r.participants {
                seen.insert((
                    d.src_ip.clone(),
                    p.security.cert_subject.clone(),
                    p.security.ca_subject.clone(),
                ));
            }
        }
    }
    let ca = Some(r"/CN=sros2CA".to_string());
    assert_eq!(
        seen,
        [
            (
                ROBOT_IP.to_string(),
                Some(r"/CN=\/lab\/base_controller".to_string()),
                ca.clone()
            ),
            (
                TELEOP_IP.to_string(),
                Some(r"/CN=\/lab\/teleop_twist".to_string()),
                ca.clone()
            ),
            // The unsecured rogue announces no identity.
            (ROGUE_IP.to_string(), None, None),
            // The foreign-CA rogue claims the teleop's subject; its CA has
            // the same (default sros2) subject name.
            (
                FOREIGN_CA_IP.to_string(),
                Some(r"/CN=\/lab\/teleop_twist".to_string()),
                ca
            ),
        ]
        .into()
    );
}

#[test]
fn sros2_learned_run_is_blind_to_topics_and_says_so() {
    let c = commission("fastrtps_sros2_baseline.pcap");
    // SEDP is encrypted: no topic, no envelope, only the participants.
    assert!(c.profile.writer_topics.is_empty());
    assert!(c.profile.motion_envelopes.is_empty());
    assert_eq!(c.profile.participant_identities.len(), 2);
    assert!(c
        .report
        .warnings
        .iter()
        .any(|w| w.code == "protected_discovery"));
    let v = keystore().visibility();
    assert!(v.iter().any(|l| l.contains("no topic")), "{v:?}");
}

#[test]
fn sros2_restarted_robot_resolves_and_rogues_are_reported() {
    let profile = commission("fastrtps_sros2_baseline.pcap").profile;
    let opts = PipelineOptions {
        sros2: Some(keystore()),
        ..PipelineOptions::default()
    };
    let r = replay_opts(profile.clone(), "fastrtps_sros2_rogue.pcap", opts);
    let n = notable(&r.findings);
    // The restarted robot and teleop (new prefixes, same certificates)
    // resolve to their identities: nothing from them but the shared-memory
    // locators (these runs use Fast DDS default transports) and the
    // teleop leaving.
    for (rule, ip) in &n {
        if rule == rules::CAPTURE_UNSUPPORTED_TRANSPORT
            || (rule == rules::PARTICIPANT_REMOVED && ip == TELEOP_IP)
        {
            continue;
        }
        assert!(ip != ROBOT_IP && ip != TELEOP_IP, "{rule} from {ip}");
    }
    assert!(r.pipeline.stats().identity.resolved >= 2);
    // The unsecured rogue: unknown participant, and unauthenticated on a
    // domain that requires authentication.
    assert!(n.contains(&(
        "robot.ros2.unknown_participant".to_string(),
        ROGUE_IP.to_string()
    )));
    let untrusted: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|f| f.deviation.rule == "robot.ros2.untrusted_security_identity")
        .collect();
    assert_eq!(
        untrusted
            .iter()
            .map(|f| (f.src_ip.as_str(), f.deviation.severity))
            .collect::<Vec<_>>(),
        [(ROGUE_IP, Severity::Medium)],
        "{untrusted:#?}"
    );
    // The foreign-CA rogue claims a granted subject: only its address
    // gives it away (unknown participant). Telling it apart by its
    // certificate needs the handshake (not inspected; see sros2 docs).
    assert!(n.contains(&(
        "robot.ros2.unknown_participant".to_string(),
        FOREIGN_CA_IP.to_string()
    )));

    // (Before identity.rs matched the subject hash of a secured prefix, the
    // restarted robot and teleop were unknown participants here: `learn`
    // takes the identity's `vendor` from the prefix.)

    // The subject hash only stands in for the vendor of a participant that
    // announces a DDS-Security identity: the unsecured rogue cannot borrow
    // it even from a robot address.
    let mut pinned = profile;
    for id in pinned.participant_identities.values_mut() {
        id.ips.insert(ROGUE_IP.into());
    }
    let r = replay_opts(
        pinned,
        "fastrtps_sros2_rogue.pcap",
        PipelineOptions::default(),
    );
    assert!(notable(&r.findings).contains(&(
        "robot.ros2.unknown_participant".to_string(),
        ROGUE_IP.to_string()
    )));
}

#[test]
fn sros2_participant_from_another_keystore_is_high() {
    // A keystore copy that grants only the robot's controller: the teleop's
    // subject is then foreign.
    let dir = std::env::temp_dir().join(format!("robodr-sros2-ks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("lab/base_controller")).unwrap();
    std::fs::copy(fixture("sros2/governance.xml"), dir.join("governance.xml")).unwrap();
    std::fs::copy(
        fixture("sros2/lab/base_controller/permissions.xml"),
        dir.join("lab/base_controller/permissions.xml"),
    )
    .unwrap();
    let policy = robodr_ros2_pipeline::sros2::Sros2Policy::load(&dir).unwrap();
    let opts = PipelineOptions {
        sros2: Some(std::sync::Arc::new(policy)),
        ..PipelineOptions::default()
    };
    let profile = commission("fastrtps_sros2_baseline.pcap").profile;
    let r = replay_opts(profile, "fastrtps_sros2_baseline.pcap", opts);
    let high: BTreeSet<String> = r
        .findings
        .iter()
        .filter(|f| {
            f.deviation.rule == "robot.ros2.untrusted_security_identity"
                && f.deviation.severity == Severity::High
        })
        .map(|f| f.src_ip.clone())
        .collect();
    assert_eq!(high, [TELEOP_IP.to_string()].into());
    std::fs::remove_dir_all(&dir).ok();
}
