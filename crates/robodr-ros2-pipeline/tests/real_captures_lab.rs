//! Real ROS 2 Jazzy lab captures beyond the first set, see
//! `fixtures/captures/ros2-jazzy/README.md`:
//!
//! - `*_gz_*`: a headless Gazebo (Harmonic) robot (gz bridge,
//!   robot_state_publisher, /clock, /tf, /joint_states, /odom) driven over
//!   /cmd_vel, learned from one run and replayed against a restarted run
//!   with a rogue publisher;
//! - `*_frag_*`: every participant with a small maximum message size, so
//!   SEDP (and a large JointTrajectory) travels as DATA_FRAG;
//! - `zenoh_*`: the same robot on `rmw_zenoh_cpp`: no RTPS at all, which
//!   must be reported as a blind spot.

use robodr_capture::{CaptureFile, RtpsPortMap};
use robodr_commission::{Commissioning, LearnConfig, Learner, PcapSource, WarningLevel};
use robodr_events::profile::Profile;
use robodr_events::Severity;
use robodr_ros2_pipeline::{
    rules, CaptureDatagramSource, DatagramSource, Finding, MotionSample, Pipeline, PipelineOptions,
    ReassemblyLimits,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

const VENDORS: [&str; 2] = ["fastrtps", "cyclonedds"];
const ROBOT_IP: &str = "10.77.10.10";
const TELEOP_IP: &str = "10.77.10.21";
const ROGUE_IP: &str = "10.77.10.66";
const ARM: &str = "/arm_controller/joint_trajectory";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/captures/ros2-jazzy")
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

fn learn(file: &str) -> Profile {
    commission(file).profile
}

struct Replay {
    findings: Vec<Finding>,
    motion: Vec<MotionSample>,
    pipeline: Pipeline,
}

fn replay_with(profile: Profile, file: &str, opts: PipelineOptions) -> Replay {
    let bytes = std::fs::read(fixture(file)).unwrap();
    let mut src = CaptureDatagramSource::new(
        CaptureFile::new(&bytes[..]).unwrap(),
        robodr_ros2_pipeline::source::rtps_filter(RtpsPortMap::ros2_default()),
    );
    let mut p = Pipeline::new(profile, opts);
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

fn replay(profile: Profile, file: &str) -> Replay {
    replay_with(profile, file, PipelineOptions::default())
}

/// Findings of Medium severity or more, as (rule, source IP).
fn notable(f: &[Finding]) -> BTreeSet<(String, String)> {
    f.iter()
        .filter(|x| x.deviation.severity >= Severity::Medium)
        .map(|x| (x.deviation.rule.to_string(), x.src_ip.clone()))
        .collect()
}

fn teleop_left() -> BTreeSet<(String, String)> {
    [(
        rules::PARTICIPANT_REMOVED.to_string(),
        TELEOP_IP.to_string(),
    )]
    .into()
}

// --- Gazebo -----------------------------------------------------------------

#[test]
fn gazebo_learn_yields_every_robot_process_and_the_sim_graph() {
    for v in VENDORS {
        let p = learn(&format!("{v}_gz_baseline.pcap"));
        assert!(p.validate().is_ok(), "{v}: {:?}", p.validate());
        assert_eq!(
            p.participant_identities.keys().cloned().collect::<Vec<_>>(),
            ["gz_bridge", "robot_state_publisher", "teleop_twist"],
            "{v}"
        );
        for id in ["gz_bridge", "robot_state_publisher"] {
            assert_eq!(
                p.participant_identities[id].ips,
                [ROBOT_IP.to_string()].into(),
                "{v}"
            );
        }
        for t in [
            "/clock",
            "/cmd_vel",
            "/joint_states",
            "/odom",
            "/robot_description",
            "/tf",
            "/tf_static",
        ] {
            assert!(p.writer_topics.contains(t), "{v}: {t}");
        }
        let max = p.motion_envelopes["/cmd_vel"].max_linear_speed.unwrap();
        assert!((0.3..1.0).contains(&max), "{v}: {max}");
    }
}

#[test]
fn gazebo_learned_run_replays_clean() {
    for v in VENDORS {
        let f = format!("{v}_gz_baseline.pcap");
        let r = replay(learn(&f), &f);
        assert_eq!(
            notable(&r.findings),
            teleop_left(),
            "{v}: {:#?}",
            r.findings
        );
    }
}

#[test]
fn gazebo_rogue_is_caught_and_the_restarted_sim_is_not_flagged() {
    for v in VENDORS {
        let profile = learn(&format!("{v}_gz_baseline.pcap"));
        let learned = profile.participants.clone();
        let r = replay(profile, &format!("{v}_gz_rogue_cmd_vel.pcap"));
        let n = notable(&r.findings);
        for (rule, ip) in &n {
            if ip == ROBOT_IP || ip == TELEOP_IP {
                assert_eq!(rule, rules::PARTICIPANT_REMOVED, "{v}: {rule} from {ip}");
            }
        }
        for rule in [
            "robot.ros2.unknown_participant",
            "robot.ros2.unauthorized_motion_writer",
            "robot.motion.linear_over_envelope",
        ] {
            assert!(
                n.contains(&(rule.to_string(), ROGUE_IP.to_string())),
                "{v}: {rule} missing: {:#?}",
                r.findings
            );
        }
        // All three processes restarted with new prefixes, each resolved
        // and confirmed by its node; the bridge and robot_state_publisher
        // start together on one host, so one provisional slot is corrected.
        let st = r.pipeline.stats().identity;
        assert!(
            st.resolved >= 3 && st.confirmed >= 3 && st.pool_full == 0,
            "{v}: {st:?}"
        );
        let held: BTreeSet<String> = r
            .pipeline
            .identity_holders()
            .into_iter()
            .map(|(g, n)| {
                assert!(
                    !learned.contains(&robodr_rtps::hex12(&g)),
                    "{v}: new prefixes"
                );
                n
            })
            .collect();
        assert_eq!(
            held,
            ["gz_bridge", "robot_state_publisher"]
                .map(String::from)
                .into(),
            "{v}"
        );
        assert!(r
            .findings
            .iter()
            .filter(|x| x.deviation.severity == Severity::Critical)
            .all(|x| x.src_ip == ROGUE_IP));
    }
}

#[test]
fn gazebo_odom_data_before_its_sedp_is_not_unattributed() {
    // Fast DDS sends /odom samples to the station's reader ~47 ms before
    // the bridge's own SEDP publication reaches it: with the motion decoder
    // watching /odom this was a High robot.motion.unattributed_sample on the
    // legitimate robot. The grace window keeps it quiet.
    for v in VENDORS {
        let f = format!("{v}_gz_baseline.pcap");
        let mut opts = PipelineOptions::default();
        opts.motion.feedback_topics = ["/odom".to_string()].into();
        let r = replay_with(learn(&f), &f, opts);
        assert_eq!(
            notable(&r.findings),
            teleop_left(),
            "{v}: {:#?}",
            r.findings
        );
        let odom = r.motion.iter().filter(|s| s.topic == "rt/odom").count();
        assert!(odom > 200, "{v}: {odom}");
        assert!(r.motion.iter().all(|s| s.attribution.is_trusted()));
    }
    // The run where it was seen (kept as fastrtps_gz_dual_odom.pcap, see the
    // README): the bridge's /odom writer was announced 47 ms late.
    let mut opts = PipelineOptions::default();
    opts.motion.feedback_topics = ["/odom".to_string()].into();
    let r = replay_with(
        learn("fastrtps_gz_baseline.pcap"),
        "fastrtps_gz_dual_odom.pcap",
        opts,
    );
    assert!(r.pipeline.stats().motion.announced_late >= 1);
    assert!(!r
        .findings
        .iter()
        .any(|x| x.deviation.rule == rules::MOTION_UNATTRIBUTED_SAMPLE));
}

// --- DATA_FRAG ----------------------------------------------------------------

#[test]
fn fragmented_discovery_is_learned_completely() {
    for v in VENDORS {
        let c = commission(&format!("{v}_frag_run1.pcap"));
        let d = c.report.runs[0].capture.clone().unwrap();
        assert!(d.discovery_data_frag > 100, "{v}: {d:?}");
        assert!(d.discovery_frag_completed > 50, "{v}: {d:?}");
        assert_eq!(
            (
                d.discovery_frag_rejected,
                d.discovery_frag_evicted,
                d.discovery_frag_incomplete
            ),
            (0, 0, 0),
            "{v}: {d:?}"
        );
        assert!(c
            .report
            .warnings
            .iter()
            .any(|w| w.code == "fragmented_discovery_reassembled"));
        assert!(!c
            .report
            .warnings
            .iter()
            .any(|w| w.code == "fragmented_discovery_unreassembled"));
        let p = &c.profile;
        assert_eq!(
            p.participant_identities.keys().cloned().collect::<Vec<_>>(),
            [
                "arm_driver",
                "arm_teleop",
                "base_controller",
                "teleop_twist"
            ],
            "{v}"
        );
        // Every node's parameter services came through SEDP fragments.
        assert_eq!(p.services.len(), 4 * 7, "{v}: {:?}", p.services);
        // The 40-point JointTrajectory (a DATA_FRAG user sample) was decoded.
        let joint = p.motion_envelopes[ARM].max_joint_speed.unwrap();
        assert!((0.2..0.3).contains(&joint), "{v}: {joint}");
    }
}

#[test]
fn fragmented_runs_replay_clean_with_one_low_finding_per_host() {
    for v in VENDORS {
        let r = replay(
            learn(&format!("{v}_frag_run1.pcap")),
            &format!("{v}_frag_run2.pcap"),
        );
        let n = notable(&r.findings);
        assert!(n.is_subset(&teleop_left()), "{v}: {:#?}", r.findings);
        let frag: BTreeSet<String> = r
            .findings
            .iter()
            .filter(|x| x.deviation.rule == rules::FRAGMENTED_DISCOVERY)
            .map(|x| {
                assert_eq!(x.deviation.severity, Severity::Low);
                x.src_ip.clone()
            })
            .collect();
        assert_eq!(frag, [ROBOT_IP, TELEOP_IP].map(String::from).into(), "{v}");
        let st = r.pipeline.stats();
        assert!(st.fragment_samples_completed > 50, "{v}: {st:?}");
        assert_eq!(st.fragments_rejected, 0, "{v}");
        assert_eq!(st.identity.confirmed, 4, "{v}: {:?}", st.identity);
        // Motion commands rebuilt from user DATA_FRAG, within the envelope.
        let arm: Vec<&MotionSample> = r
            .motion
            .iter()
            .filter(|s| s.topic == "rt/arm_controller/joint_trajectory")
            .collect();
        assert!(arm.len() >= 15, "{v}: {}", arm.len());
        assert!(arm.iter().all(|s| s.from_fragments), "{v}");
    }
}

/// Review 2, H1: the reassembler marks a sample whose fragment copies
/// disagreed as contested (an enforcement point then refuses to relax
/// anything for it). Honest stacks never send disagreeing copies: both
/// vendors' fragmented runs, Cyclone's resends of a fragment to one reader
/// included, complete with no conflict and nothing contested.
#[test]
fn honest_fragmented_discovery_is_never_contested() {
    for v in VENDORS {
        for run in ["run1", "run2"] {
            let file = format!("{v}_frag_{run}.pcap");
            let bytes = std::fs::read(fixture(&file)).unwrap();
            let mut src = CaptureDatagramSource::new(
                CaptureFile::new(&bytes[..]).unwrap(),
                robodr_ros2_pipeline::source::rtps_filter(RtpsPortMap::ros2_default()),
            );
            let mut reasm = robodr_rtps::FragmentReassembler::new(ReassemblyLimits::default());
            let (mut fragmented, mut contested) = (0usize, 0usize);
            while let Some(d) = src.recv().unwrap() {
                let Some(r) = reasm.parse_datagram_detailed(&d.payload) else {
                    continue;
                };
                fragmented += r.endpoints.iter().filter(|e| e.from_fragments).count();
                contested += r.endpoints.iter().filter(|e| e.contested).count()
                    + r.removed_endpoints.iter().filter(|e| e.contested).count()
                    + r.removed_participants
                        .iter()
                        .filter(|e| e.contested)
                        .count();
            }
            assert!(fragmented > 50, "{file}: {fragmented}");
            assert_eq!((contested, reasm.conflicts()), (0, 0), "{file}");
        }
    }
}

#[test]
fn the_old_reassembly_quota_lost_cyclone_sedp_bursts() {
    // Evidence for the raised defaults: with the previous caps (16 pending,
    // 4 per source) Cyclone's burst of first fragments evicted the
    // announcements before their second fragments arrived.
    let old = ReassemblyLimits {
        max_pending_samples: 16,
        max_total_bytes: 256 * 1024,
        max_pending_per_source: 4,
        ..ReassemblyLimits::default()
    };
    let r = replay_with(
        learn("cyclonedds_frag_run1.pcap"),
        "cyclonedds_frag_run2.pcap",
        PipelineOptions {
            reassembly: old,
            ..PipelineOptions::default()
        },
    );
    assert!(notable(&r.findings).contains(&(
        rules::DISCOVERY_FRAGMENT_EVICTED.to_string(),
        ROBOT_IP.to_string()
    )));
}

// --- Zenoh --------------------------------------------------------------------

#[test]
fn a_zenoh_robot_is_reported_as_a_blind_spot() {
    for file in ["zenoh_baseline.pcap", "zenoh_rogue_cmd_vel.pcap"] {
        let r = replay(learn("fastrtps_baseline.pcap"), file);
        let st = r.pipeline.stats();
        assert_eq!(st.datagrams, 0, "{file}: no RTPS at all");
        let blind: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|x| x.deviation.rule == rules::CAPTURE_UNSUPPORTED_MIDDLEWARE)
            .collect();
        assert_eq!(blind.len(), 1, "{file}: {:#?}", r.findings);
        assert_eq!(blind[0].deviation.severity, Severity::High);
        assert!(blind[0].deviation.detail.contains("blind"));
        assert!(
            blind[0].src_ip.starts_with("10.77.10."),
            "{}",
            blind[0].src_ip
        );
        // Nothing else but a Low not_udp for the ICMPv6 MLD reports of this
        // unfiltered capture (the TCP itself is not counted as not_udp).
        let others: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|x| x.deviation.rule != rules::CAPTURE_UNSUPPORTED_MIDDLEWARE)
            .collect();
        assert!(
            others
                .iter()
                .all(|x| x.deviation.rule == rules::CAPTURE_NOT_UDP
                    && x.deviation.severity == Severity::Low),
            "{file}: {others:#?}"
        );
    }
}

#[test]
fn learning_from_a_zenoh_capture_warns_and_learns_nothing() {
    let c = commission("zenoh_baseline.pcap");
    let d = c.report.runs[0].capture.clone().unwrap();
    assert!(d.zenoh_packets > 100, "{d:?}");
    assert_eq!(d.rtps_datagrams, 0);
    let w = c
        .report
        .warnings
        .iter()
        .find(|w| w.code == "unsupported_middleware")
        .expect("warning");
    assert_eq!(w.level, WarningLevel::Warn);
    assert!(w.message.contains("no RTPS at all"), "{}", w.message);
    assert!(c
        .report
        .warnings
        .iter()
        .any(|w| w.code == "no_rtps_in_capture"));
    assert!(c.profile.participants.is_empty());
    assert!(c.profile.participant_identities.is_empty());
}

#[test]
fn zenoh_beside_rtps_is_medium_and_names_its_source() {
    let mut p = Pipeline::new(learn("fastrtps_baseline.pcap"), PipelineOptions::default());
    let h = robodr_ros2_pipeline::CaptureHealth {
        zenoh: 3,
        zenoh_last_src: Some([10, 77, 10, 30].into()),
        rtps: 10,
        ..Default::default()
    };
    let f = p.capture_findings(&h);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].deviation.rule, rules::CAPTURE_UNSUPPORTED_MIDDLEWARE);
    assert_eq!(f[0].deviation.severity, Severity::Medium);
    assert_eq!(f[0].src_ip, "10.77.10.30");
    assert!(f[0].deviation.detail.contains("only the RTPS part"));
    // No new Zenoh packets: nothing more.
    assert!(p.capture_findings(&h).is_empty());
}
