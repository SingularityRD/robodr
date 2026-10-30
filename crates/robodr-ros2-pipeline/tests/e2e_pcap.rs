//! Offline end to end: a generated pcap -> `CaptureDatagramSource` ->
//! `Pipeline` -> findings, against a locked / unlocked / invalid profile.

mod common;

use common::*;
use robodr_capture::{synth, CaptureFile, RtpsPortMap};
use robodr_events::{Mode, Severity};
use robodr_ros2_pipeline::{
    rules, CaptureDatagramSource, DatagramSource, Finding, Pipeline, PipelineOptions, ProfileStatus,
};

/// Run every datagram of an in-memory pcap through a pipeline.
fn run(pcap_bytes: &[u8], pipeline: &mut Pipeline) -> Vec<Finding> {
    let mut src = CaptureDatagramSource::new(
        CaptureFile::new(pcap_bytes).unwrap(),
        robodr_ros2_pipeline::source::rtps_filter(RtpsPortMap::ros2_default()),
    );
    let mut out = pipeline.status_findings();
    while let Some(d) = src.recv().unwrap() {
        out.extend(pipeline.process_datagram(&d));
    }
    out
}

fn rules_of(f: &[Finding]) -> Vec<(String, Severity)> {
    f.iter()
        .map(|x| (x.deviation.rule.to_string(), x.deviation.severity))
        .collect()
}

#[test]
fn locked_profile_flags_exactly_the_rogue_participant_and_motion_writer() {
    let bytes = pcap(&scenario_frames(5));
    let mut p = Pipeline::new(robot_profile(true), PipelineOptions::default());
    assert_eq!(p.status(), &ProfileStatus::Enforcing);
    let f = run(&bytes, &mut p);
    assert_eq!(
        rules_of(&f),
        vec![
            ("robot.ros2.unknown_participant".into(), Severity::High),
            (
                "robot.ros2.unauthorized_motion_writer".into(),
                Severity::Critical
            ),
        ],
        "{f:#?}"
    );
    assert!(f[0].deviation.detail.contains(ROGUE_HEX));
    assert_eq!(f[0].src_ip, ROGUE_IP.to_string());
    assert!(f[1].deviation.detail.contains("/cmd_vel"));
    assert!(f[1].deviation.detail.contains(ROGUE_HEX));
    for x in &f {
        assert_eq!(x.mode(), Mode::Enforce);
        assert!(!x.is_observe_only());
        assert_eq!(x.extra().profile_status, "enforcing");
    }
    // Dedup: 5 rogue beacons + the SEDP datagram's header participant all
    // collapse into one participant finding.
    let s = p.stats();
    assert_eq!(s.findings, 2);
    assert_eq!(s.duplicates, 5, "{s:?}");
    assert_eq!(s.anomalies, 0);
    // 3 legit + 5 beacons + 1 rogue SEDP + 1 legit beacon; the DNS frame is
    // filtered by the capture layer before the pipeline.
    assert_eq!(s.datagrams, 10);
    assert_eq!(s.not_rtps, 0);
}

#[test]
fn many_repeated_beacons_still_one_finding() {
    let bytes = pcap(&scenario_frames(200));
    let mut p = Pipeline::new(robot_profile(true), PipelineOptions::default());
    let f = run(&bytes, &mut p);
    assert_eq!(f.len(), 2);
    assert_eq!(p.remembered(), 2);
    assert_eq!(p.stats().duplicates, 200);
}

#[test]
fn unlocked_profile_reports_the_same_findings_observe_only() {
    let bytes = pcap(&scenario_frames(3));
    let mut p = Pipeline::new(robot_profile(false), PipelineOptions::default());
    assert_eq!(p.status(), &ProfileStatus::Observing);
    let f = run(&bytes, &mut p);
    assert_eq!(f.len(), 2);
    for x in &f {
        assert!(x.is_observe_only());
        assert!(x.description().starts_with("[observe-only] "));
        let e = x.extra();
        assert!(e.observe_only);
        assert_eq!(e.mode, Mode::Observe);
        assert_eq!(e.profile_status, "observing");
    }
    assert_eq!(f[1].deviation.severity, Severity::Critical);
}

#[test]
fn invalid_profile_is_refused_and_runs_observe_only() {
    // A locked profile from disk with a negative envelope limit and a
    // mangled topic name: Profile::validate fails.
    let dir = temp_dir("invalid-profile");
    let path = dir.join("profile.json");
    let mut prof = robot_profile(true);
    prof.motion_envelopes
        .get_mut("/cmd_vel")
        .unwrap()
        .max_linear_speed = Some(-1.0);
    prof.writer_topics.insert("rt/cmd_vel".into());
    write(&path, serde_json::to_string(&prof).unwrap().as_bytes());
    let loaded = robodr_ros2_pipeline::load_profile(&path).unwrap();
    assert!(loaded.profile.locked);

    let mut p = Pipeline::from_loaded(loaded, PipelineOptions::default());
    let ProfileStatus::Refused(errors) = p.status().clone() else {
        panic!("expected refused, got {:?}", p.status());
    };
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_eq!(p.mode(), Mode::Observe);

    let f = run(&pcap(&scenario_frames(2)), &mut p);
    assert_eq!(
        rules_of(&f),
        vec![
            (rules::PROFILE_REFUSED.into(), Severity::High),
            ("robot.ros2.unknown_participant".into(), Severity::High),
            (
                "robot.ros2.unauthorized_motion_writer".into(),
                Severity::Critical
            ),
        ]
    );
    assert!(
        f.iter().all(|x| x.is_observe_only()),
        "a refused profile never enforces"
    );
    assert!(f.iter().all(|x| x.profile_status == "refused"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn fragmented_sedp_is_reassembled_and_flagged() {
    // The rogue announces its cmd_vel writer only through DATA_FRAG, three
    // RTPS messages, each in its own UDP datagram; the last one is also
    // IP-fragmented.
    let frags = sedp_fragmented(ROGUE, "rt/cmd_vel", TWIST, 300, 160);
    assert!(frags.len() >= 3, "{}", frags.len());
    let mut frames = vec![frame(
        ROBOT_IP,
        SPDP_GROUP,
        7400,
        &spdp_datagram(LEGIT, ROBOT_IP),
    )];
    let n = frags.len();
    for (i, d) in frags.iter().enumerate() {
        let ip = synth::ipv4_udp(ROGUE_IP, ROBOT_IP, 49152, 7410, d);
        if i + 1 == n {
            for piece in synth::ipv4_fragment(&ip, 64) {
                frames.push(synth::ethernet(0x0800, &piece));
            }
        } else {
            frames.push(synth::ethernet(0x0800, &ip));
        }
    }
    let mut p = Pipeline::new(robot_profile(true), PipelineOptions::default());
    let f = run(&pcap(&frames), &mut p);
    let r = rules_of(&f);
    assert!(r.contains(&(
        "robot.ros2.unauthorized_motion_writer".into(),
        Severity::Critical
    )));
    assert!(r.contains(&("robot.ros2.unknown_participant".into(), Severity::High)));
    assert!(r.contains(&(rules::FRAGMENTED_DISCOVERY.into(), Severity::Low)));
    assert_eq!(f.len(), 3, "{f:#?}");
    let s = p.stats();
    assert_eq!(s.discovery_fragments, n as u64);
    assert_eq!(s.fragment_samples_completed, 1);
    assert_eq!(s.fragments_rejected, 0);
    assert_eq!(p.reassembler().pending_samples(), 0);

    // Without fragmentation reporting, the writer is still caught.
    let mut q = Pipeline::new(
        robot_profile(true),
        PipelineOptions {
            report_fragmentation: false,
            ..Default::default()
        },
    );
    let f = run(&pcap(&frames), &mut q);
    assert_eq!(f.len(), 2);
}

#[test]
fn oversized_fragmented_sample_is_rejected_and_reported() {
    // A sample claiming 2 MiB is over the reassembly cap (512 KiB by
    // default, 1 MiB at most). An SEDP publication a DDS stack may accept
    // went uninspected: Critical.
    let mut d = header(ROGUE);
    d.extend(data_frag(
        ENTITY_SEDP_PUB_WRITER,
        1,
        1,
        1024,
        2 << 20,
        &[0u8; 1024],
    ));
    let frames = vec![frame(ROGUE_IP, ROBOT_IP, 7410, &d)];
    let mut p = Pipeline::new(robot_profile(true), PipelineOptions::default());
    let f = run(&pcap(&frames), &mut p);
    let r = rules_of(&f);
    assert!(
        r.contains(&(
            rules::DISCOVERY_FRAGMENT_REJECTED.into(),
            Severity::Critical
        )),
        "{r:?}"
    );
    assert_eq!(p.stats().fragments_rejected, 1);
    assert_eq!(p.reassembler().pending_bytes(), 0);
}

#[test]
fn legit_only_traffic_is_silent() {
    let frames: Vec<_> = scenario_frames(0)
        .into_iter()
        .take(4)
        .chain(std::iter::once(frame(
            ROBOT_IP,
            SPDP_GROUP,
            7400,
            &spdp_datagram(LEGIT, ROBOT_IP),
        )))
        .collect();
    let mut p = Pipeline::new(robot_profile(true), PipelineOptions::default());
    assert!(run(&pcap(&frames), &mut p).is_empty());
}

#[test]
fn pcap_file_on_disk_through_open_file() {
    let dir = temp_dir("open-file");
    let path = dir.join("lab.pcap");
    write(&path, &pcap(&scenario_frames(2)));
    let mut src = CaptureDatagramSource::open_file(&path, RtpsPortMap::ros2_default()).unwrap();
    let mut p = Pipeline::new(robot_profile(true), PipelineOptions::default());
    let mut n = 0;
    while let Some(d) = src.recv().unwrap() {
        n += p.process_datagram(&d).len();
    }
    assert_eq!(n, 2);
    assert_eq!(src.stats().filtered_out, 1);
    std::fs::remove_dir_all(&dir).ok();
}
