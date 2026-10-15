//! The synthetic RTPS fixtures of `robodr-rtps` (`tests/fixtures/*.bin`),
//! wrapped into a pcap and run through `CaptureDatagramSource` ->
//! `Pipeline`. Expectations are derived from the fixtures' `.json` golden
//! snapshots, so this test follows them when they are re-blessed.

mod common;

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use common::*;
use robodr_capture::{CaptureFile, RtpsPortMap};
use robodr_events::profile::{Envelope, Profile};
use robodr_events::Severity;
use robodr_ros2_pipeline::{CaptureDatagramSource, DatagramSource, Pipeline, PipelineOptions};
use serde_json::Value;

const FIXTURE_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 10, 21);
const FASTDDS: &str = "010f3a7c2104000001000000";

struct Fixtures {
    pcap: Vec<u8>,
    datagrams: usize,
    participants: BTreeSet<String>,
    /// (kind, guid_prefix, topic)
    endpoints: BTreeSet<(String, String, String)>,
}

fn load() -> Fixtures {
    let dir = rtps_fixtures_dir();
    let mut bins: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    bins.sort();
    assert!(bins.len() >= 8, "fixtures missing in {}", dir.display());
    let mut frames = Vec::new();
    let mut participants = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    for bin in &bins {
        let bytes = std::fs::read(bin).unwrap();
        frames.push(frame(FIXTURE_IP, ROBOT_IP, 7410, &bytes));
        let golden: Value =
            serde_json::from_slice(&std::fs::read(bin.with_extension("json")).unwrap()).unwrap();
        for e in golden.as_array().unwrap() {
            let kind = e["kind"].as_str().unwrap().to_string();
            let g = e["guid_prefix"].as_str().unwrap().to_string();
            if kind == "participant" {
                participants.insert(g);
            } else {
                endpoints.insert((kind, g, e["topic"].as_str().unwrap().to_string()));
            }
        }
    }
    Fixtures {
        datagrams: frames.len(),
        pcap: pcap(&frames),
        participants,
        endpoints,
    }
}

fn run(bytes: &[u8], profile: Profile) -> (Vec<(String, Severity)>, Pipeline) {
    let mut src = CaptureDatagramSource::new(
        CaptureFile::new(bytes).unwrap(),
        robodr_ros2_pipeline::source::rtps_filter(RtpsPortMap::ros2_default()),
    );
    let mut p = Pipeline::new(profile, PipelineOptions::default());
    let mut out = Vec::new();
    while let Some(d) = src.recv().unwrap() {
        for f in p.process_datagram(&d) {
            assert!(!f.is_observe_only());
            out.push((f.deviation.rule.to_string(), f.deviation.severity));
        }
    }
    (out, p)
}

/// Everything in the fixtures, allowlisted.
fn allow_all(fx: &Fixtures) -> Profile {
    let mut p = Profile {
        model: "fixture-lab".into(),
        locked: true,
        participants: fx.participants.clone(),
        ..Default::default()
    };
    for t in ["/cmd_vel", "/scan"] {
        p.writer_topics.insert(t.into());
    }
    p.services.insert("/add_two_ints".into());
    p.actions.insert("/fibonacci".into());
    p
}

#[test]
fn fixtures_parse_cleanly_and_a_complete_profile_is_silent() {
    let fx = load();
    assert_eq!(fx.participants.len(), 4);
    let (f, p) = run(&fx.pcap, allow_all(&fx));
    assert!(f.is_empty(), "{f:?}");
    let s = p.stats();
    assert_eq!(s.datagrams as usize, fx.datagrams);
    assert_eq!(s.not_rtps, 0);
    assert_eq!(s.anomalies, 0);
    // One event per golden entry.
    assert_eq!(
        s.events as usize,
        fx.endpoints.len() + (fx.datagrams/* each datagram has >= 1 participant event */)
    );
}

#[test]
fn empty_locked_profile_flags_every_participant_and_endpoint_once() {
    let fx = load();
    let profile = Profile {
        model: "empty".into(),
        locked: true,
        ..Default::default()
    };
    let (f, _) = run(&fx.pcap, profile);
    let count = |rule: &str| f.iter().filter(|(r, _)| r == rule).count();
    assert_eq!(
        count("robot.ros2.unknown_participant"),
        fx.participants.len()
    );
    let writers = fx.endpoints.iter().filter(|e| e.0 == "writer").count();
    let readers = fx.endpoints.iter().filter(|e| e.0 == "reader").count();
    assert_eq!(
        count("robot.ros2.unknown_writer_topic")
            + count("robot.ros2.unknown_service")
            + count("robot.ros2.unknown_action"),
        writers
    );
    assert_eq!(count("robot.ros2.unknown_service"), 1);
    assert_eq!(count("robot.ros2.unknown_action"), 2);
    assert_eq!(count("robot.ros2.unknown_reader"), readers);
    assert_eq!(f.len(), fx.participants.len() + writers + readers);
}

#[test]
fn unprofiled_fastdds_participant_on_cmd_vel_is_critical() {
    let fx = load();
    let mut profile = allow_all(&fx);
    profile.participants.remove(FASTDDS);
    profile.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(0.5),
            max_joint_speed: None,
        },
    );
    let (f, _) = run(&fx.pcap, profile);
    assert_eq!(
        f,
        vec![
            ("robot.ros2.unknown_participant".to_string(), Severity::High),
            (
                "robot.ros2.unauthorized_motion_writer".to_string(),
                Severity::Critical
            ),
        ]
    );
}

#[test]
fn fixtures_fed_directly_match_capture_path() {
    // The same datagrams without the capture layer give the same findings.
    let fx = load();
    let profile = Profile {
        model: "empty".into(),
        locked: true,
        ..Default::default()
    };
    let (via_capture, _) = run(&fx.pcap, profile.clone());
    let mut p = Pipeline::new(profile, PipelineOptions::default());
    let mut direct = Vec::new();
    let mut bins: Vec<_> = std::fs::read_dir(rtps_fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    bins.sort();
    for b in bins {
        for f in p.process(&std::fs::read(b).unwrap(), &FIXTURE_IP.to_string()) {
            direct.push((f.deviation.rule.to_string(), f.deviation.severity));
        }
    }
    assert_eq!(via_capture, direct);
}
