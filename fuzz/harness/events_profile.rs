//! Harness: model-profile JSON (`robodr_events::profile::Profile`) parse,
//! `validate` and `evaluate`.
//!
//! Input: arbitrary bytes, tried as JSON. Invariants beyond "no panic":
//!
//! * `validate` and `evaluate` are deterministic;
//! * an unlocked (observe-mode) profile only ever produces observe-only
//!   deviations, so it can never lead to an action;
//! * the profile survives a serialise/parse round trip with the same
//!   identity sets and the same validation verdict.
//!
//! Probe events are derived from the profile itself (every participant,
//! writer topic and envelope channel, with commands at, above and beyond
//! the limit, plus NaN / infinite / negative values) and from a fixed set of
//! hostile names, so evaluation reaches the deviation paths.
#![allow(dead_code)]

use robodr_events::graph::{Endpoint, Participant};
use robodr_events::profile::Profile;
use robodr_events::{MotionCommand, MotionFeedback, RobotEvent};

const HOSTILE_NAMES: [&str; 8] = [
    "",
    "/",
    "rt/cmd_vel",
    "rq/node/get_parametersRequest",
    "/a//b",
    "/\u{0}",
    "/cmd_vel\u{202e}",
    "ros_discovery_info",
];

fn speeds(limit: Option<f64>) -> Vec<Option<f64>> {
    let mut v = vec![
        None,
        Some(0.0),
        Some(-0.0),
        Some(f64::NAN),
        Some(f64::INFINITY),
        Some(f64::NEG_INFINITY),
        Some(f64::MAX),
        Some(-1.0),
    ];
    if let Some(l) = limit {
        v.extend([Some(l), Some(-l), Some(l * 1.5 + 1e-9), Some(l.next_up())]);
    }
    v
}

pub fn probe_events(p: &Profile) -> Vec<RobotEvent> {
    let mut ev = Vec::new();
    let guids: Vec<String> = p
        .participants
        .iter()
        .take(4)
        .cloned()
        .chain(["ffffffffffffffffffffffff".to_string(), String::new()])
        .collect();
    for g in &guids {
        ev.push(RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: g.clone(),
            src_ip: "198.51.100.7".into(),
            locators: vec![],
        }));
    }
    let topics: Vec<String> = p
        .writer_topics
        .iter()
        .chain(p.reader_topics.iter())
        .chain(p.raw_dds_topics.iter())
        .take(8)
        .cloned()
        .chain(HOSTILE_NAMES.iter().map(|s| s.to_string()))
        .collect();
    for t in &topics {
        for raw in [format!("rt{t}"), t.clone()] {
            let e = Endpoint {
                guid_prefix: guids[0].clone(),
                topic: raw,
                type_name: "std_msgs::msg::dds_::String_".into(),
            };
            ev.push(RobotEvent::Ros2WriterDiscovered(e.clone()));
            ev.push(RobotEvent::Ros2ReaderDiscovered(e));
        }
    }
    let channels: Vec<(String, Option<f64>, Option<f64>)> = p
        .motion_envelopes
        .iter()
        .take(4)
        .map(|(c, e)| (c.clone(), e.max_linear_speed, e.max_joint_speed))
        .chain([("/unprofiled".to_string(), None, None)])
        .collect();
    for (ch, lin, joint) in &channels {
        for s in speeds(*lin) {
            ev.push(RobotEvent::MotionCommand(MotionCommand {
                channel: ch.clone(),
                source_guid: Some(guids[0].clone()),
                linear_speed: s,
                joint_speed: None,
                angular_speed: s,
            }));
        }
        for s in speeds(*joint) {
            ev.push(RobotEvent::MotionCommand(MotionCommand {
                channel: ch.clone(),
                source_guid: None,
                linear_speed: None,
                joint_speed: s,
                angular_speed: None,
            }));
        }
        ev.push(RobotEvent::MotionFeedback(MotionFeedback {
            channel: ch.clone(),
            measured_linear_speed: Some(f64::NAN),
            measured_joint_speed: None,
            linear_velocity: Some(f64::INFINITY),
            angular_velocity: None,
            publisher_guid: Some(guids[0].clone()),
            timestamp_ns: u64::MAX,
        }));
    }
    ev
}

/// Run every check on a parsed profile (shared with the firewall harness).
pub fn check_profile(p: &Profile) {
    let verdict = p.validate();
    assert_eq!(verdict, p.validate(), "validate is not deterministic");
    for e in probe_events(p) {
        let d = p.evaluate(&e);
        assert_eq!(
            format!("{d:?}"),
            format!("{:?}", p.evaluate(&e)),
            "evaluate is not deterministic"
        );
        if let Some(d) = &d {
            if !p.locked {
                assert!(
                    d.is_observe_only(),
                    "unlocked profile produced an enforcing deviation {d:?} for {e:?}"
                );
            }
        }
    }
    let text = serde_json::to_string(p).expect("a Profile always serialises");
    let back: Profile = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("serialised profile does not parse: {e}\n{text}"));
    assert_eq!(back.model, p.model);
    assert_eq!(back.locked, p.locked);
    assert_eq!(back.participants, p.participants);
    assert_eq!(back.writer_topics, p.writer_topics);
    assert_eq!(
        back.motion_envelopes.keys().collect::<Vec<_>>(),
        p.motion_envelopes.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        back.validate().is_ok(),
        verdict.is_ok(),
        "round trip changed validity"
    );
}

pub fn run(data: &[u8]) {
    let Ok(p) = serde_json::from_slice::<Profile>(data) else {
        return;
    };
    check_profile(&p);
}
