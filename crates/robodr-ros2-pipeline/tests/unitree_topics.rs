//! Every Unitree SDK2 topic the decoders cover goes through the live
//! pipeline: SEDP announces the writer with its DDS type name
//! (`unitree_go::msg::dds_::LowCmd_`, ...), the topic `rt/...` is
//! de-mangled like a ROS topic (`rt/api/sport/request` ->
//! `/api/sport/request`, `rt/dex3/left/cmd` -> `/dex3/left/cmd`), the
//! user DATA is CDR-decoded by the announced type and mapped to a
//! `MotionCommand` / `MotionFeedback`; low-level joint commands carry their
//! per-slot frame (for the joint firewall). Plus the model-aware API
//! interpretation and the legacy UDP path's pipeline-level behaviour.

mod common;

use std::time::{Duration, Instant};

use common::*;
use robodr_cdr::{Limits, UnitreeKind};
use robodr_events::graph::{demangle, RosNameKind};
use robodr_events::profile::{Envelope, Profile};
use robodr_events::RobotEvent;
use robodr_ros2_pipeline::{
    rules, Ingress, LegacyOptions, LegacyUdp, MotionOptions, Pipeline, PipelineOptions,
};

const P: [u8; 12] = [0x51; 12];

/// The smallest all-zero CDR_LE payload a fixed-size Unitree type decodes
/// from without trailing bytes (sequence types decode as empty).
fn zero_payload(kind: UnitreeKind) -> Vec<u8> {
    for len in 0..4096 {
        let mut p = vec![0x00, 0x01, 0, 0];
        p.extend(std::iter::repeat_n(0u8, len));
        if let Ok(d) = robodr_cdr::decode_unitree(kind, &p, &Limits::default()) {
            if d.trailing_bytes == 0 {
                return p;
            }
        }
    }
    panic!("{kind:?}: no zero payload decodes");
}

fn joint_env() -> Envelope {
    Envelope {
        max_joint_speed: Some(10.0),
        max_joint_torque: Some(100.0),
        max_joint_kp: Some(500.0),
        max_joint_position_step: Some(0.5),
        ..Default::default()
    }
}

struct Topic {
    rt: &'static str,
    kind: UnitreeKind,
    command: bool,
}

const TOPICS: &[Topic] = &[
    Topic {
        rt: "rt/lowcmd",
        kind: UnitreeKind::HgLowCmd,
        command: true,
    },
    Topic {
        rt: "rt/user_lowcmd",
        kind: UnitreeKind::HgLowCmd,
        command: true,
    },
    Topic {
        rt: "rt/arm_sdk",
        kind: UnitreeKind::HgLowCmd,
        command: true,
    },
    Topic {
        rt: "rt/hand_sdk",
        kind: UnitreeKind::GoMotorCmds,
        command: true,
    },
    Topic {
        rt: "rt/dex3/left/cmd",
        kind: UnitreeKind::HgHandCmd,
        command: true,
    },
    Topic {
        rt: "rt/dex3/right/cmd",
        kind: UnitreeKind::HgHandCmd,
        command: true,
    },
    Topic {
        rt: "rt/waistpitchcmd",
        kind: UnitreeKind::HgMotorCmd,
        command: true,
    },
    Topic {
        rt: "rt/api/sport/request",
        kind: UnitreeKind::ApiRequest,
        command: true,
    },
    Topic {
        rt: "rt/lowstate",
        kind: UnitreeKind::HgLowState,
        command: false,
    },
    Topic {
        rt: "rt/lf/lowstate",
        kind: UnitreeKind::GoLowState,
        command: false,
    },
    Topic {
        rt: "rt/sportmodestate",
        kind: UnitreeKind::GoSportModeState,
        command: false,
    },
    Topic {
        rt: "rt/lf/sportmodestate",
        kind: UnitreeKind::GoSportModeState,
        command: false,
    },
    Topic {
        rt: "rt/secondary_imu",
        kind: UnitreeKind::HgImuState,
        command: false,
    },
    Topic {
        rt: "rt/waistpitchstate",
        kind: UnitreeKind::HgMotorState,
        command: false,
    },
    Topic {
        rt: "rt/dex3/left/state",
        kind: UnitreeKind::HgHandState,
        command: false,
    },
    Topic {
        rt: "rt/lf/dex3/right/state",
        kind: UnitreeKind::HgHandState,
        command: false,
    },
];

fn payload(t: &Topic) -> Vec<u8> {
    if t.kind == UnitreeKind::ApiRequest {
        // StopMove: a known call with no argument.
        let mut p = vec![0x00, 0x01, 0, 0];
        p.extend_from_slice(&1i64.to_le_bytes()); // identity.id
        p.extend_from_slice(&1003i64.to_le_bytes()); // identity.api_id
        p.extend_from_slice(&0i64.to_le_bytes()); // lease.id
        p.extend_from_slice(&0i32.to_le_bytes()); // policy.priority
        p.extend_from_slice(&[0, 0, 0, 0]); // noreply + pad
        p.extend_from_slice(&3u32.to_le_bytes()); // parameter "{}"
        p.extend_from_slice(b"{}\0");
        p.push(0); // pad
        p.extend_from_slice(&0u32.to_le_bytes()); // binary
        return p;
    }
    zero_payload(t.kind)
}

#[test]
fn unitree_topic_names_demangle_as_ros_topics() {
    for t in TOPICS {
        let rn = demangle(t.rt);
        assert_eq!(rn.kind, RosNameKind::Topic, "{}", t.rt);
        assert_eq!(rn.name, &t.rt[2..], "{}", t.rt);
    }
    for (rt, name) in [
        ("rt/api/sport/response", "/api/sport/response"),
        (
            "rt/api/motion_switcher/request",
            "/api/motion_switcher/request",
        ),
        ("rt/wirelesscontroller", "/wirelesscontroller"),
        ("rt/lf/dex3/left/state", "/lf/dex3/left/state"),
    ] {
        let rn = demangle(rt);
        assert_eq!((rn.kind, rn.name.as_str()), (RosNameKind::Topic, name));
    }
}

#[test]
fn every_unitree_topic_decodes_through_the_pipeline() {
    let mut profile = Profile {
        model: "unitree-topics".into(),
        locked: true,
        ..Default::default()
    };
    profile.participants.insert(hex(&P));
    let mut feedback = std::collections::BTreeSet::new();
    for t in TOPICS {
        let ch = demangle(t.rt).name;
        profile.writer_topics.insert(ch.clone());
        if t.command {
            let env = if t.kind == UnitreeKind::ApiRequest {
                Envelope {
                    max_linear_speed: Some(1.0),
                    ..Default::default()
                }
            } else {
                joint_env()
            };
            profile.motion_envelopes.insert(ch, env);
        } else {
            feedback.insert(ch);
        }
    }
    profile.validate().unwrap();
    let mut p = Pipeline::new(
        profile,
        PipelineOptions {
            motion: MotionOptions {
                feedback_topics: feedback,
                ..MotionOptions::default()
            },
            ..Default::default()
        },
    );
    let t0 = Instant::now();
    let mut n = 0u64;
    let mut feed = |p: &mut Pipeline, d: &[u8]| {
        n += 1;
        p.process_with_motion_at(
            d,
            &ROBOT_IP.to_string(),
            Ingress::Unknown,
            t0 + Duration::from_millis(n),
            n,
        )
    };
    let mut subs = vec![spdp_sub(P, &[ROBOT_IP])];
    for (i, t) in TOPICS.iter().enumerate() {
        subs.push(sedp_writer_sub(
            P,
            [0, 0, i as u8 + 1, 3],
            t.rt,
            t.kind.dds_type_name(),
        ));
    }
    let o = feed(&mut p, &datagram(P, &subs));
    assert!(o.findings.is_empty(), "{:?}", o.findings);
    for (i, t) in TOPICS.iter().enumerate() {
        let d = datagram(
            P,
            &[user_data(
                [0, 0, i as u8 + 1, 3],
                [0; 4],
                1,
                &payload(t),
                true,
            )],
        );
        let o = feed(&mut p, &d);
        assert!(o.findings.is_empty(), "{}: {:?}", t.rt, o.findings);
        assert_eq!(o.motion.len(), 1, "{}", t.rt);
        let s = &o.motion[0];
        assert_eq!(s.topic, t.rt);
        assert_eq!(s.type_name, t.kind.dds_type_name());
        match (&s.event, t.command) {
            (RobotEvent::MotionCommand(c), true) => assert_eq!(c.channel, &t.rt[2..]),
            (RobotEvent::MotionFeedback(f), false) => assert_eq!(f.channel, &t.rt[2..]),
            (e, _) => panic!("{}: {e:?}", t.rt),
        }
        let joint = matches!(
            t.kind,
            UnitreeKind::HgLowCmd
                | UnitreeKind::GoMotorCmds
                | UnitreeKind::HgHandCmd
                | UnitreeKind::HgMotorCmd
        );
        assert_eq!(s.joint.is_some(), joint, "{}", t.rt);
        if let Some(j) = &s.joint {
            if t.kind == UnitreeKind::HgLowCmd {
                assert_eq!(j.frame.as_slice().len(), 35);
                assert_eq!((j.mode_pr, j.mode_machine), (Some(0), Some(0)));
                // An all-zero frame does not carry the SDK's CRC.
                assert_eq!(j.crc_ok, Some(false));
            } else {
                assert_eq!((j.mode_pr, j.crc_ok), (None, None));
            }
        }
    }
    let st = p.stats().motion;
    assert_eq!(st.undecodable, 0);
    assert_eq!(st.commands, 8);
    assert_eq!(st.feedback, 8);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `SwitchToUserCtrl` (G1 loco 7110) and `SetStandHeight` (7104): `Unknown`
/// (High) without the model; with `robot_model` G1 the handover is a
/// `control_handover` finding and the posture call none.
#[test]
fn model_specific_api_ids_are_classified_with_the_model() {
    let run = |model: Option<robodr_cdr::UnitreeModel>| {
        let mut profile = Profile {
            model: "g1".into(),
            locked: true,
            ..Default::default()
        };
        profile.participants.insert(hex(&P));
        profile.writer_topics.insert("/api/sport/request".into());
        profile.motion_envelopes.insert(
            "/api/sport/request".into(),
            Envelope {
                max_linear_speed: Some(1.0),
                ..Default::default()
            },
        );
        let mut p = Pipeline::new(
            profile,
            PipelineOptions {
                motion: MotionOptions {
                    robot_model: model,
                    ..MotionOptions::default()
                },
                ..Default::default()
            },
        );
        let w = [0, 0, 9, 3];
        let mut out = Vec::new();
        for (i, d) in [
            datagram(
                P,
                &[
                    spdp_sub(P, &[ROBOT_IP]),
                    sedp_writer_sub(
                        P,
                        w,
                        "rt/api/sport/request",
                        "unitree_api::msg::dds_::Request_",
                    ),
                ],
            ),
            datagram(P, &[user_data(w, [0; 4], 1, &request(7110, "{}"), true)]),
            datagram(
                P,
                &[user_data(
                    w,
                    [0; 4],
                    2,
                    &request(7104, r#"{"data":0.7}"#),
                    true,
                )],
            ),
        ]
        .iter()
        .enumerate()
        {
            let o = p.process_with_motion_at(
                d,
                &ROBOT_IP.to_string(),
                Ingress::Unknown,
                Instant::now() + Duration::from_millis(i as u64),
                i as u64,
            );
            out.extend(
                o.findings
                    .into_iter()
                    .map(|f| (f.deviation.rule.to_string(), f.deviation.detail.clone())),
            );
        }
        out
    };
    let none = run(None);
    assert_eq!(none.len(), 2, "{none:?}");
    assert!(none
        .iter()
        .all(|(r, _)| r == "robot.motion.unverifiable_command"));
    let g1 = run(Some(robodr_cdr::UnitreeModel::G1));
    assert_eq!(g1.len(), 1, "{g1:?}");
    assert_eq!(g1[0].0, "robot.motion.control_handover");
    assert!(g1[0].1.contains("SwitchToUserCtrl"), "{g1:?}");
}

fn request(api_id: i64, param: &str) -> Vec<u8> {
    let mut p = vec![0x00, 0x01, 0, 0];
    p.extend_from_slice(&1i64.to_le_bytes());
    p.extend_from_slice(&api_id.to_le_bytes());
    p.extend_from_slice(&0i64.to_le_bytes());
    p.extend_from_slice(&0i32.to_le_bytes());
    p.extend_from_slice(&[0, 0, 0, 0]);
    let s = param.as_bytes();
    p.extend_from_slice(&(s.len() as u32 + 1).to_le_bytes());
    p.extend_from_slice(s);
    p.push(0);
    while (p.len() - 4) % 4 != 0 {
        p.push(0);
    }
    p.extend_from_slice(&0u32.to_le_bytes());
    p
}

/// The legacy UDP path at the pipeline: ignored (counted) while off; on, a
/// command from an unlisted sender is Critical, a compressed `LowState`
/// undecodable (a compressed `LowCmd` decodes), and every finding is
/// deduplicated.
#[test]
fn legacy_udp_at_the_pipeline() {
    use robodr_cdr::unitree_legacy::channels;
    let mut profile = Profile {
        model: "go1".into(),
        locked: true,
        ..Default::default()
    };
    profile.writer_topics.insert(channels::HIGH_CMD.into());
    profile.motion_envelopes.insert(
        channels::HIGH_CMD.into(),
        Envelope {
            max_linear_speed: Some(1.0),
            ..Default::default()
        },
    );
    let mut high = vec![0u8; robodr_cdr::unitree_legacy::LEGACY_HIGH_CMD_LEN];
    high[22] = 2; // mode: target-velocity walking
    high[53..57].copy_from_slice(&3.0f32.to_le_bytes()); // velocity[0]
    let udp = LegacyUdp::new(8090, 8082, "192.168.123.161".parse().unwrap());
    // Off.
    let mut off = Pipeline::new(profile.clone(), PipelineOptions::default());
    let o = off.process_legacy_at(&high, "192.168.123.15", &udp, Instant::now(), 1);
    assert!(o.findings.is_empty() && o.motion.is_empty());
    assert_eq!(off.stats().legacy.ignored, 1);
    // On.
    let mut on = Pipeline::new(
        profile,
        PipelineOptions {
            legacy: LegacyOptions {
                enabled: true,
                command_senders: ["192.168.123.15".parse().unwrap()].into_iter().collect(),
                ..LegacyOptions::default()
            },
            ..Default::default()
        },
    );
    let t0 = Instant::now();
    let o = on.process_legacy_at(&high, "192.168.123.15", &udp, t0, 1);
    let rules: Vec<_> = o
        .findings
        .iter()
        .map(|f| f.deviation.rule.to_string())
        .collect();
    assert_eq!(
        rules,
        ["robot.motion.linear_over_envelope"],
        "{:?}",
        o.findings
    );
    assert_eq!(o.motion.len(), 1);
    assert_eq!(o.motion[0].topic, channels::HIGH_CMD);
    match &o.motion[0].event {
        RobotEvent::MotionCommand(c) => {
            assert_eq!(c.linear_speed, Some(3.0));
            assert_eq!(c.source_guid, None);
        }
        e => panic!("{e:?}"),
    }
    for i in 0..3 {
        let o = on.process_legacy_at(&high, "192.168.123.66", &udp, t0, 2 + i);
        if i == 0 {
            let f = o
                .findings
                .iter()
                .find(|f| f.deviation.rule == rules::LEGACY_UNKNOWN_SENDER)
                .expect("unknown sender");
            assert_eq!(f.deviation.severity, robodr_events::Severity::Critical);
            assert_eq!(f.src_ip, "192.168.123.66");
        } else {
            assert!(o.findings.is_empty(), "deduplicated: {:?}", o.findings);
        }
    }
    let o = on.process_legacy_at(&[0x5a; 807], "192.168.123.10", &udp, t0, 9);
    assert_eq!(o.findings.len(), 1);
    assert_eq!(
        o.findings[0].deviation.rule,
        rules::MOTION_UNDECODABLE_SAMPLE
    );
    assert!(o.motion.is_empty());
    let st = on.stats().legacy;
    assert_eq!((st.commands, st.unknown_sender, st.undecodable), (4, 3, 1));
}
