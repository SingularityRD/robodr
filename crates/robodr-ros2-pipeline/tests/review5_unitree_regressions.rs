//! Review of the Unitree decoders (commit 958a2ae), end to end through
//! `Pipeline`: joint commands carry their torque / gain / position step,
//! and an aliased API id is a High finding.

mod common;

#[path = "../../robodr-cdr/tests/common/mod.rs"]
mod cdrenc;

use std::time::{Duration, Instant};

use common::*;
use robodr_cdr::Representation;
use robodr_events::profile::{Envelope, Profile};
use robodr_events::{RobotEvent, Severity};
use robodr_ros2_pipeline::{rules, Ingress, MotionOptions, Pipeline, PipelineOptions};

const HG_LOWCMD: &str = "unitree_hg::msg::dds_::LowCmd_";
const REQUEST: &str = "unitree_api::msg::dds_::Request_";

fn profile(env: Envelope) -> Profile {
    let mut p = robot_profile(true);
    p.motion_envelopes.insert("/cmd_vel".into(), env);
    p
}

struct Run {
    p: Pipeline,
    t0: Instant,
    n: u64,
}

impl Run {
    fn started(env: Envelope, w: [u8; 4], type_name: &str) -> Self {
        let mut r = Run {
            p: Pipeline::new(
                profile(env),
                PipelineOptions {
                    motion: MotionOptions::default(),
                    ..Default::default()
                },
            ),
            t0: Instant::now(),
            n: 0,
        };
        let (f, _) = r.feed(&motion_discovery());
        assert!(f.is_empty(), "{f:?}");
        let (f, _) = r.feed(&datagram(
            LEGIT,
            &[sedp_writer_sub(LEGIT, w, "rt/cmd_vel", type_name)],
        ));
        assert!(f.is_empty(), "{f:?}");
        r
    }

    fn feed(&mut self, d: &[u8]) -> (Vec<(String, Severity)>, Vec<RobotEvent>) {
        self.n += 1;
        let o = self.p.process_with_motion_at(
            d,
            &ROBOT_IP.to_string(),
            Ingress::Unknown,
            self.t0 + Duration::from_millis(self.n),
            1_000_000_000 + self.n,
        );
        (
            o.findings
                .iter()
                .map(|f| (f.deviation.rule.to_string(), f.deviation.severity))
                .collect(),
            o.motion.into_iter().map(|m| m.event).collect(),
        )
    }
}

/// An hg `LowCmd_` whose slot 4 is (mode, q, dq, tau, kp, kd).
fn hg_low_cmd(slot4: (u8, f32, f32, f32, f32, f32)) -> Vec<u8> {
    let mut e = cdrenc::Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.byte(0);
        e.byte(0);
        e.nonprim_seq(|e| {
            for i in 0..35 {
                let m = if i == 4 {
                    slot4
                } else {
                    (0, 0.0, 0.0, 0.0, 0.0, 0.0)
                };
                e.byte(m.0);
                for v in [m.1, m.2, m.3, m.4, m.5] {
                    e.f32(v);
                }
                e.u32(0);
            }
        });
        for _ in 0..4 {
            e.u32(0);
        }
        e.u32(0);
    });
    e.finish()
}

#[test]
fn joint_frames_carry_torque_gain_and_position_step() {
    let w = [0, 0, 0x60, 0x03];
    let env = Envelope {
        max_joint_speed: Some(2.0),
        max_joint_torque: Some(30.0),
        max_joint_kp: Some(100.0),
        max_joint_position_step: Some(0.05),
        ..Default::default()
    };
    let mut r = Run::started(env, w, HG_LOWCMD);
    let send = |r: &mut Run, sn: u32, m| {
        r.feed(&datagram(
            LEGIT,
            &[user_data(w, CMD_READER, sn, &hg_low_cmd(m), true)],
        ))
    };
    // First frame: kp 60 at q 0.0, mode 0 (arm-SDK style): no step yet.
    let (f, ev) = send(&mut r, 1, (0, 0.0, 0.0, 5.0, 60.0, 1.0));
    assert!(f.is_empty(), "{f:?}");
    let RobotEvent::MotionCommand(c) = &ev[0] else {
        panic!("{ev:?}")
    };
    assert_eq!(c.joint_torque, Some(5.0));
    assert_eq!(c.joint_kp, Some(60.0));
    assert_eq!(c.joint_position_step, None);
    // A small step is fine.
    let (f, ev) = send(&mut r, 2, (0, 0.02, 0.0, 5.0, 60.0, 1.0));
    assert!(f.is_empty(), "{f:?}");
    let RobotEvent::MotionCommand(c) = &ev[0] else {
        panic!()
    };
    assert!((c.joint_position_step.unwrap() - 0.02).abs() < 1e-6);
    // A 1 rad jump of the position target: Critical.
    let (f, _) = send(&mut r, 3, (0, 1.02, 0.0, 5.0, 60.0, 1.0));
    assert_eq!(
        f,
        vec![(
            "robot.motion.joint_over_envelope".to_string(),
            Severity::Critical
        )]
    );
    // A torque-only frame of 500 N·m: Critical.
    let (f, _) = send(&mut r, 4, (1, 0.0, 0.0, 500.0, 0.0, 0.0));
    assert_eq!(
        f,
        vec![(
            "robot.motion.joint_over_envelope".to_string(),
            Severity::Critical
        )]
    );
}

#[test]
fn torque_frame_without_a_torque_bound_is_unverifiable() {
    let w = [0, 0, 0x61, 0x03];
    let mut r = Run::started(
        Envelope {
            max_joint_speed: Some(2.0),
            ..Default::default()
        },
        w,
        HG_LOWCMD,
    );
    let (f, _) = r.feed(&datagram(
        LEGIT,
        &[user_data(
            w,
            CMD_READER,
            1,
            &hg_low_cmd((1, 0.0, 0.0, 500.0, 0.0, 0.0)),
            true,
        )],
    ));
    assert_eq!(
        f,
        vec![(
            rules::MOTION_UNVERIFIABLE_COMMAND.to_string(),
            Severity::Medium
        )]
    );
}

fn api_request(api_id: i64, parameter: &[u8]) -> Vec<u8> {
    let mut e = cdrenc::Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.structure(|e| {
            e.structure(|e| {
                e.i64(1);
                e.i64(api_id);
            });
            e.structure(|e| e.i64(0));
            e.structure(|e| {
                e.i32(0);
                e.byte(0);
            });
        });
        e.string(parameter);
        e.octet_seq(&[]);
    });
    e.finish()
}

#[test]
fn aliased_api_id_is_a_high_finding() {
    let w = [0, 0, 0x62, 0x03];
    let mut r = Run::started(
        Envelope {
            max_linear_speed: Some(1.0),
            ..Default::default()
        },
        w,
        REQUEST,
    );
    // In range: an unknown call on an unspecified service (the channel is
    // /cmd_vel, not /api/<svc>/request) is flagged by the profile only.
    let (f, _) = r.feed(&datagram(
        LEGIT,
        &[user_data(
            w,
            CMD_READER,
            1,
            &api_request(1008, br#"{"x":0.5,"y":0,"z":0}"#),
            true,
        )],
    ));
    assert!(
        !f.iter().any(|x| x.0 == rules::MOTION_API_ID_OUT_OF_RANGE),
        "{f:?}"
    );
    let (f, ev) = r.feed(&datagram(
        LEGIT,
        &[user_data(
            w,
            CMD_READER,
            2,
            &api_request((1i64 << 32) + 1008, br#"{"x":5.0,"y":0,"z":0}"#),
            true,
        )],
    ));
    assert!(
        f.contains(&(
            rules::MOTION_API_ID_OUT_OF_RANGE.to_string(),
            Severity::High
        )),
        "{f:?}"
    );
    // ... and the call is read as the robot reads it: Move at 5 m/s.
    let RobotEvent::MotionCommand(c) = &ev[0] else {
        panic!()
    };
    assert_eq!(c.linear_speed, Some(5.0));
    assert!(
        f.contains(&(
            "robot.motion.linear_over_envelope".to_string(),
            Severity::Critical
        )),
        "{f:?}"
    );
}
