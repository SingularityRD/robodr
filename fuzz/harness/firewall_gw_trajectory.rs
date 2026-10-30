//! Harness: the gateway's ROS 2 joint-trajectory channels
//! (`robodr-firewall-gw`, `crate::trajectory`): the strict decoder (both
//! layouts, both request headers), the lenient probe, the bound check and
//! the in-place time scaling, through `Gateway::process`.
//!
//! Input: byte 0 = flags (bit 0: `on_velocity_violation: time_scale` on
//! both channels; bit 1: the goal channel expects the Cyclone request
//! header; bit 2: no SEDP announcement, so samples are classified by the
//! content probe). Then records `len (u16 LE) | kind (u8) | len bytes`:
//! `kind & 1` = 0 a `JointTrajectory` sample, 1 a `send_goal` request;
//! `kind & 2` an RTPS DATA from the attacker's IP. The raw record bytes
//! also go to `decode_strict` / `plausible` / `check` of every layout.
//!
//! Invariants beyond "no panic":
//! - `Accept` leaves the packet byte-identical; `AcceptModified` keeps its
//!   length and valid IP / UDP checksums;
//! - every trajectory sample forwarded on an enforced channel decodes
//!   strictly with the channel's layout and **passes** the channel's
//!   bounds (a time-scaled one after its rewrite): the gateway never
//!   forwards a trajectory it could not read or that is outside them;
//! - a time-scaled sample keeps its joint names, positions and efforts.
#![allow(dead_code)]

use std::time::Instant;

use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::rtps::{self, Content, WalkOptions};
use robodr_firewall_gw::testkit::{self};
use robodr_firewall_gw::trajectory::{self, GoalHeader, Layout, TrajectoryVerdict};
use robodr_firewall_gw::{PacketMeta, Verdict};

const TOPIC: &str = "rt/arm_controller/joint_trajectory";
const GOAL_TOPIC: &str = "rq/arm_controller/follow_joint_trajectory/_action/send_goalRequest";

/// The channel bounds of `testkit::trajectory_gateway` (effective speed
/// 1.0: the profile envelope caps the configured 1.5).
pub fn limits(time_scale: bool) -> trajectory::TrajectoryLimits {
    trajectory::TrajectoryLimits {
        joints: testkit::TRAJ_JOINTS
            .iter()
            .map(|n| trajectory::JointBounds {
                name: (*n).into(),
                min_position: -testkit::TRAJ_Q,
                max_position: testkit::TRAJ_Q,
                max_velocity: testkit::TRAJ_V,
                max_acceleration: testkit::TRAJ_A,
                max_effort: testkit::TRAJ_EFFORT,
            })
            .collect(),
        max_points: 64,
        max_duration_ns: 20_000_000_000,
        time_scale,
        max_time_scale: 4.0,
    }
}

/// A record.
pub fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = (body.len() as u16).to_le_bytes().to_vec();
    v.push(kind);
    v.extend_from_slice(body);
    v
}

pub fn run(data: &[u8]) {
    let Some((&flags, mut rest)) = data.split_first() else {
        return;
    };
    let time_scale = flags & 1 != 0;
    let cyclone = flags & 2 != 0;
    let goal_layout = Layout::Goal(if cyclone {
        GoalHeader::Cyclone
    } else {
        GoalHeader::None
    });
    for l in [
        Layout::Trajectory,
        Layout::Goal(GoalHeader::None),
        Layout::Goal(GoalHeader::Cyclone),
    ] {
        let _ = trajectory::plausible(rest, l);
        if let Ok(t) = trajectory::decode_strict(rest, l, 4096) {
            let _ = trajectory::check(&t, &limits(true));
        }
    }
    let mut gw = testkit::trajectory_gateway(|v| {
        for c in [1, 2] {
            if time_scale {
                v["channels"][c]["trajectory"]["on_velocity_violation"] = "time_scale".into();
            }
        }
        if cyclone {
            v["channels"][2]["trajectory"]["request_header"] = "cyclone".into();
        }
    });
    let meta = |now| PacketMeta {
        now_ns: now,
        queue_delay_ns: None,
        instant: Instant::now(),
        src_mac: None,
    };
    if flags & 4 == 0 {
        for (w, topic, ty) in [
            (
                testkit::TRAJ_WRITER,
                TOPIC,
                "trajectory_msgs::msg::dds_::JointTrajectory_",
            ),
            (
                testkit::GOAL_WRITER,
                GOAL_TOPIC,
                "control_msgs::action::dds_::FollowJointTrajectory_SendGoal_Request_",
            ),
        ] {
            let mut p = testkit::packet(
                testkit::CONTROLLER_IP,
                7410,
                &testkit::sedp_datagram(testkit::PREFIX, w, topic, ty),
            );
            gw.process(&mut p, meta(1));
        }
    }
    let mut now = 1_000_000_000u64;
    let mut records = 0;
    let mut sn = 0i64;
    while rest.len() >= 3 && records < 32 {
        records += 1;
        let len = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
        let kind = rest[2];
        let body = &rest[3..3 + len.min(rest.len() - 3)];
        rest = &rest[3 + body.len()..];
        let goal = kind & 1 != 0;
        let src = if kind & 2 != 0 {
            testkit::ATTACKER_IP
        } else {
            testkit::CONTROLLER_IP
        };
        let writer = if goal {
            testkit::GOAL_WRITER
        } else {
            testkit::TRAJ_WRITER
        };
        sn += 1;
        now += 50_000_000;
        let pkt = testkit::packet(
            src,
            testkit::DDS_PORT,
            &testkit::data_datagram(writer, sn, body),
        );
        let mut out = pkt.clone();
        let v = gw.process(&mut out, meta(now));
        match v {
            Verdict::Accept => assert_eq!(out, pkt, "Accept changed bytes"),
            Verdict::AcceptModified => {
                assert_eq!(out.len(), pkt.len());
                assert!(
                    parse_ipv4_udp(&out).is_ok(),
                    "bad checksums after a rewrite"
                );
            }
            Verdict::Drop => {}
        }
        if v == Verdict::Drop {
            continue;
        }
        let Ok(ip) = parse_ipv4_udp(&out) else {
            continue;
        };
        let d = &out[ip.payload()];
        let mut samples = Vec::new();
        if rtps::walk(d, WalkOptions::default(), &mut samples).is_err() {
            continue;
        }
        for s in samples
            .iter()
            .filter(|s| !s.builtin && s.content == Content::Data)
        {
            let Some(r) = s.payload.clone() else {
                continue;
            };
            // Only samples the gateway classified to an enforced channel
            // (an unknown writer the probe could not match is not a motion
            // channel's and passes).
            if gw
                .discovery()
                .writer(&s.writer)
                .and_then(|w| w.channel)
                .is_none()
            {
                continue;
            }
            let slot = &d[r];
            // Which channel did the gateway classify it to? Without SEDP
            // the probe may have put it on either: accept a strict pass on
            // either layout (both channels have the same bounds).
            let layouts = [Layout::Trajectory, goal_layout];
            let ok = layouts.iter().any(|l| {
                trajectory::decode_strict(slot, *l, 64)
                    .is_ok_and(|t| trajectory::check(&t, &limits(false)) == TrajectoryVerdict::Pass)
            });
            assert!(
                ok,
                "forwarded a trajectory that is undecodable or outside its bounds"
            );
            if v == Verdict::AcceptModified && slot != body {
                let l = if goal {
                    goal_layout
                } else {
                    Layout::Trajectory
                };
                if let (Ok(a), Ok(b)) = (
                    trajectory::decode_strict(slot, l, 64),
                    trajectory::decode_strict(body, l, 64),
                ) {
                    assert_eq!(a.joint_names, b.joint_names);
                    for (x, y) in a.points.iter().zip(&b.points) {
                        assert_eq!(x.positions, y.positions);
                        assert_eq!(x.effort, y.effort);
                    }
                }
            }
        }
    }
}
