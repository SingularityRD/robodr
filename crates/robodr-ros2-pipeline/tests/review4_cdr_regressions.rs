//! Review 4 (`robodr-cdr`) regressions, end to end through `Pipeline`: the
//! decoder's new errors / anomalies are surfaced as findings on the motion
//! decode path.

mod common;

#[path = "../../robodr-cdr/tests/common/mod.rs"]
mod cdrenc;

use std::time::{Duration, Instant};

use common::*;
use robodr_events::{RobotEvent, Severity};
use robodr_ros2_pipeline::{rules, Ingress, MotionOptions, Pipeline, PipelineOptions};

const JT: &str = "trajectory_msgs::msg::dds_::JointTrajectory_";

struct Run {
    p: Pipeline,
    t0: Instant,
    n: u64,
}

impl Run {
    fn started() -> Self {
        let mut r = Run {
            p: Pipeline::new(
                robot_profile(true),
                PipelineOptions {
                    motion: MotionOptions::default(),
                    ..Default::default()
                },
            ),
            t0: Instant::now(),
            n: 0,
        };
        let o = r.feed(&motion_discovery());
        assert!(o.is_empty(), "{o:?}");
        r
    }

    /// Returns (rule, severity, detail) of each finding.
    fn feed(&mut self, d: &[u8]) -> Vec<(String, Severity, String)> {
        self.feed_full(d).0
    }

    fn feed_full(&mut self, d: &[u8]) -> (Vec<(String, Severity, String)>, usize) {
        self.n += 1;
        let o = self.p.process_with_motion_at(
            d,
            &ROBOT_IP.to_string(),
            Ingress::Unknown,
            self.t0 + Duration::from_millis(self.n),
            1_000_000_000 + self.n,
        );
        let f = o
            .findings
            .iter()
            .map(|f| {
                (
                    f.deviation.rule.to_string(),
                    f.deviation.severity,
                    f.deviation.detail.clone(),
                )
            })
            .collect();
        (f, o.motion.len())
    }
}

fn cmd(payload: &[u8], sn: u32) -> Vec<u8> {
    datagram(
        LEGIT,
        &[user_data(CMD_WRITER, CMD_READER, sn, payload, true)],
    )
}

fn twist(id: u16, vx: f64, vy: f64) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend_from_slice(&[0, 0]);
    for v in [vx, vy, 0.0, 0.0, 0.0, 0.0] {
        p.extend_from_slice(&v.to_le_bytes());
    }
    p
}

#[test]
fn real_xcdr2_ids_decode_and_unknown_ids_are_undecodable_findings() {
    let mut r = Run::started();
    // CDR2_LE (0x0007), within the envelope: decoded, no finding.
    let (f, n) = r.feed_full(&cmd(&twist(0x0007, 0.5, 0.0), 1));
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(n, 1);
    // CDR2_LE over the envelope: the Critical rule fires (was invisible).
    let f = r.feed(&cmd(&twist(0x0007, 5.0, 0.0), 2));
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].0, "robot.motion.linear_over_envelope");
    assert_eq!(f[0].1, Severity::Critical);
    // The old wrong id 0x0011 is unknown: reported as undecodable.
    let (f, n) = r.feed_full(&cmd(&twist(0x0011, 5.0, 0.0), 3));
    assert_eq!(n, 0);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].0, rules::MOTION_UNDECODABLE_SAMPLE);
    assert_eq!(f[0].1, Severity::Medium);
    assert!(
        f[0].2.contains("unknown encapsulation 0x0011"),
        "{}",
        f[0].2
    );
}

#[test]
fn lateral_command_on_a_holonomic_base_hits_the_envelope() {
    let mut r = Run::started();
    let f = r.feed(&cmd(&twist(0x0001, 0.0, 5.0), 1));
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].0, "robot.motion.linear_over_envelope");
    let f = r.feed(&cmd(&twist(0x0001, 0.0, f64::NAN), 2));
    assert_eq!(f[0].0, "robot.motion.non_finite_command");
    assert_eq!(f[0].1, Severity::Critical);
}

#[test]
fn excess_trailing_bytes_are_a_low_finding_deduplicated() {
    let mut r = Run::started();
    // 3 bytes of end padding: nothing.
    let mut p = twist(0x0001, 0.1, 0.0);
    p.extend_from_slice(&[0; 3]);
    let f = r.feed(&cmd(&p, 1));
    assert!(f.is_empty(), "{f:?}");
    // 4000 bytes: a Low decode anomaly; the sample is still decoded.
    let mut p = twist(0x0001, 0.1, 0.0);
    p.extend_from_slice(&[0xAA; 4000]);
    let (f, n) = r.feed_full(&cmd(&p, 2));
    assert_eq!(n, 1);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].0, rules::MOTION_DECODE_ANOMALY);
    assert_eq!(f[0].1, Severity::Low);
    // A different amount from the same writer: same finding, deduplicated.
    let mut p = twist(0x0001, 0.1, 0.0);
    p.extend_from_slice(&[0xBB; 17]);
    assert!(r.feed(&cmd(&p, 3)).is_empty());
    assert_eq!(r.p.stats().motion.anomalies, 2);
}

#[test]
fn zero_length_string_is_undecodable() {
    let mut r = Run::started();
    let w = [0, 0, 0x40, 0x03];
    let mut p = vec![0x00, 0x01, 0, 0];
    for v in [0u32, 0, 0] {
        p.extend_from_slice(&v.to_le_bytes()); // stamp, frame_id length 0
    }
    p.extend_from_slice(&[0; 4]); // pad to 8
    for _ in 0..6 {
        p.extend_from_slice(&0f64.to_le_bytes());
    }
    let d = datagram(
        LEGIT,
        &[
            sedp_writer_sub(
                LEGIT,
                w,
                "rt/cmd_vel",
                "geometry_msgs::msg::dds_::TwistStamped_",
            ),
            user_data(w, CMD_READER, 1, &p, true),
        ],
    );
    let f = r.feed(&d);
    assert!(
        f.iter()
            .any(|f| f.0 == rules::MOTION_UNDECODABLE_SAMPLE && f.2.contains("length 0")),
        "{f:?}"
    );
}

#[test]
fn position_only_trajectory_is_reported_unverifiable_or_bounded() {
    let mut r = Run::started();
    let w = [0, 0, 0x50, 0x03];
    let pt = |pos: &'static [f64], sec: i32| cdrenc::PointSpec {
        positions: pos,
        velocities: &[],
        accelerations: &[],
        effort: &[],
        sec,
        nanosec: 0,
    };
    // Single position-only point: unverifiable (Medium), not silent.
    let one = cdrenc::joint_trajectory(
        robodr_cdr::Representation::CdrLe,
        &[b"j1"],
        &[pt(&[100.0], 0)],
    );
    let d = datagram(
        LEGIT,
        &[
            sedp_writer_sub(LEGIT, w, "rt/cmd_vel", JT),
            user_data(w, CMD_READER, 1, &one, true),
        ],
    );
    let (f, n) = r.feed_full(&d);
    assert_eq!(n, 1);
    let unv: Vec<_> = f
        .iter()
        .filter(|f| f.0 == rules::MOTION_UNVERIFIABLE_COMMAND)
        .collect();
    assert_eq!(unv.len(), 1, "{f:?}");
    assert_eq!(unv[0].1, Severity::Medium);
    assert_eq!(r.p.stats().motion.unverifiable, 1);
    // Two points, 100 rad in zero time: infinite speed, Critical.
    let jump = cdrenc::joint_trajectory(
        robodr_cdr::Representation::CdrLe,
        &[b"j1"],
        &[pt(&[0.0], 1), pt(&[100.0], 1)],
    );
    let o = r.p.process_with_motion_at(
        &datagram(LEGIT, &[user_data(w, CMD_READER, 2, &jump, true)]),
        &ROBOT_IP.to_string(),
        Ingress::Unknown,
        r.t0 + Duration::from_secs(1),
        2_000_000_000,
    );
    let RobotEvent::MotionCommand(c) = &o.motion[0].event else {
        panic!()
    };
    assert_eq!(c.joint_speed, Some(f64::INFINITY));
    assert!(o
        .findings
        .iter()
        .any(|f| f.deviation.rule == "robot.motion.non_finite_command"
            && f.deviation.severity == Severity::Critical));
}
