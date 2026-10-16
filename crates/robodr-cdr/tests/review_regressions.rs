//! Regression tests for the independent review (rev4) of `robodr-cdr`.
//!
//! Each test is a reviewer PoC (`/home/claude/rev4/.../review_poc.rs`)
//! turned around: it asserts the **fixed** behaviour. The hand encoder below
//! is the reviewer's, independent of the crate and of `tests/common`.

use robodr_cdr::*;
use robodr_events::profile::{Envelope, Profile};
use robodr_events::{RobotEvent, Severity};

/// Minimal independent XCDR writer (LE only).
struct W {
    b: Vec<u8>,
    max_align: usize,
}
impl W {
    fn new(id: u16, max_align: usize) -> Self {
        let mut b = id.to_be_bytes().to_vec();
        b.extend_from_slice(&[0, 0]);
        W { b, max_align }
    }
    fn pad(&mut self, a: usize) {
        let a = a.min(self.max_align);
        while !(self.b.len() - 4).is_multiple_of(a) {
            self.b.push(0);
        }
    }
    fn u32(&mut self, v: u32) {
        self.pad(4);
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn f(&mut self, v: f64) {
        self.pad(8);
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn s(&mut self, s: &str) {
        self.u32(s.len() as u32 + 1);
        self.b.extend_from_slice(s.as_bytes());
        self.b.push(0);
    }
}

fn l() -> Limits {
    Limits::default()
}
fn ctx() -> EventContext<'static> {
    EventContext {
        channel: "/cmd_vel",
        writer_guid: None,
        timestamp_ns: 0,
    }
}
fn twist_payload(id: u16, v: [f64; 6]) -> Vec<u8> {
    let mut w = W::new(id, 8);
    for x in v {
        w.f(x);
    }
    w.b
}

fn profile() -> Profile {
    let mut p = Profile {
        model: "ugv".into(),
        locked: true,
        ..Default::default()
    };
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(1.0),
            max_joint_speed: Some(1.0),
            ..Default::default()
        },
    );
    p
}

// ---------------------------------------------------------------- F1 (High)

/// XTypes 1.3 Table 60 / Cyclone DDS / Fast CDR identifiers decode; the
/// never-assigned 0x0010..0x0015 range (the old, wrong mapping) is unknown.
#[test]
fn f1_xcdr2_encapsulation_ids_follow_xtypes_table_60() {
    let table = [
        (0x0000u16, Representation::CdrBe),
        (0x0001, Representation::CdrLe),
        (0x0002, Representation::PlCdrBe),
        (0x0003, Representation::PlCdrLe),
        (0x0004, Representation::Xml),
        (0x0006, Representation::Cdr2Be),
        (0x0007, Representation::Cdr2Le),
        (0x0008, Representation::DCdr2Be),
        (0x0009, Representation::DCdr2Le),
        (0x000a, Representation::PlCdr2Be),
        (0x000b, Representation::PlCdr2Le),
    ];
    for (id, rep) in table {
        assert_eq!(Representation::from_id(id), Some(rep), "0x{id:04x}");
        assert_eq!(rep.id(), id);
    }
    for id in [
        0x0005u16, 0x000c, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015,
    ] {
        assert_eq!(Representation::from_id(id), None, "0x{id:04x}");
    }
    // A Twist's CDR2 body is byte-identical to XCDR1 (all doubles from @0):
    // a real CDR2_LE (0x0007) sample decodes now.
    let p = twist_payload(0x0007, [5.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
    let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
    assert_eq!(d.encapsulation.representation, Representation::Cdr2Le);
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!(c.linear_speed, Some(5.0));
    // CDR2_BE too.
    let mut p = 0x0006u16.to_be_bytes().to_vec();
    p.extend_from_slice(&[0, 0]);
    for x in [-2.0f64, 0.0, 0.0, 0.0, 0.0, 0.5] {
        p.extend_from_slice(&x.to_be_bytes());
    }
    let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!((c.linear_speed, c.angular_speed), (Some(-2.0), Some(0.5)));
    // Parameter-list XCDR2 is recognised and refused.
    for (id, rep) in [
        (0x000au16, Representation::PlCdr2Be),
        (0x000b, Representation::PlCdr2Le),
    ] {
        assert_eq!(
            decode_payload(MessageKind::Twist, &twist_payload(id, [0.0; 6]), &l()),
            Err(DecodeError::UnsupportedRepresentation(rep))
        );
    }
    // The old, wrong ids are now unknown (decode error, reported upstream).
    for id in 0x0010u16..=0x0015 {
        assert_eq!(
            decode_payload(MessageKind::Twist, &twist_payload(id, [0.0; 6]), &l()),
            Err(DecodeError::UnknownRepresentation(id))
        );
    }
}

/// D_CDR2_LE (0x0009) with the default nesting (every struct delimited).
#[test]
fn f1_d_cdr2_le_with_real_id_decodes() {
    let mut w = W::new(0x0009, 4);
    w.u32(56); // DHEADER(Twist)
    for v in [[0.25, 0.0, 0.0], [0.0, 0.0, -0.5]] {
        w.u32(24);
        for x in v {
            w.f(x);
        }
    }
    let d = decode_payload(MessageKind::Twist, &w.b, &l()).unwrap();
    assert_eq!(d.trailing_bytes, 0);
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!((c.linear_speed, c.angular_speed), (Some(0.25), Some(-0.5)));
}

// ---------------------------------------------------------------- F2 (Medium)

// F2 was first fixed by folding every Twist axis into a signed magnitude.
// Since `MotionCommand` carries all six axes, the same safety properties are
// asserted on the per-axis mapping: nothing a hostile writer puts in a
// non-x / non-z component escapes the envelope or the non-finite rule.

#[test]
fn f2_lateral_and_non_finite_components_reach_the_command() {
    // Lateral 50 m/s: carried as linear_y, bounded by the resultant check
    // (the envelope is not holonomic and has no lateral limit).
    let p = twist_payload(0x0001, [0.0, 50.0, 0.0, 0.0, 0.0, 0.0]);
    let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!(c.linear_speed, Some(0.0));
    assert_eq!(c.linear_y, Some(50.0));
    assert_eq!(c.angular_speed, Some(0.0));
    let dev = profile().evaluate(&RobotEvent::MotionCommand(c)).unwrap();
    assert_eq!(dev.rule_str(), "robot.motion.linear_over_envelope");
    assert_eq!(dev.severity, Severity::Critical);

    // NaN / ±inf in any component → that axis is non-finite → Critical.
    for (i, bad) in [
        (0, f64::NAN),
        (1, f64::NAN),
        (2, f64::INFINITY),
        (1, f64::NEG_INFINITY),
        (3, f64::NAN),
        (4, f64::INFINITY),
        (5, -f64::NAN),
    ] {
        let mut v = [0.0; 6];
        v[i] = bad;
        let p = twist_payload(0x0001, v);
        let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
        let c = d.message.to_command(&ctx()).unwrap();
        let axes = [
            c.linear_speed,
            c.linear_y,
            c.linear_z,
            c.angular_x,
            c.angular_y,
            c.angular_speed,
        ];
        for (j, a) in axes.iter().enumerate() {
            let a = a.expect("every Twist axis is carried");
            assert_eq!(a.is_finite(), j != i, "component {j} for bad {i}: {a}");
        }
        let dev = profile().evaluate(&RobotEvent::MotionCommand(c)).unwrap();
        assert_eq!(dev.rule_str(), "robot.motion.non_finite_command");
        assert_eq!(dev.severity, Severity::Critical);
    }

    // Finite components whose resultant overflows → over envelope.
    let p = twist_payload(0x0001, [0.5, f64::MAX, f64::MAX, 0.0, 0.0, 0.0]);
    let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!(c.linear_resultant(), Some(f64::INFINITY));
    let dev = profile().evaluate(&RobotEvent::MotionCommand(c)).unwrap();
    assert_eq!(dev.rule_str(), "robot.motion.linear_over_envelope");
}

#[test]
fn f2_sign_of_x_and_z_is_kept_and_planar_commands_are_unchanged() {
    // Differential drive (y = z = 0): exactly linear.x / angular.z.
    let p = twist_payload(0x0001, [-0.4, 0.0, 0.0, 0.0, 0.0, -1.2]);
    let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!((c.linear_speed, c.angular_speed), (Some(-0.4), Some(-1.2)));
    assert_eq!((c.linear_y, c.linear_z), (Some(0.0), Some(0.0)));
    // Reversing diagonally: each axis signed, as sent (no folded magnitude).
    let p = twist_payload(0x0001, [-3.0, 4.0, 0.0, 0.0, 0.0, 0.0]);
    let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!((c.linear_speed, c.linear_y), (Some(-3.0), Some(4.0)));
    assert_eq!(c.linear_resultant(), Some(5.0));
    // Roll / pitch rates go to their own axes; yaw stays angular.z.
    let p = twist_payload(0x0001, [0.0, 0.0, 0.0, 3.0, -4.0, -1.0]);
    let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!(c.angular_speed, Some(-1.0));
    assert_eq!((c.angular_x, c.angular_y), (Some(3.0), Some(-4.0)));
    assert_eq!(c.roll_pitch_rate(), Some(5.0));
}

#[test]
fn f2_twist_stamped_uses_the_same_mapping() {
    let mut w = W::new(0x0001, 8);
    w.u32(1);
    w.u32(2);
    w.s("base");
    for x in [0.1, f64::NAN, 0.0, 0.0, 0.0, 0.0] {
        w.f(x);
    }
    let d = decode_payload(MessageKind::TwistStamped, &w.b, &l()).unwrap();
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!(c.linear_speed, Some(0.1));
    assert!(c.linear_y.unwrap().is_nan());
    let dev = profile().evaluate(&RobotEvent::MotionCommand(c)).unwrap();
    assert_eq!(dev.rule_str(), "robot.motion.non_finite_command");
}

// ---------------------------------------------------------------- F3 (Medium)

/// A JointTrajectory with `points` = (positions, time_from_start) only.
fn trajectory(points: &[(&[f64], i32, u32)], velocities: &[f64]) -> Vec<u8> {
    let mut w = W::new(0x0001, 8);
    w.u32(0);
    w.u32(0);
    w.s(""); // header
    w.u32(1);
    w.s("j1"); // joint_names
    w.u32(points.len() as u32);
    for (pos, sec, nsec) in points {
        w.u32(pos.len() as u32);
        for p in *pos {
            w.f(*p);
        }
        w.u32(velocities.len() as u32);
        for v in velocities {
            w.f(*v);
        }
        w.u32(0);
        w.u32(0); // acc / effort empty
        w.u32(*sec as u32);
        w.u32(*nsec);
    }
    w.b
}

fn joint_speed(p: &[u8]) -> (Option<f64>, Vec<DecodeAnomaly>) {
    let d = decode_payload(MessageKind::JointTrajectory, p, &l()).unwrap();
    assert_eq!(d.trailing_bytes, 0);
    let c = d.message.to_command(&ctx()).unwrap();
    (c.joint_speed, d.anomalies())
}

#[test]
fn f3_single_position_only_point_is_reported_unverifiable() {
    // The reviewer's PoC: one point, 100 rad, time_from_start 0. The start
    // position is not in the message, so no speed can be derived: it must
    // be reported, never a silent None.
    let (s, an) = joint_speed(&trajectory(&[(&[100.0], 0, 0)], &[]));
    assert_eq!(s, None);
    assert_eq!(an.len(), 1);
    assert!(matches!(an[0], DecodeAnomaly::UnverifiableCommand { .. }));
}

#[test]
fn f3_speed_is_derived_from_consecutive_positions() {
    // 0 → 2 rad in 0.5 s → 4 rad/s; then 2 → 2.5 in 1 s → 0.5 rad/s.
    let (s, an) = joint_speed(&trajectory(
        &[
            (&[0.0], 0, 0),
            (&[2.0], 0, 500_000_000),
            (&[2.5], 1, 500_000_000),
        ],
        &[],
    ));
    assert_eq!(s, Some(4.0));
    assert!(an.is_empty());
    // The derived rate goes through the profile envelope (1 rad/s).
    let bytes = trajectory(&[(&[0.0], 0, 0), (&[2.0], 1, 0)], &[]);
    let d = decode_payload(MessageKind::JointTrajectory, &bytes, &l()).unwrap();
    let ev = d.message.to_event(&ctx());
    let dev = profile().evaluate(&ev).unwrap();
    assert_eq!(dev.rule_str(), "robot.motion.joint_over_envelope");
}

#[test]
fn f3_jump_without_time_is_infinite_and_critical() {
    for (t0, t1) in [((1, 0), (1, 0)), ((2, 0), (1, 0)), ((0, 0), (-1, 0))] {
        let (s, _) = joint_speed(&trajectory(
            &[(&[0.0], t0.0, t0.1), (&[100.0], t1.0, t1.1)],
            &[],
        ));
        assert_eq!(s, Some(f64::INFINITY), "{t0:?} -> {t1:?}");
    }
    let bytes = trajectory(&[(&[0.0], 1, 0), (&[100.0], 1, 0)], &[]);
    let d = decode_payload(MessageKind::JointTrajectory, &bytes, &l()).unwrap();
    let dev = profile().evaluate(&d.message.to_event(&ctx())).unwrap();
    assert_eq!(dev.rule_str(), "robot.motion.non_finite_command");
    assert_eq!(dev.severity, Severity::Critical);
    // No movement in zero time is fine.
    let (s, _) = joint_speed(&trajectory(&[(&[3.0], 1, 0), (&[3.0], 1, 0)], &[]));
    assert_eq!(s, Some(0.0));
}

#[test]
fn f3_declared_velocities_cannot_hide_position_steps() {
    // Declares 0.1 rad/s but moves 10 rad in 1 s.
    let (s, an) = joint_speed(&trajectory(&[(&[0.0], 0, 0), (&[10.0], 1, 0)], &[0.1]));
    assert_eq!(s, Some(10.0));
    assert!(an.is_empty());
    // A single point with velocities is verifiable from them.
    let (s, an) = joint_speed(&trajectory(&[(&[1.0], 0, 0)], &[-0.3]));
    assert_eq!(s, Some(0.3));
    assert!(an.is_empty());
}

#[test]
fn f3_nan_positions_poison_the_speed() {
    let (s, _) = joint_speed(&trajectory(&[(&[0.0], 0, 0), (&[f64::NAN], 1, 0)], &[]));
    assert!(s.unwrap().is_nan());
}

// ---------------------------------------------------------------- F4 (Low)

#[test]
fn f4_trailing_bytes_beyond_padding_are_an_anomaly() {
    let mut p = twist_payload(0x0001, [0.1, 0.0, 0.0, 0.0, 0.0, 0.0]);
    p.extend_from_slice(&[0xAA; 4000]);
    let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
    assert_eq!(d.trailing_bytes, 4000);
    assert_eq!(
        d.anomalies(),
        vec![DecodeAnomaly::ExcessTrailingBytes {
            trailing: 4000,
            allowed: MAX_END_PADDING
        }]
    );
    // Up to 3 bytes is ordinary XCDR end padding.
    for n in 0..=3 {
        let mut p = twist_payload(0x0001, [0.1, 0.0, 0.0, 0.0, 0.0, 0.0]);
        p.extend(std::iter::repeat_n(0u8, n));
        let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
        assert!(d.anomalies().is_empty(), "{n}");
    }
    let mut p = twist_payload(0x0001, [0.1, 0.0, 0.0, 0.0, 0.0, 0.0]);
    p.extend_from_slice(&[0; 4]);
    let d = decode_payload(MessageKind::Twist, &p, &l()).unwrap();
    assert_eq!(d.anomalies().len(), 1);
}

// ---------------------------------------------------------------- F5 (Info)

#[test]
fn f5_zero_length_string_is_rejected() {
    let mut w = W::new(0x0001, 8);
    w.u32(0);
    w.u32(0);
    w.u32(0); // frame_id length 0
    for x in [0.0; 6] {
        w.f(x);
    }
    assert_eq!(
        decode_payload(MessageKind::TwistStamped, &w.b, &l()),
        Err(DecodeError::StringLengthZero { at: 8 })
    );
    // The well-formed empty string (length 1, NUL) decodes.
    let mut w = W::new(0x0001, 8);
    w.u32(0);
    w.u32(0);
    w.s("");
    for x in [0.0; 6] {
        w.f(x);
    }
    let d = decode_payload(MessageKind::TwistStamped, &w.b, &l()).unwrap();
    let MotionMessage::TwistStamped(t) = d.message else {
        panic!()
    };
    assert!(t.header.frame_id.is_empty());
}

// ---------------------------------------------------------------- F6 (Info)

#[test]
fn f6_d_cdr2_nesting_is_configurable() {
    // D_CDR2_LE, DHEADER on the top-level Twist only (nested @final).
    let mut w = W::new(0x0009, 4);
    w.u32(48);
    for x in [0.25, 0.0, 0.0, 0.0, 0.0, -0.5] {
        w.f(x);
    }
    let top_only = Limits {
        d_cdr2_nesting: DelimitedNesting::TopLevelOnly,
        ..Limits::default()
    };
    let d = decode_payload(MessageKind::Twist, &w.b, &top_only).unwrap();
    assert_eq!(d.trailing_bytes, 0);
    let c = d.message.to_command(&ctx()).unwrap();
    assert_eq!((c.linear_speed, c.angular_speed), (Some(0.25), Some(-0.5)));
    // The default (XTypes 1.3: unannotated = @appendable) expects nested
    // DHEADERs and refuses this layout instead of misreading it.
    assert_eq!(
        Limits::default().d_cdr2_nesting,
        DelimitedNesting::AllStructs
    );
    assert!(decode_payload(MessageKind::Twist, &w.b, &l()).is_err());
    // The setting does not affect CDR2 (plain) or XCDR1.
    let p = twist_payload(0x0001, [0.25, 0.0, 0.0, 0.0, 0.0, -0.5]);
    assert!(decode_payload(MessageKind::Twist, &p, &top_only).is_ok());
    let p = twist_payload(0x0007, [0.25, 0.0, 0.0, 0.0, 0.0, -0.5]);
    assert!(decode_payload(MessageKind::Twist, &p, &top_only).is_ok());
}

#[test]
fn f6_top_level_only_nesting_for_a_nested_message() {
    // TwistStamped, D_CDR2_LE, top-level DHEADER only:
    // @0 DHEADER, @4 sec, @8 nsec, @12 len 5, @16 "odom\0" → @21, pad → @24,
    // 6 doubles (4-aligned) → @72. DHEADER = 68.
    let mut w = W::new(0x0009, 4);
    w.u32(68);
    w.u32(1);
    w.u32(2);
    w.s("odom");
    for x in [0.5, 0.0, 0.0, 0.0, 0.0, 0.1] {
        w.f(x);
    }
    let top_only = Limits {
        d_cdr2_nesting: DelimitedNesting::TopLevelOnly,
        ..Limits::default()
    };
    let d = decode_payload(MessageKind::TwistStamped, &w.b, &top_only).unwrap();
    assert_eq!(d.trailing_bytes, 0);
    let MotionMessage::TwistStamped(t) = d.message else {
        panic!()
    };
    assert_eq!(t.header.stamp, Time { sec: 1, nanosec: 2 });
    assert_eq!(t.header.frame_id.as_bytes(), b"odom");
    assert_eq!(t.twist.angular.z, 0.1);
}

// ---------------------------------------------------------------- independent spec checks kept

fn odom(max_align: usize, id: u16) -> Vec<u8> {
    let mut w = W::new(id, max_align);
    w.u32(7);
    w.u32(9);
    w.s("map");
    w.s("base"); // ends @25: XCDR1 pads to 32, XCDR2 to 28
    for i in 0..7 {
        w.f(i as f64);
    }
    for i in 0..36 {
        w.f(100.0 + i as f64);
    }
    for v in [1.5, -0.5, 0.25, 0.0, 0.0, -0.75] {
        w.f(v);
    }
    for i in 0..36 {
        w.f(200.0 + i as f64);
    }
    w.b
}

#[test]
fn ok_odometry_independent_xcdr1_and_xcdr2() {
    for (a, id) in [(8, 0x0001u16), (4, 0x0007)] {
        let p = odom(a, id);
        let d = decode_payload(MessageKind::Odometry, &p, &l()).unwrap();
        assert_eq!(d.trailing_bytes, 0);
        let MotionMessage::Odometry(o) = &d.message else {
            panic!()
        };
        assert_eq!(o.header.stamp, Time { sec: 7, nanosec: 9 });
        assert_eq!(o.child_frame_id.as_bytes(), b"base");
        assert_eq!(o.pose.pose.orientation.w, 6.0);
        assert_eq!(o.pose.covariance[35], 135.0);
        assert_eq!(o.twist.twist.linear.y, -0.5);
        assert_eq!(o.twist.twist.angular.z, -0.75);
        assert_eq!(o.twist.covariance[0], 200.0);
        let f = d.message.to_feedback(&ctx()).unwrap();
        assert_eq!(f.linear_velocity, Some(1.5));
        assert_eq!(f.angular_velocity, Some(-0.75));
        assert!(d.anomalies().is_empty());
    }
}
