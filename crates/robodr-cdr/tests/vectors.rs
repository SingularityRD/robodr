//! Hand-derived byte vectors and round trips.
//!
//! Every vector below was written by hand from the rules in DDS-XTypes 1.3
//! §7.4.3 (XCDR1/XCDR2 serialization) and DDSI-RTPS 2.5 §10 (encapsulation
//! header), *not* produced by a DDS implementation. Offsets in the comments
//! are relative to the CDR body (first octet after the 4-byte header), which
//! is the alignment origin.
//!
//! IEEE-754 doubles used (big-endian bit pattern):
//!   0.5   = 3FE0 0000 0000 0000      -0.25 = BFD0 0000 0000 0000
//!   1.0   = 3FF0 0000 0000 0000      -1.0  = BFF0 0000 0000 0000
//! Little-endian bodies store these bytes reversed, e.g. 0.5 = 00..00 E0 3F.

mod common;

use common::*;
use robodr_cdr::*;
use robodr_events::RobotEvent;

const L: Limits = Limits {
    max_payload_len: 256 * 1024,
    max_string_len: 256,
    max_sequence_len: 1024,
    max_trajectory_points: 1024,
    d_cdr2_nesting: robodr_cdr::DelimitedNesting::AllStructs,
};

fn twist_of(d: &Decoded<'_>) -> Twist {
    match &d.message {
        MotionMessage::Twist(t) => *t,
        MotionMessage::TwistStamped(t) => t.twist,
        m => panic!("not a twist: {m:?}"),
    }
}

const LIN: [f64; 3] = [0.5, 0.0, 0.0];
const ANG: [f64; 3] = [0.0, 0.0, -0.25];

fn expected_twist() -> Twist {
    Twist {
        linear: Vector3 {
            x: 0.5,
            y: 0.0,
            z: 0.0,
        },
        angular: Vector3 {
            x: 0.0,
            y: 0.0,
            z: -0.25,
        },
    }
}

// ---------------------------------------------------------------- Twist

/// geometry_msgs/Twist, XCDR1 little endian (CDR_LE = 0x0001).
/// Six doubles; offset 0 is 8-aligned, so no padding anywhere: 48 bytes.
const TWIST_CDR_LE: &str = "
    00 01 00 00                 encapsulation CDR_LE, options 0
    00 00 00 00 00 00 E0 3F     @0  linear.x  = 0.5
    00 00 00 00 00 00 00 00     @8  linear.y  = 0
    00 00 00 00 00 00 00 00     @16 linear.z  = 0
    00 00 00 00 00 00 00 00     @24 angular.x = 0
    00 00 00 00 00 00 00 00     @32 angular.y = 0
    00 00 00 00 00 00 D0 BF     @40 angular.z = -0.25
";

/// Same message, XCDR1 big endian (CDR_BE = 0x0000).
const TWIST_CDR_BE: &str = "
    00 00 00 00
    3F E0 00 00 00 00 00 00     @0  linear.x = 0.5
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    BF D0 00 00 00 00 00 00     @40 angular.z = -0.25
";

/// XCDR2 delimited (D_CDR2_LE = 0x0009): Twist and each Vector3 are
/// appendable, so each gets a DHEADER (uint32 byte count of what follows).
///   Vector3 body = 3*8 = 24 (0x18); with its DHEADER = 28.
///   Twist body   = 28 + 28 = 56 (0x38).
/// Doubles are 4-aligned under XCDR2, so @8 needs no padding.
const TWIST_DCDR2_LE: &str = "
    00 09 00 00
    38 00 00 00                 @0  DHEADER(Twist)   = 56
    18 00 00 00                 @4  DHEADER(linear)  = 24
    00 00 00 00 00 00 E0 3F     @8  linear.x = 0.5
    00 00 00 00 00 00 00 00     @16
    00 00 00 00 00 00 00 00     @24
    18 00 00 00                 @32 DHEADER(angular) = 24
    00 00 00 00 00 00 00 00     @36
    00 00 00 00 00 00 00 00     @44
    00 00 00 00 00 00 D0 BF     @52 angular.z = -0.25   (end @60)
";

/// D_CDR2_BE (0x0008): same layout, big-endian DHEADERs and doubles.
const TWIST_DCDR2_BE: &str = "
    00 08 00 00
    00 00 00 38
    00 00 00 18
    3F E0 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 18
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    BF D0 00 00 00 00 00 00
";

#[test]
fn twist_hand_vectors_decode() {
    for (name, v) in [
        ("CDR_LE", TWIST_CDR_LE),
        ("CDR_BE", TWIST_CDR_BE),
        ("D_CDR2_LE", TWIST_DCDR2_LE),
        ("D_CDR2_BE", TWIST_DCDR2_BE),
    ] {
        let bytes = hex(v);
        let d = decode_payload(MessageKind::Twist, &bytes, &L).unwrap();
        assert_eq!(twist_of(&d), expected_twist(), "{name}");
        assert_eq!(d.trailing_bytes, 0, "{name}");
        assert_eq!(d.consumed, bytes.len() - 4, "{name}");
    }
}

#[test]
fn twist_plain_cdr2_body_equals_xcdr1_body() {
    // Six doubles from offset 0: identical under 8- or 4-alignment.
    let mut v = hex(TWIST_CDR_LE);
    v[1] = 0x07; // CDR2_LE
    let d = decode_payload(MessageKind::Twist, &v, &L).unwrap();
    assert_eq!(twist_of(&d), expected_twist());
}

#[test]
fn encoder_reproduces_twist_hand_vectors() {
    for (rep, v) in [
        (Representation::CdrLe, TWIST_CDR_LE),
        (Representation::CdrBe, TWIST_CDR_BE),
        (Representation::DCdr2Le, TWIST_DCDR2_LE),
        (Representation::DCdr2Be, TWIST_DCDR2_BE),
    ] {
        let mut e = Enc::new(rep);
        e.twist(LIN, ANG);
        assert_eq!(e.finish(), hex(v), "{rep:?}");
    }
}

// ---------------------------------------------------------------- TwistStamped

/// TwistStamped{header{stamp{sec 1, nanosec 2}, frame_id "odom"}, twist},
/// XCDR1 LE. "odom" has length 5 including the NUL and ends at @17; the
/// first double must be 8-aligned → 7 padding octets, twist at @24.
const TS_CDR_LE: &str = "
    00 01 00 00
    01 00 00 00                 @0  stamp.sec = 1
    02 00 00 00                 @4  stamp.nanosec = 2
    05 00 00 00                 @8  frame_id length 5
    6F 64 6F 6D 00              @12 'o' 'd' 'o' 'm' NUL  (end @17)
    00 00 00 00 00 00 00        @17 pad to 8 → @24
    00 00 00 00 00 00 E0 3F     @24 linear.x = 0.5
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 D0 BF     @64 angular.z = -0.25   (end @72)
";

/// Same message, XCDR2 plain (CDR2_LE = 0x0007): doubles align to 4 only,
/// so 3 padding octets after @17 and the twist starts at @20.
const TS_CDR2_LE: &str = "
    00 07 00 00
    01 00 00 00
    02 00 00 00
    05 00 00 00
    6F 64 6F 6D 00              (end @17)
    00 00 00                    pad to 4 → @20
    00 00 00 00 00 00 E0 3F     @20 linear.x = 0.5
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 D0 BF     @60 angular.z           (end @68)
";

/// Same message, XCDR2 delimited (D_CDR2_LE). DHEADER sizes:
///   Time   = 4 + 4 = 8
///   Header = DHEADER(Time) 4 + 8 + len 4 + "odom\0" 5 = 21 (@8..@29)
///   Twist  = 56 (as above)
///   TwistStamped = @4..@92 = 88 (0x58): Header 25, 3 pad, Twist 60.
/// The padding after the Header belongs to the next DHEADER's alignment,
/// not to the Header's size.
const TS_DCDR2_LE: &str = "
    00 09 00 00
    58 00 00 00                 @0  DHEADER(TwistStamped) = 88
    15 00 00 00                 @4  DHEADER(Header) = 21
    08 00 00 00                 @8  DHEADER(Time) = 8
    01 00 00 00                 @12 sec
    02 00 00 00                 @16 nanosec
    05 00 00 00                 @20 frame_id length
    6F 64 6F 6D 00              @24 (end @29)
    00 00 00                    @29 pad → @32
    38 00 00 00                 @32 DHEADER(Twist) = 56
    18 00 00 00                 @36 DHEADER(linear)
    00 00 00 00 00 00 E0 3F     @40
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    18 00 00 00                 @64 DHEADER(angular)
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    00 00 00 00 00 00 D0 BF     @84 (end @92)
";

#[test]
fn twist_stamped_hand_vectors() {
    for (name, v, body_len) in [
        ("CDR_LE", TS_CDR_LE, 72),
        ("CDR2_LE", TS_CDR2_LE, 68),
        ("D_CDR2_LE", TS_DCDR2_LE, 92),
    ] {
        let bytes = hex(v);
        assert_eq!(bytes.len(), 4 + body_len, "{name} vector length");
        let d = decode_payload(MessageKind::TwistStamped, &bytes, &L).unwrap();
        let MotionMessage::TwistStamped(ts) = d.message else {
            panic!()
        };
        assert_eq!(ts.header.stamp, Time { sec: 1, nanosec: 2 }, "{name}");
        assert_eq!(ts.header.frame_id.as_str(), Some("odom"), "{name}");
        assert_eq!(ts.twist, expected_twist(), "{name}");
        assert_eq!(d.trailing_bytes, 0, "{name}");
    }
}

#[test]
fn encoder_reproduces_twist_stamped_hand_vectors() {
    for (rep, v) in [
        (Representation::CdrLe, TS_CDR_LE),
        (Representation::Cdr2Le, TS_CDR2_LE),
        (Representation::DCdr2Le, TS_DCDR2_LE),
    ] {
        let mut e = Enc::new(rep);
        e.twist_stamped(1, 2, b"odom", LIN, ANG);
        assert_eq!(e.finish(), hex(v), "{rep:?}");
    }
}

#[test]
fn wrong_version_label_misreads_rather_than_guessing() {
    // XCDR1 bytes labelled CDR2: the reader honours the label (alignment 4),
    // reads the twist from @20 (inside the XCDR1 padding) and gets garbage.
    // This documents that the encapsulation id is authoritative.
    let mut v = hex(TS_CDR_LE);
    v[1] = 0x07; // CDR2_LE
    let d = decode_payload(MessageKind::TwistStamped, &v, &L).unwrap();
    assert_ne!(twist_of(&d), expected_twist());
    assert_eq!(d.trailing_bytes, 4);
}

// ---------------------------------------------------------------- JointState

/// JointState{header{0,0,""}, name ["a","bc"], position [1.0],
/// velocity [-1.0, 0.5], effort []}, XCDR1 LE.
const JS_CDR_LE: &str = "
    00 01 00 00
    00 00 00 00                 @0  sec
    00 00 00 00                 @4  nanosec
    01 00 00 00                 @8  frame_id length 1 (just NUL)
    00                          @12
    00 00 00                    @13 pad → @16
    02 00 00 00                 @16 name: 2 elements
    02 00 00 00                 @20 'a' length 2
    61 00                       @24
    00 00                       @26 pad → @28
    03 00 00 00                 @28 'bc' length 3
    62 63 00                    @32 (end @35)
    00                          @35 pad → @36
    01 00 00 00                 @36 position: 1 element
    00 00 00 00 00 00 F0 3F     @40 1.0 (already 8-aligned)
    02 00 00 00                 @48 velocity: 2 elements
    00 00 00 00                 @52 pad → @56 (double alignment 8)
    00 00 00 00 00 00 F0 BF     @56 -1.0
    00 00 00 00 00 00 E0 3F     @64 0.5
    00 00 00 00                 @72 effort: 0 elements (no element, no pad)
";

/// Same values, XCDR1 BE.
const JS_CDR_BE: &str = "
    00 00 00 00
    00 00 00 00
    00 00 00 00
    00 00 00 01
    00 00 00 00
    00 00 00 02
    00 00 00 02  61 00 00 00
    00 00 00 03  62 63 00 00
    00 00 00 01
    3F F0 00 00 00 00 00 00
    00 00 00 02
    00 00 00 00
    BF F0 00 00 00 00 00 00
    3F E0 00 00 00 00 00 00
    00 00 00 00
";

/// Same values, XCDR2 plain (CDR2_LE). `string[]` has a non-primitive
/// element type, so it is preceded by a DHEADER covering the count and the
/// strings: @20..@39 = 19 (0x13). `float64[]` gets none, and its doubles are
/// 4-aligned (no pad before -1.0 this time).
const JS_CDR2_LE: &str = "
    00 07 00 00
    00 00 00 00
    00 00 00 00
    01 00 00 00
    00 00 00 00                 @12 NUL + 3 pad → @16
    13 00 00 00                 @16 DHEADER(name) = 19
    02 00 00 00                 @20 count 2
    02 00 00 00  61 00  00 00   @24 'a'   (pad @30 → @32)
    03 00 00 00  62 63 00       @32 'bc'  (end @39)
    00                          @39 pad → @40
    01 00 00 00                 @40 position count
    00 00 00 00 00 00 F0 3F     @44 1.0 (4-aligned is enough)
    02 00 00 00                 @52 velocity count
    00 00 00 00 00 00 F0 BF     @56 -1.0
    00 00 00 00 00 00 E0 3F     @64 0.5
    00 00 00 00                 @72 effort count 0
";

fn check_joint_state(d: &Decoded<'_>) {
    let MotionMessage::JointState(js) = &d.message else {
        panic!()
    };
    let names: Vec<_> = js.name.iter().map(|s| s.as_bytes().to_vec()).collect();
    assert_eq!(names, vec![b"a".to_vec(), b"bc".to_vec()]);
    assert_eq!(js.position.iter().collect::<Vec<_>>(), vec![1.0]);
    assert_eq!(js.velocity.iter().collect::<Vec<_>>(), vec![-1.0, 0.5]);
    assert!(js.effort.is_empty());
    assert_eq!(js.velocity.max_abs(), Some(1.0));
    assert_eq!(js.velocity.get(1), Some(0.5));
    assert_eq!(js.velocity.get(2), None);
    assert_eq!(js.header.frame_id.as_str(), Some(""));
}

#[test]
fn joint_state_hand_vectors() {
    for (name, v, rep) in [
        ("CDR_LE", JS_CDR_LE, Representation::CdrLe),
        ("CDR_BE", JS_CDR_BE, Representation::CdrBe),
        ("CDR2_LE", JS_CDR2_LE, Representation::Cdr2Le),
    ] {
        let bytes = hex(v);
        assert_eq!(bytes.len(), 80, "{name}");
        let d = decode_payload(MessageKind::JointState, &bytes, &L).unwrap();
        check_joint_state(&d);
        assert_eq!(d.trailing_bytes, 0, "{name}");
        // The encoder agrees with the hand derivation.
        let mut e = Enc::new(rep);
        e.header(0, 0, b"");
        e.string_seq(&[b"a", b"bc"]);
        e.f64_seq(&[1.0]);
        e.f64_seq(&[-1.0, 0.5]);
        e.f64_seq(&[]);
        assert_eq!(e.finish(), bytes, "{name} encoder");
    }
}

// ---------------------------------------------------------------- round trips

fn odom_spec() -> OdomSpec<'static> {
    let mut pose_cov = [0.0; 36];
    let mut twist_cov = [0.0; 36];
    for i in 0..36 {
        pose_cov[i] = i as f64;
        twist_cov[i] = -(i as f64) / 4.0;
    }
    OdomSpec {
        frame: b"odom",
        child: b"base_link",
        position: [1.0, 2.0, 3.0],
        orientation: [0.0, 0.0, 0.6, 0.8],
        pose_cov,
        lin: [-0.75, 0.1, 0.0],
        ang: [0.0, 0.0, 0.3],
        twist_cov,
    }
}

#[test]
fn odometry_round_trip_all_encodings() {
    let s = odom_spec();
    for rep in ALL_REPS {
        let bytes = odometry(rep, &s);
        let d = decode_payload(MessageKind::Odometry, &bytes, &L).unwrap();
        let MotionMessage::Odometry(o) = d.message else {
            panic!()
        };
        assert_eq!(
            o.header.stamp,
            Time {
                sec: 10,
                nanosec: 20
            }
        );
        assert_eq!(o.header.frame_id.as_str(), Some("odom"));
        assert_eq!(o.child_frame_id.as_str(), Some("base_link"));
        assert_eq!(o.pose.pose.position.z, 3.0);
        assert_eq!(o.pose.pose.orientation.w, 0.8);
        assert_eq!(o.pose.covariance, s.pose_cov);
        assert_eq!(o.twist.twist.linear.x, -0.75);
        assert_eq!(o.twist.twist.angular.z, 0.3);
        assert_eq!(o.twist.covariance, s.twist_cov);
        assert_eq!(d.trailing_bytes, 0, "{rep:?}");
    }
}

#[test]
fn imu_round_trip_all_encodings() {
    for rep in ALL_REPS {
        let bytes = imu(rep, b"imu_link", [0.01, -0.02, -1.5]);
        let d = decode_payload(MessageKind::Imu, &bytes, &L).unwrap();
        let MotionMessage::Imu(i) = d.message else {
            panic!()
        };
        assert_eq!(i.header.frame_id.as_str(), Some("imu_link"));
        assert_eq!(i.orientation.w, 1.0);
        assert_eq!(i.orientation_covariance, [0.1; 9]);
        assert_eq!(i.angular_velocity.z, -1.5);
        assert_eq!(i.angular_velocity_covariance, [0.2; 9]);
        assert_eq!(i.linear_acceleration.z, 9.81);
        assert_eq!(i.linear_acceleration_covariance, [0.3; 9]);
        assert_eq!(d.trailing_bytes, 0, "{rep:?}");
    }
}

#[test]
fn joint_state_round_trip_all_encodings() {
    for rep in ALL_REPS {
        let bytes = joint_state(
            rep,
            &[b"j1", b"joint_two", b""],
            &[0.1, 0.2, 0.3],
            &[1.0, -2.5, 0.0],
            &[],
        );
        let d = decode_payload(MessageKind::JointState, &bytes, &L).unwrap();
        let MotionMessage::JointState(js) = d.message else {
            panic!()
        };
        let names: Vec<_> = js.name.iter().map(|s| s.to_string_lossy()).collect();
        assert_eq!(names, ["j1", "joint_two", ""]);
        assert_eq!(js.position.len(), 3);
        assert_eq!(js.velocity.max_abs(), Some(2.5));
        assert!(js.effort.is_empty());
        assert_eq!(d.trailing_bytes, 0, "{rep:?}");
    }
}

#[test]
fn joint_trajectory_round_trip_all_encodings() {
    let points = [
        PointSpec {
            positions: &[0.0, 0.1],
            velocities: &[0.5, -0.7],
            accelerations: &[],
            effort: &[],
            sec: 1,
            nanosec: 0,
        },
        PointSpec {
            positions: &[0.2, 0.3],
            velocities: &[],
            accelerations: &[1.0, 1.0],
            effort: &[3.0],
            sec: 2,
            nanosec: 500,
        },
    ];
    for rep in ALL_REPS {
        let bytes = joint_trajectory(rep, &[b"shoulder", b"elbow"], &points);
        let d = decode_payload(MessageKind::JointTrajectory, &bytes, &L).unwrap();
        let MotionMessage::JointTrajectory(jt) = &d.message else {
            panic!()
        };
        assert_eq!(jt.header.frame_id.as_str(), Some("base_link"));
        assert_eq!(jt.joint_names.len(), 2);
        assert_eq!(jt.points.len(), 2);
        assert_eq!(jt.points[0].velocities.get(1), Some(-0.7));
        assert!(jt.points[1].velocities.is_empty());
        assert_eq!(jt.points[1].effort.get(0), Some(3.0));
        assert_eq!(
            jt.points[1].time_from_start,
            Time {
                sec: 2,
                nanosec: 500
            }
        );
        assert_eq!(jt.max_abs_velocity(), Some(0.7));
        assert_eq!(d.trailing_bytes, 0, "{rep:?}");
    }
}

#[test]
fn appendable_extension_members_are_skipped_under_dcdr2() {
    // A newer Twist version with an extra member appended inside the Twist
    // DHEADER: decoding still lands on the right values and consumes it.
    let mut e = Enc::new(Representation::DCdr2Le);
    e.begin_dheader();
    e.vec3(LIN);
    e.vec3(ANG);
    e.u32(0xDEAD_BEEF); // unknown appended member
    e.end_dheader();
    let bytes = e.finish();
    let d = decode_payload(MessageKind::Twist, &bytes, &L).unwrap();
    assert_eq!(twist_of(&d), expected_twist());
    assert_eq!(d.trailing_bytes, 0);
}

#[test]
fn trailing_padding_is_reported_not_rejected() {
    let mut v = hex(TS_CDR2_LE);
    v[3] = 0x02; // options: 2 padding octets
    v.extend_from_slice(&[0, 0]);
    let d = decode_payload(MessageKind::TwistStamped, &v, &L).unwrap();
    assert_eq!(d.encapsulation.padding(), 2);
    assert_eq!(d.trailing_bytes, 2);
}

// ---------------------------------------------------------------- non-finite

#[test]
fn non_finite_values_are_decoded_faithfully() {
    let mut e = Enc::new(Representation::CdrLe);
    e.twist([f64::NAN, 0.0, 0.0], [0.0, 0.0, f64::NEG_INFINITY]);
    let bytes = e.finish();
    let d = decode_payload(MessageKind::Twist, &bytes, &L).unwrap();
    let t = twist_of(&d);
    assert!(t.linear.x.is_nan());
    assert_eq!(t.angular.z, f64::NEG_INFINITY);
    let ctx = EventContext {
        channel: "/cmd_vel",
        writer_guid: Some("01.0f"),
        timestamp_ns: 7,
    };
    let RobotEvent::MotionCommand(c) = d.message.to_event(&ctx) else {
        panic!()
    };
    assert!(c.linear_speed.unwrap().is_nan());
    assert_eq!(c.angular_speed, Some(f64::NEG_INFINITY));
}

#[test]
fn joint_state_nan_velocity_poisons_max() {
    let bytes = joint_state(
        Representation::CdrLe,
        &[b"a", b"b", b"c"],
        &[],
        &[9.0, f64::NAN, 1.0],
        &[],
    );
    let d = decode_payload(MessageKind::JointState, &bytes, &L).unwrap();
    let ctx = EventContext {
        channel: "/joint_states",
        writer_guid: None,
        timestamp_ns: 1,
    };
    let f = d.message.to_feedback(&ctx).unwrap();
    assert!(f.measured_joint_speed.unwrap().is_nan());
}

// ---------------------------------------------------------------- events

#[test]
fn twist_maps_to_signed_motion_command() {
    let bytes = hex(TWIST_CDR_LE);
    let d = decode_payload(MessageKind::Twist, &bytes, &L).unwrap();
    let ctx = EventContext {
        channel: "/cmd_vel",
        writer_guid: Some("aa.bb"),
        timestamp_ns: 99,
    };
    assert_eq!(d.message.role(), MotionRole::Command);
    assert!(d.message.to_feedback(&ctx).is_none());
    let RobotEvent::MotionCommand(c) = d.message.to_event(&ctx) else {
        panic!()
    };
    assert_eq!(c.channel, "/cmd_vel");
    assert_eq!(c.source_guid.as_deref(), Some("aa.bb"));
    assert_eq!(c.linear_speed, Some(0.5));
    assert_eq!(c.angular_speed, Some(-0.25)); // sign kept
    assert_eq!(c.joint_speed, None);
    // Every other Twist axis is present (zero in this vector).
    for a in [c.linear_y, c.linear_z, c.angular_x, c.angular_y] {
        assert!(a.is_some_and(|v| v.is_finite()), "{c:?}");
    }
}

#[test]
fn odometry_maps_to_signed_feedback_with_magnitude() {
    let bytes = odometry(Representation::CdrLe, &odom_spec());
    let d = decode_payload(MessageKind::Odometry, &bytes, &L).unwrap();
    let ctx = EventContext {
        channel: "/odom",
        writer_guid: Some("cc"),
        timestamp_ns: 1234,
    };
    let RobotEvent::MotionFeedback(f) = d.message.to_event(&ctx) else {
        panic!()
    };
    assert_eq!(f.linear_velocity, Some(-0.75));
    assert_eq!(f.angular_velocity, Some(0.3));
    // Holonomic axes are carried signed, per axis.
    assert_eq!(f.linear_velocity_y, Some(0.1));
    assert_eq!(f.linear_velocity_z, Some(0.0));
    assert_eq!(
        (f.angular_velocity_x, f.angular_velocity_y),
        (Some(0.0), Some(0.0))
    );
    let mag = f.measured_linear_speed.unwrap();
    assert!((mag - (0.75f64 * 0.75 + 0.01).sqrt()).abs() < 1e-12);
    assert_eq!(f.publisher_guid.as_deref(), Some("cc"));
    // The wire stamp (10 s) is NOT used; the observation time is.
    assert_eq!(f.timestamp_ns, 1234);
}

#[test]
fn imu_and_trajectory_mapping() {
    let ctx = EventContext {
        channel: "/x",
        writer_guid: None,
        timestamp_ns: 0,
    };
    let b = imu(Representation::CdrBe, b"imu", [0.2, -0.1, -0.4]);
    let d = decode_payload(MessageKind::Imu, &b, &L).unwrap();
    let f = d.message.to_feedback(&ctx).unwrap();
    assert_eq!(f.angular_velocity, Some(-0.4));
    assert_eq!(
        (f.angular_velocity_x, f.angular_velocity_y),
        (Some(0.2), Some(-0.1))
    );
    assert_eq!((f.linear_velocity_y, f.linear_velocity_z), (None, None));
    assert_eq!(f.linear_velocity, None);
    assert_eq!(f.measured_linear_speed, None);

    let b = joint_trajectory(Representation::CdrLe, &[b"j"], &[]);
    let d = decode_payload(MessageKind::JointTrajectory, &b, &L).unwrap();
    let c = d.message.to_command(&ctx).unwrap();
    // No points: the controller holds position; a checkable zero, not None.
    assert_eq!(c.joint_speed, Some(0.0));
    assert_eq!(c.linear_speed, None);
    assert!(!c.has_extra_axes());
    assert!(d.anomalies().is_empty());
}

// ---------------------------------------------------------------- registry

#[test]
fn registry_keys_by_dds_and_ros_names() {
    let r = Registry::with_builtin();
    // 19 kinds (6 ROS + 13 Unitree), each under its DDS and ROS name.
    assert_eq!(r.len(), 38);
    assert_eq!(
        r.kind("geometry_msgs::msg::dds_::Twist_"),
        Some(MessageKind::Twist)
    );
    assert_eq!(r.kind("nav_msgs/msg/Odometry"), Some(MessageKind::Odometry));
    assert_eq!(r.kind("geometry_msgs::msg::dds_::Twist"), None); // exact only
    let bytes = hex(TWIST_CDR_BE);
    let d = r
        .decode("geometry_msgs::msg::dds_::Twist_", &bytes, &L)
        .unwrap();
    assert_eq!(twist_of(&d), expected_twist());
    assert_eq!(
        r.decode("std_msgs::msg::dds_::String_", &bytes, &L),
        Err(DecodeError::UnknownType)
    );
    // A Twist body read as an Imu: the header's frame_id length lands on
    // the zero half of a double (a 0 length prefix is malformed).
    assert!(matches!(
        decode_by_type_name("sensor_msgs::msg::dds_::Imu_", &bytes, &L),
        Err(DecodeError::StringLengthZero { .. })
    ));
    for k in MessageKind::ALL {
        assert_eq!(MessageKind::from_type_name(k.dds_type_name()), Some(k));
        assert_eq!(MessageKind::from_type_name(k.ros_type_name()), Some(k));
    }
}

#[test]
fn registry_custom_registration() {
    let mut r = Registry::new();
    assert!(r.is_empty());
    // e.g. a vendor-renamed type carrying a plain Twist.
    r.register(
        "acme::msg::dds_::DriveCmd_",
        MessageKind::Twist,
        registry::builtin_decoder(MessageKind::Twist),
    );
    let bytes = hex(TWIST_CDR_LE);
    let d = r.decode("acme::msg::dds_::DriveCmd_", &bytes, &L).unwrap();
    assert_eq!(twist_of(&d), expected_twist());
    assert_eq!(
        r.type_names().collect::<Vec<_>>(),
        ["acme::msg::dds_::DriveCmd_"]
    );
}
