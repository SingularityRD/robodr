//! Truncated, oversized and hostile payloads: each must yield a precise
//! `DecodeError`, never a panic, never an allocation proportional to a
//! claimed length.

mod common;

use common::*;
use robodr_cdr::*;

fn lim() -> Limits {
    Limits::default()
}

fn all_valid_samples() -> Vec<(MessageKind, Vec<u8>)> {
    let mut out = Vec::new();
    for rep in ALL_REPS {
        let mut e = Enc::new(rep);
        e.twist([1.0, 2.0, 3.0], [4.0, 5.0, 6.0]);
        out.push((MessageKind::Twist, e.finish()));
        let mut e = Enc::new(rep);
        e.twist_stamped(1, 2, b"frame", [1.0; 3], [2.0; 3]);
        out.push((MessageKind::TwistStamped, e.finish()));
        out.push((
            MessageKind::Odometry,
            odometry(
                rep,
                &OdomSpec {
                    frame: b"odom",
                    child: b"base",
                    position: [0.0; 3],
                    orientation: [0.0, 0.0, 0.0, 1.0],
                    pose_cov: [0.5; 36],
                    lin: [1.0, 0.0, 0.0],
                    ang: [0.0, 0.0, 1.0],
                    twist_cov: [0.25; 36],
                },
            ),
        ));
        out.push((MessageKind::Imu, imu(rep, b"imu", [0.0, 0.0, 1.0])));
        out.push((
            MessageKind::JointState,
            joint_state(rep, &[b"a", b"bb", b"ccc"], &[1.0], &[2.0, 3.0], &[4.0]),
        ));
        out.push((
            MessageKind::JointTrajectory,
            joint_trajectory(
                rep,
                &[b"a"],
                &[PointSpec {
                    positions: &[1.0],
                    velocities: &[2.0],
                    accelerations: &[],
                    effort: &[],
                    sec: 0,
                    nanosec: 1,
                }],
            ),
        ));
    }
    out
}

#[test]
fn every_strict_prefix_is_rejected() {
    // These encodings end exactly at their last member, so any shorter
    // payload lacks bytes and must fail (cleanly).
    for (kind, bytes) in all_valid_samples() {
        assert!(
            decode_payload(kind, &bytes, &lim()).is_ok(),
            "{kind:?} full"
        );
        for n in 0..bytes.len() {
            let r = decode_payload(kind, &bytes[..n], &lim());
            assert!(r.is_err(), "{kind:?} prefix {n}/{} decoded", bytes.len());
            if n < 4 {
                assert_eq!(r, Err(DecodeError::MissingEncapsulation));
            }
        }
    }
}

#[test]
fn every_kind_on_every_sample_never_panics() {
    // Decoding with the wrong decoder is a realistic mistake (misconfigured
    // type map); it must still be just an Ok/Err.
    for (_, bytes) in all_valid_samples() {
        for kind in MessageKind::ALL {
            let _ = decode_payload(kind, &bytes, &lim());
        }
    }
}

#[test]
fn unknown_and_unsupported_representations() {
    let body = [0u8; 48];
    for (id, want) in [
        (0x0002u16, Some(Representation::PlCdrBe)),
        (0x0003, Some(Representation::PlCdrLe)),
        (0x0004, Some(Representation::Xml)),
        (0x000a, Some(Representation::PlCdr2Be)),
        (0x000b, Some(Representation::PlCdr2Le)),
        (0x0005, None),
        // Never-assigned ids (an earlier version of this crate mapped
        // XCDR2 here by mistake).
        (0x0010, None),
        (0x0011, None),
        (0x0012, None),
        (0x0013, None),
        (0x0014, None),
        (0x0015, None),
        (0x0100, None),
        (0xffff, None),
    ] {
        let mut p = id.to_be_bytes().to_vec();
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&body);
        let r = decode_payload(MessageKind::Twist, &p, &lim());
        match want {
            Some(rep) => assert_eq!(r, Err(DecodeError::UnsupportedRepresentation(rep))),
            None => assert_eq!(r, Err(DecodeError::UnknownRepresentation(id))),
        }
    }
}

#[test]
fn payload_cap() {
    let mut e = Enc::new(Representation::CdrLe);
    e.twist([0.0; 3], [0.0; 3]);
    let bytes = e.finish();
    let l = Limits {
        max_payload_len: 51,
        ..lim()
    };
    assert_eq!(
        decode_payload(MessageKind::Twist, &bytes, &l),
        Err(DecodeError::PayloadTooLarge { len: 52, max: 51 })
    );
}

/// Header with a string whose length prefix is `len`, followed by `tail`.
fn ts_with_len(rep: Representation, len: u32, tail: &[u8]) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.i32(0);
    e.u32(0);
    e.u32(len);
    e.body.extend_from_slice(tail);
    e.finish()
}

#[test]
fn hostile_string_lengths() {
    for rep in [Representation::CdrLe, Representation::CdrBe] {
        // 0xFFFFFFFF: over the cap, rejected before touching bytes.
        let p = ts_with_len(rep, u32::MAX, &[]);
        assert!(matches!(
            decode_payload(MessageKind::TwistStamped, &p, &lim()),
            Err(DecodeError::StringTooLong {
                at: 8,
                len: u32::MAX,
                max: 256
            })
        ));
        // Within cap but beyond the buffer.
        let p = ts_with_len(rep, 200, b"abc\0");
        assert!(matches!(
            decode_payload(MessageKind::TwistStamped, &p, &lim()),
            Err(DecodeError::Truncated { .. })
        ));
        // Missing terminator.
        let p = ts_with_len(rep, 3, b"abc");
        assert_eq!(
            decode_payload(MessageKind::TwistStamped, &p, &lim()),
            Err(DecodeError::StringNotTerminated { at: 8 })
        );
    }
    // Cap is configurable.
    let mut e = Enc::new(Representation::CdrLe);
    e.twist_stamped(0, 0, b"0123456789", [0.0; 3], [0.0; 3]);
    let p = e.finish();
    let l = Limits {
        max_string_len: 10,
        ..lim()
    };
    assert!(matches!(
        decode_payload(MessageKind::TwistStamped, &p, &l),
        Err(DecodeError::StringTooLong {
            len: 11,
            max: 10,
            ..
        })
    ));
    let l = Limits {
        max_string_len: 11,
        ..lim()
    };
    assert!(decode_payload(MessageKind::TwistStamped, &p, &l).is_ok());
}

#[test]
fn embedded_nul_and_invalid_utf8_are_kept_as_bytes() {
    let mut e = Enc::new(Representation::CdrLe);
    e.twist_stamped(0, 0, b"a\0\xff", [0.0; 3], [0.0; 3]);
    let p = e.finish();
    let d = decode_payload(MessageKind::TwistStamped, &p, &lim()).unwrap();
    let MotionMessage::TwistStamped(ts) = d.message else {
        panic!()
    };
    assert_eq!(ts.header.frame_id.as_bytes(), b"a\0\xff");
    assert_eq!(ts.header.frame_id.as_str(), None);
}

fn joint_state_header(rep: Representation) -> Enc {
    let mut e = Enc::new(rep);
    e.header(0, 0, b"");
    e
}

#[test]
fn hostile_sequence_counts() {
    for rep in ALL_REPS {
        let delimited = matches!(rep, Representation::DCdr2Be | Representation::DCdr2Le);
        if delimited {
            continue; // covered by the DHEADER tests below
        }
        let xcdr2 = rep.version() == Some(XcdrVersion::Xcdr2);
        // name[] count = u32::MAX.
        let mut e = joint_state_header(rep);
        if xcdr2 {
            e.u32(4); // DHEADER covering just the count
        }
        e.u32(u32::MAX);
        let p = e.finish();
        assert!(
            matches!(
                decode_payload(MessageKind::JointState, &p, &lim()),
                Err(DecodeError::SequenceTooLong {
                    len: u32::MAX,
                    max: 1024,
                    ..
                })
            ),
            "{rep:?}"
        );
        // position[] count within cap but far beyond the bytes present:
        // rejected before iterating.
        let mut e = joint_state_header(rep);
        e.string_seq(&[]);
        e.u32(1000);
        e.f64(1.0);
        let p = e.finish();
        assert!(
            matches!(
                decode_payload(MessageKind::JointState, &p, &lim()),
                Err(DecodeError::Truncated { .. })
            ),
            "{rep:?}"
        );
    }
    // Configurable cap: exactly at the cap passes, one over fails.
    let p = joint_state(Representation::CdrLe, &[], &[0.0; 4], &[], &[]);
    let l = Limits {
        max_sequence_len: 4,
        ..lim()
    };
    assert!(decode_payload(MessageKind::JointState, &p, &l).is_ok());
    let l = Limits {
        max_sequence_len: 3,
        ..lim()
    };
    assert!(matches!(
        decode_payload(MessageKind::JointState, &p, &l),
        Err(DecodeError::SequenceTooLong { len: 4, max: 3, .. })
    ));
}

#[test]
fn trajectory_point_cap() {
    let pts: Vec<PointSpec<'_>> = (0..5)
        .map(|_| PointSpec {
            positions: &[],
            velocities: &[],
            accelerations: &[],
            effort: &[],
            sec: 0,
            nanosec: 0,
        })
        .collect();
    let p = joint_trajectory(Representation::CdrLe, &[], &pts);
    let l = Limits {
        max_trajectory_points: 4,
        ..lim()
    };
    assert!(matches!(
        decode_payload(MessageKind::JointTrajectory, &p, &l),
        Err(DecodeError::SequenceTooLong { len: 5, max: 4, .. })
    ));
    // A huge claimed count with few bytes is refused before reserving.
    let mut e = Enc::new(Representation::CdrLe);
    e.header(0, 0, b"");
    e.u32(0); // joint_names
    e.u32(1_000_000); // points
    let p = e.finish();
    let l = Limits {
        max_trajectory_points: u32::MAX,
        ..lim()
    };
    assert!(matches!(
        decode_payload(MessageKind::JointTrajectory, &p, &l),
        Err(DecodeError::Truncated { .. })
    ));
}

#[test]
fn dheader_out_of_bounds_and_overrun() {
    // Top-level DHEADER larger than the body.
    let mut e = Enc::new(Representation::DCdr2Le);
    e.u32(1000);
    e.vec3([0.0; 3]);
    let p = e.finish();
    assert!(matches!(
        decode_payload(MessageKind::Twist, &p, &lim()),
        Err(DecodeError::DelimiterOutOfBounds { at: 0, size: 1000 })
    ));
    // Top-level DHEADER too small for its members: the nested Vector3
    // DHEADER now exceeds the (shrunk) container.
    let mut e = Enc::new(Representation::DCdr2Le);
    e.twist([1.0; 3], [2.0; 3]);
    let mut p = e.finish();
    p[4] = 40; // was 56: linear fits, angular's DHEADER (@32) no longer does
    assert!(matches!(
        decode_payload(MessageKind::Twist, &p, &lim()),
        Err(DecodeError::DelimiterOutOfBounds { .. })
    ));
    // Nested DHEADER smaller than its 3 doubles: reading runs into its end.
    let mut e = Enc::new(Representation::DCdr2Le);
    e.twist([1.0; 3], [2.0; 3]);
    let mut p = e.finish();
    p[8] = 16; // linear's DHEADER was 24
    assert!(matches!(
        decode_payload(MessageKind::Twist, &p, &lim()),
        Err(DecodeError::Truncated { .. })
    ));
    // DHEADER = u32::MAX: no overflow, clean error.
    let mut e = Enc::new(Representation::DCdr2Be);
    e.u32(u32::MAX);
    let p = e.finish();
    assert!(matches!(
        decode_payload(MessageKind::Twist, &p, &lim()),
        Err(DecodeError::DelimiterOutOfBounds { .. })
    ));
    // string[] DHEADER (plain XCDR2) shorter than its strings.
    let mut e = joint_state_header(Representation::Cdr2Le);
    e.u32(6); // DHEADER: count + 2 bytes only
    e.u32(1);
    e.string(b"abc");
    e.f64_seq(&[]);
    e.f64_seq(&[]);
    e.f64_seq(&[]);
    let p = e.finish();
    assert!(decode_payload(MessageKind::JointState, &p, &lim()).is_err());
}

#[test]
fn error_display_is_informative() {
    let e = DecodeError::SequenceTooLong {
        at: 16,
        len: 5,
        max: 4,
    };
    assert_eq!(
        e.to_string(),
        "sequence length 5 at offset 16 exceeds cap 4"
    );
    let _: &dyn std::error::Error = &e;
}
