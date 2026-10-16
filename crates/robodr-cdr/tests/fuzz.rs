//! Property-style fuzz loops with a std-only PRNG (no cargo-fuzz here).
//! The property: decoding never panics, and when it succeeds the reported
//! `consumed + trailing_bytes` equals the body length and every view can be
//! fully iterated.

mod common;

use common::*;
use robodr_cdr::*;

fn exercise(d: &Decoded<'_>, body_len: usize) {
    assert_eq!(d.consumed + d.trailing_bytes, body_len);
    let ctx = EventContext {
        channel: "/fuzz",
        writer_guid: None,
        timestamp_ns: 0,
    };
    let _ = d.message.to_event(&ctx);
    match &d.message {
        MotionMessage::JointState(j) => {
            assert_eq!(j.name.iter().count(), j.name.len());
            assert_eq!(j.position.iter().count(), j.position.len());
            let _ = j.velocity.max_abs();
        }
        MotionMessage::JointTrajectory(t) => {
            assert_eq!(t.joint_names.iter().count(), t.joint_names.len());
            let _ = t.max_abs_velocity();
        }
        _ => {}
    }
}

fn try_all(bytes: &[u8], limits: &Limits) {
    for kind in MessageKind::ALL {
        if let Ok(d) = decode_payload(kind, bytes, limits) {
            exercise(&d, bytes.len() - 4);
        }
    }
}

fn seeds(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    for rep in ALL_REPS {
        let mut e = Enc::new(rep);
        e.twist(
            [rng.f64_any(), rng.f64_any(), rng.f64_any()],
            [rng.f64_any(), rng.f64_any(), rng.f64_any()],
        );
        v.push(e.finish());
        let mut e = Enc::new(rep);
        e.twist_stamped(-1, u32::MAX, b"base_link", [rng.f64_any(); 3], [0.0; 3]);
        v.push(e.finish());
        v.push(joint_state(
            rep,
            &[b"a", b"", b"long_joint_name"],
            &[rng.f64_any()],
            &[rng.f64_any(), rng.f64_any()],
            &[],
        ));
        v.push(imu(rep, b"i", [rng.f64_any(); 3]));
        v.push(joint_trajectory(
            rep,
            &[b"x", b"y"],
            &[
                PointSpec {
                    positions: &[1.0, 2.0],
                    velocities: &[rng.f64_any(), 0.0],
                    accelerations: &[],
                    effort: &[],
                    sec: 1,
                    nanosec: 2,
                },
                PointSpec {
                    positions: &[],
                    velocities: &[],
                    accelerations: &[3.0],
                    effort: &[4.0],
                    sec: 3,
                    nanosec: 4,
                },
            ],
        ));
    }
    v
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let limits = Limits::default();
    for _ in 0..20_000 {
        let len = rng.below(200);
        let mut b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        // Bias toward valid headers so the body decoders get exercised.
        if len >= 2 && rng.below(4) != 0 {
            b[0] = 0;
            b[1] = [0x00, 0x01, 0x10, 0x11, 0x14, 0x15][rng.below(6)];
        }
        try_all(&b, &limits);
    }
}

#[test]
fn mutated_valid_payloads_never_panic() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let tight = Limits {
        max_payload_len: 4096,
        max_string_len: 16,
        max_sequence_len: 8,
        max_trajectory_points: 4,
        // Fuzz the other D_CDR2 nesting mode too.
        d_cdr2_nesting: robodr_cdr::DelimitedNesting::TopLevelOnly,
    };
    let loose = Limits {
        max_payload_len: usize::MAX,
        max_string_len: u32::MAX,
        max_sequence_len: u32::MAX,
        max_trajectory_points: u32::MAX,
        d_cdr2_nesting: robodr_cdr::DelimitedNesting::AllStructs,
    };
    for round in 0..400 {
        for seed in seeds(&mut rng) {
            for _ in 0..12 {
                let mut b = seed.clone();
                let n_mut = 1 + rng.below(4);
                for _ in 0..n_mut {
                    if b.is_empty() {
                        break;
                    }
                    let i = rng.below(b.len());
                    match rng.below(6) {
                        0 => b[i] ^= 1 << rng.below(8),
                        1 => b[i] = rng.next() as u8,
                        2 => b.truncate(i),
                        3 => {
                            // Overwrite an aligned u32 with a hostile length.
                            let at = 4 + (i.saturating_sub(4) & !3);
                            let v: u32 = [0, 1, 0x7fff_ffff, u32::MAX, 0xffff_fff0][rng.below(5)];
                            if at + 4 <= b.len() {
                                b[at..at + 4].copy_from_slice(&v.to_le_bytes());
                            }
                        }
                        4 => b.insert(i, rng.next() as u8),
                        _ => {
                            let extra = rng.below(16);
                            b.extend((0..extra).map(|_| rng.next() as u8));
                        }
                    }
                }
                let lim = if round % 2 == 0 { &tight } else { &loose };
                try_all(&b, lim);
            }
        }
    }
}

#[test]
fn unmutated_seeds_decode_with_right_kind() {
    let mut rng = Rng(42);
    let kinds = [
        MessageKind::Twist,
        MessageKind::TwistStamped,
        MessageKind::JointState,
        MessageKind::Imu,
        MessageKind::JointTrajectory,
    ];
    for (i, s) in seeds(&mut rng).iter().enumerate() {
        let k = kinds[i % kinds.len()];
        let d = decode_payload(k, s, &Limits::default()).unwrap();
        assert_eq!(d.message.kind(), k);
        assert_eq!(d.trailing_bytes, 0);
        exercise(&d, s.len() - 4);
    }
}
