//! Hand-built byte vectors and round trips for the Unitree decoders.
//!
//! The encoder (`common::Enc`) lays out XCDR1 / XCDR2 exactly as the reader
//! expects (it reproduces the core ROS vectors byte for byte in
//! `vectors.rs`), so building a message and decoding it exercises the real
//! wire layout. Every message is built in XCDR1 little- and big-endian; a
//! few are also built in plain XCDR2 (`CDR2_LE`) to cover the 4-byte
//! alignment and the non-primitive-array DHEADER.
//!
//! Status: these are hand-built vectors from Unitree's published IDL / msg
//! definitions, not captures from a real robot.

mod common;

use common::*;
use robodr_cdr::unitree::*;
use robodr_cdr::{
    decode_payload, DecodeError, EventContext, Limits, MessageKind, MotionMessage, MotionRole,
    Representation,
};
use robodr_events::RobotEvent;

const L: Limits = Limits {
    max_payload_len: 256 * 1024,
    max_string_len: 256,
    max_sequence_len: 1024,
    max_trajectory_points: 1024,
    d_cdr2_nesting: robodr_cdr::DelimitedNesting::AllStructs,
};

const XCDR1: [Representation; 2] = [Representation::CdrLe, Representation::CdrBe];

/// A motor command (mode, q, dq, tau, kp, kd).
type Mc = (u8, f32, f32, f32, f32, f32);

fn enc_go_motor_cmd(e: &mut Enc, m: Mc) {
    e.byte(m.0);
    e.f32(m.1);
    e.f32(m.2);
    e.f32(m.3);
    e.f32(m.4);
    e.f32(m.5);
    for _ in 0..3 {
        e.u32(0); // reserve[3]
    }
}

/// Builds a go `LowCmd_` with the given 20 motor commands and crc.
fn go_low_cmd(rep: Representation, motors: &[Mc; 20], crc: u32) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.bytes(&[0xFE, 0xEF]); // head
        e.byte(0xFF); // level_flag
        e.byte(0); // frame_reserve
        for _ in 0..2 {
            e.u32(0); // sn
        }
        for _ in 0..2 {
            e.u32(0); // version
        }
        e.u16(0); // bandwidth
        e.nonprim_seq(|e| {
            for m in motors {
                enc_go_motor_cmd(e, *m);
            }
        });
        e.byte(0); // bms_cmd.off
        e.bytes(&[0; 3]); // bms_cmd.reserve
        e.bytes(&[0; 40]); // wireless_remote
        e.bytes(&[0; 12]); // led
        e.bytes(&[0; 2]); // fan
        e.byte(0); // gpio
        e.u32(0); // reserve
        e.u32(crc); // crc
    });
    e.finish()
}

fn enc_go_imu(e: &mut Enc) {
    for _ in 0..4 {
        e.f32(0.0); // quaternion
    }
    e.f32(0.1); // gyroscope x
    e.f32(-0.2); // gyroscope y
    e.f32(0.3); // gyroscope z
    for _ in 0..3 {
        e.f32(0.0); // accelerometer
    }
    for _ in 0..3 {
        e.f32(0.0); // rpy
    }
    e.byte(0); // temperature i8
}

fn enc_go_motor_state(e: &mut Enc, dq: f32) {
    e.byte(0); // mode
    e.f32(0.0); // q
    e.f32(dq); // dq
    e.f32(0.0); // ddq
    e.f32(0.0); // tau_est
    e.f32(0.0); // q_raw
    e.f32(0.0); // dq_raw
    e.f32(0.0); // ddq_raw
    e.byte(0); // temperature i8
    e.u32(0); // lost
    e.u32(0); // reserve[2]
    e.u32(0);
}

fn go_low_state(rep: Representation, dqs: &[f32; 20], crc: u32) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.bytes(&[0, 0]);
        e.byte(0xFF);
        e.byte(0);
        e.u32(0);
        e.u32(0);
        e.u32(0);
        e.u32(0);
        e.u16(0);
        enc_go_imu(e);
        e.nonprim_seq(|e| {
            for dq in dqs {
                enc_go_motor_state(e, *dq);
            }
        });
        // bms_state
        e.bytes(&[0, 0, 0, 0]); // version_high/low, status, soc
        e.i32(0); // current
        e.u16(0); // cycle
        e.bytes(&[0, 0, 0, 0]); // bq_ntc[2], mcu_ntc[2] (i8)
        for _ in 0..15 {
            e.u16(0); // cell_vol
        }
        for _ in 0..4 {
            e.i16(0); // foot_force
        }
        for _ in 0..4 {
            e.i16(0); // foot_force_est
        }
        e.u32(0); // tick
        e.bytes(&[0; 40]); // wireless_remote
        e.byte(0); // bit_flag
        e.f32(0.0); // adc_reel
        e.byte(0); // temperature_ntc1 i8
        e.byte(0); // temperature_ntc2 i8
        e.f32(0.0); // power_v
        e.f32(0.0); // power_a
        for _ in 0..4 {
            e.u16(0); // fan_frequency
        }
        e.u32(0); // reserve
        e.u32(crc); // crc
    });
    e.finish()
}

fn go_sport_mode_state(rep: Representation, velocity: [f32; 3], yaw_speed: f32) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.structure(|e| {
            e.i32(1); // stamp.sec
            e.u32(2); // stamp.nanosec
        });
        e.u32(0); // error_code
        enc_go_imu(e);
        e.byte(0); // mode
        e.f32(0.0); // progress
        e.byte(0); // gait_type
        e.f32(0.0); // foot_raise_height
        for _ in 0..3 {
            e.f32(0.0); // position
        }
        e.f32(0.0); // body_height
        for v in velocity {
            e.f32(v);
        }
        e.f32(yaw_speed);
        for _ in 0..4 {
            e.f32(0.0); // range_obstacle
        }
        for _ in 0..4 {
            e.i16(0); // foot_force
        }
        for _ in 0..12 {
            e.f32(0.0); // foot_position_body
        }
        for _ in 0..12 {
            e.f32(0.0); // foot_speed_body
        }
        // The SDK IDL's PathPoint_[10] is omitted: the .msg layout ends
        // here, and the decoder reads it only if present.
    });
    e.finish()
}

fn wireless_controller(rep: Representation) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.f32(0.5); // lx
        e.f32(-0.5); // ly
        e.f32(0.0); // rx
        e.f32(0.0); // ry
        e.u16(0x00FF); // keys
    });
    e.finish()
}

fn enc_hg_motor_cmd(e: &mut Enc, m: Mc) {
    e.byte(m.0);
    e.f32(m.1);
    e.f32(m.2);
    e.f32(m.3);
    e.f32(m.4);
    e.f32(m.5);
    e.u32(0); // reserve (single u32)
}

fn hg_low_cmd(rep: Representation, motors: &[Mc; 35], crc: u32) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.byte(0); // mode_pr
        e.byte(0); // mode_machine
        e.nonprim_seq(|e| {
            for m in motors {
                enc_hg_motor_cmd(e, *m);
            }
        });
        for _ in 0..4 {
            e.u32(0); // reserve[4]
        }
        e.u32(crc);
    });
    e.finish()
}

fn enc_hg_imu(e: &mut Enc) {
    for _ in 0..4 {
        e.f32(0.0);
    }
    e.f32(0.4); // gyro x
    e.f32(0.5); // gyro y
    e.f32(-0.6); // gyro z
    for _ in 0..3 {
        e.f32(0.0);
    }
    for _ in 0..3 {
        e.f32(0.0);
    }
    e.i16(0); // temperature i16
}

fn enc_hg_motor_state(e: &mut Enc, dq: f32) {
    e.byte(0);
    e.f32(0.0);
    e.f32(dq);
    e.f32(0.0);
    e.f32(0.0);
    e.i16(0);
    e.i16(0);
    e.f32(0.0); // vol
    e.u32(0);
    e.u32(0); // sensor[2]
    e.u32(0); // motorstate
    for _ in 0..4 {
        e.u32(0); // reserve[4]
    }
}

fn hg_low_state(rep: Representation, dqs: &[f32; 35], crc: u32) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.u32(0);
        e.u32(0); // version[2]
        e.byte(0); // mode_pr
        e.byte(0); // mode_machine
        e.u32(0); // tick
        enc_hg_imu(e);
        e.nonprim_seq(|e| {
            for dq in dqs {
                enc_hg_motor_state(e, *dq);
            }
        });
        e.bytes(&[0; 40]); // wireless_remote
        for _ in 0..4 {
            e.u32(0); // reserve[4]
        }
        e.u32(crc);
    });
    e.finish()
}

fn hg_imu_state(rep: Representation) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(enc_hg_imu);
    e.finish()
}

fn hg_double_imu(rep: Representation) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        enc_hg_imu(e);
        e.u32(7); // tick
    });
    e.finish()
}

/// A hg hand command with `n` motors (the hand sequence is bounded).
fn hg_hand_cmd(rep: Representation, dqs: &[(f32, f32)]) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.nonprim_seq(|e| {
            e.u32(dqs.len() as u32);
            for &(dq, kd) in dqs {
                e.structure(|e| enc_hg_motor_cmd(e, (1, 0.0, dq, 0.0, 0.0, kd)));
            }
        });
        for _ in 0..4 {
            e.u32(0); // reserve[4]
        }
    });
    e.finish()
}

/// An api `Request_`.
fn api_request(rep: Representation, api_id: i64, parameter: &[u8]) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.structure(|e| {
            e.structure(|e| {
                e.i64(100); // identity.id
                e.i64(api_id); // identity.api_id
            });
            e.structure(|e| e.i64(0)); // lease.id
            e.structure(|e| {
                e.i32(0); // policy.priority
                e.byte(1); // policy.noreply
            });
        });
        e.string(parameter); // parameter
        e.octet_seq(&[]); // binary
    });
    e.finish()
}

fn api_response(rep: Representation, code: i32, data: &[u8]) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.structure(|e| {
            e.structure(|e| {
                e.i64(100);
                e.i64(1008);
            });
            e.structure(|e| e.i32(code)); // status.code
        });
        e.string(data);
        e.octet_seq(&[1, 2, 3]);
    });
    e.finish()
}

fn zero_motors<const N: usize>() -> [Mc; N] {
    [(0, 0.0, 0.0, 0.0, 0.0, 0.0); N]
}

// ---------------------------------------------------------------- decode

#[test]
fn go_low_cmd_decodes_to_a_joint_command() {
    // CRC correctness is tested against independent vectors in
    // `tests/unitree_vectors.rs` (review item 13: the CRC asserted here
    // used to be recomputed by the decoder itself, which is circular).
    let mut motors = zero_motors::<20>();
    motors[2] = (1, 0.0, -2.5, 0.0, 0.0, 4.0); // kd != 0: the dq acts
    motors[5] = (1, 0.0, 9.0, 0.0, 0.0, 0.0); // kd == 0, ignored
    let bytes = go_low_cmd(Representation::CdrLe, &motors, 0);
    let d = decode_payload(MessageKind::UnitreeGoLowCmd, &bytes, &L).unwrap();
    assert_eq!(d.trailing_bytes, 0);
    let MotionMessage::UnitreeGoLowCmd(c) = d.message else {
        panic!();
    };
    // The crc field (0) does not match: crc_ok is false, and nothing else
    // changes (crc_ok is advisory, review item 8).
    assert!(!c.crc_ok());
    let frame = c.joint_frame();
    assert_eq!(frame.as_slice().len(), 20);
    assert_eq!(frame.max_commanded_joint_speed(), 2.5);
    // The pipeline event is a joint command with that speed.
    let ev = d.message.to_event(&ctx());
    match ev {
        RobotEvent::MotionCommand(c) => assert_eq!(c.joint_speed, Some(2.5)),
        e => panic!("{e:?}"),
    }
    assert_eq!(d.message.role(), MotionRole::Command);
    assert_eq!(d.message.unitree_crc_ok(), Some(false));
}

fn ctx() -> EventContext<'static> {
    EventContext {
        channel: "rt/lowcmd",
        writer_guid: Some("abc"),
        timestamp_ns: 0,
    }
}

#[test]
fn go_low_state_feedback() {
    for rep in XCDR1 {
        let mut dqs = [0.0f32; 20];
        dqs[7] = -3.0;
        let bytes = go_low_state(rep, &dqs, 0);
        let d = decode_payload(MessageKind::UnitreeGoLowState, &bytes, &L).unwrap();
        assert_eq!(d.trailing_bytes, 0, "{rep:?}");
        let MotionMessage::UnitreeGoLowState(s) = &d.message else {
            panic!();
        };
        assert_eq!(s.joint_frame().max_abs_velocity(), Some(3.0));
        match d.message.to_event(&ctx()) {
            RobotEvent::MotionFeedback(f) => {
                assert_eq!(f.measured_joint_speed, Some(3.0));
                assert_eq!(f.angular_velocity_x, Some(0.1_f32 as f64));
                assert_eq!(f.angular_velocity, Some(0.3_f32 as f64));
            }
            e => panic!("{e:?}"),
        }
    }
}

#[test]
fn go_sport_mode_state_velocity() {
    for rep in XCDR1 {
        let bytes = go_sport_mode_state(rep, [1.5, -0.5, 0.0], 0.8);
        let d = decode_payload(MessageKind::UnitreeGoSportModeState, &bytes, &L).unwrap();
        assert_eq!(d.trailing_bytes, 0, "{rep:?}");
        match d.message.to_event(&ctx()) {
            RobotEvent::MotionFeedback(f) => {
                assert_eq!(f.linear_velocity, Some(1.5_f32 as f64));
                assert_eq!(f.linear_velocity_y, Some(-0.5_f32 as f64));
                assert_eq!(f.angular_velocity, Some(0.8_f32 as f64));
                let want = (1.5_f32 as f64).hypot(-0.5_f32 as f64);
                assert_eq!(f.measured_linear_speed, Some(want));
            }
            e => panic!("{e:?}"),
        }
    }
}

#[test]
fn go_sport_mode_state_with_path_point_tail() {
    // Append a PathPoint_[10] (70 floats) after the .msg body: the decoder
    // consumes it (SDK IDL layout) rather than leaving trailing bytes.
    let mut e = Enc::new(Representation::CdrLe);
    let base = go_sport_mode_state(Representation::CdrLe, [0.0; 3], 0.0);
    e.bytes(&base[4..]); // reuse the body (drop the 4-byte header)
    for _ in 0..70 {
        e.f32(0.0);
    }
    let mut bytes = Representation::CdrLe.id().to_be_bytes().to_vec();
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&e.body);
    let d = decode_unitree(UnitreeKind::GoSportModeState, &bytes, &L).unwrap();
    match d.message {
        UnitreeMessage::GoSportModeState(s) => assert!(s.path_point.is_some()),
        m => panic!("{m:?}"),
    }
    assert_eq!(d.trailing_bytes, 0);
}

#[test]
fn hg_low_cmd_and_state() {
    for rep in XCDR1 {
        let mut cmd = zero_motors::<35>();
        cmd[30] = (1, 0.0, 1.25, 0.0, 0.0, 2.0);
        let cb = hg_low_cmd(rep, &cmd, 0);
        let d = decode_payload(MessageKind::UnitreeHgLowCmd, &cb, &L).unwrap();
        let MotionMessage::UnitreeHgLowCmd(c) = &d.message else {
            panic!();
        };
        assert_eq!(c.joint_frame().as_slice().len(), 35);
        assert_eq!(c.joint_frame().max_commanded_joint_speed(), 1.25);

        let mut dqs = [0.0f32; 35];
        dqs[0] = 5.0;
        let sb = hg_low_state(rep, &dqs, 0);
        let d = decode_payload(MessageKind::UnitreeHgLowState, &sb, &L).unwrap();
        match &d.message {
            MotionMessage::UnitreeHgLowState(s) => {
                assert_eq!(s.joint_frame().max_abs_velocity(), Some(5.0));
            }
            m => panic!("{m:?}"),
        }
    }
}

#[test]
fn hg_hand_cmd_bounded_sequence() {
    let bytes = hg_hand_cmd(
        Representation::CdrLe,
        &[(1.0, 2.0), (-3.0, 2.0), (0.0, 0.0)],
    );
    let d = decode_payload(MessageKind::UnitreeHgHandCmd, &bytes, &L).unwrap();
    let MotionMessage::UnitreeHgHandCmd(c) = &d.message else {
        panic!();
    };
    assert_eq!(c.joint_frame().as_slice().len(), 3);
    assert_eq!(c.joint_frame().max_commanded_joint_speed(), 3.0);
    // A sequence longer than the cap is rejected, not truncated.
    let tight = Limits {
        max_sequence_len: 2,
        ..L
    };
    assert!(matches!(
        decode_payload(MessageKind::UnitreeHgHandCmd, &bytes, &tight),
        Err(DecodeError::SequenceTooLong { .. })
    ));
}

#[test]
fn hg_imu_variants() {
    for rep in XCDR1 {
        let ib = hg_imu_state(rep);
        let d = decode_payload(MessageKind::UnitreeHgImuState, &ib, &L).unwrap();
        match d.message.to_event(&ctx()) {
            RobotEvent::MotionFeedback(f) => {
                assert_eq!(f.angular_velocity_x, Some(0.4_f32 as f64));
                assert_eq!(f.angular_velocity, Some(-0.6_f32 as f64));
            }
            e => panic!("{e:?}"),
        }
        let db = hg_double_imu(rep);
        let d = decode_payload(MessageKind::UnitreeHgDoubleImuState, &db, &L).unwrap();
        match d.message {
            MotionMessage::UnitreeHgDoubleImuState(s) => assert_eq!(s.tick, 7),
            m => panic!("{m:?}"),
        }
        assert_eq!(d.trailing_bytes, 0);
    }
}

// ---------------------------------------------------------------- API

#[test]
fn api_request_move_to_twist() {
    for rep in XCDR1 {
        let bytes = api_request(rep, 1008, br#"{"x":0.6,"y":-0.2,"z":0.9}"#);
        let d = decode_payload(MessageKind::UnitreeApiRequest, &bytes, &L).unwrap();
        let MotionMessage::UnitreeApiRequest(q) = &d.message else {
            panic!();
        };
        assert_eq!(q.api_id, 1008);
        assert!(q.noreply());
        let call = q.call(ApiService::Sport, Some(UnitreeModel::Go2));
        assert!(matches!(
            call,
            ApiCall::Move {
                vx,
                vy,
                vyaw
            } if vx == 0.6 && vy == -0.2 && vyaw == 0.9
        ));
        // As an event: a twist-like command on the api channel.
        let c = EventContext {
            channel: "rt/api/sport/request",
            writer_guid: None,
            timestamp_ns: 0,
        };
        match d.message.to_event(&c) {
            RobotEvent::MotionCommand(mc) => {
                assert_eq!(mc.linear_speed, Some(0.6));
                assert_eq!(mc.linear_y, Some(-0.2));
                assert_eq!(mc.angular_speed, Some(0.9));
            }
            e => panic!("{e:?}"),
        }
    }
}

#[test]
fn api_loco_set_velocity_and_fsm() {
    let bytes = api_request(
        Representation::CdrLe,
        7105,
        br#"{"velocity":[0.3,0.0,-0.4],"duration":1.0}"#,
    );
    let q = match decode_unitree(UnitreeKind::ApiRequest, &bytes, &L)
        .unwrap()
        .message
    {
        UnitreeMessage::ApiRequest(q) => q,
        m => panic!("{m:?}"),
    };
    assert!(matches!(
        q.call(ApiService::Sport, Some(UnitreeModel::G1)),
        ApiCall::SetVelocity { vx, vy, vyaw, duration }
            if vx == 0.3 && vy == 0.0 && vyaw == -0.4 && duration == 1.0
    ));
    // Damp = SetFsmId(1) on the loco service.
    let bytes = api_request(Representation::CdrLe, 7101, br#"{"data":1}"#);
    let q = match decode_unitree(UnitreeKind::ApiRequest, &bytes, &L)
        .unwrap()
        .message
    {
        UnitreeMessage::ApiRequest(q) => q,
        m => panic!("{m:?}"),
    };
    assert!(matches!(
        q.call(ApiService::Sport, Some(UnitreeModel::G1)),
        ApiCall::SetFsmId {
            fsm_id: 1,
            meaning: FsmMeaning::Damp
        }
    ));
}

#[test]
fn api_unknown_and_malformed_and_hostile_json() {
    // Unknown api_id: not an error.
    let bytes = api_request(Representation::CdrLe, 9999, b"");
    let q = match decode_unitree(UnitreeKind::ApiRequest, &bytes, &L)
        .unwrap()
        .message
    {
        UnitreeMessage::ApiRequest(q) => q,
        m => panic!("{m:?}"),
    };
    assert_eq!(
        q.call(ApiService::Sport, Some(UnitreeModel::Go2)),
        ApiCall::Unknown { api_id: 9999 }
    );
    // Move with a non-numeric axis: Malformed, a velocity call with no speed.
    let bytes = api_request(Representation::CdrLe, 1008, br#"{"x":"fast","y":0,"z":0}"#);
    let q = match decode_unitree(UnitreeKind::ApiRequest, &bytes, &L)
        .unwrap()
        .message
    {
        UnitreeMessage::ApiRequest(q) => q,
        m => panic!("{m:?}"),
    };
    let call = q.call(ApiService::Sport, Some(UnitreeModel::Go2));
    assert_eq!(call.class(), ApiClass::Malformed);
    // A malformed velocity call surfaces as a non-finite body velocity.
    assert!(call.body_velocity().unwrap().0.is_nan());

    // Hostile JSON: duplicate key, oversized, deeply nested, not UTF-8.
    for p in [
        br#"{"x":1,"x":2}"#.to_vec(),
        vec![b'{'; 20_000],
        {
            let mut v = b"{\"a\":".to_vec();
            v.extend(std::iter::repeat_n(b'[', 100));
            v
        },
        b"{\"x\":\"\xff\"}".to_vec(),
    ] {
        // A big parameter needs a matching CDR string cap (the robot's
        // own parameter strings are short, but the JSON size cap must be
        // what rejects the oversized one, not the CDR layer here).
        let big = Limits {
            max_string_len: 128 * 1024,
            ..L
        };
        let bytes = api_request(Representation::CdrLe, 1008, &p);
        let d = decode_payload(MessageKind::UnitreeApiRequest, &bytes, &big).unwrap();
        // The message still decodes (the parameter is opaque bytes); only
        // interpretation reports the problem, and it is an anomaly.
        let MotionMessage::UnitreeApiRequest(q) = &d.message else {
            panic!();
        };
        assert!(q.parameter_json().is_err());
        assert_eq!(
            q.call(ApiService::Sport, Some(UnitreeModel::Go2)).class(),
            ApiClass::Malformed
        );
        assert_eq!(d.anomalies().len(), 1, "unverifiable command anomaly");
    }
}

#[test]
fn api_response_and_wireless_are_not_motion() {
    let bytes = api_response(Representation::CdrLe, 0, br#"{"ok":1}"#);
    let d = decode_unitree(UnitreeKind::ApiResponse, &bytes, &L).unwrap();
    match d.message {
        UnitreeMessage::ApiResponse(r) => {
            assert_eq!(r.status_code, 0);
            assert_eq!(r.binary, &[1, 2, 3]);
        }
        m => panic!("{m:?}"),
    }
    // Response / WirelessController are not MessageKinds.
    assert!(UnitreeKind::ApiResponse.message_kind().is_none());
    assert!(UnitreeKind::GoWirelessController.message_kind().is_none());
    let wb = wireless_controller(Representation::CdrLe);
    let w = decode_unitree(UnitreeKind::GoWirelessController, &wb, &L).unwrap();
    assert!(matches!(w.message, UnitreeMessage::GoWirelessController(_)));
}

// ---------------------------------------------------------------- hostile

/// Build one valid sample of every Unitree kind.
fn all_unitree_samples() -> Vec<(UnitreeKind, Vec<u8>)> {
    vec![
        (
            UnitreeKind::GoLowCmd,
            go_low_cmd(Representation::CdrLe, &zero_motors(), 0),
        ),
        (
            UnitreeKind::GoLowState,
            go_low_state(Representation::CdrLe, &[0.0; 20], 0),
        ),
        (
            UnitreeKind::GoSportModeState,
            go_sport_mode_state(Representation::CdrLe, [0.0; 3], 0.0),
        ),
        (
            UnitreeKind::GoWirelessController,
            wireless_controller(Representation::CdrLe),
        ),
        (
            UnitreeKind::HgLowCmd,
            hg_low_cmd(Representation::CdrLe, &zero_motors(), 0),
        ),
        (
            UnitreeKind::HgLowState,
            hg_low_state(Representation::CdrLe, &[0.0; 35], 0),
        ),
        (
            UnitreeKind::HgHandCmd,
            hg_hand_cmd(Representation::CdrLe, &[(1.0, 1.0)]),
        ),
        (UnitreeKind::HgImuState, hg_imu_state(Representation::CdrLe)),
        (
            UnitreeKind::HgDoubleImuState,
            hg_double_imu(Representation::CdrLe),
        ),
        (
            UnitreeKind::ApiRequest,
            api_request(Representation::CdrLe, 1008, br#"{"x":0,"y":0,"z":0}"#),
        ),
        (
            UnitreeKind::ApiResponse,
            api_response(Representation::CdrLe, 0, b"x"),
        ),
    ]
}

#[test]
fn every_truncation_is_an_error_not_a_panic() {
    for (kind, bytes) in all_unitree_samples() {
        assert!(decode_unitree(kind, &bytes, &L).is_ok(), "{kind:?} full");
        for n in 0..bytes.len() {
            // HandState is not in this list; the rest end exactly at their
            // last member, so every strict prefix must fail cleanly.
            let r = decode_unitree(kind, &bytes[..n], &L);
            assert!(r.is_err(), "{kind:?} prefix {n}/{} decoded", bytes.len());
        }
    }
}

#[test]
fn every_kind_on_every_sample_never_panics() {
    for (_, bytes) in all_unitree_samples() {
        for kind in UnitreeKind::ALL {
            let _ = decode_unitree(kind, &bytes, &L);
        }
        for kind in MessageKind::ALL {
            let _ = decode_payload(kind, &bytes, &L);
        }
    }
}

#[test]
fn hand_state_decodes_with_empty_sequences() {
    // HandState has three leading sequences; build one with empty motor and
    // sensor lists to exercise the zero-length path.
    let mut e = Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.nonprim_seq(|e| e.u32(0)); // motor_state[]
        e.nonprim_seq(|e| e.u32(0)); // press_sensor_state[]
        enc_hg_imu(e); // imu_state
        e.f32(0.0); // power_v
        e.f32(0.0); // power_a
        e.f32(0.0); // system_v
        e.f32(0.0); // device_v
        e.u32(0);
        e.u32(0); // error[2]
        e.u32(0);
        e.u32(0); // reserve[2]
    });
    let bytes = e.finish();
    let d = decode_payload(MessageKind::UnitreeHgHandState, &bytes, &L).unwrap();
    match &d.message {
        MotionMessage::UnitreeHgHandState(s) => {
            assert_eq!(s.joint_frame().max_abs_velocity(), None);
        }
        m => panic!("{m:?}"),
    }
}

// ---------------------------------------------------------------- xcdr2

#[test]
fn plain_xcdr2_go_low_cmd() {
    // CDR2_LE: doubles / u32 align to 4; there are none wider than 4 here,
    // so the body is identical to XCDR1, but the 20-element struct array is
    // still read without a DHEADER (plain XCDR2).
    let bytes = go_low_cmd(Representation::Cdr2Le, &zero_motors(), 0);
    let d = decode_payload(MessageKind::UnitreeGoLowCmd, &bytes, &L).unwrap();
    assert_eq!(d.encapsulation.representation, Representation::Cdr2Le);
    assert_eq!(d.trailing_bytes, 0);
}

#[test]
fn delimited_xcdr2_api_request() {
    // The Unitree types are @final (review item 12): under a D_CDR2_LE
    // header the body is read exactly as plain XCDR2, with no struct
    // DHEADERs (Cyclone DDS takes the extensibility from the type).
    let mut bytes = api_request(Representation::Cdr2Le, 1008, br#"{"x":0,"y":0,"z":0}"#);
    bytes[1] = 0x09; // D_CDR2_LE
    let d = decode_payload(MessageKind::UnitreeApiRequest, &bytes, &L).unwrap();
    assert_eq!(d.encapsulation.representation, Representation::DCdr2Le);
    let MotionMessage::UnitreeApiRequest(q) = &d.message else {
        panic!();
    };
    assert_eq!(q.api_id, 1008);
    assert_eq!(d.trailing_bytes, 0);
    // A body that wraps every struct in a DHEADER (what an @appendable
    // type would send) is not this type's layout: it is not read as one.
    let wrapped = api_request(Representation::DCdr2Le, 1008, br#"{"x":0,"y":0,"z":0}"#);
    match decode_payload(MessageKind::UnitreeApiRequest, &wrapped, &L) {
        Err(_) => {}
        Ok(d) => {
            let MotionMessage::UnitreeApiRequest(q) = &d.message else {
                panic!();
            };
            assert_ne!(q.api_id, 1008);
        }
    }
}

// ---------------------------------------------------------------- model table

#[test]
fn model_table_is_consistent() {
    use robodr_cdr::unitree::{Generation, IdlFamily};
    for m in UnitreeModel::ALL {
        let info = m.info();
        assert_eq!(info.model, m);
        assert!(!info.source.is_empty(), "{m:?} has no source");
        assert_eq!(UnitreeModel::from_name(info.name), Some(m), "{m:?} name");
        assert_eq!(
            UnitreeModel::from_name(&format!("{m:?}")),
            Some(m),
            "{m:?} debug name"
        );
        // Motor slots follow the IDL family.
        match info.idl {
            Some(IdlFamily::Go) | Some(IdlFamily::LegacyComm) => {
                assert_eq!(info.motor_slots, Some(MOTOR_SLOTS_GO))
            }
            Some(IdlFamily::Hg) => assert_eq!(info.motor_slots, Some(MOTOR_SLOTS_HG)),
            None => assert_eq!(info.motor_slots, None),
        }
        // Legacy models use the UDP generation; SDK2 models the DDS one.
        let legacy = matches!(
            m,
            UnitreeModel::Go1 | UnitreeModel::A1 | UnitreeModel::Aliengo | UnitreeModel::B1
        );
        assert_eq!(
            info.generation == Generation::LegacyUdp,
            legacy,
            "{m:?} generation"
        );
        // Actuated motors never exceed the available slots.
        if let (Some(a), Some(s)) = (info.actuated_motors, info.motor_slots) {
            assert!(a <= s, "{m:?}: {a} actuated > {s} slots");
        }
    }
    // Specific, SDK-sourced counts.
    assert_eq!(UnitreeModel::Go2.info().actuated_motors, Some(12));
    assert_eq!(UnitreeModel::G1.info().actuated_motors, Some(29));
    assert_eq!(UnitreeModel::H2.info().actuated_motors, Some(31));
    assert_eq!(UnitreeModel::H1_2.info().actuated_motors, Some(27));
    assert_eq!(UnitreeModel::R1.info().actuated_motors, Some(26));
    assert_eq!(UnitreeModel::from_name("h1-2"), Some(UnitreeModel::H1_2));
    assert_eq!(UnitreeModel::from_name("nonesuch"), None);
}

#[test]
fn type_names_round_trip() {
    for k in UnitreeKind::ALL {
        assert_eq!(UnitreeKind::from_type_name(k.dds_type_name()), Some(k));
        assert_eq!(UnitreeKind::from_type_name(k.ros_type_name()), Some(k));
        if let Some(mk) = k.message_kind() {
            assert_eq!(mk.unitree_kind(), Some(k));
            assert_eq!(MessageKind::from_type_name(k.dds_type_name()), Some(mk));
            assert_eq!(MessageKind::from_type_name(k.ros_type_name()), Some(mk));
        }
    }
    // The registry resolves the Unitree DDS names.
    let reg = robodr_cdr::Registry::with_builtin();
    assert_eq!(
        reg.kind("unitree_go::msg::dds_::LowCmd_"),
        Some(MessageKind::UnitreeGoLowCmd)
    );
    assert_eq!(
        reg.kind("unitree_hg::msg::dds_::LowCmd_"),
        Some(MessageKind::UnitreeHgLowCmd)
    );
    assert_eq!(
        reg.kind("unitree_api::msg::dds_::Request_"),
        Some(MessageKind::UnitreeApiRequest)
    );
}
