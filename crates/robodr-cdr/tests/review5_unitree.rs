//! Regressions for the independent review of the Unitree decoders
//! (commit 958a2ae). One section per review item; every test here failed
//! before its fix.

mod common;

use common::*;
use robodr_cdr::unitree::*;
use robodr_cdr::{
    decode_payload, EventContext, Limits, MessageKind, MotionMessage, Representation,
};
use robodr_events::profile::{Envelope, Profile};
use robodr_events::{CommandClass, MotionCommand, RobotEvent, Severity};

/// A motor command (mode, q, dq, tau, kp, kd).
type Mc = (u8, f32, f32, f32, f32, f32);

const IDLE: Mc = (0, 0.0, 0.0, 0.0, 0.0, 0.0);

fn hg_low_cmd(motors: &[Mc; 35]) -> Vec<u8> {
    let mut e = Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.byte(0); // mode_pr
        e.byte(0); // mode_machine
        e.nonprim_seq(|e| {
            for m in motors {
                enc_hg_motor_cmd(e, *m);
            }
        });
        for _ in 0..4 {
            e.u32(0);
        }
        e.u32(0); // crc (not checked here)
    });
    e.finish()
}

fn enc_hg_motor_cmd(e: &mut Enc, m: Mc) {
    e.byte(m.0);
    for v in [m.1, m.2, m.3, m.4, m.5] {
        e.f32(v);
    }
    e.u32(0);
}

fn api_request(api_id: i64, parameter: &[u8]) -> Vec<u8> {
    let mut e = Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.structure(|e| {
            e.structure(|e| {
                e.i64(7);
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

fn ctx(channel: &str) -> EventContext<'_> {
    EventContext {
        channel,
        writer_guid: Some("w"),
        timestamp_ns: 0,
    }
}

fn command(kind: MessageKind, bytes: &[u8], channel: &str) -> MotionCommand {
    let d = decode_payload(kind, bytes, &Limits::default()).unwrap();
    match d.message.to_event(&ctx(channel)) {
        RobotEvent::MotionCommand(c) => c,
        e => panic!("{e:?}"),
    }
}

fn hg_command(motors: &[Mc; 35], channel: &str) -> MotionCommand {
    command(MessageKind::UnitreeHgLowCmd, &hg_low_cmd(motors), channel)
}

fn request(api_id: i64, parameter: &[u8]) -> ApiRequest<'static> {
    let bytes: &'static [u8] = Box::leak(api_request(api_id, parameter).into_boxed_slice());
    match decode_unitree(UnitreeKind::ApiRequest, bytes, &Limits::default())
        .unwrap()
        .message
    {
        UnitreeMessage::ApiRequest(q) => q,
        m => panic!("{m:?}"),
    }
}

fn profile(channel: &str, env: Envelope) -> Profile {
    let mut p = Profile {
        model: "g1".into(),
        locked: true,
        ..Default::default()
    };
    p.writer_topics.insert(channel.into());
    p.motion_envelopes.insert(channel.into(), env);
    p
}

fn verdict(p: &Profile, c: MotionCommand) -> Option<(String, Severity)> {
    p.evaluate(&RobotEvent::MotionCommand(c))
        .map(|d| (d.rule.to_string(), d.severity))
}

// ------------------------------------------------- 1. mode is not "active"

/// `rt/arm_sdk` frames always carry `mode = 0` and move the arms with
/// kp / kd / dq; the blend weight sits in `motor_cmd[29].q` on G1
/// (`example/g1/high_level/g1_arm7_sdk_dds_example.cpp`).
#[test]
fn item1_arm_sdk_mode_zero_slots_count() {
    let mut m = [IDLE; 35];
    m[15] = (0, 0.3, 4.0, 0.0, 60.0, 3.0); // left shoulder pitch
    m[29] = (0, 1.0, 0.0, 0.0, 0.0, 0.0); // arm SDK weight
    let c = hg_command(&m, "/arm_sdk");
    assert_eq!(c.joint_speed, Some(4.0));
    // A non-finite value in any slot poisons the frame, mode or not.
    let mut bad = [IDLE; 35];
    bad[3].2 = f32::NAN;
    assert!(hg_command(&bad, "/arm_sdk").joint_speed.unwrap().is_nan());
    let mut bad = [IDLE; 35];
    bad[34].4 = f32::INFINITY; // kp of an unused slot
    assert!(hg_command(&bad, "/arm_sdk").joint_speed.unwrap().is_nan());
}

// ------------------------------------- 2. torque / gain commands checkable

#[test]
fn item2_torque_and_gain_frames_are_checked() {
    let ch = "/lowcmd";
    let mut torque = [IDLE; 35];
    torque[3] = (1, 0.0, 0.0, 500.0, 0.0, 0.0);
    let mut gain = [IDLE; 35];
    gain[3] = (1, 0.0, 0.0, 0.0, 500.0, 0.0);
    let ct = hg_command(&torque, ch);
    let cg = hg_command(&gain, ch);
    assert_eq!(ct.joint_speed, Some(0.0));
    assert_eq!(ct.joint_torque, Some(500.0));
    assert_eq!(cg.joint_kp, Some(500.0));
    let bounded = profile(
        ch,
        Envelope {
            max_joint_speed: Some(5.0),
            max_joint_torque: Some(50.0),
            max_joint_kp: Some(150.0),
            max_joint_position_step: Some(0.1),
            ..Default::default()
        },
    );
    let over = Some((
        "robot.motion.joint_over_envelope".to_string(),
        Severity::Critical,
    ));
    assert_eq!(verdict(&bounded, ct.clone()), over);
    assert_eq!(verdict(&bounded, cg.clone()), over);
    let legacy = profile(
        ch,
        Envelope {
            max_joint_speed: Some(5.0),
            ..Default::default()
        },
    );
    let unverifiable = Some((
        "robot.motion.unverifiable_command".to_string(),
        Severity::Medium,
    ));
    assert_eq!(verdict(&legacy, ct), unverifiable);
    assert_eq!(verdict(&legacy, cg), unverifiable);
}

// ---------------------------------------------- 3. api_id low 32 bits

#[test]
fn item3_api_id_is_dispatched_on_its_low_32_bits() {
    let aliased = (1i64 << 32) + 1008; // low 32 bits = 1008 = Move
    let q = request(aliased, br#"{"x":2.5,"y":0,"z":0}"#);
    let call = q.call_for_topic("rt/api/sport/request", None);
    assert_eq!(call.body_velocity(), Some((2.5, 0.0, 0.0)));
    // -2^32 + 1008 aliases too.
    let q = request(1008 - (1i64 << 32), br#"{"x":2.5,"y":0,"z":0}"#);
    assert_eq!(
        q.call_for_topic("rt/api/sport/request", None)
            .body_velocity(),
        Some((2.5, 0.0, 0.0))
    );
    // And the out-of-range id is itself an anomaly.
    let bytes = api_request(aliased, br#"{"x":2.5,"y":0,"z":0}"#);
    let d = decode_payload(MessageKind::UnitreeApiRequest, &bytes, &Limits::default()).unwrap();
    assert_eq!(d.anomalies().len(), 1, "{:?}", d.anomalies());
    // An in-range id is not.
    let bytes = api_request(1008, br#"{"x":0.5,"y":0,"z":0}"#);
    let d = decode_payload(MessageKind::UnitreeApiRequest, &bytes, &Limits::default()).unwrap();
    assert!(d.anomalies().is_empty());
}

// --------------------------------------- 4. missing velocity services

#[test]
fn item4_obstacles_avoid_and_agv_move_are_velocity() {
    let q = request(1003, br#"{"x":0.4,"y":-0.1,"yaw":0.7,"mode":0}"#);
    assert_eq!(
        q.call_for_topic("rt/api/obstacles_avoid/request", None)
            .body_velocity(),
        Some((0.4, -0.1, 0.7))
    );
    // mode 1 / 2: a position target, not a velocity.
    for mode in [1, 2] {
        let p = format!(r#"{{"x":3,"y":0,"yaw":0,"mode":{mode}}}"#);
        let q = request(1003, p.as_bytes());
        let call = q.call_for_topic("rt/api/obstacles_avoid/request", None);
        assert_eq!(call.body_velocity(), None);
        assert_eq!(call.class(), ApiClass::Trajectory);
    }
    let q = request(1001, br#"{"vx":0.8,"vy":0.0,"vyaw":-0.5}"#);
    assert_eq!(
        q.call_for_topic("rt/api/agv/request", None).body_velocity(),
        Some((0.8, 0.0, -0.5))
    );
    // As events: a twist-like command.
    let bytes = api_request(1001, br#"{"vx":0.8,"vy":0.0,"vyaw":-0.5}"#);
    let c = command(MessageKind::UnitreeApiRequest, &bytes, "/api/agv/request");
    assert_eq!(c.linear_speed, Some(0.8));
    assert_eq!(c.angular_speed, Some(-0.5));
}

#[test]
fn item4_other_motion_services() {
    // robot_state ServiceSwitch can stop / start the sport service.
    let q = request(1001, br#"{"name":"sport_mode","switch":0}"#);
    assert_eq!(
        q.call_for_topic("rt/api/robot_state/request", None).class(),
        ApiClass::ControlHandover
    );
    // uwbswitch SwitchSet makes the Go2 follow the UWB tag.
    let q = request(1001, br#"{"enable":true}"#);
    assert_eq!(
        q.call_for_topic("rt/api/uwbswitch/request", None).class(),
        ApiClass::ControlHandover
    );
    // Non-motion services stay uninterpreted.
    let q = request(1001, br#"{"x":1}"#);
    assert!(matches!(
        q.call_for_topic("rt/api/voice/request", None),
        ApiCall::Unknown { .. }
    ));
}

// ------------------------------- 5. non-velocity motion calls are flagged

#[test]
fn item5_api_class_reaches_the_event_and_is_flagged() {
    /// (channel, api_id, parameter, class, rule, severity).
    type Case<'a> = (&'a str, i64, &'a [u8], CommandClass, &'a str, Severity);
    let cases: [Case<'_>; 6] = [
        (
            "/api/motion_switcher/request",
            1003,
            b"",
            CommandClass::ControlHandover,
            "robot.motion.control_handover",
            Severity::High,
        ),
        (
            "/api/loco/request",
            8204,
            br#"{"x":5,"y":0,"yaw":0,"relative":true}"#,
            CommandClass::Trajectory,
            "robot.motion.unverifiable_command",
            Severity::Medium,
        ),
        (
            "/api/arm/request",
            7106,
            br#"{"action_id":17}"#,
            CommandClass::Trick,
            "robot.motion.unverifiable_command",
            Severity::High,
        ),
        (
            "/api/sport/request",
            4242,
            b"",
            CommandClass::Unknown,
            "robot.motion.unverifiable_command",
            Severity::High,
        ),
        (
            "/api/sport/request",
            7101,
            br#"{"data":"x"}"#,
            CommandClass::Malformed,
            "robot.motion.unverifiable_command",
            Severity::High,
        ),
        (
            "/api/motion_switcher/request",
            1002,
            br#"{"name":"ai"}"#,
            CommandClass::ControlHandover,
            "robot.motion.control_handover",
            Severity::High,
        ),
    ];
    for (ch, id, param, class, rule, sev) in cases {
        let bytes = api_request(id, param);
        let c = command(MessageKind::UnitreeApiRequest, &bytes, ch);
        assert_eq!(c.command_class, Some(class), "{ch} {id}");
        assert!(c.command_name.is_some());
        let p = profile(
            ch,
            Envelope {
                max_linear_speed: Some(1.0),
                ..Default::default()
            },
        );
        assert_eq!(verdict(&p, c), Some((rule.to_string(), sev)), "{ch} {id}");
    }
    // The event path does not know the model: a G1-only id is Unknown
    // there (High), and ControlHandover once the model is known.
    let q = request(7110, br#"{"data":false}"#);
    assert_eq!(q.call(ApiService::Sport, None).class(), ApiClass::Unknown);
    assert_eq!(
        q.call(ApiService::Sport, Some(UnitreeModel::G1)).class(),
        ApiClass::ControlHandover
    );
    // A velocity call within the envelope stays clean.
    let bytes = api_request(1008, br#"{"x":0.5,"y":0,"z":0}"#);
    let c = command(MessageKind::UnitreeApiRequest, &bytes, "/api/sport/request");
    assert_eq!(c.command_class, Some(CommandClass::Velocity));
    let p = profile(
        "/api/sport/request",
        Envelope {
            max_linear_speed: Some(1.0),
            ..Default::default()
        },
    );
    assert_eq!(verdict(&p, c), None);
}

// ------------------------------------------- 6. long / array parameters

#[test]
fn item6_trajectory_follow_parameter_decodes_with_default_limits() {
    // unitree_sdk2py/b2/sport/sport_client.py TrajectoryFollow: a JSON
    // *array* of 30 path points (~3 KB).
    let mut p = String::from("[");
    for i in 0..30 {
        if i > 0 {
            p.push(',');
        }
        p.push_str(&format!(
            r#"{{"t_from_start": {:.6}, "x": 0.123456, "y": -0.654321, "yaw": 0.000001, "vx": 0.5, "vy": 0.0, "vyaw": 0.25}}"#,
            f64::from(i) * 0.1
        ));
    }
    p.push(']');
    assert!(p.len() > 2048, "{}", p.len());
    let bytes = api_request(1018, p.as_bytes());
    let d = decode_payload(MessageKind::UnitreeApiRequest, &bytes, &Limits::default())
        .expect("a 3 KB parameter decodes with the default limits");
    let MotionMessage::UnitreeApiRequest(q) = &d.message else {
        panic!();
    };
    // A top-level array is valid JSON for an opaque argument.
    assert!(d.anomalies().is_empty(), "{:?}", d.anomalies());
    let call = q.call(ApiService::Sport, Some(UnitreeModel::B2));
    assert_eq!(call.class(), ApiClass::Trajectory, "{call:?}");
    // A parameter above the JSON cap is refused by the CDR layer.
    let huge = vec![b' '; robodr_cdr::unitree::json::MAX_JSON_LEN + 1];
    let bytes = api_request(1008, &huge);
    assert!(decode_payload(MessageKind::UnitreeApiRequest, &bytes, &Limits::default()).is_err());
}

// ------------------------------------------------- 7. Dex3 mode bitfield

#[test]
fn item7_dex3_mode_is_a_bitfield_and_never_gates_checks() {
    // id 0, status 0, timeout 0: mode octet 0, but the motor is driven.
    let mut e = Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.nonprim_seq(|e| {
            e.u32(2);
            e.structure(|e| enc_hg_motor_cmd(e, (0x00, 0.1, 6.0, 0.0, 0.5, 0.1)));
            // id 1, status 1, timeout 1.
            e.structure(|e| enc_hg_motor_cmd(e, (0x91, 0.1, 1.0, 0.0, 0.5, 0.1)));
        });
        for _ in 0..4 {
            e.u32(0);
        }
    });
    let bytes = e.finish();
    let c = command(MessageKind::UnitreeHgHandCmd, &bytes, "/dex3/left/cmd");
    assert_eq!(c.joint_speed, Some(6.0));
}

// ----------------------------------------------- 10. Python-only FSM ids

#[test]
fn item10_python_fsm_ids_and_r1_arm_task() {
    let q = request(7101, br#"{"data":702}"#);
    assert!(matches!(
        q.call(ApiService::Sport, Some(UnitreeModel::G1)),
        ApiCall::SetFsmId {
            meaning: FsmMeaning::StandUp,
            ..
        }
    ));
    let q = request(7101, br#"{"data":702}"#);
    assert!(matches!(
        q.call(ApiService::Sport, Some(UnitreeModel::R1)),
        ApiCall::SetFsmId {
            meaning: FsmMeaning::LieDown,
            ..
        }
    ));
    let q = request(7101, br#"{"data":701}"#);
    assert!(matches!(
        q.call(ApiService::Sport, Some(UnitreeModel::R1)),
        ApiCall::SetFsmId {
            meaning: FsmMeaning::StandUp,
            ..
        }
    ));
    let q = request(7106, br#"{"data":1}"#);
    assert_eq!(
        q.call(ApiService::Sport, Some(UnitreeModel::R1)).name(),
        Some("SetArmTask")
    );
}

/// The G1 has 29 actuated motors, but slots 29..35 are on the wire and the
/// robot reads them (slot 29 is the arm-SDK weight): every slot is
/// evaluated.
#[test]
fn item10_slots_past_the_actuated_count_are_evaluated() {
    let mut m = [IDLE; 35];
    m[33] = (1, 0.0, 0.0, 300.0, 0.0, 0.0);
    let c = hg_command(&m, "/lowcmd");
    assert_eq!(c.joint_torque, Some(300.0));
    let info = UnitreeModel::G1.info();
    assert_eq!(info.actuated_motors, Some(29));
    assert_eq!(info.arm_sdk_weight_slot, Some(29));
}

// -------------------------------------------- 7. Dex3 bitfield accessor

#[test]
fn item7_dex3_mode_decodes() {
    let m = HgMotorCmd {
        mode: 0x91,
        ..Default::default()
    };
    assert_eq!(
        m.dex3_mode(),
        Dex3Mode {
            id: 1,
            status: 1,
            timeout: true
        }
    );
    assert_eq!(
        Dex3Mode::from_octet(0x16),
        Dex3Mode {
            id: 6,
            status: 1,
            timeout: false
        }
    );
    assert_eq!(Dex3Mode::from_octet(0), Dex3Mode::default());
}

// ------------------------------------------ 9. undecoded command types

fn go_motor_cmds(cmds: &[Mc]) -> Vec<u8> {
    let mut e = Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.nonprim_seq(|e| {
            e.u32(cmds.len() as u32);
            for m in cmds {
                e.structure(|e| {
                    e.byte(m.0);
                    for v in [m.1, m.2, m.3, m.4, m.5] {
                        e.f32(v);
                    }
                    for _ in 0..3 {
                        e.u32(0);
                    }
                });
            }
        });
    });
    e.finish()
}

/// `rt/hand_sdk` (`example/g1/high_level/g1_hand_sdk_example.cpp`):
/// `unitree_go` `MotorCmds_`, weight × 100 in `cmds[0].mode`, the hand
/// driven by `tau` only.
#[test]
fn item9_hand_sdk_motor_cmds() {
    let cmds = [
        (100, 0.0, 0.0, 0.3, 0.0, 0.0),
        (0, 0.0, 0.0, 0.3, 0.0, 0.0),
        (0, 0.0, 0.0, 0.3, 0.0, 0.0),
        (0, 0.0, 0.0, -9.0, 0.0, 0.0),
    ];
    let bytes = go_motor_cmds(&cmds);
    let d = decode_unitree_by_type_name(
        "unitree_go::msg::dds_::MotorCmds_",
        &bytes,
        &Limits::default(),
    )
    .unwrap();
    let UnitreeMessage::GoMotorCmds(m) = d.message else {
        panic!("{:?}", d.message);
    };
    assert_eq!(m.cmds.len(), 4);
    assert_eq!(m.hand_sdk_weight(), Some(1.0));
    let c = command(MessageKind::UnitreeGoMotorCmds, &bytes, "/hand_sdk");
    assert_eq!(c.joint_torque, Some(9.0));
    assert_eq!(c.joint_speed, Some(0.0));
    // ROS name too, and a too-long sequence is refused.
    assert_eq!(
        MessageKind::from_type_name("unitree_go/msg/MotorCmds"),
        Some(MessageKind::UnitreeGoMotorCmds)
    );
    let long = go_motor_cmds(&[IDLE; MAX_MOTOR_CMDS + 1]);
    assert!(decode_payload(MessageKind::UnitreeGoMotorCmds, &long, &Limits::default()).is_err());
}

/// `rt/waistpitchcmd` / `rt/waistpitchstate` (`example/g1/g1d/g1d_waist_example.cpp`):
/// standalone `unitree_hg` `MotorCmd_` / `MotorState_`.
#[test]
fn item9_waist_motor_cmd_and_state() {
    let mut e = Enc::new(Representation::CdrLe);
    e.structure(|e| enc_hg_motor_cmd(e, (1, 0.0, 0.0, 0.0, 500.0, 12.0)));
    let bytes = e.finish();
    let c = command(MessageKind::UnitreeHgMotorCmd, &bytes, "/waistpitchcmd");
    assert_eq!(c.joint_kp, Some(500.0));
    assert_eq!(
        MessageKind::from_type_name("unitree_hg::msg::dds_::MotorCmd_"),
        Some(MessageKind::UnitreeHgMotorCmd)
    );
    let mut e = Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.byte(1);
        for v in [0.1f32, -0.75, 0.0, 0.0] {
            e.f32(v);
        }
        e.i16(0);
        e.i16(0);
        e.f32(0.0);
        e.u32(0);
        e.u32(0);
        e.u32(0);
        for _ in 0..4 {
            e.u32(0);
        }
    });
    let bytes = e.finish();
    let d = decode_payload(MessageKind::UnitreeHgMotorState, &bytes, &Limits::default()).unwrap();
    assert_eq!(d.trailing_bytes, 0);
    match d.message.to_event(&ctx("/waistpitchstate")) {
        RobotEvent::MotionFeedback(f) => assert_eq!(f.measured_joint_speed, Some(0.75)),
        e => panic!("{e:?}"),
    }
}

#[test]
fn item9_model_topic_table_covers_every_command_topic() {
    let g1 = UnitreeModel::G1.info();
    for t in [
        topics::USER_LOWCMD,
        topics::HAND_SDK,
        topics::WAIST_PITCH_CMD,
        topics::WAIST_PITCH_STATE,
        topics::ARM_SDK,
    ] {
        assert!(g1.other_topics.contains(&t), "{t}");
    }
    assert!(g1.api_services.contains(&"agv"));
    let go2 = UnitreeModel::Go2.info();
    for s in ["obstacles_avoid", "robot_state", "uwbswitch"] {
        assert!(go2.api_services.contains(&s), "{s}");
    }
    assert!(go2.other_topics.contains(&topics::LF_LOWSTATE));
}

// ------------------------------------------------- 3. anomaly identity

#[test]
fn item3_out_of_range_id_anomaly_names_the_dispatched_id() {
    let bytes = api_request((1i64 << 32) + 1008, b"");
    let d = decode_payload(MessageKind::UnitreeApiRequest, &bytes, &Limits::default()).unwrap();
    assert_eq!(
        d.anomalies(),
        vec![robodr_cdr::DecodeAnomaly::ApiIdOutOfRange {
            api_id: (1i64 << 32) + 1008
        }]
    );
    assert!(d.anomalies()[0].to_string().contains("1008"));
    // decode_unitree reports it too.
    let u = decode_unitree(UnitreeKind::ApiRequest, &bytes, &Limits::default()).unwrap();
    assert_eq!(u.anomalies().len(), 1);
}

// ------------------------------------------------------- 8. CRC advisory

/// The CRC never changes the event: a frame with a wrong CRC maps to the
/// same command as one with the right CRC.
#[test]
fn item8_crc_does_not_change_the_event() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/unitree/hglowcmd_le.bin"
    ))
    .unwrap();
    let mut bad = bytes.clone();
    let n = bad.len();
    bad[n - 1] ^= 0xFF; // the crc field
    let a = command(MessageKind::UnitreeHgLowCmd, &bytes, "/lowcmd");
    let b = command(MessageKind::UnitreeHgLowCmd, &bad, "/lowcmd");
    assert_eq!(a, b);
    let da = decode_payload(MessageKind::UnitreeHgLowCmd, &bytes, &Limits::default()).unwrap();
    let db = decode_payload(MessageKind::UnitreeHgLowCmd, &bad, &Limits::default()).unwrap();
    assert_eq!(da.message.unitree_crc_ok(), Some(true));
    assert_eq!(db.message.unitree_crc_ok(), Some(false));
    assert_eq!(da.anomalies(), db.anomalies());
}
