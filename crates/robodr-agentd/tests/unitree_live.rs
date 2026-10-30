//! Unitree, end to end through the live daemon: a synthetic capture of the
//! robot's bus -> `robodr-capture` (RTPS and legacy UDP) -> pipeline
//! (SEDP-typed CDR decode of the Unitree IDL / legacy frame decode) ->
//! agent (profile envelope, recording-only Motion Firewall with the
//! low-level **joint** channel, responder) -> spool + black box.
//!
//! Per robot (Go2: `unitree_go` IDL, 12 of 20 slots; G1: `unitree_hg`, 29
//! of 35; H1: `unitree_go`, 20 slots, arm SDK; Go1: legacy UDP), the
//! profile is **learned** with `robodr-commission` from a clean capture and
//! locked, then:
//!
//! * (a) the clean capture replayed: no finding at all;
//! * (b) a rogue participant writing `rt/lowcmd`: discovery findings and the
//!   joint firewall's unknown-source verdict;
//! * (c) torque / kp / position step over the learned envelope: profile
//!   findings (and the joint firewall's would-have rejections);
//! * (d) `rt/arm_sdk` frames with `mode = 0` still count as motion;
//! * (e) an API id aliased past `int32` (`2^32 + id`): High finding;
//! * (f) a sport velocity request over the envelope: Critical deviation;
//! * (g) humanoids: no verdict ever records a zero / damping substitute.
//!
//! Every byte is built from the published IDL / `comm.h` layouts (the CRC
//! computed by `robodr-cdr`); the independent reviewer vectors of
//! `robodr-cdr/tests/data/unitree/` are also replayed through the daemon.
//! No capture of a real Unitree robot was available.

mod common;

#[path = "../../robodr-cdr/tests/common/mod.rs"]
mod cdrenc;

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::pcap::{datagram, frame, sedp_writer_sub, spdp_sub, user_data, ROBOT_IP, SPDP_GROUP};
use common::*;
use robodr_capture::{synth, LinkType, PcapWriter};
use robodr_cdr::{decode_unitree, Limits, Representation, UnitreeKind, UnitreeMessage};
use robodr_commission::{InputOptions, LearnConfig, Learner, PcapSource};
use robodr_events::profile::Profile;
use robodr_events::Severity;
use robodr_firewall::FirewallConfig;

const LEGIT: [u8; 12] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
];
const ROGUE: [u8; 12] = [0xee; 12];
const ROGUE_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 66);
/// `0123456789abcdef0123456700000103`: the allowed source of the shipped
/// firewall examples.
const LOWCMD_W: [u8; 4] = [0, 0, 1, 3];
const ARM_W: [u8; 4] = [0, 0, 2, 3];
const API_W: [u8; 4] = [0, 0, 3, 3];
const NO_READER: [u8; 4] = [0; 4];
const GO_LOWCMD: &str = "unitree_go::msg::dds_::LowCmd_";
const HG_LOWCMD: &str = "unitree_hg::msg::dds_::LowCmd_";
const REQUEST: &str = "unitree_api::msg::dds_::Request_";

/// A motor command (mode, q, dq, tau, kp, kd).
type Mc = (u8, f32, f32, f32, f32, f32);

// ------------------------------------------------------------- encoders --

fn go_low_cmd_raw(motors: &[Mc], crc: u32) -> Vec<u8> {
    assert_eq!(motors.len(), 20);
    let mut e = cdrenc::Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.bytes(&[0xFE, 0xEF]);
        e.byte(0xFF);
        e.byte(0);
        for _ in 0..4 {
            e.u32(0); // sn, version
        }
        e.u16(0);
        e.nonprim_seq(|e| {
            for m in motors {
                e.byte(m.0);
                for v in [m.1, m.2, m.3, m.4, m.5] {
                    e.f32(v);
                }
                for _ in 0..3 {
                    e.u32(0);
                }
            }
        });
        e.byte(0);
        e.bytes(&[0; 3]);
        e.bytes(&[0; 40]);
        e.bytes(&[0; 12]);
        e.bytes(&[0; 2]);
        e.byte(0);
        e.u32(0);
        e.u32(crc);
    });
    e.finish()
}

fn hg_low_cmd_raw(mode_pr: u8, motors: &[Mc], crc: u32) -> Vec<u8> {
    assert_eq!(motors.len(), 35);
    let mut e = cdrenc::Enc::new(Representation::CdrLe);
    e.structure(|e| {
        e.byte(mode_pr);
        e.byte(0); // mode_machine
        e.nonprim_seq(|e| {
            for m in motors {
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
        e.u32(crc);
    });
    e.finish()
}

/// A low-level command with the CRC the SDK computes (valid).
fn low_cmd(hg: bool, motors: &[Mc]) -> Vec<u8> {
    let raw = |crc| {
        if hg {
            hg_low_cmd_raw(0, motors, crc)
        } else {
            go_low_cmd_raw(motors, crc)
        }
    };
    let kind = if hg {
        UnitreeKind::HgLowCmd
    } else {
        UnitreeKind::GoLowCmd
    };
    let zero = raw(0);
    let d = decode_unitree(kind, &zero, &Limits::default()).unwrap();
    let crc = match d.message {
        UnitreeMessage::GoLowCmd(c) => c.computed_crc(),
        UnitreeMessage::HgLowCmd(c) => c.computed_crc(),
        _ => unreachable!(),
    };
    let out = raw(crc);
    assert_eq!(
        decode_unitree(kind, &out, &Limits::default())
            .unwrap()
            .message
            .crc_ok(),
        Some(true)
    );
    out
}

fn api_request(api_id: i64, parameter: &str) -> Vec<u8> {
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
        e.string(parameter.as_bytes());
        e.octet_seq(&[]);
    });
    e.finish()
}

// ------------------------------------------------------------- captures --

/// Frames with explicit capture times (the joint firewall's clock).
#[derive(Default)]
struct Timeline {
    t_us: u64,
    frames: Vec<(Duration, Vec<u8>)>,
}

impl Timeline {
    /// Append `f` `dt_us` after the previous frame.
    fn after(&mut self, dt_us: u64, f: Vec<u8>) {
        self.t_us += dt_us;
        self.frames.push((
            Duration::from_secs(1_760_000_000) + Duration::from_micros(self.t_us),
            f,
        ));
    }

    fn pcap(&self) -> Vec<u8> {
        let mut w = PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).unwrap();
        for (ts, f) in &self.frames {
            w.write_packet(*ts, f, f.len() as u32).unwrap();
        }
        w.into_inner()
    }
}

fn unicast(src: Ipv4Addr, d: &[u8]) -> Vec<u8> {
    frame(src, ROBOT_IP, 7411, d)
}

/// The SDK2 robot under test.
struct Robot {
    name: &'static str,
    model: &'static str,
    hg: bool,
    /// The joint firewall file (its `/lowcmd` channel).
    firewall: String,
    policy: &'static str,
    /// `rt/api/<svc>/request` and the service's velocity call.
    api_topic: &'static str,
    velocity: fn(f64) -> (i64, String),
    /// A model-specific posture id (classified only with the model).
    model_specific: Option<(i64, &'static str)>,
    arm_sdk: bool,
}

impl Robot {
    fn fw(&self) -> FirewallConfig {
        FirewallConfig::from_json(&self.firewall).unwrap()
    }

    fn slots(&self) -> usize {
        if self.hg {
            35
        } else {
            20
        }
    }

    fn humanoid(&self) -> bool {
        matches!(
            self.fw().platform.morphology,
            robodr_firewall::Morphology::Humanoid
        )
    }

    /// A clean frame inside the firewall file's envelope, `k`-th of the
    /// stream (small position wobble, small velocity / torque).
    fn clean_motors(&self, k: u64) -> Vec<Mc> {
        let fc = self.fw();
        let spec = &fc.joint_channels["/lowcmd"];
        spec.motors
            .iter()
            .map(|m| {
                if !m.enabled {
                    return (0, 0.0, 0.0, 0.0, 0.0, 0.0);
                }
                let mid = (m.q_min.unwrap() + m.q_max.unwrap()) / 2.0;
                let q = mid + 0.002 * (k % 5) as f64;
                let kp = m.kp_min.max(20.0).min(m.kp_max.unwrap());
                let kd = m.kd_min.max(1.0).min(m.kd_max.unwrap());
                (1, q as f32, 0.2, 0.5, kp as f32, kd as f32)
            })
            .collect()
    }

    /// An arm-SDK frame: `mode = 0` on every slot (as the SDK sends it),
    /// gains and torque on the arm slots.
    fn arm_motors(&self, k: u64, tau: f32) -> Vec<Mc> {
        (0..self.slots())
            .map(|i| {
                if (13..22).contains(&i) {
                    (0, 0.1 + 0.002 * (k % 5) as f32, 0.2, tau, 20.0, 1.0)
                } else {
                    (0, 0.0, 0.0, 0.0, 0.0, 0.0)
                }
            })
            .collect()
    }

    fn discovery(&self, prefix: [u8; 12], ip: Ipv4Addr) -> Vec<u8> {
        let lowcmd = if self.hg { HG_LOWCMD } else { GO_LOWCMD };
        let mut subs = vec![
            spdp_sub(prefix, &[ip]),
            sedp_writer_sub(prefix, LOWCMD_W, "rt/lowcmd", lowcmd),
            sedp_writer_sub(prefix, API_W, self.api_topic, REQUEST),
        ];
        if self.arm_sdk {
            subs.push(sedp_writer_sub(prefix, ARM_W, "rt/arm_sdk", lowcmd));
        }
        datagram(prefix, &subs)
    }

    fn data(&self, w: [u8; 4], sn: u32, payload: &[u8]) -> Vec<u8> {
        unicast(
            ROBOT_IP,
            &datagram(LEGIT, &[user_data(w, NO_READER, sn, payload, true)]),
        )
    }

    /// The clean session: discovery, `n` low-level frames 2 ms apart, a
    /// velocity request every 10th (and the model-specific posture call
    /// every 20th), arm-SDK frames when the robot has them.
    fn clean(&self, tl: &mut Timeline, n: u64, sn0: u32) {
        tl.after(
            1000,
            frame(ROBOT_IP, SPDP_GROUP, 7400, &self.discovery(LEGIT, ROBOT_IP)),
        );
        for k in 0..n {
            let sn = sn0 + k as u32;
            tl.after(
                2000,
                self.data(LOWCMD_W, sn, &low_cmd(self.hg, &self.clean_motors(k))),
            );
            if k % 10 == 0 {
                let (id, p) = (self.velocity)(0.3 + 0.01 * (k % 3) as f64);
                tl.after(100, self.data(API_W, sn, &api_request(id, &p)));
            }
            if let (Some((id, p)), 0) = (self.model_specific, k % 20) {
                tl.after(100, self.data(API_W, sn + 100_000, &api_request(id, p)));
            }
            if self.arm_sdk {
                tl.after(
                    100,
                    self.data(ARM_W, sn, &low_cmd(self.hg, &self.arm_motors(k, 0.5))),
                );
            }
        }
    }
}

fn learn(pcap: &[u8], legacy: bool) -> Profile {
    let cfg = LearnConfig {
        model: "unitree-lab".into(),
        min_participant_announcements: 1,
        min_participant_duration: Duration::ZERO,
        ..LearnConfig::default()
    };
    let mut opts = InputOptions::default();
    if legacy {
        opts.unitree_legacy_ports = [8007, 8080, 8082, 8090].into_iter().collect();
    }
    let mut l = Learner::new(cfg).unwrap();
    l.ingest(&mut PcapSource::new_with_options("clean", pcap, &opts).unwrap())
        .unwrap();
    let c = l.finish();
    let mut p = c.profile;
    p.validate().unwrap();
    p.locked = true;
    p
}

struct Run {
    found: Vec<(robodr_agentd::SpoolRecord, robodr_ocsf::FindingEnvelope)>,
    sum: robodr_agentd::Summary,
    log: String,
    blackbox: PathBuf,
}

impl Run {
    fn rules(&self) -> BTreeSet<String> {
        rules(&self.found).into_iter().collect()
    }

    fn with(&self, rule: &str) -> Vec<&robodr_ocsf::FindingEnvelope> {
        self.found
            .iter()
            .filter(|(_, e)| e.entity_context.rule_id == rule)
            .map(|(_, e)| e)
            .collect()
    }

    fn assert_rule(&self, rule: &str, sev: Severity) {
        let w = self.with(rule);
        assert!(
            w.iter().any(|e| e.severity == sev),
            "{rule} {sev:?} missing: {:?}\n{}",
            self.rules(),
            self.log
        );
    }

    fn assert_detail(&self, rule: &str, needle: &str) {
        assert!(
            self.with(rule)
                .iter()
                .any(|e| serde_json::to_string(e).unwrap().contains(needle)),
            "{rule} with {needle:?} missing: {:?}",
            self.rules()
        );
    }
}

/// Run the daemon over `tl` with the learned profile.
#[allow(clippy::too_many_arguments)]
fn run(
    tag: &str,
    profile: &Profile,
    policy: &str,
    tl: &Timeline,
    robot_model: Option<&str>,
    firewall: Option<(&str, serde_json::Value)>,
    sensor_extra: serde_json::Value,
) -> Run {
    let s = setup(tag, profile);
    std::fs::write(
        &s.policy,
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../config")
                .join(policy),
        )
        .unwrap(),
    )
    .unwrap();
    let pcap = s.dir.join("capture.pcap");
    std::fs::write(&pcap, tl.pcap()).unwrap();
    let mut sensor = serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}});
    if let (Some(o), serde_json::Value::Object(extra)) = (sensor.as_object_mut(), sensor_extra) {
        o.extend(extra);
    }
    let mut cfg = s.config(
        sensor,
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    if let Some(m) = robot_model {
        cfg["robot"]["robot_model"] = m.into();
    }
    if let Some((text, max_angular)) = firewall {
        let p = s.dir.join("firewall.json");
        std::fs::write(&p, text).unwrap();
        cfg["firewall"] = serde_json::json!({"joint_config": p, "max_angular": max_angular});
    }
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert_eq!(sum.reason, robodr_agentd::StopReason::InputsEnded, "{log}");
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint.clone()), &found);
    Run {
        found,
        sum,
        log,
        blackbox: s.blackbox.clone(),
    }
}

/// Every non-clean scenario after a clean prefix; returns the timeline.
fn attacks(r: &Robot) -> Timeline {
    let mut tl = Timeline::default();
    r.clean(&mut tl, 40, 1);
    let mut sn = 1000;
    let mut next = || {
        sn += 1;
        sn
    };
    // (c) torque, kp and position step over the envelope, 2 ms apart.
    let mut over = r.clean_motors(40);
    over[0].3 = 1000.0;
    tl.after(2000, r.data(LOWCMD_W, next(), &low_cmd(r.hg, &over)));
    let mut over = r.clean_motors(41);
    over[0].4 = 1000.0;
    tl.after(2000, r.data(LOWCMD_W, next(), &low_cmd(r.hg, &over)));
    let mut over = r.clean_motors(42);
    over[0].1 += 1.0;
    tl.after(2000, r.data(LOWCMD_W, next(), &low_cmd(r.hg, &over)));
    tl.after(
        2000,
        r.data(LOWCMD_W, next(), &low_cmd(r.hg, &r.clean_motors(43))),
    );
    // (g) every enabled joint limp (gains zero, motors on).
    let limp: Vec<Mc> = r
        .clean_motors(44)
        .into_iter()
        .map(|m| (m.0, m.1, 0.0, 0.0, 0.0, 0.0))
        .collect();
    tl.after(2000, r.data(LOWCMD_W, next(), &low_cmd(r.hg, &limp)));
    tl.after(
        2000,
        r.data(LOWCMD_W, next(), &low_cmd(r.hg, &r.clean_motors(45))),
    );
    // (d) arm SDK: mode 0 on every slot, torque over the envelope.
    if r.arm_sdk {
        tl.after(
            1000,
            r.data(ARM_W, next(), &low_cmd(r.hg, &r.arm_motors(46, 100.0))),
        );
    }
    // (e) an api_id aliased past int32, (f) a velocity over the envelope.
    let (id, p) = (r.velocity)(0.3);
    tl.after(
        1000,
        r.data(API_W, next(), &api_request((1i64 << 32) + id, &p)),
    );
    let (id, p) = (r.velocity)(5.0);
    tl.after(1000, r.data(API_W, next(), &api_request(id, &p)));
    // (b) a rogue participant writes rt/lowcmd (clean values).
    tl.after(
        1000,
        frame(ROGUE_IP, SPDP_GROUP, 7400, &r.discovery(ROGUE, ROGUE_IP)),
    );
    tl.after(
        1000,
        unicast(
            ROGUE_IP,
            &datagram(
                ROGUE,
                &[user_data(
                    LOWCMD_W,
                    NO_READER,
                    1,
                    &low_cmd(r.hg, &r.clean_motors(47)),
                    true,
                )],
            ),
        ),
    );
    tl
}

/// The twist channel's yaw bound (`/arm_sdk` is a joint-velocity channel
/// and needs none; `/lowcmd` is the joint firewall's).
fn max_angular(r: &Robot) -> serde_json::Value {
    let ch = robodr_events::graph::demangle(r.api_topic).name;
    serde_json::json!({ ch: 1.0 })
}

fn scenario(r: &Robot) {
    // Learn from a clean capture.
    let mut clean = Timeline::default();
    r.clean(&mut clean, 120, 1);
    let profile = learn(&clean.pcap(), false);
    assert!(profile.participants.contains("0123456789abcdef01234567"));
    let env = &profile.motion_envelopes["/lowcmd"];
    assert!(env.max_joint_torque.is_some() && env.max_joint_kp.is_some());
    assert!(env.max_joint_position_step.is_some(), "{env:?}");
    let api = robodr_events::graph::demangle(r.api_topic).name;
    assert!(profile.motion_envelopes[&api].max_linear_speed.unwrap() < 1.0);
    if r.arm_sdk {
        assert!(profile.motion_envelopes.contains_key("/arm_sdk"));
    }
    let fw = || Some((r.firewall.as_str(), max_angular(r)));

    // (a) The clean capture: no finding at all, every joint frame checked.
    let a = run(
        &format!("{}-clean", r.name),
        &profile,
        r.policy,
        &clean,
        Some(r.model),
        fw(),
        serde_json::json!({}),
    );
    assert!(a.found.is_empty(), "{:?}\n{}", a.rules(), a.log);
    // Every decoded joint frame (rt/lowcmd and rt/arm_sdk) goes to the
    // agent; the joint firewall checks the /lowcmd ones (its channel).
    let per_stream = if r.arm_sdk { 2 } else { 1 };
    assert_eq!(a.sum.stats.joint_frames, 120 * per_stream, "{}", a.log);
    assert_eq!(a.sum.agent.joint_firewall_checks, 120);
    assert_eq!(a.sum.agent.joint_frames_missing, 0);
    assert_eq!(a.sum.pipeline.motion.undecodable, 0);

    // The model-specific call: classified with the model (no finding
    // above), `Unknown` (High) without it.
    if let Some((id, _)) = r.model_specific {
        let b = run(
            &format!("{}-nomodel", r.name),
            &profile,
            r.policy,
            &clean,
            None,
            fw(),
            serde_json::json!({}),
        );
        assert_eq!(
            b.rules(),
            ["robot.motion.unverifiable_command".to_string()].into(),
            "{}",
            b.log
        );
        b.assert_detail("robot.motion.unverifiable_command", &format!("api_id {id}"));
    }

    // (b) - (g).
    let x = run(
        &format!("{}-attacks", r.name),
        &profile,
        r.policy,
        &attacks(r),
        Some(r.model),
        fw(),
        serde_json::json!({}),
    );
    // (b) rogue rt/lowcmd writer.
    x.assert_rule("robot.ros2.unknown_participant", Severity::High);
    x.assert_rule("robot.ros2.unauthorized_motion_writer", Severity::Critical);
    x.assert_rule("robot.firewall.rejected_unknown_source", Severity::Critical);
    // (c) torque / kp / step over the learned envelope ...
    x.assert_rule("robot.motion.joint_over_envelope", Severity::Critical);
    for what in [
        "joint torque",
        "joint position gain kp",
        "joint position-target step",
    ] {
        x.assert_detail("robot.motion.joint_over_envelope", what);
    }
    // ... and the joint firewall's would-have verdicts (recording only).
    for rule in [
        "robot.firewall.joint_torque_out_of_envelope",
        "robot.firewall.joint_gain_out_of_envelope",
        "robot.firewall.joint_step_out_of_envelope",
    ] {
        assert!(!x.with(rule).is_empty(), "{rule}: {:?}", x.rules());
    }
    // (d) arm SDK frames with mode 0 are motion.
    if r.arm_sdk {
        x.assert_detail("robot.motion.joint_over_envelope", "/arm_sdk");
    }
    // (e) aliased api id, (f) velocity over the envelope.
    x.assert_rule("robot.motion.api_id_out_of_range", Severity::High);
    x.assert_rule("robot.motion.linear_over_envelope", Severity::Critical);
    x.assert_detail("robot.motion.linear_over_envelope", &api);
    // Recorded, never enforced; decoded frames carry their facts.
    assert!(notes_with(&x.blackbox, "robodr.firewall_joint_verdict") >= 1);
    assert_eq!(notes_with(&x.blackbox, "\"enforcing\":true"), 0);
    assert!(notes_with(&x.blackbox, "\"crc_ok\":true") >= 1);
    // (g) humanoid: no zero / damping substitute, the limp frame is a
    // would-have rejection.
    assert_eq!(notes_with(&x.blackbox, "\"substitute\":\"zero\""), 0);
    if r.humanoid() {
        // Rejected (would have held the last frame): per slot when the
        // envelope gives every joint a minimum gain (the shipped G1
        // example), as a whole limp frame otherwise.
        let fc = r.fw();
        let limp_allowed = fc.joint_channels["/lowcmd"]
            .motors
            .iter()
            .filter(|m| m.enabled)
            .all(|m| m.allow_limp);
        let rule = if limp_allowed {
            "robot.firewall.joint_limp_frame"
        } else {
            "robot.firewall.joint_gain_below_minimum"
        };
        assert!(!x.with(rule).is_empty(), "{rule}: {:?}", x.rules());
        assert!(notes_with(&x.blackbox, "\"would_have\":\"rejected: ") >= 1);
    }
}

fn go2_velocity(vx: f64) -> (i64, String) {
    (1008, format!(r#"{{"x":{vx},"y":0,"z":0.1}}"#))
}

fn loco_velocity(id: i64) -> impl Fn(f64) -> (i64, String) {
    move |vx| (id, format!(r#"{{"velocity":[{vx},0,0.1],"duration":1.0}}"#))
}

fn g1_velocity(vx: f64) -> (i64, String) {
    loco_velocity(7105)(vx)
}

fn h1_velocity(vx: f64) -> (i64, String) {
    loco_velocity(8105)(vx)
}

fn config(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config")
            .join(name),
    )
    .unwrap()
}

/// An H1 joint firewall (`unitree_go` LowCmd, 20 slots; slot 9 is the
/// arm-SDK weight, not a motor). Illustrative limits.
fn h1_firewall() -> String {
    let motors: Vec<serde_json::Value> = (0..20)
        .map(|i| {
            if i == 9 {
                serde_json::json!({"name": "arm_sdk_weight", "enabled": false})
            } else {
                // No minimum gain (`allow_limp`, an explicit opt-out): the
                // humanoid whole-frame rule (`joint_limp_frame`) is then
                // what stops an all-limp frame.
                serde_json::json!({
                    "name": format!("joint_{i}"), "enabled": true,
                    "q_min": -2.0, "q_max": 2.0, "dq_max": 30.0, "tau_max": 200.0,
                    "kp_min": 0.0, "kp_max": 300.0, "kd_min": 0.0, "kd_max": 10.0,
                    "allow_limp": true, "max_dq_step": 0.15, "tau_pd_max": 200.0
                })
            }
        })
        .collect();
    serde_json::json!({
        "platform": {"morphology": "humanoid",
                     "fail_behaviour": {"hold_last": {"max_hold_ns": 200000000}},
                     "fault_policy": "fail_hold", "foreign_source_action": "drop"},
        "joint_channels": {"/lowcmd": {
            "allowed_sources": ["0123456789abcdef0123456700000103"],
            "require_crc": true,
            "rate": {"expected_hz": 500.0, "min_interval_ns": 1000000, "max_interval_ns": 10000000},
            "motors": motors
        }}
    })
    .to_string()
}

#[test]
fn go2_end_to_end() {
    scenario(&Robot {
        name: "go2",
        model: "Go2",
        hg: false,
        firewall: config("firewall.unitree-go2.example.json"),
        policy: "response-policy.unitree-go2.example.json",
        api_topic: "rt/api/sport/request",
        velocity: go2_velocity,
        // Euler (posture): a Go2 / A2 sport id, Unknown without the model.
        model_specific: Some((1007, r#"{"x":0,"y":0.1,"z":0}"#)),
        arm_sdk: false,
    });
}

#[test]
fn g1_end_to_end() {
    scenario(&Robot {
        name: "g1",
        model: "G1",
        hg: true,
        firewall: config("firewall.unitree-g1.example.json"),
        policy: "response-policy.unitree-g1.example.json",
        api_topic: "rt/api/sport/request",
        velocity: g1_velocity,
        // SetStandHeight (posture): a G1 / H2 loco id, Unknown without the
        // model.
        model_specific: Some((7104, r#"{"data":0.7}"#)),
        arm_sdk: true,
    });
}

#[test]
fn h1_end_to_end() {
    scenario(&Robot {
        name: "h1",
        model: "H1",
        hg: false,
        firewall: h1_firewall(),
        policy: "response-policy.unitree-g1.example.json",
        api_topic: "rt/api/loco/request",
        velocity: h1_velocity,
        model_specific: None,
        arm_sdk: true,
    });
}

// ----------------------------------------------------- independent vectors --

/// The reviewer vectors of `robodr-cdr/tests/data/unitree/` (random field
/// values, CRC computed independently, CDR_LE / CDR_BE / XCDR2) decode on
/// the live path: every one reaches the joint firewall with `crc_ok`
/// true, and their wild values are reported, never silently passed.
#[test]
fn independent_vectors_through_the_daemon() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../robodr-cdr/tests/data/unitree");
    for (hg, files, fw) in [
        (
            false,
            ["golowcmd_le.bin", "golowcmd_be.bin", "golowcmd_x2.bin"],
            config("firewall.unitree-go2.example.json"),
        ),
        (
            true,
            ["hglowcmd_le.bin", "hglowcmd_be.bin", "hglowcmd_x2.bin"],
            config("firewall.unitree-g1.example.json"),
        ),
    ] {
        let r = Robot {
            name: if hg { "vec-hg" } else { "vec-go" },
            model: if hg { "G1" } else { "Go2" },
            hg,
            firewall: fw,
            policy: if hg {
                "response-policy.unitree-g1.example.json"
            } else {
                "response-policy.unitree-go2.example.json"
            },
            api_topic: "rt/api/sport/request",
            velocity: if hg { g1_velocity } else { go2_velocity },
            model_specific: None,
            arm_sdk: false,
        };
        let mut clean = Timeline::default();
        r.clean(&mut clean, 40, 1);
        let profile = learn(&clean.pcap(), false);
        let mut tl = Timeline::default();
        r.clean(&mut tl, 10, 1);
        for (i, f) in files.iter().enumerate() {
            let payload = std::fs::read(dir.join(f)).unwrap();
            tl.after(2000, r.data(LOWCMD_W, 500 + i as u32, &payload));
        }
        let x = run(
            r.name,
            &profile,
            r.policy,
            &tl,
            Some(r.model),
            Some((r.firewall.as_str(), max_angular(&r))),
            serde_json::json!({}),
        );
        assert_eq!(x.sum.pipeline.motion.undecodable, 0, "{}", x.log);
        assert_eq!(x.sum.stats.joint_frames, 13);
        // Independent CRCs verify on the live path.
        assert!(notes_with(&x.blackbox, "\"crc_ok\":true") >= 3);
        assert_eq!(notes_with(&x.blackbox, "\"crc_ok\":false"), 0);
        // Random values far outside any envelope.
        assert!(
            !x.with("robot.motion.joint_over_envelope").is_empty(),
            "{:?}",
            x.rules()
        );
    }
}

// ------------------------------------------------------- Go1 legacy UDP --

const PC_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 123, 15);
const SPORT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 123, 161);
const BASIC_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 123, 10);
const INTRUDER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 123, 66);

fn with_crc(mut b: Vec<u8>) -> Vec<u8> {
    b.extend_from_slice(&[0; 4]);
    let crc = robodr_cdr::unitree::frame_crc(&b).unwrap();
    let n = b.len();
    b[n - 4..].copy_from_slice(&crc.to_le_bytes());
    b
}

/// `comm.h` `HighCmd` (129 bytes).
fn high_cmd(mode: u8, vx: f32, yaw: f32) -> Vec<u8> {
    let mut b = vec![0xFE, 0xEF, 0xEE, 0];
    b.extend_from_slice(&[0; 8 + 8 + 2]);
    b.extend_from_slice(&[mode, 0, 0]);
    let f = |b: &mut Vec<u8>, v: f32| b.extend_from_slice(&v.to_le_bytes());
    f(&mut b, 0.08); // footRaiseHeight
    f(&mut b, 0.0); // bodyHeight
    for _ in 0..5 {
        f(&mut b, 0.0); // position[2], euler[3]
    }
    f(&mut b, vx);
    f(&mut b, 0.0);
    f(&mut b, yaw);
    b.extend_from_slice(&[0; 4 + 12 + 40 + 4]); // bms, led, wireless, reserve
    let b = with_crc(b);
    assert_eq!(b.len(), robodr_cdr::unitree_legacy::LEGACY_HIGH_CMD_LEN);
    b
}

/// `comm.h` `LowCmd`, declared layout (734 bytes): 12 legs active.
fn legacy_low_cmd(k: u64, tau: f32) -> Vec<u8> {
    let mut b = vec![0xFE, 0xEF, 0xFF, 0];
    b.extend_from_slice(&[0; 8 + 8 + 2]);
    for i in 0..20 {
        let on = i < 12;
        b.push(if on { 0x0A } else { 0 });
        let vals: [f32; 5] = if on {
            [0.1 + 0.002 * (k % 5) as f32, 0.2, tau, 20.0, 1.0]
        } else {
            [0.0; 5]
        };
        for v in vals {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[0; 12]);
    }
    b.extend_from_slice(&[0; 4 + 40 + 4]);
    let b = with_crc(b);
    assert_eq!(b.len(), robodr_cdr::unitree_legacy::LEGACY_LOW_CMD_LEN);
    b
}

fn udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    synth::ethernet(0x0800, &synth::ipv4_udp(src, dst, sport, dport, payload))
}

fn go1_clean(tl: &mut Timeline, n: u64) {
    for k in 0..n {
        let vx = 0.3 + 0.01 * (k % 3) as f32;
        tl.after(
            2000,
            udp(PC_IP, SPORT_IP, 8090, 8082, &high_cmd(2, vx, 0.1)),
        );
        tl.after(100, udp(SPORT_IP, PC_IP, 8082, 8090, &vec![0; 1087]));
        tl.after(
            100,
            udp(PC_IP, BASIC_IP, 8090, 8007, &legacy_low_cmd(k, 0.5)),
        );
    }
}

#[test]
fn go1_legacy_udp_end_to_end() {
    use robodr_cdr::unitree_legacy::channels;
    let mut clean = Timeline::default();
    go1_clean(&mut clean, 60);
    // Learnable from the capture (robodr-commission --unitree-legacy).
    let profile = learn(&clean.pcap(), true);
    for ch in [channels::HIGH_CMD, channels::LOW_CMD] {
        assert!(profile.writer_topics.contains(ch), "{profile:?}");
    }
    let hi = profile.motion_envelopes[channels::HIGH_CMD]
        .max_linear_speed
        .unwrap();
    assert!((0.3..1.0).contains(&hi), "{hi}");
    let lo = &profile.motion_envelopes[channels::LOW_CMD];
    assert!(lo.max_joint_torque.is_some() && lo.max_joint_position_step.is_some());
    // Without --unitree-legacy the same capture teaches nothing.
    let mut l = Learner::new(LearnConfig::default()).unwrap();
    let bytes = clean.pcap();
    let mut src = PcapSource::new("clean", &bytes[..]).unwrap();
    l.ingest(&mut src).unwrap();
    assert!(l.finish().profile.motion_envelopes.is_empty());
    let mut src = PcapSource::new_with_options(
        "clean",
        &bytes[..],
        &InputOptions {
            unitree_legacy_ports: [8007, 8082, 8090].into_iter().collect(),
        },
    )
    .unwrap();
    while let Some(e) = robodr_commission::EventSource::next_event(&mut src) {
        e.unwrap();
    }
    let d = robodr_commission::EventSource::capture_diagnostics(&src).unwrap();
    assert_eq!(d.unitree_legacy_commands, 120);
    assert_eq!(
        d.unitree_legacy_command_senders,
        [PC_IP.to_string()].into_iter().collect()
    );

    let legacy = serde_json::json!({"unitree_legacy": {
        "enabled": true, "command_senders": [PC_IP.to_string()]}});
    let policy = "response-policy.unitree-go2.example.json";
    // (a) clean replay: nothing.
    let a = run(
        "go1-clean",
        &profile,
        policy,
        &clean,
        Some("Go1"),
        None,
        legacy.clone(),
    );
    assert!(a.found.is_empty(), "{:?}\n{}", a.rules(), a.log);
    assert_eq!(a.sum.pipeline.legacy.commands, 120);
    assert_eq!(a.sum.pipeline.legacy.states, 60);
    assert_eq!(a.sum.pipeline.legacy.unknown_sender, 0);
    assert_eq!(
        a.sum.stats.motion_events, 120,
        "commands only (no feedback topic)"
    );

    // Attacks.
    let mut tl = Timeline::default();
    go1_clean(&mut tl, 10);
    // (b) an unknown host sends commands (legit values).
    tl.after(
        2000,
        udp(INTRUDER_IP, SPORT_IP, 8090, 8082, &high_cmd(2, 0.3, 0.0)),
    );
    // (f) a velocity over the envelope from the legit PC.
    tl.after(
        2000,
        udp(PC_IP, SPORT_IP, 8090, 8082, &high_cmd(2, 3.0, 0.0)),
    );
    // A trick (backflip, mode 9): nothing in the request bounds it.
    tl.after(
        2000,
        udp(PC_IP, SPORT_IP, 8090, 8082, &high_cmd(9, 0.0, 0.0)),
    );
    // (c) joint torque over the envelope (declared LowCmd layout).
    tl.after(
        2000,
        udp(PC_IP, BASIC_IP, 8090, 8007, &legacy_low_cmd(10, 60.0)),
    );
    // A v3.8.6 compressed LowCmd (614 bytes) is decoded like the declared
    // one (its absurd joint values are over the envelope); a compressed
    // LowState (807 bytes) is still reported, not inspected.
    tl.after(2000, udp(PC_IP, BASIC_IP, 8090, 8007, &[0x5a; 614]));
    tl.after(2000, udp(BASIC_IP, PC_IP, 8007, 8090, &[0x5a; 807]));
    // Spoofed robot state from the intruder.
    tl.after(2000, udp(INTRUDER_IP, PC_IP, 8082, 8090, &vec![0; 1087]));
    let x = run(
        "go1-attacks",
        &profile,
        policy,
        &tl,
        Some("Go1"),
        None,
        legacy,
    );
    x.assert_rule("robot.unitree.legacy_unknown_sender", Severity::Critical);
    x.assert_rule("robot.unitree.legacy_unknown_sender", Severity::Medium);
    x.assert_detail(
        "robot.unitree.legacy_unknown_sender",
        &INTRUDER_IP.to_string(),
    );
    x.assert_rule("robot.motion.linear_over_envelope", Severity::Critical);
    x.assert_detail("robot.motion.linear_over_envelope", channels::HIGH_CMD);
    x.assert_rule("robot.motion.unverifiable_command", Severity::High);
    x.assert_detail("robot.motion.unverifiable_command", "HighCmd mode 9");
    x.assert_rule("robot.motion.joint_over_envelope", Severity::Critical);
    x.assert_detail("robot.motion.joint_over_envelope", channels::LOW_CMD);
    x.assert_rule("robot.motion.undecodable_sample", Severity::Medium);
    x.assert_detail("robot.motion.undecodable_sample", "compressed");
    // Legacy off: the same capture is filtered out by the capture layer
    // (nothing decoded, nothing reported).
    let off = run(
        "go1-off",
        &profile,
        policy,
        &tl,
        None,
        None,
        serde_json::json!({}),
    );
    assert_eq!(off.sum.pipeline.legacy.datagrams, 0);
    assert!(off.found.is_empty(), "{:?}", off.rules());
}
