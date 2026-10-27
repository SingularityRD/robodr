//! The agent's low-level joint firewall (`Agent::handle_with_joint`): a
//! Unitree joint channel is checked frame by frame with
//! `Firewall::check_joint` and its verdict recorded as
//! `robodr.firewall_joint_verdict`. Here the firewall **enforces** (locked
//! profile, the file's own `hold_last` platform), so the substitutes it
//! would emit inline are visible: on a humanoid never a zero / damping
//! frame, only the held last frame or nothing.

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::*;
use robodr_agent::*;
use robodr_events::profile::Profile;
use robodr_events::{MotionCommand, RobotEvent};
use robodr_firewall::{FirewallConfig, JointFrame, MotorCmd};
use robodr_responder::{Morphology, OperationalContext, PlatformFamily, ResponsePolicy};

const WRITER: &str = "0123456789abcdef0123456700000103";
const ROGUE_WRITER: &str = "eeeeeeeeeeeeeeeeeeeeeeee00000103";

fn repo_config(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config")
            .join(name),
    )
    .unwrap()
}

struct Rig {
    agent: Agent,
    fc: FirewallConfig,
    t: u64,
}

fn rig(tag: &str, model: &str, fw: FirewallConfig, morphology: Morphology) -> Rig {
    let mut profile: Profile = robodr_agent::strict_from_str(&repo_config(&format!(
        "profile.unitree-{model}.example.json"
    )))
    .unwrap();
    profile.locked = true;
    let mut policy: ResponsePolicy = ResponsePolicy::from_json(&repo_config(&format!(
        "response-policy.unitree-{model}.example.json"
    )))
    .unwrap();
    policy.morphology = morphology;
    let dir = tmpdir(tag);
    let mut cfg = config(&dir, profile.clone(), policy);
    cfg.context = OperationalContext {
        platform: PlatformFamily::Other,
        morphology,
        ..context()
    };
    let max_angular: BTreeMap<String, f64> = profile
        .motion_envelopes
        .iter()
        .filter(|(k, e)| k.starts_with("/api/") && e.max_joint_speed.is_none())
        .map(|(k, _)| (k.clone(), 1.0))
        .collect();
    let mut fs = FirewallSettings::from_profile_and_joints(
        &profile,
        &BTreeMap::new(),
        &max_angular,
        fw.joint_channels.clone(),
    )
    .unwrap();
    fs.platform = fw.platform;
    cfg.firewall = Some(fs);
    Rig {
        agent: build(cfg),
        fc: fw,
        t: 0,
    }
}

impl Rig {
    /// A frame inside the file's envelope.
    fn clean(&self) -> Vec<MotorCmd> {
        self.fc.joint_channels["/lowcmd"]
            .motors
            .iter()
            .map(|m| {
                if !m.enabled {
                    return MotorCmd::OFF;
                }
                let q = (m.q_min.unwrap() + m.q_max.unwrap()) / 2.0;
                let kp = m.kp_min.max(20.0);
                let kd = m.kd_min.max(1.0);
                MotorCmd::enabled(q, 0.2, 0.5, kp, kd)
            })
            .collect()
    }

    /// Hand one frame to the agent `dt_ns` after the previous one.
    fn send(&mut self, source: &str, motors: &[MotorCmd], dt_ns: u64) -> Vec<Outcome> {
        self.t += dt_ns;
        let frame = JointFrame::from_slice(motors, Some(true)).map(|mut f| {
            f.mode_pr = Some(0);
            f.mode_machine = Some(0);
            f
        });
        let ev = RobotEvent::MotionCommand(MotionCommand {
            channel: "/lowcmd".into(),
            source_guid: Some(source.into()),
            joint_speed: Some(0.2),
            joint_torque: Some(0.5),
            joint_kp: Some(20.0),
            ..Default::default()
        });
        let input = frame.map(|frame| JointInput {
            frame,
            stamp_ns: self.t,
        });
        self.agent.handle_with_joint(
            at(self.t),
            &ev,
            input.as_ref(),
            robodr_responder::SafetyState::MovingSlow,
        )
    }
}

fn verdicts(outs: &[Outcome]) -> Vec<FirewallVerdictRecord> {
    outs.iter().filter_map(|o| o.firewall.clone()).collect()
}

#[test]
fn humanoid_joint_firewall_never_substitutes_a_zero_frame() {
    let fc = FirewallConfig::from_json(&repo_config("firewall.unitree-g1.example.json")).unwrap();
    let mut r = rig("joint-g1", "g1", fc, Morphology::Humanoid);
    let clean = r.clean();
    assert!(r.send(WRITER, &clean, 2_000_000).is_empty(), "clean frame");
    let mut all = Vec::new();
    // Over torque, limp (every gain zero), non-finite, too early, rogue.
    let mut torque = clean.clone();
    torque[0].tau = 1000.0;
    all.extend(verdicts(&r.send(WRITER, &torque, 2_000_000)));
    let limp: Vec<MotorCmd> = clean
        .iter()
        .map(|m| MotorCmd {
            kp: 0.0,
            kd: 0.0,
            tau: 0.0,
            ..*m
        })
        .collect();
    all.extend(verdicts(&r.send(WRITER, &limp, 2_000_000)));
    let mut nan = clean.clone();
    nan[3].q = f64::NAN;
    all.extend(verdicts(&r.send(WRITER, &nan, 2_000_000)));
    // Accepted again (no outcome), then a frame 0.1 ms after it.
    assert!(r.send(WRITER, &clean, 2_000_000).is_empty());
    all.extend(verdicts(&r.send(WRITER, &clean, 100_000)));
    all.extend(verdicts(&r.send(ROGUE_WRITER, &clean, 2_000_000)));
    assert!(all.len() >= 5, "{all:#?}");
    for v in &all {
        assert_eq!(v.kind, "robodr.firewall_joint_verdict");
        assert!(v.enforcing);
        assert_eq!(v.verdict, "rejected", "{v:?}");
        assert!(
            matches!(v.substitute, None | Some("hold_last")),
            "a humanoid never gets a zero / damping frame: {v:?}"
        );
        let j = v.joint.expect("joint detail");
        assert_eq!((j.slots, j.crc_ok, j.mode_pr), (35, Some(true), Some(0)));
    }
    assert!(all.iter().any(|v| v.substitute == Some("hold_last")));
    // The foreign source and the too-early frame emit nothing.
    assert!(all
        .iter()
        .any(|v| v.reject_reason.as_deref() == Some("UnknownSource") && v.substitute.is_none()));
    assert!(all
        .iter()
        .any(|v| v.reject_reason.as_deref() == Some("RateLimited") && v.substitute.is_none()));
    let st = r.agent.stats();
    assert_eq!(st.joint_firewall_checks, 7);
    assert_eq!(st.joint_frames_missing, 0);
}

/// The contrast: a quadruped configured with `zero_velocity` does get the
/// damping frame (so the field above is meaningful).
#[test]
fn quadruped_with_zero_velocity_gets_the_damping_substitute() {
    let mut fc =
        FirewallConfig::from_json(&repo_config("firewall.unitree-go2.example.json")).unwrap();
    fc.platform.fail_behaviour = robodr_firewall::FailBehaviour::ZeroVelocity;
    let mut r = rig("joint-go2", "go2", fc, Morphology::Quadruped);
    let clean = r.clean();
    assert!(r.send(WRITER, &clean, 2_000_000).is_empty());
    let mut torque = clean.clone();
    torque[0].tau = 1000.0;
    let v = verdicts(&r.send(WRITER, &torque, 2_000_000));
    assert!(v.iter().any(|v| v.substitute == Some("zero")), "{v:#?}");
}

/// A command on the joint channel without its frame is not checked by the
/// firewall (counted); out-of-order capture stamps are clamped, never a
/// clock-regression rejection.
#[test]
fn missing_frames_are_counted_and_stamps_clamped() {
    let fc = FirewallConfig::from_json(&repo_config("firewall.unitree-g1.example.json")).unwrap();
    let mut r = rig("joint-misc", "g1", fc, Morphology::Humanoid);
    let clean = r.clean();
    assert!(r.send(WRITER, &clean, 2_000_000).is_empty());
    let ev = RobotEvent::MotionCommand(MotionCommand {
        channel: "/lowcmd".into(),
        source_guid: Some(WRITER.into()),
        joint_speed: Some(0.2),
        ..Default::default()
    });
    let outs = r
        .agent
        .handle(at(r.t + 1), &ev, robodr_responder::SafetyState::MovingSlow);
    assert!(verdicts(&outs).is_empty());
    assert_eq!(r.agent.stats().joint_frames_missing, 1);
    // A stamp older than the previous one.
    r.t += 4_000_000;
    let frame = JointFrame::from_slice(&clean, Some(true)).map(|mut f| {
        f.mode_pr = Some(0);
        f
    });
    let input = JointInput {
        frame: frame.unwrap(),
        stamp_ns: 1,
    };
    let outs = r.agent.handle_with_joint(
        at(r.t),
        &ev,
        Some(&input),
        robodr_responder::SafetyState::MovingSlow,
    );
    assert_eq!(r.agent.stats().joint_clock_clamped, 1);
    assert!(
        !verdicts(&outs)
            .iter()
            .any(|v| v.reject_reason.as_deref() == Some("ClockRegression")),
        "{outs:#?}"
    );
}
