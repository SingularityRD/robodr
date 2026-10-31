//! Unit tests that need crate internals (fault injection). The decision table,
//! property and allocation tests live in `tests/`.

use crate::*;
use robodr_events::profile::{Envelope, Profile};
use std::collections::BTreeMap;

const P: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";
const MS: u64 = 1_000_000;

fn firewall(platform: PlatformConfig, locked: bool) -> (Firewall, SourceId, ChannelId) {
    let mut p = Profile {
        model: "ugv".into(),
        locked,
        ..Default::default()
    };
    p.participants.insert(P.into());
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(1.0),
            max_joint_speed: None,
            ..Default::default()
        },
    );
    let spec = ChannelSpec {
        allowed_sources: vec![format!("{P}00000103")],
        max_angular_speed: Some(1.0),
        ..Default::default()
    };
    let pol = Policy::compile(&p, platform, &BTreeMap::from([("/cmd_vel".into(), spec)])).unwrap();
    let fw = Firewall::new(pol);
    let s = fw.source_id(&format!("{P}00000103")).unwrap();
    let c = fw.channel_id("/cmd_vel").unwrap();
    (fw, s, c)
}

fn twist(s: SourceId, c: ChannelId, stamp: u64, vx: f64) -> Command {
    Command::twist(s, c, stamp, Twist::new(Vec3::new(vx, 0.0, 0.0), Vec3::ZERO))
}

#[test]
fn injected_fault_fail_safe_zeroes() {
    let (mut fw, s, c) = firewall(
        PlatformConfig {
            fail_behaviour: FailBehaviour::HoldLast {
                max_hold_ns: 1_000 * MS,
            },
            ..Default::default()
        },
        true,
    );
    assert!(fw.check(&twist(s, c, 10 * MS, 0.5), 10 * MS).is_passed());
    fw.inject_fault = true;
    let v = fw.check(&twist(s, c, 20 * MS, 0.5), 20 * MS);
    match v {
        Verdict::Rejected {
            reason: RejectReason::InternalFault,
            substitute: Some(sub),
        } => {
            // Fail-safe never holds, even on a HoldLast platform.
            assert_eq!(sub.kind, SubstituteKind::Zero);
            assert!(sub.cmd.motion.is_zero());
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(fw.stats().faults, 1);
    let devs = fw.drain_deviations();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].rule, rules::INTERNAL_FAULT);
}

#[test]
fn injected_fault_fail_open_passes_original() {
    let (mut fw, s, c) = firewall(
        PlatformConfig {
            fault_policy: FaultPolicy::FailOpen,
            ..Default::default()
        },
        true,
    );
    fw.inject_fault = true;
    let cmd = twist(s, c, 10 * MS, 0.5);
    assert_eq!(
        fw.check(&cmd, 10 * MS),
        Verdict::Passed {
            cmd,
            would_have: Some(WouldHave::Rejected {
                reason: RejectReason::InternalFault
            })
        }
    );
    assert_eq!(fw.events().as_slice()[0].action, EventAction::ObservedOnly);
}

#[test]
fn fault_verdict_follows_policy() {
    let (mut fw, s, c) = firewall(PlatformConfig::default(), true);
    let v = fw.fault_verdict(&twist(s, c, 1, 0.1), 1);
    assert_eq!(v.reject_reason(), Some(RejectReason::InternalFault));
    assert!(v.output().unwrap().motion.is_zero());
    // Unknown channel: nothing to emit.
    let v = fw.fault_verdict(&twist(s, ChannelId(9), 1, 0.1), 1);
    assert_eq!(
        v,
        Verdict::Rejected {
            reason: RejectReason::InternalFault,
            substitute: None
        }
    );
}

/// A humanoid joint channel on a policy whose fault policy is forced (past
/// the compile-time refusal) to `FailOpen` / `FailSafe`: a fault still holds
/// the last valid frame, never forwards the input nor damps.
#[test]
fn humanoid_joint_fault_holds_whatever_the_fault_policy() {
    let mut p = Profile {
        model: "humanoid".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert(P.into());
    p.writer_topics.insert("/lowcmd".into());
    p.motion_envelopes.insert(
        "/lowcmd".into(),
        Envelope {
            max_joint_speed: Some(30.0),
            ..Default::default()
        },
    );
    let motor = MotorLimits {
        kp_min: 5.0,
        max_dq_step: Some(0.5),
        ..MotorLimits::enabled((-1.0, 1.0), 10.0, 20.0, 100.0, 5.0)
    };
    let spec = JointChannelSpec {
        allowed_sources: vec![format!("{P}00000103")],
        motors: vec![motor; 4],
        rate: Some(JointRate::around(500.0)),
        ..Default::default()
    };
    let platform = PlatformConfig {
        morphology: Morphology::Humanoid,
        fail_behaviour: FailBehaviour::HoldLast {
            max_hold_ns: 50 * MS,
        },
        fault_policy: FaultPolicy::FailHold,
        ..Default::default()
    };
    for forced in [FaultPolicy::FailOpen, FaultPolicy::FailSafe] {
        let mut pol = Policy::compile_with_joints(
            &p,
            platform,
            &BTreeMap::new(),
            &BTreeMap::from([("/lowcmd".to_string(), spec.clone())]),
        )
        .unwrap();
        pol.platform.fault_policy = forced;
        let mut fw = Firewall::new(pol);
        let s = fw.source_id(&format!("{P}00000103")).unwrap();
        let c = fw.channel_id("/lowcmd").unwrap();
        let m = MotorCmd::enabled(0.1, 0.0, 1.0, 40.0, 1.0);
        let frame = JointFrame::from_slice(&[m; 4], Some(true)).unwrap();
        let first = JointCommand::new(s, c, 10 * MS, frame);
        assert!(fw.check_joint(&first, 10 * MS).is_passed());
        // A gateway-declared fault.
        let v = fw.joint_fault_verdict(&JointCommand::new(s, c, 12 * MS, frame), 12 * MS);
        assert_eq!(v.reject_reason(), Some(RejectReason::InternalFault));
        assert_eq!(
            v.substitute_kind(),
            Some(SubstituteKind::HoldLast),
            "{forced:?}"
        );
        // A failed post-condition inside `check_joint`.
        fw.inject_fault = true;
        let v = fw.check_joint(&JointCommand::new(s, c, 14 * MS, frame), 14 * MS);
        assert_eq!(v.reject_reason(), Some(RejectReason::InternalFault));
        assert_eq!(
            v.substitute_kind(),
            Some(SubstituteKind::HoldLast),
            "{forced:?}"
        );
        assert!(fw
            .events()
            .as_slice()
            .iter()
            .all(|e| e.action != EventAction::ObservedOnly));
    }
}

/// `late_verdict` / `joint_late_verdict`: the fault policy's verdict and
/// substitute and the `faults` count of `fault_verdict`, without an
/// `internal_fault` event (the gateway reports late packets as overload);
/// a fault the firewall raises itself is still recorded.
#[test]
fn late_verdict_applies_the_fault_policy_without_an_event() {
    let (mut fw, s, c) = firewall(PlatformConfig::default(), true);
    let late = fw.late_verdict(&twist(s, c, 1, 0.1), 1);
    let fault = fw.fault_verdict(&twist(s, c, 2, 0.1), 2);
    assert_eq!(late.reject_reason(), Some(RejectReason::InternalFault));
    assert_eq!(fault.reject_reason(), Some(RejectReason::InternalFault));
    assert!(late.output().unwrap().motion.is_zero());
    assert!(fault.output().unwrap().motion.is_zero());
    assert_eq!(fw.stats().faults, 2);
    let devs = fw.drain_deviations();
    assert_eq!(devs.len(), 1, "only fault_verdict records: {devs:?}");
    // Fail-open: the original passes, still without an event.
    let (mut fw, s, c) = firewall(
        PlatformConfig {
            fault_policy: FaultPolicy::FailOpen,
            ..Default::default()
        },
        true,
    );
    assert!(fw.late_verdict(&twist(s, c, 1, 0.1), 1).is_passed());
    assert!(fw.events().as_slice().is_empty());
    // A failed post-condition is recorded.
    fw.inject_fault = true;
    fw.check(&twist(s, c, 10 * MS, 0.1), 10 * MS);
    assert_eq!(fw.events().as_slice().len(), 1);
    assert_eq!(fw.events().as_slice()[0].rule, rules::INTERNAL_FAULT);
}

#[test]
fn joint_late_verdict_holds_without_an_event() {
    let mut p = Profile {
        model: "humanoid".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert(P.into());
    p.writer_topics.insert("/lowcmd".into());
    p.motion_envelopes.insert(
        "/lowcmd".into(),
        Envelope {
            max_joint_speed: Some(30.0),
            ..Default::default()
        },
    );
    let spec = JointChannelSpec {
        allowed_sources: vec![format!("{P}00000103")],
        motors: vec![
            MotorLimits {
                kp_min: 5.0,
                max_dq_step: Some(0.5),
                ..MotorLimits::enabled((-1.0, 1.0), 10.0, 20.0, 100.0, 5.0)
            };
            4
        ],
        rate: Some(JointRate::around(500.0)),
        ..Default::default()
    };
    let platform = PlatformConfig {
        morphology: Morphology::Humanoid,
        fail_behaviour: FailBehaviour::HoldLast {
            max_hold_ns: 50 * MS,
        },
        fault_policy: FaultPolicy::FailHold,
        ..Default::default()
    };
    let pol = Policy::compile_with_joints(
        &p,
        platform,
        &BTreeMap::new(),
        &BTreeMap::from([("/lowcmd".to_string(), spec)]),
    )
    .unwrap();
    let mut fw = Firewall::new(pol);
    let s = fw.source_id(&format!("{P}00000103")).unwrap();
    let c = fw.channel_id("/lowcmd").unwrap();
    let m = MotorCmd::enabled(0.1, 0.0, 1.0, 40.0, 1.0);
    let frame = JointFrame::from_slice(&[m; 4], Some(true)).unwrap();
    assert!(fw
        .check_joint(&JointCommand::new(s, c, 10 * MS, frame), 10 * MS)
        .is_passed());
    let v = fw.joint_late_verdict(&JointCommand::new(s, c, 12 * MS, frame), 12 * MS);
    assert_eq!(v.reject_reason(), Some(RejectReason::InternalFault));
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    assert_eq!(fw.stats().faults, 1);
    assert!(fw.events().as_slice().is_empty());
    // A hold that outlives max_hold_ns is still reported.
    let v = fw.joint_late_verdict(&JointCommand::new(s, c, 100 * MS, frame), 100 * MS);
    assert_eq!(v.reject_reason(), Some(RejectReason::InternalFault));
    assert!(fw
        .events()
        .as_slice()
        .iter()
        .all(|e| e.rule != rules::INTERNAL_FAULT));
    assert!(fw
        .events()
        .as_slice()
        .iter()
        .any(|e| e.rule == rules::JOINT_HOLD_EXCEEDED));
    let fault = fw.joint_fault_verdict(&JointCommand::new(s, c, 102 * MS, frame), 102 * MS);
    assert_eq!(fault.reject_reason(), Some(RejectReason::InternalFault));
    assert!(fw
        .events()
        .as_slice()
        .iter()
        .any(|e| e.rule == rules::INTERNAL_FAULT));
}
