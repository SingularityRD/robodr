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
