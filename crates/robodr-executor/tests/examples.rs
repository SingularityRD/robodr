//! The shipped example configurations (`config/executor*.example.json`)
//! validate, and with their matching response policies they decide what
//! the docs say: the generic one isolates with management, uplink, control
//! bus and motion path kept open; the Unitree G1 one never isolates or
//! quarantines (humanoid, empty `fall_safe_restrict`) and never touches the
//! robot network that carries `rt/lowcmd`, even with a policy that would
//! otherwise allow it.

use std::path::{Path, PathBuf};

use robodr_executor::config::{load_policy, ExecutorConfig, Resolved};
use robodr_executor::decision::{codes, precheck, Effect};
use robodr_executor::order::{Locator, Order, Origin, Target};
use robodr_responder::{
    ActionId, Connectivity, ControlMode, MissionPhase, OperationalContext, ResponsePolicy,
    RestrictTarget, SafetyState,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config")
}

fn example(name: &str) -> Resolved {
    let text = std::fs::read_to_string(root().join(name)).unwrap();
    ExecutorConfig::parse(&text).unwrap().validate().unwrap()
}

fn policy(name: &str) -> ResponsePolicy {
    let mut p = load_policy(&root().join(name)).unwrap();
    // The shipped policies are not OEM-validated (observe mode); judge as
    // if they were, to see the executor's own rules.
    p.oem_validated = true;
    p
}

fn order(action: ActionId, p: &ResponsePolicy, target: Target) -> Order {
    Order {
        id: "ex-1".into(),
        action,
        target,
        ttl_s: None,
        judged_state: SafetyState::Idle,
        context: OperationalContext {
            platform: p.platform,
            morphology: p.morphology,
            phase: MissionPhase::Parked,
            connectivity: Connectivity::Connected,
            control: ControlMode::Autonomous,
            operator_present: true,
            profile_locked: true,
        },
        plan_morphology: p.morphology,
        human_approved: true,
        replay: false,
        origin: Origin::ControlPlane {
            key_id: "soc:x:1".into(),
            requested_by: "analyst".into(),
        },
        issued_ms: 0,
        soc: None,
    }
}

/// Both examples name the SOC's public key (trust boundary M1): the same
/// file as agentd's `control_plane.soc_keys`.
#[test]
fn examples_name_the_soc_keys() {
    for name in ["executor.example.json", "executor.unitree-g1.example.json"] {
        let c = example(name);
        assert_eq!(
            c.config.soc.keys,
            vec![PathBuf::from("/etc/robodr/soc/soc.pub")],
            "{name}"
        );
        assert_eq!(c.config.soc.max_clock_skew_s, 30, "{name}");
    }
}

#[test]
fn generic_example_isolates_and_keeps_the_allow_lists() {
    let c = example("executor.example.json");
    let p = policy("response-policy.example.json");
    match precheck(&order(ActionId::IsolateNetwork, &p, Target::None), &p, &c)
        .unwrap()
        .effect
    {
        Effect::Isolate(s) => {
            assert_eq!(s.allow.len(), 4);
            assert_eq!(s.protected.len(), 1);
            // DDS discovery stays open on the control-bus interface... and,
            // since the motion path names an address only, on any.
            let d = s.discovery.expect("discovery kept open");
            assert_eq!(
                d.groups,
                vec!["239.255.0.1".parse::<std::net::IpAddr>().unwrap()]
            );
            assert_eq!(d.ports, vec![7400, 7401]);
            assert!(d.interfaces.is_empty());
        }
        e => panic!("{e:?}"),
    }
}

#[test]
fn unitree_g1_example_never_cuts_the_balance_loop() {
    let c = example("executor.unitree-g1.example.json");
    let mut p = policy("response-policy.unitree-g1.example.json");
    let rogue = Target::Participant {
        guid_prefix: "0110a2b3c4d5e6f701000000".parse().unwrap(),
        locators: vec![Locator {
            ip: "192.168.123.99".parse().unwrap(),
            port: 7411,
        }],
    };
    for (a, t) in [
        (ActionId::IsolateNetwork, Target::None),
        (ActionId::QuarantineNode, rogue.clone()),
    ] {
        assert_eq!(
            precheck(&order(a, &p, t), &p, &c).unwrap_err().code,
            codes::FALL_HAZARD,
            "{a:?}"
        );
    }
    // Even an OEM that lists both as fall-safe gets nothing on the robot
    // network: a participant there is refused, and isolation keeps it open.
    p.fall_safe_restrict = vec![RestrictTarget::Network, RestrictTarget::Participant];
    assert_eq!(
        precheck(&order(ActionId::QuarantineNode, &p, rogue), &p, &c)
            .unwrap_err()
            .code,
        codes::MOTION_PATH
    );
    match precheck(&order(ActionId::IsolateNetwork, &p, Target::None), &p, &c)
        .unwrap()
        .effect
    {
        Effect::Isolate(s) => {
            assert_eq!(s.protected.len(), 2, "low_level entries stay protected");
            assert!(s.protected.iter().all(|e| e.low_level));
        }
        e => panic!("{e:?}"),
    }
}
