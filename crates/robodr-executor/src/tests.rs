//! Unit tests: the decision matrix (action × morphology × safety state ×
//! policy × approval) and the engine's journal / TTL / reconciliation logic
//! against an in-memory nftables model. The real-nftables tests (network
//! namespaces, traffic) are in `tests/netns.rs`.

use std::sync::{Arc, Mutex};

use robodr_responder::{
    ActionId, Connectivity, ControlMode, MissionPhase, Morphology, OperationalContext,
    PlatformFamily, ResponsePolicy, RestrictTarget, SafetyState,
};
use serde_json::{json, Value};

use crate::config::{ExecutorConfig, Resolved};
use crate::decision::{codes, precheck, recheck_safety, Current, Effect};
use crate::engine::{Engine, FixedSafety, Status};
use crate::fault::{self, Point};
use crate::journal::EventKind;
use crate::nft::Nft;
use crate::order::{Locator, Order, Origin, Target};

pub const GUID: &str = "0110a2b3c4d5e6f701000000";
pub const LOWCMD_GUID: &str = "0110aaaabbbbccccdddd0000";

pub fn config_json(state_dir: &str) -> String {
    json!({
        "schema": "robodr-executor-config/v1",
        "robot_id": "ugv-007",
        "socket": "/run/robodr-executor/executor.sock",
        "key_file": "/run/credentials/robodr-executor.service/executor.key",
        "state_dir": state_dir,
        "policy_path": "/etc/robodr/response-policy.json",
        "network": {
            "management": [{"cidr": "10.20.0.0/24", "proto": "tcp", "port": 443}],
            "uplink": [{"cidr": "10.20.0.10"}],
            "control_buses": {"exempt": true, "entries": [{"interface": "eth1"}]},
            "motion_control_path": [
                {"cidr": "192.168.123.0/24", "udp_ports": [7400, 7600], "note": "robot DDS bus"},
                {"guid_prefix": LOWCMD_GUID, "low_level": true, "note": "rt/lowcmd writer"}
            ]
        },
        "ttl": {"default_s": 600, "max_s": 3600}
    })
    .to_string()
}

pub fn cfg(state_dir: &str) -> Resolved {
    ExecutorConfig::parse(&config_json(state_dir))
        .unwrap()
        .validate()
        .unwrap()
}

pub fn policy(m: Morphology, validated: bool, fsr: &[RestrictTarget]) -> ResponsePolicy {
    let mut p = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
    p.morphology = m;
    p.oem_validated = validated;
    p.fall_safe_restrict = fsr.to_vec();
    p
}

pub fn ctx(m: Morphology) -> OperationalContext {
    OperationalContext {
        platform: PlatformFamily::Ugv,
        morphology: m,
        phase: MissionPhase::Transit,
        connectivity: Connectivity::Connected,
        control: ControlMode::Autonomous,
        operator_present: true,
        profile_locked: true,
    }
}

pub fn order(id: &str, action: ActionId, m: Morphology, state: SafetyState) -> Order {
    Order {
        id: id.into(),
        action,
        target: match action {
            ActionId::QuarantineNode => Target::Participant {
                guid_prefix: GUID.parse().unwrap(),
                locators: vec![Locator {
                    ip: "10.0.0.7".parse().unwrap(),
                    port: 7410,
                }],
            },
            _ => Target::None,
        },
        ttl_s: Some(60),
        judged_state: state,
        context: ctx(m),
        plan_morphology: m,
        human_approved: true,
        replay: false,
        origin: Origin::ControlPlane {
            key_id: "soc:test:1".into(),
            requested_by: "analyst".into(),
        },
        issued_ms: 0,
    }
}

/// Independent statement of the matrix the decision must implement.
fn expected(
    a: ActionId,
    m: Morphology,
    s: SafetyState,
    validated: bool,
    fsr: &[RestrictTarget],
    approved: bool,
) -> Result<&'static str, &'static str> {
    match a {
        ActionId::SafePause | ActionId::RequestSafeState | ActionId::RollbackConfig => {
            return Err(codes::NOT_EXECUTOR_ACTION)
        }
        ActionId::RecordEvidence => return Ok("evidence"),
        _ => {}
    }
    if !validated {
        return Err(codes::OBSERVE_MODE);
    }
    if s.safety_system_engaged() {
        return Err(codes::SAFETY_SYSTEM_ENGAGED);
    }
    if a == ActionId::RestrictMotion {
        return Ok("advisory");
    }
    let class = if a == ActionId::IsolateNetwork {
        RestrictTarget::Network
    } else {
        RestrictTarget::Participant
    };
    if matches!(m, Morphology::Humanoid | Morphology::Unspecified) {
        if !fsr.contains(&class) {
            return Err(codes::FALL_HAZARD);
        }
        if !approved {
            return Err(codes::NEEDS_APPROVAL);
        }
    }
    if matches!(
        m,
        Morphology::Humanoid | Morphology::Quadruped | Morphology::Unspecified
    ) && a == ActionId::QuarantineNode
        && !approved
    {
        return Err(codes::NEEDS_APPROVAL);
    }
    Ok(if a == ActionId::IsolateNetwork {
        "isolate"
    } else {
        "quarantine"
    })
}

#[test]
fn decision_matrix_action_morphology_state_policy_approval() {
    let c = cfg("/tmp/unused");
    let fsrs: [&[RestrictTarget]; 4] = [
        &[],
        &[RestrictTarget::Network],
        &[RestrictTarget::Participant],
        &[RestrictTarget::Network, RestrictTarget::Participant],
    ];
    let mut cases = 0;
    for a in ActionId::ALL {
        for m in Morphology::ALL {
            for s in SafetyState::ALL {
                for validated in [false, true] {
                    for fsr in fsrs {
                        for approved in [false, true] {
                            let p = policy(m, validated, fsr);
                            let mut o = order("r1", a, m, s);
                            o.human_approved = approved;
                            let got = precheck(&o, &p, &c);
                            let want = expected(a, m, s, validated, fsr, approved);
                            match (&got, want) {
                                (Ok(pl), Ok(kind)) => {
                                    let k = match pl.effect {
                                        Effect::Evidence => "evidence",
                                        Effect::Advisory { .. } => "advisory",
                                        Effect::Isolate(_) => "isolate",
                                        Effect::Quarantine(_) => "quarantine",
                                    };
                                    assert_eq!(k, kind, "{a:?} {m:?} {s:?} {validated} {fsr:?}");
                                }
                                (Err(r), Err(code)) => {
                                    assert_eq!(
                                        r.code, code,
                                        "{a:?} {m:?} {s:?} {validated} {fsr:?} {approved}"
                                    )
                                }
                                _ => panic!(
                                    "{a:?} {m:?} {s:?} validated={validated} fsr={fsr:?} \
                                     approved={approved}: got {got:?}, want {want:?}"
                                ),
                            }
                            // Invariants that hold whatever the matrix says.
                            if let Ok(pl) = &got {
                                assert!(!a.may_de_energise());
                                if matches!(pl.effect, Effect::Isolate(_) | Effect::Quarantine(_)) {
                                    assert!(!s.safety_system_engaged());
                                    assert!(pl.ttl_s.is_some_and(|t| t > 0));
                                    if m.falls_when_de_energised() {
                                        assert!(approved);
                                    }
                                }
                            }
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 7 * 7 * 7 * 2 * 4 * 2);
}

#[test]
fn morphology_is_the_executors_own() {
    let c = cfg("/tmp/unused");
    let p = policy(Morphology::Humanoid, true, &[]);
    // A wheeled order (context and plan) on a humanoid's executor.
    let o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        precheck(&o, &p, &c).unwrap_err().code,
        codes::MORPHOLOGY_MISMATCH
    );
    // A relabelled plan.
    let mut o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::Humanoid,
        SafetyState::Idle,
    );
    o.plan_morphology = Morphology::WheeledMobile;
    assert_eq!(
        precheck(&o, &p, &c).unwrap_err().code,
        codes::MORPHOLOGY_MISMATCH
    );
}

#[test]
fn replay_observe_and_targets_are_refused() {
    let c = cfg("/tmp/unused");
    let p = policy(Morphology::WheeledMobile, true, &[]);
    let mut o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    o.replay = true;
    assert_eq!(precheck(&o, &p, &c).unwrap_err().code, codes::REPLAY);
    let mut o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    o.context.profile_locked = false;
    assert_eq!(precheck(&o, &p, &c).unwrap_err().code, codes::OBSERVE_MODE);
    let mut o = order(
        "r1",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    o.target = Target::Node { name: "/x".into() };
    assert_eq!(
        precheck(&o, &p, &c).unwrap_err().code,
        codes::UNSUPPORTED_TARGET
    );
    o.target = Target::Process { name: "ctl".into() };
    assert_eq!(
        precheck(&o, &p, &c).unwrap_err().code,
        codes::UNSUPPORTED_TARGET
    );
    o.target = Target::None;
    assert_eq!(precheck(&o, &p, &c).unwrap_err().code, codes::INVALID_ORDER);
    let mut o = order(
        "bad id!",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(precheck(&o, &p, &c).unwrap_err().code, codes::INVALID_ORDER);
    o.id = "r1".into();
    o.ttl_s = Some(3601);
    assert_eq!(
        precheck(&o, &p, &c).unwrap_err().code,
        codes::TTL_OUT_OF_RANGE
    );
    o.ttl_s = Some(0);
    assert_eq!(
        precheck(&o, &p, &c).unwrap_err().code,
        codes::TTL_OUT_OF_RANGE
    );
    o.ttl_s = None;
    assert_eq!(precheck(&o, &p, &c).unwrap().ttl_s, Some(600));
}

#[test]
fn motion_control_path_is_never_cut() {
    let c = cfg("/tmp/unused");
    let wheeled = policy(Morphology::WheeledMobile, true, &[]);
    // A participant whose locator is on the protected robot DDS bus.
    let mut o = order(
        "r1",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    o.target = Target::Participant {
        guid_prefix: GUID.parse().unwrap(),
        locators: vec![Locator {
            ip: "192.168.123.161".parse().unwrap(),
            port: 7411,
        }],
    };
    assert_eq!(
        precheck(&o, &wheeled, &c).unwrap_err().code,
        codes::MOTION_PATH
    );
    // Same address, port outside the protected range: allowed.
    o.target = Target::Participant {
        guid_prefix: GUID.parse().unwrap(),
        locators: vec![Locator {
            ip: "192.168.123.161".parse().unwrap(),
            port: 9000,
        }],
    };
    assert!(precheck(&o, &wheeled, &c).is_ok());
    // The rt/lowcmd writer (low_level): refused even when the policy lists
    // participants as fall-safe on a humanoid.
    let humanoid = policy(Morphology::Humanoid, true, &[RestrictTarget::Participant]);
    let mut o = order(
        "r1",
        ActionId::QuarantineNode,
        Morphology::Humanoid,
        SafetyState::Idle,
    );
    o.target = Target::Participant {
        guid_prefix: LOWCMD_GUID.parse().unwrap(),
        locators: vec![],
    };
    assert_eq!(
        precheck(&o, &humanoid, &c).unwrap_err().code,
        codes::MOTION_PATH
    );
    // Isolation keeps the motion path (both entries) on a wheeled robot...
    let o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    match precheck(&o, &wheeled, &c).unwrap().effect {
        Effect::Isolate(s) => {
            assert_eq!(s.protected.len(), 2);
            assert_eq!(s.allow.len(), 3);
        }
        e => panic!("{e:?}"),
    }
    // ...and on a humanoid whose OEM listed network as fall-safe only the
    // low-level entry stays protected.
    let h = policy(Morphology::Humanoid, true, &[RestrictTarget::Network]);
    let o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::Humanoid,
        SafetyState::Idle,
    );
    match precheck(&o, &h, &c).unwrap().effect {
        Effect::Isolate(s) => {
            assert_eq!(s.protected.len(), 1);
            assert!(s.protected[0].low_level);
        }
        e => panic!("{e:?}"),
    }
    // Control buses not exempt when configured so.
    let mut c2 = c.clone();
    c2.config.network.control_buses.exempt = false;
    match precheck(&o, &h, &c2).unwrap().effect {
        Effect::Isolate(s) => assert_eq!(s.allow.len(), 2),
        e => panic!("{e:?}"),
    }
    // No management channel: isolation is never executed.
    let mut c3 = c.clone();
    c3.config.network.management.clear();
    let o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        precheck(&o, &wheeled, &c3).unwrap_err().code,
        codes::NO_MANAGEMENT_CHANNEL
    );
}

#[test]
fn safety_recheck_immediately_before_apply() {
    let o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::MovingSlow,
    );
    let cur = |state, age_ms| Ok(Current { state, age_ms });
    assert!(recheck_safety(&o, cur(SafetyState::MovingSlow, 10), 500).is_ok());
    for s in SafetyState::ALL {
        if s != SafetyState::MovingSlow {
            let code = recheck_safety(&o, cur(s, 10), 500).unwrap_err().code;
            if s.safety_system_engaged() {
                assert_eq!(code, codes::SAFETY_SYSTEM_ENGAGED);
            } else {
                assert_eq!(code, codes::SAFETY_STATE_CHANGED);
            }
        }
    }
    assert_eq!(
        recheck_safety(&o, cur(SafetyState::MovingSlow, 501), 500)
            .unwrap_err()
            .code,
        codes::SAFETY_STATE_STALE
    );
    assert_eq!(
        recheck_safety(&o, Err("no feed".into()), 500)
            .unwrap_err()
            .code,
        codes::SAFETY_STATE_UNAVAILABLE
    );
}

// --- Engine against an in-memory nftables model -------------------------------

/// A minimal model of `nft -j`: one optional `inet robodr` table built from
/// our own transactions, plus switches to fail or tamper.
#[derive(Default)]
pub struct Model {
    pub table: Option<Vec<Value>>,
    pub fail_apply: bool,
    pub applies: usize,
}

#[derive(Clone, Default)]
pub struct FakeNft(pub Arc<Mutex<Model>>);

impl Nft for FakeNft {
    fn run(&mut self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let mut m = self.0.lock().unwrap();
        match args {
            ["-j", "-f", "-"] => {
                if m.fail_apply {
                    return Err("nft failed: injected".into());
                }
                m.applies += 1;
                let batch: Value = serde_json::from_slice(stdin.unwrap()).unwrap();
                let mut t = m.table.clone();
                for cmd in batch["nftables"].as_array().unwrap() {
                    if let Some(a) = cmd.get("add") {
                        if let Some(tb) = a.get("table") {
                            if t.is_none() {
                                t = Some(vec![json!({"table": tb})]);
                            }
                        } else if let Some(c) = a.get("chain") {
                            t.as_mut().unwrap().push(json!({ "chain": c }));
                        } else if let Some(r) = a.get("rule") {
                            let mut r = r.clone();
                            for e in r["expr"].as_array_mut().unwrap() {
                                if e.get("counter").is_some() {
                                    *e = json!({"counter": {"packets": 0, "bytes": 0}});
                                }
                            }
                            t.as_mut().unwrap().push(json!({ "rule": r }));
                        }
                    } else if cmd.get("delete").is_some() {
                        t = None;
                    }
                }
                m.table = t;
                Ok(Vec::new())
            }
            ["-j", "list", "tables"] => {
                let mut v = vec![json!({"metainfo": {}})];
                if m.table.is_some() {
                    v.push(json!({"table": {"family": "inet", "name": "robodr"}}));
                }
                Ok(serde_json::to_vec(&json!({ "nftables": v })).unwrap())
            }
            ["-j", "list", "table", "inet", "robodr"] => match &m.table {
                Some(t) => Ok(serde_json::to_vec(&json!({ "nftables": t })).unwrap()),
                None => Err("No such file or directory".into()),
            },
            other => Err(format!("unexpected nft call {other:?}")),
        }
    }
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "robodr-executor-unit-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn engine(dir: &std::path::Path, nft: &FakeNft, boot: &str, now: u64) -> Engine {
    Engine::open(
        cfg(dir.to_str().unwrap()),
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        boot,
        now,
    )
    .unwrap()
}

fn idle() -> FixedSafety {
    FixedSafety(Current {
        state: SafetyState::Idle,
        age_ms: 5,
    })
}

fn kinds(e: &Engine) -> Vec<EventKind> {
    e.state().events.iter().map(|e| e.kind).collect()
}

#[test]
fn apply_verify_revert_and_idempotency() {
    let d = tmpdir("avr");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut idle(), 1_000);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(out.deadline_ms, Some(61_000));
    assert!(nft.0.lock().unwrap().table.is_some());
    // Same id, same order: duplicate, not applied again.
    let applies = nft.0.lock().unwrap().applies;
    let dup = e.submit(&o, &mut idle(), 1_100);
    assert!(dup.duplicate);
    assert_eq!(nft.0.lock().unwrap().applies, applies);
    // Same id, other order: conflict.
    let mut o2 = o.clone();
    o2.ttl_s = Some(30);
    assert_eq!(
        e.submit(&o2, &mut idle(), 1_100).refusal.unwrap().code,
        codes::ID_CONFLICT
    );
    // A second isolation is refused while one is active.
    let o3 = order(
        "r3",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        e.submit(&o3, &mut idle(), 1_100).refusal.unwrap().code,
        codes::ALREADY_ACTIVE
    );
    // Revert: table gone; again: idempotent.
    assert_eq!(e.revert("r1", "test", 2_000).status, Status::Reverted);
    assert!(nft.0.lock().unwrap().table.is_none());
    assert_eq!(e.revert("r1", "test", 2_100).status, Status::Reverted);
    assert_eq!(e.revert("nope", "test", 2_100).status, Status::Unknown);
    assert!(kinds(&e).contains(&EventKind::Applied));
    assert!(kinds(&e).contains(&EventKind::Verified));
    assert!(kinds(&e).contains(&EventKind::Reverted));
}

#[test]
fn safety_change_at_apply_time_applies_nothing() {
    let d = tmpdir("safety");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let mut estop = FixedSafety(Current {
        state: SafetyState::EStopActive,
        age_ms: 1,
    });
    let out = e.submit(&o, &mut estop, 1_000);
    assert_eq!(out.refusal.unwrap().code, codes::SAFETY_SYSTEM_ENGAGED);
    assert!(nft.0.lock().unwrap().table.is_none());
    assert_eq!(nft.0.lock().unwrap().applies, 0);
}

#[test]
fn failed_apply_and_failed_verify_roll_back() {
    let d = tmpdir("fail");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    nft.0.lock().unwrap().fail_apply = true;
    let o = order(
        "r1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut idle(), 1_000);
    assert_eq!(out.status, Status::Failed);
    assert!(e.state().entries.is_empty());
    nft.0.lock().unwrap().fail_apply = false;
    // Journal write failure: nothing applied.
    fault::arm(Point::JournalWrite);
    let o2 = order(
        "r2",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let out = e.submit(&o2, &mut idle(), 1_000);
    fault::disarm();
    assert_eq!(out.status, Status::Failed);
    assert!(nft.0.lock().unwrap().table.is_none());
}

#[test]
fn ttl_expiry_reverts_and_survives_restart() {
    let d = tmpdir("ttl");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let q = order(
        "q1",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let i = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let mut q = q;
    q.ttl_s = Some(10);
    assert_eq!(e.submit(&q, &mut idle(), 1_000).status, Status::Verified);
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
    e.tick(5_000);
    assert_eq!(e.state().entries.len(), 2);
    e.tick(11_000);
    assert_eq!(e.status("q1").status, Status::Reverted);
    assert_eq!(e.status("i1").status, Status::Verified);
    drop(e);
    // Restart (same boot) before the isolation's deadline: re-verified.
    let e = engine(&d, &nft, "b1", 30_000);
    assert_eq!(e.status("i1").status, Status::Verified);
    drop(e);
    // Restart after the deadline: reverted at reconciliation.
    let e = engine(&d, &nft, "b1", 62_000);
    assert_eq!(e.status("i1").status, Status::Reverted);
    assert!(nft.0.lock().unwrap().table.is_none());
}

#[test]
fn reboot_reapplies_but_operator_removal_is_honoured() {
    let d = tmpdir("reboot");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let i = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
    drop(e);
    // Reboot: the kernel ruleset is empty; the action is re-applied.
    nft.0.lock().unwrap().table = None;
    let mut e = engine(&d, &nft, "b2", 2_000);
    assert_eq!(e.status("i1").status, Status::Verified);
    assert!(nft.0.lock().unwrap().table.is_some());
    // Operator emergency disable while running: honoured, not re-applied.
    nft.0.lock().unwrap().table = None;
    e.periodic_verify(3_000);
    assert_eq!(e.status("i1").status, Status::RemovedExternally);
    assert!(nft.0.lock().unwrap().table.is_none());
    e.tick(60_000);
    assert!(nft.0.lock().unwrap().table.is_none());
    // Operator removal while the executor was down (same boot).
    let i2 = order(
        "i2",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i2, &mut idle(), 4_000).status, Status::Verified);
    drop(e);
    nft.0.lock().unwrap().table = None;
    let e = engine(&d, &nft, "b2", 5_000);
    assert_eq!(e.status("i2").status, Status::RemovedExternally);
    assert!(nft.0.lock().unwrap().table.is_none());
}

#[test]
fn drift_is_repaired() {
    let d = tmpdir("drift");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let i = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
    // Someone deletes the final drop rule of the input chain.
    {
        let mut m = nft.0.lock().unwrap();
        let t = m.table.as_mut().unwrap();
        let last_input = t
            .iter()
            .rposition(|o| o.get("rule").is_some_and(|r| r["chain"] == "input"))
            .unwrap();
        t.remove(last_input);
    }
    e.periodic_verify(2_000);
    assert!(kinds(&e).contains(&EventKind::Drift));
    let listed = crate::nft::read_table(&mut nft.clone()).unwrap();
    assert!(crate::nft::verify(listed.as_deref(), &e.rendered()).is_ok());
}

#[test]
fn crash_between_apply_and_journal_commit_is_reverted_at_restart() {
    let d = tmpdir("crash");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let keep = order(
        "k1",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&keep, &mut idle(), 1_000).status, Status::Verified);
    let before = nft.0.lock().unwrap().table.clone();
    let i = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    fault::arm(Point::AfterApply);
    let out = e.submit(&i, &mut idle(), 2_000);
    fault::disarm();
    assert!(out.error.unwrap().contains("fault injected"));
    // The isolation rules are installed but the journal still says applying.
    assert_ne!(nft.0.lock().unwrap().table, before);
    drop(e);
    let e = engine(&d, &nft, "b1", 3_000);
    assert_eq!(e.status("i1").status, Status::Failed);
    assert_eq!(e.status("k1").status, Status::Verified);
    // Exactly the earlier table (only the quarantine) is in place again.
    let listed = crate::nft::read_table(&mut nft.clone()).unwrap();
    assert!(crate::nft::verify(listed.as_deref(), &e.rendered()).is_ok());
    assert_eq!(strip(&nft.0.lock().unwrap().table), strip(&before));

    // Crash after the revert intent: completed at restart.
    let mut e = e;
    fault::arm(Point::AfterRevertIntent);
    e.revert("k1", "test", 4_000);
    fault::disarm();
    drop(e);
    let e = engine(&d, &nft, "b1", 5_000);
    assert_eq!(e.status("k1").status, Status::Reverted);
    assert!(nft.0.lock().unwrap().table.is_none());
}

fn strip(t: &Option<Vec<Value>>) -> Option<Vec<Value>> {
    t.clone()
}

#[test]
fn corrupt_journal_deletes_the_table_and_starts_empty() {
    let d = tmpdir("corrupt");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let i = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
    drop(e);
    std::fs::write(d.join("journal.json"), b"{not json").unwrap();
    let e = engine(&d, &nft, "b1", 2_000);
    assert!(e.state().entries.is_empty());
    assert!(nft.0.lock().unwrap().table.is_none());
    assert!(kinds(&e).contains(&EventKind::JournalReset));
}

#[test]
fn advisory_and_not_executor_actions_touch_nothing() {
    let d = tmpdir("advisory");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let o = order(
        "m1",
        ActionId::RestrictMotion,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&o, &mut idle(), 1_000).status, Status::Advisory);
    for a in [
        ActionId::SafePause,
        ActionId::RequestSafeState,
        ActionId::RollbackConfig,
    ] {
        let o = order(a.as_str(), a, Morphology::WheeledMobile, SafetyState::Idle);
        assert_eq!(
            e.submit(&o, &mut idle(), 1_000).refusal.unwrap().code,
            codes::NOT_EXECUTOR_ACTION
        );
    }
    let o = order(
        "ev",
        ActionId::RecordEvidence,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        e.submit(&o, &mut idle(), 1_000).refusal.unwrap().code,
        codes::EVIDENCE_ELSEWHERE
    );
    assert_eq!(nft.0.lock().unwrap().applies, 0);
}

#[test]
fn humanoid_refusals_reach_no_rule() {
    let d = tmpdir("humanoid");
    let nft = FakeNft::default();
    let mut e = Engine::open(
        cfg(d.to_str().unwrap()),
        policy(Morphology::Humanoid, true, &[]),
        Box::new(nft.clone()),
        "b1",
        1_000,
    )
    .unwrap();
    for a in ActionId::ALL {
        let o = order(a.as_str(), a, Morphology::Humanoid, SafetyState::Idle);
        let out = e.submit(&o, &mut idle(), 1_000);
        assert!(
            matches!(out.status, Status::Refused | Status::Advisory),
            "{a:?}: {out:?}"
        );
    }
    assert_eq!(nft.0.lock().unwrap().applies, 0);
    assert!(nft.0.lock().unwrap().table.is_none());
}

#[test]
fn evidence_adapter_marks_and_verifies() {
    struct Sink(Vec<Value>);
    impl crate::evidence::EvidenceSink for Sink {
        fn mark(&mut self, note: &Value) -> Result<String, String> {
            self.0.push(note.clone());
            Ok(format!("robodr-blackbox://ugv-007/0/{}", self.0.len()))
        }
        fn verify(&mut self, r: &str) -> Result<(), String> {
            if r.ends_with(&self.0.len().to_string()) {
                Ok(())
            } else {
                Err("missing".into())
            }
        }
    }
    // Accepted even while the e-stop is engaged and in observe mode.
    let mut o = order(
        "ev1",
        ActionId::RecordEvidence,
        Morphology::Humanoid,
        SafetyState::EStopActive,
    );
    o.context.profile_locked = false;
    let mut s = Sink(Vec::new());
    let out = crate::evidence::record(&o, &["robodr-blackbox://x/0/1".into()], &mut s, 5);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(s.0[0]["kind"], "robodr.evidence_mark");
    assert_eq!(s.0[0]["bundle"][0], "robodr-blackbox://x/0/1");
    // A replay or another action is refused and marks nothing.
    o.replay = true;
    assert_eq!(
        crate::evidence::record(&o, &[], &mut s, 6).status,
        Status::Refused
    );
    let o = order(
        "x",
        ActionId::IsolateNetwork,
        Morphology::Humanoid,
        SafetyState::Idle,
    );
    assert_eq!(
        crate::evidence::record(&o, &[], &mut s, 6).status,
        Status::Refused
    );
    assert_eq!(s.0.len(), 1);
}

#[test]
fn journal_round_trips_every_effect() {
    let d = tmpdir("roundtrip");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    for (id, a) in [
        ("i1", ActionId::IsolateNetwork),
        ("q1", ActionId::QuarantineNode),
    ] {
        let o = order(id, a, Morphology::WheeledMobile, SafetyState::Idle);
        assert_eq!(e.submit(&o, &mut idle(), 1_000).status, Status::Verified);
    }
    let before = e.state().clone();
    drop(e);
    match crate::journal::Journal::new(&d).load() {
        crate::journal::Loaded::State(s) => {
            assert_eq!(s.entries, before.entries);
            assert_eq!(s.history, before.history);
        }
        other => panic!("{other:?}"),
    }
}
