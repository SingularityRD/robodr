//! Unit tests: the decision matrix (action × morphology × safety state ×
//! policy × approval × target × motion path × profile lock × TTL) and the
//! engine's journal / TTL / reconciliation logic against an in-memory
//! nftables model. The real-nftables tests (network namespaces, traffic)
//! are in `tests/netns.rs`.

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

/// The test SOC's Ed25519 seed (its public key file: [`soc_key_path`]).
pub const SOC_SEED: [u8; 32] = [7; 32];
pub const SOC_KEY_ID: &str = "soc:test:1";

/// The test SOC's public key file (written once per process, root-owned,
/// mode 0644: what `soc.keys` accepts).
pub fn soc_key_path() -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = std::env::temp_dir().join(format!("robodr-exec-test-soc-{}.pub", std::process::id()));
    if !p.exists() {
        let tmp = p.with_extension(
            format!("{:?}", std::thread::current().id())
                .replace(|c: char| !c.is_ascii_alphanumeric(), ""),
        );
        std::fs::write(
            &tmp,
            crate::soc::testing::public_key_json(&SOC_SEED, SOC_KEY_ID),
        )
        .unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::rename(&tmp, &p).unwrap();
    }
    p
}

static NONCES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Attach a fresh SOC request (signed at `ts_s`, a new nonce) to a
/// control-plane order, matching the order as it now is.
pub fn sign_at(o: Order, ts_s: u64) -> Order {
    let n = NONCES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    crate::soc::testing::sign_order(
        o,
        &SOC_SEED,
        "ugv-007",
        ts_s,
        &format!("test-nonce-{n:020}"),
    )
}

/// [`sign_at`] at 1 s (the engine tests run at a wall clock of 1..30 s).
pub fn signed(o: Order) -> Order {
    sign_at(o, 1)
}

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
                {"cidr": "192.168.123.161", "guid_prefix": LOWCMD_GUID, "low_level": true,
                 "note": "rt/lowcmd writer"}
            ],
            "quarantine": {"cidrs": ["10.0.0.0/24", "192.168.123.0/24"]}
        },
        "ttl": {"default_s": 600, "max_s": 3600},
        "soc": {"keys": [soc_key_path()]}
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

/// A control-plane order with a matching SOC request (see [`signed`]).
pub fn order(id: &str, action: ActionId, m: Morphology, state: SafetyState) -> Order {
    signed(unsigned(id, action, m, state))
}

/// The same order without its SOC request.
pub fn unsigned(id: &str, action: ActionId, m: Morphology, state: SafetyState) -> Order {
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
            key_id: SOC_KEY_ID.into(),
            requested_by: "analyst".into(),
        },
        issued_ms: 0,
        soc: None,
    }
}

/// A quarantine target of the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tgt {
    /// An unprotected GUID, its locator outside every motion-path address.
    Outside,
    /// An unprotected GUID, its locator inside the robot bus (192.168.123/24).
    InsideBus,
    /// The protected low-level participant's GUID.
    ProtectedGuid,
    /// An unprotected GUID without locators.
    NoLocators,
}

impl Tgt {
    const ALL: [Tgt; 4] = [
        Tgt::Outside,
        Tgt::InsideBus,
        Tgt::ProtectedGuid,
        Tgt::NoLocators,
    ];

    fn target(self) -> Target {
        let loc = |ip: &str| Locator {
            ip: ip.parse().unwrap(),
            port: 7410,
        };
        match self {
            Tgt::Outside => Target::Participant {
                guid_prefix: GUID.parse().unwrap(),
                locators: vec![loc("10.0.0.7")],
            },
            Tgt::InsideBus => Target::Participant {
                guid_prefix: GUID.parse().unwrap(),
                locators: vec![loc("192.168.123.50")],
            },
            Tgt::ProtectedGuid => Target::Participant {
                guid_prefix: LOWCMD_GUID.parse().unwrap(),
                locators: vec![loc("10.0.0.7")],
            },
            Tgt::NoLocators => Target::Participant {
                guid_prefix: GUID.parse().unwrap(),
                locators: vec![],
            },
        }
    }
}

/// A motion-control-path configuration of the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mp {
    /// The robot bus (not low-level) and the low-level writer (cidr + GUID).
    BusAndLowcmd,
    /// The whole robot network is low-level (the Unitree G1 example).
    LowLevelNetwork,
    /// No motion control path configured.
    None,
    /// An interface-only entry (no address: nothing can be proven outside).
    InterfaceOnly,
}

impl Mp {
    const ALL: [Mp; 4] = [
        Mp::BusAndLowcmd,
        Mp::LowLevelNetwork,
        Mp::None,
        Mp::InterfaceOnly,
    ];

    fn entries(self) -> Value {
        match self {
            Mp::BusAndLowcmd => json!([
                {"cidr": "192.168.123.0/24", "udp_ports": [7400, 7600]},
                {"cidr": "192.168.123.161", "guid_prefix": LOWCMD_GUID, "low_level": true}
            ]),
            Mp::LowLevelNetwork => json!([{"cidr": "192.168.123.0/24", "low_level": true}]),
            Mp::None => json!([]),
            Mp::InterfaceOnly => json!([{"interface": "eth2"}]),
        }
    }

    fn cfg(self) -> Resolved {
        let mut v: Value = serde_json::from_str(&config_json("/tmp/unused")).unwrap();
        v["network"]["motion_control_path"] = self.entries();
        ExecutorConfig::parse(&v.to_string())
            .unwrap()
            .validate()
            .unwrap()
    }

    /// (low_level, has cidr containing 192.168.123.50, guid is LOWCMD,
    /// interface-only) per entry.
    fn model(self) -> Vec<(bool, bool, bool, bool)> {
        match self {
            Mp::BusAndLowcmd => vec![(false, true, false, false), (true, false, true, false)],
            Mp::LowLevelNetwork => vec![(true, true, false, false)],
            Mp::None => vec![],
            Mp::InterfaceOnly => vec![(false, false, false, true)],
        }
    }
}

/// One cell of the matrix.
#[derive(Debug, Clone, Copy)]
struct Cell<'a> {
    a: ActionId,
    m: Morphology,
    s: SafetyState,
    validated: bool,
    fsr: &'a [RestrictTarget],
    approved: bool,
    tgt: Tgt,
    mp: Mp,
    locked: bool,
    ttl: Option<u64>,
}

/// Independent statement of the matrix the decision must implement.
fn expected(c: &Cell<'_>) -> Result<&'static str, &'static str> {
    let a = c.a;
    match a {
        ActionId::SafePause | ActionId::RequestSafeState | ActionId::RollbackConfig => {
            return Err(codes::NOT_EXECUTOR_ACTION)
        }
        ActionId::RecordEvidence => return Ok("evidence"),
        _ => {}
    }
    if !c.validated || !c.locked {
        return Err(codes::OBSERVE_MODE);
    }
    if c.s.safety_system_engaged() {
        return Err(codes::SAFETY_SYSTEM_ENGAGED);
    }
    if c.s == SafetyState::Unknown {
        return Err(codes::SAFETY_STATE_UNAVAILABLE);
    }
    if a == ActionId::RestrictMotion {
        return Ok("advisory");
    }
    let class = if a == ActionId::IsolateNetwork {
        RestrictTarget::Network
    } else {
        RestrictTarget::Participant
    };
    if matches!(c.m, Morphology::Humanoid | Morphology::Unspecified) {
        if !c.fsr.contains(&class) {
            return Err(codes::FALL_HAZARD);
        }
        if !c.approved {
            return Err(codes::NEEDS_APPROVAL);
        }
    }
    let quarantine = a == ActionId::QuarantineNode;
    if matches!(
        c.m,
        Morphology::Humanoid | Morphology::Quadruped | Morphology::Unspecified
    ) && quarantine
        && !c.approved
    {
        return Err(codes::NEEDS_APPROVAL);
    }
    if quarantine {
        // Entries this quarantine may not cut.
        let keep: Vec<_> =
            c.mp.model()
                .into_iter()
                .filter(|(low, ..)| *low || !c.fsr.contains(&RestrictTarget::Participant))
                .collect();
        if c.tgt == Tgt::ProtectedGuid && keep.iter().any(|(_, _, g, _)| *g) {
            return Err(codes::MOTION_PATH);
        }
        if c.tgt == Tgt::NoLocators {
            return Err(codes::LOCATORS_REQUIRED);
        }
        for (_, bus, _, iface_only) in &keep {
            if *iface_only || (*bus && c.tgt == Tgt::InsideBus) {
                return Err(codes::MOTION_PATH);
            }
        }
    }
    let ttl = c.ttl.unwrap_or(600);
    if ttl == 0 || ttl > 3600 {
        return Err(codes::TTL_OUT_OF_RANGE);
    }
    Ok(if quarantine { "quarantine" } else { "isolate" })
}

#[test]
fn decision_matrix_action_morphology_state_policy_approval() {
    let cfgs: Vec<(Mp, Resolved)> = Mp::ALL.iter().map(|m| (*m, m.cfg())).collect();
    let fsrs: [&[RestrictTarget]; 4] = [
        &[],
        &[RestrictTarget::Network],
        &[RestrictTarget::Participant],
        &[RestrictTarget::Network, RestrictTarget::Participant],
    ];
    let mut cases = 0usize;
    for a in ActionId::ALL {
        for m in Morphology::ALL {
            for s in SafetyState::ALL {
                for validated in [false, true] {
                    for fsr in fsrs {
                        let p = policy(m, validated, fsr);
                        for approved in [false, true] {
                            for tgt in Tgt::ALL {
                                for (mp, c) in &cfgs {
                                    for locked in [false, true] {
                                        for ttl in [None, Some(60), Some(3601)] {
                                            let cell = Cell {
                                                a,
                                                m,
                                                s,
                                                validated,
                                                fsr,
                                                approved,
                                                tgt,
                                                mp: *mp,
                                                locked,
                                                ttl,
                                            };
                                            check_cell(&cell, &p, c);
                                            cases += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // 7 actions x 7 morphologies x 7 states x 2 validation x 4 fall-safe
    // sets x 2 approval (the v1 matrix: 5 488) x 4 targets x 4 motion paths
    // x 2 profile locks x 3 TTLs.
    assert_eq!(cases, 7 * 7 * 7 * 2 * 4 * 2 * 4 * 4 * 2 * 3);
    assert_eq!(cases, 526_848);
}

fn check_cell(cell: &Cell<'_>, p: &ResponsePolicy, c: &Resolved) {
    // precheck is pure: the approval flag here is what `soc::verify`
    // established (the engine tests cover the signature).
    let mut o = unsigned("r1", cell.a, cell.m, cell.s);
    o.human_approved = cell.approved;
    o.context.profile_locked = cell.locked;
    o.ttl_s = cell.ttl;
    if cell.a == ActionId::QuarantineNode {
        o.target = cell.tgt.target();
    }
    let got = precheck(&o, p, c);
    let want = expected(cell);
    match (&got, want) {
        (Ok(pl), Ok(kind)) => {
            let k = match pl.effect {
                Effect::Evidence => "evidence",
                Effect::Advisory { .. } => "advisory",
                Effect::Isolate(_) => "isolate",
                Effect::Quarantine(_) => "quarantine",
            };
            assert_eq!(k, kind, "{cell:?}");
        }
        (Err(r), Err(code)) => assert_eq!(r.code, code, "{cell:?}: {}", r.reason),
        _ => panic!("{cell:?}: got {got:?}, want {want:?}"),
    }
    // Invariants that hold whatever the matrix says.
    if let Ok(pl) = &got {
        assert!(!cell.a.may_de_energise());
        if matches!(pl.effect, Effect::Isolate(_) | Effect::Quarantine(_)) {
            assert!(!cell.s.safety_system_engaged());
            assert_ne!(cell.s, SafetyState::Unknown);
            assert!(cell.locked && cell.validated);
            assert!(pl.ttl_s.is_some_and(|t| (1..=3600).contains(&t)));
            if cell.m.falls_when_de_energised() {
                assert!(cell.approved);
            }
        }
        let class = match pl.effect {
            Effect::Isolate(_) => RestrictTarget::Network,
            _ => RestrictTarget::Participant,
        };
        let keep: Vec<_> = c
            .config
            .network
            .motion_control_path
            .iter()
            .filter(|e| e.low_level || !p.fall_safe_restrict.contains(&class))
            .cloned()
            .collect();
        match &pl.effect {
            // What may not be cut is frozen into the effect (rendered
            // before any drop).
            Effect::Isolate(s) => assert_eq!(s.protected, keep, "{cell:?}"),
            Effect::Quarantine(q) => {
                assert_eq!(q.protected, keep, "{cell:?}");
                assert!(!q.locators.is_empty());
                for e in &keep {
                    assert!(e.cidr.is_some(), "{cell:?}");
                    assert!(q.locators.iter().all(|l| !e.cidr.unwrap().contains(l.ip)));
                }
            }
            _ => {}
        }
    }
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
    // Same address, port outside the protected range: still refused (a
    // locator must lie outside the protected address, the port proves
    // nothing about the participant).
    o.target = Target::Participant {
        guid_prefix: GUID.parse().unwrap(),
        locators: vec![Locator {
            ip: "192.168.123.161".parse().unwrap(),
            port: 9000,
        }],
    };
    assert_eq!(
        precheck(&o, &wheeled, &c).unwrap_err().code,
        codes::MOTION_PATH
    );
    // Outside: allowed, and the protected entries travel with it.
    o.target = Target::Participant {
        guid_prefix: GUID.parse().unwrap(),
        locators: vec![Locator {
            ip: "10.0.0.7".parse().unwrap(),
            port: 7410,
        }],
    };
    match precheck(&o, &wheeled, &c).unwrap().effect {
        Effect::Quarantine(q) => assert_eq!(q.protected.len(), 2),
        e => panic!("{e:?}"),
    }
    // Without locators: refused.
    o.target = Target::Participant {
        guid_prefix: GUID.parse().unwrap(),
        locators: vec![],
    };
    assert_eq!(
        precheck(&o, &wheeled, &c).unwrap_err().code,
        codes::LOCATORS_REQUIRED
    );
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
            } else if s == SafetyState::Unknown {
                // L6: an unknown state never allows anything.
                assert_eq!(code, codes::SAFETY_STATE_UNAVAILABLE);
            } else {
                assert_eq!(code, codes::SAFETY_STATE_CHANGED);
            }
        }
    }
    // L6: judged in an unknown state, current unknown too: refused.
    let mut u = o.clone();
    u.judged_state = SafetyState::Unknown;
    assert_eq!(
        recheck_safety(&u, cur(SafetyState::Unknown, 10), 500)
            .unwrap_err()
            .code,
        codes::SAFETY_STATE_UNAVAILABLE
    );
    // The re-arm check after a reboot: known, fresh, not engaged.
    use crate::decision::recheck_rearm;
    assert!(recheck_rearm(cur(SafetyState::Idle, 10), 500).is_ok());
    assert!(recheck_rearm(cur(SafetyState::MovingFast, 10), 500).is_ok());
    for (st, age, code) in [
        (SafetyState::Unknown, 10, codes::SAFETY_STATE_UNAVAILABLE),
        (SafetyState::EStopActive, 10, codes::SAFETY_SYSTEM_ENGAGED),
        (SafetyState::Idle, 501, codes::SAFETY_STATE_STALE),
    ] {
        assert_eq!(recheck_rearm(cur(st, age), 500).unwrap_err().code, code);
    }
    assert_eq!(
        recheck_rearm(Err("x".into()), 500).unwrap_err().code,
        codes::SAFETY_STATE_UNAVAILABLE
    );
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

fn engine(
    dir: &std::path::Path,
    nft: &FakeNft,
    boot: &str,
    now: impl Into<crate::engine::Now>,
) -> Engine {
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
    let q = signed(q);
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

/// L1: within a boot the TTL runs on CLOCK_BOOTTIME: a wall-clock step back
/// does not extend an action, a step forward (NTP at boot) does not cut it
/// short.
#[test]
fn l1_ttl_runs_on_boottime_within_a_boot() {
    use crate::engine::Now;
    let at = |wall_ms, boot_ms| Now {
        wall_ms,
        boot_ms: Some(boot_ms),
    };
    let d = tmpdir("clock");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", at(100_000, 5_000));
    let i = sign_at(
        unsigned(
            "i1",
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        ),
        100,
    );
    assert_eq!(
        e.submit(&i, &mut idle(), at(100_000, 5_000)).status,
        Status::Verified
    );
    // The wall clock jumps an hour forward (first NTP sync): still active.
    e.tick(at(3_700_000, 6_000));
    assert_eq!(e.status("i1").status, Status::Verified);
    // ... and back 50 s: 60 s on boottime still decide.
    e.tick(at(50_000, 64_000));
    assert_eq!(e.status("i1").status, Status::Verified);
    e.tick(at(50_100, 65_000));
    assert_eq!(e.status("i1").status, Status::Reverted);
    assert!(nft.0.lock().unwrap().table.is_none());
    // A restart in the same boot keeps the boottime deadline, whatever the
    // wall clock says.
    let i2 = sign_at(
        unsigned(
            "i2",
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        ),
        100,
    );
    assert_eq!(
        e.submit(&i2, &mut idle(), at(100_000, 70_000)).status,
        Status::Verified
    );
    drop(e);
    let e = engine(&d, &nft, "b1", at(10_000, 71_000));
    assert_eq!(e.status("i2").status, Status::Verified);
    drop(e);
    let e = engine(&d, &nft, "b1", at(10_000, 130_000));
    assert_eq!(e.status("i2").status, Status::Reverted);
    // Without a boot clock the wall clock decides, and a step back never
    // extends.
    let i3 = sign_at(
        unsigned(
            "i3",
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        ),
        100,
    );
    let mut e = e;
    let wall = |w| Now {
        wall_ms: w,
        boot_ms: None,
    };
    assert_eq!(
        e.submit(&i3, &mut idle(), wall(100_000)).status,
        Status::Verified
    );
    e.tick(wall(50_000));
    assert_eq!(e.status("i3").status, Status::Reverted);
}

/// L4: after a reboot an action is re-validated against the current
/// configuration and policy and installed again only with a fresh, known
/// safety state that is not engaged.
#[test]
fn l4_reboot_reapply_needs_revalidation_and_a_fresh_safety_check() {
    let d = tmpdir("reboot");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let i = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let q = order(
        "q1",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
    assert_eq!(e.submit(&q, &mut idle(), 1_000).status, Status::Verified);
    drop(e);
    // Reboot: the kernel ruleset is empty; nothing is installed at start.
    nft.0.lock().unwrap().table = None;
    let mut e = engine(&d, &nft, "b2", 2_000);
    assert_eq!(e.status("i1").status, Status::Held);
    assert_eq!(e.status("q1").status, Status::Held);
    assert!(nft.0.lock().unwrap().table.is_none());
    assert!(kinds(&e).contains(&EventKind::Held));
    // No safety state, an engaged one, an unknown one: still held.
    let cur = |state| Ok(Current { state, age_ms: 5 });
    e.rearm_held(Err("agentd has none".into()), 2_100);
    e.rearm_held(cur(SafetyState::EStopActive), 2_200);
    e.rearm_held(cur(SafetyState::Unknown), 2_300);
    assert_eq!(e.status("i1").status, Status::Held);
    assert!(nft.0.lock().unwrap().table.is_none());
    // A fresh, known state: re-armed, installed, verified.
    e.rearm_held(cur(SafetyState::MovingSlow), 2_400);
    assert_eq!(e.status("i1").status, Status::Verified);
    assert_eq!(e.status("q1").status, Status::Verified);
    let listed = crate::nft::read_table(&mut nft.clone()).unwrap();
    assert!(crate::nft::verify(listed.as_deref(), &e.rendered()).is_ok());
    drop(e);
    // Another reboot, and the configuration changed meanwhile: the
    // participant's locator is now on the protected robot bus.
    nft.0.lock().unwrap().table = None;
    let mut v: Value = serde_json::from_str(&config_json(d.to_str().unwrap())).unwrap();
    v["network"]["motion_control_path"][0]["cidr"] = json!("10.0.0.0/24");
    let c2 = ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap();
    let mut e = Engine::open(
        c2,
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        "b3",
        3_000,
    )
    .unwrap();
    assert_eq!(e.status("q1").status, Status::Reverted);
    assert!(e.status("q1").note.unwrap().contains("motion_path"));
    assert_eq!(e.status("i1").status, Status::Held);
    // A held action expires at its deadline like any other.
    e.tick(61_001);
    assert_eq!(e.status("i1").status, Status::Reverted);
    assert!(nft.0.lock().unwrap().table.is_none());
}

/// M3: the operator's emergency disable is honoured by every path (the
/// periodic check, a revert, a new order, a restart) and lifted only by an
/// explicit re-arm.
#[test]
fn m3_operator_removal_is_honoured_until_rearm() {
    let d = tmpdir("operator");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let i = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let q = order(
        "q1",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
    assert_eq!(e.submit(&q, &mut idle(), 1_000).status, Status::Verified);
    // Removed, then a revert of one of them before the periodic check: the
    // other is not re-installed.
    nft.0.lock().unwrap().table = None;
    assert_eq!(
        e.revert("q1", "test", 1_100).status,
        Status::RemovedExternally
    );
    assert!(nft.0.lock().unwrap().table.is_none());
    assert_eq!(e.status("i1").status, Status::RemovedExternally);
    assert!(e.state().operator_disabled);
    // Every order is refused until re-armed, also after a restart.
    let i2 = order(
        "i2",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        e.submit(&i2, &mut idle(), 1_200).refusal.unwrap().code,
        codes::OPERATOR_DISABLED
    );
    drop(e);
    let mut e = engine(&d, &nft, "b1", 1_300);
    let i3 = order(
        "i3",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        e.submit(&i3, &mut idle(), 1_400).refusal.unwrap().code,
        codes::OPERATOR_DISABLED
    );
    assert!(nft.0.lock().unwrap().table.is_none());
    assert!(e.rearm("test", 1_500).unwrap());
    let i4 = order(
        "i4",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i4, &mut idle(), 1_600).status, Status::Verified);
    // Removed while down (same boot): disabled again at the restart.
    drop(e);
    nft.0.lock().unwrap().table = None;
    let e = engine(&d, &nft, "b1", 1_700);
    assert_eq!(e.status("i4").status, Status::RemovedExternally);
    assert!(e.state().operator_disabled);
    assert!(nft.0.lock().unwrap().table.is_none());
    // The periodic check sets it too.
    let mut e = e;
    e.rearm("test", 1_800).unwrap();
    let i5 = order(
        "i5",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i5, &mut idle(), 1_900).status, Status::Verified);
    nft.0.lock().unwrap().table = None;
    e.periodic_verify(2_000);
    assert_eq!(e.status("i5").status, Status::RemovedExternally);
    assert!(e.state().operator_disabled);
    e.tick(60_000);
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
    // A High notice: an event marked HIGH and a status flag that persists
    // until the operator acknowledges it.
    let ev = e
        .state()
        .events
        .iter()
        .find(|x| x.kind == EventKind::JournalReset)
        .unwrap();
    assert!(ev.detail.starts_with("HIGH:"));
    assert_eq!(e.state().journal_reset_ms, Some(2_000));
    drop(e);
    let mut e = engine(&d, &nft, "b1", 3_000);
    assert_eq!(e.state().journal_reset_ms, Some(2_000));
    e.rearm("acknowledged", 4_000).unwrap();
    assert_eq!(e.state().journal_reset_ms, None);
}

/// L7: the policy (and configuration) are re-read before every order.
#[test]
fn l7_policy_is_reread_per_order() {
    let d = tmpdir("reload");
    let pol_path = d.join("policy.json");
    let cfg_path = d.join("executor.json");
    let mut v: Value = serde_json::from_str(&config_json(d.to_str().unwrap())).unwrap();
    v["policy_path"] = json!(pol_path);
    std::fs::write(&cfg_path, v.to_string()).unwrap();
    let write_policy = |validated: bool| {
        let p = policy(Morphology::WheeledMobile, validated, &[]);
        std::fs::write(&pol_path, serde_json::to_string(&p).unwrap()).unwrap();
    };
    write_policy(true);
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000).with_reload(cfg_path.clone());
    // The OEM withdraws the validation: the next order is judged by it.
    write_policy(false);
    let i = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        e.submit(&i, &mut idle(), 1_100).refusal.unwrap().code,
        codes::OBSERVE_MODE
    );
    write_policy(true);
    let i2 = order(
        "i2",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i2, &mut idle(), 1_200).status, Status::Verified);
    // An unreadable policy refuses (never falls back to an old one).
    e.revert("i2", "test", 1_300);
    std::fs::write(&pol_path, b"{broken").unwrap();
    let i3 = order(
        "i3",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        e.submit(&i3, &mut idle(), 1_400).refusal.unwrap().code,
        codes::CONFIG_UNAVAILABLE
    );
}

/// M5 (model): a revert whose journal write fails is reported `reverting`
/// (never `reverted`) until the journal records it.
#[test]
fn m5_unjournalled_revert_is_not_reported_reverted() {
    let d = tmpdir("m5");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let i = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
    fault::arm(Point::JournalWrite);
    let out = e.revert("i1", "test", 2_000);
    assert_eq!(out.status, Status::Reverting, "{out:?}");
    assert!(
        nft.0.lock().unwrap().table.is_none(),
        "the rules are lifted"
    );
    e.tick(3_000);
    assert_eq!(e.status("i1").status, Status::Reverting);
    fault::disarm();
    e.tick(4_000);
    assert_eq!(e.status("i1").status, Status::Reverted);
    assert!(kinds(&e).contains(&EventKind::JournalError));
    drop(e);
    let e = engine(&d, &nft, "b1", 5_000);
    assert_eq!(e.status("i1").status, Status::Reverted);
    assert!(nft.0.lock().unwrap().table.is_none());
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

/// M2: a client that sends a request one byte at a time (never a full
/// line) neither blocks TTL enforcement nor other clients.
#[test]
fn m2_slow_client_never_delays_ttl_enforcement() {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    let d = tmpdir("slowloris");
    let sock = d.join("executor.sock");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", crate::engine::Now::system());
    let mut i = order(
        "i-ttl3",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    i.ttl_s = Some(3);
    let i = sign_at(i, crate::proto::wall_ms() / 1000);
    let start = std::time::Instant::now();
    assert_eq!(
        e.submit(&i, &mut idle(), crate::engine::Now::system())
            .status,
        Status::Verified
    );
    let listener = crate::server::bind(&sock, 0o600).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    let server = std::thread::spawn(move || {
        let key = crate::proto::Key::from_bytes([3u8; 32]);
        crate::server::serve(
            &listener,
            &mut e,
            &key,
            "b1",
            &|| st.load(Ordering::SeqCst),
            &mut |_, _| {},
        );
    });
    // Slow clients: one byte every 900 ms, never a newline.
    let mut lorises = Vec::new();
    for _ in 0..3 {
        let p = sock.clone();
        let st = stop.clone();
        lorises.push(std::thread::spawn(move || {
            let Ok(mut s) = std::os::unix::net::UnixStream::connect(&p) else {
                return;
            };
            while !st.load(Ordering::SeqCst) {
                if s.write_all(b"{").is_err() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(900));
            }
        }));
    }
    // A well-behaved client is still served meanwhile.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let client = crate::client::Client::new(
        sock.clone(),
        crate::proto::Key::from_bytes([3u8; 32]),
        std::time::Duration::from_secs(10),
    );
    let t = std::time::Instant::now();
    assert!(client.ping().is_ok());
    assert!(
        t.elapsed() < std::time::Duration::from_secs(2),
        "ping waited {:?} behind slow clients",
        t.elapsed()
    );
    // The 3 s TTL expires on time (tick every 500 ms).
    while nft.0.lock().unwrap().table.is_some() {
        assert!(
            start.elapsed() < std::time::Duration::from_millis(4_500),
            "TTL not enforced after {:?} with slow clients connected",
            start.elapsed()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(start.elapsed() >= std::time::Duration::from_secs(3));
    stop.store(true, Ordering::SeqCst);
    for l in lorises {
        l.join().unwrap();
    }
    server.join().unwrap();
}

// --- Trust boundary M1: the executor verifies the SOC's approval itself ------

fn refusal_code(o: &crate::engine::Outcome) -> String {
    o.refusal
        .as_ref()
        .map(|r| r.code.clone())
        .unwrap_or_default()
}

fn wheeled(id: &str, a: ActionId) -> Order {
    unsigned(id, a, Morphology::WheeledMobile, SafetyState::Idle)
}

/// A SOC request with an explicit body and signer (forgeries, tampering).
fn soc_with(
    o: &Order,
    seed: &[u8; 32],
    robot: &str,
    target_robot: &str,
    ts: u64,
    nonce: &str,
    body: &str,
) -> Order {
    let mut o = o.clone();
    o.soc = Some(Box::new(crate::soc::SocRequest::sign(
        seed,
        robot,
        SOC_KEY_ID,
        "POST",
        &format!("/api/v2/robots/{target_robot}/action-requests"),
        ts,
        nonce,
        body,
    )));
    o
}

#[test]
fn m1_forged_orders_from_agentd_are_refused() {
    let d = tmpdir("m1forged");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let base = wheeled("f1", ActionId::IsolateNetwork);
    let body = crate::soc::testing::body_for(&base);
    let n = |i: u32| format!("forged-nonce-{i:08}");
    let cases: Vec<(Order, &str)> = vec![
        // No SOC request at all, approval asserted by agentd.
        (base.clone(), codes::SOC_SIGNATURE_INVALID),
        // Signed by a key the executor does not hold.
        (
            soc_with(&base, &[9; 32], "ugv-007", "ugv-007", 1, &n(1), &body),
            codes::SOC_SIGNATURE_INVALID,
        ),
        // Signed for another robot (robot id in the signing message).
        (
            soc_with(&base, &SOC_SEED, "ugv-008", "ugv-007", 1, &n(2), &body),
            codes::SOC_SIGNATURE_INVALID,
        ),
        // Body changed after signing.
        (
            {
                let mut o = soc_with(&base, &SOC_SEED, "ugv-007", "ugv-007", 1, &n(3), &body);
                o.soc.as_mut().unwrap().body = body.replace("\"test\"", "\"tset\"");
                o
            },
            codes::SOC_SIGNATURE_INVALID,
        ),
        // Truncated signature.
        (
            {
                let mut o = soc_with(&base, &SOC_SEED, "ugv-007", "ugv-007", 1, &n(4), &body);
                o.soc.as_mut().unwrap().signature.truncate(100);
                o
            },
            codes::SOC_SIGNATURE_INVALID,
        ),
        // Outside the timestamp window (now = 1 s, signed at 40 s / 0 s
        // works, 40 does not).
        (
            soc_with(&base, &SOC_SEED, "ugv-007", "ugv-007", 40, &n(5), &body),
            codes::SOC_REQUEST_STALE,
        ),
        // A valid request to another path (a GET of the robot).
        (
            {
                let mut o = base.clone();
                o.soc = Some(Box::new(crate::soc::SocRequest::sign(
                    &SOC_SEED,
                    "ugv-007",
                    SOC_KEY_ID,
                    "GET",
                    "/api/v2/robots/ugv-007",
                    1,
                    &n(6),
                    "",
                )));
                o
            },
            codes::ORDER_MISMATCH,
        ),
        // Signed for another robot's path (but ours in the message).
        (
            soc_with(&base, &SOC_SEED, "ugv-007", "ugv-008", 1, &n(7), &body),
            codes::ORDER_MISMATCH,
        ),
        // The SOC approved quarantine of one participant; agentd orders an
        // isolation with that approval.
        (
            {
                let q = wheeled("f1", ActionId::QuarantineNode);
                let qb = crate::soc::testing::body_for(&q);
                soc_with(&base, &SOC_SEED, "ugv-007", "ugv-007", 1, &n(8), &qb)
            },
            codes::ORDER_MISMATCH,
        ),
        // A longer TTL than approved.
        (
            {
                let mut o = soc_with(&base, &SOC_SEED, "ugv-007", "ugv-007", 1, &n(9), &body);
                o.ttl_s = Some(3600);
                o
            },
            codes::ORDER_MISMATCH,
        ),
        // Approval evidence missing (authority, source).
        (
            soc_with(
                &base,
                &SOC_SEED,
                "ugv-007",
                "ugv-007",
                1,
                &n(10),
                &body.replace("\"request\"", "\"override\""),
            ),
            codes::APPROVAL_MISSING,
        ),
        (
            soc_with(
                &base,
                &SOC_SEED,
                "ugv-007",
                "ugv-007",
                1,
                &n(11),
                &body.replace("\"soc-test\"", "\"\""),
            ),
            codes::APPROVAL_MISSING,
        ),
        // Unknown field in the signed body.
        (
            soc_with(
                &base,
                &SOC_SEED,
                "ugv-007",
                "ugv-007",
                1,
                &n(12),
                &body.replace("{\"action\"", "{\"override\":1,\"action\""),
            ),
            codes::ORDER_MISMATCH,
        ),
    ];
    for (i, (o, want)) in cases.into_iter().enumerate() {
        // A refused id is final: every case on a fresh executor.
        let mut e = engine(&tmpdir(&format!("m1forged{i}")), &nft, "b1", 1_000);
        let out = e.submit(&o, &mut idle(), 1_000);
        assert_eq!(out.status, Status::Refused, "case {i}: {out:?}");
        assert_eq!(refusal_code(&out), want, "case {i}: {out:?}");
        assert!(nft.0.lock().unwrap().table.is_none(), "case {i} installed");
    }
    // The genuine request is applied.
    let ok = signed(base);
    assert_eq!(e.submit(&ok, &mut idle(), 1_000).status, Status::Verified);
}

#[test]
fn m1_planner_orders_cannot_claim_an_approval() {
    let d = tmpdir("m1planner");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let mut p = wheeled("plan:1", ActionId::IsolateNetwork);
    p.origin = Origin::Planner {
        rule: "r".into(),
        finding_id: None,
    };
    // Claims a human approval: refused.
    let out = e.submit(&p, &mut idle(), 1_000);
    assert_eq!(refusal_code(&out), codes::APPROVAL_MISSING, "{out:?}");
    // Unchanged planner path: unapproved on a wheeled robot is executed.
    p.id = "plan:2".into();
    p.human_approved = false;
    assert_eq!(e.submit(&p, &mut idle(), 1_000).status, Status::Verified);
    // And never on a robot that balances: no quarantine without a human on
    // any balancing morphology, nothing at all on a humanoid / unspecified
    // (also when the OEM listed the target class as fall-safe).
    let all = [RestrictTarget::Network, RestrictTarget::Participant];
    for m in [
        Morphology::Humanoid,
        Morphology::Quadruped,
        Morphology::Unspecified,
    ] {
        for a in [ActionId::IsolateNetwork, ActionId::QuarantineNode] {
            let mut o = unsigned("plan:x", a, m, SafetyState::Idle);
            o.human_approved = false;
            o.origin = Origin::Planner {
                rule: "r".into(),
                finding_id: None,
            };
            let r = precheck(&o, &policy(m, true, &all), &cfg("/tmp/x"));
            let refused = r.is_err();
            let want = m != Morphology::Quadruped || a == ActionId::QuarantineNode;
            assert_eq!(refused, want, "{m:?} {a:?}: {r:?}");
            if refused {
                assert_eq!(r.unwrap_err().code, codes::NEEDS_APPROVAL, "{m:?} {a:?}");
            }
        }
    }
}

#[test]
fn m1_matching_signed_order_is_applied_and_replay_refused_across_restarts() {
    let d = tmpdir("m1replay");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let o = order(
        "r-ok",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&o, &mut idle(), 1_000).status, Status::Verified);
    assert_eq!(e.revert("r-ok", "test", 1_100).status, Status::Reverted);
    // The same request under another order id: the nonce was used.
    let mut again = o.clone();
    again.id = "r-other".into();
    assert_eq!(
        refusal_code(&e.submit(&again, &mut idle(), 1_200)),
        codes::SOC_NONCE_REPLAYED
    );
    drop(e);
    // Restart after the executor's history was lost (journal removed): the
    // replay store still knows the request.
    std::fs::remove_file(d.join(crate::journal::FILE)).unwrap();
    let mut e = engine(&d, &nft, "b1", 2_000);
    let out = e.submit(&o, &mut idle(), 2_000);
    assert_eq!(refusal_code(&out), codes::SOC_NONCE_REPLAYED, "{out:?}");
    assert!(nft.0.lock().unwrap().table.is_none());
    drop(e);
    // The replay store removed while the journal exists: fenced up to the
    // start + the skew window (F8), an old request is refused, a request
    // signed after the fence is accepted.
    std::fs::remove_file(d.join(crate::soc::NONCE_FILE)).unwrap();
    let mut e = engine(&d, &nft, "b1", 3_000);
    let mut o2 = o.clone();
    o2.id = "r-two".into();
    let o2 = sign_at(o2, 3);
    assert_eq!(
        refusal_code(&e.submit(&o2, &mut idle(), 3_000)),
        codes::SOC_REQUEST_STALE
    );
    let mut o3 = o.clone();
    o3.id = "r-three".into();
    let o3 = sign_at(o3, 33);
    assert_eq!(
        refusal_code(&e.submit(&o3, &mut idle(), 33_000)),
        codes::SOC_REQUEST_STALE,
        "inside the skew window of the start"
    );
    let mut o3 = o.clone();
    o3.id = "r-three-b".into();
    let o3 = sign_at(o3, 34);
    assert_eq!(e.submit(&o3, &mut idle(), 34_000).status, Status::Verified);
    drop(e);
    // A corrupt store fences too.
    std::fs::write(d.join(crate::soc::NONCE_FILE), b"{not json").unwrap();
    let mut e = engine(&d, &nft, "b1", 5_000);
    let mut o4 = o.clone();
    o4.id = "r-four".into();
    let o4 = sign_at(o4, 5);
    assert_eq!(
        refusal_code(&e.submit(&o4, &mut idle(), 5_000)),
        codes::SOC_REQUEST_STALE
    );
}

#[test]
fn m1_soc_keys_are_the_executors_own() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("m1keys");
    let nft = FakeNft::default();
    // No key configured: nothing approved.
    let mut v: Value = serde_json::from_str(&config_json(d.to_str().unwrap())).unwrap();
    v["soc"] = json!({"keys": []});
    let c = ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap();
    let mut e = Engine::open(
        c,
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        "b1",
        1_000,
    )
    .unwrap();
    let o = order(
        "k1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        refusal_code(&e.submit(&o, &mut idle(), 1_000)),
        codes::SOC_SIGNATURE_INVALID
    );
    drop(e);
    // A group-writable key file is not trusted (soc_keys_unavailable).
    let kp = d.join("soc-gw.pub");
    std::fs::write(
        &kp,
        crate::soc::testing::public_key_json(&SOC_SEED, SOC_KEY_ID),
    )
    .unwrap();
    std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o664)).unwrap();
    v["soc"] = json!({"keys": [kp]});
    let c = ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap();
    let d2 = tmpdir("m1keys2");
    let mut c = c;
    c.config.state_dir = d2.clone();
    let mut e = Engine::open(
        c,
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        "b1",
        1_000,
    )
    .unwrap();
    let o = signed(wheeled("k2", ActionId::IsolateNetwork));
    assert_eq!(
        refusal_code(&e.submit(&o, &mut idle(), 1_000)),
        codes::SOC_KEYS_UNAVAILABLE
    );
    // A secret key file is refused too.
    let sk = robodr_blackbox::KeyFile::ed25519_from_seed(&SOC_SEED, Some(SOC_KEY_ID))
        .unwrap()
        .to_json();
    std::fs::write(&kp, sk).unwrap();
    std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600)).unwrap();
    let o = signed(wheeled("k3", ActionId::IsolateNetwork));
    assert_eq!(
        refusal_code(&e.submit(&o, &mut idle(), 1_000)),
        codes::SOC_KEYS_UNAVAILABLE
    );
}

// --- Review of the executor M1 (`fcd58b2`): F3, F4, F8, F9, design option ---

/// An order on its own executor; the engine served over a real unix socket
/// (agentd's path), with the system clock.
fn served(
    tag: &str,
    edit: impl FnOnce(&mut Value),
) -> (
    std::path::PathBuf,
    FakeNft,
    crate::client::Client,
    Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    use crate::proto::Key;
    let d = tmpdir(tag);
    let nft = FakeNft::default();
    let sock = d.join("executor.sock");
    let mut v: Value = serde_json::from_str(&config_json(d.to_str().unwrap())).unwrap();
    v["socket"] = json!(sock);
    edit(&mut v);
    let c = ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap();
    let mut engine = Engine::open(
        c,
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        "b1",
        crate::proto::wall_ms(),
    )
    .unwrap();
    let listener = crate::server::bind(&sock, 0o600).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let st = stop.clone();
    let server = std::thread::spawn(move || {
        let key = Key::from_bytes([0x5a; 32]);
        crate::server::serve(
            &listener,
            &mut engine,
            &key,
            "b1",
            &|| st.load(std::sync::atomic::Ordering::SeqCst),
            &mut |_, _| {},
        );
    });
    let client = crate::client::Client::new(
        sock,
        Key::from_bytes([0x5a; 32]),
        std::time::Duration::from_secs(5),
    );
    (d, nft, client, stop, server)
}

fn now_s() -> u64 {
    crate::proto::wall_ms() / 1000
}

/// F3: a revert of a SOC-approved action needed no SOC signature: agentd
/// (or anyone holding the protocol key) could lift a containment the SOC
/// ordered. Over the real socket: an unsigned revert of a control-plane
/// action is refused and the rules stay; TTL expiry and planner actions
/// keep reverting without one.
#[test]
fn f3_control_plane_revert_needs_the_socs_signature() {
    let (_d, nft, client, stop, server) = served("f3", |_| {});
    let o = sign_at(
        unsigned(
            "r-f3",
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        ),
        now_s(),
    );
    let out = client
        .submit(&o, &mut || Ok((SafetyState::Idle, 3)))
        .unwrap();
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let out = client.revert("r-f3", "agentd says so").unwrap();
    assert_eq!(
        out.status,
        Status::Verified,
        "unsigned revert lifted it: {out:?}"
    );
    assert_eq!(refusal_code(&out), codes::SOC_SIGNATURE_INVALID, "{out:?}");
    assert!(nft.0.lock().unwrap().table.is_some());
    // Signed, but for another action / as a submit / by another key / with
    // a non-strict body: refused, still in force.
    let rv = |_: &str, seed: &[u8; 32], target: String, body: &str, nonce: &str| {
        crate::soc::SocRequest::sign(
            seed,
            "ugv-007",
            SOC_KEY_ID,
            "POST",
            &target,
            now_s(),
            nonce,
            body,
        )
    };
    let path = |id: &str| format!("/api/v2/robots/ugv-007/action-requests/{id}/revert");
    let body = r#"{"reason":"contained","requested_by":"analyst"}"#;
    for (k, (soc, want)) in [
        (
            rv(
                "x",
                &SOC_SEED,
                path("r-other"),
                body,
                "f3-revert-nonce-0001",
            ),
            codes::ORDER_MISMATCH,
        ),
        (
            rv(
                "x",
                &SOC_SEED,
                "/api/v2/robots/ugv-007/action-requests".into(),
                body,
                "f3-revert-nonce-0002",
            ),
            codes::ORDER_MISMATCH,
        ),
        (
            rv("x", &[9; 32], path("r-f3"), body, "f3-revert-nonce-0003"),
            codes::SOC_SIGNATURE_INVALID,
        ),
        (
            rv(
                "x",
                &SOC_SEED,
                path("r-f3"),
                r#"{"requested_by":"analyst","force":true}"#,
                "f3-revert-nonce-0004",
            ),
            codes::ORDER_MISMATCH,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let out = client.revert_signed("r-f3", "x", Some(&soc)).unwrap();
        assert_eq!(out.status, Status::Verified, "case {k}: {out:?}");
        assert_eq!(refusal_code(&out), want, "case {k}: {out:?}");
    }
    assert!(nft.0.lock().unwrap().table.is_some());
    // The SOC's signed revert of this action lifts it.
    let good = rv("x", &SOC_SEED, path("r-f3"), body, "f3-revert-nonce-0005");
    let out = client.revert_signed("r-f3", "x", Some(&good)).unwrap();
    assert_eq!(out.status, Status::Reverted, "{out:?}");
    assert!(nft.0.lock().unwrap().table.is_none());
    // Replayed against another approved action: the nonce was used.
    let o2 = sign_at(
        unsigned(
            "r-f3b",
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        ),
        now_s(),
    );
    assert_eq!(
        client
            .submit(&o2, &mut || Ok((SafetyState::Idle, 3)))
            .unwrap()
            .status,
        Status::Verified
    );
    let out = client.revert_signed("r-f3b", "x", Some(&good)).unwrap();
    assert_eq!(out.status, Status::Verified);
    assert_eq!(refusal_code(&out), codes::ORDER_MISMATCH, "{out:?}");
    // A planner action reverts without a signature.
    let mut p = unsigned(
        "plan:f3",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    p.human_approved = false;
    p.origin = Origin::Planner {
        rule: "r".into(),
        finding_id: None,
    };
    let out = client
        .submit(&p, &mut || Ok((SafetyState::Idle, 3)))
        .unwrap();
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(
        client.revert("plan:f3", "planner").unwrap().status,
        Status::Reverted
    );
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    server.join().unwrap();
}

/// F4: the participant's locators come from SPDP (unauthenticated); a
/// forged locator could make a quarantine drop an arbitrary UDP endpoint
/// (a DNS server, the SOC's syslog). Locators must lie in a configured
/// quarantinable CIDR and in the robot's DDS port ranges, one address
/// family.
#[test]
fn f4_quarantine_locators_are_scoped() {
    let p = policy(Morphology::WheeledMobile, true, &[]);
    let with = |q: Option<Value>| -> Resolved {
        let mut v: Value = serde_json::from_str(&config_json("/tmp/f4")).unwrap();
        match q {
            Some(q) => v["network"]["quarantine"] = q,
            None => {
                v["network"].as_object_mut().unwrap().remove("quarantine");
            }
        }
        ExecutorConfig::parse(&v.to_string())
            .and_then(ExecutorConfig::validate)
            .expect("network.quarantine is a config key")
    };
    let q = |locs: &[(&str, u16)]| {
        let mut o = unsigned(
            "q-f4",
            ActionId::QuarantineNode,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        );
        o.target = Target::Participant {
            guid_prefix: GUID.parse().unwrap(),
            locators: locs
                .iter()
                .map(|(ip, port)| Locator {
                    ip: ip.parse().unwrap(),
                    port: *port,
                })
                .collect(),
        };
        o
    };
    let scoped = with(Some(json!({"cidrs": ["10.0.0.0/24"]})));
    // In scope: a DDS port of domain 0 in the quarantinable network.
    assert!(precheck(&q(&[("10.0.0.7", 7410)]), &p, &scoped).is_ok());
    for (what, locs) in [
        ("not a DDS port", vec![("10.0.0.7", 53)]),
        (
            "outside the quarantinable CIDRs",
            vec![("10.20.0.10", 7410)],
        ),
        (
            "mixed families",
            vec![("10.0.0.7", 7410), ("fd00::7", 7410)],
        ),
    ] {
        let r = precheck(&q(&locs), &p, &scoped);
        assert_eq!(
            r.as_ref().map_err(|e| e.code.as_str()).err(),
            Some("locator_out_of_scope"),
            "{what}: {r:?}"
        );
    }
    // No quarantinable network configured: no quarantine at all.
    let r = precheck(&q(&[("10.0.0.7", 7410)]), &p, &with(None));
    assert_eq!(
        r.as_ref().map_err(|e| e.code.as_str()).err(),
        Some("locator_out_of_scope"),
        "{r:?}"
    );
}

/// F8: the replay store's fence was the start time; a request signed up to
/// `max_clock_skew_s` in the future (inside the window) before the store
/// was lost could be replayed after the restart.
#[test]
fn f8_fence_covers_the_skew_window() {
    let d = tmpdir("f8");
    std::fs::write(d.join(crate::journal::FILE), b"{}").unwrap();
    let mut s = crate::soc::ReplayStore::open(&d, 100, 30, true);
    // Signed at 120 (20 s ahead of the clock at start, inside the 30 s
    // window): it may have been presented before the store was lost.
    let r = s.check("k", "nonce-nonce-nonce-01", 120, 101, 30);
    assert_eq!(
        r.map_err(|e| e.code),
        Err(codes::SOC_REQUEST_STALE.to_string())
    );
    // Signed after start + skew: accepted.
    assert!(s.check("k", "nonce-nonce-nonce-02", 131, 131, 30).is_ok());
}

/// F9 (a): a SOC key equal to one of the robot's own keys (its black-box /
/// finding signing key) is refused: whoever holds the robot's key could
/// otherwise approve containment.
#[test]
fn f9a_soc_key_equal_to_a_robot_key_is_refused() {
    let d = tmpdir("f9a");
    let nft = FakeNft::default();
    let mut v: Value = serde_json::from_str(&config_json(d.to_str().unwrap())).unwrap();
    v["soc"]["robot_keys"] = json!([soc_key_path()]);
    let c = ExecutorConfig::parse(&v.to_string())
        .and_then(ExecutorConfig::validate)
        .expect("soc.robot_keys is a config key");
    let mut e = Engine::open(
        c,
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        "b1",
        1_000,
    )
    .unwrap();
    let o = order(
        "f9a",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut idle(), 1_000);
    assert_eq!(refusal_code(&out), "soc_keys_unavailable", "{out:?}");
    assert!(nft.0.lock().unwrap().table.is_none());
}

/// F9 (b): an action held after a reboot is re-armed only while the SOC key
/// that approved it is still configured.
#[test]
fn f9b_rearm_rechecks_the_approving_key() {
    let d = tmpdir("f9b");
    let nft = FakeNft::default();
    let mut e = engine(&d, &nft, "b1", 1_000);
    let i = order(
        "i-f9b",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
    drop(e);
    nft.0.lock().unwrap().table = None;
    let mut v: Value = serde_json::from_str(&config_json(d.to_str().unwrap())).unwrap();
    v["soc"] = json!({"keys": []});
    let c = ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap();
    let mut e = Engine::open(
        c,
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        "b2",
        2_000,
    )
    .unwrap();
    e.rearm_held(
        Ok(Current {
            state: SafetyState::Idle,
            age_ms: 5,
        }),
        2_100,
    );
    let st = e.status("i-f9b");
    assert_eq!(
        st.status,
        Status::Reverted,
        "re-armed without its key: {st:?}"
    );
    assert!(
        st.note
            .as_deref()
            .unwrap_or("")
            .contains("approval_key_removed"),
        "{st:?}"
    );
    assert!(nft.0.lock().unwrap().table.is_none());
}

/// F9 (c): one unreadable SOC key file refuses every control-plane order
/// (integrity first), with its own refusal code.
#[test]
fn f9c_bad_key_file_has_its_own_code() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("f9c");
    let nft = FakeNft::default();
    let bad = d.join("bad.pub");
    std::fs::write(&bad, b"{not a key").unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut v: Value = serde_json::from_str(&config_json(d.to_str().unwrap())).unwrap();
    v["soc"]["keys"] = json!([soc_key_path(), bad]);
    let c = ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap();
    let mut e = Engine::open(
        c,
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        "b1",
        1_000,
    )
    .unwrap();
    let o = order(
        "f9c",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(
        refusal_code(&e.submit(&o, &mut idle(), 1_000)),
        "soc_keys_unavailable"
    );
}

/// Design option: a site may require a human's approval for every
/// containment, on every morphology (planner orders refused).
#[test]
fn require_approval_for_all_containment_refuses_planner_orders() {
    let p = policy(Morphology::WheeledMobile, true, &[]);
    let mut v: Value = serde_json::from_str(&config_json("/tmp/x")).unwrap();
    v["require_approval_for_all_containment"] = json!(true);
    let strict = ExecutorConfig::parse(&v.to_string())
        .and_then(ExecutorConfig::validate)
        .expect("require_approval_for_all_containment is a config key");
    let mut o = unsigned(
        "plan:all",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    o.human_approved = false;
    o.origin = Origin::Planner {
        rule: "r".into(),
        finding_id: None,
    };
    assert!(
        precheck(&o, &p, &cfg("/tmp/x")).is_ok(),
        "default: unchanged"
    );
    assert_eq!(
        precheck(&o, &p, &strict).map_err(|e| e.code).err(),
        Some(codes::NEEDS_APPROVAL.to_string())
    );
    o.human_approved = true;
    assert!(precheck(&o, &p, &strict).is_ok());
}
