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
use crate::engine::{Engine, FixedSafety, Outcome, Status};
use crate::fault::{self, Point};
use crate::journal::{EventKind, Journal, Loaded};
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
                guid_only: false,
                excluded: Vec::new(),
                addresses: Vec::new(),
                excluded_addresses: Vec::new(),
                evidence_truncated: false,
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
                guid_only: false,
                excluded: Vec::new(),
                addresses: Vec::new(),
                excluded_addresses: Vec::new(),
                evidence_truncated: false,
            },
            Tgt::InsideBus => Target::Participant {
                guid_prefix: GUID.parse().unwrap(),
                locators: vec![loc("192.168.123.50")],
                guid_only: false,
                excluded: Vec::new(),
                addresses: Vec::new(),
                excluded_addresses: Vec::new(),
                evidence_truncated: false,
            },
            Tgt::ProtectedGuid => Target::Participant {
                guid_prefix: LOWCMD_GUID.parse().unwrap(),
                locators: vec![loc("10.0.0.7")],
                guid_only: false,
                excluded: Vec::new(),
                addresses: Vec::new(),
                excluded_addresses: Vec::new(),
                evidence_truncated: false,
            },
            Tgt::NoLocators => Target::Participant {
                guid_prefix: GUID.parse().unwrap(),
                locators: vec![],
                guid_only: false,
                excluded: Vec::new(),
                addresses: Vec::new(),
                excluded_addresses: Vec::new(),
                evidence_truncated: false,
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
                Effect::Motion(_) => "motion",
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
        guid_only: false,
        excluded: Vec::new(),
        addresses: Vec::new(),
        excluded_addresses: Vec::new(),
        evidence_truncated: false,
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
        guid_only: false,
        excluded: Vec::new(),
        addresses: Vec::new(),
        excluded_addresses: Vec::new(),
        evidence_truncated: false,
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
        guid_only: false,
        excluded: Vec::new(),
        addresses: Vec::new(),
        excluded_addresses: Vec::new(),
        evidence_truncated: false,
    };
    match precheck(&o, &wheeled, &c).unwrap().effect {
        Effect::Quarantine(q) => assert_eq!(q.protected.len(), 2),
        e => panic!("{e:?}"),
    }
    // Without locators: refused.
    o.target = Target::Participant {
        guid_prefix: GUID.parse().unwrap(),
        locators: vec![],
        guid_only: false,
        excluded: Vec::new(),
        addresses: Vec::new(),
        excluded_addresses: Vec::new(),
        evidence_truncated: false,
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
        guid_only: false,
        excluded: Vec::new(),
        addresses: Vec::new(),
        excluded_addresses: Vec::new(),
        evidence_truncated: false,
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
    // Review R2-3: the state of an applied quarantine says what it cuts.
    let q = e.status("q1").quarantine.expect("quarantine scope");
    assert!(!q.locators.is_empty(), "{q:?}");
    assert!(e.status("i1").quarantine.is_none());
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

fn seal_key(b: u8) -> std::sync::Arc<robodr_blackbox::StateSealKey> {
    crate::proto::Key::from_bytes([b; 32])
        .state_seal_key()
        .unwrap()
}

fn sealed_engine(
    dir: &std::path::Path,
    nft: &FakeNft,
    now: u64,
    key: &std::sync::Arc<robodr_blackbox::StateSealKey>,
) -> Engine {
    if !dir.join(crate::journal::FILE).exists() {
        // A first start, as the package prepares it (review finding 2).
        std::fs::write(dir.join(crate::journal::INIT_MARKER), "").unwrap();
    }
    sealed_engine_as_is(dir, nft, now, key)
}

/// [`sealed_engine`] without preparing anything.
fn sealed_engine_as_is(
    dir: &std::path::Path,
    nft: &FakeNft,
    now: u64,
    key: &std::sync::Arc<robodr_blackbox::StateSealKey>,
) -> Engine {
    Engine::open_sealed(
        cfg(dir.to_str().unwrap()),
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        "b1",
        now,
        key.clone(),
    )
    .unwrap()
}

fn reset_reason(e: &Engine) -> String {
    e.state()
        .events
        .iter()
        .find(|x| x.kind == EventKind::JournalReset)
        .map(|x| x.detail.clone())
        .unwrap_or_default()
}

/// Gap 1: the executor's journal is sealed under a key derived from the
/// link key. A tampered journal, one under another key (wrong key), an
/// older sealed copy put back (replayed: accepted, the seal cannot tell; see
/// the README) and an unsealed v1 file are each handled: never believed when
/// the seal fails, the table deleted, a High `journal_reset` event, and
/// every order refused (`journal_reset`) until `rearm`.
#[test]
fn gap1_a_sealed_journal_that_fails_its_seal_is_not_believed() {
    let key = seal_key(7);
    let nft = FakeNft::default();
    let iso = |id: &str| {
        order(
            id,
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        )
    };
    // Sealed on disk; reopened intact.
    let d = tmpdir("seal-ok");
    let mut e = sealed_engine(&d, &nft, 1_000, &key);
    assert_eq!(
        e.submit(&iso("i1"), &mut idle(), 1_000).status,
        Status::Verified
    );
    drop(e);
    let text = std::fs::read_to_string(d.join("journal.json")).unwrap();
    assert!(
        text.starts_with("robodr-executor-journal/v2 hmac-sha256:"),
        "{text}"
    );
    let soc = std::fs::read_to_string(d.join(crate::soc::NONCE_FILE)).unwrap();
    assert!(soc.starts_with(crate::soc::NONCE_SEALED_FORMAT), "{soc}");
    let e = sealed_engine(&d, &nft, 2_000, &key);
    assert_eq!(e.state().entries.len(), 1);
    assert!(e.state().journal_reset_ms.is_none());
    assert!(nft.0.lock().unwrap().table.is_some());
    drop(e);

    // Tampered: the active action edited out (the JSON is valid, the seal
    // is not).
    let tampered = text.replace("\"phase\": \"active\"", "\"phase\": \"reverting\"");
    assert_ne!(tampered, text);
    std::fs::write(d.join("journal.json"), &tampered).unwrap();
    let mut e = sealed_engine(&d, &nft, 3_000, &key);
    assert!(e.state().entries.is_empty());
    assert!(
        nft.0.lock().unwrap().table.is_none(),
        "fail towards doing nothing"
    );
    let why = reset_reason(&e);
    assert!(why.starts_with("HIGH:") && why.contains("edited"), "{why}");
    assert_eq!(e.state().journal_reset_ms, Some(3_000));
    // Orders are refused until the operator re-arms.
    let o = e.submit(&iso("i2"), &mut idle(), 3_100);
    assert_eq!(o.status, Status::Refused);
    assert_eq!(o.refusal.unwrap().code, codes::JOURNAL_RESET);
    e.rearm("checked", 3_200).unwrap();
    assert_eq!(
        e.submit(&iso("i3"), &mut idle(), 3_300).status,
        Status::Verified
    );
    drop(e);

    // Wrong key: the same file under another unit's key.
    let e = sealed_engine(&d, &nft, 4_000, &seal_key(8));
    let why = reset_reason(&e);
    assert!(why.contains("another key"), "{why}");
    assert!(e.state().journal_reset_ms.is_some());
    drop(e);

    // Truncated: cut in the middle of the JSON.
    let d = tmpdir("seal-trunc");
    let mut e = sealed_engine(&d, &nft, 1_000, &key);
    e.submit(&iso("t1"), &mut idle(), 1_000);
    drop(e);
    let full = std::fs::read(d.join("journal.json")).unwrap();
    std::fs::write(d.join("journal.json"), &full[..full.len() / 2]).unwrap();
    let e = sealed_engine(&d, &nft, 2_000, &key);
    assert!(reset_reason(&e).contains("seal"), "{}", reset_reason(&e));
    drop(e);

    // An unsealed v1 journal: not trusted until `seal-journal` upgraded it.
    let d = tmpdir("seal-v1");
    let mut e = engine(&d, &nft, "b1", 1_000);
    assert_eq!(
        e.submit(&iso("v1"), &mut idle(), 1_000).status,
        Status::Verified
    );
    drop(e);
    let v1 = std::fs::read(d.join("journal.json")).unwrap();
    let e = sealed_engine(&d, &nft, 2_000, &key);
    assert!(
        reset_reason(&e).contains("seal-journal"),
        "{}",
        reset_reason(&e)
    );
    drop(e);
    // Review finding 7: once the journal has been written sealed, putting
    // an unsealed file back is not an upgrade.
    std::fs::write(d.join("journal.json"), &v1).unwrap();
    let j = Journal::sealed(&d, key.clone());
    let err = j.seal_legacy().unwrap_err();
    assert!(err.contains("not an upgrade"), "{err}");
    // The documented one-time upgrade (before the sealed executor ever ran)
    // keeps the v1 state, but not as installed: held for re-validation.
    let d = tmpdir("seal-v1-upgrade");
    std::fs::write(d.join("journal.json"), &v1).unwrap();
    nft.0.lock().unwrap().table = None;
    let j = Journal::sealed(&d, key.clone());
    let m = j.seal_legacy().unwrap();
    assert!(m.contains("1 active action"), "{m}");
    assert!(j.seal_legacy().unwrap_err().contains("not an upgrade"));
    match j.load() {
        Loaded::State(s) => {
            assert_eq!(s.entries.len(), 1);
            assert!(s.boot_id.is_empty(), "adopted as of no boot");
        }
        other => panic!("{other:?}"),
    }
    let e = sealed_engine(&d, &nft, 2_000, &key);
    assert_eq!(e.status("v1").status, Status::Held, "re-validated, held");
    assert!(nft.0.lock().unwrap().table.is_none(), "not re-installed");
}

/// Review findings 1/2: the journal's epoch and head; an older sealed copy
/// put back (same boot) is not re-installed blindly, and agentd's anchor
/// resets it.
#[test]
fn review_an_older_sealed_copy_is_caught() {
    let key = seal_key(7);
    let nft = FakeNft::default();
    let iso = |id: &str| {
        order(
            id,
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        )
    };
    let d = tmpdir("rv-old-copy");
    let mut e = sealed_engine(&d, &nft, 1_000, &key);
    assert!(
        !d.join(crate::journal::INIT_MARKER).exists(),
        "the first-start marker is consumed"
    );
    assert!(d.join(crate::journal::SEALED_MARKER).exists());
    assert_eq!(
        e.submit(&iso("i1"), &mut idle(), 1_000).status,
        Status::Verified
    );
    let old = std::fs::read(d.join("journal.json")).unwrap();
    let anchored = e.state().head();
    assert_eq!(anchored.epoch.len(), 32);
    e.revert("i1", "done", 1_100);
    assert_eq!(e.status("i1").status, Status::Reverted);
    drop(e);
    // The table is gone now (i1 reverted); something else keeps it alive
    // so the copy is not taken for an emergency disable.
    let mut e = sealed_engine(&d, &nft, 1_150, &key);
    let q1 = order(
        "q1",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&q1, &mut idle(), 1_150).status, Status::Verified);
    // What agentd saw last (its anchor).
    let anchored_after = e.state().head();
    assert_eq!(anchored_after.epoch, anchored.epoch);
    assert!(anchored_after.next_seq > anchored.next_seq);
    drop(e);
    // The older copy (i1 active) put back, same boot.
    std::fs::write(d.join("journal.json"), &old).unwrap();
    let mut e = sealed_engine(&d, &nft, 1_200, &key);
    assert_eq!(
        e.status("i1").status,
        Status::Held,
        "an active entry missing from the live table is re-validated and held, not re-installed"
    );
    let table = format!("{:?}", nft.0.lock().unwrap().table);
    assert!(
        !table.contains(&crate::nft::tag("i1")),
        "i1 re-installed: {table}"
    );
    // agentd's anchor (the newest head it saw) unmasks the copy.
    assert!(e.check_anchor(&anchored_after, 1_300));
    assert!(e.state().journal_reset_ms.is_some());
    assert!(e.state().entries.is_empty());
    assert_eq!(
        e.state().prev_epoch.as_deref(),
        Some(anchored.epoch.as_str())
    );
    assert_ne!(e.state().epoch, anchored.epoch);
    assert!(reset_reason(&e).contains("behind agentd's anchored head"));
    let o = e.submit(&iso("i2"), &mut idle(), 1_400);
    assert_eq!(o.refusal.unwrap().code, codes::JOURNAL_RESET);
    // The old epoch is the new one's predecessor: no second reset.
    assert!(!e.check_anchor(&anchored_after, 1_500));
    // A foreign epoch with actions in force resets; a reset nobody saw
    // yet that holds nothing is adopted.
    let foreign = crate::journal::JournalHead {
        epoch: "ab".repeat(16),
        next_seq: 1,
    };
    assert!(!e.check_anchor(&foreign, 1_600), "empty reset: adopted");
    e.rearm("checked", 1_700).unwrap();
    // The reset fenced the SOC replay store: requests signed before it are
    // refused, a fresh one is executed.
    let stale = e.submit(&iso("i3"), &mut idle(), 1_800);
    assert_eq!(stale.refusal.unwrap().code, codes::SOC_REQUEST_STALE);
    let i4 = sign_at(
        unsigned(
            "i4",
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        ),
        40,
    );
    assert_eq!(e.submit(&i4, &mut idle(), 40_000).status, Status::Verified);
    let other = crate::journal::JournalHead {
        epoch: "cd".repeat(16),
        next_seq: 1,
    };
    assert!(e.check_anchor(&other, 40_100));
    assert_eq!(e.status("i4").status, Status::Reverted);
}

/// Review findings 1/2: the anchor never resets a journal that is merely
/// ahead of it (this run's answers, a restart, an executor without a
/// first-start journal yet).
#[test]
fn review_the_anchor_leaves_a_current_journal_alone() {
    let key = seal_key(7);
    let nft = FakeNft::default();
    let d = tmpdir("rv-anchor-ok");
    let mut e = sealed_engine(&d, &nft, 1_000, &key);
    let o = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let h0 = e.answer_head();
    assert!(!e.check_anchor(&h0, 1_000));
    assert_eq!(e.submit(&o, &mut idle(), 1_000).status, Status::Verified);
    let h1 = e.answer_head();
    assert!(!e.check_anchor(&h1, 1_100));
    drop(e);
    let mut e = sealed_engine(&d, &nft, 2_000, &key);
    assert!(e.state().next_seq > h1.next_seq, "the restart added events");
    assert!(!e.check_anchor(&h1, 2_000));
    assert_eq!(e.status("i1").status, Status::Verified);
    assert!(e.state().journal_reset_ms.is_none());
}

/// Review finding 2: deleting the sealed journal (and the replay store) is
/// not a first start: without the first-start marker it is a reset, the
/// SOC replay store is fenced and orders are refused until `rearm`.
#[test]
fn review_a_deleted_journal_is_a_reset_not_a_first_start() {
    let key = seal_key(7);
    let nft = FakeNft::default();
    let d = tmpdir("rv-deleted");
    let mut e = sealed_engine(&d, &nft, 1_000, &key);
    let o = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&o, &mut idle(), 1_000).status, Status::Verified);
    // The operator's emergency disable, then the state files deleted.
    nft.0.lock().unwrap().table = None;
    e.periodic_verify(1_100);
    assert!(e.state().operator_disabled);
    drop(e);
    std::fs::remove_file(d.join("journal.json")).unwrap();
    std::fs::remove_file(d.join(crate::soc::NONCE_FILE)).unwrap();
    let mut e = sealed_engine_as_is(&d, &nft, 2_000, &key);
    assert!(e.state().journal_reset_ms.is_some(), "not a first start");
    assert!(reset_reason(&e).contains("first-start marker"));
    let o = order(
        "i2",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut idle(), 2_100);
    assert_eq!(out.refusal.unwrap().code, codes::JOURNAL_RESET);
    drop(e);
    let s = crate::soc::ReplayStore::open_sealed(&d, 2_005, 30, true, Some(key.clone()));
    assert_eq!(s.fence_s(), Some(32), "replay store fenced (now + skew)");
}

/// Review finding 8: the state files are written through a fresh temporary
/// file with a random name: a planted file or symlink at the old fixed
/// temporary name is never written through.
#[test]
fn review_writes_never_follow_a_planted_temp_file() {
    let d = tmpdir("rv-tmp");
    let victim = d.join("victim");
    std::fs::write(&victim, "untouched").unwrap();
    std::os::unix::fs::symlink(&victim, d.join("journal.json.tmp")).unwrap();
    std::os::unix::fs::symlink(&victim, d.join(format!("{}.tmp", crate::soc::NONCE_FILE))).unwrap();
    let nft = FakeNft::default();
    let mut e = sealed_engine(&d, &nft, 1_000, &seal_key(7));
    let o = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&o, &mut idle(), 1_000).status, Status::Verified);
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
    let left = std::fs::read_dir(&d)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|x| x.file_name().to_string_lossy().contains(".tmp-"))
        .count();
    assert_eq!(left, 0, "no temporary file left behind");
}

/// Review finding 10: `stop-cleanup` reads the sealed journal with the
/// seal key, so its actions are marked reverted (not left `active` for the
/// next start to read as an emergency disable).
#[test]
fn review_abandon_marks_a_sealed_journal() {
    let key = seal_key(7);
    let nft = FakeNft::default();
    let d = tmpdir("rv-abandon");
    let mut e = sealed_engine(&d, &nft, 1_000, &key);
    let o = order(
        "i1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    assert_eq!(e.submit(&o, &mut idle(), 1_000).status, Status::Verified);
    drop(e);
    let c = cfg(d.to_str().unwrap());
    let mut n = nft.clone();
    let mut ports = crate::motion::SystemPorts;
    let k = crate::engine::abandon(
        Some(&c),
        &mut n,
        "stopped",
        2_000,
        Some(key.clone()),
        &mut ports,
    )
    .unwrap();
    assert_eq!(k, 1);
    assert!(nft.0.lock().unwrap().table.is_none());
    let e = sealed_engine(&d, &nft, 3_000, &key);
    assert_eq!(e.status("i1").status, Status::Reverted);
    assert!(
        !e.state().operator_disabled,
        "not taken for an emergency disable"
    );
    assert!(e.state().journal_reset_ms.is_none());
}

/// Gap 1: the executor's SOC replay store is sealed too; a store that
/// fails its seal fences like a damaged one.
#[test]
fn gap1_a_soc_replay_store_that_fails_its_seal_fences() {
    let key = seal_key(9);
    let d = tmpdir("seal-soc");
    let mut s = crate::soc::ReplayStore::open_sealed(&d, 1_000, 30, false, Some(key.clone()));
    assert!(s.fence_s().is_none());
    assert!(s
        .check("k", "nonce-aaaaaaaaaaaaaaaa", 1_000, 1_000, 30)
        .is_ok());
    drop(s);
    let p = d.join(crate::soc::NONCE_FILE);
    let text = std::fs::read_to_string(&p).unwrap();
    // The nonce removed, the seal line kept: a replay would pass if believed.
    std::fs::write(
        &p,
        text.replace("nonce-aaaaaaaaaaaaaaaa", "nonce-zzzzzzzzzzzzzzzz"),
    )
    .unwrap();
    let s = crate::soc::ReplayStore::open_sealed(&d, 1_005, 30, true, Some(key));
    assert_eq!(s.fence_s(), Some(1_035));
    assert!(s.fenced_because.unwrap().contains("seal"));
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

/// Review (WP6): the `commissioning` section lives in executor.json, which
/// is not bound. Deleting it (or re-pointing its trust anchors) while the
/// executor runs must not bring back unsigned `oem_validated` flags on the
/// next re-read, and the changed commissioning notes are logged and
/// journalled instead of dropped.
#[test]
fn wp6_commissioning_section_is_sticky_and_its_notes_are_journalled() {
    let d = tmpdir("sticky-commissioning");
    let pol_path = d.join("policy.json");
    let cfg_path = d.join("executor.json");
    let p = policy(Morphology::WheeledMobile, true, &[]);
    std::fs::write(&pol_path, serde_json::to_string(&p).unwrap()).unwrap();
    let mut v: Value = serde_json::from_str(&config_json(d.to_str().unwrap())).unwrap();
    v["policy_path"] = json!(pol_path);
    // No profile at that path: nothing is bound, the policy's flag is not
    // honoured.
    v["commissioning"] = json!({"profile_path": d.join("profile.json"),
                                "trusted_keys": d.join("trust.json")});
    std::fs::write(&cfg_path, v.to_string()).unwrap();
    let (c, p, notes) = crate::config::load_commissioned(&cfg_path).unwrap();
    assert!(!p.oem_validated, "{notes:?}");
    let nft = FakeNft::default();
    let mut e = Engine::open(c, p, Box::new(nft.clone()), "b1", 1_000)
        .unwrap()
        .with_reload(cfg_path.clone())
        .with_commissioning_notes(notes.clone());
    let commissioning_events = |e: &Engine| {
        e.events_since(0, 10_000)
            .into_iter()
            .filter(|ev| ev.kind == EventKind::Reconciled && ev.detail.contains("commissioning"))
            .count()
    };
    let isolate = |id: &str| {
        order(
            id,
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        )
    };
    assert_eq!(
        e.submit(&isolate("i1"), &mut idle(), 1_100)
            .refusal
            .unwrap()
            .code,
        codes::OBSERVE_MODE
    );
    // Same notes as at start: nothing new is logged.
    assert_eq!(commissioning_events(&e), 0);

    // The section is deleted at runtime: still verified against it.
    v.as_object_mut().unwrap().remove("commissioning");
    std::fs::write(&cfg_path, v.to_string()).unwrap();
    assert_eq!(
        e.submit(&isolate("i2"), &mut idle(), 1_200)
            .refusal
            .unwrap()
            .code,
        codes::OBSERVE_MODE
    );
    assert!(
        e.commissioning_notes()
            .first()
            .is_some_and(|n| n.contains("removed")),
        "{:?}",
        e.commissioning_notes()
    );
    assert_eq!(commissioning_events(&e), 1);

    // Re-pointed at other trust anchors: the same.
    v["commissioning"] = json!({"profile_path": "/elsewhere/profile.json",
                                "trusted_keys": "/elsewhere/trust.json"});
    std::fs::write(&cfg_path, v.to_string()).unwrap();
    assert_eq!(
        e.submit(&isolate("i3"), &mut idle(), 1_300)
            .refusal
            .unwrap()
            .code,
        codes::OBSERVE_MODE
    );
    assert!(e.commissioning_notes()[0].contains("changed"));
    assert_eq!(commissioning_events(&e), 2);
    let _ = std::fs::remove_dir_all(&d);
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
            guid_only: false,
            excluded: Vec::new(),
            addresses: Vec::new(),
            excluded_addresses: Vec::new(),
            evidence_truncated: false,
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
    ] {
        let r = precheck(&q(&locs), &p, &scoped);
        assert_eq!(
            r.as_ref().map_err(|e| e.code.as_str()).err(),
            Some("locator_out_of_scope"),
            "{what}: {r:?}"
        );
    }
    // Review of the F3 fix (H2b): one bad locator next to good ones is left
    // out (listed, never acted on) instead of refusing the whole order.
    let r = precheck(
        &q(&[
            ("10.0.0.7", 7410),
            ("fd00::7", 7410),
            ("10.0.0.7", 53),
            ("10.20.0.10", 7410),
            ("127.0.0.1", 7410),
        ]),
        &p,
        &scoped,
    );
    match r.map(|x| x.effect) {
        Ok(Effect::Quarantine(qs)) => {
            assert_eq!(qs.locators.len(), 1, "{qs:?}");
            assert_eq!(qs.locators[0].ip.to_string(), "10.0.0.7");
            assert_eq!(qs.excluded.len(), 4, "{qs:?}");
            assert!(qs
                .excluded
                .iter()
                .all(|x| x.reason.starts_with("executor: ")));
        }
        e => panic!("{e:?}"),
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

/// Like agentd's `ReplayGuard` (control plane v2 review, finding 5): once
/// the store dropped a dead pair, a clock that goes back below that moment
/// would bring the pair's timestamp back into the window. The store keeps
/// a persisted high-water mark and fences up to it plus the skew, while
/// running and after a restart.
#[test]
fn replay_store_fences_when_the_clock_goes_back() {
    let d = tmpdir("hwm");
    std::fs::write(d.join(crate::journal::FILE), b"{}").unwrap();
    let mut s = crate::soc::ReplayStore::open(&d, 1_000, 30, false);
    assert_eq!(s.fence_s(), None);
    assert!(s
        .check("k", "nonce-nonce-nonce-01", 1_000, 1_000, 30)
        .is_ok());
    // 100 s later the pair is dead and dropped by the next check.
    assert!(s
        .check("k", "nonce-nonce-nonce-02", 1_100, 1_100, 30)
        .is_ok());
    assert_eq!(s.len(), 1);
    // The clock steps back to 1_005: the first request is in the window
    // again, but its pair is gone. Fenced, not accepted.
    let r = s.check("k", "nonce-nonce-nonce-01", 1_000, 1_005, 30);
    assert_eq!(
        r.map_err(|e| e.code),
        Err(codes::SOC_REQUEST_STALE.to_string())
    );
    assert_eq!(s.fence_s(), Some(1_130));
    drop(s);
    // After a restart with the clock still behind: fenced again from the
    // persisted mark.
    let mut s = crate::soc::ReplayStore::open(&d, 1_005, 30, true);
    assert_eq!(s.fence_s(), Some(1_130));
    assert!(s.fenced_because.is_some());
    let r = s.check("k", "nonce-nonce-nonce-01", 1_000, 1_005, 30);
    assert_eq!(
        r.map_err(|e| e.code),
        Err(codes::SOC_REQUEST_STALE.to_string())
    );
    // A clock that does not go back is never fenced by the mark.
    let d2 = tmpdir("hwm-fwd");
    let mut s = crate::soc::ReplayStore::open(&d2, 1_000, 30, false);
    assert!(s
        .check("k", "nonce-nonce-nonce-01", 1_000, 1_000, 30)
        .is_ok());
    assert!(s
        .check("k", "nonce-nonce-nonce-02", 1_100, 1_100, 30)
        .is_ok());
    drop(s);
    let s = crate::soc::ReplayStore::open(&d2, 1_200, 30, true);
    assert_eq!(s.fence_s(), None);
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

/// Review of the F3 fix (H2): agentd vouches for a GUID-prefix-only
/// quarantine (`guid_only`) when no locator can be vouched for (a decoy
/// contested them). The executor then quarantines by the GUID-prefix drop
/// alone, but every one of its own refusals still applies, and an order
/// whose every locator lies on the motion control path is still refused.
#[test]
fn review_guid_only_quarantine_keeps_every_refusal() {
    let c = cfg("/tmp/unused");
    let wheeled = policy(Morphology::WheeledMobile, true, &[]);
    let target = |g: &str, locs: &[(&str, u16)], guid_only: bool| Target::Participant {
        guid_prefix: g.parse().unwrap(),
        locators: locs
            .iter()
            .map(|(ip, port)| Locator {
                ip: ip.parse().unwrap(),
                port: *port,
            })
            .collect(),
        guid_only,
        excluded: vec![crate::order::ExcludedLocator {
            ip: "10.0.0.66".parse().unwrap(),
            port: 7410,
            reason: "contested: another live participant was seen at this address".into(),
        }],
        addresses: Vec::new(),
        excluded_addresses: Vec::new(),
        evidence_truncated: false,
    };
    let mut o = order(
        "g1",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    // Vouched, nothing left: the GUID-prefix drop alone.
    o.target = target(GUID, &[], true);
    match precheck(&o, &wheeled, &c).unwrap().effect {
        Effect::Quarantine(q) => {
            assert!(q.locators.is_empty());
            assert_eq!(q.excluded.len(), 1);
            assert!(
                q.excluded[0].reason.starts_with("agentd: contested"),
                "{q:?}"
            );
            let r = crate::nft::render(&[crate::nft::Active {
                id: "g1",
                effect: &Effect::Quarantine(q.clone()),
            }]);
            let text = format!("{r:?}");
            assert!(!text.contains("10.0.0.66"), "{text}");
        }
        e => panic!("{e:?}"),
    }
    // Not vouched: refused as before.
    o.target = target(GUID, &[], false);
    assert_eq!(
        precheck(&o, &wheeled, &c).unwrap_err().code,
        codes::LOCATORS_REQUIRED
    );
    // Vouched, but every locator on the motion control path: refused.
    o.target = target(GUID, &[("192.168.123.50", 7410)], true);
    assert_eq!(
        precheck(&o, &wheeled, &c).unwrap_err().code,
        codes::MOTION_PATH
    );
    // A motion-path locator next to one outside: left out, the rest acted on.
    o.target = target(GUID, &[("192.168.123.50", 7410), ("10.0.0.7", 7410)], false);
    match precheck(&o, &wheeled, &c).unwrap().effect {
        Effect::Quarantine(q) => {
            assert_eq!(q.locators.len(), 1);
            assert!(q
                .excluded
                .iter()
                .any(|x| x.reason.contains("motion control path")));
        }
        e => panic!("{e:?}"),
    }
    // The low-level writer's own prefix: refused, vouched or not.
    o.target = target(LOWCMD_GUID, &[], true);
    assert_eq!(
        precheck(&o, &wheeled, &c).unwrap_err().code,
        codes::MOTION_PATH
    );
    // A humanoid: a human must approve, vouched or not.
    let humanoid = policy(Morphology::Humanoid, true, &[RestrictTarget::Participant]);
    let mut h = unsigned(
        "g2",
        ActionId::QuarantineNode,
        Morphology::Humanoid,
        SafetyState::Idle,
    );
    h.target = target(GUID, &[], true);
    h.human_approved = false;
    assert_eq!(
        precheck(&h, &humanoid, &c).unwrap_err().code,
        codes::NEEDS_APPROVAL
    );
    // An interface-only motion-path entry: nothing can be proven outside it.
    let mut v: Value = serde_json::from_str(&config_json("/tmp/unused")).unwrap();
    v["network"]["motion_control_path"] = json!([{"interface": "eth2"}]);
    let iface = ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap();
    o.target = target(GUID, &[], true);
    assert_eq!(
        precheck(&o, &wheeled, &iface).unwrap_err().code,
        codes::MOTION_PATH
    );
    // Excluded reasons are bounded text.
    let mut bad = o.clone();
    if let Target::Participant { excluded, .. } = &mut bad.target {
        excluded[0].reason = "line\nbreak".into();
    }
    assert!(bad.validate().is_err());
}

/// Review R2-3 / R2-7: the answer's new `quarantine` field is skipped when
/// absent, and an answer carrying fields this build does not know still
/// parses (an older agentd reads a newer executor's answers; the order
/// itself stays strict, so the executor is upgraded first).
#[test]
fn outcomes_stay_readable_across_versions() {
    let o = Outcome {
        id: "x".into(),
        status: Status::Verified,
        action: None,
        refusal: None,
        error: None,
        applied_ms: None,
        deadline_ms: None,
        duplicate: false,
        note: None,
        quarantine: None,
    };
    let text = serde_json::to_string(&o).unwrap();
    assert!(!text.contains("quarantine"), "{text}");
    let newer: Outcome = serde_json::from_str(
        r#"{"id":"x","status":"verified","quarantine":{"locators":[]},"from_the_future":1}"#,
    )
    .unwrap();
    assert_eq!(newer.quarantine.unwrap().locators.len(), 0);
}

/// Review R3-1: `containment: "full"` meant "every announced locator has a
/// rule", but a locator rule matches only traffic **from the announced
/// port**, and Fast DDS sends from ephemeral ports: inbound traffic was
/// held back only by the (evadable) GUID-prefix drop. A source address is
/// now cut whole, to and from the robot's DDS ports, whatever the source
/// port, after the same exclusions as a locator; `containment` says
/// exactly what the rendered rules reach.
#[test]
fn review3_r3_1_addresses_are_cut_whole_and_containment_matches_the_rules() {
    use crate::decision::{merge_ranges, Containment};
    use crate::net::PortRange;
    use crate::nftmodel::{rtps, verdict_rendered, Packet};
    use std::net::IpAddr;

    let c = cfg("/tmp/unused");
    let wheeled = policy(Morphology::WheeledMobile, true, &[]);
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let target = |locs: &[(&str, u16)], addrs: &[&str], truncated: bool| Target::Participant {
        guid_prefix: GUID.parse().unwrap(),
        locators: locs
            .iter()
            .map(|(a, port)| Locator {
                ip: a.parse().unwrap(),
                port: *port,
            })
            .collect(),
        guid_only: false,
        excluded: Vec::new(),
        addresses: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        excluded_addresses: Vec::new(),
        evidence_truncated: truncated,
    };
    let plan = |t: Target| {
        let mut o = order(
            "r3-1",
            ActionId::QuarantineNode,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        );
        o.target = t;
        match precheck(&o, &wheeled, &c).unwrap().effect {
            Effect::Quarantine(q) => q,
            e => panic!("{e:?}"),
        }
    };

    // Every exclusion of a locator applies to an address too.
    let q = plan(target(
        &[("10.0.0.7", 7410)],
        &[
            "10.0.0.7",
            "10.0.0.8",
            "127.0.0.1",
            "192.168.123.50",
            "10.5.0.1",
            "10.20.0.5",
            "fd00::7",
        ],
        false,
    ));
    assert_eq!(q.addresses, vec![ip("10.0.0.7"), ip("10.0.0.8")], "{q:?}");
    let why = |a: &str| {
        q.excluded_addresses
            .iter()
            .find(|x| x.ip == ip(a))
            .map(|x| x.reason.clone())
            .unwrap_or_else(|| panic!("{a} not left out: {q:?}"))
    };
    assert!(why("127.0.0.1").contains("loopback"));
    assert!(why("192.168.123.50").contains("motion control path"));
    assert!(why("10.5.0.1").contains("network.quarantine.cidrs"));
    assert!(why("10.20.0.5").contains("network.quarantine.cidrs"));
    assert!(why("fd00::7").contains("network.quarantine.cidrs"));
    assert_eq!(q.dds_ports, vec![PortRange::new(7400, 7649).unwrap()]);
    assert_eq!(q.containment(), Containment::Partial);

    // What the rendered rules do with real-looking packets.
    let effect = Effect::Quarantine(q.clone());
    let r = crate::nft::render(&[crate::nft::Active {
        id: "r3-1",
        effect: &effect,
    }]);
    let robot = ip("10.0.0.1");
    let other = rtps("0110ffffffffffffffff0000");
    let v = |p: Packet| verdict_rendered(&r, &p).unwrap();
    let pkt = |chain: &str, s: (&str, u16), d: (&str, u16), pl: &[u8]| {
        Packet::udp(chain, (ip(s.0), s.1), (ip(d.0), d.1), pl)
    };
    // From an ephemeral port, re-attributed RTPS: dropped.
    assert_eq!(
        v(pkt(
            "input",
            ("10.0.0.7", 51_234),
            ("10.0.0.1", 7410),
            &other
        )),
        "drop"
    );
    assert_eq!(
        v(pkt("input", ("10.0.0.8", 40_000), ("10.0.0.1", 7600), b"x")),
        "drop"
    );
    assert_eq!(
        v(pkt(
            "forward",
            ("10.0.0.7", 51_234),
            ("10.0.0.30", 7401),
            b"x"
        )),
        "drop"
    );
    // Only the robot's DDS ports; another host untouched.
    assert_eq!(
        v(pkt("input", ("10.0.0.7", 51_234), ("10.0.0.1", 22), b"x")),
        "accept"
    );
    assert_eq!(
        v(pkt(
            "input",
            ("10.0.0.9", 51_234),
            ("10.0.0.1", 7410),
            &other
        )),
        "accept"
    );
    // Never over loopback.
    assert_eq!(
        v(pkt("input", ("10.0.0.7", 51_234), ("10.0.0.1", 7410), b"x").on("lo", "")),
        "accept"
    );
    // To the host on a DDS port: dropped; elsewhere: delivered.
    assert_eq!(
        v(pkt(
            "output",
            ("10.0.0.1", 40_000),
            ("10.0.0.8", 7499),
            b"x"
        )),
        "drop"
    );
    assert_eq!(
        v(pkt("output", ("10.0.0.1", 40_000), ("10.0.0.8", 53), b"x")),
        "accept"
    );
    // The motion control path is accepted before any drop.
    assert_eq!(
        v(pkt(
            "input",
            ("192.168.123.50", 51_234),
            ("10.0.0.1", 7410),
            b"x"
        )),
        "accept"
    );
    // The GUID-prefix drop still applies from anywhere.
    assert_eq!(
        v(pkt(
            "input",
            ("10.0.0.9", 51_234),
            (&robot.to_string(), 7410),
            &rtps(GUID)
        )),
        "drop"
    );

    // `full` only when every address and locator is covered.
    let q = plan(target(&[("10.0.0.7", 7410)], &["10.0.0.7"], false));
    assert_eq!(q.containment(), Containment::Full);
    let q = plan(target(&[("10.0.0.7", 7410)], &["10.0.0.7"], true));
    assert_eq!(q.containment(), Containment::Partial, "forgotten evidence");
    let q = plan(target(&[("10.0.0.7", 7410)], &[], false));
    assert_eq!(q.containment(), Containment::Partial, "locator rules only");
    let q = plan(target(&[("10.0.0.7", 7410)], &["10.0.0.8"], false));
    assert_eq!(
        q.containment(),
        Containment::Partial,
        "a locator not covered"
    );
    // An address alone is enough to act on (no `locators_required`).
    let q = plan(target(&[], &["10.0.0.8"], false));
    assert_eq!(q.containment(), Containment::Full);
    assert!(q.locators.is_empty());
    // Nothing IP-level left, GUID prefix vouched: `guid_only`.
    let mut t = target(&[], &["10.5.0.1"], false);
    if let Target::Participant { guid_only, .. } = &mut t {
        *guid_only = true;
    }
    let q = plan(t);
    assert_eq!(q.containment(), Containment::GuidOnly);
    assert_eq!(q.excluded_addresses.len(), 1);
    // Every address on the motion control path: refused, as for locators.
    let mut o = order(
        "r3-1b",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    o.target = target(&[], &["192.168.123.50"], false);
    assert_eq!(
        precheck(&o, &wheeled, &c).unwrap_err().code,
        codes::MOTION_PATH
    );
    // A journal entry from before this revision: locator rules only.
    let old: crate::decision::QuarantineSpec = serde_json::from_value(json!({
        "guid_prefix": GUID,
        "locators": [{"ip": "10.0.0.7", "port": 7410}],
        "protected": []
    }))
    .unwrap();
    assert_eq!(old.containment(), Containment::Partial);
    // Adjacent domains' ranges are merged (nftables lists them merged).
    assert_eq!(
        merge_ranges(vec![
            PortRange::new(7650, 7899).unwrap(),
            PortRange::new(7400, 7649).unwrap(),
            PortRange::new(9000, 9001).unwrap(),
        ]),
        vec![
            PortRange::new(7400, 7899).unwrap(),
            PortRange::new(9000, 9001).unwrap()
        ]
    );
    // Order limits.
    let mut bad = o.clone();
    bad.target = target(&[], &["239.255.0.1"], false);
    assert!(bad.validate().is_err());
    let many: Vec<String> = (1..=17).map(|i| format!("10.0.0.{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    bad.target = target(&[], &many, false);
    assert!(bad.validate().is_err());
}

/// Review finding 2: the protocol socket accepted `rearm` from any holder
/// of the link key, which agentd holds, so a compromised agentd could end
/// the operator's emergency disable. A `rearm` sealed with the right key
/// is now refused (no answer) and the executor stays disabled; the
/// operator re-arms on the journal with the executor stopped.
#[test]
fn review_finding_2_no_rearm_on_the_agentd_socket() {
    use std::io::{BufRead as _, Write as _};
    let (_d, nft, client, stop, server) = served("f2-rearm", |_| {});
    let i = sign_at(
        unsigned(
            "r-f2",
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        ),
        now_s(),
    );
    let out = client
        .submit(&i, &mut || Ok((SafetyState::Idle, 3)))
        .unwrap();
    assert_eq!(out.status, Status::Verified, "{out:?}");
    nft.0.lock().unwrap().table = None;
    let i2 = sign_at(
        unsigned(
            "r-f2b",
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        ),
        now_s(),
    );
    let out = client
        .submit(&i2, &mut || Ok((SafetyState::Idle, 3)))
        .unwrap();
    assert_eq!(refusal_code(&out), codes::OPERATOR_DISABLED, "{out:?}");
    assert!(client.health().unwrap().operator_disabled);
    // What a key holder (agentd) could send before the fix.
    let key = crate::proto::Key::from_bytes([0x5a; 32]);
    let n = crate::proto::new_nonce().unwrap();
    let line = crate::proto::seal_text(
        &key,
        crate::proto::wall_ms(),
        &n,
        "",
        r#"{"op":"rearm","reason":"agentd says so"}"#.into(),
    )
    .unwrap();
    let mut s = std::os::unix::net::UnixStream::connect(&client.socket).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    s.write_all(&line).unwrap();
    let mut answer = String::new();
    let _ = std::io::BufReader::new(s).read_line(&mut answer);
    assert!(!answer.contains("rearmed"), "{answer}");
    let h = client.health().unwrap();
    assert!(h.operator_disabled, "a key holder re-armed the executor");
    assert!(crate::server::serving(&client.socket).unwrap());
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    server.join().unwrap();
    // Stopped: the operator's journal re-arm (the CLI's path).
    assert!(!crate::server::serving(&client.socket).unwrap());
}

/// An engine on `config_json` with `soc` replaced by `soc`.
fn engine_soc(
    dir: &std::path::Path,
    nft: &FakeNft,
    boot: &str,
    now: u64,
    soc: Value,
) -> Result<Engine, String> {
    let mut v: Value = serde_json::from_str(&config_json(dir.to_str().unwrap())).unwrap();
    v["soc"] = soc;
    let c = ExecutorConfig::parse(&v.to_string())?.validate()?;
    Engine::open(
        c,
        policy(Morphology::WheeledMobile, true, &[]),
        Box::new(nft.clone()),
        boot,
        now,
    )
}

/// Sales-readiness T67: a SOC key's scope (`soc.key_scopes`) bounds the
/// actions it approves and reverts, and their TTL, in the executor itself
/// (agentd's own check is not trusted for it); a re-arm after a reboot
/// re-checks the scope as configured then.
#[test]
fn t67_soc_key_scope_bounds_actions_ttl_reverts_and_rearm() {
    let d = tmpdir("t67");
    let nft = FakeNft::default();
    let scoped = |actions: Value, max: Value| {
        json!({"keys": [soc_key_path()],
               "key_scopes": {SOC_KEY_ID: {"actions": actions, "max_ttl_s": max}}})
    };
    let mut e = engine_soc(
        &d,
        &nft,
        "b1",
        1_000,
        scoped(json!(["isolate_network"]), json!(900)),
    )
    .unwrap();
    // An action outside the key's scope: refused, nothing installed.
    let q = order(
        "t67-q",
        ActionId::QuarantineNode,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    let out = e.submit(&q, &mut idle(), 1_000);
    assert_eq!(refusal_code(&out), codes::KEY_SCOPE_DENIED, "{out:?}");
    assert!(nft.0.lock().unwrap().table.is_none());
    // In scope, but longer than the key may approve.
    let mut long = unsigned(
        "t67-long",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    long.ttl_s = Some(901);
    let out = e.submit(&signed(long), &mut idle(), 1_000);
    assert_eq!(refusal_code(&out), codes::KEY_SCOPE_DENIED, "{out:?}");
    assert!(nft.0.lock().unwrap().table.is_none());
    // No TTL named: the executor's default (600 s) is what is bounded.
    let mut dflt = unsigned(
        "t67-default",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
        SafetyState::Idle,
    );
    dflt.ttl_s = None;
    let out = e.submit(&signed(dflt), &mut idle(), 1_000);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    drop(e);
    // The scope narrowed (same boot): the key can no longer revert it.
    let mut e = engine_soc(
        &d,
        &nft,
        "b1",
        2_000,
        scoped(json!(["quarantine_node"]), json!(900)),
    )
    .unwrap();
    let rv = crate::soc::SocRequest::sign(
        &SOC_SEED,
        "ugv-007",
        SOC_KEY_ID,
        "POST",
        "/api/v2/robots/ugv-007/action-requests/t67-default/revert",
        2,
        "t67-revert-nonce-0001",
        r#"{"requested_by":"analyst"}"#,
    );
    let out = e.revert_request("t67-default", "done", Some(&rv), &mut idle(), 2_000);
    assert_eq!(refusal_code(&out), codes::KEY_SCOPE_DENIED, "{out:?}");
    assert_eq!(e.status("t67-default").status, Status::Verified);
    assert!(nft.0.lock().unwrap().table.is_some());
    drop(e);
    // After a reboot the held isolation is re-armed only if the key's
    // scope (as configured now) still allows it.
    nft.0.lock().unwrap().table = None;
    let mut e = engine_soc(
        &d,
        &nft,
        "b2",
        3_000,
        scoped(json!(["quarantine_node"]), json!(900)),
    )
    .unwrap();
    e.rearm_held(
        Ok(Current {
            state: SafetyState::Idle,
            age_ms: 5,
        }),
        3_100,
    );
    let st = e.status("t67-default");
    assert_eq!(st.status, Status::Reverted, "re-armed out of scope: {st:?}");
    assert!(
        st.note
            .as_deref()
            .unwrap_or("")
            .contains("key_scope_denied"),
        "{st:?}"
    );
    assert!(nft.0.lock().unwrap().table.is_none());
    drop(e);
    // require_key_scopes: a key without an entry approves nothing.
    let mut e = engine_soc(
        &d,
        &nft,
        "b2",
        4_000,
        json!({"keys": [soc_key_path()], "require_key_scopes": true}),
    )
    .unwrap();
    let i = sign_at(
        unsigned(
            "t67-unscoped",
            ActionId::IsolateNetwork,
            Morphology::WheeledMobile,
            SafetyState::Idle,
        ),
        4,
    );
    let out = e.submit(&i, &mut idle(), 4_000);
    assert_eq!(refusal_code(&out), codes::KEY_SCOPE_DENIED, "{out:?}");
    drop(e);
    // Configuration rules.
    for bad in [
        scoped(json!([]), json!(900)),
        scoped(json!(["isolate_network", "isolate_network"]), json!(900)),
        scoped(json!(["isolate_everything"]), json!(900)),
        scoped(json!(["isolate_network"]), json!(0)),
        scoped(json!(["isolate_network"]), json!(3601)),
        json!({"keys": [], "key_scopes": {"": {"actions": ["isolate_network"]}}}),
        json!({"keys": [], "key_scopes": {SOC_KEY_ID: {"actions": ["isolate_network"], "x": 1}}}),
    ] {
        assert!(
            engine_soc(&d, &nft, "b3", 5_000, bad.clone()).is_err(),
            "accepted {bad}"
        );
    }
}
