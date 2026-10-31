//! Harness: the executor's own check of the SOC's approval
//! (`robodr_executor::soc::verify` / `verify_revert`, executor M1 and
//! review finding F3): the trust boundary between agentd and the
//! executor. agentd (or anything that reaches the executor's socket with
//! its key) chooses every byte of the order and of the forwarded request.
//!
//! Input: `selector body`. `selector % 4` picks the entry point:
//!
//! 0. the body as an `Order` (JSON), **re-signed** with the harness SOC key
//!    for this robot (`soc::testing::sign_order`), then `verify`: mutations
//!    get past the signature and reach the order-vs-signed-body checks;
//! 1. the body as an `Order` with whatever `soc` it carries, then `verify`;
//! 2. the body as a `SocRequest` (JSON), re-signed with the harness key
//!    (method, target, timestamp, nonce and body kept), then
//!    `verify_revert` for the action `act-1`;
//! 3. the body as a `SocRequest` as is, then `verify_revert`.
//!
//! Every input gets a fresh replay store (in `/dev/shm` when there is one).
//!
//! Invariants beyond "no panic":
//!
//! * an accepted order comes from the control plane, names at most
//!   `MAX_APPROVERS` approvers and carries a request whose signature is the
//!   harness key's (deterministic Ed25519) over exactly its fields for this
//!   robot: nothing unsigned, re-encoded or signed for another robot is
//!   accepted;
//! * an accepted order is the order the SOC signed (review finding F3):
//!   its id, action, `ttl_s`, target, origin key id and `requested_by`
//!   equal the signed body's `request_id`, `action`, `ttl_seconds`,
//!   parameters, the request's `key_id` and `requested_by`
//!   ([`signed_body_matches`], an oracle written independently of
//!   `verify`'s own comparison);
//! * the same approval is never accepted twice (`soc_nonce_replayed`), and
//!   never by an executor of another robot (`soc_signature_invalid`);
//! * a planner order never carries an approval (`approval_missing`);
//! * an accepted revert is `POST` for exactly that action, signed by the
//!   harness key, accepted once, and never for another action.
//!
//! Std-only smoke test: `crates/robodr-executor/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_executor::decision::codes;
use robodr_executor::order::{Order, Origin};
use robodr_executor::soc::{
    testing, verify, verify_revert, Context, ReplayStore, SocKey, SocRequest, MAX_APPROVERS,
};
use std::path::PathBuf;

pub const SEED: [u8; 32] = [0x5a; 32];
pub const KEY_ID: &str = "soc-fuzz";
pub const ROBOT: &str = "robot-fuzz";
pub const OTHER_ROBOT: &str = "robot-other";
pub const NOW_S: u64 = 1_760_000_000;
pub const SKEW_S: u64 = 300;
pub const ACTION: &str = "act-1";
/// The nonce the harness signs with (selector 0 / 2).
pub const NONCE: &str = "fuzz-nonce-000000001";

fn keys() -> Vec<SocKey> {
    vec![SocKey {
        key_id: KEY_ID.into(),
        public: robodr_blackbox::sign_ed25519::public_key_from_seed(&SEED),
    }]
}

fn store_dir() -> PathBuf {
    let base = if std::path::Path::new("/dev/shm").is_dir() {
        PathBuf::from("/dev/shm")
    } else {
        std::env::temp_dir()
    };
    let d = base.join(format!("robodr-fuzz-executor-soc-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    d
}

/// A fresh, empty replay store.
fn store(sub: &str) -> ReplayStore {
    let d = store_dir().join(sub);
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::create_dir_all(&d);
    ReplayStore::open(&d, NOW_S, SKEW_S, false)
}

fn cx<'a>(keys: &'a [SocKey], robot: &'a str) -> Context<'a> {
    Context {
        keys,
        robot_id: robot,
        max_skew_s: SKEW_S,
        now_ms: NOW_S * 1000,
    }
}

/// The harness key's own signature over `r` for `ROBOT`.
fn signed_by_harness(r: &SocRequest) -> bool {
    let again = SocRequest::sign(
        &SEED,
        ROBOT,
        &r.key_id,
        &r.method,
        &r.target,
        r.timestamp,
        &r.nonce,
        &r.body,
    );
    again.signature == r.signature.to_ascii_lowercase()
}

pub fn run(data: &[u8]) {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    match sel % 4 {
        0 | 1 => {
            let Ok(mut order) = serde_json::from_slice::<Order>(body) else {
                return;
            };
            if sel % 4 == 0 {
                order = testing::sign_order(order, &SEED, ROBOT, NOW_S, NONCE);
            }
            approval(&order);
        }
        _ => {
            let Ok(mut req) = serde_json::from_slice::<SocRequest>(body) else {
                return;
            };
            if sel % 4 == 2 {
                req = SocRequest::sign(
                    &SEED,
                    ROBOT,
                    &req.key_id,
                    &req.method,
                    &req.target,
                    req.timestamp,
                    &req.nonce,
                    &req.body,
                );
            }
            revert(&req);
        }
    }
}

fn approval(order: &Order) {
    let keys = keys();
    let mut replay = store("a");
    let first = verify(order, &cx(&keys, ROBOT), &mut replay);
    if matches!(order.origin, Origin::Planner { .. }) {
        let e = first.as_ref().expect_err("a planner order verified");
        assert_eq!(e.code, codes::APPROVAL_MISSING);
        return;
    }
    let Ok(approvers) = first else {
        return;
    };
    assert!(approvers.len() <= MAX_APPROVERS);
    let soc = order
        .soc
        .as_deref()
        .expect("an accepted order carries its request");
    assert!(
        signed_by_harness(soc),
        "accepted a request the key did not sign"
    );
    assert_eq!(soc.method, "POST");
    if let Err(why) = signed_body_matches(order) {
        panic!("accepted an order that is not the one the SOC signed: {why}");
    }
    let again = verify(order, &cx(&keys, ROBOT), &mut replay).expect_err("approval replayed");
    assert_eq!(again.code, codes::SOC_NONCE_REPLAYED);
    let mut other = store("b");
    let e = verify(order, &cx(&keys, OTHER_ROBOT), &mut other)
        .expect_err("approval accepted by another robot");
    assert_eq!(e.code, codes::SOC_SIGNATURE_INVALID);
}

/// Whether `order` is the order its SOC request's body describes, checked
/// field by field against the body as JSON (not through `verify`'s own
/// types): the binding that makes the signature an approval of *this*
/// order. `Err` names the first field that differs.
pub fn signed_body_matches(order: &Order) -> Result<(), String> {
    use robodr_executor::net::GuidPrefix;
    use robodr_executor::order::Target;
    use serde_json::Value;
    let soc = order.soc.as_deref().ok_or("no signed request")?;
    let body: Value = serde_json::from_str(&soc.body).map_err(|e| format!("signed body: {e}"))?;
    let str_of = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let Origin::ControlPlane {
        key_id,
        requested_by,
    } = &order.origin
    else {
        return Err("not a control-plane order".into());
    };
    if &soc.key_id != key_id {
        return Err("key_id".into());
    }
    if str_of(&body, "request_id").as_deref() != Some(order.id.as_str()) {
        return Err("request_id".into());
    }
    if str_of(&body, "action").as_deref() != Some(order.action.as_str()) {
        return Err("action".into());
    }
    if str_of(&body, "requested_by").as_deref() != Some(requested_by.as_str()) {
        return Err("requested_by".into());
    }
    let ttl = match body.get("ttl_seconds") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or("ttl_seconds is not a u64")?),
    };
    if ttl != order.ttl_s {
        return Err("ttl_seconds".into());
    }
    let none = Value::Null;
    let params = body.get("parameters").unwrap_or(&none);
    let p_str = |k: &str| str_of(params, k);
    let p_f64 = |k: &str| params.get(k).and_then(Value::as_f64);
    let target_ok = match (&order.target, order.action.as_str()) {
        (Target::None, "restrict_motion" | "rollback_config") => true,
        (Target::Motion(m), "restrict_motion") => {
            m.factor.is_none()
                && m.config.is_none()
                && m.to_version.is_none()
                && m.max_linear_speed == p_f64("max_linear_speed")
                && m.max_joint_speed == p_f64("max_joint_speed")
                && m.workspace_zone == p_str("workspace_zone")
        }
        (Target::Motion(m), "rollback_config") => {
            m.factor.is_none()
                && m.max_linear_speed.is_none()
                && m.max_joint_speed.is_none()
                && m.workspace_zone.is_none()
                && m.config.as_deref() == Some(p_str("config").as_deref().unwrap_or("profile"))
                && m.to_version == p_str("to_version")
        }
        (Target::Participant { guid_prefix, .. }, "quarantine_node") => p_str("participant_guid")
            .and_then(|g| g.parse::<GuidPrefix>().ok())
            .is_some_and(|g| g == *guid_prefix),
        (Target::Node { name }, "quarantine_node") => match p_str("participant_guid") {
            Some(g) => g.parse::<GuidPrefix>().is_err() && &g == name,
            None => p_str("node").as_deref() == Some(name.as_str()),
        },
        (Target::None, "quarantine_node") => {
            p_str("participant_guid").is_none() && p_str("node").is_none()
        }
        (Target::None, _) => true,
        _ => false,
    };
    if !target_ok {
        return Err("target".into());
    }
    Ok(())
}

fn revert(req: &SocRequest) {
    let keys = keys();
    let mut replay = store("r");
    let Ok((requested_by, approvers)) =
        verify_revert(ACTION, Some(req), &cx(&keys, ROBOT), &mut replay)
    else {
        return;
    };
    assert!(
        signed_by_harness(req),
        "accepted a revert the key did not sign"
    );
    assert_eq!(req.method, "POST");
    assert!(!requested_by.is_empty() && requested_by.chars().count() <= 100);
    assert!(approvers.len() <= MAX_APPROVERS);
    let again = verify_revert(ACTION, Some(req), &cx(&keys, ROBOT), &mut replay)
        .expect_err("revert replayed");
    assert_eq!(again.code, codes::SOC_NONCE_REPLAYED);
    let mut other = store("o");
    assert!(
        verify_revert("act-2", Some(req), &cx(&keys, ROBOT), &mut other).is_err(),
        "a revert of {ACTION} lifted act-2"
    );
}

/// A control-plane order for `action` (target per action).
pub fn order(id: &str, action: robodr_responder::ActionId) -> Order {
    use robodr_executor::order::{Locator, Target};
    use robodr_responder::{
        ActionId, Connectivity, ControlMode, MissionPhase, Morphology, OperationalContext,
        PlatformFamily, SafetyState,
    };
    let target = match action {
        ActionId::QuarantineNode => Target::Participant {
            guid_prefix: "0110a2b3c4d5e6f701000000".parse().expect("GUID prefix"),
            locators: vec![Locator {
                ip: std::net::IpAddr::from([10, 0, 0, 7]),
                port: 7410,
            }],
            guid_only: false,
            excluded: Vec::new(),
            addresses: Vec::new(),
            excluded_addresses: Vec::new(),
            evidence_truncated: false,
        },
        _ => Target::None,
    };
    Order {
        id: id.into(),
        action,
        target,
        ttl_s: Some(60),
        judged_state: SafetyState::Idle,
        context: OperationalContext {
            platform: PlatformFamily::Ugv,
            morphology: Morphology::WheeledMobile,
            phase: MissionPhase::Parked,
            connectivity: Connectivity::Connected,
            control: ControlMode::Autonomous,
            operator_present: true,
            profile_locked: true,
        },
        plan_morphology: Morphology::WheeledMobile,
        human_approved: true,
        replay: false,
        origin: Origin::ControlPlane {
            key_id: KEY_ID.into(),
            requested_by: "analyst".into(),
        },
        issued_ms: NOW_S * 1000,
        soc: None,
    }
}

/// The revert request for `ACTION` (unsigned).
pub fn revert_request() -> SocRequest {
    SocRequest {
        method: "POST".into(),
        target: format!("/api/v2/robots/{ROBOT}/action-requests/{ACTION}/revert"),
        key_id: KEY_ID.into(),
        timestamp: NOW_S,
        nonce: "fuzz-nonce-revert-0001".into(),
        signature: "00".repeat(64),
        body: r#"{"requested_by":"analyst","reason":"contained"}"#.into(),
    }
}

fn seed(sel: u8, v: &impl serde::Serialize) -> Vec<u8> {
    let mut b = vec![sel];
    b.extend_from_slice(&serde_json::to_vec(v).expect("seed serialises"));
    b
}

/// The committed seed corpus (`fuzz/corpus/executor_soc/`): every entry
/// point with an input it accepts (the planner order: refused, as it must).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    use robodr_responder::ActionId;
    let isolate = order("req-isolate-1", ActionId::IsolateNetwork);
    let quarantine = order("req-quarantine-1", ActionId::QuarantineNode);
    let signed = testing::sign_order(
        quarantine.clone(),
        &SEED,
        ROBOT,
        NOW_S,
        "fuzz-nonce-signed-0001",
    );
    let r = revert_request();
    let rs = SocRequest::sign(
        &SEED,
        ROBOT,
        &r.key_id,
        &r.method,
        &r.target,
        r.timestamp,
        &r.nonce,
        &r.body,
    );
    let mut planner = isolate.clone();
    planner.origin = Origin::Planner {
        rule: "robodr.rule.x".into(),
        finding_id: None,
    };
    vec![
        ("0-isolate", seed(0, &isolate)),
        ("0-quarantine", seed(0, &quarantine)),
        ("0-planner", seed(0, &planner)),
        ("1-signed-quarantine", seed(1, &signed)),
        ("2-revert", seed(2, &r)),
        ("3-signed-revert", seed(3, &rs)),
    ]
}
