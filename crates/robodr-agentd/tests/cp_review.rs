//! Regression tests for the control plane v2 review (findings 3 to 9) that
//! need no running daemon: the engine with the real executor link, the
//! journals, the replay fence, the evidence store. Each failed before its
//! fix; the daemon-level ones live in `control_plane.rs`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use robodr_agentd::control::api::{
    parse_revert, parse_submit, Call, Engine, EnvelopeCaps, Host, Meta,
};
use robodr_agentd::executor_link::{ExecutorLink, ExecutorSpec, SafetyCell, Staged};
use robodr_executor::proto::Key;
use robodr_responder::{
    Connectivity, ControlMode, MissionPhase, Morphology, OperationalContext, PlatformFamily,
    ResponsePolicy, SafetyState,
};
use serde_json::{json, Value};

fn tmp(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-cp-review-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct FakeHost {
    policy: ResponsePolicy,
    notes: Vec<Value>,
    fail: bool,
}

impl FakeHost {
    fn new() -> Self {
        let mut p = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        p.oem_validated = true;
        p.morphology = Morphology::WheeledMobile;
        Self {
            policy: p,
            notes: Vec::new(),
            fail: false,
        }
    }
}

impl Host for FakeHost {
    fn safety_state(&mut self) -> SafetyState {
        SafetyState::Idle
    }
    fn safety_source(&self) -> &'static str {
        "configuration"
    }
    fn context(&self) -> OperationalContext {
        OperationalContext {
            platform: PlatformFamily::Ugv,
            morphology: Morphology::WheeledMobile,
            phase: MissionPhase::Transit,
            connectivity: Connectivity::Connected,
            control: ControlMode::Autonomous,
            operator_present: true,
            profile_locked: true,
        }
    }
    fn policy(&self) -> &ResponsePolicy {
        &self.policy
    }
    fn caps(&self) -> EnvelopeCaps {
        EnvelopeCaps::default()
    }
    fn health(&self) -> &'static str {
        "ok"
    }
    fn wall_ms(&self) -> u64 {
        1_000_000
    }
    fn record(&mut self, _: &str, note: &Value) -> Result<String, String> {
        if self.fail {
            return Err("black box unavailable".into());
        }
        self.notes.push(note.clone());
        Ok(format!(
            "robodr-blackbox://ugv-007/0/{}?sha256=00",
            self.notes.len()
        ))
    }
}

fn meta() -> Meta {
    Meta {
        key_id: "soc-1".into(),
        ..Meta::default()
    }
}

fn submit(id: &str, action: &str, params: Value, ttl: Option<u64>) -> Call {
    let body = serde_json::to_vec(&json!({
        "request_id": id, "action": action, "parameters": params, "ttl_seconds": ttl,
        "reason": "test", "requested_by": "analyst@soc", "source": "soc-a",
        "authority": "request",
    }))
    .unwrap();
    Call::Submit(parse_submit(&body).unwrap())
}

/// The real link, pointed at a socket nobody listens on (nothing is ever
/// dispatched in these tests; only what it stages is looked at).
fn link(dir: &std::path::Path) -> ExecutorLink {
    ExecutorLink::start(
        &ExecutorSpec {
            socket: dir.join("nobody.sock"),
            key: Key::from_bytes([7; 32]),
            planner_orders: false,
            timeout: Duration::from_millis(500),
        },
        SafetyCell::default(),
    )
    .unwrap()
}

fn staged_ids(v: &[Staged]) -> Vec<String> {
    v.iter()
        .map(|s| match s {
            Staged::Submit(o) => format!("submit {} {:?}", o.id, o.action),
            Staged::Evidence(o) => format!("evidence {} {:?}", o.id, o.action),
            Staged::Revert { id, .. } => format!("revert {id}"),
        })
        .collect()
}

/// Review finding 3: a request answered "failed: nothing was decided"
/// must leave nothing staged for the executor; a retry with the same
/// request_id but another action in the same poll batch used to dispatch
/// both orders.
#[test]
fn a_failed_submit_or_revert_stages_nothing_for_the_executor() {
    let dir = tmp("stage");
    let link = link(&dir);
    let mut e = Engine::new(
        "ugv-007",
        16,
        Box::new(link.control_executor(Morphology::WheeledMobile)),
    );
    let mut h = FakeHost::new();
    h.fail = true;
    let a = e.handle(
        &submit("x-1", "isolate_network", json!({}), Some(600)),
        &meta(),
        &mut h,
    );
    assert_eq!(a.body["status"], "failed", "{}", a.body);
    h.fail = false;
    let b = e.handle(
        &submit("x-1", "quarantine_node", json!({"node": "/rogue"}), None),
        &meta(),
        &mut h,
    );
    assert_eq!(b.body["status"], "pending", "{}", b.body);
    let staged = link.take_staged();
    assert_eq!(
        staged_ids(&staged),
        vec!["submit x-1 QuarantineNode".to_string()]
    );
    // Even if something stale were staged, the daemon releases an order
    // only when it matches the stored request.
    let stored = e.get("x-1");
    for s in &staged {
        if let Staged::Submit(o) = s {
            assert!(robodr_agentd::executor_link::release_ok(o, stored));
            let mut other = o.clone();
            other.action = robodr_responder::ActionId::IsolateNetwork;
            assert!(!robodr_agentd::executor_link::release_ok(&other, stored));
            assert!(!robodr_agentd::executor_link::release_ok(o, None));
        }
    }
    // A revert whose note the black box refuses stages nothing either.
    h.fail = true;
    let rv = parse_revert(br#"{"reason":"done","requested_by":"analyst@soc"}"#).unwrap();
    let r = e.handle(&Call::Revert("x-1".into(), rv), &meta(), &mut h);
    assert_eq!(r.body["status"], "failed", "{}", r.body);
    assert!(staged_ids(&link.take_staged()).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
