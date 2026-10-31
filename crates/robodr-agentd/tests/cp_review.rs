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

/// The sealing of a replay store in a test directory (gap 1).
fn seal() -> robodr_agentd::control::journal::Sealing {
    robodr_agentd::control::journal::Sealing::new(
        robodr_agentd::control::journal::Sealing::derive_key(&[0x42; 32]).unwrap(),
    )
}

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

fn corrupt_last_lines(p: &std::path::Path, k: usize) {
    let mut text = std::fs::read(p).unwrap();
    let starts: Vec<usize> = std::iter::once(0)
        .chain(
            text.iter()
                .enumerate()
                .filter(|(_, b)| **b == b'\n')
                .map(|(i, _)| i + 1),
        )
        .collect();
    let lines = starts.len() - 1;
    for l in lines - k..lines {
        text[starts[l] + 70] ^= 0x01;
    }
    std::fs::write(p, &text).unwrap();
}

/// Review finding 4 (nonce store): nonces in damaged trailing lines used
/// to be forgotten (cut as a torn tail) and accepted again. Damage now
/// fences the store: a replay of a lost nonce is refused.
#[test]
fn nonce_journal_tail_damage_fences_the_store() {
    use robodr_agentd::control::auth::{AuthFailure, ReplayGuard, MAX_NONCES, NONCE_JOURNAL};
    let dir = tmp("nonces");
    let now = 1_800_000_000;
    drop(ReplayGuard::persistent(&dir, 30, MAX_NONCES, now - 3600, &seal()).unwrap());
    let (mut g, _) = ReplayGuard::persistent(&dir, 30, MAX_NONCES, now, &seal()).unwrap();
    for n in 0..3 {
        g.check("soc-1", &format!("nonce-{n}"), now, now).unwrap();
    }
    drop(g);
    corrupt_last_lines(&dir.join(NONCE_JOURNAL), 2);
    let (mut g, load) = ReplayGuard::persistent(&dir, 30, MAX_NONCES, now + 1, &seal()).unwrap();
    assert!(load.damaged >= 2, "{load:?}");
    assert!(load.fence.is_some(), "{load:?}");
    for n in 0..3 {
        let r = g.check("soc-1", &format!("nonce-{n}"), now, now + 1);
        assert!(
            matches!(r, Err(AuthFailure::Replayed | AuthFailure::Fenced)),
            "nonce-{n} accepted again: {r:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review finding 4 (refuse mode): ids the damaged journal lost and the
/// black box could not restore, or every unknown id when the black box
/// could not be read, are refused instead of judged again.
#[test]
fn unreconciled_request_ids_are_refused() {
    let mut e = Engine::new(
        "ugv-007",
        16,
        Box::new(robodr_agentd::control::api::RecordingExecutor),
    );
    let mut h = FakeHost::new();
    e.refuse_ids(vec!["lost-1".into()], None);
    let a = e.handle(
        &submit("lost-1", "safe_pause", json!({}), None),
        &meta(),
        &mut h,
    );
    assert_eq!(
        (a.status, a.body["error"]["code"].as_str()),
        (503, Some("state_unavailable")),
        "{}",
        a.body
    );
    let b = e.handle(
        &submit("new-1", "safe_pause", json!({}), None),
        &meta(),
        &mut h,
    );
    assert_eq!(b.body["status"], "recorded_not_executed", "{}", b.body);
    e.refuse_ids(Vec::new(), Some("black box unreadable".into()));
    let c = e.handle(
        &submit("new-2", "safe_pause", json!({}), None),
        &meta(),
        &mut h,
    );
    assert_eq!(c.status, 503, "{}", c.body);
    // A stored request is still answered (a duplicate, not judged).
    let d = e.handle(
        &submit("new-1", "safe_pause", json!({}), None),
        &meta(),
        &mut h,
    );
    assert_eq!(d.body["duplicate"], true, "{}", d.body);
    assert_eq!(h.notes.len(), 1);
}

/// Review finding 5: the replay fence must cover every timestamp that may
/// have been accepted before: (a) up to now + skew, not now; (b) whenever
/// the nonce journal had to be created (a wiped state directory looks
/// like a first install); (c) when the wall clock went back below the
/// persisted high-water mark (entries dropped while it was ahead).
#[test]
fn the_replay_fence_covers_the_window_creation_and_clock_steps() {
    use robodr_agentd::control::auth::{AuthFailure, ReplayGuard, MAX_NONCES, NONCE_JOURNAL};
    let skew = 30;
    let t = 1_800_000_000u64;
    // (b) + (a): a created journal fences up to now + skew.
    let dir = tmp("fence-created");
    let (mut g, load) = ReplayGuard::persistent(&dir, skew, MAX_NONCES, t, &seal()).unwrap();
    assert!(load.created);
    assert_eq!(load.fence, Some(t + skew), "{load:?}");
    assert_eq!(
        g.check("soc-1", "n-future", t + skew, t),
        Err(AuthFailure::Fenced),
        "a request signed up to skew ahead may have been seen before the wipe"
    );
    assert_eq!(g.check("soc-1", "n-fresh", t + skew + 1, t + 1), Ok(()));
    drop(g);
    // (a) on damage too.
    let p = dir.join(NONCE_JOURNAL);
    let mut text = std::fs::read(&p).unwrap();
    let mid = text.iter().position(|b| *b == b'\n').unwrap() + 70;
    text[mid] ^= 1;
    std::fs::write(&p, &text).unwrap();
    let (_, load) = ReplayGuard::persistent(&dir, skew, MAX_NONCES, t + 2, &seal()).unwrap();
    assert_eq!(load.fence, Some(t + 2 + skew), "{load:?}");
    let _ = std::fs::remove_dir_all(&dir);

    // (c) across a restart: a nonce accepted at t, dropped (expired) while
    // the clock read t + 100, replayed after the clock went back to t.
    let dir = tmp("fence-clock");
    let (g, _) = ReplayGuard::persistent(&dir, skew, MAX_NONCES, t - 3600, &seal()).unwrap();
    drop(g);
    let (mut g, load) = ReplayGuard::persistent(&dir, skew, MAX_NONCES, t, &seal()).unwrap();
    assert_eq!(load.fence, None, "{load:?}");
    g.check("soc-1", "n-1", t, t).unwrap();
    drop(g);
    let (g, load) = ReplayGuard::persistent(&dir, skew, MAX_NONCES, t + 100, &seal()).unwrap();
    assert_eq!((load.expired, load.fence), (1, None), "{load:?}");
    drop(g);
    let (mut g, load) = ReplayGuard::persistent(&dir, skew, MAX_NONCES, t, &seal()).unwrap();
    // The fence is the newest dropped pair's dead_after (signed t, dead
    // after t + skew + 1) plus the skew, not the clock at the drop (M4):
    // a forward step before the drop does not lock the API out.
    assert_eq!(load.fence, Some(t + skew + 1 + skew), "{load:?}");
    assert_eq!(
        g.check("soc-1", "n-1", t, t),
        Err(AuthFailure::Fenced),
        "replayed after the clock went back"
    );
    drop(g);
    let _ = std::fs::remove_dir_all(&dir);

    // (c) while running: pairs dropped (cache full) while the clock read
    // t + 100, then the clock steps back to t.
    let dir = tmp("fence-run");
    let (g, _) = ReplayGuard::persistent(&dir, skew, 2, t - 3600, &seal()).unwrap();
    drop(g);
    let (mut g, _) = ReplayGuard::persistent(&dir, skew, 2, t, &seal()).unwrap();
    g.check("soc-1", "n-a", t, t).unwrap();
    g.check("soc-1", "n-b", t, t).unwrap();
    g.check("soc-1", "n-c", t + 100, t + 100).unwrap();
    assert_eq!(
        g.check("soc-1", "n-a", t, t),
        Err(AuthFailure::Fenced),
        "replayed after the clock went back while running"
    );
    assert_eq!(g.fence(), Some(t + skew + 1 + skew));
    // A step back with nothing dropped since is harmless (no fence).
    let dir2 = tmp("fence-run2");
    let (g, _) = ReplayGuard::persistent(&dir2, skew, MAX_NONCES, t - 3600, &seal()).unwrap();
    drop(g);
    let (mut g, _) = ReplayGuard::persistent(&dir2, skew, MAX_NONCES, t + 1, &seal()).unwrap();
    g.check("soc-1", "n-x", t + 1, t + 1).unwrap();
    assert_eq!(g.check("soc-1", "n-y", t, t), Ok(()));
    assert_eq!(g.fence(), None);
    let _ = std::fs::remove_dir_all(&dir2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review finding 6: after an executor reboot the executor holds a
/// verified action (not re-armed until a fresh safety state); the request
/// used to read plain `verified`. Answers now say it: `in_force: false`
/// and `state.executor_state: "held"`, without journalling it (the
/// executor's re-arm brings it back).
#[test]
fn a_held_action_is_not_reported_in_force() {
    use robodr_executor::engine::{Outcome, Status as ExStatus};
    let dir = tmp("held");
    let link = link(&dir);
    let mut e = Engine::new(
        "ugv-007",
        16,
        Box::new(link.control_executor(Morphology::WheeledMobile)),
    );
    let mut h = FakeHost::new();
    let id = "q-1";
    let a = e.handle(
        &submit(id, "quarantine_node", json!({"node": "/rogue"}), None),
        &meta(),
        &mut h,
    );
    assert_eq!(a.body["status"], "pending", "{}", a.body);
    assert_eq!(a.body["in_force"], false, "{}", a.body);
    let outcome = |status| Outcome {
        id: id.into(),
        status,
        action: Some(robodr_responder::ActionId::QuarantineNode),
        refusal: None,
        error: None,
        applied_ms: Some(1),
        deadline_ms: None,
        duplicate: false,
        note: None,
        quarantine: None,
    };
    link.put(outcome(ExStatus::Verified));
    let get = |e: &mut Engine, h: &mut FakeHost| e.handle(&Call::Get(id.into()), &meta(), h).body;
    let v = get(&mut e, &mut h);
    assert_eq!(v["status"], "verified", "{v}");
    assert_eq!(v["in_force"], true, "{v}");
    assert!(v["state"].get("executor_state").is_none(), "{v}");
    // The executor rebooted and holds it.
    link.put(outcome(ExStatus::Held));
    let v = get(&mut e, &mut h);
    assert_eq!(v["status"], "verified", "the journalled state stays: {v}");
    assert_eq!(v["in_force"], false, "{v}");
    assert_eq!(v["state"]["executor_state"], "held", "{v}");
    // Re-armed: in force again.
    link.put(outcome(ExStatus::Verified));
    let v = get(&mut e, &mut h);
    assert_eq!(v["in_force"], true, "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}
