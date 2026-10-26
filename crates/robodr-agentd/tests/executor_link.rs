//! executor v1 end to end: the real daemon with `control_plane` and
//! `executor.enabled`, an in-process `robodr-executor` server (its engine on
//! an in-memory nftables model: real nftables and real traffic are proven
//! in `crates/robodr-executor/tests/netns.rs`), signed SOC requests, the
//! executor's apply-time safety re-check against agentd's live safety
//! state, request states `pending` → `verified` → `reverted`, executor
//! refusals, `record_evidence` marks and the executor's events in the
//! black box.

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use common::pcap::robot_profile;
use common::*;
use robodr_agentd::control::auth::signing_message;
use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::{Ed25519SigningKey, KeyFile};
use robodr_executor::engine::Engine;
use robodr_executor::nft::Nft;
use robodr_executor::proto::Key;
use serde_json::{json, Value};

const SOC_ID: &str = "soc:soc-a:1";
const SOC_SEED: [u8; 32] = [0x51; 32];
const EXEC_KEY: [u8; 32] = [0x6b; 32];
const PROTECTED_GUID: &str = "0110aaaabbbbccccdddd0000";

fn nonce() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "exec-nonce-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn call(path: &Path, method: &'static str, target: &str, body: &[u8]) -> (u16, Value) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let n = nonce();
    let key = Ed25519SigningKey::from_seed(SOC_ID, &SOC_SEED).unwrap();
    let sig = to_hex(&key.sign_message(&signing_message(
        method, target, ROBOT, SOC_ID, ts, &n, body,
    )));
    let mut req = format!(
        "{method} {target} HTTP/1.1\r\nHost: robot\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nX-RoboDR-Key-Id: {SOC_ID}\r\nX-RoboDR-Timestamp: {ts}\r\n\
         X-RoboDR-Nonce: {n}\r\nX-RoboDR-Signature: {sig}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    let mut s = UnixStream::connect(path).unwrap();
    s.write_all(&req).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = String::from_utf8_lossy(&out[..split])
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (
        status,
        serde_json::from_slice(&out[split + 4..]).unwrap_or(Value::Null),
    )
}

fn submit(control: &Path, id: &str, action: &str, params: Value, ttl: Option<u64>) -> Value {
    let body = serde_json::to_vec(&json!({
        "request_id": id, "action": action, "parameters": params, "ttl_seconds": ttl,
        "reason": "test", "requested_by": "analyst@soc", "source": "soc-a",
        "authority": "request",
    }))
    .unwrap();
    let (st, v) = call(
        control,
        "POST",
        &format!("/api/v1/robots/{ROBOT}/action-requests"),
        &body,
    );
    assert_eq!(st, 200, "{v}");
    v
}

fn get(control: &Path, id: &str) -> Value {
    let (st, v) = call(
        control,
        "GET",
        &format!("/api/v1/robots/{ROBOT}/action-requests/{id}"),
        b"",
    );
    assert_eq!(st, 200, "{v}");
    v
}

fn revert(control: &Path, id: &str) -> Value {
    let body = br#"{"reason":"done","requested_by":"analyst@soc"}"#;
    let (st, v) = call(
        control,
        "POST",
        &format!("/api/v1/robots/{ROBOT}/action-requests/{id}/revert"),
        body,
    );
    assert_eq!(st, 200, "{v}");
    v
}

fn wait_status(control: &Path, id: &str, want: &str) -> Value {
    wait_for(10, want, || {
        let v = get(control, id);
        (v["status"] == want).then_some(v)
    })
}

/// In-memory `nft -j` model (one `inet robodr` table).
#[derive(Clone, Default)]
struct Model(Arc<Mutex<Option<Vec<Value>>>>);

impl Nft for Model {
    fn run(&mut self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let mut t = self.0.lock().unwrap();
        match args {
            ["-j", "-f", "-"] => {
                let batch: Value = serde_json::from_slice(stdin.unwrap()).unwrap();
                let mut cur = t.clone();
                for cmd in batch["nftables"].as_array().unwrap() {
                    if let Some(a) = cmd.get("add") {
                        if let Some(tb) = a.get("table") {
                            if cur.is_none() {
                                cur = Some(vec![json!({ "table": tb })]);
                            }
                        } else if let Some((k, v)) = a.as_object().unwrap().iter().next() {
                            let mut v = v.clone();
                            if let Some(ex) = v.get_mut("expr").and_then(Value::as_array_mut) {
                                for e in ex {
                                    if e.get("counter").is_some() {
                                        *e = json!({"counter": {"packets": 0, "bytes": 0}});
                                    }
                                }
                            }
                            cur.as_mut().unwrap().push(json!({ k.clone(): v }));
                        }
                    } else {
                        cur = None;
                    }
                }
                *t = cur;
                Ok(Vec::new())
            }
            ["-j", "list", "tables"] => {
                let v: Vec<Value> = t
                    .iter()
                    .map(|_| json!({"table": {"family": "inet", "name": "robodr"}}))
                    .collect();
                Ok(serde_json::to_vec(&json!({ "nftables": v })).unwrap())
            }
            ["-j", "list", "table", "inet", "robodr"] => match &*t {
                Some(objs) => Ok(serde_json::to_vec(&json!({ "nftables": objs })).unwrap()),
                None => Err("no table".into()),
            },
            _ => Err("unexpected".into()),
        }
    }
}

struct ExecutorThread {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ExecutorThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn start_executor(dir: &Path, sock: &Path, policy: &Path, model: &Model) -> ExecutorThread {
    let state = dir.join("executor-state");
    std::fs::create_dir_all(&state).unwrap();
    let cfg = robodr_executor::ExecutorConfig::parse(
        &json!({
            "schema": "robodr-executor-config/v1",
            "robot_id": ROBOT,
            "socket": sock,
            "key_file": dir.join("unused.key"),
            "state_dir": state,
            "policy_path": policy,
            "network": {
                "management": [{"cidr": "10.20.0.0/24"}],
                "motion_control_path": [{"guid_prefix": PROTECTED_GUID, "low_level": true}]
            },
            "max_safety_age_ms": 2000
        })
        .to_string(),
    )
    .unwrap()
    .validate()
    .unwrap();
    let pol = robodr_executor::config::load_policy(policy).unwrap();
    let mut engine = Engine::open(
        cfg,
        pol,
        Box::new(model.clone()),
        "test-boot",
        robodr_executor::proto::wall_ms(),
    )
    .unwrap();
    let listener = robodr_executor::server::bind(sock, 0o600).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    let handle = std::thread::spawn(move || {
        let key = Key::from_bytes(EXEC_KEY);
        robodr_executor::server::serve(
            &listener,
            &mut engine,
            &key,
            "test-boot",
            &|| st.load(Ordering::SeqCst),
            &mut |_, _| {},
        );
    });
    ExecutorThread {
        stop,
        handle: Some(handle),
    }
}

fn write_soc_pub(dir: &Path) -> PathBuf {
    let p = dir.join("soc.pub");
    KeyFile::ed25519_from_seed(&SOC_SEED, Some(SOC_ID))
        .unwrap()
        .to_public()
        .unwrap()
        .write_new(&p)
        .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    p
}

fn notes(blackbox: &Path, kind: &str) -> Vec<Value> {
    records(blackbox)
        .iter()
        .filter_map(|r| serde_json::from_slice::<Value>(&r.payload).ok())
        .filter(|v| v["kind"] == kind)
        .collect()
}

#[test]
fn accepted_requests_are_executed_verified_and_reverted_through_the_executor() {
    let s = setup("exec-e2e", &robot_profile(true));
    let safety = s.dir.join("safety.sock");
    let control = s.dir.join("control.sock");
    let exec_sock = s.dir.join("executor.sock");
    let key_file = s.dir.join("executor.key");
    std::fs::write(&key_file, to_hex(&EXEC_KEY)).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let model = Model::default();
    let _exec = start_executor(&s.dir, &exec_sock, &s.policy, &model);

    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        json!({}),
    );
    cfg["context"] = json!({});
    cfg["safety_feed"] = json!({"socket": {"path": safety, "stale_after_ms": 600000}});
    cfg["control_plane"] = json!({
        "unix_socket": control,
        "soc_keys": [write_soc_pub(&s.dir)],
        "rate_per_minute": 600, "burst": 100,
    });
    cfg["executor"] = json!({
        "enabled": true, "socket": exec_sock, "key_file": key_file,
        "planner_orders": false,
    });
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    let mut plc = wait_for(5, "safety socket", || UnixStream::connect(&safety).ok());
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    writeln!(plc, "{{\"state\":\"idle\"}}").unwrap();
    wait_for(10, "idle", || {
        (status(&s.spool)?["safety_state"] == "idle").then_some(())
    });

    // The robot says it executes now.
    let (_, robot) = call(&control, "GET", &format!("/api/v1/robots/{ROBOT}"), b"");
    assert_eq!(robot["executes_actions"], true, "{robot}");
    assert_eq!(robot["executor"], "robodr-executor");

    // isolate_network: pending, then verified (executed), rules installed.
    let v = submit(&control, "iso-1", "isolate_network", json!({}), Some(120));
    assert_eq!(v["status"], "pending", "{v}");
    let v = wait_status(&control, "iso-1", "verified");
    assert_eq!(v["executed"], true);
    assert!(model.0.lock().unwrap().is_some());

    // quarantine_node of a participant: verified; of the protected rt/lowcmd
    // writer: refused by the executor's own check.
    submit(
        &control,
        "q-1",
        "quarantine_node",
        json!({"participant_guid": "0110a2b3c4d5e6f701000000"}),
        None,
    );
    wait_status(&control, "q-1", "verified");
    submit(
        &control,
        "q-2",
        "quarantine_node",
        json!({"participant_guid": PROTECTED_GUID}),
        None,
    );
    let v = wait_status(&control, "q-2", "refused");
    assert_eq!(v["refusal"]["code"], "motion_path", "{v}");
    assert_eq!(v["executed"], false);

    // record_evidence: a black-box mark naming the request note.
    let v = submit(&control, "ev-1", "record_evidence", json!({}), None);
    let req_evidence = v["state"]["evidence"].as_str().unwrap().to_string();
    wait_status(&control, "ev-1", "verified");
    let marks = notes(&s.blackbox, "robodr.evidence_mark");
    assert_eq!(marks.len(), 1);
    assert_eq!(marks[0]["bundle"][0], req_evidence.as_str());

    // restrict_motion: advisory only (no gateway in v1).
    submit(
        &control,
        "m-1",
        "restrict_motion",
        json!({"max_linear_speed": 0.5}),
        Some(60),
    );
    wait_status(&control, "m-1", "recorded_not_executed");

    // Revert: pending, then reverted; the table holds only the quarantine.
    let v = revert(&control, "iso-1");
    assert_eq!(v["status"], "pending", "{v}");
    let v = wait_status(&control, "iso-1", "reverted");
    assert_eq!(v["executed"], true);
    let v = revert(&control, "q-1");
    assert_eq!(v["status"], "pending");
    wait_status(&control, "q-1", "reverted");
    assert!(model.0.lock().unwrap().is_none());

    // The e-stop engages: the control plane refuses before the executor.
    writeln!(plc, "{{\"state\":\"estop_active\"}}").unwrap();
    wait_for(10, "estop", || {
        (status(&s.spool)?["safety_state"] == "estop_active").then_some(())
    });
    let v = submit(&control, "iso-2", "isolate_network", json!({}), Some(60));
    assert_eq!(v["status"], "refused");
    assert!(model.0.lock().unwrap().is_none());

    // The executor's events are in the black box.
    wait_for(10, "executor events", || {
        let evs = notes(&s.blackbox, "robodr.executor_event");
        let kinds: Vec<String> = evs
            .iter()
            .map(|e| e["event"]["kind"].as_str().unwrap_or("").to_string())
            .collect();
        (kinds.contains(&"verified".to_string()) && kinds.contains(&"reverted".to_string()))
            .then_some(())
    });
    let st = status(&s.spool).unwrap();
    assert!(st["executor"]["verified"].as_u64().unwrap() >= 2, "{st}");
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    let sum = res.unwrap();
    assert!(log.contains("executor v1 enabled"), "{log}");
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
}

#[test]
fn unreachable_executor_fails_the_request_and_executes_nothing() {
    let s = setup("exec-down", &robot_profile(true));
    let control = s.dir.join("control.sock");
    let key_file = s.dir.join("executor.key");
    std::fs::write(&key_file, to_hex(&EXEC_KEY)).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        json!({}),
    );
    cfg["context"] = json!({"safety_state": "idle"});
    cfg["control_plane"] = json!({"unix_socket": control, "soc_keys": [write_soc_pub(&s.dir)]});
    cfg["executor"] = json!({
        "enabled": true, "socket": s.dir.join("nobody.sock"), "key_file": key_file,
        "timeout_ms": 500,
    });
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log).map_err(|e| e.to_string())
    });
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    submit(&control, "iso-1", "isolate_network", json!({}), Some(60));
    let v = wait_status(&control, "iso-1", "failed");
    assert!(
        v["state"]["error"]
            .as_str()
            .unwrap()
            .contains("executor unreachable"),
        "{v}"
    );
    assert_eq!(v["executed"], false);
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap().unwrap();
}

#[test]
fn executor_section_is_strict_and_off_by_default() {
    let s = setup("exec-cfg", &robot_profile(true));
    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        json!({}),
    );
    // Off by default.
    let r = s.resolve(&cfg);
    assert!(r.executor.is_none());
    cfg["executor"] = json!({"enabled": false});
    assert!(s.resolve(&cfg).executor.is_none());
    // Enabled needs a key with private permissions.
    cfg["executor"] = json!({"enabled": true});
    assert!(robodr_agentd::load(&s.write_config(&cfg)).is_err());
    let key_file = s.dir.join("executor.key");
    std::fs::write(&key_file, to_hex(&EXEC_KEY)).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    cfg["executor"] = json!({"enabled": true, "key_file": key_file});
    assert!(robodr_agentd::load(&s.write_config(&cfg)).is_err());
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(s.resolve(&cfg).executor.is_some());
    cfg["executor"]["unknown"] = json!(1);
    assert!(robodr_agentd::load(&s.write_config(&cfg)).is_err());
}
