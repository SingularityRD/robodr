//! The control-plane action API end to end: the real daemon, a test SOC key,
//! signed requests over the unix socket and TCP, judgment against the live
//! safety state (PLC socket feed), the black-box records (verified, and the
//! recorded SOC signature re-verified offline), the answer signature (finding
//! key) and the observe-only findings for failed authentication and invalid
//! requests. Nothing is ever executed: accepted means recorded.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use common::pcap::robot_profile;
use common::*;
use robodr_agentd::control::auth::{answer_message, signing_message, API_VERSION};
use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::{Ed25519SigningKey, KeyFile};
use serde_json::{json, Value};

const SOC_ID: &str = "soc:autosecops:1";
const SOC_SEED: [u8; 32] = [0x51; 32];
const FINDING_ID: &str = "finding:ugv-007:1";
const FINDING_SEED: [u8; 32] = [0x52; 32];

fn soc() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(SOC_ID, &SOC_SEED).unwrap()
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn nonce() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "test-nonce-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// One signed request's parts.
#[derive(Clone)]
struct Req {
    method: &'static str,
    target: String,
    body: Vec<u8>,
    key_id: String,
    ts: u64,
    nonce: String,
    sig: String,
}

fn signed(method: &'static str, target: &str, body: &[u8]) -> Req {
    signed_with(&soc(), SOC_ID, method, target, body, now_s())
}

fn signed_with(
    key: &Ed25519SigningKey,
    key_id: &str,
    method: &'static str,
    target: &str,
    body: &[u8],
    ts: u64,
) -> Req {
    let nonce = nonce();
    let msg = signing_message(method, target, ROBOT, key_id, ts, &nonce, body);
    Req {
        method,
        target: target.into(),
        body: body.to_vec(),
        key_id: key_id.into(),
        ts,
        nonce,
        sig: to_hex(&key.sign_message(&msg)),
    }
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
    raw_body: Vec<u8>,
}

fn exchange<S: Read + Write>(mut s: S, r: &Req) -> Resp {
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: robot\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         X-RoboDR-Key-Id: {}\r\nX-RoboDR-Timestamp: {}\r\nX-RoboDR-Nonce: {}\r\n\
         X-RoboDR-Signature: {}\r\n\r\n",
        r.method,
        r.target,
        r.body.len(),
        r.key_id,
        r.ts,
        r.nonce,
        r.sig
    )
    .into_bytes();
    head.extend_from_slice(&r.body);
    s.write_all(&head).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8(out[..split].to_vec()).unwrap();
    let raw_body = out[split + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: serde_json::from_slice(&raw_body).unwrap_or(Value::Null),
        raw_body,
    }
}

fn unix(path: &Path, r: &Req) -> Resp {
    exchange(UnixStream::connect(path).unwrap(), r)
}

fn tcp(port: u16, r: &Req) -> Resp {
    exchange(TcpStream::connect(("127.0.0.1", port)).unwrap(), r)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn submit_body(id: &str, action: &str, params: Value, ttl: Option<u64>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "request_id": id,
        "action": action,
        "parameters": params,
        "ttl_seconds": ttl,
        "reason": "rogue /cmd_vel writer (test)",
        "requested_by": "analyst@soc",
        "source": "autosecops",
        "authority": "request",
    }))
    .unwrap()
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

fn write_finding_key(dir: &Path) -> PathBuf {
    let p = dir.join("finding.key");
    KeyFile::ed25519_from_seed(&FINDING_SEED, Some(FINDING_ID))
        .unwrap()
        .write_new(&p)
        .unwrap();
    p
}

type DaemonThread = std::thread::JoinHandle<(Result<robodr_agentd::Summary, String>, String)>;

fn spawn(r: robodr_agentd::Resolved) -> (Arc<AtomicBool>, DaemonThread) {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    (stop, h)
}

fn set_state(plc: &mut UnixStream, spool: &Path, state: &str) {
    writeln!(plc, "{{\"state\":\"{state}\"}}").unwrap();
    plc.flush().unwrap();
    wait_for(10, state, || {
        let st = status(spool)?;
        (st["safety_state"] == state).then_some(())
    });
}

fn notes(blackbox: &Path, kind: &str) -> Vec<Value> {
    records(blackbox)
        .iter()
        .filter_map(|r| serde_json::from_slice::<Value>(&r.payload).ok())
        .filter(|v| v["kind"] == kind)
        .collect()
}

#[test]
fn signed_requests_are_judged_recorded_and_never_executed() {
    let s = setup("cp-e2e", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let safety = s.dir.join("safety.sock");
    let control = s.dir.join("control.sock");
    let soc_pub = write_soc_pub(&s.dir);
    let finding_key = write_finding_key(&s.dir);
    let port = free_port();
    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": events}]),
        json!({}),
    );
    cfg["context"] = json!({});
    cfg["safety_feed"] = json!({"socket": {"path": safety, "stale_after_ms": 600000}});
    cfg["finding_signing"] = json!({"key_file": finding_key});
    cfg["control_plane"] = json!({
        "listen_tcp": format!("127.0.0.1:{port}"),
        "unix_socket": control,
        "soc_keys": [soc_pub],
        "rate_per_minute": 600,
        "burst": 100,
    });
    let (stop, h) = spawn(s.resolve(&cfg));
    let mut plc = wait_for(5, "safety socket", || UnixStream::connect(&safety).ok());
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    set_state(&mut plc, &s.spool, "moving_slow");

    let base = format!("/api/v1/robots/{ROBOT}");
    let requests = format!("{base}/action-requests");

    // The robot snapshot: live safety state, and it says it executes nothing.
    let r = unix(&control, &signed("GET", &base, b""));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["robot_id"], ROBOT);
    assert_eq!(r.body["safety_state"]["state"], "moving_slow");
    assert_eq!(r.body["safety_state"]["source"], "safety_feed");
    assert_eq!(r.body["executes_actions"], false);
    assert_eq!(r.body["mode"], "enforce");
    // The answer is signed with the finding key, bound to the request.
    let finding_pub = KeyFile::ed25519_from_seed(&FINDING_SEED, None)
        .unwrap()
        .public_key()
        .unwrap();
    let check_answer = |req: &Req, resp: &Resp| {
        let h = resp
            .headers
            .iter()
            .find(|(n, _)| n == "x-robodr-answer-signature")
            .map(|(_, v)| v.clone())
            .expect("answer signature");
        let sig = h.split("sig=").nth(1).unwrap();
        assert!(h.contains(&format!("key_id={FINDING_ID}")), "{h}");
        let msg = answer_message(&req.sig, resp.status, &resp.raw_body);
        assert!(robodr_blackbox::sign_ed25519::verify(
            &finding_pub,
            &msg,
            &robodr_blackbox::crypto::from_hex(sig).unwrap()
        ));
    };

    // Accepted = recorded as a plan, not executed.
    let id = "robot_restrict_motion:ugv-007:00112233aabbccdd";
    let req = signed(
        "POST",
        &requests,
        &submit_body(
            id,
            "restrict_motion",
            json!({"max_linear_speed": 0.5}),
            Some(600),
        ),
    );
    let r = unix(&control, &req);
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["request_id"], id);
    assert_eq!(r.body["status"], "recorded_not_executed", "{}", r.body);
    assert_eq!(r.body["executed"], false);
    assert_eq!(r.body["state"]["decision"], "accepted");
    assert_eq!(r.body["state"]["executor"], "recording");
    assert_eq!(r.body["state"]["ladder_step"], "limit_motion");
    assert_eq!(r.body["state"]["safety_state"], "moving_slow");
    assert_eq!(r.body["state"]["plan_actions"][1]["factor"], 0.5);
    let evidence = r.body["state"]["evidence"].as_str().unwrap().to_string();
    assert!(
        evidence.starts_with("robodr-blackbox://ugv-007/"),
        "{evidence}"
    );
    check_answer(&req, &r);

    // The exact same bytes again: a replay.
    let r = unix(&control, &req);
    assert_eq!(r.status, 401);
    assert_eq!(r.body["error"]["code"], "replayed_nonce");
    // Idempotent resubmission (fresh nonce): the stored request.
    let again = signed(
        "POST",
        &requests,
        &submit_body(
            id,
            "restrict_motion",
            json!({"max_linear_speed": 0.5}),
            Some(600),
        ),
    );
    let r = unix(&control, &again);
    assert_eq!(r.body["duplicate"], true);
    assert_eq!(r.body["status"], "recorded_not_executed");
    // Read it back over TCP (percent-encoded id, as AutoSecOps sends it).
    let get = format!("{requests}/{}", id.replace(':', "%3A"));
    let r = tcp(port, &signed("GET", &get, b""));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["status"], "recorded_not_executed");
    assert_eq!(r.body["state"]["evidence"], evidence.as_str());

    // Authentication failures: tampered body, unknown key, stale clock,
    // another robot, no credentials at all.
    let mut tampered = signed(
        "POST",
        &requests,
        &submit_body("t1", "safe_pause", json!({}), None),
    );
    tampered.body = submit_body("t1", "request_safe_state", json!({}), None);
    assert_eq!(
        unix(&control, &tampered).body["error"]["code"],
        "bad_signature"
    );
    let stranger = Ed25519SigningKey::from_seed("intruder", &[0x99; 32]).unwrap();
    let r = unix(
        &control,
        &signed_with(&stranger, "intruder", "GET", &base, b"", now_s()),
    );
    assert_eq!(
        (r.status, r.body["error"]["code"].as_str()),
        (401, Some("unknown_key"))
    );
    let r = unix(
        &control,
        &signed_with(&soc(), SOC_ID, "GET", &base, b"", now_s() - 3600),
    );
    assert_eq!(r.body["error"]["code"], "stale_timestamp");
    let mut other_robot = signed("GET", "/api/v1/robots/ugv-008", b"");
    other_robot.sig = {
        let msg = signing_message(
            "GET",
            "/api/v1/robots/ugv-008",
            "ugv-008",
            SOC_ID,
            other_robot.ts,
            &other_robot.nonce,
            b"",
        );
        to_hex(&soc().sign_message(&msg))
    };
    assert_eq!(
        unix(&control, &other_robot).body["error"]["code"],
        "bad_signature"
    );
    let mut raw = UnixStream::connect(&control).unwrap();
    raw.write_all(b"GET /api/v1/robots/ugv-007 HTTP/1.1\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    raw.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 401"), "{out}");

    // Authenticated but invalid: refused and recorded, never judged.
    let r = unix(
        &control,
        &signed(
            "POST",
            &requests,
            &submit_body("bad1", "unlock_brakes", json!({}), None),
        ),
    );
    assert_eq!(
        (r.status, r.body["error"]["code"].as_str()),
        (400, Some("unknown_action"))
    );
    let r = tcp(
        port,
        &signed(
            "POST",
            &requests,
            &submit_body("bad2", "isolate_network", json!({}), None),
        ),
    );
    assert_eq!(r.body["error"]["code"], "ttl_required");
    let r = unix(
        &control,
        &signed(
            "POST",
            &requests,
            &submit_body("bad3", "safe_pause", json!({"linear_x": 2.0}), None),
        ),
    );
    assert_eq!(r.body["error"]["code"], "unknown_field");

    // E-stop: the safety system has authority; the request is refused.
    set_state(&mut plc, &s.spool, "estop_active");
    let stop_id = "robot_request_safe_state:ugv-007";
    let r = unix(
        &control,
        &signed(
            "POST",
            &requests,
            &submit_body(stop_id, "request_safe_state", json!({}), None),
        ),
    );
    assert_eq!(r.body["status"], "refused", "{}", r.body);
    assert_eq!(r.body["refusal"]["code"], "safety_system_engaged");
    assert_eq!(r.body["refusal"]["safety_state"], "estop_active");
    assert_eq!(r.body["executed"], false);

    // Revert of the recorded plan: it never took effect.
    let rv =
        serde_json::to_vec(&json!({"reason": "false positive", "requested_by": "analyst@soc"}))
            .unwrap();
    let r = unix(
        &control,
        &signed(
            "POST",
            &format!("{requests}/{}/revert", id.replace(':', "%3A")),
            &rv,
        ),
    );
    assert_eq!(r.body["status"], "not_applied", "{}", r.body);
    // The irreversible one is not reverted by request.
    let r = unix(
        &control,
        &signed(
            "POST",
            &format!("{requests}/{}/revert", stop_id.replace(':', "%3A")),
            &rv,
        ),
    );
    assert_eq!(r.body["refusal"]["code"], "not_reversible");

    // The failure findings are raised (health_report_ms is 0 in tests).
    wait_for(10, "control-plane findings", || {
        let found = spooled(&s.spool);
        let rs = rules(&found);
        (rs.iter()
            .any(|r| r == "robot.agent.control_plane_unauthenticated")
            && rs.iter().any(|r| r == "robot.agent.control_plane_invalid"))
        .then_some(())
    });
    let st = status(&s.spool).unwrap();
    let cp = &st["control_plane"];
    assert_eq!(cp["api"], API_VERSION);
    assert_eq!(cp["executes_actions"], false);
    assert_eq!(cp["recorded_not_executed"], 1, "{cp}");
    assert_eq!(cp["refused"], 1, "{cp}");
    assert_eq!(cp["invalid"], 3, "{cp}");
    assert_eq!(cp["duplicates"], 1, "{cp}");
    assert!(cp["unauthenticated"].as_u64().unwrap() >= 6, "{cp}");
    assert_eq!(cp["listening"].as_array().unwrap().len(), 2);

    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    let sum = res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert!(log.contains("control plane on"), "{log}");
    assert!(!control.exists(), "control socket removed at shutdown");

    // The black box verifies, and holds every decision.
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
    let reqs = notes(&s.blackbox, "robodr.control_plane_request");
    assert_eq!(reqs.len(), 2, "{reqs:#?}");
    let accepted = reqs
        .iter()
        .find(|n| n["decision"] == "accepted")
        .expect("accepted note");
    assert_eq!(accepted["status"], "recorded_not_executed");
    assert_eq!(accepted["executed"], false);
    assert_eq!(accepted["safety_state"], "moving_slow");
    let refused = reqs.iter().find(|n| n["decision"] == "refused").unwrap();
    assert_eq!(refused["refusal"]["code"], "safety_system_engaged");
    assert_eq!(refused["safety_state"], "estop_active");
    assert_eq!(notes(&s.blackbox, "robodr.control_plane_rejected").len(), 3);
    assert_eq!(notes(&s.blackbox, "robodr.control_plane_revert").len(), 2);
    // The recorded request proves itself: its SOC signature re-verifies
    // offline from the note alone.
    let a = &accepted["auth"];
    let msg = signing_message(
        a["method"].as_str().unwrap(),
        a["target"].as_str().unwrap(),
        ROBOT,
        a["key_id"].as_str().unwrap(),
        a["timestamp"].as_u64().unwrap(),
        a["nonce"].as_str().unwrap(),
        a["body"].as_str().unwrap().as_bytes(),
    );
    assert!(robodr_blackbox::sign_ed25519::verify(
        &soc().public_key(),
        &msg,
        &robodr_blackbox::crypto::from_hex(a["signature"].as_str().unwrap()).unwrap()
    ));
    // The findings are observe-only self-health.
    for (_, env) in found.iter().filter(|(_, e)| {
        e.entity_context
            .rule_id
            .starts_with("robot.agent.control_plane_")
    }) {
        assert_eq!(env.entity_context.mode, robodr_ocsf::Mode::Observe);
    }
}

#[test]
fn off_by_default_and_strict_config() {
    let s = setup("cp-cfg", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": events}]),
        json!({}),
    );
    let r = s.resolve(&cfg);
    assert!(r.control_plane.is_none());
    let soc_pub = write_soc_pub(&s.dir);
    let load = |cp: Value| {
        let mut c = cfg.clone();
        c["control_plane"] = cp;
        robodr_agentd::load(&s.write_config(&c))
    };
    let e =
        load(json!({"unix_socket": s.dir.join("c.sock"), "soc_keys": [soc_pub], "verbose": true}))
            .unwrap_err();
    assert!(e.contains("verbose"), "{e}");
    let e = load(json!({"unix_socket": events, "soc_keys": [soc_pub]})).unwrap_err();
    assert!(e.contains("also an event_inputs"), "{e}");
    let e =
        load(json!({"unix_socket": s.spool.join("c.sock"), "soc_keys": [soc_pub]})).unwrap_err();
    assert!(e.contains("spool.dir"), "{e}");
    let e = load(json!({"listen_tcp": "192.0.2.1:8787", "soc_keys": [soc_pub]})).unwrap_err();
    assert!(e.contains("loopback"), "{e}");
    let ok = load(json!({"listen_tcp": "127.0.0.1:8787", "soc_keys": [soc_pub]})).unwrap();
    let spec = ok.control_plane.unwrap();
    assert_eq!(spec.keys.len(), 1);
    assert_eq!(spec.keys[0].key_id, SOC_ID);
    // Running without the section: no listener, no status block.
    let (stop, h) = spawn(r);
    wait_for(5, "status", || status(&s.spool));
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    let st = status(&s.spool).unwrap();
    assert!(st.get("control_plane").is_none());
    assert!(!log.contains("control plane on"));
}
