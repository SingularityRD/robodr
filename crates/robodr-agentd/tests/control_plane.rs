//! The control-plane API `robodr-control-plane/v2` end to end: the real
//! daemon, a test SOC key, signed requests over the unix socket, loopback
//! TCP and mutual TLS (test PKI under `tests/data/control-tls/`, made by
//! its `gen.sh`), judgment against the live safety state (PLC socket feed),
//! the black-box records (verified, and the recorded SOC signature
//! re-verified offline), the mandatory answer signature (finding key), the
//! persistent request state and replay store across a restart, the
//! evidence API (export, chunked resumable download, verification with the
//! robot's public keys, tamper detection) and the observe-only findings for
//! failed authentication and invalid requests. Nothing is ever executed:
//! accepted means recorded.

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
use robodr_agentd::control::evidence::{
    manifest_message, parse_signature_header, Manifest, H_MANIFEST_SIGNATURE,
};
use robodr_blackbox::crypto::{from_hex, sha256, to_hex};
use robodr_blackbox::{Bundle, Ed25519SigningKey, KeyFile, Keyring};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{json, Value};

const SOC_ID: &str = "soc:soc-a:1";
const SOC_SEED: [u8; 32] = [0x51; 32];
const FINDING_ID: &str = "finding:ugv-007:1";
const FINDING_SEED: [u8; 32] = [0x52; 32];
const BB_ID: &str = "bb:ugv-007:1";
const BB_SEED: [u8; 32] = [0x53; 32];

fn soc() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(SOC_ID, &SOC_SEED).unwrap()
}

fn finding_pub() -> [u8; 32] {
    KeyFile::ed25519_from_seed(&FINDING_SEED, None)
        .unwrap()
        .public_key()
        .unwrap()
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

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
    raw_body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn request_bytes(r: &Req) -> Vec<u8> {
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
    head
}

/// Parse a complete answer (`None` if there is none).
fn parse_response(out: &[u8]) -> Option<Resp> {
    let split = out.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8(out[..split].to_vec()).ok()?;
    let raw_body = out[split + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")?
        .1
        .parse()
        .ok()?;
    if raw_body.len() != len {
        return None;
    }
    Some(Resp {
        status,
        headers,
        body: serde_json::from_slice(&raw_body).unwrap_or(Value::Null),
        raw_body,
    })
}

fn exchange_raw<S: Read + Write>(mut s: S, raw: &[u8]) -> Result<Resp, String> {
    s.write_all(raw).map_err(|e| e.to_string())?;
    let _ = s.flush();
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => {
                // A TLS peer that closed without close_notify after a full
                // answer is fine; anything else is the error.
                if let Some(r) = parse_response(&out) {
                    return Ok(r);
                }
                return Err(e.to_string());
            }
        }
    }
    parse_response(&out).ok_or_else(|| format!("no answer ({} bytes)", out.len()))
}

fn unix(path: &Path, r: &Req) -> Resp {
    exchange_raw(UnixStream::connect(path).unwrap(), &request_bytes(r)).unwrap()
}

fn tcp(port: u16, r: &Req) -> Resp {
    exchange_raw(
        TcpStream::connect(("127.0.0.1", port)).unwrap(),
        &request_bytes(r),
    )
    .unwrap()
}

fn tls_data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/control-tls")
        .join(name)
}

/// A TLS client trusting the robot CA, with client certificate `client`
/// (`soc`, `soc2`, `soc-expired`, `other`) or none.
fn tls_client(client: Option<&str>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(tls_data("robot-ca.pem")).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let b = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots);
    Arc::new(match client {
        None => b.with_no_client_auth(),
        Some(n) => {
            let chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_file_iter(tls_data(&format!("{n}.pem")))
                    .unwrap()
                    .map(|c| c.unwrap())
                    .collect();
            let key = PrivateKeyDer::from_pem_file(tls_data(&format!("{n}.key"))).unwrap();
            b.with_client_auth_cert(chain, key).unwrap()
        }
    })
}

fn mtls_raw(port: u16, client: Option<&str>, raw: &[u8]) -> Result<Resp, String> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let conn = rustls::ClientConnection::new(
        tls_client(client),
        ServerName::try_from("127.0.0.1").unwrap(),
    )
    .map_err(|e| e.to_string())?;
    exchange_raw(rustls::StreamOwned::new(conn, tcp), raw)
}

fn mtls(port: u16, client: Option<&str>, r: &Req) -> Result<Resp, String> {
    mtls_raw(port, client, &request_bytes(r))
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
        "source": "soc-a",
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

/// A private state directory (0700).
fn state_dir(s: &Setup) -> PathBuf {
    let d = s.dir.join("cp-state");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A replay store from an earlier run (an hour ago): a store created at
    // start is fenced for the clock skew (CP review finding 5).
    let ago = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3600;
    drop(
        robodr_agentd::control::auth::ReplayGuard::persistent(
            &d,
            30,
            robodr_agentd::control::auth::MAX_NONCES,
            ago,
        )
        .unwrap(),
    );
    d
}

/// The robot's TLS files in `dir` (the key copied private, as systemd's
/// credential copy is).
fn tls_section(dir: &Path, pins: &[&str]) -> Value {
    let key = dir.join("cp-tls.key");
    std::fs::copy(tls_data("robot.key"), &key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    for f in ["robot.pem", "soc-ca.pem"] {
        std::fs::copy(tls_data(f), dir.join(f)).unwrap();
        std::fs::set_permissions(dir.join(f), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    json!({
        "cert_chain": dir.join("robot.pem"),
        "key_file": key,
        "client_ca": dir.join("soc-ca.pem"),
        "client_spki_sha256": pins,
    })
}

/// SHA-256 of a test certificate's SPKI (a pin value).
fn spki_pin(name: &str) -> String {
    let c = CertificateDer::pem_file_iter(tls_data(&format!("{name}.pem")))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    to_hex(&robodr_agentd::control::tls::spki_sha256(&c).unwrap())
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

fn finish(stop: Arc<AtomicBool>, h: DaemonThread) -> (robodr_agentd::Summary, String) {
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    let sum = res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    (sum, log)
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

/// The answer signature is there and verifies with the finding key, bound
/// to the request.
fn check_answer(req: &Req, resp: &Resp) {
    let h = resp
        .header("x-robodr-answer-signature")
        .unwrap_or_else(|| panic!("answer signature missing: {resp:?}"));
    let (kid, sig) = parse_signature_header(h).expect("well-formed answer signature");
    assert_eq!(kid, FINDING_ID);
    let msg = answer_message(&req.sig, resp.status, &resp.raw_body);
    assert!(
        robodr_blackbox::sign_ed25519::verify(&finding_pub(), &msg, &sig),
        "answer signature does not verify"
    );
}

fn base_config(s: &Setup, events: &Path) -> Value {
    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": events}]),
        json!({}),
    );
    cfg["finding_signing"] = json!({"key_file": write_finding_key(&s.dir)});
    cfg
}

#[test]
fn signed_requests_are_judged_recorded_and_never_executed() {
    let s = setup("cp-e2e", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let safety = s.dir.join("safety.sock");
    let control = s.dir.join("control.sock");
    let soc_pub = write_soc_pub(&s.dir);
    let port = free_port();
    let mut cfg = base_config(&s, &events);
    cfg["context"] = json!({});
    cfg["safety_feed"] = json!({"socket": {"path": safety, "stale_after_ms": 600000}});
    cfg["control_plane"] = json!({
        "listen_tcp": format!("127.0.0.1:{port}"),
        "unix_socket": control,
        "state_dir": state_dir(&s),
        "soc_keys": [soc_pub],
        "rate_per_minute": 600,
        "burst": 100,
    });
    let (stop, h) = spawn(s.resolve(&cfg));
    let mut plc = wait_for(5, "safety socket", || UnixStream::connect(&safety).ok());
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    // The socket was created with its final mode (no bind -> chmod window).
    let mode = std::fs::metadata(&control).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    set_state(&mut plc, &s.spool, "moving_slow");

    let base = format!("/api/v2/robots/{ROBOT}");
    let requests = format!("{base}/action-requests");

    // The robot snapshot: live safety state, and it says it executes nothing.
    let req = signed("GET", &base, b"");
    let r = unix(&control, &req);
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["api"], API_VERSION);
    assert_eq!(r.body["robot_id"], ROBOT);
    assert_eq!(r.body["safety_state"]["state"], "moving_slow");
    assert_eq!(r.body["safety_state"]["source"], "safety_feed");
    assert_eq!(r.body["executes_actions"], false);
    assert_eq!(r.body["mode"], "enforce");
    check_answer(&req, &r);

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
    assert!(r.header("x-robodr-answer-signature").is_none());
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
    // Read it back over loopback TCP (percent-encoded id).
    let get = format!("{requests}/{}", id.replace(':', "%3A"));
    let g = signed("GET", &get, b"");
    let r = tcp(port, &g);
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["status"], "recorded_not_executed");
    assert_eq!(r.body["state"]["evidence"], evidence.as_str());
    check_answer(&g, &r);

    // Authentication failures: tampered body, unknown key, stale clock,
    // another robot, a v1 signature, no credentials at all.
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
    let mut other_robot = signed("GET", "/api/v2/robots/ugv-008", b"");
    other_robot.sig = {
        let msg = signing_message(
            "GET",
            "/api/v2/robots/ugv-008",
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
    // A request signed in the v1 domain does not verify in v2.
    let mut v1 = signed("GET", &base, b"");
    v1.sig = {
        let msg = String::from_utf8(signing_message(
            "GET", &base, ROBOT, SOC_ID, v1.ts, &v1.nonce, b"",
        ))
        .unwrap()
        .replacen("robodr-control-plane/v2", "robodr-control-plane/v1", 1);
        to_hex(&soc().sign_message(msg.as_bytes()))
    };
    assert_eq!(unix(&control, &v1).body["error"]["code"], "bad_signature");
    let mut raw = UnixStream::connect(&control).unwrap();
    raw.write_all(b"GET /api/v2/robots/ugv-007 HTTP/1.1\r\n\r\n")
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
    // The evidence API is off unless configured.
    let ev = signed("GET", &format!("{base}/evidence"), b"");
    let r = unix(&control, &ev);
    assert_eq!(
        (r.status, r.body["error"]["code"].as_str()),
        (404, Some("evidence_disabled"))
    );
    check_answer(&ev, &r);

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
    assert!(cp["unauthenticated"].as_u64().unwrap() >= 7, "{cp}");
    assert_eq!(cp["listening"].as_array().unwrap().len(), 2);
    assert_eq!(cp["answer_sign_failures"], 0);

    let (sum, log) = finish(stop, h);
    assert!(
        log.contains("control plane (robodr-control-plane/v2) on"),
        "{log}"
    );
    assert!(!control.exists(), "control socket removed at shutdown");
    // No private bind directory is left behind.
    assert!(!std::fs::read_dir(&s.dir).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".rbind-")));

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
    assert_eq!(accepted["api"], API_VERSION);
    assert!(accepted["decision_id"].as_str().unwrap().len() == 32);
    let refused = reqs.iter().find(|n| n["decision"] == "refused").unwrap();
    assert_eq!(refused["refusal"]["code"], "safety_system_engaged");
    assert_eq!(refused["safety_state"], "estop_active");
    assert_eq!(notes(&s.blackbox, "robodr.control_plane_rejected").len(), 3);
    assert_eq!(notes(&s.blackbox, "robodr.control_plane_revert").len(), 2);
    assert_eq!(notes(&s.blackbox, "robodr.control_plane_start").len(), 1);
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
        &from_hex(a["signature"].as_str().unwrap()).unwrap()
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

/// Mutual TLS on a TCP listener: the SOC's client certificate (chain to the
/// configured CA, the SPKI pin) **and** the Ed25519 signature are both
/// required; everything else is refused before any HTTP and counted.
#[test]
fn mutual_tls_accepts_the_soc_and_refuses_everyone_else() {
    let s = setup("cp-mtls", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let soc_pub = write_soc_pub(&s.dir);
    let port = free_port();
    let mut cfg = base_config(&s, &events);
    cfg["control_plane"] = json!({
        "listen_tcp": format!("127.0.0.1:{port}"),
        "tls": tls_section(&s.dir, &[&spki_pin("soc")]),
        "state_dir": state_dir(&s),
        "soc_keys": [soc_pub],
        "rate_per_minute": 600,
        "burst": 100,
    });
    let (stop, h) = spawn(s.resolve(&cfg));
    let base = format!("/api/v2/robots/{ROBOT}");
    // The SOC: its certificate and its signature.
    let req = signed("GET", &base, b"");
    let r = wait_for(5, "mTLS listener", || mtls(port, Some("soc"), &req).ok());
    assert_eq!(r.status, 200, "{}", r.body);
    check_answer(&req, &r);
    // A valid certificate does not replace the signature.
    let r = mtls_raw(
        port,
        Some("soc"),
        format!("GET {base} HTTP/1.1\r\nHost: robot\r\n\r\n").as_bytes(),
    )
    .unwrap();
    assert_eq!(
        (r.status, r.body["error"]["code"].as_str()),
        (401, Some("missing_credentials"))
    );
    let mut bad = signed("GET", &base, b"");
    bad.sig = "00".repeat(64);
    let r = mtls(port, Some("soc"), &bad).unwrap();
    assert_eq!(r.body["error"]["code"], "bad_signature");
    // Replay over TLS: refused like anywhere else.
    assert_eq!(
        mtls(port, Some("soc"), &req).unwrap().body["error"]["code"],
        "replayed_nonce"
    );
    // No client certificate, another CA, the right CA but an unpinned key,
    // an expired certificate: no channel, no answer.
    for (n, (client, why)) in [
        (None, "no client certificate"),
        (Some("other"), "UnknownIssuer"),
        (Some("soc2"), "matches no configured pin"),
        (Some("soc-expired"), "Expired"),
    ]
    .into_iter()
    .enumerate()
    {
        let r = mtls(port, client, &signed("GET", &base, b""));
        assert!(r.is_err(), "{client:?} got an answer: {r:?}");
        // The robot names the reason (status.json, last_auth_failure).
        let last = wait_for(10, why, || {
            let st = status(&s.spool)?;
            let cp = &st["control_plane"];
            (cp["tls_failures"].as_u64()? > n as u64)
                .then(|| cp["last_auth_failure"].as_str().unwrap_or("").to_string())
        });
        assert!(last.contains(why), "{client:?}: {last}");
    }
    // Plain HTTP to the TLS port: no answer either.
    let plain = exchange_raw(
        TcpStream::connect(("127.0.0.1", port)).unwrap(),
        &request_bytes(&signed("GET", &base, b"")),
    );
    assert!(plain.is_err(), "{plain:?}");
    // Counted as failed authentications (TLS), reported as a finding.
    let st = wait_for(10, "tls failures counted", || {
        let st = status(&s.spool)?;
        (st["control_plane"]["tls_failures"].as_u64()? >= 5).then_some(st)
    });
    let cp = &st["control_plane"];
    assert!(
        cp["listening"][0].as_str().unwrap().starts_with("mtls:"),
        "{cp}"
    );
    assert_eq!(cp["tls"]["client_pins"], 1);
    assert_eq!(cp["tls"]["server_spki_sha256"], spki_pin("robot"));
    assert!(
        cp["last_auth_failure"]
            .as_str()
            .unwrap()
            .contains("tls_handshake_failed"),
        "{cp}"
    );
    wait_for(10, "unauthenticated finding", || {
        rules(&spooled(&s.spool))
            .iter()
            .any(|r| r == "robot.agent.control_plane_unauthenticated")
            .then_some(())
    });
    finish(stop, h);
    // The client certificate's identity is in the evidence.
    let start = notes(&s.blackbox, "robodr.control_plane_start");
    assert_eq!(start[0]["tls"]["client_pins"], 1);

    // Without a pin, any client certificate of the SOC CA is accepted (the
    // signature still decides); an expired one still is not.
    let mut cfg2 = cfg.clone();
    cfg2["control_plane"]["tls"]["client_spki_sha256"] = json!([]);
    let (stop, h) = spawn(s.resolve(&cfg2));
    let req = signed("GET", &base, b"");
    let r = wait_for(5, "mTLS listener", || mtls(port, Some("soc2"), &req).ok());
    assert_eq!(r.status, 200);
    assert!(mtls(port, Some("soc-expired"), &signed("GET", &base, b"")).is_err());
    finish(stop, h);
}

/// The request state and the replay store survive a restart: a status
/// query after the restart answers exactly as before, a replay of a
/// request accepted before it is refused, a resubmission is a duplicate.
#[test]
fn state_survives_a_restart_and_replays_stay_refused() {
    let s = setup("cp-restart", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let control = s.dir.join("control.sock");
    let soc_pub = write_soc_pub(&s.dir);
    let mut cfg = base_config(&s, &events);
    cfg["control_plane"] = json!({
        "unix_socket": control,
        "state_dir": state_dir(&s),
        "soc_keys": [soc_pub],
        "rate_per_minute": 600,
        "burst": 100,
        // A short window: the fence below lasts for it.
        "max_clock_skew_s": 2,
    });
    let requests = format!("/api/v2/robots/{ROBOT}/action-requests");
    let id = "robot_restrict_motion:ugv-007:restart";
    let body = submit_body(
        id,
        "restrict_motion",
        json!({"max_linear_speed": 0.5}),
        Some(600),
    );
    let get_target = format!("{requests}/{}", id.replace(':', "%3A"));

    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    let submit = signed("POST", &requests, &body);
    let r = unix(&control, &submit);
    assert_eq!(r.body["status"], "recorded_not_executed", "{}", r.body);
    let before = unix(&control, &signed("GET", &get_target, b"")).body;
    finish(stop, h);

    // Restart.
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    let g = signed("GET", &get_target, b"");
    let r = unix(&control, &g);
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.body, before,
        "a status query after a restart is consistent"
    );
    check_answer(&g, &r);
    // The very request accepted before the restart, replayed: refused.
    let r = unix(&control, &submit);
    assert_eq!(
        (r.status, r.body["error"]["code"].as_str()),
        (401, Some("replayed_nonce"))
    );
    // A fresh resubmission is a duplicate, not judged again.
    let r = unix(&control, &signed("POST", &requests, &body));
    assert_eq!(r.body["duplicate"], true);
    let st = status(&s.spool).unwrap();
    let cp = &st["control_plane"];
    assert_eq!(cp["restored"], 1, "{cp}");
    assert_eq!(cp["state"]["restored"], 1, "{cp}");
    assert!(
        cp["state"]["replay"]["restored"].as_u64().unwrap() >= 2,
        "{cp}"
    );
    assert!(cp["replay_fence"].is_null(), "{cp}");
    finish(stop, h);
    assert_eq!(notes(&s.blackbox, "robodr.control_plane_request").len(), 1);

    // The replay store removed while the request journal stays: the
    // restart fences up to now + skew (a request accepted before may have
    // been signed up to the skew ahead; CP review finding 5): requests
    // signed before it are refused, fresh ones once the window has passed.
    let old = signed("GET", &get_target, b"");
    std::fs::remove_file(s.dir.join("cp-state/nonces.journal")).unwrap();
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    let r = unix(&control, &old);
    assert_eq!(r.body["error"]["code"], "stale_timestamp", "{}", r.body);
    // Signed now: still inside the fence (wire code stale_timestamp).
    let r = unix(&control, &signed("GET", &get_target, b""));
    assert_eq!(r.body["error"]["code"], "stale_timestamp", "{}", r.body);
    std::thread::sleep(std::time::Duration::from_millis(3100));
    let r = unix(&control, &signed("GET", &get_target, b""));
    assert_eq!(r.status, 200, "{}", r.body);
    let st = status(&s.spool).unwrap();
    assert!(st["control_plane"]["replay_fence"].is_u64());
    let (_, log) = finish(stop, h);
    assert!(log.contains("replay store fenced"), "{log}");
}

/// The evidence API: inventory, an export for a decision's evidence link,
/// the signed manifest, a chunked download that is resumed after a
/// "disconnect", verification with the robot's public keys only, tamper
/// detection, idempotency, conflicts and deletion. No key material leaves.
#[test]
fn evidence_export_end_to_end() {
    let s = setup("cp-evidence", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let control = s.dir.join("control.sock");
    let soc_pub = write_soc_pub(&s.dir);
    // An Ed25519 black-box key (the production setup): the SOC verifies
    // with its public file only.
    let bb_key = s.dir.join("bb.key");
    KeyFile::ed25519_from_seed(&BB_SEED, Some(BB_ID))
        .unwrap()
        .write_new(&bb_key)
        .unwrap();
    let bb_pub = s.dir.join("bb.pub");
    KeyFile::ed25519_from_seed(&BB_SEED, Some(BB_ID))
        .unwrap()
        .to_public()
        .unwrap()
        .write_new(&bb_pub)
        .unwrap();
    let mut cfg = base_config(&s, &events);
    cfg["blackbox"]["key_file"] = json!(bb_key);
    cfg["blackbox"].as_object_mut().unwrap().remove("key_id");
    cfg["control_plane"] = json!({
        "unix_socket": control,
        "state_dir": state_dir(&s),
        "soc_keys": [soc_pub],
        "rate_per_minute": 600,
        "burst": 100,
        "evidence": {"chunk_bytes": 16384, "max_exports": 2},
    });
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    let base = format!("/api/v2/robots/{ROBOT}");
    // A decision whose evidence the SOC then exports.
    let r = unix(
        &control,
        &signed(
            "POST",
            &format!("{base}/action-requests"),
            &submit_body("ev-1", "record_evidence", json!({}), None),
        ),
    );
    assert_eq!(r.body["status"], "recorded_not_executed", "{}", r.body);
    let link = r.body["state"]["evidence"].as_str().unwrap().to_string();
    // Let heartbeats add records around it.
    std::thread::sleep(std::time::Duration::from_millis(600));

    // Inventory.
    let inv_req = signed("GET", &format!("{base}/evidence"), b"");
    let inv = unix(&control, &inv_req);
    assert_eq!(inv.status, 200, "{}", inv.body);
    check_answer(&inv_req, &inv);
    assert_eq!(inv.body["chain"]["identity"]["device_id"], ROBOT);
    assert_eq!(inv.body["chain"]["identity"]["key_id"], BB_ID);
    assert_eq!(inv.body["retained"]["first_seq"], 0);
    assert!(inv.body["retained"]["records"].as_u64().unwrap() > 5);
    assert_eq!(inv.body["exports"], json!([]));
    assert_eq!(inv.body["limits"]["chunk_bytes"], 16384);

    // Export the decision's records with context.
    let exports = format!("{base}/evidence/exports");
    let create_body = serde_json::to_vec(&json!({
        "export_id": "case-42:ev-1",
        "selector": {"finding": {"finding_id": "rf1-test", "evidence": [link], "context_records": 4}},
        "requested_by": "analyst@soc",
        "reason": "case 42",
    }))
    .unwrap();
    let create = signed("POST", &exports, &create_body);
    let r = unix(&control, &create);
    assert_eq!(r.status, 201, "{}", r.body);
    check_answer(&create, &r);
    let manifest_bytes = r.raw_body.clone();
    let m: Manifest = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(m.export_id, "case-42:ev-1");
    assert_eq!(m.robot_id, ROBOT);
    assert_eq!(m.key_id, SOC_ID);
    assert_eq!(m.chain.identity.device_id, ROBOT);
    assert_eq!(m.chain.signing_key.key_id, BB_ID);
    assert_eq!(m.referenced.len(), 1);
    assert!(m.records.count >= 5, "{:?}", m.records);
    assert!(m.evidence.starts_with("robodr-blackbox://ugv-007/"));
    // The manifest is signed with the finding key (detached, verifiable
    // offline from the stored bytes).
    let (kid, sig) = parse_signature_header(
        r.header(&H_MANIFEST_SIGNATURE.to_ascii_lowercase())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(kid, FINDING_ID);
    assert!(robodr_blackbox::sign_ed25519::verify(
        &finding_pub(),
        &manifest_message(&manifest_bytes),
        &sig
    ));

    // Download: the first chunk, then a "disconnect", then the manifest is
    // fetched again and the download resumes at the missing chunks.
    let chunk = |i: u64| {
        let req = signed("GET", &format!("{exports}/case-42%3Aev-1/chunks/{i}"), b"");
        let r = unix(&control, &req);
        assert_eq!(
            r.status,
            200,
            "chunk {i}: {:?}",
            String::from_utf8_lossy(&r.raw_body)
        );
        assert_eq!(r.header("content-type"), Some("application/octet-stream"));
        check_answer(&req, &r);
        r.raw_body
    };
    let mut parts: Vec<Option<Vec<u8>>> = vec![None; m.bundle.chunks.len()];
    parts[0] = Some(chunk(0));
    let again = signed("GET", &format!("{exports}/case-42%3Aev-1"), b"");
    let r2 = unix(&control, &again);
    assert_eq!(r2.status, 200);
    assert_eq!(r2.raw_body, manifest_bytes, "the manifest is stable");
    for c in &m.bundle.chunks {
        if parts[c.index as usize].is_none() {
            parts[c.index as usize] = Some(chunk(c.index));
        }
    }
    let mut bundle = Vec::new();
    for (c, p) in m.bundle.chunks.iter().zip(&parts) {
        let p = p.as_ref().unwrap();
        assert_eq!(p.len() as u64, c.bytes);
        assert_eq!(to_hex(&sha256(p)), c.sha256, "chunk {}", c.index);
        bundle.extend_from_slice(p);
    }
    assert_eq!(to_hex(&sha256(&bundle)), m.bundle.sha256);
    // An unknown chunk.
    let r = unix(
        &control,
        &signed("GET", &format!("{exports}/case-42%3Aev-1/chunks/9999"), b""),
    );
    assert_eq!(r.body["error"]["code"], "unknown_chunk");

    // Verify like the SOC: the robot's black-box *public* key file only.
    let mut ring = Keyring::new();
    ring.load_public_file(&bb_pub).unwrap();
    let b = Bundle::from_bytes(&bundle).unwrap();
    let rep = b.verify_with_key(&ring, None, Some(ROBOT), Some(&m.chain.signing_key));
    assert!(rep.is_intact(), "{rep:?}");
    assert_eq!(rep.first_seq, Some(m.records.first_seq));
    assert_eq!(rep.last_seq, Some(m.records.last_seq));
    assert_eq!(
        rep.last_hash.as_deref(),
        Some(m.records.last_sha256.as_str())
    );
    // The linked record is in it, with the link's hash.
    let linked = &m.referenced[0];
    assert!(b
        .records()
        .iter()
        .any(|r| r.seq == linked.seq && to_hex(&r.hash) == linked.sha256));
    // One flipped byte: tamper.
    let mut t = bundle.clone();
    let pos = t.len() / 2;
    t[pos] ^= 0x01;
    if let Ok(tb) = Bundle::from_bytes(&t) {
        assert!(!tb
            .verify_with_key(&ring, None, Some(ROBOT), Some(&m.chain.signing_key))
            .is_intact());
    }
    // No key material in what left the robot.
    let secrets = [
        to_hex(&BB_SEED),
        to_hex(&FINDING_SEED),
        std::fs::read_to_string(&bb_key).unwrap(),
    ];
    for sec in &secrets {
        assert!(
            !bundle.windows(sec.len()).any(|w| w == sec.as_bytes()),
            "secret material in the bundle"
        );
        assert!(!manifest_bytes
            .windows(sec.len())
            .any(|w| w == sec.as_bytes()));
    }

    // Idempotent re-create: the same manifest; another selection under the
    // id: a conflict.
    let r = unix(&control, &signed("POST", &exports, &create_body));
    assert_eq!(r.status, 200);
    assert_eq!(r.raw_body, manifest_bytes);
    let other = serde_json::to_vec(&json!({
        "export_id": "case-42:ev-1",
        "selector": {"seq_range": {"from_seq": 0, "to_seq": 1}},
        "requested_by": "analyst@soc",
    }))
    .unwrap();
    let r = unix(&control, &signed("POST", &exports, &other));
    assert_eq!(
        (r.status, r.body["error"]["code"].as_str()),
        (409, Some("export_id_conflict"))
    );
    // A second export, then the limit (max_exports 2).
    let second = serde_json::to_vec(&json!({
        "export_id": "case-42:range",
        "selector": {"seq_range": {"from_seq": 0, "to_seq": 3}},
        "requested_by": "analyst@soc",
    }))
    .unwrap();
    assert_eq!(
        unix(&control, &signed("POST", &exports, &second)).status,
        201
    );
    let third = serde_json::to_vec(&json!({
        "export_id": "case-43",
        "selector": {"seq_range": {"from_seq": 0, "to_seq": 2}},
        "requested_by": "analyst@soc",
    }))
    .unwrap();
    let r = unix(&control, &signed("POST", &exports, &third));
    assert_eq!(r.body["error"]["code"], "export_limit");
    // A selection beyond what is retained.
    let far = serde_json::to_vec(&json!({
        "export_id": "case-44",
        "selector": {"seq_range": {"from_seq": 0, "to_seq": 999999999}},
        "requested_by": "analyst@soc",
    }))
    .unwrap();
    // An invalid body is refused (400) and recorded.
    let r = unix(
        &control,
        &signed(
            "POST",
            &exports,
            br#"{"export_id": "x", "selector": {}, "requested_by": "a"}"#,
        ),
    );
    assert_eq!(
        (r.status, r.body["error"]["code"].as_str()),
        (400, Some("invalid_selector"))
    );
    // Delete, then the manifest is gone and the limit freed.
    let del = signed("DELETE", &format!("{exports}/case-42%3Arange"), b"");
    let r = unix(&control, &del);
    assert_eq!(r.body["deleted"], true, "{}", r.body);
    check_answer(&del, &r);
    let r = unix(
        &control,
        &signed("GET", &format!("{exports}/case-42%3Arange"), b""),
    );
    assert_eq!(r.body["error"]["code"], "unknown_export");
    let r = unix(&control, &signed("POST", &exports, &far));
    assert_eq!(
        (r.status, r.body["error"]["code"].as_str()),
        (416, Some("out_of_range"))
    );
    let st = status(&s.spool).unwrap();
    let ev = &st["control_plane"]["evidence"];
    assert_eq!(ev["exports"], 1, "{ev}");
    assert!(ev["chunks_served"].as_u64().unwrap() >= m.bundle.chunks.len() as u64);
    assert_eq!(st["control_plane"]["evidence_exports"], 2);
    finish(stop, h);

    // The export survives a restart (the SOC can resume after one), and
    // its creation is a black-box note.
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    let r = unix(
        &control,
        &signed("GET", &format!("{exports}/case-42%3Aev-1"), b""),
    );
    assert_eq!(r.raw_body, manifest_bytes);
    finish(stop, h);
    let ex = notes(&s.blackbox, "robodr.control_plane_evidence_export");
    assert_eq!(ex.len(), 2);
    assert_eq!(ex[0]["export_id"], "case-42:ev-1");
    assert_eq!(ex[0]["bundle"]["sha256"], m.bundle.sha256);
    assert_eq!(ex[0]["auth"]["key_id"], SOC_ID);
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
    let fk = write_finding_key(&s.dir);
    let state = state_dir(&s);
    let load = |cp: Value, signing: bool| {
        let mut c = cfg.clone();
        c["control_plane"] = cp;
        if signing {
            c["finding_signing"] = json!({"key_file": fk});
        }
        robodr_agentd::load(&s.write_config(&c))
    };
    let e = load(
        json!({"unix_socket": s.dir.join("c.sock"), "state_dir": state, "soc_keys": [soc_pub], "verbose": true}),
        true,
    )
    .unwrap_err();
    assert!(e.contains("verbose"), "{e}");
    let e = load(
        json!({"unix_socket": events, "state_dir": state, "soc_keys": [soc_pub]}),
        true,
    )
    .unwrap_err();
    assert!(e.contains("also an event_inputs"), "{e}");
    let e = load(
        json!({"unix_socket": s.spool.join("c.sock"), "state_dir": state, "soc_keys": [soc_pub]}),
        true,
    )
    .unwrap_err();
    assert!(e.contains("spool.dir"), "{e}");
    let e = load(
        json!({"unix_socket": s.dir.join("c.sock"), "state_dir": s.blackbox.join("cp"), "soc_keys": [soc_pub]}),
        true,
    )
    .unwrap_err();
    assert!(e.contains("blackbox.dir"), "{e}");
    // Off loopback only with mutual TLS; allow_remote is gone.
    let e = load(
        json!({"listen_tcp": "192.0.2.1:8787", "state_dir": state, "soc_keys": [soc_pub]}),
        true,
    )
    .unwrap_err();
    assert!(e.contains("mutual TLS"), "{e}");
    let e = load(
        json!({"listen_tcp": "192.0.2.1:8787", "allow_remote": true, "state_dir": state, "soc_keys": [soc_pub]}),
        true,
    )
    .unwrap_err();
    assert!(e.contains("removed"), "{e}");
    // Answers are always signed: finding_signing is required.
    let e = load(
        json!({"listen_tcp": "127.0.0.1:8787", "state_dir": state, "soc_keys": [soc_pub]}),
        false,
    )
    .unwrap_err();
    assert!(e.contains("finding_signing"), "{e}");
    // TLS files are checked at load: a private key others can read.
    let mut tls = tls_section(&s.dir, &[]);
    std::fs::set_permissions(
        tls["key_file"].as_str().unwrap(),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let e = load(
        json!({"listen_tcp": "192.0.2.1:8787", "tls": tls, "state_dir": state, "soc_keys": [soc_pub]}),
        true,
    )
    .unwrap_err();
    assert!(e.contains("key_file") && e.contains("chmod 600"), "{e}");
    std::fs::set_permissions(
        tls["key_file"].as_str().unwrap(),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    tls["client_spki_sha256"] = json!(["nothex"]);
    let e = load(
        json!({"listen_tcp": "192.0.2.1:8787", "tls": tls, "state_dir": state, "soc_keys": [soc_pub]}),
        true,
    )
    .unwrap_err();
    assert!(e.contains("64 hex"), "{e}");
    // The key that does not belong to the certificate.
    let mut tls2 = tls_section(&s.dir, &[]);
    let wrong = s.dir.join("wrong.key");
    std::fs::copy(tls_data("soc.key"), &wrong).unwrap();
    std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600)).unwrap();
    tls2["key_file"] = json!(wrong);
    let e = load(
        json!({"listen_tcp": "192.0.2.1:8787", "tls": tls2, "state_dir": state, "soc_keys": [soc_pub]}),
        true,
    )
    .unwrap_err();
    assert!(e.contains("certificate / key"), "{e}");
    let ok = load(
        json!({"listen_tcp": "192.0.2.1:8787", "tls": tls_section(&s.dir, &[&spki_pin("soc")]),
               "state_dir": state, "soc_keys": [soc_pub], "evidence": {}}),
        true,
    )
    .unwrap();
    let spec = ok.control_plane.unwrap();
    assert_eq!(spec.keys.len(), 1);
    assert_eq!(spec.keys[0].key_id, SOC_ID);
    assert_eq!(spec.tls.as_ref().unwrap().client_pins, 1);
    assert!(spec.evidence.is_some());
    // A state directory others can read refuses to start (not at load).
    let mut c = cfg.clone();
    c["finding_signing"] = json!({"key_file": fk});
    c["control_plane"] =
        json!({"unix_socket": s.dir.join("c.sock"), "state_dir": state, "soc_keys": [soc_pub]});
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = s.resolve(&c);
    let mut log = Vec::new();
    let e = robodr_agentd::run(&r, &|| true, &mut log)
        .unwrap_err()
        .to_string();
    assert!(e.contains("state_dir") && e.contains("chmod 700"), "{e}");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Running without the section: no listener, no status block.
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "status", || status(&s.spool));
    let (_, log) = finish(stop, h);
    let st = status(&s.spool).unwrap();
    assert!(st.get("control_plane").is_none());
    assert!(!log.contains("control plane ("));
}

// ---------------------------------------------------------------------
// Control plane v2 review regressions (each failed before its fix).
// ---------------------------------------------------------------------

fn unix_try(path: &Path, r: &Req) -> Result<Resp, String> {
    let s = UnixStream::connect(path).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    exchange_raw(s, &request_bytes(r))
}

/// Review finding 2: idle TCP peers that never authenticate used to take
/// every slot of the one cap shared with the root-only unix socket. The
/// unix socket has its own slots now, TCP handshakes / unauthenticated
/// reads have theirs, and one source address cannot take them all.
#[test]
fn idle_tcp_peers_cannot_lock_out_the_unix_socket() {
    let s = setup("cp-caps", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let control = s.dir.join("control.sock");
    let soc_pub = write_soc_pub(&s.dir);
    let port = free_port();
    let mut cfg = base_config(&s, &events);
    cfg["control_plane"] = json!({
        "listen_tcp": format!("127.0.0.1:{port}"),
        "unix_socket": control,
        "state_dir": state_dir(&s),
        "soc_keys": [soc_pub],
        "rate_per_minute": 600,
        "burst": 100,
    });
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    let base = format!("/api/v2/robots/{ROBOT}");
    // Eight idle TCP connections (never a byte sent).
    let idle: Vec<TcpStream> = (0..8)
        .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let req = signed("GET", &base, b"");
    let r = unix_try(&control, &req).expect("the unix socket must still answer");
    assert_eq!(r.status, 200, "{}", r.body);
    check_answer(&req, &r);
    // The per-source cap: six of the eight were cut.
    let mut closed_early = 0;
    for mut c in idle {
        c.set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let mut b = [0u8; 1];
        if matches!(c.read(&mut b), Ok(0)) {
            closed_early += 1;
        }
    }
    assert!(closed_early >= 6, "closed early: {closed_early}");
    // W2-4: the per-source share evicts the source's own oldest
    // pre-authentication connections instead of refusing the newcomer.
    let st = status(&s.spool).unwrap();
    assert!(
        st["control_plane"]["admission"]["evicted"]
            .as_u64()
            .unwrap()
            >= 6,
        "{}",
        st["control_plane"]
    );
    finish(stop, h);
}

/// Flip a byte in each of the last `k` lines of a journal.
fn corrupt_last_lines(p: &Path, k: usize) {
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

/// Review finding 4 (request journal): damage at the end of the journal
/// beyond one line used to be cut as a torn tail, so a committed request
/// was forgotten and judged (and recorded) again after a restart. Now it is
/// damage: the journal is quarantined and the requests are rebuilt from
/// their signed black-box notes, so the resubmission is a duplicate.
#[test]
fn request_journal_tail_damage_is_rebuilt_from_the_black_box() {
    let s = setup("cp-jdamage", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let control = s.dir.join("control.sock");
    let soc_pub = write_soc_pub(&s.dir);
    let mut cfg = base_config(&s, &events);
    cfg["control_plane"] = json!({
        "unix_socket": control,
        "state_dir": state_dir(&s),
        "soc_keys": [soc_pub],
        "rate_per_minute": 600,
        "burst": 100,
    });
    let requests = format!("/api/v2/robots/{ROBOT}/action-requests");
    let bodies: Vec<(String, Vec<u8>)> = (0..3)
        .map(|n| {
            let id = format!("robot_restrict_motion:ugv-007:jd{n}");
            let b = submit_body(
                &id,
                "restrict_motion",
                json!({"max_linear_speed": 0.5}),
                Some(600),
            );
            (id, b)
        })
        .collect();
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    let mut first = Vec::new();
    for (_, b) in &bodies {
        let r = unix(&control, &signed("POST", &requests, b));
        assert_eq!(r.body["status"], "recorded_not_executed", "{}", r.body);
        first.push(r.body);
    }
    finish(stop, h);
    // The last request's begin + commit lines damaged.
    corrupt_last_lines(&s.dir.join("cp-state/requests.journal"), 2);
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    for ((id, b), before) in bodies.iter().zip(&first) {
        let r = unix(&control, &signed("POST", &requests, b));
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.body["duplicate"], true, "{id} judged again: {}", r.body);
        assert_eq!(r.body["state"]["evidence"], before["state"]["evidence"]);
    }
    let st = status(&s.spool).unwrap();
    let cp = &st["control_plane"];
    assert!(
        cp["state"]["journal_damaged"].as_u64().unwrap() >= 2,
        "{cp}"
    );
    assert!(cp["state"]["journal_quarantined"].is_string(), "{cp}");
    assert_eq!(cp["state"]["rebuilt_from_blackbox"], 1, "{cp}");
    finish(stop, h);
    assert_eq!(
        notes(&s.blackbox, "robodr.control_plane_request").len(),
        3,
        "no request was judged twice"
    );
}

// --- W2-4: TLS slowloris on the control plane (red team 2026-10-30, S2) ---

/// A TCP connection to `127.0.0.1:port` from the loopback address `src`.
fn connect_from(src: std::net::Ipv4Addr, port: u16) -> std::io::Result<TcpStream> {
    use socket2::{Domain, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    s.bind(&std::net::SocketAddr::from((src, 0)).into())?;
    s.connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)).into(),
        std::time::Duration::from_secs(2),
    )?;
    Ok(s.into())
}

/// The red team's S2 attacker: from `src`, a TLS ClientHello prefix one
/// byte every `gap`, reopened at once whenever cut, until `stop`. With
/// `fast_hello`, a complete ClientHello (rustls, no client certificate) at
/// once and then nothing: the strongest pre-authentication squatter that
/// costs no crypto on the attacker's side. Returns the connections opened.
fn squatter(
    src: std::net::Ipv4Addr,
    port: u16,
    gap: std::time::Duration,
    fast_hello: bool,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<u64> {
    std::thread::spawn(move || {
        let mut prefix = vec![
            0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
        ];
        prefix.extend([0x5a; 32]);
        let mut opened = 0u64;
        while !stop.load(Ordering::SeqCst) {
            let Ok(mut tcp) = connect_from(src, port) else {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            };
            opened += 1;
            let bytes = if fast_hello {
                let mut conn = rustls::ClientConnection::new(
                    tls_client(None),
                    ServerName::try_from("127.0.0.1").unwrap(),
                )
                .unwrap();
                let mut hello = Vec::new();
                conn.write_tls(&mut hello).unwrap();
                if tcp.write_all(&hello).is_err() {
                    continue;
                }
                Vec::new()
            } else {
                prefix.clone()
            };
            let t0 = std::time::Instant::now();
            // Trickle (or, after a full hello, keep the connection open)
            // until cut or 30 s.
            let mut i = 0;
            loop {
                if stop.load(Ordering::SeqCst) || t0.elapsed().as_secs() > 30 {
                    break;
                }
                let r = if bytes.is_empty() {
                    tcp.set_read_timeout(Some(gap)).unwrap();
                    let mut b = [0u8; 4096];
                    match tcp.read(&mut b) {
                        Ok(0) => Err(()),
                        Ok(_) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
                        Err(_) => Err(()),
                    }
                } else {
                    let r = tcp
                        .write_all(&bytes[i % bytes.len()..][..1])
                        .map_err(|_| ());
                    i += 1;
                    std::thread::sleep(gap);
                    // A cut connection shows on the next write or as EOF.
                    tcp.set_nonblocking(true).unwrap();
                    let mut b = [0u8; 64];
                    let eof = matches!(tcp.read(&mut b), Ok(0));
                    tcp.set_nonblocking(false).unwrap();
                    if eof {
                        Err(())
                    } else {
                        r
                    }
                };
                if r.is_err() {
                    break;
                }
            }
        }
        opened
    })
}

/// SOC probes every `every`: (answered 200 within the read deadline, all
/// probes, slowest successful round trip).
fn soc_probes(port: u16, n: usize, every: std::time::Duration) -> (usize, usize, u128) {
    let base = format!("/api/v2/robots/{ROBOT}");
    let mut ok = 0;
    let mut slowest = 0;
    for _ in 0..n {
        std::thread::sleep(every);
        let t0 = std::time::Instant::now();
        let r = mtls(port, Some("soc"), &signed("GET", &base, b""));
        let ms = t0.elapsed().as_millis();
        if matches!(&r, Ok(r) if r.status == 200) && ms < 5000 {
            ok += 1;
            slowest = slowest.max(ms);
        } else {
            eprintln!("SOC probe failed after {ms} ms: {:?}", r.map(|r| r.status));
        }
    }
    (ok, n, slowest)
}

fn slowloris_config(s: &Setup, events: &Path, port: u16, extra: Value) -> Value {
    let mut cfg = base_config(s, events);
    cfg["control_plane"] = json!({
        "listen_tcp": format!("127.0.0.1:{port}"),
        "tls": tls_section(&s.dir, &[]),
        "state_dir": state_dir(s),
        "soc_keys": [write_soc_pub(&s.dir)],
        "rate_per_minute": 600,
        "burst": 100,
    });
    for (k, v) in extra.as_object().unwrap() {
        cfg["control_plane"][k] = v.clone();
    }
    cfg
}

/// Red team 2026-10-30 S2 (W2-4): 8 loopback sources x 2 connections
/// trickling TLS ClientHellos and reopening at once used to hold all four
/// pre-authentication slots: the SOC got 1-3 of 20 requests through. With
/// eviction by progress, the subnet share and the hello timeout, a SOC in
/// the attackers' own /24 (127.0.0.1) and outside `priority_sources` is
/// still served within its deadline; the attack is reported as handshake
/// pressure, not as failed authentication.
#[test]
fn s2_multi_source_tls_slowloris_does_not_lock_out_the_soc() {
    let s = setup("cp-s2", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let port = free_port();
    let cfg = slowloris_config(&s, &events, port, json!({}));
    let (stop, h) = spawn(s.resolve(&cfg));
    let base = format!("/api/v2/robots/{ROBOT}");
    wait_for(5, "mTLS listener", || {
        mtls(port, Some("soc"), &signed("GET", &base, b"")).ok()
    });
    let halt = Arc::new(AtomicBool::new(false));
    let attackers: Vec<_> = (0..8u8)
        .flat_map(|i| [i, i])
        .map(|i| {
            squatter(
                std::net::Ipv4Addr::new(127, 0, 0, 10 + i),
                port,
                std::time::Duration::from_millis(200),
                false,
                halt.clone(),
            )
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    // A SOC that asks now and then (every 1.1 s, like the red team's 2 s).
    let (ok, n, slowest) = soc_probes(port, 8, std::time::Duration::from_millis(1100));
    halt.store(true, Ordering::SeqCst);
    let opened: u64 = attackers.into_iter().map(|t| t.join().unwrap()).sum();
    assert_eq!(
        ok, n,
        "SOC answered {ok}/{n} during the attack (slowest {slowest} ms)"
    );
    assert!(opened >= 16, "attacker connections: {opened}");
    let st = wait_for(10, "pressure counted", || {
        let st = status(&s.spool)?;
        (st["control_plane"]["handshake_pressure"].as_u64()? > 0).then_some(st)
    });
    let cp = &st["control_plane"];
    let adm = &cp["admission"];
    assert!(
        adm["evicted"].as_u64().unwrap() + adm["too_slow"].as_u64().unwrap() > 0,
        "{cp}"
    );
    assert!(adm["promoted"].as_u64().unwrap() >= n as u64, "{cp}");
    // A trickled handshake is pressure, not a failed authentication.
    assert_eq!(cp["unauthenticated"], 0, "{cp}");
    wait_for(10, "pressure finding", || {
        rules(&spooled(&s.spool))
            .iter()
            .any(|r| r == "robot.agent.control_plane_pressure")
            .then_some(())
    });
    finish(stop, h);
}

/// W2-4: `priority_sources` reserve pre-authentication slots: 32 sources
/// that send complete ClientHellos at once (the strongest squatters: they
/// rank as progressing until the floor cuts them) and the SOC, listed,
/// still gets every request through; its connections are counted as
/// priority admissions.
#[test]
fn priority_sources_keep_the_soc_served_under_a_fast_hello_flood() {
    let s = setup("cp-prio", &robot_profile(true));
    let events = s.dir.join("ev.sock");
    let port = free_port();
    let cfg = slowloris_config(
        &s,
        &events,
        port,
        json!({"priority_sources": ["127.0.0.1/32"], "priority_connections": 2}),
    );
    let (stop, h) = spawn(s.resolve(&cfg));
    let base = format!("/api/v2/robots/{ROBOT}");
    wait_for(5, "mTLS listener", || {
        mtls(port, Some("soc"), &signed("GET", &base, b"")).ok()
    });
    let halt = Arc::new(AtomicBool::new(false));
    let attackers: Vec<_> = (0..32u8)
        .map(|i| {
            squatter(
                std::net::Ipv4Addr::new(127, 0, 1, 10 + i),
                port,
                std::time::Duration::from_millis(200),
                true,
                halt.clone(),
            )
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    // Even a SOC that asks back to back (never quiet).
    let (ok, n, slowest) = soc_probes(port, 10, std::time::Duration::from_millis(100));
    halt.store(true, Ordering::SeqCst);
    for t in attackers {
        t.join().unwrap();
    }
    assert_eq!(ok, n, "SOC answered {ok}/{n} (slowest {slowest} ms)");
    let st = status(&s.spool).unwrap();
    let adm = &st["control_plane"]["admission"];
    assert!(
        adm["admitted_priority"].as_u64().unwrap() > n as u64,
        "{adm}"
    );
    finish(stop, h);
}
