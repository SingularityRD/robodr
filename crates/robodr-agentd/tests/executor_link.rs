//! executor v1 end to end on control plane v2: the real daemon with
//! `control_plane` (`robodr-control-plane/v2`: persistent state directory,
//! signed answers, mutual TLS) and `executor.enabled`, an in-process
//! `robodr-executor` server (its engine on an in-memory nftables model: real
//! nftables and real traffic are proven in
//! `crates/robodr-executor/tests/netns.rs`), signed SOC requests, the
//! executor's apply-time safety re-check against agentd's live safety
//! state, request states `pending` → `verified` → `reverted` (every answer
//! signed with the finding key, the states journalled: they survive a
//! restart), executor refusals, `record_evidence` marks and the executor's
//! events in the black box.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use common::pcap::robot_profile;
use common::*;
use robodr_agentd::control::auth::{answer_message, signing_message};
use robodr_agentd::control::evidence::parse_signature_header;
use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::{Ed25519SigningKey, KeyFile};
use robodr_executor::engine::Engine;
use robodr_executor::nft::Nft;
use robodr_executor::proto::Key;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{json, Value};

const SOC_ID: &str = "soc:soc-a:1";
const SOC_SEED: [u8; 32] = [0x51; 32];
const FINDING_ID: &str = "finding:ugv-007:1";
const FINDING_SEED: [u8; 32] = [0x52; 32];
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

/// Where the control plane is reached.
#[derive(Clone, Copy)]
enum Via<'a> {
    Unix(&'a Path),
    /// Mutual TLS on loopback with the test SOC client certificate.
    Mtls(u16),
}

fn tls_data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/control-tls")
        .join(name)
}

/// A TLS client trusting the robot CA, presenting the `soc` certificate.
fn tls_client() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(tls_data("robot-ca.pem")).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(tls_data("soc.pem"))
        .unwrap()
        .map(|c| c.unwrap())
        .collect();
    let key = PrivateKeyDer::from_pem_file(tls_data("soc.key")).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .unwrap(),
    )
}

/// The robot's TLS files in `dir` (the key copied private).
fn tls_section(dir: &Path) -> Value {
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
    })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn read_all<S: Read>(mut s: S) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

/// One signed v2 request; the answer's status and body. Every answer is
/// checked: its signature verifies with the finding key, bound to this
/// request's signature.
fn call(via: Via<'_>, method: &'static str, target: &str, body: &[u8]) -> (u16, Value) {
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
    let out = match via {
        Via::Unix(path) => {
            let mut s = UnixStream::connect(path).unwrap();
            s.write_all(&req).unwrap();
            read_all(s)
        }
        Via::Mtls(port) => {
            let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let conn = rustls::ClientConnection::new(
                tls_client(),
                ServerName::try_from("127.0.0.1").unwrap(),
            )
            .unwrap();
            let mut s = rustls::StreamOwned::new(conn, tcp);
            s.write_all(&req).unwrap();
            let _ = s.flush();
            read_all(s)
        }
    };
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&out[..split]).into_owned();
    let raw = &out[split + 4..];
    let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
    let answer_sig = head
        .split("\r\n")
        .filter_map(|l| l.split_once(": "))
        .find(|(n, _)| n.eq_ignore_ascii_case("x-robodr-answer-signature"))
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| panic!("answer signature missing: {head}"));
    let (kid, asig) = parse_signature_header(&answer_sig).expect("well-formed answer signature");
    assert_eq!(kid, FINDING_ID);
    let finding_pub = KeyFile::ed25519_from_seed(&FINDING_SEED, None)
        .unwrap()
        .public_key()
        .unwrap();
    assert!(
        robodr_blackbox::sign_ed25519::verify(
            &finding_pub,
            &answer_message(&sig, status, raw),
            &asig
        ),
        "answer signature does not verify"
    );
    (status, serde_json::from_slice(raw).unwrap_or(Value::Null))
}

fn submit(via: Via<'_>, id: &str, action: &str, params: Value, ttl: Option<u64>) -> Value {
    let body = serde_json::to_vec(&json!({
        "request_id": id, "action": action, "parameters": params, "ttl_seconds": ttl,
        "reason": "test", "requested_by": "analyst@soc", "source": "soc-a",
        "authority": "request",
    }))
    .unwrap();
    let (st, v) = call(
        via,
        "POST",
        &format!("/api/v2/robots/{ROBOT}/action-requests"),
        &body,
    );
    assert_eq!(st, 200, "{v}");
    v
}

fn get(via: Via<'_>, id: &str) -> Value {
    let (st, v) = call(
        via,
        "GET",
        &format!("/api/v2/robots/{ROBOT}/action-requests/{id}"),
        b"",
    );
    assert_eq!(st, 200, "{v}");
    v
}

fn revert(via: Via<'_>, id: &str) -> Value {
    let body = br#"{"reason":"done","requested_by":"analyst@soc"}"#;
    let (st, v) = call(
        via,
        "POST",
        &format!("/api/v2/robots/{ROBOT}/action-requests/{id}/revert"),
        body,
    );
    assert_eq!(st, 200, "{v}");
    v
}

fn wait_status(via: Via<'_>, id: &str, want: &str) -> Value {
    wait_for(10, want, || {
        let v = get(via, id);
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
                "motion_control_path": [
                    {"cidr": "192.168.123.0/24", "guid_prefix": PROTECTED_GUID, "low_level": true}
                ]
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

/// The finding key (v2 signs every answer with it).
fn write_finding_key(dir: &Path) -> PathBuf {
    let p = dir.join("finding.key");
    if !p.exists() {
        KeyFile::ed25519_from_seed(&FINDING_SEED, Some(FINDING_ID))
            .unwrap()
            .write_new(&p)
            .unwrap();
    }
    p
}

/// A private state directory (0700) for the request journal and replay
/// store.
fn state_dir(s: &Setup) -> PathBuf {
    let d = s.dir.join("cp-state");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn write_exec_key(dir: &Path) -> PathBuf {
    let key_file = dir.join("executor.key");
    std::fs::write(&key_file, to_hex(&EXEC_KEY)).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    key_file
}

/// agentd with the control plane on `control` (plus mutual TLS on
/// `tls_port`, if any), the live safety feed on `safety` and the executor
/// on `exec_sock`.
fn exec_config(
    s: &Setup,
    control: &Path,
    tls_port: Option<u16>,
    safety: &Path,
    exec_sock: &Path,
) -> Value {
    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        json!({}),
    );
    cfg["finding_signing"] = json!({"key_file": write_finding_key(&s.dir)});
    cfg["context"] = json!({});
    cfg["safety_feed"] = json!({"socket": {"path": safety, "stale_after_ms": 600000}});
    cfg["control_plane"] = json!({
        "unix_socket": control,
        "state_dir": state_dir(s),
        "soc_keys": [write_soc_pub(&s.dir)],
        "rate_per_minute": 600, "burst": 100,
    });
    if let Some(port) = tls_port {
        cfg["control_plane"]["listen_tcp"] = json!(format!("127.0.0.1:{port}"));
        cfg["control_plane"]["tls"] = tls_section(&s.dir);
    }
    cfg["executor"] = json!({
        "enabled": true, "socket": exec_sock, "key_file": write_exec_key(&s.dir),
        "planner_orders": false,
    });
    cfg
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

/// Connect the PLC feed and wait until agentd judges by `idle`.
fn plc_idle(s: &Setup, safety: &Path, control: &Path) -> UnixStream {
    let mut plc = wait_for(5, "safety socket", || UnixStream::connect(safety).ok());
    wait_for(5, "control socket", || UnixStream::connect(control).ok());
    writeln!(plc, "{{\"state\":\"idle\"}}").unwrap();
    wait_for(10, "idle", || {
        (status(&s.spool)?["safety_state"] == "idle").then_some(())
    });
    plc
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
    let model = Model::default();
    let _exec = start_executor(&s.dir, &exec_sock, &s.policy, &model);
    let port = free_port();
    let cfg = exec_config(&s, &control, Some(port), &safety, &exec_sock);
    let (stop, h) = spawn(s.resolve(&cfg));
    let mut plc = plc_idle(&s, &safety, &control);
    let ux = Via::Unix(&control);
    let tls = Via::Mtls(port);

    // The robot says it executes now (over mutual TLS, signed).
    let (_, robot) = wait_for(5, "mTLS listener", || {
        TcpStream::connect(("127.0.0.1", port)).ok()?;
        Some(call(tls, "GET", &format!("/api/v2/robots/{ROBOT}"), b""))
    });
    assert_eq!(robot["executes_actions"], true, "{robot}");
    assert_eq!(robot["executor"], "robodr-executor");
    assert_eq!(robot["api"], "robodr-control-plane/v2");

    // isolate_network: pending, then verified (executed), rules installed;
    // the verified state is signed over mutual TLS as well.
    let v = submit(tls, "iso-1", "isolate_network", json!({}), Some(120));
    assert_eq!(v["status"], "pending", "{v}");
    let v = wait_status(ux, "iso-1", "verified");
    assert_eq!(v["executed"], true);
    assert_eq!(get(tls, "iso-1")["status"], "verified");
    assert!(model.0.lock().unwrap().is_some());

    // quarantine_node of a participant: verified once agentd has seen its
    // SPDP locators (outside the protected network) and hands them on; of
    // the protected rt/lowcmd writer: refused by the executor's own check.
    let mut ev = wait_for(5, "event socket", || {
        UnixStream::connect(s.dir.join("ev.sock")).ok()
    });
    writeln!(
        ev,
        "{{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"0110a2b3c4d5e6f701000000\",\
         \"src_ip\":\"10.0.0.7\",\"locators\":[\"10.0.0.7:7410\"]}}"
    )
    .unwrap();
    wait_for(10, "participant event", || {
        (status(&s.spool)?["inputs"][0]["received"].as_u64()? >= 1).then_some(())
    });
    submit(
        ux,
        "q-1",
        "quarantine_node",
        json!({"participant_guid": "0110a2b3c4d5e6f701000000"}),
        None,
    );
    wait_status(ux, "q-1", "verified");
    let table = serde_json::to_string(&*model.0.lock().unwrap()).unwrap();
    assert!(
        table.contains("10.0.0.7"),
        "locator rule installed: {table}"
    );
    // A participant agentd knows no locators for: refused by the executor.
    submit(
        ux,
        "q-3",
        "quarantine_node",
        json!({"participant_guid": "0110a2b3c4d5e6f703000000"}),
        None,
    );
    let v = wait_status(ux, "q-3", "refused");
    assert_eq!(v["refusal"]["code"], "locators_required", "{v}");
    submit(
        ux,
        "q-2",
        "quarantine_node",
        json!({"participant_guid": PROTECTED_GUID}),
        None,
    );
    let v = wait_status(ux, "q-2", "refused");
    assert_eq!(v["refusal"]["code"], "motion_path", "{v}");
    assert_eq!(v["executed"], false);

    // record_evidence: a black-box mark naming the request note.
    let v = submit(ux, "ev-1", "record_evidence", json!({}), None);
    let req_evidence = v["state"]["evidence"].as_str().unwrap().to_string();
    wait_status(ux, "ev-1", "verified");
    let marks = notes(&s.blackbox, "robodr.evidence_mark");
    assert_eq!(marks.len(), 1);
    assert_eq!(marks[0]["bundle"][0], req_evidence.as_str());

    // restrict_motion: advisory only (no gateway in v1).
    submit(
        ux,
        "m-1",
        "restrict_motion",
        json!({"max_linear_speed": 0.5}),
        Some(60),
    );
    wait_status(ux, "m-1", "recorded_not_executed");

    // Revert: pending, then reverted; the table holds only the quarantine.
    let v = revert(tls, "iso-1");
    assert_eq!(v["status"], "pending", "{v}");
    let v = wait_status(ux, "iso-1", "reverted");
    assert_eq!(v["executed"], true);
    assert_eq!(v["state"]["revert"]["result"], "pending", "{v}");
    let v = revert(ux, "q-1");
    assert_eq!(v["status"], "pending");
    wait_status(ux, "q-1", "reverted");
    assert!(model.0.lock().unwrap().is_none());
    // A second revert of a reverted request: answered `reverted`, nothing
    // is sent again.
    assert_eq!(revert(ux, "q-1")["status"], "reverted");

    // The e-stop engages: the control plane refuses before the executor.
    writeln!(plc, "{{\"state\":\"estop_active\"}}").unwrap();
    wait_for(10, "estop", || {
        (status(&s.spool)?["safety_state"] == "estop_active").then_some(())
    });
    let v = submit(ux, "iso-2", "isolate_network", json!({}), Some(60));
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
    let (sum, log) = finish(stop, h);
    assert!(log.contains("executor v1 enabled"), "{log}");
    assert!(
        log.contains("accepted ones are handed to robodr-executor"),
        "{log}"
    );
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
}

/// Executor states are journalled (control plane v2): a request that read
/// `verified` reads `verified` after a restart, one verified while nobody
/// asked does too, a revert after the restart reaches the executor and its
/// `reverted` survives the next restart.
#[test]
fn executor_states_survive_a_restart() {
    let s = setup("exec-restart", &robot_profile(true));
    let safety = s.dir.join("safety.sock");
    let control = s.dir.join("control.sock");
    let exec_sock = s.dir.join("executor.sock");
    let model = Model::default();
    let _exec = start_executor(&s.dir, &exec_sock, &s.policy, &model);
    let cfg = exec_config(&s, &control, None, &safety, &exec_sock);
    let ux = Via::Unix(&control);

    let (stop, h) = spawn(s.resolve(&cfg));
    let plc = plc_idle(&s, &safety, &control);
    submit(ux, "iso-1", "isolate_network", json!({}), Some(600));
    let verified = wait_status(ux, "iso-1", "verified");
    // The participant's SPDP locators (a quarantine needs them).
    let mut ev = wait_for(5, "event socket", || {
        UnixStream::connect(s.dir.join("ev.sock")).ok()
    });
    writeln!(
        ev,
        "{{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"0110a2b3c4d5e6f701000000\",\
         \"src_ip\":\"10.0.0.7\",\"locators\":[\"10.0.0.7:7410\"]}}"
    )
    .unwrap();
    wait_for(10, "participant event", || {
        (status(&s.spool)?["inputs"][0]["received"].as_u64()? >= 1).then_some(())
    });
    // Never queried before the restart: the daemon journals the executor's
    // word as it arrives.
    submit(
        ux,
        "q-1",
        "quarantine_node",
        json!({"participant_guid": "0110a2b3c4d5e6f701000000"}),
        None,
    );
    wait_for(10, "q-1 verified by the executor", || {
        (status(&s.spool)?["executor"]["verified"].as_u64()? >= 2).then_some(())
    });
    // Give the main loop a turn to journal it.
    let journal = s.dir.join("cp-state/requests.journal");
    wait_for(10, "q-1 journalled", || {
        let j = std::fs::read_to_string(&journal).ok()?;
        j.lines()
            .any(|l| l.contains("\"q-1\"") && l.contains("\"status\":\"verified\""))
            .then_some(())
    });
    drop(plc);
    finish(stop, h);

    // Restart: both still read verified (the link's memory is empty).
    let (stop, h) = spawn(s.resolve(&cfg));
    let plc = plc_idle(&s, &safety, &control);
    let v = get(ux, "iso-1");
    assert_eq!(v["status"], "verified", "{v}");
    assert_eq!(v["executed"], true);
    assert_eq!(
        v["state"], verified["state"],
        "the same state after a restart"
    );
    assert_eq!(get(ux, "q-1")["status"], "verified");
    // A revert after the restart reaches the executor.
    assert_eq!(revert(ux, "iso-1")["status"], "pending");
    wait_status(ux, "iso-1", "reverted");
    drop(plc);
    finish(stop, h);

    // And the revert survives the next restart.
    let (stop, h) = spawn(s.resolve(&cfg));
    let _plc = plc_idle(&s, &safety, &control);
    let v = get(ux, "iso-1");
    assert_eq!(v["status"], "reverted", "{v}");
    assert_eq!(v["state"]["revert"]["requested_by"], "analyst@soc");
    assert_eq!(get(ux, "q-1")["status"], "verified");
    let st = status(&s.spool).unwrap();
    assert_eq!(st["control_plane"]["state"]["journal_damaged"], 0, "{st}");
    finish(stop, h);
    // One request note each; the restarts judged nothing again.
    assert_eq!(notes(&s.blackbox, "robodr.control_plane_request").len(), 2);
}

#[test]
fn unreachable_executor_fails_the_request_and_executes_nothing() {
    let s = setup("exec-down", &robot_profile(true));
    let control = s.dir.join("control.sock");
    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        json!({}),
    );
    cfg["finding_signing"] = json!({"key_file": write_finding_key(&s.dir)});
    cfg["context"] = json!({"safety_state": "idle"});
    cfg["control_plane"] = json!({
        "unix_socket": control,
        "state_dir": state_dir(&s),
        "soc_keys": [write_soc_pub(&s.dir)],
    });
    cfg["executor"] = json!({
        "enabled": true, "socket": s.dir.join("nobody.sock"),
        "key_file": write_exec_key(&s.dir), "timeout_ms": 500,
    });
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(5, "control socket", || UnixStream::connect(&control).ok());
    let ux = Via::Unix(&control);
    submit(ux, "iso-1", "isolate_network", json!({}), Some(60));
    let v = wait_status(ux, "iso-1", "failed");
    assert!(
        v["state"]["error"]
            .as_str()
            .unwrap()
            .contains("executor unreachable"),
        "{v}"
    );
    assert_eq!(v["executed"], false);
    finish(stop, h);
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
