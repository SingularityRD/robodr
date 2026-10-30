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

use common::pcap::{
    frame, robot_profile, sedp_datagram, spdp_datagram, ROGUE, ROGUE_HEX, SPDP_GROUP, TWIST,
};
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
struct Model(Arc<Mutex<Option<Vec<Value>>>>, Arc<AtomicBool>);

impl Nft for Model {
    fn run(&mut self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let mut t = self.0.lock().unwrap();
        match args {
            // The switch in `.1`: every transaction fails (a stuck revert).
            ["-j", "-f", "-"] if self.1.load(Ordering::SeqCst) => {
                Err("injected: nft transaction failed".into())
            }
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
                ],
                // Executor review F4: where a quarantine may act.
                "quarantine": {"cidrs": ["10.0.0.0/24"]}
            },
            "max_safety_age_ms": 2000,
            // Executor M1: its own copy of the SOC's public key.
            "soc": {"keys": [write_soc_pub(dir)]}
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
    if p.exists() {
        return p;
    }
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
            &robodr_agentd::control::journal::Sealing::from_blackbox_key_file(&s.key).unwrap(),
        )
        .unwrap(),
    );
    d
}

fn state_dir_path(s: &Setup) -> PathBuf {
    s.dir.join("cp-state")
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

    // restrict_motion: advisory only (the executor does not drive the gateway).
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

/// GA-ROADMAP S5 (gap 2): a failed (stuck) revert is a High finding
/// `robot.agent.executor_revert_failed`, not only a black-box note: once per
/// request while the executor retries, naming the action, the TTL and the
/// error; the failure is in the black box.
#[test]
fn a_failed_revert_is_a_high_finding_with_action_ttl_and_error() {
    let s = setup("exec-revert-failed", &robot_profile(true));
    let safety = s.dir.join("safety.sock");
    let control = s.dir.join("control.sock");
    let exec_sock = s.dir.join("executor.sock");
    let model = Model::default();
    let _exec = start_executor(&s.dir, &exec_sock, &s.policy, &model);
    let cfg = exec_config(&s, &control, None, &safety, &exec_sock);
    let (stop, h) = spawn(s.resolve(&cfg));
    let _plc = plc_idle(&s, &safety, &control);
    let ux = Via::Unix(&control);

    submit(ux, "iso-rf", "isolate_network", json!({}), Some(120));
    wait_status(ux, "iso-rf", "verified");
    assert!(model.0.lock().unwrap().is_some());
    // The table can no longer be changed: the revert fails, and keeps
    // failing on every retry.
    model.1.store(true, Ordering::SeqCst);
    revert(ux, "iso-rf");
    wait_for(15, "revert_failed events", || {
        let evs = notes(&s.blackbox, "robodr.executor_event");
        (evs.iter()
            .filter(|e| e["event"]["kind"] == "revert_failed")
            .count()
            >= 2)
            .then_some(())
    });
    assert!(
        model.0.lock().unwrap().is_some(),
        "the rules are still in force"
    );
    wait_for(10, "revert-failed finding", || {
        (notes_with(&s.blackbox, "robot.agent.executor_revert_failed") >= 1).then_some(())
    });
    let (_, log) = finish(stop, h);
    let found = spooled(&s.spool);
    let f: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.agent.executor_revert_failed")
        .collect();
    assert_eq!(f.len(), 1, "once per request, not per retry\n{log}");
    let env = &f[0].1;
    assert_eq!(env.severity, robodr_events::Severity::High);
    assert_eq!(env.entity_context.mode, robodr_ocsf::Mode::Observe);
    assert_eq!(
        env.title,
        robodr_ocsf::rule_info("robot.agent.executor_revert_failed").title
    );
    let detail = &env.entity_context.detail.value;
    for want in [
        "isolate_network",
        "iso-rf",
        "ttl 120s",
        "injected: nft transaction failed",
    ] {
        assert!(detail.contains(want), "{want} missing: {detail}");
    }
    // The finding is in the black box too.
    assert!(
        notes_with(&s.blackbox, "robot.agent.executor_revert_failed") >= 1,
        "finding recorded in the black box"
    );
}

/// Gap 1 end to end: the request journal and the replay store are sealed
/// and their heads anchored in the black box. A clean restart verifies
/// them (no finding); an older copy of the request journal put back is a
/// Critical `robot.agent.control_plane_state_untrusted`, the forgotten
/// request is restored from the black box (never judged again); an edited
/// entry is a High one. Nothing is reset silently.
#[test]
fn gap1_a_rolled_back_or_edited_request_journal_is_caught_at_start() {
    let s = setup("exec-state-seal", &robot_profile(true));
    let safety = s.dir.join("safety.sock");
    let control = s.dir.join("control.sock");
    let exec_sock = s.dir.join("executor.sock");
    let model = Model::default();
    let _exec = start_executor(&s.dir, &exec_sock, &s.policy, &model);
    let cfg = exec_config(&s, &control, None, &safety, &exec_sock);
    let journal = state_dir_path(&s).join("requests.journal");
    let ux = Via::Unix(&control);
    let untrusted = |s: &Setup| -> Vec<(robodr_events::Severity, String)> {
        spooled(&s.spool)
            .into_iter()
            .filter(|(_, e)| {
                e.entity_context.rule_id == "robot.agent.control_plane_state_untrusted"
            })
            .map(|(_, e)| (e.severity, e.entity_context.detail.value))
            .collect()
    };

    // Run 1: one request; a clean stop anchors both heads.
    let (stop, h) = spawn(s.resolve(&cfg));
    let plc = plc_idle(&s, &safety, &control);
    submit(ux, "ev-a", "record_evidence", json!({}), None);
    wait_status(ux, "ev-a", "verified");
    finish(stop, h);
    drop(plc);
    let old_copy = std::fs::read(&journal).unwrap();
    let text = String::from_utf8(old_copy.clone()).unwrap();
    assert!(text.contains("robodr-cp-journal/v2"), "{text}");
    let heads = notes(&s.blackbox, "robodr.control_plane_state_head");
    assert!(heads.iter().any(|n| n["clean"] == true), "{heads:?}");

    // Run 2: verified against the clean head; a second request.
    let (stop, h) = spawn(s.resolve(&cfg));
    let plc = plc_idle(&s, &safety, &control);
    submit(ux, "ev-b", "record_evidence", json!({}), None);
    wait_status(ux, "ev-b", "verified");
    finish(stop, h);
    drop(plc);
    assert!(untrusted(&s).is_empty(), "a clean restart is not tampering");

    // Run 3: the older copy put back (ev-b forgotten by the file).
    std::fs::write(&journal, &old_copy).unwrap();
    let (stop, h) = spawn(s.resolve(&cfg));
    let plc = plc_idle(&s, &safety, &control);
    // 200: restored from its black-box note, not unknown.
    let v = get(ux, "ev-b");
    assert!(v.to_string().contains("ev-b"), "restored: {v}");
    let (_, log) = finish(stop, h);
    drop(plc);
    let u = untrusted(&s);
    assert_eq!(u.len(), 1, "{log}");
    assert_eq!(u[0].0, robodr_events::Severity::Critical);
    assert!(u[0].1.contains("request journal rolled back"), "{}", u[0].1);

    // Run 4: an entry edited (valid JSON, no key): High.
    let text = std::fs::read_to_string(&journal).unwrap();
    let edited = text.replacen("ev-a", "ev-z", 1);
    assert_ne!(edited, text);
    std::fs::write(&journal, edited).unwrap();
    let (stop, h) = spawn(s.resolve(&cfg));
    let plc = plc_idle(&s, &safety, &control);
    let (_, log) = finish(stop, h);
    drop(plc);
    let u = untrusted(&s);
    assert_eq!(u.len(), 2, "{log}");
    assert!(
        u.iter()
            .any(|(sev, d)| *sev == robodr_events::Severity::High
                && d.contains("failing their seal")),
        "{u:?}"
    );
    assert!(std::fs::read_dir(state_dir_path(&s).join("quarantine"))
        .unwrap()
        .next()
        .is_some());
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

/// Red team F3 (row R6e): the SOC quarantines the rogue participant after
/// a GUID spray (R2) pushed it out of the binding table. agentd used to
/// hand the executor no locators then (`locators_required`); it now hands
/// it the rogue's own last announced ones, and the quarantine is verified.
#[test]
fn a_rogue_pushed_out_by_a_guid_spray_is_still_quarantined_by_its_own_locators() {
    let s = setup("exec-rt-f3", &robot_profile(true));
    let safety = s.dir.join("safety.sock");
    let control = s.dir.join("control.sock");
    let exec_sock = s.dir.join("executor.sock");
    let model = Model::default();
    let _exec = start_executor(&s.dir, &exec_sock, &s.policy, &model);
    let rogue_ip = std::net::Ipv4Addr::new(10, 0, 0, 66);
    let spray_ip = std::net::Ipv4Addr::new(10, 0, 0, 77);
    let mut frames = vec![
        frame(rogue_ip, SPDP_GROUP, 7400, &spdp_datagram(ROGUE, rogue_ip)),
        frame(
            rogue_ip,
            rogue_ip,
            7410,
            &sedp_datagram(ROGUE, "rt/cmd_vel", TWIST),
        ),
    ];
    const SPRAY: u32 = 1500;
    for i in 0..SPRAY {
        let mut g = [0xd1; 12];
        g[8..12].copy_from_slice(&i.to_be_bytes());
        frames.push(frame(
            spray_ip,
            SPDP_GROUP,
            7400,
            &spdp_datagram(g, spray_ip),
        ));
    }
    let mut cfg = exec_config(&s, &control, None, &safety, &exec_sock);
    cfg["sensor"]["capture"] = json!({"enabled": true, "pcap_replay": s.pcap(&frames)});
    let (stop, h) = spawn(s.resolve(&cfg));
    let _plc = plc_idle(&s, &safety, &control);
    wait_for(60, "capture replayed", || {
        let st = status(&s.spool)?;
        (st["daemon"]["datagrams"].as_u64()? >= u64::from(SPRAY) + 2).then_some(())
    });
    let st = status(&s.spool).unwrap();
    assert!(
        st["pipeline"]["binding"]["evicted"].as_u64().unwrap() > 0,
        "the spray evicted bindings: {}",
        st["pipeline"]["binding"]
    );
    let ux = Via::Unix(&control);
    submit(
        ux,
        "q-rogue",
        "quarantine_node",
        json!({"participant_guid": ROGUE_HEX}),
        None,
    );
    let v = wait_status(ux, "q-rogue", "verified");
    assert_eq!(v["executed"], true, "{v}");
    let table = serde_json::to_string(&*model.0.lock().unwrap()).unwrap();
    assert!(table.contains("10.0.0.66"), "rogue locator rule: {table}");
    assert!(!table.contains("10.0.0.77"), "never the sprayer's: {table}");
    finish(stop, h);
}

// --- Review of the red-team fixes (wt/redfix, H1, H2, M7) -------------------
// The reviewer's proofs of concept through the real agentd and the real
// (in-process) executor: the quarantine of a rogue never cuts another
// participant's address, and the rogue cannot make itself unquarantinable.

const LEGIT_HEX_: &str = common::pcap::LEGIT_HEX;
const DECOY: [u8; 12] = [0xc7; 12];
const DECOY_HEX: &str = "c7c7c7c7c7c7c7c7c7c7c7c7";

fn v4(d: u8) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new(10, 0, 0, d)
}

/// SPDP for `prefix` sent from `src`, announcing locators on `ips`.
fn spdp_from(src: std::net::Ipv4Addr, prefix: [u8; 12], ips: &[std::net::Ipv4Addr]) -> Vec<u8> {
    use common::pcap::{datagram, spdp_sub};
    frame(
        src,
        SPDP_GROUP,
        7400,
        &datagram(prefix, &[spdp_sub(prefix, ips)]),
    )
}

fn writer_from(src: std::net::Ipv4Addr, prefix: [u8; 12]) -> Vec<u8> {
    frame(
        src,
        v4(10),
        7410,
        &sedp_datagram(prefix, "rt/cmd_vel", TWIST),
    )
}

/// The request's state once the executor answered (verified / refused /
/// failed).
fn wait_final(via: Via<'_>, id: &str) -> Value {
    wait_for(10, "executor answer", || {
        let v = get(via, id);
        matches!(
            v["status"].as_str(),
            Some("verified" | "refused" | "failed")
        )
        .then_some(v)
    })
}

/// Replay `frames` (`step` apart), optionally feed participant `events`
/// (JSONL), then quarantine `guid` from the SOC. The request's final state
/// and the nftables model's table (`"null"` when nothing is installed).
fn soc_quarantine(
    tag: &str,
    frames: &[Vec<u8>],
    step: std::time::Duration,
    events: &[&str],
    guid: &str,
) -> (Value, String) {
    let s = setup(tag, &robot_profile(true));
    let safety = s.dir.join("safety.sock");
    let control = s.dir.join("control.sock");
    let exec_sock = s.dir.join("executor.sock");
    let model = Model::default();
    let _exec = start_executor(&s.dir, &exec_sock, &s.policy, &model);
    let mut cfg = exec_config(&s, &control, None, &safety, &exec_sock);
    cfg["sensor"]["capture"] = json!({"enabled": true, "pcap_replay": s.pcap_spaced(frames, step)});
    let (stop, h) = spawn(s.resolve(&cfg));
    let _plc = plc_idle(&s, &safety, &control);
    wait_for(30, "capture replayed", || {
        let st = status(&s.spool)?;
        (st["daemon"]["datagrams"].as_u64()? >= frames.len() as u64).then_some(())
    });
    if !events.is_empty() {
        let mut ev = wait_for(5, "event socket", || {
            UnixStream::connect(s.dir.join("ev.sock")).ok()
        });
        for e in events {
            writeln!(ev, "{e}").unwrap();
        }
        wait_for(10, "participant events", || {
            (status(&s.spool)?["inputs"][0]["received"].as_u64()? >= events.len() as u64)
                .then_some(())
        });
    }
    let ux = Via::Unix(&control);
    submit(
        ux,
        "q-review",
        "quarantine_node",
        json!({"participant_guid": guid}),
        None,
    );
    let v = wait_final(ux, "q-review");
    let table = serde_json::to_string(&*model.0.lock().unwrap()).unwrap();
    finish(stop, h);
    (v, table)
}

/// H1 (PoC 2): the profiled participant's lease ran out; one SPDP for its
/// prefix from the attacker's host, then a decoy announcing the robot
/// participant's address next to its own. The SOC quarantines the decoy:
/// the robot participant's address must never be cut.
#[test]
fn review_h1_quarantine_of_a_decoy_never_cuts_the_profiled_participant() {
    let frames = vec![
        spdp_from(v4(10), common::pcap::LEGIT, &[v4(10)]),
        spdp_from(v4(66), common::pcap::LEGIT, &[v4(66)]),
        spdp_from(v4(66), DECOY, &[v4(66), v4(10)]),
    ];
    let (v, table) = soc_quarantine(
        "rv-h1",
        &frames,
        std::time::Duration::from_secs(120),
        &[],
        DECOY_HEX,
    );
    assert!(
        !table.contains("\"10.0.0.10\""),
        "the robot participant's address was cut: {v}\n{table}"
    );
    assert_eq!(v["status"], "verified", "{v}");
    assert!(table.contains("\"10.0.0.66\""), "{table}");
}

/// H2a: a live decoy prefix (from its own address) copies the rogue's
/// locators. The rogue's quarantine used to be refused
/// (`locators_required`).
#[test]
fn review_h2a_a_decoy_cannot_make_the_rogue_unquarantinable() {
    let frames = vec![
        spdp_from(v4(66), ROGUE, &[v4(66)]),
        writer_from(v4(66), ROGUE),
        spdp_from(v4(67), DECOY, &[v4(66)]),
    ];
    let (v, table) = soc_quarantine(
        "rv-h2a",
        &frames,
        std::time::Duration::from_millis(10),
        &[],
        ROGUE_HEX,
    );
    assert_eq!(v["status"], "verified", "{v}");
    assert!(table.contains("\"10.0.0.66\""), "{table}");
    assert!(!table.contains("\"10.0.0.67\""), "{table}");
}

/// H2a from the rogue's own address (review R2-3 (a); it was mis-titled
/// "spoofed": the rogue's second prefix needs no spoofing). Both prefixes
/// have evidence at the same ip:port; it used to be handed to neither, so
/// the rogue was quarantined by GUID prefix only. They share the host: the
/// rogue's address is cut.
#[test]
fn review_h2a_a_self_decoy_does_not_reduce_the_quarantine_to_guid_only() {
    let frames = vec![
        spdp_from(v4(66), ROGUE, &[v4(66)]),
        writer_from(v4(66), ROGUE),
        spdp_from(v4(66), DECOY, &[v4(66)]),
    ];
    let (v, table) = soc_quarantine(
        "rv-h2a-self",
        &frames,
        std::time::Duration::from_millis(10),
        &[],
        ROGUE_HEX,
    );
    assert_eq!(v["status"], "verified", "{v}");
    assert!(table.contains("robodr quarantine_node"), "{table}");
    assert!(table.contains("\"10.0.0.66\""), "self-decoy: {table}");
}

/// H2b: the rogue announces (and sends SPDP from) a locator outside the
/// quarantine scope and one inside the motion control path, plus a loopback
/// one. They used to make the executor refuse the whole order; they are
/// now dropped (with the reason in the answer's note) and the rest, plus
/// the GUID-prefix drop, is quarantined.
#[test]
fn review_h2b_poison_locators_are_dropped_not_a_reason_to_refuse() {
    let far = std::net::Ipv4Addr::new(10, 99, 0, 1);
    let motion = std::net::Ipv4Addr::new(192, 168, 123, 5);
    let lo = std::net::Ipv4Addr::LOCALHOST;
    let ips = [v4(66), far, motion, lo];
    let frames = vec![
        spdp_from(v4(66), ROGUE, &ips),
        spdp_from(far, ROGUE, &ips),
        spdp_from(motion, ROGUE, &ips),
        writer_from(v4(66), ROGUE),
    ];
    let (v, table) = soc_quarantine(
        "rv-h2b",
        &frames,
        std::time::Duration::from_millis(10),
        &[],
        ROGUE_HEX,
    );
    assert_eq!(v["status"], "verified", "{v}");
    assert!(table.contains("\"10.0.0.66\""), "{table}");
    for bad in ["10.99.0.1", "192.168.123.5", "127.0.0.1"] {
        assert!(!table.contains(&format!("\"{bad}\"")), "{bad}: {table}");
    }
}

/// M7: a JSONL participant event used to fill the locators of a prefix the
/// binding table deliberately gave none (here the profiled prefix,
/// contested by a second host): the robot participant's quarantine was
/// executed on whatever the event announced.
#[test]
fn review_m7_an_event_input_does_not_bypass_the_binding_tables_refusal() {
    let frames = vec![
        spdp_from(v4(10), common::pcap::LEGIT, &[v4(10)]),
        spdp_from(v4(66), common::pcap::LEGIT, &[v4(66)]),
    ];
    let ev = format!(
        "{{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"{LEGIT_HEX_}\",\
         \"src_ip\":\"10.0.0.66\",\"locators\":[\"10.0.0.66:7410\",\"10.0.0.10:7410\"]}}"
    );
    let (v, table) = soc_quarantine(
        "rv-m7",
        &frames,
        std::time::Duration::from_millis(10),
        &[&ev],
        LEGIT_HEX_,
    );
    assert_eq!(v["status"], "refused", "{v}\n{table}");
    assert_eq!(v["refusal"]["code"], "locators_required", "{v}");
    assert_eq!(table, "null");
}

// --- Second review of the red-team fixes (wt/redfix, R2-3, R2-6) ------------

/// R2-3: the rogue announced its locators only on an address it never
/// sends from (no spoofing), so the executor installed the RTPS-header
/// GUID-prefix drop alone (bypassable with INFO_SRC or a new prefix). The
/// SOC still read `verified` / `in_force: true` with no hint of the scope.
/// The answer now says how far the quarantine reaches (`containment`) and
/// what was cut and left out (`state.quarantine`).
#[test]
fn review2_r2_3_the_soc_answer_carries_the_quarantine_scope() {
    // GUID prefix only: every locator is on an address it never sent from,
    // and the address it sends from is outside the executor's quarantine
    // scope (since review R3-1 an in-scope one is cut whole: `partial`,
    // `review3_r3_1_*`).
    let out = std::net::Ipv4Addr::new(10, 99, 0, 66);
    let frames = vec![spdp_from(out, ROGUE, &[v4(68)]), writer_from(out, ROGUE)];
    let (v, table) = soc_quarantine(
        "rv2-r2-3-guid",
        &frames,
        std::time::Duration::from_millis(10),
        &[],
        ROGUE_HEX,
    );
    assert_eq!(v["status"], "verified", "{v}");
    assert_eq!(v["in_force"], true, "{v}");
    assert_eq!(v["containment"], "guid_only", "{v}");
    assert_containment_matches_rules(&v, &table);
    let q = &v["state"]["quarantine"];
    assert_eq!(q["locators"], json!([]), "{v}");
    let ex = q["excluded"].as_array().unwrap_or_else(|| panic!("{v}"));
    assert!(
        ex.iter().any(|x| x["locator"] == "10.0.0.68:7410"
            && x["reason"].as_str().unwrap().contains("never seen sending")),
        "{v}"
    );
    assert_eq!(q["addresses"], json!([]), "{v}");
    let exa = q["excluded_addresses"].as_array().unwrap();
    assert!(
        exa.iter().any(|x| x["address"] == "10.99.0.66"
            && x["reason"]
                .as_str()
                .unwrap()
                .contains("network.quarantine.cidrs")),
        "{v}"
    );
    // Full: every announced locator cut.
    let frames = vec![
        spdp_from(v4(66), ROGUE, &[v4(66)]),
        writer_from(v4(66), ROGUE),
    ];
    let (v, table) = soc_quarantine(
        "rv2-r2-3-full",
        &frames,
        std::time::Duration::from_millis(10),
        &[],
        ROGUE_HEX,
    );
    assert_eq!(v["containment"], "full", "{v}");
    assert_containment_matches_rules(&v, &table);
    assert_eq!(
        v["state"]["quarantine"]["locators"],
        json!(["10.0.0.66:7410", "10.0.0.66:7411"]),
        "{v}"
    );
    // Partial: one announced locator outside the executor's scope.
    let far = std::net::Ipv4Addr::new(10, 99, 0, 1);
    let frames = vec![
        spdp_from(v4(66), ROGUE, &[v4(66), far]),
        spdp_from(far, ROGUE, &[v4(66), far]),
        writer_from(v4(66), ROGUE),
    ];
    let (v, table) = soc_quarantine(
        "rv2-r2-3-part",
        &frames,
        std::time::Duration::from_millis(10),
        &[],
        ROGUE_HEX,
    );
    assert_eq!(v["containment"], "partial", "{v}");
    assert_containment_matches_rules(&v, &table);
    let ex = v["state"]["quarantine"]["excluded"].as_array().unwrap();
    assert!(ex.iter().any(|x| x["locator"] == "10.99.0.1:7410"), "{v}");
}

/// R2-6: agentd cut the binding's locators to the order's limit (16)
/// silently: the rogue could push its real port out with 16 decoy ports on
/// its own address, and nothing said why it was not cut.
#[test]
fn review2_r2_6_locators_over_the_order_limit_are_listed_as_left_out() {
    use robodr_agentd::executor_link::{attach_locators, LocatorBook};
    use robodr_executor::order::{Order, Origin, Target};
    let o = Order {
        id: "q".into(),
        action: robodr_responder::ActionId::QuarantineNode,
        target: Target::Participant {
            guid_prefix: ROGUE_HEX.parse().unwrap(),
            locators: Vec::new(),
            guid_only: false,
            excluded: Vec::new(),
            addresses: Vec::new(),
            excluded_addresses: Vec::new(),
            evidence_truncated: false,
        },
        ttl_s: None,
        judged_state: robodr_responder::SafetyState::Idle,
        context: robodr_responder::OperationalContext {
            platform: robodr_responder::PlatformFamily::Ugv,
            morphology: robodr_responder::Morphology::WheeledMobile,
            phase: robodr_responder::MissionPhase::Transit,
            connectivity: robodr_responder::Connectivity::Connected,
            control: robodr_responder::ControlMode::Autonomous,
            operator_present: true,
            profile_locked: true,
        },
        plan_morphology: robodr_responder::Morphology::WheeledMobile,
        human_approved: true,
        replay: false,
        origin: Origin::Planner {
            rule: "r".into(),
            finding_id: None,
        },
        issued_ms: 0,
        soc: None,
    };
    let all: Vec<std::net::SocketAddr> = (0..20u16)
        .map(|i| format!("10.0.0.66:{}", 7400 + i).parse().unwrap())
        .collect();
    let out = attach_locators(
        o,
        |_, _| robodr_ros2_pipeline::QuarantineTarget {
            locators: all.clone(),
            excluded: Vec::new(),
            known: true,
            guid_only: true,
            ..Default::default()
        },
        &LocatorBook::default(),
    );
    let Target::Participant {
        locators, excluded, ..
    } = &out.target
    else {
        panic!()
    };
    assert_eq!(locators.len(), robodr_executor::order::MAX_LOCATORS);
    let left: Vec<u16> = excluded.iter().map(|x| x.port).collect();
    assert_eq!(left, vec![7416, 7417, 7418, 7419], "{excluded:?}");
    assert!(excluded.iter().all(|x| x.reason.contains("limit")));
    out.validate().unwrap();
}

// --- Third review of the red-team fixes (wt/redfix, R3-1) --------------------

/// What table `inet robodr` (the executor's nftables model) does with one
/// UDP datagram: `"accept"` or `"drop"`.
fn model_verdict(
    table: &str,
    chain: &str,
    src: (&str, u16),
    dst: (&str, u16),
    payload: &[u8],
) -> String {
    use robodr_executor::nftmodel::{verdict_listed, Packet};
    let objs: Vec<Value> = serde_json::from_str::<Option<Vec<Value>>>(table)
        .unwrap()
        .unwrap_or_default();
    let p = Packet::udp(
        chain,
        (src.0.parse().unwrap(), src.1),
        (dst.0.parse().unwrap(), dst.1),
        payload,
    );
    verdict_listed(&objs, &p).unwrap().to_string()
}

/// `containment` must match the rules actually written: every address in
/// `state.quarantine.addresses` drops a datagram from an ephemeral source
/// port to a DDS port of the robot whatever its RTPS header says; `full`
/// only when nothing was left out and every cut locator's address is one
/// of them; `guid_only` only when no address or locator rule exists.
fn assert_containment_matches_rules(v: &Value, table: &str) {
    let q = &v["state"]["quarantine"];
    let addrs: Vec<String> = q["addresses"]
        .as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
        .unwrap_or_default();
    let other = robodr_executor::nftmodel::rtps(DECOY_HEX);
    for a in &addrs {
        assert_eq!(
            model_verdict(table, "input", (a, 52_101), ("10.0.0.1", 7410), &other),
            "drop",
            "address {a} is reported cut but its traffic passes: {v}\n{table}"
        );
    }
    let locators: Vec<String> = q["locators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    match v["containment"].as_str().unwrap() {
        "full" => {
            assert!(!addrs.is_empty(), "{v}");
            assert_eq!(q["excluded"], json!([]), "{v}");
            assert!(
                q.get("excluded_addresses")
                    .is_none_or(|x| x.as_array().is_some_and(Vec::is_empty)),
                "{v}"
            );
            for l in &locators {
                let ip = l.parse::<std::net::SocketAddr>().unwrap().ip().to_string();
                assert!(addrs.contains(&ip), "locator {l} not covered: {v}");
            }
        }
        "guid_only" => {
            assert!(addrs.is_empty() && locators.is_empty(), "{v}");
        }
        "partial" => {}
        other => panic!("containment {other}: {v}"),
    }
}

/// R3-1: `containment: "full"` meant "every announced locator has a rule",
/// but the inbound rule matched only `saddr <ip> udp sport <announced
/// port>`. Fast DDS sends from ephemeral ports, so inbound traffic of a
/// "fully contained" participant was held back only by the GUID-prefix
/// drop, which `INFO_SRC` re-attribution evades. The address it sends from
/// is now cut whole (to the robot's DDS ports, any source port).
#[test]
fn review3_r3_1_a_participant_sending_from_an_ephemeral_port_is_dropped() {
    let frames = vec![
        spdp_from(v4(66), ROGUE, &[v4(66)]),
        writer_from(v4(66), ROGUE),
    ];
    let (v, table) = soc_quarantine(
        "rv3-r3-1",
        &frames,
        std::time::Duration::from_millis(10),
        &[],
        ROGUE_HEX,
    );
    assert_eq!(v["status"], "verified", "{v}");
    assert_eq!(v["containment"], "full", "{v}");
    // RTPS re-attributed to another prefix, from an ephemeral port: dropped.
    let other = robodr_executor::nftmodel::rtps(DECOY_HEX);
    assert_eq!(
        model_verdict(
            &table,
            "input",
            ("10.0.0.66", 52_101),
            ("10.0.0.1", 7410),
            &other
        ),
        "drop",
        "{v}\n{table}"
    );
    assert_eq!(
        model_verdict(
            &table,
            "input",
            ("10.0.0.66", 52_101),
            ("10.0.0.1", 7650),
            b"x"
        ),
        "accept",
        "only the robot's DDS ports (domain 0: 7400-7649) are cut: {table}"
    );
    assert_eq!(
        model_verdict(
            &table,
            "forward",
            ("10.0.0.66", 52_101),
            ("10.0.0.20", 7411),
            b"x"
        ),
        "drop",
        "{table}"
    );
    // Another host on the same network: untouched.
    assert_eq!(
        model_verdict(
            &table,
            "input",
            ("10.0.0.67", 52_101),
            ("10.0.0.1", 7410),
            &other
        ),
        "accept",
        "{table}"
    );
    // To the participant's host, any DDS port: dropped.
    assert_eq!(
        model_verdict(
            &table,
            "output",
            ("10.0.0.1", 40_000),
            ("10.0.0.66", 7499),
            b"x"
        ),
        "drop",
        "{table}"
    );
    assert_eq!(
        v["state"]["quarantine"]["addresses"],
        json!(["10.0.0.66"]),
        "{v}"
    );
    assert_containment_matches_rules(&v, &table);

    // An observed source address it never announced as a locator is cut
    // too; the announced-only one is not (left out): `partial`.
    let frames = vec![
        spdp_from(v4(66), ROGUE, &[v4(68)]),
        writer_from(v4(66), ROGUE),
    ];
    let (v, table) = soc_quarantine(
        "rv3-r3-1-unannounced",
        &frames,
        std::time::Duration::from_millis(10),
        &[],
        ROGUE_HEX,
    );
    assert_eq!(v["status"], "verified", "{v}");
    assert_eq!(v["containment"], "partial", "{v}");
    assert_eq!(
        model_verdict(
            &table,
            "input",
            ("10.0.0.66", 52_101),
            ("10.0.0.1", 7410),
            &other
        ),
        "drop",
        "{v}\n{table}"
    );
    assert_containment_matches_rules(&v, &table);
}

/// Review of gap 1, finding 1: after the executor's journal is reset (its
/// event sequence starts again at 1), agentd still sees the new events,
/// the `journal_reset` among them, and raises the epoch change: it does not
/// keep waiting for sequence numbers above the old ones.
#[test]
fn review_gap1_f1_agentd_follows_an_executor_journal_reset() {
    let s = setup("exec-epoch", &robot_profile(true));
    let exec_sock = s.dir.join("executor.sock");
    let model = Model::default();
    let exec = start_executor(&s.dir, &exec_sock, &s.policy, &model);
    // A few events (operator re-arms) so the sequence is well above 1.
    let client = robodr_executor::client::Client::new(
        exec_sock.clone(),
        Key::from_bytes(EXEC_KEY),
        std::time::Duration::from_secs(5),
    );
    for _ in 0..5 {
        client.rearm("test").unwrap();
    }
    let spec = robodr_agentd::executor_link::ExecutorSpec {
        socket: exec_sock.clone(),
        key: Key::from_bytes(EXEC_KEY),
        planner_orders: false,
        timeout: std::time::Duration::from_secs(5),
    };
    let link = robodr_agentd::executor_link::ExecutorLink::start(
        &spec,
        robodr_agentd::executor_link::SafetyCell::default(),
    )
    .unwrap();
    let first = wait_for(10, "the executor's events", || {
        let evs = link.take_events();
        (evs.len() >= 5).then_some(evs)
    });
    assert!(first.iter().all(|e| e.seq >= 1));
    let before = wait_for(5, "a journal head", || link.journal_head());
    // The executor restarts on an unreadable journal: reset, sequence
    // restarted, a new epoch.
    drop(exec);
    std::fs::write(s.dir.join("executor-state/journal.json"), b"garbage").unwrap();
    let _exec = start_executor(&s.dir, &exec_sock, &s.policy, &model);
    let evs = wait_for(15, "the journal_reset event after the reset", || {
        let evs = link.take_events();
        evs.iter()
            .any(|e| e.kind == robodr_executor::journal::EventKind::JournalReset)
            .then_some(evs)
    });
    assert!(evs.iter().all(|e| e.seq < before.next_seq), "{evs:?}");
    let alarms = link.take_head_alarms();
    assert_eq!(alarms.len(), 1, "{alarms:?}");
    assert!(alarms[0].1.contains("epoch changed"), "{}", alarms[0].1);
    assert_ne!(link.journal_head().unwrap().epoch, before.epoch);
}
