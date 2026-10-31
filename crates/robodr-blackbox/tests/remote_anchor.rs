//! `RemoteHeadAnchor` under a real `Recorder`, against a real
//! `robodr-anchor-receiver` process on 127.0.0.1: a cut log tail plus rolled
//! back `head.json` / `checkpoint.json` is reported as `TruncationDetected`
//! (also after the receiver restarted), a wiped store too, an unreachable
//! receiver is an anchor failure on the record, and the one-way mode
//! (`robodr-blackbox anchor-mark` + `robodr-anchor-receiver ingest`)
//! detects a rollback on the far side.
mod common;
use common::*;
use robodr_blackbox::record::{ResumePayload, TruncationPayload};
use robodr_blackbox::remote_anchor::{RemoteAnchorConfig, RemoteHeadAnchor, ALERTS_FILE};
use robodr_blackbox::store::{segment_file_name, CHECKPOINT_FILE, EXTERNAL_ANCHOR, HEAD_FILE};
use robodr_blackbox::*;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

const UNIT: &str = "ugv-07";

struct Keys {
    _dir: TestDir,
    unit_secret: PathBuf,
    unit_pub: PathBuf,
    recv_secret: PathBuf,
    recv_pub: PathBuf,
}

fn keys() -> Keys {
    let d = TestDir::new("ra-keys");
    let unit_secret = d.sub("unit.key");
    let recv_secret = d.sub("receiver.key");
    let u = KeyFile::generate_ed25519(Some("ugv-07-bb")).unwrap();
    u.write_new(&unit_secret).unwrap();
    u.to_public()
        .unwrap()
        .write_new(&d.sub("unit.key.pub"))
        .unwrap();
    let r = KeyFile::generate_ed25519(Some("anchor-receiver")).unwrap();
    r.write_new(&recv_secret).unwrap();
    r.to_public()
        .unwrap()
        .write_new(&d.sub("receiver.key.pub"))
        .unwrap();
    Keys {
        unit_pub: d.sub("unit.key.pub"),
        recv_pub: d.sub("receiver.key.pub"),
        unit_secret,
        recv_secret,
        _dir: d,
    }
}

impl Keys {
    fn unit_signer(&self) -> Box<dyn Signer> {
        KeyFile::load_secret(&self.unit_secret)
            .unwrap()
            .signer()
            .unwrap()
    }
    fn receiver_verifier(&self) -> Box<dyn Verifier + Send + Sync> {
        Box::new(
            KeyFile::load_public(&self.recv_pub)
                .unwrap()
                .ed25519_verifying_key()
                .unwrap(),
        )
    }
}

fn write_config(dir: &Path, k: &Keys, state: &Path, listen: &str) -> PathBuf {
    let p = dir.join("receiver.json");
    let c = serde_json::json!({
        "listen": listen,
        "state_dir": state,
        "key_file": k.recv_secret,
        "units": [{"unit": UNIT, "public_key": k.unit_pub}],
        "max_connections": 8,
        "io_timeout_ms": 2000,
        "allow_plaintext": true
    });
    std::fs::write(&p, c.to_string()).unwrap();
    p
}

fn bin(name: &str) -> Command {
    Command::new(match name {
        "receiver" => env!("CARGO_BIN_EXE_robodr-anchor-receiver"),
        _ => env!("CARGO_BIN_EXE_robodr-blackbox"),
    })
}

struct Receiver {
    child: Child,
    addr: String,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(config: &Path) -> Receiver {
    let mut child = bin("receiver")
        .args(["serve", "--config"])
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addr = line
        .split("listening on ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or_else(|| panic!("no address in {line:?}"))
        .to_string();
    Receiver { child, addr }
}

fn anchor(k: &Keys, addr: &str) -> Arc<RemoteHeadAnchor> {
    let mut c = RemoteAnchorConfig::new(addr, UNIT);
    c.timeout = Duration::from_secs(2);
    c.allow_plaintext = true;
    Arc::new(RemoteHeadAnchor::new(c, k.receiver_verifier(), k.unit_signer()).unwrap())
}

fn base_cfg(dir: &Path, a: Option<Arc<RemoteHeadAnchor>>) -> RecorderConfig {
    let mut c = cfg(dir, big());
    c.max_segment_bytes = 1 << 20;
    c.head_mark_every_records = 4;
    c.head_mark_interval_ns = 0;
    c.head_anchor = a.map(|a| a as Arc<dyn HeadAnchor>);
    c
}

fn open_with(c: RecorderConfig, k: &Keys) -> Recorder {
    Recorder::open(c, k.unit_signer(), clock()).unwrap()
}

fn truncated(r: &Recorder) -> bool {
    r.open_incidents()
        .iter()
        .any(|i| matches!(i, OpenIncident::TruncationDetected { .. }))
}

fn truncations(dir: &Path) -> Vec<TruncationPayload> {
    all_records(dir)
        .iter()
        .filter(|r| r.kind == RecordKind::TruncationDetected)
        .filter_map(|r| r.payload_json())
        .collect()
}

#[test]
fn real_receiver_reports_a_cut_tail_with_rolled_back_state() {
    let k = keys();
    let d = TestDir::new("ra-it");
    let log = d.sub("log");
    let state = d.sub("receiver-state");
    let config = write_config(d.path(), &k, &state, "127.0.0.1:0");
    let recv = start(&config);

    // Record; keep the state an attacker restores later; record more.
    let a = anchor(&k, &recv.addr);
    let mut r = open_with(base_cfg(&log, Some(Arc::clone(&a))), &k);
    for i in 0..4 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let kept = r.head_mark().unwrap();
    let snap: Vec<(&str, Option<Vec<u8>>)> = [HEAD_FILE, CHECKPOINT_FILE]
        .iter()
        .map(|n| (*n, std::fs::read(log.join(n)).ok()))
        .collect();
    for i in 4..24 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let last = r.close().unwrap().seq;
    assert!(a.flush(Duration::from_secs(10)), "marks delivered");
    assert_eq!(a.delivered_seq(), Some(last));
    assert_eq!(a.delivery_failures(), 0);
    drop(a);

    // The receiver restarts: the mark is durable.
    drop(recv);
    let recv = start(&config);
    let st = bin("receiver")
        .args(["status", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap();
    assert_eq!(v["units"][0]["held_seq"], last, "{v}");

    // The attack: whole frames after `kept` removed, state rolled back.
    let p = log.join(segment_file_name(0));
    let b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    let pos = fr.iter().position(|(_, _, x)| x.seq == kept + 1).unwrap();
    std::fs::write(&p, &b[..fr[pos].0]).unwrap();
    for (n, b) in &snap {
        match b {
            Some(b) => std::fs::write(log.join(n), b).unwrap(),
            None => {
                let _ = std::fs::remove_file(log.join(n));
            }
        }
    }

    // Control: without the anchor the cut log opens clean.
    let ctl = d.sub("control");
    std::fs::create_dir_all(&ctl).unwrap();
    for e in std::fs::read_dir(&log).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), ctl.join(e.file_name())).unwrap();
        }
    }
    let r = open_with(base_cfg(&ctl, None), &k);
    assert!(!truncated(&r), "{:?}", r.open_incidents());
    drop(r);

    // With the remote anchor (a fresh client, as after a reboot).
    let a = anchor(&k, &recv.addr);
    let r = open_with(base_cfg(&log, Some(Arc::clone(&a))), &k);
    assert!(truncated(&r), "{:?}", r.open_incidents());
    assert_eq!(r.anchor_failures(), 0, "{:?}", r.last_anchor_error());
    assert!(
        r.head().unwrap().0 > last,
        "numbering continues after the mark"
    );
    r.close().unwrap();
    let td = truncations(&log);
    assert_eq!(td.len(), 1);
    let ev = td[0]
        .evidence
        .iter()
        .find(|e| e.file == EXTERNAL_ANCHOR)
        .expect("anchor evidence");
    assert_eq!(ev.seq, last, "the remote anchor holds the exact head");
    assert!(a.flush(Duration::from_secs(10)));

    // Wiped store: reported too.
    std::fs::remove_dir_all(&log).unwrap();
    let r = open_with(base_cfg(&log, Some(Arc::clone(&a))), &k);
    assert!(truncated(&r), "{:?}", r.open_incidents());
    r.close().unwrap();
    assert!(a.flush(Duration::from_secs(10)));
    drop(a);
    let st = bin("receiver")
        .args(["status", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap();
    assert!(v["units"][0]["held_seq"].as_u64().unwrap() > last, "{v}");
    assert_eq!(v["units"][0]["alerts"], 0, "{v}");

    // Receiver down: no bound, an anchor failure on the record.
    let addr = recv.addr.clone();
    drop(recv);
    let a = anchor(&k, &addr);
    let r = open_with(base_cfg(&log, Some(a)), &k);
    assert!(r.anchor_failures() > 0);
    drop(r);
    let rs: Vec<ResumePayload> = all_records(&log)
        .iter()
        .filter(|r| r.kind == RecordKind::Resume)
        .filter_map(|r| r.payload_json())
        .collect();
    assert!(rs
        .last()
        .unwrap()
        .rejected_state
        .iter()
        .any(|s| s.contains(EXTERNAL_ANCHOR) && s.contains("remote anchor")));
}

#[test]
fn one_way_marks_detect_a_rollback_on_the_far_side() {
    let k = keys();
    let d = TestDir::new("ra-oneway");
    let log = d.sub("log");
    let state = d.sub("receiver-state");
    let config = write_config(d.path(), &k, &state, "127.0.0.1:0");
    let mark = |out: &Path| {
        let o = bin("blackbox")
            .arg("anchor-mark")
            .arg(&log)
            .arg("--key")
            .arg(&k.unit_secret)
            .args(["--unit", UNIT, "--out"])
            .arg(out)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    let ingest = |f: &Path| {
        bin("receiver")
            .args(["ingest", "--config"])
            .arg(&config)
            .arg(f)
            .output()
            .unwrap()
    };

    let mut r = open_with(base_cfg(&log, None), &k);
    for i in 0..8 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.head_mark().unwrap();
    let old_head = std::fs::read(log.join(HEAD_FILE)).unwrap();
    mark(&d.sub("m1.json"));
    for i in 8..20 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.close().unwrap();
    mark(&d.sub("m2.json"));
    // Refuses to overwrite.
    let o = bin("blackbox")
        .arg("anchor-mark")
        .arg(&log)
        .arg("--key")
        .arg(&k.unit_secret)
        .args(["--unit", UNIT, "--out"])
        .arg(d.sub("m2.json"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));

    let o = ingest(&d.sub("m1.json"));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    let o = ingest(&d.sub("m2.json"));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    // The same mark again is a no-op.
    assert!(ingest(&d.sub("m2.json")).status.success());

    // Later the unit's head.json was rolled back; its next mark is lower.
    std::fs::write(log.join(HEAD_FILE), &old_head).unwrap();
    mark(&d.sub("m3.json"));
    let o = ingest(&d.sub("m3.json"));
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stdout).contains("REFUSED"));
    let alerts = std::fs::read_to_string(state.join(ALERTS_FILE)).unwrap();
    assert!(alerts.contains("\"kind\":\"lower\""), "{alerts}");

    // A tampered mark file: bad signature, refused.
    let mut j: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.sub("m2.json")).unwrap()).unwrap();
    j["mark"]["seq"] = 1_000_000.into();
    std::fs::write(d.sub("m4.json"), j.to_string()).unwrap();
    assert_eq!(ingest(&d.sub("m4.json")).status.code(), Some(1));

    // While `serve` holds the state directory, ingest is refused (exit 2).
    let recv = start(&config);
    assert_eq!(ingest(&d.sub("m2.json")).status.code(), Some(2));
    drop(recv);

    // Config errors.
    let mut bad: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    bad["bogus"] = 1.into();
    let bp = d.sub("bad.json");
    std::fs::write(&bp, bad.to_string()).unwrap();
    let o = bin("receiver")
        .args(["status", "--config"])
        .arg(&bp)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("bogus"));
    // A secret key file as a unit's public key is refused.
    bad = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    bad["units"][0]["public_key"] = k.unit_secret.to_str().unwrap().into();
    std::fs::write(&bp, bad.to_string()).unwrap();
    let o = bin("receiver")
        .args(["status", "--config"])
        .arg(&bp)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

/// A private copy of `fixtures/tls/` with key files 0600.
fn tls_fixtures(d: &TestDir) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = d.sub("pki");
    std::fs::create_dir_all(&dir).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tls");
    for n in [
        "ca.pem",
        "server.pem",
        "server.key",
        "client.pem",
        "client.key",
    ] {
        std::fs::copy(src.join(n), dir.join(n)).unwrap();
        let mode = if n.ends_with(".key") { 0o600 } else { 0o644 };
        std::fs::set_permissions(dir.join(n), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    dir
}

#[test]
fn receiver_binary_serves_mutual_tls_and_refuses_plain_tcp_by_default() {
    let k = keys();
    let d = TestDir::new("ra-tls-bin");
    let pki = tls_fixtures(&d);
    let state = d.sub("receiver-state");
    let config = write_config(d.path(), &k, &state, "127.0.0.1:0");
    let mut c: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();

    // Neither tls nor allow_plaintext: serve refuses to start (exit 2).
    c.as_object_mut().unwrap().remove("allow_plaintext");
    std::fs::write(&config, c.to_string()).unwrap();
    let o = bin("receiver")
        .args(["serve", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("allow_plaintext"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // Both: ambiguous, refused.
    c["allow_plaintext"] = true.into();
    c["tls"] = serde_json::json!({
        "cert_chain": pki.join("server.pem"),
        "key_file": pki.join("server.key"),
        "client_ca": pki.join("ca.pem"),
    });
    std::fs::write(&config, c.to_string()).unwrap();
    let o = bin("receiver")
        .args(["serve", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));

    // Mutual TLS.
    c.as_object_mut().unwrap().remove("allow_plaintext");
    std::fs::write(&config, c.to_string()).unwrap();
    let recv = start(&config);
    let tls = robodr_blackbox::tls::load_client(&robodr_blackbox::tls::ClientTlsFiles {
        ca_file: pki.join("ca.pem"),
        cert_chain: Some(pki.join("client.pem")),
        key_file: Some(pki.join("client.key")),
        ..Default::default()
    })
    .unwrap();
    let mut rc = RemoteAnchorConfig::new(recv.addr.clone(), UNIT);
    rc.tls = Some(tls);
    let a = Arc::new(RemoteHeadAnchor::new(rc, k.receiver_verifier(), k.unit_signer()).unwrap());
    let log = d.sub("log");
    let mut r = open_with(base_cfg(&log, Some(Arc::clone(&a))), &k);
    for i in 0..8 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let last = r.close().unwrap().seq;
    assert!(
        a.flush(Duration::from_secs(10)),
        "marks delivered over mTLS"
    );
    assert_eq!(a.delivered_seq(), Some(last));
    assert_eq!(a.current().unwrap().map(|h| h.seq), Some(last));

    // A plain-TCP client is refused at the handshake: nothing reaches the
    // receiver, and the unit counts an anchor failure.
    let mut pc = RemoteAnchorConfig::new(recv.addr.clone(), UNIT);
    pc.allow_plaintext = true;
    let p = RemoteHeadAnchor::new(pc, k.receiver_verifier(), k.unit_signer()).unwrap();
    assert!(p.current().is_err());
}

/// One plain-TCP `current` query; the answer line.
fn current_query(addr: &str, unit: &str) -> serde_json::Value {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let line = serde_json::json!({"protocol": "robodr-anchor/v1", "op": "current",
                                  "unit": unit, "nonce": "ab".repeat(32)});
    s.write_all(format!("{line}\n").as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    serde_json::from_str(out.trim()).unwrap()
}

/// Poll `current` for `unit` until `want(answer)` (the reload watcher runs
/// every 100 ms here), at most 10 s.
fn wait_for(addr: &str, unit: &str, want: impl Fn(&serde_json::Value) -> bool) -> bool {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(10) {
        if want(&current_query(addr, unit)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// T71: the receiver reloads its unit list while serving (a unit added is
/// served, a unit removed is refused, a broken configuration keeps the
/// previous list), and `check` validates what `serve` would load.
#[test]
fn receiver_reloads_its_unit_list_while_serving_and_check_validates_the_config() {
    let k = keys();
    let d = TestDir::new("ra-reload");
    let state = d.sub("receiver-state");
    let second = KeyFile::generate_ed25519(Some("ugv-08-bb")).unwrap();
    let second_pub = d.sub("ugv-08.key.pub");
    second.to_public().unwrap().write_new(&second_pub).unwrap();
    let cfg = |units: serde_json::Value| {
        serde_json::json!({
            "listen": "127.0.0.1:0", "state_dir": state, "key_file": k.recv_secret,
            "units": units, "allow_plaintext": true, "reload_poll_ms": 100
        })
        .to_string()
    };
    let one = serde_json::json!([{"unit": UNIT, "public_key": k.unit_pub}]);
    let two = serde_json::json!([{"unit": UNIT, "public_key": k.unit_pub},
                                 {"unit": "ugv-08", "public_key": second_pub}]);
    let only_second = serde_json::json!([{"unit": "ugv-08", "public_key": second_pub}]);
    let path = d.sub("receiver.json");
    std::fs::write(&path, cfg(one.clone())).unwrap();

    // check: everything loads (exit 0); a missing unit key fails (exit 2).
    let o = bin("receiver")
        .args(["check", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    assert!(String::from_utf8_lossy(&o.stdout).contains("ok   unit ugv-07"));
    let bad = d.sub("bad.json");
    std::fs::write(
        &bad,
        cfg(serde_json::json!([{"unit": UNIT, "public_key": d.sub("missing.pub")}])),
    )
    .unwrap();
    let o = bin("receiver")
        .args(["check", "--config"])
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stdout).contains("FAIL"));

    let recv = start(&path);
    let unknown = |v: &serde_json::Value| {
        v["ok"] == false && v["error"].as_str().unwrap_or("").contains("unknown unit")
    };
    let served = |v: &serde_json::Value| v["ok"] == true;
    assert!(served(&current_query(&recv.addr, UNIT)));
    assert!(unknown(&current_query(&recv.addr, "ugv-08")));
    // Add a unit: served without a restart.
    std::fs::write(&path, cfg(two)).unwrap();
    assert!(
        wait_for(&recv.addr, "ugv-08", served),
        "ugv-08 never served"
    );
    // A configuration that does not load: refused, the previous list stays.
    std::fs::write(&path, "{ not json").unwrap();
    std::thread::sleep(Duration::from_millis(400));
    assert!(served(&current_query(&recv.addr, "ugv-08")));
    assert!(served(&current_query(&recv.addr, UNIT)));
    // Remove the first unit (decommissioned): refused from then on, its
    // state stays on disk.
    std::fs::write(&path, cfg(only_second)).unwrap();
    assert!(wait_for(&recv.addr, UNIT, unknown), "{UNIT} still served");
    assert!(served(&current_query(&recv.addr, "ugv-08")));
    // check works while serve runs (the listen address is ephemeral here).
    let o = bin("receiver")
        .args(["check", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
}

/// T6: with TLS, `check` prints the days left on the server certificate
/// and each unit CRL in use, and fails on an expired server certificate.
#[test]
fn check_reports_tls_credential_expiry() {
    use std::os::unix::fs::PermissionsExt;
    let k = keys();
    let d = TestDir::new("ra-expiry");
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tls");
    for n in [
        "server.pem",
        "server.key",
        "expired.pem",
        "expired.key",
        "crl-ca.pem",
        "crl-ca.crl.pem",
    ] {
        std::fs::copy(src.join(n), d.sub(n)).unwrap();
        let mode = if n.ends_with(".key") { 0o600 } else { 0o644 };
        std::fs::set_permissions(d.sub(n), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let check = |leaf: &str| {
        let path = d.sub(&format!("{leaf}.json"));
        let c = serde_json::json!({
            "listen": "127.0.0.1:0", "state_dir": d.sub("state"), "key_file": k.recv_secret,
            "units": [{"unit": UNIT, "public_key": k.unit_pub}],
            "tls": {"cert_chain": d.sub(&format!("{leaf}.pem")),
                    "key_file": d.sub(&format!("{leaf}.key")),
                    "client_ca": d.sub("crl-ca.pem"),
                    "crl_files": [d.sub("crl-ca.crl.pem")]}
        });
        std::fs::write(&path, c.to_string()).unwrap();
        let o = bin("receiver")
            .args(["check", "--config"])
            .arg(&path)
            .output()
            .unwrap();
        (
            o.status.code(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
        )
    };
    // Certificate and CRL valid until 2125.
    let (code, out) = check("server");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("ok   server certificate expires in "), "{out}");
    assert!(
        out.lines()
            .any(|l| l.starts_with("ok   crl:") && l.contains(" expires in ")),
        "{out}"
    );
    // A server certificate that expired in 2001.
    let (code, out) = check("expired");
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("FAIL server certificate expired "), "{out}");
}
