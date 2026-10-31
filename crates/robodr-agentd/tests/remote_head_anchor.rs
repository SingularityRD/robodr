//! `blackbox.head_anchor` kind `remote`: configuration checks (TLS
//! required unless plain TCP is explicitly allowed), a daemon anchored to
//! an in-process `AnchorReceiver` over mutual TLS (marks arrive, a second
//! run opens clean against the held mark), a daemon whose receiver
//! presents a certificate for another host (anchor failures, nothing
//! reaches the receiver), and a daemon whose receiver is unreachable keeps
//! recording (failures counted).

mod common;

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use robodr_blackbox::remote_anchor::{AnchorReceiver, ServeOptions, UnitKey};
use robodr_blackbox::KeyFile;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct Keys {
    unit: PathBuf,
    unit_id: String,
    receiver: KeyFile,
    receiver_pub: PathBuf,
}

/// An Ed25519 black-box key file and a receiver key pair under `s.dir/keys`.
fn keys(s: &Setup) -> Keys {
    let d = s.dir.join("keys");
    std::fs::create_dir_all(&d).unwrap();
    let unit = d.join("blackbox-ed.key");
    let k = KeyFile::generate_ed25519(Some("agentd-bb-ed")).unwrap();
    k.write_new(&unit).unwrap();
    let receiver = KeyFile::generate_ed25519(Some("anchor-receiver")).unwrap();
    let receiver_pub = d.join("receiver.key.pub");
    receiver
        .to_public()
        .unwrap()
        .write_new(&receiver_pub)
        .unwrap();
    Keys {
        unit,
        unit_id: k.key_id.clone(),
        receiver,
        receiver_pub,
    }
}

fn replay_cfg(s: &Setup, k: &Keys, address: &str) -> serde_json::Value {
    let pcap = s.pcap(&scenario_frames(1));
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["blackbox"]["key_file"] = k.unit.to_str().unwrap().into();
    cfg["blackbox"]["key_id"] = k.unit_id.clone().into();
    cfg["blackbox"]["head_anchor"] = serde_json::json!({
        "kind": "remote",
        "address": address,
        "receiver_public_key": k.receiver_pub,
        "timeout_ms": 2000,
        "allow_plaintext": true
    });
    cfg
}

/// A private copy of `fixtures/tls/` under `s.dir/pki` (keys 0600).
fn pki(s: &Setup) -> PathBuf {
    let d = s.dir.join("pki");
    std::fs::create_dir_all(&d).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tls");
    for n in [
        "ca.pem",
        "server.pem",
        "server.key",
        "client.pem",
        "client.key",
        "wrong-host.pem",
        "wrong-host.key",
        "crl-ca.crl.pem",
    ] {
        std::fs::copy(src.join(n), d.join(n)).unwrap();
        let mode = if n.ends_with(".key") { 0o600 } else { 0o644 };
        std::fs::set_permissions(d.join(n), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    d
}

/// [`replay_cfg`] over mutual TLS (no `allow_plaintext`).
fn tls_cfg(s: &Setup, k: &Keys, address: &str, pki: &Path) -> serde_json::Value {
    let mut cfg = replay_cfg(s, k, address);
    let a = cfg["blackbox"]["head_anchor"].as_object_mut().unwrap();
    a.remove("allow_plaintext");
    a.insert(
        "tls".into(),
        serde_json::json!({
            "ca_file": pki.join("ca.pem"),
            "cert_chain": pki.join("client.pem"),
            "key_file": pki.join("client.key"),
        }),
    );
    cfg
}

#[test]
fn remote_anchor_config_is_checked() {
    let s = setup("remote-anchor-cfg", &robot_profile(true));
    let k = keys(&s);
    let cfg = replay_cfg(&s, &k, "127.0.0.1:7461");
    // Loading never touches the network.
    let r = s.resolve(&cfg);
    assert!(
        !r.warnings.iter().any(|w| w.contains("head_anchor")),
        "{:?}",
        r.warnings
    );
    assert_eq!(
        r.config.blackbox.head_anchor.as_ref().unwrap().kind(),
        "remote"
    );
    let mut min = cfg.clone();
    min["blackbox"]["head_anchor"]
        .as_object_mut()
        .unwrap()
        .remove("timeout_ms");
    assert!(robodr_agentd::load(&s.write_config(&min)).is_ok());

    let refused = |field: &str, v: serde_json::Value, want: &str| {
        let mut bad = cfg.clone();
        bad["blackbox"]["head_anchor"][field] = v;
        let e = robodr_agentd::load(&s.write_config(&bad)).unwrap_err();
        assert!(e.contains(want), "{field}: {e}");
    };
    refused("address", "nohost".into(), "address");
    refused("address", "host:0".into(), "address");
    refused("address", "a b:1".into(), "address");
    refused("receiver_public_key", "rel.pub".into(), "absolute");
    refused(
        "receiver_public_key",
        s.dir.join("missing.pub").to_str().into(),
        "receiver_public_key",
    );
    // A secret key file is not a public key.
    refused(
        "receiver_public_key",
        k.unit.to_str().into(),
        "receiver_public_key",
    );
    std::fs::create_dir_all(&s.blackbox).unwrap();
    let inside = s.blackbox.join("receiver.pub");
    std::fs::copy(&k.receiver_pub, &inside).unwrap();
    refused(
        "receiver_public_key",
        inside.to_str().into(),
        "must not be inside blackbox.dir",
    );
    refused("timeout_ms", 50.into(), "timeout_ms");
    refused("timeout_ms", 30_001.into(), "timeout_ms");
    refused("bogus", 1.into(), "bogus");

    // Plain TCP only when explicitly allowed; TLS files are checked at load.
    let mut plain = cfg.clone();
    plain["blackbox"]["head_anchor"]
        .as_object_mut()
        .unwrap()
        .remove("allow_plaintext");
    let e = robodr_agentd::load(&s.write_config(&plain)).unwrap_err();
    assert!(e.contains("allow_plaintext"), "{e}");
    let p = pki(&s);
    let tls = tls_cfg(&s, &k, "127.0.0.1:7461", &p);
    assert!(robodr_agentd::load(&s.write_config(&tls)).is_ok());
    let tls_refused = |f: &dyn Fn(&mut serde_json::Value), want: &str| {
        let mut bad = tls.clone();
        f(&mut bad["blackbox"]["head_anchor"]);
        let e = robodr_agentd::load(&s.write_config(&bad)).unwrap_err();
        assert!(e.contains(want), "{want}: {e}");
    };
    tls_refused(&|a| a["allow_plaintext"] = true.into(), "both set");
    tls_refused(&|a| a["tls"]["ca_file"] = "ca.pem".into(), "absolute");
    tls_refused(
        &|a| a["tls"]["ca_file"] = p.join("missing.pem").to_str().into(),
        "ca_file",
    );
    tls_refused(
        &|a| {
            a["tls"].as_object_mut().unwrap().remove("key_file");
        },
        "both cert_chain and key_file",
    );
    tls_refused(
        &|a| a["tls"]["server_spki_sha256"] = serde_json::json!(["00"]),
        "pin",
    );
    tls_refused(
        &|a| a["tls"]["server_name"] = "bad name".into(),
        "server name",
    );
    tls_refused(&|a| a["tls"]["bogus"] = 1.into(), "bogus");
    // crl_files: absolute, and each must hold a CRL.
    tls_refused(
        &|a| a["tls"]["crl_files"] = serde_json::json!(["ca.crl"]),
        "crl_files",
    );
    tls_refused(
        &|a| a["tls"]["crl_files"] = serde_json::json!([p.join("ca.pem")]),
        "no X509 CRL",
    );
    let mut with_crl = tls.clone();
    with_crl["blackbox"]["head_anchor"]["tls"]["crl_files"] =
        serde_json::json!([p.join("crl-ca.crl.pem")]);
    assert!(robodr_agentd::load(&s.write_config(&with_crl)).is_ok());
    std::fs::set_permissions(p.join("client.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    tls_refused(&|_| {}, "mode 0644");
    std::fs::set_permissions(p.join("client.key"), std::fs::Permissions::from_mode(0o600)).unwrap();

    // The receiver verifies with the public key: HMAC is refused.
    let mut hmac = cfg.clone();
    hmac["blackbox"]["key_file"] = s.key.to_str().unwrap().into();
    hmac["blackbox"]["key_id"] = KEY_ID.into();
    let e = robodr_agentd::load(&s.write_config(&hmac)).unwrap_err();
    assert!(e.contains("ed25519"), "{e}");
}

struct Server {
    recv: Arc<AnchorReceiver>,
    stop: Arc<AtomicBool>,
    addr: String,
    th: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.th.take() {
            let _ = t.join();
        }
    }
}

fn serve(state: &Path, k: &Keys) -> Server {
    serve_with(
        state,
        k,
        ServeOptions {
            allow_plaintext: true,
            ..ServeOptions::default()
        },
    )
}

fn serve_with(state: &Path, k: &Keys, opts: ServeOptions) -> Server {
    let unit_pub = KeyFile::load(&k.unit).unwrap().to_public().unwrap();
    let recv = Arc::new(
        AnchorReceiver::open(
            state,
            vec![UnitKey {
                unit: ROBOT.into(),
                verifier: Box::new(unit_pub.ed25519_verifying_key().unwrap()),
            }],
            Box::new(k.receiver.ed25519_signing_key().unwrap()),
            None,
        )
        .unwrap(),
    );
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let (r2, s2) = (Arc::clone(&recv), Arc::clone(&stop));
    let th = std::thread::spawn(move || {
        r2.serve(l, &opts, &s2).unwrap();
    });
    Server {
        recv,
        stop,
        addr,
        th: Some(th),
    }
}

#[test]
fn daemon_anchors_to_a_remote_receiver() {
    let s = setup("remote-anchor-run", &robot_profile(true));
    let k = keys(&s);
    let srv = serve(&s.dir.join("receiver-state"), &k);
    let cfg = replay_cfg(&s, &k, &srv.addr);
    let r = s.resolve(&cfg);
    robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
    let st = status(&s.spool).expect("status.json");
    assert_eq!(st["blackbox"]["anchored"], true, "{st}");
    assert_eq!(st["blackbox"]["anchor_kind"], "remote", "{st}");
    assert_eq!(st["blackbox"]["anchor_failures"], 0, "{st}");
    // The final mark is delivered when the recorder (and its anchor) drop.
    let held = srv.recv.held(ROBOT).expect("a mark at the receiver");
    assert!(held.seq > 0);
    // A second run opens clean against the held mark and moves it on.
    robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
    let st = status(&s.spool).expect("status.json");
    assert_eq!(st["blackbox"]["anchor_failures"], 0, "{st}");
    assert!(srv.recv.held(ROBOT).unwrap().seq > held.seq);
    assert_eq!(srv.recv.alerts(ROBOT), 0);
}

#[test]
fn daemon_anchors_over_mutual_tls_and_refuses_a_wrong_host() {
    let s = setup("remote-anchor-tls", &robot_profile(true));
    let k = keys(&s);
    let p = pki(&s);
    let server = |leaf: &str| {
        robodr_blackbox::tls::load_server(&robodr_blackbox::tls::ServerTlsFiles {
            cert_chain: p.join(format!("{leaf}.pem")),
            key_file: p.join(format!("{leaf}.key")),
            client_ca: Some(p.join("ca.pem")),
            crl_files: Vec::new(),
        })
        .unwrap()
    };
    let srv = serve_with(
        &s.dir.join("receiver-state"),
        &k,
        ServeOptions {
            tls: Some(server("server")),
            ..ServeOptions::default()
        },
    );
    let r = s.resolve(&tls_cfg(&s, &k, &srv.addr, &p));
    robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
    let st = status(&s.spool).expect("status.json");
    assert_eq!(st["blackbox"]["anchor_failures"], 0, "{st}");
    assert!(srv.recv.held(ROBOT).expect("a mark over mTLS").seq > 0);
    drop(srv);

    // A receiver whose certificate names another host: every exchange
    // fails at the handshake, the daemon keeps recording and counts it.
    let s = setup("remote-anchor-tls-wrong", &robot_profile(true));
    let srv = serve_with(
        &s.dir.join("receiver-state"),
        &k,
        ServeOptions {
            tls: Some(server("wrong-host")),
            ..ServeOptions::default()
        },
    );
    let r = s.resolve(&tls_cfg(&s, &k, &srv.addr, &p));
    robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
    let st = status(&s.spool).expect("status.json");
    assert!(
        st["blackbox"]["anchor_failures"].as_u64().unwrap() > 0,
        "{st}"
    );
    assert!(srv.recv.held(ROBOT).is_none());
}

#[test]
fn unreachable_receiver_never_stops_recording() {
    let s = setup("remote-anchor-down", &robot_profile(true));
    let k = keys(&s);
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = replay_cfg(&s, &k, &format!("127.0.0.1:{port}"));
    let r = s.resolve(&cfg);
    robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
    let st = status(&s.spool).expect("status.json");
    assert_eq!(st["blackbox"]["anchored"], true, "{st}");
    assert_eq!(st["blackbox"]["anchor_kind"], "remote");
    assert!(
        st["blackbox"]["anchor_failures"].as_u64().unwrap() > 0,
        "{st}"
    );
}
