//! `blackbox.head_anchor` kind `remote`: configuration checks, a daemon
//! anchored to an in-process `AnchorReceiver` (marks arrive, a second run
//! opens clean against the held mark), and a daemon whose receiver is
//! unreachable keeps recording (failures counted).

mod common;

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use robodr_blackbox::remote_anchor::{AnchorReceiver, ServeOptions, UnitKey};
use robodr_blackbox::KeyFile;
use std::net::TcpListener;
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
        "timeout_ms": 2000
    });
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
        r2.serve(l, &ServeOptions::default(), &s2).unwrap();
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
