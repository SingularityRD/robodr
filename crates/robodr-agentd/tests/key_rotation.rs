//! Black-box key rotation in the daemon (`blackbox.previous_keys`) and the
//! legacy-HMAC policy (`blackbox.allow_hmac`).
//!
//! A log signed with key A and rotated in place to key B
//! (`Recorder::rotate_key`, what `robodr-blackbox rotate` does) is
//! continued by the daemon with B only when A's public key is listed in
//! `blackbox.previous_keys`; without it the daemon refuses to start and
//! names the setting. The continued chain verifies with both public keys.

mod common;

use std::path::{Path, PathBuf};

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use robodr_agentd::StopReason;
use robodr_blackbox::{KeyFile, Keyring, Recorder, RecorderConfig, SteppingClock, TimeSource};

/// Write an Ed25519 key pair `<name>.key` / `<name>.key.pub` (bound to
/// `device`, if given) under `dir`.
fn key_pair(dir: &Path, name: &str, seed: u8, device: Option<&str>) -> (KeyFile, PathBuf) {
    let k = KeyFile::ed25519_from_seed(&[seed; 32], Some(name))
        .unwrap()
        .with_device_id(device)
        .unwrap();
    let p = dir.join(format!("{name}.key"));
    k.write_new(&p).unwrap();
    k.to_public()
        .unwrap()
        .write_new(&dir.join(format!("{name}.key.pub")))
        .unwrap();
    (k, p)
}

/// The fixture config with `key` as the black-box key (no HMAC opt-in).
fn config_with_key(s: &Setup, key: &Path) -> serde_json::Value {
    let pcap = s.pcap(&scenario_frames(3));
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let bb = cfg["blackbox"].as_object_mut().unwrap();
    bb.remove("allow_hmac");
    bb.remove("key_id");
    bb.insert("key_file".into(), serde_json::json!(key));
    cfg
}

#[test]
fn rotated_black_box_continues_only_with_the_previous_key() {
    let s = setup("rotation", &robot_profile(true));
    let (ka, pa) = key_pair(&s.dir, "bb-a", 0x51, Some(ROBOT));
    let (kb, pb) = key_pair(&s.dir, "bb-b", 0x52, Some(ROBOT));

    // 1. The daemon writes its black box with key A.
    let cfg_a = config_with_key(&s, &pa);
    let sum = robodr_agentd::run(&s.resolve(&cfg_a), &|| false, &mut Vec::new()).unwrap();
    assert_eq!(sum.reason, StopReason::InputsEnded);
    let first = spooled(&s.spool).len();
    assert!(first > 0);

    // 2. Rotation A -> B with the daemon stopped (robodr-blackbox rotate).
    let clock = Box::new(SteppingClock::new(
        2_000_000_000_000_000_000,
        1_000,
        TimeSource::Unknown,
    ));
    let mut r = Recorder::open(
        RecorderConfig::new(&s.blackbox, ROBOT, "rotation-boot"),
        ka.signer().unwrap(),
        clock,
    )
    .unwrap();
    r.rotate_key(kb.signer().unwrap(), None, "scheduled rotation")
        .unwrap();
    r.close().unwrap();

    // 3. Key B alone: refused (fail closed), naming the remedy. The
    //    configuration itself still loads (--check-config).
    let cfg_b = config_with_key(&s, &pb);
    let resolved = s.resolve(&cfg_b);
    let e = match robodr_agentd::run(&resolved, &|| false, &mut Vec::new()) {
        Ok(_) => panic!("a rotated black box without its previous key must be refused"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("blackbox.previous_keys"), "{e}");
    assert!(e.contains("previous key"), "{e}");

    // 4. With A's public key as a previous key the chain continues.
    let mut cfg_b = cfg_b;
    cfg_b["blackbox"]["previous_keys"] = serde_json::json!([s.dir.join("bb-a.key.pub")]);
    let r = s.resolve(&cfg_b);
    assert_eq!(
        r.previous_keys.as_ref().map(|p| p.key_ids()),
        Some(vec!["bb-a"])
    );
    // The accepted-profile records signed by A still count as witnesses.
    assert!(
        !r.warnings.iter().any(|w| w.contains("do not verify")),
        "{:?}",
        r.warnings
    );
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert_eq!(sum.reason, StopReason::InputsEnded, "{log}");
    assert!(spooled(&s.spool).len() > first, "{log}");

    // 5. The whole chain (A, rotation, B) verifies with both public keys,
    //    and not with B's alone.
    let mut ring = Keyring::new();
    ring.set_refuse_hmac(true);
    ring.load_public_file(&s.dir.join("bb-a.key.pub")).unwrap();
    ring.load_public_file(&s.dir.join("bb-b.key.pub")).unwrap();
    let opts = robodr_blackbox::VerifyOptions {
        expected_device_id: Some(ROBOT.into()),
        checkpoint: Some(sum.finished.checkpoint.clone()),
        ..Default::default()
    };
    let report = robodr_blackbox::verify::verify_dir(&s.blackbox, &ring, &opts).unwrap();
    assert!(report.is_intact(), "{report:#?}");
    let mut only_b = Keyring::new();
    only_b
        .load_public_file(&s.dir.join("bb-b.key.pub"))
        .unwrap();
    let report = robodr_blackbox::verify::verify_dir(&s.blackbox, &only_b, &opts).unwrap();
    assert!(!report.is_intact());
}

#[test]
fn legacy_hmac_black_box_key_is_refused_unless_allowed() {
    let s = setup("hmac-policy", &robot_profile(true));
    let mut cfg = s.config(
        serde_json::json!({"listen_spdp": true}),
        serde_json::json!([]),
        serde_json::json!({}),
    );
    // The fixture key is legacy bare-hex HMAC.
    cfg["blackbox"]
        .as_object_mut()
        .unwrap()
        .remove("allow_hmac");
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(
        e.contains("hmac-sha256") && e.contains("blackbox.allow_hmac"),
        "{e}"
    );
    // A JSON HMAC key file too.
    let json = s.dir.join("hmac.key");
    KeyFile::hmac_from_secret(&KEY, Some(KEY_ID))
        .unwrap()
        .write_new(&json)
        .unwrap();
    cfg["blackbox"]["key_file"] = serde_json::json!(json);
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(e.contains("refused"), "{e}");
    // Explicitly allowed: loads, with the warning (existing logs stay
    // usable).
    cfg["blackbox"]["allow_hmac"] = serde_json::json!(true);
    let r = s.resolve(&cfg);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("hmac-sha256") && w.contains("allow_hmac")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn previous_keys_are_validated() {
    let s = setup("prev-validate", &robot_profile(true));
    let (_, pa) = key_pair(&s.dir, "bb-a", 0x61, None);
    let (_, _) = key_pair(&s.dir, "bb-old", 0x62, Some(ROBOT));
    let (_, _) = key_pair(&s.dir, "bb-other-unit", 0x63, Some("ugv-999"));
    let hmac = s.dir.join("old-hmac.key");
    KeyFile::hmac_from_secret(&[0x64; 32], Some("bb-hmac"))
        .unwrap()
        .write_new(&hmac)
        .unwrap();
    let base = config_with_key(&s, &pa);
    let with = |prev: serde_json::Value, allow: bool| {
        let mut c = base.clone();
        c["blackbox"]["previous_keys"] = prev;
        c["blackbox"]["allow_hmac"] = serde_json::json!(allow);
        robodr_agentd::load(&s.write_config(&c))
    };
    let pubf = |n: &str| s.dir.join(format!("{n}.key.pub"));
    // Good: a public key of this unit.
    let r = with(serde_json::json!([pubf("bb-old")]), false).unwrap();
    assert_eq!(r.previous_keys.unwrap().key_ids(), vec!["bb-old"]);
    for (prev, allow, needle) in [
        // An ed25519 secret: the public file suffices.
        (
            serde_json::json!([s.dir.join("bb-old.key")]),
            false,
            "public file",
        ),
        // The current key.
        (serde_json::json!([pubf("bb-a")]), false, "current"),
        (serde_json::json!([pa.clone()]), false, "blackbox.key_file"),
        // Bound to another unit.
        (serde_json::json!([pubf("bb-other-unit")]), false, "ugv-999"),
        // Legacy HMAC without the opt-in.
        (serde_json::json!([hmac.clone()]), false, "allow_hmac"),
        // Twice.
        (
            serde_json::json!([pubf("bb-old"), pubf("bb-old")]),
            false,
            "twice",
        ),
        (serde_json::json!(["rel/old.pub"]), false, "absolute"),
        (
            serde_json::json!([s.dir.join("missing.pub")]),
            false,
            "missing.pub",
        ),
    ] {
        let e = with(prev.clone(), allow).unwrap_err();
        assert!(e.contains(needle), "{prev}: {e}");
    }
    // HMAC previous key with the opt-in: accepted, with a warning.
    let r = with(serde_json::json!([hmac]), true).unwrap();
    assert_eq!(r.previous_keys.unwrap().key_ids(), vec!["bb-hmac"]);
    assert!(r.warnings.iter().any(|w| w.contains("bb-hmac")));
}
