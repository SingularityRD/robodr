//! Legacy HMAC black-box keys: refused by default (`blackbox.allow_hmac`,
//! as in `robodr-agentd`), usable with the opt-in, and migrated to Ed25519
//! with `robodr-deliverd rekey`.

mod common;

use common::*;
use robodr_blackbox::KeyFile;
use std::process::{Command, Output};

fn out(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn hmac_black_box_key_is_refused_unless_allowed_and_migrates_to_ed25519() {
    let u = Unit::new("hmac-policy");
    let hmac = u.dir().join("bb-hmac.key");
    KeyFile::hmac_from_secret(&[0x33; 32], Some("unit-bb-hmac"))
        .unwrap()
        .write_new(&hmac)
        .unwrap();
    let mut cfg = u.cfg.clone();
    cfg.blackbox.key = hmac.clone();
    assert!(!cfg.blackbox.allow_hmac, "refused by default");

    // 1. Refused at start, naming the setting; nothing is written.
    let e = match robodr_deliverd::Engine::open(cfg.clone(), Box::new(u.clock.clone())) {
        Ok(_) => panic!("an hmac black-box key must be refused without allow_hmac"),
        Err(e) => e.0,
    };
    assert!(
        e.contains("legacy hmac-sha256") && e.contains("blackbox.allow_hmac"),
        "{e}"
    );
    assert!(!robodr_deliverd::journal::Journal::has_records(
        &cfg.blackbox.dir
    ));
    // The journal itself refuses it too.
    assert!(
        robodr_deliverd::journal::Journal::open(&cfg.blackbox.dir, UNIT, &hmac)
            .err()
            .is_some_and(|e| e.contains("blackbox.allow_hmac"))
    );

    // 2. With the opt-in the agent runs on it (and warns).
    cfg.blackbox.allow_hmac = true;
    let e = robodr_deliverd::Engine::open(cfg.clone(), Box::new(u.clock.clone())).unwrap();
    assert!(e.state().locked.is_none(), "{:?}", e.state().locked);
    e.close().unwrap();
    assert!(robodr_deliverd::journal::Journal::has_records(
        &cfg.blackbox.dir
    ));

    // 3. Migration: rekey HMAC -> Ed25519. Without the opt-in the HMAC old
    //    key is refused; with it the journal moves to the new key.
    let new = u.dir().join("bb-ed.key");
    KeyFile::ed25519_from_seed(&[0x34; 32], Some("unit-bb-ed"))
        .unwrap()
        .write_new(&new)
        .unwrap();
    let rekey = |c: &robodr_deliverd::config::Config| {
        let p = u.dir().join("deliverd-hmac.json");
        std::fs::write(&p, serde_json::to_vec_pretty(c).unwrap()).unwrap();
        Command::new(env!("CARGO_BIN_EXE_robodr-deliverd"))
            .args(["rekey", "--config"])
            .arg(&p)
            .arg("--old-key")
            .arg(&hmac)
            .arg("--new-key")
            .arg(&new)
            .output()
            .unwrap()
    };
    let mut strict = cfg.clone();
    strict.blackbox.allow_hmac = false;
    let o = rekey(&strict);
    assert_ne!(o.status.code(), Some(0), "{}", out(&o));
    assert!(out(&o).contains("blackbox.allow_hmac"), "{}", out(&o));
    let o = rekey(&cfg);
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    assert!(out(&o).contains("\"rekeyed\""), "{}", out(&o));

    // 4. The agent now runs on the Ed25519 key without the opt-in.
    let mut ed = cfg.clone();
    ed.blackbox.key = new;
    ed.blackbox.allow_hmac = false;
    let e = robodr_deliverd::Engine::open(ed, Box::new(u.clock.clone())).unwrap();
    assert!(e.state().locked.is_none(), "{:?}", e.state().locked);
    e.close().unwrap();
}

#[test]
fn allow_hmac_is_a_config_field_defaulting_to_false() {
    let d = robodr_deliverd::config::BlackboxCfg::default();
    assert!(!d.allow_hmac);
    let parsed: robodr_deliverd::config::BlackboxCfg =
        serde_json::from_str(r#"{"dir":"/var/lib/x","key":"/run/k","allow_hmac":true}"#).unwrap();
    assert!(parsed.allow_hmac);
    let parsed: robodr_deliverd::config::BlackboxCfg =
        serde_json::from_str(r#"{"dir":"/var/lib/x","key":"/run/k"}"#).unwrap();
    assert!(!parsed.allow_hmac);
}
