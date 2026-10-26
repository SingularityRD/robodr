//! Wave-6 wiring of the daemon: correlation (robodr-correlate), per-finding
//! signatures (contract §2a), black-box upkeep (quarantine report).

mod common;

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::pcap::{frame, robot_profile, scenario_frames, spdp_datagram, SPDP_GROUP};
use common::*;
use robodr_ocsf::Mode;

const FINDING_SEED: [u8; 32] = [0x5a; 32];
const FINDING_KEY_ID: &str = "finding:ugv-007:1";

/// Unknown participants announced from `n` distinct source addresses.
fn flood_frames(n: u8) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut prefix = [0xd0; 12];
            prefix[11] = i;
            let ip = Ipv4Addr::new(192, 168, 50, 100 + i);
            frame(ip, SPDP_GROUP, 7400, &spdp_datagram(prefix, ip))
        })
        .collect()
}

fn replay_cfg(s: &Setup, frames: &[Vec<u8>]) -> serde_json::Value {
    let pcap = s.pcap(frames);
    s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    )
}

fn write_finding_key(path: &Path, key_id: &str) {
    robodr_blackbox::KeyFile::ed25519_from_seed(&FINDING_SEED, Some(key_id))
        .unwrap()
        .write_new(path)
        .unwrap();
}

fn load_err(s: &Setup, cfg: &serde_json::Value) -> String {
    robodr_agentd::load(&s.write_config(cfg)).unwrap_err()
}

// ------------------------------------------------------------- correlation

#[test]
fn discovery_flood_is_correlated_recorded_and_spooled() {
    let s = setup("w6-flood", &robot_profile(true));
    let cfg = replay_cfg(&s, &flood_frames(8));
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    let found = spooled(&s.spool);
    let r = rules(&found);
    assert_eq!(
        r.iter()
            .filter(|x| *x == "robot.ros2.unknown_participant")
            .count(),
        8,
        "{r:?}\n{log}"
    );
    let corr: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.correlate.discovery_flood")
        .collect();
    assert_eq!(corr.len(), 1, "{r:?}\n{log}");
    let env = &corr[0].1;
    // Contract 1.3 catalog entry; the individual findings are still there.
    assert_eq!(
        env.title,
        robodr_ocsf::rule_info("robot.correlate.discovery_flood").title
    );
    assert_eq!(
        env.ocsf.finding_info.data_sources,
        vec!["robodr_correlation"]
    );
    assert_eq!(env.entity_context.mode, Mode::Enforce, "locked profile");
    assert!(env.severity >= robodr_events::Severity::High);
    assert_eq!(sum.stats.correlated_findings, 1);
    assert_eq!(notes_with(&s.blackbox, "robodr.correlated_finding"), 1);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
    let st = status(&s.spool).unwrap();
    assert_eq!(st["correlation"]["findings"], 1, "{st}");
    assert_eq!(st["correlation"]["signals"], 8, "{st}");
}

#[test]
fn correlation_can_be_disabled() {
    let s = setup("w6-nocorr", &robot_profile(true));
    let mut cfg = replay_cfg(&s, &flood_frames(8));
    cfg["correlation"] = serde_json::json!({"enabled": false});
    let sum = robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut Vec::new()).unwrap();
    let r = rules(&spooled(&s.spool));
    assert_eq!(r.len(), 8, "{r:?}");
    assert!(r.iter().all(|x| !x.starts_with("robot.correlate.")));
    assert_eq!(sum.stats.correlated_findings, 0);
    assert!(status(&s.spool).unwrap().get("correlation").is_none());
}

#[test]
fn an_observe_only_profile_keeps_correlations_observe_only() {
    let s = setup("w6-observe", &robot_profile(false));
    let cfg = replay_cfg(&s, &flood_frames(8));
    robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut Vec::new()).unwrap();
    let found = spooled(&s.spool);
    let corr: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id.starts_with("robot.correlate."))
        .collect();
    assert_eq!(corr.len(), 1);
    assert_eq!(corr[0].1.entity_context.mode, Mode::Observe);
}

fn rules_file(dir: &Path, name: &str, rules: serde_json::Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(
        &p,
        serde_json::to_vec(&serde_json::json!({"version": 1, "rules": rules})).unwrap(),
    )
    .unwrap();
    p
}

fn lab_rule(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "title": "Two unknown participants",
        "severity": "medium",
        "window_secs": 60,
        "group_by": null,
        "pattern": {"kind": "threshold",
                    "match": {"rules": ["robot.ros2.unknown_participant"]},
                    "count": 2}
    })
}

#[test]
fn correlation_rule_files_are_validated_as_one_set() {
    let s = setup("w6-rules", &robot_profile(true));
    let base = replay_cfg(&s, &flood_frames(1));
    let defaults = robodr_correlate::RuleSet::default_rules().len();

    // Added rules.
    let p = rules_file(
        &s.dir,
        "extra.json",
        serde_json::json!([lab_rule("robot.correlate.lab_two")]),
    );
    let mut cfg = base.clone();
    cfg["correlation"] = serde_json::json!({"rules_path": p});
    let r = s.resolve(&cfg);
    assert_eq!(r.correlation.as_ref().unwrap().len(), defaults + 1);

    // Only the file.
    cfg["correlation"] = serde_json::json!({"rules_path": p, "include_default_rules": false});
    assert_eq!(s.resolve(&cfg).correlation.unwrap().len(), 1);

    // A duplicate of a shipped id is refused (never a partial set).
    let dup = rules_file(
        &s.dir,
        "dup.json",
        serde_json::json!([lab_rule("robot.correlate.discovery_flood")]),
    );
    cfg["correlation"] = serde_json::json!({"rules_path": dup});
    assert!(
        load_err(&s, &cfg).contains("duplicate"),
        "{}",
        load_err(&s, &cfg)
    );

    // Malformed file, unknown key, no rules at all, relative path.
    let bad = s.dir.join("bad.json");
    std::fs::write(&bad, b"{\"version\":1,\"rules\":[{\"id\":").unwrap();
    cfg["correlation"] = serde_json::json!({"rules_path": bad});
    load_err(&s, &cfg);
    cfg["correlation"] = serde_json::json!({"rules": []});
    assert!(load_err(&s, &cfg).contains("unknown field"));
    cfg["correlation"] = serde_json::json!({"include_default_rules": false});
    assert!(load_err(&s, &cfg).contains("no rules"));
    cfg["correlation"] = serde_json::json!({"rules_path": "rel.json"});
    assert!(load_err(&s, &cfg).contains("absolute"));
}

#[test]
fn custom_correlation_rule_fires_in_the_daemon() {
    let s = setup("w6-custom", &robot_profile(true));
    let p = rules_file(
        &s.dir,
        "extra.json",
        serde_json::json!([lab_rule("robot.correlate.lab_two")]),
    );
    let mut cfg = replay_cfg(&s, &flood_frames(2));
    cfg["correlation"] = serde_json::json!({"rules_path": p, "include_default_rules": false});
    robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut Vec::new()).unwrap();
    let found = spooled(&s.spool);
    let corr: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.correlate.lab_two")
        .collect();
    assert_eq!(corr.len(), 1, "{:?}", rules(&found));
    // A deployment rule id gets the generic correlation catalog entry.
    assert_eq!(corr[0].1.title, "Correlated RoboDR detection");
}

// --------------------------------------------------------- finding signing

#[test]
fn findings_are_signed_with_the_dedicated_key() {
    let s = setup("w6-sign", &robot_profile(true));
    let key = s.dir.join("finding.key");
    write_finding_key(&key, FINDING_KEY_ID);
    let pcap = s.pcap(&scenario_frames(2));
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["finding_signing"] = serde_json::json!({"key_file": key});
    robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut Vec::new()).unwrap();
    let found = spooled(&s.spool);
    assert!(found.len() >= 2);
    let vk = robodr_blackbox::KeyFile::ed25519_from_seed(&FINDING_SEED, Some(FINDING_KEY_ID))
        .unwrap()
        .to_public()
        .unwrap()
        .ed25519_verifying_key()
        .unwrap();
    let mut keys: std::collections::BTreeMap<String, Box<dyn robodr_blackbox::Verifier>> =
        std::collections::BTreeMap::new();
    keys.insert(ROBOT.into(), Box::new(vk));
    for (rec, _) in &found {
        let (name, value) = rec.headers.last().unwrap();
        assert_eq!(name, robodr_ocsf::SIG_HEADER);
        let v = robodr_ocsf::parse_and_validate_signed(
            &rec.value,
            Some(value),
            &keys,
            robodr_ocsf::SignaturePolicy::Strict,
        )
        .unwrap();
        assert_eq!(
            v.signature,
            robodr_ocsf::SignatureStatus::Verified {
                unit_id: ROBOT.into(),
                key_id: FINDING_KEY_ID.into()
            }
        );
    }
    assert_eq!(status(&s.spool).unwrap()["signs_findings"], true);
}

#[test]
fn unsuitable_finding_keys_are_refused() {
    let s = setup("w6-badkey", &robot_profile(true));
    let base = replay_cfg(&s, &flood_frames(1));
    let with = |p: &Path| {
        let mut c = base.clone();
        c["finding_signing"] = serde_json::json!({ "key_file": p });
        c
    };
    // HMAC: every verifier could forge.
    let hmac = s.dir.join("hmac.key");
    robodr_blackbox::KeyFile::hmac_from_secret(&[0x77; 32], Some("f-hmac"))
        .unwrap()
        .write_new(&hmac)
        .unwrap();
    assert!(load_err(&s, &with(&hmac)).contains("ed25519"));
    // The black-box key id: not a dedicated key.
    let same = s.dir.join("same.key");
    write_finding_key(&same, KEY_ID);
    assert!(load_err(&s, &with(&same)).contains("black-box key"));
    // Readable by others.
    let open = s.dir.join("open.key");
    write_finding_key(&open, FINDING_KEY_ID);
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_err(&s, &with(&open)).contains("chmod 600"));
    // Inside the spool (the exporter would ship it).
    std::fs::create_dir_all(&s.spool).unwrap();
    let shipped = s.spool.join("finding.key");
    write_finding_key(&shipped, FINDING_KEY_ID);
    assert!(load_err(&s, &with(&shipped)).contains("inside spool.dir"));
    // Unknown key in the section.
    let mut c = base.clone();
    c["finding_signing"] = serde_json::json!({"key": "x"});
    assert!(load_err(&s, &c).contains("unknown field"));
}

// ---------------------------------------------------------- black-box upkeep

#[test]
fn quarantined_segment_is_a_high_observe_only_finding() {
    let s = setup("w6-quarantine", &robot_profile(true));
    // Pre-populate a multi-segment black box with the daemon's key, then
    // damage a closed segment.
    let mut c = robodr_blackbox::RecorderConfig::new(&s.blackbox, ROBOT, "test-boot");
    c.max_segment_bytes = 4096;
    let clock = robodr_blackbox::SystemClock::new(robodr_blackbox::TimeSource::Unknown);
    let mut r = robodr_blackbox::Recorder::open(c, Box::new(verifier()), Box::new(clock)).unwrap();
    let mut i = 0u64;
    while r.segments().len() < 4 {
        r.append_note(
            &serde_json::json!({"kind": "fill", "i": i, "pad": "x".repeat(200)}),
            false,
        )
        .unwrap();
        i += 1;
    }
    r.close().unwrap();
    let p = s
        .blackbox
        .join(robodr_blackbox::store::segment_file_name(1));
    let mut b = std::fs::read(&p).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0x20;
    std::fs::write(&p, &b).unwrap();

    let cfg = replay_cfg(&s, &scenario_frames(1));
    let mut log = Vec::new();
    robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    let found = spooled(&s.spool);
    let q: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.agent.evidence_quarantined")
        .collect();
    assert_eq!(q.len(), 1, "{:?}\n{log}", rules(&found));
    assert_eq!(q[0].1.severity, robodr_events::Severity::High);
    assert_eq!(q[0].1.entity_context.mode, Mode::Observe, "self-health");
    assert!(log.contains("evidence_quarantined"), "{log}");
}

#[test]
fn correlation_state_pressure_is_an_observe_only_health_finding() {
    let s = setup("w6-pressure", &robot_profile(true));
    // A per-IP sequence rule: every unknown participant from a fresh address
    // opens a single-signal group; past the per-rule group cap they are
    // evicted, which the daemon reports.
    let p = rules_file(
        &s.dir,
        "seq.json",
        serde_json::json!([{
            "id": "robot.correlate.lab_seq",
            "title": "Participant then writer from one address",
            "severity": "medium",
            "window_secs": 60,
            "group_by": "ip",
            "pattern": {"kind": "sequence", "steps": [
                {"rules": ["robot.ros2.unknown_participant"]},
                {"rules": ["robot.ros2.unauthorized_motion_writer"]}
            ]}
        }]),
    );
    let frames: Vec<Vec<u8>> = (0..300u16)
        .map(|i| {
            let mut prefix = [0xc0; 12];
            prefix[10..].copy_from_slice(&i.to_be_bytes());
            let ip = Ipv4Addr::new(10, 1, (i >> 8) as u8, (i & 0xff) as u8);
            frame(ip, SPDP_GROUP, 7400, &spdp_datagram(prefix, ip))
        })
        .collect();
    // A flood: 300 fresh addresses within 0.3 s of capture time (the
    // replay is judged on its packet timestamps; at the default 1 s apart
    // the 60 s window would expire groups before the cap is reached).
    let pcap = s.pcap_spaced(&frames, Duration::from_millis(1));
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["correlation"] = serde_json::json!({"rules_path": p, "include_default_rules": false});
    cfg["sensor"]["rate_limit_burst"] = 10_000.into();
    let mut log = Vec::new();
    robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    let st = status(&s.spool).unwrap();
    assert!(
        st["correlation"]["groups_evicted"].as_u64().unwrap() > 0,
        "{st}\n{log}"
    );
    let found = spooled(&s.spool);
    let pr: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.agent.correlation_pressure")
        .collect();
    assert!(!pr.is_empty(), "{log}");
    assert!(pr
        .iter()
        .all(|(_, e)| e.entity_context.mode == Mode::Observe));
}
