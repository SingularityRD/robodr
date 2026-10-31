//! The shipped example configurations, relocated into a temp root that has
//! exactly what a commissioned robot has with the shipped unit (profile and
//! its signature, profile trust file, response policy, black-box key
//! credential): the base example passes `--check-config` (`load`) as is;
//! the full example additionally needs its optional files (trust roots,
//! revocation list, finding-signing key, the SOC's control-plane public
//! key) and is refused without them.

mod common;

use common::pcap::robot_profile;
use common::*;
use std::path::Path;

/// Replace the example's absolute install paths with ones under `root`.
fn relocate(text: &str, s: &Setup) -> String {
    let root = s.dir.to_str().unwrap();
    text.replace("/etc/robodr/profile.json", s.profile.to_str().unwrap())
        .replace(
            "/etc/robodr/profile-trust.json",
            &format!("{root}/profile-trust.json"),
        )
        .replace(
            "/etc/robodr/response-policy.json",
            s.policy.to_str().unwrap(),
        )
        .replace(
            "/run/credentials/robodr-agentd.service/",
            &format!("{root}/credentials/"),
        )
        .replace("/etc/robodr/", &format!("{root}/etc/"))
        .replace("/var/lib/robodr/", &format!("{root}/var/"))
        .replace("/run/robodr-agentd/", &format!("{root}/run/"))
}

fn example(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config")
            .join(name),
    )
    .unwrap()
}

fn setup_root(tag: &str) -> Setup {
    let mut prof = robot_profile(true);
    // The example's safety-feed writer must be a profiled participant on a
    // profiled writer topic for the feed to resolve.
    prof.participants.insert("0110a2b3c4d5e6f701000000".into());
    prof.writer_topics.insert("/estop".into());
    let s = setup(tag, &prof);
    for d in ["run", "var", "etc", "credentials"] {
        std::fs::create_dir_all(s.dir.join(d)).unwrap();
    }
    // The shipped unit's black-box credential is an Ed25519 key (legacy
    // HMAC keys, like the fixture's, are refused without allow_hmac).
    robodr_blackbox::KeyFile::ed25519_from_seed(&[0x21; 32], Some("bb-example"))
        .unwrap()
        .write_new(&s.dir.join("credentials/blackbox.key"))
        .unwrap();
    s
}

#[test]
fn base_example_passes_check_config_on_a_default_install() {
    let s = setup_root("example-base");
    let path = s.dir.join("agentd.json");
    std::fs::write(&path, relocate(&example("agentd.example.json"), &s)).unwrap();
    let r = robodr_agentd::load(&path);
    assert!(r.is_ok(), "{:?}", r.err());
}

#[test]
fn full_example_needs_its_optional_files() {
    let s = setup_root("example-full");
    let text = relocate(&example("agentd.full.example.json"), &s);
    assert!(text.contains("finding_signing") && text.contains("trust_roots"));
    let path = s.dir.join("agentd.json");
    std::fs::write(&path, &text).unwrap();
    let e = robodr_agentd::load(&path).expect_err("missing optional files are refused");
    assert!(
        e.contains("trust-roots") || e.contains("profile-revocations") || e.contains("finding.key"),
        "{e}"
    );
    // Once those are removed (= the base example), it loads.
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut v = v;
    v.as_object_mut().unwrap().remove("finding_signing");
    v.as_object_mut().unwrap().remove("control_plane");
    let t = v["sensor"]["profile_trust"].as_object_mut().unwrap();
    for k in ["trust_roots", "revocation_list", "revocation_policy"] {
        t.remove(k);
    }
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let r = robodr_agentd::load(&path);
    assert!(r.is_ok(), "{:?}", r.err());
}

#[test]
fn full_example_control_plane_loads_with_its_soc_key() {
    let s = setup_root("example-cp");
    let text = relocate(&example("agentd.full.example.json"), &s);
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let t = v["sensor"]["profile_trust"].as_object_mut().unwrap();
    for k in ["trust_roots", "revocation_list", "revocation_policy"] {
        t.remove(k);
    }
    let path = s.dir.join("agentd.json");
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    // The finding key (answers are signed: required with control_plane).
    robodr_blackbox::KeyFile::ed25519_from_seed(&[0x34; 32], Some("finding:ugv-007:1"))
        .unwrap()
        .write_new(&s.dir.join("credentials/finding.key"))
        .unwrap();
    // Without the SOC's public key file: refused, naming it.
    let e = robodr_agentd::load(&path).expect_err("SOC key missing");
    assert!(e.contains("soc.pub"), "{e}");
    let key = s.dir.join("etc/soc/soc.pub");
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    robodr_blackbox::KeyFile::ed25519_from_seed(&[0x33; 32], Some("soc:soc-a:1"))
        .unwrap()
        .to_public()
        .unwrap()
        .write_new(&key)
        .unwrap();
    // Without the TLS files: refused, naming them.
    let e = robodr_agentd::load(&path).expect_err("TLS files missing");
    assert!(e.contains("control_plane.tls"), "{e}");
    let tls = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/control-tls");
    let cp = s.dir.join("etc/control-plane");
    std::fs::create_dir_all(&cp).unwrap();
    std::fs::copy(tls.join("robot.pem"), cp.join("robot.pem")).unwrap();
    std::fs::copy(tls.join("soc-ca.pem"), cp.join("soc-ca.pem")).unwrap();
    let k = s.dir.join("credentials/cp-tls.key");
    std::fs::copy(tls.join("robot.key"), &k).unwrap();
    for f in [cp.join("robot.pem"), cp.join("soc-ca.pem")] {
        std::fs::set_permissions(f, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    }
    std::fs::set_permissions(&k, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let r = robodr_agentd::load(&path).unwrap_or_else(|e| panic!("{e}"));
    let cp = r.control_plane.expect("control_plane");
    assert!(cp.tcp.is_some_and(|a| !a.ip().is_loopback()));
    assert!(cp.tls.is_some(), "off loopback only with mutual TLS");
    assert!(cp.evidence.is_some());
    assert_eq!(cp.keys.len(), 1);
    assert!(cp.unix.unwrap().ends_with("run/control.sock"));
    assert!(cp.state_dir.ends_with("var/control-plane/agentd"));
}

/// Review M6: every rule id a shipped response policy overrides
/// (`rule_overrides[].rule` in `config/*.json` and the agent's example
/// policy) is one some detector raises, i.e. in the OCSF rule catalog. An
/// override of an id nothing emits silently does nothing (Pulsar host
/// detections arrive as `robot.host.<rule>` since contract 2.5; an override
/// of `robot.host.pulsar_threat` still covers every one of them).
#[test]
fn policy_overrides_name_cataloged_rules() {
    let generic = robodr_ocsf::rule_info("robot.nope.nothing");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for dir in ["config", "crates/robodr-agent/examples"] {
        for e in std::fs::read_dir(root.join(dir)).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "json") {
                files.push(p);
            }
        }
    }
    let mut checked = 0;
    for f in files {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        let Some(ovs) = v.get("rule_overrides").and_then(|o| o.as_array()) else {
            continue;
        };
        for o in ovs {
            let rule = o["rule"].as_str().unwrap();
            assert_ne!(
                robodr_ocsf::rule_info(rule).title,
                generic.title,
                "{}: override of {rule}, which no detector raises",
                f.display()
            );
            checked += 1;
        }
    }
    assert!(checked >= 4, "{checked}");
}

/// Review 2, M18: the example names its key where systemd puts it while
/// the unit runs (`/run/credentials/robodr-agentd.service/`), so the
/// documented pre-start `--check-config` failed on every fresh install (the
/// directory exists only while the service runs). Outside the unit the
/// check now reads the key where the shipped unit loads it from.
#[test]
fn check_config_before_the_first_start_reads_the_units_credential_sources() {
    let s = setup_root("example-prestart");
    let root = s.dir.to_str().unwrap().to_string();
    // The credentials directory of a service that has not run: missing.
    let creds = format!("{root}/run-credentials/robodr-agentd.service");
    let mut v: serde_json::Value = serde_json::from_str(
        &relocate(&example("agentd.example.json"), &s)
            .replace(&format!("{root}/credentials/"), &format!("{creds}/")),
    )
    .unwrap();
    v["key_protection"] = serde_json::json!({ "credentials_dir": creds });
    let path = s.dir.join("agentd.json");
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    // The key where the shipped unit loads it from.
    std::fs::create_dir_all(s.dir.join("etc/keys")).unwrap();
    std::fs::rename(
        s.dir.join("credentials/blackbox.key"),
        s.dir.join("etc/keys/agentd-blackbox.key"),
    )
    .unwrap();
    let units = s.dir.join("units");
    std::fs::create_dir_all(&units).unwrap();
    let unit = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd/robodr-agentd.service"),
    )
    .unwrap()
    .replace("/etc/robodr/keys/", &format!("{root}/etc/keys/"));
    std::fs::write(units.join("robodr-agentd.service"), unit).unwrap();

    // Before: the plain load (and the old check) fails on the missing
    // credential.
    let e = robodr_agentd::load(&path).expect_err("no credentials directory");
    assert!(e.contains("blackbox.key"), "{e}");
    // The check outside the unit reads the unit's source and passes.
    let (r, notes) = robodr_agentd::load_for_check(&path, &[units.as_path()], false)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.config.robot.id, v["robot"]["id"].as_str().unwrap());
    assert!(
        notes.iter().any(|n| n.contains("credential blackbox.key")
            && n.contains(&format!("{root}/etc/keys/agentd-blackbox.key"))),
        "{notes:?}"
    );
    // Inside the unit nothing is rewritten (systemd handed the files over).
    assert!(robodr_agentd::load_for_check(&path, &[units.as_path()], true).is_err());
    // A unit without that credential: refused, naming the drop-in to add.
    std::fs::write(units.join("robodr-agentd.service"), "[Service]\n").unwrap();
    let e = robodr_agentd::load_for_check(&path, &[units.as_path()], false).unwrap_err();
    assert!(e.contains("LoadCredential=blackbox.key:"), "{e}");
}
