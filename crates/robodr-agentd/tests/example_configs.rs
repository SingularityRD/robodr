//! The shipped example configurations, relocated into a temp root that has
//! exactly what a commissioned robot has with the shipped unit (profile and
//! its signature, profile trust file, response policy, black-box key
//! credential): the base example passes `--check-config` (`load`) as is;
//! the full example additionally needs its optional files (trust roots,
//! revocation list, finding-signing key) and is refused without them.

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
            "/run/credentials/robodr-agentd.service/blackbox.key",
            s.key.to_str().unwrap(),
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
    let t = v["sensor"]["profile_trust"].as_object_mut().unwrap();
    for k in ["trust_roots", "revocation_list", "revocation_policy"] {
        t.remove(k);
    }
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let r = robodr_agentd::load(&path);
    assert!(r.is_ok(), "{:?}", r.err());
}
