//! SIEM content and the pipeline signature verifier (gap T62) against real
//! findings.
//!
//! * `integrations/check_content.py`: every field the Splunk, Elastic and
//!   Sentinel content reads is in the contract schema, every rule id it
//!   names is in the catalog, the generated detections are current, and the
//!   Elastic ingest pipeline maps each finding below to the expected ECS
//!   document.
//! * `integrations/verify/robodr_verify.py`: findings signed by this crate
//!   verify; tampered values, another robot's key, duplicate or malformed
//!   headers and (under the strict policy) missing headers are rejected.
//!
//! Needs `python3` with PyYAML, and `cryptography` for the verifier. Skipped
//! with a message when missing, unless `ROBODR_REQUIRE_EXTERNAL_VALIDATOR=1`
//! (set it in CI).

#[path = "support/catalog_ids.rs"]
mod catalog_ids;
mod common;

use robodr_blackbox::Ed25519SigningKey;
use robodr_events::graph::Participant;
use robodr_events::{Deviation, Severity};
use robodr_ocsf::{sign_value, to_json, FindingBuilder, Subject};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "robodr-ocsf-integrations-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Runs a python script; `None` when python3 or a module is missing (and
/// not required).
fn python(script: &str, args: &[&str], stdin_file: Option<&Path>) -> Option<Output> {
    let mut c = Command::new("python3");
    c.arg("-I").arg(root().join(script)).args(args);
    if let Some(f) = stdin_file {
        c.stdin(std::fs::File::open(f).unwrap());
    }
    let required = std::env::var_os("ROBODR_REQUIRE_EXTERNAL_VALIDATOR").is_some();
    match c.output() {
        Ok(o) if o.status.code() == Some(2) => {
            let e = String::from_utf8_lossy(&o.stderr).to_string();
            assert!(!required, "{script}: {e}");
            eprintln!("SKIP {script}: {e}");
            None
        }
        Ok(o) => Some(o),
        Err(e) => {
            assert!(!required, "python3: {e}");
            eprintln!("SKIP {script}: python3: {e}");
            None
        }
    }
}

fn findings() -> Vec<String> {
    let ctx = common::ctx();
    let mut out = Vec::new();
    let part = Participant {
        guid_prefix: "0102030405060708090a0b0c".into(),
        src_ip: "10.77.10.66".into(),
        locators: vec![],
    };
    for (i, id) in catalog_ids::catalog_rule_ids().iter().enumerate() {
        let dev = Deviation::new(id.clone(), Severity::High, "integration content check");
        let mut b = FindingBuilder::from_deviation(&dev, &ctx).seen(common::T0, common::T0 + 1);
        // Every other finding carries a participant subject (source.ip etc.).
        if i % 2 == 0 {
            b = b.subject(Subject::from_participant(&part));
        }
        out.push(to_json(&b.build().unwrap()).unwrap());
    }
    out.push(to_json(&common::example_finding()).unwrap());
    out
}

#[test]
fn siem_content_matches_the_contract_and_maps_real_findings() {
    let dir = scratch("content");
    let f = dir.join("findings.ndjson");
    let lines = findings();
    std::fs::write(&f, lines.join("\n") + "\n").unwrap();
    let Some(o) = python(
        "integrations/check_content.py",
        &["--findings", f.to_str().unwrap()],
        None,
    ) else {
        return;
    };
    let stdout = String::from_utf8_lossy(&o.stdout);
    let stderr = String::from_utf8_lossy(&o.stderr);
    if stdout.contains("PyYAML not installed")
        && std::env::var_os("ROBODR_REQUIRE_EXTERNAL_VALIDATOR").is_none()
    {
        eprintln!("SKIP: PyYAML not installed");
        return;
    }
    assert!(o.status.success(), "{stdout}\n{stderr}");
    assert!(
        stderr.contains(&format!("{} finding(s)", lines.len())),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn key(robot: &str) -> Ed25519SigningKey {
    let mut seed = [0x5a; 32];
    for (d, s) in seed.iter_mut().zip(robot.bytes()) {
        *d ^= s;
    }
    Ed25519SigningKey::from_seed(format!("finding:{robot}:1"), &seed).unwrap()
}

fn record(value: &str, headers: Value) -> String {
    json!({"value": value, "headers": headers}).to_string()
}

#[test]
fn pipeline_verifier_accepts_signed_findings_and_rejects_the_rest() {
    let dir = scratch("verify");
    let value = to_json(&common::example_finding()).unwrap();
    let k = key("ugv-007");
    let sig = sign_value(&value, &k).unwrap().to_header_value();
    let other = key("ugv-008");
    assert_ne!(k.public_key(), other.public_key());
    // ugv-008's key under ugv-007's key id: a relabelled foreign signature.
    let other_relabelled = Ed25519SigningKey::from_seed("finding:ugv-007:1", &{
        let mut seed = [0x5a; 32];
        for (d, s) in seed.iter_mut().zip("ugv-008".bytes()) {
            *d ^= s;
        }
        seed
    })
    .unwrap();
    let other_sig = sign_value(&value, &other_relabelled)
        .unwrap()
        .to_header_value();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    // Same key id under both robots: only ugv-007's key may vouch.
    let keyring = json!({
        "ugv-007": {"finding:ugv-007:1": hex(&k.public_key())},
        "ugv-008": {"finding:ugv-007:1": hex(&other.public_key()),
                    "finding:ugv-008:1": hex(&other.public_key())},
    });
    let kr = dir.join("keys.json");
    std::fs::write(&kr, keyring.to_string()).unwrap();
    let tampered = value.replacen("\"count\":3", "\"count\":4", 1);
    assert_ne!(tampered, value);
    let reordered: Value = serde_json::from_str(&value).unwrap();
    // The same signature with its hex digits in upper case.
    let upper_sig = {
        let (head, hex) = sig.split_at(sig.rfind(":\"").unwrap() + 2);
        format!("{head}{}", hex.to_uppercase())
    };
    let cases: Vec<(&str, String, bool)> = vec![
        (
            "signed",
            record(&value, json!([["robodr-finding-sig", sig]])),
            true,
        ),
        (
            "header name case",
            record(&value, json!([["Robodr-Finding-Sig", sig]])),
            true,
        ),
        (
            "header as object",
            record(&value, json!({"robodr-finding-sig": sig})),
            true,
        ),
        (
            "tampered value",
            record(&tampered, json!([["robodr-finding-sig", sig]])),
            false,
        ),
        (
            "re-serialised value",
            record(
                &serde_json::to_string_pretty(&reordered).unwrap(),
                json!([["robodr-finding-sig", sig]]),
            ),
            false,
        ),
        (
            "another robot's key",
            record(&value, json!([["robodr-finding-sig", other_sig]])),
            false,
        ),
        (
            "duplicate header",
            record(
                &value,
                json!([["robodr-finding-sig", sig], ["robodr-finding-sig", sig]]),
            ),
            false,
        ),
        ("unsigned", record(&value, json!([])), false),
        (
            "hmac",
            record(
                &value,
                json!([["robodr-finding-sig", sig.replace("ed25519", "hmac-sha256")]]),
            ),
            false,
        ),
        (
            "extra header field",
            record(
                &value,
                json!([[
                    "robodr-finding-sig",
                    sig.replace("{\"alg\"", "{\"x\":1,\"alg\"")
                ]]),
            ),
            false,
        ),
        (
            "upper-case sig",
            record(&value, json!([["robodr-finding-sig", upper_sig]])),
            false,
        ),
        ("not json", "nope".to_string(), false),
    ];
    let mut failures = Vec::new();
    for (name, line, ok) in &cases {
        let input = dir.join("in.ndjson");
        std::fs::write(&input, format!("{line}\n")).unwrap();
        let Some(o) = python(
            "integrations/verify/robodr_verify.py",
            &["--keyring", kr.to_str().unwrap()],
            Some(&input),
        ) else {
            return;
        };
        let out = String::from_utf8_lossy(&o.stdout).to_string();
        let accepted = o.status.success() && out.lines().count() == 1;
        if accepted != *ok {
            failures.push(format!(
                "{name}: accepted={accepted}, want {ok}: {}",
                String::from_utf8_lossy(&o.stderr)
            ));
        }
        if accepted {
            let v: Value = serde_json::from_str(out.trim()).unwrap();
            assert_eq!(v["robodr_verification"]["status"], "verified", "{name}");
            assert_eq!(v["robodr_verification"]["key_id"], "finding:ugv-007:1");
            assert_eq!(v["finding_id"], reordered["finding_id"]);
        }
    }
    // Optional policy: an unsigned finding passes, marked unsigned; a bad
    // signature still fails.
    let input = dir.join("opt.ndjson");
    std::fs::write(
        &input,
        format!(
            "{}\n{}\n",
            record(&value, json!([])),
            record(&tampered, json!([["robodr-finding-sig", sig]]))
        ),
    )
    .unwrap();
    if let Some(o) = python(
        "integrations/verify/robodr_verify.py",
        &["--keyring", kr.to_str().unwrap(), "--policy", "optional"],
        Some(&input),
    ) {
        let out = String::from_utf8_lossy(&o.stdout).to_string();
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("\"status\":\"unsigned\""), "{out}");
        assert_eq!(o.status.code(), Some(1));
    }
    assert!(failures.is_empty(), "{failures:#?}");
    let _ = std::fs::remove_dir_all(&dir);
}
