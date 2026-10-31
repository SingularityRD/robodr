//! SIEM content and the pipeline signature verifier (gap T62) against real
//! findings.
//!
//! * `integrations/check_content.py`: every field the Splunk, Elastic and
//!   Sentinel content reads is in the contract schema, every rule id it
//!   names is in the catalog, the generated detections are current, and the
//!   Elastic ingest pipelines map each finding below to the expected ECS
//!   document, and a verification status the finding itself carries is
//!   discarded on every route a verifier did not write it on (Splunk
//!   sourcetype, Elastic pipeline, Sentinel stream).
//! * `integrations/verify/robodr_verify.py`: findings signed by this crate
//!   verify; tampered values, another robot's key, duplicate or malformed
//!   headers and (under the strict policy) missing headers are rejected.
//!
//! Needs `python3` with PyYAML, and `cryptography` for the verifier. Skipped
//! with a message when missing, unless `ROBODR_REQUIRE_EXTERNAL_VALIDATOR=1`
//! (the CI pure job sets it).

#[path = "support/catalog_ids.rs"]
mod catalog_ids;
mod common;
#[path = "support/python.rs"]
mod py_support;

use curve25519_dalek::scalar::{clamp_integer, Scalar};
use py_support::missing_module;
use robodr_blackbox::sign::SignError;
use robodr_blackbox::{Ed25519SigningKey, Signer};
use robodr_events::graph::Participant;
use robodr_events::{Deviation, Severity};
use robodr_ocsf::{sign_value, to_json, FindingBuilder, Subject};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
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
        // Exit 2 without the missing-module message is a usage or tooling
        // error: returned, and the caller's assertions fail on it.
        Ok(o) if missing_module(&o) => {
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
        let mut b = common::with_required(FindingBuilder::from_deviation(&dev, &ctx), id)
            .seen(common::T0, common::T0 + 1);
        // Every other finding carries a participant subject (source.ip etc.).
        if i % 2 == 0 {
            b = b.subject(Subject::from_participant(&part));
        }
        // The health record rule requires its record (contract 2.5).
        if id == robodr_ocsf::AGENT_HEALTH_RULE {
            b = b.agent_health(common::health::sample());
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
    // The same findings against a real Elasticsearch, when one is given
    // (a scratch cluster: the pipelines and template are overwritten).
    if let Some(es) = std::env::var_os("ROBODR_ES_URL") {
        let o = Command::new("python3")
            .arg("-I")
            .arg(root().join("integrations/elastic/live_check.py"))
            .arg("--es")
            .arg(&es)
            .arg("--findings")
            .arg(&f)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&o.stdout);
        let stderr = String::from_utf8_lossy(&o.stderr);
        assert!(o.status.success(), "{stdout}\n{stderr}");
        eprintln!("{stderr}");
        // And the detection rules, previewed in a real Kibana.
        if let Some(kb) = std::env::var_os("ROBODR_KIBANA_URL") {
            let o = Command::new("python3")
                .arg("-I")
                .arg(root().join("integrations/elastic/live_check_rules.py"))
                .arg("--es")
                .arg(&es)
                .arg("--kibana")
                .arg(&kb)
                .arg("--findings")
                .arg(&f)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            assert!(o.status.success(), "{stdout}\n{stderr}");
            eprintln!("{stderr}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn seed(robot: &str) -> [u8; 32] {
    let mut seed = [0x5a; 32];
    for (d, s) in seed.iter_mut().zip(robot.bytes()) {
        *d ^= s;
    }
    seed
}

fn key(robot: &str) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(format!("finding:{robot}:1"), &seed(robot)).unwrap()
}

/// Signs with R = the identity point (small order) under `robot`'s real
/// key: S = k * a, so [S]B = R + [k]A holds and a cofactorless check that
/// does not look at R (the `cryptography` package) accepts it. Only the
/// strict small-order-R check refuses it.
struct SmallOrderR {
    key_id: String,
    a: Scalar,
    public: [u8; 32],
}

const IDENTITY: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
};

impl SmallOrderR {
    fn new(robot: &str) -> Self {
        let h = Sha512::digest(seed(robot));
        let mut lo = [0u8; 32];
        lo.copy_from_slice(&h[..32]);
        Self {
            key_id: format!("finding:{robot}:1"),
            a: Scalar::from_bytes_mod_order(clamp_integer(lo)),
            public: key(robot).public_key(),
        }
    }
}

impl Signer for SmallOrderR {
    fn algorithm(&self) -> &str {
        "ed25519"
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let k = Scalar::from_hash(
            Sha512::new()
                .chain_update(IDENTITY)
                .chain_update(self.public)
                .chain_update(message),
        );
        let mut sig = IDENTITY.to_vec();
        sig.extend_from_slice((k * self.a).as_bytes());
        Ok(sig)
    }
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
    let ext = reordered["external_id"].as_str().unwrap();
    let unbound = value.replacen(
        &format!("\"external_id\":\"{ext}\""),
        "\"external_id\":\"ugv-007:rf1-00000000000000000000000000000000\"",
        1,
    );
    assert_ne!(unbound, value);
    let unbound_sig = sign_value(&unbound, &k).unwrap().to_header_value();
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
        (
            // Correctly signed by ugv-007, but external_id does not bind
            // this finding_id (contract §2: finding_id bound to the robot).
            "finding_id not bound",
            record(&unbound, json!([["robodr-finding-sig", unbound_sig]])),
            false,
        ),
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
        let err = String::from_utf8_lossy(&o.stderr).to_string();
        let accepted = o.status.success() && out.lines().count() == 1;
        // A rejection is exit 1 with the record counted as rejected, not a
        // usage error or a crash.
        let rejected =
            o.status.code() == Some(1) && out.is_empty() && err.contains("0 forwarded, 1 rejected");
        if accepted != *ok || (!ok && !rejected) {
            failures.push(format!("{name}: accepted={accepted}, want {ok}: {err}"));
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

/// verify_strict semantics (contract §2a): a small-order public key in the
/// keyring would let R = identity, S = 0 "verify" any value under the
/// cofactorless equation; the `cryptography` package accepts that, so the
/// verifier refuses weak keys and weak R itself.
#[test]
fn pipeline_verifier_refuses_small_order_keys_and_signatures() {
    let dir = scratch("verify-weak");
    let value = to_json(&common::example_finding()).unwrap();
    let k = key("ugv-007");
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let identity = format!("01{}", "00".repeat(31));
    let forged = format!(
        "{{\"alg\":\"ed25519\",\"key_id\":\"finding:weak:1\",\"sig\":\"{identity}{}\"}}",
        "00".repeat(32)
    );
    let input = dir.join("in.ndjson");
    std::fs::write(
        &input,
        record(&value, json!([["robodr-finding-sig", forged]])) + "\n",
    )
    .unwrap();
    // A keyring holding a small-order key is refused as a whole.
    let kr = dir.join("weak.json");
    std::fs::write(
        &kr,
        json!({"ugv-007": {"finding:ugv-007:1": hex(&k.public_key()),
                           "finding:weak:1": identity}})
        .to_string(),
    )
    .unwrap();
    let Some(o) = python(
        "integrations/verify/robodr_verify.py",
        &["--keyring", kr.to_str().unwrap()],
        Some(&input),
    ) else {
        return;
    };
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        o.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("weak or non-canonical"), "{err}");
    // A small-order R under the robot's real key, with S chosen so the
    // cofactorless equation holds: the `cryptography` package alone accepts
    // it; the strict R check must reject it, and say so.
    let weak_r = sign_value(&value, &SmallOrderR::new("ugv-007"))
        .unwrap()
        .to_header_value();
    assert!(
        weak_r.contains(&format!("\"sig\":\"{identity}")),
        "{weak_r}"
    );
    std::fs::write(
        &input,
        record(&value, json!([["robodr-finding-sig", weak_r]])) + "\n",
    )
    .unwrap();
    std::fs::write(
        &kr,
        json!({"ugv-007": {"finding:ugv-007:1": hex(&k.public_key())}}).to_string(),
    )
    .unwrap();
    let o = python(
        "integrations/verify/robodr_verify.py",
        &["--keyring", kr.to_str().unwrap()],
        Some(&input),
    )
    .unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        o.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("weak or non-canonical point"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
