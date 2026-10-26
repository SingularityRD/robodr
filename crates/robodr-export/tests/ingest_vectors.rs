//! The shared `robodr.ingest` contract vectors
//! (`docs/contracts/fixtures/ingest/`): the committed files are exactly
//! what the generator (`examples/ingest_vectors.rs`) writes, and the
//! reference consumer (`tests/common/ingest.rs`, contract §4–§6) gives the
//! expected response for every request.

#[path = "common/ingest.rs"]
mod ingest;
#[path = "common/vectors.rs"]
mod vectors;

use ingest::{Consumer, Registry, Role};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts/fixtures/ingest")
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
    for e in fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        if e.file_type().unwrap().is_dir() {
            walk(root, &p, out);
        } else {
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, fs::read(&p).unwrap());
        }
    }
}

#[test]
fn committed_vectors_are_byte_identical_to_the_generator() {
    let root = fixture_dir();
    let mut committed = BTreeMap::new();
    walk(&root, &root, &mut committed);
    let generated: BTreeMap<String, Vec<u8>> = vectors::files().into_iter().collect();
    let hint =
        "regenerate with `cargo run -p robodr-export --example ingest_vectors` and review the diff";
    for (k, v) in &generated {
        match committed.get(k) {
            None => panic!("{k}: missing from docs/contracts/fixtures/ingest; {hint}"),
            Some(c) => assert!(c == v, "{k}: differs from the generator; {hint}"),
        }
    }
    for k in committed.keys() {
        assert!(
            generated.contains_key(k),
            "{k}: not produced by the generator; {hint}"
        );
    }
}

#[test]
fn generator_is_deterministic() {
    assert!(vectors::files() == vectors::files());
}

fn registry() -> Registry {
    let mut r = Registry::default();
    for (id, req) in vectors::ROBOTS {
        r = r.robot(id, req);
    }
    for k in vectors::keys() {
        let role = match k.role {
            "uplink" => Role::Uplink,
            "relay" => Role::Relay,
            "finding" => Role::Finding,
            _ => continue,
        };
        r = r.key(&k.key_id(), role, k.robot, k.public());
    }
    r
}

fn strip_detail(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(rej) = v.get_mut("rejected").and_then(|r| r.as_array_mut()) {
        for x in rej {
            x.as_object_mut().unwrap().remove("detail");
        }
    }
    if v.get("code").is_some() {
        v.as_object_mut().unwrap().remove("detail");
    }
    v
}

#[test]
fn reference_consumer_gives_every_expected_response() {
    let cases = vectors::cases();
    assert!(cases.len() >= 18);
    let mut statuses = std::collections::BTreeSet::new();
    let mut codes = std::collections::BTreeSet::new();
    for c in cases {
        let mut srv = Consumer::new(registry());
        for (i, r) in c.requests.iter().enumerate() {
            srv.now_ms = Some(r.server_time_ms);
            let a = srv.handle(&r.headers, &r.body);
            let got: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
            let got = strip_detail(got);
            assert_eq!(
                (a.status, &got),
                (r.expect_status, &r.expect_body),
                "case {} request {}",
                c.name,
                i + 1
            );
            statuses.insert(a.status);
            if let Some(rej) = got.get("rejected").and_then(|x| x.as_array()) {
                for x in rej {
                    codes.insert(x["code"].as_str().unwrap().to_string());
                }
            }
            if let Some(cd) = got.get("code").and_then(|x| x.as_str()) {
                codes.insert(cd.to_string());
            }
        }
    }
    // Every status and code of the contract is covered by a vector (429 is
    // rate-limit state, not a vector).
    assert_eq!(
        statuses.into_iter().collect::<Vec<_>>(),
        vec![200, 400, 401, 409, 413, 415]
    );
    for want in [
        "invalid_line",
        "invalid_finding",
        "unsupported_contract",
        "too_large",
        "robot_mismatch",
        "unknown_robot",
        "bad_finding_signature",
        "missing_finding_signature",
        "unknown_key",
        "stale_timestamp",
        "bad_signature",
        "batch_id_reuse",
        "bad_header",
        "empty_batch",
        "too_many_lines",
        "unsupported_media_type",
    ] {
        assert!(codes.contains(want), "no vector for {want}");
    }
}

#[test]
fn vector_keys_are_derived_ids_and_load_as_key_files() {
    for k in vectors::keys() {
        let id = k.key_id();
        assert!(robodr_export::uplink::wire::is_valid_key_id(&id), "{id}");
        let files: BTreeMap<String, Vec<u8>> = vectors::files().into_iter().collect();
        let publ = &files[&format!("keys/{}.key.pub", k.name)];
        let kf = robodr_blackbox::KeyFile::from_json(std::str::from_utf8(publ).unwrap()).unwrap();
        assert!(kf.is_public());
        assert_eq!(kf.key_id, id);
        assert_eq!(kf.public_key().unwrap(), k.public());
        assert_eq!(kf.device_id.as_deref(), k.robot);
    }
}
