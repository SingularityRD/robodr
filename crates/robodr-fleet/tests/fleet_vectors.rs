//! The shared `robodr.fleet-api` contract vectors
//! (`docs/contracts/fixtures/fleet/`): the committed files are exactly what
//! the generator (`examples/fleet_vectors.rs`) writes, and replaying every
//! committed request, as `manifest.json` describes, through the reference
//! SOC (`tests/common/soc.rs`) gives the committed response.

#[path = "common/soc.rs"]
mod soc;
#[path = "common/vectors.rs"]
mod vectors;

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts/fixtures/fleet")
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

const HINT: &str =
    "regenerate with `cargo run -p robodr-fleet --example fleet_vectors` and review the diff";

#[test]
fn committed_vectors_are_byte_identical_to_the_generator() {
    let root = fixture_dir();
    let mut committed = BTreeMap::new();
    walk(&root, &root, &mut committed);
    let generated: BTreeMap<String, Vec<u8>> = vectors::files().into_iter().collect();
    for (k, v) in &generated {
        match committed.get(k) {
            None => panic!("{k}: missing from docs/contracts/fixtures/fleet; {HINT}"),
            Some(c) => assert!(c == v, "{k}: differs from the generator; {HINT}"),
        }
    }
    for k in committed.keys() {
        assert!(
            generated.contains_key(k),
            "{k}: not produced by the generator; {HINT}"
        );
    }
}

#[test]
fn committed_fuzz_seeds_match_the_generator() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
    let (tok, env) = vectors::fuzz_seeds();
    for (name, seeds) in [("fleet_token", tok), ("fleet_envelope", env)] {
        let mut committed = BTreeMap::new();
        walk(&root.join(name), &root.join(name), &mut committed);
        let generated: BTreeMap<String, Vec<u8>> = seeds.into_iter().collect();
        assert!(committed == generated, "fuzz/corpus/{name} differs; {HINT}");
    }
}

#[test]
fn generator_is_deterministic() {
    assert!(vectors::files() == vectors::files());
}

fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}

/// Replay from the committed files only, following `manifest.json`.
#[test]
fn replaying_the_committed_requests_gives_the_committed_responses() {
    let root = fixture_dir();
    let m = read_json(&root.join("manifest.json"));
    let soc_pub =
        robodr_blackbox::KeyFile::load_public(&root.join(m["soc_key"].as_str().unwrap())).unwrap();
    let soc_secret = robodr_blackbox::KeyFile::from_json(
        &fs::read_to_string(root.join("keys/soc.key")).unwrap(),
    )
    .unwrap()
    .ed25519_signing_key()
    .unwrap();
    assert_eq!(soc_secret.public_key(), soc_pub.public_key().unwrap());
    let base = m["base_path"].as_str().unwrap();
    let cases = m["cases"].as_array().unwrap();
    assert!(cases.len() >= 17);
    let mut statuses = std::collections::BTreeSet::new();
    for c in cases {
        let seed = soc_secret.to_seed();
        let key = robodr_blackbox::Ed25519SigningKey::from_seed_with_derived_id(&seed);
        let approval = robodr_blackbox::KeyFile::from_json(
            &fs::read_to_string(root.join("keys/soc-approval.key")).unwrap(),
        )
        .unwrap()
        .ed25519_signing_key()
        .unwrap();
        let mut soc = soc::Soc::new(key, approval, m["workspace"].as_str().unwrap(), 0);
        let setup = &c["setup"];
        for t in setup["tokens"].as_array().unwrap() {
            soc.register_token(&fs::read_to_string(root.join(t.as_str().unwrap())).unwrap());
        }
        for (what, map) in [
            ("revocations", &mut soc.revocations),
            ("offers", &mut soc.offers),
            ("approvals", &mut soc.approvals),
            ("rings", &mut soc.rings),
        ] {
            if let Some(o) = setup[what].as_object() {
                for (k, f) in o {
                    map.insert(k.clone(), fs::read(root.join(f.as_str().unwrap())).unwrap());
                }
            }
        }
        for r in c["requests"].as_array().unwrap() {
            let stem = root.join(r.as_str().unwrap());
            let req = read_json(&PathBuf::from(format!("{}.request.json", stem.display())));
            let body = fs::read(format!("{}.body", stem.display())).unwrap();
            let headers: Vec<(String, String)> = req["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| (h[0].as_str().unwrap().into(), h[1].as_str().unwrap().into()))
                .collect();
            soc.now_ms = req["server_time_ms"].as_u64().unwrap();
            let target = req["target"].as_str().unwrap().strip_prefix(base).unwrap();
            let resp = soc.handle(req["method"].as_str().unwrap(), target, &headers, &body);
            let want = read_json(&PathBuf::from(format!("{}.response.json", stem.display())));
            let got = vectors::response_json(resp.status, &resp.body, "x");
            assert_eq!(got["status"], want["status"], "{}", stem.display());
            statuses.insert(resp.status);
            if resp.status == 200 {
                let committed = fs::read(
                    stem.parent()
                        .unwrap()
                        .join(want["body_file"].as_str().unwrap()),
                )
                .unwrap();
                assert_eq!(resp.body, committed, "{}", stem.display());
                assert_eq!(got["envelope"], want["envelope"]);
            } else {
                assert_eq!(got["body"], want["body"], "{}", stem.display());
            }
        }
    }
    for s in [200, 400, 401, 403, 404, 409, 410, 415] {
        assert!(statuses.contains(&s), "no vector answers {s}");
    }
}
