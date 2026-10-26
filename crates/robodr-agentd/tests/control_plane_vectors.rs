//! The shared `robodr-control-plane/v2` contract vectors
//! (`docs/contracts/fixtures/control-plane-v2/`): the committed files are
//! exactly what the generator (`examples/control_plane_vectors.rs`) writes,
//! and every vector holds against this crate's implementation: requests
//! parse, authenticate (or are refused) and route as stated; answer and
//! manifest signatures verify with the finding public key; the chunks
//! reassemble to the bundle; the bundle verifies with the black-box public
//! key (the tampered copy does not).

#[path = "common/cp_vectors.rs"]
mod cp_vectors;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cp_vectors as v;
use robodr_agentd::control::auth::{self, answer_message, SocKey};
use robodr_agentd::control::evidence::{manifest_message, parse_signature_header, Manifest};
use robodr_agentd::control::http::{self, Stream};
use robodr_agentd::control::{route, Route};
use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_blackbox::{Bundle, KeyFile, Keyring};
use serde_json::Value;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts/fixtures/control-plane-v2")
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

fn read(rel: &str) -> Vec<u8> {
    fs::read(fixture_dir().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn committed_vectors_are_byte_identical_to_the_generator() {
    let root = fixture_dir();
    let mut committed = BTreeMap::new();
    walk(&root, &root, &mut committed);
    let generated: BTreeMap<String, Vec<u8>> = v::files().into_iter().collect();
    let hint = "regenerate with `cargo run -p robodr-agentd --example control_plane_vectors` \
                and review the diff";
    for (k, g) in &generated {
        match committed.get(k) {
            None => panic!("{k}: missing from docs/contracts/fixtures/control-plane-v2; {hint}"),
            Some(c) => assert!(c == g, "{k}: differs from the generator; {hint}"),
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
    assert!(v::files() == v::files());
}

struct Bytes(std::io::Cursor<Vec<u8>>);

impl std::io::Read for Bytes {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(b)
    }
}
impl std::io::Write for Bytes {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Stream for Bytes {
    fn set_read_deadline(&self, _: std::time::Duration) -> std::io::Result<()> {
        Ok(())
    }
}

fn pub_key(rel: &str) -> [u8; 32] {
    KeyFile::from_json(std::str::from_utf8(&read(rel)).unwrap())
        .unwrap()
        .public_key()
        .unwrap()
}

#[test]
fn requests_authenticate_and_route_as_stated() {
    let soc = SocKey {
        key_id: v::SOC_ID.into(),
        public: pub_key("keys/soc.key.pub"),
    };
    let finding = pub_key("keys/finding.key.pub");
    let mut checked = 0;
    for vec in v::vectors() {
        let meta: Value =
            serde_json::from_slice(&read(&format!("requests/{}.json", vec.name))).unwrap();
        let raw = read(&format!("requests/{}.http", vec.name));
        let req = http::read_request(
            &mut Bytes(std::io::Cursor::new(raw)),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap_or_else(|e| panic!("{}: {e:?}", vec.name));
        let c = auth::credentials(&req).unwrap();
        // The documented signing message is what this implementation signs.
        let msg = auth::signing_message(
            &req.method,
            &req.target,
            v::ROBOT,
            &c.key_id,
            c.timestamp,
            &c.nonce,
            &req.body,
        );
        let ok = auth::verify(&req, &c, std::slice::from_ref(&soc), v::ROBOT);
        let exp = &meta["expect"];
        if exp["authenticated"] == true {
            assert_eq!(ok, Ok(()), "{}", vec.name);
            assert_eq!(
                meta["signing_message"].as_str().unwrap().as_bytes(),
                msg.as_slice()
            );
            assert_eq!(meta["body_sha256"], to_hex(&sha256(&req.body)));
            let r = route(&req.method, &req.target, v::ROBOT).unwrap();
            let name = match &r {
                Route::Robot => "robot",
                Route::Submit => "submit",
                Route::Get(_) => "get",
                Route::Revert(_) => "revert",
                Route::EvidenceInventory => "evidence_inventory",
                Route::EvidenceCreate => "evidence_create",
                Route::EvidenceManifest(_) => "evidence_manifest",
                Route::EvidenceDelete(_) => "evidence_delete",
                Route::EvidenceChunk(..) => "evidence_chunk",
            };
            assert_eq!(exp["route"], name, "{}", vec.name);
            match (&r, exp.get("id")) {
                (Route::Get(id) | Route::Revert(id), Some(e))
                | (Route::EvidenceManifest(id) | Route::EvidenceDelete(id), Some(e))
                | (Route::EvidenceChunk(id, _), Some(e)) => assert_eq!(e, id.as_str()),
                (_, None) => {}
                (r, e) => panic!("{}: {r:?} {e:?}", vec.name),
            }
            match r {
                Route::Submit => {
                    robodr_agentd::control::api::parse_submit(&req.body).unwrap();
                }
                Route::Revert(_) => {
                    robodr_agentd::control::api::parse_revert(&req.body).unwrap();
                }
                Route::EvidenceCreate => {
                    robodr_agentd::control::evidence::parse_export(&req.body, v::ROBOT).unwrap();
                }
                _ => {}
            }
        } else {
            let f = ok.unwrap_err();
            assert_eq!(
                (f.status(), f.code()),
                (401, "bad_signature"),
                "{}",
                vec.name
            );
            assert_eq!(exp["code"], f.code());
        }
        if let Some(a) = meta.get("answer") {
            let body = read(a["body_file"].as_str().unwrap());
            let status = a["status"].as_u64().unwrap() as u16;
            let m = answer_message(&c.signature_hex, status, &body);
            assert_eq!(
                a["answer_message"].as_str().unwrap().as_bytes(),
                m.as_slice()
            );
            let (kid, sig) =
                parse_signature_header(a["x_robodr_answer_signature"].as_str().unwrap()).unwrap();
            assert_eq!(kid, v::FINDING_ID);
            assert!(
                robodr_blackbox::sign_ed25519::verify(&finding, &m, &sig),
                "{}",
                vec.name
            );
        }
        checked += 1;
    }
    assert!(checked >= 13);
}

#[test]
fn the_evidence_export_verifies_with_the_public_keys_only() {
    let manifest_bytes = read("evidence/manifest.json");
    let m: Manifest = serde_json::from_slice(&manifest_bytes).unwrap();
    // The manifest signature (finding key).
    let sig_text = String::from_utf8(read("evidence/manifest.sig")).unwrap();
    let (kid, sig) = parse_signature_header(&sig_text).unwrap();
    assert_eq!(kid, v::FINDING_ID);
    assert_eq!(
        read("evidence/manifest.message"),
        manifest_message(&manifest_bytes)
    );
    assert!(robodr_blackbox::sign_ed25519::verify(
        &pub_key("keys/finding.key.pub"),
        &manifest_message(&manifest_bytes),
        &sig
    ));
    // The chunks reassemble to the bundle the manifest describes.
    let mut bundle = Vec::new();
    for c in &m.bundle.chunks {
        let b = read(&format!("evidence/chunks/{:04}.bin", c.index));
        assert_eq!(b.len() as u64, c.bytes);
        assert_eq!(c.offset, bundle.len() as u64);
        assert_eq!(to_hex(&sha256(&b)), c.sha256);
        bundle.extend(b);
    }
    assert!(m.bundle.chunks.len() >= 3, "several chunks");
    assert_eq!(bundle, read("evidence/bundle.rbbx"));
    assert_eq!(to_hex(&sha256(&bundle)), m.bundle.sha256);
    // The bundle verifies with the black-box public key file alone.
    let mut ring = Keyring::new();
    let p = fixture_dir().join("keys/blackbox.key.pub");
    ring.load_public_file(&p).unwrap();
    let expected: Value = serde_json::from_slice(&read("evidence/expected.json")).unwrap();
    let b = Bundle::from_bytes(&bundle).unwrap();
    let rep = b.verify_with_key(&ring, None, Some(v::ROBOT), Some(&m.chain.signing_key));
    assert!(rep.is_intact(), "{rep:?}");
    assert_eq!(rep.first_seq, expected["first_seq"].as_u64());
    assert_eq!(rep.last_seq, expected["last_seq"].as_u64());
    assert_eq!(
        rep.verified_records as u64,
        expected["records"].as_u64().unwrap()
    );
    assert_eq!(rep.last_hash.as_deref(), expected["last_sha256"].as_str());
    assert_eq!(rep.chain_id.as_deref(), expected["chain_id"].as_str());
    // Every referenced record is in it, with the link's hash.
    for r in &m.referenced {
        assert!(b
            .records()
            .iter()
            .any(|x| x.seq == r.seq && to_hex(&x.hash) == r.sha256));
    }
    // The anchor is the record before the first one.
    assert_eq!(m.anchor.as_ref().unwrap().seq + 1, m.records.first_seq);
    // The tampered copy is tamper.
    let t = Bundle::from_bytes(&read("evidence/tampered/bundle-flipped-byte.rbbx")).unwrap();
    let rep = t.verify_with_key(&ring, None, Some(v::ROBOT), Some(&m.chain.signing_key));
    assert!(!rep.is_intact());
    let kinds: Vec<String> = rep.tamper().map(|f| format!("{:?}", f.kind)).collect();
    assert!(
        kinds.iter().any(|k| k.contains("HashMismatch")),
        "{kinds:?}"
    );
    assert!(
        rep.tamper()
            .any(|f| f.location.as_ref().is_some_and(|l| l.seq == Some(10))),
        "{rep:?}"
    );
    // The secret key files are published on purpose (test keys); the
    // bundle and manifest hold none of them.
    for k in ["keys/soc.key", "keys/finding.key", "keys/blackbox.key"] {
        let secret = KeyFile::from_json(std::str::from_utf8(&read(k)).unwrap()).unwrap();
        let hex = to_hex(secret.secret());
        for blob in [&bundle, &manifest_bytes] {
            assert!(!blob.windows(hex.len()).any(|w| w == hex.as_bytes()));
        }
    }
}
