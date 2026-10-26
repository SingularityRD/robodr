//! The `robodr-control-plane/v2` contract test vectors
//! (`docs/contracts/fixtures/control-plane-v2/`), generated
//! deterministically: fixed test keys (seeds below), fixed timestamps and
//! nonces, and a synthetic black box (a `Genesis` record and notes signed
//! with the test black-box key), so a SOC implementation can check its
//! signing, answer verification, evidence download and bundle verification
//! byte for byte.
//!
//! Used by `examples/control_plane_vectors.rs` (writes the files) and
//! `tests/control_plane_vectors.rs` (the committed files are exactly this
//! output, and every vector holds against this crate's implementation).
#![allow(dead_code)]

use std::collections::BTreeMap;

use robodr_agentd::control::auth::{answer_message, signing_message, API_VERSION};
use robodr_agentd::control::evidence::{
    self, bundle_info, manifest_message, Manifest, MemSource, RecordRef, Selector, MANIFEST_KIND,
    MANIFEST_VERSION,
};
use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_blackbox::record::{
    signing_message as record_signing_message, ChainIdentity, GenesisPayload, Record, RecordKind,
    FORMAT_VERSION, ZERO_HASH,
};
use robodr_blackbox::{Ed25519SigningKey, KeyFile, Signer, TimeSource, Timestamp};
use serde_json::{json, Value};

pub const ROBOT: &str = "ugv-007";
pub const SOC_ID: &str = "soc:soc-a:1";
pub const SOC_SEED: [u8; 32] = [0x51; 32];
pub const FINDING_ID: &str = "finding:ugv-007:1";
pub const FINDING_SEED: [u8; 32] = [0x52; 32];
pub const BB_ID: &str = "bb:ugv-007:1";
pub const BB_SEED: [u8; 32] = [0x53; 32];
/// Request timestamps (Unix seconds).
pub const TS: u64 = 1_800_000_000;
/// Wall time of the first black-box record (ns); 1 s per record.
pub const BB_T0_NS: u64 = 1_799_999_900 * 1_000_000_000;
pub const CHUNK_BYTES: u64 = 1024;

pub fn soc() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(SOC_ID, &SOC_SEED).unwrap()
}

pub fn finding() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(FINDING_ID, &FINDING_SEED).unwrap()
}

pub fn blackbox() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(BB_ID, &BB_SEED).unwrap()
}

fn keyfile(seed: &[u8; 32], id: &str) -> KeyFile {
    KeyFile::ed25519_from_seed(seed, Some(id)).unwrap()
}

pub fn identity() -> ChainIdentity {
    ChainIdentity {
        device_id: ROBOT.into(),
        boot_id: "contract-vectors-boot".into(),
        key_id: BB_ID.into(),
        algorithm: "ed25519".into(),
        created_wall_ns: BB_T0_NS,
    }
}

/// The synthetic black box: one segment, `Genesis` then 23 notes (two of
/// them decision notes a finding links to).
pub fn segment() -> Vec<u8> {
    let id = identity();
    let chain_id = id.chain_id();
    let key = blackbox();
    let mut out = Vec::new();
    let mut prev = ZERO_HASH;
    for seq in 0..24u64 {
        let (kind, payload) = if seq == 0 {
            (
                RecordKind::Genesis,
                serde_json::to_vec(&GenesisPayload {
                    identity: id.clone(),
                    recorder_version: "contract-vectors".into(),
                    format_version: FORMAT_VERSION,
                })
                .unwrap(),
            )
        } else {
            let note = match seq {
                10 => json!({"kind": "robodr.control_plane_request", "api": API_VERSION,
                             "request_id": "robot_safe_pause:ugv-007:0001", "decision": "accepted",
                             "status": "recorded_not_executed", "executed": false}),
                12 => json!({"kind": "deviation", "rule": "robot.ros2.unauthorized_motion_writer",
                             "severity": "high"}),
                _ => json!({"kind": "robodr.agentd_heartbeat", "n": seq}),
            };
            (RecordKind::Note, serde_json::to_vec(&note).unwrap())
        };
        let mut r = Record {
            chain_id,
            seq,
            time: Timestamp {
                wall_ns: BB_T0_NS + seq * 1_000_000_000,
                mono_ns: seq * 1_000_000_000,
                source: TimeSource::Rtc,
            },
            kind,
            critical: seq == 10,
            payload,
            prev_hash: prev,
            hash: ZERO_HASH,
            sig: Vec::new(),
        };
        r.hash = r.compute_hash();
        r.sig = key.sign(&record_signing_message(&r.hash)).unwrap();
        prev = r.hash;
        out.extend_from_slice(&r.encode_frame());
    }
    out
}

pub fn source() -> MemSource {
    let mut m = BTreeMap::new();
    m.insert(0u64, segment());
    MemSource(m)
}

/// The evidence link of record `seq` (segment 0).
pub fn link(seq: u64) -> String {
    let ix = evidence::index(&source()).unwrap();
    let m = ix.records.iter().find(|r| r.seq == seq).unwrap();
    RecordRef {
        segment: m.segment,
        seq,
        sha256: to_hex(&m.hash),
    }
    .uri(ROBOT)
}

/// One signed request.
pub struct Vector {
    pub name: &'static str,
    pub description: &'static str,
    pub method: &'static str,
    pub target: String,
    pub body: Vec<u8>,
    pub nonce: String,
    /// What the robot must do with it.
    pub expect: Value,
    /// A sample answer (status, content type, body) the robot signs.
    pub answer: Option<(u16, &'static str, Vec<u8>)>,
    /// Re-sign in another way (negative vectors).
    pub sign_as: SignAs,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignAs {
    Valid,
    /// The signature of another body.
    TamperedBody,
    /// Signed for another robot id.
    OtherRobot,
    /// Signed in the removed v1 domain.
    V1Domain,
}

pub fn signature(v: &Vector) -> (Vec<u8>, String) {
    let (robot, body): (&str, &[u8]) = match v.sign_as {
        SignAs::OtherRobot => ("ugv-008", &v.body),
        SignAs::TamperedBody => (ROBOT, b"{}"),
        _ => (ROBOT, &v.body),
    };
    let mut msg = signing_message(v.method, &v.target, robot, SOC_ID, TS, &v.nonce, body);
    if v.sign_as == SignAs::V1Domain {
        msg = String::from_utf8(msg)
            .unwrap()
            .replacen("robodr-control-plane/v2", "robodr-control-plane/v1", 1)
            .into_bytes();
    }
    let sig = soc().sign_message(&msg);
    (msg, to_hex(&sig))
}

pub fn request_bytes(v: &Vector) -> Vec<u8> {
    let (_, sig) = signature(v);
    let mut out = format!(
        "{} {} HTTP/1.1\r\nHost: ugv-007.robots.example\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nX-RoboDR-Key-Id: {SOC_ID}\r\nX-RoboDR-Timestamp: {TS}\r\n\
         X-RoboDR-Nonce: {}\r\nX-RoboDR-Signature: {sig}\r\n\r\n",
        v.method,
        v.target,
        v.body.len(),
        v.nonce
    )
    .into_bytes();
    out.extend_from_slice(&v.body);
    out
}

pub fn answer_header(request_sig_hex: &str, status: u16, body: &[u8]) -> String {
    let sig = finding()
        .sign(&answer_message(request_sig_hex, status, body))
        .unwrap();
    format!("ed25519;key_id={FINDING_ID};sig={}", to_hex(&sig))
}

/// The evidence export of the vectors: the finding links seq 10 and 12,
/// 3 context records on each side (seqs 7..=15).
pub struct Export {
    pub bundle: Vec<u8>,
    pub manifest: Manifest,
    pub manifest_bytes: Vec<u8>,
    pub manifest_signature: String,
}

pub fn export() -> Export {
    let src = source();
    let ix = evidence::index(&src).unwrap();
    let sel = Selector::Finding {
        finding_id: "rf1-0011223344556677".into(),
        evidence: vec![
            evidence::parse_link(&link(10), ROBOT).unwrap(),
            evidence::parse_link(&link(12), ROBOT).unwrap(),
        ],
        context_records: 3,
    };
    let (lo, hi, refs) = evidence::select(&ix, &sel).unwrap();
    let built = evidence::build(&src, &ix, lo, hi, refs, 1 << 20).unwrap();
    let manifest = Manifest {
        kind: MANIFEST_KIND.into(),
        version: MANIFEST_VERSION,
        api: API_VERSION.into(),
        robot_id: ROBOT.into(),
        export_id: "case-42:ev-1".into(),
        created_at_ms: TS * 1000,
        expires_at_ms: TS * 1000 + 86_400_000,
        requested_by: "analyst@soc".into(),
        reason: "case 42".into(),
        key_id: SOC_ID.into(),
        selector: sel,
        chain: built.chain.clone(),
        records: built.records.clone(),
        anchor: built.anchor.clone(),
        referenced: built.referenced.clone(),
        bundle: bundle_info(&built.bundle, CHUNK_BYTES),
        evidence: format!(
            "robodr-blackbox://{ROBOT}/0/24?sha256={}",
            to_hex(&sha256(b"the export's own note (illustrative)"))
        ),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_signature = evidence::sign_manifest(&finding(), &manifest_bytes).unwrap();
    Export {
        bundle: built.bundle,
        manifest,
        manifest_bytes,
        manifest_signature,
    }
}

pub fn vectors() -> Vec<Vector> {
    let base = format!("/api/v2/robots/{ROBOT}");
    let x = export();
    let submit = serde_json::to_vec(&json!({
        "request_id": "robot_safe_pause:ugv-007:0001",
        "action": "safe_pause",
        "parameters": {},
        "reason": "rogue /cmd_vel writer",
        "requested_by": "analyst@soc",
        "source": "soc-a",
        "authority": "request",
    }))
    .unwrap();
    let state = json!({
        "request_id": "robot_safe_pause:ugv-007:0001",
        "status": "recorded_not_executed",
        "executed": false,
        "state": {"robot_id": ROBOT, "action": "safe_pause", "decision": "accepted",
                  "executor": "recording", "executed": false, "evidence": link(10)},
    });
    let export_body = serde_json::to_vec(&json!({
        "export_id": "case-42:ev-1",
        "selector": {"finding": {
            "finding_id": "rf1-0011223344556677",
            "evidence": [link(10), link(12)],
            "context_records": 3,
        }},
        "requested_by": "analyst@soc",
        "reason": "case 42",
    }))
    .unwrap();
    let n = |i: u32| format!("contract-nonce-{i:04}");
    let j = |v: Value| serde_json::to_vec(&v).unwrap();
    let mut out = vec![
        Vector {
            name: "01-robot",
            description: "robot snapshot",
            method: "GET",
            target: base.clone(),
            body: Vec::new(),
            nonce: n(1),
            expect: json!({"route": "robot", "authenticated": true}),
            answer: Some((
                200,
                "application/json",
                j(json!({"robot_id": ROBOT, "online": true, "api": API_VERSION,
                         "executor": "recording", "executes_actions": false})),
            )),
            sign_as: SignAs::Valid,
        },
        Vector {
            name: "02-submit",
            description: "action request (safe_pause)",
            method: "POST",
            target: format!("{base}/action-requests"),
            body: submit.clone(),
            nonce: n(2),
            expect: json!({"route": "submit", "authenticated": true}),
            answer: Some((200, "application/json", j(state.clone()))),
            sign_as: SignAs::Valid,
        },
        Vector {
            name: "03-get-request",
            description: "request state, percent-encoded request id",
            method: "GET",
            target: format!("{base}/action-requests/robot_safe_pause%3Augv-007%3A0001"),
            body: Vec::new(),
            nonce: n(3),
            expect: json!({"route": "get", "id": "robot_safe_pause:ugv-007:0001", "authenticated": true}),
            answer: Some((200, "application/json", j(state))),
            sign_as: SignAs::Valid,
        },
        Vector {
            name: "04-revert",
            description: "revert of a recorded request",
            method: "POST",
            target: format!("{base}/action-requests/robot_safe_pause%3Augv-007%3A0001/revert"),
            body: j(json!({"reason": "false positive", "requested_by": "analyst@soc"})),
            nonce: n(4),
            expect: json!({"route": "revert", "id": "robot_safe_pause:ugv-007:0001", "authenticated": true}),
            answer: None,
            sign_as: SignAs::Valid,
        },
        Vector {
            name: "05-evidence-inventory",
            description: "evidence inventory",
            method: "GET",
            target: format!("{base}/evidence"),
            body: Vec::new(),
            nonce: n(5),
            expect: json!({"route": "evidence_inventory", "authenticated": true}),
            answer: None,
            sign_as: SignAs::Valid,
        },
        Vector {
            name: "06-evidence-export",
            description: "export of a finding's evidence (seqs 10 and 12, 3 context records each side); answer 201 = the manifest bytes",
            method: "POST",
            target: format!("{base}/evidence/exports"),
            body: export_body,
            nonce: n(6),
            expect: json!({"route": "evidence_create", "authenticated": true}),
            answer: Some((201, "application/json", x.manifest_bytes.clone())),
            sign_as: SignAs::Valid,
        },
        Vector {
            name: "07-evidence-manifest",
            description: "the manifest again (resume after a disconnect)",
            method: "GET",
            target: format!("{base}/evidence/exports/case-42%3Aev-1"),
            body: Vec::new(),
            nonce: n(7),
            expect: json!({"route": "evidence_manifest", "id": "case-42:ev-1", "authenticated": true}),
            answer: Some((200, "application/json", x.manifest_bytes.clone())),
            sign_as: SignAs::Valid,
        },
    ];
    for (i, c) in x.manifest.bundle.chunks.iter().enumerate().take(2) {
        let bytes = x.bundle[c.offset as usize..(c.offset + c.bytes) as usize].to_vec();
        out.push(Vector {
            name: if i == 0 { "08-evidence-chunk-0" } else { "09-evidence-chunk-1" },
            description: "one chunk (application/octet-stream)",
            method: "GET",
            target: format!("{base}/evidence/exports/case-42%3Aev-1/chunks/{i}"),
            body: Vec::new(),
            nonce: n(8 + i as u32),
            expect: json!({"route": "evidence_chunk", "id": "case-42:ev-1", "chunk": i, "authenticated": true}),
            answer: Some((200, "application/octet-stream", bytes)),
            sign_as: SignAs::Valid,
        });
    }
    out.extend([
        Vector {
            name: "10-evidence-delete",
            description: "delete an export",
            method: "DELETE",
            target: format!("{base}/evidence/exports/case-42%3Aev-1"),
            body: Vec::new(),
            nonce: n(10),
            expect: json!({"route": "evidence_delete", "id": "case-42:ev-1", "authenticated": true}),
            answer: Some((
                200,
                "application/json",
                j(json!({"export_id": "case-42:ev-1", "deleted": true})),
            )),
            sign_as: SignAs::Valid,
        },
        Vector {
            name: "11-bad-signature",
            description: "signature over another body: 401 bad_signature, unsigned answer",
            method: "POST",
            target: format!("{base}/action-requests"),
            body: submit.clone(),
            nonce: n(11),
            expect: json!({"authenticated": false, "status": 401, "code": "bad_signature"}),
            answer: None,
            sign_as: SignAs::TamperedBody,
        },
        Vector {
            name: "12-other-robot",
            description: "signed for robot ugv-008: 401 bad_signature",
            method: "GET",
            target: base.clone(),
            body: Vec::new(),
            nonce: n(12),
            expect: json!({"authenticated": false, "status": 401, "code": "bad_signature"}),
            answer: None,
            sign_as: SignAs::OtherRobot,
        },
        Vector {
            name: "13-v1-domain",
            description: "signed in the removed robodr-control-plane/v1 domain: 401 bad_signature",
            method: "GET",
            target: base,
            body: Vec::new(),
            nonce: n(13),
            expect: json!({"authenticated": false, "status": 401, "code": "bad_signature"}),
            answer: None,
            sign_as: SignAs::V1Domain,
        },
    ]);
    out
}

/// Every file of the fixture directory: relative path -> bytes.
pub fn files() -> Vec<(String, Vec<u8>)> {
    let mut f: Vec<(String, Vec<u8>)> = Vec::new();
    let text = |s: String| s.into_bytes();
    // Keys (TEST ONLY: the secrets are published on purpose).
    for (name, seed, id) in [
        ("soc", SOC_SEED, SOC_ID),
        ("finding", FINDING_SEED, FINDING_ID),
        ("blackbox", BB_SEED, BB_ID),
    ] {
        let k = keyfile(&seed, id);
        f.push((format!("keys/{name}.key"), text(k.to_json())));
        f.push((
            format!("keys/{name}.key.pub"),
            text(k.to_public().unwrap().to_json()),
        ));
    }
    // Requests and answers.
    let mut cases = Vec::new();
    for v in vectors() {
        let (msg, sig) = signature(&v);
        let raw = request_bytes(&v);
        f.push((format!("requests/{}.http", v.name), raw));
        let mut meta = json!({
            "name": v.name,
            "description": v.description,
            "method": v.method,
            "target": v.target,
            "robot_id": ROBOT,
            "key_id": SOC_ID,
            "timestamp": TS,
            "nonce": v.nonce,
            "body_sha256": to_hex(&sha256(&v.body)),
            "signing_message": String::from_utf8(msg).unwrap(),
            "signature": sig,
            "expect": v.expect,
        });
        if let Some((status, ctype, body)) = &v.answer {
            let ext = if *ctype == "application/json" {
                "json"
            } else {
                "bin"
            };
            let body_file = format!("answers/{}.body.{ext}", v.name);
            f.push((body_file.clone(), body.clone()));
            let mut a = json!({
                "status": status,
                "content_type": ctype,
                "body_file": body_file,
                "body_sha256": to_hex(&sha256(body)),
                "answer_message": String::from_utf8(answer_message(&sig, *status, body)).unwrap(),
                "x_robodr_answer_signature": answer_header(&sig, *status, body),
            });
            if v.name == "06-evidence-export" || v.name == "07-evidence-manifest" {
                a["x_robodr_manifest_signature"] = json!(export().manifest_signature);
            }
            meta["answer"] = a;
        }
        f.push((
            format!("requests/{}.json", v.name),
            serde_json::to_vec_pretty(&meta).unwrap(),
        ));
        cases.push(json!({"name": v.name, "description": v.description}));
    }
    // Evidence.
    let x = export();
    f.push((
        "evidence/blackbox/seg-0000000000000000.rbb".into(),
        segment(),
    ));
    f.push(("evidence/bundle.rbbx".into(), x.bundle.clone()));
    f.push(("evidence/manifest.json".into(), x.manifest_bytes.clone()));
    f.push((
        "evidence/manifest.sig".into(),
        x.manifest_signature.clone().into_bytes(),
    ));
    f.push((
        "evidence/manifest.message".into(),
        manifest_message(&x.manifest_bytes),
    ));
    for c in &x.manifest.bundle.chunks {
        f.push((
            format!("evidence/chunks/{:04}.bin", c.index),
            x.bundle[c.offset as usize..(c.offset + c.bytes) as usize].to_vec(),
        ));
    }
    // A tampered copy: one byte of the payload of seq 10 flipped.
    let mut t = x.bundle.clone();
    let needle = b"robot_safe_pause:ugv-007:0001";
    let at = t
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("decision note in the bundle");
    t[at] ^= 0x01;
    f.push(("evidence/tampered/bundle-flipped-byte.rbbx".into(), t));
    f.push((
        "evidence/expected.json".into(),
        serde_json::to_vec_pretty(&json!({
            "bundle_sha256": x.manifest.bundle.sha256,
            "chain_id": x.manifest.chain.chain_id,
            "device_id": ROBOT,
            "signing_key": x.manifest.chain.signing_key,
            "first_seq": x.manifest.records.first_seq,
            "last_seq": x.manifest.records.last_seq,
            "records": x.manifest.records.count,
            "last_sha256": x.manifest.records.last_sha256,
            "anchor": x.manifest.anchor,
            "referenced": x.manifest.referenced,
            "verdict": "intact",
            "tampered/bundle-flipped-byte.rbbx": "tamper (HashMismatch at seq 10)",
        }))
        .unwrap(),
    ));
    f.push((
        "manifest.json".into(),
        serde_json::to_vec_pretty(&json!({
            "contract": "docs/contracts/robodr.control-plane.md",
            "api": API_VERSION,
            "generator": "cargo run -p robodr-agentd --example control_plane_vectors",
            "robot_id": ROBOT,
            "keys": {
                "soc": {"key_id": SOC_ID, "file": "keys/soc.key.pub"},
                "finding": {"key_id": FINDING_ID, "file": "keys/finding.key.pub",
                            "verifies": "X-RoboDR-Answer-Signature, X-RoboDR-Manifest-Signature"},
                "blackbox": {"key_id": BB_ID, "file": "keys/blackbox.key.pub",
                             "verifies": "the records of evidence/bundle.rbbx"},
                "note": "TEST KEYS ONLY: the secret key files are published on purpose",
            },
            "chunk_bytes": CHUNK_BYTES,
            "cases": cases,
        }))
        .unwrap(),
    ));
    f.sort_by(|a, b| a.0.cmp(&b.0));
    f
}
