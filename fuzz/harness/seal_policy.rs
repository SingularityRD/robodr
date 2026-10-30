//! Harness: the signed PCR policy (`robodr_seal::policy`) and the unit
//! enrolment record (`robodr_seal::unit::UnitRecord`).
//!
//! Input: a selector byte, then the document. Invariants beyond "no
//! panic":
//!
//! * a policy that parses is exactly its canonical encoding, has a version
//!   in 0..=63, 1..=24 strictly increasing PCR indices, an approved policy
//!   that is a pure function of its members, and a `tpm2_policypcr`
//!   selection that names exactly its PCRs;
//! * a policy that verifies against the harness authority is for the
//!   harness platform and floor index, and its signature verifies over
//!   its recomputed `aHash`; it never verifies against another key;
//! * an enrolment record that parses has a usable recipient and survives
//!   a serialise / parse round trip unchanged.
//!
//! Shared via `#[path]` with `crates/robodr-seal/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_seal::keys::PolicyKey;
use robodr_seal::{policy, unit::UnitRecord};

pub const PLATFORM: &str = "ugv-x1";
pub const FLOOR_NV: u32 = 0x0150_0041;

/// The harness policy authority (fixed scalar; RFC 6979 signatures are
/// deterministic, so the seeds are too).
pub fn authority() -> PolicyKey {
    PolicyKey::from_bytes(&[7u8; 32]).expect("valid scalar")
}

pub fn other() -> PolicyKey {
    PolicyKey::from_bytes(&[9u8; 32]).expect("valid scalar")
}

pub fn run(data: &[u8]) {
    let Some((&sel, doc)) = data.split_first() else {
        return;
    };
    if sel & 1 == 0 {
        policy_doc(doc);
    } else {
        unit_record(doc);
    }
}

fn policy_doc(doc: &[u8]) {
    if let Ok(p) = policy::parse(doc) {
        assert_eq!(
            robodr_pkg::common::to_canonical(&p.doc).expect("serialises"),
            doc
        );
        assert!(p.doc.version <= policy::MAX_VERSION);
        assert!(!p.pcrs.is_empty() && p.pcrs.len() <= 24);
        assert!(p.pcrs.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(
            p.approved,
            policy::approved_policy(&p.pcrs, p.floor_nv, p.doc.version)
        );
        let list = p.pcr_list();
        assert_eq!(
            list.trim_start_matches("sha256:").split(',').count(),
            p.pcrs.len()
        );
    }
    let auth = authority();
    if let Ok(p) = policy::verify(doc, &auth.public(), PLATFORM, FLOOR_NV) {
        assert_eq!(p.doc.platform, PLATFORM);
        assert_eq!(p.floor_nv, FLOOR_NV);
        robodr_seal::keys::policy_verify(&auth.public(), &p.digest(), &p.signature)
            .expect("verified signature");
        assert!(policy::verify(doc, &other().public(), PLATFORM, FLOOR_NV).is_err());
    }
}

fn unit_record(doc: &[u8]) {
    if let Ok(r) = UnitRecord::parse(doc) {
        let rec = r.recipient().expect("a parsed record has a recipient");
        assert!(rec.fingerprint().starts_with("sha256:"));
        let again = serde_json::to_vec(&r).expect("serialises");
        assert_eq!(UnitRecord::parse(&again).expect("round trip"), r);
    }
}

/// Seeds: a policy signed by the harness authority, one by another key,
/// and a TPM and a fallback enrolment record.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let pcrs = [(0u8, [0u8; 32]), (7u8, [0x11u8; 32])];
    let good = policy::sign(&authority(), PLATFORM, 3, &pcrs, FLOOR_NV).expect("signs");
    let rogue = policy::sign(&other(), PLATFORM, 3, &pcrs, FLOOR_NV).expect("signs");
    let p256 = robodr_seal::wrap::p256_public_bytes(
        &p256::SecretKey::from_slice(&[5u8; 32])
            .expect("scalar")
            .public_key(),
    );
    let tpm = serde_json::json!({
        "format": "robodr-seal-unit/1", "unit": "ugv-07", "platform": PLATFORM, "mode": "tpm",
        "uwk_public": robodr_seal::to_hex(&p256),
        "tpm": {"srk": "0x81000001", "epoch_nv": "0x01500040", "epoch": 1, "floor_nv": "0x01500041",
                "policy_authority": robodr_seal::to_hex(&authority().public()),
                "policy_authority_name": format!("000b{}", "ab".repeat(32)),
                "auth_policy": "cd".repeat(32)},
        "fallback_key": null
    });
    let fb = serde_json::json!({
        "format": "robodr-seal-unit/1", "unit": "ugv-09", "platform": PLATFORM, "mode": "fallback",
        "uwk_public": "42".repeat(32), "tpm": null,
        "fallback_key": "/run/robodr-sealed/.robodr-seal/uwk.key"
    });
    let with = |sel: u8, b: Vec<u8>| [vec![sel], b].concat();
    vec![
        ("seed-policy.bin", with(0, good)),
        ("seed-policy-rogue.bin", with(0, rogue)),
        (
            "seed-unit-tpm.bin",
            with(1, serde_json::to_vec(&tpm).expect("json")),
        ),
        (
            "seed-unit-fallback.bin",
            with(1, serde_json::to_vec(&fb).expect("json")),
        ),
    ]
}
