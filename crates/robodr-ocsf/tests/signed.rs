//! Detached per-finding signatures (contract 1.2, `robodr_ocsf::sig`).

mod common;

use std::collections::{BTreeMap, HashMap};

use robodr_blackbox::{Ed25519SigningKey, HmacSha256Key, Keyring, Signer, Verifier};
use robodr_ocsf::sig::{signing_message, SIG_ALG};
use robodr_ocsf::*;

fn key(unit: &str, n: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(format!("finding:{unit}:{n}"), &[n; 32]).unwrap()
}

fn keys(pairs: &[(&str, &Ed25519SigningKey)]) -> BTreeMap<String, Box<dyn Verifier>> {
    pairs
        .iter()
        .map(|(u, k)| {
            (
                u.to_string(),
                Box::new(k.verifying_key()) as Box<dyn Verifier>,
            )
        })
        .collect()
}

fn signed_example(k: &Ed25519SigningKey) -> Record {
    record_signed(&common::example_finding(), Some(12), k).unwrap()
}

#[test]
fn round_trip_verifies_and_returns_the_finding() {
    let k = key("ugv-007", 1);
    let rec = signed_example(&k);
    // The signature header is appended after the 1.1 headers, which are unchanged.
    let plain = record(&common::example_finding(), Some(12)).unwrap();
    assert_eq!(rec.value, plain.value);
    assert_eq!(&rec.headers[..plain.headers.len()], &plain.headers[..]);
    assert_eq!(rec.headers.last().unwrap().0, SIG_HEADER);
    assert_eq!(rec.headers.len(), plain.headers.len() + 1);

    let ks = keys(&[("ugv-007", &k)]);
    let v = verify_record(&rec, &ks, SignaturePolicy::Strict).unwrap();
    assert_eq!(v.envelope, common::example_finding());
    assert_eq!(
        v.signature,
        SignatureStatus::Verified {
            unit_id: "ugv-007".into(),
            key_id: "finding:ugv-007:1".into()
        }
    );
    // Header form is exactly {alg,key_id,sig}.
    let h = signature_header(&rec.headers).unwrap().unwrap();
    let s = FindingSignature::from_header_value(h).unwrap();
    assert_eq!(s.alg, "ed25519");
    assert_eq!(s.key_id, "finding:ugv-007:1");
    assert_eq!(s.sig.len(), 128);
    // Deterministic (Ed25519): same value, same signature.
    assert_eq!(signed_example(&k), rec);
    // HashMap also works as a key registry.
    let hm: HashMap<String, Box<dyn Verifier>> = keys(&[("ugv-007", &k)]).into_iter().collect();
    assert!(verify_record(&rec, &hm, SignaturePolicy::Strict).is_ok());
    // Re-signing replaces, never duplicates, the header.
    let mut again = rec.clone();
    sign_record(&mut again, &k).unwrap();
    assert_eq!(again, rec);
}

#[test]
fn signed_bytes_are_the_record_value_verbatim() {
    let k = key("ugv-007", 1);
    let rec = signed_example(&k);
    let s = FindingSignature::from_header_value(signature_header(&rec.headers).unwrap().unwrap())
        .unwrap();
    let msg = signing_message(SIG_ALG, &s.key_id, rec.value.as_bytes());
    assert!(k.verifying_key().verify(&msg, &s.sig_bytes().unwrap()));
    // Today re-serialising a parsed finding gives the same bytes, but a
    // semantically equal re-formatting (pretty print) does not verify:
    // verification never canonicalises.
    let env = parse_and_validate(&rec.value).unwrap();
    assert_eq!(to_json(&env).unwrap(), rec.value);
    let pretty = serde_json::to_string_pretty(&env).unwrap();
    let ks = keys(&[("ugv-007", &k)]);
    assert_eq!(
        parse_and_validate_signed(
            &pretty,
            Some(&s.to_header_value()),
            &ks,
            SignaturePolicy::Strict
        ),
        Err(SignatureError::BadSignature)
    );
}

#[test]
fn tampering_with_any_byte_of_the_value_is_rejected() {
    let k = key("ugv-007", 1);
    let rec = signed_example(&k);
    let sig = signature_header(&rec.headers).unwrap().unwrap().to_string();
    let ks = keys(&[("ugv-007", &k)]);
    let raw = rec.value.as_bytes();
    let mut checked_sig = 0;
    for i in 0..raw.len() {
        let mut t = raw.to_vec();
        t[i] ^= 0x01;
        // Flipping the low bit keeps ASCII ASCII; skip the rare non-UTF-8 case.
        let Ok(s) = String::from_utf8(t) else {
            continue;
        };
        match parse_and_validate_signed(&s, Some(&sig), &ks, SignaturePolicy::Strict) {
            Ok(_) => panic!("byte {i} tampered but accepted"),
            Err(SignatureError::BadSignature) => checked_sig += 1,
            Err(SignatureError::Invalid(_)) => {}
            Err(e) => panic!("byte {i}: unexpected {e}"),
        }
    }
    // Plenty of single-byte forgeries survive the validator; only the
    // signature catches them.
    assert!(checked_sig > 10, "{checked_sig}");
    // Appending whitespace keeps the JSON equal but changes the bytes.
    let padded = format!("{} ", rec.value);
    assert_eq!(
        parse_and_validate_signed(&padded, Some(&sig), &ks, SignaturePolicy::Strict),
        Err(SignatureError::BadSignature)
    );
}

#[test]
fn tampering_with_the_signature_object_is_rejected() {
    let k = key("ugv-007", 1);
    let k2 = key("ugv-007", 2);
    let rec = signed_example(&k);
    let s = FindingSignature::from_header_value(signature_header(&rec.headers).unwrap().unwrap())
        .unwrap();
    // Both keys belong to ugv-007 (rotation): the key id is part of the
    // signed message, so relabelling a signature to the other key fails.
    let mut ring = Keyring::new();
    ring.add(Box::new(k.verifying_key())).unwrap();
    ring.add(Box::new(k2.verifying_key())).unwrap();
    let mut ks: BTreeMap<String, Box<dyn Verifier>> = BTreeMap::new();
    ks.insert("ugv-007".into(), Box::new(ring));
    assert!(verify_record(&rec, &ks, SignaturePolicy::Strict).is_ok());
    let rec2 = signed_example(&k2);
    assert!(verify_record(&rec2, &ks, SignaturePolicy::Strict).is_ok());

    let relabelled = FindingSignature {
        key_id: k2.key_id().into(),
        ..s.clone()
    };
    let check =
        |sig: &str| parse_and_validate_signed(&rec.value, Some(sig), &ks, SignaturePolicy::Strict);
    assert_eq!(
        check(&relabelled.to_header_value()),
        Err(SignatureError::BadSignature)
    );
    for i in 0..s.sig.len() {
        let mut b = s.sig.clone().into_bytes();
        b[i] = if b[i] == b'0' { b'1' } else { b'0' };
        let t = FindingSignature {
            sig: String::from_utf8(b).unwrap(),
            ..s.clone()
        };
        assert_eq!(
            check(&t.to_header_value()),
            Err(SignatureError::BadSignature),
            "sig digit {i}"
        );
    }
    let unknown = FindingSignature {
        key_id: "finding:ugv-007:9".into(),
        ..s.clone()
    };
    assert_eq!(
        check(&unknown.to_header_value()),
        Err(SignatureError::BadSignature)
    );
    let hmac = FindingSignature {
        alg: "hmac-sha256".into(),
        ..s.clone()
    };
    assert!(matches!(
        check(&hmac.to_header_value()),
        Err(SignatureError::UnsupportedAlgorithm(_))
    ));
    assert!(matches!(
        check("garbage"),
        Err(SignatureError::Malformed(_))
    ));
}

#[test]
fn a_key_of_another_unit_never_vouches() {
    let k7 = key("ugv-007", 1);
    let k8 = key("ugv-008", 2);
    let ks = keys(&[("ugv-007", &k7), ("ugv-008", &k8)]);
    // ugv-008 (compromised, or a rogue producer with its key) forges a
    // finding naming ugv-007.
    let forged = signed_example(&k8);
    assert_eq!(
        verify_record(&forged, &ks, SignaturePolicy::Strict),
        Err(SignatureError::BadSignature)
    );
    // Unit without a registered key.
    let only8 = keys(&[("ugv-008", &k8)]);
    assert_eq!(
        verify_record(&signed_example(&k7), &only8, SignaturePolicy::Strict),
        Err(SignatureError::UnknownUnit("ugv-007".into()))
    );
    // A keyring that binds the key to another device refuses it even if an
    // operator registered the ring under the wrong unit.
    let mut ring = Keyring::new();
    ring.add_bound(Box::new(k8.verifying_key()), Some("ugv-008"))
        .unwrap();
    let mut wrong: BTreeMap<String, Box<dyn Verifier>> = BTreeMap::new();
    wrong.insert("ugv-007".into(), Box::new(ring));
    assert_eq!(
        verify_record(&forged, &wrong, SignaturePolicy::Strict),
        Err(SignatureError::KeyUnitMismatch {
            unit: "ugv-007".into(),
            key_device: "ugv-008".into()
        })
    );
    // Correctly bound: accepted.
    let mut ring = Keyring::new();
    ring.add_bound(Box::new(k7.verifying_key()), Some("ugv-007"))
        .unwrap();
    let mut right: BTreeMap<String, Box<dyn Verifier>> = BTreeMap::new();
    right.insert("ugv-007".into(), Box::new(ring));
    assert!(verify_record(&signed_example(&k7), &right, SignaturePolicy::Strict).is_ok());
}

#[test]
fn missing_signature_policy() {
    let k = key("ugv-007", 1);
    let ks = keys(&[("ugv-007", &k)]);
    let plain = record(&common::example_finding(), Some(12)).unwrap();
    assert_eq!(
        verify_record(&plain, &ks, SignaturePolicy::Strict),
        Err(SignatureError::Missing)
    );
    let v = verify_record(&plain, &ks, SignaturePolicy::Optional).unwrap();
    assert_eq!(v.signature, SignatureStatus::Unsigned);
    // Optional does not mean "ignore a bad signature".
    let mut bad = signed_example(&key("ugv-007", 3));
    assert_eq!(
        verify_record(&bad, &ks, SignaturePolicy::Optional),
        Err(SignatureError::BadSignature)
    );
    // Two signature headers: ambiguous, rejected in both policies.
    bad.headers.push((SIG_HEADER, "x".into()));
    for p in [SignaturePolicy::Strict, SignaturePolicy::Optional] {
        assert_eq!(verify_record(&bad, &ks, p), Err(SignatureError::Duplicate));
    }
    // Invalid values are rejected before any key lookup.
    assert!(matches!(
        parse_and_validate_signed("{}", None, &ks, SignaturePolicy::Optional),
        Err(SignatureError::Invalid(_))
    ));
}

#[test]
fn replay_is_detectable_by_the_consumer_not_by_the_signature() {
    let k = key("ugv-007", 1);
    let ks = keys(&[("ugv-007", &k)]);
    let rec = signed_example(&k);
    // A captured record re-sent verbatim verifies again ...
    let a = verify_record(&rec, &ks, SignaturePolicy::Strict).unwrap();
    let b = verify_record(&rec, &ks, SignaturePolicy::Strict).unwrap();
    // ... and carries the same replay key, so the consumer's dedup catches it.
    assert_eq!(a.replay_key(), b.replay_key());
    let rk = a.replay_key();
    assert_eq!(rk.robot_id, "ugv-007");
    assert_eq!(rk.finding_id, a.envelope.finding_id);
    assert_eq!(rk.event_uid, a.envelope.ocsf.metadata.uid);
    assert_eq!(rk.time_ms, common::T0 + 4_250);
    assert_eq!(rk.count, 3);
    // A genuine later emission of the same finding: same finding id, new
    // event uid and time.
    let ctx = common::ctx();
    let dev = robodr_events::Deviation::new(
        "robot.ros2.unauthorized_motion_writer",
        robodr_events::Severity::Critical,
        "x",
    );
    let later = FindingBuilder::from_deviation(&dev, &ctx)
        .event(&robodr_events::RobotEvent::Ros2WriterDiscovered(
            common::writer("rt/cmd_vel"),
        ))
        .seen(common::T0, common::T0 + 9_000)
        .occurrences(4)
        .build()
        .unwrap();
    assert_eq!(later.finding_id, a.envelope.finding_id);
    let rec2 = record_signed(&later, None, &k).unwrap();
    let c = verify_record(&rec2, &ks, SignaturePolicy::Strict).unwrap();
    assert_eq!(c.replay_key().finding_id, rk.finding_id);
    assert_ne!(c.replay_key().event_uid, rk.event_uid);
    assert!(c.replay_key().time_ms > rk.time_ms);
}

#[test]
fn only_ed25519_signers_are_accepted() {
    let h = HmacSha256Key::new("hmac-key", &[9; 32]).unwrap();
    assert_eq!(
        record_signed(&common::example_finding(), None, &h),
        Err(SignatureError::UnsupportedAlgorithm("hmac-sha256".into()))
    );
    // Oversized values are refused before signing.
    let k = key("ugv-007", 1);
    assert!(matches!(
        sign_value(&" ".repeat(64 * 1024 + 1), &k),
        Err(SignatureError::Invalid(_))
    ));
    // A signer returning a wrong-length signature is reported, not shipped.
    struct Short;
    impl Signer for Short {
        fn algorithm(&self) -> &str {
            "ed25519"
        }
        fn key_id(&self) -> &str {
            "short"
        }
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, robodr_blackbox::sign::SignError> {
            Ok(vec![0; 10])
        }
    }
    assert!(matches!(
        sign_value("{}", &Short),
        Err(SignatureError::Signing(_))
    ));
}

#[test]
fn hostile_headers_never_panic() {
    let k = key("ugv-007", 1);
    let ks = keys(&[("ugv-007", &k)]);
    let rec = signed_example(&k);
    for h in [
        "",
        "{",
        "\u{0}",
        "{\"alg\":\"ed25519\",\"key_id\":\"\u{202e}x\",\"sig\":\"00\"}",
        "{\"alg\":1,\"key_id\":2,\"sig\":3}",
        &"[".repeat(10_000),
        &format!(
            "{{\"alg\":\"ed25519\",\"key_id\":\"k\",\"sig\":\"{}\"}}",
            "é".repeat(64)
        ),
    ] {
        for p in [SignaturePolicy::Strict, SignaturePolicy::Optional] {
            assert!(parse_and_validate_signed(&rec.value, Some(h), &ks, p).is_err());
        }
    }
}

#[test]
fn schema_and_contract_document_the_signature_header() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts");
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("robodr-finding.schema.json")).unwrap(),
    )
    .unwrap();
    let def = &schema["$defs"]["FindingSignatureHeader"];
    assert_eq!(def["required"], serde_json::json!(["alg", "key_id", "sig"]));
    assert_eq!(def["additionalProperties"], serde_json::json!(false));
    assert_eq!(def["properties"]["alg"]["const"], SIG_ALG);
    assert_eq!(
        def["properties"]["sig"]["pattern"],
        format!("^[0-9a-f]{{{}}}$", robodr_ocsf::sig::SIG_LEN * 2)
    );
    assert_eq!(
        schema["$id"].as_str().unwrap(),
        format!("https://schemas.singularityrd.com/robodr/findings/{CONTRACT_VERSION}")
    );
    let md = std::fs::read_to_string(dir.join("robodr.findings.md")).unwrap();
    assert!(md.contains(SIG_HEADER));
    assert!(md.contains(&format!("**{CONTRACT_VERSION}**")));
    assert!(md.contains("robodr-ocsf/finding-sig/v1"));
}
