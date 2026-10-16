//! rev4 crypto review findings, ported from the PoCs
//! (`rev4_crypto_poc.rs`, written against the pre-KeyFile-v2 tree) as
//! regression tests that assert the FIXED behaviour:
//!
//! - K1: a record verifies only under the key its chain names (algorithm
//!   included), switched only by an authenticated `KeyRotation`; keyrings
//!   refuse to mix HMAC and Ed25519 without an opt-in; a key bound to a
//!   device verifies only that device's chains.
//! - K2: Ed25519 key files verify through a keyring; seed/public lengths
//!   are exact.
//! - Bundles across a rotation that happened in an earlier bundle.
mod common;
use common::*;
use robodr_blackbox::keys::Keyring;
use robodr_blackbox::record::{
    signing_message, KeyRef, Record, RecordKind, SegmentStartPayload, ZERO_HASH,
};
use robodr_blackbox::sign::SignError;
use robodr_blackbox::sign_ed25519::public_key_from_seed;
use robodr_blackbox::store::segment_file_name;
use robodr_blackbox::verify::{verify_dir, FindingKind, VerifyOptions};
use robodr_blackbox::{
    Ed25519SigningKey, Ed25519VerifyingKey, HmacSha256Key, KeyFile, KeyFileError, Receiver,
    Recorder, RecorderConfig, RetentionMode, Signer, SteppingClock, TimeSource, Verifier,
};
use robodr_events::{Deviation, Severity};
use std::path::Path;

const SEED_A: [u8; 32] = [0xA1; 32];
const SEED_B: [u8; 32] = [0xB2; 32];

fn unit_a() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed("unit-a", &SEED_A).unwrap()
}

fn unit_b() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed("unit-b", &SEED_B).unwrap()
}

fn pub_a() -> Ed25519VerifyingKey {
    Ed25519VerifyingKey::from_bytes("unit-a", &public_key_from_seed(&SEED_A)).unwrap()
}

fn pub_b() -> Ed25519VerifyingKey {
    Ed25519VerifyingKey::from_bytes("unit-b", &public_key_from_seed(&SEED_B)).unwrap()
}

/// A signer that *claims* to be `ed25519 / unit-a` but signs with another key.
struct Liar {
    inner: Box<dyn Signer>,
}
impl Signer for Liar {
    fn algorithm(&self) -> &str {
        "ed25519"
    }
    fn key_id(&self) -> &str {
        "unit-a"
    }
    fn sign(&self, m: &[u8]) -> Result<Vec<u8>, SignError> {
        self.inner.sign(m)
    }
    fn verify_own(&self, m: &[u8], s: &[u8]) -> Option<bool> {
        self.inner.verify_own(m, s)
    }
}

fn forge_log(dir: &Path, inner: Box<dyn Signer>) {
    let mut rec = Recorder::open(
        RecorderConfig::new(dir, "ugv-a", "boot-1"),
        Box::new(Liar { inner }),
        Box::new(SteppingClock::new(1, 1_000, TimeSource::Rtc)),
    )
    .unwrap();
    rec.append_deviation(&Deviation::new(
        "robot.forged",
        Severity::Low,
        "never happened",
    ))
    .unwrap();
    rec.close().unwrap();
}

fn honest_log(dir: &Path, device: &str, n: u64) {
    let mut c = cfg(dir, big());
    c.device_id = device.into();
    let mut r = Recorder::open(c, Box::new(unit_a()), clock()).unwrap();
    for i in 0..n {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.close().unwrap();
}

fn fleet_ring() -> Keyring {
    let mut ring = Keyring::new();
    ring.add(Box::new(pub_a())).unwrap();
    ring.add(Box::new(pub_b())).unwrap();
    ring
}

fn vd(dir: &Path, v: &dyn Verifier) -> robodr_blackbox::Report {
    verify_dir(dir, v, &VerifyOptions::default()).unwrap()
}

fn key_mismatch(k: &FindingKind) -> bool {
    matches!(k, FindingKind::KeyMismatch { .. })
}

/// K1 (was: PASSED = intact): an HMAC key the verifying station could sign
/// with no longer vouches for evidence whose identity says `ed25519 / unit-a`.
#[test]
fn k1_hmac_key_cannot_vouch_for_ed25519_unit_evidence() {
    let d = TestDir::new("r4-k1");
    forge_log(
        d.path(),
        Box::new(HmacSha256Key::new("station-hmac", &[0x55; 32]).unwrap()),
    );
    let hmac = || Box::new(HmacSha256Key::new("station-hmac", &[0x55; 32]).unwrap());
    // Mixing the station's HMAC key into the Ed25519 fleet ring is refused...
    let mut ring = Keyring::new();
    ring.add(Box::new(pub_a())).unwrap();
    assert!(matches!(
        ring.add(hmac()),
        Err(KeyFileError::MixedAlgorithms { .. })
    ));
    assert_eq!(ring.len(), 1);
    // ... and even when explicitly allowed, it cannot vouch for unit-a.
    ring.set_allow_mixed_algorithms(true);
    ring.add(hmac()).unwrap();
    let rep = vd(d.path(), &ring);
    let id = rep.identity.clone().expect("identity");
    assert_eq!(
        (id.algorithm.as_str(), id.key_id.as_str()),
        ("ed25519", "unit-a")
    );
    assert!(!rep.is_intact(), "{}", dump(&rep));
    assert!(has(&rep, key_mismatch), "{}", dump(&rep));
    // The HMAC key alone (an unambiguous one-key ring, or the bare key):
    // its id and algorithm are not the chain's.
    let mut solo = Keyring::new();
    solo.add(hmac()).unwrap();
    assert!(!vd(d.path(), &solo).is_intact());
    assert!(!vd(d.path(), &*hmac()).is_intact());
}

/// K1b (was: PASSED = intact): unit-b's key no longer forges evidence
/// attributed to unit-a when verified with a fleet keyring.
#[test]
fn k1b_other_unit_key_cannot_forge_unit_a_evidence() {
    let d = TestDir::new("r4-k1b");
    forge_log(d.path(), Box::new(unit_b()));
    let rep = vd(d.path(), &fleet_ring());
    assert_eq!(rep.identity.as_ref().unwrap().key_id, "unit-a");
    assert!(!rep.is_intact(), "{}", dump(&rep));
    assert!(has(&rep, key_mismatch));
    // A bare verifier for unit-b is not unit-a's key either.
    assert!(!vd(d.path(), &pub_b()).is_intact());
    // The key lookup takes the algorithm into account: an HMAC key filed
    // under an ed25519-looking id never answers for an ed25519 key.
    let id = "ed25519:0011223344556677";
    let h = HmacSha256Key::new(id, &[9; 32]).unwrap();
    let tag = h.sign(b"m").unwrap();
    let mut r = Keyring::new();
    r.add(Box::new(HmacSha256Key::new(id, &[9; 32]).unwrap()))
        .unwrap();
    assert!(!r.verify_key(id, "ed25519", b"m", &tag));
    assert!(r.verify_key(id, "hmac-sha256", b"m", &tag));
    assert!(!h.verify_key(id, "ed25519", b"m", &tag));
    // A keyring never answers "any key?" for more than one key.
    let sig = unit_b().sign(b"m").unwrap();
    assert!(!fleet_ring().verify(b"m", &sig));
    assert!(fleet_ring().verify_key("unit-b", "ed25519", b"m", &sig));
    assert!(!fleet_ring().verify_key("unit-a", "ed25519", b"m", &sig));
}

#[test]
fn k1_honest_logs_still_verify_with_a_fleet_ring() {
    let d = TestDir::new("r4-honest");
    honest_log(d.path(), "ugv-01", 60);
    let rep = vd(d.path(), &fleet_ring());
    assert!(rep.is_intact() && rep.is_clean(), "{}", dump(&rep));
    assert_eq!(
        rep.signing_key,
        Some(KeyRef {
            key_id: "unit-a".into(),
            algorithm: "ed25519".into()
        })
    );
    assert!(vd(d.path(), &pub_a()).is_clean());
    let mut only_b = Keyring::new();
    only_b.add(Box::new(pub_b())).unwrap();
    assert!(!vd(d.path(), &only_b).is_intact());
}

/// Appends a forged segment to a closed log: a `SegmentStart` that names
/// unit-b as the signing key (no rotation record) and one note, both
/// signed by unit-b and correctly hash-linked.
fn append_key_switch_segment(dir: &Path) {
    let recs = all_records(dir);
    let last = recs.last().unwrap().clone();
    let ss: SegmentStartPayload = recs
        .iter()
        .rev()
        .find(|r| r.kind == RecordKind::SegmentStart)
        .and_then(|r| r.payload_json())
        .unwrap();
    let next_index = ss.segment_index + 1;
    let payload = SegmentStartPayload {
        segment_index: next_index,
        signing_key: Some(KeyRef {
            key_id: "unit-b".into(),
            algorithm: "ed25519".into(),
        }),
        ..ss
    };
    let b = unit_b();
    let mut prev = last.hash;
    let mut out = Vec::new();
    for (i, (kind, body)) in [
        (
            RecordKind::SegmentStart,
            serde_json::to_vec(&payload).unwrap(),
        ),
        (RecordKind::Note, br#"{"forged":true}"#.to_vec()),
    ]
    .into_iter()
    .enumerate()
    {
        let mut r = Record {
            chain_id: last.chain_id,
            seq: last.seq + 1 + i as u64,
            time: last.time,
            kind,
            critical: kind.is_control(),
            payload: body,
            prev_hash: prev,
            hash: ZERO_HASH,
            sig: Vec::new(),
        };
        r.hash = r.compute_hash();
        r.sig = b.sign(&signing_message(&r.hash)).unwrap();
        prev = r.hash;
        out.extend(r.encode_frame());
    }
    std::fs::write(dir.join(segment_file_name(next_index)), out).unwrap();
}

#[test]
fn k1_segment_start_cannot_switch_an_established_key() {
    let d = TestDir::new("r4-switch");
    honest_log(d.path(), "ugv-01", 60);
    append_key_switch_segment(d.path());
    let rep = vd(d.path(), &fleet_ring());
    assert!(!rep.is_intact(), "{}", dump(&rep));
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::KeySwitchRefused { named_key_id, established_key_id, .. }
            if named_key_id == "unit-b" && established_key_id == "unit-a"
    )));
    assert!(has(&rep, |k| matches!(k, FindingKind::BadSignature { .. })));
}

/// A legitimate rotation (unit-a -> unit-b) followed by cyclic retention
/// dropping every segment the rotation record was in: the retained tail
/// names unit-b only in its `SegmentStart`s.
fn rotated_and_wrapped(dir: &Path) {
    let mut c = cfg(dir, RetentionMode::Cyclic { max_segments: 2 });
    c.device_id = "ugv-01".into();
    let mut r = Recorder::open(c, Box::new(unit_a()), clock()).unwrap();
    recorded(r.append_note(&note(0), false).unwrap());
    r.rotate_key(Box::new(unit_b()), None, "scheduled").unwrap();
    let mut i = 1;
    while r.segments()[0] < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    r.close().unwrap();
}

#[test]
fn k1_tail_named_key_is_unproven_unless_bound_to_the_device() {
    let d = TestDir::new("r4-tail");
    rotated_and_wrapped(d.path());
    assert!(!all_records(d.path())
        .iter()
        .any(|r| r.kind == RecordKind::KeyRotation));
    let unproven = |k: &FindingKind| matches!(k, FindingKind::SigningKeyUnproven { key_id, .. } if key_id == "unit-b");

    // Unbound keys: authentic, but the attribution is flagged.
    let rep = vd(d.path(), &fleet_ring());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(!rep.is_clean());
    assert!(has(&rep, unproven));
    assert_eq!(
        rep.findings.iter().filter(|f| unproven(&f.kind)).count(),
        1,
        "reported once"
    );

    // unit-b bound to this device: clean.
    let mut bound = Keyring::new();
    bound.add_bound(Box::new(pub_a()), Some("ugv-01")).unwrap();
    bound.add_bound(Box::new(pub_b()), Some("ugv-01")).unwrap();
    let rep = vd(d.path(), &bound);
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(!has(&rep, unproven), "{}", dump(&rep));

    // unit-b bound to another unit: it may not vouch for this chain.
    let mut other = Keyring::new();
    other.add_bound(Box::new(pub_b()), Some("ugv-99")).unwrap();
    let rep = vd(d.path(), &other);
    assert!(!rep.is_intact());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::KeyDeviceMismatch { key_device, chain_device, .. }
            if key_device == "ugv-99" && chain_device == "ugv-01"
    )));
}

#[test]
fn k1_full_rotation_history_is_proven_without_binding() {
    let d = TestDir::new("r4-rot");
    let mut c = cfg(d.path(), big());
    c.device_id = "ugv-01".into();
    let mut r = Recorder::open(c, Box::new(unit_a()), clock()).unwrap();
    for i in 0..30 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.rotate_key(Box::new(unit_b()), None, "t").unwrap();
    for i in 30..60 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.close().unwrap();
    let rep = vd(d.path(), &fleet_ring());
    assert!(rep.is_intact() && rep.is_clean(), "{}", dump(&rep));
    assert_eq!(rep.signing_key.unwrap().key_id, "unit-b");
    // Either key alone is not enough.
    assert!(!vd(d.path(), &pub_a()).is_intact());
    assert!(!vd(d.path(), &pub_b()).is_intact());
}

#[test]
fn k1_identity_key_bound_to_another_device_is_refused() {
    let d = TestDir::new("r4-bind");
    honest_log(d.path(), "ugv-01", 10);
    let mut ok = Keyring::new();
    ok.add_bound(Box::new(pub_a()), Some("ugv-01")).unwrap();
    assert!(vd(d.path(), &ok).is_clean());
    let mut wrong = Keyring::new();
    wrong.add_bound(Box::new(pub_a()), Some("ugv-02")).unwrap();
    let rep = vd(d.path(), &wrong);
    assert!(!rep.is_intact());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::KeyDeviceMismatch { .. }
    )));
    // Through key files: device_id in the public file binds it.
    let kf = KeyFile::ed25519_from_seed(&SEED_A, Some("unit-a"))
        .unwrap()
        .with_device_id(Some("ugv-02"))
        .unwrap()
        .to_public()
        .unwrap();
    let mut from_file = Keyring::new();
    from_file.add_json(&kf.to_json()).unwrap();
    assert!(!vd(d.path(), &from_file).is_intact());
}

/// K2 (was: UnsupportedAlgorithm / 1-byte seed accepted).
#[test]
fn k2_ed25519_key_files_are_usable_and_validated() {
    let hex = |b: &[u8]| robodr_blackbox::crypto::to_hex(b);
    let json = format!(
        r#"{{"format":"robodr-blackbox-key/v1","algorithm":"ed25519","key_id":"unit-a","secret_hex":"{}"}}"#,
        hex(&SEED_A)
    );
    let mut ring = Keyring::new();
    ring.add_json(&json).unwrap();
    let d = TestDir::new("r4-k2");
    honest_log(d.path(), "ugv-01", 5);
    assert!(vd(d.path(), &ring).is_clean());
    let tiny = r#"{"format":"robodr-blackbox-key/v1","algorithm":"ed25519","key_id":"u","secret_hex":"00"}"#;
    assert!(KeyFile::from_json(tiny).is_err());
    assert!(Keyring::new().add_json(tiny).is_err());
}

/// Receiver state carries the signing key across bundles, so a bundle
/// after the one holding the rotation verifies under the new key.
#[test]
fn receiver_tracks_the_key_across_bundles_after_a_rotation() {
    let d = TestDir::new("r4-rx");
    let key_b = || HmacSha256Key::new("unit-key-2", &[0x43; 32]).unwrap();
    let mut r = open(cfg(d.path(), big()));
    recorded(r.append_note(&note(0), false).unwrap());
    let mut ring = Keyring::new();
    ring.add(Box::new(verifier())).unwrap();
    ring.add(Box::new(key_b())).unwrap();
    let mut rx = Receiver::new(Some("ugv-01".into()));
    let b1 = r.export_pending(None).unwrap().unwrap();
    assert!(rx.accept(&b1, &ring).is_intact());
    r.mark_exported(&b1).unwrap();
    r.rotate_key(Box::new(key_b()), None, "t").unwrap();
    recorded(r.append_note(&note(1), false).unwrap());
    let b2 = r.export_pending(None).unwrap().unwrap();
    assert!(rx.accept(&b2, &ring).is_intact());
    r.mark_exported(&b2).unwrap();
    assert_eq!(rx.signing_key().unwrap().key_id, "unit-key-2");
    let saved_state = rx.state().unwrap().clone();
    let saved_key = rx.signing_key().cloned();
    recorded(r.append_note(&note(2), false).unwrap());
    recorded(r.append_note(&note(3), false).unwrap());
    let b3 = r.export_pending(None).unwrap().unwrap();
    assert!(!b3
        .records()
        .iter()
        .any(|x| matches!(x.kind, RecordKind::KeyRotation | RecordKind::SegmentStart)));
    let rep = rx.accept(&b3, &ring);
    assert!(rep.is_intact() && rep.is_clean(), "{}", dump(&rep));
    // A receiver restored without the key cannot tell which key signs b3.
    let mut blind = Receiver::with_state(Some("ugv-01".into()), saved_state.clone());
    assert!(!blind.accept(&b3, &ring).is_intact());
    let mut restored = Receiver::with_state_and_key(Some("ugv-01".into()), saved_state, saved_key);
    assert!(restored.accept(&b3, &ring).is_intact());
}
