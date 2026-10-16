//! Ed25519 end to end: the packer signs with a unit's secret key, the
//! importer holds only public keys. A key that can verify cannot sign, so
//! the SOC cannot forge a batch.

mod common;

use common::*;
use robodr_blackbox::{
    Ed25519SigningKey, Ed25519VerifyingKey, FsyncPolicy, KeyFile, Recorder, RecorderConfig, Signer,
    SteppingClock, TimeSource,
};
use robodr_diode::manifest::{manifest_signing_message, MANIFEST_FILE, SIGNATURE_FILE};
use robodr_diode::unpack::RECORDS_FILE;
use robodr_diode::{ImportReport, Importer, Keyring, PackConfig, Packer};
use std::fs;
use std::path::Path;

const ED_SEED: [u8; 32] = [0x17; 32];
const ED_KEY_ID: &str = "diode-ugv-007-ed";

fn ed_signer() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(ED_KEY_ID, &ED_SEED).unwrap()
}

/// What the SOC holds: the public half, loaded from a public key file.
fn ed_public() -> Ed25519VerifyingKey {
    let pubfile = KeyFile::ed25519_from_seed(&ED_SEED, Some(ED_KEY_ID))
        .unwrap()
        .to_public()
        .unwrap();
    assert!(pubfile.is_public() && pubfile.secret().is_empty());
    let back = KeyFile::from_json(&pubfile.to_json()).unwrap();
    back.ed25519_verifying_key().unwrap()
}

fn public_ring(unit: &str) -> Keyring {
    let mut k = Keyring::new();
    k.add(unit, Box::new(ed_public())).unwrap();
    k
}

fn ed_packer(site: &Site) -> Packer {
    Packer::open(
        &site.outbox,
        &site.pack_state,
        PackConfig::new(UNIT),
        Box::new(ed_signer()),
    )
    .unwrap()
}

fn codes(r: &ImportReport) -> Vec<String> {
    r.quarantined
        .iter()
        .map(|q| reason_code(&q.reason))
        .collect()
}

/// A black-box bundle recorded with an Ed25519 key.
fn ed_bundle(n: u64, key: Ed25519SigningKey) -> Vec<u8> {
    let d = TempDir::new("edbb");
    let mut cfg = RecorderConfig::new(d.path().join("bb"), UNIT, "boot-a");
    cfg.fsync = FsyncPolicy::SealsOnly;
    let mut r = Recorder::open(
        cfg,
        Box::new(key),
        Box::new(SteppingClock::new(1_000_000, 1_000, TimeSource::Gps)),
    )
    .unwrap();
    for i in 0..n {
        r.append_note(&serde_json::json!({ "i": i }), false)
            .unwrap();
    }
    r.export_pending(None).unwrap().unwrap().to_bytes()
}

#[test]
fn round_trip_with_only_public_keys_on_the_high_side() {
    let site = Site::new("ed-rt");
    let bb_key = Ed25519SigningKey::from_seed("bb-ugv-007-ed", &[0x33; 32]).unwrap();
    let bb_pub = bb_key.verifying_key();
    let bb = ed_bundle(3, bb_key);
    let pubd = ed_packer(&site)
        .pack(&findings(4), std::slice::from_ref(&bb), NOW)
        .unwrap();
    assert_eq!(pubd.len(), 1);
    // The signature file names the algorithm and is a 64-byte Ed25519 sig.
    let sig: serde_json::Value = serde_json::from_slice(
        &fs::read(site.outbox.join(&pubd[0].name).join(SIGNATURE_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(sig["algorithm"], "ed25519");
    assert_eq!(sig["key_id"], ED_KEY_ID);
    assert_eq!(sig["sig"].as_str().unwrap().len(), 128);
    site.transfer_all();

    let mut imp = Importer::open(site.import_cfg(), public_ring(UNIT)).unwrap();
    imp.add_bundle_verifier(Box::new(bb_pub));
    let r = imp.run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.accepted.len(), 1);
    let a = &r.accepted[0];
    assert_eq!((a.findings, a.bundles, a.bundles_verified), (4, 1, 1));
    assert_eq!(read_lines(&a.output.join(RECORDS_FILE)).len(), 4);
}

/// Someone on the high side (or anywhere) tries to forge a batch for the
/// unit. Without the unit's seed every attempt is quarantined.
#[test]
fn soc_cannot_forge_a_batch() {
    let site = Site::new("ed-forge");
    let name = {
        let p = ed_packer(&site).pack(&findings(1), &[], NOW).unwrap();
        p[0].name.clone()
    };
    site.transfer_all();
    let dir = site.inbox().join(&name);

    // 1. Edit the manifest and re-sign with a different Ed25519 key under
    //    the unit's key id: bad signature.
    let mut v: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap();
    v["created_at_ms"] = serde_json::json!(NOW + 1);
    let bytes = serde_json::to_vec_pretty(&v).unwrap();
    let attacker = Ed25519SigningKey::from_seed(ED_KEY_ID, &[0x99; 32]).unwrap();
    write_sig(&dir, &bytes, &attacker);
    let mut imp = Importer::open(site.import_cfg(), public_ring(UNIT)).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["bad_signature"], "{r:?}");
    assert!(r.accepted.is_empty());

    // 2. Downgrade: an HMAC tag under the Ed25519 key id is refused by
    //    algorithm before any MAC is computed.
    site.transfer_all();
    let hmac = robodr_blackbox::HmacSha256Key::new(ED_KEY_ID, &[1; 32]).unwrap();
    write_sig(&dir, &bytes, &hmac);
    let mut imp = Importer::open(site.import_cfg(), public_ring(UNIT)).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["algorithm_mismatch"], "{r:?}");

    // 3. The genuine batch still imports (state was never advanced).
    let _ = fs::remove_dir_all(&dir);
    site.transfer_all();
    let mut imp = Importer::open(site.import_cfg(), public_ring(UNIT)).unwrap();
    let r = imp.run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.accepted.len(), 1);
}

#[test]
fn wrong_unit_or_unknown_public_key_is_quarantined() {
    // The ring maps the key to another unit.
    let site = Site::new("ed-wrong-unit");
    ed_packer(&site).pack(&findings(1), &[], NOW).unwrap();
    site.transfer_all();
    let mut imp = Importer::open(site.import_cfg(), public_ring("ugv-008")).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["unit_key_mismatch"], "{r:?}");

    // The ring holds a different unit's public key only.
    let site = Site::new("ed-unknown");
    ed_packer(&site).pack(&findings(1), &[], NOW).unwrap();
    site.transfer_all();
    let mut ring = Keyring::new();
    let other = Ed25519SigningKey::from_seed("diode-ugv-008-ed", &[0x18; 32]).unwrap();
    ring.add("ugv-008", Box::new(other.verifying_key()))
        .unwrap();
    let mut imp = Importer::open(site.import_cfg(), ring).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["unknown_key"], "{r:?}");

    // Same key id, but the SOC was given the wrong public key.
    let site = Site::new("ed-wrong-pub");
    ed_packer(&site).pack(&findings(1), &[], NOW).unwrap();
    site.transfer_all();
    let mut ring = Keyring::new();
    let wrong = Ed25519SigningKey::from_seed(ED_KEY_ID, &[0x18; 32]).unwrap();
    ring.add(UNIT, Box::new(wrong.verifying_key())).unwrap();
    let mut imp = Importer::open(site.import_cfg(), ring).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["bad_signature"], "{r:?}");
}

#[test]
fn key_rotation_from_hmac_to_ed25519_keeps_the_chain() {
    // Batches 1 (HMAC, legacy) and 2 (Ed25519) of one unit: the packer
    // state chains them; the importer holds the legacy key and the new
    // public key for that unit.
    let site = Site::new("ed-rotate");
    let b1 = site.packer().pack(&findings(1), &[], NOW).unwrap();
    let b2 = ed_packer(&site).pack(&[finding(1)], &[], NOW + 1).unwrap();
    assert_eq!((b1[0].seq, b2[0].seq), (1, 2));
    site.transfer_all();
    let mut ring = keyring();
    ring.add(UNIT, Box::new(ed_public())).unwrap();
    let mut imp = Importer::open(site.import_cfg(), ring).unwrap();
    let r = imp.run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(
        r.accepted.iter().map(|a| a.seq).collect::<Vec<_>>(),
        vec![1, 2]
    );
}

fn write_sig(dir: &Path, bytes: &[u8], key: &dyn Signer) {
    let sig = key.sign(&manifest_signing_message(bytes)).unwrap();
    fs::write(dir.join(MANIFEST_FILE), bytes).unwrap();
    let s = serde_json::json!({
        "format": "robodr-diode/1",
        "algorithm": key.algorithm(),
        "key_id": key.key_id(),
        "sig": robodr_blackbox::crypto::to_hex(&sig),
    });
    fs::write(dir.join(SIGNATURE_FILE), serde_json::to_vec(&s).unwrap()).unwrap();
}
