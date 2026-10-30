//! Sealed RPKs from the release tool (Sprint 13c, `docs/SECURE-DELIVERY.md`
//! §7.2): `build rpk --seal-to`, quorum signing and verification of the
//! ciphertext, bundling, and the depot / unit side through `robodr-seal`.

mod common;

use common::*;
use robodr_pkg::rpk::{Kind, CHUNKS_DIR, MANIFEST_FILE};
use robodr_pkg::Code;
use robodr_release::ops::{self, Target};
use robodr_seal::chunk::ContentKey;
use robodr_seal::unit::{Mode, UnitRecord};
use robodr_seal::wrap::{p256_random, P256Secret, Unwrapper, WrapContext, X25519Secret};
use std::path::{Path, PathBuf};

const MARKER: &[u8] = b"ROBODR-TEST-SEALED-MARKER-55e1";
const SBOM: &[u8] = br#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#;

fn model_payload() -> Vec<(&'static str, Vec<u8>)> {
    let mut big = bytes(7, 9 * 1024 * 1024);
    big[8 * 1024 * 1024 + 5..8 * 1024 * 1024 + 5 + MARKER.len()].copy_from_slice(MARKER);
    vec![
        ("model/weights.onnx", big),
        ("model/labels.txt", [b"cat\n".as_slice(), MARKER].concat()),
        ("sbom.cdx.json", SBOM.to_vec()),
    ]
}

fn build_sealed(
    work: &Path,
    depots: &[[u8; 32]],
    kind: Kind,
) -> Result<PathBuf, robodr_release::fsio::Fail> {
    let pl = work.join(format!("payload-{}", depots.len()));
    let _ = std::fs::remove_dir_all(&pl);
    std::fs::create_dir_all(&pl).unwrap();
    let files = model_payload();
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, b)| (*p, b.as_slice())).collect();
    payload(&pl, &refs);
    let mut s = spec("nav-model", 4);
    s.kind = kind;
    s.sbom_path = Some("sbom.cdx.json".into());
    let out = work.join(format!("rpks-{}", depots.len()));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    ops::build_rpk_with(&s, &pl, &out, Some(depots)).map(|b| b.dir)
}

fn unit_record(name: &str, r: &robodr_seal::wrap::Recipient) -> UnitRecord {
    UnitRecord {
        format: robodr_seal::unit::UNIT_FORMAT.into(),
        unit: name.into(),
        platform: "ugv-x1".into(),
        mode: Mode::Tpm,
        uwk_public: robodr_seal::to_hex(r.public_bytes()),
        tpm: None,
        fallback_key: None,
    }
}

#[test]
fn a_sealed_rpk_builds_signs_verifies_and_opens_only_on_its_unit() {
    let t = Tmp::new("sealed-rpk");
    let k = keys();
    let trust = default_trust();
    let depot = X25519Secret::generate().unwrap();
    let depot2 = X25519Secret::generate().unwrap();
    let dir = build_sealed(t.path(), &[depot.public(), depot2.public()], Kind::Model).unwrap();
    for key in [&k.rel[0], &k.rel[1]] {
        ops::sign(&Target::Rpk(dir.clone()), key, Some(&trust), NOW).unwrap();
    }
    let v = ops::verify_rpk_dir(&dir, &trust, NOW).unwrap();
    let m = &v.manifest;
    assert!(m.is_sealed());
    assert_eq!(m.seal.as_ref().unwrap().depot_wraps.len(), 2);
    // The ciphertext on disk: no plaintext marker anywhere; the SBOM is
    // the one clear file.
    for e in std::fs::read_dir(dir.join(CHUNKS_DIR)).unwrap() {
        let b = std::fs::read(e.unwrap().path()).unwrap();
        assert!(!b.windows(MARKER.len()).any(|w| w == MARKER));
    }
    let manifest = std::fs::read(dir.join(MANIFEST_FILE)).unwrap();
    assert!(!manifest.windows(MARKER.len()).any(|w| w == MARKER));
    let sbom = m.sbom_entry().unwrap();
    assert!(!m.is_sealed_file(sbom));
    let sbom_chunk = &m.chunks[sbom.chunks[0] as usize];
    assert_eq!(
        std::fs::read(dir.join(CHUNKS_DIR).join(&sbom_chunk.sha256)).unwrap(),
        SBOM
    );
    // Bundled with parity like any RPK.
    let b = signed_bundle(
        t.path(),
        &trust,
        1,
        None,
        std::slice::from_ref(&dir),
        Some((4, 2, 1 << 20)),
        "bundle",
        &[&k.rel[0], &k.rel[1]],
    );
    assert!(b.join("bundle.json").exists());
    // Depot: re-wrap for unit ugv-07 (either depot can).
    let u7 = P256Secret(p256_random().unwrap());
    let wk = robodr_seal::rpk::rewrap_for_unit(
        &depot2,
        m,
        &v.digest,
        &unit_record("ugv-07", &u7.recipient()),
    )
    .unwrap();
    // Unit: unwrap, check the commitment, open every sealed file.
    let key = robodr_seal::wrap::unwrap(
        &u7,
        &robodr_seal::from_hex(&wk.wrap).unwrap(),
        &WrapContext::Unit {
            unit: "ugv-07".into(),
            rpk_digest: v.digest.clone(),
        },
    )
    .unwrap();
    let ck = ContentKey::from_bytes(&key[..]).unwrap();
    let seal = m.seal.as_ref().unwrap();
    ck.check_commit(
        &robodr_seal::unit::seal_id(seal).unwrap(),
        &robodr_seal::from_hex(&seal.ck_commit).unwrap(),
    )
    .unwrap();
    let want = model_payload();
    for (i, f) in m.content.iter().enumerate() {
        if !m.is_sealed_file(f) {
            continue;
        }
        let mut out = Vec::new();
        robodr_seal::rpk::open_file(
            &ck,
            m,
            i,
            &mut |c| Ok(std::fs::read(dir.join(CHUNKS_DIR).join(&c.sha256)).unwrap()),
            &mut |p| {
                out.extend_from_slice(p);
                Ok(())
            },
        )
        .unwrap();
        let w = &want.iter().find(|(p, _)| *p == f.path).unwrap().1;
        assert_eq!(&out, w, "{}", f.path);
    }
    // Another unit's key cannot open ugv-07's wrap.
    let u8_ = P256Secret(p256_random().unwrap());
    assert!(robodr_seal::wrap::unwrap(
        &u8_,
        &robodr_seal::from_hex(&wk.wrap).unwrap(),
        &WrapContext::Unit {
            unit: "ugv-07".into(),
            rpk_digest: v.digest.clone()
        }
    )
    .is_err());
}

#[test]
fn sealed_chunks_are_verified_like_any_chunk() {
    let t = Tmp::new("sealed-tamper");
    let k = keys();
    let trust = default_trust();
    let depot = X25519Secret::generate().unwrap();
    let dir = build_sealed(t.path(), &[depot.public()], Kind::Files).unwrap();
    for key in [&k.rel[0], &k.rel[1]] {
        ops::sign(&Target::Rpk(dir.clone()), key, Some(&trust), NOW).unwrap();
    }
    ops::verify_rpk_dir(&dir, &trust, NOW).unwrap();
    let m =
        robodr_pkg::rpk::parse_manifest(&std::fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap();
    let sealed_chunk = &m.chunks[m
        .content
        .iter()
        .find(|f| m.is_sealed_file(f))
        .unwrap()
        .chunks[0] as usize];
    let p = dir.join(CHUNKS_DIR).join(&sealed_chunk.sha256);
    let orig = std::fs::read(&p).unwrap();
    // A flipped byte (nonce, body or tag).
    for at in [0usize, 30, orig.len() - 1] {
        let mut b = orig.clone();
        b[at] ^= 1;
        std::fs::write(&p, &b).unwrap();
        assert_eq!(
            code(ops::verify_rpk_dir(&dir, &trust, NOW)),
            Code::FileMismatch
        );
    }
    std::fs::write(&p, &orig).unwrap();
    ops::verify_rpk_dir(&dir, &trust, NOW).unwrap();
    // The same place from another sealed build of the same payload (a
    // swap between two sealed copies) has another hash.
    let other = build_sealed(&t.path().join("b"), &[depot.public()], Kind::Files).unwrap();
    let m2 = robodr_pkg::rpk::parse_manifest(&std::fs::read(other.join(MANIFEST_FILE)).unwrap())
        .unwrap();
    let c2 = &m2.chunks[m2
        .content
        .iter()
        .find(|f| m2.is_sealed_file(f))
        .unwrap()
        .chunks[0] as usize];
    assert_ne!(c2.sha256, sealed_chunk.sha256, "fresh key per build");
    std::fs::copy(other.join(CHUNKS_DIR).join(&c2.sha256), &p).unwrap();
    assert_eq!(
        code(ops::verify_rpk_dir(&dir, &trust, NOW)),
        Code::FileMismatch
    );
    // A sealed build of a kind that is not installed into the sealed
    // volume is refused.
    let e = build_sealed(&t.path().join("c"), &[depot.public()], Kind::RobodrRules);
    assert!(e.is_err());
}

#[test]
fn build_rpk_seal_to_through_the_binary() {
    let t = Tmp::new("sealed-cli");
    let d = t.path();
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_robodr-release"))
        .args(["build", "rpk", "--spec"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    robodr_seal::keys::x25519_generate(&d.join("depot.key"), &d.join("depot.key.pub")).unwrap();
    let pl = d.join("payload");
    std::fs::create_dir_all(&pl).unwrap();
    payload(&pl, &[("cfg/mission.yaml", b"route: secret-route-1\n")]);
    let mut s = spec("mission-cfg", 2);
    s.kind = Kind::Config;
    std::fs::write(d.join("spec.json"), serde_json::to_vec(&s).unwrap()).unwrap();
    std::fs::create_dir_all(d.join("out")).unwrap();
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_robodr-release"))
        .args([
            "build",
            "rpk",
            "--spec",
            d.join("spec.json").to_str().unwrap(),
            "--payload",
            pl.to_str().unwrap(),
            "--out-dir",
            d.join("out").to_str().unwrap(),
            "--seal-to",
            d.join("depot.key.pub").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["sealed"], true);
    // A secret key is not a --seal-to public key.
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_robodr-release"))
        .args([
            "build",
            "rpk",
            "--spec",
            d.join("spec.json").to_str().unwrap(),
            "--payload",
            pl.to_str().unwrap(),
            "--out-dir",
            d.join("out2").to_str().unwrap(),
            "--seal-to",
            d.join("depot.key").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
}
