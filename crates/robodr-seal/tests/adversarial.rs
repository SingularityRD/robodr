//! Adversarial tests of sealing against a real software TPM
//! (`ROBODR_SWTPM=1`): policy rollback to an older signed policy, a wrong
//! unit's key, tampered and misdirected wraps, a foreign policy authority,
//! owner-authorization protection of the floor. Chunk reordering,
//! truncation, cross-RPK swaps and nonce reuse are in the library's unit
//! tests (`src/chunk.rs`, `src/rpk.rs`); Tang unreachable is in
//! `exit_criteria.rs`.

mod common;

use common::*;
use robodr_seal::keys::PolicyKey;
use robodr_seal::policy;
use robodr_seal::tpm::{DEFAULT_EPOCH_NV, DEFAULT_FLOOR_NV};
use robodr_seal::unit::Unit;
use robodr_seal::wrap::{self, WrapContext, X25519Secret};
use robodr_seal::ErrorKind;

const PLATFORM: &str = "ugv-x1";
const PCRS: [u8; 2] = [0, 7];

fn ctx(unit: &str) -> WrapContext {
    WrapContext::Unit {
        unit: unit.into(),
        rpk_digest: "ab".repeat(32),
    }
}

struct Fx {
    sw: SwTpm,
    dir: Tmp,
    authority: PolicyKey,
    unit: Unit,
}

fn fx(name: &str) -> Fx {
    let dir = tmp(name);
    let sw = SwTpm::start(&dir.join("swtpm"));
    sw.tpm().provision(None).unwrap();
    let authority = PolicyKey::generate().unwrap();
    let unit = Unit::enroll_tpm(
        &dir.join("seal"),
        "ugv-07",
        PLATFORM,
        &authority.public(),
        sw.tpm(),
    )
    .unwrap();
    let p = policy::sign(&authority, PLATFORM, 1, &sw.pcrs(&PCRS), DEFAULT_FLOOR_NV).unwrap();
    unit.install_policy(&p).unwrap();
    Fx {
        sw,
        dir,
        authority,
        unit,
    }
}

/// A boot-chain update: firmware measured differently (PCR 7), the
/// authority signs v2 for it, the unit commits v2 (revoking v1). Rolling
/// the boot chain back to the old, still validly signed state (v1's PCR
/// values) must not unseal: install refuses v1, and v1 written in place
/// anyway is refused by the TPM at the floor check.
#[test]
fn policy_rollback_to_an_older_signed_policy_is_refused() {
    if !swtpm_enabled("policy_rollback") {
        return;
    }
    let mut f = fx("policy-rollback");
    let w = wrap::wrap(
        &f.unit.record().recipient().unwrap(),
        &[1u8; 32],
        &ctx("ugv-07"),
    )
    .unwrap();
    f.unit.unwrap(&w, &ctx("ugv-07")).unwrap();
    let v1 = std::fs::read(f.dir.join("seal/policy.json")).unwrap();
    // The update: new measurements, new signed policy v2.
    f.sw.extend(7, [0x42; 32]);
    assert_eq!(
        f.unit.unwrap(&w, &ctx("ugv-07")).unwrap_err().kind,
        ErrorKind::PolicyRefused
    );
    let v2 = policy::sign(
        &f.authority,
        PLATFORM,
        2,
        &f.sw.pcrs(&PCRS),
        DEFAULT_FLOOR_NV,
    )
    .unwrap();
    f.unit.install_policy(&v2).unwrap();
    f.unit.unwrap(&w, &ctx("ugv-07")).unwrap();
    // A commit is refused while the policy in force does not unseal: a
    // v3 for wrong values must never revoke v2.
    let wrong = vec![(0u8, [9u8; 32]), (7u8, [9u8; 32])];
    let v3 = policy::sign(&f.authority, PLATFORM, 3, &wrong, DEFAULT_FLOOR_NV).unwrap();
    f.unit.install_policy(&v3).unwrap();
    assert!(f.unit.commit_policy().is_err());
    assert_eq!(f.sw.tpm().floor_bits().unwrap(), 0, "nothing revoked");
    f.unit.install_policy(&v2).unwrap();
    assert_eq!(f.unit.commit_policy().unwrap(), 2);
    assert_eq!(f.sw.tpm().floor_bits().unwrap(), 0b11, "v0 and v1 revoked");
    // Roll the boot chain back (power cycle: PCR 7 is the old value again,
    // which v1 matches and v2 does not).
    f.sw.restart();
    let e = f.unit.install_policy(&v1).unwrap_err();
    assert_eq!(e.kind, ErrorKind::PolicyRefused, "{e}");
    std::fs::write(f.dir.join("seal/policy.json"), &v1).unwrap();
    let e = f.unit.unwrap(&w, &ctx("ugv-07")).unwrap_err();
    assert_eq!(e.kind, ErrorKind::PolicyRefused, "{e}");
    assert!(e.detail.contains("revoked"), "the TPM's floor check: {e}");
    // v2 does not match the rolled-back measurements either.
    f.unit.install_policy(&v2).unwrap();
    assert_eq!(
        f.unit.unwrap(&w, &ctx("ugv-07")).unwrap_err().kind,
        ErrorKind::PolicyRefused
    );
}

/// With an owner authorization set (provisioning, OPERATIONS), nobody on
/// the unit can undefine the floor (which would clear its bits and revive
/// revoked policies) or the epoch.
#[test]
fn the_floor_and_epoch_cannot_be_undefined_without_owner_authorization() {
    if !swtpm_enabled("owner_auth") {
        return;
    }
    let f = fx("owner-auth");
    let o = f.sw.tool(
        "tpm2_changeauth",
        &["-c", "o", "file:-"],
        Some(b"site-owner-secret"),
    );
    assert!(o.ok(), "{}", o.error_line());
    for idx in [DEFAULT_FLOOR_NV, DEFAULT_EPOCH_NV] {
        let i = format!("0x{idx:08x}");
        let o = f.sw.tool("tpm2_nvundefine", &[&i, "-C", "o"], None);
        assert!(!o.ok(), "undefined {i} without owner auth");
    }
    // Provisioning again with the authorization is idempotent.
    let p = f.sw.tpm().provision(Some(b"site-owner-secret")).unwrap();
    assert_eq!(p, Default::default());
}

/// Two units (two UWKs, here in the same TPM): a wrap made for one is
/// useless to the other, whatever it is labelled.
#[test]
fn a_wrap_for_another_unit_is_refused() {
    if !swtpm_enabled("wrong_unit") {
        return;
    }
    let f = fx("wrong-unit");
    let other = Unit::enroll_tpm(
        &f.dir.join("seal-08"),
        "ugv-08",
        PLATFORM,
        &f.authority.public(),
        f.sw.tpm(),
    )
    .unwrap();
    let p = policy::sign(
        &f.authority,
        PLATFORM,
        1,
        &f.sw.pcrs(&PCRS),
        DEFAULT_FLOOR_NV,
    )
    .unwrap();
    other.install_policy(&p).unwrap();
    let depot = X25519Secret::generate().unwrap();
    let (_, m, digest) = sealed_rpk(
        &f.dir.join("rel"),
        "nav-model",
        PLATFORM,
        &[("a.bin", b"x".repeat(10))],
        &[depot.public()],
    );
    let wk7 = robodr_seal::rpk::rewrap_for_unit(&depot, &m, &digest, f.unit.record()).unwrap();
    let w7 = robodr_seal::from_hex(&wk7.wrap).unwrap();
    let seal = m.seal.as_ref().unwrap();
    f.unit.unwrap_content_key(&w7, &digest, seal).unwrap();
    // ugv-08 with ugv-07's wrap (a media pack moved to another unit).
    let e = other.unwrap_content_key(&w7, &digest, seal).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unauthentic, "{e}");
    // ugv-07's wrap for another RPK digest.
    assert_eq!(
        f.unit
            .unwrap_content_key(&w7, &"cd".repeat(32), seal)
            .unwrap_err()
            .kind,
        ErrorKind::Unauthentic
    );
    // A wrap of another RPK's key presented for this one: the key
    // commitment refuses it before any chunk is opened.
    let (_, m2, d2) = sealed_rpk(
        &f.dir.join("rel2"),
        "nav-model",
        PLATFORM,
        &[("a.bin", b"y".repeat(10))],
        &[depot.public()],
    );
    let wk_other = robodr_seal::rpk::rewrap_for_unit(&depot, &m2, &d2, f.unit.record()).unwrap();
    let mut forged = wk_other.clone();
    forged.rpk_digest = digest.clone();
    // Re-wrapped by the depot under the right label, but it is the other
    // RPK's key (a depot bug or a malicious depot): commitment mismatch.
    let k2 = f
        .unit
        .unwrap_content_key(
            &robodr_seal::from_hex(&wk_other.wrap).unwrap(),
            &d2,
            m2.seal.as_ref().unwrap(),
        )
        .unwrap();
    let relabel = wrap::wrap(
        &f.unit.record().recipient().unwrap(),
        k2.expose(),
        &WrapContext::Unit {
            unit: "ugv-07".into(),
            rpk_digest: digest.clone(),
        },
    )
    .unwrap();
    let e = f
        .unit
        .unwrap_content_key(&relabel, &digest, seal)
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unauthentic);
    assert!(e.detail.contains("commitment"), "{e}");
}

#[test]
fn tampered_wraps_are_refused() {
    if !swtpm_enabled("tampered_wraps") {
        return;
    }
    let f = fx("tampered-wraps");
    let r = f.unit.record().recipient().unwrap();
    let w = wrap::wrap(&r, &[5u8; 32], &ctx("ugv-07")).unwrap();
    // Every region: algorithm byte, ephemeral point, nonce, ciphertext,
    // tag. (Not every byte: each try is a TPM round trip.)
    for i in [0usize, 1, 2, 40, 65, 66, 70, 89, 90, 100, 120, 137] {
        let mut t = w.clone();
        t[i] ^= 0x01;
        let e = f.unit.unwrap(&t, &ctx("ugv-07")).unwrap_err();
        assert!(
            matches!(
                e.kind,
                ErrorKind::Unauthentic | ErrorKind::Invalid | ErrorKind::PolicyRefused
            ),
            "byte {i}: {e}"
        );
    }
    for n in [0usize, 1, 66, 137] {
        assert!(f.unit.unwrap(&w[..n], &ctx("ugv-07")).is_err());
    }
    // An X25519 wrap (a fallback unit's) never reaches the TPM.
    let x = X25519Secret::generate().unwrap();
    let wx = wrap::wrap(
        &wrap::Recipient::X25519(x.public()),
        &[5u8; 32],
        &ctx("ugv-07"),
    )
    .unwrap();
    assert_eq!(
        f.unit.unwrap(&wx, &ctx("ugv-07")).unwrap_err().kind,
        ErrorKind::Unauthentic
    );
    // Still fine untampered.
    assert_eq!(*f.unit.unwrap(&w, &ctx("ugv-07")).unwrap(), [5u8; 32]);
}

/// The TPM itself refuses a policy signed by another key, even when the
/// unit's own check is bypassed.
#[test]
fn the_tpm_refuses_a_foreign_authority() {
    if !swtpm_enabled("foreign_authority") {
        return;
    }
    let f = fx("foreign-authority");
    let rogue = PolicyKey::generate().unwrap();
    let forged = policy::sign(&rogue, PLATFORM, 1, &f.sw.pcrs(&PCRS), DEFAULT_FLOOR_NV).unwrap();
    let pol = policy::parse(&forged).unwrap();
    let t = f.unit.record().tpm.clone().unwrap();
    let authority: [u8; 65] = robodr_seal::from_hex(&t.policy_authority)
        .unwrap()
        .try_into()
        .unwrap();
    let name = robodr_seal::from_hex(&t.policy_authority_name).unwrap();
    let seal = f.dir.join("seal");
    let pu = std::fs::read(seal.join("uwk.pub")).unwrap();
    let pr = std::fs::read(seal.join("uwk.priv")).unwrap();
    let tpm = f.sw.tpm();
    let w = robodr_seal::tpm::WorkDir::new(&f.dir).unwrap();
    let eph = wrap::p256_public_bytes(&wrap::p256_random().unwrap().public_key());
    let e = tpm
        .ecdh(&w, &pu, &pr, &pol, &authority, &name, t.epoch, &eph)
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::PolicyRefused, "{e}");
    // With the rogue key presented as the authority, its TPM name differs
    // from the enrolled one.
    let rname = tpm.external_key_name(&w, &rogue.public()).unwrap();
    assert_ne!(rname, name);
    let e = tpm
        .ecdh(&w, &pu, &pr, &pol, &rogue.public(), &name, t.epoch, &eph)
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::PolicyRefused, "{e}");
    // And a valid policy for another platform is refused at install.
    let other = policy::sign(
        &f.authority,
        "arm-x2",
        1,
        &f.sw.pcrs(&PCRS),
        DEFAULT_FLOOR_NV,
    )
    .unwrap();
    assert!(f.unit.install_policy(&other).is_err());
}

/// A unit that was never given a policy, or whose TPM is not configured,
/// fails closed.
#[test]
fn missing_policy_or_tpm_fails_closed() {
    if !swtpm_enabled("fail_closed") {
        return;
    }
    let f = fx("fail-closed");
    let seal = f.dir.join("seal");
    let w = wrap::wrap(
        &f.unit.record().recipient().unwrap(),
        &[5u8; 32],
        &ctx("ugv-07"),
    )
    .unwrap();
    std::fs::remove_file(seal.join("policy.json")).unwrap();
    assert_eq!(
        f.unit.unwrap(&w, &ctx("ugv-07")).unwrap_err().kind,
        ErrorKind::PolicyRefused
    );
    assert!(Unit::open(&seal, None).is_err());
    // Another handle configuration than enrolled is refused.
    let mut cfg = f.sw.cfg();
    cfg.epoch_nv = 0x0150_0050;
    let t = robodr_seal::tpm::Tpm::new(cfg, Box::new(robodr_seal::cmd::System)).unwrap();
    assert!(Unit::open(&seal, Some(t)).is_err());
}
