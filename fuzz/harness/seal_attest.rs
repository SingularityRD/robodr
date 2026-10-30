//! Harness: the TPM structures a depot checks at enrolment
//! (`robodr_seal::attest`), the enrolment request (`robodr_seal::enrol`),
//! the site lease (`robodr_seal::lease`) and the unit report
//! (`robodr_seal::report`), Sprints 14a / 14b.
//!
//! Input: a selector byte, then the document. `0`: a `TPM2B_PUBLIC`;
//! `1`: a `TPMS_ATTEST`; `2`: an enrolment request (verified against the
//! harness authority and nonce); `3`: a lease (verified against the harness
//! lease key); `4`: a signed unit report (verified against the harness
//! identity key). Invariants beyond "no panic":
//!
//! * a public area that parses is SHA-256-named, its name is a pure
//!   function of its bytes, and an ECC key is a point on P-256;
//! * an attestation that parses carries the TPM-generated magic (parsing
//!   refuses anything else);
//! * an enrolment request without TPM evidence never verifies for a TPM
//!   record; a request never verifies for another nonce;
//! * a lease that verifies is for the harness unit; one past its clock or
//!   reset budget is `LeaseExpired`;
//! * a report that verifies parses to the same body as unverified.
//!
//! Shared via `#[path]` with `crates/robodr-seal/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_seal::keys::PolicyKey;
use robodr_seal::{attest, enrol, lease, report};

pub const UNIT: &str = "ugv-07";
pub const PLATFORM: &str = "ugv-x1";
pub const NONCE: [u8; 32] = [3u8; 32];
/// A UWK public area and the AK's certification of it, from swtpm 0.7.
pub const UWK_PUB: &str = "00780023000b000204320020000000000000000000000000000000000000000000000000000000000000000000100019000b00030010002078e908548d94c5488258a608d4ce13bd944554070da8c294527ed532322b32380020a1bb4ce051b520e20bf4876cb2913843dee4f3a20ba2f38c20243e10dce8c8c7";
pub const ATTEST: &str = "ff54434780170022000b986fb1d653125d0373c0b28219c9d87d14f23dd77c74f0ea98d130c4246fdeef000400ff55aa000000000000c90000000002000000000120191023001636360022000b21175b15fcdfcde82249d5eacebbc5676b6de3caf93f26673e8aa376f7f6eff10022000b6e5f93f5bae4be2698e6dd0aac53c25d5c7ddde9122448018c8314f36d3165e0";

pub fn authority() -> PolicyKey {
    PolicyKey::from_bytes(&[7u8; 32]).expect("valid scalar")
}

pub fn lease_key() -> PolicyKey {
    PolicyKey::from_bytes(&[11u8; 32]).expect("valid scalar")
}

pub fn identity() -> PolicyKey {
    PolicyKey::from_bytes(&[13u8; 32]).expect("valid scalar")
}

pub fn run(data: &[u8]) {
    let Some((&sel, doc)) = data.split_first() else {
        return;
    };
    match sel % 5 {
        0 => {
            if let Ok(p) = attest::parse_tpm2b_public(doc) {
                assert_eq!(p.name_alg, attest::TPM_ALG_SHA256);
                assert_eq!(
                    p.name(),
                    attest::parse_tpm2b_public(doc).expect("again").name()
                );
                if let attest::PublicKey::EccP256(pt) = p.key {
                    assert!(p256::PublicKey::from_sec1_bytes(&pt).is_ok());
                }
            }
        }
        1 => {
            if let Ok(a) = attest::parse_attest(doc) {
                assert!(a.extra_data.len() <= 64 && a.qualified_signer.len() <= 66);
            }
        }
        2 => {
            if let Ok(r) = enrol::parse_request(doc) {
                let auth = authority().public();
                let x = enrol::Expect {
                    authority: &auth,
                    lease_key: None,
                    nonce: &NONCE,
                };
                if let Ok(c) = enrol::verify_request(&r, &x) {
                    assert_eq!(c.request.nonce, robodr_seal::to_hex(&NONCE));
                    assert!(c.ek.is_some() == (r.record.mode == robodr_seal::unit::Mode::Tpm));
                }
                let other = [4u8; 32];
                let y = enrol::Expect { nonce: &other, ..x };
                assert!(enrol::verify_request(&r, &y).is_err());
            }
        }
        3 => {
            if let Ok(l) = lease::Lease::parse(doc) {
                let name = robodr_seal::policy::external_p256_name(&authority().public());
                if l.verify(&lease_key().public(), UNIT, &name, PLATFORM)
                    .is_ok()
                {
                    assert_eq!(l.unit, UNIT);
                    let late = lease::TpmTime {
                        clock: l.clock_before,
                        reset_count: 0,
                        restart_count: 0,
                        safe: true,
                    };
                    assert_eq!(
                        l.check_now(&late).unwrap_err().kind,
                        robodr_seal::ErrorKind::LeaseExpired
                    );
                }
            }
        }
        _ => {
            if let Ok(r) = report::verify(doc, &identity().public()) {
                assert_eq!(report::parse_unverified(doc).expect("parses").0, r);
            }
        }
    }
}

/// Seeds: the swtpm public area and attestation, a fallback enrolment
/// request, a lease and a signed report.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let hex = |s: &str| robodr_seal::from_hex(s).expect("hex");
    let with = |sel: u8, b: Vec<u8>| [vec![sel], b].concat();
    let name = robodr_seal::policy::external_p256_name(&authority().public());
    let l = lease::issue(
        &lease::LeaseGrant {
            site: "site-f",
            unit: UNIT,
            platform: PLATFORM,
            authority_name: &name,
            lease_seq: 1,
            issued_at: 1_790_000_000,
            now: lease::TpmTime {
                clock: 1000,
                reset_count: 2,
                restart_count: 0,
                safe: true,
            },
            lifetime_ms: 3_600_000,
            reboots: 2,
        },
        &lease_key(),
    )
    .expect("lease");
    let r = report::UnitReport {
        format: report::REPORT_FORMAT.into(),
        site: "site-f".into(),
        unit: UNIT.into(),
        reported_at: 1_790_000_000,
        tpm_resets: 2,
        tpm_clock: 5000,
        deployment_id: Some("dep-0001".into()),
        deployment_seq: 1,
        deployment_digest: Some("ab".repeat(32)),
        items: vec![report::ReportItem {
            name: "nav".into(),
            serial: 2,
            rpk_digest: "cd".repeat(32),
            status: report::ItemState::Installed,
            deferrals: 0,
        }],
        installed: vec![],
        erased: false,
    };
    let id = identity();
    let signed = r.sign(&|d| id.sign_digest(d)).expect("sign");
    let req = enrol::EnrolRequest {
        format: enrol::REQUEST_FORMAT.into(),
        unit: UNIT.into(),
        platform: PLATFORM.into(),
        nonce: robodr_seal::to_hex(&NONCE),
        record: robodr_seal::unit::UnitRecord {
            format: robodr_seal::unit::UNIT_FORMAT.into(),
            unit: UNIT.into(),
            platform: PLATFORM.into(),
            mode: robodr_seal::unit::Mode::Fallback,
            uwk_public: robodr_seal::to_hex(&[9u8; 32]),
            tpm: None,
            fallback_key: Some("/run/robodr/sealed/.robodr-seal/uwk.key".into()),
        },
        identity_public: robodr_seal::to_hex(&id.public()),
        tpm: None,
    };
    vec![
        ("public.bin", with(0, hex(UWK_PUB))),
        ("attest.bin", with(1, hex(ATTEST))),
        (
            "request.bin",
            with(2, serde_json::to_vec(&req).expect("json")),
        ),
        ("lease.bin", with(3, l.to_bytes().expect("lease bytes"))),
        ("report.bin", with(4, signed)),
    ]
}
