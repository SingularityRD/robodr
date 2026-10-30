//! Unit enrolment with TPM credential activation (`docs/SECURE-DELIVERY.md`
//! §8, Sprint 14a; closes the 13c gap "rewrap trusts any unit record",
//! §7.9 item 12).
//!
//! ```text
//! depot                                         unit (robodr-seal enrol-request / enrol-activate)
//!  enrol begin  → nonce N ─────────────────────►
//!                ◄──── request: record, EK public + certificate, AK public,
//!                      UWK and UIK public areas each certified by the AK
//!                      (TPM2_Certify), signed PCR policy + quote(N)
//!  verify (this module + EK chain) ;
//!  TPM2_MakeCredential(EK, name(AK), secret S)
//!                ─── challenge ───────────────►  TPM2_ActivateCredential(AK, EK) → S
//!                ◄──── response S
//!  S matches → activated; two operators approve → enrolled
//! ```
//!
//! Why it holds (T4 / T5: "a depot cannot be tricked into wrapping keys
//! for a software-emulated TPM", §7.1):
//!
//! * the EK certificate chains to a TPM vendor CA the site's trust file
//!   lists (checked by the depot), and the EK public area is the
//!   certificate's key;
//! * `ActivateCredential` returns `S` only inside the TPM holding that EK
//!   and only for a loaded object whose name is the AK's name; the name
//!   covers the AK's attributes, so the AK is a restricted signing key
//!   created in that TPM ([`crate::attest::check_ak`]);
//! * a restricted AK signs only TPM-generated attestations, so its
//!   `TPM2_Certify` of the UWK and of the UIK says they are loaded in the
//!   same TPM; their names cover their attributes (created inside,
//!   non-exportable) and their authPolicy, which the depot recomputes from
//!   the **site's** policy authority, the erase epoch and (14b) the
//!   site's lease key, never from the record's word;
//! * the quote over the signed policy's PCRs with the depot's nonce shows
//!   the boot measurements now match the signed policy.
//!
//! An AK of another TPM fails activation; a key created outside a TPM, or
//! imported, fails the attribute check; a software "TPM" has no EK
//! certificate from a listed vendor CA.

use crate::attest::{self, Public, UIK_ATTRS, UWK_ATTRS};
use crate::policy::{self, PcrValue};
use crate::unit::{Mode, UnitRecord};
use crate::{invalid, unauthentic, SealError};
use serde::{Deserialize, Serialize};

pub const REQUEST_FORMAT: &str = "robodr-enrol-request/1";
pub const CHALLENGE_FORMAT: &str = "robodr-enrol-challenge/1";
pub const RESPONSE_FORMAT: &str = "robodr-enrol-response/1";
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_CHALLENGE_BYTES: usize = 8 * 1024;

/// A signed TPM attestation, hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHex {
    pub attest: String,
    pub sig: String,
}

/// A quote, hex, with the PCR values it covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteHex {
    pub attest: String,
    pub sig: String,
    pub pcrs: Vec<PcrValue>,
}

/// TPM evidence of a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmEvidence {
    /// `TPM2B_PUBLIC` of the EK (RSA 2048).
    pub ek_public: String,
    /// DER EK certificate from the TPM's NV (`null`: none stored).
    pub ek_certificate: Option<String>,
    pub ak_public: String,
    pub uwk_public_area: String,
    pub uwk_certify: SignedHex,
    pub uik_public_area: String,
    pub uik_certify: SignedHex,
    /// The signed PCR policy in force (`policy.json` bytes, hex).
    pub policy: String,
    pub quote: QuoteHex,
}

/// The enrolment request (`robodr-enrol-request/1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolRequest {
    pub format: String,
    pub unit: String,
    pub platform: String,
    /// The depot's nonce (64 hex).
    pub nonce: String,
    pub record: UnitRecord,
    /// SEC1 P-256 public key of the unit identity key (TLS, reports).
    pub identity_public: String,
    /// `null` for a unit without a TPM (unattested).
    pub tpm: Option<TpmEvidence>,
}

/// The depot's credential challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolChallenge {
    pub format: String,
    pub unit: String,
    pub nonce: String,
    /// `tpm2_makecredential` output, hex.
    pub credential: String,
}

/// The unit's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolResponse {
    pub format: String,
    pub unit: String,
    pub nonce: String,
    pub secret: String,
}

fn hexb(s: &str, max: usize, what: &str) -> Result<Vec<u8>, SealError> {
    if s.len() > 2 * max {
        return Err(invalid(format!("{what}: too long")));
    }
    crate::from_hex(s).ok_or_else(|| invalid(format!("{what}: not lower-case hex")))
}

fn parse_json<T: serde::de::DeserializeOwned>(
    b: &[u8],
    max: usize,
    what: &str,
) -> Result<T, SealError> {
    if b.len() > max {
        return Err(invalid(format!("{what}: too large")));
    }
    serde_json::from_slice(b).map_err(|e| {
        invalid(format!(
            "{what}: {}",
            robodr_pkg::common::trunc(&e.to_string())
        ))
    })
}

pub fn parse_request(b: &[u8]) -> Result<EnrolRequest, SealError> {
    let r: EnrolRequest = parse_json(b, MAX_REQUEST_BYTES, "enrolment request")?;
    if r.format != REQUEST_FORMAT
        || !robodr_pkg::common::is_label(&r.unit)
        || !robodr_pkg::common::is_label(&r.platform)
        || !robodr_pkg::common::is_hex64(&r.nonce)
    {
        return Err(invalid(
            "enrolment request: format, unit, platform or nonce",
        ));
    }
    // The record as the depot will store it, checked like the unit's own.
    let rb = serde_json::to_vec(&r.record).map_err(|e| invalid(e.to_string()))?;
    UnitRecord::parse(&rb)?;
    if r.record.unit != r.unit || r.record.platform != r.platform {
        return Err(invalid(
            "enrolment request: record of another unit or platform",
        ));
    }
    Ok(r)
}

pub fn parse_challenge(b: &[u8]) -> Result<EnrolChallenge, SealError> {
    let c: EnrolChallenge = parse_json(b, MAX_CHALLENGE_BYTES, "enrolment challenge")?;
    if c.format != CHALLENGE_FORMAT
        || !robodr_pkg::common::is_label(&c.unit)
        || !robodr_pkg::common::is_hex64(&c.nonce)
    {
        return Err(invalid("enrolment challenge: format, unit or nonce"));
    }
    hexb(&c.credential, 2048, "credential")?;
    Ok(c)
}

pub fn parse_response(b: &[u8]) -> Result<EnrolResponse, SealError> {
    let c: EnrolResponse = parse_json(b, MAX_CHALLENGE_BYTES, "enrolment response")?;
    if c.format != RESPONSE_FORMAT
        || !robodr_pkg::common::is_label(&c.unit)
        || !robodr_pkg::common::is_hex64(&c.nonce)
    {
        return Err(invalid("enrolment response: format, unit or nonce"));
    }
    hexb(&c.secret, 64, "secret")?;
    Ok(c)
}

/// What the site expects of every unit (the depot's configuration and
/// trust, never the request).
#[derive(Debug, Clone)]
pub struct Expect<'a> {
    /// The site's policy authority (SEC1 P-256).
    pub authority: &'a [u8; 65],
    /// The site's lease key (SEC1 P-256), if units must be lease-gated.
    pub lease_key: Option<&'a [u8; 65]>,
    /// The nonce the depot issued for this unit.
    pub nonce: &'a [u8; 32],
}

/// A request whose TPM evidence verified (EK certificate chain and
/// credential activation are the depot's).
#[derive(Debug, Clone)]
pub struct Checked {
    pub request: EnrolRequest,
    pub ek: Option<Public>,
    pub ek_certificate: Option<Vec<u8>>,
    pub ak_name: Option<[u8; 34]>,
    pub identity: [u8; 65],
    /// The PCR values the quote covered (they match the signed policy).
    pub pcrs: Vec<(u8, [u8; 32])>,
    pub policy_version: Option<u32>,
    /// The TPM's time `(reset count, clock)` in the enrolment quote (fresh:
    /// it carries the depot's nonce; signed by the AK). The depot accepts
    /// only later reports from this enrolment on (no replay of reports the
    /// unit signed before it).
    pub tpm_time: Option<(u32, u64)>,
}

/// Verify everything in a request that needs no TPM and no CA: see the
/// module docs. A unit without a TPM yields an unattested result (the
/// depot decides whether it accepts one).
pub fn verify_request(r: &EnrolRequest, x: &Expect<'_>) -> Result<Checked, SealError> {
    let nonce = crate::from_hex(&r.nonce).ok_or_else(|| invalid("nonce"))?;
    if !crate::ct_eq(&nonce, x.nonce) {
        return Err(unauthentic(
            "enrolment request: not for this challenge (nonce)",
        ));
    }
    let identity: [u8; 65] = hexb(&r.identity_public, 65, "identity_public")?
        .try_into()
        .map_err(|_| invalid("identity_public: 65 bytes"))?;
    crate::wrap::Recipient::p256(&identity)?;
    let Some(t) = &r.tpm else {
        if r.record.mode != Mode::Fallback {
            return Err(invalid(
                "enrolment request: a TPM unit without TPM evidence",
            ));
        }
        return Ok(Checked {
            request: r.clone(),
            ek: None,
            ek_certificate: None,
            ak_name: None,
            identity,
            pcrs: Vec::new(),
            policy_version: None,
            tpm_time: None,
        });
    };
    let rec = r
        .record
        .tpm
        .as_ref()
        .filter(|_| r.record.mode == Mode::Tpm)
        .ok_or_else(|| invalid("enrolment request: TPM evidence for a unit without a TPM"))?;
    let ek = attest::parse_tpm2b_public(&hexb(&t.ek_public, 1024, "ek_public")?)?;
    if ek.type_alg != attest::TPM_ALG_RSA
        || ek.attributes & attest::attr::RESIDENT != attest::attr::RESIDENT
        || ek.attributes & attest::attr::RESTRICTED == 0
        || ek.attributes & attest::attr::DECRYPT == 0
    {
        return Err(unauthentic("EK: not a restricted RSA storage key of a TPM"));
    }
    let ak_pub = attest::parse_tpm2b_public(&hexb(&t.ak_public, 1024, "ak_public")?)?;
    let ak = attest::check_ak(&ak_pub)?;
    let sh = |s: &SignedHex, w: &str| -> Result<(Vec<u8>, Vec<u8>), SealError> {
        Ok((hexb(&s.attest, 1024, w)?, hexb(&s.sig, 80, w)?))
    };
    // UWK: certified, created in the TPM, the record's key, the site's policy.
    let uwk = attest::parse_tpm2b_public(&hexb(&t.uwk_public_area, 1024, "uwk_public_area")?)?;
    let (a, s) = sh(&t.uwk_certify, "uwk_certify")?;
    attest::verify_certified(&ak, &uwk, UWK_ATTRS, &a, &s)?;
    if uwk.scheme != attest::TPM_ALG_ECDH {
        return Err(unauthentic("UWK: not an ECDH key"));
    }
    if crate::to_hex(&uwk.p256()?) != r.record.uwk_public {
        return Err(unauthentic(
            "the certified UWK is not the record's uwk_public",
        ));
    }
    let authority_name = policy::external_p256_name(x.authority);
    if rec.policy_authority != crate::to_hex(x.authority)
        || rec.policy_authority_name != crate::to_hex(&authority_name)
    {
        return Err(unauthentic(
            "the record names another policy authority than the site's",
        ));
    }
    let epoch_nv = crate::unit::parse_handle(&rec.epoch_nv, 0x01)?;
    let floor_nv = crate::unit::parse_handle(&rec.floor_nv, 0x01)?;
    let expected = match x.lease_key {
        Some(lk) => {
            let ln = policy::external_p256_name(lk);
            if rec.lease_key.as_deref() != Some(crate::to_hex(lk).as_str())
                || rec.lease_key_name.as_deref() != Some(crate::to_hex(&ln).as_str())
            {
                return Err(unauthentic(
                    "the site requires a lease-gated UWK bound to its lease key; this unit's is not",
                ));
            }
            policy::uwk_auth_policy_lease(&ln, &r.unit, epoch_nv, rec.epoch)
        }
        None => {
            if rec.lease_key.is_some() {
                return Err(unauthentic(
                    "the UWK names a lease key the site does not use",
                ));
            }
            policy::uwk_auth_policy(&authority_name, &r.platform, epoch_nv, rec.epoch)
        }
    };
    if uwk.auth_policy != expected || rec.auth_policy != crate::to_hex(&expected) {
        return Err(unauthentic(
            "the certified UWK's authPolicy is not the site's (authority, platform, erase epoch, \
             lease)",
        ));
    }
    // UIK: certified, created in the TPM, the identity key presented.
    let uik = attest::parse_tpm2b_public(&hexb(&t.uik_public_area, 1024, "uik_public_area")?)?;
    let (a, s) = sh(&t.uik_certify, "uik_certify")?;
    attest::verify_certified(&ak, &uik, UIK_ATTRS, &a, &s)?;
    if uik.scheme != attest::TPM_ALG_ECDSA || uik.scheme_hash != attest::TPM_ALG_SHA256 {
        return Err(unauthentic("UIK: not ECDSA with SHA-256"));
    }
    if uik.p256()? != identity {
        return Err(unauthentic("the certified UIK is not identity_public"));
    }
    // Boot measurements now match the signed policy, fresh for this nonce.
    let pol_bytes = hexb(&t.policy, policy::MAX_POLICY_BYTES, "policy")?;
    let pol = policy::verify(&pol_bytes, x.authority, &r.platform, floor_nv)?;
    let pcrs: Vec<(u8, [u8; 32])> = t
        .quote
        .pcrs
        .iter()
        .map(|p| {
            let v = hexb(&p.value, 32, "pcr value")?;
            let a: [u8; 32] = v.try_into().map_err(|_| invalid("pcr value: 32 bytes"))?;
            Ok((p.index, a))
        })
        .collect::<Result<_, SealError>>()?;
    let qa = hexb(&t.quote.attest, 1024, "quote")?;
    let qs = hexb(&t.quote.sig, 80, "quote")?;
    let quoted = attest::verify_quote(&ak, &qa, &qs, x.nonce, &pcrs)?;
    let want = pol.pcrs.clone();
    if pcrs != want {
        return Err(SealError::new(
            crate::ErrorKind::PolicyRefused,
            "the quoted boot measurements do not match the unit's signed policy (Deviation)",
        ));
    }
    let ek_certificate = match &t.ek_certificate {
        Some(c) => Some(hexb(c, 4096, "ek_certificate")?),
        None => None,
    };
    Ok(Checked {
        request: r.clone(),
        ek: Some(ek),
        ek_certificate,
        ak_name: Some(ak_pub.name()),
        identity,
        pcrs,
        policy_version: Some(pol.doc.version),
        tpm_time: Some((quoted.reset_count, quoted.clock)),
    })
}
