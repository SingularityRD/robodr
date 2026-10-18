//! Detached per-finding signatures (contract `robot-edr.findings` ≥ 1.2).
//!
//! # Why
//!
//! The validator ([`validate`](mod@crate::validate)) proves a finding is *well formed*: it
//! matches the rule catalog, its tainted fields are neutralised, its ids are
//! derived correctly. It cannot prove *who* produced it. On a connected
//! (non-diode) path anyone who can produce to `robot-edr.findings` can forge a
//! finding that matches the catalog exactly (a fake "all quiet", or a fake
//! alarm naming another robot). This module adds an optional, detached
//! Ed25519 signature made by the robot's finding key, and a verifier that
//! binds that key to the unit the finding names.
//!
//! # Canonical bytes (what is signed)
//!
//! **The signed bytes are the exact UTF-8 bytes of the Kafka record value**,
//! i.e. the output of [`crate::kafka::to_json`] (compact `serde_json` of the
//! validated envelope, field order = struct order) as emitted by the producer.
//! There is no canonicalisation step on either side:
//!
//! * the producer signs the string it puts in the record value;
//! * the consumer verifies over the raw bytes it received, **before** and
//!   independently of parsing; it never re-serialises to verify.
//!
//! Consequently, any hop that re-formats the value (pretty-printing, key
//! reordering, re-escaping, re-serialising a parsed envelope) invalidates the
//! signature. That is intended: forwarders must carry the value verbatim.
//! (Today `to_json(parse(value)) == value` holds for everything the builder
//! emits — tested — but consumers must not rely on it.)
//!
//! The Ed25519 message is domain-separated and length-framed so a finding
//! signature can never be confused with a black-box record signature made by
//! the same key type, nor with a signature under another algorithm or key id:
//!
//! ```text
//! message = "robodr-ocsf/finding-sig/v1" 0x00
//!           u32be(len(alg))    alg      (ASCII, "ed25519")
//!           u32be(len(key_id)) key_id   (ASCII)
//!           u64be(len(value))  value    (the record value bytes, verbatim)
//! ```
//!
//! # Carrier: a Kafka header
//!
//! The signature travels in the record header [`SIG_HEADER`]
//! (`robodr-finding-sig`), never inside the value: an in-value field would
//! make the signed bytes depend on the signature (requiring an
//! exclude-and-re-serialise canonical form, exactly what we avoid), and it
//! keeps the value — and the golden example — byte-identical to 1.1.
//! The header value is compact JSON with exactly three fields, in this order:
//!
//! ```json
//! {"alg":"ed25519","key_id":"ed25519:0123abcd…","sig":"<128 lower-case hex>"}
//! ```
//!
//! # Binding to the unit
//!
//! [`parse_and_validate_signed`] looks the verifier up by the robot id the
//! finding *itself* names (`entity_context.robot.id`, which the validator
//! already ties to `external_id`, `ocsf.device.uid` and the finding id). A key
//! registered for unit B therefore never vouches for a finding that names unit
//! A, and a key that its keyring binds to a device ([`Verifier::key_device`])
//! is refused for any other unit.
//!
//! # Replay
//!
//! A signature proves origin, not freshness: a captured signed record can be
//! re-sent verbatim and will verify again. That is unavoidable for detached
//! signatures and is **the consumer's job**: dedup on [`ReplayKey`]
//! (`robot id`, `event uid` = `ocsf.metadata.uid`, which already hashes finding
//! id + `last_seen_time` + count) — the contract already tells consumers to
//! drop exact duplicates on `event-uid` — and optionally reject findings whose
//! `ocsf.time` is older than a freshness window. Nothing here keeps state.
//!
//! # Policies
//!
//! * [`SignaturePolicy::Strict`]: a missing signature is an error. Use on
//!   every connected path once all producers sign.
//! * [`SignaturePolicy::Optional`]: unsigned findings are accepted and
//!   reported as [`SignatureStatus::Unsigned`] (migration from 1.1).
//!   A signature that is *present* must still verify in both policies.
//!
//! # Limits
//!
//! * Ed25519 only. HMAC keys ([`robodr_blackbox::HmacSha256Key`]) are refused:
//!   a symmetric key lets every verifier forge.
//! * Ed25519 is `robodr-blackbox`'s wrapper over the audited
//!   `ed25519-dalek` crate (strict verification, RFC 8032 vectors).
//! * Key distribution (which public key belongs to which unit) is the
//!   commissioning / fleet registry's job; this module only consumes it.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::BuildHasher;

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::sign::SignError;
use robodr_blackbox::{Signer, Verifier};
use serde::{Deserialize, Serialize};

use crate::kafka::{record, Record};
use crate::model::FindingEnvelope;
use crate::validate::{parse_and_validate, ValidationError, MAX_FINDING_BYTES};

/// Kafka header carrying the detached signature.
pub const SIG_HEADER: &str = "robodr-finding-sig";
/// The only accepted signature algorithm.
pub const SIG_ALG: &str = "ed25519";
/// Domain separator prefixed to every signed message.
pub const SIG_DOMAIN: &[u8] = b"robodr-ocsf/finding-sig/v1\0";
/// Ed25519 signature length in bytes.
pub const SIG_LEN: usize = 64;
/// Maximum key id length (same as the black box's key ids).
pub const MAX_KEY_ID: usize = 128;
/// Maximum accepted header value length (bytes), checked before parsing.
pub const MAX_SIG_HEADER_BYTES: usize = 512;

/// The detached signature object (the [`SIG_HEADER`] value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingSignature {
    /// Always [`SIG_ALG`].
    pub alg: String,
    /// Key id of the signing key (printable ASCII, 1..=128 bytes).
    pub key_id: String,
    /// Signature, 128 lower-case hex digits.
    pub sig: String,
}

/// Why signing or signature verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Strict policy and no signature header.
    Missing,
    /// More than one signature header on one record.
    Duplicate,
    /// The header value is not a well-formed signature object.
    Malformed(&'static str),
    /// Algorithm other than [`SIG_ALG`] (signer or header).
    UnsupportedAlgorithm(String),
    /// Key id empty, too long or not printable ASCII.
    BadKeyId,
    /// No verifier is registered for the unit the finding names.
    UnknownUnit(String),
    /// The verifier binds `key_id` to another device than the finding's unit.
    KeyUnitMismatch { unit: String, key_device: String },
    /// The signature does not verify over the received bytes under the
    /// unit's key named by `key_id`.
    BadSignature,
    /// The value itself failed contract validation.
    Invalid(Vec<ValidationError>),
    /// The signing backend failed.
    Signing(String),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "finding signature missing (strict policy)"),
            Self::Duplicate => write!(f, "more than one {SIG_HEADER} header"),
            Self::Malformed(why) => write!(f, "malformed finding signature: {why}"),
            Self::UnsupportedAlgorithm(a) => {
                write!(f, "unsupported finding signature algorithm {:?}", trunc(a))
            }
            Self::BadKeyId => write!(f, "finding signature key id is invalid"),
            Self::UnknownUnit(u) => write!(f, "no finding key registered for unit {:?}", trunc(u)),
            Self::KeyUnitMismatch { unit, key_device } => write!(
                f,
                "finding key is bound to unit {:?}, finding names {:?}",
                trunc(key_device),
                trunc(unit)
            ),
            Self::BadSignature => write!(f, "finding signature does not verify"),
            Self::Invalid(errs) => {
                write!(f, "finding invalid: ")?;
                for (i, e) in errs.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
            Self::Signing(e) => write!(f, "finding signing failed: {e}"),
        }
    }
}

impl std::error::Error for SignatureError {}

impl From<SignError> for SignatureError {
    fn from(e: SignError) -> Self {
        Self::Signing(e.0)
    }
}

fn trunc(s: &str) -> &str {
    let mut end = s.len().min(64);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn check_key_id(id: &str) -> Result<(), SignatureError> {
    if id.is_empty() || id.len() > MAX_KEY_ID || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(SignatureError::BadKeyId);
    }
    Ok(())
}

fn decode_sig(hex: &str) -> Result<[u8; SIG_LEN], SignatureError> {
    if hex.len() != SIG_LEN * 2 {
        return Err(SignatureError::Malformed("sig must be 128 hex digits"));
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; SIG_LEN];
    for (o, p) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        match (nib(p[0]), nib(p[1])) {
            (Some(h), Some(l)) => *o = (h << 4) | l,
            _ => return Err(SignatureError::Malformed("sig must be lower-case hex")),
        }
    }
    Ok(out)
}

impl FindingSignature {
    /// Compact JSON for the [`SIG_HEADER`] value (fixed field order).
    pub fn to_header_value(&self) -> String {
        // Three String fields cannot fail to serialise.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse and check a [`SIG_HEADER`] value: size-capped, exactly the three
    /// fields (no unknown or duplicate keys), `alg` = [`SIG_ALG`], a valid
    /// key id and 128 lower-case hex digits.
    pub fn from_header_value(s: &str) -> Result<Self, SignatureError> {
        if s.len() > MAX_SIG_HEADER_BYTES {
            return Err(SignatureError::Malformed("header value too long"));
        }
        let me: Self = serde_json::from_str(s)
            .map_err(|_| SignatureError::Malformed("not a {alg,key_id,sig} object"))?;
        me.check()?;
        Ok(me)
    }

    /// Check field formats (not the signature itself).
    pub fn check(&self) -> Result<(), SignatureError> {
        if self.alg != SIG_ALG {
            return Err(SignatureError::UnsupportedAlgorithm(self.alg.clone()));
        }
        check_key_id(&self.key_id)?;
        decode_sig(&self.sig)?;
        Ok(())
    }

    /// Raw signature bytes (after [`FindingSignature::check`]).
    pub fn sig_bytes(&self) -> Result<[u8; SIG_LEN], SignatureError> {
        decode_sig(&self.sig)
    }
}

/// The exact message that is signed for record value `value` (see the
/// module docs for the framing).
pub fn signing_message(alg: &str, key_id: &str, value: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + 16 + alg.len() + key_id.len() + value.len());
    m.extend_from_slice(SIG_DOMAIN);
    // alg and key_id are length-checked (<= MAX_KEY_ID) before use; the
    // saturating casts only matter for hostile direct callers.
    m.extend_from_slice(&u32::try_from(alg.len()).unwrap_or(u32::MAX).to_be_bytes());
    m.extend_from_slice(alg.as_bytes());
    m.extend_from_slice(
        &u32::try_from(key_id.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    m.extend_from_slice(key_id.as_bytes());
    m.extend_from_slice(&(value.len() as u64).to_be_bytes());
    m.extend_from_slice(value);
    m
}

/// Sign a record value (the exact bytes that will be sent). The signer must
/// be Ed25519; the value must be within [`MAX_FINDING_BYTES`]. The value is
/// not validated here — sign only what [`crate::kafka::to_json`] produced.
pub fn sign_value(value: &str, signer: &dyn Signer) -> Result<FindingSignature, SignatureError> {
    if signer.algorithm() != SIG_ALG {
        return Err(SignatureError::UnsupportedAlgorithm(
            signer.algorithm().to_string(),
        ));
    }
    check_key_id(signer.key_id())?;
    if value.len() > MAX_FINDING_BYTES {
        return Err(SignatureError::Invalid(vec![ValidationError::TooLarge {
            len: value.len(),
            max: MAX_FINDING_BYTES,
        }]));
    }
    let msg = signing_message(SIG_ALG, signer.key_id(), value.as_bytes());
    let sig = signer.sign(&msg)?;
    if sig.len() != SIG_LEN {
        return Err(SignatureError::Signing(format!(
            "signer returned {} bytes, expected {SIG_LEN}",
            sig.len()
        )));
    }
    Ok(FindingSignature {
        alg: SIG_ALG.to_string(),
        key_id: signer.key_id().to_string(),
        sig: to_hex(&sig),
    })
}

/// Sign `rec.value` and set the [`SIG_HEADER`] header (appended last;
/// an existing signature header is replaced).
pub fn sign_record(rec: &mut Record, signer: &dyn Signer) -> Result<(), SignatureError> {
    let s = sign_value(&rec.value, signer)?;
    rec.headers.retain(|(k, _)| *k != SIG_HEADER);
    rec.headers.push((SIG_HEADER, s.to_header_value()));
    Ok(())
}

/// [`record`] plus [`sign_record`]: a validated, signed record.
pub fn record_signed(
    env: &FindingEnvelope,
    partitions: Option<u32>,
    signer: &dyn Signer,
) -> Result<Record, SignatureError> {
    let mut rec = record(env, partitions).map_err(SignatureError::Invalid)?;
    sign_record(&mut rec, signer)?;
    Ok(rec)
}

/// The single [`SIG_HEADER`] value among `headers` (name compared
/// case-insensitively, as Kafka clients differ). `Ok(None)` if absent,
/// [`SignatureError::Duplicate`] if more than one.
pub fn signature_header<K: AsRef<str>, V: AsRef<str>>(
    headers: &[(K, V)],
) -> Result<Option<&str>, SignatureError> {
    let mut found = None;
    for (k, v) in headers {
        if k.as_ref().eq_ignore_ascii_case(SIG_HEADER) {
            if found.is_some() {
                return Err(SignatureError::Duplicate);
            }
            found = Some(v.as_ref());
        }
    }
    Ok(found)
}

/// Whether an unsigned finding is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePolicy {
    /// A signature is required.
    Strict,
    /// Unsigned findings pass as [`SignatureStatus::Unsigned`]; a present
    /// signature must still verify.
    Optional,
}

/// Finding-key lookup by unit (robot id). Implemented for maps of
/// `robot id -> Box<dyn Verifier>`; the verifier may be a single key or a
/// [`robodr_blackbox::Keyring`] holding the unit's current and previous keys.
pub trait VerifierByUnit {
    fn verifier_for(&self, unit_id: &str) -> Option<&dyn Verifier>;
}

impl VerifierByUnit for BTreeMap<String, Box<dyn Verifier>> {
    fn verifier_for(&self, unit_id: &str) -> Option<&dyn Verifier> {
        self.get(unit_id).map(|b| b.as_ref())
    }
}

impl<S: BuildHasher> VerifierByUnit for HashMap<String, Box<dyn Verifier>, S> {
    fn verifier_for(&self, unit_id: &str) -> Option<&dyn Verifier> {
        self.get(unit_id).map(|b| b.as_ref())
    }
}

/// Outcome of signature checking for an accepted finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Verified under `key_id`, a key registered for `unit_id`
    /// (= the finding's `entity_context.robot.id`).
    Verified { unit_id: String, key_id: String },
    /// No signature; accepted only under [`SignaturePolicy::Optional`].
    Unsigned,
}

/// Replay/dedup hint. A valid signature does not make a record fresh; the
/// consumer dedups (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplayKey {
    /// `entity_context.robot.id`.
    pub robot_id: String,
    /// `finding_id` (stable across repeats of one finding).
    pub finding_id: String,
    /// `ocsf.metadata.uid`: one emission (finding id, last seen, count).
    /// Two records with equal `(robot_id, event_uid)` are the same emission.
    pub event_uid: String,
    /// `ocsf.time` (= last seen, ms since epoch): for freshness windows.
    pub time_ms: u64,
    /// `ocsf.count`.
    pub count: u64,
}

impl ReplayKey {
    pub fn of(env: &FindingEnvelope) -> Self {
        Self {
            robot_id: env.entity_context.robot.id.clone(),
            finding_id: env.finding_id.clone(),
            event_uid: env.ocsf.metadata.uid.clone(),
            time_ms: env.ocsf.time,
            count: env.ocsf.count,
        }
    }
}

/// A validated finding plus its signature status.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedFinding {
    pub envelope: FindingEnvelope,
    pub signature: SignatureStatus,
}

impl VerifiedFinding {
    /// See [`ReplayKey`]: dedup is the consumer's job.
    pub fn replay_key(&self) -> ReplayKey {
        ReplayKey::of(&self.envelope)
    }
}

/// Validate a received finding and its detached signature.
///
/// * `raw` — the record value exactly as received (signed bytes).
/// * `signature` — the [`SIG_HEADER`] value, if any
///   (see [`signature_header`]).
/// * `keys` — finding verifiers by unit id.
///
/// Order: the header is parsed (cheap, size-capped), then `raw` is validated
/// with [`parse_and_validate`], then the key of the unit the finding names
/// verifies the signature over `raw`'s bytes. Any present signature must
/// verify, whatever the policy.
pub fn parse_and_validate_signed(
    raw: &str,
    signature: Option<&str>,
    keys: &dyn VerifierByUnit,
    policy: SignaturePolicy,
) -> Result<VerifiedFinding, SignatureError> {
    let sig = signature
        .map(FindingSignature::from_header_value)
        .transpose()?;
    let envelope = parse_and_validate(raw).map_err(SignatureError::Invalid)?;
    let Some(sig) = sig else {
        return match policy {
            SignaturePolicy::Strict => Err(SignatureError::Missing),
            SignaturePolicy::Optional => Ok(VerifiedFinding {
                envelope,
                signature: SignatureStatus::Unsigned,
            }),
        };
    };
    let unit = envelope.entity_context.robot.id.as_str();
    let verifier = keys
        .verifier_for(unit)
        .ok_or_else(|| SignatureError::UnknownUnit(unit.to_string()))?;
    if let Some(dev) = verifier.key_device(&sig.key_id) {
        if dev != unit {
            return Err(SignatureError::KeyUnitMismatch {
                unit: unit.to_string(),
                key_device: dev.to_string(),
            });
        }
    }
    let bytes = sig.sig_bytes()?;
    let msg = signing_message(&sig.alg, &sig.key_id, raw.as_bytes());
    if !verifier.verify_key(&sig.key_id, &sig.alg, &msg, &bytes) {
        return Err(SignatureError::BadSignature);
    }
    let unit_id = unit.to_string();
    Ok(VerifiedFinding {
        envelope,
        signature: SignatureStatus::Verified {
            unit_id,
            key_id: sig.key_id,
        },
    })
}

/// [`parse_and_validate_signed`] for a whole [`Record`] (signature taken
/// from its headers).
pub fn verify_record(
    rec: &Record,
    keys: &dyn VerifierByUnit,
    policy: SignaturePolicy,
) -> Result<VerifiedFinding, SignatureError> {
    let sig = signature_header(&rec.headers)?;
    parse_and_validate_signed(&rec.value, sig, keys, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_value_parsing_is_strict() {
        let good = FindingSignature {
            alg: SIG_ALG.into(),
            key_id: "ed25519:abcd".into(),
            sig: "ab".repeat(64),
        };
        let v = good.to_header_value();
        assert_eq!(
            v,
            format!(
                "{{\"alg\":\"ed25519\",\"key_id\":\"ed25519:abcd\",\"sig\":\"{}\"}}",
                "ab".repeat(64)
            )
        );
        assert_eq!(FindingSignature::from_header_value(&v).unwrap(), good);

        let bad = [
            String::new(),
            "null".into(),
            "[]".into(),
            v.replace("ed25519\",\"key", "hmac-sha256\",\"key"),
            v.replace("\"key_id\":\"ed25519:abcd\"", "\"key_id\":\"\""),
            v.replace("\"key_id\":\"ed25519:abcd\"", "\"key_id\":\"a b\""),
            v.replace(&"ab".repeat(64), &"AB".repeat(64)),
            v.replace(&"ab".repeat(64), &"ab".repeat(63)),
            v.replace(&"ab".repeat(64), &"zz".repeat(64)),
            v.replace('}', ",\"extra\":1}"),
            v.replace('}', ",\"sig\":\"00\"}"),
            format!("{v}{}", " ".repeat(MAX_SIG_HEADER_BYTES)),
            format!(
                "{{\"alg\":\"ed25519\",\"key_id\":\"{}\",\"sig\":\"{}\"}}",
                "k".repeat(129),
                "ab".repeat(64)
            ),
            v.replace('}', ""),
        ];
        for b in &bad {
            assert!(FindingSignature::from_header_value(b).is_err(), "{b}");
        }
    }

    #[test]
    fn signing_message_is_framed() {
        let a = signing_message("ed25519", "k1", b"v");
        let b = signing_message("ed25519", "k", b"1v");
        assert_ne!(a, b);
        assert!(a.starts_with(SIG_DOMAIN));
        assert!(a.ends_with(b"\0\0\0\0\0\0\0\x01v"));
    }

    #[test]
    fn duplicate_signature_headers_are_rejected() {
        let h = [("robodr-finding-sig", "a"), ("ROBODR-FINDING-SIG", "b")];
        assert_eq!(signature_header(&h), Err(SignatureError::Duplicate));
        let h = [("robot-id", "x")];
        assert_eq!(signature_header(&h), Ok(None));
    }

    #[test]
    fn display_truncates_hostile_strings() {
        let e = SignatureError::UnknownUnit("é".repeat(100));
        assert!(e.to_string().len() < 120);
    }
}
