//! The wire formats of `docs/contracts/robodr.fleet-api.md`: enrollment
//! tokens, signed envelopes and their payloads, request authentication,
//! and strict parsing. Pure: no I/O, no clock (times are parameters).
//!
//! Every signature in this API is Ed25519 (strict verification, RFC 8032)
//! over a **length-framed message** that binds a domain, the envelope
//! `type`, the signing key id and the SHA-256 of the exact payload bytes
//! (§2.3). Payloads are carried as base64url of their exact bytes, so no
//! canonical-JSON question can arise: whoever verifies hashes the bytes it
//! decoded, never a re-serialisation.

use robodr_blackbox::crypto::{ct_eq, from_hex, hmac_sha256, sha256, to_hex};
use robodr_blackbox::sign_ed25519::{derive_key_id, verify, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use robodr_blackbox::Ed25519SigningKey;
use robodr_events::profile::is_sha256_digest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::b64;

// ------------------------------------------------------------- constants --

/// Path prefix of every fleet endpoint, below the API root (`{base}`).
pub const API_PREFIX: &str = "/robot-edr/v2/fleet";
/// `POST`: enrollment request envelope -> enrollment answer envelope.
pub const PATH_ENROLL: &str = "/robot-edr/v2/fleet/enroll";
/// `POST`: rotation request envelope -> rotation answer envelope.
pub const PATH_ROTATE: &str = "/robot-edr/v2/fleet/keys/rotate";
/// `POST`: retire request envelope -> retire answer envelope.
pub const PATH_RETIRE: &str = "/robot-edr/v2/fleet/keys/retire";
/// `POST`: cancel request envelope -> cancel answer envelope.
pub const PATH_CANCEL: &str = "/robot-edr/v2/fleet/keys/cancel";
/// `GET` + `/<platform>`: the root-signed revocation list.
pub const PATH_REVOCATIONS: &str = "/robot-edr/v2/fleet/revocations";
/// `POST`: a draft profile for review.
pub const PATH_PROFILE_DRAFTS: &str = "/robot-edr/v2/fleet/profiles/drafts";
/// `GET`: the profile offer for this robot.
pub const PATH_PROFILE_CURRENT: &str = "/robot-edr/v2/fleet/profiles/current";
/// `GET` + `/<64 hex>`: the approval envelope for a profile digest.
pub const PATH_PROFILE_APPROVALS: &str = "/robot-edr/v2/fleet/profiles/approvals";
/// `GET`: the ring-information envelope.
pub const PATH_RING: &str = "/robot-edr/v2/fleet/ring";
/// `POST`: decommission request envelope -> decommission answer envelope
/// (§5.6).
pub const PATH_DECOMMISSION: &str = "/robot-edr/v2/fleet/decommission";

/// Prefix of a compact enrollment token.
pub const TOKEN_PREFIX: &str = "rdet1.";
/// `format` of an envelope.
pub const ENVELOPE_FORMAT: &str = "robodr-fleet-envelope/v1";

pub const TOKEN_FORMAT: &str = "robodr-fleet-enroll-token/v1";
pub const ENROLL_REQUEST_FORMAT: &str = "robodr-fleet-enroll-request/v1";
pub const ENROLL_ANSWER_FORMAT: &str = "robodr-fleet-enroll-answer/v1";
pub const ROTATE_REQUEST_FORMAT: &str = "robodr-fleet-rotate-request/v1";
pub const ROTATE_ANSWER_FORMAT: &str = "robodr-fleet-rotate-answer/v1";
pub const RETIRE_REQUEST_FORMAT: &str = "robodr-fleet-retire-request/v1";
pub const RETIRE_ANSWER_FORMAT: &str = "robodr-fleet-retire-answer/v1";
pub const CANCEL_REQUEST_FORMAT: &str = "robodr-fleet-cancel-request/v1";
pub const CANCEL_ANSWER_FORMAT: &str = "robodr-fleet-cancel-answer/v1";
pub const APPROVAL_FORMAT: &str = "robodr-fleet-profile-approval/v1";
pub const RING_FORMAT: &str = "robodr-fleet-ring/v1";
pub const OFFER_FORMAT: &str = "robodr-fleet-profile-offer/v1";
pub const DECOMMISSION_REQUEST_FORMAT: &str = "robodr-fleet-decommission-request/v1";
pub const DECOMMISSION_ANSWER_FORMAT: &str = "robodr-fleet-decommission-answer/v1";

/// Envelope / token `type` values (also the signature domain's type field).
pub const T_TOKEN: &str = "enroll-token";
pub const T_ENROLL_REQUEST: &str = "enroll-request";
pub const T_ENROLL_ANSWER: &str = "enroll-answer";
pub const T_ROTATE_REQUEST: &str = "rotate-request";
pub const T_ROTATE_ANSWER: &str = "rotate-answer";
pub const T_RETIRE_REQUEST: &str = "retire-request";
pub const T_RETIRE_ANSWER: &str = "retire-answer";
pub const T_CANCEL_REQUEST: &str = "cancel-request";
pub const T_CANCEL_ANSWER: &str = "cancel-answer";
pub const T_APPROVAL: &str = "profile-approval";
pub const T_RING: &str = "ring-info";
pub const T_DECOMMISSION_REQUEST: &str = "decommission-request";
pub const T_DECOMMISSION_ANSWER: &str = "decommission-answer";
const TYPES: [&str; 13] = [
    T_TOKEN,
    T_ENROLL_REQUEST,
    T_ENROLL_ANSWER,
    T_ROTATE_REQUEST,
    T_ROTATE_ANSWER,
    T_RETIRE_REQUEST,
    T_RETIRE_ANSWER,
    T_CANCEL_REQUEST,
    T_CANCEL_ANSWER,
    T_APPROVAL,
    T_RING,
    T_DECOMMISSION_REQUEST,
    T_DECOMMISSION_ANSWER,
];

/// Signature domain (§2.3).
pub const SIG_DOMAIN: &[u8] = b"robodr-fleet/sig/v1\0";
/// Token MAC domain (§3.2).
pub const MAC_DOMAIN: &[u8] = b"robodr-fleet/token-mac/v1\0";
/// Token MAC key derivation domain (§3.2).
pub const MAC_KEY_DOMAIN: &[u8] = b"robodr-fleet/token-mac-key/v1\0";
/// Request authentication domain (§2.5).
pub const REQUEST_DOMAIN: &[u8] = b"robodr-fleet/request/v1\0";
/// Key-handover statement domain (fleet journal, §5.4).
pub const HANDOVER_DOMAIN: &[u8] = b"robodr-fleet/key-handover/v1\0";

/// Largest envelope (file or HTTP body) accepted.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
/// Largest decoded payload accepted.
pub const MAX_PAYLOAD_BYTES: usize = 32 * 1024;
/// Largest compact token accepted.
pub const MAX_TOKEN_BYTES: usize = 4 * 1024;
/// Longest validity window of a token (7 days).
pub const MAX_TOKEN_VALIDITY_MS: u64 = 7 * 24 * 3600 * 1000;
/// Longest validity window of a profile approval (7 days).
pub const MAX_APPROVAL_VALIDITY_MS: u64 = 7 * 24 * 3600 * 1000;
/// Clock skew tolerated between robot and SOC (5 minutes, inclusive).
pub const MAX_SKEW_MS: u64 = 300_000;
/// Most signatures in one envelope.
pub const MAX_SIGS: usize = 4;
/// Most operators named in an approval.
pub const MAX_APPROVERS: usize = 8;
/// Largest profile offer (HTTP body).
pub const MAX_OFFER_BYTES: usize = 2 * 1024 * 1024;

/// Key roles a robot registers (§4).
pub const ROLES: [&str; 3] = ["uplink", "finding", "blackbox"];
/// Roles `rotate` handles (§5).
pub const ROTATABLE: [&str; 2] = ["uplink", "finding"];
/// Why a unit is decommissioned (§5.6).
pub const DECOMMISSION_REASONS: [&str; 3] = ["end_of_life", "transfer", "repair"];

// ---------------------------------------------------------------- errors --

/// Why a token, envelope or payload is refused (pure checks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub String);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WireError {}

impl From<WireError> for String {
    fn from(e: WireError) -> Self {
        e.0
    }
}

fn err<T>(m: impl Into<String>) -> Result<T, WireError> {
    Err(WireError(m.into()))
}

// ------------------------------------------------------------ primitives --

/// `sha256:` + hex of SHA-256(`bytes`).
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", to_hex(&sha256(bytes)))
}

/// The fingerprint of an Ed25519 public key: [`digest`] of its 32 bytes
/// (the same as `robodr_commission::trust::key_fingerprint`).
pub fn fingerprint(public: &[u8; PUBLIC_KEY_LEN]) -> String {
    digest(public)
}

fn push_framed(m: &mut Vec<u8>, part: &[u8]) {
    m.extend_from_slice(&(part.len() as u32).to_be_bytes());
    m.extend_from_slice(part);
}

/// The message an envelope (or token) signature covers (§2.3).
pub fn sig_message(kind: &str, key_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = SIG_DOMAIN.to_vec();
    push_framed(&mut m, kind.as_bytes());
    push_framed(&mut m, key_id.as_bytes());
    m.extend_from_slice(&sha256(payload));
    m
}

/// The token MAC key: SHA-256(domain || nonce) (§3.2).
pub fn mac_key(nonce: &[u8; 32]) -> [u8; 32] {
    let mut m = MAC_KEY_DOMAIN.to_vec();
    m.extend_from_slice(nonce);
    sha256(&m)
}

/// The message the token MAC covers (§3.2).
pub fn mac_message(token_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = MAC_DOMAIN.to_vec();
    push_framed(&mut m, token_id.as_bytes());
    m.extend_from_slice(&sha256(payload));
    m
}

/// HMAC-SHA256 under [`mac_key`] over [`mac_message`].
pub fn token_mac(nonce: &[u8; 32], token_id: &str, payload: &[u8]) -> [u8; 32] {
    hmac_sha256(&mac_key(nonce), &mac_message(token_id, payload))
}

/// The message a request-authentication signature covers (§2.5).
pub fn request_message(
    method: &str,
    target: &str,
    key_id: &str,
    timestamp_ms: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut m = REQUEST_DOMAIN.to_vec();
    push_framed(&mut m, method.as_bytes());
    push_framed(&mut m, target.as_bytes());
    push_framed(&mut m, key_id.as_bytes());
    m.extend_from_slice(&timestamp_ms.to_be_bytes());
    m.extend_from_slice(&sha256(body));
    m
}

/// The key-handover statement both keys of a rotation sign in the fleet
/// journal (§5.4): binds the rotation to the journal head it follows.
pub fn handover_message(
    rotation_id: &str,
    role: &str,
    old_fingerprint: &str,
    new_fingerprint: &str,
    journal_head: &str,
) -> Vec<u8> {
    let mut m = HANDOVER_DOMAIN.to_vec();
    for p in [
        rotation_id,
        role,
        old_fingerprint,
        new_fingerprint,
        journal_head,
    ] {
        push_framed(&mut m, p.as_bytes());
    }
    m
}

/// Ed25519 strict verification of `sig_hex` (128 lower-case hex) by
/// `public` over `message`.
pub fn verify_hex(public: &[u8; PUBLIC_KEY_LEN], message: &[u8], sig_hex: &str) -> bool {
    if !is_lower_hex(sig_hex, SIGNATURE_LEN * 2) {
        return false;
    }
    match from_hex(sig_hex) {
        Some(sig) => verify(public, message, &sig),
        None => false,
    }
}

// ----------------------------------------------------------- field rules --

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `[A-Za-z0-9._-]{1,64}` (robot id, site, platform: the profile label rule).
pub fn is_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `[A-Za-z0-9._:-]{1,64}` (workspace, token id, approval id).
pub fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// `ed25519:<16 lower-case hex>` (the derived RoboDR key id).
pub fn is_key_id(s: &str) -> bool {
    s.strip_prefix("ed25519:")
        .is_some_and(|h| is_lower_hex(h, 16))
}

/// `<prefix><32 lower-case hex>`.
fn is_prefixed_id(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix).is_some_and(|h| is_lower_hex(h, 32))
}

/// A semantic-ish version string: 1–64 of `[0-9A-Za-z.+~-]`, starting with
/// a digit (Debian upstream versions included).
pub fn is_version(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_digit()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~' | b'-'))
}

/// Decode the 32-byte public key in `public_hex` and check that `key_id`
/// and `fingerprint` are the ones derived from it.
pub fn check_public(
    public_hex: &str,
    key_id: &str,
    fpr: &str,
) -> Result<[u8; PUBLIC_KEY_LEN], WireError> {
    if !is_lower_hex(public_hex, PUBLIC_KEY_LEN * 2) {
        return err("public_hex must be 64 lower-case hex digits");
    }
    let raw = from_hex(public_hex).ok_or_else(|| WireError("public_hex".into()))?;
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk.copy_from_slice(&raw);
    robodr_blackbox::Ed25519VerifyingKey::from_bytes_with_derived_id(&pk)
        .map_err(|e| WireError(format!("public key: {e}")))?;
    if derive_key_id(&pk) != key_id {
        return err(format!(
            "key_id {key_id:?} is not the id derived from public_hex"
        ));
    }
    if fingerprint(&pk) != fpr {
        return err("fingerprint is not SHA-256 of public_hex");
    }
    Ok(pk)
}

// --------------------------------------------------------- strict JSON --

/// Parse `bytes` as one JSON object with **exactly** the keys `keys` (each
/// once, any order; no other key), then into `T`. Duplicate keys at any
/// depth are refused.
pub fn strict_parse<T: DeserializeOwned>(bytes: &[u8], keys: &[&str]) -> Result<T, WireError> {
    let text = std::str::from_utf8(bytes).map_err(|_| WireError("not UTF-8".into()))?;
    robodr_commission::profile_file::reject_duplicate_keys(text)
        .map_err(|e| WireError(format!("JSON: {e}")))?;
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| WireError(format!("JSON: {e}")))?;
    let Some(obj) = v.as_object() else {
        return err("not a JSON object");
    };
    for k in keys {
        if !obj.contains_key(*k) {
            return err(format!("missing key {k:?}"));
        }
    }
    if let Some(extra) = obj.keys().find(|k| !keys.contains(&k.as_str())) {
        return err(format!("unknown key {extra:?}"));
    }
    serde_json::from_value(v).map_err(|e| WireError(format!("JSON: {e}")))
}

fn check_nested_keys(v: &serde_json::Value, keys: &[&str], what: &str) -> Result<(), WireError> {
    let Some(obj) = v.as_object() else {
        return err(format!("{what} is not an object"));
    };
    if obj.len() != keys.len() || keys.iter().any(|k| !obj.contains_key(*k)) {
        return err(format!("{what} must have exactly the keys {keys:?}"));
    }
    Ok(())
}

/// Serialise a payload: compact JSON, keys in declaration order, no
/// trailing newline (the exact bytes that are signed). The payload structs
/// hold strings, integers and vectors of them only, so this does not fail
/// in practice; an error is still reported, never signed over.
pub fn payload_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>, WireError> {
    serde_json::to_vec(v).map_err(|e| WireError(format!("payload does not serialise: {e}")))
}

// ------------------------------------------------------------ envelopes --

/// One envelope signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSig {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

/// The token MAC of an enrollment request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvMac {
    pub alg: String,
    pub token_id: String,
    pub mac: String,
}

/// A signed envelope (§2.2), as carried in an HTTP body or a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub format: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// base64url (no padding) of the exact payload bytes.
    pub payload: String,
    pub sigs: Vec<EnvSig>,
    /// Only on an `enroll-request`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<EnvMac>,
}

/// A parsed, structurally valid envelope with its decoded payload. The
/// signatures are **not** verified yet ([`Opened::verify_by`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub envelope: Envelope,
    pub payload: Vec<u8>,
}

impl Envelope {
    /// A new envelope of `kind` over `payload`, signed by `signers` in
    /// order.
    pub fn sign(kind: &str, payload: &[u8], signers: &[&Ed25519SigningKey]) -> Self {
        let sigs = signers
            .iter()
            .map(|k| {
                let key_id = robodr_blackbox::Signer::key_id(*k).to_string();
                EnvSig {
                    alg: "ed25519".into(),
                    sig: to_hex(&k.sign_message(&sig_message(kind, &key_id, payload))),
                    key_id,
                }
            })
            .collect();
        Self {
            format: ENVELOPE_FORMAT.into(),
            kind: kind.into(),
            payload: b64::encode(payload),
            sigs,
            mac: None,
        }
    }

    /// The bytes of an envelope file / HTTP body: compact JSON + `\n`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        let mut v = serde_json::to_vec(self)
            .map_err(|e| WireError(format!("envelope does not serialise: {e}")))?;
        v.push(b'\n');
        Ok(v)
    }

    /// [`Envelope::to_bytes`] as text (JSON is UTF-8).
    pub fn to_text(&self) -> Result<String, WireError> {
        String::from_utf8(self.to_bytes()?)
            .map_err(|e| WireError(format!("envelope is not UTF-8: {e}")))
    }

    /// Strictly parse an envelope of the expected `kind` (§2.2).
    pub fn parse(bytes: &[u8], kind: &str) -> Result<Opened, WireError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return err(format!("envelope larger than {MAX_ENVELOPE_BYTES} bytes"));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| WireError("not UTF-8".into()))?;
        // One optional final LF, nothing else around the object.
        let core = text.strip_suffix('\n').unwrap_or(text);
        if core.trim() != core {
            return err("white space around the envelope");
        }
        let v: serde_json::Value = {
            robodr_commission::profile_file::reject_duplicate_keys(core)
                .map_err(|e| WireError(format!("JSON: {e}")))?;
            serde_json::from_str(core).map_err(|e| WireError(format!("JSON: {e}")))?
        };
        let Some(obj) = v.as_object() else {
            return err("envelope is not a JSON object");
        };
        let want: &[&str] = if kind == T_ENROLL_REQUEST {
            &["format", "type", "payload", "sigs", "mac"]
        } else {
            &["format", "type", "payload", "sigs"]
        };
        check_nested_keys(&v, want, "envelope")?;
        for s in obj["sigs"].as_array().into_iter().flatten() {
            check_nested_keys(s, &["alg", "key_id", "sig"], "sigs[]")?;
        }
        if kind == T_ENROLL_REQUEST {
            check_nested_keys(&obj["mac"], &["alg", "token_id", "mac"], "mac")?;
        }
        let e: Envelope =
            serde_json::from_value(v).map_err(|e| WireError(format!("envelope: {e}")))?;
        if e.format != ENVELOPE_FORMAT {
            return err(format!(
                "format {:?}, expected {ENVELOPE_FORMAT:?}",
                trunc(&e.format)
            ));
        }
        if !TYPES.contains(&e.kind.as_str()) {
            return err(format!("unknown type {:?}", trunc(&e.kind)));
        }
        if e.kind != kind {
            return err(format!("type {:?}, expected {kind:?}", e.kind));
        }
        if e.sigs.is_empty() || e.sigs.len() > MAX_SIGS {
            return err(format!("sigs must hold 1..={MAX_SIGS} signatures"));
        }
        for (i, s) in e.sigs.iter().enumerate() {
            if s.alg != "ed25519" {
                return err(format!("sigs[{i}].alg must be \"ed25519\""));
            }
            if !is_key_id(&s.key_id) {
                return err(format!("sigs[{i}].key_id is not ed25519:<16 hex>"));
            }
            if !is_lower_hex(&s.sig, SIGNATURE_LEN * 2) {
                return err(format!("sigs[{i}].sig is not 128 lower-case hex"));
            }
            if e.sigs[..i].iter().any(|o| o.key_id == s.key_id) {
                return err(format!("sigs[{i}]: key id signs twice"));
            }
        }
        if let Some(m) = &e.mac {
            if m.alg != "hmac-sha256" || !is_ident(&m.token_id) || !is_lower_hex(&m.mac, 64) {
                return err("mac must be {alg: \"hmac-sha256\", token_id, mac: 64 hex}");
            }
        }
        let payload = b64::decode(&e.payload)
            .ok_or_else(|| WireError("payload is not canonical base64url".into()))?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return err(format!("payload larger than {MAX_PAYLOAD_BYTES} bytes"));
        }
        Ok(Opened {
            envelope: e,
            payload,
        })
    }
}

impl Opened {
    /// The signature by `key_id` verifies under `public` (the caller has
    /// already decided that this key may sign this type).
    pub fn verify_by(&self, key_id: &str, public: &[u8; PUBLIC_KEY_LEN]) -> Result<(), WireError> {
        let Some(s) = self.envelope.sigs.iter().find(|s| s.key_id == key_id) else {
            return err(format!("no signature by {key_id}"));
        };
        if !verify_hex(
            public,
            &sig_message(&self.envelope.kind, key_id, &self.payload),
            &s.sig,
        ) {
            return err(format!("signature by {key_id} does not verify"));
        }
        Ok(())
    }

    /// The signer key ids in order.
    pub fn signers(&self) -> Vec<&str> {
        self.envelope
            .sigs
            .iter()
            .map(|s| s.key_id.as_str())
            .collect()
    }

    /// `sha256:` of the payload bytes (what answers name as
    /// `request_digest`).
    pub fn payload_digest(&self) -> String {
        digest(&self.payload)
    }

    /// Verify the token MAC (enroll requests).
    pub fn verify_mac(&self, nonce: &[u8; 32]) -> Result<(), WireError> {
        let Some(m) = &self.envelope.mac else {
            return err("no token mac");
        };
        let want = token_mac(nonce, &m.token_id, &self.payload);
        match from_hex(&m.mac) {
            Some(got) if ct_eq(&got, &want) => Ok(()),
            _ => err("token mac does not verify"),
        }
    }
}

/// Shorten untrusted text for an error message.
pub fn trunc(s: &str) -> &str {
    let mut end = s.len().min(64);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------- token --

/// The payload of an enrollment token (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPayload {
    pub format: String,
    pub token_id: String,
    pub workspace: String,
    pub robot_id: String,
    pub site: Option<String>,
    pub soc_key_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// 32 random bytes, 64 lower-case hex: the token secret.
    pub nonce: String,
}

const TOKEN_KEYS: &[&str] = &[
    "format",
    "token_id",
    "workspace",
    "robot_id",
    "site",
    "soc_key_id",
    "issued_at_ms",
    "expires_at_ms",
    "nonce",
];

/// A parsed token (structure checked, signature not yet verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub payload: TokenPayload,
    pub payload_bytes: Vec<u8>,
    pub sig: [u8; SIGNATURE_LEN],
    /// `payload.nonce`, decoded at parse time.
    nonce: [u8; 32],
}

impl Token {
    /// Issue a token (SOC side; tests and vectors).
    pub fn issue(p: &TokenPayload, soc: &Ed25519SigningKey) -> Result<String, WireError> {
        let bytes = payload_bytes(p)?;
        let sig = soc.sign_message(&sig_message(T_TOKEN, &p.soc_key_id, &bytes));
        Ok(format!(
            "{TOKEN_PREFIX}{}.{}",
            b64::encode(&bytes),
            b64::encode(&sig)
        ))
    }

    /// Strictly parse a compact token (§3.1). Surrounding white space (a
    /// pasted line) is trimmed; nothing else is tolerated.
    pub fn parse(s: &str) -> Result<Self, WireError> {
        let s = s.trim_matches(|c| c == ' ' || c == '\t' || c == '\r' || c == '\n');
        if s.len() > MAX_TOKEN_BYTES {
            return err("token too long");
        }
        let Some(rest) = s.strip_prefix(TOKEN_PREFIX) else {
            return err(format!("token must start with {TOKEN_PREFIX:?}"));
        };
        let mut parts = rest.split('.');
        let (Some(p), Some(sg), None) = (parts.next(), parts.next(), parts.next()) else {
            return err("token must be rdet1.<payload>.<signature>");
        };
        let payload_bytes =
            b64::decode(p).ok_or_else(|| WireError("token payload is not base64url".into()))?;
        let sig = b64::decode(sg)
            .filter(|v| v.len() == SIGNATURE_LEN)
            .ok_or_else(|| WireError("token signature is not 64 bytes of base64url".into()))?;
        let payload: TokenPayload = strict_parse(&payload_bytes, TOKEN_KEYS)?;
        payload.check()?;
        let nonce = from_hex(&payload.nonce)
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| WireError("token nonce is not 32 bytes of hex".into()))?;
        let s64 = <[u8; SIGNATURE_LEN]>::try_from(sig)
            .map_err(|_| WireError("token signature is not 64 bytes".into()))?;
        Ok(Self {
            payload,
            payload_bytes,
            sig: s64,
            nonce,
        })
    }

    /// The token signature verifies under `public` (the SOC key named by
    /// `soc_key_id`).
    pub fn verify(&self, public: &[u8; PUBLIC_KEY_LEN]) -> Result<(), WireError> {
        let m = sig_message(T_TOKEN, &self.payload.soc_key_id, &self.payload_bytes);
        if verify(public, &m, &self.sig) {
            Ok(())
        } else {
            err("token signature does not verify under the SOC key it names")
        }
    }

    /// The 32-byte nonce.
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    /// Check validity against `now_ms` (inclusive bounds; `skew` tolerated
    /// before `issued_at_ms`).
    pub fn check_time(&self, now_ms: u64) -> Result<(), WireError> {
        let p = &self.payload;
        if now_ms > p.expires_at_ms {
            return err(format!(
                "token {} expired at {} ms (now {now_ms} ms)",
                p.token_id, p.expires_at_ms
            ));
        }
        if now_ms.saturating_add(MAX_SKEW_MS) < p.issued_at_ms {
            return err(format!(
                "token {} is issued in the future ({} ms; robot clock {now_ms} ms): fix the robot clock",
                p.token_id, p.issued_at_ms
            ));
        }
        Ok(())
    }
}

impl TokenPayload {
    pub fn check(&self) -> Result<(), WireError> {
        if self.format != TOKEN_FORMAT {
            return err(format!("token format {:?}", trunc(&self.format)));
        }
        if !is_ident(&self.token_id) || !is_ident(&self.workspace) {
            return err("token_id / workspace must be [A-Za-z0-9._:-]{1,64}");
        }
        if !is_label(&self.robot_id) || self.site.as_deref().is_some_and(|s| !is_label(s)) {
            return err("robot_id / site must be [A-Za-z0-9._-]{1,64}");
        }
        if !is_key_id(&self.soc_key_id) {
            return err("soc_key_id must be ed25519:<16 hex>");
        }
        if self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_TOKEN_VALIDITY_MS
        {
            return err("token validity must be > 0 and <= 7 days");
        }
        if !is_lower_hex(&self.nonce, 64) || self.nonce.bytes().all(|b| b == b'0') {
            return err("nonce must be 64 lower-case hex (32 random bytes)");
        }
        Ok(())
    }
}

// --------------------------------------------------------------- enroll --

/// One key of an enrollment request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub role: String,
    pub key_id: String,
    pub public_hex: String,
    pub fingerprint: String,
}

/// One key as the SOC confirms it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRef {
    pub role: String,
    pub key_id: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub format: String,
    pub request_id: String,
    pub token_id: String,
    pub workspace: String,
    pub robot_id: String,
    pub site: Option<String>,
    pub created_at_ms: u64,
    pub agentd_version: String,
    pub profile_digest: Option<String>,
    pub keys: Vec<KeyEntry>,
}

pub const ENROLL_REQUEST_KEYS: &[&str] = &[
    "format",
    "request_id",
    "token_id",
    "workspace",
    "robot_id",
    "site",
    "created_at_ms",
    "agentd_version",
    "profile_digest",
    "keys",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollAnswer {
    pub format: String,
    pub request_id: String,
    pub request_digest: String,
    pub token_id: String,
    pub workspace: String,
    pub robot_id: String,
    pub site: Option<String>,
    pub keys: Vec<KeyRef>,
    pub enrolled_at_ms: u64,
}

pub const ENROLL_ANSWER_KEYS: &[&str] = &[
    "format",
    "request_id",
    "request_digest",
    "token_id",
    "workspace",
    "robot_id",
    "site",
    "keys",
    "enrolled_at_ms",
];

fn check_keys_array(v: &serde_json::Value, with_public: bool) -> Result<(), WireError> {
    let want: &[&str] = if with_public {
        &["role", "key_id", "public_hex", "fingerprint"]
    } else {
        &["role", "key_id", "fingerprint"]
    };
    let Some(a) = v.get("keys").and_then(|k| k.as_array()) else {
        return err("keys must be an array");
    };
    if a.len() != ROLES.len() {
        return err(format!("keys must list exactly the roles {ROLES:?}"));
    }
    for k in a {
        check_nested_keys(k, want, "keys[]")?;
    }
    Ok(())
}

fn parse_value(bytes: &[u8]) -> Result<serde_json::Value, WireError> {
    let text = std::str::from_utf8(bytes).map_err(|_| WireError("not UTF-8".into()))?;
    serde_json::from_str(text).map_err(|e| WireError(format!("JSON: {e}")))
}

impl EnrollRequest {
    pub fn parse(payload: &[u8]) -> Result<Self, WireError> {
        let r: Self = strict_parse(payload, ENROLL_REQUEST_KEYS)?;
        check_keys_array(&parse_value(payload)?, true)?;
        r.check()?;
        Ok(r)
    }

    pub fn check(&self) -> Result<(), WireError> {
        if self.format != ENROLL_REQUEST_FORMAT {
            return err("enroll request format");
        }
        if !is_prefixed_id(&self.request_id, "rfe1-") {
            return err("request_id must be rfe1-<32 hex>");
        }
        if !is_ident(&self.token_id) || !is_ident(&self.workspace) || !is_label(&self.robot_id) {
            return err("token_id / workspace / robot_id malformed");
        }
        if self.site.as_deref().is_some_and(|s| !is_label(s)) {
            return err("site malformed");
        }
        if !is_version(&self.agentd_version) {
            return err("agentd_version malformed");
        }
        if self
            .profile_digest
            .as_deref()
            .is_some_and(|d| !is_sha256_digest(d))
        {
            return err("profile_digest must be sha256:<64 hex> or null");
        }
        if self.keys.len() != ROLES.len() {
            return err("keys must list uplink, finding, blackbox");
        }
        for (k, role) in self.keys.iter().zip(ROLES) {
            if k.role != role {
                return err(format!("keys must be in the order {ROLES:?}"));
            }
            check_public(&k.public_hex, &k.key_id, &k.fingerprint)?;
        }
        let mut fprs: Vec<&str> = self.keys.iter().map(|k| k.fingerprint.as_str()).collect();
        fprs.sort_unstable();
        fprs.dedup();
        if fprs.len() != ROLES.len() {
            return err("the three role keys must be distinct");
        }
        Ok(())
    }

    /// The public key of `role`.
    pub fn key(&self, role: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.role == role)
    }
}

impl EnrollAnswer {
    pub fn parse(payload: &[u8]) -> Result<Self, WireError> {
        let a: Self = strict_parse(payload, ENROLL_ANSWER_KEYS)?;
        check_keys_array(&parse_value(payload)?, false)?;
        if a.format != ENROLL_ANSWER_FORMAT
            || !is_prefixed_id(&a.request_id, "rfe1-")
            || !is_sha256_digest(&a.request_digest)
            || !is_ident(&a.token_id)
            || !is_ident(&a.workspace)
            || !is_label(&a.robot_id)
            || a.site.as_deref().is_some_and(|s| !is_label(s))
        {
            return err("enroll answer malformed");
        }
        Ok(a)
    }
}

// --------------------------------------------------------------- rotate --

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateRequest {
    pub format: String,
    pub rotation_id: String,
    pub workspace: String,
    pub robot_id: String,
    pub role: String,
    pub old_key_id: String,
    pub old_fingerprint: String,
    pub new_key_id: String,
    pub new_public_hex: String,
    pub new_fingerprint: String,
    pub created_at_ms: u64,
}

pub const ROTATE_REQUEST_KEYS: &[&str] = &[
    "format",
    "rotation_id",
    "workspace",
    "robot_id",
    "role",
    "old_key_id",
    "old_fingerprint",
    "new_key_id",
    "new_public_hex",
    "new_fingerprint",
    "created_at_ms",
];

impl RotateRequest {
    pub fn parse(payload: &[u8]) -> Result<Self, WireError> {
        let r: Self = strict_parse(payload, ROTATE_REQUEST_KEYS)?;
        if r.format != ROTATE_REQUEST_FORMAT
            || !is_prefixed_id(&r.rotation_id, "rfr1-")
            || !is_ident(&r.workspace)
            || !is_label(&r.robot_id)
            || !ROTATABLE.contains(&r.role.as_str())
            || !is_key_id(&r.old_key_id)
            || !is_sha256_digest(&r.old_fingerprint)
        {
            return err("rotate request malformed");
        }
        check_public(&r.new_public_hex, &r.new_key_id, &r.new_fingerprint)?;
        if r.new_fingerprint == r.old_fingerprint {
            return err("the new key equals the old key");
        }
        Ok(r)
    }
}

/// Answer to a rotate, retire or cancel request (§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAnswer {
    pub format: String,
    pub rotation_id: String,
    pub request_digest: String,
    pub workspace: String,
    pub robot_id: String,
    pub role: String,
    pub old_key_id: String,
    pub new_key_id: String,
    /// `overlap` (rotate), `retired` (retire) or `cancelled` (cancel).
    pub status: String,
    pub at_ms: u64,
}

pub const KEY_ANSWER_KEYS: &[&str] = &[
    "format",
    "rotation_id",
    "request_digest",
    "workspace",
    "robot_id",
    "role",
    "old_key_id",
    "new_key_id",
    "status",
    "at_ms",
];

impl KeyAnswer {
    pub fn parse(payload: &[u8], format: &str, status: &str) -> Result<Self, WireError> {
        let a: Self = strict_parse(payload, KEY_ANSWER_KEYS)?;
        if a.format != format
            || a.status != status
            || !is_prefixed_id(&a.rotation_id, "rfr1-")
            || !is_sha256_digest(&a.request_digest)
            || !is_ident(&a.workspace)
            || !is_label(&a.robot_id)
            || !ROTATABLE.contains(&a.role.as_str())
            || !is_key_id(&a.old_key_id)
            || !is_key_id(&a.new_key_id)
        {
            return err(format!("{format} malformed"));
        }
        Ok(a)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetireRequest {
    pub format: String,
    pub rotation_id: String,
    pub workspace: String,
    pub robot_id: String,
    pub role: String,
    pub old_key_id: String,
    pub new_key_id: String,
    pub created_at_ms: u64,
}

pub const RETIRE_REQUEST_KEYS: &[&str] = &[
    "format",
    "rotation_id",
    "workspace",
    "robot_id",
    "role",
    "old_key_id",
    "new_key_id",
    "created_at_ms",
];

impl RetireRequest {
    pub fn parse(payload: &[u8]) -> Result<Self, WireError> {
        let r: Self = strict_parse(payload, RETIRE_REQUEST_KEYS)?;
        if r.format != RETIRE_REQUEST_FORMAT
            || !is_prefixed_id(&r.rotation_id, "rfr1-")
            || !is_ident(&r.workspace)
            || !is_label(&r.robot_id)
            || !ROTATABLE.contains(&r.role.as_str())
            || !is_key_id(&r.old_key_id)
            || !is_key_id(&r.new_key_id)
        {
            return err("retire request malformed");
        }
        Ok(r)
    }
}

/// Cancel request (§5.5): ends a rotation the robot will not complete,
/// signed by the **old** key (the one that stays).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelRequest {
    pub format: String,
    pub rotation_id: String,
    /// Digest of the rotate request payload being cancelled.
    pub request_digest: String,
    pub workspace: String,
    pub robot_id: String,
    pub role: String,
    pub old_key_id: String,
    pub new_key_id: String,
    pub created_at_ms: u64,
}

pub const CANCEL_REQUEST_KEYS: &[&str] = &[
    "format",
    "rotation_id",
    "request_digest",
    "workspace",
    "robot_id",
    "role",
    "old_key_id",
    "new_key_id",
    "created_at_ms",
];

impl CancelRequest {
    pub fn parse(payload: &[u8]) -> Result<Self, WireError> {
        let r: Self = strict_parse(payload, CANCEL_REQUEST_KEYS)?;
        if r.format != CANCEL_REQUEST_FORMAT
            || !is_prefixed_id(&r.rotation_id, "rfr1-")
            || !is_sha256_digest(&r.request_digest)
            || !is_ident(&r.workspace)
            || !is_label(&r.robot_id)
            || !ROTATABLE.contains(&r.role.as_str())
            || !is_key_id(&r.old_key_id)
            || !is_key_id(&r.new_key_id)
            || r.old_key_id == r.new_key_id
        {
            return err("cancel request malformed");
        }
        Ok(r)
    }
}

// --------------------------------------------------------- decommission --

/// Decommission request (§5.6): the unit asks the SOC to retire every key
/// it holds and to close its registration. Signed by the unit's three
/// registered keys, in the order `uplink`, `finding`, `blackbox`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecommissionRequest {
    pub format: String,
    pub decommission_id: String,
    pub workspace: String,
    pub robot_id: String,
    /// One of [`DECOMMISSION_REASONS`].
    pub reason: String,
    /// The unit's registered keys, in role order (`uplink`, `finding`,
    /// `blackbox`).
    pub keys: Vec<KeyRef>,
    /// The fleet journal head the request follows (64 lower-case hex of the
    /// record hash, or `genesis`): binds the request to the unit's chain.
    pub journal_head: String,
    pub created_at_ms: u64,
}

pub const DECOMMISSION_REQUEST_KEYS: &[&str] = &[
    "format",
    "decommission_id",
    "workspace",
    "robot_id",
    "reason",
    "keys",
    "journal_head",
    "created_at_ms",
];

/// The SOC's answer to a decommission request (§5.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecommissionAnswer {
    pub format: String,
    pub decommission_id: String,
    pub request_digest: String,
    pub workspace: String,
    pub robot_id: String,
    pub reason: String,
    /// The keys the SOC retired (the request's, in its order).
    pub keys: Vec<KeyRef>,
    /// `"decommissioned"`.
    pub status: String,
    pub at_ms: u64,
}

pub const DECOMMISSION_ANSWER_KEYS: &[&str] = &[
    "format",
    "decommission_id",
    "request_digest",
    "workspace",
    "robot_id",
    "reason",
    "keys",
    "status",
    "at_ms",
];

/// The three key references of a decommission document: roles in order,
/// well-formed ids and fingerprints, pairwise distinct.
fn check_key_refs(keys: &[KeyRef]) -> Result<(), WireError> {
    if keys.len() != ROLES.len() {
        return err(format!("keys must list exactly the roles {ROLES:?}"));
    }
    for (k, role) in keys.iter().zip(ROLES) {
        if k.role != role {
            return err(format!("keys must be in the order {ROLES:?}"));
        }
        if !is_key_id(&k.key_id) || !is_sha256_digest(&k.fingerprint) {
            return err("keys[]: key_id must be ed25519:<16 hex>, fingerprint sha256:<64 hex>");
        }
    }
    let mut ids: Vec<&str> = keys.iter().map(|k| k.key_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    let mut fprs: Vec<&str> = keys.iter().map(|k| k.fingerprint.as_str()).collect();
    fprs.sort_unstable();
    fprs.dedup();
    if ids.len() != ROLES.len() || fprs.len() != ROLES.len() {
        return err("the three role keys must be distinct");
    }
    Ok(())
}

/// `genesis` or 64 lower-case hex (a fleet journal head).
pub fn is_journal_head(s: &str) -> bool {
    s == "genesis" || is_lower_hex(s, 64)
}

impl DecommissionRequest {
    pub fn parse(payload: &[u8]) -> Result<Self, WireError> {
        let r: Self = strict_parse(payload, DECOMMISSION_REQUEST_KEYS)?;
        check_keys_array(&parse_value(payload)?, false)?;
        if r.format != DECOMMISSION_REQUEST_FORMAT
            || !is_prefixed_id(&r.decommission_id, "rfd1-")
            || !is_ident(&r.workspace)
            || !is_label(&r.robot_id)
            || !DECOMMISSION_REASONS.contains(&r.reason.as_str())
            || !is_journal_head(&r.journal_head)
        {
            return err("decommission request malformed");
        }
        check_key_refs(&r.keys)?;
        Ok(r)
    }

    /// The key of `role`.
    pub fn key(&self, role: &str) -> Option<&KeyRef> {
        self.keys.iter().find(|k| k.role == role)
    }
}

impl DecommissionAnswer {
    pub fn parse(payload: &[u8]) -> Result<Self, WireError> {
        let a: Self = strict_parse(payload, DECOMMISSION_ANSWER_KEYS)?;
        check_keys_array(&parse_value(payload)?, false)?;
        if a.format != DECOMMISSION_ANSWER_FORMAT
            || !is_prefixed_id(&a.decommission_id, "rfd1-")
            || !is_sha256_digest(&a.request_digest)
            || !is_ident(&a.workspace)
            || !is_label(&a.robot_id)
            || !DECOMMISSION_REASONS.contains(&a.reason.as_str())
            || a.status != "decommissioned"
        {
            return err("decommission answer malformed");
        }
        check_key_refs(&a.keys)?;
        Ok(a)
    }
}

// -------------------------------------------------------------- profile --

/// Operator approval of the observe -> enforce transition (§6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub format: String,
    pub approval_id: String,
    pub workspace: String,
    pub robot_id: String,
    pub platform: String,
    pub profile_digest: String,
    pub profile_version: u64,
    pub transition: String,
    pub approved_by: Vec<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

pub const APPROVAL_KEYS: &[&str] = &[
    "format",
    "approval_id",
    "workspace",
    "robot_id",
    "platform",
    "profile_digest",
    "profile_version",
    "transition",
    "approved_by",
    "issued_at_ms",
    "expires_at_ms",
];

impl Approval {
    pub fn parse(payload: &[u8]) -> Result<Self, WireError> {
        let a: Self = strict_parse(payload, APPROVAL_KEYS)?;
        if a.format != APPROVAL_FORMAT
            || !is_ident(&a.approval_id)
            || !is_ident(&a.workspace)
            || !is_label(&a.robot_id)
            || !is_label(&a.platform)
            || !is_sha256_digest(&a.profile_digest)
            || a.profile_version == 0
            || a.transition != "enforce"
        {
            return err("profile approval malformed");
        }
        if a.approved_by.is_empty()
            || a.approved_by.len() > MAX_APPROVERS
            || a.approved_by.iter().any(|o| !is_ident(o))
        {
            return err("approved_by must name 1..=8 operators ([A-Za-z0-9._:-]{1,64})");
        }
        let mut o = a.approved_by.clone();
        o.sort();
        o.dedup();
        if o.len() != a.approved_by.len() {
            return err("approved_by names an operator twice");
        }
        if a.expires_at_ms <= a.issued_at_ms
            || a.expires_at_ms - a.issued_at_ms > MAX_APPROVAL_VALIDITY_MS
        {
            return err("approval validity must be > 0 and <= 7 days");
        }
        Ok(a)
    }
}

/// The profile offer (unsigned wrapper; the profile carries its own
/// signature, §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    pub format: String,
    pub profile_version: u64,
    pub digest: String,
    /// base64url of the exact profile file bytes.
    pub profile: String,
    /// base64url of the exact `<profile>.sig` bytes.
    pub sig: String,
}

pub const OFFER_KEYS: &[&str] = &["format", "profile_version", "digest", "profile", "sig"];

impl Offer {
    /// Parse and decode; returns (offer, profile bytes, sig bytes).
    pub fn parse(bytes: &[u8]) -> Result<(Self, Vec<u8>, Vec<u8>), WireError> {
        if bytes.len() > MAX_OFFER_BYTES {
            return err("profile offer too large");
        }
        let o: Self = strict_parse(bytes, OFFER_KEYS)?;
        if o.format != OFFER_FORMAT || !is_sha256_digest(&o.digest) || o.profile_version == 0 {
            return err("profile offer malformed");
        }
        let p = b64::decode(&o.profile).ok_or_else(|| WireError("offer.profile".into()))?;
        let s = b64::decode(&o.sig).ok_or_else(|| WireError("offer.sig".into()))?;
        if digest(&p) != o.digest {
            return err("offer.digest is not the digest of offer.profile");
        }
        Ok((o, p, s))
    }
}

// ----------------------------------------------------------------- ring --

/// Update-ring information (§7): information only, never an install order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingInfo {
    pub format: String,
    pub serial: u64,
    pub workspace: String,
    pub robot_id: String,
    pub ring: u8,
    pub target_version: Option<String>,
    pub bundle_sha256: Option<String>,
    /// The lowest release this robot may run (known-vulnerable releases
    /// below it): raises the unit's security floor (`install-bundle.sh`).
    pub min_version: Option<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

pub const RING_KEYS: &[&str] = &[
    "format",
    "serial",
    "workspace",
    "robot_id",
    "ring",
    "target_version",
    "bundle_sha256",
    "min_version",
    "issued_at_ms",
    "expires_at_ms",
];

impl RingInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, WireError> {
        let r: Self = strict_parse(payload, RING_KEYS)?;
        if r.format != RING_FORMAT
            || r.serial == 0
            || !is_ident(&r.workspace)
            || !is_label(&r.robot_id)
            || r.ring > 2
            || r.target_version.as_deref().is_some_and(|v| !is_version(v))
            || r.min_version.as_deref().is_some_and(|v| !is_version(v))
            || r.bundle_sha256
                .as_deref()
                .is_some_and(|h| !is_lower_hex(h, 64))
            || r.expires_at_ms <= r.issued_at_ms
        {
            return err("ring info malformed");
        }
        Ok(r)
    }
}

// --------------------------------------------------------------- errors --

/// A SOC error body `{"code": "...", "detail": "..."}` (§2.6). `None` if
/// the body is not one.
pub fn error_code(body: &[u8]) -> Option<(String, String)> {
    #[derive(Deserialize)]
    struct E {
        code: String,
        #[serde(default)]
        detail: String,
    }
    let e: E = serde_json::from_slice(body).ok()?;
    let ok = !e.code.is_empty()
        && e.code.len() <= 64
        && e.code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit());
    ok.then(|| {
        let d: String = e
            .detail
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        (e.code, d)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed_with_derived_id(&[b; 32])
    }

    #[test]
    fn envelope_roundtrip_and_tamper() {
        let k = key(1);
        let e = Envelope::sign(T_RING, b"{\"a\":1}", &[&k]);
        let o = Envelope::parse(&e.to_bytes().unwrap(), T_RING).unwrap();
        o.verify_by(robodr_blackbox::Signer::key_id(&k), &k.public_key())
            .unwrap();
        // Another type: refused before any signature check.
        assert!(Envelope::parse(&e.to_bytes().unwrap(), T_APPROVAL).is_err());
        // A payload byte changed: the signature fails.
        let mut t = e.clone();
        t.payload = b64::encode(b"{\"a\":2}");
        let o = Envelope::parse(&t.to_bytes().unwrap(), T_RING).unwrap();
        assert!(o
            .verify_by(robodr_blackbox::Signer::key_id(&k), &k.public_key())
            .is_err());
        // Unknown key, duplicate key.
        let txt = String::from_utf8(e.to_bytes().unwrap()).unwrap();
        let extra = txt.replacen("{\"format\"", "{\"x\":1,\"format\"", 1);
        assert!(Envelope::parse(extra.as_bytes(), T_RING).is_err());
        let dup = txt.replacen("{\"format\"", "{\"type\":\"ring-info\",\"format\"", 1);
        assert!(Envelope::parse(dup.as_bytes(), T_RING).is_err());
    }

    #[test]
    fn token_roundtrip_and_checks() {
        let soc = key(9);
        let p = TokenPayload {
            format: TOKEN_FORMAT.into(),
            token_id: "tok-1".into(),
            workspace: "ws-1".into(),
            robot_id: "ugv-001".into(),
            site: Some("lab".into()),
            soc_key_id: robodr_blackbox::Signer::key_id(&soc).into(),
            issued_at_ms: 1_000_000,
            expires_at_ms: 2_000_000,
            nonce: "ab".repeat(32),
        };
        let t = Token::issue(&p, &soc).unwrap();
        let parsed = Token::parse(&format!(" {t}\n")).unwrap();
        parsed.verify(&soc.public_key()).unwrap();
        assert!(parsed.verify(&key(8).public_key()).is_err());
        parsed.check_time(1_500_000).unwrap();
        assert!(parsed.check_time(2_000_001).is_err());
        parsed.check_time(1_000_000 - MAX_SKEW_MS).unwrap();
        assert!(parsed.check_time(1_000_000 - MAX_SKEW_MS - 1).is_err());
        assert!(Token::parse(&t.replacen("rdet1.", "rdet2.", 1)).is_err());
        assert!(Token::parse(&format!("{t}.x")).is_err());
    }

    #[test]
    fn decommission_payloads_are_strict() {
        let kr = |role: &str, b: u8| {
            let k = key(b);
            KeyRef {
                role: role.into(),
                key_id: robodr_blackbox::Signer::key_id(&k).into(),
                fingerprint: fingerprint(&k.public_key()),
            }
        };
        let good = DecommissionRequest {
            format: DECOMMISSION_REQUEST_FORMAT.into(),
            decommission_id: format!("rfd1-{}", "a".repeat(32)),
            workspace: "ws-1".into(),
            robot_id: "ugv-001".into(),
            reason: "end_of_life".into(),
            keys: vec![kr("uplink", 1), kr("finding", 2), kr("blackbox", 3)],
            journal_head: "genesis".into(),
            created_at_ms: 1,
        };
        let p = |r: &DecommissionRequest| payload_bytes(r).unwrap();
        assert_eq!(DecommissionRequest::parse(&p(&good)).unwrap(), good);
        let mut r = good.clone();
        r.keys.swap(0, 1);
        assert!(DecommissionRequest::parse(&p(&r)).is_err(), "role order");
        let mut r = good.clone();
        r.keys[2] = kr("blackbox", 1);
        assert!(
            DecommissionRequest::parse(&p(&r)).is_err(),
            "same key twice"
        );
        let mut r = good.clone();
        r.keys.pop();
        assert!(DecommissionRequest::parse(&p(&r)).is_err(), "two keys");
        let mut r = good.clone();
        r.reason = "scrapped".into();
        assert!(DecommissionRequest::parse(&p(&r)).is_err(), "reason");
        let mut r = good.clone();
        r.journal_head = "AB".repeat(32);
        assert!(DecommissionRequest::parse(&p(&r)).is_err(), "journal head");
        let mut r = good.clone();
        r.decommission_id = format!("rfr1-{}", "a".repeat(32));
        assert!(DecommissionRequest::parse(&p(&r)).is_err(), "id prefix");
        // An extra key inside keys[] is refused.
        let txt = String::from_utf8(p(&good)).unwrap().replacen(
            "{\"role\":\"uplink\"",
            "{\"x\":1,\"role\":\"uplink\"",
            1,
        );
        assert!(DecommissionRequest::parse(txt.as_bytes()).is_err());
        let a = DecommissionAnswer {
            format: DECOMMISSION_ANSWER_FORMAT.into(),
            decommission_id: good.decommission_id.clone(),
            request_digest: digest(b"x"),
            workspace: "ws-1".into(),
            robot_id: "ugv-001".into(),
            reason: "transfer".into(),
            keys: good.keys.clone(),
            status: "decommissioned".into(),
            at_ms: 2,
        };
        assert_eq!(
            DecommissionAnswer::parse(&payload_bytes(&a).unwrap()).unwrap(),
            a
        );
        let mut b = a.clone();
        b.status = "retired".into();
        assert!(DecommissionAnswer::parse(&payload_bytes(&b).unwrap()).is_err());
    }

    /// `robodr-uplink --check` authenticates a fleet request with its own
    /// copy of the §2.5 message (robodr-export cannot depend on this
    /// crate): the two must stay byte-identical.
    #[test]
    fn uplink_check_signs_the_same_request_message() {
        for (m, t, k, ts, b) in [
            (
                "GET",
                "/api/robot-edr/v2/fleet/ring",
                "ed25519:0011223344556677",
                1u64,
                &b""[..],
            ),
            (
                "POST",
                "/x",
                "ed25519:aaaaaaaaaaaaaaaa",
                u64::MAX,
                &b"{\"a\":1}"[..],
            ),
        ] {
            assert_eq!(
                request_message(m, t, k, ts, b),
                robodr_export::uplink::check::fleet_request_message(m, t, k, ts, b)
            );
        }
    }

    #[test]
    fn approval_validity_is_capped() {
        let a = |validity: u64| {
            payload_bytes(&Approval {
                format: APPROVAL_FORMAT.into(),
                approval_id: "ap-1".into(),
                workspace: "ws-1".into(),
                robot_id: "ugv-001".into(),
                platform: "ugv-x1".into(),
                profile_digest: format!("sha256:{}", "a".repeat(64)),
                profile_version: 1,
                transition: "enforce".into(),
                approved_by: vec!["op-a".into()],
                issued_at_ms: 1_000,
                expires_at_ms: 1_000 + validity,
            })
            .unwrap()
        };
        Approval::parse(&a(7 * 24 * 3600 * 1000)).unwrap();
        assert!(Approval::parse(&a(7 * 24 * 3600 * 1000 + 1)).is_err());
    }
}
