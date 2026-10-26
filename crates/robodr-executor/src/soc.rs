//! Trust boundary (executor M1): the executor verifies the SOC's approval
//! itself.
//!
//! agentd forwards, with every order that comes from the control plane, the
//! SOC's original `robodr-control-plane/v2` request exactly as it was
//! signed ([`SocRequest`]: method, target, key id, timestamp, nonce,
//! signature and body). Before the executor accepts the order's
//! `human_approved`, it checks with **its own** copy of the SOC public keys
//! (`soc.keys` in the executor configuration, `robodr-blackbox keygen`
//! public key files, the same format agentd reads):
//!
//! 1. the request is well formed and names a configured key
//!    (`soc_signature_invalid`);
//! 2. the Ed25519 signature verifies over the contract's signing message
//!    (`docs/contracts/robodr.control-plane.md` §2) for **this executor's**
//!    robot id, so a request signed for another robot never verifies
//!    (`soc_signature_invalid`);
//! 3. the timestamp is within `soc.max_clock_skew_s` of the executor's wall
//!    clock and not fenced (`soc_request_stale`);
//! 4. the (key, nonce) pair was never seen while the timestamp is in the
//!    window: the executor keeps its **own** replay store,
//!    `<state_dir>/soc_nonces.json`, written atomically (fsync) before the
//!    order goes further, so a replay is refused across restarts
//!    (`soc_nonce_replayed`; a store that cannot record the pair, or is
//!    full of live pairs, refuses: `soc_replay_store_unavailable`). A store
//!    that is missing while the executor's journal exists, or unreadable,
//!    fences every request whose timestamp is not later than the start;
//! 5. the request is `POST /api/v2/robots/<own robot id>/action-requests`
//!    and the order's id, action, target and TTL equal the signed body's
//!    `request_id`, `action`, `parameters` (`participant_guid` / `node`)
//!    and `ttl_seconds`; the origin's key id and `requested_by` equal the
//!    signed ones (`order_mismatch`);
//! 6. the approval evidence the contract requires is present in the signed
//!    body: `authority: "request"`, a `requested_by` (1..=100 characters,
//!    no control characters), a `source` (`[a-z0-9_-]{1,32}`) and a
//!    `reason` of at most 500 characters (`approval_missing`).
//!
//! **Reverts** (review finding F3): an action a SOC approved is lifted only
//! by the SOC's own signed revert request ([`verify_revert`]): the same
//! checks 1-4 (key, signature for this robot, timestamp, the same replay
//! store), the request is `POST /api/v2/robots/<own robot id>/
//! action-requests/<the action's id>/revert`, and its body is the
//! contract's strict revert body (`requested_by`, optional `reason`).
//! agentd forwards it with the revert. Reverts that need no signature:
//! planner actions (never approved by anyone), TTL expiry, restart
//! reconciliation and the operator's `robodr-executor revert-all` (local,
//! root).
//!
//! **Keys** ([`load_keys`]): one key file that cannot be read or is refused
//! refuses every control-plane order (`soc_keys_unavailable`): falling back
//! to the remaining keys would silently change who can approve. A SOC key
//! equal to one of the robot's own keys (`soc.robot_keys`, its black-box /
//! finding signing keys) is refused the same way (review F9 a).
//!
//! Only then is `human_approved` true. An order from the on-robot planner
//! carries no SOC request and can never claim an approval
//! (`approval_missing`), so it is limited to what the response policy
//! allows without one ([`crate::decision::precheck`]).
//!
//! What the executor still takes from agentd: the safety state and the
//! operational context the request was judged in (it has no safety feed of
//! its own; the safety state is re-checked against agentd's live view just
//! before apply) and the participant's locators (re-checked against the
//! motion control path). None of these can widen an approval: they can only
//! make the executor's own rules refuse.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use robodr_blackbox::crypto::{from_hex, sha256, to_hex};
use serde::{Deserialize, Serialize};

use crate::decision::{codes, Refusal};
use crate::net::GuidPrefix;
use crate::order::{Order, Origin, Target};

/// The signature domain (the control plane's API version).
pub const API_VERSION: &str = "robodr-control-plane/v2";
/// Most SOC keys the executor accepts.
pub const MAX_SOC_KEYS: usize = 16;
/// Largest SOC public key file.
pub const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
/// The replay store (in the state directory).
pub const NONCE_FILE: &str = "soc_nonces.json";
pub const NONCE_SCHEMA: &str = "robodr-executor-soc-nonces/v1";
/// Most live (key, nonce) pairs remembered (the control plane's limit).
pub const MAX_NONCES: usize = 8192;
/// Largest signed body (the control plane's limit, §1).
pub const MAX_BODY: usize = 16 * 1024;
/// Longest request target (§1).
pub const MAX_TARGET: usize = 1024;
/// Nonce length bounds (§2).
pub const MIN_NONCE_LEN: usize = 16;
pub const MAX_NONCE_LEN: usize = 128;

/// The SOC's request exactly as it was signed and received by agentd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocRequest {
    pub method: String,
    /// The request target exactly as sent.
    pub target: String,
    pub key_id: String,
    /// Unix seconds (`X-RoboDR-Timestamp`).
    pub timestamp: u64,
    pub nonce: String,
    /// `X-RoboDR-Signature`, 128 hex digits.
    pub signature: String,
    /// The body bytes (valid UTF-8: agentd parsed it as JSON).
    pub body: String,
}

/// A configured SOC public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocKey {
    pub key_id: String,
    pub public: [u8; 32],
}

/// The bytes a SOC signs for one request (contract §2).
pub fn signing_message(
    method: &str,
    target: &str,
    robot_id: &str,
    key_id: &str,
    timestamp: u64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "{API_VERSION}\n{method}\n{target}\n{robot_id}\n{key_id}\n{timestamp}\n{nonce}\n{}",
        to_hex(&sha256(body))
    )
    .into_bytes()
}

impl SocRequest {
    /// Sign a request with an Ed25519 seed (SOC tooling and tests; the
    /// executor itself never holds a SOC secret).
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        seed: &[u8; 32],
        robot_id: &str,
        key_id: &str,
        method: &str,
        target: &str,
        timestamp: u64,
        nonce: &str,
        body: &str,
    ) -> Self {
        let msg = signing_message(
            method,
            target,
            robot_id,
            key_id,
            timestamp,
            nonce,
            body.as_bytes(),
        );
        let sig = robodr_blackbox::sign_ed25519::sign(seed, &msg);
        SocRequest {
            method: method.into(),
            target: target.into(),
            key_id: key_id.into(),
            timestamp,
            nonce: nonce.into(),
            signature: to_hex(&sig),
            body: body.into(),
        }
    }

    fn well_formed(&self) -> Result<Vec<u8>, String> {
        if self.key_id.is_empty()
            || self.key_id.len() > 128
            || !self.key_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err("malformed key id".into());
        }
        if !(MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&self.nonce.len())
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("malformed nonce".into());
        }
        if self.target.is_empty() || self.target.len() > MAX_TARGET {
            return Err("malformed target".into());
        }
        if self.method.is_empty()
            || self.method.len() > 16
            || !self.method.bytes().all(|b| b.is_ascii_uppercase())
        {
            return Err("malformed method".into());
        }
        if self.body.len() > MAX_BODY {
            return Err(format!("body larger than {MAX_BODY} bytes"));
        }
        if self.signature.len() != 128 {
            return Err("signature is not 128 hex digits".into());
        }
        from_hex(&self.signature).ok_or_else(|| "signature is not hex".to_string())
    }
}

/// Load one SOC public key file with the control plane's rules: absolute
/// path, a regular file (not a symlink) owned by root or this process's
/// user, not writable by group or others, a `robodr-blackbox` **public**
/// Ed25519 key file whose `device_id`, if set, is this robot.
pub fn load_key(path: &Path, robot_id: &str) -> Result<SocKey, String> {
    let shown = path.display();
    if !path.is_absolute() {
        return Err(format!("SOC key {shown}: must be an absolute path"));
    }
    let lmeta = std::fs::symlink_metadata(path).map_err(|e| format!("SOC key {shown}: {e}"))?;
    if !lmeta.file_type().is_file() {
        return Err(format!(
            "SOC key {shown}: not a regular file (symlinks are refused)"
        ));
    }
    let f = File::open(path).map_err(|e| format!("SOC key {shown}: {e}"))?;
    let meta = f.metadata().map_err(|e| format!("SOC key {shown}: {e}"))?;
    if meta.ino() != lmeta.ino() || meta.dev() != lmeta.dev() {
        return Err(format!("SOC key {shown}: changed while being opened"));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "SOC key {shown}: mode {mode:03o} lets group/others write it (whoever can write it \
             can approve containment); chmod 644"
        ));
    }
    let euid = robodr_blackbox::keys::effective_uid();
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(format!(
            "SOC key {shown}: owned by uid {}, not by root or the executor's uid {euid}",
            meta.uid()
        ));
    }
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(format!(
            "SOC key {shown}: larger than {MAX_KEY_FILE_BYTES} bytes"
        ));
    }
    let mut text = String::new();
    f.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("SOC key {shown}: {e}"))?;
    let k =
        robodr_blackbox::KeyFile::from_json(&text).map_err(|e| format!("SOC key {shown}: {e}"))?;
    if !k.is_public() {
        return Err(format!(
            "SOC key {shown}: holds secret material; give the SOC's public key file only"
        ));
    }
    if k.algorithm != robodr_blackbox::sign_ed25519::ED25519 {
        return Err(format!("SOC key {shown}: must be an ed25519 key"));
    }
    if let Some(d) = &k.device_id {
        if d != robot_id {
            return Err(format!(
                "SOC key {shown}: bound to device {:?}, not to this robot",
                crate::net::clip(d)
            ));
        }
    }
    let public = k
        .public_key()
        .ok_or_else(|| format!("SOC key {shown}: no public key"))?;
    Ok(SocKey {
        key_id: k.key_id.clone(),
        public,
    })
}

/// Load every configured SOC key (duplicate key ids refuse). Any error
/// refuses them all (module docs).
pub fn load_keys(paths: &[PathBuf], robot_id: &str) -> Result<Vec<SocKey>, String> {
    load_keys_checked(paths, &[], robot_id)
}

/// [`load_keys`], also refusing a SOC key whose public key equals one of
/// the robot's own keys (`robot_keys`, read with the same file rules).
pub fn load_keys_checked(
    paths: &[PathBuf],
    robot_keys: &[PathBuf],
    robot_id: &str,
) -> Result<Vec<SocKey>, String> {
    let mut out: Vec<SocKey> = Vec::new();
    for p in paths {
        let k = load_key(p, robot_id)?;
        if out.iter().any(|o| o.key_id == k.key_id) {
            return Err(format!(
                "SOC key {}: key id {:?} is listed twice",
                p.display(),
                crate::net::clip(&k.key_id)
            ));
        }
        out.push(k);
    }
    for p in robot_keys {
        let own = load_key(p, robot_id).map_err(|e| format!("soc.robot_keys: {e}"))?;
        if let Some(k) = out.iter().find(|k| k.public == own.public) {
            return Err(format!(
                "SOC key {:?} is the robot's own key {} (soc.robot_keys): whoever holds the \
                 robot's key could approve containment",
                crate::net::clip(&k.key_id),
                p.display()
            ));
        }
    }
    Ok(out)
}

/// The signed body, strictly (unknown or duplicate fields refuse, like the
/// control plane's own parser).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBody {
    request_id: String,
    action: String,
    #[serde(default)]
    parameters: Option<SignedParams>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    reason: Option<String>,
    requested_by: String,
    source: String,
    authority: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedParams {
    #[serde(default)]
    max_linear_speed: Option<f64>,
    #[serde(default)]
    max_joint_speed: Option<f64>,
    #[serde(default)]
    workspace_zone: Option<String>,
    #[serde(default)]
    participant_guid: Option<String>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    config: Option<String>,
    #[serde(default)]
    to_version: Option<String>,
}

fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The target of the order an executable request is submitted with.
fn signed_target(action: &str, p: &SignedParams) -> Target {
    if action != "quarantine_node" {
        return Target::None;
    }
    // Exactly as agentd derives it (`executor_link::order_for`).
    match (&p.participant_guid, &p.node) {
        (Some(g), _) => match g.parse::<GuidPrefix>() {
            Ok(guid_prefix) => Target::Participant {
                guid_prefix,
                locators: Vec::new(),
            },
            Err(_) => Target::Node { name: g.clone() },
        },
        (None, Some(n)) => Target::Node { name: n.clone() },
        (None, None) => Target::None,
    }
}

fn same_target(order: &Target, signed: &Target) -> bool {
    match (order, signed) {
        (
            Target::Participant { guid_prefix: a, .. },
            Target::Participant { guid_prefix: b, .. },
        ) => a == b,
        (a, b) => a == b,
    }
}

/// What [`verify`] needs besides the order.
pub struct Context<'a> {
    pub keys: &'a [SocKey],
    pub robot_id: &'a str,
    pub max_skew_s: u64,
    pub now_ms: u64,
}

fn refuse(code: &'static str, why: impl Into<String>) -> Refusal {
    Refusal::new(code, why)
}

/// Verify a control-plane order's SOC request (rules 1-6 of the module
/// docs). `Ok` means a human approved exactly this order.
pub fn verify(order: &Order, cx: &Context<'_>, replay: &mut ReplayStore) -> Result<(), Refusal> {
    let Origin::ControlPlane {
        key_id,
        requested_by,
    } = &order.origin
    else {
        return Err(refuse(
            codes::APPROVAL_MISSING,
            "only a control-plane order carries a SOC approval",
        ));
    };
    let Some(soc) = order.soc.as_deref() else {
        return Err(refuse(
            codes::SOC_SIGNATURE_INVALID,
            "the order claims a SOC request but carries no signed request: the executor accepts \
             an approval only with the SOC's own signature",
        ));
    };
    let sig = soc.well_formed().map_err(|e| {
        refuse(
            codes::SOC_SIGNATURE_INVALID,
            format!("the SOC request is malformed ({e})"),
        )
    })?;
    if cx.keys.is_empty() {
        return Err(refuse(
            codes::SOC_SIGNATURE_INVALID,
            "no SOC key is configured in the executor (soc.keys): no approval can be verified",
        ));
    }
    let Some(key) = cx.keys.iter().find(|k| k.key_id == soc.key_id) else {
        return Err(refuse(
            codes::SOC_SIGNATURE_INVALID,
            format!(
                "key id {:?} is not one of the executor's SOC keys",
                crate::net::clip(&soc.key_id)
            ),
        ));
    };
    let msg = signing_message(
        &soc.method,
        &soc.target,
        cx.robot_id,
        &soc.key_id,
        soc.timestamp,
        &soc.nonce,
        soc.body.as_bytes(),
    );
    if !robodr_blackbox::sign_ed25519::verify(&key.public, &msg, &sig) {
        return Err(refuse(
            codes::SOC_SIGNATURE_INVALID,
            format!(
                "the SOC signature does not verify for robot {} with key {:?} over this request \
                 and body",
                cx.robot_id,
                crate::net::clip(&soc.key_id)
            ),
        ));
    }
    let now_s = cx.now_ms / 1000;
    if soc.timestamp.abs_diff(now_s) > cx.max_skew_s {
        return Err(refuse(
            codes::SOC_REQUEST_STALE,
            format!(
                "the SOC request was signed at {} (Unix s), the executor's clock reads {now_s}: \
                 outside the {} s window",
                soc.timestamp, cx.max_skew_s
            ),
        ));
    }
    replay.check(&soc.key_id, &soc.nonce, soc.timestamp, now_s, cx.max_skew_s)?;
    // The request is the SOC's; now it must be this order.
    let want = format!("/api/v2/robots/{}/action-requests", cx.robot_id);
    if soc.method != "POST" || pct_decode(&soc.target).as_deref() != Some(want.as_str()) {
        return Err(refuse(
            codes::ORDER_MISMATCH,
            format!(
                "the signed request is {} {:?}, not an action request to this robot ({want})",
                crate::net::clip(&soc.method),
                crate::net::clip(&soc.target)
            ),
        ));
    }
    if &soc.key_id != key_id {
        return Err(refuse(
            codes::ORDER_MISMATCH,
            "the order's origin names another SOC key than the signed request",
        ));
    }
    let body: SignedBody = serde_json::from_str(&soc.body).map_err(|e| {
        refuse(
            codes::ORDER_MISMATCH,
            format!("the signed body is not a strict action request: {e}"),
        )
    })?;
    // Approval evidence (contract §4).
    if body.authority != "request" {
        return Err(refuse(
            codes::APPROVAL_MISSING,
            "the signed body's authority is not \"request\"",
        ));
    }
    let rb_ok = !body.requested_by.is_empty()
        && body.requested_by.chars().count() <= 100
        && !body.requested_by.chars().any(char::is_control);
    let src_ok = !body.source.is_empty()
        && body.source.len() <= 32
        && body
            .source
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    let reason_ok = body
        .reason
        .as_deref()
        .is_none_or(|r| r.chars().count() <= 500 && !r.chars().any(char::is_control));
    if !rb_ok || !src_ok || !reason_ok {
        return Err(refuse(
            codes::APPROVAL_MISSING,
            "the signed body lacks the approval evidence the contract requires (requested_by \
             1..=100 characters, source [a-z0-9_-]{1,32}, reason <= 500 characters)",
        ));
    }
    if &body.requested_by != requested_by {
        return Err(refuse(
            codes::ORDER_MISMATCH,
            "the order's requested_by differs from the signed request's",
        ));
    }
    let params = body.parameters.unwrap_or_default();
    let _ = (
        params.max_linear_speed,
        params.max_joint_speed,
        &params.workspace_zone,
        &params.config,
        &params.to_version,
    );
    let mismatch = if body.request_id != order.id {
        Some("request_id")
    } else if body.action != order.action.as_str() {
        Some("action")
    } else if body.ttl_seconds != order.ttl_s {
        Some("ttl_seconds")
    } else if !same_target(&order.target, &signed_target(&body.action, &params)) {
        Some("target")
    } else {
        None
    };
    if let Some(field) = mismatch {
        return Err(refuse(
            codes::ORDER_MISMATCH,
            format!("the order's {field} differs from the signed request's: not executed"),
        ));
    }
    Ok(())
}

/// The strict revert body (contract §6: `{"reason"?, "requested_by"}`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRevert {
    #[serde(default)]
    reason: Option<String>,
    requested_by: String,
}

/// Verify the SOC's signed revert request for action `id` (module docs,
/// F3). `Ok` means a SOC key holder asked for exactly this revert.
pub fn verify_revert(
    id: &str,
    soc: Option<&SocRequest>,
    cx: &Context<'_>,
    replay: &mut ReplayStore,
) -> Result<(), Refusal> {
    let Some(soc) = soc else {
        return Err(refuse(
            codes::SOC_SIGNATURE_INVALID,
            "the action was approved by the SOC: only the SOC's signed revert request lifts it \
             (none was forwarded)",
        ));
    };
    let sig = soc.well_formed().map_err(|e| {
        refuse(
            codes::SOC_SIGNATURE_INVALID,
            format!("the SOC revert request is malformed ({e})"),
        )
    })?;
    if cx.keys.is_empty() {
        return Err(refuse(
            codes::SOC_SIGNATURE_INVALID,
            "no SOC key is configured in the executor (soc.keys): no revert can be verified",
        ));
    }
    let Some(key) = cx.keys.iter().find(|k| k.key_id == soc.key_id) else {
        return Err(refuse(
            codes::SOC_SIGNATURE_INVALID,
            format!(
                "key id {:?} is not one of the executor's SOC keys",
                crate::net::clip(&soc.key_id)
            ),
        ));
    };
    let msg = signing_message(
        &soc.method,
        &soc.target,
        cx.robot_id,
        &soc.key_id,
        soc.timestamp,
        &soc.nonce,
        soc.body.as_bytes(),
    );
    if !robodr_blackbox::sign_ed25519::verify(&key.public, &msg, &sig) {
        return Err(refuse(
            codes::SOC_SIGNATURE_INVALID,
            format!(
                "the SOC revert signature does not verify for robot {}",
                cx.robot_id
            ),
        ));
    }
    let now_s = cx.now_ms / 1000;
    if soc.timestamp.abs_diff(now_s) > cx.max_skew_s {
        return Err(refuse(
            codes::SOC_REQUEST_STALE,
            format!(
                "the SOC revert was signed at {} (Unix s), the executor's clock reads {now_s}: \
                 outside the {} s window",
                soc.timestamp, cx.max_skew_s
            ),
        ));
    }
    let want = format!("/api/v2/robots/{}/action-requests/{id}/revert", cx.robot_id);
    if soc.method != "POST" || pct_decode(&soc.target).as_deref() != Some(want.as_str()) {
        return Err(refuse(
            codes::ORDER_MISMATCH,
            format!(
                "the signed request is {} {:?}, not the revert of this action ({want})",
                crate::net::clip(&soc.method),
                crate::net::clip(&soc.target)
            ),
        ));
    }
    let body: SignedRevert = serde_json::from_str(&soc.body).map_err(|e| {
        refuse(
            codes::ORDER_MISMATCH,
            format!("the signed body is not a strict revert request: {e}"),
        )
    })?;
    let rb_ok = !body.requested_by.is_empty()
        && body.requested_by.chars().count() <= 100
        && !body.requested_by.chars().any(char::is_control);
    let reason_ok = body
        .reason
        .as_deref()
        .is_none_or(|r| r.chars().count() <= 500 && !r.chars().any(char::is_control));
    if !rb_ok || !reason_ok {
        return Err(refuse(
            codes::APPROVAL_MISSING,
            "the signed revert lacks a valid requested_by (1..=100 characters) or has an \
             invalid reason",
        ));
    }
    // Last, so a refused request does not burn its nonce.
    replay.check(&soc.key_id, &soc.nonce, soc.timestamp, now_s, cx.max_skew_s)
}

/// One persisted (key, nonce) pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonceEntry {
    key_id: String,
    nonce: String,
    /// Unix second after which the pair is dead.
    dead_after: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonceFile {
    schema: String,
    #[serde(default)]
    fence_s: Option<u64>,
    entries: Vec<NonceEntry>,
}

/// The executor's own SOC replay store (`<state_dir>/soc_nonces.json`).
#[derive(Debug)]
pub struct ReplayStore {
    dir: PathBuf,
    seen: BTreeMap<(String, String), u64>,
    /// Timestamps `<=` this are refused (the store could not be trusted at
    /// start).
    fence_s: Option<u64>,
    /// Why the store was fenced at start (reported once as an event).
    pub fenced_because: Option<String>,
}

impl ReplayStore {
    /// Open the store in `dir`. `state_existed`: the executor's journal is
    /// there, so a missing store was removed (fence). A damaged store
    /// fences too. Never fails: a store that cannot be read or written
    /// refuses requests later, it does not stop the executor (reverts and
    /// TTL expiry must keep working).
    ///
    /// The fence is `now_s + skew_s` (review finding F8): a request signed
    /// up to `skew_s` ahead of the clock was inside the window before the
    /// start and may have been presented to the lost store.
    pub fn open(dir: &Path, now_s: u64, skew_s: u64, state_existed: bool) -> Self {
        let fence_at = now_s.saturating_add(skew_s);
        let mut s = ReplayStore {
            dir: dir.to_path_buf(),
            seen: BTreeMap::new(),
            fence_s: None,
            fenced_because: None,
        };
        let p = s.path();
        match crate::config::read_small(&p) {
            Ok(text) => match serde_json::from_str::<NonceFile>(&text) {
                Ok(f) if f.schema == NONCE_SCHEMA => {
                    s.fence_s = f.fence_s;
                    for e in f.entries {
                        if e.dead_after >= now_s {
                            s.seen.insert((e.key_id, e.nonce), e.dead_after);
                        }
                    }
                }
                Ok(_) => s.fence(fence_at, format!("{NONCE_FILE}: unknown schema")),
                Err(e) => s.fence(fence_at, format!("{NONCE_FILE}: {e}")),
            },
            Err(_) if !p.exists() => {
                if state_existed {
                    s.fence(
                        fence_at,
                        format!("{NONCE_FILE} is missing while the executor's journal exists"),
                    );
                }
            }
            Err(e) => s.fence(fence_at, e),
        }
        // Start from a compact file (an error here is retried on the next
        // insert, which refuses if it fails again).
        let _ = s.save();
        s
    }

    fn fence(&mut self, now_s: u64, why: String) {
        self.fence_s = Some(self.fence_s.map_or(now_s, |f| f.max(now_s)));
        self.fenced_because = Some(why);
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(NONCE_FILE)
    }

    pub fn fence_s(&self) -> Option<u64> {
        self.fence_s
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn save(&self) -> Result<(), String> {
        let f = NonceFile {
            schema: NONCE_SCHEMA.into(),
            fence_s: self.fence_s,
            entries: self
                .seen
                .iter()
                .map(|((k, n), d)| NonceEntry {
                    key_id: k.clone(),
                    nonce: n.clone(),
                    dead_after: *d,
                })
                .collect(),
        };
        let data = serde_json::to_vec(&f).map_err(|e| e.to_string())?;
        let tmp = self.dir.join(format!("{NONCE_FILE}.tmp"));
        let res = (|| -> std::io::Result<()> {
            let mut fh = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            fh.write_all(&data)?;
            fh.sync_all()?;
            drop(fh);
            std::fs::rename(&tmp, self.path())?;
            File::open(&self.dir)?.sync_all()
        })();
        res.map_err(|e| format!("{}: {e}", self.path().display()))
    }

    /// Check the fence and the pair, and make the pair durable before `Ok`.
    pub fn check(
        &mut self,
        key_id: &str,
        nonce: &str,
        timestamp: u64,
        now_s: u64,
        skew_s: u64,
    ) -> Result<(), Refusal> {
        if self.fence_s.is_some_and(|f| timestamp <= f) {
            return Err(refuse(
                codes::SOC_REQUEST_STALE,
                "signed before the executor started with an untrusted SOC replay store: the SOC \
                 must sign the request again",
            ));
        }
        let k = (key_id.to_string(), nonce.to_string());
        if self.seen.get(&k).is_some_and(|d| *d >= now_s) {
            return Err(refuse(
                codes::SOC_NONCE_REPLAYED,
                "this SOC request (key, nonce) was already presented to the executor",
            ));
        }
        self.seen.retain(|_, d| *d >= now_s);
        if self.seen.len() >= MAX_NONCES {
            return Err(refuse(
                codes::SOC_REPLAY_STORE_UNAVAILABLE,
                "the executor's SOC replay store is full of live requests: retry later",
            ));
        }
        self.seen
            .insert(k.clone(), timestamp.saturating_add(skew_s).max(now_s));
        if let Err(e) = self.save() {
            self.seen.remove(&k);
            return Err(refuse(
                codes::SOC_REPLAY_STORE_UNAVAILABLE,
                format!("the SOC request could not be recorded against replay ({e})"),
            ));
        }
        Ok(())
    }
}

/// Test and tooling support: a signed body for an order (what a SOC would
/// send for it) and the order with that request attached.
pub mod testing {
    use super::*;

    /// The action-request body a SOC would sign for `order`.
    pub fn body_for(order: &Order) -> String {
        let requested_by = match &order.origin {
            Origin::ControlPlane { requested_by, .. } => requested_by.clone(),
            Origin::Planner { .. } => "planner".into(),
        };
        let mut params = serde_json::Map::new();
        match &order.target {
            Target::Participant { guid_prefix, .. } => {
                params.insert("participant_guid".into(), guid_prefix.to_hex().into());
            }
            Target::Node { name } => {
                params.insert("node".into(), name.clone().into());
            }
            _ => {}
        }
        if order.action == robodr_responder::ActionId::RestrictMotion {
            params.insert("max_linear_speed".into(), 0.5.into());
        }
        let mut v = serde_json::json!({
            "request_id": order.id,
            "action": order.action.as_str(),
            "parameters": params,
            "reason": "test",
            "requested_by": requested_by,
            "source": "soc-test",
            "authority": "request",
        });
        if let Some(t) = order.ttl_s {
            v["ttl_seconds"] = t.into();
        }
        v.to_string()
    }

    /// Attach a SOC request signed with `seed` for `robot_id`, timestamp
    /// `ts_s` and `nonce`.
    pub fn sign_order(
        mut order: Order,
        seed: &[u8; 32],
        robot_id: &str,
        ts_s: u64,
        nonce: &str,
    ) -> Order {
        let key_id = match &order.origin {
            Origin::ControlPlane { key_id, .. } => key_id.clone(),
            Origin::Planner { .. } => "none".into(),
        };
        let body = body_for(&order);
        order.soc = Some(Box::new(SocRequest::sign(
            seed,
            robot_id,
            &key_id,
            "POST",
            &format!("/api/v2/robots/{robot_id}/action-requests"),
            ts_s,
            nonce,
            &body,
        )));
        order
    }

    /// A public key file (JSON text) for `seed`.
    pub fn public_key_json(seed: &[u8; 32], key_id: &str) -> String {
        let pk = robodr_blackbox::sign_ed25519::public_key_from_seed(seed);
        robodr_blackbox::KeyFile::ed25519_public(&pk, Some(key_id))
            .map(|k| k.to_json())
            .unwrap_or_default()
    }
}
