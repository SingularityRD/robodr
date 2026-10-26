//! Reference SOC of `docs/contracts/robodr.fleet-api.md` (§3–§8): the
//! processing rules as the contract states them, in memory. Used by the
//! integration tests (behind an in-process HTTPS server or directly as a
//! `SocTransport`) and by the contract-vector generator, so the expected
//! responses in `docs/contracts/fixtures/fleet/` are what this text
//! requires. The AutoSecOps implementation is tested against the vectors.
#![allow(dead_code)]

use robodr_blackbox::crypto::{from_hex, to_hex};
use robodr_blackbox::sign_ed25519::PUBLIC_KEY_LEN;
use robodr_blackbox::{Ed25519SigningKey, Signer};
use robodr_fleet::client::{HttpResponse, SocTransport, TransportError};
use robodr_fleet::wire::{
    self, Approval, CancelRequest, EnrollAnswer, EnrollRequest, Envelope, KeyAnswer, KeyRef,
    RetireRequest, RingInfo, RotateRequest, TokenPayload,
};
use std::collections::BTreeMap;

pub const BASE: &str = "/api";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRec {
    pub robot: String,
    pub role: String,
    pub public: [u8; PUBLIC_KEY_LEN],
    pub fingerprint: String,
    /// `None`: active; `Some(t)`: retired / revoked at `t`.
    pub retired_at: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TokenRec {
    pub payload: TokenPayload,
    /// (request digest, stored answer body) once consumed.
    pub consumed: Option<(String, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct RotationRec {
    pub robot: String,
    pub role: String,
    pub old_key_id: String,
    pub new_key_id: String,
    pub request_digest: String,
    pub answer: Vec<u8>,
    /// (retire request digest, stored answer) once retired.
    pub retired: Option<(String, Vec<u8>)>,
    /// (cancel request digest, stored answer) once cancelled (§5.5).
    pub cancelled: Option<(String, Vec<u8>)>,
}

impl RotationRec {
    /// Still open: neither retired nor cancelled.
    pub fn open(&self) -> bool {
        self.retired.is_none() && self.cancelled.is_none()
    }
}

pub struct Soc {
    /// The online fleet key (tokens, answers, ring information).
    pub soc_key: Ed25519SigningKey,
    /// The approval key (profile approvals only; §6.3).
    pub approval_key: Ed25519SigningKey,
    pub workspace: String,
    pub now_ms: u64,
    pub tokens: BTreeMap<String, TokenRec>,
    pub keys: BTreeMap<String, KeyRec>,
    pub robots: BTreeMap<String, Option<String>>,
    pub rotations: BTreeMap<String, RotationRec>,
    pub revocations: BTreeMap<String, Vec<u8>>,
    pub offers: BTreeMap<String, Vec<u8>>,
    pub approvals: BTreeMap<String, Vec<u8>>,
    pub rings: BTreeMap<String, Vec<u8>>,
    pub drafts: Vec<(String, Vec<u8>)>,
    /// Every request seen: (method, target).
    pub log: Vec<(String, String)>,
}

pub struct Resp {
    pub status: u16,
    pub body: Vec<u8>,
}

fn e(status: u16, code: &str, detail: &str) -> Resp {
    Resp {
        status,
        body: serde_json::to_vec(&serde_json::json!({"code": code, "detail": detail})).unwrap(),
    }
}

fn ok(body: Vec<u8>) -> Resp {
    Resp { status: 200, body }
}

pub fn header<'a>(h: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    h.iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

impl Soc {
    pub fn new(
        soc_key: Ed25519SigningKey,
        approval_key: Ed25519SigningKey,
        workspace: &str,
        now_ms: u64,
    ) -> Self {
        Self {
            soc_key,
            approval_key,
            workspace: workspace.into(),
            now_ms,
            tokens: BTreeMap::new(),
            keys: BTreeMap::new(),
            robots: BTreeMap::new(),
            rotations: BTreeMap::new(),
            revocations: BTreeMap::new(),
            offers: BTreeMap::new(),
            approvals: BTreeMap::new(),
            rings: BTreeMap::new(),
            drafts: Vec::new(),
            log: Vec::new(),
        }
    }

    pub fn soc_key_id(&self) -> String {
        self.soc_key.key_id().to_string()
    }

    /// Issue a token (§3.1) with a nonce derived from `seed` (vectors) .
    pub fn issue_token(
        &mut self,
        token_id: &str,
        robot: &str,
        site: Option<&str>,
        validity_ms: u64,
        nonce: [u8; 32],
    ) -> String {
        self.issue_token_for(
            token_id,
            &self.workspace.clone(),
            robot,
            site,
            validity_ms,
            nonce,
        )
    }

    pub fn issue_token_for(
        &mut self,
        token_id: &str,
        workspace: &str,
        robot: &str,
        site: Option<&str>,
        validity_ms: u64,
        nonce: [u8; 32],
    ) -> String {
        let p = TokenPayload {
            format: wire::TOKEN_FORMAT.into(),
            token_id: token_id.into(),
            workspace: workspace.into(),
            robot_id: robot.into(),
            site: site.map(str::to_string),
            soc_key_id: self.soc_key_id(),
            issued_at_ms: self.now_ms,
            expires_at_ms: self.now_ms + validity_ms,
            nonce: to_hex(&nonce),
        };
        self.tokens.insert(
            token_id.into(),
            TokenRec {
                payload: p.clone(),
                consumed: None,
            },
        );
        wire::Token::issue(&p, &self.soc_key)
    }

    /// Register a token this SOC issued earlier (vectors: the token file).
    pub fn register_token(&mut self, token: &str) {
        let t = wire::Token::parse(token).expect("token");
        t.verify(&self.soc_key.public_key())
            .expect("issued by this SOC");
        self.tokens.insert(
            t.payload.token_id.clone(),
            TokenRec {
                payload: t.payload,
                consumed: None,
            },
        );
    }

    pub fn active_key(&self, robot: &str, role: &str) -> Vec<&String> {
        self.keys
            .iter()
            .filter(|(_, k)| k.robot == robot && k.role == role && k.retired_at.is_none())
            .map(|(id, _)| id)
            .collect()
    }

    fn sign(&self, kind: &str, payload: &[u8]) -> Vec<u8> {
        Envelope::sign(kind, payload, &[&self.soc_key]).to_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn approval(
        &mut self,
        approval_id: &str,
        robot: &str,
        platform: &str,
        digest: &str,
        version: u64,
        approvers: &[&str],
        validity_ms: u64,
    ) -> Vec<u8> {
        let a = Approval {
            format: wire::APPROVAL_FORMAT.into(),
            approval_id: approval_id.into(),
            workspace: self.workspace.clone(),
            robot_id: robot.into(),
            platform: platform.into(),
            profile_digest: digest.into(),
            profile_version: version,
            transition: "enforce".into(),
            approved_by: approvers.iter().map(|s| s.to_string()).collect(),
            issued_at_ms: self.now_ms,
            expires_at_ms: self.now_ms + validity_ms,
        };
        let env = Envelope::sign(
            wire::T_APPROVAL,
            &wire::payload_bytes(&a),
            &[&self.approval_key],
        )
        .to_bytes();
        self.approvals
            .insert(digest.trim_start_matches("sha256:").into(), env.clone());
        env
    }

    pub fn ring(&mut self, robot: &str, serial: u64, ring: u8, target: Option<&str>) -> Vec<u8> {
        self.ring_with_min(robot, serial, ring, target, None)
    }

    pub fn ring_with_min(
        &mut self,
        robot: &str,
        serial: u64,
        ring: u8,
        target: Option<&str>,
        min_version: Option<&str>,
    ) -> Vec<u8> {
        let r = RingInfo {
            format: wire::RING_FORMAT.into(),
            serial,
            workspace: self.workspace.clone(),
            robot_id: robot.into(),
            ring,
            target_version: target.map(str::to_string),
            bundle_sha256: target.map(|_| "ab".repeat(32)),
            min_version: min_version.map(str::to_string),
            issued_at_ms: self.now_ms,
            expires_at_ms: self.now_ms + 86_400_000,
        };
        let env = self.sign(wire::T_RING, &wire::payload_bytes(&r));
        self.rings.insert(robot.into(), env.clone());
        env
    }

    pub fn offer(&mut self, robot: &str, version: u64, profile: &[u8], sig: &[u8]) {
        let o = wire::Offer {
            format: wire::OFFER_FORMAT.into(),
            profile_version: version,
            digest: wire::digest(profile),
            profile: robodr_fleet::b64::encode(profile),
            sig: robodr_fleet::b64::encode(sig),
        };
        self.offers
            .insert(robot.into(), serde_json::to_vec(&o).unwrap());
    }

    /// Process one request (`target` without the base path).
    pub fn handle(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Resp {
        self.log.push((method.into(), target.into()));
        let post = |p: &str| method == "POST" && target == p;
        if post(wire::PATH_ENROLL) {
            return self.enroll(headers, body);
        }
        if post(wire::PATH_ROTATE)
            || post(wire::PATH_RETIRE)
            || post(wire::PATH_CANCEL)
            || post(wire::PATH_PROFILE_DRAFTS)
        {
            if let Err(r) = check_json(
                headers,
                body,
                if post(wire::PATH_PROFILE_DRAFTS) {
                    8 << 20
                } else {
                    64 << 10
                },
            ) {
                return r;
            }
            let (robot, auth_key) = match self.auth(method, target, headers, body) {
                Ok(r) => r,
                Err(r) => return r,
            };
            return if post(wire::PATH_ROTATE) {
                self.rotate(&robot, &auth_key, body)
            } else if post(wire::PATH_RETIRE) {
                self.retire(&robot, &auth_key, body)
            } else if post(wire::PATH_CANCEL) {
                self.cancel(&robot, &auth_key, body)
            } else {
                self.draft(&robot, body)
            };
        }
        if method == "GET" {
            let robot = match self.auth(method, target, headers, body) {
                Ok((r, _)) => r,
                Err(r) => return r,
            };
            if target == wire::PATH_PROFILE_CURRENT {
                return match self.offers.get(&robot) {
                    Some(b) => ok(b.clone()),
                    None => e(404, "no_profile", "no profile published for this robot"),
                };
            }
            if target == wire::PATH_RING {
                return match self.rings.get(&robot) {
                    Some(b) => ok(b.clone()),
                    None => e(404, "no_ring", "no ring assigned"),
                };
            }
            if let Some(p) = target.strip_prefix(&format!("{}/", wire::PATH_REVOCATIONS)) {
                return match self.revocations.get(p) {
                    Some(b) => ok(b.clone()),
                    None => e(404, "no_list", "no revocation list for this platform"),
                };
            }
            if let Some(h) = target.strip_prefix(&format!("{}/", wire::PATH_PROFILE_APPROVALS)) {
                return match self.approvals.get(h) {
                    Some(b) => ok(b.clone()),
                    None => e(404, "no_approval", "no approval for this digest"),
                };
            }
        }
        e(404, "not_found", "no such endpoint")
    }

    /// §2.5 request authentication; returns the robot and the key id that
    /// authenticated the request.
    fn auth(
        &self,
        method: &str,
        target: &str,
        h: &[(String, String)],
        body: &[u8],
    ) -> Result<(String, String), Resp> {
        let one = |n: &str| -> Result<&str, Resp> {
            match header(h, n).as_slice() {
                [v] => Ok(v),
                _ => Err(e(400, "bad_header", &format!("{n} missing or repeated"))),
            }
        };
        let key_id = one("X-RoboDR-Key-Id")?;
        let ts = one("X-RoboDR-Timestamp")?;
        let sig = one("X-RoboDR-Signature")?;
        if !wire::is_key_id(key_id) {
            return Err(e(400, "bad_header", "X-RoboDR-Key-Id"));
        }
        let ts_ok = !ts.is_empty()
            && ts.len() <= 20
            && ts.bytes().all(|b| b.is_ascii_digit())
            && (ts == "0" || !ts.starts_with('0'));
        let Some(ts) = ts_ok.then(|| ts.parse::<u64>().ok()).flatten() else {
            return Err(e(400, "bad_header", "X-RoboDR-Timestamp"));
        };
        if sig.len() != 128 || !sig.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(e(400, "bad_header", "X-RoboDR-Signature"));
        }
        let Some(k) = self
            .keys
            .get(key_id)
            .filter(|k| k.role == "uplink" && k.retired_at.is_none())
        else {
            return Err(e(401, "unknown_key", "not an active uplink key"));
        };
        if self.now_ms.abs_diff(ts) > wire::MAX_SKEW_MS {
            return Err(e(401, "stale_timestamp", "clock skew"));
        }
        let msg = wire::request_message(method, &format!("{BASE}{target}"), key_id, ts, body);
        if !wire::verify_hex(&k.public, &msg, sig) {
            return Err(e(401, "bad_signature", "request signature"));
        }
        Ok((k.robot.clone(), key_id.to_string()))
    }

    fn enroll(&mut self, h: &[(String, String)], body: &[u8]) -> Resp {
        if let Err(r) = check_json(h, body, wire::MAX_ENVELOPE_BYTES) {
            return r;
        }
        let o = match Envelope::parse(body, wire::T_ENROLL_REQUEST) {
            Ok(o) => o,
            Err(x) => return e(400, "bad_request", &x.0),
        };
        let req = match EnrollRequest::parse(&o.payload) {
            Ok(r) => r,
            Err(x) => return e(400, "bad_request", &x.0),
        };
        let mac = o.envelope.mac.as_ref().expect("parse requires mac");
        if mac.token_id != req.token_id {
            return e(
                400,
                "bad_request",
                "mac.token_id differs from the request's token_id",
            );
        }
        let Some(tok) = self.tokens.get(&req.token_id).cloned() else {
            return e(401, "bad_token", "unknown token");
        };
        let nonce: [u8; 32] = from_hex(&tok.payload.nonce).unwrap().try_into().unwrap();
        if o.verify_mac(&nonce).is_err() {
            return e(401, "bad_token", "token mac");
        }
        // Proof of possession of every key: signed by the request's
        // uplink, finding and blackbox keys, in that order, nothing else.
        let ids: Vec<&str> = req.keys.iter().map(|k| k.key_id.as_str()).collect();
        let all_verify = req.keys.iter().all(|k| {
            let pk: [u8; 32] = from_hex(&k.public_hex).unwrap().try_into().unwrap();
            o.verify_by(&k.key_id, &pk).is_ok()
        });
        if o.signers() != ids || !all_verify {
            return e(
                401,
                "bad_signature",
                "must be signed by the request's uplink, finding and blackbox keys, in that order",
            );
        }
        let digest = o.payload_digest();
        if let Some((d, ans)) = &tok.consumed {
            return if *d == digest {
                ok(ans.clone())
            } else {
                e(
                    409,
                    "token_used",
                    "token already consumed by another request",
                )
            };
        }
        if self.now_ms > tok.payload.expires_at_ms {
            return e(410, "token_expired", "token expired");
        }
        if req.workspace != tok.payload.workspace {
            return e(
                403,
                "workspace_mismatch",
                "request names another workspace than its token",
            );
        }
        if req.robot_id != tok.payload.robot_id || req.site != tok.payload.site {
            return e(
                403,
                "robot_mismatch",
                "request names another robot or site than its token",
            );
        }
        for k in &req.keys {
            if self.keys.contains_key(&k.key_id)
                || self.keys.values().any(|r| r.fingerprint == k.fingerprint)
            {
                return e(409, "key_conflict", "a key is already registered");
            }
        }
        // Re-enrollment replaces every key the robot had.
        for k in self.keys.values_mut() {
            if k.robot == req.robot_id && k.retired_at.is_none() {
                k.retired_at = Some(self.now_ms);
            }
        }
        for k in &req.keys {
            self.keys.insert(
                k.key_id.clone(),
                KeyRec {
                    robot: req.robot_id.clone(),
                    role: k.role.clone(),
                    public: from_hex(&k.public_hex).unwrap().try_into().unwrap(),
                    fingerprint: k.fingerprint.clone(),
                    retired_at: None,
                },
            );
        }
        self.robots.insert(req.robot_id.clone(), req.site.clone());
        let a = EnrollAnswer {
            format: wire::ENROLL_ANSWER_FORMAT.into(),
            request_id: req.request_id.clone(),
            request_digest: digest.clone(),
            token_id: req.token_id.clone(),
            workspace: req.workspace.clone(),
            robot_id: req.robot_id.clone(),
            site: req.site.clone(),
            keys: req
                .keys
                .iter()
                .map(|k| KeyRef {
                    role: k.role.clone(),
                    key_id: k.key_id.clone(),
                    fingerprint: k.fingerprint.clone(),
                })
                .collect(),
            enrolled_at_ms: self.now_ms,
        };
        let ans = self.sign(wire::T_ENROLL_ANSWER, &wire::payload_bytes(&a));
        self.tokens.get_mut(&req.token_id).unwrap().consumed = Some((digest, ans.clone()));
        ok(ans)
    }

    fn rotate(&mut self, robot: &str, auth_key: &str, body: &[u8]) -> Resp {
        let o = match Envelope::parse(body, wire::T_ROTATE_REQUEST) {
            Ok(o) => o,
            Err(x) => return e(400, "bad_request", &x.0),
        };
        let r = match RotateRequest::parse(&o.payload) {
            Ok(r) => r,
            Err(x) => return e(400, "bad_request", &x.0),
        };
        if r.workspace != self.workspace || r.robot_id != robot {
            return e(
                403,
                "robot_mismatch",
                "rotation for another robot or workspace",
            );
        }
        if r.role == "uplink" && auth_key != r.old_key_id {
            return e(
                401,
                "wrong_key",
                "an uplink rotation is authenticated by its old uplink key",
            );
        }
        let digest = o.payload_digest();
        if let Some(rec) = self.rotations.get(&r.rotation_id) {
            if rec.cancelled.is_some() {
                return e(409, "rotation_cancelled", "this rotation was cancelled");
            }
            return if rec.request_digest == digest {
                ok(rec.answer.clone())
            } else {
                e(
                    409,
                    "rotation_id_reuse",
                    "rotation id known with another request",
                )
            };
        }
        let Some(old) = self.keys.get(&r.old_key_id).filter(|k| {
            k.robot == robot
                && k.role == r.role
                && k.retired_at.is_none()
                && k.fingerprint == r.old_fingerprint
        }) else {
            return e(
                409,
                "stale_key",
                "old key is not this robot's active key of that role",
            );
        };
        let new_pk: [u8; 32] = from_hex(&r.new_public_hex).unwrap().try_into().unwrap();
        if o.signers() != [r.old_key_id.as_str(), r.new_key_id.as_str()]
            || o.verify_by(&r.old_key_id, &old.public).is_err()
            || o.verify_by(&r.new_key_id, &new_pk).is_err()
        {
            return e(
                401,
                "bad_signature",
                "must be signed by the old key, then the new key",
            );
        }
        if self
            .rotations
            .values()
            .any(|x| x.robot == robot && x.role == r.role && x.open())
        {
            return e(
                409,
                "rotation_in_progress",
                "another rotation of this role is open",
            );
        }
        if self.keys.contains_key(&r.new_key_id)
            || self
                .keys
                .values()
                .any(|k| k.fingerprint == r.new_fingerprint)
        {
            return e(409, "key_conflict", "the new key is already registered");
        }
        self.keys.insert(
            r.new_key_id.clone(),
            KeyRec {
                robot: robot.into(),
                role: r.role.clone(),
                public: new_pk,
                fingerprint: r.new_fingerprint.clone(),
                retired_at: None,
            },
        );
        let a = KeyAnswer {
            format: wire::ROTATE_ANSWER_FORMAT.into(),
            rotation_id: r.rotation_id.clone(),
            request_digest: digest.clone(),
            workspace: r.workspace.clone(),
            robot_id: robot.into(),
            role: r.role.clone(),
            old_key_id: r.old_key_id.clone(),
            new_key_id: r.new_key_id.clone(),
            status: "overlap".into(),
            at_ms: self.now_ms,
        };
        let ans = self.sign(wire::T_ROTATE_ANSWER, &wire::payload_bytes(&a));
        self.rotations.insert(
            r.rotation_id.clone(),
            RotationRec {
                robot: robot.into(),
                role: r.role,
                old_key_id: r.old_key_id,
                new_key_id: r.new_key_id,
                request_digest: digest,
                answer: ans.clone(),
                retired: None,
                cancelled: None,
            },
        );
        ok(ans)
    }

    fn retire(&mut self, robot: &str, auth_key: &str, body: &[u8]) -> Resp {
        let o = match Envelope::parse(body, wire::T_RETIRE_REQUEST) {
            Ok(o) => o,
            Err(x) => return e(400, "bad_request", &x.0),
        };
        let r = match RetireRequest::parse(&o.payload) {
            Ok(r) => r,
            Err(x) => return e(400, "bad_request", &x.0),
        };
        let Some(rec) = self.rotations.get(&r.rotation_id).cloned() else {
            return e(404, "unknown_rotation", "no such rotation");
        };
        if rec.robot != robot || r.robot_id != robot || r.workspace != self.workspace {
            return e(403, "robot_mismatch", "rotation of another robot");
        }
        if r.role != rec.role || r.old_key_id != rec.old_key_id || r.new_key_id != rec.new_key_id {
            return e(
                400,
                "bad_request",
                "retire request does not match the rotation",
            );
        }
        if r.role == "uplink" && auth_key != r.new_key_id {
            return e(
                401,
                "wrong_key",
                "an uplink retirement is authenticated by the new uplink key",
            );
        }
        if rec.cancelled.is_some() {
            return e(409, "rotation_cancelled", "this rotation was cancelled");
        }
        let new_pk = self.keys[&r.new_key_id].public;
        if o.signers() != [r.new_key_id.as_str()] || o.verify_by(&r.new_key_id, &new_pk).is_err() {
            return e(401, "bad_signature", "must be signed by the new key");
        }
        let digest = o.payload_digest();
        if let Some((d, ans)) = &rec.retired {
            return if *d == digest {
                ok(ans.clone())
            } else {
                e(
                    409,
                    "already_retired",
                    "rotation already retired by another request",
                )
            };
        }
        self.keys.get_mut(&r.old_key_id).unwrap().retired_at = Some(self.now_ms);
        let a = KeyAnswer {
            format: wire::RETIRE_ANSWER_FORMAT.into(),
            rotation_id: r.rotation_id.clone(),
            request_digest: digest.clone(),
            workspace: r.workspace.clone(),
            robot_id: robot.into(),
            role: r.role.clone(),
            old_key_id: r.old_key_id.clone(),
            new_key_id: r.new_key_id.clone(),
            status: "retired".into(),
            at_ms: self.now_ms,
        };
        let ans = self.sign(wire::T_RETIRE_ANSWER, &wire::payload_bytes(&a));
        self.rotations.get_mut(&r.rotation_id).unwrap().retired = Some((digest, ans.clone()));
        ok(ans)
    }

    /// §5.5: close a rotation the robot will not complete. Signed by the
    /// old key; for `uplink`, also authenticated by it. An unknown rotation
    /// id is recorded as cancelled, so a rotate request with that id that
    /// arrives later is refused.
    fn cancel(&mut self, robot: &str, auth_key: &str, body: &[u8]) -> Resp {
        let o = match Envelope::parse(body, wire::T_CANCEL_REQUEST) {
            Ok(o) => o,
            Err(x) => return e(400, "bad_request", &x.0),
        };
        let r = match CancelRequest::parse(&o.payload) {
            Ok(r) => r,
            Err(x) => return e(400, "bad_request", &x.0),
        };
        if r.workspace != self.workspace || r.robot_id != robot {
            return e(403, "robot_mismatch", "rotation of another robot");
        }
        if r.role == "uplink" && auth_key != r.old_key_id {
            return e(
                401,
                "wrong_key",
                "an uplink cancellation is authenticated by the old uplink key",
            );
        }
        let rec = self.rotations.get(&r.rotation_id).cloned();
        if let Some(rec) = &rec {
            if rec.robot != robot {
                return e(403, "robot_mismatch", "rotation of another robot");
            }
            if r.role != rec.role
                || r.old_key_id != rec.old_key_id
                || r.new_key_id != rec.new_key_id
                || r.request_digest != rec.request_digest
            {
                return e(
                    400,
                    "bad_request",
                    "cancel request does not match the rotation",
                );
            }
        }
        let Some(old) = self
            .keys
            .get(&r.old_key_id)
            .filter(|k| k.robot == robot && k.role == r.role)
        else {
            return e(
                409,
                "stale_key",
                "old key is not a key of this robot and role",
            );
        };
        if o.signers() != [r.old_key_id.as_str()]
            || o.verify_by(&r.old_key_id, &old.public).is_err()
        {
            return e(401, "bad_signature", "must be signed by the old key only");
        }
        let digest = o.payload_digest();
        if let Some(rec) = &rec {
            if let Some((d, ans)) = &rec.cancelled {
                return if *d == digest {
                    ok(ans.clone())
                } else {
                    e(
                        409,
                        "already_cancelled",
                        "rotation already cancelled by another request",
                    )
                };
            }
            if rec.retired.is_some() {
                return e(409, "already_retired", "the rotation is complete");
            }
        }
        if old.retired_at.is_some() {
            return e(
                409,
                "stale_key",
                "old key is not this robot's active key of that role",
            );
        }
        // Effects: the new key (if registered by this rotation) is retired;
        // the old key stays active.
        if rec.is_some() {
            if let Some(k) = self.keys.get_mut(&r.new_key_id) {
                k.retired_at.get_or_insert(self.now_ms);
            }
        }
        let a = KeyAnswer {
            format: wire::CANCEL_ANSWER_FORMAT.into(),
            rotation_id: r.rotation_id.clone(),
            request_digest: digest.clone(),
            workspace: r.workspace.clone(),
            robot_id: robot.into(),
            role: r.role.clone(),
            old_key_id: r.old_key_id.clone(),
            new_key_id: r.new_key_id.clone(),
            status: "cancelled".into(),
            at_ms: self.now_ms,
        };
        let ans = self.sign(wire::T_CANCEL_ANSWER, &wire::payload_bytes(&a));
        let entry = self
            .rotations
            .entry(r.rotation_id.clone())
            .or_insert_with(|| RotationRec {
                robot: robot.into(),
                role: r.role.clone(),
                old_key_id: r.old_key_id.clone(),
                new_key_id: r.new_key_id.clone(),
                request_digest: r.request_digest.clone(),
                answer: Vec::new(),
                retired: None,
                cancelled: None,
            });
        entry.cancelled = Some((digest, ans.clone()));
        ok(ans)
    }

    fn draft(&mut self, robot: &str, body: &[u8]) -> Resp {
        let Ok(t) = std::str::from_utf8(body) else {
            return e(400, "invalid_profile", "not UTF-8");
        };
        match robodr_commission::parse_profile_text(t) {
            Ok(p) if !p.locked => {}
            Ok(_) => return e(400, "invalid_profile", "a locked profile is not a draft"),
            Err(x) => return e(400, "invalid_profile", &x.to_string()),
        }
        let d = wire::digest(body);
        self.drafts.push((robot.into(), body.to_vec()));
        ok(serde_json::to_vec(&serde_json::json!({"digest": d, "status": "received"})).unwrap())
    }
}

fn check_json(h: &[(String, String)], body: &[u8], max: usize) -> Result<(), Resp> {
    let ct = header(h, "Content-Type");
    let ok_ct = matches!(ct.as_slice(), [v] if v.eq_ignore_ascii_case("application/json"));
    if !ok_ct {
        return Err(e(
            415,
            "unsupported_media_type",
            "Content-Type must be application/json",
        ));
    }
    if body.len() > max {
        return Err(e(413, "too_large", "body too large"));
    }
    Ok(())
}

/// The reference SOC as an in-memory transport.
pub struct Direct<'a> {
    pub soc: &'a std::cell::RefCell<Soc>,
}

impl SocTransport for Direct<'_> {
    fn send(
        &mut self,
        method: &str,
        target: &str,
        headers: Vec<(&'static str, String)>,
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let h: Vec<(String, String)> = headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let r = self.soc.borrow_mut().handle(method, target, &h, body);
        Ok(HttpResponse {
            status: r.status,
            retry_after: None,
            body: r.body,
        })
    }

    fn base_path(&self) -> String {
        BASE.into()
    }
}

/// A transport that never reaches the SOC (network down).
pub struct Down;

impl SocTransport for Down {
    fn send(
        &mut self,
        _: &str,
        _: &str,
        _: Vec<(&'static str, String)>,
        _: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        Err(TransportError("connect: connection refused".into()))
    }

    fn base_path(&self) -> String {
        BASE.into()
    }
}
