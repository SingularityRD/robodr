//! A reference **consumer** of the `robodr.ingest` API, contract v1
//! (`docs/contracts/robodr.ingest-api.md` §4–§6), for tests: it checks the
//! producer (`robodr-uplink`) and the shared contract vectors
//! (`docs/contracts/fixtures/ingest/`) against the contract text. Test code
//! only; not the AutoSecOps implementation.
#![allow(dead_code)]

use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_blackbox::sign_ed25519::verify;
use robodr_export::uplink::wire;
use robodr_ocsf::FindingSignature;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Uplink,
    Relay,
    Finding,
}

#[derive(Debug, Clone)]
pub struct RegKey {
    pub role: Role,
    /// Bound robot (uplink, finding).
    pub robot: Option<String>,
    pub public: [u8; 32],
    pub revoked: bool,
    /// Relay only: site scope (§3); `None` = the whole workspace.
    pub site: Option<String>,
    /// Relay only: origin-vouching (§3, §4 step 5.4).
    pub vouches_origin: bool,
}

/// A workspace's registry (§3).
#[derive(Debug, Clone, Default)]
pub struct Registry {
    /// robot id -> require_finding_signature
    pub robots: BTreeMap<String, bool>,
    /// robot id -> site it is registered with (robots without one have no
    /// site: a site-scoped relay covers none of them)
    pub robot_sites: BTreeMap<String, String>,
    /// key id -> key
    pub keys: BTreeMap<String, RegKey>,
}

impl Registry {
    pub fn robot(mut self, id: &str, require_sig: bool) -> Self {
        self.robots.insert(id.into(), require_sig);
        self
    }
    pub fn robot_at(mut self, id: &str, require_sig: bool, site: Option<&str>) -> Self {
        self.robots.insert(id.into(), require_sig);
        if let Some(s) = site {
            self.robot_sites.insert(id.into(), s.into());
        }
        self
    }
    pub fn key(mut self, key_id: &str, role: Role, robot: Option<&str>, public: [u8; 32]) -> Self {
        self.keys.insert(
            key_id.into(),
            RegKey {
                role,
                robot: robot.map(str::to_string),
                public,
                revoked: false,
                site: None,
                vouches_origin: false,
            },
        );
        self
    }
    /// A `relay` key with its §3 attributes.
    pub fn relay(
        mut self,
        key_id: &str,
        public: [u8; 32],
        site: Option<&str>,
        vouches_origin: bool,
    ) -> Self {
        self.keys.insert(
            key_id.into(),
            RegKey {
                role: Role::Relay,
                robot: None,
                public,
                revoked: false,
                site: site.map(str::to_string),
                vouches_origin,
            },
        );
        self
    }
}

/// A scripted answer that overrides normal processing (consumed in order
/// before processing; `None` = process normally).
#[derive(Debug, Clone)]
pub enum Script {
    Process,
    Status(u16, Option<String>, String),
}

/// One received request.
#[derive(Debug, Clone)]
pub struct Seen {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub status: u16,
}

pub struct Consumer {
    pub reg: Registry,
    /// Server clock (ms); `None` = the request's own timestamp (no skew).
    pub now_ms: Option<u64>,
    /// (key id, batch id) -> (body sha256, stored 200 body)
    stored: HashMap<(String, String), (String, serde_json::Value)>,
    /// external_id -> event uids
    findings: HashMap<String, HashSet<String>>,
    pub script: VecDeque<Script>,
    pub seen: Vec<Seen>,
    /// 413 when a request has more lines than this (simulates a server with
    /// lower limits than the contract's).
    pub max_lines: usize,
}

pub struct Answer {
    pub status: u16,
    pub retry_after: Option<String>,
    pub body: Vec<u8>,
}

fn err(status: u16, code: &str, detail: &str) -> Answer {
    Answer {
        status,
        retry_after: None,
        body: serde_json::to_vec(&serde_json::json!({"code": code, "detail": detail})).unwrap(),
    }
}

fn deser_present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Option<FindingSignature>>, D::Error> {
    Option::<FindingSignature>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    value: String,
    #[serde(default, deserialize_with = "deser_present")]
    sig: Option<Option<FindingSignature>>,
}

/// The lines of a body (§2.3): split on LF; a final LF is optional.
pub fn split_lines(body: &[u8]) -> Vec<&[u8]> {
    let b = body.strip_suffix(b"\n").unwrap_or(body);
    b.split(|c| *c == b'\n').collect()
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let mut it = h.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name));
    let first = it.next().map(|(_, v)| v.as_str());
    if it.next().is_some() {
        return None;
    }
    first
}

fn is_lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_timestamp(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

/// `MAJOR` of a `contract_version` string (§4 step 5.2), if the value is a
/// JSON object carrying a well-formed one: exactly three dot-separated
/// parts of 1–9 ASCII decimal digits each (leading zeros allowed), MAJOR
/// read as a decimal number — the Rust validator's rule
/// (`robodr_ocsf::validate::contract_major`), used here directly.
fn contract_major(value: &str) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_str(value).ok()?;
    let cv = v.get("contract_version")?.as_str()?;
    robodr_ocsf::validate::contract_major(cv)
}

impl Consumer {
    pub fn new(reg: Registry) -> Self {
        Self {
            reg,
            now_ms: None,
            stored: HashMap::new(),
            findings: HashMap::new(),
            script: VecDeque::new(),
            seen: Vec::new(),
            max_lines: wire::MAX_LINES,
        }
    }

    /// Distinct findings (external ids) stored.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Distinct emissions (event uids) stored.
    pub fn event_count(&self) -> usize {
        self.findings.values().map(HashSet::len).sum()
    }

    pub fn handle(&mut self, headers: &[(String, String)], body: &[u8]) -> Answer {
        let a = match self.script.pop_front() {
            Some(Script::Status(s, ra, b)) => Answer {
                status: s,
                retry_after: ra,
                body: b.into_bytes(),
            },
            _ => self.process(headers, body),
        };
        self.seen.push(Seen {
            headers: headers.to_vec(),
            body: body.to_vec(),
            status: a.status,
        });
        a
    }

    /// §4, in order.
    pub fn process(&mut self, headers: &[(String, String)], body: &[u8]) -> Answer {
        // 1. Content type, limits, header syntax.
        if !header(headers, "content-type")
            .is_some_and(|v| v.eq_ignore_ascii_case(wire::CONTENT_TYPE))
        {
            return err(
                415,
                "unsupported_media_type",
                "Content-Type must be application/x-ndjson",
            );
        }
        if body.len() > wire::MAX_BODY_BYTES {
            return err(413, "body_too_large", "body over 4 MiB");
        }
        let lines = if body.is_empty() {
            Vec::new()
        } else {
            split_lines(body)
        };
        if lines.len() > wire::MAX_LINES.min(self.max_lines) {
            return err(413, "too_many_lines", "more lines than allowed");
        }
        let (Some(key_id), Some(batch_id), Some(ts), Some(sig)) = (
            header(headers, wire::H_KEY_ID),
            header(headers, wire::H_BATCH_ID),
            header(headers, wire::H_TIMESTAMP),
            header(headers, wire::H_SIGNATURE),
        ) else {
            return err(
                400,
                "bad_header",
                "a required header is missing or repeated",
            );
        };
        if !wire::is_valid_key_id(key_id) {
            return err(400, "bad_header", "X-RoboDR-Key-Id");
        }
        if !wire::is_valid_batch_id(batch_id) {
            return err(400, "bad_header", "X-RoboDR-Batch-Id");
        }
        let Some(ts) = valid_timestamp(ts) else {
            return err(400, "bad_header", "X-RoboDR-Timestamp");
        };
        if !is_lower_hex(sig, 128) {
            return err(400, "bad_header", "X-RoboDR-Signature");
        }
        if body.is_empty() {
            return err(400, "empty_batch", "the body has no line");
        }
        // 2. Authentication.
        let Some(k) = self.reg.keys.get(key_id).cloned() else {
            return err(401, "unknown_key", "unknown key");
        };
        if k.revoked || k.role == Role::Finding {
            return err(401, "unknown_key", "key cannot authenticate a batch");
        }
        let now = self.now_ms.unwrap_or(ts);
        if now.abs_diff(ts) > 300_000 {
            return err(401, "stale_timestamp", "timestamp skew over 300 s");
        }
        if !wire::verify_batch(&k.public, key_id, batch_id, ts, body, sig) {
            return err(401, "bad_signature", "batch signature does not verify");
        }
        // 3. Replay.
        let body_hash = to_hex(&sha256(body));
        let skey = (key_id.to_string(), batch_id.to_string());
        if let Some((h, stored)) = self.stored.get(&skey) {
            if *h != body_hash {
                return err(409, "batch_id_reuse", "batch id seen with another body");
            }
            let mut v = stored.clone();
            v["replayed"] = serde_json::Value::Bool(true);
            return Answer {
                status: 200,
                retry_after: None,
                body: serde_json::to_vec(&v).unwrap(),
            };
        }
        // 4. Rate limit: scripted only (Script::Status(429, ..)).
        // 5. Lines.
        let (mut created, mut updated, mut dups) = (0u64, 0u64, 0u64);
        let mut rejected = Vec::new();
        for (i, raw) in lines.iter().enumerate() {
            match self.line(&k, raw) {
                Ok(0) => created += 1,
                Ok(1) => updated += 1,
                Ok(_) => dups += 1,
                Err((code, detail)) => rejected.push(serde_json::json!({
                    "line": i + 1, "code": code, "detail": detail
                })),
            }
        }
        let v = serde_json::json!({
            "batch_id": batch_id,
            "replayed": false,
            "accepted": created + updated + dups,
            "created": created,
            "updated": updated,
            "duplicates": dups,
            "rejected": rejected,
        });
        self.stored.insert(skey, (body_hash, v.clone()));
        Answer {
            status: 200,
            retry_after: None,
            body: serde_json::to_vec(&v).unwrap(),
        }
    }

    /// One line: `Ok(0)` created, `Ok(1)` updated, `Ok(2)` duplicate.
    fn line(&mut self, k: &RegKey, raw: &[u8]) -> Result<u8, (&'static str, String)> {
        // 5.1 the line object
        if raw.is_empty() {
            return Err(("invalid_line", "empty line".into()));
        }
        if raw.contains(&b'\r') {
            return Err(("invalid_line", "CR in line".into()));
        }
        // A JSON object (serde would also read a struct from an array).
        let v: serde_json::Value =
            serde_json::from_slice(raw).map_err(|e| ("invalid_line", e.to_string()))?;
        if !v.is_object() {
            return Err(("invalid_line", "not a JSON object".into()));
        }
        // Parsed again as the strict struct: unknown and duplicate keys fail.
        let l: Line = serde_json::from_slice(raw).map_err(|e| ("invalid_line", e.to_string()))?;
        let Some(sig) = l.sig else {
            return Err(("invalid_line", "missing sig".into()));
        };
        if let Some(s) = &sig {
            s.check().map_err(|e| ("invalid_line", e.to_string()))?;
        }
        // 5.2 the value
        if l.value.len() > wire::MAX_VALUE_BYTES {
            return Err(("too_large", "value over 256 KiB".into()));
        }
        if let Some(m) = contract_major(&l.value) {
            if m != 2 {
                return Err(("unsupported_contract", format!("contract major {m}")));
            }
        }
        let env = robodr_ocsf::parse_and_validate(&l.value)
            .map_err(|e| ("invalid_finding", format!("{}", e[0])))?;
        // Only MAJOR 2 reaches validation (above); a validator that also
        // parses 1.x for replay must still accept nothing but 2.x here.
        if !robodr_ocsf::validate::is_emittable_contract_version(&env.contract_version) {
            return Err(("unsupported_contract", env.contract_version.clone()));
        }
        let robot = env.entity_context.robot.id.clone();
        // 5.3 robot binding
        match k.role {
            Role::Uplink => {
                if k.robot.as_deref() != Some(robot.as_str()) {
                    return Err(("robot_mismatch", format!("finding names robot {robot}")));
                }
            }
            Role::Relay => {
                if !self.reg.robots.contains_key(&robot) {
                    return Err(("unknown_robot", format!("robot {robot} not registered")));
                }
                if let Some(site) = &k.site {
                    if self.reg.robot_sites.get(&robot) != Some(site) {
                        return Err((
                            "site_mismatch",
                            format!("robot {robot} is not registered with site {site}"),
                        ));
                    }
                }
            }
            Role::Finding => unreachable!("refused at authentication"),
        }
        // 5.4 per-finding signature
        match &sig {
            Some(s) => {
                let fk = self
                    .reg
                    .keys
                    .get(&s.key_id)
                    .filter(|fk| {
                        fk.role == Role::Finding
                            && !fk.revoked
                            && fk.robot.as_deref() == Some(robot.as_str())
                    })
                    .ok_or(("bad_finding_signature", "no finding key".to_string()))?;
                let msg = robodr_ocsf::sig::signing_message(&s.alg, &s.key_id, l.value.as_bytes());
                if !verify(&fk.public, &msg, &s.sig_bytes().unwrap()) {
                    return Err(("bad_finding_signature", "does not verify".into()));
                }
            }
            None => {
                let required = self.reg.robots.get(&robot).copied().unwrap_or(false);
                let vouched = k.role == Role::Relay && k.vouches_origin;
                if required && !vouched {
                    return Err(("missing_finding_signature", "robot requires it".into()));
                }
            }
        }
        // 5.5 dedup
        let uids = self.findings.entry(env.external_id.clone()).or_default();
        let fresh = uids.is_empty();
        if !uids.insert(env.ocsf.metadata.uid.clone()) {
            return Ok(2);
        }
        Ok(if fresh { 0 } else { 1 })
    }
}

/// [`Consumer`] as a [`robodr_export::uplink::http::Transport`] (no
/// network), recording every request.
pub struct MockTransport {
    pub consumer: std::sync::Arc<std::sync::Mutex<Consumer>>,
    /// Transport errors to return before the next requests (consumed first).
    pub fail_next: usize,
}

impl robodr_export::uplink::http::Transport for MockTransport {
    fn post(
        &mut self,
        req: &robodr_export::uplink::http::HttpRequest<'_>,
    ) -> Result<
        robodr_export::uplink::http::HttpResponse,
        robodr_export::uplink::http::TransportError,
    > {
        if self.fail_next > 0 {
            self.fail_next -= 1;
            return Err(robodr_export::uplink::http::TransportError(
                "connection reset (mock)".into(),
            ));
        }
        let headers: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        let a = self.consumer.lock().unwrap().handle(&headers, req.body);
        Ok(robodr_export::uplink::http::HttpResponse {
            status: a.status,
            retry_after: a.retry_after,
            body: a.body,
        })
    }
}
