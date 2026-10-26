//! The shared `robodr.fleet-api` contract vectors
//! (`docs/contracts/fixtures/fleet/`), built deterministically from fixed
//! test keys and run through the reference SOC (`soc.rs`) for the expected
//! responses. Used by `examples/fleet_vectors.rs` (writes them) and
//! `tests/fleet_vectors.rs` (byte-identical check and independent replay).
#![allow(dead_code)]

use crate::soc::{Soc, BASE};
use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::{Ed25519SigningKey, KeyFile, Signer};
use robodr_fleet::keys::RoleKey;
use robodr_fleet::wire::{self, EnrollRequest, Envelope, RetireRequest, RotateRequest, Token};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const WORKSPACE: &str = "ws-test-0001";
pub const T0: u64 = 1_790_000_000_000;
pub const SOC_SEED: [u8; 32] = [0x50; 32];

/// (file stem, seed, robot, role) of every test key.
pub const KEYS: &[(&str, u8, &str, &str)] = &[
    ("soc", 0x50, "", "soc"),
    ("ugv-001-uplink", 0x61, "ugv-001", "uplink"),
    ("ugv-001-finding", 0x62, "ugv-001", "finding"),
    ("ugv-001-blackbox", 0x63, "ugv-001", "blackbox"),
    ("ugv-001-uplink-next", 0x64, "ugv-001", "uplink"),
    ("ugv-002-uplink", 0x71, "ugv-002", "uplink"),
    ("ugv-002-finding", 0x72, "ugv-002", "finding"),
    ("ugv-002-blackbox", 0x73, "ugv-002", "blackbox"),
    ("profile-signer", 0x51, "", "profile"),
    ("trust-root", 0x52, "", "root"),
];

pub fn key(stem: &str) -> Ed25519SigningKey {
    let seed = KEYS.iter().find(|k| k.0 == stem).expect("known key").1;
    Ed25519SigningKey::from_seed_with_derived_id(&[seed; 32])
}

fn rk(stem: &str) -> RoleKey {
    let role = KEYS.iter().find(|k| k.0 == stem).unwrap().3;
    RoleKey {
        role: role.into(),
        signing: key(stem),
    }
}

/// (token id, robot, site, nonce byte).
pub const TOKENS: &[(&str, &str, Option<&str>, u8)] = &[
    ("tok-1", "ugv-001", Some("lab-1"), 0x33),
    ("tok-2", "ugv-002", Some("lab-1"), 0x34),
    ("tok-3", "ugv-001", None, 0x35),
];

pub fn token_text(id: &str) -> String {
    let (_, robot, site, n) = TOKENS.iter().find(|t| t.0 == id).unwrap();
    let mut s = Soc::new(key("soc"), WORKSPACE, T0);
    s.issue_token(id, robot, *site, 3_600_000, [*n; 32])
}

fn token(id: &str) -> Token {
    Token::parse(&token_text(id)).unwrap()
}

/// An enrollment request body for `robot` from token `tok`.
pub fn enroll_body(
    tok: &str,
    robot: &str,
    site: Option<&str>,
    workspace: &str,
    seq: u8,
    signer: Option<&str>,
    mac_nonce: Option<u8>,
) -> Vec<u8> {
    let keys = [
        rk(&format!("{robot}-uplink")),
        rk(&format!("{robot}-finding")),
        rk(&format!("{robot}-blackbox")),
    ];
    let req = EnrollRequest {
        format: wire::ENROLL_REQUEST_FORMAT.into(),
        request_id: format!("rfe1-{}", format!("{seq:02x}").repeat(16)),
        token_id: tok.into(),
        workspace: workspace.into(),
        robot_id: robot.into(),
        site: site.map(str::to_string),
        created_at_ms: T0 + 30_000,
        agentd_version: "0.1.0-alpha.1".into(),
        profile_digest: None,
        keys: keys.iter().map(RoleKey::entry).collect(),
    };
    let t = match TOKENS.iter().find(|x| x.0 == tok) {
        Some(_) => token(tok),
        None => token("tok-1"),
    };
    let mut e = robodr_fleet::enroll::build_request_envelope(&req, &keys[0], &t);
    if let Some(s) = signer {
        let payload = wire::payload_bytes(&req);
        let mac = e.mac.clone();
        e = Envelope::sign(wire::T_ENROLL_REQUEST, &payload, &[&key(s)]);
        e.mac = mac;
    }
    if let Some(n) = mac_nonce {
        let payload = wire::payload_bytes(&req);
        e.mac.as_mut().unwrap().mac = to_hex(&wire::token_mac(&[n; 32], tok, &payload));
    }
    e.to_bytes()
}

fn rotate_body(rotation: u8, old: &str, new: &str, signers: &[&str]) -> Vec<u8> {
    let (o, n) = (key(old), key(new));
    let req = RotateRequest {
        format: wire::ROTATE_REQUEST_FORMAT.into(),
        rotation_id: format!("rfr1-{}", format!("{rotation:02x}").repeat(16)),
        workspace: WORKSPACE.into(),
        robot_id: "ugv-001".into(),
        role: "uplink".into(),
        old_key_id: o.key_id().into(),
        old_fingerprint: wire::fingerprint(&o.public_key()),
        new_key_id: n.key_id().into(),
        new_public_hex: to_hex(&n.public_key()),
        new_fingerprint: wire::fingerprint(&n.public_key()),
        created_at_ms: T0 + 100_000,
    };
    let ks: Vec<Ed25519SigningKey> = signers.iter().map(|s| key(s)).collect();
    let refs: Vec<&Ed25519SigningKey> = ks.iter().collect();
    Envelope::sign(wire::T_ROTATE_REQUEST, &wire::payload_bytes(&req), &refs).to_bytes()
}

fn retire_body(rotation: u8, old: &str, new: &str) -> Vec<u8> {
    let req = RetireRequest {
        format: wire::RETIRE_REQUEST_FORMAT.into(),
        rotation_id: format!("rfr1-{}", format!("{rotation:02x}").repeat(16)),
        workspace: WORKSPACE.into(),
        robot_id: "ugv-001".into(),
        role: "uplink".into(),
        old_key_id: key(old).key_id().into(),
        new_key_id: key(new).key_id().into(),
        created_at_ms: T0 + 200_000,
    };
    Envelope::sign(
        wire::T_RETIRE_REQUEST,
        &wire::payload_bytes(&req),
        &[&key(new)],
    )
    .to_bytes()
}

/// One request of a case.
pub struct Step {
    pub method: &'static str,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub server_time_ms: u64,
}

fn json_post(target: &str, body: Vec<u8>, at: u64) -> Step {
    Step {
        method: "POST",
        target: format!("{BASE}{target}"),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body,
        server_time_ms: at,
    }
}

/// An authenticated request (§2.5) by `signer` at `ts`.
fn authed(
    method: &'static str,
    target: &str,
    body: Vec<u8>,
    signer: &str,
    ts: u64,
    at: u64,
) -> Step {
    let full = format!("{BASE}{target}");
    let mut headers = Vec::new();
    if method == "POST" {
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
    }
    for (k, v) in robodr_fleet::client::auth_headers(method, &full, &body, &key(signer), ts) {
        headers.push((k.to_string(), v));
    }
    Step {
        method,
        target: full,
        headers,
        body,
        server_time_ms: at,
    }
}

/// Fixed SOC-side publications of a case (served verbatim).
#[derive(Default)]
pub struct Setup {
    pub tokens: Vec<&'static str>,
    pub revocations: Vec<(String, Vec<u8>)>,
    pub offers: Vec<(String, Vec<u8>)>,
    pub approvals: Vec<(String, Vec<u8>)>,
    pub rings: Vec<(String, Vec<u8>)>,
}

pub struct Case {
    pub name: &'static str,
    pub description: &'static str,
    pub setup: Setup,
    pub steps: Vec<Step>,
}

fn signed_profile() -> (Vec<u8>, Vec<u8>) {
    use robodr_events::profile::{Profile, ProfileMetadata, PROFILE_SCHEMA_VERSION};
    let mut p = Profile {
        model: "ugv-test".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert("01103f5a8c2e000000000101".into());
    p.writer_topics.insert("/cmd_vel".into());
    p.metadata = Some(ProfileMetadata {
        schema_version: PROFILE_SCHEMA_VERSION,
        profile_version: 4,
        platform: "ugv-x1".into(),
        unit_id: Some("ugv-001".into()),
        locked_by: "op-a".into(),
        locked_at: 1_790_000_000,
        parent_digest: None,
        attestation: None,
    });
    let text = robodr_commission::sealed_text(&p).unwrap();
    let sig =
        robodr_commission::trust::ProfileSignature::create(text.as_bytes(), &key("profile-signer"))
            .unwrap()
            .to_text();
    (text.into_bytes(), sig.into_bytes())
}

fn draft_profile() -> Vec<u8> {
    let mut p = robodr_events::profile::Profile {
        model: "ugv-test".into(),
        ..Default::default()
    };
    p.writer_topics.insert("/cmd_vel".into());
    robodr_commission::to_json(&p).unwrap().into_bytes()
}

fn publications() -> Setup {
    let mut s = Soc::new(key("soc"), WORKSPACE, T0);
    let (p, sig) = signed_profile();
    s.offer("ugv-001", 4, &p, &sig);
    let digest = wire::digest(&p);
    let ap = s.approval(
        "ap-1",
        "ugv-001",
        "ugv-x1",
        &digest,
        4,
        &["op-a", "op-b"],
        3_600_000,
    );
    let ring = s.ring("ugv-001", 1, 1, Some("0.2.0"));
    let rev = robodr_commission::trust::RevocationList::create(
        2,
        1_790_000_000,
        "ugv-x1",
        Vec::<String>::new(),
        Vec::<String>::new(),
        &key("trust-root"),
    )
    .unwrap()
    .to_text()
    .into_bytes();
    Setup {
        tokens: vec!["tok-1"],
        revocations: vec![("ugv-x1".into(), rev)],
        offers: vec![("ugv-001".into(), s.offers["ugv-001"].clone())],
        approvals: vec![(digest.trim_start_matches("sha256:").into(), ap)],
        rings: vec![("ugv-001".into(), ring)],
    }
}

pub fn cases() -> Vec<Case> {
    let t = T0 + 60_000;
    let enroll1 = || enroll_body("tok-1", "ugv-001", Some("lab-1"), WORKSPACE, 1, None, None);
    let up = "ugv-001-uplink";
    let next = "ugv-001-uplink-next";
    let mut v = vec![
        Case {
            name: "01-enroll-ok",
            description: "valid enrollment request (uplink-signed, token MAC) -> SOC-signed answer naming the request digest and the three keys",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![json_post(wire::PATH_ENROLL, enroll1(), t)],
        },
        Case {
            name: "02-enroll-retry",
            description: "the same request again (lost answer): the stored answer, byte-identical",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![
                json_post(wire::PATH_ENROLL, enroll1(), t),
                json_post(wire::PATH_ENROLL, enroll1(), t + 5_000),
            ],
        },
        Case {
            name: "03-enroll-token-used",
            description: "a second, different request (other request id) with a consumed token -> 409 token_used",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![
                json_post(wire::PATH_ENROLL, enroll1(), t),
                json_post(
                    wire::PATH_ENROLL,
                    enroll_body("tok-1", "ugv-001", Some("lab-1"), WORKSPACE, 2, None, None),
                    t + 5_000,
                ),
            ],
        },
        Case {
            name: "04-enroll-bad-token",
            description: "MAC under another nonce -> 401 bad_token; unknown token id -> 401 bad_token",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![
                json_post(
                    wire::PATH_ENROLL,
                    enroll_body("tok-1", "ugv-001", Some("lab-1"), WORKSPACE, 1, None, Some(0x99)),
                    t,
                ),
                json_post(
                    wire::PATH_ENROLL,
                    enroll_body("tok-9", "ugv-001", Some("lab-1"), WORKSPACE, 1, None, Some(0x33)),
                    t,
                ),
            ],
        },
        Case {
            name: "05-enroll-expired",
            description: "valid request processed after the token expired (air-gapped import too late) -> 410 token_expired",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![json_post(wire::PATH_ENROLL, enroll1(), T0 + 3_600_001)],
        },
        Case {
            name: "06-enroll-binding",
            description: "request names another workspace than its token -> 403 workspace_mismatch; another robot -> 403 robot_mismatch; another site -> 403 robot_mismatch",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![
                json_post(
                    wire::PATH_ENROLL,
                    enroll_body("tok-1", "ugv-001", Some("lab-1"), "ws-other", 1, None, None),
                    t,
                ),
                json_post(
                    wire::PATH_ENROLL,
                    enroll_body("tok-1", "ugv-002", Some("lab-1"), WORKSPACE, 1, None, None),
                    t,
                ),
                json_post(
                    wire::PATH_ENROLL,
                    enroll_body("tok-1", "ugv-001", Some("lab-2"), WORKSPACE, 1, None, None),
                    t,
                ),
            ],
        },
        Case {
            name: "07-enroll-bad-signature",
            description: "request signed by its finding key instead of its uplink key -> 401 bad_signature",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![json_post(
                wire::PATH_ENROLL,
                enroll_body("tok-1", "ugv-001", Some("lab-1"), WORKSPACE, 1, Some("ugv-001-finding"), None),
                t,
            )],
        },
        Case {
            name: "08-enroll-malformed",
            description: "envelope without mac -> 400 bad_request; Content-Type text/plain -> 415; trailing garbage -> 400",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![
                json_post(wire::PATH_ENROLL, {
                    let o = Envelope::parse(&enroll1(), wire::T_ENROLL_REQUEST).unwrap();
                    let mut e = o.envelope;
                    e.mac = None;
                    e.to_bytes()
                }, t),
                Step {
                    headers: vec![("Content-Type".into(), "text/plain".into())],
                    ..json_post(wire::PATH_ENROLL, enroll1(), t)
                },
                json_post(wire::PATH_ENROLL, {
                    let mut b = enroll1();
                    b.extend_from_slice(b"x");
                    b
                }, t),
            ],
        },
        Case {
            name: "09-enroll-key-conflict",
            description: "ugv-002 enrolls with keys already registered to ugv-001 -> 409 key_conflict",
            setup: Setup { tokens: vec!["tok-1", "tok-2"], ..Default::default() },
            steps: vec![json_post(wire::PATH_ENROLL, enroll1(), t), json_post(wire::PATH_ENROLL, {
                // ugv-002's request carrying ugv-001's uplink key.
                let tk = token("tok-2");
                let keys = [rk("ugv-001-uplink"), rk("ugv-002-finding"), rk("ugv-002-blackbox")];
                let req = EnrollRequest {
                    format: wire::ENROLL_REQUEST_FORMAT.into(),
                    request_id: format!("rfe1-{}", "03".repeat(16)),
                    token_id: "tok-2".into(),
                    workspace: WORKSPACE.into(),
                    robot_id: "ugv-002".into(),
                    site: Some("lab-1".into()),
                    created_at_ms: T0 + 30_000,
                    agentd_version: "0.1.0-alpha.1".into(),
                    profile_digest: None,
                    keys: keys.iter().map(RoleKey::entry).collect(),
                };
                robodr_fleet::enroll::build_request_envelope(&req, &keys[0], &tk).to_bytes()
            }, t)],
        },
        Case {
            name: "10-rotate-and-retire",
            description: "enroll; rotate the uplink key (request authenticated by the old key, signed by old then new) -> overlap; the new key authenticates; retire (authenticated and signed by the new key) -> retired; the old key no longer authenticates (401 unknown_key)",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![
                json_post(wire::PATH_ENROLL, enroll1(), t),
                authed("POST", wire::PATH_ROTATE, rotate_body(1, up, next, &[up, next]), up, t + 40_000, t + 40_000),
                authed("GET", wire::PATH_RING, Vec::new(), next, t + 41_000, t + 41_000),
                authed("POST", wire::PATH_RETIRE, retire_body(1, up, next), next, t + 50_000, t + 50_000),
                authed("POST", wire::PATH_RETIRE, retire_body(1, up, next), next, t + 51_000, t + 51_000),
                authed("GET", wire::PATH_RING, Vec::new(), up, t + 52_000, t + 52_000),
            ],
        },
        Case {
            name: "11-rotate-refusals",
            description: "rotate signed by the old key only -> 401 bad_signature; valid rotate; the same again -> stored answer; another rotation of the role while one is open -> 409 rotation_in_progress; old key that is not the active one -> 409 stale_key",
            setup: Setup { tokens: vec!["tok-1"], ..Default::default() },
            steps: vec![
                json_post(wire::PATH_ENROLL, enroll1(), t),
                authed("POST", wire::PATH_ROTATE, rotate_body(1, up, next, &[up]), up, t + 40_000, t + 40_000),
                authed("POST", wire::PATH_ROTATE, rotate_body(1, up, next, &[up, next]), up, t + 41_000, t + 41_000),
                authed("POST", wire::PATH_ROTATE, rotate_body(1, up, next, &[up, next]), up, t + 42_000, t + 42_000),
                authed("POST", wire::PATH_ROTATE, rotate_body(2, up, next, &[up, next]), up, t + 43_000, t + 43_000),
                authed("POST", wire::PATH_ROTATE, rotate_body(3, "ugv-002-uplink", next, &["ugv-002-uplink", next]), up, t + 44_000, t + 44_000),
            ],
        },
        Case {
            name: "12-request-auth",
            description: "GET ring: valid; timestamp 300001 ms off -> 401 stale_timestamp; signature for another path -> 401 bad_signature; finding key -> 401 unknown_key; X-RoboDR-Timestamp twice -> 400 bad_header; no auth headers -> 400 bad_header",
            setup: Setup { tokens: vec!["tok-1"], rings: publications().rings, ..Default::default() },
            steps: vec![
                json_post(wire::PATH_ENROLL, enroll1(), t),
                authed("GET", wire::PATH_RING, Vec::new(), up, t, t),
                authed("GET", wire::PATH_RING, Vec::new(), up, t, t + 300_001),
                {
                    let mut s = authed("GET", wire::PATH_PROFILE_CURRENT, Vec::new(), up, t, t);
                    s.target = format!("{BASE}{}", wire::PATH_RING);
                    s
                },
                authed("GET", wire::PATH_RING, Vec::new(), "ugv-001-finding", t, t),
                {
                    let mut s = authed("GET", wire::PATH_RING, Vec::new(), up, t, t);
                    s.headers.push(("X-RoboDR-Timestamp".into(), t.to_string()));
                    s
                },
                Step {
                    method: "GET",
                    target: format!("{BASE}{}", wire::PATH_RING),
                    headers: Vec::new(),
                    body: Vec::new(),
                    server_time_ms: t,
                },
            ],
        },
        Case {
            name: "13-distribution",
            description: "authenticated GETs: revocation list (verbatim, root-signed), unknown platform -> 404 no_list, profile offer, approval for the offered digest, unknown digest -> 404 no_approval, ring info; draft publish -> received; a locked profile as draft -> 400 invalid_profile",
            setup: publications(),
            steps: {
                let (p, _) = signed_profile();
                let hex = wire::digest(&p).trim_start_matches("sha256:").to_string();
                vec![
                    json_post(wire::PATH_ENROLL, enroll1(), t),
                    authed("GET", &format!("{}/ugv-x1", wire::PATH_REVOCATIONS), Vec::new(), up, t, t),
                    authed("GET", &format!("{}/other-x", wire::PATH_REVOCATIONS), Vec::new(), up, t, t),
                    authed("GET", wire::PATH_PROFILE_CURRENT, Vec::new(), up, t, t),
                    authed("GET", &format!("{}/{hex}", wire::PATH_PROFILE_APPROVALS), Vec::new(), up, t, t),
                    authed("GET", &format!("{}/{}", wire::PATH_PROFILE_APPROVALS, "0".repeat(64)), Vec::new(), up, t, t),
                    authed("GET", wire::PATH_RING, Vec::new(), up, t, t),
                    authed("POST", wire::PATH_PROFILE_DRAFTS, draft_profile(), up, t, t),
                    authed("POST", wire::PATH_PROFILE_DRAFTS, p, up, t, t),
                ]
            },
        },
    ];
    // Third token: a fleet-wide site (null) token.
    v.push(Case {
        name: "14-enroll-no-site",
        description: "token without a site; the request carries site null -> answer with site null",
        setup: Setup {
            tokens: vec!["tok-3"],
            ..Default::default()
        },
        steps: vec![json_post(
            wire::PATH_ENROLL,
            enroll_body("tok-3", "ugv-001", None, WORKSPACE, 4, None, None),
            t,
        )],
    });
    v
}

fn pretty(v: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    s.into_bytes()
}

fn sha(b: &[u8]) -> String {
    to_hex(&robodr_blackbox::crypto::sha256(b))
}

/// A SOC for `case` (fresh, setup applied).
pub fn soc_for(case: &Case) -> Soc {
    let mut s = Soc::new(key("soc"), WORKSPACE, T0);
    for tok in &case.setup.tokens {
        s.register_token(&token_text(tok));
    }
    for (k, b) in &case.setup.revocations {
        s.revocations.insert(k.clone(), b.clone());
    }
    for (k, b) in &case.setup.offers {
        s.offers.insert(k.clone(), b.clone());
    }
    for (k, b) in &case.setup.approvals {
        s.approvals.insert(k.clone(), b.clone());
    }
    for (k, b) in &case.setup.rings {
        s.rings.insert(k.clone(), b.clone());
    }
    s
}

/// The expected `<n>.response.json` value for a response.
pub fn response_json(status: u16, body: &[u8], body_file: &str) -> Value {
    if status != 200 {
        let v: Value = serde_json::from_slice(body).unwrap();
        return json!({"status": status, "body": {"code": v["code"]}});
    }
    // An envelope: its type, signer and decoded payload.
    for kind in [
        wire::T_ENROLL_ANSWER,
        wire::T_ROTATE_ANSWER,
        wire::T_RETIRE_ANSWER,
        wire::T_APPROVAL,
        wire::T_RING,
    ] {
        if let Ok(o) = Envelope::parse(body, kind) {
            let payload: Value = serde_json::from_slice(&o.payload).unwrap();
            return json!({"status": 200, "body_file": body_file, "body_sha256": sha(body),
                          "envelope": {"type": kind, "signed_by": o.signers(), "payload": payload}});
        }
    }
    json!({"status": 200, "body_file": body_file, "body_sha256": sha(body)})
}

/// Every vector file (path relative to the fixture root -> bytes).
pub fn files() -> Vec<(String, Vec<u8>)> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut keys = Vec::new();
    for (stem, seed, robot, role) in KEYS {
        let kf = KeyFile::ed25519_from_seed(&[*seed; 32], None).unwrap();
        out.insert(format!("keys/{stem}.key"), kf.to_json().into_bytes());
        out.insert(
            format!("keys/{stem}.key.pub"),
            kf.to_public().unwrap().to_json().into_bytes(),
        );
        keys.push(
            json!({"file": format!("keys/{stem}.key"), "key_id": kf.key_id,
                         "robot": if robot.is_empty() { Value::Null } else { json!(robot) },
                         "role": role}),
        );
    }
    let mut toks = Vec::new();
    for (id, robot, site, n) in TOKENS {
        out.insert(
            format!("tokens/{id}.txt"),
            format!("{}\n", token_text(id)).into_bytes(),
        );
        toks.push(
            json!({"file": format!("tokens/{id}.txt"), "token_id": id, "robot": robot,
                         "site": site, "nonce_hex": to_hex(&[*n; 32])}),
        );
    }
    let mut cases_json = Vec::new();
    for case in cases() {
        let mut soc = soc_for(&case);
        let dir = format!("cases/{}", case.name);
        let mut setup = serde_json::Map::new();
        setup.insert(
            "tokens".into(),
            json!(case
                .setup
                .tokens
                .iter()
                .map(|t| format!("tokens/{t}.txt"))
                .collect::<Vec<_>>()),
        );
        for (what, list) in [
            ("revocations", &case.setup.revocations),
            ("offers", &case.setup.offers),
            ("approvals", &case.setup.approvals),
            ("rings", &case.setup.rings),
        ] {
            if list.is_empty() {
                continue;
            }
            let mut m = serde_json::Map::new();
            for (k, b) in list {
                let f = format!("{dir}/setup/{what}-{k}.body");
                out.insert(f.clone(), b.clone());
                m.insert(k.clone(), json!(f));
            }
            setup.insert(what.into(), Value::Object(m));
        }
        let mut reqs = Vec::new();
        for (i, s) in case.steps.iter().enumerate() {
            let n = i + 1;
            soc.now_ms = s.server_time_ms;
            let target = s.target.strip_prefix(BASE).unwrap();
            let r = soc.handle(s.method, target, &s.headers, &s.body);
            out.insert(format!("{dir}/{n}.body"), s.body.clone());
            out.insert(
                format!("{dir}/{n}.request.json"),
                pretty(&json!({
                    "method": s.method, "target": s.target,
                    "headers": s.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                    "server_time_ms": s.server_time_ms,
                    "body_file": format!("{n}.body"), "body_sha256": sha(&s.body),
                })),
            );
            let rb = format!("{n}.response.body");
            if r.status == 200 {
                out.insert(format!("{dir}/{rb}"), r.body.clone());
            }
            out.insert(
                format!("{dir}/{n}.response.json"),
                pretty(&response_json(r.status, &r.body, &rb)),
            );
            reqs.push(json!(format!("{dir}/{n}")));
        }
        cases_json.push(json!({"name": case.name, "description": case.description,
                               "setup": setup, "requests": reqs}));
    }
    let manifest = json!({
        "contract": "robodr.fleet-api v1 (docs/contracts/robodr.fleet-api.md)",
        "workspace": WORKSPACE,
        "base_path": BASE,
        "soc_key": "keys/soc.key.pub",
        "run": "each case starts from an empty workspace whose SOC fleet key is keys/soc.key; register the setup tokens (as issued: the token file), serve the setup publications verbatim (revocations by platform, offers and rings by robot, approvals by digest hex), then send the requests in order with the server clock at server_time_ms; target includes base_path",
        "compare": "status; error bodies by code; 200 envelopes by type, signer list and decoded payload (JSON value equality; the committed body bytes are the reference's, Ed25519 is deterministic so an implementation serialising payloads as compact JSON in the contract's key order reproduces them exactly); other 200 bodies byte-exact (body_sha256)",
        "keys": keys,
        "tokens": toks,
        "cases": cases_json,
    });
    out.insert("manifest.json".into(), pretty(&manifest));
    out.into_iter().collect()
}

/// Fuzz seeds: (token seeds, envelope seeds), each (file name, bytes).
pub fn fuzz_seeds() -> (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>) {
    let toks = TOKENS
        .iter()
        .map(|(id, ..)| (format!("seed-{id}.txt"), token_text(id).into_bytes()))
        .collect();
    let mut envs = Vec::new();
    for (rel, bytes) in files() {
        let is_env = rel.ends_with(".body")
            && (bytes.starts_with(b"{\"format\":\"robodr-fleet-envelope/v1\"")
                || bytes.starts_with(b"{\"format\":\"robodr-fleet-profile-offer/v1\""));
        if is_env && envs.iter().all(|(_, b): &(String, Vec<u8>)| *b != bytes) {
            let name = rel.trim_start_matches("cases/").replace('/', "-");
            envs.push((format!("seed-{name}"), bytes));
        }
    }
    (toks, envs)
}
