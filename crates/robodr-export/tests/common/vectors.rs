//! Deterministic generator of the shared `robodr.ingest` contract test
//! vectors (`docs/contracts/fixtures/ingest/`). Used by
//! `examples/ingest_vectors.rs` (writes the files) and
//! `tests/ingest_vectors.rs` (asserts the committed files are byte-identical
//! and that the reference consumer gives the expected responses).
//!
//! Everything is fixed: key seeds, finding times, request timestamps;
//! Ed25519 signatures are deterministic (RFC 8032). The request bodies and
//! signatures are made with `robodr_export::uplink::wire`, i.e. exactly the
//! producer's code.
#![allow(dead_code)]

use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_blackbox::sign_ed25519::Ed25519SigningKey;
use robodr_blackbox::KeyFile;
use robodr_events::graph::Endpoint;
use robodr_events::{Deviation, RobotEvent, Severity};
use robodr_export::uplink::wire;
use robodr_ocsf::*;
use serde_json::{json, Value};

pub const FORMAT: &str = "robodr-ingest-vectors/1";
/// Finding times.
pub const T0: u64 = 1_790_000_000_000;
/// Request timestamps start here.
pub const TS0: u64 = 1_790_000_100_000;
/// Server clock = request timestamp + this (well within the ±300 s skew).
pub const SERVER_LAG_MS: u64 = 1_000;

pub const ROBOT_1: &str = "ugv-001";
pub const ROBOT_2: &str = "ugv-002";
pub const ROBOT_UNKNOWN: &str = "ugv-099";
/// Registered with another site than `ugv-001` / `ugv-002`.
pub const ROBOT_3: &str = "ugv-003";
/// Sites the robots are registered with (§3, site-scoped relays).
pub const SITE_A: &str = "test-range";
pub const SITE_B: &str = "range-b";

/// A fixed-seed Ed25519 key of the vectors.
pub struct VKey {
    pub name: &'static str,
    /// `uplink`, `relay`, `finding`, or `unregistered`.
    pub role: &'static str,
    pub robot: Option<&'static str>,
    /// Relay only: the site scope (§3).
    pub site: Option<&'static str>,
    /// Relay only: origin-vouching (§3).
    pub vouches_origin: bool,
    pub seed: [u8; 32],
}

impl VKey {
    fn new(name: &'static str, role: &'static str, robot: Option<&'static str>) -> Self {
        let mut m = b"robodr-ingest-vectors/v1/key/".to_vec();
        m.extend_from_slice(name.as_bytes());
        Self {
            name,
            role,
            robot,
            site: None,
            vouches_origin: false,
            seed: sha256(&m),
        }
    }
    fn site(mut self, site: &'static str) -> Self {
        self.site = Some(site);
        self
    }
    fn vouching(mut self) -> Self {
        self.vouches_origin = true;
        self
    }
    pub fn signing(&self) -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed_with_derived_id(&self.seed)
    }
    pub fn key_id(&self) -> String {
        robodr_blackbox::Signer::key_id(&self.signing()).to_string()
    }
    pub fn public(&self) -> [u8; 32] {
        self.signing().public_key()
    }
    fn files(&self) -> (String, String) {
        let kf = KeyFile::ed25519_from_seed(&self.seed, None)
            .unwrap()
            .with_device_id(self.robot)
            .unwrap();
        let mut s = kf.to_json();
        let mut p = kf.to_public().unwrap().to_json();
        for x in [&mut s, &mut p] {
            if !x.ends_with('\n') {
                x.push('\n');
            }
        }
        (s, p)
    }
}

pub fn keys() -> Vec<VKey> {
    vec![
        VKey::new("uplink-ugv-001", "uplink", Some(ROBOT_1)),
        VKey::new("relay-soc", "relay", None),
        VKey::new("finding-ugv-001", "finding", Some(ROBOT_1)),
        VKey::new("finding-ugv-002", "finding", Some(ROBOT_2)),
        VKey::new("unregistered", "unregistered", None),
        // Added with the site / origin-vouching relay decisions (§3).
        VKey::new("relay-diode", "relay", None).vouching(),
        VKey::new("relay-site-test-range", "relay", None).site(SITE_A),
    ]
}

fn key(name: &str) -> VKey {
    keys().into_iter().find(|k| k.name == name).unwrap()
}

/// A robot of the workspace (§3).
pub struct VRobot {
    pub id: &'static str,
    pub require_finding_signature: bool,
    /// The site it is registered with.
    pub site: &'static str,
}

/// The workspace's robots.
pub const ROBOTS: [VRobot; 3] = [
    VRobot {
        id: ROBOT_1,
        require_finding_signature: false,
        site: SITE_A,
    },
    VRobot {
        id: ROBOT_2,
        require_finding_signature: true,
        site: SITE_A,
    },
    VRobot {
        id: ROBOT_3,
        require_finding_signature: false,
        site: SITE_B,
    },
];

fn ctx(robot: &str) -> RobotContext {
    let mut c = RobotContext::new(
        RobotInfo {
            id: robot.into(),
            model: "ugv-tracked-v1".into(),
            platform_family: PlatformFamily::LinuxRos2,
            site: if robot == ROBOT_3 { SITE_B } else { SITE_A }.into(),
            firmware: Some(FirmwareRef {
                version: "2.4.1".into(),
                sha256: "1f".repeat(32),
            }),
        },
        ProfileRef {
            version: "7".into(),
            sha256: "c0".repeat(32),
        },
        Mode::Enforce,
    );
    c.product_version = "0.1.0-alpha.1".into();
    c
}

/// A valid finding value: subject `i` on `robot`, emission `n` (n > 1 is
/// a repeat of the same finding: same finding id, new event uid).
pub fn value(robot: &str, i: u64, n: u64) -> String {
    let topic = format!("rt/topic_{i}");
    let dev = Deviation::new(
        "robot.ros2.unknown_writer_topic",
        Severity::High,
        format!("writer on {topic}"),
    );
    let c = ctx(robot);
    let env = FindingBuilder::from_deviation(&dev, &c)
        .event(&RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: "0102030405060708090a0b0c".into(),
            topic,
            type_name: "std_msgs::msg::dds_::String_".into(),
        }))
        .seen(T0 + i, T0 + i + (n - 1) * 1000)
        .occurrences(n)
        .build()
        .expect("finding builds");
    to_json(&env).expect("finding serialises")
}

/// A `robot.agent.health` record of `robot` (findings contract 2.5):
/// record `seq`, one period (60 s) after the previous one. Every record is
/// an emission of the same finding.
pub fn health_value(robot: &str, seq: u64) -> String {
    let dev = Deviation::new(AGENT_HEALTH_RULE, Severity::Low, "health record")
        .with_mode(robodr_events::Mode::Observe);
    let c = ctx(robot);
    let record = AgentHealth {
        state: HealthLabel::Ok,
        reasons: vec![],
        interval_ms: 60_000,
        uptime_ms: seq * 60_000,
        seq,
        versions: vec![ComponentVersion {
            component: "robodr-agentd".into(),
            version: "0.1.0-alpha.1".into(),
        }],
        inputs: vec![InputFreshness {
            name: "capture:eth0".into(),
            last_rx_age_ms: Some(40),
            received: 1000 * seq,
            dropped: 0,
            malformed: 0,
            ended: false,
        }],
        counters: HealthCounters::default(),
        blackbox: BlackBoxHealth {
            degraded: false,
            anchored: true,
            anchor_failures: 0,
        },
        reachability: vec![Reachability {
            component: "executor".into(),
            state: ReachState::NotConfigured,
            last_ok_age_ms: None,
        }],
        credentials: vec![],
        clock: ClockHealth {
            synchronized: Some(true),
            max_error_ms: Some(3),
            source: Some(robodr_ocsf::ClockSource::Adjtimex),
            adjtimex_errno: None,
            timesync_age_ms: None,
            wall_jumps: 0,
        },
        disks: vec![DiskHealth {
            name: "spool".into(),
            free_bytes: 900,
            total_bytes: 1000,
        }],
    };
    let env = FindingBuilder::from_deviation(&dev, &c)
        .agent_health(record)
        .seen(T0, T0 + (seq - 1) * 60_000)
        .occurrences(seq)
        .build()
        .expect("health finding builds");
    to_json(&env).expect("health finding serialises")
}

fn signed(v: &str, k: &VKey) -> FindingSignature {
    sign_value(v, &k.signing()).unwrap()
}

fn line(v: &str, s: Option<&FindingSignature>) -> Vec<u8> {
    let mut l = wire::encode_line(v, s).into_bytes();
    l.push(b'\n');
    l
}

/// A JSON object of exactly `len` bytes naming `contract_version` `cv`.
fn padded(cv: &str, len: usize) -> String {
    let head = format!("{{\"contract_version\":\"{cv}\",\"pad\":\"");
    let tail = "\"}";
    let n = len - head.len() - tail.len();
    format!("{head}{}{tail}", "x".repeat(n))
}

/// Request headers, in order.
pub type Headers = Vec<(String, String)>;

/// One request of a case.
pub struct Req {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub server_time_ms: u64,
    pub expect_status: u16,
    pub expect_body: Value,
}

pub struct Case {
    pub name: &'static str,
    pub description: &'static str,
    pub requests: Vec<Req>,
}

fn ts(case: u64, req: u64) -> u64 {
    TS0 + case * 10_000 + req * 1_000
}

/// Signed headers for `body` from `sender`, batch id derived by the
/// producer's rule from the case name.
fn signed_req(
    case: &str,
    sender: &VKey,
    t: u64,
    body: Vec<u8>,
) -> (Vec<(String, String)>, Vec<u8>) {
    let n = body.iter().filter(|b| **b == b'\n').count().max(1) as u64;
    let positions: Vec<u64> = (1..=n).collect();
    let id = wire::batch_id(&format!("vectors:{case}"), &positions, &body);
    (headers_for(sender, &id, t, &body), body)
}

fn headers_for(sender: &VKey, batch_id: &str, t: u64, body: &[u8]) -> Vec<(String, String)> {
    let k = sender.signing();
    let kid = sender.key_id();
    vec![
        ("Content-Type".into(), wire::CONTENT_TYPE.into()),
        (wire::H_KEY_ID.into(), kid.clone()),
        (wire::H_BATCH_ID.into(), batch_id.into()),
        (wire::H_TIMESTAMP.into(), t.to_string()),
        (
            wire::H_SIGNATURE.into(),
            wire::sign_batch(&k, &kid, batch_id, t, body),
        ),
    ]
}

fn ok(batch_id: &str, created: u64, updated: u64, dups: u64, rejected: &[(u64, &str)]) -> Value {
    json!({
        "batch_id": batch_id,
        "replayed": false,
        "accepted": created + updated + dups,
        "created": created,
        "updated": updated,
        "duplicates": dups,
        "rejected": rejected.iter().map(|(l, c)| json!({"line": l, "code": c})).collect::<Vec<_>>(),
    })
}

fn code(c: &str) -> Value {
    json!({ "code": c })
}

fn hdr<'a>(h: &'a [(String, String)], n: &str) -> &'a str {
    &h.iter().find(|(k, _)| k == n).unwrap().1
}

fn simple(
    no: u64,
    name: &'static str,
    description: &'static str,
    sender: &str,
    body: Vec<u8>,
    expect: impl FnOnce(&str) -> Value,
) -> Case {
    let t = ts(no, 1);
    let (headers, body) = signed_req(name, &key(sender), t, body);
    let id = hdr(&headers, wire::H_BATCH_ID).to_string();
    Case {
        name,
        description,
        requests: vec![Req {
            server_time_ms: t + SERVER_LAG_MS,
            expect_status: 200,
            expect_body: expect(&id),
            headers,
            body,
        }],
    }
}

pub fn cases() -> Vec<Case> {
    let up = "uplink-ugv-001";
    let f1 = key("finding-ugv-001");
    let f2 = key("finding-ugv-002");
    let unreg = key("unregistered");
    let mut cases = Vec::new();

    cases.push(simple(
        1,
        "01-valid-single",
        "uplink key, one unsigned finding of its own robot",
        up,
        line(&value(ROBOT_1, 1, 1), None),
        |id| ok(id, 1, 0, 0, &[]),
    ));

    let a1 = value(ROBOT_1, 2, 1);
    let a2 = value(ROBOT_1, 2, 2);
    let b = value(ROBOT_1, 3, 1);
    let body = [
        line(&a1, Some(&signed(&a1, &f1))),
        line(&b, Some(&signed(&b, &f1))),
        line(&a1, Some(&signed(&a1, &f1))),
        line(&a2, Some(&signed(&a2, &f1))),
    ]
    .concat();
    cases.push(simple(
        2,
        "02-signed-multi",
        "per-finding signatures; lines are processed in order: line 3 repeats line 1 \
         (duplicate), line 4 is a new emission of line 1's finding (updated)",
        up,
        body,
        |id| ok(id, 2, 1, 1, &[]),
    ));

    let body = [
        line(&value(ROBOT_1, 4, 1), None),
        line(&value(ROBOT_2, 4, 1), None),
    ]
    .concat();
    cases.push(simple(
        3,
        "03-wrong-robot",
        "uplink key bound to ugv-001; line 2 names ugv-002",
        up,
        body,
        |id| ok(id, 1, 0, 0, &[(2, "robot_mismatch")]),
    ));

    let r1 = value(ROBOT_1, 5, 1);
    let r2 = value(ROBOT_2, 5, 1);
    let body = [
        line(&r1, Some(&signed(&r1, &f1))),
        line(&r2, Some(&signed(&r2, &f2))),
        line(&value(ROBOT_UNKNOWN, 5, 1), None),
        line(&value(ROBOT_2, 6, 1), None),
    ]
    .concat();
    cases.push(simple(
        4,
        "04-relay",
        "relay key: any registered robot; ugv-099 is not registered; ugv-002 requires \
         per-finding signatures",
        "relay-soc",
        body,
        |id| {
            ok(
                id,
                2,
                0,
                0,
                &[(3, "unknown_robot"), (4, "missing_finding_signature")],
            )
        },
    ));

    let v6 = value(ROBOT_1, 7, 1);
    let v7 = value(ROBOT_1, 8, 1);
    let v8 = value(ROBOT_1, 9, 1);
    let v9 = value(ROBOT_1, 10, 1);
    let v10 = value(ROBOT_1, 11, 1);
    let body = [
        line(&v6, Some(&signed(&v7, &f1))),
        line(&v8, Some(&signed(&v8, &unreg))),
        line(&v9, Some(&signed(&v9, &f2))),
        line(&v10, Some(&signed(&v10, &f1))),
    ]
    .concat();
    cases.push(simple(
        5,
        "05-bad-finding-sig",
        "line 1: signature over other bytes; line 2: key not registered; line 3: finding \
         key of another robot; line 4: valid",
        up,
        body,
        |id| {
            ok(
                id,
                1,
                0,
                0,
                &[
                    (1, "bad_finding_signature"),
                    (2, "bad_finding_signature"),
                    (3, "bad_finding_signature"),
                ],
            )
        },
    ));

    let v = value(ROBOT_1, 12, 1);
    let vs = serde_json::to_string(&v).unwrap();
    let good_sig = signed(&v, &f1);
    let mut bad_sig = good_sig.clone();
    bad_sig.alg = "hmac-sha256".into();
    let bad_sig_json = serde_json::to_string(&bad_sig).unwrap();
    let mut body = Vec::new();
    for l in [
        format!("{{\"value\":{vs}}}"),
        format!("{{\"value\":{vs},\"sig\":null,\"extra\":1}}"),
        "{\"value\":1,\"sig\":null}".to_string(),
        format!("{{\"value\":{vs},\"value\":{vs},\"sig\":null}}"),
        format!("[{vs},null]"),
        format!("{{\"value\":{vs},\"sig\":{bad_sig_json}}}"),
        format!("{{\"sig\":null,\"value\":{vs}}}"),
    ] {
        body.extend_from_slice(l.as_bytes());
        body.push(b'\n');
    }
    body.extend_from_slice(b"{\"value\":\"\xff\",\"sig\":null}\n");
    body.extend_from_slice(&line(&value(ROBOT_1, 13, 1), None));
    cases.push(simple(
        6,
        "06-invalid-line",
        "line objects: missing sig; unknown key; value not a string; duplicate key; not an \
         object; malformed sig object (alg); key order value/sig swapped (valid: JSON objects \
         are unordered) ; invalid UTF-8; valid",
        up,
        body,
        |id| {
            ok(
                id,
                2,
                0,
                0,
                &[
                    (1, "invalid_line"),
                    (2, "invalid_line"),
                    (3, "invalid_line"),
                    (4, "invalid_line"),
                    (5, "invalid_line"),
                    (6, "invalid_line"),
                    (8, "invalid_line"),
                ],
            )
        },
    ));

    let good = value(ROBOT_1, 14, 1);
    let ext = format!("\"external_id\":\"{ROBOT_1}:");
    assert!(good.contains(&ext));
    let tampered = good.replacen(&ext, &format!("\"external_id\":\"{ROBOT_2}:"), 1);
    let body = [
        line("not json", None),
        line(&tampered, None),
        line(&value(ROBOT_1, 15, 1), None),
    ]
    .concat();
    cases.push(simple(
        7,
        "07-invalid-finding",
        "value not JSON; external_id not <robot_id>:<finding_id>; valid",
        up,
        body,
        |id| {
            ok(
                id,
                1,
                0,
                0,
                &[(1, "invalid_finding"), (2, "invalid_finding")],
            )
        },
    ));

    let good = value(ROBOT_1, 16, 1);
    let cv = format!("\"contract_version\":\"{}\"", robodr_ocsf::CONTRACT_VERSION);
    assert!(good.contains(&cv));
    let v3 = good.replacen(&cv, "\"contract_version\":\"3.0.0\"", 1);
    let v1 = good.replacen(&cv, "\"contract_version\":\"1.3.0\"", 1);
    let body = [
        line(&v3, None),
        line(&v1, None),
        line(&value(ROBOT_1, 17, 1), None),
    ]
    .concat();
    cases.push(simple(
        8,
        "08-unsupported-contract",
        "contract_version 3.0.0 and 1.3.0 (only 2.x is ingested; the producer upgrades \
         unsigned 1.x before sending); valid",
        up,
        body,
        |id| {
            ok(
                id,
                1,
                0,
                0,
                &[(1, "unsupported_contract"), (2, "unsupported_contract")],
            )
        },
    ));

    let body = [
        line(&padded("2.1.0", wire::MAX_VALUE_BYTES + 1), None),
        line(&padded("2.1.0", wire::MAX_VALUE_BYTES), None),
        line(&value(ROBOT_1, 18, 1), None),
    ]
    .concat();
    cases.push(simple(
        9,
        "09-oversize-value",
        "decoded value of 256 KiB + 1 bytes (too_large, before validation); exactly 256 KiB \
         (validated: over the findings contract's 64 KiB, invalid_finding); valid",
        up,
        body,
        |id| ok(id, 1, 0, 0, &[(1, "too_large"), (2, "invalid_finding")]),
    ));

    let body = [
        line(&value(ROBOT_1, 19, 1), None),
        b"\n".to_vec(),
        line(&value(ROBOT_1, 20, 1), None),
    ]
    .concat();
    cases.push(simple(
        10,
        "10-empty-line",
        "an empty line between two valid ones",
        up,
        body,
        |id| ok(id, 2, 0, 0, &[(2, "invalid_line")]),
    ));

    let mut body = Vec::new();
    for i in [21, 22] {
        let mut l = wire::encode_line(&value(ROBOT_1, i, 1), None).into_bytes();
        l.extend_from_slice(b"\r\n");
        body.extend_from_slice(&l);
    }
    cases.push(simple(
        11,
        "11-crlf",
        "CRLF line ends: every line carries a CR and is refused",
        up,
        body,
        |id| ok(id, 0, 0, 0, &[(1, "invalid_line"), (2, "invalid_line")]),
    ));

    let mut body = line(&value(ROBOT_1, 23, 1), None);
    body.extend_from_slice(wire::encode_line(&value(ROBOT_1, 24, 1), None).as_bytes());
    cases.push(simple(
        12,
        "12-no-final-lf",
        "the final LF is optional",
        up,
        body,
        |id| ok(id, 2, 0, 0, &[]),
    ));

    // 13: replay (retry with a new timestamp and signature).
    {
        let body = [
            line(&value(ROBOT_1, 25, 1), None),
            line(&value(ROBOT_1, 26, 1), None),
        ]
        .concat();
        let (h1, body) = signed_req("13-replay", &key(up), ts(13, 1), body);
        let id = hdr(&h1, wire::H_BATCH_ID).to_string();
        let t2 = ts(13, 2);
        let h2 = headers_for(&key(up), &id, t2, &body);
        let mut replayed = ok(&id, 2, 0, 0, &[]);
        replayed["replayed"] = json!(true);
        cases.push(Case {
            name: "13-replay",
            description: "the same batch (same key, batch id and body) re-sent with a new \
                          timestamp and signature: the stored response, replayed: true, \
                          nothing changes",
            requests: vec![
                Req {
                    headers: h1,
                    body: body.clone(),
                    server_time_ms: ts(13, 1) + SERVER_LAG_MS,
                    expect_status: 200,
                    expect_body: ok(&id, 2, 0, 0, &[]),
                },
                Req {
                    headers: h2,
                    body,
                    server_time_ms: t2 + SERVER_LAG_MS,
                    expect_status: 200,
                    expect_body: replayed,
                },
            ],
        });
    }

    // 14: batch id reused with another body.
    {
        let (h1, b1) = signed_req(
            "14-batch-id-reuse",
            &key(up),
            ts(14, 1),
            line(&value(ROBOT_1, 27, 1), None),
        );
        let id = hdr(&h1, wire::H_BATCH_ID).to_string();
        let b2 = line(&value(ROBOT_1, 28, 1), None);
        let h2 = headers_for(&key(up), &id, ts(14, 2), &b2);
        cases.push(Case {
            name: "14-batch-id-reuse",
            description: "a known batch id with a different body: 409, nothing processed",
            requests: vec![
                Req {
                    headers: h1,
                    body: b1,
                    server_time_ms: ts(14, 1) + SERVER_LAG_MS,
                    expect_status: 200,
                    expect_body: ok(&id, 1, 0, 0, &[]),
                },
                Req {
                    headers: h2,
                    body: b2,
                    server_time_ms: ts(14, 2) + SERVER_LAG_MS,
                    expect_status: 409,
                    expect_body: code("batch_id_reuse"),
                },
            ],
        });
    }

    // 15: authentication.
    {
        let body = line(&value(ROBOT_1, 29, 1), None);
        let name = "15-auth";
        let mut reqs = Vec::new();
        // Bad signature: signed over another timestamp.
        let t = ts(15, 1);
        let (mut h, b) = signed_req(name, &key(up), t, body.clone());
        let id = hdr(&h, wire::H_BATCH_ID).to_string();
        let other = headers_for(&key(up), &id, t + 1, &b);
        h[4].1 = other[4].1.clone();
        reqs.push((h, b, t + SERVER_LAG_MS, 401, "bad_signature"));
        // Stale: 300 001 ms behind / ahead of the server clock.
        let t = ts(15, 2);
        let (h, b) = signed_req(name, &key(up), t, body.clone());
        reqs.push((h, b, t + 300_001, 401, "stale_timestamp"));
        let t = ts(15, 3);
        let (h, b) = signed_req(name, &key(up), t, body.clone());
        reqs.push((h, b, t - 300_001, 401, "stale_timestamp"));
        // Exactly 300 000 ms: accepted (inclusive bound) — see request 6.
        // Unknown key; a finding key (wrong role).
        let t = ts(15, 4);
        let (h, b) = signed_req(name, &unreg, t, body.clone());
        reqs.push((h, b, t + SERVER_LAG_MS, 401, "unknown_key"));
        let t = ts(15, 5);
        let (h, b) = signed_req(name, &f1, t, body.clone());
        reqs.push((h, b, t + SERVER_LAG_MS, 401, "unknown_key"));
        let mut requests: Vec<Req> = reqs
            .into_iter()
            .map(|(headers, body, st, s, c)| Req {
                headers,
                body,
                server_time_ms: st,
                expect_status: s,
                expect_body: code(c),
            })
            .collect();
        let t = ts(15, 6);
        let (h, b) = signed_req(name, &key(up), t, body);
        let id = hdr(&h, wire::H_BATCH_ID).to_string();
        requests.push(Req {
            headers: h,
            body: b,
            server_time_ms: t + 300_000,
            expect_status: 200,
            expect_body: ok(&id, 1, 0, 0, &[]),
        });
        cases.push(Case {
            name,
            description: "401s: bad batch signature; timestamp 300 001 ms behind and ahead of \
                          the server clock; unknown key; a finding key as sender (wrong role). \
                          Last: 300 000 ms skew is accepted (the bound is inclusive)",
            requests,
        });
    }

    // 16: content type.
    {
        let name = "16-content-type";
        let mut requests = Vec::new();
        for (i, ct) in ["application/x-ndjson; charset=utf-8", "application/json"]
            .iter()
            .enumerate()
        {
            let t = ts(16, i as u64 + 1);
            let (mut h, b) = signed_req(name, &key(up), t, line(&value(ROBOT_1, 30, 1), None));
            h[0].1 = (*ct).to_string();
            requests.push(Req {
                headers: h,
                body: b,
                server_time_ms: t + SERVER_LAG_MS,
                expect_status: 415,
                expect_body: code("unsupported_media_type"),
            });
        }
        cases.push(Case {
            name,
            description: "Content-Type must be the media type application/x-ndjson without \
                          parameters",
            requests,
        });
    }

    // 17: too many lines.
    {
        let t = ts(17, 1);
        let (h, b) = signed_req(
            "17-too-many-lines",
            &key(up),
            t,
            b"{}\n".repeat(wire::MAX_LINES + 1),
        );
        cases.push(Case {
            name: "17-too-many-lines",
            description: "1001 lines: 413 before anything else is looked at (a 4 MiB + 1 byte \
                          body gets 413 body_too_large the same way; not stored here)",
            requests: vec![Req {
                headers: h,
                body: b,
                server_time_ms: t + SERVER_LAG_MS,
                expect_status: 413,
                expect_body: code("too_many_lines"),
            }],
        });
    }

    // 18: header syntax.
    {
        let name = "18-bad-header";
        let body = line(&value(ROBOT_1, 31, 1), None);
        let mut requests = Vec::new();
        let mut push = |i: u64, edit: &dyn Fn(&mut Headers)| {
            let t = ts(18, i);
            let (mut h, b) = signed_req(name, &key(up), t, body.clone());
            edit(&mut h);
            requests.push(Req {
                headers: h,
                body: b,
                server_time_ms: t + SERVER_LAG_MS,
                expect_status: 400,
                expect_body: code("bad_header"),
            });
        };
        push(1, &|h| h[2].1 = "bad id!".into());
        push(2, &|h| h[2].1 = "a".repeat(65));
        push(3, &|h| h[3].1 = format!("0{}", h[3].1));
        push(4, &|h| h[3].1 = format!("+{}", h[3].1));
        push(5, &|h| h[4].1 = h[4].1.to_uppercase());
        push(6, &|h| {
            h.remove(4);
        });
        push(7, &|h| h[1].1 = "ed25519:0123456789ABCDEF".into());
        push(8, &|h| h[1].1 = "hmac-sha256:0123456789abcdef".into());
        cases.push(Case {
            name,
            description: "400 bad_header: batch id with a space; 65-char batch id; timestamp \
                          with a leading zero; with a sign; upper-case signature hex; no \
                          signature header; upper-case key id hex; non-ed25519 key id",
            requests,
        });
    }

    // 19: empty body.
    {
        let t = ts(19, 1);
        let k = key(up);
        let h = headers_for(&k, "empty-1", t, b"");
        cases.push(Case {
            name: "19-empty-body",
            description: "a zero-byte body: 400 empty_batch",
            requests: vec![Req {
                headers: h,
                body: Vec::new(),
                server_time_ms: t + SERVER_LAG_MS,
                expect_status: 400,
                expect_body: code("empty_batch"),
            }],
        });
    }

    cases.extend(cases_2026_10_26_review(&f1));

    // 27: the agent health record (findings contract 2.5): two signed
    // periods of one robot are one finding, created then updated.
    let h1 = health_value(ROBOT_1, 1);
    let h2 = health_value(ROBOT_1, 2);
    cases.push(simple(
        27,
        "27-agent-health",
        "findings contract 2.5: two signed robot.agent.health records of one robot (one \
         finding: created, then updated)",
        up,
        [
            line(&h1, Some(&signed(&h1, &f1))),
            line(&h2, Some(&signed(&h2, &f1))),
        ]
        .concat(),
        |id| ok(id, 1, 1, 0, &[]),
    ));
    cases
}

/// Cases added after the first producer's review (contract §10, 2026-10-26
/// review): site-scoped and origin-vouching relays, `site_mismatch`, the
/// `contract_version` major rule, lone surrogates, duplicate keys inside
/// `sig`, a `sig.key_id` with a space, repeated headers, the timestamp
/// bound, a missing `Content-Type`, a body of 4 MiB + 1.
fn cases_2026_10_26_review(f1: &VKey) -> Vec<Case> {
    let mut cases = Vec::new();

    // 20: origin-vouching relay (the SOC-side diode importer) vs a plain
    // relay, for ugv-002 (require_finding_signature).
    {
        let name = "20-vouching-relay";
        let t1 = ts(20, 1);
        let v1 = value(ROBOT_2, 40, 1);
        let v2 = value(ROBOT_2, 41, 1);
        let body = [
            line(&v1, None),
            line(&v2, Some(&signed(&v2, f1))),
            line(&value(ROBOT_UNKNOWN, 42, 1), None),
        ]
        .concat();
        let (h1, b1) = signed_req(name, &key("relay-diode"), t1, body);
        let id1 = hdr(&h1, wire::H_BATCH_ID).to_string();
        let t2 = ts(20, 2);
        let body = [
            line(&value(ROBOT_2, 43, 1), None),
            line(&value(ROBOT_1, 43, 1), None),
        ]
        .concat();
        let (h2, b2) = signed_req(name, &key("relay-soc"), t2, body);
        let id2 = hdr(&h2, wire::H_BATCH_ID).to_string();
        cases.push(Case {
            name,
            description: "request 1, origin-vouching relay (relay-diode): ugv-002 requires                           per-finding signatures, sig null is accepted (vouches_origin); a                           present sig is still verified (signed with ugv-001's finding key:                           bad_finding_signature); vouching does not register robots (ugv-099:                           unknown_robot). Request 2, plain relay (relay-soc): ugv-002 with sig                           null is missing_finding_signature; ugv-001 is accepted",
            requests: vec![
                Req {
                    headers: h1,
                    body: b1,
                    server_time_ms: t1 + SERVER_LAG_MS,
                    expect_status: 200,
                    expect_body: ok(
                        &id1,
                        1,
                        0,
                        0,
                        &[(2, "bad_finding_signature"), (3, "unknown_robot")],
                    ),
                },
                Req {
                    headers: h2,
                    body: b2,
                    server_time_ms: t2 + SERVER_LAG_MS,
                    expect_status: 200,
                    expect_body: ok(&id2, 1, 0, 0, &[(1, "missing_finding_signature")]),
                },
            ],
        });
    }

    // 21: site-scoped relay (site test-range).
    let body = [
        line(&value(ROBOT_1, 44, 1), None),
        line(&value(ROBOT_3, 44, 1), None),
        line(&value(ROBOT_UNKNOWN, 44, 1), None),
        line(&value(ROBOT_2, 44, 1), None),
    ]
    .concat();
    cases.push(simple(
        21,
        "21-site-scoped-relay",
        "relay key scoped to site test-range: ugv-001 (test-range) accepted; ugv-003 \
         (registered with range-b) site_mismatch; ugv-099 (not registered) unknown_robot, \
         checked before the site; ugv-002 (test-range, requires signatures) with sig null: \
         missing_finding_signature (a site-scoped relay does not vouch)",
        "relay-site-test-range",
        body,
        |id| {
            ok(
                id,
                1,
                0,
                0,
                &[
                    (2, "site_mismatch"),
                    (3, "unknown_robot"),
                    (4, "missing_finding_signature"),
                ],
            )
        },
    ));

    // 22: contract_version syntax (§4 step 5.2).
    let good = value(ROBOT_1, 45, 1);
    let cv = format!("\"contract_version\":\"{}\"", robodr_ocsf::CONTRACT_VERSION);
    assert!(good.contains(&cv));
    let with = |v: &str| good.replacen(&cv, &format!("\"contract_version\":\"{v}\""), 1);
    let body = [
        line(&with("1.03.0"), None),
        line(&with("2.1"), None),
        line(&with("0000000002.1.0"), None),
        line(&with("+2.1.0"), None),
        line(&with("3.0.0-rc1"), None),
        line(&with("02.1.0"), None),
    ]
    .concat();
    cases.push(simple(
        22,
        "22-contract-version-syntax",
        "MAJOR.MINOR.PATCH, each part 1-9 ASCII digits, leading zeros allowed, MAJOR read as \
         a number: 1.03.0 is major 1 (unsupported_contract); 2.1, a 10-digit part, a sign and \
         a suffix are not well formed, so the value is validated and fails \
         (invalid_finding); 02.1.0 is major 2 and validates like 2.1.0 (accepted)",
        "uplink-ugv-001",
        body,
        |id| {
            ok(
                id,
                1,
                0,
                0,
                &[
                    (1, "unsupported_contract"),
                    (2, "invalid_finding"),
                    (3, "invalid_finding"),
                    (4, "invalid_finding"),
                    (5, "invalid_finding"),
                ],
            )
        },
    ));

    // 23: line syntax.
    let v = value(ROBOT_1, 46, 1);
    let vs = serde_json::to_string(&v).unwrap();
    let s = signed(&v, f1);
    let mut body = Vec::new();
    for l in [
        "{\"value\":\"\\ud800\",\"sig\":null}".to_string(),
        "{\"value\":\"a\\udc00b\",\"sig\":null}".to_string(),
        format!(
            "{{\"value\":{vs},\"sig\":{{\"alg\":\"ed25519\",\"alg\":\"ed25519\",\"key_id\":\"{}\",\"sig\":\"{}\"}}}}",
            s.key_id, s.sig
        ),
        format!(
            "{{\"value\":{vs},\"sig\":{{\"alg\":\"ed25519\",\"key_id\":\"finding key\",\"sig\":\"{}\"}}}}",
            s.sig
        ),
    ] {
        body.extend_from_slice(l.as_bytes());
        body.push(b'\n');
    }
    body.extend_from_slice(&line(&v, Some(&s)));
    cases.push(simple(
        23,
        "23-line-syntax",
        "a lone high surrogate escape and a lone low surrogate escape in value (the decoded \
         value must be valid UTF-8): invalid_line; a key twice inside sig: invalid_line; \
         sig.key_id with a space (key ids are ASCII 0x21-0x7E): invalid_line; valid",
        "uplink-ugv-001",
        body,
        |id| {
            ok(
                id,
                1,
                0,
                0,
                &[
                    (1, "invalid_line"),
                    (2, "invalid_line"),
                    (3, "invalid_line"),
                    (4, "invalid_line"),
                ],
            )
        },
    ));

    // 24: header syntax (more).
    {
        let name = "24-header-syntax";
        let body = line(&value(ROBOT_1, 47, 1), None);
        let mut requests = Vec::new();
        let t = ts(24, 1);
        let (mut h, b) = signed_req(name, &key("uplink-ugv-001"), t, body.clone());
        let dup = h[2].clone();
        h.insert(3, dup);
        requests.push(Req {
            headers: h,
            body: b,
            server_time_ms: t + SERVER_LAG_MS,
            expect_status: 400,
            expect_body: code("bad_header"),
        });
        let t = ts(24, 2);
        let (mut h, b) = signed_req(name, &key("uplink-ugv-001"), t, body.clone());
        h[3].1 = "18446744073709551616".into();
        requests.push(Req {
            headers: h,
            body: b,
            server_time_ms: t + SERVER_LAG_MS,
            expect_status: 400,
            expect_body: code("bad_header"),
        });
        let t = ts(24, 3);
        let max = u64::MAX;
        let (h, b) = signed_req(name, &key("uplink-ugv-001"), max, body);
        requests.push(Req {
            headers: h,
            body: b,
            server_time_ms: t + SERVER_LAG_MS,
            expect_status: 401,
            expect_body: code("stale_timestamp"),
        });
        cases.push(Case {
            name,
            description: "X-RoboDR-Batch-Id twice (same value): 400 bad_header; timestamp \
                          2^64 (20 digits, over 2^64-1): 400 bad_header; timestamp exactly \
                          2^64-1, correctly signed: well formed, 401 stale_timestamp",
            requests,
        });
    }

    // 25: no Content-Type.
    {
        let t = ts(25, 1);
        let (mut h, b) = signed_req(
            "25-no-content-type",
            &key("uplink-ugv-001"),
            t,
            line(&value(ROBOT_1, 48, 1), None),
        );
        h.remove(0);
        cases.push(Case {
            name: "25-no-content-type",
            description: "no Content-Type header: 415 unsupported_media_type (step 1.1, \
                          before the X-RoboDR-* headers)",
            requests: vec![Req {
                headers: h,
                body: b,
                server_time_ms: t + SERVER_LAG_MS,
                expect_status: 415,
                expect_body: code("unsupported_media_type"),
            }],
        });
    }

    // 26: body of 4 MiB + 1 bytes (one line, well under the line limit).
    {
        let t = ts(26, 1);
        let head = b"{\"value\":\"";
        let tail = b"\",\"sig\":null}\n";
        let mut body = head.to_vec();
        body.resize(wire::MAX_BODY_BYTES + 1 - tail.len(), b'x');
        body.extend_from_slice(tail);
        assert_eq!(body.len(), wire::MAX_BODY_BYTES + 1);
        let (h, b) = signed_req("26-body-too-large", &key("uplink-ugv-001"), t, body);
        cases.push(Case {
            name: "26-body-too-large",
            description: "a body of 4 MiB + 1 bytes (4 194 305, one line): 413 body_too_large, \
                          nothing processed",
            requests: vec![Req {
                headers: h,
                body: b,
                server_time_ms: t + SERVER_LAG_MS,
                expect_status: 413,
                expect_body: code("body_too_large"),
            }],
        });
    }

    cases
}

fn pretty(v: &Value) -> Vec<u8> {
    let mut b = serde_json::to_vec_pretty(v).unwrap();
    b.push(b'\n');
    b
}

/// Every file of the fixture directory: `(relative path, bytes)`, sorted.
pub fn files() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut key_list = Vec::new();
    for k in keys() {
        let (s, p) = k.files();
        let sec = format!("keys/{}.key", k.name);
        let publ = format!("keys/{}.key.pub", k.name);
        out.push((sec.clone(), s.into_bytes()));
        out.push((publ.clone(), p.into_bytes()));
        key_list.push(json!({
            "name": k.name,
            "role": k.role,
            "robot": k.robot,
            "site": k.site,
            "vouches_origin": k.vouches_origin,
            "key_id": k.key_id(),
            "public_key_hex": to_hex(&k.public()),
            "public_key_file": publ,
            "secret_key_file": sec,
        }));
    }
    let mut case_list = Vec::new();
    for c in cases() {
        let mut reqs = Vec::new();
        for (i, r) in c.requests.iter().enumerate() {
            let base = format!("cases/{}/{}", c.name, i + 1);
            out.push((format!("{base}.body"), r.body.clone()));
            out.push((
                format!("{base}.request.json"),
                pretty(&json!({
                    "method": "POST",
                    "path": wire::INGEST_PATH,
                    "server_time_ms": r.server_time_ms,
                    "headers": r.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                    "body_file": format!("{}.body", i + 1),
                    "body_sha256": to_hex(&sha256(&r.body)),
                })),
            ));
            out.push((
                format!("{base}.response.json"),
                pretty(&json!({"status": r.expect_status, "body": r.expect_body})),
            ));
            reqs.push(base);
        }
        case_list.push(json!({
            "name": c.name,
            "description": c.description,
            "requests": reqs,
        }));
    }
    let manifest = json!({
        "format": FORMAT,
        "contract": "robodr.ingest HTTP API v1 (docs/contracts/robodr.ingest-api.md)",
        "generator": "cargo run -p robodr-export --example ingest_vectors",
        "warning": "TEST KEYS ONLY. The secret key files are published on purpose so the vectors can be regenerated; never register them anywhere real.",
        "how_to_run": [
            "Each case starts from an EMPTY workspace holding exactly `workspace` (robots and keys below) and no findings, batches or rate-limit state.",
            "Run the case's requests in order against the same workspace. Set the server clock to the request's `server_time_ms` (the 401 stale_timestamp vectors depend on it). Rate limiting must not trigger.",
            "Send `headers` exactly (names case-insensitive) and the body file byte for byte to `path`.",
            "Compare the HTTP status, then the JSON body: 200 bodies field by field except that each `rejected` entry's free-text `detail` is not compared (and absent here); error bodies by `code` only (`detail` is free text). Unknown extra response fields are allowed (contract §8)."
        ],
        "workspace": {
            "robots": ROBOTS.iter().map(|r| json!({"id": r.id, "require_finding_signature": r.require_finding_signature, "site": r.site})).collect::<Vec<_>>(),
            "keys": "every entry of `keys` whose role is uplink, relay or finding (role `unregistered` is NOT registered), with its `robot` (uplink, finding), and for relay keys its `site` scope (null: the whole workspace) and `vouches_origin` flag (contract section 3)",
        },
        "keys": key_list,
        "cases": case_list,
    });
    out.push(("manifest.json".into(), pretty(&manifest)));
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}
