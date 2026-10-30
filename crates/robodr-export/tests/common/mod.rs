//! Shared fixtures: temp dirs, findings, and an in-process fake Kafka
//! cluster (std `TcpListener`) implementing ApiVersions v0, Metadata v1–8,
//! Produce v3–8 and InitProducerId v0–1 from the protocol documentation,
//! with a broker's idempotent-producer checks (sequence numbers, epochs,
//! duplicates of the last five batches).
#![allow(dead_code)]

use robodr_events::graph::Endpoint;
use robodr_events::{Deviation, RobotEvent, Severity};
use robodr_export::kafka::batch::{decode_batches, DecodedRecord};
use robodr_export::kafka::proto::{self, ApiRange, ApiVersionsResponse};
use robodr_ocsf::*;
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const T0: u64 = 1_790_000_000_000;
pub const NOW: u64 = 1_790_000_100_000;
pub const UNIT: &str = "ugv-007";
pub const TOPIC: &str = robodr_ocsf::DEFAULT_TOPIC;

static N: AtomicU64 = AtomicU64::new(0);

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "robodr-export-it-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn ctx(robot: &str) -> RobotContext {
    let mut c = RobotContext::new(
        RobotInfo {
            id: robot.into(),
            model: "ugv-tracked-v1".into(),
            platform_family: PlatformFamily::LinuxRos2,
            site: "range-north".into(),
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

/// A distinct, valid finding per `i`.
pub fn finding_for(robot: &str, i: u64) -> FindingEnvelope {
    let topic = format!("rt/topic_{i}");
    let dev = Deviation::new(
        "robot.ros2.unknown_writer_topic",
        Severity::High,
        format!("writer on {topic}"),
    );
    FindingBuilder::from_deviation(&dev, &ctx(robot))
        .event(&RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: "0102030405060708090a0b0c".into(),
            topic,
            type_name: "std_msgs::msg::dds_::String_".into(),
        }))
        .seen(T0 + i, T0 + i)
        .build()
        .expect("finding builds")
}

pub fn finding(i: u64) -> FindingEnvelope {
    finding_for(UNIT, i)
}

// ------------------------------------------------------------ fake broker

/// What the cluster does with the next Produce request (consumed in order;
/// when the script is empty, requests succeed).
#[derive(Debug, Clone)]
pub enum Action {
    Ok,
    /// Every partition of the request fails with this code (nothing appended).
    Error(i16),
    /// Append, then close the connection without answering.
    DisconnectAfterAppend,
    /// Close the connection without appending or answering.
    DisconnectBeforeAppend,
    /// Write half a response frame, then close (nothing appended).
    PartialFrame,
    /// Never answer (the client must time out); nothing appended.
    Hang,
    /// Answer with a garbage frame (huge size prefix).
    Garbage,
    /// Move every partition's leadership to this node, then answer
    /// NOT_LEADER_OR_FOLLOWER.
    MoveLeader(i32),
}

#[derive(Debug, Default)]
pub struct State {
    /// `(node id, port)`.
    pub brokers: Vec<(i32, u16)>,
    pub leaders: Vec<i32>,
    pub log: BTreeMap<i32, Vec<DecodedRecord>>,
    pub script: VecDeque<Action>,
    pub produce_requests: u64,
    /// `(node, api_key, version)` of every request.
    pub seen: Vec<(i32, i16, i16)>,
    /// Records with a value longer than this get MESSAGE_TOO_LARGE.
    pub max_value_bytes: usize,
    /// A partition's `records` (all its batches) longer than this get
    /// MESSAGE_TOO_LARGE, like a topic's `max.message.bytes`.
    pub max_batch_bytes: usize,
    /// `log.message.timestamp.after.max.ms`: a record whose CreateTime is
    /// further ahead of the broker's clock gets INVALID_TIMESTAMP (32), as
    /// Kafka 4.0 does by default (1 h). `None`: not checked.
    pub timestamp_after_max_ms: Option<i64>,
    /// The broker's clock relative to the test host's (ms): -7_200_000
    /// makes a publisher look 2 h ahead.
    pub clock_offset_ms: i64,
    /// Close a connection with no request for this long (the broker's
    /// `connections.max.idle.ms`); read when a connection is accepted.
    pub idle_close: Option<Duration>,
    pub produce_max_version: i16,
    pub acks_seen: Vec<i16>,
    pub batches_seen: u64,
    /// Serve TLS (read when a connection is accepted).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Require SASL/SCRAM before Metadata / Produce.
    pub scram: Option<ScramServer>,
    /// Connections that completed SCRAM.
    pub authenticated: u64,
    /// SCRAM attempts refused.
    pub auth_failures: u64,
    /// Offer InitProducerId (v0-4) in ApiVersions.
    pub init_pid_supported: bool,
    /// Answer InitProducerId with this error (e.g. 31,
    /// CLUSTER_AUTHORIZATION_FAILED).
    pub init_pid_error: Option<i16>,
    /// Next producer id handed out.
    pub next_pid: i64,
    /// Idempotent producer state per `(producer id, partition)`, as a
    /// broker keeps it: the epoch, the last sequence written, and the last
    /// five batches `(first seq, last seq, base offset)` for duplicate
    /// detection.
    pub producers: BTreeMap<(i64, i32), ProducerEntry>,
    /// Answer a recognised duplicate with DUPLICATE_SEQUENCE_NUMBER (46)
    /// instead of success with the original offset (current brokers).
    pub dup_error_code: bool,
    /// Idempotent batches received (with a producer id).
    pub idempotent_batches: u64,
    /// Duplicates recognised (not appended).
    pub duplicates: u64,
    /// `(partition, producer id, epoch, base sequence, records)` of every
    /// idempotent batch appended.
    pub appended: Vec<(i32, i64, i16, i32, i32)>,
}

/// What a broker remembers of an idempotent producer on one partition.
#[derive(Debug, Clone, Default)]
pub struct ProducerEntry {
    pub epoch: i16,
    pub last_seq: i32,
    pub recent: VecDeque<(i32, i32, i64)>,
}

/// `seq + n`, wrapping like Kafka.
pub fn inc_seq(seq: i32, n: i32) -> i32 {
    if seq > i32::MAX - n {
        n - (i32::MAX - seq) - 1
    } else {
        seq + n
    }
}

/// The broker's sequence check for one idempotent batch (Kafka's
/// `ProducerAppendInfo`): `Ok(None)` append, `Ok(Some(offset))` duplicate
/// of a recent batch, `Err(code)` refuse.
fn check_sequence(
    st: &State,
    pid: i64,
    epoch: i16,
    p: i32,
    first: i32,
    n: i32,
) -> Result<Option<i64>, i16> {
    let last = inc_seq(first, n - 1);
    match st.producers.get(&(pid, p)) {
        // An unknown (or expired) producer: any sequence is accepted.
        None => Ok(None),
        Some(e) if epoch < e.epoch => Err(47),
        Some(e) if epoch > e.epoch => {
            if first == 0 {
                Ok(None)
            } else {
                Err(45)
            }
        }
        Some(e) => {
            if let Some((_, _, off)) = e.recent.iter().find(|(f, l, _)| *f == first && *l == last) {
                Ok(Some(*off))
            } else if first == inc_seq(e.last_seq, 1) {
                Ok(None)
            } else {
                Err(45)
            }
        }
    }
}

/// The broker side of SASL/SCRAM (RFC 5802), for the fake cluster.
#[derive(Debug, Clone)]
pub struct ScramServer {
    pub mechanism: robodr_export::kafka::sasl::Mechanism,
    pub user: String,
    pub password: String,
    pub iterations: u32,
    /// SaslAuthenticate v1 `session_lifetime_ms`.
    pub session_lifetime_ms: i64,
    /// Answer with a wrong server signature (an impostor broker).
    pub forge_server_signature: bool,
}

impl ScramServer {
    pub fn new(mechanism: robodr_export::kafka::sasl::Mechanism, user: &str, pw: &str) -> Self {
        Self {
            mechanism,
            user: user.into(),
            password: pw.into(),
            iterations: 4096,
            session_lifetime_ms: 0,
            forge_server_signature: false,
        }
    }
}

#[derive(Clone)]
pub struct Cluster {
    pub state: Arc<Mutex<State>>,
}

impl Cluster {
    /// `nodes` brokers (ids 1..=nodes), `partitions` partitions all led by node 1.
    pub fn start(nodes: i32, partitions: usize) -> Self {
        Self::start_with(nodes, partitions, |_| {})
    }

    /// [`Cluster::start`] with `f` applied to the initial state (TLS,
    /// SCRAM).
    pub fn start_with(nodes: i32, partitions: usize, f: impl FnOnce(&mut State)) -> Self {
        let mut init = State {
            leaders: vec![1; partitions],
            max_value_bytes: usize::MAX,
            max_batch_bytes: usize::MAX,
            produce_max_version: 8,
            init_pid_supported: true,
            next_pid: 1000,
            ..Default::default()
        };
        f(&mut init);
        let state = Arc::new(Mutex::new(init));
        for node in 1..=nodes {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            state.lock().unwrap().brokers.push((node, port));
            let st = state.clone();
            std::thread::spawn(move || {
                for s in l.incoming() {
                    let Ok(s) = s else { continue };
                    let st = st.clone();
                    std::thread::spawn(move || {
                        let (idle, tls) = {
                            let g = st.lock().unwrap();
                            (g.idle_close, g.tls.clone())
                        };
                        if idle.is_some() {
                            let _ = s.set_read_timeout(idle);
                        }
                        match tls {
                            None => serve(node, s, st),
                            Some(cfg) => {
                                let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                                    return;
                                };
                                serve(node, rustls::StreamOwned::new(conn, s), st)
                            }
                        }
                    });
                }
            });
        }
        Self { state }
    }

    pub fn bootstrap(&self) -> Vec<String> {
        let s = self.state.lock().unwrap();
        vec![format!("127.0.0.1:{}", s.brokers[0].1)]
    }

    pub fn script(&self, a: impl IntoIterator<Item = Action>) {
        self.state.lock().unwrap().script.extend(a);
    }

    pub fn values(&self, partition: i32) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .log
            .get(&partition)
            .map(|v| {
                v.iter()
                    .map(|r| String::from_utf8(r.value.clone().unwrap()).unwrap())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn all_records(&self) -> Vec<(i32, DecodedRecord)> {
        let s = self.state.lock().unwrap();
        s.log
            .iter()
            .flat_map(|(p, v)| v.iter().map(move |r| (*p, r.clone())))
            .collect()
    }

    pub fn total(&self) -> usize {
        self.state.lock().unwrap().log.values().map(Vec::len).sum()
    }

    /// Forget every idempotent producer (as after
    /// `producer.id.expiration.ms`): their next batch is accepted with any
    /// sequence.
    pub fn forget_producers(&self) {
        self.state.lock().unwrap().producers.clear();
    }

    /// InitProducerId requests answered.
    pub fn init_pid_requests(&self) -> usize {
        let s = self.state.lock().unwrap();
        s.seen
            .iter()
            .filter(|(_, k, _)| *k == proto::API_INIT_PRODUCER_ID)
            .count()
    }
}

fn read_frame(s: &mut impl Read) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).ok()?;
    let n = i32::from_be_bytes(len);
    if !(0..=(64 << 20)).contains(&n) {
        return None;
    }
    let mut b = vec![0u8; n as usize];
    s.read_exact(&mut b).ok()?;
    Some(b)
}

fn write_response(s: &mut impl Write, corr: i32, body: &[u8]) -> std::io::Result<()> {
    let mut f = Vec::with_capacity(body.len() + 8);
    f.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    f.extend_from_slice(&corr.to_be_bytes());
    f.extend_from_slice(body);
    s.write_all(&f)?;
    s.flush()
}

/// One connection's SCRAM state.
#[derive(Default)]
struct ScramConn {
    mechanism_ok: bool,
    /// `(client-first-bare, server-first)` after the first message.
    first: Option<(String, String)>,
    done: bool,
}

/// Answer one SaslAuthenticate message: `Ok(reply)` or `Err(reason)`.
fn scram_step(srv: &ScramServer, c: &mut ScramConn, msg: &[u8]) -> Result<String, String> {
    use robodr_export::kafka::sasl::{b64_decode, b64_encode};
    let m = srv.mechanism;
    let msg = std::str::from_utf8(msg).map_err(|_| "not UTF-8")?;
    match c.first.take() {
        None => {
            let bare = msg.strip_prefix("n,,").ok_or("bad GS2 header")?;
            let mut parts = bare.split(',');
            let user = parts
                .next()
                .and_then(|u| u.strip_prefix("n="))
                .ok_or("no user")?
                .replace("=2C", ",")
                .replace("=3D", "=");
            let cnonce = parts
                .next()
                .and_then(|r| r.strip_prefix("r="))
                .ok_or("no nonce")?;
            if user != srv.user {
                return Err("unknown user".into());
            }
            let sf = format!(
                "r={cnonce}fakebrokernonce,s={},i={}",
                b64_encode(b"robodr-salt"),
                srv.iterations
            );
            c.first = Some((bare.to_string(), sf.clone()));
            Ok(sf)
        }
        Some((bare, sf)) => {
            let (without_proof, proof) = msg.rsplit_once(",p=").ok_or("no proof")?;
            let proof = b64_decode(proof).ok_or("bad proof")?;
            let auth = format!("{bare},{sf},{without_proof}");
            let salted = m.hi(srv.password.as_bytes(), b"robodr-salt", srv.iterations);
            let client_key = m.hmac(&salted, b"Client Key");
            let stored: Vec<u8> = {
                use sha2::Digest;
                match m {
                    robodr_export::kafka::sasl::Mechanism::ScramSha256 => {
                        sha2::Sha256::digest(&client_key).to_vec()
                    }
                    robodr_export::kafka::sasl::Mechanism::ScramSha512 => {
                        sha2::Sha512::digest(&client_key).to_vec()
                    }
                }
            };
            let sig = m.hmac(&stored, auth.as_bytes());
            let ck: Vec<u8> = proof.iter().zip(&sig).map(|(a, b)| a ^ b).collect();
            if ck != client_key {
                return Err("bad proof".into());
            }
            let server_key = m.hmac(&salted, b"Server Key");
            let mut ss = m.hmac(&server_key, auth.as_bytes());
            if srv.forge_server_signature {
                ss[0] ^= 1;
            }
            c.done = true;
            Ok(format!("v={}", b64_encode(&ss)))
        }
    }
}

fn serve<S: Read + Write>(node: i32, mut s: S, st: Arc<Mutex<State>>) {
    use robodr_export::kafka::sasl;
    let scram = st.lock().unwrap().scram.clone();
    let mut sc = ScramConn::default();
    while let Some(frame) = read_frame(&mut s) {
        let Ok((h, mut r)) = proto::parse_request_header(&frame) else {
            return;
        };
        st.lock()
            .unwrap()
            .seen
            .push((node, h.api_key, h.api_version));
        if scram.is_some()
            && !sc.done
            && ![
                proto::API_VERSIONS,
                sasl::API_SASL_HANDSHAKE,
                sasl::API_SASL_AUTHENTICATE,
            ]
            .contains(&h.api_key)
        {
            // Like Kafka: unauthenticated, the connection is closed.
            return;
        }
        match h.api_key {
            sasl::API_SASL_HANDSHAKE => {
                let mech = r.string().unwrap_or_default().to_string();
                let Some(srv) = &scram else { return };
                sc.mechanism_ok = mech == srv.mechanism.name();
                let body = sasl::encode_handshake_response(
                    if sc.mechanism_ok { 0 } else { 33 },
                    &[srv.mechanism.name()],
                );
                if write_response(&mut s, h.correlation_id, &body).is_err() {
                    return;
                }
            }
            sasl::API_SASL_AUTHENTICATE => {
                let msg = r
                    .nullable_bytes()
                    .ok()
                    .flatten()
                    .unwrap_or_default()
                    .to_vec();
                let Some(srv) = &scram else { return };
                let res = if sc.mechanism_ok {
                    scram_step(srv, &mut sc, &msg)
                } else {
                    Err("no handshake".into())
                };
                let resp = match &res {
                    Ok(reply) => sasl::AuthenticateResponse {
                        error_code: 0,
                        error_message: None,
                        auth_bytes: reply.clone().into_bytes(),
                        session_lifetime_ms: if sc.done { srv.session_lifetime_ms } else { 0 },
                    },
                    Err(e) => sasl::AuthenticateResponse {
                        error_code: 58,
                        error_message: Some(format!("Authentication failed: {e}")),
                        auth_bytes: Vec::new(),
                        session_lifetime_ms: 0,
                    },
                };
                {
                    let mut g = st.lock().unwrap();
                    if res.is_err() {
                        g.auth_failures += 1;
                    } else if sc.done {
                        g.authenticated += 1;
                    }
                }
                let body = sasl::encode_authenticate_response(h.api_version, &resp);
                if write_response(&mut s, h.correlation_id, &body).is_err() || res.is_err() {
                    return;
                }
            }
            proto::API_INIT_PRODUCER_ID => {
                let req = proto::decode_init_producer_id_request(&mut r).expect("init pid");
                assert_eq!(req.0, None, "no transactional id");
                let resp = {
                    let mut g = st.lock().unwrap();
                    match g.init_pid_error {
                        Some(code) => proto::InitProducerIdResponse {
                            throttle_time_ms: 0,
                            error_code: code,
                            producer_id: -1,
                            producer_epoch: -1,
                        },
                        None => {
                            let id = g.next_pid;
                            g.next_pid += 1;
                            proto::InitProducerIdResponse {
                                throttle_time_ms: 0,
                                error_code: 0,
                                producer_id: id,
                                producer_epoch: 0,
                            }
                        }
                    }
                };
                let body = proto::encode_init_producer_id_response(&resp);
                if write_response(&mut s, h.correlation_id, &body).is_err() {
                    return;
                }
            }
            proto::API_VERSIONS => {
                let (pmax, init_pid) = {
                    let g = st.lock().unwrap();
                    (g.produce_max_version, g.init_pid_supported)
                };
                let init_pid_api = init_pid.then_some(ApiRange {
                    api_key: proto::API_INIT_PRODUCER_ID,
                    min: 0,
                    max: 4,
                });
                let mut apis = vec![
                    ApiRange {
                        api_key: sasl::API_SASL_HANDSHAKE,
                        min: 0,
                        max: 1,
                    },
                    ApiRange {
                        api_key: sasl::API_SASL_AUTHENTICATE,
                        min: 0,
                        max: 2,
                    },
                ];
                if scram.is_none() {
                    apis.clear();
                }
                let body = proto::encode_api_versions_response(&ApiVersionsResponse {
                    error_code: 0,
                    apis: apis
                        .into_iter()
                        .chain(vec![
                            ApiRange {
                                api_key: 0,
                                min: 0,
                                max: pmax,
                            },
                            ApiRange {
                                api_key: 3,
                                min: 0,
                                max: 12,
                            },
                            ApiRange {
                                api_key: 18,
                                min: 0,
                                max: 3,
                            },
                        ])
                        .chain(init_pid_api)
                        .collect(),
                });
                if write_response(&mut s, h.correlation_id, &body).is_err() {
                    return;
                }
            }
            proto::API_METADATA => {
                let topics = proto::decode_metadata_request(&mut r).unwrap();
                let st = st.lock().unwrap();
                let m = proto::MetadataResponse {
                    brokers: st
                        .brokers
                        .iter()
                        .map(|(id, port)| proto::Broker {
                            node_id: *id,
                            host: "127.0.0.1".into(),
                            port: i32::from(*port),
                        })
                        .collect(),
                    topics: topics
                        .iter()
                        .map(|t| proto::TopicMeta {
                            error_code: if t == TOPIC { 0 } else { 3 },
                            name: t.clone(),
                            partitions: if t == TOPIC {
                                st.leaders
                                    .iter()
                                    .enumerate()
                                    .map(|(i, l)| proto::PartitionMeta {
                                        error_code: 0,
                                        partition: i as i32,
                                        leader: *l,
                                    })
                                    .collect()
                            } else {
                                vec![]
                            },
                        })
                        .collect(),
                };
                let body = proto::encode_metadata_response(h.api_version, &m);
                drop(st);
                if write_response(&mut s, h.correlation_id, &body).is_err() {
                    return;
                }
            }
            proto::API_PRODUCE => {
                let req = proto::decode_produce_request(&mut r).expect("produce request");
                let action = {
                    let mut st = st.lock().unwrap();
                    st.produce_requests += 1;
                    st.acks_seen.push(req.acks);
                    st.script.pop_front().unwrap_or(Action::Ok)
                };
                let mut parts = Vec::new();
                let append = matches!(action, Action::Ok | Action::DisconnectAfterAppend);
                for (topic, ps) in &req.topics {
                    for (p, bytes) in ps {
                        let batches = decode_batches(bytes).expect("valid RecordBatch (CRC)");
                        let mut st = st.lock().unwrap();
                        st.batches_seen += batches.len() as u64;
                        let mut code = match &action {
                            Action::Error(c) => *c,
                            Action::MoveLeader(_) => 6,
                            _ => 0,
                        };
                        if code == 0 && topic != TOPIC {
                            code = 3;
                        }
                        if code == 0 && st.leaders.get(*p as usize) != Some(&node) {
                            code = 6;
                        }
                        let too_big = batches
                            .iter()
                            .flat_map(|b| &b.records)
                            .any(|r| r.value.as_ref().map_or(0, Vec::len) > st.max_value_bytes);
                        if code == 0 && too_big {
                            code = 10;
                        }
                        if code == 0 && bytes.len() > st.max_batch_bytes {
                            code = 10;
                        }
                        if let Some(after) = st.timestamp_after_max_ms {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as i64
                                + st.clock_offset_ms;
                            let ahead = batches
                                .iter()
                                .flat_map(|b| &b.records)
                                .any(|r| r.timestamp_ms > now + after);
                            if code == 0 && ahead {
                                code = 32;
                            }
                        }
                        let mut base = -1;
                        if code == 0 && append {
                            for b in batches {
                                let n = b.records.len() as i32;
                                assert_eq!(b.last_offset_delta, n - 1);
                                let offset = st.log.get(p).map_or(0, Vec::len) as i64;
                                if b.producer_id >= 0 {
                                    st.idempotent_batches += 1;
                                    assert!(b.producer_epoch >= 0 && b.base_sequence >= 0);
                                    match check_sequence(
                                        &st,
                                        b.producer_id,
                                        b.producer_epoch,
                                        *p,
                                        b.base_sequence,
                                        n,
                                    ) {
                                        Err(c) => {
                                            code = c;
                                            break;
                                        }
                                        Ok(Some(orig)) => {
                                            st.duplicates += 1;
                                            if st.dup_error_code {
                                                code = 46;
                                            } else if base < 0 {
                                                base = orig;
                                            }
                                            continue;
                                        }
                                        Ok(None) => {
                                            let e = st
                                                .producers
                                                .entry((b.producer_id, *p))
                                                .or_default();
                                            if e.epoch != b.producer_epoch {
                                                e.recent.clear();
                                            }
                                            e.epoch = b.producer_epoch;
                                            e.last_seq = inc_seq(b.base_sequence, n - 1);
                                            e.recent.push_back((
                                                b.base_sequence,
                                                e.last_seq,
                                                offset,
                                            ));
                                            if e.recent.len() > 5 {
                                                e.recent.pop_front();
                                            }
                                            st.appended.push((
                                                *p,
                                                b.producer_id,
                                                b.producer_epoch,
                                                b.base_sequence,
                                                n,
                                            ));
                                        }
                                    }
                                }
                                if base < 0 {
                                    base = offset;
                                }
                                st.log.entry(*p).or_default().extend(b.records);
                            }
                        }
                        if code != 0 {
                            base = -1;
                        }
                        parts.push(proto::PartitionProduceResponse {
                            partition: *p,
                            error_code: code,
                            base_offset: base,
                            record_errors: vec![],
                            error_message: None,
                        });
                    }
                }
                if let Action::MoveLeader(n) = action {
                    let mut st = st.lock().unwrap();
                    for l in st.leaders.iter_mut() {
                        *l = n;
                    }
                }
                match action {
                    Action::DisconnectAfterAppend | Action::DisconnectBeforeAppend => return,
                    Action::Hang => {
                        std::thread::sleep(Duration::from_secs(5));
                        return;
                    }
                    Action::PartialFrame => {
                        let _ = s.write_all(&[0, 0, 0, 100, 0, 0]);
                        return;
                    }
                    Action::Garbage => {
                        let _ = s.write_all(&[0x7f, 0xff, 0xff, 0xff, 1, 2, 3]);
                        return;
                    }
                    _ => {}
                }
                let body = proto::encode_produce_response(
                    h.api_version,
                    &proto::ProduceResponse {
                        topics: vec![(req.topics[0].0.clone(), parts)],
                    },
                );
                if write_response(&mut s, h.correlation_id, &body).is_err() {
                    return;
                }
            }
            _ => return,
        }
    }
}

/// Header value as a string.
pub fn header(r: &DecodedRecord, k: &str) -> Option<String> {
    r.headers
        .iter()
        .find(|(hk, _)| hk == k)
        .and_then(|(_, v)| v.clone())
        .map(|v| String::from_utf8(v).unwrap())
}
