//! Shared fixtures: temp dirs, findings, and an in-process fake Kafka
//! cluster (std `TcpListener`) implementing ApiVersions v0, Metadata v1–8
//! and Produce v3–8 from the protocol documentation.
#![allow(dead_code)]

use robodr_events::graph::Endpoint;
use robodr_events::{Deviation, RobotEvent, Severity};
use robodr_export::kafka::batch::{decode_batches, DecodedRecord};
use robodr_export::kafka::proto::{self, ApiRange, ApiVersionsResponse};
use robodr_ocsf::*;
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const T0: u64 = 1_790_000_000_000;
pub const NOW: u64 = 1_790_000_100_000;
pub const UNIT: &str = "ugv-007";
pub const TOPIC: &str = "robot-edr.findings";

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
    pub produce_max_version: i16,
    pub acks_seen: Vec<i16>,
    pub batches_seen: u64,
}

#[derive(Clone)]
pub struct Cluster {
    pub state: Arc<Mutex<State>>,
}

impl Cluster {
    /// `nodes` brokers (ids 1..=nodes), `partitions` partitions all led by node 1.
    pub fn start(nodes: i32, partitions: usize) -> Self {
        let state = Arc::new(Mutex::new(State {
            leaders: vec![1; partitions],
            max_value_bytes: usize::MAX,
            produce_max_version: 8,
            ..Default::default()
        }));
        for node in 1..=nodes {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            state.lock().unwrap().brokers.push((node, port));
            let st = state.clone();
            std::thread::spawn(move || {
                for s in l.incoming() {
                    let Ok(s) = s else { continue };
                    let st = st.clone();
                    std::thread::spawn(move || serve(node, s, st));
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
}

fn read_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
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

fn write_response(s: &mut TcpStream, corr: i32, body: &[u8]) -> std::io::Result<()> {
    let mut f = Vec::with_capacity(body.len() + 8);
    f.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    f.extend_from_slice(&corr.to_be_bytes());
    f.extend_from_slice(body);
    s.write_all(&f)
}

fn serve(node: i32, mut s: TcpStream, st: Arc<Mutex<State>>) {
    while let Some(frame) = read_frame(&mut s) {
        let Ok((h, mut r)) = proto::parse_request_header(&frame) else {
            return;
        };
        st.lock()
            .unwrap()
            .seen
            .push((node, h.api_key, h.api_version));
        match h.api_key {
            proto::API_VERSIONS => {
                let pmax = st.lock().unwrap().produce_max_version;
                let body = proto::encode_api_versions_response(&ApiVersionsResponse {
                    error_code: 0,
                    apis: vec![
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
                    ],
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
                        let mut base = -1;
                        if code == 0 && append {
                            let log = st.log.entry(*p).or_default();
                            base = log.len() as i64;
                            for b in batches {
                                assert_eq!(b.producer_id, -1, "idempotence must be off");
                                log.extend(b.records);
                            }
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
