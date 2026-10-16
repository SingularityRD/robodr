//! A minimal, synchronous Kafka producer (std only).
//!
//! * Plain TCP. **No TLS, no SASL.** Put it behind a local TLS proxy
//!   (stunnel, a sidecar) or run it on an isolated SOC network segment.
//! * On every new connection: ApiVersions v0, then the highest common
//!   version of Metadata (1–8) and Produce (3–8) is used.
//! * `acks = -1` (all in-sync replicas), idempotence **off** (producer id
//!   -1), compression NONE, one request in flight per call (requests are
//!   sent one at a time and awaited), so per-partition order is preserved
//!   within a [`Producer::send`] call and between calls.
//! * Delivery is **at-least-once**: a request whose response is lost (time
//!   out, disconnect) is re-sent, and the broker may then hold it twice.
//!   Consumers deduplicate on `event-uid` (contract §2).
//! * Retriable errors (leader moves, timeouts, not enough replicas, I/O)
//!   are retried with exponential backoff, refreshing metadata when the
//!   error says leadership may have changed; a call that makes no progress
//!   for `retries` rounds, or exceeds `delivery_timeout`, fails without
//!   reporting anything as delivered that was not acknowledged.
//! * Record-level errors (`MESSAGE_TOO_LARGE`, `INVALID_RECORD`, ...) are
//!   narrowed down by re-sending that partition's records one at a time;
//!   the offending record is reported as [`Outcome::Rejected`], the others
//!   are delivered. Records that cannot fit in `max_request_bytes` are
//!   rejected client-side without being sent.
//! * Fatal errors (authorisation, unsupported version, invalid topic) stop
//!   the call: [`ProduceError::Fatal`].
//! * Bounds: requests ≤ `max_request_bytes`, response frames ≤
//!   `max_response_bytes`, connect/request timeouts with a hard deadline per
//!   request (a slow-dripping broker cannot extend it).

use super::batch::{encode_batch, ProduceRecord, BATCH_OVERHEAD};
use super::errors::{self, classify, ErrorClass};
use super::proto::{self, ApiRange};
use super::wire::DecodeError;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Producer settings. [`ProducerConfig::new`] gives safe defaults.
#[derive(Debug, Clone)]
pub struct ProducerConfig {
    /// `host:port` bootstrap brokers, tried in order.
    pub bootstrap: Vec<String>,
    pub client_id: String,
    pub connect_timeout: Duration,
    /// Hard deadline for one request/response exchange.
    pub request_timeout: Duration,
    /// Broker-side `timeout_ms` of a Produce request (waiting for acks).
    pub produce_timeout_ms: i32,
    /// Upper bound for one [`Producer::send`] call.
    pub delivery_timeout: Duration,
    /// Largest request frame sent (Kafka `max.request.size`, 1 MiB).
    pub max_request_bytes: usize,
    /// Largest response frame accepted.
    pub max_response_bytes: usize,
    /// Rounds without progress before giving up.
    pub retries: u32,
    pub retry_backoff: Duration,
    pub retry_backoff_max: Duration,
    /// Refresh metadata at least this often.
    pub metadata_max_age: Duration,
}

impl ProducerConfig {
    pub fn new(bootstrap: Vec<String>) -> Self {
        Self {
            bootstrap,
            client_id: "robodr-kafka-publish".into(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            produce_timeout_ms: 30_000,
            delivery_timeout: Duration::from_secs(120),
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 16 * 1024 * 1024,
            retries: 10,
            retry_backoff: Duration::from_millis(100),
            retry_backoff_max: Duration::from_secs(10),
            metadata_max_age: Duration::from_secs(300),
        }
    }

    fn check(&self) -> Result<(), ProduceError> {
        let bad = |m: &str| Err(ProduceError::Config(m.into()));
        if self.bootstrap.is_empty() {
            return bad("no bootstrap brokers");
        }
        if self.client_id.len() > 255 {
            return bad("client id too long");
        }
        if !(4096..=(64 << 20)).contains(&self.max_request_bytes) {
            return bad("max_request_bytes must be in 4096..=64 MiB");
        }
        if !(4096..=(1 << 30)).contains(&self.max_response_bytes) {
            return bad("max_response_bytes must be in 4096..=1 GiB");
        }
        if self.produce_timeout_ms <= 0 {
            return bad("produce_timeout_ms must be > 0");
        }
        if self.request_timeout.is_zero() || self.connect_timeout.is_zero() {
            return bad("timeouts must be > 0");
        }
        Ok(())
    }
}

/// What happened to one record of a [`Producer::send`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Delivered {
        partition: i32,
        offset: i64,
    },
    /// The broker (or the client-side size check) refused this record; it
    /// will never be accepted as is. `code` is the Kafka error code.
    Rejected {
        code: i16,
        reason: String,
    },
}

/// Why a [`Producer::send`] call failed. Records whose outcome is not known
/// must be treated as **not delivered** (they may still have been written).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProduceError {
    Config(String),
    /// Non-retriable broker error (authorisation, version, topic...).
    Fatal {
        code: i16,
        context: String,
    },
    /// The broker does not support a version this client implements.
    Unsupported(String),
    RetriesExhausted(String),
    Timeout(String),
}

impl fmt::Display for ProduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration: {m}"),
            Self::Fatal { code, context } => {
                write!(
                    f,
                    "fatal Kafka error {code} ({}): {context}",
                    errors::name(*code)
                )
            }
            Self::Unsupported(m) => write!(f, "unsupported broker: {m}"),
            Self::RetriesExhausted(m) => write!(f, "retries exhausted: {m}"),
            Self::Timeout(m) => write!(f, "delivery timeout: {m}"),
        }
    }
}

impl std::error::Error for ProduceError {}

/// Counters, for logs and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProducerStats {
    pub connects: u64,
    pub requests: u64,
    pub metadata_refreshes: u64,
    pub retries: u64,
    pub io_errors: u64,
    pub delivered: u64,
    pub rejected: u64,
}

/// Connection-level failure: retried on another round.
#[derive(Debug)]
enum NetError {
    Io(io::Error),
    Protocol(String),
    Unsupported(String),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "I/O: {e}"),
            NetError::Protocol(m) => write!(f, "protocol: {m}"),
            NetError::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl From<io::Error> for NetError {
    fn from(e: io::Error) -> Self {
        NetError::Io(e)
    }
}

impl From<DecodeError> for NetError {
    fn from(e: DecodeError) -> Self {
        NetError::Protocol(e.0)
    }
}

struct Conn {
    stream: TcpStream,
    produce_v: i16,
    metadata_v: i16,
}

fn read_exact_deadline(s: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out"));
        }
        s.set_read_timeout(Some(deadline - now))?;
        match s.read(&mut buf[off..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "broker closed the connection",
                ))
            }
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out"))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl Conn {
    fn exchange(
        &mut self,
        cfg: &ProducerConfig,
        corr: &mut i32,
        api: i16,
        version: i16,
        body: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        *corr = corr.wrapping_add(1);
        let id = *corr;
        let frame = proto::frame_request(api, version, id, &cfg.client_id, body)?;
        if frame.len() > cfg.max_request_bytes {
            return Err(NetError::Protocol(format!(
                "request of {} bytes exceeds max_request_bytes",
                frame.len()
            )));
        }
        let deadline = Instant::now() + cfg.request_timeout;
        self.stream.set_write_timeout(Some(cfg.request_timeout))?;
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        let mut len = [0u8; 4];
        read_exact_deadline(&mut self.stream, &mut len, deadline)?;
        let n = i32::from_be_bytes(len);
        if n < 4 || n as usize > cfg.max_response_bytes {
            return Err(NetError::Protocol(format!("response frame size {n}")));
        }
        let mut buf = vec![0u8; n as usize];
        read_exact_deadline(&mut self.stream, &mut buf, deadline)?;
        let got = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if got != id {
            return Err(NetError::Protocol(format!(
                "correlation id {got}, expected {id}"
            )));
        }
        buf.drain(..4);
        Ok(buf)
    }

    fn open(addr: &str, cfg: &ProducerConfig, corr: &mut i32) -> Result<Conn, NetError> {
        let mut last = None;
        let addrs = addr.to_socket_addrs()?;
        let mut stream = None;
        for a in addrs {
            match TcpStream::connect_timeout(&a, cfg.connect_timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let stream = match stream {
            Some(s) => s,
            None => {
                return Err(NetError::Io(last.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("{addr}: no address"))
                })))
            }
        };
        stream.set_nodelay(true)?;
        let mut c = Conn {
            stream,
            produce_v: 0,
            metadata_v: 0,
        };
        let body = c.exchange(cfg, corr, proto::API_VERSIONS, 0, &[])?;
        let av = proto::decode_api_versions(&body)?;
        if av.error_code != 0 {
            return Err(NetError::Protocol(format!(
                "ApiVersions error {}",
                av.error_code
            )));
        }
        let pick = |apis: &[ApiRange], key, ours, what: &str| {
            proto::negotiate(apis, key, ours).ok_or_else(|| {
                NetError::Unsupported(format!(
                    "{addr}: no common {what} version (client {}-{})",
                    ours.0, ours.1
                ))
            })
        };
        c.produce_v = pick(
            &av.apis,
            proto::API_PRODUCE,
            proto::PRODUCE_VERSIONS,
            "Produce",
        )?;
        c.metadata_v = pick(
            &av.apis,
            proto::API_METADATA,
            proto::METADATA_VERSIONS,
            "Metadata",
        )?;
        Ok(c)
    }
}

#[derive(Debug, Clone)]
struct TopicState {
    /// Leader node per partition index (`None`: no leader right now).
    leaders: Vec<Option<i32>>,
    fetched: Instant,
}

/// See the module docs. One producer per thread; not `Sync`.
pub struct Producer {
    cfg: ProducerConfig,
    corr: i32,
    conns: HashMap<i32, Conn>,
    bootstrap_conn: Option<Conn>,
    brokers: HashMap<i32, String>,
    topics: HashMap<String, TopicState>,
    stale: bool,
    stats: ProducerStats,
}

enum Retry {
    Again(String),
    Fatal(ProduceError),
}

impl Producer {
    /// Validate the configuration. Connects lazily.
    pub fn new(cfg: ProducerConfig) -> Result<Self, ProduceError> {
        cfg.check()?;
        Ok(Self {
            cfg,
            corr: 0,
            conns: HashMap::new(),
            bootstrap_conn: None,
            brokers: HashMap::new(),
            topics: HashMap::new(),
            stale: true,
            stats: ProducerStats::default(),
        })
    }

    pub fn stats(&self) -> ProducerStats {
        self.stats
    }

    pub fn config(&self) -> &ProducerConfig {
        &self.cfg
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let f = 1u32 << attempt.saturating_sub(1).min(16);
        self.cfg
            .retry_backoff
            .saturating_mul(f)
            .min(self.cfg.retry_backoff_max)
    }

    fn sleep_until_or(&self, d: Duration, deadline: Instant) {
        let now = Instant::now();
        if now < deadline {
            std::thread::sleep(d.min(deadline - now));
        }
    }

    /// Fetch metadata for `topic` from any reachable broker.
    fn refresh(&mut self, topic: &str) -> Result<(), Retry> {
        self.stats.metadata_refreshes += 1;
        let mut last = String::from("no broker reachable");
        // Known leaders first, then the bootstrap list.
        let ids: Vec<i32> = self.conns.keys().copied().collect();
        for id in ids {
            let Some(mut c) = self.conns.remove(&id) else {
                continue;
            };
            match self.metadata_on(&mut c, topic) {
                Ok(m) => {
                    self.conns.insert(id, c);
                    return self.apply_metadata(topic, m);
                }
                Err(e) => {
                    self.stats.io_errors += 1;
                    last = format!("broker {id}: {e}");
                }
            }
        }
        if let Some(mut c) = self.bootstrap_conn.take() {
            match self.metadata_on(&mut c, topic) {
                Ok(m) => {
                    self.bootstrap_conn = Some(c);
                    return self.apply_metadata(topic, m);
                }
                Err(e) => {
                    self.stats.io_errors += 1;
                    last = format!("bootstrap: {e}");
                }
            }
        }
        let boot = self.cfg.bootstrap.clone();
        for addr in &boot {
            self.stats.connects += 1;
            let mut c = match Conn::open(addr, &self.cfg, &mut self.corr) {
                Ok(c) => c,
                Err(NetError::Unsupported(m)) => {
                    return Err(Retry::Fatal(ProduceError::Unsupported(m)))
                }
                Err(e) => {
                    self.stats.io_errors += 1;
                    last = format!("{addr}: {e}");
                    continue;
                }
            };
            match self.metadata_on(&mut c, topic) {
                Ok(m) => {
                    self.bootstrap_conn = Some(c);
                    return self.apply_metadata(topic, m);
                }
                Err(e) => {
                    self.stats.io_errors += 1;
                    last = format!("{addr}: {e}");
                }
            }
        }
        Err(Retry::Again(format!("metadata: {last}")))
    }

    fn metadata_on(
        &mut self,
        c: &mut Conn,
        topic: &str,
    ) -> Result<proto::MetadataResponse, NetError> {
        self.stats.requests += 1;
        let v = c.metadata_v;
        let body = proto::encode_metadata_request(v, &[topic])?;
        let resp = c.exchange(&self.cfg, &mut self.corr, proto::API_METADATA, v, &body)?;
        Ok(proto::decode_metadata(v, &resp)?)
    }

    fn apply_metadata(&mut self, topic: &str, m: proto::MetadataResponse) -> Result<(), Retry> {
        for b in &m.brokers {
            if !(1..=65535).contains(&b.port) || b.host.is_empty() {
                continue;
            }
            let addr = if b.host.contains(':') && !b.host.starts_with('[') {
                format!("[{}]:{}", b.host, b.port)
            } else {
                format!("{}:{}", b.host, b.port)
            };
            if self.brokers.get(&b.node_id) != Some(&addr) {
                // Address changed: drop a connection to the old one.
                self.conns.remove(&b.node_id);
                self.brokers.insert(b.node_id, addr);
            }
        }
        let Some(t) = m.topics.iter().find(|t| t.name == topic) else {
            return Err(Retry::Again(format!("metadata did not include {topic}")));
        };
        match classify(t.error_code) {
            ErrorClass::None => {}
            ErrorClass::Retriable { .. } => {
                return Err(Retry::Again(format!(
                    "topic {topic}: {}",
                    errors::name(t.error_code)
                )))
            }
            _ => {
                return Err(Retry::Fatal(ProduceError::Fatal {
                    code: t.error_code,
                    context: format!("metadata for topic {topic}"),
                }))
            }
        }
        let n = t.partitions.len();
        if n == 0 {
            return Err(Retry::Again(format!("topic {topic} has no partitions")));
        }
        let mut leaders = vec![None; n];
        for p in &t.partitions {
            let Ok(i) = usize::try_from(p.partition) else {
                continue;
            };
            if i < n && p.error_code != errors::LEADER_NOT_AVAILABLE && p.leader >= 0 {
                leaders[i] = Some(p.leader);
            }
        }
        self.topics.insert(
            topic.to_string(),
            TopicState {
                leaders,
                fetched: Instant::now(),
            },
        );
        self.stale = false;
        Ok(())
    }

    fn ensure_metadata(&mut self, topic: &str) -> Result<(), Retry> {
        let fresh = self
            .topics
            .get(topic)
            .is_some_and(|t| t.fetched.elapsed() < self.cfg.metadata_max_age);
        if self.stale || !fresh {
            self.refresh(topic)?;
        }
        Ok(())
    }

    /// Run `f` with retries/backoff until it succeeds, fails fatally, or
    /// the retry budget / deadline is spent.
    fn with_retries<T>(
        &mut self,
        what: &str,
        mut f: impl FnMut(&mut Self) -> Result<T, Retry>,
    ) -> Result<T, ProduceError> {
        let deadline = Instant::now() + self.cfg.delivery_timeout;
        let mut attempt = 0;
        loop {
            match f(self) {
                Ok(v) => return Ok(v),
                Err(Retry::Fatal(e)) => return Err(e),
                Err(Retry::Again(m)) => {
                    attempt += 1;
                    self.stats.retries += 1;
                    if attempt > self.cfg.retries {
                        return Err(ProduceError::RetriesExhausted(format!("{what}: {m}")));
                    }
                    if Instant::now() >= deadline {
                        return Err(ProduceError::Timeout(format!("{what}: {m}")));
                    }
                    self.stale = true;
                    self.sleep_until_or(self.backoff(attempt), deadline);
                }
            }
        }
    }

    /// Partition count of `topic` (fetching metadata if needed).
    pub fn partition_count(&mut self, topic: &str) -> Result<u32, ProduceError> {
        let t = topic.to_string();
        self.with_retries("metadata", |p| {
            p.ensure_metadata(&t)?;
            Ok(p.topics.get(&t).map_or(0, |s| s.leaders.len() as u32))
        })
    }

    /// Fixed request bytes besides the batches: frame size, header,
    /// transactional id, acks, timeout, topic array and name, partition array.
    fn request_overhead(&self, topic: &str) -> usize {
        4 + 10 + self.cfg.client_id.len() + 2 + 2 + 4 + 4 + 2 + topic.len() + 4
    }

    /// Per-partition bytes besides the records.
    const PART_OVERHEAD: usize = 4 + 4 + BATCH_OVERHEAD;

    fn conn_for(&mut self, node: i32) -> Result<&mut Conn, NetError> {
        if !self.conns.contains_key(&node) {
            let addr = self
                .brokers
                .get(&node)
                .cloned()
                .ok_or_else(|| NetError::Protocol(format!("unknown broker {node}")))?;
            self.stats.connects += 1;
            let c = Conn::open(&addr, &self.cfg, &mut self.corr)?;
            self.conns.insert(node, c);
        }
        Ok(self.conns.get_mut(&node).expect("inserted above"))
    }

    /// Produce `records` (`(partition, record)`) to `topic` with
    /// `acks=all`, preserving the order of the records of each partition.
    ///
    /// Returns one [`Outcome`] per input record (same order). On `Err`,
    /// some records may have been delivered; none is reported as such, so a
    /// caller that retries the whole call delivers at-least-once.
    pub fn send(
        &mut self,
        topic: &str,
        records: &[(i32, ProduceRecord)],
    ) -> Result<Vec<Outcome>, ProduceError> {
        let deadline = Instant::now() + self.cfg.delivery_timeout;
        let mut out: Vec<Option<Outcome>> = vec![None; records.len()];
        let mut queues: BTreeMap<i32, VecDeque<usize>> = BTreeMap::new();
        let overhead = self.request_overhead(topic);
        let single_cap = self
            .cfg
            .max_request_bytes
            .saturating_sub(overhead + Self::PART_OVERHEAD);
        for (i, (p, r)) in records.iter().enumerate() {
            if *p < 0 {
                return Err(ProduceError::Config(format!("negative partition {p}")));
            }
            if r.size_bound() > single_cap {
                out[i] = Some(Outcome::Rejected {
                    code: errors::MESSAGE_TOO_LARGE,
                    reason: format!(
                        "record needs up to {} bytes, more than fits in max_request_bytes {}",
                        r.size_bound(),
                        self.cfg.max_request_bytes
                    ),
                });
                self.stats.rejected += 1;
            } else {
                queues.entry(*p).or_default().push_back(i);
            }
        }
        let mut single: BTreeSet<i32> = BTreeSet::new();
        let mut attempt: u32 = 0;
        while !queues.is_empty() {
            let mut trouble: Option<String> = None;
            let mut progress = false;
            if let Err(r) = self.ensure_metadata(topic) {
                match r {
                    Retry::Fatal(e) => return Err(e),
                    Retry::Again(m) => trouble = Some(m),
                }
            }
            if trouble.is_none() {
                let leaders = self
                    .topics
                    .get(topic)
                    .map(|t| t.leaders.clone())
                    .unwrap_or_default();
                let mut by_leader: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
                for &p in queues.keys() {
                    match leaders.get(p as usize) {
                        Some(Some(l)) => by_leader.entry(*l).or_default().push(p),
                        Some(None) => {
                            self.stale = true;
                            trouble = Some(format!("partition {p} has no leader"));
                        }
                        None => {
                            // Partition beyond the topic's count (the count
                            // only grows, so metadata is stale or the caller
                            // used a wrong count).
                            self.stale = true;
                            trouble = Some(format!(
                                "partition {p} not in topic metadata ({} partitions)",
                                leaders.len()
                            ));
                        }
                    }
                }
                for (leader, parts) in by_leader {
                    let pr = self.produce_round(
                        topic,
                        leader,
                        &parts,
                        records,
                        &mut queues,
                        &mut single,
                        &mut out,
                    )?;
                    progress |= pr.progress;
                    if let Some(t) = pr.trouble {
                        trouble = Some(t);
                    }
                }
            }
            if let Some(t) = trouble {
                if progress {
                    attempt = 0;
                    continue;
                }
                attempt += 1;
                self.stats.retries += 1;
                if attempt > self.cfg.retries {
                    return Err(ProduceError::RetriesExhausted(t));
                }
                if Instant::now() >= deadline {
                    return Err(ProduceError::Timeout(t));
                }
                self.sleep_until_or(self.backoff(attempt), deadline);
            } else if Instant::now() >= deadline && !queues.is_empty() {
                return Err(ProduceError::Timeout("records still pending".into()));
            }
        }
        Ok(out
            .into_iter()
            .map(|o| {
                o.unwrap_or(Outcome::Rejected {
                    code: errors::UNKNOWN_SERVER_ERROR,
                    reason: "internal: no outcome".into(),
                })
            })
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    fn produce_round(
        &mut self,
        topic: &str,
        leader: i32,
        parts: &[i32],
        records: &[(i32, ProduceRecord)],
        queues: &mut BTreeMap<i32, VecDeque<usize>>,
        single: &mut BTreeSet<i32>,
        out: &mut [Option<Outcome>],
    ) -> Result<RoundResult, ProduceError> {
        let mut res = RoundResult::default();
        // Fill the request in partition order within the size budget.
        let mut budget = self
            .cfg
            .max_request_bytes
            .saturating_sub(self.request_overhead(topic));
        let mut plan: Vec<(i32, Vec<usize>)> = Vec::new();
        for &p in parts {
            if budget < Self::PART_OVERHEAD {
                break;
            }
            let mut room = budget - Self::PART_OVERHEAD;
            let mut take = Vec::new();
            let limit = if single.contains(&p) { 1 } else { usize::MAX };
            for &i in queues.get(&p).into_iter().flatten() {
                let need = records[i].1.size_bound();
                if need > room || take.len() >= limit {
                    break;
                }
                room -= need;
                take.push(i);
            }
            if take.is_empty() {
                continue;
            }
            budget = room;
            plan.push((p, take));
        }
        if plan.is_empty() {
            return Ok(res);
        }
        let mut batches = Vec::with_capacity(plan.len());
        for (p, idx) in &plan {
            let recs: Vec<ProduceRecord> = idx.iter().map(|&i| records[i].1.clone()).collect();
            let b = encode_batch(&recs)
                .map_err(|e| ProduceError::Config(format!("encoding batch: {e:?}")))?;
            batches.push((*p, b));
        }
        let conn = match self.conn_for(leader) {
            Ok(c) => c,
            Err(NetError::Unsupported(m)) => return Err(ProduceError::Unsupported(m)),
            Err(e) => {
                self.stats.io_errors += 1;
                self.stale = true;
                res.trouble = Some(format!("connect to broker {leader}: {e}"));
                return Ok(res);
            }
        };
        let v = conn.produce_v;
        let body =
            proto::encode_produce_request(v, -1, self.cfg.produce_timeout_ms, topic, &batches)
                .map_err(|e| ProduceError::Config(e.0))?;
        self.stats.requests += 1;
        let Self {
            conns, cfg, corr, ..
        } = self;
        let conn = conns.get_mut(&leader).expect("connected above");
        let resp = conn
            .exchange(cfg, corr, proto::API_PRODUCE, v, &body)
            .and_then(|b| proto::decode_produce_response(v, &b).map_err(NetError::from));
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                // Connection state unknown: drop it.
                self.conns.remove(&leader);
                self.stats.io_errors += 1;
                self.stale = true;
                res.trouble = Some(format!("produce to broker {leader}: {e}"));
                return Ok(res);
            }
        };
        for (p, idx) in plan {
            let pr = resp
                .topics
                .iter()
                .filter(|(n, _)| n == topic)
                .flat_map(|(_, v)| v.iter())
                .find(|x| x.partition == p);
            let Some(pr) = pr else {
                res.trouble = Some(format!("broker {leader} omitted partition {p}"));
                continue;
            };
            match classify(pr.error_code) {
                ErrorClass::None => {
                    let q = queues.get_mut(&p).expect("planned from queue");
                    for (k, &i) in idx.iter().enumerate() {
                        q.pop_front();
                        out[i] = Some(Outcome::Delivered {
                            partition: p,
                            offset: pr.base_offset.saturating_add(k as i64),
                        });
                        self.stats.delivered += 1;
                    }
                    if q.is_empty() {
                        queues.remove(&p);
                    }
                    res.progress = true;
                }
                ErrorClass::Record if idx.len() > 1 => {
                    single.insert(p);
                    res.progress = true;
                }
                ErrorClass::Record => {
                    let q = queues.get_mut(&p).expect("planned from queue");
                    q.pop_front();
                    if q.is_empty() {
                        queues.remove(&p);
                    }
                    single.remove(&p);
                    out[idx[0]] = Some(Outcome::Rejected {
                        code: pr.error_code,
                        reason: format!(
                            "{}{}",
                            errors::name(pr.error_code),
                            pr.error_message
                                .as_deref()
                                .map(|m| format!(": {}", m.chars().take(200).collect::<String>()))
                                .unwrap_or_default()
                        ),
                    });
                    self.stats.rejected += 1;
                    res.progress = true;
                }
                ErrorClass::Retriable { refresh } => {
                    self.stale |= refresh;
                    res.trouble = Some(format!(
                        "partition {p} on broker {leader}: {}",
                        errors::name(pr.error_code)
                    ));
                }
                ErrorClass::Fatal => {
                    return Err(ProduceError::Fatal {
                        code: pr.error_code,
                        context: format!("produce to {topic}/{p} on broker {leader}"),
                    })
                }
            }
        }
        Ok(res)
    }
}

#[derive(Default)]
struct RoundResult {
    progress: bool,
    trouble: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_checks() {
        assert!(Producer::new(ProducerConfig::new(vec![])).is_err());
        let mut c = ProducerConfig::new(vec!["127.0.0.1:1".into()]);
        c.max_request_bytes = 100;
        assert!(Producer::new(c).is_err());
        let c = ProducerConfig::new(vec!["127.0.0.1:1".into()]);
        assert!(Producer::new(c).is_ok());
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let mut c = ProducerConfig::new(vec!["x:1".into()]);
        c.retry_backoff = Duration::from_millis(100);
        c.retry_backoff_max = Duration::from_millis(1000);
        let p = Producer::new(c).unwrap();
        assert_eq!(p.backoff(1), Duration::from_millis(100));
        assert_eq!(p.backoff(2), Duration::from_millis(200));
        assert_eq!(p.backoff(4), Duration::from_millis(800));
        assert_eq!(p.backoff(5), Duration::from_millis(1000));
        assert_eq!(p.backoff(1000), Duration::from_millis(1000));
    }

    #[test]
    fn unreachable_bootstrap_exhausts_retries() {
        // Port 1 on localhost: connection refused, quickly.
        let mut c = ProducerConfig::new(vec!["127.0.0.1:1".into()]);
        c.retries = 2;
        c.retry_backoff = Duration::from_millis(1);
        let mut p = Producer::new(c).unwrap();
        let e = p.partition_count("t").unwrap_err();
        assert!(matches!(e, ProduceError::RetriesExhausted(_)), "{e}");
    }
}
