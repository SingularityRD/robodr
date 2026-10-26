//! A minimal, synchronous Kafka producer (std only).
//!
//! * Plain TCP. **No TLS, no SASL.** Put it behind a local TLS proxy
//!   (stunnel, a sidecar) or run it on an isolated SOC network segment.
//!   Pointed at a TLS listener (answers with a TLS alert) or a SASL listener
//!   (closes the connection after ApiVersions), the error says so.
//! * Connections unused for `connections_max_idle` (9 min, as the Java
//!   client) are closed before the broker's own idle timeout (10 min)
//!   would make the next request fail.
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
//!   narrowed down by halving that partition's batch until it is accepted
//!   or holds one record (as the Java client splits a batch on
//!   `MESSAGE_TOO_LARGE`); the halved size is kept for the rest of the call,
//!   so a batch that is only too large as a whole (topic
//!   `max.message.bytes` below `max_request_bytes`) does not degrade to one
//!   record per request. The offending record is reported as
//!   [`Outcome::Rejected`], the others are delivered. Records that cannot
//!   fit in `max_request_bytes` are rejected client-side without being sent.
//! * Fatal errors (authorisation, unsupported version, invalid topic) stop
//!   the call: [`ProduceError::Fatal`].
//! * Bounds: requests ≤ `max_request_bytes`, response frames ≤
//!   `max_response_bytes`, connect/request timeouts with a hard deadline per
//!   request covering both writing the request and reading the response (a
//!   slow-draining or slow-dripping broker cannot extend it). The request
//!   deadline must exceed the broker-side `produce_timeout_ms` (default
//!   30 s + 5 s), or a slow but healthy acknowledgement would be cut off and
//!   re-sent. The broker list learnt from metadata is replaced (not merged)
//!   on every refresh and capped at [`MAX_BROKERS`] entries.
//! * Name resolution: IP-literal addresses (`10.0.0.5:9092`,
//!   `[fd00::5]:9092`) are used directly. Host names are resolved by the
//!   system resolver on a helper thread, waited for at most
//!   `connect_timeout`; a resolver that hangs longer fails the attempt (the
//!   thread is abandoned and finishes on its own) and at most
//!   [`MAX_RESOLVER_THREADS`] such threads may be outstanding at once, so a
//!   dead DNS server cannot pile up threads. On an air-gapped SOC network,
//!   prefer IP literals (and advertised listeners that are IP literals).

use super::batch::{encode_batch, ProduceRecord, BATCH_OVERHEAD};
use super::errors::{self, classify, ErrorClass};
use super::proto::{self, ApiRange};
use super::wire::DecodeError;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Most brokers kept from a metadata response.
pub const MAX_BROKERS: usize = 1024;
/// Most outstanding name-resolution helper threads (process-wide).
pub const MAX_RESOLVER_THREADS: usize = 4;
static RESOLVERS: AtomicUsize = AtomicUsize::new(0);

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
    /// Close a connection unused for this long instead of using it (Java
    /// `connections.max.idle.ms`, 9 min): brokers close idle connections
    /// after their own `connections.max.idle.ms` (default 10 min), and a
    /// request on such a connection fails and costs a retry.
    pub connections_max_idle: Duration,
}

impl ProducerConfig {
    pub fn new(bootstrap: Vec<String>) -> Self {
        Self {
            bootstrap,
            client_id: "robodr-kafka-publish".into(),
            connect_timeout: Duration::from_secs(10),
            // Must exceed produce_timeout_ms (checked).
            request_timeout: Duration::from_secs(35),
            produce_timeout_ms: 30_000,
            delivery_timeout: Duration::from_secs(120),
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 16 * 1024 * 1024,
            retries: 10,
            retry_backoff: Duration::from_millis(100),
            retry_backoff_max: Duration::from_secs(10),
            metadata_max_age: Duration::from_secs(300),
            connections_max_idle: Duration::from_secs(540),
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
        if self.connections_max_idle.is_zero() {
            return bad("connections_max_idle must be > 0");
        }
        if self.request_timeout.is_zero() || self.connect_timeout.is_zero() {
            return bad("timeouts must be > 0");
        }
        if self.request_timeout <= Duration::from_millis(self.produce_timeout_ms as u64) {
            return bad(
                "request_timeout must exceed produce_timeout_ms (the broker may wait that long \
                 for acknowledgements before answering)",
            );
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
    /// No request after the ApiVersions handshake has completed yet. A
    /// SASL listener answers ApiVersions (allowed before authentication)
    /// and then closes the connection on the first other request.
    fresh: bool,
    /// End of the last completed exchange (or of the handshake).
    last_used: Instant,
}

/// Explain a response that is really a TLS record (a plaintext request to
/// a TLS listener is answered with a TLS alert, `15 03 0x ...`).
fn tls_hint(prefix: [u8; 4]) -> Option<String> {
    (matches!(prefix[0], 0x15 | 0x16) && prefix[1] == 0x03).then(|| {
        format!(
            "the broker answered with a TLS record ({:02x} {:02x} {:02x} ...): this listener \
             requires TLS, and this client speaks PLAINTEXT only (use a PLAINTEXT listener \
             or a local TLS proxy)",
            prefix[0], prefix[1], prefix[2]
        )
    })
}

/// A connection closed by the broker right after a successful ApiVersions
/// handshake: name the likely cause.
fn sasl_hint(e: io::Error) -> io::Error {
    if matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    ) {
        io::Error::new(
            e.kind(),
            format!(
                "{e} on the first request after ApiVersions: if this listener requires \
                 SASL, note that this client has no SASL/TLS (use a PLAINTEXT listener)"
            ),
        )
    } else {
        e
    }
}

/// Write all of `buf` before `deadline` (the write timeout is re-armed with
/// the remaining time before every `write`, so a peer that drains slowly
/// cannot extend the exchange).
fn write_all_deadline(s: &mut TcpStream, mut buf: &[u8], deadline: Instant) -> io::Result<()> {
    while !buf.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out"));
        }
        s.set_write_timeout(Some(deadline - now))?;
        match s.write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "broker closed the connection",
                ))
            }
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out"))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Resolve `addr` (`host:port`). IP literals never touch the resolver;
/// host names are resolved on a helper thread waited for at most `timeout`
/// (see the module docs).
pub(crate) fn resolve(addr: &str, timeout: Duration) -> io::Result<Vec<SocketAddr>> {
    if let Ok(a) = addr.parse::<SocketAddr>() {
        return Ok(vec![a]);
    }
    // Claim a resolver slot.
    let mut cur = RESOLVERS.load(Ordering::Acquire);
    loop {
        if cur >= MAX_RESOLVER_THREADS {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{addr}: too many name lookups outstanding (resolver hanging?)"),
            ));
        }
        match RESOLVERS.compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(v) => cur = v,
        }
    }
    let (tx, rx) = mpsc::channel();
    let owned = addr.to_string();
    let spawned = std::thread::Builder::new()
        .name("robodr-kafka-dns".into())
        .spawn(move || {
            let r = owned.to_socket_addrs().map(|i| i.collect::<Vec<_>>());
            RESOLVERS.fetch_sub(1, Ordering::AcqRel);
            let _ = tx.send(r);
        });
    if let Err(e) = spawned {
        RESOLVERS.fetch_sub(1, Ordering::AcqRel);
        return Err(e);
    }
    match rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{addr}: name resolution timed out"),
        )),
    }
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
        let hint = self.fresh && api != proto::API_VERSIONS;
        let io = |e: io::Error| NetError::Io(if hint { sasl_hint(e) } else { e });
        write_all_deadline(&mut self.stream, &frame, deadline).map_err(io)?;
        let mut len = [0u8; 4];
        read_exact_deadline(&mut self.stream, &mut len, deadline).map_err(io)?;
        let n = i32::from_be_bytes(len);
        if n < 4 || n as usize > cfg.max_response_bytes {
            if let Some(m) = tls_hint(len) {
                return Err(NetError::Protocol(m));
            }
            return Err(NetError::Protocol(format!("response frame size {n}")));
        }
        let mut buf = vec![0u8; n as usize];
        read_exact_deadline(&mut self.stream, &mut buf, deadline).map_err(io)?;
        if api != proto::API_VERSIONS {
            self.fresh = false;
        }
        self.last_used = Instant::now();
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
        let addrs = resolve(addr, cfg.connect_timeout)?;
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
            fresh: true,
            last_used: Instant::now(),
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

    /// Drop connections idle for `connections_max_idle` or longer.
    fn close_idle(&mut self) {
        let max = self.cfg.connections_max_idle;
        self.conns.retain(|_, c| c.last_used.elapsed() < max);
        if self
            .bootstrap_conn
            .as_ref()
            .is_some_and(|c| c.last_used.elapsed() >= max)
        {
            self.bootstrap_conn = None;
        }
    }

    /// Fetch metadata for `topic` from any reachable broker.
    fn refresh(&mut self, topic: &str) -> Result<(), Retry> {
        self.close_idle();
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
        // The response's broker list replaces ours (bounded): brokers that
        // left the cluster are forgotten, with their connections.
        let mut fresh: HashMap<i32, String> = HashMap::new();
        for b in &m.brokers {
            if fresh.len() >= MAX_BROKERS {
                break;
            }
            if !(1..=65535).contains(&b.port) || b.host.is_empty() || b.host.len() > 255 {
                continue;
            }
            let addr = if b.host.contains(':') && !b.host.starts_with('[') {
                format!("[{}]:{}", b.host, b.port)
            } else {
                format!("{}:{}", b.host, b.port)
            };
            fresh.insert(b.node_id, addr);
        }
        // Keep a connection only to a broker still listed at the same address.
        self.conns.retain(|id, _| {
            fresh
                .get(id)
                .is_some_and(|a| self.brokers.get(id) == Some(a))
        });
        self.brokers = fresh;
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
        self.close_idle();
        let Self {
            conns,
            brokers,
            cfg,
            corr,
            stats,
            ..
        } = self;
        match conns.entry(node) {
            std::collections::hash_map::Entry::Occupied(o) => Ok(o.into_mut()),
            std::collections::hash_map::Entry::Vacant(slot) => {
                let addr = brokers
                    .get(&node)
                    .cloned()
                    .ok_or_else(|| NetError::Protocol(format!("unknown broker {node}")))?;
                stats.connects += 1;
                let c = Conn::open(&addr, cfg, corr)?;
                Ok(slot.insert(c))
            }
        }
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
        // Per-partition cap on records per batch, set by record-level errors
        // (see `produce_round`).
        let mut limits: BTreeMap<i32, usize> = BTreeMap::new();
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
                        &mut limits,
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
        limits: &mut BTreeMap<i32, usize>,
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
            let limit = limits.get(&p).copied().unwrap_or(usize::MAX);
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
        // Connected above; if it is gone anyway, report trouble (the caller
        // retries) rather than abort.
        let Some(conn) = conns.get_mut(&leader) else {
            res.trouble = Some(format!("broker {leader}: connection lost before produce"));
            return Ok(res);
        };
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
                    // `plan` is built from `queues`; skip (the records stay
                    // undecided and are retried) rather than abort.
                    let Some(q) = queues.get_mut(&p) else {
                        res.trouble = Some(format!("partition {p}: no queue for planned records"));
                        continue;
                    };
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
                    // Halve the batch: a record that is too large (or
                    // invalid) is isolated in log2(n) requests, and a batch
                    // that is only too large as a whole (the topic's
                    // `max.message.bytes` below `max_request_bytes`) settles
                    // on a size that fits instead of one record per request.
                    limits.insert(p, idx.len() / 2);
                    res.progress = true;
                }
                ErrorClass::Record => {
                    // `plan` is built from `queues`; skip (the records stay
                    // undecided and are retried) rather than abort.
                    let Some(q) = queues.get_mut(&p) else {
                        res.trouble = Some(format!("partition {p}: no queue for planned records"));
                        continue;
                    };
                    q.pop_front();
                    if q.is_empty() {
                        queues.remove(&p);
                    }
                    limits.remove(&p);
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
    fn request_timeout_must_exceed_produce_timeout() {
        let d = ProducerConfig::new(vec!["127.0.0.1:1".into()]);
        assert!(
            d.request_timeout > Duration::from_millis(d.produce_timeout_ms as u64),
            "defaults are consistent"
        );
        let mut c = d.clone();
        c.request_timeout = Duration::from_millis(c.produce_timeout_ms as u64);
        assert!(matches!(Producer::new(c), Err(ProduceError::Config(_))));
        let mut c = d.clone();
        c.request_timeout = Duration::from_secs(1);
        c.produce_timeout_ms = 999;
        assert!(Producer::new(c).is_ok());
        let mut c = d;
        c.produce_timeout_ms = i32::MAX;
        assert!(Producer::new(c).is_err());
    }

    #[test]
    fn ip_literals_skip_the_resolver() {
        let t = Duration::from_millis(1);
        assert_eq!(
            resolve("10.0.0.5:9092", t).unwrap(),
            vec!["10.0.0.5:9092".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            resolve("[fd00::5]:9092", t).unwrap(),
            vec!["[fd00::5]:9092".parse::<SocketAddr>().unwrap()]
        );
        // Malformed: an error, never a panic.
        assert!(resolve("no-port", Duration::from_secs(2)).is_err());
    }

    fn meta(brokers: Vec<proto::Broker>) -> proto::MetadataResponse {
        proto::MetadataResponse {
            brokers,
            topics: vec![proto::TopicMeta {
                error_code: 0,
                name: "t".into(),
                partitions: vec![proto::PartitionMeta {
                    error_code: 0,
                    partition: 0,
                    leader: 1,
                }],
            }],
        }
    }

    fn broker(id: i32, host: &str) -> proto::Broker {
        proto::Broker {
            node_id: id,
            host: host.into(),
            port: 9092,
        }
    }

    #[test]
    fn broker_map_is_replaced_and_capped() {
        let mut p = Producer::new(ProducerConfig::new(vec!["127.0.0.1:1".into()])).unwrap();
        // A hostile response with a huge broker list is capped.
        let many: Vec<_> = (0..(MAX_BROKERS as i32 + 500))
            .map(|i| broker(i, "10.0.0.1"))
            .collect();
        assert!(p.apply_metadata("t", meta(many)).is_ok());
        assert_eq!(p.brokers.len(), MAX_BROKERS);
        // The next refresh replaces the list: departed brokers are gone.
        let r = p.apply_metadata("t", meta(vec![broker(1, "10.0.0.2"), broker(7, "fd00::7")]));
        assert!(r.is_ok());
        assert_eq!(p.brokers.len(), 2);
        assert_eq!(p.brokers[&1], "10.0.0.2:9092");
        assert_eq!(p.brokers[&7], "[fd00::7]:9092");
        // Invalid entries are skipped.
        let mut bad = broker(3, "");
        bad.port = 0;
        assert!(p.apply_metadata("t", meta(vec![bad])).is_ok());
        assert!(p.brokers.is_empty());
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
