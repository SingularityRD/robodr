//! A minimal, synchronous Kafka producer (std only).
//!
//! * **TLS** ([`ProducerConfig::tls`], `robodr_blackbox::tls`: rustls,
//!   TLS 1.3 / 1.2): every broker's certificate is verified against the
//!   configured CA file only (chain, validity, `serverAuth`, and the broker's
//!   host as dialled, bootstrap or advertised, unless `server_name` is
//!   set), optional SPKI pins add to that, and an optional client
//!   certificate gives mutual TLS. **Plain TCP is refused** unless
//!   [`ProducerConfig::allow_plaintext`] is set explicitly; there is no
//!   fallback from TLS to plain TCP.
//! * **SASL/SCRAM** ([`ProducerConfig::sasl`], [`super::sasl`]):
//!   SCRAM-SHA-256 / -512 after ApiVersions, over TLS only. Pointed at a
//!   TLS listener without TLS (answers with a TLS alert) or a SASL listener
//!   without SASL (closes the connection after ApiVersions), the error says
//!   so.
//! * Connections unused for `connections_max_idle` (9 min, as the Java
//!   client) are closed before the broker's own idle timeout (10 min)
//!   would make the next request fail.
//! * On every new connection: ApiVersions v0, then the highest common
//!   version of Metadata (1–8) and Produce (3–8) is used.
//! * `acks = -1` (all in-sync replicas), compression NONE, **one request
//!   in flight** (requests are sent one at a time and awaited; Kafka's
//!   `max.in.flight.requests.per.connection` is effectively 1, within the
//!   idempotent producer's limit of 5), so per-partition order is
//!   preserved within a [`Producer::send`] call and between calls.
//! * **Idempotent** by default ([`ProducerConfig::idempotence`], see
//!   "Idempotence" below). With it off (producer id -1) delivery is
//!   at-least-once: a request whose response is lost (time out,
//!   disconnect) is re-sent, and the broker may then hold it twice.
//!   Consumers deduplicate on `event-uid` (contract §2) either way.
//! * Retriable errors (leader moves, timeouts, not enough replicas, I/O,
//!   `CORRUPT_MESSAGE`) are retried with exponential backoff, refreshing
//!   metadata when the error says leadership may have changed; a call that
//!   makes no progress for `retries` rounds, or exceeds `delivery_timeout`,
//!   fails without reporting anything as delivered that was not
//!   acknowledged. `INVALID_TIMESTAMP` is retried the same way and never
//!   blamed on a record: the CreateTime is this host's clock, so the
//!   error means the clock is off (the failure says so; see
//!   [`super::errors::hint`]).
//! * Record-level errors (`MESSAGE_TOO_LARGE`, `RECORD_LIST_TOO_LARGE`,
//!   `INVALID_RECORD`) are
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
//!
//! # Idempotence
//!
//! Before the first Produce request the producer asks a broker for a
//! producer id (InitProducerId v0–1, no transactional id) and then sends
//! every batch with that id, its epoch and a per-partition base sequence
//! (0, 1, ... per record, wrapping at `i32::MAX` as Kafka does). The broker
//! appends a batch only if its sequence follows the last one it wrote for
//! that id and partition, and recognises a re-send of one of its last five
//! batches. A batch whose acknowledgement was lost is therefore **re-sent
//! exactly as it was** (same records, same base sequence; also to a new
//! leader): the broker either appends it (it never had it) or answers
//! success for the copy it holds. It is never written twice. Errors:
//!
//! * `DUPLICATE_SEQUENCE_NUMBER`: the broker already holds the batch:
//!   **success** (offset -1 if the broker does not say).
//! * `OUT_OF_ORDER_SEQUENCE_NUMBER`, `UNKNOWN_PRODUCER_ID`,
//!   `INVALID_PRODUCER_EPOCH`, `PRODUCER_FENCED`: the broker's state for
//!   this producer id disagrees with ours (lost in an unclean leader
//!   election, or another process uses the same persisted id); the batch
//!   was not appended. The producer **resets**: a new producer id, every
//!   sequence back to 0, the undecided records re-sent under it (counted
//!   in [`ProducerStats::producer_id_resets`]). A batch of another
//!   partition that was in doubt at that moment (its response lost) may
//!   then be written twice: at-least-once, never a loss.
//! * A record-level error on a batch that is being **re-sent** (an earlier
//!   copy got no decisive answer) also resets the producer id instead of
//!   giving the batch's sequences back: the earlier copy may have been
//!   appended (Kafka validates records before it looks for duplicates), and
//!   a later batch reusing those sequences would be answered
//!   `DUPLICATE_SEQUENCE_NUMBER`, i.e. reported delivered but never
//!   written. A batch sent once and refused frees its sequences.
//! * InitProducerId `CLUSTER_AUTHORIZATION_FAILED` is fatal and says why:
//!   brokers before Kafka 3.0 require the `IDEMPOTENT_WRITE` cluster ACL
//!   (3.0+ imply it from `WRITE` on a topic); grant it, or turn
//!   idempotence off. A broker without InitProducerId v0–1 is refused the
//!   same way.
//!
//! **Across restarts** ([`Producer::send_journaled`]): before each Produce
//! request that carries a newly numbered batch, the producer hands the
//! caller its [`IdempotentState`] (producer id, epoch, next sequence of
//! every partition, already counting the batches about to be sent) and a
//! [`SendJournal`] (this call's batches: acknowledged with their offset,
//! or in doubt) to store durably. A restarted caller restores the state
//! ([`Producer::restore_idempotent_state`]) and passes the journal back
//! with the same records: acknowledged batches are reported delivered
//! without a request, the batch in doubt is re-sent as it was, and the
//! broker deduplicates it. That holds while the broker remembers the
//! producer id (`producer.id.expiration.ms`, default one day after its
//! last write); after that a broker accepts the id again with any
//! sequence, so the in-doubt batch may be written twice.

use super::batch::{encode_batch_idempotent, ProduceRecord, ProducerFields, BATCH_OVERHEAD};
use super::errors::{self, classify, ErrorClass};
use super::proto::{self, ApiRange};
use super::sasl::{self, SaslConfig, ScramClient};
use super::wire::DecodeError;
use robodr_blackbox::tls::{ClientTls, DeadlineTcp};
use rustls::{ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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
    /// TLS to every broker (`robodr_blackbox::tls::load_client`).
    pub tls: Option<ClientTls>,
    /// SASL/SCRAM after the TLS handshake (needs `tls`).
    pub sasl: Option<SaslConfig>,
    /// Plain TCP when `tls` is `None` (default `false`: refused).
    pub allow_plaintext: bool,
    /// Idempotent producer (default `true`, see the module docs). Turn it
    /// off for brokers that refuse InitProducerId to this principal
    /// (`IDEMPOTENT_WRITE` / cluster authorisation) or do not offer it.
    pub idempotence: bool,
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
            tls: None,
            sasl: None,
            allow_plaintext: false,
            idempotence: true,
        }
    }

    fn check(&self) -> Result<(), ProduceError> {
        let bad = |m: &str| Err(ProduceError::Config(m.into()));
        if self.bootstrap.is_empty() {
            return bad("no bootstrap brokers");
        }
        match (&self.tls, self.allow_plaintext) {
            (None, false) => {
                return bad(
                    "plain TCP to the brokers is refused: configure TLS (a CA file), or allow \
                     plain TCP explicitly (isolated network or a local TLS proxy only)",
                )
            }
            (Some(_), true) => return bad("TLS and allow_plaintext are both set: remove one"),
            _ => {}
        }
        if self.sasl.is_some() && self.tls.is_none() {
            return bad("SASL needs TLS (an authenticated plain-TCP connection can be taken over)");
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
    /// The caller could not store the idempotence journal
    /// ([`Producer::send_journaled`]); that request was not sent.
    Journal(String),
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
            Self::Journal(m) => write!(f, "idempotence journal not saved (not sent): {m}"),
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
    /// Producer ids obtained (InitProducerId).
    pub producer_ids: u64,
    /// Producer id resets after a sequence / epoch / unknown-id error.
    pub producer_id_resets: u64,
    /// Batches the broker reported as already written (re-sends).
    pub duplicates: u64,
    /// Batches reported delivered from a resumed journal, without a request.
    pub journal_acked: u64,
}

/// The idempotent producer's identity and sequences (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotentState {
    pub producer_id: i64,
    pub producer_epoch: i16,
    /// Topic -> partition -> sequence number of its next record.
    pub sequences: BTreeMap<String, BTreeMap<i32, i32>>,
}

impl IdempotentState {
    fn new(producer_id: i64, producer_epoch: i16) -> Self {
        Self {
            producer_id,
            producer_epoch,
            sequences: BTreeMap::new(),
        }
    }

    /// Next sequence of `topic`/`partition` (0 if never written).
    pub fn next(&self, topic: &str, partition: i32) -> i32 {
        self.sequences
            .get(topic)
            .and_then(|m| m.get(&partition))
            .copied()
            .unwrap_or(0)
    }

    fn set(&mut self, topic: &str, partition: i32, seq: i32) {
        self.sequences
            .entry(topic.to_string())
            .or_default()
            .insert(partition, seq);
    }

    /// Plausible (e.g. as read back from a file): non-negative id, epoch,
    /// partitions and sequences.
    pub fn is_valid(&self) -> bool {
        self.producer_id >= 0
            && self.producer_epoch >= 0
            && self
                .sequences
                .values()
                .all(|m| m.iter().all(|(p, s)| *p >= 0 && *s >= 0))
    }
}

/// `seq + n` the way Kafka increments sequence numbers (wrapping from
/// `i32::MAX` to 0). `n` is at most the records of one batch.
pub fn increment_sequence(seq: i32, n: i32) -> i32 {
    if seq > i32::MAX - n {
        n - (i32::MAX - seq) - 1
    } else {
        seq + n
    }
}

/// One idempotent batch of a [`Producer::send_journaled`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalBatch {
    pub producer_id: i64,
    pub producer_epoch: i16,
    pub partition: i32,
    pub base_sequence: i32,
    /// Indices of its records in the call's `records`, in order.
    pub records: Vec<u32>,
    /// Base offset once acknowledged (-1 when the broker did not say);
    /// `None`: sent, outcome unknown.
    pub offset: Option<i64>,
}

/// The batches of one [`Producer::send_journaled`] call (see the module
/// docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendJournal {
    pub topic: String,
    pub batches: Vec<JournalBatch>,
}

/// Stores the idempotence state and journal durably before a request is
/// sent (`Err`: the request is not sent).
pub type PersistFn<'a> = dyn FnMut(&IdempotentState, &SendJournal) -> Result<(), String> + 'a;

/// Connection-level failure: retried on another round.
#[derive(Debug)]
enum NetError {
    Io(io::Error),
    Protocol(String),
    Unsupported(String),
    /// SASL authentication failed (not retried).
    Auth {
        code: i16,
        context: String,
    },
}

impl NetError {
    /// A connection error that fails the whole call.
    fn fatal(&self) -> Option<ProduceError> {
        match self {
            NetError::Unsupported(m) => Some(ProduceError::Unsupported(m.clone())),
            NetError::Auth { code, context } => Some(ProduceError::Fatal {
                code: *code,
                context: context.clone(),
            }),
            _ => None,
        }
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "I/O: {e}"),
            NetError::Protocol(m) => write!(f, "protocol: {m}"),
            NetError::Unsupported(m) => write!(f, "unsupported: {m}"),
            NetError::Auth { context, .. } => write!(f, "authentication: {context}"),
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

/// A broker connection: plain TCP or TLS over it.
enum Stream {
    Plain(TcpStream),
    /// Every read and write bounded by the exchange's deadline (review F3:
    /// rustls loops over reads, a socket timeout armed once does not bound
    /// a peer that trickles bytes).
    Tls(Box<StreamOwned<ClientConnection, DeadlineTcp>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            Stream::Tls(t) => &t.sock.tcp,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(t) => t.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(t) => t.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(t) => t.flush(),
        }
    }
}

struct Conn {
    stream: Stream,
    produce_v: i16,
    metadata_v: i16,
    /// InitProducerId version, if the broker offers one we implement.
    init_pid_v: Option<i16>,
    /// No request after the ApiVersions handshake has completed yet. A
    /// SASL listener answers ApiVersions (allowed before authentication)
    /// and then closes the connection on the first other request.
    fresh: bool,
    /// End of the last completed exchange (or of the handshake).
    last_used: Instant,
    /// Close before this (a SASL session lifetime announced by the broker).
    expires: Option<Instant>,
}

impl Conn {
    fn usable(&self, max_idle: Duration) -> bool {
        self.last_used.elapsed() < max_idle && self.expires.is_none_or(|e| Instant::now() < e)
    }
}

/// Explain a response that is really a TLS record (a plaintext request to
/// a TLS listener is answered with a TLS alert, `15 03 0x ...`).
/// Name a TLS failure inside an I/O error (rustls reports alerts and
/// certificate errors as `io::Error(InvalidData, rustls::Error)`).
fn tls_io(e: io::Error) -> io::Error {
    if e.get_ref()
        .is_some_and(|x| x.downcast_ref::<rustls::Error>().is_some())
    {
        io::Error::new(
            e.kind(),
            format!("TLS: {}", robodr_blackbox::tls::describe(&e)),
        )
    } else {
        e
    }
}

fn tls_hint(prefix: [u8; 4]) -> Option<String> {
    (matches!(prefix[0], 0x15 | 0x16) && prefix[1] == 0x03).then(|| {
        format!(
            "the broker answered with a TLS record ({:02x} {:02x} {:02x} ...): this listener \
             requires TLS (configure the brokers' CA file instead of allowing plain TCP)",
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
                 SASL, configure SASL/SCRAM (mechanism, user, password file)"
            ),
        )
    } else {
        e
    }
}

/// Write all of `buf` before `deadline` (the write timeout is re-armed with
/// the remaining time before every `write`, so a peer that drains slowly
/// cannot extend the exchange).
fn write_all_deadline(s: &mut Stream, mut buf: &[u8], deadline: Instant) -> io::Result<()> {
    let arm = |s: &Stream| -> io::Result<()> {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out"));
        }
        // TLS writes may read (key updates), so both are bounded.
        s.tcp().set_write_timeout(Some(deadline - now))?;
        s.tcp().set_read_timeout(Some(deadline - now))
    };
    while !buf.is_empty() {
        arm(s)?;
        match s.write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "broker closed the connection",
                ))
            }
            Ok(n) => buf = buf.get(n..).unwrap_or_default(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out"))
            }
            Err(e) => return Err(e),
        }
    }
    // TLS buffers records; push them out within the deadline.
    if let Stream::Tls(_) = s {
        arm(s)?;
        s.flush().map_err(|e| {
            if e.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(io::ErrorKind::TimedOut, "request timed out")
            } else {
                e
            }
        })?;
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

fn read_exact_deadline(s: &mut Stream, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out"));
        }
        s.tcp().set_read_timeout(Some(deadline - now))?;
        s.tcp().set_write_timeout(Some(deadline - now))?;
        match s.read(buf.get_mut(off..).unwrap_or_default()) {
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
        if let Stream::Tls(t) = &mut self.stream {
            t.sock.set_deadline(deadline);
        }
        let hint = self.fresh && api != proto::API_VERSIONS && api != sasl::API_SASL_HANDSHAKE;
        let io = |e: io::Error| {
            NetError::Io(if hint {
                sasl_hint(tls_io(e))
            } else {
                tls_io(e)
            })
        };
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
        if api != proto::API_VERSIONS
            && api != sasl::API_SASL_HANDSHAKE
            && api != sasl::API_SASL_AUTHENTICATE
        {
            self.fresh = false;
        }
        self.last_used = Instant::now();
        let got = buf.first_chunk().map_or(-1, |b| i32::from_be_bytes(*b));
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
        let stream = match &cfg.tls {
            None => Stream::Plain(stream),
            Some(tls) => {
                let name = tls
                    .name_for(robodr_blackbox::tls::host_of(addr))
                    .map_err(NetError::Protocol)?;
                // The handshake is bounded like a request.
                let t = robodr_blackbox::tls::connect_client(
                    stream,
                    tls,
                    name,
                    Instant::now()
                        + cfg
                            .request_timeout
                            .min(cfg.connect_timeout.saturating_mul(2)),
                )
                .map_err(|e| {
                    NetError::Io(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("{addr}: {e}"),
                    ))
                })?;
                Stream::Tls(Box::new(t))
            }
        };
        let mut c = Conn {
            stream,
            produce_v: 0,
            metadata_v: 0,
            init_pid_v: None,
            fresh: true,
            last_used: Instant::now(),
            expires: None,
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
        c.init_pid_v = proto::negotiate(
            &av.apis,
            proto::API_INIT_PRODUCER_ID,
            proto::INIT_PRODUCER_ID_VERSIONS,
        );
        if let Some(s) = &cfg.sasl {
            let hv = pick(
                &av.apis,
                sasl::API_SASL_HANDSHAKE,
                sasl::HANDSHAKE_VERSIONS,
                "SaslHandshake",
            )?;
            let av_ = pick(
                &av.apis,
                sasl::API_SASL_AUTHENTICATE,
                sasl::AUTHENTICATE_VERSIONS,
                "SaslAuthenticate",
            )?;
            c.authenticate(addr, cfg, corr, s, hv, av_)?;
        }
        Ok(c)
    }

    /// SASL/SCRAM ([`super::sasl`]); failures are fatal ([`NetError::Auth`]).
    fn authenticate(
        &mut self,
        addr: &str,
        cfg: &ProducerConfig,
        corr: &mut i32,
        s: &SaslConfig,
        handshake_v: i16,
        auth_v: i16,
    ) -> Result<(), NetError> {
        let mech = s.mechanism.name();
        let auth = |code: i16, m: String| NetError::Auth {
            code,
            context: format!("{addr}: SASL {mech}: {m}"),
        };
        let body = sasl::encode_handshake_request(mech)?;
        let resp = self.exchange(cfg, corr, sasl::API_SASL_HANDSHAKE, handshake_v, &body)?;
        let (code, enabled) = sasl::decode_handshake_response(&resp)?;
        if code != 0 {
            let shown: Vec<String> = enabled
                .iter()
                .take(8)
                .map(|m| m.chars().take(40).collect())
                .collect();
            return Err(auth(
                code,
                format!(
                    "the broker refused the mechanism ({}; it offers {shown:?})",
                    super::errors::name(code)
                ),
            ));
        }
        let mut scram = ScramClient::start(s.mechanism, &s.username)
            .map_err(|e| auth(super::errors::SASL_AUTHENTICATION_FAILED, e))?;
        let step = |c: &mut Conn, corr: &mut i32, msg: &[u8]| -> Result<_, NetError> {
            let body = sasl::encode_authenticate_request(msg)?;
            let resp = c.exchange(cfg, corr, sasl::API_SASL_AUTHENTICATE, auth_v, &body)?;
            let r = sasl::decode_authenticate_response(auth_v, &resp)?;
            if r.error_code != 0 {
                return Err(auth(
                    r.error_code,
                    format!(
                        "{} ({})",
                        super::errors::name(r.error_code),
                        r.error_message
                            .unwrap_or_default()
                            .chars()
                            .map(|c| if c.is_control() { ' ' } else { c })
                            .collect::<String>()
                    ),
                ));
            }
            Ok(r)
        };
        let first = step(self, corr, scram.client_first().as_bytes())?;
        let server_first = std::str::from_utf8(&first.auth_bytes).map_err(|_| {
            auth(
                super::errors::SASL_AUTHENTICATION_FAILED,
                "server-first-message is not UTF-8".into(),
            )
        })?;
        let fin = scram
            .client_final(server_first, s.password())
            .map_err(|e| auth(super::errors::SASL_AUTHENTICATION_FAILED, e))?;
        let last = step(self, corr, fin.as_bytes())?;
        let server_final = std::str::from_utf8(&last.auth_bytes).map_err(|_| {
            auth(
                super::errors::SASL_AUTHENTICATION_FAILED,
                "server-final-message is not UTF-8".into(),
            )
        })?;
        scram
            .verify_final(server_final)
            .map_err(|e| auth(super::errors::SASL_AUTHENTICATION_FAILED, e))?;
        if last.session_lifetime_ms > 0 {
            // Re-authenticate by reconnecting before the broker would close
            // the connection (KIP-368 re-authentication is not implemented).
            let ms = (last.session_lifetime_ms as u64).saturating_mul(4) / 5;
            self.expires = Some(Instant::now() + Duration::from_millis(ms));
        }
        Ok(())
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
    /// Idempotent producer id and sequences (`None`: idempotence off, or
    /// no id yet / reset).
    idem: Option<IdempotentState>,
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
            idem: None,
        })
    }

    /// The idempotent producer's id and sequences (`None`: idempotence off,
    /// or no producer id yet).
    pub fn idempotent_state(&self) -> Option<&IdempotentState> {
        self.idem.as_ref()
    }

    /// Continue with a persisted id and sequences (see the module docs).
    /// Ignored with idempotence off, or when `s` is not
    /// [valid](IdempotentState::is_valid).
    pub fn restore_idempotent_state(&mut self, s: IdempotentState) {
        if self.cfg.idempotence && s.is_valid() {
            self.idem = Some(s);
        }
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
        self.conns.retain(|_, c| c.usable(max));
        if self.bootstrap_conn.as_ref().is_some_and(|c| !c.usable(max)) {
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
                Err(e) if e.fatal().is_some() => {
                    return Err(Retry::Fatal(
                        e.fatal()
                            .unwrap_or(ProduceError::Unsupported(e.to_string())),
                    ))
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
                if let Some(l) = leaders.get_mut(i) {
                    *l = Some(p.leader);
                }
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

    /// Obtain a producer id (InitProducerId) from broker `node` unless
    /// idempotence is off or one is held.
    fn ensure_producer_id(&mut self, node: i32) -> Result<(), Retry> {
        if !self.cfg.idempotence || self.idem.is_some() {
            return Ok(());
        }
        let v = match self.conn_for(node) {
            Ok(c) => c.init_pid_v,
            Err(e) => {
                if let Some(f) = e.fatal() {
                    return Err(Retry::Fatal(f));
                }
                self.stats.io_errors += 1;
                self.stale = true;
                return Err(Retry::Again(format!("connect to broker {node}: {e}")));
            }
        };
        let Some(v) = v else {
            return Err(Retry::Fatal(ProduceError::Unsupported(format!(
                "broker {node} offers no InitProducerId v{}-{} (needed by the idempotent \
                 producer): upgrade the broker, or turn idempotence off",
                proto::INIT_PRODUCER_ID_VERSIONS.0,
                proto::INIT_PRODUCER_ID_VERSIONS.1
            ))));
        };
        let body = proto::encode_init_producer_id_request(v)
            .map_err(|e| Retry::Fatal(ProduceError::Config(e.0)))?;
        self.stats.requests += 1;
        let Self {
            conns, cfg, corr, ..
        } = self;
        let Some(conn) = conns.get_mut(&node) else {
            return Err(Retry::Again(format!("broker {node}: connection lost")));
        };
        let resp = conn
            .exchange(cfg, corr, proto::API_INIT_PRODUCER_ID, v, &body)
            .and_then(|b| proto::decode_init_producer_id_response(&b).map_err(NetError::from));
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                self.conns.remove(&node);
                self.stats.io_errors += 1;
                self.stale = true;
                return Err(Retry::Again(format!(
                    "init producer id on broker {node}: {e}"
                )));
            }
        };
        match (resp.error_code, classify(resp.error_code)) {
            (_, ErrorClass::None) => {
                if resp.producer_id < 0 || resp.producer_epoch < 0 {
                    return Err(Retry::Again(format!(
                        "broker {node} answered InitProducerId with id {} epoch {}",
                        resp.producer_id, resp.producer_epoch
                    )));
                }
                self.idem = Some(IdempotentState::new(resp.producer_id, resp.producer_epoch));
                self.stats.producer_ids += 1;
                Ok(())
            }
            (errors::CLUSTER_AUTHORIZATION_FAILED, _) => Err(Retry::Fatal(ProduceError::Fatal {
                code: resp.error_code,
                context: format!(
                    "InitProducerId on broker {node}: this principal may not produce \
                     idempotently (brokers before Kafka 3.0 need the IDEMPOTENT_WRITE ACL on \
                     the cluster; 3.0+ imply it from WRITE on a topic): grant it, or turn \
                     idempotence off"
                ),
            })),
            (_, ErrorClass::Retriable { refresh }) => {
                self.stale |= refresh;
                Err(Retry::Again(format!(
                    "init producer id on broker {node}: {}",
                    errors::name(resp.error_code)
                )))
            }
            _ => Err(Retry::Fatal(ProduceError::Fatal {
                code: resp.error_code,
                context: format!("InitProducerId on broker {node}"),
            })),
        }
    }

    /// Produce `records` (`(partition, record)`) to `topic` with
    /// `acks=all`, preserving the order of the records of each partition.
    ///
    /// Returns one [`Outcome`] per input record (same order). On `Err`,
    /// some records may have been delivered; none is reported as such, so a
    /// caller that retries the whole call delivers at-least-once (with
    /// idempotence, the broker drops the batches it already holds while it
    /// remembers them; [`Producer::send_journaled`] carries that across
    /// restarts).
    pub fn send(
        &mut self,
        topic: &str,
        records: &[(i32, ProduceRecord)],
    ) -> Result<Vec<Outcome>, ProduceError> {
        self.send_journaled(topic, records, None, &mut |_, _| Ok(()))
    }

    /// [`Producer::send`] for a caller that persists the idempotence state
    /// (see the module docs): `persist` is called before every request that
    /// carries a newly numbered batch and must store both arguments
    /// durably; `resume` is the journal last stored for **the same
    /// `records`** (same order and partitions) by a call that did not
    /// finish. A journal that does not fit `records` (index out of range,
    /// another partition or topic) is ignored: its records are sent as new
    /// ones (a possible duplicate, never a loss). With idempotence off,
    /// `persist` is never called and `resume` is ignored.
    pub fn send_journaled(
        &mut self,
        topic: &str,
        records: &[(i32, ProduceRecord)],
        resume: Option<&SendJournal>,
        persist: &mut PersistFn<'_>,
    ) -> Result<Vec<Outcome>, ProduceError> {
        let deadline = Instant::now() + self.cfg.delivery_timeout;
        let mut call = Call {
            topic,
            records,
            out: vec![None; records.len()],
            queues: BTreeMap::new(),
            limits: BTreeMap::new(),
            fixed: BTreeMap::new(),
            acked: Vec::new(),
            persist,
        };
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
                let Some(slot) = call.out.get_mut(i) else {
                    continue;
                };
                *slot = Some(Outcome::Rejected {
                    code: errors::MESSAGE_TOO_LARGE,
                    reason: format!(
                        "record needs up to {} bytes, more than fits in max_request_bytes {}",
                        r.size_bound(),
                        self.cfg.max_request_bytes
                    ),
                });
                self.stats.rejected += 1;
            } else {
                call.queues.entry(*p).or_default().push_back(i);
            }
        }
        if let Some(j) = resume {
            self.resume_journal(&mut call, j);
        }
        let mut attempt: u32 = 0;
        while !call.queues.is_empty() {
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
                for &p in call.queues.keys() {
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
                if let Some(&node) = by_leader.keys().next() {
                    match self.ensure_producer_id(node) {
                        Ok(()) => {}
                        Err(Retry::Fatal(e)) => return Err(e),
                        Err(Retry::Again(m)) => {
                            trouble = Some(m);
                            by_leader.clear();
                        }
                    }
                }
                for (leader, parts) in by_leader {
                    let pr = self.produce_round(&mut call, leader, &parts)?;
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
            } else if Instant::now() >= deadline && !call.queues.is_empty() {
                return Err(ProduceError::Timeout("records still pending".into()));
            }
        }
        Ok(call
            .out
            .into_iter()
            .map(|o| {
                o.unwrap_or(Outcome::Rejected {
                    code: errors::UNKNOWN_SERVER_ERROR,
                    reason: "internal: no outcome".into(),
                })
            })
            .collect())
    }

    /// Apply a resumed journal (see [`Producer::send_journaled`]):
    /// acknowledged batches become outcomes, the batch in doubt of each
    /// partition (current producer id only) is re-sent as it was.
    fn resume_journal(&mut self, call: &mut Call<'_, '_>, j: &SendJournal) {
        if !self.cfg.idempotence || j.topic != call.topic {
            return;
        }
        // Validate everything first: a journal that does not fit is
        // ignored as a whole.
        let mut seen = BTreeSet::new();
        for b in &j.batches {
            if b.records.is_empty() {
                return;
            }
            for &i in &b.records {
                let i = i as usize;
                let fits = call.records.get(i).is_some_and(|(p, _)| *p == b.partition)
                    && call.out.get(i).is_some_and(Option::is_none)
                    && seen.insert(i);
                if !fits {
                    return;
                }
            }
        }
        let current = self
            .idem
            .as_ref()
            .map(|s| (s.producer_id, s.producer_epoch));
        for b in &j.batches {
            match b.offset {
                Some(off) => {
                    call.decide_delivered(b, off);
                    self.stats.delivered += b.records.len() as u64;
                    self.stats.journal_acked += 1;
                    call.acked.push(b.clone());
                }
                None if current == Some((b.producer_id, b.producer_epoch))
                    && !call.fixed.contains_key(&b.partition) =>
                {
                    call.fixed.insert(b.partition, b.clone());
                }
                // In doubt under an earlier producer id: sent again as new
                // records (a possible duplicate).
                None => {}
            }
        }
    }

    fn produce_round(
        &mut self,
        call: &mut Call<'_, '_>,
        leader: i32,
        parts: &[i32],
    ) -> Result<RoundResult, ProduceError> {
        let mut res = RoundResult::default();
        let topic = call.topic;
        let records = call.records;
        let idem_on = self.cfg.idempotence;
        // Fill the request in partition order within the size budget. A
        // batch in doubt (idempotence) is re-sent exactly as it was.
        let mut budget = self
            .cfg
            .max_request_bytes
            .saturating_sub(self.request_overhead(topic));
        // `(partition, record indices, fields, re-send)`: a re-send is a batch
        // that was sent before without a decisive answer (lost reply, retriable
        // error, resumed journal), so the broker may already hold it.
        let mut plan: Vec<(i32, Vec<usize>, ProducerFields, bool)> = Vec::new();
        let mut numbered: Vec<i32> = Vec::new();
        for &p in parts {
            if budget < Self::PART_OVERHEAD {
                break;
            }
            let mut room = budget - Self::PART_OVERHEAD;
            if let Some(f) = call.fixed.get(&p) {
                let need: usize = f
                    .records
                    .iter()
                    .filter_map(|&i| records.get(i as usize))
                    .map(|(_, r)| r.size_bound())
                    .sum();
                if need <= room {
                    budget = room - need;
                    plan.push((
                        p,
                        f.records.iter().map(|&i| i as usize).collect(),
                        ProducerFields {
                            producer_id: f.producer_id,
                            producer_epoch: f.producer_epoch,
                            base_sequence: f.base_sequence,
                        },
                        true,
                    ));
                    continue;
                }
                if !plan.is_empty() {
                    // Next request.
                    continue;
                }
                // Does not fit even alone (a resumed journal written with a
                // larger max_request_bytes): give up re-sending it as is.
                // Its sequences stay used, so the broker answers the next
                // batch with OUT_OF_ORDER_SEQUENCE_NUMBER and we reset.
                call.fixed.remove(&p);
            }
            let fields = if idem_on {
                match &self.idem {
                    Some(s) => ProducerFields {
                        producer_id: s.producer_id,
                        producer_epoch: s.producer_epoch,
                        base_sequence: s.next(topic, p),
                    },
                    // Reset in this round: numbered after the next
                    // InitProducerId.
                    None => continue,
                }
            } else {
                ProducerFields::NONE
            };
            let mut take = Vec::new();
            let limit = call.limits.get(&p).copied().unwrap_or(usize::MAX);
            for &i in call.queues.get(&p).into_iter().flatten() {
                let Some((_, r)) = records.get(i) else {
                    break;
                };
                let need = r.size_bound();
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
            if let Some(s) = self.idem.as_mut().filter(|_| idem_on) {
                let n = i32::try_from(take.len()).unwrap_or(i32::MAX);
                s.set(topic, p, increment_sequence(fields.base_sequence, n));
                call.fixed.insert(
                    p,
                    JournalBatch {
                        producer_id: fields.producer_id,
                        producer_epoch: fields.producer_epoch,
                        partition: p,
                        base_sequence: fields.base_sequence,
                        records: take.iter().map(|&i| i as u32).collect(),
                        offset: None,
                    },
                );
                numbered.push(p);
            }
            plan.push((p, take, fields, false));
        }
        if plan.is_empty() {
            return Ok(res);
        }
        // Persist the newly numbered batches before they can reach a broker.
        if !numbered.is_empty() {
            if let Some(s) = self.idem.clone() {
                let journal = call.journal();
                if let Err(m) = (call.persist)(&s, &journal) {
                    for p in &numbered {
                        if let Some(f) = call.fixed.remove(p) {
                            if let Some(st) = self.idem.as_mut() {
                                st.set(topic, *p, f.base_sequence);
                            }
                        }
                    }
                    return Err(ProduceError::Journal(m));
                }
            }
        }
        let mut batches = Vec::with_capacity(plan.len());
        for (p, idx, fields, _) in &plan {
            let recs: Vec<ProduceRecord> = idx
                .iter()
                .filter_map(|&i| records.get(i))
                .map(|(_, r)| r.clone())
                .collect();
            let b = encode_batch_idempotent(&recs, *fields)
                .map_err(|e| ProduceError::Config(format!("encoding batch: {e:?}")))?;
            batches.push((*p, b));
        }
        let conn = match self.conn_for(leader) {
            Ok(c) => c,
            Err(e) if e.fatal().is_some() => {
                return Err(e
                    .fatal()
                    .unwrap_or(ProduceError::Unsupported(e.to_string())))
            }
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
                // Connection state unknown: drop it. The batches stay in
                // doubt and are re-sent as they are.
                self.conns.remove(&leader);
                self.stats.io_errors += 1;
                self.stale = true;
                res.trouble = Some(format!("produce to broker {leader}: {e}"));
                return Ok(res);
            }
        };
        for (p, idx, fields, resent) in plan {
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
            let class = classify(pr.error_code);
            match class {
                ErrorClass::None | ErrorClass::Duplicate => {
                    // A duplicate may not say where the original is.
                    let base = if pr.base_offset < 0 {
                        -1
                    } else {
                        pr.base_offset
                    };
                    let b = JournalBatch {
                        producer_id: fields.producer_id,
                        producer_epoch: fields.producer_epoch,
                        partition: p,
                        base_sequence: fields.base_sequence,
                        records: idx.iter().map(|&i| i as u32).collect(),
                        offset: Some(base),
                    };
                    call.decide_delivered(&b, base);
                    self.stats.delivered += idx.len() as u64;
                    if class == ErrorClass::Duplicate {
                        self.stats.duplicates += 1;
                    }
                    if idem_on {
                        call.fixed.remove(&p);
                        call.acked.push(b);
                    }
                    res.progress = true;
                }
                ErrorClass::Record if idx.len() > 1 => {
                    // Halve the batch: a record that is too large (or
                    // invalid) is isolated in log2(n) requests, and a batch
                    // that is only too large as a whole (the topic's
                    // `max.message.bytes` below `max_request_bytes`) settles
                    // on a size that fits instead of one record per request.
                    // This request appended nothing; see `release` for the
                    // sequences.
                    call.limits.insert(p, idx.len() / 2);
                    self.release(call, p, fields, resent);
                    res.progress = true;
                }
                ErrorClass::Record => {
                    self.release(call, p, fields, resent);
                    call.remove_from_queue(p, &idx);
                    call.limits.remove(&p);
                    // A one-record batch (`idx.len() == 1` here), so the
                    // slot exists. Were it missing, the record would end
                    // as `Rejected` "internal: no outcome" (it left the
                    // queue above): reported, never silently dropped, and
                    // the call is not aborted.
                    if let Some(slot) = idx.first().and_then(|&i| call.out.get_mut(i)) {
                        *slot = Some(Outcome::Rejected {
                            code: pr.error_code,
                            reason: format!(
                                "{}{}",
                                errors::name(pr.error_code),
                                pr.error_message
                                    .as_deref()
                                    .map(|m| format!(
                                        ": {}",
                                        m.chars().take(200).collect::<String>()
                                    ))
                                    .unwrap_or_default()
                            ),
                        });
                        self.stats.rejected += 1;
                    }
                    res.progress = true;
                }
                ErrorClass::Retriable { refresh } => {
                    self.stale |= refresh;
                    res.trouble = Some(format!(
                        "partition {p} on broker {leader}: {}{}",
                        errors::name(pr.error_code),
                        errors::hint(pr.error_code)
                            .map(|h| format!(" ({h})"))
                            .unwrap_or_default()
                    ));
                }
                ErrorClass::Sequence if idem_on => {
                    // Reset (see the module docs): a new producer id is
                    // obtained before the next request, every undecided
                    // record is numbered again under it.
                    if self.idem.take().is_some() {
                        self.stats.producer_id_resets += 1;
                    }
                    call.fixed.clear();
                    res.trouble = Some(format!(
                        "partition {p} on broker {leader}: {} (producer id {} reset)",
                        errors::name(pr.error_code),
                        fields.producer_id
                    ));
                }
                ErrorClass::Sequence | ErrorClass::Fatal => {
                    return Err(ProduceError::Fatal {
                        code: pr.error_code,
                        context: format!("produce to {topic}/{p} on broker {leader}"),
                    })
                }
            }
        }
        Ok(res)
    }

    /// The batch planned for `p` with `fields` was refused with a
    /// record-level error. This request appended nothing, but a **re-sent**
    /// batch (`resent`: an earlier copy got no decisive answer) may have
    /// been appended by that earlier copy: Kafka validates records (size,
    /// timestamps, ...) before it looks for duplicates, so a topic limit
    /// lowered in between refuses the copy of a batch it already holds.
    /// Rewinding its sequences would hand them to the next batch, which the
    /// broker would then answer `DUPLICATE_SEQUENCE_NUMBER` (reported
    /// delivered, never written). So a re-sent batch never gives its
    /// sequences back: the producer id is reset instead (as on a sequence
    /// error; at worst a duplicate, never a loss). A batch sent once only
    /// frees its sequences ([`Producer::unnumber`]).
    fn release(&mut self, call: &mut Call<'_, '_>, p: i32, fields: ProducerFields, resent: bool) {
        if !resent {
            self.unnumber(call, p, fields);
            return;
        }
        let ours = call.fixed.get(&p).is_some_and(|f| {
            (f.producer_id, f.producer_epoch, f.base_sequence)
                == (
                    fields.producer_id,
                    fields.producer_epoch,
                    fields.base_sequence,
                )
        });
        if !ours {
            return;
        }
        if self
            .idem
            .take_if(|s| {
                (s.producer_id, s.producer_epoch) == (fields.producer_id, fields.producer_epoch)
            })
            .is_some()
        {
            self.stats.producer_id_resets += 1;
        }
        // Every batch numbered under the old id is renumbered under the new
        // one (as after a sequence error).
        call.fixed.clear();
    }

    /// The batch planned for `p` with `fields` was refused as a whole and
    /// was never sent before (nothing appended): free its sequences, unless
    /// a reset or another batch intervened.
    fn unnumber(&mut self, call: &mut Call<'_, '_>, p: i32, fields: ProducerFields) {
        let ours = call.fixed.get(&p).is_some_and(|f| {
            (f.producer_id, f.producer_epoch, f.base_sequence)
                == (
                    fields.producer_id,
                    fields.producer_epoch,
                    fields.base_sequence,
                )
        });
        if !ours {
            return;
        }
        call.fixed.remove(&p);
        if let Some(s) = self.idem.as_mut().filter(|s| {
            (s.producer_id, s.producer_epoch) == (fields.producer_id, fields.producer_epoch)
        }) {
            s.set(call.topic, p, fields.base_sequence);
        }
    }
}

/// One [`Producer::send_journaled`] call in progress.
struct Call<'a, 'p> {
    topic: &'a str,
    records: &'a [(i32, ProduceRecord)],
    out: Vec<Option<Outcome>>,
    /// Undecided records of each partition, in order.
    queues: BTreeMap<i32, VecDeque<usize>>,
    /// Per-partition cap on records per batch, set by record-level errors.
    limits: BTreeMap<i32, usize>,
    /// Idempotence: the numbered batch of a partition whose outcome is not
    /// known; re-sent exactly as it is.
    fixed: BTreeMap<i32, JournalBatch>,
    /// Idempotence: this call's acknowledged batches.
    acked: Vec<JournalBatch>,
    persist: &'p mut PersistFn<'p>,
}

impl Call<'_, '_> {
    fn journal(&self) -> SendJournal {
        SendJournal {
            topic: self.topic.to_string(),
            batches: self
                .acked
                .iter()
                .chain(self.fixed.values())
                .cloned()
                .collect(),
        }
    }

    fn remove_from_queue(&mut self, p: i32, idx: &[usize]) {
        if let Some(q) = self.queues.get_mut(&p) {
            q.retain(|i| !idx.contains(i));
            if q.is_empty() {
                self.queues.remove(&p);
            }
        }
    }

    /// `b`'s records are delivered at `base` (consecutive offsets; -1 stays
    /// -1).
    fn decide_delivered(&mut self, b: &JournalBatch, base: i64) {
        let idx: Vec<usize> = b.records.iter().map(|&i| i as usize).collect();
        for (k, &i) in idx.iter().enumerate() {
            if let Some(o) = self.out.get_mut(i) {
                *o = Some(Outcome::Delivered {
                    partition: b.partition,
                    offset: if base < 0 {
                        -1
                    } else {
                        base.saturating_add(k as i64)
                    },
                });
            }
        }
        self.remove_from_queue(b.partition, &idx);
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

    fn plain(b: Vec<String>) -> ProducerConfig {
        let mut c = ProducerConfig::new(b);
        c.allow_plaintext = true;
        c
    }

    #[test]
    fn config_checks() {
        assert!(Producer::new(plain(vec![])).is_err());
        let mut c = plain(vec!["127.0.0.1:1".into()]);
        c.max_request_bytes = 100;
        assert!(Producer::new(c).is_err());
        let c = plain(vec!["127.0.0.1:1".into()]);
        assert!(Producer::new(c).is_ok());
    }

    #[test]
    fn request_timeout_must_exceed_produce_timeout() {
        let d = plain(vec!["127.0.0.1:1".into()]);
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
        let mut p = Producer::new(plain(vec!["127.0.0.1:1".into()])).unwrap();
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
        let mut c = plain(vec!["x:1".into()]);
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
        let mut c = plain(vec!["127.0.0.1:1".into()]);
        c.retries = 2;
        c.retry_backoff = Duration::from_millis(1);
        let mut p = Producer::new(c).unwrap();
        let e = p.partition_count("t").unwrap_err();
        assert!(matches!(e, ProduceError::RetriesExhausted(_)), "{e}");
    }
}
