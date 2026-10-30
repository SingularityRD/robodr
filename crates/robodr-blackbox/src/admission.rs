//! Connection admission for the mutual-TLS servers (agentd's control plane,
//! `robodr-anchor-receiver`, `robodr-depot serve`): who may hold one of the
//! few connection slots, for how long, and who is cut first (red team
//! 2026-10-30, W2-4).
//!
//! The servers handle one request per connection on a thread each, so a
//! slot is a scarce resource. A peer that opens TLS handshakes and trickles
//! a byte a second used to keep every slot busy from a handful of source
//! addresses (S2: the SOC got 1 to 3 of 20 requests through). The rules
//! here make a pre-authentication connection unable to starve a client
//! that completes mutual TLS:
//!
//! * **Two pools.** A connection starts in the bounded *pre-authentication*
//!   pool (handshake, or the whole request on a plain listener). Once the
//!   server has authenticated it (a completed handshake with a valid client
//!   certificate, see each server) it moves ([`Ticket::promote`]) to the
//!   *authenticated* pool, which pre-authentication connections never
//!   occupy.
//! * **Eviction, not refusal.** When the pre-authentication pool (or the
//!   newcomer's source or subnet share of it) is full, the newcomer is
//!   admitted and the connection with the **least progress** in that scope
//!   is cut: one whose ClientHello is not complete yet (the server has not
//!   answered) before one whose is, then the lowest received-bytes rate
//!   since accept (bytes already queued at accept count, see
//!   [`Admission::admit_seen`]; at most [`RANK_BYTES_CAP`] count; a fresh
//!   connection is credited
//!   [`FRESH_CREDIT_BYTES`] over at least [`MIN_SCORE_AGE`]), the oldest
//!   on a tie. A trickling peer is always behind a client that sends its
//!   ClientHello and certificate at once.
//! * **Reserved slots** (`priority_sources`, optional): connections from
//!   these CIDRs (the SOC network) get their own pre-authentication slots
//!   that no other source can occupy, with their own rate bucket.
//! * **Shares.** At most `max_per_source` pre-authentication connections
//!   per source address and `max_per_subnet` per IPv4 /24 or IPv6 /64
//!   ([`subnet_key`]), so a spread of addresses in one subnet does not scale
//!   the attack. Reaching a share evicts within the share.
//! * **Progress deadline** ([`ProgressPolicy`], [`Progress`]): besides each
//!   server's absolute deadline, the server's first answer bytes (for TLS:
//!   the ServerHello, i.e. a complete ClientHello was received) must be
//!   written within `hello_timeout`, and after that the bytes received
//!   must keep up with `min_bytes_per_s` (counted from `hello_timeout` on).
//!   A trickling handshake is cut after about a second instead of five.
//! * **Rate limit.** A new pre-authentication connection takes a token
//!   from its source's bucket (an IPv4 address or an IPv6 /64; half the
//!   global rate, burst the global rate) and from the global bucket (burst
//!   twice the rate); priority sources use their own global bucket. A
//!   source that hammers runs out of its own tokens and is closed at
//!   accept without touching anyone else's. When the global bucket is
//!   empty, a **quiet** source (no connection admitted from it in the last
//!   [`QUIET_PERIOD`]) is still admitted (counted as `admitted_quiet`): an
//!   attacker reconnecting in a loop cannot use up the budget of a SOC that
//!   connects now and then. CPU stays bounded by the global rate plus one
//!   handshake per quiet source and second.
//!
//! Every decision is counted ([`AdmissionStats`]): evictions, connections
//! cut for lack of progress and rate-limited ones are the "handshake
//! pressure" a server reports.
//!
//! # Limits
//!
//! An unlisted client competes with attackers on progress: an attacker
//! that opens many connections from many subnets and sends complete
//! ClientHellos quickly can still evict an unlisted client's handshake
//! (it costs the attacker real bandwidth and the global token budget). The
//! guarantee is for `priority_sources`; outside it the odds are on the side
//! of the client that completes its handshake quickly.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Default time to the server's first answer bytes (a complete ClientHello).
pub const DEFAULT_HELLO_TIMEOUT: Duration = Duration::from_millis(1000);
/// Allowed `hello_timeout`, milliseconds.
pub const HELLO_TIMEOUT_MS_RANGE: (u64, u64) = (200, 5000);
/// Default progress floor after `hello_timeout`, bytes per second.
pub const DEFAULT_MIN_BYTES_PER_S: u32 = 128;
/// Allowed progress floor, bytes per second. Below 16 the floor never
/// binds before a 5 s deadline; above 4096 a client on a slow or long link
/// (a 1-2 KiB certificate flight one round trip after the ClientHello) may
/// be cut.
pub const MIN_BYTES_PER_S_RANGE: (u32, u32) = (16, 4096);
/// The bytes a fresh connection is credited with when ranking for eviction.
pub const FRESH_CREDIT_BYTES: u64 = 64;
/// Ages below this rank as this age (a connection accepted a microsecond
/// ago is not infinitely fast).
pub const MIN_SCORE_AGE: Duration = Duration::from_millis(100);
/// Bytes beyond this do not rank as progress: a handshake needs a few KiB
/// (ClientHello, certificate chain); a peer padding its ClientHello to
/// 16 KiB must not outrank a client that sends what it needs.
pub const RANK_BYTES_CAP: u64 = 4096;
/// A source with no admission for this long is quiet (see the module docs).
pub const QUIET_PERIOD: Duration = Duration::from_secs(1);
/// Most per-source rate buckets kept; full (idle) ones are dropped first.
pub const MAX_SOURCE_BUCKETS: usize = 4096;
/// Most `priority_sources` entries.
pub const MAX_PRIORITY_SOURCES: usize = 32;

/// An IPv4 or IPv6 network (`10.20.0.0/16`, `fd00:1::/64`, or one address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `addr/prefix` or a bare address (a host). Host bits must be
    /// zero (`10.0.0.1/24` is refused: probably a typo).
    pub fn parse(s: &str) -> Result<Self, String> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr = IpAddr::from_str(a).map_err(|_| format!("{s:?}: not an IP network"))?;
        let addr = canonical(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            None => max,
            Some(p) => {
                if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("{s:?}: bad prefix length"));
                }
                p.parse::<u8>()
                    .ok()
                    .filter(|n| *n <= max)
                    .ok_or_else(|| format!("{s:?}: prefix length must be 0..={max}"))?
            }
        };
        if mask(addr, prefix) != addr {
            return Err(format!(
                "{s:?}: host bits set (did you mean {}/{prefix}?)",
                mask(addr, prefix)
            ));
        }
        Ok(Self { net: addr, prefix })
    }

    /// Whether `ip` (IPv4-mapped IPv6 counts as IPv4) is in this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        ip.is_ipv4() == self.net.is_ipv4() && mask(ip, self.prefix) == self.net
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) as IPv4; everything else unchanged.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let bits = u32::from(a);
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix.min(32)))
            };
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix.min(128)))
            };
            IpAddr::V6(Ipv6Addr::from(bits & m))
        }
    }
}

/// The rate-limit key of a source: its IPv4 address or its IPv6 /64 (a
/// host usually holds a whole /64).
pub fn source_key(ip: IpAddr) -> IpAddr {
    let ip = canonical(ip);
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(_) => mask(ip, 64),
    }
}

/// The subnet whose share a source counts against: its IPv4 /24 or its
/// IPv6 /64.
pub fn subnet_key(ip: IpAddr) -> IpAddr {
    let ip = canonical(ip);
    match ip {
        IpAddr::V4(_) => mask(ip, 24),
        IpAddr::V6(_) => mask(ip, 64),
    }
}

/// How fast a pre-authentication connection must progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressPolicy {
    /// The server must have written its first bytes (TLS: the ServerHello
    /// flight, so a complete ClientHello arrived) within this of accept.
    pub hello_timeout: Duration,
    /// From `hello_timeout` on, the bytes received since accept must stay
    /// at or above this many per second elapsed past `hello_timeout`.
    pub min_bytes_per_s: u32,
}

impl Default for ProgressPolicy {
    fn default() -> Self {
        Self {
            hello_timeout: DEFAULT_HELLO_TIMEOUT,
            min_bytes_per_s: DEFAULT_MIN_BYTES_PER_S,
        }
    }
}

impl ProgressPolicy {
    /// Check the configured values against their safe bounds; `what`
    /// prefixes the error (the config key's parent).
    pub fn validated(
        hello_timeout_ms: u64,
        min_bytes_per_s: u32,
        what: &str,
    ) -> Result<Self, String> {
        let (lo, hi) = HELLO_TIMEOUT_MS_RANGE;
        if !(lo..=hi).contains(&hello_timeout_ms) {
            return Err(format!(
                "{what}handshake_hello_timeout_ms = {hello_timeout_ms}: must be {lo}..={hi}"
            ));
        }
        let (lo, hi) = MIN_BYTES_PER_S_RANGE;
        if !(lo..=hi).contains(&min_bytes_per_s) {
            return Err(format!(
                "{what}handshake_min_bytes_per_s = {min_bytes_per_s}: must be {lo}..={hi}"
            ));
        }
        Ok(Self {
            hello_timeout: Duration::from_millis(hello_timeout_ms),
            min_bytes_per_s,
        })
    }
}

/// Why a progress deadline fired (the error message of the read).
pub const TOO_SLOW_HELLO: &str = "handshake too slow: no ClientHello within the hello timeout";
pub const TOO_SLOW_FLOOR: &str = "handshake too slow: below the progress floor";

/// One connection's progress, shared between its socket wrapper (which
/// reports bytes and asks for the deadline) and the pool (which ranks it
/// and may evict it).
#[derive(Debug)]
pub struct Progress {
    accepted: Instant,
    policy: ProgressPolicy,
    bytes_in: AtomicU64,
    /// Bytes already queued when the connection was accepted (peeked).
    seen_at_accept: u64,
    spoke: AtomicBool,
    enforce: AtomicBool,
    evicted: AtomicBool,
    cut: AtomicBool,
    stats: Option<Arc<AdmissionStats>>,
}

impl Progress {
    /// A tracker outside any pool (tests, single connections).
    pub fn new(policy: ProgressPolicy, accepted: Instant) -> Self {
        Self::with_stats(policy, accepted, None, 0)
    }

    fn with_stats(
        policy: ProgressPolicy,
        accepted: Instant,
        stats: Option<Arc<AdmissionStats>>,
        seen_at_accept: u64,
    ) -> Self {
        Self {
            accepted,
            policy,
            bytes_in: AtomicU64::new(0),
            seen_at_accept,
            spoke: AtomicBool::new(false),
            enforce: AtomicBool::new(true),
            evicted: AtomicBool::new(false),
            cut: AtomicBool::new(false),
            stats,
        }
    }

    /// `n` bytes were read from the peer.
    pub fn on_read(&self, n: usize) {
        self.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// The server wrote to the peer (its handshake flight or an answer).
    pub fn on_write(&self) {
        self.spoke.store(true, Ordering::Relaxed);
    }

    /// Stop enforcing (the connection authenticated).
    pub fn release(&self) {
        self.enforce.store(false, Ordering::Relaxed);
    }

    pub fn bytes_in(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }

    pub fn accepted(&self) -> Instant {
        self.accepted
    }

    /// Whether the server has answered (TLS: the ClientHello was complete).
    pub fn answered(&self) -> bool {
        self.spoke.load(Ordering::Relaxed)
    }

    /// Whether the pool evicted this connection (its socket was shut down).
    pub fn evicted(&self) -> bool {
        self.evicted.load(Ordering::Relaxed)
    }

    /// Whether a progress deadline cut this connection.
    pub fn was_cut(&self) -> bool {
        self.cut.load(Ordering::Relaxed)
    }

    /// The progress deadline now (`None`: not enforced).
    pub fn deadline(&self) -> Option<Instant> {
        if !self.enforce.load(Ordering::Relaxed) {
            return None;
        }
        let hello = self.accepted + self.policy.hello_timeout;
        if !self.spoke.load(Ordering::Relaxed) {
            return Some(hello);
        }
        let floor = u64::from(self.policy.min_bytes_per_s.max(1));
        let ms = self.bytes_in().saturating_mul(1000) / floor;
        Some(hello + Duration::from_millis(ms))
    }

    /// Before a read: `Ok(deadline)` (`None`: not enforced), or the
    /// `TimedOut` error once the deadline has passed (counted once as
    /// [`AdmissionStats::too_slow`]).
    pub fn check(&self, now: Instant) -> io::Result<Option<Instant>> {
        match self.deadline() {
            Some(d) if now >= d => Err(self.too_slow()),
            d => Ok(d),
        }
    }

    fn too_slow(&self) -> io::Error {
        if !self.cut.swap(true, Ordering::Relaxed) {
            if let Some(s) = &self.stats {
                s.too_slow.fetch_add(1, Ordering::Relaxed);
            }
        }
        let why = if self.spoke.load(Ordering::Relaxed) {
            TOO_SLOW_FLOOR
        } else {
            TOO_SLOW_HELLO
        };
        io::Error::new(io::ErrorKind::TimedOut, why)
    }

    /// Eviction rank, lowest first: (the server answered, received
    /// bytes per second since accept with [`FRESH_CREDIT_BYTES`] credit
    /// and ages below [`MIN_SCORE_AGE`] counted as that). `(false, 0)`
    /// once the progress deadline has passed.
    fn rank(&self, now: Instant) -> (bool, u128) {
        if self.deadline().is_some_and(|d| now >= d) {
            return (false, 0);
        }
        let age = now
            .saturating_duration_since(self.accepted)
            .max(MIN_SCORE_AGE)
            .as_millis()
            .max(1);
        let bytes = self.bytes_in().max(self.seen_at_accept).min(RANK_BYTES_CAP);
        (
            self.spoke.load(Ordering::Relaxed),
            u128::from(bytes.saturating_add(FRESH_CREDIT_BYTES)) * 1000 / age,
        )
    }
}

/// Cumulative admission counters (shared; read with [`Admission::stats`]).
#[derive(Debug, Default)]
pub struct AdmissionStats {
    pub admitted: AtomicU64,
    pub admitted_priority: AtomicU64,
    /// Closed at accept: no rate token (the source's own bucket, or the
    /// global / priority bucket for a source that is not quiet).
    pub refused_rate: AtomicU64,
    /// Admitted with the global bucket empty because the source was quiet.
    pub admitted_quiet: AtomicU64,
    /// Pre-authentication connections cut to admit a newcomer.
    pub evicted: AtomicU64,
    /// Cut by their progress deadline (ClientHello late, below the floor).
    pub too_slow: AtomicU64,
    /// Moved to the authenticated pool.
    pub promoted: AtomicU64,
    /// Authenticated, but the authenticated pool (or the source's share of
    /// it) was full: stayed in the pre-authentication pool.
    pub promote_full: AtomicU64,
}

/// A snapshot of [`AdmissionStats`] plus the pools' occupancy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AdmissionSnapshot {
    pub admitted: u64,
    pub admitted_priority: u64,
    pub refused_rate: u64,
    pub admitted_quiet: u64,
    pub evicted: u64,
    pub too_slow: u64,
    pub promoted: u64,
    pub promote_full: u64,
    pub pre_auth_open: usize,
    pub priority_open: usize,
    pub authenticated_open: usize,
}

impl AdmissionSnapshot {
    /// Evictions, progress cuts and rate refusals: the handshake pressure.
    pub fn pressure(&self) -> u64 {
        self.evicted
            .saturating_add(self.too_slow)
            .saturating_add(self.refused_rate)
    }
}

/// The admission rules of one listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionConfig {
    /// Pre-authentication slots of unlisted sources.
    pub max_pre_auth: usize,
    /// Pre-authentication connections per source address (each pool).
    pub max_per_source: usize,
    /// Pre-authentication connections per IPv4 /24 or IPv6 /64 (unlisted
    /// sources).
    pub max_per_subnet: usize,
    /// Networks with reserved pre-authentication slots.
    pub priority_sources: Vec<Cidr>,
    /// Reserved pre-authentication slots of `priority_sources` (0: none).
    pub max_priority: usize,
    /// Authenticated slots.
    pub max_authed: usize,
    /// Authenticated connections per source address.
    pub max_authed_per_source: usize,
    /// New pre-authentication connections per second (global bucket, burst
    /// twice this; each source half of it, burst this). 0: no rate limit.
    pub rate_per_s: u32,
    pub progress: ProgressPolicy,
}

impl AdmissionConfig {
    /// `max` slots in each pool, `per_source` per address, no subnet share
    /// beyond `max`, no priority sources, no rate limit, default progress.
    pub fn simple(max: usize, per_source: usize) -> Self {
        let max = max.max(1);
        let per_source = per_source.clamp(1, max);
        Self {
            max_pre_auth: max,
            max_per_source: per_source,
            max_per_subnet: max,
            priority_sources: Vec::new(),
            max_priority: 0,
            max_authed: max,
            max_authed_per_source: per_source,
            rate_per_s: 0,
            progress: ProgressPolicy::default(),
        }
    }

    fn normalized(mut self) -> Self {
        self.max_pre_auth = self.max_pre_auth.max(1);
        self.max_per_source = self.max_per_source.max(1);
        self.max_per_subnet = self.max_per_subnet.max(1);
        self.max_authed = self.max_authed.max(1);
        self.max_authed_per_source = self.max_authed_per_source.max(1);
        if self.priority_sources.is_empty() {
            self.max_priority = 0;
        }
        self
    }
}

/// Parse a `priority_sources` list (at most [`MAX_PRIORITY_SOURCES`]).
pub fn parse_priority_sources(list: &[String], what: &str) -> Result<Vec<Cidr>, String> {
    if list.len() > MAX_PRIORITY_SOURCES {
        return Err(format!(
            "{what}priority_sources: at most {MAX_PRIORITY_SOURCES} networks"
        ));
    }
    list.iter()
        .map(|s| Cidr::parse(s).map_err(|e| format!("{what}priority_sources: {e}")))
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    at: Instant,
}

impl Bucket {
    fn new(rate: f64, burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            rate,
            burst,
            at: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        self.at = self.at.max(now);
    }

    fn has(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= 1.0
    }

    fn take(&mut self) {
        self.tokens -= 1.0;
    }

    fn full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.burst
    }
}

#[derive(Debug)]
struct Entry {
    id: u64,
    ip: IpAddr,
    subnet: IpAddr,
    priority: bool,
    progress: Arc<Progress>,
    kill: Option<TcpStream>,
}

#[derive(Debug)]
struct State {
    next_id: u64,
    pre: Vec<Entry>,
    authed: usize,
    authed_per_source: HashMap<IpAddr, usize>,
    global: Bucket,
    priority: Bucket,
    sources: HashMap<IpAddr, SourceRate>,
}

#[derive(Debug, Clone, Copy)]
struct SourceRate {
    bucket: Bucket,
    /// The last admission from this source.
    last: Option<Instant>,
}

impl SourceRate {
    fn quiet(&self, now: Instant) -> bool {
        self.last
            .is_none_or(|t| now.saturating_duration_since(t) >= QUIET_PERIOD)
    }

    fn idle(&mut self, now: Instant) -> bool {
        self.quiet(now) && self.bucket.full(now)
    }
}

#[derive(Debug)]
struct Shared {
    cfg: AdmissionConfig,
    state: Mutex<State>,
    stats: Arc<AdmissionStats>,
}

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The pools of one listener. Cheap to clone (shared).
#[derive(Debug, Clone)]
pub struct Admission {
    shared: Arc<Shared>,
}

/// Why a connection was closed at accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// No token in the new-connection rate bucket.
    RateLimited,
}

impl Admission {
    pub fn new(cfg: AdmissionConfig) -> Self {
        let cfg = cfg.normalized();
        let now = Instant::now();
        let rate = f64::from(cfg.rate_per_s);
        let state = State {
            next_id: 0,
            pre: Vec::new(),
            authed: 0,
            authed_per_source: HashMap::new(),
            global: Bucket::new(rate, (rate * 2.0).max(1.0), now),
            priority: Bucket::new(rate, (rate * 2.0).max(1.0), now),
            sources: HashMap::new(),
        };
        Self {
            shared: Arc::new(Shared {
                cfg,
                state: Mutex::new(state),
                stats: Arc::new(AdmissionStats::default()),
            }),
        }
    }

    pub fn config(&self) -> &AdmissionConfig {
        &self.shared.cfg
    }

    /// Whether `ip` is in a priority network (with reserved slots).
    pub fn is_priority(&self, ip: IpAddr) -> bool {
        let c = &self.shared.cfg;
        c.max_priority > 0 && c.priority_sources.iter().any(|n| n.contains(ip))
    }

    /// Admit a new connection from `ip` into the pre-authentication pool,
    /// evicting the least-progress connection of its scope when that is
    /// full. `kill` is a handle of the connection's socket (`try_clone`)
    /// the pool shuts down to evict it; without one an evicted connection
    /// only learns it from [`Progress::evicted`] at its next read.
    pub fn admit(&self, ip: IpAddr, kill: Option<TcpStream>) -> Result<Ticket, Refused> {
        self.admit_at(ip, kill, 0, Instant::now())
    }

    /// [`Admission::admit`] for a connection that already had `seen` bytes
    /// queued when it was accepted (a non-blocking `peek` by the accept
    /// loop): until its thread has read them, they rank it as having sent
    /// them, so the churn of a flood cannot evict a client whose
    /// ClientHello is already there before its thread gets to it.
    pub fn admit_seen(
        &self,
        ip: IpAddr,
        kill: Option<TcpStream>,
        seen: usize,
    ) -> Result<Ticket, Refused> {
        self.admit_at(ip, kill, seen as u64, Instant::now())
    }

    fn admit_at(
        &self,
        ip: IpAddr,
        kill: Option<TcpStream>,
        seen: u64,
        now: Instant,
    ) -> Result<Ticket, Refused> {
        let sh = &self.shared;
        let cfg = &sh.cfg;
        let ip = canonical(ip);
        let priority = self.is_priority(ip);
        let subnet = subnet_key(ip);
        let mut g = lock(&sh.state);
        if cfg.rate_per_s > 0 {
            match take_token(&mut g, cfg, priority, source_key(ip), now) {
                Token::Refused => {
                    sh.stats.refused_rate.fetch_add(1, Ordering::Relaxed);
                    return Err(Refused::RateLimited);
                }
                Token::Quiet => {
                    sh.stats.admitted_quiet.fetch_add(1, Ordering::Relaxed);
                }
                Token::Taken => {}
            }
        }
        let same_pool = |e: &Entry| e.priority == priority;
        let pool_cap = if priority {
            cfg.max_priority
        } else {
            cfg.max_pre_auth
        };
        let n_src = g.pre.iter().filter(|e| same_pool(e) && e.ip == ip).count();
        let n_net = g
            .pre
            .iter()
            .filter(|e| !e.priority && e.subnet == subnet)
            .count();
        let n_pool = g.pre.iter().filter(|e| same_pool(e)).count();
        let victim = if n_src >= cfg.max_per_source {
            worst(&g.pre, now, |e| same_pool(e) && e.ip == ip)
        } else if !priority && n_net >= cfg.max_per_subnet {
            worst(&g.pre, now, |e| !e.priority && e.subnet == subnet)
        } else if n_pool >= pool_cap {
            worst(&g.pre, now, same_pool)
        } else {
            None
        };
        if let Some(i) = victim {
            let e = g.pre.swap_remove(i);
            e.progress.evicted.store(true, Ordering::Relaxed);
            if let Some(k) = &e.kill {
                let _ = k.shutdown(Shutdown::Both);
            }
            sh.stats.evicted.fetch_add(1, Ordering::Relaxed);
        }
        let id = g.next_id;
        g.next_id = g.next_id.wrapping_add(1);
        let progress = Arc::new(Progress::with_stats(
            cfg.progress,
            now,
            Some(sh.stats.clone()),
            seen,
        ));
        g.pre.push(Entry {
            id,
            ip,
            subnet,
            priority,
            progress: progress.clone(),
            kill,
        });
        sh.stats.admitted.fetch_add(1, Ordering::Relaxed);
        if priority {
            sh.stats.admitted_priority.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Ticket {
            shared: sh.clone(),
            id,
            ip,
            progress,
            authed: false,
        })
    }

    /// Counters and pool occupancy now.
    pub fn stats(&self) -> AdmissionSnapshot {
        let s = &self.shared.stats;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let st = lock(&self.shared.state);
        AdmissionSnapshot {
            admitted: g(&s.admitted),
            admitted_priority: g(&s.admitted_priority),
            refused_rate: g(&s.refused_rate),
            admitted_quiet: g(&s.admitted_quiet),
            evicted: g(&s.evicted),
            too_slow: g(&s.too_slow),
            promoted: g(&s.promoted),
            promote_full: g(&s.promote_full),
            pre_auth_open: st.pre.iter().filter(|e| !e.priority).count(),
            priority_open: st.pre.iter().filter(|e| e.priority).count(),
            authenticated_open: st.authed,
        }
    }
}

enum Token {
    Taken,
    /// The global (or priority) bucket was empty; the source was quiet.
    Quiet,
    Refused,
}

fn take_token(
    g: &mut State,
    cfg: &AdmissionConfig,
    priority: bool,
    source: IpAddr,
    now: Instant,
) -> Token {
    let rate = (f64::from(cfg.rate_per_s) / 2.0).max(0.5);
    let burst = f64::from(cfg.rate_per_s).max(2.0);
    if !g.sources.contains_key(&source) && g.sources.len() >= MAX_SOURCE_BUCKETS {
        // Drop the idle ones; if every one is busy, a new source has no
        // bucket of its own: the global one decides, and it is not quiet.
        g.sources.retain(|_, r| !r.idle(now));
    }
    let has_own = g.sources.len() < MAX_SOURCE_BUCKETS || g.sources.contains_key(&source);
    let quiet = if has_own {
        let r = g.sources.entry(source).or_insert(SourceRate {
            bucket: Bucket::new(rate, burst, now),
            last: None,
        });
        if !r.bucket.has(now) {
            return Token::Refused;
        }
        r.quiet(now)
    } else {
        false
    };
    let global = if priority {
        &mut g.priority
    } else {
        &mut g.global
    };
    let token = if global.has(now) {
        global.take();
        Token::Taken
    } else if quiet {
        Token::Quiet
    } else {
        return Token::Refused;
    };
    if let Some(r) = g.sources.get_mut(&source) {
        r.bucket.take();
        r.last = Some(now);
    }
    token
}

/// The least-progress entry matching `f` (lowest rank, oldest on a tie).
fn worst(pre: &[Entry], now: Instant, f: impl Fn(&Entry) -> bool) -> Option<usize> {
    pre.iter()
        .enumerate()
        .filter(|(_, e)| f(e))
        .min_by_key(|(_, e)| (e.progress.rank(now), e.progress.accepted))
        .map(|(i, _)| i)
}

/// A connection's hold on the pools; released on drop.
#[derive(Debug)]
pub struct Ticket {
    shared: Arc<Shared>,
    id: u64,
    ip: IpAddr,
    progress: Arc<Progress>,
    authed: bool,
}

impl Ticket {
    /// The connection's progress tracker (give it to the socket wrapper).
    pub fn progress(&self) -> Arc<Progress> {
        self.progress.clone()
    }

    pub fn is_authenticated(&self) -> bool {
        self.authed
    }

    /// Whether the pool evicted this connection.
    pub fn evicted(&self) -> bool {
        self.progress.evicted()
    }

    /// Move to the authenticated pool (and stop the progress deadline).
    /// `false` when it is full (or the source's share of it), the
    /// connection then keeps its pre-authentication slot, or when the
    /// connection was evicted meanwhile.
    pub fn promote(&mut self) -> bool {
        if self.authed {
            return true;
        }
        let sh = &self.shared;
        let mut g = lock(&sh.state);
        let Some(i) = g.pre.iter().position(|e| e.id == self.id) else {
            return false;
        };
        let from_ip = g.authed_per_source.get(&self.ip).copied().unwrap_or(0);
        if g.authed >= sh.cfg.max_authed || from_ip >= sh.cfg.max_authed_per_source {
            sh.stats.promote_full.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        g.pre.swap_remove(i);
        g.authed += 1;
        g.authed_per_source.insert(self.ip, from_ip + 1);
        self.authed = true;
        self.progress.release();
        sh.stats.promoted.fetch_add(1, Ordering::Relaxed);
        true
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut g = lock(&self.shared.state);
        if self.authed {
            g.authed = g.authed.saturating_sub(1);
            if let Some(n) = g.authed_per_source.get_mut(&self.ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    g.authed_per_source.remove(&self.ip);
                }
            }
        } else if let Some(i) = g.pre.iter().position(|e| e.id == self.id) {
            g.pre.swap_remove(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn cfg(max: usize, per_src: usize, per_net: usize) -> AdmissionConfig {
        AdmissionConfig {
            max_pre_auth: max,
            max_per_source: per_src,
            max_per_subnet: per_net,
            ..AdmissionConfig::simple(max, per_src)
        }
    }

    #[test]
    fn cidrs_parse_and_match() {
        let c = Cidr::parse("10.20.0.0/16").unwrap();
        assert!(c.contains(v4(10, 20, 3, 4)));
        assert!(!c.contains(v4(10, 21, 0, 1)));
        // IPv4-mapped IPv6 is the IPv4 address.
        assert!(c.contains("::ffff:10.20.9.9".parse().unwrap()));
        let h = Cidr::parse("192.0.2.7").unwrap();
        assert_eq!(h.to_string(), "192.0.2.7/32");
        assert!(h.contains(v4(192, 0, 2, 7)) && !h.contains(v4(192, 0, 2, 8)));
        let six = Cidr::parse("fd00:1::/64").unwrap();
        assert!(six.contains("fd00:1::abcd".parse().unwrap()));
        assert!(!six.contains("fd00:2::1".parse().unwrap()));
        assert!(!six.contains(v4(10, 20, 3, 4)));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(v4(1, 2, 3, 4)));
        for bad in [
            "10.0.0.1/24",
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/-1",
            "x/8",
            "",
            "fd00::/129",
            "10.0.0.0/+8",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(subnet_key(v4(10, 1, 2, 3)), v4(10, 1, 2, 0));
        assert_eq!(
            subnet_key("fd00:1:2:3:4:5:6:7".parse().unwrap()),
            "fd00:1:2:3::".parse::<IpAddr>().unwrap()
        );
        let list: Vec<String> = (0..33).map(|i| format!("10.0.{i}.0/24")).collect();
        assert!(parse_priority_sources(&list, "x.").is_err());
        assert_eq!(parse_priority_sources(&list[..2], "x.").unwrap().len(), 2);
    }

    #[test]
    fn progress_deadline_hello_then_floor() {
        let t0 = Instant::now();
        let p = Progress::new(
            ProgressPolicy {
                hello_timeout: Duration::from_millis(1000),
                min_bytes_per_s: 100,
            },
            t0,
        );
        assert_eq!(p.deadline(), Some(t0 + Duration::from_millis(1000)));
        // Bytes alone do not move the hello deadline: the server must
        // have answered (a complete ClientHello).
        p.on_read(300);
        assert_eq!(p.deadline(), Some(t0 + Duration::from_millis(1000)));
        p.on_write();
        // 300 B at 100 B/s: three seconds past the hello timeout.
        assert_eq!(p.deadline(), Some(t0 + Duration::from_millis(4000)));
        assert!(p.check(t0 + Duration::from_millis(3999)).is_ok());
        let e = p.check(t0 + Duration::from_millis(4000)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(e.to_string(), TOO_SLOW_FLOOR);
        assert!(p.was_cut());
        p.release();
        assert_eq!(p.deadline(), None);
        assert!(p.check(t0 + Duration::from_secs(60)).is_ok());
        let q = Progress::new(ProgressPolicy::default(), t0);
        assert_eq!(
            q.check(t0 + Duration::from_secs(2))
                .unwrap_err()
                .to_string(),
            TOO_SLOW_HELLO
        );
    }

    #[test]
    fn policy_bounds() {
        assert!(ProgressPolicy::validated(1000, 128, "").is_ok());
        assert!(ProgressPolicy::validated(199, 128, "").is_err());
        assert!(ProgressPolicy::validated(5001, 128, "").is_err());
        assert!(ProgressPolicy::validated(1000, 15, "").is_err());
        let e = ProgressPolicy::validated(1000, 4097, "cp.").unwrap_err();
        assert!(e.contains("cp.handshake_min_bytes_per_s"), "{e}");
    }

    /// A full pool admits the newcomer and cuts the least-progress
    /// connection, never one that is progressing well.
    #[test]
    fn eviction_cuts_the_slowest_not_the_newcomer() {
        let a = Admission::new(cfg(3, 3, 3));
        let t0 = Instant::now();
        let slow = a.admit_at(v4(10, 0, 0, 1), None, 0, t0).unwrap();
        let fast = a.admit_at(v4(10, 0, 1, 1), None, 0, t0).unwrap();
        let mid = a.admit_at(v4(10, 0, 2, 1), None, 0, t0).unwrap();
        slow.progress().on_read(2);
        fast.progress().on_read(4000);
        mid.progress().on_read(300);
        // At 900 ms: slow 73 B/s, mid 404 B/s, fast 4515 B/s.
        let later = t0 + Duration::from_millis(900);
        let new = a.admit_at(v4(10, 0, 3, 1), None, 0, later).unwrap();
        assert!(slow.evicted());
        assert!(!fast.evicted() && !mid.evicted() && !new.evicted());
        assert_eq!(a.stats().evicted, 1);
        assert_eq!(a.stats().pre_auth_open, 3);
        // A fresh connection is credited 64 B over 100 ms (640 B/s): it
        // ranks above mid, which goes next.
        let n2 = a.admit_at(v4(10, 0, 4, 1), None, 0, later).unwrap();
        assert!(mid.evicted() && !new.evicted() && !fast.evicted());
        drop(n2);
        drop(slow);
        // An evicted ticket's drop does not free someone else's slot.
        assert_eq!(a.stats().pre_auth_open, 2);
        drop((fast, mid, new));
        assert_eq!(a.stats().pre_auth_open, 0);
        // Equal progress: the oldest goes.
        let a = Admission::new(cfg(2, 2, 2));
        let old = a.admit_at(v4(10, 0, 0, 1), None, 0, t0).unwrap();
        let young = a
            .admit_at(v4(10, 0, 1, 1), None, 0, t0 + Duration::from_millis(10))
            .unwrap();
        let _n = a
            .admit_at(v4(10, 0, 2, 1), None, 0, t0 + Duration::from_millis(50))
            .unwrap();
        assert!(old.evicted() && !young.evicted());
    }

    /// A connection whose ClientHello is complete (the server answered)
    /// outranks any that is still sending one; bytes queued at accept
    /// count before the thread has read them.
    #[test]
    fn a_completed_hello_and_queued_bytes_protect_from_eviction() {
        let a = Admission::new(cfg(2, 2, 2));
        let t0 = Instant::now();
        let soc = a.admit_at(v4(10, 0, 0, 1), None, 0, t0).unwrap();
        soc.progress().on_read(20);
        soc.progress().on_write();
        let trickler = a.admit_at(v4(10, 0, 1, 1), None, 0, t0).unwrap();
        trickler.progress().on_read(40);
        // At 900 ms the trickler has the higher byte rate but no answer.
        let later = t0 + Duration::from_millis(900);
        let _n = a.admit_at(v4(10, 0, 2, 1), None, 0, later).unwrap();
        assert!(trickler.evicted() && !soc.evicted());
        // Padding does not buy rank: 16 KiB at 4 s ranks as 4 KiB.
        let a = Admission::new(cfg(2, 2, 2));
        let pad = a.admit_at(v4(10, 0, 0, 1), None, 0, t0).unwrap();
        pad.progress().on_read(16384);
        pad.progress().on_write();
        let t4 = t0 + Duration::from_secs(4);
        let real = a.admit_at(v4(10, 0, 1, 1), None, 0, t4).unwrap();
        real.progress().on_read(1500);
        real.progress().on_write();
        let _n = a
            .admit_at(v4(10, 0, 2, 1), None, 0, t4 + Duration::from_millis(50))
            .unwrap();
        assert!(pad.evicted() && !real.evicted());
        // Queued bytes: a client accepted with its ClientHello waiting
        // ranks above fresh empty connections at once.
        let a = Admission::new(cfg(2, 2, 2));
        let hello = a.admit_at(v4(10, 0, 0, 1), None, 300, t0).unwrap();
        let empty = a.admit_at(v4(10, 0, 1, 1), None, 0, t0).unwrap();
        let _n = a.admit_at(v4(10, 0, 2, 1), None, 0, t0).unwrap();
        assert!(empty.evicted() && !hello.evicted());
    }

    /// Evicting shuts the socket down: the blocked reader returns at once.
    #[test]
    fn eviction_shuts_the_socket_down() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, peer) = l.accept().unwrap();
        let a = Admission::new(cfg(1, 1, 1));
        let t = a.admit(peer.ip(), s.try_clone().ok()).unwrap();
        let h = std::thread::spawn(move || {
            let mut s = s;
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let t0 = Instant::now();
            let mut b = [0u8; 1];
            let r = io::Read::read(&mut s, &mut b);
            (r.map_err(|e| e.kind()), t0.elapsed())
        });
        std::thread::sleep(Duration::from_millis(100));
        let _t2 = a.admit(peer.ip(), None).unwrap();
        let (r, took) = h.join().unwrap();
        assert!(matches!(r, Ok(0) | Err(_)), "{r:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(t.evicted());
        drop(c);
    }

    /// Per-source and per-subnet shares: a source or a /24 at its share
    /// evicts within the share, never in another subnet.
    #[test]
    fn source_and_subnet_shares_evict_within_the_share() {
        let a = Admission::new(cfg(16, 2, 3));
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let other = a.admit_at(v4(192, 168, 9, 9), None, 0, t0).unwrap();
        // Another subnet's connection is the slowest of all...
        let mut attackers = Vec::new();
        for i in 0..12u8 {
            let t = a
                .admit_at(v4(10, 0, 0, 10 + i), None, 0, at(u64::from(i)))
                .unwrap();
            t.progress().on_read(100);
            attackers.push(t);
        }
        // ...and still never evicted by the /24's newcomers.
        assert!(!other.evicted());
        let open = attackers.iter().filter(|t| !t.evicted()).count();
        assert_eq!(open, 3, "the /24 holds its share only");
        assert_eq!(a.stats().pre_auth_open, 4);
        // Per source: the third from one address evicts that address's own.
        let x1 = a.admit_at(v4(172, 16, 0, 1), None, 0, at(20)).unwrap();
        let x2 = a.admit_at(v4(172, 16, 0, 1), None, 0, at(21)).unwrap();
        let x3 = a.admit_at(v4(172, 16, 0, 1), None, 0, at(22)).unwrap();
        assert!(x1.evicted() && !x2.evicted() && !x3.evicted());
        assert!(!other.evicted());
        // IPv6: one /64 is one subnet.
        let six: Vec<Ticket> = (1..=5u16)
            .map(|i| {
                let ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, i));
                a.admit_at(ip, None, 0, at(30 + u64::from(i))).unwrap()
            })
            .collect();
        assert_eq!(six.iter().filter(|t| !t.evicted()).count(), 3);
        assert!(!other.evicted());
    }

    /// Priority sources have reserved slots no other source can take, and
    /// their own global rate bucket.
    #[test]
    fn priority_sources_keep_reserved_slots() {
        let mut c = cfg(2, 2, 2);
        c.priority_sources = vec![Cidr::parse("10.9.0.0/16").unwrap()];
        c.max_priority = 1;
        c.rate_per_s = 2;
        let a = Admission::new(c);
        let t0 = Instant::now();
        let soc = a.admit_at(v4(10, 9, 1, 1), None, 0, t0).unwrap();
        // A flood from elsewhere: rate-limited and evicting among itself.
        let mut flood = Vec::new();
        for i in 0..40u8 {
            if let Ok(t) = a.admit_at(v4(10, 0, i % 4, 1), None, 0, t0) {
                flood.push(t);
            }
        }
        assert!(!soc.evicted(), "the reserved slot holds");
        let st = a.stats();
        assert_eq!((st.priority_open, st.pre_auth_open), (1, 2));
        assert!(st.refused_rate > 0, "{st:?}");
        // The SOC's bucket is its own: still a token for it.
        let soc2 = a.admit_at(v4(10, 9, 1, 2), None, 0, t0).unwrap();
        // The reserved pool is one slot: the newcomer evicts the older.
        assert!(soc.evicted() && !soc2.evicted());
        assert!(a.is_priority(v4(10, 9, 200, 1)) && !a.is_priority(v4(10, 8, 0, 1)));
    }

    /// Per-source buckets stop a hammering source on its own; an empty
    /// global bucket refuses busy sources but not quiet ones.
    #[test]
    fn rate_limit_is_per_source_and_global_with_quiet_sources_passing() {
        let mut c = cfg(16, 16, 16);
        c.rate_per_s = 10; // global 10/s burst 20; per source 5/s burst 10
        let a = Admission::new(c);
        let t0 = Instant::now();
        let mut held = Vec::new();
        let mut try_at = |ip: IpAddr, t: Instant| match a.admit_at(ip, None, 0, t) {
            Ok(x) => {
                held.push(x);
                true
            }
            Err(Refused::RateLimited) => false,
        };
        // One source hammering: its own burst (10), then refused.
        let ok = (0..30).filter(|_| try_at(v4(10, 0, 0, 1), t0)).count();
        assert_eq!(ok, 10);
        // Ten other sources take the rest of the global burst (20).
        let ok = (1..=10u8).filter(|i| try_at(v4(10, 0, 1, *i), t0)).count();
        assert_eq!(ok, 10);
        // Global empty: a source that just connected (not quiet) is refused...
        assert!(!try_at(v4(10, 0, 1, 1), t0));
        // ...a quiet one (never seen) still gets in, once.
        assert!(try_at(v4(192, 168, 7, 7), t0));
        assert!(!try_at(v4(192, 168, 7, 7), t0 + Duration::from_millis(50)));
        let st = a.stats();
        assert_eq!((st.refused_rate, st.admitted_quiet), (22, 1));
        // Two seconds later the global bucket is full again; drain it
        // with new sources, then the hammering source, quiet for two
        // seconds, passes once more.
        let t2 = t0 + Duration::from_secs(2);
        let ok = (0..20u8).filter(|i| try_at(v4(10, 0, 2, *i), t2)).count();
        assert_eq!(ok, 20);
        assert!(try_at(v4(10, 0, 0, 1), t2));
        assert!(!try_at(v4(10, 0, 0, 1), t2));
        // IPv6: one /64 is one source.
        let six = |i: u16| IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 9, 0, 0, 0, i));
        let t9 = t0 + Duration::from_secs(9);
        let ok = (1..=20u16).filter(|i| try_at(six(*i), t9)).count();
        assert_eq!(ok, 10);
    }

    /// The authenticated pool is separate: a full pre-authentication pool
    /// does not stop a connection that authenticated, and promoting frees
    /// its pre-authentication slot.
    #[test]
    fn promotion_moves_to_the_authenticated_pool() {
        let mut c = cfg(2, 2, 2);
        c.max_authed = 1;
        let a = Admission::new(c);
        let mut s1 = a.admit(v4(10, 0, 0, 1), None).unwrap();
        let mut s2 = a.admit(v4(10, 0, 1, 1), None).unwrap();
        assert!(s1.progress().deadline().is_some());
        assert!(s1.promote());
        assert!(s1.is_authenticated() && s1.progress().deadline().is_none());
        // Authenticated full: s2 keeps its pre-auth slot.
        assert!(!s2.promote());
        assert_eq!(a.stats().promote_full, 1);
        // Pre-auth newcomers never evict an authenticated connection.
        let mut flood = Vec::new();
        for i in 0..10u8 {
            flood.push(a.admit(v4(10, 0, 2 + i, 1), None).unwrap());
        }
        assert!(!s1.evicted());
        let st = a.stats();
        assert_eq!((st.pre_auth_open, st.authenticated_open), (2, 1));
        drop(s1);
        assert_eq!(a.stats().authenticated_open, 0);
        // s2 was evicted by the flood: it can no longer promote.
        assert!(s2.evicted() && !s2.promote());
    }
}
