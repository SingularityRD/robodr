//! The control-plane action API (`control_plane`, off by default).
//!
//! A SOC asks for one of the seven catalog actions
//! ([`robodr_responder::actions`]) on this
//! robot; agentd validates the request, judges it with the response policy
//! against the robot's *current* safety state (Cyber-Jidoka,
//! [`api::judge`]), records the request and the decision in the signed
//! black box and answers. Contract: `docs/contracts/robodr.control-plane.md`.
//!
//! **Nothing is executed.** The only executor is [`api::RecordingExecutor`]:
//! an accepted request is answered `recorded_not_executed`
//! (`"executed": false`), "accepted and recorded as a plan", never
//! `applied`. RoboDR never overrides the platform's safety authority: the
//! strongest action is a *request* for a safe state, and while the safety
//! system is engaged every request is refused.
//!
//! ```text
//!  SOC ── HTTP/1.1 (TCP and/or unix socket) ──► listener thread
//!          one request per connection           │ bounded parse (http), Ed25519 signature,
//!                                               │ timestamp window + nonce cache, rate limit (auth)
//!                                               │ strict body (api::parse_submit)
//!                                               ▼ bounded channel (try_send; full = 503)
//!                                         main loop (Daemon::control_poll)
//!                                               │ api::Engine: judge against the live safety
//!                                               │ state, policy, context; black-box note;
//!                                               │ RecordingExecutor (nothing executed); store
//!                                               ▼
//!                                         answer (optionally signed with the finding key)
//! ```
//!
//! # Threat model (summary; full text in the contract and `SECURITY.md`)
//!
//! * **Who may ask.** Only holders of a configured SOC Ed25519 key
//!   (`soc_keys`, public key files). The signature covers the method, the
//!   exact target, this robot's id, the key id, a timestamp, a nonce and
//!   the body hash ([`auth::signing_message`]), so a request cannot be
//!   altered, moved to another robot or replayed (timestamp window plus a
//!   nonce cache that fails closed when full).
//! * **What may be asked.** The seven catalog actions, their own
//!   parameters, TTL rules (`safe_pause` / `request_safe_state` are refused
//!   on a humanoid: it would fall);
//!   no motion command, no override. A valid signature does not widen
//!   this: an authenticated but invalid body is refused (400) and
//!   recorded.
//! * **What happens.** Nothing reaches the robot: the request is judged and
//!   recorded. A refusal is final (never retried here).
//! * **Transport.** agentd has no TLS stack: requests are authenticated,
//!   not confidential. Answers are unauthenticated unless
//!   `finding_signing` is configured, in which case every answer to an
//!   authenticated request carries [`auth::H_ANSWER_SIGNATURE`]
//!   (domain-separated, bound to the request signature). Listen on
//!   loopback or a unix socket and put TLS in front for anything remote;
//!   a non-loopback TCP address needs `allow_remote: true`.
//! * **Abuse.** Bounded parsing, a read deadline, a connection cap, a
//!   per-key rate limit and a bounded queue to the main loop: a flood
//!   costs the control plane's availability (503 / 429), never the
//!   detection loop's. Failed authentications are counted and reported as
//!   the observe-only finding `robot.agent.control_plane_unauthenticated`
//!   (High, rate-limited), authenticated invalid requests as
//!   `robot.agent.control_plane_invalid` (Medium).

pub mod api;
pub mod auth;
pub mod http;

use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use api::{Answer, ApiError, Call, Meta};
use auth::{AuthFailure, RateLimiter, ReplayGuard, SocKey};

/// Most SOC keys.
pub const MAX_SOC_KEYS: usize = 16;
/// Longest a connection may take to send its request.
pub const READ_DEADLINE: Duration = Duration::from_secs(5);
/// Calls waiting for the main loop.
pub const CALL_QUEUE: usize = 16;
/// Calls the main loop handles per iteration.
pub const CALLS_PER_POLL: usize = 8;
/// Largest SOC public key file.
pub const MAX_SOC_KEY_FILE_BYTES: u64 = 4096;

fn default_mode() -> String {
    "0600".into()
}
fn default_skew() -> u64 {
    30
}
fn default_rate() -> u32 {
    30
}
fn default_burst() -> u32 {
    10
}
fn default_connections() -> usize {
    4
}
fn default_requests() -> usize {
    1024
}
fn default_answer_ms() -> u64 {
    5000
}

/// `control_plane` (optional; absent = no listener at all).
///
/// ```json
/// "control_plane": {
///   "listen_tcp": "127.0.0.1:8787",
///   "unix_socket": "/run/robodr-agentd/control.sock",
///   "soc_keys": ["/etc/robodr/soc/soc.pub"]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneSection {
    /// TCP address (`ip:port`, port not 0). Loopback unless `allow_remote`.
    #[serde(default)]
    pub listen_tcp: Option<String>,
    /// Permit a non-loopback `listen_tcp` (plain HTTP: put TLS in front).
    #[serde(default)]
    pub allow_remote: bool,
    /// Absolute path of a unix stream socket (private directory).
    #[serde(default)]
    pub unix_socket: Option<PathBuf>,
    /// `"0600"` (default) or `"0660"` for `unix_socket`.
    #[serde(default = "default_mode")]
    pub socket_mode: String,
    /// SOC public key files (`robodr-blackbox keygen` `.pub`, Ed25519).
    pub soc_keys: Vec<PathBuf>,
    /// Allowed |robot clock - request timestamp|, 1..=300 s.
    #[serde(default = "default_skew")]
    pub max_clock_skew_s: u64,
    /// Authenticated requests per key and minute, 1..=600.
    #[serde(default = "default_rate")]
    pub rate_per_minute: u32,
    /// Burst per key, 1..=100.
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// Concurrent connections over all listeners, 1..=16.
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    /// Requests kept for GET / revert / idempotency, 16..=65536.
    #[serde(default = "default_requests")]
    pub max_requests: usize,
    /// How long a connection waits for the main loop, 100..=30000 ms.
    #[serde(default = "default_answer_ms")]
    pub answer_timeout_ms: u64,
}

/// A validated [`ControlPlaneSection`] with its keys loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneSpec {
    pub tcp: Option<SocketAddr>,
    pub unix: Option<PathBuf>,
    pub unix_mode: u32,
    pub keys: Vec<SocKey>,
    pub skew_s: u64,
    pub rate_per_minute: u32,
    pub burst: u32,
    pub max_connections: usize,
    pub max_requests: usize,
    pub answer_timeout: Duration,
}

fn range(what: &str, v: u64, lo: u64, hi: u64) -> Result<(), String> {
    if (lo..=hi).contains(&v) {
        Ok(())
    } else {
        Err(format!("control_plane.{what} = {v}: must be {lo}..={hi}"))
    }
}

impl ControlPlaneSection {
    /// Validate and load the SOC keys. `robot_id` binds keys that name a
    /// device; `own_key_ids` are the black-box and finding key ids (a SOC
    /// key must be neither).
    pub fn resolve(
        &self,
        robot_id: &str,
        own_key_ids: &[&str],
    ) -> Result<ControlPlaneSpec, String> {
        let tcp = match &self.listen_tcp {
            None => None,
            Some(s) => {
                let a: SocketAddr = s.parse().map_err(|_| {
                    format!(
                        "control_plane.listen_tcp {:?}: not an ip:port address",
                        robodr_ros2_pipeline::sanitize(s)
                    )
                })?;
                if a.port() == 0 {
                    return Err("control_plane.listen_tcp: port 0 is not allowed".into());
                }
                if !a.ip().is_loopback() && !self.allow_remote {
                    return Err(format!(
                        "control_plane.listen_tcp {a} is not a loopback address: the API is plain \
                         HTTP (authenticated, not encrypted); listen on loopback and put TLS in \
                         front, or set allow_remote = true"
                    ));
                }
                Some(a)
            }
        };
        if let Some(p) = &self.unix_socket {
            if p.as_os_str().is_empty() || !p.is_absolute() {
                return Err("control_plane.unix_socket must be an absolute path".into());
            }
            if p.file_name().is_none() || p.parent().is_none() {
                return Err("control_plane.unix_socket must name a file in a directory".into());
            }
        }
        if tcp.is_none() && self.unix_socket.is_none() {
            return Err(
                "control_plane: set listen_tcp and/or unix_socket (remove the section to keep \
                 the API off)"
                    .into(),
            );
        }
        let unix_mode = match self.socket_mode.as_str() {
            "0600" => 0o600,
            "0660" => 0o660,
            other => {
                return Err(format!(
                    "control_plane.socket_mode {:?}: must be \"0600\" or \"0660\"",
                    robodr_ros2_pipeline::sanitize(other)
                ))
            }
        };
        range("max_clock_skew_s", self.max_clock_skew_s, 1, 300)?;
        range("rate_per_minute", u64::from(self.rate_per_minute), 1, 600)?;
        range("burst", u64::from(self.burst), 1, 100)?;
        range("max_connections", self.max_connections as u64, 1, 16)?;
        range("max_requests", self.max_requests as u64, 16, 65_536)?;
        range("answer_timeout_ms", self.answer_timeout_ms, 100, 30_000)?;
        if self.soc_keys.is_empty() {
            return Err("control_plane.soc_keys: at least one SOC public key file".into());
        }
        if self.soc_keys.len() > MAX_SOC_KEYS {
            return Err(format!(
                "control_plane.soc_keys: at most {MAX_SOC_KEYS} keys"
            ));
        }
        let mut keys: Vec<SocKey> = Vec::new();
        for p in &self.soc_keys {
            let k = load_soc_key(p, robot_id)?;
            if keys.iter().any(|o| o.key_id == k.key_id) {
                return Err(format!(
                    "control_plane.soc_keys: key id {:?} is listed twice",
                    robodr_ros2_pipeline::sanitize(&k.key_id)
                ));
            }
            if own_key_ids.contains(&k.key_id.as_str()) {
                return Err(format!(
                    "control_plane.soc_keys {}: key id {:?} is this robot's own black-box or \
                     finding key; a SOC key must be the SOC's",
                    p.display(),
                    robodr_ros2_pipeline::sanitize(&k.key_id)
                ));
            }
            keys.push(k);
        }
        Ok(ControlPlaneSpec {
            tcp,
            unix: self.unix_socket.clone(),
            unix_mode,
            keys,
            skew_s: self.max_clock_skew_s,
            rate_per_minute: self.rate_per_minute,
            burst: self.burst,
            max_connections: self.max_connections,
            max_requests: self.max_requests,
            answer_timeout: Duration::from_millis(self.answer_timeout_ms),
        })
    }
}

/// Load one SOC public key file: absolute path, a regular file (not a
/// symlink) owned by root or the daemon's user, not writable by group or
/// others (whoever can write it can add a key that commands requests), at
/// most [`MAX_SOC_KEY_FILE_BYTES`], a `robodr-blackbox` **public** Ed25519
/// key file whose `device_id`, if set, is this robot.
pub fn load_soc_key(path: &std::path::Path, robot_id: &str) -> Result<SocKey, String> {
    let shown = path.display();
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(format!(
            "control_plane.soc_keys: {shown} must be an absolute path"
        ));
    }
    let lmeta = std::fs::symlink_metadata(path).map_err(|e| format!("SOC key {shown}: {e}"))?;
    if !lmeta.file_type().is_file() {
        return Err(format!(
            "SOC key {shown}: not a regular file (symlinks are refused)"
        ));
    }
    let f = File::open(path).map_err(|e| format!("SOC key {shown}: {e}"))?;
    let meta = f.metadata().map_err(|e| format!("SOC key {shown}: {e}"))?;
    if meta.ino() != lmeta.ino() || meta.dev() != lmeta.dev() {
        return Err(format!("SOC key {shown}: changed while being opened"));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "SOC key {shown}: mode {mode:03o} lets group/others write it; chmod 644"
        ));
    }
    let euid = crate::config::effective_uid();
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(format!(
            "SOC key {shown}: owned by uid {}, not by the daemon's uid {euid} or root",
            meta.uid()
        ));
    }
    if meta.len() > MAX_SOC_KEY_FILE_BYTES {
        return Err(format!(
            "SOC key {shown}: larger than {MAX_SOC_KEY_FILE_BYTES} bytes"
        ));
    }
    let mut text = String::new();
    f.take(MAX_SOC_KEY_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("SOC key {shown}: {e}"))?;
    let k =
        robodr_blackbox::KeyFile::from_json(&text).map_err(|e| format!("SOC key {shown}: {e}"))?;
    if !k.is_public() {
        return Err(format!(
            "SOC key {shown}: holds secret material; give the SOC's public key file (.pub) only"
        ));
    }
    if k.algorithm != robodr_blackbox::sign_ed25519::ED25519 {
        return Err(format!("SOC key {shown}: must be an ed25519 key"));
    }
    if let Some(d) = &k.device_id {
        if d != robot_id {
            return Err(format!(
                "SOC key {shown}: bound to device {:?}, not to this robot",
                robodr_ros2_pipeline::sanitize(d)
            ));
        }
    }
    let public = k
        .public_key()
        .ok_or_else(|| format!("SOC key {shown}: no public key"))?;
    Ok(SocKey {
        key_id: k.key_id.clone(),
        public,
    })
}

/// Counters of the listener side (shared with the threads).
#[derive(Debug, Default)]
pub struct Counters {
    pub connections: AtomicU64,
    pub connections_rejected: AtomicU64,
    /// Requests that could not be read (malformed, too large, timeout).
    pub malformed: AtomicU64,
    pub unauthenticated: AtomicU64,
    pub authenticated: AtomicU64,
    pub rate_limited: AtomicU64,
    /// Answered 503 because the main loop did not take or answer in time.
    pub busy: AtomicU64,
    pub not_found: AtomicU64,
    pub answers_signed: AtomicU64,
    last_auth_failure: Mutex<Option<String>>,
}

impl Counters {
    fn note_auth_failure(&self, why: String) {
        self.unauthenticated.fetch_add(1, Ordering::Relaxed);
        *self
            .last_auth_failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(why);
    }

    pub fn last_auth_failure(&self) -> Option<String> {
        self.last_auth_failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// `status.json` / heartbeat view.
#[derive(Debug, Clone, Serialize)]
pub struct ControlStatus {
    pub api: &'static str,
    pub listening: Vec<String>,
    pub executor: &'static str,
    pub executes_actions: bool,
    pub connections: u64,
    pub connections_rejected: u64,
    pub malformed: u64,
    pub unauthenticated: u64,
    pub authenticated: u64,
    pub rate_limited: u64,
    pub busy: u64,
    pub not_found: u64,
    pub answers_signed: u64,
    pub last_auth_failure: Option<String>,
    #[serde(flatten)]
    pub engine: api::EngineStats,
}

/// One call on its way to the main loop.
pub struct CallMsg {
    pub call: Call,
    pub meta: Meta,
    pub reply: SyncSender<Answer>,
}

/// What the listener threads share.
struct Shared {
    robot_id: String,
    keys: Vec<SocKey>,
    replay: Mutex<ReplayGuard>,
    rate: Mutex<RateLimiter>,
    counters: Arc<Counters>,
    calls: SyncSender<CallMsg>,
    answer_signer: Option<Mutex<Box<dyn robodr_blackbox::Signer>>>,
    answer_timeout: Duration,
    active: AtomicUsize,
    max_connections: usize,
    stop: Arc<AtomicBool>,
}

/// The running control plane: listener threads and the main-loop side.
pub struct ControlPlane {
    pub engine: api::Engine,
    rx: Option<Receiver<CallMsg>>,
    counters: Arc<Counters>,
    threads: Vec<JoinHandle<()>>,
    listening: Vec<String>,
    stop: Arc<AtomicBool>,
}

impl std::fmt::Debug for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlane")
            .field("listening", &self.listening)
            .field("engine", &self.engine)
            .finish()
    }
}

impl ControlPlane {
    /// Bind the listeners and start their threads. `answer_signer` (the
    /// finding key) signs answers to authenticated requests.
    pub fn start(
        spec: &ControlPlaneSpec,
        robot_id: &str,
        answer_signer: Option<Box<dyn robodr_blackbox::Signer>>,
    ) -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel::<CallMsg>(CALL_QUEUE);
        let counters = Arc::new(Counters::default());
        let shared = Arc::new(Shared {
            robot_id: robot_id.to_string(),
            keys: spec.keys.clone(),
            replay: Mutex::new(ReplayGuard::new(spec.skew_s, auth::MAX_NONCES)),
            rate: Mutex::new(RateLimiter::new(spec.rate_per_minute, spec.burst)),
            counters: counters.clone(),
            calls: tx,
            answer_signer: answer_signer.map(Mutex::new),
            answer_timeout: spec.answer_timeout,
            active: AtomicUsize::new(0),
            max_connections: spec.max_connections,
            stop: stop.clone(),
        });
        // Bind everything first: a failure then leaves no thread behind.
        let mut listening = Vec::new();
        let tcp = match spec.tcp {
            None => None,
            Some(addr) => {
                let l = TcpListener::bind(addr)
                    .and_then(|l| l.set_nonblocking(true).map(|()| l))
                    .map_err(|e| format!("control_plane.listen_tcp {addr}: {e}"))?;
                listening.push(
                    l.local_addr()
                        .map(|a| format!("tcp:{a}"))
                        .unwrap_or_else(|_| format!("tcp:{addr}")),
                );
                Some(l)
            }
        };
        let unix = match &spec.unix {
            None => None,
            Some(path) => {
                let hs = crate::host::HostThreatsSpec {
                    path: path.clone(),
                    allowed_uids: vec![0],
                    mode: spec.unix_mode,
                    max_connections: 1,
                };
                let sock = crate::host::bind_host_socket(&hs, crate::config::effective_uid())
                    .map_err(|e| format!("control_plane.unix_socket {}: {e}", path.display()))?;
                listening.push(format!("unix:{}", path.display()));
                Some(sock)
            }
        };
        let mut threads = Vec::new();
        let mut spawned = Ok(());
        if let Some(l) = tcp {
            let sh = shared.clone();
            match std::thread::Builder::new()
                .name("agentd-cp-tcp".into())
                .spawn(move || run_tcp(l, sh))
            {
                Ok(h) => threads.push(h),
                Err(e) => spawned = Err(format!("control plane thread: {e}")),
            }
        }
        if let Some(sock) = unix {
            if spawned.is_ok() {
                let sh = shared.clone();
                let path = sock.path.clone();
                match std::thread::Builder::new()
                    .name("agentd-cp-unix".into())
                    .spawn(move || run_unix(sock, sh))
                {
                    Ok(h) => threads.push(h),
                    Err(e) => {
                        let _ = std::fs::remove_file(&path);
                        spawned = Err(format!("control plane thread: {e}"));
                    }
                }
            } else {
                sock.remove_if_ours();
            }
        }
        if let Err(e) = spawned {
            stop.store(true, Ordering::SeqCst);
            for t in threads {
                let _ = t.join();
            }
            return Err(e);
        }
        Ok(Self {
            engine: api::Engine::new(
                robot_id,
                spec.max_requests,
                Box::new(api::RecordingExecutor),
            ),
            rx: Some(rx),
            counters,
            threads,
            listening,
            stop,
        })
    }

    /// Up to [`CALLS_PER_POLL`] waiting calls.
    pub fn take_calls(&mut self) -> Vec<CallMsg> {
        let mut out = Vec::new();
        let Some(rx) = &self.rx else {
            return out;
        };
        while out.len() < CALLS_PER_POLL {
            match rx.try_recv() {
                Ok(m) => out.push(m),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        out
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn status(&self) -> ControlStatus {
        let c = &self.counters;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        ControlStatus {
            api: auth::API_VERSION,
            listening: self.listening.clone(),
            executor: self.engine.executor_name(),
            executes_actions: self.engine.executes(),
            connections: g(&c.connections),
            connections_rejected: g(&c.connections_rejected),
            malformed: g(&c.malformed),
            unauthenticated: g(&c.unauthenticated),
            authenticated: g(&c.authenticated),
            rate_limited: g(&c.rate_limited),
            busy: g(&c.busy),
            not_found: g(&c.not_found),
            answers_signed: g(&c.answers_signed),
            last_auth_failure: c.last_auth_failure(),
            engine: self.engine.stats,
        }
    }

    /// Stop: refuse what is queued (the senders see the channel close and
    /// answer 503) and join the listener threads (each joins its
    /// connections, which are bounded by [`READ_DEADLINE`]).
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.rx = None;
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for ControlPlane {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn wall_s() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn run_tcp(l: TcpListener, sh: Arc<Shared>) {
    let mut conns: Vec<JoinHandle<()>> = Vec::new();
    while !sh.stop.load(Ordering::Relaxed) {
        match l.accept() {
            Ok((s, addr)) => {
                conns.retain(|h| !h.is_finished());
                if s.set_nonblocking(false).is_err()
                    || s.set_write_timeout(Some(READ_DEADLINE)).is_err()
                {
                    continue;
                }
                spawn_conn(&sh, &mut conns, format!("tcp:{addr}"), move |sh, peer| {
                    serve::<TcpStream>(s, peer, sh)
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    for h in conns {
        let _ = h.join();
    }
}

fn run_unix(sock: crate::input::EventSocket, sh: Arc<Shared>) {
    let mut conns: Vec<JoinHandle<()>> = Vec::new();
    while !sh.stop.load(Ordering::Relaxed) {
        match sock.listener.accept() {
            Ok((s, _)) => {
                conns.retain(|h| !h.is_finished());
                if s.set_nonblocking(false).is_err()
                    || s.set_write_timeout(Some(READ_DEADLINE)).is_err()
                {
                    continue;
                }
                let peer = match crate::host::peer_uid(&s) {
                    Ok(uid) => format!("unix:uid={uid}"),
                    Err(_) => "unix".to_string(),
                };
                spawn_conn(&sh, &mut conns, peer, move |sh, peer| {
                    serve::<UnixStream>(s, peer, sh)
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    for h in conns {
        let _ = h.join();
    }
    sock.remove_if_ours();
}

fn spawn_conn<F>(sh: &Arc<Shared>, conns: &mut Vec<JoinHandle<()>>, peer: String, f: F)
where
    F: FnOnce(&Shared, String) + Send + 'static,
{
    if sh.active.load(Ordering::SeqCst) >= sh.max_connections {
        sh.counters
            .connections_rejected
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    sh.active.fetch_add(1, Ordering::SeqCst);
    sh.counters.connections.fetch_add(1, Ordering::Relaxed);
    let s2 = sh.clone();
    match std::thread::Builder::new()
        .name("agentd-cp-conn".into())
        .spawn(move || {
            f(&s2, peer);
            s2.active.fetch_sub(1, Ordering::SeqCst);
        }) {
        Ok(h) => conns.push(h),
        Err(_) => {
            sh.active.fetch_sub(1, Ordering::SeqCst);
            sh.counters
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Percent-decode one path segment (`%XX` only; the result must be ASCII).
fn pct_decode(seg: &str) -> Option<String> {
    let b = seg.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    let s = String::from_utf8(out).ok()?;
    s.is_ascii().then_some(s)
}

/// The API routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Robot,
    Submit,
    Get(String),
    Revert(String),
}

/// Map method and target to a route (after authentication).
pub fn route(method: &str, target: &str, robot_id: &str) -> Result<Route, ApiError> {
    let not_found = || ApiError::new(404, "not_found", "no such resource");
    let rest = target
        .strip_prefix("/api/v1/robots/")
        .ok_or_else(not_found)?;
    let segs: Vec<&str> = rest.split('/').collect();
    let robot = segs
        .first()
        .and_then(|s| pct_decode(s))
        .ok_or_else(not_found)?;
    if robot != robot_id {
        return Err(ApiError::new(
            404,
            "unknown_robot",
            "this agentd serves another robot",
        ));
    }
    let method_err = || ApiError::new(405, "method_not_allowed", "method not allowed here");
    let decode_id = |s: &str| {
        let id = pct_decode(s).ok_or_else(not_found)?;
        if api::request_id_ok(&id) {
            Ok(id)
        } else {
            Err(ApiError::new(404, "unknown_request", "not a request id"))
        }
    };
    match (method, segs.as_slice()) {
        ("GET", [_]) => Ok(Route::Robot),
        (_, [_]) => Err(method_err()),
        ("POST", [_, "action-requests"]) => Ok(Route::Submit),
        (_, [_, "action-requests"]) => Err(method_err()),
        ("GET", [_, "action-requests", id]) => Ok(Route::Get(decode_id(id)?)),
        (_, [_, "action-requests", _]) => Err(method_err()),
        ("POST", [_, "action-requests", id, "revert"]) => Ok(Route::Revert(decode_id(id)?)),
        (_, [_, "action-requests", _, "revert"]) => Err(method_err()),
        _ => Err(not_found()),
    }
}

fn to_body(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec())
}

fn send<S: http::Stream>(s: &mut S, status: u16, body: &Value, extra: &[(&str, String)]) {
    let _ = http::write_response(s, status, &to_body(body), extra);
}

/// Serve one connection: read, authenticate, route, hand to the main loop,
/// answer. Never panics; every exit writes an answer if the peer is there.
fn serve<S: http::Stream>(mut s: S, peer: String, sh: &Shared) {
    let c = &sh.counters;
    let req = match http::read_request(&mut s, Instant::now() + READ_DEADLINE) {
        Ok(r) => r,
        Err(e) => {
            c.malformed.fetch_add(1, Ordering::Relaxed);
            send(&mut s, e.status, &api::error_body(e.code, &e.message), &[]);
            return;
        }
    };
    let fail = |s: &mut S, f: AuthFailure| {
        c.note_auth_failure(format!(
            "{} ({} {}) from {peer}",
            f.code(),
            req.method,
            robodr_ros2_pipeline::sanitize(&req.target)
        ));
        send(s, f.status(), &api::error_body(f.code(), &f.message()), &[]);
    };
    let creds = match auth::credentials(&req) {
        Ok(c) => c,
        Err(f) => return fail(&mut s, f),
    };
    if let Err(f) = auth::verify(&req, &creds, &sh.keys, &sh.robot_id) {
        return fail(&mut s, f);
    }
    let Some(now_s) = wall_s() else {
        return fail(&mut s, AuthFailure::ClockUnavailable);
    };
    let checked = sh
        .replay
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .check(&creds.key_id, &creds.nonce, creds.timestamp, now_s);
    if let Err(f) = checked {
        return fail(&mut s, f);
    }
    c.authenticated.fetch_add(1, Ordering::Relaxed);
    // From here on the peer proved the key: answers are signed.
    let sign = |status: u16, body: &[u8]| -> Vec<(&'static str, String)> {
        let Some(signer) = &sh.answer_signer else {
            return Vec::new();
        };
        let signer = signer.lock().unwrap_or_else(PoisonError::into_inner);
        match signer.sign(&auth::answer_message(&creds.signature_hex, status, body)) {
            Ok(sig) => {
                c.answers_signed.fetch_add(1, Ordering::Relaxed);
                vec![(
                    auth::H_ANSWER_SIGNATURE,
                    format!(
                        "ed25519;key_id={};sig={}",
                        signer.key_id(),
                        robodr_blackbox::crypto::to_hex(&sig)
                    ),
                )]
            }
            Err(_) => Vec::new(),
        }
    };
    let answer = |s: &mut S, status: u16, body: &Value| {
        let bytes = to_body(body);
        let extra = sign(status, &bytes);
        let _ = http::write_response(s, status, &bytes, &extra);
    };
    let limited = sh
        .rate
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .allow(&creds.key_id, Instant::now());
    if let Err(retry) = limited {
        c.rate_limited.fetch_add(1, Ordering::Relaxed);
        let body = api::error_body(
            "rate_limited",
            &format!("too many requests for this key; retry after {retry} s"),
        );
        let bytes = to_body(&body);
        let mut extra = sign(429, &bytes);
        extra.push(("Retry-After", retry.to_string()));
        let _ = http::write_response(&mut s, 429, &bytes, &extra);
        return;
    }
    let call = match route(&req.method, &req.target, &sh.robot_id) {
        Err(e) => {
            c.not_found.fetch_add(1, Ordering::Relaxed);
            return answer(&mut s, e.status, &e.body());
        }
        Ok(Route::Robot) => Call::Robot,
        Ok(Route::Get(id)) => Call::Get(id),
        Ok(Route::Submit) => match api::parse_submit(&req.body) {
            Ok(r) => Call::Submit(r),
            Err(e) => Call::Invalid(e),
        },
        Ok(Route::Revert(id)) => match api::parse_revert(&req.body) {
            Ok(r) => Call::Revert(id, r),
            Err(e) => Call::Invalid(e),
        },
    };
    let meta = Meta {
        key_id: creds.key_id.clone(),
        nonce: creds.nonce.clone(),
        timestamp: creds.timestamp,
        signature: creds.signature_hex.clone(),
        method: req.method.clone(),
        target: req.target.clone(),
        // Bounded (MAX_BODY_BYTES) and, for a parsed call, valid UTF-8.
        body: String::from_utf8_lossy(&req.body).into_owned(),
        peer: peer.clone(),
    };
    let busy = |s: &mut S, why: &str| {
        c.busy.fetch_add(1, Ordering::Relaxed);
        answer(s, 503, &api::error_body("busy", why));
    };
    if sh.stop.load(Ordering::Relaxed) {
        return busy(&mut s, "the daemon is stopping");
    }
    let (tx, rx) = sync_channel::<Answer>(1);
    match sh.calls.try_send(CallMsg {
        call,
        meta,
        reply: tx,
    }) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => return busy(&mut s, "too many requests in flight"),
        Err(TrySendError::Disconnected(_)) => return busy(&mut s, "the daemon is stopping"),
    }
    match rx.recv_timeout(sh.answer_timeout) {
        Ok(a) => answer(&mut s, a.status, &a.body),
        Err(_) => busy(
            &mut s,
            "the daemon did not answer in time; the request may still be recorded, read it back \
             with GET",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        let r = |m: &str, t: &str| route(m, t, "ugv-007");
        assert_eq!(r("GET", "/api/v1/robots/ugv-007"), Ok(Route::Robot));
        assert_eq!(
            r("POST", "/api/v1/robots/ugv-007/action-requests"),
            Ok(Route::Submit)
        );
        assert_eq!(
            r(
                "GET",
                "/api/v1/robots/ugv-007/action-requests/robot_safe_pause%3Augv-007"
            ),
            Ok(Route::Get("robot_safe_pause:ugv-007".into()))
        );
        assert_eq!(
            r("POST", "/api/v1/robots/ugv%2D007/action-requests/a/revert"),
            Ok(Route::Revert("a".into()))
        );
        assert_eq!(
            r("GET", "/api/v1/robots/ugv-008").unwrap_err().code,
            "unknown_robot"
        );
        assert_eq!(r("POST", "/api/v1/robots/ugv-007").unwrap_err().status, 405);
        assert_eq!(
            r("GET", "/api/v1/robots/ugv-007/action-requests")
                .unwrap_err()
                .status,
            405
        );
        assert_eq!(
            r("GET", "/api/v1/robots/ugv-007/other").unwrap_err().status,
            404
        );
        assert_eq!(r("GET", "/api/v2/robots/ugv-007").unwrap_err().status, 404);
        assert_eq!(
            r("GET", "/api/v1/robots/ugv-007/action-requests/a%2Fb")
                .unwrap_err()
                .code,
            "unknown_request"
        );
        assert_eq!(
            r("GET", "/api/v1/robots/ugv-007/action-requests/%zz")
                .unwrap_err()
                .status,
            404
        );
        assert_eq!(
            r("GET", "/api/v1/robots/ugv-007/action-requests/%c3%a9")
                .unwrap_err()
                .status,
            404
        );
        assert_eq!(r("GET", "/api/v1/robots/ugv-007/").unwrap_err().status, 404);
    }

    fn section(v: serde_json::Value) -> Result<ControlPlaneSection, serde_json::Error> {
        serde_json::from_value(v)
    }

    #[test]
    fn section_is_strict() {
        assert!(
            section(serde_json::json!({"soc_keys": [], "listen_tcp": "127.0.0.1:1", "x": 1}))
                .is_err()
        );
        let s = section(serde_json::json!({"soc_keys": [], "listen_tcp": "127.0.0.1:1"})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("at least one"));
        let s = section(serde_json::json!({"soc_keys": [], "listen_tcp": "0.0.0.0:8787"})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("loopback"));
        let s = section(serde_json::json!({"soc_keys": [], "listen_tcp": "127.0.0.1:0"})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("port 0"));
        let s = section(serde_json::json!({"soc_keys": []})).unwrap();
        assert!(s
            .resolve("r", &[])
            .unwrap_err()
            .contains("listen_tcp and/or"));
        let s = section(serde_json::json!({"soc_keys": [], "unix_socket": "rel.sock"})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("absolute"));
        let s = section(
            serde_json::json!({"soc_keys": [], "listen_tcp": "127.0.0.1:1", "max_clock_skew_s": 0}),
        )
        .unwrap();
        assert!(s
            .resolve("r", &[])
            .unwrap_err()
            .contains("max_clock_skew_s"));
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-cp-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn soc_key_files_are_checked() {
        let d = tmp("keys");
        let k = robodr_blackbox::KeyFile::ed25519_from_seed(&[9; 32], Some("soc-a")).unwrap();
        let pubk = k.to_public().unwrap();
        let p = d.join("soc.pub");
        pubk.write_new(&p).unwrap();
        let got = load_soc_key(&p, "ugv-007").unwrap();
        assert_eq!(got.key_id, "soc-a");
        assert_eq!(Some(got.public), k.public_key());
        // Group-writable: refused.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(load_soc_key(&p, "ugv-007").unwrap_err().contains("write"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        // A symlink: refused.
        let l = d.join("link.pub");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(load_soc_key(&l, "ugv-007").unwrap_err().contains("symlink"));
        // A secret key: refused.
        let sp = d.join("soc.key");
        k.write_new(&sp).unwrap();
        assert!(load_soc_key(&sp, "ugv-007").unwrap_err().contains("secret"));
        // Bound to another unit: refused; to this one: fine.
        let bound = robodr_blackbox::KeyFile::ed25519_from_seed(&[9; 32], Some("soc-b"))
            .unwrap()
            .to_public()
            .unwrap()
            .with_device_id(Some("ugv-008"))
            .unwrap();
        let bp = d.join("bound.pub");
        bound.write_new(&bp).unwrap();
        assert!(load_soc_key(&bp, "ugv-007").unwrap_err().contains("bound"));
        assert!(load_soc_key(&bp, "ugv-008").is_ok());
        // Through the section: duplicates and own key ids refused.
        let s = section(serde_json::json!({
            "listen_tcp": "127.0.0.1:1", "soc_keys": [p, p]
        }))
        .unwrap();
        assert!(s.resolve("ugv-007", &[]).unwrap_err().contains("twice"));
        let s = section(serde_json::json!({"listen_tcp": "127.0.0.1:1", "soc_keys": [p]})).unwrap();
        assert!(s
            .resolve("ugv-007", &["soc-a"])
            .unwrap_err()
            .contains("own"));
        assert_eq!(s.resolve("ugv-007", &[]).unwrap().keys.len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
