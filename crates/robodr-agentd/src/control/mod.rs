//! The control-plane API `robodr-control-plane/v2` (`control_plane`, off by
//! default).
//!
//! A SOC asks for one of the seven catalog actions
//! ([`robodr_responder::actions`]) on this
//! robot; agentd validates the request, judges it with the response policy
//! against the robot's *current* safety state (Cyber-Jidoka,
//! [`api::judge`]), records the request and the decision in the signed
//! black box and in its persistent request journal ([`state`]) and answers.
//! With `evidence` configured, the SOC also lists and exports black-box
//! evidence ([`evidence`]). Contract: `docs/contracts/robodr.control-plane.md`.
//!
//! **Nothing is executed by default.** The executor is
//! [`api::RecordingExecutor`]: an accepted request is answered
//! `recorded_not_executed` (`"executed": false`), "accepted and recorded as
//! a plan", never `applied`. Only with agentd's `executor.enabled` (executor
//! v1, [`crate::executor_link`]) is the engine's executor replaced
//! ([`api::Engine::set_executor`]): requests then read `pending`,
//! `verified`, `refused`, `failed`, `reverted`, each state journalled
//! ([`state`]) before it is answered (signed like every answer). RoboDR never overrides the platform's safety authority: the
//! strongest action is a *request* for a safe state, and while the safety
//! system is engaged every request is refused.
//!
//! ```text
//!  SOC ── mTLS (rustls) TCP / loopback TCP / unix socket ──► listener thread
//!          one request per connection           │ TLS: client cert chain + pin (tls)
//!                                               │ bounded parse (http), Ed25519 signature,
//!                                               │ timestamp window + persisted nonce store,
//!                                               │ rate limit (auth); strict body
//!                                               │ evidence: index / export / chunks (evidence)
//!                                               ▼ bounded channel (try_send; full = 503)
//!                                         main loop (Daemon::control_poll)
//!                                               │ api::Engine: judge against the live safety
//!                                               │ state, policy, context; journal begin;
//!                                               │ black-box note; journal commit; store
//!                                               ▼
//!                                         answer, always signed with the finding key
//! ```
//!
//! # Threat model (summary; full text in the contract and `SECURITY.md`)
//!
//! * **Who may ask.** On a TCP listener that is not loopback, only a peer
//!   with a client certificate from the configured SOC CA (and pin, if
//!   set) gets a channel (mutual TLS, [`tls`]); then, on every listener,
//!   only holders of a configured SOC Ed25519 key (`soc_keys`) get an
//!   answer other than 401. Both are required: a stolen client certificate
//!   cannot sign, a stolen SOC key cannot connect from the network. The
//!   signature covers the method, the exact target, this robot's id, the
//!   key id, a timestamp, a nonce and the body hash
//!   ([`auth::signing_message`]), so a request cannot be altered, moved to
//!   another robot or replayed (timestamp window plus a nonce store that is
//!   persisted across restarts and fails closed when full).
//! * **What may be asked.** The seven catalog actions, their own
//!   parameters, TTL rules (`safe_pause` / `request_safe_state` are refused
//!   on a humanoid: it would fall); no motion command, no override. A
//!   valid signature does not widen this: an authenticated but invalid
//!   body is refused (400) and recorded. Evidence: read-only exports of
//!   black-box frames, never key material.
//! * **What happens.** Nothing reaches the robot: the request is judged and
//!   recorded. A refusal is final (never retried here).
//! * **Answers.** Every answer to an authenticated request carries
//!   [`auth::H_ANSWER_SIGNATURE`] (the finding key, domain-separated, bound
//!   to the request signature); `finding_signing` is required.
//! * **Abuse.** Bounded parsing, a read deadline, a connection cap, per-key
//!   rate limits (one for chunk downloads) and a bounded queue to the main
//!   loop: a flood costs the control plane's availability (503 / 429),
//!   never the detection loop's. Failed authentications (TLS handshakes
//!   included) are counted and reported as the observe-only finding
//!   `robot.agent.control_plane_unauthenticated` (High, rate-limited),
//!   authenticated invalid requests as `robot.agent.control_plane_invalid`
//!   (Medium).

pub mod api;
pub mod auth;
pub mod evidence;
pub mod fsutil;
pub mod http;
pub mod journal;
pub mod state;
pub mod tls;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use api::{Answer, ApiError, Call, Meta};
use auth::{AuthFailure, RateLimiter, ReplayGuard, SocKey};

/// Most SOC keys.
pub const MAX_SOC_KEYS: usize = 16;
/// Longest a connection may take to complete its TLS handshake, and then
/// (again) to send its request.
pub const READ_DEADLINE: Duration = Duration::from_secs(5);
/// Concurrent connections on the unix socket (root-only; its own slots,
/// never shared with the TCP listener).
pub const UNIX_CONNECTIONS: usize = 2;
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
fn default_connections_per_source() -> usize {
    2
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
///   "listen_tcp": "0.0.0.0:8787",
///   "tls": { "cert_chain": "...", "key_file": "...", "client_ca": "..." },
///   "unix_socket": "/run/robodr-agentd/control.sock",
///   "state_dir": "/var/lib/robodr/control-plane/agentd",
///   "soc_keys": ["/etc/robodr/soc/soc.pub"],
///   "evidence": {}
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneSection {
    /// TCP address (`ip:port`, port not 0). Without `tls` it must be
    /// loopback (plain HTTP); with `tls` every connection is mutual TLS.
    #[serde(default)]
    pub listen_tcp: Option<String>,
    /// Removed in v2 (plain HTTP off loopback): refused with a pointer to
    /// `tls`.
    #[serde(default)]
    pub allow_remote: Option<bool>,
    /// Mutual TLS for `listen_tcp` ([`tls::TlsSection`]).
    #[serde(default)]
    pub tls: Option<tls::TlsSection>,
    /// Absolute path of a unix stream socket (private directory).
    #[serde(default)]
    pub unix_socket: Option<PathBuf>,
    /// `"0600"` (default) or `"0660"` for `unix_socket`.
    #[serde(default = "default_mode")]
    pub socket_mode: String,
    /// Private directory of the persistent state: request journal, replay
    /// store, evidence exports (absolute; mode 0700, owned by the daemon).
    pub state_dir: PathBuf,
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
    /// Concurrent TCP connections, 1..=16, counted twice over: up to this
    /// many still in the TLS handshake / unauthenticated request read, and
    /// up to this many authenticated. The unix socket has its own slots
    /// ([`UNIX_CONNECTIONS`]), so TCP peers cannot lock it out.
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    /// Concurrent TCP connections from one source address, 1..=16 (at
    /// most `max_connections` take effect).
    #[serde(default = "default_connections_per_source")]
    pub max_connections_per_source: usize,
    /// Requests kept for GET / revert / idempotency, 16..=65536.
    #[serde(default = "default_requests")]
    pub max_requests: usize,
    /// How long a connection waits for the main loop, 100..=30000 ms.
    #[serde(default = "default_answer_ms")]
    pub answer_timeout_ms: u64,
    /// The evidence API ([`evidence::EvidenceSection`]); absent = off.
    #[serde(default)]
    pub evidence: Option<evidence::EvidenceSection>,
}

/// A validated [`ControlPlaneSection`] with its keys and TLS loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneSpec {
    pub tcp: Option<SocketAddr>,
    pub tls: Option<tls::TlsSpec>,
    pub unix: Option<PathBuf>,
    pub unix_mode: u32,
    pub state_dir: PathBuf,
    pub keys: Vec<SocKey>,
    pub skew_s: u64,
    pub rate_per_minute: u32,
    pub burst: u32,
    pub max_connections: usize,
    pub max_connections_per_source: usize,
    pub max_requests: usize,
    pub answer_timeout: Duration,
    pub evidence: Option<evidence::EvidenceSection>,
}

fn range(what: &str, v: u64, lo: u64, hi: u64) -> Result<(), String> {
    if (lo..=hi).contains(&v) {
        Ok(())
    } else {
        Err(format!("control_plane.{what} = {v}: must be {lo}..={hi}"))
    }
}

impl ControlPlaneSection {
    /// Validate and load the SOC keys and the TLS material. `robot_id`
    /// binds keys that name a device; `own_key_ids` are the black-box and
    /// finding key ids (a SOC key must be neither). The state directory is
    /// checked when the control plane starts.
    pub fn resolve(
        &self,
        robot_id: &str,
        own_key_ids: &[&str],
    ) -> Result<ControlPlaneSpec, String> {
        if self.allow_remote.is_some() {
            return Err(
                "control_plane.allow_remote was removed in robodr-control-plane/v2: plain HTTP is \
                 served on loopback and the unix socket only; a non-loopback listen_tcp needs \
                 control_plane.tls (mutual TLS)"
                    .into(),
            );
        }
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
                if !a.ip().is_loopback() && self.tls.is_none() {
                    return Err(format!(
                        "control_plane.listen_tcp {a} is not a loopback address: off loopback \
                         the API is served only over mutual TLS; configure control_plane.tls \
                         (cert_chain, key_file, client_ca)"
                    ));
                }
                Some(a)
            }
        };
        if self.tls.is_some() && tcp.is_none() {
            return Err("control_plane.tls applies to listen_tcp, which is not set".into());
        }
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
        if self.state_dir.as_os_str().is_empty() || !self.state_dir.is_absolute() {
            return Err("control_plane.state_dir must be an absolute path".into());
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
        range(
            "max_connections_per_source",
            self.max_connections_per_source as u64,
            1,
            16,
        )?;
        range("max_requests", self.max_requests as u64, 16, 65_536)?;
        range("answer_timeout_ms", self.answer_timeout_ms, 100, 30_000)?;
        if let Some(e) = &self.evidence {
            e.validate()?;
        }
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
        let tls = match &self.tls {
            None => None,
            Some(t) => Some(t.resolve(crate::config::effective_uid())?),
        };
        Ok(ControlPlaneSpec {
            tcp,
            tls,
            unix: self.unix_socket.clone(),
            unix_mode,
            state_dir: self.state_dir.clone(),
            keys,
            skew_s: self.max_clock_skew_s,
            rate_per_minute: self.rate_per_minute,
            burst: self.burst,
            max_connections: self.max_connections,
            max_connections_per_source: self.max_connections_per_source.min(self.max_connections),
            max_requests: self.max_requests,
            answer_timeout: Duration::from_millis(self.answer_timeout_ms),
            evidence: self.evidence.clone(),
        })
    }

    /// Every file and directory path the section names (for the daemon's
    /// "not inside the black box or spool" checks).
    pub fn paths(&self) -> Vec<&Path> {
        let mut v: Vec<&Path> = vec![self.state_dir.as_path()];
        v.extend(self.unix_socket.as_deref());
        v.extend(self.soc_keys.iter().map(PathBuf::as_path));
        if let Some(t) = &self.tls {
            v.extend([
                t.cert_chain.as_path(),
                t.key_file.as_path(),
                t.client_ca.as_path(),
            ]);
            v.extend(t.client_crl.as_deref());
            v.extend(t.crl_files.iter().map(PathBuf::as_path));
        }
        v
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
    /// Failed authentications, TLS handshakes included.
    pub unauthenticated: AtomicU64,
    /// TLS handshakes that failed (also in `unauthenticated`).
    pub tls_failures: AtomicU64,
    pub authenticated: AtomicU64,
    pub rate_limited: AtomicU64,
    /// Answered 503 because the main loop did not take or answer in time.
    pub busy: AtomicU64,
    pub not_found: AtomicU64,
    pub answers_signed: AtomicU64,
    /// Answers that could not be signed (sent as 500, unsigned).
    pub answer_sign_failures: AtomicU64,
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

/// What the persistent state looked like at start (status, start note).
#[derive(Debug, Clone, Default, Serialize)]
pub struct StateStatus {
    pub state_dir: String,
    /// Requests restored from the journal.
    pub restored: usize,
    pub journal_created: bool,
    pub journal_torn_bytes: u64,
    pub journal_damaged: usize,
    pub journal_quarantined: Option<String>,
    /// Dangling decisions settled from the black box.
    pub resolved_committed: usize,
    pub resolved_aborted: usize,
    /// After journal damage: requests and revert records restored from
    /// their black-box notes (review finding 4).
    pub rebuilt_from_blackbox: usize,
    pub rebuilt_reverts: usize,
    /// Request ids whose note did not convert back (resubmissions refused).
    pub lost_request_ids: usize,
    /// Set when the journal was damaged and the black box could not be read
    /// to reconcile it: every new request id is refused until a restart
    /// reconciles (fail closed).
    pub refusing_new_request_ids: Option<String>,
    pub replay: auth::ReplayLoad,
    /// Evidence exports kept / discarded at start.
    pub exports_restored: usize,
    pub exports_discarded: u64,
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
    pub tls_failures: u64,
    pub authenticated: u64,
    pub rate_limited: u64,
    pub busy: u64,
    pub not_found: u64,
    pub answers_signed: u64,
    pub answer_sign_failures: u64,
    pub last_auth_failure: Option<String>,
    /// The robot's TLS identity and the client trust (with `tls`).
    pub tls: Option<Value>,
    pub replay_entries: usize,
    pub replay_store_errors: u64,
    pub replay_fence: Option<u64>,
    pub state: StateStatus,
    /// Evidence API counters (with `evidence`).
    pub evidence: Option<Value>,
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
    replay: Arc<Mutex<ReplayGuard>>,
    rate: Mutex<RateLimiter>,
    chunk_rate: Mutex<RateLimiter>,
    counters: Arc<Counters>,
    calls: SyncSender<CallMsg>,
    answer_signer: Mutex<Box<dyn robodr_blackbox::Signer>>,
    answer_timeout: Duration,
    tcp_slots: TcpSlots,
    unix_active: AtomicUsize,
    stop: Arc<AtomicBool>,
    evidence: Option<Arc<evidence::Service>>,
}

/// The running control plane: listener threads and the main-loop side.
pub struct ControlPlane {
    pub engine: api::Engine,
    rx: Option<Receiver<CallMsg>>,
    counters: Arc<Counters>,
    replay: Arc<Mutex<ReplayGuard>>,
    threads: Vec<JoinHandle<()>>,
    listening: Vec<String>,
    tls: Option<Value>,
    /// Live revocation counters of the client verifier (with CRLs).
    crl: Option<Arc<robodr_blackbox::crl::CrlStats>>,
    state: StateStatus,
    evidence: Option<Arc<evidence::Service>>,
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

/// Settles dangling journal decisions: given decision ids, the black-box
/// references of the notes that carry them.
pub type Reconcile<'a> = &'a dyn Fn(&[String]) -> std::io::Result<BTreeMap<String, String>>;

impl ControlPlane {
    /// Open the persistent state, bind the listeners and start their
    /// threads. `answer_signer` (the finding key) signs every answer to an
    /// authenticated request and every evidence manifest. `blackbox_dir`
    /// is read (only) by the evidence API; `reconcile` settles decisions a
    /// crash left half-journaled.
    pub fn start(
        spec: &ControlPlaneSpec,
        robot_id: &str,
        answer_signer: Box<dyn robodr_blackbox::Signer>,
        blackbox_dir: &Path,
        reconcile: Reconcile<'_>,
    ) -> Result<Self, String> {
        let now_s = wall_s().ok_or("control plane: the wall clock is unavailable")?;
        let euid = crate::config::effective_uid();
        let dir = &spec.state_dir;
        fsutil::check_private_dir(dir, euid)
            .map_err(|e| format!("control_plane.state_dir: {e}"))?;
        // The request journal (and the decisions a crash left dangling).
        let (mut journal, mut restored) = state::open(dir, spec.max_requests).map_err(|e| {
            format!(
                "control_plane.state_dir: {}: {e}",
                dir.join(state::REQUEST_JOURNAL).display()
            )
        })?;
        let mut st = StateStatus {
            state_dir: dir.display().to_string(),
            journal_created: restored.created,
            journal_torn_bytes: restored.torn_bytes,
            journal_damaged: restored.damaged,
            journal_quarantined: restored.quarantined.clone(),
            ..StateStatus::default()
        };
        if !restored.pending.is_empty() || !restored.pending_reverts.is_empty() {
            let ids: Vec<String> = restored
                .pending
                .keys()
                .chain(restored.pending_reverts.keys())
                .cloned()
                .collect();
            let found = reconcile(&ids).map_err(|e| {
                format!("control plane: reading the black box to settle the request journal: {e}")
            })?;
            let (c, a) = state::resolve(&mut journal, &mut restored, &found, spec.max_requests)
                .map_err(|e| format!("control plane: request journal: {e}"))?;
            st.resolved_committed = c;
            st.resolved_aborted = a;
        }
        // Damage (not a torn tail) may have taken committed requests with
        // it: the black box is the record, rebuild from it (review finding
        // 4). If it cannot be read, refuse every new request id rather than
        // judge (and maybe execute) a known one again.
        let mut lost: Vec<String> = Vec::new();
        if restored.damaged > 0 {
            match evidence::find_request_notes(
                &evidence::DirSource(blackbox_dir.to_path_buf()),
                robot_id,
            ) {
                Ok(notes) => {
                    let rb = state::rebuild(&mut restored, &notes, spec.max_requests);
                    st.rebuilt_from_blackbox = rb.requests;
                    st.rebuilt_reverts = rb.reverts;
                    st.lost_request_ids = rb.unreadable.len();
                    lost = rb.unreadable;
                }
                Err(e) => {
                    st.refusing_new_request_ids = Some(format!(
                        "the request journal was damaged and the black box could not be read \
                         to reconcile it ({e})"
                    ));
                }
            }
        }
        st.journal_damaged = restored.damaged;
        st.restored = restored.stored.len();
        let mut engine = api::Engine::with_journal(
            robot_id,
            spec.max_requests,
            Box::new(api::RecordingExecutor),
            journal,
            restored.stored,
        );
        engine.stats.resolved_committed = st.resolved_committed as u64;
        engine.stats.resolved_aborted = st.resolved_aborted as u64;
        engine.stats.journal_damaged = st.journal_damaged as u64;
        engine.refuse_ids(lost, st.refusing_new_request_ids.clone());
        // The replay store: fenced if it cannot be trusted.
        let (replay, rload) = ReplayGuard::persistent(dir, spec.skew_s, auth::MAX_NONCES, now_s)
            .map_err(|e| {
                format!(
                    "control_plane.state_dir: {}: {e}",
                    dir.join(auth::NONCE_JOURNAL).display()
                )
            })?;
        st.replay = rload;
        // Evidence exports.
        let evidence = match &spec.evidence {
            None => None,
            Some(e) => {
                let store = evidence::Store::open(dir, now_s.saturating_mul(1000))
                    .map_err(|err| format!("control_plane.state_dir: exports: {err}"))?;
                st.exports_restored = store.exports.len();
                st.exports_discarded = store.discarded_at_open;
                Some(Arc::new(evidence::Service {
                    spec: e.clone(),
                    blackbox: blackbox_dir.to_path_buf(),
                    store: Mutex::new(store),
                    building: Mutex::new(()),
                }))
            }
        };
        let replay = Arc::new(Mutex::new(replay));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel::<CallMsg>(CALL_QUEUE);
        let counters = Arc::new(Counters::default());
        let (chunk_rate, chunk_burst) = spec
            .evidence
            .as_ref()
            .map(|e| (e.chunk_rate_per_minute, e.chunk_burst))
            .unwrap_or((1, 1));
        let shared = Arc::new(Shared {
            robot_id: robot_id.to_string(),
            keys: spec.keys.clone(),
            replay: replay.clone(),
            rate: Mutex::new(RateLimiter::new(spec.rate_per_minute, spec.burst)),
            chunk_rate: Mutex::new(RateLimiter::new(chunk_rate, chunk_burst)),
            counters: counters.clone(),
            calls: tx,
            answer_signer: Mutex::new(answer_signer),
            answer_timeout: spec.answer_timeout,
            tcp_slots: TcpSlots::new(spec.max_connections, spec.max_connections_per_source),
            unix_active: AtomicUsize::new(0),
            stop: stop.clone(),
            evidence: evidence.clone(),
        });
        // Bind everything first: a failure then leaves no thread behind.
        let mut listening = Vec::new();
        let tcp = match spec.tcp {
            None => None,
            Some(addr) => {
                let l = TcpListener::bind(addr)
                    .and_then(|l| l.set_nonblocking(true).map(|()| l))
                    .map_err(|e| format!("control_plane.listen_tcp {addr}: {e}"))?;
                let shown = l
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| addr.to_string());
                listening.push(match spec.tls {
                    Some(_) => format!("mtls:{shown}"),
                    None => format!("tcp:{shown}"),
                });
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
                let sock = crate::host::bind_host_socket(&hs, euid)
                    .map_err(|e| format!("control_plane.unix_socket {}: {e}", path.display()))?;
                listening.push(format!("unix:{}", path.display()));
                Some(sock)
            }
        };
        let tls_cfg = spec.tls.as_ref().map(|t| t.config.clone());
        let mut threads = Vec::new();
        let mut spawned = Ok(());
        if let Some(l) = tcp {
            let sh = shared.clone();
            match std::thread::Builder::new()
                .name("agentd-cp-tcp".into())
                .spawn(move || run_tcp(l, tls_cfg, sh))
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
            engine,
            rx: Some(rx),
            counters,
            replay,
            threads,
            listening,
            tls: spec.tls.as_ref().map(|t| {
                json!({
                    "server_spki_sha256": t.server_spki_sha256,
                    "client_cas": t.client_cas,
                    "client_pins": t.client_pins,
                    "client_crls": t.client_crls,
                })
            }),
            crl: spec.tls.as_ref().and_then(|t| t.crl.clone()),
            state: st,
            evidence,
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

    /// What the persistent state looked like at start.
    pub fn state_status(&self) -> &StateStatus {
        &self.state
    }

    pub fn status(&self) -> ControlStatus {
        let c = &self.counters;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let (replay_entries, replay_store_errors, replay_fence) = {
            let r = self.replay.lock().unwrap_or_else(PoisonError::into_inner);
            (r.len(), r.store_errors, r.fence())
        };
        let evidence = self.evidence.as_ref().map(|e| {
            let st = e.store.lock().unwrap_or_else(PoisonError::into_inner);
            json!({
                "exports": st.exports.len(),
                "bytes": st.bytes(),
                "created": st.created,
                "deleted": st.deleted,
                "expired": st.expired,
                "chunks_served": st.chunks_served,
                "corrupt": st.corrupt,
            })
        });
        ControlStatus {
            api: auth::API_VERSION,
            listening: self.listening.clone(),
            executor: self.engine.executor_name(),
            executes_actions: self.engine.executes(),
            connections: g(&c.connections),
            connections_rejected: g(&c.connections_rejected),
            malformed: g(&c.malformed),
            unauthenticated: g(&c.unauthenticated),
            tls_failures: g(&c.tls_failures),
            authenticated: g(&c.authenticated),
            rate_limited: g(&c.rate_limited),
            busy: g(&c.busy),
            not_found: g(&c.not_found),
            answers_signed: g(&c.answers_signed),
            answer_sign_failures: g(&c.answer_sign_failures),
            last_auth_failure: c.last_auth_failure(),
            tls: self.tls.clone().map(|mut t| {
                if let (Some(c), Some(o)) = (&self.crl, t.as_object_mut()) {
                    o.insert("crl".into(), json!(c.status()));
                }
                t
            }),
            replay_entries,
            replay_store_errors,
            replay_fence,
            state: self.state.clone(),
            evidence,
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

fn wall_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

fn run_tcp(l: TcpListener, tls: Option<Arc<rustls::ServerConfig>>, sh: Arc<Shared>) {
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
                let Some(slot) = sh.tcp_slots.enter(addr.ip()) else {
                    sh.counters
                        .connections_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let slot = Slot::Tcp(slot);
                match &tls {
                    None => spawn_conn(
                        &sh,
                        &mut conns,
                        slot,
                        format!("tcp:{addr}"),
                        move |sh, slot, peer| {
                            serve::<http::DeadlineTcp>(http::DeadlineTcp::new(s), peer, sh, slot)
                        },
                    ),
                    Some(cfg) => {
                        let cfg = cfg.clone();
                        spawn_conn(
                            &sh,
                            &mut conns,
                            slot,
                            format!("mtls:{addr}"),
                            move |sh, slot, peer| match tls::accept(
                                &cfg,
                                s,
                                Instant::now() + READ_DEADLINE,
                            ) {
                                Ok((stream, spki)) => serve::<tls::TlsStream>(
                                    stream,
                                    format!("{peer};client_spki_sha256={spki}"),
                                    sh,
                                    slot,
                                ),
                                Err(why) => {
                                    sh.counters.tls_failures.fetch_add(1, Ordering::Relaxed);
                                    sh.counters.note_auth_failure(format!(
                                        "tls_handshake_failed ({}) from {peer}",
                                        robodr_ros2_pipeline::sanitize(&why)
                                    ));
                                }
                            },
                        )
                    }
                }
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
                if sh.unix_active.fetch_add(1, Ordering::SeqCst) >= UNIX_CONNECTIONS {
                    sh.unix_active.fetch_sub(1, Ordering::SeqCst);
                    sh.counters
                        .connections_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let slot = Slot::Unix(sh.clone());
                spawn_conn(&sh, &mut conns, slot, peer, move |sh, slot, peer| {
                    serve::<UnixStream>(s, peer, sh, slot)
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

/// The TCP listener's connection slots (review finding 2): `pre_auth`
/// counts connections still in the TLS handshake or before their request
/// authenticated, `authed` the authenticated ones (each up to `max`), and
/// `per_source` bounds what one source address holds in all. The unix
/// socket never uses these.
#[derive(Debug)]
pub struct TcpSlots {
    max: usize,
    max_per_source: usize,
    inner: Arc<Mutex<SlotCounts>>,
}

#[derive(Debug, Default)]
struct SlotCounts {
    pre_auth: usize,
    authed: usize,
    per_source: BTreeMap<std::net::IpAddr, usize>,
}

/// A TCP connection's hold on [`TcpSlots`]; released on drop.
#[derive(Debug)]
pub struct TcpSlot {
    inner: Arc<Mutex<SlotCounts>>,
    max: usize,
    ip: std::net::IpAddr,
    authed: bool,
}

fn lock_counts(m: &Mutex<SlotCounts>) -> std::sync::MutexGuard<'_, SlotCounts> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TcpSlots {
    pub fn new(max: usize, max_per_source: usize) -> Self {
        Self {
            max,
            max_per_source: max_per_source.min(max),
            inner: Arc::new(Mutex::new(SlotCounts::default())),
        }
    }

    /// A pre-authentication slot for a connection from `ip`, or `None`
    /// (closed at once).
    pub fn enter(&self, ip: std::net::IpAddr) -> Option<TcpSlot> {
        let mut g = lock_counts(&self.inner);
        let from_ip = g.per_source.get(&ip).copied().unwrap_or(0);
        if g.pre_auth >= self.max || from_ip >= self.max_per_source {
            return None;
        }
        g.pre_auth += 1;
        g.per_source.insert(ip, from_ip + 1);
        Some(TcpSlot {
            inner: self.inner.clone(),
            max: self.max,
            ip,
            authed: false,
        })
    }

    /// (pre-authentication, authenticated) connections now.
    pub fn counts(&self) -> (usize, usize) {
        let g = lock_counts(&self.inner);
        (g.pre_auth, g.authed)
    }
}

impl TcpSlot {
    /// Move to an authenticated slot; `false` when they are all taken.
    pub fn authenticate(&mut self) -> bool {
        if self.authed {
            return true;
        }
        let mut g = lock_counts(&self.inner);
        if g.authed >= self.max {
            return false;
        }
        g.authed += 1;
        g.pre_auth = g.pre_auth.saturating_sub(1);
        self.authed = true;
        true
    }
}

impl Drop for TcpSlot {
    fn drop(&mut self) {
        let mut g = lock_counts(&self.inner);
        if self.authed {
            g.authed = g.authed.saturating_sub(1);
        } else {
            g.pre_auth = g.pre_auth.saturating_sub(1);
        }
        if let Some(n) = g.per_source.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.per_source.remove(&self.ip);
            }
        }
    }
}

/// What a connection thread holds: a unix slot or a TCP slot.
enum Slot {
    Unix(Arc<Shared>),
    Tcp(TcpSlot),
}

impl Slot {
    fn authenticate(&mut self) -> bool {
        match self {
            Slot::Unix(_) => true,
            Slot::Tcp(t) => t.authenticate(),
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Slot::Unix(sh) = self {
            sh.unix_active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn spawn_conn<F>(
    sh: &Arc<Shared>,
    conns: &mut Vec<JoinHandle<()>>,
    mut slot: Slot,
    peer: String,
    f: F,
) where
    F: FnOnce(&Shared, &mut Slot, String) + Send + 'static,
{
    sh.counters.connections.fetch_add(1, Ordering::Relaxed);
    let s2 = sh.clone();
    match std::thread::Builder::new()
        .name("agentd-cp-conn".into())
        .spawn(move || {
            f(&s2, &mut slot, peer);
            drop(slot);
        }) {
        Ok(h) => conns.push(h),
        Err(_) => {
            sh.counters
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Percent-decode one path segment (`%XX`, two hex digits, only; the
/// result must be ASCII).
pub fn pct_decode(seg: &str) -> Option<String> {
    let b = seg.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            // Two hex digits: from_str_radix alone would take a sign ("+1").
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let h = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    let s = String::from_utf8(out).ok()?;
    s.is_ascii().then_some(s)
}

/// The API's path prefix.
pub const PREFIX: &str = "/api/v2/robots/";

/// The API routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Robot,
    Submit,
    Get(String),
    Revert(String),
    /// `GET .../evidence`
    EvidenceInventory,
    /// `POST .../evidence/exports`
    EvidenceCreate,
    /// `GET .../evidence/exports/{export_id}`
    EvidenceManifest(String),
    /// `DELETE .../evidence/exports/{export_id}`
    EvidenceDelete(String),
    /// `GET .../evidence/exports/{export_id}/chunks/{index}`
    EvidenceChunk(String, u64),
}

impl Route {
    pub fn is_evidence(&self) -> bool {
        matches!(
            self,
            Route::EvidenceInventory
                | Route::EvidenceCreate
                | Route::EvidenceManifest(_)
                | Route::EvidenceDelete(_)
                | Route::EvidenceChunk(..)
        )
    }
}

/// A chunk index: decimal, no sign, no leading zero (but `0`), at most
/// 10 digits.
fn chunk_index(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

/// Map method and target to a route (after authentication).
pub fn route(method: &str, target: &str, robot_id: &str) -> Result<Route, ApiError> {
    let not_found = || ApiError::new(404, "not_found", "no such resource");
    let rest = target.strip_prefix(PREFIX).ok_or_else(not_found)?;
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
    let decode_id = |s: &str, code: &'static str| {
        let id = pct_decode(s).ok_or_else(not_found)?;
        if api::request_id_ok(&id) {
            Ok(id)
        } else {
            Err(ApiError::new(404, code, "not a valid id"))
        }
    };
    match (method, segs.as_slice()) {
        ("GET", [_]) => Ok(Route::Robot),
        (_, [_]) => Err(method_err()),
        ("POST", [_, "action-requests"]) => Ok(Route::Submit),
        (_, [_, "action-requests"]) => Err(method_err()),
        ("GET", [_, "action-requests", id]) => Ok(Route::Get(decode_id(id, "unknown_request")?)),
        (_, [_, "action-requests", _]) => Err(method_err()),
        ("POST", [_, "action-requests", id, "revert"]) => {
            Ok(Route::Revert(decode_id(id, "unknown_request")?))
        }
        (_, [_, "action-requests", _, "revert"]) => Err(method_err()),
        ("GET", [_, "evidence"]) => Ok(Route::EvidenceInventory),
        (_, [_, "evidence"]) => Err(method_err()),
        ("POST", [_, "evidence", "exports"]) => Ok(Route::EvidenceCreate),
        (_, [_, "evidence", "exports"]) => Err(method_err()),
        ("GET", [_, "evidence", "exports", id]) => {
            Ok(Route::EvidenceManifest(decode_id(id, "unknown_export")?))
        }
        ("DELETE", [_, "evidence", "exports", id]) => {
            Ok(Route::EvidenceDelete(decode_id(id, "unknown_export")?))
        }
        (_, [_, "evidence", "exports", _]) => Err(method_err()),
        ("GET", [_, "evidence", "exports", id, "chunks", n]) => {
            let id = decode_id(id, "unknown_export")?;
            let n = chunk_index(n)
                .ok_or_else(|| ApiError::new(404, "unknown_chunk", "not a chunk index"))?;
            Ok(Route::EvidenceChunk(id, n))
        }
        (_, [_, "evidence", "exports", _, "chunks", _]) => Err(method_err()),
        _ => Err(not_found()),
    }
}

fn to_body(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec())
}

fn send<S: http::Stream>(s: &mut S, status: u16, body: &Value, extra: &[(&str, String)]) {
    s.set_write_deadline(Instant::now() + http::ANSWER_WRITE_DEADLINE);
    let _ = http::write_response(s, status, &to_body(body), extra);
    s.finish();
}

/// One answer to an authenticated request, before it is signed.
struct Reply {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    extra: Vec<(&'static str, String)>,
}

impl Reply {
    fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            content_type: http::JSON,
            body: to_body(v),
            extra: Vec::new(),
        }
    }

    fn error(e: &ApiError) -> Self {
        Self::json(e.status, &e.body())
    }
}

/// Hand a call to the main loop and wait for its answer.
fn dispatch(sh: &Shared, call: Call, meta: Meta) -> Result<Answer, &'static str> {
    if sh.stop.load(Ordering::Relaxed) {
        return Err("the daemon is stopping");
    }
    let (tx, rx) = sync_channel::<Answer>(1);
    match sh.calls.try_send(CallMsg {
        call,
        meta,
        reply: tx,
    }) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => return Err("too many requests in flight"),
        Err(TrySendError::Disconnected(_)) => return Err("the daemon is stopping"),
    }
    rx.recv_timeout(sh.answer_timeout).map_err(|_| {
        "the daemon did not answer in time; the request may still be recorded, read it back with \
         GET"
    })
}

/// Serve one connection: read, authenticate, route, hand to the main loop
/// (or the evidence API), answer. Never panics; every exit writes an
/// answer if the peer is there.
fn serve<S: http::Stream>(mut s: S, peer: String, sh: &Shared, slot: &mut Slot) {
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
    let has_slot = slot.authenticate();
    // From here on the peer proved the key: every answer is signed.
    let answer = |s: &mut S, mut r: Reply| {
        s.set_write_deadline(Instant::now() + http::ANSWER_WRITE_DEADLINE);
        let signed = {
            let signer = sh
                .answer_signer
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            signer
                .sign(&auth::answer_message(
                    &creds.signature_hex,
                    r.status,
                    &r.body,
                ))
                .map(|sig| {
                    format!(
                        "ed25519;key_id={};sig={}",
                        signer.key_id(),
                        robodr_blackbox::crypto::to_hex(&sig)
                    )
                })
        };
        match signed {
            Ok(h) => {
                c.answers_signed.fetch_add(1, Ordering::Relaxed);
                r.extra.push((auth::H_ANSWER_SIGNATURE, h));
                let _ = http::write_typed(s, r.status, r.content_type, &r.body, &r.extra);
            }
            Err(_) => {
                // Never an unsigned success: the SOC treats it as a failure.
                c.answer_sign_failures.fetch_add(1, Ordering::Relaxed);
                let body = api::error_body(
                    "answer_signing_failed",
                    "the robot could not sign its answer; nothing should be trusted from it",
                );
                let _ = http::write_response(s, 500, &to_body(&body), &[]);
            }
        }
        s.finish();
    };
    if !has_slot {
        c.busy.fetch_add(1, Ordering::Relaxed);
        return answer(
            &mut s,
            Reply::json(
                503,
                &api::error_body(
                    "busy",
                    "every authenticated connection slot is taken; retry shortly",
                ),
            ),
        );
    }
    let route = route(&req.method, &req.target, &sh.robot_id);
    let is_chunk = matches!(route, Ok(Route::EvidenceChunk(..)));
    let limiter = if is_chunk { &sh.chunk_rate } else { &sh.rate };
    let limited = limiter
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .allow(&creds.key_id, Instant::now());
    if let Err(retry) = limited {
        c.rate_limited.fetch_add(1, Ordering::Relaxed);
        let mut r = Reply::json(
            429,
            &api::error_body(
                "rate_limited",
                &format!("too many requests for this key; retry after {retry} s"),
            ),
        );
        r.extra.push(("Retry-After", retry.to_string()));
        return answer(&mut s, r);
    }
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
    let busy = |why: &str| {
        c.busy.fetch_add(1, Ordering::Relaxed);
        Reply::json(503, &api::error_body("busy", why))
    };
    let route = match route {
        Err(e) => {
            c.not_found.fetch_add(1, Ordering::Relaxed);
            return answer(&mut s, Reply::error(&e));
        }
        Ok(r) => r,
    };
    if route.is_evidence() {
        let Some(svc) = sh.evidence.as_ref() else {
            c.not_found.fetch_add(1, Ordering::Relaxed);
            return answer(
                &mut s,
                Reply::error(&ApiError::new(
                    404,
                    "evidence_disabled",
                    "the evidence API is not configured on this robot",
                )),
            );
        };
        let r = evidence_call(sh, svc, &route, &req.body, meta, &busy);
        return answer(&mut s, r);
    }
    let call = match route {
        Route::Robot => Call::Robot,
        Route::Get(id) => Call::Get(id),
        Route::Submit => match api::parse_submit(&req.body) {
            Ok(r) => Call::Submit(r),
            Err(e) => Call::Invalid(e),
        },
        Route::Revert(id) => match api::parse_revert(&req.body) {
            Ok(r) => Call::Revert(id, r),
            Err(e) => Call::Invalid(e),
        },
        // Handled above.
        _ => return answer(&mut s, busy("unroutable")),
    };
    let r = match dispatch(sh, call, meta) {
        Ok(a) => Reply::json(a.status, &a.body),
        Err(why) => busy(why),
    };
    answer(&mut s, r)
}

/// The build lock, or `None` when another build holds it (a poisoned lock
/// is taken over: it guards no data).
fn try_building(svc: &evidence::Service) -> Option<std::sync::MutexGuard<'_, ()>> {
    match svc.building.try_lock() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

/// The evidence API calls (listener thread; only the export note goes to
/// the main loop).
fn evidence_call(
    sh: &Shared,
    svc: &evidence::Service,
    route: &Route,
    body: &[u8],
    meta: Meta,
    busy: &dyn Fn(&str) -> Reply,
) -> Reply {
    let Some(now_ms) = wall_ms() else {
        return Reply::error(&ApiError::new(
            503,
            "clock_unavailable",
            "the robot's wall clock is unavailable",
        ));
    };
    let lock = || svc.store.lock().unwrap_or_else(PoisonError::into_inner);
    lock().purge(now_ms);
    let manifest_reply = |status: u16, st: &evidence::Stored| Reply {
        status,
        content_type: http::JSON,
        body: st.manifest_bytes.clone(),
        extra: vec![(evidence::H_MANIFEST_SIGNATURE, st.signature.clone())],
    };
    let unknown = || {
        Reply::error(&ApiError::new(
            404,
            "unknown_export",
            "no export with this id on this robot (it may have expired)",
        ))
    };
    match route {
        Route::EvidenceInventory => {
            let Some(_g) = try_building(svc) else {
                return Reply::error(&ApiError::new(
                    503,
                    "evidence_busy",
                    "another evidence index or export is running; retry shortly",
                ));
            };
            let src = evidence::DirSource(svc.blackbox.clone());
            let mut inv = match evidence::index(&src) {
                Ok(ix) => evidence::inventory(&ix, &sh.robot_id),
                Err(e) => return Reply::error(&e),
            };
            api::json_set(&mut inv, "exports", json!(lock().list()));
            let limits = json!({
                "max_export_bytes": svc.spec.max_export_bytes,
                "chunk_bytes": svc.spec.chunk_bytes,
                "max_exports": svc.spec.max_exports,
                "max_storage_bytes": svc.spec.max_storage_bytes,
                "export_ttl_s": svc.spec.export_ttl_s,
            });
            api::json_set(&mut inv, "limits", limits);
            Reply::json(200, &inv)
        }
        Route::EvidenceManifest(id) => match lock().exports.get(id) {
            Some(st) => manifest_reply(200, st),
            None => unknown(),
        },
        Route::EvidenceDelete(id) => {
            if lock().delete(id) {
                Reply::json(200, &json!({"export_id": id, "deleted": true}))
            } else {
                unknown()
            }
        }
        Route::EvidenceChunk(id, n) => {
            let Some(st) = lock().exports.get(id).cloned() else {
                return unknown();
            };
            match evidence::read_chunk(&st, *n) {
                Ok(bytes) => {
                    lock().chunks_served += 1;
                    Reply {
                        status: 200,
                        content_type: http::OCTETS,
                        body: bytes,
                        extra: Vec::new(),
                    }
                }
                Err(e) => {
                    if e.code == "export_corrupt" {
                        let mut g = lock();
                        g.corrupt += 1;
                        g.drop_corrupt(&st);
                    }
                    Reply::error(&e)
                }
            }
        }
        Route::EvidenceCreate => {
            let req = match evidence::parse_export(body, &sh.robot_id) {
                Ok(r) => r,
                Err(e) => {
                    // Authenticated but invalid: recorded like any other.
                    return match dispatch(sh, Call::Invalid(e), meta) {
                        Ok(a) => Reply::json(a.status, &a.body),
                        Err(why) => busy(why),
                    };
                }
            };
            {
                let g = lock();
                if let Some(st) = g.exports.get(&req.export_id) {
                    return if st.digest == req.digest() {
                        manifest_reply(200, st)
                    } else {
                        Reply::error(&ApiError::new(
                            409,
                            "export_id_conflict",
                            "this export_id was already used for another selection",
                        ))
                    };
                }
                if g.exports.len() >= svc.spec.max_exports {
                    return Reply::error(&ApiError::new(
                        409,
                        "export_limit",
                        format!(
                            "{} exports are kept (max_exports); delete one or wait for one to \
                             expire",
                            g.exports.len()
                        ),
                    ));
                }
            }
            let Some(_g) = try_building(svc) else {
                return Reply::error(&ApiError::new(
                    503,
                    "evidence_busy",
                    "another evidence index or export is running; retry shortly",
                ));
            };
            // Review finding 7: the bundle is streamed into a temp export
            // (never held in memory), within the storage quota and the
            // free-space headroom, and within a build deadline.
            let src = evidence::DirSource(svc.blackbox.clone());
            let (ix, lo, hi, refs) = match evidence::index(&src).and_then(|ix| {
                let (lo, hi, refs) = evidence::select(&ix, &req.selector)?;
                Ok((ix, lo, hi, refs))
            }) {
                Ok(v) => v,
                Err(e) => return Reply::error(&e),
            };
            let estimate = evidence::selection_bytes(&ix, lo, hi);
            let storage_full = |used: u64, bytes: u64| {
                Reply::error(&ApiError::new(
                    507,
                    "storage_full",
                    format!(
                        "the kept exports use {used} bytes; this one ({bytes} bytes) would exceed \
                         max_storage_bytes; delete exports first"
                    ),
                ))
            };
            let (used, exports_dir) = {
                let g = lock();
                (g.bytes(), g.dir.clone())
            };
            if estimate <= svc.spec.max_export_bytes
                && used.saturating_add(estimate) > svc.spec.max_storage_bytes
            {
                return storage_full(used, estimate);
            }
            if let Err(e) = evidence::check_free_space(evidence::free_bytes(&exports_dir), estimate)
            {
                return Reply::error(&e);
            }
            let unstorable = |e: std::io::Error| {
                Reply::error(&ApiError::new(
                    503,
                    "evidence_unavailable",
                    format!("the export could not be stored ({e}); retry later"),
                ))
            };
            let tmp = match evidence::TempExport::create(&exports_dir) {
                Ok(t) => t,
                Err(e) => return unstorable(e),
            };
            let deadline = Instant::now() + evidence::BUILD_DEADLINE;
            let cancel = || sh.stop.load(Ordering::Relaxed) || Instant::now() > deadline;
            let built = tmp.bundle_file().map_err(&unstorable).and_then(|f| {
                let mut w = std::io::BufWriter::new(f);
                let r = evidence::build_into(
                    &src,
                    &ix,
                    lo,
                    hi,
                    refs,
                    svc.spec.max_export_bytes,
                    svc.spec.chunk_bytes,
                    &mut w,
                    &cancel,
                )
                .map_err(|e| Reply::error(&e))?;
                let f = w.into_inner().map_err(|e| unstorable(e.into_error()))?;
                f.sync_all().map_err(unstorable)?;
                Ok(r)
            });
            let (binfo, built) = match built {
                Ok(b) => b,
                Err(r) => return r,
            };
            let used = lock().bytes();
            if used.saturating_add(binfo.bytes) > svc.spec.max_storage_bytes {
                return storage_full(used, binfo.bytes);
            }
            let note = json!({
                "kind": "robodr.control_plane_evidence_export",
                "api": auth::API_VERSION,
                "robot_id": sh.robot_id,
                "export_id": req.export_id,
                "selector": req.selector,
                "requested_by": req.requested_by,
                "reason": req.reason,
                "auth": meta,
                "chain_id": built.chain.chain_id,
                "records": built.records,
                "anchor": built.anchor,
                "bundle": {
                    "format": binfo.format,
                    "bytes": binfo.bytes,
                    "sha256": binfo.sha256,
                    "chunk_bytes": binfo.chunk_bytes,
                    "chunks": binfo.chunks.len(),
                },
            });
            let key_id = meta.key_id.clone();
            let evidence_ref = match dispatch(sh, Call::EvidenceNote(Box::new(note)), meta) {
                Ok(a) if a.status == 200 => match a.body.get("evidence").and_then(Value::as_str) {
                    Some(e) => e.to_string(),
                    None => return Reply::json(503, &api::error_body("evidence_unavailable", "")),
                },
                Ok(a) => return Reply::json(a.status, &a.body),
                Err(why) => return busy(why),
            };
            let manifest = evidence::Manifest {
                kind: evidence::MANIFEST_KIND.into(),
                version: evidence::MANIFEST_VERSION,
                api: auth::API_VERSION.into(),
                robot_id: sh.robot_id.clone(),
                export_id: req.export_id.clone(),
                created_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(svc.spec.export_ttl_s.saturating_mul(1000)),
                requested_by: req.requested_by.clone(),
                reason: req.reason.clone(),
                key_id,
                selector: req.selector.clone(),
                chain: built.chain.clone(),
                records: built.records.clone(),
                anchor: built.anchor.clone(),
                referenced: built.referenced.clone(),
                bundle: binfo,
                evidence: evidence_ref,
            };
            let manifest_bytes = match serde_json::to_vec(&manifest) {
                Ok(b) => b,
                Err(e) => {
                    return Reply::error(&ApiError::new(
                        503,
                        "evidence_unavailable",
                        format!("manifest: {e}"),
                    ))
                }
            };
            let signature = {
                let signer = sh
                    .answer_signer
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                evidence::sign_manifest(signer.as_ref(), &manifest_bytes)
            };
            let Ok(signature) = signature else {
                sh.counters
                    .answer_sign_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Reply::error(&ApiError::new(
                    503,
                    "evidence_unavailable",
                    "the manifest could not be signed; nothing was exported",
                ));
            };
            match tmp.finish(manifest, manifest_bytes, signature) {
                Ok(st) => {
                    let r = manifest_reply(201, &st);
                    lock().insert(st);
                    r
                }
                Err(e) => unstorable(e),
            }
        }
        _ => busy("unroutable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review finding 9: `%XX` takes two hex digits only; a sign
    /// (`from_str_radix` accepts a leading `+`) is not one.
    #[test]
    fn pct_decode_takes_hex_digits_only() {
        assert_eq!(pct_decode("a%3Ab").as_deref(), Some("a:b"));
        assert_eq!(pct_decode("%+1"), None);
        assert_eq!(pct_decode("x%+aY"), None);
        assert_eq!(pct_decode("%-1"), None);
        assert_eq!(pct_decode("%4"), None);
        assert_eq!(pct_decode("%G0"), None);
    }

    /// Review finding 2: per-source and pre-/post-authentication slots.
    #[test]
    fn tcp_slots_are_bounded_per_source_and_per_phase() {
        let ip = |n: u8| std::net::IpAddr::from([10, 0, 0, n]);
        let slots = TcpSlots::new(3, 2);
        let a1 = slots.enter(ip(1)).unwrap();
        let mut a2 = slots.enter(ip(1)).unwrap();
        assert!(slots.enter(ip(1)).is_none(), "per-source cap");
        let b1 = slots.enter(ip(2)).unwrap();
        assert!(slots.enter(ip(3)).is_none(), "pre-auth slots full");
        // Authenticating frees a pre-auth slot (handshakes are counted
        // apart from authenticated connections).
        assert!(a2.authenticate());
        assert_eq!(slots.counts(), (2, 1));
        let mut c1 = slots.enter(ip(3)).unwrap();
        assert!(c1.authenticate());
        drop(a1);
        drop(b1);
        assert_eq!(slots.counts(), (0, 2));
        // The source cap still counts the authenticated connection.
        let a3 = slots.enter(ip(1)).unwrap();
        assert!(slots.enter(ip(1)).is_none());
        drop((a2, a3, c1));
        assert_eq!(slots.counts(), (0, 0));
        assert!(slots.inner.lock().unwrap().per_source.is_empty());
        // Authenticated slots full: authenticate() says no.
        let slots = TcpSlots::new(1, 1);
        let mut x = slots.enter(ip(1)).unwrap();
        assert!(x.authenticate());
        let mut y = slots.enter(ip(2)).unwrap();
        assert!(!y.authenticate());
    }

    #[test]
    fn routes() {
        let r = |m: &str, t: &str| route(m, t, "ugv-007");
        assert_eq!(r("GET", "/api/v2/robots/ugv-007"), Ok(Route::Robot));
        assert_eq!(
            r("POST", "/api/v2/robots/ugv-007/action-requests"),
            Ok(Route::Submit)
        );
        assert_eq!(
            r(
                "GET",
                "/api/v2/robots/ugv-007/action-requests/robot_safe_pause%3Augv-007"
            ),
            Ok(Route::Get("robot_safe_pause:ugv-007".into()))
        );
        assert_eq!(
            r("POST", "/api/v2/robots/ugv%2D007/action-requests/a/revert"),
            Ok(Route::Revert("a".into()))
        );
        assert_eq!(
            r("GET", "/api/v2/robots/ugv-008").unwrap_err().code,
            "unknown_robot"
        );
        assert_eq!(r("POST", "/api/v2/robots/ugv-007").unwrap_err().status, 405);
        assert_eq!(
            r("GET", "/api/v2/robots/ugv-007/action-requests")
                .unwrap_err()
                .status,
            405
        );
        assert_eq!(
            r("GET", "/api/v2/robots/ugv-007/other").unwrap_err().status,
            404
        );
        // v1 is gone.
        assert_eq!(r("GET", "/api/v1/robots/ugv-007").unwrap_err().status, 404);
        assert_eq!(
            r("GET", "/api/v2/robots/ugv-007/action-requests/a%2Fb")
                .unwrap_err()
                .code,
            "unknown_request"
        );
        assert_eq!(
            r("GET", "/api/v2/robots/ugv-007/action-requests/%zz")
                .unwrap_err()
                .status,
            404
        );
        assert_eq!(
            r("GET", "/api/v2/robots/ugv-007/action-requests/%c3%a9")
                .unwrap_err()
                .status,
            404
        );
        assert_eq!(r("GET", "/api/v2/robots/ugv-007/").unwrap_err().status, 404);
        // Evidence.
        assert_eq!(
            r("GET", "/api/v2/robots/ugv-007/evidence"),
            Ok(Route::EvidenceInventory)
        );
        assert_eq!(
            r("POST", "/api/v2/robots/ugv-007/evidence/exports"),
            Ok(Route::EvidenceCreate)
        );
        assert_eq!(
            r("GET", "/api/v2/robots/ugv-007/evidence/exports/exp%3A1"),
            Ok(Route::EvidenceManifest("exp:1".into()))
        );
        assert_eq!(
            r("DELETE", "/api/v2/robots/ugv-007/evidence/exports/exp-1"),
            Ok(Route::EvidenceDelete("exp-1".into()))
        );
        assert_eq!(
            r(
                "GET",
                "/api/v2/robots/ugv-007/evidence/exports/exp-1/chunks/12"
            ),
            Ok(Route::EvidenceChunk("exp-1".into(), 12))
        );
        for bad in ["012", "-1", "", "99999999999", "1a"] {
            assert_eq!(
                r(
                    "GET",
                    &format!("/api/v2/robots/ugv-007/evidence/exports/e/chunks/{bad}")
                )
                .unwrap_err()
                .status,
                404,
                "{bad}"
            );
        }
        assert_eq!(
            r("POST", "/api/v2/robots/ugv-007/evidence/exports/e/chunks/0")
                .unwrap_err()
                .status,
            405
        );
        assert_eq!(
            r("PUT", "/api/v2/robots/ugv-007/evidence/exports/e")
                .unwrap_err()
                .status,
            405
        );
        assert_eq!(
            r("GET", "/api/v2/robots/ugv-007/evidence/exports/a%2Fb")
                .unwrap_err()
                .code,
            "unknown_export"
        );
    }

    fn section(v: serde_json::Value) -> Result<ControlPlaneSection, serde_json::Error> {
        serde_json::from_value(v)
    }

    #[test]
    fn section_is_strict() {
        let base = |extra: serde_json::Value| {
            let mut v = serde_json::json!({"soc_keys": [], "state_dir": "/var/lib/x"});
            for (k, x) in extra.as_object().unwrap() {
                v[k] = x.clone();
            }
            section(v)
        };
        assert!(base(serde_json::json!({"listen_tcp": "127.0.0.1:1", "x": 1})).is_err());
        // state_dir is required.
        assert!(section(serde_json::json!({"soc_keys": [], "listen_tcp": "127.0.0.1:1"})).is_err());
        let s = base(serde_json::json!({"listen_tcp": "127.0.0.1:1"})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("at least one"));
        let s = base(serde_json::json!({"listen_tcp": "0.0.0.0:8787"})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("mutual TLS"));
        let s =
            base(serde_json::json!({"listen_tcp": "0.0.0.0:8787", "allow_remote": true})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("removed"));
        let s =
            base(serde_json::json!({"listen_tcp": "127.0.0.1:1", "allow_remote": false})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("removed"));
        let s = base(serde_json::json!({"listen_tcp": "127.0.0.1:0"})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("port 0"));
        let s = base(serde_json::json!({})).unwrap();
        assert!(s
            .resolve("r", &[])
            .unwrap_err()
            .contains("listen_tcp and/or"));
        let s = base(serde_json::json!({"unix_socket": "rel.sock"})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("absolute"));
        let s =
            base(serde_json::json!({"unix_socket": "/run/x/c.sock", "state_dir": "rel"})).unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("state_dir"));
        let s =
            base(serde_json::json!({"listen_tcp": "127.0.0.1:1", "max_clock_skew_s": 0})).unwrap();
        assert!(s
            .resolve("r", &[])
            .unwrap_err()
            .contains("max_clock_skew_s"));
        let s = base(serde_json::json!({
            "unix_socket": "/run/x/c.sock",
            "tls": {"cert_chain": "/a", "key_file": "/b", "client_ca": "/c"}
        }))
        .unwrap();
        assert!(s
            .resolve("r", &[])
            .unwrap_err()
            .contains("applies to listen_tcp"));
        let s = base(serde_json::json!({
            "listen_tcp": "127.0.0.1:1",
            "evidence": {"chunk_bytes": 1024}
        }))
        .unwrap();
        assert!(s.resolve("r", &[]).unwrap_err().contains("chunk_bytes"));
        assert!(base(serde_json::json!({
            "listen_tcp": "127.0.0.1:1",
            "evidence": {"nope": 1}
        }))
        .is_err());
        assert!(base(serde_json::json!({
            "listen_tcp": "127.0.0.1:1",
            "tls": {"cert_chain": "/a", "key_file": "/b", "client_ca": "/c", "verify": false}
        }))
        .is_err());
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
            "listen_tcp": "127.0.0.1:1", "state_dir": "/var/lib/x", "soc_keys": [p, p]
        }))
        .unwrap();
        assert!(s.resolve("ugv-007", &[]).unwrap_err().contains("twice"));
        let s = section(
            serde_json::json!({"listen_tcp": "127.0.0.1:1", "state_dir": "/var/lib/x", "soc_keys": [p]}),
        )
        .unwrap();
        assert!(s
            .resolve("ugv-007", &["soc-a"])
            .unwrap_err()
            .contains("own"));
        assert_eq!(s.resolve("ugv-007", &[]).unwrap().keys.len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
