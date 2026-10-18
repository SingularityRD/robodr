//! Input threads: each input runs on its own OS thread and feeds one
//! bounded `std::sync::mpsc::sync_channel` shared by all inputs.
//!
//! | Input | Thread body | Ends |
//! |---|---|---|
//! | passive capture (live `AF_PACKET` or pcap replay), from `sensor.capture` | [`robodr_ros2_pipeline::CaptureSettings::open`] -> `DatagramSource::recv` | file end / error / stop |
//! | SPDP multicast socket, from `sensor.listen_spdp` | `recv_from` with a read timeout | error / stop |
//! | JSONL `RobotEvent`s on stdin | bounded line reader | EOF / error |
//! | JSONL `RobotEvent`s on a unix socket | listener + one reader per connection | error / stop |
//! | JSONL safety reports (`{"state":"estop_active"}`) on the `safety_feed` socket | same listener, [`parse_safety_line`] | error / stop |
//! | JSONL Pulsar threats / heartbeats on the `host_threats` socket | same listener with a peer-uid check ([`run_unix_listener_peers`]), [`crate::host::parse_host_line`] | error / stop |
//!
//! # Backpressure and memory bound
//!
//! Inputs never block on the queue: [`Feed::send`] uses `try_send`; when the
//! queue is full the item is dropped and counted in
//! [`InputStats::dropped`] (the daemon turns increases into
//! `robot.agent.queue_overflow` findings). Blocking would stall a live
//! capture inside the kernel ring, where losses are invisible.
//!
//! The queue is bounded twice: by item count (the channel capacity) **and**
//! by bytes, through a [`QueueBudget`] shared by every input. Each queued
//! [`Msg`] holds a [`Charge`] on the budget (datagram payload + source
//! string + the `Msg` itself; for a JSON event the line length + the `Msg`),
//! released when the daemon drops the message after handling it (or when
//! `try_send` fails). An item that does not fit is dropped and counted in
//! both [`InputStats::dropped`] and [`InputStats::budget_drops`]. So a flood
//! of 64 KiB datagrams while the pipeline lags pins at most the budget
//! (default [`DEFAULT_QUEUE_BYTES`]), not `capacity x 64 KiB`.
//!
//! # Liveness
//!
//! Only **valid** items (a datagram, a parsed `RobotEvent`) count as
//! activity ([`InputStats::last_rx_ms`]). Malformed lines are counted but do
//! not reset the silence timer: a stream of nothing but junk (a producer on
//! a newer schema, or a local process keeping the input "busy") leaves the
//! agent blind, and health reports it as silent (`unknown`).
//!
//! # Hostile input
//!
//! JSON lines are capped at [`MAX_EVENT_LINE_BYTES`]; an overlong line is
//! skipped to its newline (never buffered), and a line that is not UTF-8 or
//! not a `RobotEvent` is counted in [`InputStats::malformed`] and skipped:
//! a stream input does not end on bad data. Datagrams go to the pipeline,
//! which never panics and bounds its own memory and output.

use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use robodr_events::RobotEvent;
use robodr_ros2_pipeline::{sanitize, Datagram, DatagramSource, SharedHealth};

/// Longest accepted JSON line of an event input (bytes, newline excluded).
pub const MAX_EVENT_LINE_BYTES: usize = 64 * 1024;
/// Read timeout of socket readers (stop-flag latency).
pub const SOCKET_POLL: Duration = Duration::from_millis(200);
/// Default byte budget of the input queue (all inputs together).
pub const DEFAULT_QUEUE_BYTES: usize = 32 << 20;
/// Budget charged for a `RobotEvent` queued through [`Feed::send`] (the
/// line readers charge the actual line length instead).
pub const EVENT_ESTIMATE_BYTES: usize = 1024;

/// A byte budget shared by every input feeding one queue.
#[derive(Debug)]
pub struct QueueBudget {
    max: usize,
    used: AtomicUsize,
}

impl QueueBudget {
    pub fn new(max_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            max: max_bytes,
            used: AtomicUsize::new(0),
        })
    }

    /// Bytes currently charged.
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    pub fn max(&self) -> usize {
        self.max
    }

    /// Reserve `bytes`, or `None` if that would exceed the budget.
    pub fn try_charge(self: &Arc<Self>, bytes: usize) -> Option<Charge> {
        let mut cur = self.used.load(Ordering::Acquire);
        loop {
            let next = cur.checked_add(bytes).filter(|n| *n <= self.max)?;
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(Charge {
                        budget: self.clone(),
                        bytes,
                    })
                }
                Err(now) => cur = now,
            }
        }
    }
}

/// Bytes reserved on a [`QueueBudget`]; released on drop.
#[derive(Debug)]
pub struct Charge {
    budget: Arc<QueueBudget>,
    bytes: usize,
}

impl Charge {
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// What an input delivers.
#[derive(Debug)]
pub enum Payload {
    Datagram(Datagram),
    Event(Box<RobotEvent>),
    /// A line of the safety-state socket (see [`crate::safety`]).
    Safety(crate::safety::SafetyReport),
    /// A line of the host-threat socket (see [`crate::host`]).
    Host(crate::host::HostLine),
}

/// Turns one trimmed, non-empty, non-comment line into a payload, or says
/// why it is malformed.
pub type LineParser = fn(&str) -> Result<Payload, String>;

/// [`LineParser`] of the event inputs: a `RobotEvent`.
pub fn parse_event_line(t: &str) -> Result<Payload, String> {
    serde_json::from_str::<RobotEvent>(t)
        .map(|ev| Payload::Event(Box::new(ev)))
        .map_err(|e| format!("not a RobotEvent: {e}"))
}

/// [`LineParser`] of the safety socket: a [`crate::safety::SafetyReport`].
pub fn parse_safety_line(t: &str) -> Result<Payload, String> {
    serde_json::from_str::<crate::safety::SafetyReport>(t)
        .map(Payload::Safety)
        .map_err(|e| format!("not a safety report: {e}"))
}

/// One queued item.
#[derive(Debug)]
pub struct Msg {
    /// Index of the input in the daemon's input list.
    pub input: usize,
    /// When it was queued (queue latency = pipeline lag); also the receipt
    /// time the safety feed stamps readings with.
    pub at: Instant,
    /// The unix-socket connection it came from: unique per accepted
    /// connection of a listener for the daemon's lifetime (1, 2, ...); 0 for
    /// every other input. The safety feed keys socket writers by it.
    pub conn: u64,
    pub payload: Payload,
    /// The item's share of the queue's byte budget, released when the
    /// message is dropped (after it was handled).
    pub charge: Charge,
}

/// Counters shared between an input thread and the daemon.
#[derive(Debug, Default)]
pub struct InputStats {
    /// Items delivered by the source (queued or dropped).
    pub received: AtomicU64,
    /// Items dropped because the queue was full (item count or bytes).
    pub dropped: AtomicU64,
    /// Of `dropped`: items dropped because the queue's byte budget was
    /// exhausted.
    pub budget_drops: AtomicU64,
    /// Lines that were too long, not UTF-8 or not a `RobotEvent`.
    pub malformed: AtomicU64,
    /// Rejected connections (unix socket over `max_connections`, or a peer
    /// the listener's peer policy refused).
    pub rejected_connections: AtomicU64,
    /// Connections open right now (unix-socket inputs).
    pub connections: AtomicU64,
    /// Items the producer itself reported lost before they reached this
    /// input (host-threat forwarder heartbeats). Health counts them like
    /// queue drops.
    pub upstream_dropped: AtomicU64,
    /// Milliseconds since the daemon epoch of the last **valid** item, plus
    /// one (0 = never). Malformed items do not update it.
    pub last_rx_ms1: AtomicU64,
    /// The input has ended (EOF, error or stop).
    pub ended: AtomicBool,
    /// Why it ended, if by an error (sanitised).
    pub end_error: Mutex<Option<String>>,
    /// Last malformed-input reason (sanitised).
    pub last_malformed: Mutex<Option<String>>,
}

impl InputStats {
    pub fn last_rx_ms(&self) -> Option<u64> {
        self.last_rx_ms1.load(Ordering::Relaxed).checked_sub(1)
    }

    pub fn end_error(&self) -> Option<String> {
        self.end_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn last_malformed(&self) -> Option<String> {
        self.last_malformed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The sending side handed to an input thread.
#[derive(Clone)]
pub struct Feed {
    tx: SyncSender<Msg>,
    input: usize,
    stats: Arc<InputStats>,
    epoch: Instant,
    budget: Arc<QueueBudget>,
    /// Connection id stamped on every message ([`Msg::conn`]).
    conn: u64,
}

impl Feed {
    /// A feed with its own [`DEFAULT_QUEUE_BYTES`] budget (tests, single
    /// input). The daemon shares one budget: [`Feed::with_budget`].
    pub fn new(tx: SyncSender<Msg>, input: usize, stats: Arc<InputStats>, epoch: Instant) -> Self {
        Self::with_budget(
            tx,
            input,
            stats,
            epoch,
            QueueBudget::new(DEFAULT_QUEUE_BYTES),
        )
    }

    pub fn with_budget(
        tx: SyncSender<Msg>,
        input: usize,
        stats: Arc<InputStats>,
        epoch: Instant,
        budget: Arc<QueueBudget>,
    ) -> Self {
        Self {
            tx,
            input,
            stats,
            epoch,
            budget,
            conn: 0,
        }
    }

    /// This feed for one accepted connection: its messages carry `conn`.
    #[must_use]
    pub fn for_connection(&self, conn: u64) -> Self {
        Self {
            conn,
            ..self.clone()
        }
    }

    fn touch(&self) {
        let ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        self.stats.last_rx_ms1.store(ms + 1, Ordering::Relaxed);
    }

    /// Queue `payload` without blocking. `false` when the daemon is gone
    /// (the input thread should stop). A datagram is charged its payload and
    /// source size, an event [`EVENT_ESTIMATE_BYTES`] (plus the `Msg`).
    pub fn send(&self, payload: Payload) -> bool {
        let size = match &payload {
            Payload::Datagram(d) => d.payload.capacity().saturating_add(d.src_ip.capacity()),
            Payload::Event(_) | Payload::Safety(_) | Payload::Host(_) => EVENT_ESTIMATE_BYTES,
        };
        self.send_sized(payload, size)
    }

    /// [`Feed::send`] charging `size` bytes (plus the `Msg` itself).
    pub fn send_sized(&self, payload: Payload, size: usize) -> bool {
        self.stats.received.fetch_add(1, Ordering::Relaxed);
        self.touch();
        let bytes = size.saturating_add(std::mem::size_of::<Msg>());
        // (If the daemon is gone, its queue was discarded with the receiver,
        // so the budget is free again and `try_send` reports it below.)
        let Some(charge) = self.budget.try_charge(bytes) else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            self.stats.budget_drops.fetch_add(1, Ordering::Relaxed);
            return true;
        };
        let msg = Msg {
            input: self.input,
            at: Instant::now(),
            conn: self.conn,
            payload,
            charge,
        };
        match self.tx.try_send(msg) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Count one malformed item. Not activity: a malformed-only stream is
    /// as blind as a silent one (see the module docs).
    pub fn malformed(&self, why: &str) {
        self.stats.malformed.fetch_add(1, Ordering::Relaxed);
        *self
            .stats
            .last_malformed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(sanitize(why));
    }

    /// Mark the input ended. Everything it queued was sent before this.
    pub fn end(&self, error: Option<String>) {
        *self
            .stats
            .end_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = error.map(|e| sanitize(&e));
        self.stats.ended.store(true, Ordering::SeqCst);
    }
}

/// Run a datagram source until it ends, the daemon goes away or `stop`.
/// Publishes the source's capture health after every item.
pub fn run_datagram_source(
    mut src: Box<dyn DatagramSource + Send>,
    health: SharedHealth,
    feed: Feed,
) {
    loop {
        match src.recv() {
            Ok(Some(d)) => {
                health.publish(src.capture_health());
                if !feed.send(Payload::Datagram(d)) {
                    feed.end(None);
                    return;
                }
            }
            Ok(None) => {
                health.publish(src.capture_health());
                feed.end(None);
                return;
            }
            Err(e) => {
                health.publish(src.capture_health());
                feed.end(Some(e.to_string()));
                return;
            }
        }
    }
}

/// Receive SPDP datagrams from a (blocking, read-timeout) UDP socket.
pub fn run_udp(sock: std::net::UdpSocket, stop: Arc<AtomicBool>, feed: Feed) {
    let mut buf = vec![0u8; 65_536];
    while !stop.load(Ordering::Relaxed) {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let d = Datagram::new(buf[..n].to_vec(), from.ip().to_string());
                if !feed.send(Payload::Datagram(d)) {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => {
                feed.end(Some(e.to_string()));
                return;
            }
        }
    }
    feed.end(None);
}

/// Read JSON lines of `RobotEvent`s from `r` until EOF, a hard error, the
/// daemon going away or `stop` (checked whenever a read times out). Never
/// buffers more than [`MAX_EVENT_LINE_BYTES`] + 1 bytes.
pub fn read_event_lines<R: Read>(r: R, stop: &AtomicBool, feed: &Feed) -> io::Result<()> {
    read_lines(r, stop, feed, parse_event_line)
}

/// [`read_event_lines`] with any [`LineParser`].
pub fn read_lines<R: Read>(
    r: R,
    stop: &AtomicBool,
    feed: &Feed,
    parse: LineParser,
) -> io::Result<()> {
    let mut reader = BufReader::with_capacity(16 * 1024, r);
    let mut buf: Vec<u8> = Vec::new();
    let mut discarding = false;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let room = (MAX_EVENT_LINE_BYTES + 1).saturating_sub(buf.len()) as u64;
        match (&mut reader).take(room).read_until(b'\n', &mut buf) {
            Ok(0) => {
                // EOF (room is never 0: a full buffer is handled below).
                if !discarding && !buf.is_empty() && !handle_line(&buf, feed, parse) {
                    return Ok(());
                }
                return Ok(());
            }
            Ok(_) => {
                if buf.last() == Some(&b'\n') {
                    buf.pop();
                    if discarding {
                        discarding = false;
                    } else if !handle_line(&buf, feed, parse) {
                        return Ok(());
                    }
                    buf.clear();
                } else if buf.len() > MAX_EVENT_LINE_BYTES {
                    if !discarding {
                        feed.malformed(&format!(
                            "line longer than {MAX_EVENT_LINE_BYTES} bytes skipped"
                        ));
                        discarding = true;
                    }
                    buf.clear();
                }
                // Otherwise: a partial line at EOF; the next read returns 0.
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                // Partial data stays in `buf`; poll the stop flag.
            }
            Err(e) => return Err(e),
        }
    }
}

/// Parse one line; `false` when the daemon is gone.
fn handle_line(line: &[u8], feed: &Feed, parse: LineParser) -> bool {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Ok(text) = std::str::from_utf8(line) else {
        feed.malformed("line is not valid UTF-8");
        return true;
    };
    let t = text.trim();
    if t.is_empty() || t.starts_with('#') {
        return true;
    }
    match parse(t) {
        Ok(p) => feed.send_sized(p, line.len()),
        Err(e) => {
            feed.malformed(&e);
            true
        }
    }
}

/// Read events from stdin until EOF. The thread blocks in `read` and is not
/// joined at shutdown.
pub fn run_stdin(stop: Arc<AtomicBool>, feed: Feed) {
    let res = read_event_lines(io::stdin().lock(), &stop, &feed);
    feed.end(res.err().map(|e| format!("stdin: {e}")));
}

/// A bound event socket and the identity (device, inode) of the socket
/// file this process created, so that only that file is ever removed.
#[derive(Debug)]
pub struct EventSocket {
    pub listener: UnixListener,
    pub path: PathBuf,
    dev: u64,
    ino: u64,
}

impl EventSocket {
    /// Remove the socket file if it is still the one this process created
    /// (same device and inode). A file another instance bound at the path
    /// since (after this one's was removed) is left alone. `true` if
    /// removed. There is a small check-then-unlink window; the socket
    /// directory is private to the daemon's user (`RuntimeDirectory=`).
    pub fn remove_if_ours(&self) -> bool {
        match std::fs::symlink_metadata(&self.path) {
            Ok(m) if m.dev() == self.dev && m.ino() == self.ino => {
                std::fs::remove_file(&self.path).is_ok()
            }
            _ => false,
        }
    }
}

/// Bind the event socket at `path`, mode 0600.
///
/// * Nothing there: bind.
/// * A socket nobody listens on (`connect` is refused): stale, replaced.
/// * A socket that accepts a connection: another live instance owns it;
///   refused with `AddrInUse` (it is never unlinked from under it).
/// * Anything else (a file, a directory, a symlink): refused.
///
/// The parent directory should be private too: there is a short window
/// between bind and chmod.
pub fn bind_event_socket(path: &Path) -> io::Result<EventSocket> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => match UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "{} is in use: another process is listening on it",
                        path.display()
                    ),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => std::fs::remove_file(path)?,
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("{}: probing the existing socket: {e}", path.display()),
                ))
            }
        },
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    let sock = EventSocket {
        listener,
        path: path.to_path_buf(),
        dev: meta.dev(),
        ino: meta.ino(),
    };
    let res = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .and_then(|()| sock.listener.set_nonblocking(true));
    if let Err(e) = res {
        sock.remove_if_ours();
        return Err(e);
    }
    Ok(sock)
}

/// Accept connections on `sock` (at most `max_connections` at once; more
/// are closed and counted), one reader thread each, until `stop`. Removes
/// the socket file on exit, if it is still the one `sock` created.
pub fn run_unix_listener(
    sock: EventSocket,
    max_connections: usize,
    stop: Arc<AtomicBool>,
    feed: Feed,
) {
    run_unix_listener_with(sock, max_connections, stop, feed, parse_event_line);
}

/// [`run_unix_listener`] with any [`LineParser`] (the safety socket).
pub fn run_unix_listener_with(
    sock: EventSocket,
    max_connections: usize,
    stop: Arc<AtomicBool>,
    feed: Feed,
    parse: LineParser,
) {
    run_unix_listener_peers(sock, max_connections, stop, feed, parse, None);
}

/// [`run_unix_listener_with`] that, with `allowed_uids`, also checks every
/// connection's peer (`SO_PEERCRED`, [`crate::host::peer_uid`]): a peer
/// whose uid is not listed (or whose credentials cannot be read) is closed
/// before anything is read, counted in [`InputStats::rejected_connections`]
/// and noted as malformed input (so health reports it, rate-limited).
pub fn run_unix_listener_peers(
    sock: EventSocket,
    max_connections: usize,
    stop: Arc<AtomicBool>,
    feed: Feed,
    parse: LineParser,
    allowed_uids: Option<Vec<u32>>,
) {
    let listener = &sock.listener;
    let active = Arc::new(AtomicUsize::new(0));
    let mut readers: Vec<JoinHandle<()>> = Vec::new();
    let mut next_conn: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((conn, _)) => {
                readers.retain(|h| !h.is_finished());
                if let Some(allowed) = &allowed_uids {
                    let refused = match crate::host::peer_uid(&conn) {
                        Ok(uid) if crate::host::peer_allowed(uid, allowed) => None,
                        Ok(uid) => Some(format!(
                            "connection from uid {uid} refused (allowed uids: {allowed:?})"
                        )),
                        Err(e) => Some(format!(
                            "connection refused: peer credentials unreadable: {e}"
                        )),
                    };
                    if let Some(why) = refused {
                        feed.stats
                            .rejected_connections
                            .fetch_add(1, Ordering::Relaxed);
                        feed.malformed(&why);
                        drop(conn);
                        continue;
                    }
                }
                if active.load(Ordering::SeqCst) >= max_connections {
                    feed.stats
                        .rejected_connections
                        .fetch_add(1, Ordering::Relaxed);
                    drop(conn);
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                feed.stats.connections.fetch_add(1, Ordering::Relaxed);
                next_conn = next_conn.saturating_add(1);
                let (c_stop, c_feed, c_active) =
                    (stop.clone(), feed.for_connection(next_conn), active.clone());
                let spawned = std::thread::Builder::new()
                    .name("agentd-sock-conn".into())
                    .spawn(move || {
                        serve_connection(conn, &c_stop, &c_feed, parse);
                        c_active.fetch_sub(1, Ordering::SeqCst);
                        c_feed.stats.connections.fetch_sub(1, Ordering::Relaxed);
                    });
                match spawned {
                    Ok(h) => readers.push(h),
                    Err(_) => {
                        // Could not spawn: the closure (and the connection)
                        // was dropped.
                        active.fetch_sub(1, Ordering::SeqCst);
                        feed.stats.connections.fetch_sub(1, Ordering::Relaxed);
                        feed.stats
                            .rejected_connections
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                feed.end(Some(format!("{}: accept: {e}", sock.path.display())));
                sock.remove_if_ours();
                return;
            }
        }
    }
    for h in readers {
        let _ = h.join();
    }
    sock.remove_if_ours();
    feed.end(None);
}

fn serve_connection(conn: UnixStream, stop: &AtomicBool, feed: &Feed, parse: LineParser) {
    // The listener is non-blocking; accepted sockets inherit nothing on
    // Linux, but be explicit.
    if conn.set_nonblocking(false).is_err() || conn.set_read_timeout(Some(SOCKET_POLL)).is_err() {
        return;
    }
    if let Err(e) = read_lines(conn, stop, feed, parse) {
        feed.malformed(&format!("connection error: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{sync_channel, Receiver};

    fn feed(cap: usize) -> (Feed, Receiver<Msg>, Arc<InputStats>) {
        let (tx, rx) = sync_channel(cap);
        let st = Arc::new(InputStats::default());
        (Feed::new(tx, 0, st.clone(), Instant::now()), rx, st)
    }

    const CMD: &str = r#"{"kind":"motion_command","channel":"/cmd_vel","linear_speed":0.2}"#;

    fn events(rx: &Receiver<Msg>) -> usize {
        rx.try_iter()
            .filter(|m| matches!(m.payload, Payload::Event(_)))
            .count()
    }

    #[test]
    fn lines_good_bad_comments_and_crlf() {
        let (f, rx, st) = feed(16);
        let input = format!(
            "{CMD}\r\n\n# comment\nnot json\n{{\"kind\":\"nope\"}}\n\u{0}\u{1b}[31m\n{CMD}"
        );
        let mut bytes = input.into_bytes();
        bytes.extend_from_slice(b"\n\xff\xfe\n");
        read_event_lines(&bytes[..], &AtomicBool::new(false), &f).unwrap();
        assert_eq!(events(&rx), 2);
        assert_eq!(st.malformed.load(Ordering::Relaxed), 4);
        assert_eq!(st.received.load(Ordering::Relaxed), 2);
        assert!(st.last_rx_ms().is_some());
        let why = st.last_malformed().unwrap();
        assert!(why.contains("UTF-8"), "{why}");
        assert!(!why.chars().any(char::is_control));
    }

    #[test]
    fn overlong_lines_are_skipped_not_buffered() {
        let (f, rx, st) = feed(16);
        let mut input = vec![b'x'; MAX_EVENT_LINE_BYTES * 3];
        input.push(b'\n');
        input.extend_from_slice(CMD.as_bytes());
        input.push(b'\n');
        // Exactly at the limit is fine (not JSON though).
        input.extend(std::iter::repeat_n(b' ', MAX_EVENT_LINE_BYTES));
        input.push(b'\n');
        // Overlong without a newline at EOF.
        input.extend(std::iter::repeat_n(b'y', MAX_EVENT_LINE_BYTES + 10));
        read_event_lines(&input[..], &AtomicBool::new(false), &f).unwrap();
        assert_eq!(events(&rx), 1);
        assert_eq!(st.malformed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn full_queue_drops_and_counts() {
        let (f, rx, st) = feed(2);
        let input = format!("{CMD}\n").repeat(10);
        read_event_lines(input.as_bytes(), &AtomicBool::new(false), &f).unwrap();
        assert_eq!(events(&rx), 2);
        assert_eq!(st.dropped.load(Ordering::Relaxed), 8);
        assert_eq!(st.received.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn disconnected_daemon_stops_the_reader() {
        let (f, rx, _) = feed(2);
        drop(rx);
        let input = format!("{CMD}\n").repeat(10);
        read_event_lines(input.as_bytes(), &AtomicBool::new(false), &f).unwrap();
        assert!(!f.send(Payload::Event(Box::new(serde_json::from_str(CMD).unwrap()))));
    }

    /// A reader that times out forever after its data.
    struct Slow(Vec<u8>, bool);
    impl Read for Slow {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.1 {
                self.1 = true;
                let n = self.0.len().min(buf.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                return Ok(n);
            }
            std::thread::sleep(Duration::from_millis(5));
            Err(io::Error::new(io::ErrorKind::WouldBlock, "timeout"))
        }
    }

    #[test]
    fn timeouts_keep_partial_lines_and_honour_stop() {
        let (f, rx, _) = feed(4);
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let half = &CMD.as_bytes()[..10];
        let h = std::thread::spawn(move || {
            read_event_lines(Slow(half.to_vec(), false), &s2, &f).unwrap();
        });
        std::thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap();
        assert_eq!(events(&rx), 0);
    }

    #[test]
    fn unix_socket_input_end_to_end() {
        let dir = std::env::temp_dir().join(format!("robodr-agentd-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ev.sock");
        // A regular file in the way is refused; a stale socket is replaced.
        std::fs::write(&path, b"x").unwrap();
        assert!(bind_event_socket(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        drop(UnixListener::bind(&path).unwrap());
        let l = bind_event_socket(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let (f, rx, st) = feed(64);
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, p2) = (stop.clone(), path.clone());
        assert_eq!(l.path, p2);
        let h = std::thread::spawn(move || run_unix_listener(l, 1, s2, f));
        let mut c = UnixStream::connect(&path).unwrap();
        use std::io::Write;
        writeln!(c, "{CMD}").unwrap();
        writeln!(c, "garbage").unwrap();
        // A second concurrent connection is over the limit.
        std::thread::sleep(Duration::from_millis(150));
        let mut c2 = UnixStream::connect(&path).unwrap();
        let _ = writeln!(c2, "{CMD}");
        let deadline = Instant::now() + Duration::from_secs(5);
        while (st.malformed.load(Ordering::Relaxed) < 1
            || st.rejected_connections.load(Ordering::Relaxed) < 1)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap();
        assert_eq!(events(&rx), 1);
        assert_eq!(st.malformed.load(Ordering::Relaxed), 1);
        assert_eq!(st.rejected_connections.load(Ordering::Relaxed), 1);
        assert!(st.ended.load(Ordering::SeqCst));
        assert!(!path.exists(), "socket removed at stop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Messages carry their connection id and the time they were queued
    /// (the safety feed's receipt time).
    #[test]
    fn connection_feeds_stamp_conn_and_receipt_time() {
        let (f, rx, _) = feed(4);
        let before = Instant::now();
        let report = crate::safety::SafetyReport {
            state: robodr_responder::SafetyState::Idle,
        };
        assert!(f.send(Payload::Safety(report)));
        assert!(f.for_connection(7).send(Payload::Safety(report)));
        std::thread::sleep(Duration::from_millis(20));
        let msgs: Vec<Msg> = rx.try_iter().collect();
        assert_eq!(msgs.iter().map(|m| m.conn).collect::<Vec<_>>(), [0, 7]);
        for m in &msgs {
            assert!(m.at >= before);
            assert!(
                m.at.elapsed() >= Duration::from_millis(20),
                "queued, not handled, time"
            );
        }
    }

    /// Each accepted connection of a listener gets its own id.
    #[test]
    fn listener_connections_get_distinct_ids() {
        use std::collections::BTreeSet;
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!(
            "robodr-agentd-conn-ids-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let sock = bind_event_socket(&path).unwrap();
        let (f, rx, _) = feed(16);
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let h = std::thread::spawn(move || {
            run_unix_listener_with(sock, 4, s2, f, parse_safety_line);
        });
        let mut a = UnixStream::connect(&path).unwrap();
        writeln!(a, "{{\"state\":\"estop_active\"}}").unwrap();
        let mut b = UnixStream::connect(&path).unwrap();
        writeln!(b, "{{\"state\":\"idle\"}}").unwrap();
        writeln!(a, "{{\"state\":\"estop_active\"}}").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got: Vec<(u64, robodr_responder::SafetyState)> = Vec::new();
        while got.len() < 3 && Instant::now() < deadline {
            for m in rx.try_iter() {
                if let Payload::Safety(r) = m.payload {
                    got.push((m.conn, r.state));
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap();
        assert_eq!(got.len(), 3, "{got:?}");
        let conns: BTreeSet<u64> = got.iter().map(|(c, _)| *c).collect();
        assert_eq!(conns.len(), 2, "{got:?}");
        assert!(conns.iter().all(|c| *c >= 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A peer whose uid the policy does not list is closed before anything
    /// is read; an allowed one is served; open connections are counted.
    #[test]
    fn peer_policy_refuses_unlisted_uids() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("robodr-agentd-peers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let euid = crate::config::effective_uid();
        const HB: &str = r#"{"kind":"heartbeat","v":1,"sent":0,"dropped":0}"#;
        for (allowed, accepted) in [(vec![euid.wrapping_add(1)], false), (vec![euid], true)] {
            let path = dir.join(format!("p{accepted}.sock"));
            let sock = bind_event_socket(&path).unwrap();
            let (f, rx, st) = feed(16);
            let stop = Arc::new(AtomicBool::new(false));
            let s2 = stop.clone();
            let h = std::thread::spawn(move || {
                run_unix_listener_peers(
                    sock,
                    2,
                    s2,
                    f,
                    crate::host::parse_host_line,
                    Some(allowed),
                );
            });
            let mut c = UnixStream::connect(&path).unwrap();
            let _ = writeln!(c, "{HB}");
            let deadline = Instant::now() + Duration::from_secs(5);
            while st.received.load(Ordering::Relaxed) == 0
                && st.rejected_connections.load(Ordering::Relaxed) == 0
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            if accepted {
                assert_eq!(st.connections.load(Ordering::Relaxed), 1);
            }
            stop.store(true, Ordering::Relaxed);
            h.join().unwrap();
            let got = rx
                .try_iter()
                .filter(|m| matches!(m.payload, Payload::Host(_)))
                .count();
            assert_eq!(got, usize::from(accepted));
            assert_eq!(
                st.rejected_connections.load(Ordering::Relaxed),
                u64::from(!accepted)
            );
            if !accepted {
                assert!(st.last_malformed().unwrap().contains("refused"));
                assert_eq!(st.last_rx_ms(), None, "a refused peer is not activity");
            }
            assert_eq!(st.connections.load(Ordering::Relaxed), 0);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safety_lines_are_parsed_strictly() {
        let (f, rx, st) = feed(16);
        let input = "{\"state\":\"estop_active\"}\n{\"state\":\"none\"}\n# c\n\
                     {\"kind\":\"motion_command\",\"channel\":\"/c\"}\n{\"state\":\"idle\"}\n";
        read_lines(
            input.as_bytes(),
            &AtomicBool::new(false),
            &f,
            parse_safety_line,
        )
        .unwrap();
        let got: Vec<_> = rx
            .try_iter()
            .filter_map(|m| match m.payload {
                Payload::Safety(r) => Some(r.state),
                _ => None,
            })
            .collect();
        use robodr_responder::SafetyState as S;
        assert_eq!(got, vec![S::EStopActive, S::Idle]);
        assert_eq!(st.malformed.load(Ordering::Relaxed), 2);
        assert!(st.last_malformed().unwrap().contains("safety report"));
    }

    #[test]
    fn malformed_lines_are_not_activity() {
        let (f, rx, st) = feed(16);
        let junk = "not json\n{\"kind\":\"motion_command_v2\"}\n".repeat(20);
        read_event_lines(junk.as_bytes(), &AtomicBool::new(false), &f).unwrap();
        assert_eq!(events(&rx), 0);
        assert_eq!(st.malformed.load(Ordering::Relaxed), 40);
        assert_eq!(st.last_rx_ms(), None, "junk must not reset silence");
        read_event_lines(format!("{CMD}\n").as_bytes(), &AtomicBool::new(false), &f).unwrap();
        assert!(st.last_rx_ms().is_some());
    }

    #[test]
    fn byte_budget_bounds_the_queue_and_is_released() {
        let (tx, rx) = sync_channel(10_000);
        let st = Arc::new(InputStats::default());
        let budget = QueueBudget::new(1 << 20);
        let f = Feed::with_budget(tx, 0, st.clone(), Instant::now(), budget.clone());
        for _ in 0..100 {
            assert!(f.send(Payload::Datagram(Datagram::new(
                vec![0; 65_000],
                "10.0.0.9"
            ))));
        }
        let held = budget.used();
        assert!(held <= 1 << 20, "{held}");
        let queued = st.received.load(Ordering::Relaxed) - st.dropped.load(Ordering::Relaxed);
        assert_eq!(queued, 16, "1 MiB / ~64 KiB");
        assert_eq!(st.dropped.load(Ordering::Relaxed), 84);
        assert_eq!(st.budget_drops.load(Ordering::Relaxed), 84);
        // Handling (dropping) the messages frees the budget.
        let msgs: Vec<Msg> = rx.try_iter().collect();
        assert_eq!(msgs.len(), 16);
        assert!(msgs.iter().all(|m| m.charge.bytes() > 65_000));
        drop(msgs);
        assert_eq!(budget.used(), 0);
        assert!(f.send(Payload::Datagram(Datagram::new(vec![0; 10], "x"))));
        assert_eq!(budget.used(), rx.try_recv().unwrap().charge.bytes());
        // An item larger than the whole budget never fits.
        let tiny = QueueBudget::new(100);
        assert!(tiny.try_charge(101).is_none());
        let c = tiny.try_charge(100).unwrap();
        assert!(tiny.try_charge(1).is_none());
        drop(c);
        assert!(tiny.try_charge(usize::MAX).is_none());
    }

    #[test]
    fn full_channel_releases_the_charge() {
        let (tx, _rx) = sync_channel(1);
        let st = Arc::new(InputStats::default());
        let budget = QueueBudget::new(1 << 20);
        let f = Feed::with_budget(tx, 0, st.clone(), Instant::now(), budget.clone());
        for _ in 0..5 {
            f.send(Payload::Datagram(Datagram::new(vec![0; 1000], "x")));
        }
        assert_eq!(st.dropped.load(Ordering::Relaxed), 4);
        assert_eq!(st.budget_drops.load(Ordering::Relaxed), 0);
        assert!(budget.used() < 2000, "only the queued item is charged");
    }

    #[test]
    fn live_socket_is_not_stolen_and_cleanup_checks_the_inode() {
        let dir = std::env::temp_dir().join(format!("robodr-agentd-steal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ev.sock");
        let first = bind_event_socket(&path).unwrap();
        let e = bind_event_socket(&path).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse, "{e}");
        assert!(UnixStream::connect(&path).is_ok(), "first still reachable");
        // Someone else replaces the file: the first instance's cleanup
        // leaves the newcomer's socket alone.
        std::fs::remove_file(&path).unwrap();
        let other = UnixListener::bind(&path).unwrap();
        assert!(!first.remove_if_ours());
        assert!(path.exists());
        drop(other);
        // Stale (nobody listening): replaced, and removed by its owner.
        let second = bind_event_socket(&path).unwrap();
        assert!(second.remove_if_ours());
        assert!(!path.exists());
        assert!(!second.remove_if_ours());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
