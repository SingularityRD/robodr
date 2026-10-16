//! Input threads: each input runs on its own OS thread and feeds one
//! bounded `std::sync::mpsc::sync_channel` shared by all inputs.
//!
//! | Input | Thread body | Ends |
//! |---|---|---|
//! | passive capture (live `AF_PACKET` or pcap replay), from `sensor.capture` | [`robodr_ros2_pipeline::CaptureSettings::open`] -> `DatagramSource::recv` | file end / error / stop |
//! | SPDP multicast socket, from `sensor.listen_spdp` | `recv_from` with a read timeout | error / stop |
//! | JSONL `RobotEvent`s on stdin | bounded line reader | EOF / error |
//! | JSONL `RobotEvent`s on a unix socket | listener + one reader per connection | error / stop |
//!
//! # Backpressure
//!
//! Inputs never block on the queue: [`Feed::send`] uses `try_send`; when the
//! queue is full the item is dropped and counted in
//! [`InputStats::dropped`] (the daemon turns increases into
//! `robot.agent.queue_overflow` findings). Blocking would stall a live
//! capture inside the kernel ring, where losses are invisible.
//!
//! # Hostile input
//!
//! JSON lines are capped at [`MAX_EVENT_LINE_BYTES`]; an overlong line is
//! skipped to its newline (never buffered), and a line that is not UTF-8 or
//! not a `RobotEvent` is counted in [`InputStats::malformed`] and skipped:
//! a stream input does not end on bad data. Datagrams go to the pipeline,
//! which never panics and bounds its own memory and output.

use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
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

/// What an input delivers.
#[derive(Debug)]
pub enum Payload {
    Datagram(Datagram),
    Event(Box<RobotEvent>),
}

/// One queued item.
#[derive(Debug)]
pub struct Msg {
    /// Index of the input in the daemon's input list.
    pub input: usize,
    /// When it was queued (queue latency = pipeline lag).
    pub at: Instant,
    pub payload: Payload,
}

/// Counters shared between an input thread and the daemon.
#[derive(Debug, Default)]
pub struct InputStats {
    /// Items delivered by the source (queued or dropped).
    pub received: AtomicU64,
    /// Items dropped because the queue was full.
    pub dropped: AtomicU64,
    /// Lines that were too long, not UTF-8 or not a `RobotEvent`.
    pub malformed: AtomicU64,
    /// Rejected connections (unix socket over `max_connections`).
    pub rejected_connections: AtomicU64,
    /// Milliseconds since the daemon epoch of the last item, plus one
    /// (0 = never).
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
}

impl Feed {
    pub fn new(tx: SyncSender<Msg>, input: usize, stats: Arc<InputStats>, epoch: Instant) -> Self {
        Self {
            tx,
            input,
            stats,
            epoch,
        }
    }

    fn touch(&self) {
        let ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        self.stats.last_rx_ms1.store(ms + 1, Ordering::Relaxed);
    }

    /// Queue `payload` without blocking. `false` when the daemon is gone
    /// (the input thread should stop).
    pub fn send(&self, payload: Payload) -> bool {
        self.stats.received.fetch_add(1, Ordering::Relaxed);
        self.touch();
        let msg = Msg {
            input: self.input,
            at: Instant::now(),
            payload,
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

    /// Count one malformed item (activity: the source is not silent).
    pub fn malformed(&self, why: &str) {
        self.stats.malformed.fetch_add(1, Ordering::Relaxed);
        self.touch();
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
                if !discarding && !buf.is_empty() && !handle_line(&buf, feed) {
                    return Ok(());
                }
                return Ok(());
            }
            Ok(_) => {
                if buf.last() == Some(&b'\n') {
                    buf.pop();
                    if discarding {
                        discarding = false;
                    } else if !handle_line(&buf, feed) {
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
fn handle_line(line: &[u8], feed: &Feed) -> bool {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Ok(text) = std::str::from_utf8(line) else {
        feed.malformed("line is not valid UTF-8");
        return true;
    };
    let t = text.trim();
    if t.is_empty() || t.starts_with('#') {
        return true;
    }
    match serde_json::from_str::<RobotEvent>(t) {
        Ok(ev) => feed.send(Payload::Event(Box::new(ev))),
        Err(e) => {
            feed.malformed(&format!("not a RobotEvent: {e}"));
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

/// Bind the event socket: a stale socket at `path` is replaced, any other
/// file there is refused. The socket is made mode 0600 (the parent
/// directory should be private too: there is a short window between bind
/// and chmod).
pub fn bind_event_socket(path: &Path) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// Accept connections on `listener` (at most `max_connections` at once;
/// more are closed and counted), one reader thread each, until `stop`.
/// Removes the socket file on exit.
pub fn run_unix_listener(
    listener: UnixListener,
    path: PathBuf,
    max_connections: usize,
    stop: Arc<AtomicBool>,
    feed: Feed,
) {
    let active = Arc::new(AtomicUsize::new(0));
    let mut readers: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((conn, _)) => {
                readers.retain(|h| !h.is_finished());
                if active.load(Ordering::SeqCst) >= max_connections {
                    feed.stats
                        .rejected_connections
                        .fetch_add(1, Ordering::Relaxed);
                    drop(conn);
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let (c_stop, c_feed, c_active) = (stop.clone(), feed.clone(), active.clone());
                let spawned = std::thread::Builder::new()
                    .name("agentd-sock-conn".into())
                    .spawn(move || {
                        serve_connection(conn, &c_stop, &c_feed);
                        c_active.fetch_sub(1, Ordering::SeqCst);
                    });
                match spawned {
                    Ok(h) => readers.push(h),
                    Err(_) => {
                        // Could not spawn: the closure (and the connection)
                        // was dropped.
                        active.fetch_sub(1, Ordering::SeqCst);
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
                feed.end(Some(format!("{}: accept: {e}", path.display())));
                let _ = std::fs::remove_file(&path);
                return;
            }
        }
    }
    for h in readers {
        let _ = h.join();
    }
    let _ = std::fs::remove_file(&path);
    feed.end(None);
}

fn serve_connection(conn: UnixStream, stop: &AtomicBool, feed: &Feed) {
    // The listener is non-blocking; accepted sockets inherit nothing on
    // Linux, but be explicit.
    if conn.set_nonblocking(false).is_err() || conn.set_read_timeout(Some(SOCKET_POLL)).is_err() {
        return;
    }
    if let Err(e) = read_event_lines(conn, stop, feed) {
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
        let h = std::thread::spawn(move || run_unix_listener(l, p2, 1, s2, f));
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
}
