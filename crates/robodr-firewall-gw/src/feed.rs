//! The gateway's findings feed to agentd: JSON lines on agentd's
//! `gateway_feed` unix socket (`findings_socket` in the gateway
//! configuration), one per aggregated gateway finding
//! (`robot.gateway.*`, `crate::findings`) and per Motion Firewall
//! deviation (`robot.firewall.*`):
//!
//! ```json
//! {"format":"robodr-gateway-finding/v1","rule":"robot.gateway.trajectory_rejected",
//!  "severity":"high","detail":"channel /arm: 3 time(s) ...","mode":"enforce",
//!  "channel":"/arm","count":3}
//! ```
//!
//! agentd checks the peer (root, its own uid, the configured gateway uid),
//! accepts only `robot.gateway.*` and `robot.firewall.*` rules from it and
//! turns each line into a finding of its normal pipeline (black box,
//! spool, responder, correlation).
//!
//! Only housekeeping writes here, never the decision path. The socket is
//! connected lazily (retried at most every [`RETRY`]), written with a short
//! timeout ([`WRITE_TIMEOUT`]); while agentd is not there the lines wait in
//! a bounded backlog ([`MAX_BACKLOG`], oldest dropped first and counted).
//! The events file keeps every deviation either way.

use std::collections::VecDeque;
use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;

/// The line format tag.
pub const FORMAT: &str = "robodr-gateway-finding/v1";
/// Most lines waiting for agentd.
pub const MAX_BACKLOG: usize = 1024;
/// Reconnect interval.
pub const RETRY: Duration = Duration::from_secs(1);
/// Write timeout per housekeeping flush.
pub const WRITE_TIMEOUT: Duration = Duration::from_millis(50);

/// One line.
#[derive(Debug, Clone, Serialize)]
pub struct Line<'a> {
    pub format: &'static str,
    pub rule: &'a str,
    pub severity: robodr_events::Severity,
    pub detail: &'a str,
    pub mode: robodr_events::Mode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<&'a str>,
    pub count: u64,
}

/// The line of a deviation (`channel`, `count` for gateway findings).
pub fn line(d: &robodr_events::Deviation, channel: Option<&str>, count: u64) -> Option<String> {
    serde_json::to_string(&Line {
        format: FORMAT,
        rule: d.rule_str(),
        severity: d.severity,
        detail: &d.detail,
        mode: d.mode,
        channel,
        count,
    })
    .ok()
}

/// See the module docs.
#[derive(Debug)]
pub struct Feed {
    path: PathBuf,
    conn: Option<UnixStream>,
    backlog: VecDeque<String>,
    next_try: Option<Instant>,
    /// Lines written to agentd.
    pub sent: u64,
    /// Lines dropped from a full backlog.
    pub dropped: u64,
    /// The last connect / write error.
    pub last_error: Option<String>,
}

impl Feed {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            conn: None,
            backlog: VecDeque::new(),
            next_try: None,
            sent: 0,
            dropped: 0,
            last_error: None,
        }
    }

    pub fn push(&mut self, line: String) {
        if self.backlog.len() >= MAX_BACKLOG {
            self.backlog.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.backlog.push_back(line);
    }

    pub fn pending(&self) -> usize {
        self.backlog.len()
    }

    pub fn connected(&self) -> bool {
        self.conn.is_some()
    }

    /// Write what is waiting (housekeeping).
    pub fn flush(&mut self, now: Instant) {
        if self.backlog.is_empty() {
            return;
        }
        if self.conn.is_none() {
            if self.next_try.is_some_and(|t| now < t) {
                return;
            }
            match UnixStream::connect(&self.path) {
                Ok(c) => {
                    let _ = c.set_write_timeout(Some(WRITE_TIMEOUT));
                    self.conn = Some(c);
                    self.last_error = None;
                }
                Err(e) => {
                    self.last_error = Some(format!("{}: {e}", self.path.display()));
                    self.next_try = Some(now + RETRY);
                    return;
                }
            }
        }
        while let Some(l) = self.backlog.front() {
            let Some(c) = self.conn.as_mut() else {
                return;
            };
            let mut buf = Vec::with_capacity(l.len() + 1);
            buf.extend_from_slice(l.as_bytes());
            buf.push(b'\n');
            if let Err(e) = c.write_all(&buf) {
                // A half-written line ends with the connection; agentd's
                // reader drops it as malformed. The line is sent again.
                self.last_error = Some(format!("{}: {e}", self.path.display()));
                self.conn = None;
                self.next_try = Some(now + RETRY);
                return;
            }
            self.backlog.pop_front();
            self.sent = self.sent.saturating_add(1);
        }
    }
}

/// What the feed thread reports (status file).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedStatus {
    pub connected: bool,
    pub sent: u64,
    pub pending: usize,
    /// Lines dropped: backlog full, or the hand-off to the thread full.
    pub dropped: u64,
    pub last_error: Option<String>,
}

/// Lines handed to the feed thread before [`FeedThread::push`] drops.
pub const HANDOFF: usize = 256;

/// The feed on its own thread (review F5): connecting and writing may
/// block (a wedged agentd), so the packet thread only hands lines over
/// ([`FeedThread::push`], never blocks) and reads the status.
#[derive(Debug)]
pub struct FeedThread {
    tx: std::sync::mpsc::SyncSender<String>,
    status: std::sync::Arc<std::sync::Mutex<FeedStatus>>,
    handoff_dropped: u64,
}

impl FeedThread {
    pub fn spawn(path: PathBuf) -> std::io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(HANDOFF);
        let status = std::sync::Arc::new(std::sync::Mutex::new(FeedStatus::default()));
        let st = std::sync::Arc::clone(&status);
        std::thread::Builder::new()
            .name("gw-feed".into())
            .spawn(move || {
                let mut f = Feed::new(path);
                loop {
                    match rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(l) => f.push(l),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                    while let Ok(l) = rx.try_recv() {
                        f.push(l);
                    }
                    f.flush(Instant::now());
                    if let Ok(mut s) = st.lock() {
                        s.connected = f.connected();
                        s.sent = f.sent;
                        s.pending = f.pending();
                        s.dropped = f.dropped;
                        s.last_error = f.last_error.clone();
                    }
                }
            })?;
        Ok(Self {
            tx,
            status,
            handoff_dropped: 0,
        })
    }

    /// Hand a line to the thread (never blocks; a full hand-off drops it).
    pub fn push(&mut self, line: String) {
        if self.tx.try_send(line).is_err() {
            self.handoff_dropped = self.handoff_dropped.saturating_add(1);
        }
    }

    pub fn status(&self) -> FeedStatus {
        let mut s = self.status.lock().map(|g| g.clone()).unwrap_or_default();
        s.dropped = s.dropped.saturating_add(self.handoff_dropped);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead as _;

    #[test]
    fn lines_reach_a_listener_and_wait_while_it_is_absent() {
        let dir = std::env::temp_dir().join(format!("robodr-gw-feed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("feed.sock");
        let mut f = Feed::new(path.clone());
        let d = robodr_events::Deviation::new(
            crate::findings::rules::TRAJECTORY_REJECTED,
            robodr_events::Severity::High,
            "x",
        );
        f.push(line(&d, Some("/arm"), 3).unwrap());
        f.flush(Instant::now());
        assert!(!f.connected() && f.pending() == 1 && f.last_error.is_some());
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        f.flush(Instant::now() + RETRY);
        assert_eq!((f.sent, f.pending()), (1, 0));
        let (c, _) = l.accept().unwrap();
        let mut r = std::io::BufReader::new(c);
        let mut s = String::new();
        r.read_line(&mut s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["format"], FORMAT);
        assert_eq!(v["rule"], "robot.gateway.trajectory_rejected");
        assert_eq!(v["channel"], "/arm");
        assert_eq!(v["count"], 3);
        for _ in 0..MAX_BACKLOG + 5 {
            f.backlog.push_back(String::new());
        }
        f.push("x".into());
        assert!(f.backlog.len() <= MAX_BACKLOG + 6);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
