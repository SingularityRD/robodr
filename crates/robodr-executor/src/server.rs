//! The executor process's socket loop.
//!
//! * **Housekeeping never waits for a peer.** [`Engine::tick`] (TTL expiry,
//!   revert retries, the periodic read-back) runs on its own thread every
//!   [`TICK`], independent of any connection.
//! * **Bounded peers.** At most [`MAX_CONNECTIONS`] connections are served
//!   at once (each on its own thread; more are closed at once). A request
//!   line must arrive whole within [`MESSAGE_DEADLINE`], an absolute
//!   deadline (a peer trickling one byte at a time cannot extend it), and
//!   it is read **without** the engine: only an authenticated request takes
//!   the engine's lock. Inside a `submit`, the safety answer agentd owes
//!   must arrive within [`CONFIRM_DEADLINE`] (the engine is locked
//!   meanwhile, so housekeeping is delayed by at most that much, and only by
//!   a key holder).
//! * One engine, one lock: one nftables transaction at a time.

use std::io::{BufReader, ErrorKind};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::decision::Current;
use crate::engine::{Engine, Now, Outcome, SafetyOracle};
use crate::proto::{self, Key, Msg, NonceCache, Reject};

/// Longest a peer may take to send one whole message (absolute).
pub const MESSAGE_DEADLINE: Duration = Duration::from_secs(5);
/// Longest agentd may take to answer the safety question inside a submit.
pub const CONFIRM_DEADLINE: Duration = Duration::from_secs(2);
/// Connections served at once.
pub const MAX_CONNECTIONS: usize = 8;
/// How often the engine's housekeeping runs.
pub const TICK: Duration = Duration::from_millis(500);

/// Counters (logged, and returned by `ping`).
#[derive(Debug, Default, Clone, Copy)]
pub struct ServerStats {
    pub connections: u64,
    pub rejected: u64,
    pub handled: u64,
    /// Connections closed at once because [`MAX_CONNECTIONS`] were busy.
    pub over_limit: u64,
}

/// Bind the socket: a stale socket at `path` is replaced, anything else
/// there refuses.
pub fn bind(path: &Path, mode: u32) -> Result<UnixListener, String> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(_) => {
            return Err(format!(
                "{}: exists and is not a socket (refusing to replace it)",
                path.display()
            ))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let l = UnixListener::bind(path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    l.set_nonblocking(true)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(l)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

struct ConnOracle<'a> {
    reader: &'a mut BufReader<UnixStream>,
    writer: &'a mut UnixStream,
    key: &'a Key,
    request_nonce: &'a str,
    order_id: &'a str,
    nonces: &'a Mutex<NonceCache>,
}

impl SafetyOracle for ConnOracle<'_> {
    fn current(&mut self) -> Result<Current, String> {
        let n = proto::new_nonce()?;
        let sent = Instant::now();
        let line = proto::seal(
            self.key,
            proto::wall_ms(),
            &n,
            self.request_nonce,
            &Msg::Confirm {
                id: self.order_id.to_string(),
            },
        )?;
        proto::write_line(self.writer, &line)?;
        let raw = proto::read_line_by(self.reader, sent + CONFIRM_DEADLINE)?;
        let r =
            proto::open(self.key, &raw, proto::wall_ms(), Some(&n)).map_err(|e| e.to_string())?;
        lock(self.nonces)
            .check(&r.nonce, proto::mono_ms())
            .map_err(|e| e.to_string())?;
        let rtt = u64::try_from(sent.elapsed().as_millis()).unwrap_or(u64::MAX);
        match r.msg {
            Msg::Safety { state, age_ms } => Ok(Current {
                state,
                age_ms: age_ms.saturating_add(rtt),
            }),
            Msg::NoSafety { reason } => Err(proto_text(&reason)),
            _ => Err("expected a safety answer".into()),
        }
    }
}

fn proto_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// Handle one connection. Returns `false` when the peer was rejected.
pub fn handle(
    stream: UnixStream,
    engine: &Mutex<&mut Engine>,
    key: &Key,
    nonces: &Mutex<NonceCache>,
    boot_id: &str,
) -> Result<bool, String> {
    stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_write_timeout(Some(MESSAGE_DEADLINE)))
        .map_err(|e| e.to_string())?;
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    // The whole request, without the engine.
    let raw = proto::read_line_by(&mut reader, Instant::now() + MESSAGE_DEADLINE)?;
    let req = match proto::open(key, &raw, proto::wall_ms(), None) {
        Ok(r) => r,
        Err(Reject::Malformed(_) | Reject::BadMac | Reject::Stale | Reject::WrongReply) => {
            return Ok(false)
        }
        Err(Reject::Replayed) => return Ok(false),
    };
    if lock(nonces).check(&req.nonce, proto::mono_ms()).is_err() {
        return Ok(false);
    }
    let answer = match req.msg {
        Msg::Submit { order } => {
            let mut g = lock(engine);
            let mut oracle = ConnOracle {
                reader: &mut reader,
                writer: &mut writer,
                key,
                request_nonce: &req.nonce,
                order_id: &order.id,
                nonces,
            };
            let out = g.submit(&order, &mut oracle, Now::system());
            Msg::Outcome {
                outcome: Box::new(out),
            }
        }
        Msg::Revert { id, reason, soc } => {
            let reason = format!("revert requested: {}", proto_text(&reason));
            Msg::Outcome {
                outcome: Box::new(if crate::net::id_ok(&id) {
                    lock(engine).revert_request(&id, &reason, soc.as_deref(), Now::system())
                } else {
                    bad_id(&id)
                }),
            }
        }
        Msg::Status { id } => Msg::Outcome {
            outcome: Box::new(if crate::net::id_ok(&id) {
                lock(engine).status(&id)
            } else {
                bad_id(&id)
            }),
        },
        Msg::Events { since, anchor } => {
            let mut g = lock(engine);
            if let Some(a) = &anchor {
                // Review of gap 1: an older journal put back is caught by
                // the head agentd anchored in its black box.
                g.check_anchor(a, Now::system());
            }
            if g.has_held() {
                // Actions held after a reboot: re-armed only with the
                // safety state now.
                let mut oracle = ConnOracle {
                    reader: &mut reader,
                    writer: &mut writer,
                    key,
                    request_nonce: &req.nonce,
                    order_id: "rearm",
                    nonces,
                };
                let current = oracle.current();
                g.rearm_held(current, Now::system());
            }
            Msg::EventList {
                events: g.events_since(since, proto::MAX_EVENTS_PER_ANSWER),
                head: Some(g.answer_head()),
            }
        }
        Msg::Ping => {
            let g = lock(engine);
            let st = g.state();
            Msg::Pong {
                active: st.entries.len(),
                boot_id: boot_id.to_string(),
                operator_disabled: st.operator_disabled,
                journal_reset: st.journal_reset_ms.is_some(),
                held: st
                    .entries
                    .iter()
                    .filter(|e| e.phase == crate::journal::Phase::Held)
                    .count(),
            }
        }
        Msg::Rearm { reason } => {
            let r =
                lock(engine).rearm(&format!("operator: {}", proto_text(&reason)), Now::system());
            match r {
                Ok(was_disabled) => Msg::Rearmed { was_disabled },
                Err(e) => Msg::Error {
                    code: "journal".into(),
                    message: proto_text(&e),
                },
            }
        }
        _ => Msg::Error {
            code: "unexpected_message".into(),
            message: "not a request".into(),
        },
    };
    let n = proto::new_nonce()?;
    let line = proto::seal(key, proto::wall_ms(), &n, &req.nonce, &answer)?;
    proto::write_line(&mut writer, &line)?;
    Ok(true)
}

fn bad_id(id: &str) -> Outcome {
    let mut o = Outcome {
        id: String::new(),
        status: crate::engine::Status::Unknown,
        action: None,
        refusal: None,
        error: None,
        applied_ms: None,
        deadline_ms: None,
        duplicate: false,
        note: None,
        quarantine: None,
    };
    o.error = Some(format!("bad id {:?}", crate::net::clip(id)));
    o
}

/// Serve until `stop()` is true. `on_tick` runs after every housekeeping
/// pass (watchdog ping), on the housekeeping thread.
pub fn serve(
    listener: &UnixListener,
    engine: &mut Engine,
    key: &Key,
    boot_id: &str,
    stop: &(dyn Fn() -> bool + Sync),
    on_tick: &mut (dyn FnMut(&Engine, &ServerStats) + Send),
) -> ServerStats {
    let engine = Mutex::new(engine);
    let nonces = Mutex::new(NonceCache::default());
    let stats = Mutex::new(ServerStats::default());
    let busy = AtomicUsize::new(0);
    std::thread::scope(|s| {
        let (engine, nonces, stats, busy) = (&engine, &nonces, &stats, &busy);
        // Housekeeping: independent of every connection.
        s.spawn(move || {
            let mut next = Instant::now();
            while !stop() {
                if Instant::now() >= next {
                    let mut g = lock(engine);
                    g.tick(Now::system());
                    let st = *lock(stats);
                    on_tick(&g, &st);
                    drop(g);
                    next = Instant::now() + TICK;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        while !stop() {
            match listener.accept() {
                Ok((conn, _)) => {
                    lock(stats).connections += 1;
                    if busy.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                        let mut st = lock(stats);
                        st.over_limit += 1;
                        st.rejected += 1;
                        drop(conn);
                        continue;
                    }
                    busy.fetch_add(1, Ordering::SeqCst);
                    s.spawn(move || {
                        let r = handle(conn, engine, key, nonces, boot_id);
                        {
                            let mut st = lock(stats);
                            match r {
                                Ok(true) => st.handled += 1,
                                Ok(false) | Err(_) => st.rejected += 1,
                            }
                        }
                        busy.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    });
    let out = *lock(&stats);
    out
}
