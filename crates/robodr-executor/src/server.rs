//! The executor process's socket loop: one connection at a time (so one
//! nftables transaction at a time), a read deadline per message, and the
//! engine's housekeeping ([`Engine::tick`]) between connections.

use std::io::{BufReader, ErrorKind};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::decision::Current;
use crate::engine::{Engine, Outcome, SafetyOracle};
use crate::proto::{self, Key, Msg, NonceCache, Reject};

/// Longest a peer may take to send one message.
pub const READ_DEADLINE: Duration = Duration::from_secs(5);
/// How often the engine's housekeeping runs.
pub const TICK: Duration = Duration::from_millis(500);

/// Counters (logged, and returned by `ping`).
#[derive(Debug, Default, Clone, Copy)]
pub struct ServerStats {
    pub connections: u64,
    pub rejected: u64,
    pub handled: u64,
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

struct ConnOracle<'a> {
    reader: &'a mut BufReader<UnixStream>,
    writer: &'a mut UnixStream,
    key: &'a Key,
    request_nonce: &'a str,
    order_id: &'a str,
    nonces: &'a mut NonceCache,
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
        let raw = proto::read_line(self.reader)?;
        let now = proto::wall_ms();
        let r = proto::open(self.key, &raw, now, Some(&n)).map_err(|e| e.to_string())?;
        self.nonces
            .check(&r.nonce, now)
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
    engine: &mut Engine,
    key: &Key,
    nonces: &mut NonceCache,
    boot_id: &str,
) -> Result<bool, String> {
    stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(READ_DEADLINE)))
        .and_then(|()| stream.set_write_timeout(Some(READ_DEADLINE)))
        .map_err(|e| e.to_string())?;
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let raw = proto::read_line(&mut reader)?;
    let now = proto::wall_ms();
    let req = match proto::open(key, &raw, now, None) {
        Ok(r) => r,
        Err(Reject::Malformed(_) | Reject::BadMac | Reject::Stale | Reject::WrongReply) => {
            return Ok(false)
        }
        Err(Reject::Replayed) => return Ok(false),
    };
    if nonces.check(&req.nonce, now).is_err() {
        return Ok(false);
    }
    let answer = match req.msg {
        Msg::Submit { order } => {
            let mut oracle = ConnOracle {
                reader: &mut reader,
                writer: &mut writer,
                key,
                request_nonce: &req.nonce,
                order_id: &order.id,
                nonces,
            };
            let out = engine.submit(&order, &mut oracle, proto::wall_ms());
            Msg::Outcome {
                outcome: Box::new(out),
            }
        }
        Msg::Revert { id, reason } => {
            let reason = format!("revert requested: {}", proto_text(&reason));
            Msg::Outcome {
                outcome: Box::new(if crate::net::id_ok(&id) {
                    engine.revert(&id, &reason, proto::wall_ms())
                } else {
                    bad_id(&id)
                }),
            }
        }
        Msg::Status { id } => Msg::Outcome {
            outcome: Box::new(if crate::net::id_ok(&id) {
                engine.status(&id)
            } else {
                bad_id(&id)
            }),
        },
        Msg::Events { since } => Msg::EventList {
            events: engine.events_since(since, proto::MAX_EVENTS_PER_ANSWER),
        },
        Msg::Ping => Msg::Pong {
            active: engine.state().entries.len(),
            boot_id: boot_id.to_string(),
        },
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
    };
    o.error = Some(format!("bad id {:?}", crate::net::clip(id)));
    o
}

/// Serve until `stop()` is true. `on_tick` runs after every housekeeping
/// pass (watchdog ping).
pub fn serve(
    listener: &UnixListener,
    engine: &mut Engine,
    key: &Key,
    boot_id: &str,
    stop: &dyn Fn() -> bool,
    on_tick: &mut dyn FnMut(&Engine, &ServerStats),
) -> ServerStats {
    let mut stats = ServerStats::default();
    let mut nonces = NonceCache::default();
    let mut next_tick = Instant::now();
    while !stop() {
        match listener.accept() {
            Ok((s, _)) => {
                stats.connections += 1;
                match handle(s, engine, key, &mut nonces, boot_id) {
                    Ok(true) => stats.handled += 1,
                    Ok(false) | Err(_) => stats.rejected += 1,
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
        if Instant::now() >= next_tick {
            engine.tick(proto::wall_ms());
            on_tick(engine, &stats);
            next_tick = Instant::now() + TICK;
        }
    }
    stats
}
