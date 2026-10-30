//! LAN serving over mutual TLS (`docs/SECURE-DELIVERY.md` §4.1 step 6,
//! Sprint 14a; protocol [`robodr_pkg::wire`]).
//!
//! The TLS configuration is `robodr_blackbox::tls`'s server (the depot's
//! certificate from its unit CA; a client certificate chaining to that CA
//! is mandatory; no session resumption). On top of the chain check, the
//! client's key must be **exactly** the TPM-resident identity key of an
//! enrolled, non-revoked, non-erased unit ([`Depot::unit_of_spki`]): that
//! unit, and only that unit, is served. The request carries no unit
//! name, so one unit's connection can never fetch another unit's pack
//! (client confusion), and a report must be signed by the same unit's
//! identity key as the TLS client.
//!
//! Slots: at most `serve.max_connections` connections at once, and at most
//! `serve.max_connections_per_source` from one source address (default 4),
//! so one host cannot take every slot before authenticating. The TLS
//! handshake must complete within [`HANDSHAKE_DEADLINE`] (or `deadline_s`,
//! if shorter); the request head and a report body within
//! [`REQUEST_DEADLINE`] of the accept.

use crate::config::Config;
use crate::depot::Depot;
use crate::{err, DepotError};
use robodr_pkg::wire::{self, PackListing, Request, StreamFile, PACK_STREAM_FORMAT};
use rustls::{ServerConnection, StreamOwned};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The handshake, the request head and a report body must arrive within
/// this (or `serve.deadline_s`, if shorter) in total: a client that
/// trickles bytes cannot hold one of the `max_connections` slots for
/// longer. Streaming a pack is bounded by `deadline_s` per write.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

/// The TLS handshake (before the client is known) must complete within
/// this (or `serve.deadline_s`, if shorter): an unauthenticated peer holds
/// a slot for at most this long.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// Connection slots: at most `max` at once, `per_source` from one address.
#[derive(Clone)]
pub struct Slots {
    inner: Arc<Mutex<SlotCounts>>,
    max: usize,
    per_source: usize,
}

#[derive(Default)]
struct SlotCounts {
    live: usize,
    by_source: HashMap<IpAddr, usize>,
}

/// A taken slot; released when dropped.
pub struct Slot {
    slots: Slots,
    source: IpAddr,
}

impl Slots {
    pub fn new(max: usize, per_source: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SlotCounts::default())),
            max: max.max(1),
            per_source: per_source.max(1),
        }
    }

    /// A slot for a connection from `source`, if one is free.
    pub fn take(&self, source: IpAddr) -> Option<Slot> {
        let mut c = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let from = c.by_source.get(&source).copied().unwrap_or(0);
        if c.live >= self.max || from >= self.per_source {
            return None;
        }
        c.live += 1;
        c.by_source.insert(source, from + 1);
        Some(Slot {
            slots: self.clone(),
            source,
        })
    }

    /// Connections open now.
    pub fn live(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .live
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut c = self
            .slots
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        c.live = c.live.saturating_sub(1);
        if let Some(n) = c.by_source.get_mut(&self.source) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                c.by_source.remove(&self.source);
            }
        }
    }
}

/// The clock the server judges reports and leases on.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The server's TLS configuration from the depot's state directory.
pub fn server_config(cfg: &Config) -> Result<Arc<rustls::ServerConfig>, DepotError> {
    let t = cfg.state_dir.join("tls");
    robodr_blackbox::tls::load_server(&robodr_blackbox::tls::ServerTlsFiles {
        cert_chain: t.join("server.pem"),
        key_file: t.join("server.key"),
        client_ca: Some(t.join("ca.pem")),
        // Revocation is per unit (an enrolled, non-revoked identity key,
        // checked on every request), not by CRL.
        crl_files: Vec::new(),
    })
    .map_err(err)
}

/// Serve until `stop` is set (checked between connections). Each request
/// opens the depot under its lock ([`crate::lock`]) and closes it again,
/// so operators' commands run between requests.
pub fn serve(
    cfg: Config,
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    clock: Clock,
) -> Result<(), DepotError> {
    let s = cfg
        .serve
        .clone()
        .ok_or_else(|| err("no serve configuration"))?;
    let tls = server_config(&cfg)?;
    let deadline = Duration::from_secs(s.deadline_s);
    listener
        .set_nonblocking(true)
        .map_err(|e| err(e.to_string()))?;
    let slots = Slots::new(s.max_connections, s.max_connections_per_source);
    let cfg = Arc::new(cfg);
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((sock, peer)) => {
                let Some(slot) = slots.take(peer.ip()) else {
                    drop(sock);
                    continue;
                };
                let _ = sock.set_nonblocking(false);
                let (c, t, k) = (cfg.clone(), tls.clone(), clock.clone());
                std::thread::spawn(move || {
                    let _slot = slot;
                    let _ = handle(sock, t, &c, deadline, &k);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(err(format!("accept: {e}"))),
        }
    }
    Ok(())
}

/// The client socket with one deadline for everything read from it (the
/// handshake, the request head, a report body): each read waits only for
/// what is left, so trickling bytes does not extend it. Writes keep the
/// socket's own per-write timeout.
pub struct Timed {
    sock: TcpStream,
    until: Instant,
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rest = self
            .until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline passed")
            })?;
        self.sock.set_read_timeout(Some(rest))?;
        self.sock.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sock.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

fn respond(s: &mut impl Write, status: u16, body: &[u8]) -> std::io::Result<()> {
    s.write_all(&wire::encode_response(status, body.len() as u64))?;
    s.write_all(body)?;
    s.flush()
}

fn error_body(e: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"error": e})).unwrap_or_default()
}

/// One connection: handshake, identify the unit, one request.
pub fn handle(
    sock: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    cfg: &Config,
    deadline: Duration,
    clock: &Clock,
) -> Result<(), DepotError> {
    let _ = sock.set_write_timeout(Some(deadline.min(HANDSHAKE_DEADLINE)));
    let conn = ServerConnection::new(tls).map_err(|e| err(e.to_string()))?;
    let start = Instant::now();
    let sock = Timed {
        sock,
        until: start + deadline.min(HANDSHAKE_DEADLINE),
    };
    let mut s = StreamOwned::new(conn, sock);
    // Drive the handshake (short deadline: the client is not known yet).
    while s.conn.is_handshaking() {
        s.conn
            .complete_io(&mut s.sock)
            .map_err(|e| err(format!("TLS handshake: {e}")))?;
    }
    s.sock.until = start + deadline.min(REQUEST_DEADLINE);
    let _ = s.sock.sock.set_write_timeout(Some(deadline));
    let spki = s
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(robodr_blackbox::tls::spki_der)
        .transpose()
        .map_err(err)?
        .ok_or_else(|| err("no client certificate"))?;
    let open = || Depot::open(cfg.clone(), clock());
    let unit = open()?.unit_of_spki(&spki);
    // Read the header block (bounded).
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while wire::head_end(&head).is_none() {
        if head.len() >= wire::MAX_HEAD {
            let _ = respond(&mut s, 400, &error_body("header too large"));
            return Err(err("header too large"));
        }
        match s.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => return Err(err("connection closed before the request")),
        }
    }
    let Some(unit) = unit else {
        let _ = respond(
            &mut s,
            403,
            &error_body("this client key is not an enrolled unit's identity key"),
        );
        return Err(err("unknown client"));
    };
    let req = match wire::parse_request(&head) {
        Ok(r) => r,
        Err(e) => {
            let _ = respond(&mut s, 400, &error_body(&e.to_string()));
            return Err(err(e.to_string()));
        }
    };
    match req {
        Request::Pack => {
            let files = open().and_then(|d| d.pack_files(&unit));
            let files = match files {
                Ok(f) => f,
                Err(e) => {
                    let _ = respond(&mut s, 404, &error_body(&e.0));
                    return Err(e);
                }
            };
            stream_pack(&mut s, &files)
        }
        Request::Report(n) => {
            let mut body = vec![0u8; n];
            s.read_exact(&mut body).map_err(|e| err(e.to_string()))?;
            let r = open().and_then(|mut d| d.accept_report(Some(&unit), &body, clock()));
            match r {
                Ok(lease) => {
                    let b = serde_json::to_vec(&serde_json::json!({ "lease": lease }))
                        .unwrap_or_default();
                    respond(&mut s, 200, &b).map_err(|e| err(e.to_string()))
                }
                Err(e) => {
                    let _ = respond(&mut s, 409, &error_body(&e.0));
                    Err(e)
                }
            }
        }
    }
}

fn stream_pack(s: &mut impl Write, files: &[(String, PathBuf)]) -> Result<(), DepotError> {
    let mut listing = PackListing {
        format: PACK_STREAM_FORMAT.into(),
        files: Vec::with_capacity(files.len()),
    };
    for (rel, p) in files {
        let (size, sha256) = robodr_release::fsio::hash_file(p).map_err(|e| err(e.to_string()))?;
        listing.files.push(StreamFile {
            path: rel.clone(),
            size,
            sha256,
        });
    }
    listing.files.sort_by(|a, b| a.path.cmp(&b.path));
    let total = listing.validate().map_err(|e| err(e.to_string()))?;
    let line = robodr_pkg::common::to_canonical(&listing).map_err(|e| err(e.to_string()))?;
    s.write_all(&wire::encode_response(200, line.len() as u64 + 1 + total))
        .and_then(|()| s.write_all(&line))
        .and_then(|()| s.write_all(b"\n"))
        .map_err(|e| err(e.to_string()))?;
    let by_path: std::collections::BTreeMap<&str, &PathBuf> =
        files.iter().map(|(r, p)| (r.as_str(), p)).collect();
    for f in &listing.files {
        let p = by_path.get(f.path.as_str()).ok_or_else(|| err("listing"))?;
        let mut h = std::fs::File::open(p).map_err(|e| err(e.to_string()))?;
        let n = std::io::copy(&mut (&mut h).take(f.size), s).map_err(|e| err(e.to_string()))?;
        if n != f.size {
            return Err(err(format!("{} changed while serving", f.path)));
        }
    }
    s.flush().map_err(|e| err(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn idle(port: u16) -> TcpStream {
        let c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        c
    }

    /// `true` once the server closed `c` (EOF / reset), `false` if it is
    /// still open after `wait`.
    fn closed_within(c: &mut TcpStream, wait: Duration) -> bool {
        let t0 = Instant::now();
        let mut b = [0u8; 16];
        while t0.elapsed() < wait {
            match c.read(&mut b) {
                Ok(0) => return true,
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return true,
            }
        }
        false
    }

    /// Review (TLS, finding 4): one source address cannot take every slot
    /// before authenticating (per-source cap), and a peer that never
    /// completes the handshake is cut at the short handshake deadline, not
    /// at the request deadline.
    #[test]
    fn one_source_cannot_hold_every_slot_before_the_handshake() {
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tls");
        let d = std::env::temp_dir().join(format!("robodr-depot-slots-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("tls")).unwrap();
        for (from, mode) in [
            ("server.pem", 0o644),
            ("server.key", 0o600),
            ("ca.pem", 0o644),
        ] {
            let to = d.join("tls").join(from);
            std::fs::copy(fx.join(from), &to).unwrap();
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let mut v: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../config/depot.example.json")).unwrap();
        v["state_dir"] = d.to_str().unwrap().into();
        v["serve"]["deadline_s"] = 600.into();
        v["serve"]["max_connections"] = 16.into();
        v["serve"]
            .as_object_mut()
            .unwrap()
            .remove("max_connections_per_source");
        let cfg = Config::parse(&serde_json::to_vec(&v).unwrap()).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let th = std::thread::spawn(move || serve(cfg, l, s2, Arc::new(|| 0)));
        // The default per-source cap (4) is taken by idle peers ...
        let mut held: Vec<TcpStream> = (0..4).map(|_| idle(port)).collect();
        std::thread::sleep(Duration::from_millis(300));
        // ... so a fifth connection from the same address is closed at once.
        let mut fifth = idle(port);
        assert!(closed_within(&mut fifth, Duration::from_secs(3)));
        // The held ones are cut at the handshake deadline (10 s), well
        // before the 30 s request deadline.
        let t0 = Instant::now();
        let first = held.first_mut().unwrap();
        assert!(closed_within(first, Duration::from_secs(20)));
        let after = t0.elapsed();
        assert!(
            after < HANDSHAKE_DEADLINE + Duration::from_secs(3),
            "{after:?}"
        );
        stop.store(true, Ordering::SeqCst);
        th.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn slots_are_bounded_in_all_and_per_source() {
        let s = Slots::new(3, 2);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let a1 = s.take(a).unwrap();
        let _a2 = s.take(a).unwrap();
        assert!(s.take(a).is_none());
        let _b1 = s.take(b).unwrap();
        assert!(s.take(b).is_none(), "all slots taken");
        drop(a1);
        assert_eq!(s.live(), 2);
        assert!(s.take(a).is_some());
    }
}
