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
//! Connection admission (red team 2026-10-30, W2-4;
//! [`robodr_blackbox::admission`]): `max_connections` slots before the
//! handshake identified an enrolled unit, where a newcomer evicts the
//! connection with the least handshake progress instead of being refused
//! and a ClientHello must arrive within the hello timeout (then keep a
//! bytes/s floor), and as many slots after it, which only enrolled units
//! occupy: trickling handshakes cannot keep units from fetching their
//! packs.

use crate::config::Config;
use crate::depot::Depot;
use crate::{err, DepotError};
use robodr_pkg::wire::{self, PackListing, Request, StreamFile, PACK_STREAM_FORMAT};
use rustls::{ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The handshake, the request head and a report body must arrive within
/// this (or `serve.deadline_s`, if shorter) in total: a client that
/// trickles bytes cannot hold one of the `max_connections` slots for
/// longer. Streaming a pack is bounded by `deadline_s` per write.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

/// The clock the server judges reports and leases on.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The server's TLS configuration from the depot's state directory.
pub fn server_config(cfg: &Config) -> Result<Arc<rustls::ServerConfig>, DepotError> {
    let t = cfg.state_dir.join("tls");
    robodr_blackbox::tls::load_server(&robodr_blackbox::tls::ServerTlsFiles {
        cert_chain: t.join("server.pem"),
        key_file: t.join("server.key"),
        client_ca: Some(t.join("ca.pem")),
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
    let admission = robodr_blackbox::admission::Admission::new(s.admission().map_err(err)?);
    listener
        .set_nonblocking(true)
        .map_err(|e| err(e.to_string()))?;
    let cfg = Arc::new(cfg);
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((sock, peer)) => {
                let seen = {
                    let mut b = [0u8; 2048];
                    let _ = sock.set_nonblocking(true);
                    sock.peek(&mut b).unwrap_or(0)
                };
                let Ok(mut ticket) = admission.admit_seen(peer.ip(), sock.try_clone().ok(), seen)
                else {
                    drop(sock);
                    continue;
                };
                let _ = sock.set_nonblocking(false);
                let (c, t, k) = (cfg.clone(), tls.clone(), clock.clone());
                std::thread::spawn(move || {
                    let _ = handle(sock, t, &c, deadline, &k, Some(&mut ticket));
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
///
/// With a progress tracker (a pre-authentication connection, W2-4) its
/// deadline applies too, and bytes read and written are reported to it.
pub struct Timed {
    sock: TcpStream,
    until: Instant,
    progress: Option<Arc<robodr_blackbox::admission::Progress>>,
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let now = Instant::now();
        let mut until = self.until;
        if let Some(p) = &self.progress {
            if let Some(d) = p.check(now)? {
                until = until.min(d);
            }
        }
        let rest = until
            .checked_duration_since(now)
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline passed")
            })?;
        self.sock.set_read_timeout(Some(rest))?;
        match self.sock.read(buf) {
            Ok(n) => {
                if let Some(p) = &self.progress {
                    p.on_read(n);
                }
                Ok(n)
            }
            Err(e) => {
                if let Some(p) = &self.progress {
                    p.check(Instant::now())?;
                }
                Err(e)
            }
        }
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.sock.write(buf)?;
        if n > 0 {
            if let Some(p) = &self.progress {
                p.on_write();
            }
        }
        Ok(n)
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

/// One connection: handshake, identify the unit, one request. With an
/// admission `ticket` (the server's), the handshake runs under its
/// progress deadline and an enrolled unit's connection moves to the
/// authenticated pool.
pub fn handle(
    sock: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    cfg: &Config,
    deadline: Duration,
    clock: &Clock,
    ticket: Option<&mut robodr_blackbox::admission::Ticket>,
) -> Result<(), DepotError> {
    let _ = sock.set_write_timeout(Some(deadline));
    let conn = ServerConnection::new(tls).map_err(|e| err(e.to_string()))?;
    let sock = Timed {
        sock,
        until: Instant::now() + deadline.min(REQUEST_DEADLINE),
        progress: ticket.as_ref().map(|t| t.progress()),
    };
    let mut s = StreamOwned::new(conn, sock);
    // Drive the handshake.
    while s.conn.is_handshaking() {
        s.conn
            .complete_io(&mut s.sock)
            .map_err(|e| err(format!("TLS handshake: {e}")))?;
    }
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
    // An enrolled unit's identity key: an authenticated slot, which no
    // pre-authentication connection can take (full: it keeps its
    // pre-authentication one, under the progress deadline).
    if let (Some(t), Some(_)) = (ticket, &unit) {
        t.promote();
    }
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
