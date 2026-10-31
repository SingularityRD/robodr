//! The remote head anchor over TLS (`robodr_blackbox::tls`): a client
//! [`RemoteHeadAnchor`] against an in-process [`AnchorReceiver::serve`] on
//! 127.0.0.1, with the test PKI of `fixtures/tls/` (`gen.sh` there).
//!
//! Positive: TLS and mutual TLS round trips, a `server_name` override, SPKI
//! pins. Negative / adversarial: plain TCP refused on both sides unless
//! explicitly allowed; an untrusted CA, a wrong host name, an expired
//! certificate, a certificate without `serverAuth`, a pin mismatch; a
//! missing or foreign client certificate; a downgrade in both directions
//! (TLS client to a plain receiver, plain client to a TLS receiver); a
//! revoked receiver or unit certificate (`crl_files`). In every refused
//! case the receiver holds nothing.

mod common;

use common::TestDir;
use robodr_blackbox::export::Checkpoint;
use robodr_blackbox::record::signing_message;
use robodr_blackbox::remote_anchor::{
    AnchorReceiver, RemoteAnchorConfig, RemoteHeadAnchor, ServeOptions, UnitKey,
};
use robodr_blackbox::tls::{self, ClientTls, ClientTlsFiles, ServerTlsFiles};
use robodr_blackbox::{Ed25519SigningKey, HeadAnchor, Signer};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const UNIT: &str = "ugv-07";

/// A private copy of `fixtures/tls/` with key files 0600 (git keeps 0644).
struct Pki(TestDir);

impl Pki {
    fn new() -> Self {
        let d = TestDir::new("tls-pki");
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tls");
        for e in std::fs::read_dir(&src).unwrap() {
            let e = e.unwrap();
            let name = e.file_name().into_string().unwrap();
            if !(name.ends_with(".pem") || name.ends_with(".key")) {
                continue;
            }
            let to = d.sub(&name);
            std::fs::copy(e.path(), &to).unwrap();
            let mode = if name.ends_with(".key") { 0o600 } else { 0o644 };
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        Pki(d)
    }
    fn p(&self, n: &str) -> PathBuf {
        self.0.sub(n)
    }
    fn server(&self, leaf: &str, client_ca: Option<&str>) -> Arc<rustls::ServerConfig> {
        tls::load_server(&ServerTlsFiles {
            cert_chain: self.p(&format!("{leaf}.pem")),
            key_file: self.p(&format!("{leaf}.key")),
            client_ca: client_ca.map(|c| self.p(c)),
            crl_files: Vec::new(),
        })
        .unwrap()
    }
    fn client(
        &self,
        ca: &str,
        cert: Option<&str>,
        name: Option<&str>,
        pins: &[String],
    ) -> ClientTls {
        tls::load_client(&ClientTlsFiles {
            ca_file: self.p(ca),
            cert_chain: cert.map(|c| self.p(&format!("{c}.pem"))),
            key_file: cert.map(|c| self.p(&format!("{c}.key"))),
            server_name: name.map(str::to_string),
            spki_sha256: pins.to_vec(),
            crl_files: Vec::new(),
        })
        .unwrap()
    }
    fn pin_of(&self, leaf: &str) -> String {
        let c = CertificateDer::from_pem_file(self.p(&format!("{leaf}.pem"))).unwrap();
        robodr_blackbox::crypto::to_hex(&tls::spki_sha256(&c).unwrap())
    }
}

fn unit_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed("unit-bb", &[7; 32]).unwrap()
}
fn receiver_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed("receiver", &[9; 32]).unwrap()
}

fn cp(seq: u64) -> Checkpoint {
    let hash = [seq as u8; 32];
    Checkpoint {
        chain_id: [3; 32],
        seq,
        hash,
        key_id: "unit-bb".into(),
        sig: unit_key().sign(&signing_message(&hash)).unwrap(),
    }
}

struct Srv {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    recv: Arc<AnchorReceiver>,
    th: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    _d: TestDir,
}

impl Drop for Srv {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.th.take() {
            let _ = t.join();
        }
    }
}

fn serve(tls: Option<Arc<rustls::ServerConfig>>, allow_plaintext: bool) -> Srv {
    serve_at("127.0.0.1:0", tls, allow_plaintext)
}

fn serve_at(bind: &str, tls: Option<Arc<rustls::ServerConfig>>, allow_plaintext: bool) -> Srv {
    serve_with(
        bind,
        ServeOptions {
            max_connections: 8,
            io_timeout: Duration::from_millis(1500),
            tls,
            allow_plaintext,
            ..ServeOptions::default()
        },
    )
}

fn serve_with(bind: &str, opts: ServeOptions) -> Srv {
    let d = TestDir::new("tls-recv");
    let recv = Arc::new(
        AnchorReceiver::open(
            d.path(),
            vec![UnitKey {
                unit: UNIT.into(),
                verifier: Box::new(unit_key().verifying_key()),
            }],
            Box::new(receiver_key()),
            Some(Box::new(|_: &str| {})),
        )
        .unwrap(),
    );
    let l = TcpListener::bind(bind).unwrap();
    let addr = l.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (r2, s2) = (Arc::clone(&recv), Arc::clone(&stop));
    let th = std::thread::spawn(move || r2.serve(l, &opts, &s2));
    Srv {
        addr,
        stop,
        recv,
        th: Some(th),
        _d: d,
    }
}

fn anchor(
    addr: &SocketAddr,
    tls: Option<ClientTls>,
    allow_plaintext: bool,
) -> Result<RemoteHeadAnchor, robodr_blackbox::Error> {
    let mut c = RemoteAnchorConfig::new(addr.to_string(), UNIT);
    c.timeout = Duration::from_millis(1500);
    c.tls = tls;
    c.allow_plaintext = allow_plaintext;
    RemoteHeadAnchor::new(
        c,
        Box::new(receiver_key().verifying_key()),
        Box::new(unit_key()),
    )
}

/// Advance to seq 5 and query: `Ok(held seq)` or the first error.
fn round_trip(a: &RemoteHeadAnchor) -> Result<Option<u64>, String> {
    a.advance(&cp(5))?;
    a.flush(Duration::from_secs(3));
    if a.delivered_seq() != Some(5) {
        // Report the delivery error the next advance carries.
        a.advance(&cp(6))?;
        return Err("mark not delivered".into());
    }
    a.current().map(|h| h.map(|h| h.seq))
}

/// The receiver was never touched: no mark held.
fn untouched(s: &Srv) {
    assert!(s.recv.held(UNIT).is_none(), "receiver holds a mark");
}

#[test]
fn tls_and_mutual_tls_round_trips() {
    let pki = Pki::new();
    // Server-authenticated TLS.
    let s = serve(Some(pki.server("server", None)), false);
    let a = anchor(&s.addr, Some(pki.client("ca.pem", None, None, &[])), false).unwrap();
    assert_eq!(round_trip(&a), Ok(Some(5)));
    assert_eq!(s.recv.held(UNIT).map(|m| m.seq), Some(5));
    drop(a);
    // Mutual TLS.
    let s = serve(Some(pki.server("server", Some("ca.pem"))), false);
    let a = anchor(
        &s.addr,
        Some(pki.client("ca.pem", Some("client"), None, &[])),
        false,
    )
    .unwrap();
    assert_eq!(round_trip(&a), Ok(Some(5)));
    assert_eq!(a.delivery_failures(), 0);
    // IPv6 loopback and host name `localhost`: the name verified is the
    // address's host (SAN DNS:localhost, IP:::1).
    if TcpListener::bind("[::1]:0").is_ok() {
        let s6 = serve_at("[::1]:0", Some(pki.server("server", None)), false);
        let a = anchor(&s6.addr, Some(pki.client("ca.pem", None, None, &[])), false).unwrap();
        assert_eq!(round_trip(&a), Ok(Some(5)));
    }
    let a = {
        let mut c = RemoteAnchorConfig::new(format!("localhost:{}", s.addr.port()), UNIT);
        c.tls = Some(pki.client("ca.pem", Some("client"), None, &[]));
        RemoteHeadAnchor::new(
            c,
            Box::new(receiver_key().verifying_key()),
            Box::new(unit_key()),
        )
        .unwrap()
    };
    assert_eq!(a.current().map(|h| h.map(|h| h.seq)), Ok(Some(5)));
}

#[test]
fn plain_tcp_is_refused_on_both_sides_unless_explicitly_allowed() {
    let s = serve(None, true);
    // Client: no TLS and plain TCP not allowed.
    let e = anchor(&s.addr, None, false).unwrap_err().to_string();
    assert!(e.contains("plain TCP"), "{e}");
    // The default configuration is the refusing one.
    let c = RemoteAnchorConfig::new(s.addr.to_string(), UNIT);
    assert!(c.tls.is_none() && !c.allow_plaintext);
    // Receiver: serve() without TLS and without allow_plaintext.
    let d = TestDir::new("tls-recv-refuse");
    let r = AnchorReceiver::open(
        d.path(),
        vec![UnitKey {
            unit: UNIT.into(),
            verifier: Box::new(unit_key().verifying_key()),
        }],
        Box::new(receiver_key()),
        Some(Box::new(|_: &str| {})),
    )
    .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let e = Arc::new(r)
        .serve(l, &ServeOptions::default(), &AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    // Explicitly allowed (lab): works.
    let a = anchor(&s.addr, None, true).unwrap();
    assert_eq!(round_trip(&a), Ok(Some(5)));
}

#[test]
fn bad_server_certificates_are_refused() {
    let pki = Pki::new();
    for (leaf, why) in [
        ("other-server", "unknown issuer"),
        ("wrong-host", "wrong host name"),
        ("expired", "expired"),
        ("client-only", "no serverAuth EKU"),
    ] {
        let s = serve(Some(pki.server(leaf, None)), false);
        let a = anchor(&s.addr, Some(pki.client("ca.pem", None, None, &[])), false).unwrap();
        let e = a.current().unwrap_err();
        assert!(e.contains("certificate"), "{why}: {e}");
        let r = round_trip(&a);
        assert!(r.is_err(), "{why}: {r:?}");
        assert!(a.delivery_failures() > 0, "{why}");
        untouched(&s);
    }
    // Trusting only the unrelated CA refuses the genuine server too.
    let s = serve(Some(pki.server("server", None)), false);
    let a = anchor(
        &s.addr,
        Some(pki.client("other-ca.pem", None, None, &[])),
        false,
    )
    .unwrap();
    assert!(a.current().is_err());
    untouched(&s);
}

#[test]
fn server_name_override_is_the_name_verified() {
    let pki = Pki::new();
    let s = serve(Some(pki.server("wrong-host", None)), false);
    let ok = anchor(
        &s.addr,
        Some(pki.client("ca.pem", None, Some("wrong.example"), &[])),
        false,
    )
    .unwrap();
    assert_eq!(round_trip(&ok), Ok(Some(5)));
    let s = serve(Some(pki.server("wrong-host", None)), false);
    let bad = anchor(
        &s.addr,
        Some(pki.client("ca.pem", None, Some("other.example"), &[])),
        false,
    )
    .unwrap();
    assert!(bad.current().is_err());
    untouched(&s);
}

#[test]
fn spki_pins_are_checked_in_addition_to_the_chain() {
    let pki = Pki::new();
    let s = serve(Some(pki.server("server", None)), false);
    let good = pki.pin_of("server");
    let a = anchor(
        &s.addr,
        Some(pki.client("ca.pem", None, None, std::slice::from_ref(&good))),
        false,
    )
    .unwrap();
    assert_eq!(round_trip(&a), Ok(Some(5)));
    let s = serve(Some(pki.server("server", None)), false);
    let a = anchor(
        &s.addr,
        Some(pki.client("ca.pem", None, None, &[pki.pin_of("wrong-host")])),
        false,
    )
    .unwrap();
    let e = a.current().unwrap_err();
    assert!(e.contains("pin"), "{e}");
    untouched(&s);
    // A pin never replaces the chain: the unrelated CA's server with its own
    // pin is still refused.
    let s = serve(Some(pki.server("other-server", None)), false);
    let a = anchor(
        &s.addr,
        Some(pki.client("ca.pem", None, None, &[pki.pin_of("other-server")])),
        false,
    )
    .unwrap();
    assert!(a.current().is_err());
    untouched(&s);
    assert!(tls::load_client(&ClientTlsFiles {
        ca_file: pki.p("ca.pem"),
        spki_sha256: vec!["00".into()],
        ..Default::default()
    })
    .is_err());
}

#[test]
fn mutual_tls_refuses_missing_and_foreign_client_certificates() {
    let pki = Pki::new();
    for cert in [None, Some("other-client")] {
        let s = serve(Some(pki.server("server", Some("ca.pem"))), false);
        let a = anchor(&s.addr, Some(pki.client("ca.pem", cert, None, &[])), false).unwrap();
        assert!(a.current().is_err(), "{cert:?}");
        assert!(round_trip(&a).is_err(), "{cert:?}");
        untouched(&s);
    }
    // Half a client identity is a configuration error.
    assert!(tls::load_client(&ClientTlsFiles {
        ca_file: pki.p("ca.pem"),
        cert_chain: Some(pki.p("client.pem")),
        ..Default::default()
    })
    .is_err());
}

#[test]
fn no_downgrade_in_either_direction() {
    let pki = Pki::new();
    // A TLS client never falls back to plain TCP (a stripping
    // man-in-the-middle, or a receiver misconfigured to plain TCP).
    let plain = serve(None, true);
    let a = anchor(
        &plain.addr,
        Some(pki.client("ca.pem", None, None, &[])),
        false,
    )
    .unwrap();
    assert!(a.current().is_err());
    assert!(round_trip(&a).is_err());
    untouched(&plain);
    // A plain client never reaches a TLS receiver's request parser.
    let s = serve(Some(pki.server("server", None)), false);
    let a = anchor(&s.addr, None, true).unwrap();
    assert!(a.current().is_err());
    assert!(round_trip(&a).is_err());
    untouched(&s);
    assert!(s.recv.tls_handshake_failures() >= 2);
}

#[test]
fn file_checks() {
    let pki = Pki::new();
    let files = |key: &str| ServerTlsFiles {
        cert_chain: pki.p("server.pem"),
        key_file: pki.p(key),
        client_ca: None,
        crl_files: Vec::new(),
    };
    std::fs::set_permissions(pki.p("server.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let e = tls::load_server(&files("server.key")).unwrap_err();
    assert!(e.contains("mode 644"), "{e}");
    std::fs::set_permissions(pki.p("server.key"), std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(tls::load_server(&files("server.key")).is_err());
    std::fs::set_permissions(pki.p("server.key"), std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(tls::load_server(&files("server.key")).is_ok());
    // A certificate where the key belongs, a key that does not match.
    std::fs::set_permissions(pki.p("server.pem"), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(tls::load_server(&files("server.pem")).is_err());
    assert!(tls::load_server(&files("client.key")).is_err());
    // A CA file without a certificate, a missing file, a directory.
    assert!(tls::load_client(&ClientTlsFiles {
        ca_file: pki.p("client.key"),
        ..Default::default()
    })
    .is_err());
    assert!(tls::load_client(&ClientTlsFiles {
        ca_file: pki.p("missing.pem"),
        ..Default::default()
    })
    .is_err());
    assert!(tls::load_client(&ClientTlsFiles {
        ca_file: pki.0.path().to_path_buf(),
        ..Default::default()
    })
    .is_err());
    // A FIFO where a file belongs is refused without blocking on open.
    let fifo = pki.p("fifo.pem");
    if std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|s| s.success())
    {
        let t = std::time::Instant::now();
        let e = tls::load_client(&ClientTlsFiles {
            ca_file: fifo,
            ..Default::default()
        })
        .unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(2));
    }
}

// --- Review of the TLS work: deadlines over the whole handshake ------------

/// Send a TLS handshake record header announcing 16 KiB, then one byte every
/// `gap`, until stopped or the peer closes: a handshake that never ends but
/// never lets a single read time out.
fn trickle(mut s: TcpStream, gap: Duration, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if s.write_all(&[0x16, 0x03, 0x01, 0x40, 0x00]).is_err() {
            return;
        }
        for _ in 0..16_000 {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(gap);
            if s.write_all(&[0x01]).is_err() {
                return;
            }
        }
    })
}

/// Is the peer's side of `s` still open (no EOF / reset within 50 ms)?
fn still_open(s: &TcpStream) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let mut b = [0u8; 64];
    loop {
        match (&*s).read(&mut b) {
            Ok(0) => return false,
            Ok(_) => continue,
            Err(e) => {
                return matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                )
            }
        }
    }
}

/// Review F1: a peer without a certificate that trickles its handshake held
/// a receiver slot forever (the socket timeout was armed once, rustls loops
/// over reads); two of them locked out every unit. `io_timeout` now bounds
/// the whole connection, handshake included.
#[test]
fn receiver_cuts_a_trickled_handshake_at_io_timeout() {
    let pki = Pki::new();
    let io_timeout = Duration::from_millis(500);
    let s = serve_with(
        "127.0.0.1:0",
        ServeOptions {
            max_connections: 2,
            io_timeout,
            tls: Some(pki.server("server", Some("ca.pem"))),
            ..ServeOptions::default()
        },
    );
    let stop = Arc::new(AtomicBool::new(false));
    let mut probes = vec![];
    let mut atk = vec![];
    for _ in 0..2 {
        let c = TcpStream::connect(s.addr).unwrap();
        probes.push(c.try_clone().unwrap());
        atk.push(trickle(c, Duration::from_millis(100), Arc::clone(&stop)));
    }
    std::thread::sleep(io_timeout * 4);
    for p in &probes {
        assert!(!still_open(p), "the trickled handshake outlived io_timeout");
    }
    stop.store(true, Ordering::SeqCst);
    for t in atk {
        let _ = t.join();
    }
    let a = anchor(
        &s.addr,
        Some(pki.client("ca.pem", Some("client"), None, &[])),
        false,
    )
    .unwrap();
    assert_eq!(round_trip(&a), Ok(Some(5)));
}

/// Review F2: an on-path peer that trickles the receiver's side of the
/// handshake stalled the unit's delivery thread forever, with no anchor
/// failure ever counted. Each exchange is now bounded as a whole.
#[test]
fn a_stalled_handshake_is_an_anchor_failure_not_a_silent_hang() {
    let pki = Pki::new();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let mitm = std::thread::spawn(move || {
        l.set_nonblocking(true).unwrap();
        let mut held = vec![];
        while !s2.load(Ordering::SeqCst) {
            if let Ok((mut c, _)) = l.accept() {
                c.set_nonblocking(false).unwrap();
                let mut b = [0u8; 4096];
                let _ = c.read(&mut b); // ClientHello
                held.push(trickle(c, Duration::from_millis(100), Arc::clone(&s2)));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        for h in held {
            let _ = h.join();
        }
    });
    let timeout = Duration::from_millis(300);
    let mut c = RemoteAnchorConfig::new(addr.to_string(), UNIT);
    c.timeout = timeout;
    c.tls = Some(pki.client("ca.pem", None, None, &[]));
    let a = RemoteHeadAnchor::new(
        c,
        Box::new(receiver_key().verifying_key()),
        Box::new(unit_key()),
    )
    .unwrap();
    let t0 = Instant::now();
    assert!(a.current().is_err());
    assert!(
        t0.elapsed() < timeout * 6,
        "current took {:?}",
        t0.elapsed()
    );
    let mut errs = 0;
    for seq in 1..=8u64 {
        if a.advance(&cp(seq)).is_err() {
            errs += 1;
        }
        std::thread::sleep(timeout * 2);
    }
    assert!(errs > 0, "no advance reported the stalled delivery");
    assert!(a.delivery_failures() > 0);
    assert_eq!(a.delivered_seq(), None);
    let t1 = Instant::now();
    drop(a);
    assert!(t1.elapsed() < timeout * 8, "drop waited {:?}", t1.elapsed());
    stop.store(true, Ordering::SeqCst);
    let _ = mitm.join();
}

/// Review F1 (second half): one source address cannot take every slot,
/// before or after authenticating.
#[test]
fn one_source_cannot_hold_every_slot() {
    let pki = Pki::new();
    let s = serve_with(
        "127.0.0.1:0",
        ServeOptions {
            max_connections: 8,
            io_timeout: Duration::from_secs(3),
            tls: Some(pki.server("server", None)),
            max_connections_per_source: 2,
            ..ServeOptions::default()
        },
    );
    let held: Vec<TcpStream> = (0..2)
        .map(|_| TcpStream::connect(s.addr).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let third = TcpStream::connect(s.addr).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !still_open(&third),
        "a third connection from one source was served"
    );
    for h in &held {
        assert!(still_open(h));
    }
    drop(held);
    std::thread::sleep(Duration::from_millis(200));
    let a = anchor(&s.addr, Some(pki.client("ca.pem", None, None, &[])), false).unwrap();
    assert_eq!(round_trip(&a), Ok(Some(5)));
}

/// Review F5: key, CA and password files must be owned by root or the
/// effective user (a file another account owns could be swapped by it).
#[test]
fn files_owned_by_another_account_are_refused() {
    use std::os::unix::fs::MetadataExt;
    let pki = Pki::new();
    let me = std::fs::metadata(pki.p("ca.pem")).unwrap().uid();
    if me != 0 {
        // chown needs root; the rule is exercised in privileged CI only.
        return;
    }
    for f in ["ca.pem", "server.key"] {
        let st = std::process::Command::new("chown")
            .arg("4242")
            .arg(pki.p(f))
            .status()
            .unwrap();
        assert!(st.success());
    }
    let e = tls::load_client(&ClientTlsFiles {
        ca_file: pki.p("ca.pem"),
        ..Default::default()
    })
    .unwrap_err();
    assert!(e.contains("owned by uid 4242"), "{e}");
    let e = tls::load_server(&ServerTlsFiles {
        cert_chain: pki.p("server.pem"),
        key_file: pki.p("server.key"),
        client_ca: None,
        crl_files: Vec::new(),
    })
    .unwrap_err();
    assert!(e.contains("owned by uid 4242"), "{e}");
}

#[test]
fn crl_files_refuse_a_revoked_receiver_and_a_revoked_unit() {
    let pki = Pki::new();
    let crl = vec![pki.p("crl-ca.crl.pem")];
    let client = |cert: Option<&str>| {
        tls::load_client(&ClientTlsFiles {
            ca_file: pki.p("crl-ca.pem"),
            cert_chain: cert.map(|c| pki.p(&format!("{c}.pem"))),
            key_file: cert.map(|c| pki.p(&format!("{c}.key"))),
            crl_files: crl.clone(),
            ..ClientTlsFiles::default()
        })
        .unwrap()
    };
    let server = |leaf: &str, mutual: bool| {
        tls::load_server_tls(&ServerTlsFiles {
            cert_chain: pki.p(&format!("{leaf}.pem")),
            key_file: pki.p(&format!("{leaf}.key")),
            client_ca: mutual.then(|| pki.p("crl-ca.pem")),
            crl_files: if mutual { crl.clone() } else { Vec::new() },
        })
        .unwrap()
    };
    // The unit refuses a revoked receiver certificate, and counts it.
    let s = serve(Some(server("crl-revoked-server", false).config), false);
    let t = client(None);
    let stats = t.crl.clone().unwrap();
    let a = anchor(&s.addr, Some(t), false).unwrap();
    let e = a.current().unwrap_err();
    assert!(e.contains("Revoked"), "{e}");
    assert!(round_trip(&a).is_err());
    untouched(&s);
    assert!(stats.status().revoked_rejections >= 1);
    // The unrevoked receiver of the same CA is accepted.
    let s = serve(Some(server("crl-server", false).config), false);
    let a = anchor(&s.addr, Some(client(None)), false).unwrap();
    assert_eq!(round_trip(&a), Ok(Some(5)));
    // The receiver refuses a revoked unit certificate (mutual TLS) ...
    let srv = server("crl-server", true);
    let rstats = srv.crl.clone().unwrap();
    let s = serve(Some(srv.config.clone()), false);
    let a = anchor(&s.addr, Some(client(Some("crl-revoked-client"))), false).unwrap();
    assert!(round_trip(&a).is_err());
    untouched(&s);
    assert!(rstats.status().revoked_rejections >= 1);
    assert!(s.recv.tls_handshake_failures() >= 1);
    // ... and serves its unrevoked sibling.
    let a = anchor(&s.addr, Some(client(Some("crl-client"))), false).unwrap();
    assert_eq!(round_trip(&a), Ok(Some(5)));
    // CRLs of client certificates need a client CA.
    let e = tls::load_server(&ServerTlsFiles {
        cert_chain: pki.p("crl-server.pem"),
        key_file: pki.p("crl-server.key"),
        client_ca: None,
        crl_files: crl.clone(),
    })
    .unwrap_err();
    assert!(e.contains("client_ca"), "{e}");
    // A file without a CRL is a configuration error.
    let e = tls::load_client(&ClientTlsFiles {
        ca_file: pki.p("crl-ca.pem"),
        crl_files: vec![pki.p("crl-ca.pem")],
        ..ClientTlsFiles::default()
    })
    .unwrap_err();
    assert!(e.contains("no X509 CRL"), "{e}");
}

/// Review (TLS, finding 3): with client bindings, a unit certificate of
/// the same unit CA can no longer read another unit's head over mutual
/// TLS; the bound client still can, and marks keep their signature model.
#[test]
fn current_queries_are_bound_to_the_client_certificate() {
    let pki = Pki::new();
    let d = TestDir::new("tls-recv-bind");
    let recv = AnchorReceiver::open(
        d.path(),
        vec![UnitKey {
            unit: UNIT.into(),
            verifier: Box::new(unit_key().verifying_key()),
        }],
        Box::new(receiver_key()),
        Some(Box::new(|_: &str| {})),
    )
    .unwrap();
    let pin = |leaf: &str| {
        let c = CertificateDer::from_pem_file(pki.p(&format!("{leaf}.pem"))).unwrap();
        tls::spki_sha256(&c).unwrap()
    };
    recv.set_client_bindings(&[(UNIT.to_string(), pin("crl-client"))])
        .unwrap();
    assert!(recv.unbound_units().is_empty());
    let recv = Arc::new(recv);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (r2, s2) = (Arc::clone(&recv), Arc::clone(&stop));
    let opts = ServeOptions {
        max_connections: 8,
        io_timeout: Duration::from_millis(1500),
        tls: Some(pki.server("server", Some("crl-ca.pem"))),
        ..ServeOptions::default()
    };
    let th = std::thread::spawn(move || r2.serve(l, &opts, &s2));
    // Another unit's certificate (same CA, not bound to UNIT): its marks
    // are accepted (they verify under UNIT's key) but it cannot read
    // UNIT's head.
    let other = anchor(
        &addr,
        Some(pki.client("ca.pem", Some("crl-revoked-client"), None, &[])),
        false,
    )
    .unwrap();
    other.advance(&cp(5)).unwrap();
    assert!(other.flush(Duration::from_secs(3)));
    assert_eq!(recv.held(UNIT).map(|m| m.seq), Some(5));
    let e = other.current().unwrap_err();
    assert!(e.contains("not bound"), "{e}");
    // The unit's own certificate reads it.
    let own = anchor(
        &addr,
        Some(pki.client("ca.pem", Some("crl-client"), None, &[])),
        false,
    )
    .unwrap();
    assert_eq!(own.current().map(|h| h.map(|h| h.seq)), Ok(Some(5)));
    stop.store(true, Ordering::SeqCst);
    let _ = th.join();
}
