//! `robodr-uplink` over real TLS: an in-process HTTPS server (rustls,
//! test certificates under `tests/data/uplink-tls/`) in front of the
//! reference consumer (`tests/common/ingest.rs`).
//!
//! The test PKI (EC P-256, valid 2000-01-01 .. 2125-01-01) was made with
//! OpenSSL 3.0 (`openssl ca -selfsign` for the CA, `openssl ca` for the
//! leaf; leaf SAN `DNS:localhost, IP:127.0.0.1, IP:::1`, EKU serverAuth).
//! `other-ca.pem` / `other-server.*` are an unrelated CA and its leaf.
//! The private keys are test-only.

mod common;
#[path = "common/ingest.rs"]
mod ingest;

use common::*;
use ingest::{Consumer, Registry, Role, Script};
use robodr_agent::FindingOutput;
use robodr_agentd::spool::Spool;
use robodr_blackbox::sign_ed25519::Ed25519SigningKey;
use robodr_blackbox::Signer;
use robodr_export::uplink::http::{self, Endpoint, HttpsTransport, Timeouts, Transport};
use robodr_export::uplink::{wire, FailPoint, RetryPolicy, Uplink, UplinkConfig, UplinkError};
use robodr_export::Source;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SENDER_SEED: [u8; 32] = [0x61; 32];
const OTHER_ROBOT: &str = "ugv-008";

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/uplink-tls")
        .join(name)
}

fn sender() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed_with_derived_id(&SENDER_SEED)
}

type Headers = Vec<(String, String)>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    /// Answer with `Transfer-Encoding: chunked`.
    Chunked,
    /// Read the request, never answer.
    Hang,
}

struct Server {
    port: u16,
    consumer: Arc<Mutex<Consumer>>,
    /// Requests whose head and body were read completely.
    requests: Arc<Mutex<Vec<(String, Headers)>>>,
    mode: Arc<Mutex<Mode>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn server_config(cert: &str, key: &str) -> Arc<rustls::ServerConfig> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(data(cert))
        .unwrap()
        .map(|c| c.unwrap())
        .collect();
    let key = PrivateKeyDer::from_pem_file(data(key)).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap(),
    )
}

/// Read one request (head + Content-Length body).
fn read_request(r: &mut impl BufRead) -> Option<(String, Headers, Vec<u8>)> {
    let mut start = String::new();
    r.read_line(&mut start).ok()?;
    let mut headers = Vec::new();
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).ok()? == 0 {
            return None;
        }
        let l = l.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':')?;
        headers.push((k.to_string(), v.trim().to_string()));
    }
    let n: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))?
        .1
        .parse()
        .ok()?;
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).ok()?;
    Some((start.trim_end().to_string(), headers, body))
}

fn respond(w: &mut impl Write, a: &ingest::Answer, mode: Mode) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\n",
        a.status
    );
    if let Some(ra) = &a.retry_after {
        head.push_str(&format!("Retry-After: {ra}\r\n"));
    }
    if mode == Mode::Chunked {
        head.push_str("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
        w.write_all(head.as_bytes())?;
        for part in a.body.chunks(7) {
            write!(w, "{:x}\r\n", part.len())?;
            w.write_all(part)?;
            w.write_all(b"\r\n")?;
        }
        w.write_all(b"0\r\n\r\n")?;
    } else {
        head.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            a.body.len()
        ));
        w.write_all(head.as_bytes())?;
        w.write_all(&a.body)?;
    }
    w.flush()
}

impl Server {
    /// `tls`: `(certificate file, key file)`; `None` = plain HTTP.
    fn start(bind: &str, tls: Option<(&str, &str)>, consumer: Consumer) -> Self {
        let l = TcpListener::bind(format!("{bind}:0")).unwrap();
        l.set_nonblocking(true).unwrap();
        let s = Self {
            port: l.local_addr().unwrap().port(),
            consumer: Arc::new(Mutex::new(consumer)),
            requests: Arc::new(Mutex::new(Vec::new())),
            mode: Arc::new(Mutex::new(Mode::Normal)),
            stop: Arc::new(AtomicBool::new(false)),
        };
        let cfg = tls.map(|(c, k)| server_config(c, k));
        let (consumer, requests, mode, stop) = (
            s.consumer.clone(),
            s.requests.clone(),
            s.mode.clone(),
            s.stop.clone(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let sock = match l.accept() {
                    Ok((sock, _)) => sock,
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                };
                sock.set_nonblocking(false).unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let (consumer, requests, mode, cfg) = (
                    consumer.clone(),
                    requests.clone(),
                    mode.clone(),
                    cfg.clone(),
                );
                std::thread::spawn(move || {
                    let m = *mode.lock().unwrap();
                    let handle = |rw: &mut dyn ReadWrite| {
                        let mut br = BufReader::new(Reader(rw));
                        let Some((start, headers, body)) = read_request(&mut br) else {
                            return;
                        };
                        requests.lock().unwrap().push((start, headers.clone()));
                        if m == Mode::Hang {
                            std::thread::sleep(Duration::from_secs(3));
                            return;
                        }
                        let a = consumer.lock().unwrap().handle(&headers, &body);
                        let _ = respond(&mut Writer(br.into_inner().0), &a, m);
                    };
                    match cfg {
                        Some(cfg) => {
                            let conn = rustls::ServerConnection::new(cfg).unwrap();
                            let mut tls = rustls::StreamOwned::new(conn, sock);
                            handle(&mut tls);
                            tls.conn.send_close_notify();
                            let _ = tls.flush();
                        }
                        None => {
                            let mut sock: TcpStream = sock;
                            handle(&mut sock);
                        }
                    }
                });
            }
        });
        s
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}
struct Reader<'a>(&'a mut dyn ReadWrite);
impl Read for Reader<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(b)
    }
}
struct Writer<'a>(&'a mut dyn ReadWrite);
impl Write for Writer<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn consumer() -> Consumer {
    let s = sender();
    Consumer::new(
        Registry::default()
            .robot(UNIT, false)
            .robot(OTHER_ROBOT, false)
            .key(s.key_id(), Role::Uplink, Some(UNIT), s.public_key()),
    )
}

struct Site {
    _tmp: TempDir,
    spool: PathBuf,
    state: PathBuf,
    sleeps: Arc<Mutex<Vec<Duration>>>,
}

impl Site {
    fn new(tag: &str) -> Self {
        let tmp = TempDir::new(tag);
        let s = Self {
            spool: tmp.path().join("spool"),
            state: tmp.path().join("state"),
            sleeps: Arc::new(Mutex::new(Vec::new())),
            _tmp: tmp,
        };
        drop(Spool::open(&s.spool, 1 << 30, 1_000_000).unwrap());
        s
    }

    fn spool(&self, robot: &str, from: u64, n: u64) {
        let mut s = Spool::open(&self.spool, 1 << 30, 1_000_000).unwrap();
        for i in from..from + n {
            let rec = robodr_ocsf::record(&finding_for(robot, i), Some(12)).unwrap();
            s.write(
                &FindingOutput {
                    topic: rec.topic.to_string(),
                    key: rec.key,
                    partition: rec.partition,
                    value: rec.value,
                    headers: rec
                        .headers
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                },
                false,
            )
            .unwrap();
        }
    }

    fn count(&self, d: &str) -> usize {
        fs::read_dir(self.spool.join(d))
            .map(|r| r.count())
            .unwrap_or(0)
    }

    fn cfg(&self, fp: Option<FailPoint>) -> UplinkConfig {
        let mut c = UplinkConfig::new(Source::Spool(self.spool.clone()), &self.state);
        c.retry = RetryPolicy {
            max_attempts: 3,
            base: Duration::from_millis(10),
            max: Duration::from_millis(50),
        };
        c.fail_point = fp;
        c
    }

    fn uplink(&self, t: HttpsTransport, fp: Option<FailPoint>) -> Uplink<HttpsTransport> {
        let sleeps = self.sleeps.clone();
        Uplink::open(self.cfg(fp), t, sender())
            .unwrap()
            .with_sleeper(move |d| sleeps.lock().unwrap().push(d))
            .with_log(|_| {})
    }
}

fn tls_config(ca: &str, pins: &[[u8; 32]]) -> rustls::ClientConfig {
    http::client_config(http::load_ca_bundle(&data(ca)).unwrap(), pins).unwrap()
}

fn transport(url: &str, tls: Option<rustls::ClientConfig>) -> HttpsTransport {
    HttpsTransport::new(
        Endpoint::parse(url).unwrap(),
        tls,
        Timeouts {
            connect: Duration::from_secs(5),
            request: Duration::from_secs(5),
        },
    )
    .unwrap()
}

fn https(srv: &Server) -> HttpsTransport {
    transport(
        &format!("https://127.0.0.1:{}/api/", srv.port),
        Some(tls_config("ca.pem", &[])),
    )
}

fn server_pin() -> [u8; 32] {
    let c = CertificateDer::from_pem_file(data("server.pem")).unwrap();
    http::spki_sha256(&c).unwrap()
}

#[test]
fn https_partial_acceptance() {
    let srv = Server::start("127.0.0.1", Some(("server.pem", "server.key")), consumer());
    let site = Site::new("https-ok");
    site.spool(UNIT, 0, 3);
    site.spool(OTHER_ROBOT, 0, 1);
    let rep = site.uplink(https(&srv), None).run_once().unwrap();
    assert_eq!((rep.created, rep.rejected, rep.requests), (3, 1, 1));
    assert_eq!(
        (
            site.count("ready"),
            site.count("acked"),
            site.count("rejected")
        ),
        (0, 3, 1)
    );
    let reqs = srv.requests.lock().unwrap().clone();
    assert_eq!(reqs[0].0, "POST /api/robot-edr/v2/ingest HTTP/1.1");
    let h = |n: &str| {
        reqs[0]
            .1
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(h("Host"), Some(format!("127.0.0.1:{}", srv.port)));
    assert_eq!(h("Content-Type").as_deref(), Some("application/x-ndjson"));
    assert_eq!(h("Connection").as_deref(), Some("close"));
}

#[test]
fn https_by_host_name_with_chunked_response() {
    let srv = Server::start("127.0.0.1", Some(("server.pem", "server.key")), consumer());
    *srv.mode.lock().unwrap() = Mode::Chunked;
    let site = Site::new("https-name");
    site.spool(UNIT, 0, 2);
    let t = transport(
        &format!("https://localhost:{}", srv.port),
        Some(tls_config("ca.pem", &[server_pin()])),
    );
    let rep = site.uplink(t, None).run_once().unwrap();
    assert_eq!(rep.created, 2);
}

#[test]
fn https_401_413_and_retries() {
    // 401: refused, nothing acknowledged, not retried in the run.
    let srv = Server::start("127.0.0.1", Some(("server.pem", "server.key")), consumer());
    let site = Site::new("https-401");
    site.spool(UNIT, 0, 2);
    srv.consumer
        .lock()
        .unwrap()
        .script
        .push_back(Script::Status(
            401,
            None,
            "{\"code\":\"unknown_key\",\"detail\":\"no such key\"}".into(),
        ));
    match site.uplink(https(&srv), None).run_once() {
        Err(e @ UplinkError::Refused { status: 401, .. }) => {
            assert!(e.to_string().contains("unknown_key"), "{e}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(site.count("ready"), 2);
    assert_eq!(srv.request_count(), 1);

    // 413 halves; 429 with Retry-After and 5xx: same batch id, re-signed.
    {
        let mut c = srv.consumer.lock().unwrap();
        c.max_lines = 1;
        c.script.extend([
            Script::Process, // the 2-line batch: 413 from max_lines
            Script::Status(429, Some("3".into()), "{\"code\":\"rate_limited\"}".into()),
            Script::Status(502, None, "<html>bad gateway</html>".into()),
        ]);
    }
    let rep = site.uplink(https(&srv), None).run_once().unwrap();
    assert_eq!((rep.split_413, rep.created, rep.retries), (1, 2, 2));
    let seen = srv.consumer.lock().unwrap().seen.clone();
    let statuses: Vec<u16> = seen.iter().map(|s| s.status).collect();
    assert_eq!(statuses, [401, 413, 429, 502, 200, 200]);
    let id = |s: &ingest::Seen| {
        s.headers
            .iter()
            .find(|(k, _)| k == wire::H_BATCH_ID)
            .unwrap()
            .1
            .clone()
    };
    assert_eq!(id(&seen[2]), id(&seen[3]));
    assert_eq!(id(&seen[3]), id(&seen[4]));
    assert_ne!(id(&seen[1]), id(&seen[2]), "a halved batch is a new batch");
    let sleeps = site.sleeps.lock().unwrap().clone();
    assert!(
        sleeps[0] >= Duration::from_secs(3),
        "Retry-After: {sleeps:?}"
    );
    assert_eq!(site.count("acked"), 2);
}

#[test]
fn https_crash_after_response_gets_replayed_response() {
    let srv = Server::start("127.0.0.1", Some(("server.pem", "server.key")), consumer());
    let site = Site::new("https-replay");
    site.spool(UNIT, 0, 3);
    assert!(matches!(
        site.uplink(https(&srv), Some(FailPoint::AfterResponse))
            .run_once(),
        Err(UplinkError::Injected)
    ));
    assert_eq!(site.count("ready"), 3);
    let rep = site.uplink(https(&srv), None).run_once().unwrap();
    assert_eq!((rep.replayed, rep.created, rep.resumed), (1, 3, 1));
    assert_eq!(site.count("acked"), 3);
    let c = srv.consumer.lock().unwrap();
    assert_eq!(c.event_count(), 3, "processed once");
    assert_eq!(c.seen.len(), 2);
}

#[test]
fn spki_pin_mismatch_is_refused_before_any_request() {
    let srv = Server::start("127.0.0.1", Some(("server.pem", "server.key")), consumer());
    let site = Site::new("pin");
    site.spool(UNIT, 0, 1);
    let mut wrong = server_pin();
    wrong[0] ^= 1;
    let t = transport(
        &format!("https://127.0.0.1:{}", srv.port),
        Some(tls_config("ca.pem", &[wrong])),
    );
    match site.uplink(t, None).run_once() {
        Err(UplinkError::GaveUp { last, .. }) => {
            assert!(last.contains("matches no configured pin"), "{last}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        srv.request_count(),
        0,
        "no request over an unpinned connection"
    );
    assert_eq!(site.count("ready"), 1);
    // One matching pin among several is enough.
    let t = transport(
        &format!("https://127.0.0.1:{}", srv.port),
        Some(tls_config("ca.pem", &[wrong, server_pin()])),
    );
    assert_eq!(site.uplink(t, None).run_once().unwrap().created, 1);
}

#[test]
fn certificate_verification_cannot_be_avoided() {
    // A server certificate from another CA.
    let other = Server::start(
        "127.0.0.1",
        Some(("other-server.pem", "other-server.key")),
        consumer(),
    );
    let site = Site::new("unknown-ca");
    site.spool(UNIT, 0, 1);
    let t = transport(
        &format!("https://127.0.0.1:{}", other.port),
        Some(tls_config("ca.pem", &[])),
    );
    match site.uplink(t, None).run_once() {
        Err(UplinkError::GaveUp { last, .. }) => {
            assert!(last.contains("certificate"), "{last}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(other.request_count(), 0);
    // A pin on the right key does not replace chain verification.
    let c = CertificateDer::from_pem_file(data("other-server.pem")).unwrap();
    let pin = http::spki_sha256(&c).unwrap();
    let t = transport(
        &format!("https://127.0.0.1:{}", other.port),
        Some(tls_config("ca.pem", &[pin])),
    );
    assert!(site.uplink(t, None).run_once().is_err());
    assert_eq!(other.request_count(), 0);

    // Name mismatch: the certificate does not name 127.0.0.2.
    let srv = Server::start("127.0.0.2", Some(("server.pem", "server.key")), consumer());
    let t = transport(
        &format!("https://127.0.0.2:{}", srv.port),
        Some(tls_config("ca.pem", &[])),
    );
    assert!(site.uplink(t, None).run_once().is_err());
    assert_eq!(srv.request_count(), 0);

    // A plain-HTTP server behind an https:// URL: refused.
    let plain = Server::start("127.0.0.1", None, consumer());
    let t = transport(
        &format!("https://127.0.0.1:{}", plain.port),
        Some(tls_config("ca.pem", &[])),
    );
    assert!(site.uplink(t, None).run_once().is_err());
    assert_eq!(site.count("ready"), 1);
}

#[test]
fn plain_http_only_to_loopback() {
    for url in [
        "http://192.0.2.1/api",
        "http://soc.example.org",
        "http://localhost:8080",
        "http://0.0.0.0:80",
    ] {
        let e = Endpoint::parse(url).unwrap_err();
        assert!(e.contains("refused") || e.contains("TLS"), "{url}: {e}");
    }
    // Even a hand-built endpoint is refused by the transport.
    let ep = Endpoint {
        tls: false,
        host: "192.0.2.1".into(),
        port: 80,
        path: "/robot-edr/v2/ingest".into(),
    };
    assert!(HttpsTransport::new(ep, None, Timeouts::default()).is_err());
    // https without a TLS configuration, http with one: refused.
    let ep = Endpoint::parse("https://127.0.0.1").unwrap();
    assert!(HttpsTransport::new(ep, None, Timeouts::default()).is_err());
    let ep = Endpoint::parse("http://127.0.0.1").unwrap();
    assert!(HttpsTransport::new(ep, Some(tls_config("ca.pem", &[])), Timeouts::default()).is_err());

    // Loopback plain HTTP works (tests, a local TLS-terminating proxy).
    let srv = Server::start("127.0.0.1", None, consumer());
    let site = Site::new("plain");
    site.spool(UNIT, 0, 2);
    let t = transport(&format!("http://127.0.0.1:{}", srv.port), None);
    assert_eq!(site.uplink(t, None).run_once().unwrap().created, 2);
}

#[test]
fn a_server_that_never_answers_times_out() {
    let srv = Server::start("127.0.0.1", Some(("server.pem", "server.key")), consumer());
    *srv.mode.lock().unwrap() = Mode::Hang;
    let mut t = HttpsTransport::new(
        Endpoint::parse(&format!("https://127.0.0.1:{}", srv.port)).unwrap(),
        Some(tls_config("ca.pem", &[])),
        Timeouts {
            connect: Duration::from_secs(2),
            request: Duration::from_millis(400),
        },
    )
    .unwrap();
    let start = Instant::now();
    let r = t.post(&http::HttpRequest {
        headers: vec![("Content-Type", wire::CONTENT_TYPE.into())],
        body: b"x\n",
    });
    let e = r.unwrap_err();
    assert!(e.0.contains("timed out"), "{e}");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn cli_once_over_https() {
    let srv = Server::start("127.0.0.1", Some(("server.pem", "server.key")), consumer());
    let site = Site::new("cli");
    site.spool(UNIT, 0, 2);
    let key = site.state.parent().unwrap().join("uplink.key");
    robodr_blackbox::KeyFile::ed25519_from_seed(&SENDER_SEED, None)
        .unwrap()
        .write_new(&key)
        .unwrap();
    let bin = env!("CARGO_BIN_EXE_robodr-uplink");
    let out = std::process::Command::new(bin)
        .args(["--url", &format!("https://127.0.0.1:{}/api", srv.port)])
        .arg("--key-file")
        .arg(&key)
        .arg("--ca-bundle")
        .arg(data("ca.pem"))
        .args([
            "--spki-sha256",
            &robodr_blackbox::crypto::to_hex(&server_pin()),
        ])
        .arg("--state-dir")
        .arg(&site.state)
        .arg("--spool")
        .arg(&site.spool)
        .arg("--once")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).lines().next().unwrap()).unwrap();
    assert_eq!(report["created"], 2);
    assert_eq!(site.count("acked"), 2);

    // Usage errors: exit 2. Refused plain HTTP, missing CA bundle, bad pin.
    for args in [
        vec![
            "--url",
            "http://192.0.2.1",
            "--key-file",
            "k",
            "--state-dir",
            "s",
            "--spool",
            "p",
        ],
        vec![
            "--url",
            "https://192.0.2.1",
            "--key-file",
            "k",
            "--state-dir",
            "s",
            "--spool",
            "p",
        ],
        vec![
            "--url",
            "https://192.0.2.1",
            "--key-file",
            "k",
            "--ca-bundle",
            "c",
            "--spki-sha256",
            "zz",
            "--state-dir",
            "s",
            "--spool",
            "p",
        ],
        vec!["--bogus"],
    ] {
        let o = std::process::Command::new(bin)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
    }
    // Unreachable server with --once: exit 1, nothing acknowledged.
    site.spool(UNIT, 10, 1);
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);
    let o = std::process::Command::new(bin)
        .args(["--url", &format!("https://127.0.0.1:{port}")])
        .arg("--key-file")
        .arg(&key)
        .arg("--ca-bundle")
        .arg(data("ca.pem"))
        .arg("--state-dir")
        .arg(&site.state)
        .arg("--spool")
        .arg(&site.spool)
        .args(["--max-attempts", "2", "--backoff-base-ms", "10", "--once"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(site.count("ready"), 1);
    let o = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("robodr-uplink "));
}

/// The binary: one process per state directory (a `--once` or `reinject`
/// while the service runs fails clearly), the status file, the removed
/// `--max-retry-after-s`, and `reinject`.
#[test]
fn cli_lock_status_and_reinject() {
    let srv = Server::start("127.0.0.1", None, consumer());
    let site = Site::new("cli-lock");
    site.spool(UNIT, 0, 2);
    site.spool(OTHER_ROBOT, 0, 1); // robot_mismatch (uplink key of UNIT)
    let key = site.state.parent().unwrap().join("uplink.key");
    robodr_blackbox::KeyFile::ed25519_from_seed(&SENDER_SEED, None)
        .unwrap()
        .write_new(&key)
        .unwrap();
    let bin = env!("CARGO_BIN_EXE_robodr-uplink");
    let url = format!("http://127.0.0.1:{}", srv.port);
    let base = |extra: &[&str]| {
        let mut c = std::process::Command::new(bin);
        c.args(["--url", &url])
            .arg("--key-file")
            .arg(&key)
            .arg("--state-dir")
            .arg(&site.state)
            .arg("--spool")
            .arg(&site.spool)
            .args(extra);
        c
    };
    // Removed flag: a usage error that says why.
    let o = base(&["--max-retry-after-s", "5", "--once"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("removed"));

    // The service holds the lock while it runs (also between runs).
    let mut svc = base(&["--interval-ms", "200"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let status_path = site.state.join("uplink-status.json");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !status_path.exists() {
        assert!(std::time::Instant::now() < deadline, "no status file");
        std::thread::sleep(Duration::from_millis(50));
    }
    let o = base(&["--once"]).output().unwrap();
    let err = String::from_utf8_lossy(&o.stderr).to_string();
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("held by another robodr-uplink"), "{err}");
    let dl = site.state.join("dead-letter.jsonl");
    let reinject = |extra: &[&str]| {
        std::process::Command::new(bin)
            .arg("reinject")
            .arg("--state-dir")
            .arg(&site.state)
            .arg("--spool")
            .arg(&site.spool)
            .arg("--dead-letter")
            .arg(&dl)
            .args(extra)
            .output()
            .unwrap()
    };
    let o = reinject(&[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("held by another"));
    svc.kill().unwrap();
    svc.wait().unwrap();

    // Status file after the service's runs.
    let st: serde_json::Value = serde_json::from_slice(&fs::read(&status_path).unwrap()).unwrap();
    assert_eq!(st["format"], "robodr-uplink-status/1");
    assert_eq!(st["state"], "ok");
    assert_eq!(st["accepted_total"], 2);
    assert_eq!(st["rejected_total"], 1);
    assert_eq!(st["backlog"]["spool_ready"], 0);

    // reinject: usage errors, then a re-queue that is idempotent.
    for bad in [
        vec!["reinject", "--state-dir", "s", "--spool", "p"],
        vec![
            "reinject",
            "--state-dir",
            "s",
            "--spool",
            "p",
            "--dead-letter",
            "d",
            "--codes",
            "Bad Code",
        ],
        vec!["reinject", "--bogus"],
    ] {
        let o = std::process::Command::new(bin).args(&bad).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{bad:?}");
    }
    let o = reinject(&["--codes", "robot_mismatch", "--dry-run"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(
        (r["queued"].as_u64(), r["generation"].is_null()),
        (Some(1), true)
    );
    let o = reinject(&["--codes", "robot_mismatch"]);
    assert!(o.status.success());
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(r["queued"], 1);
    assert!(r["generation"].as_str().unwrap().starts_with("rj-"));
    let o = reinject(&["--codes", "robot_mismatch"]);
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(
        (r["queued"].as_u64(), r["already_queued"].as_u64()),
        (Some(0), Some(1))
    );
    // The re-queued record is sent (and rejected again: still the wrong
    // robot for this key) by the next run, under a new batch id.
    let before = srv.requests.lock().unwrap().len();
    let o = base(&["--once"]).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(srv.requests.lock().unwrap().len(), before + 1);
    let rep: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&o.stdout).lines().next().unwrap()).unwrap();
    assert_eq!(rep["rejected"], 1);
    assert_eq!(rep["reinjected_done"].as_array().unwrap().len(), 1);
}
