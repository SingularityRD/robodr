//! The fleet client over real TLS against an in-process HTTPS SOC stub
//! (rustls server, the test PKI of robodr-export's uplink tests: EC P-256
//! CA and a leaf for `localhost` / `127.0.0.1` / `::1`), and the
//! `robodr-enroll` binary end to end: online enrollment, rotation, ring,
//! the air-gapped file flow, exit codes.

mod common;

use common::soc::{Soc, BASE};
use common::*;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-enroll");

fn tls_data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../robodr-export/tests/data/uplink-tls")
        .join(name)
}

struct Server {
    port: u16,
    soc: Arc<Mutex<Soc>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

impl Server {
    fn url(&self) -> String {
        format!("https://127.0.0.1:{}{BASE}", self.port)
    }
}

fn now_ms() -> u64 {
    robodr_fleet::state::system_now_ms()
}

/// Serve `soc` over TLS; the SOC clock follows the system clock.
fn serve(soc: Soc) -> Server {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(tls_data("server.pem"))
        .unwrap()
        .map(|c| c.unwrap())
        .collect();
    let key = PrivateKeyDer::from_pem_file(tls_data("server.key")).unwrap();
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let soc = Arc::new(Mutex::new(soc));
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, st2) = (soc.clone(), stop.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            if st2.load(Ordering::SeqCst) {
                return;
            }
            let Ok(tcp) = conn else { continue };
            let cfg = cfg.clone();
            let soc = s2.clone();
            std::thread::spawn(move || {
                let Ok(c) = rustls::ServerConnection::new(cfg) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(c, tcp);
                let mut r = BufReader::new(&mut tls);
                let mut start = String::new();
                if r.read_line(&mut start).is_err() {
                    return;
                }
                let mut headers = Vec::new();
                loop {
                    let mut l = String::new();
                    if r.read_line(&mut l).unwrap_or(0) == 0 {
                        return;
                    }
                    let l = l.trim_end_matches(['\r', '\n']).to_string();
                    if l.is_empty() {
                        break;
                    }
                    let (k, v) = l.split_once(':').unwrap();
                    headers.push((k.to_string(), v.trim().to_string()));
                }
                let n: usize = common::soc::header(&headers, "Content-Length")
                    .first()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; n];
                if r.read_exact(&mut body).is_err() {
                    return;
                }
                drop(r);
                let mut parts = start.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let target = parts.next().unwrap_or("").to_string();
                let resp = {
                    let mut s = soc.lock().unwrap();
                    s.now_ms = now_ms();
                    match target.strip_prefix(BASE) {
                        Some(t) => s.handle(&method, t, &headers, &body),
                        None => common::soc::Resp {
                            status: 404,
                            body: br#"{"code":"not_found","detail":""}"#.to_vec(),
                        },
                    }
                };
                let head = format!(
                    "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp.status,
                    resp.body.len()
                );
                let _ = tls.write_all(head.as_bytes());
                let _ = tls.write_all(&resp.body);
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.conn.complete_io(&mut tls.sock);
            });
        }
    });
    Server { port, soc, stop }
}

fn live_soc() -> Soc {
    Soc::new(soc_key(), WORKSPACE, now_ms())
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn txt(o: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn unit_with_ca(tag: &str) -> Unit {
    let u = Unit::new(tag);
    std::fs::copy(tls_data("ca.pem"), &u.cfg.ca_bundle).unwrap();
    u
}

#[test]
fn library_over_https_enroll_rotate_ring() {
    let srv = serve(live_soc());
    let u = unit_with_ca("https-lib");
    let tok = srv
        .soc
        .lock()
        .unwrap()
        .issue_token("tok-1", ROBOT, Some(SITE), 600_000, [9; 32]);
    let now = now_ms();
    u.now.set(now);
    let ctx = u.ctx();
    let mut t = robodr_fleet::client::Https::new(&srv.url(), Some(&u.cfg.ca_bundle), &[]).unwrap();
    robodr_fleet::enroll::prepare(&ctx, &tok, &Default::default()).unwrap();
    robodr_fleet::enroll::submit(&ctx, &mut t).unwrap();
    use robodr_fleet::rotate;
    rotate::prepare(&ctx, "uplink", &rotate::no_crash).unwrap();
    rotate::submit_rotate(&ctx, &mut t, "uplink").unwrap();
    rotate::swap(&ctx, "uplink", &rotate::no_crash).unwrap();
    // The retire request authenticates with the NEW uplink key (overlap).
    rotate::submit_retire(&ctx, &mut t, "uplink", &rotate::no_crash).unwrap();
    srv.soc.lock().unwrap().ring(ROBOT, 1, 0, Some("9.9.9"));
    let s = robodr_fleet::ring::fetch(&ctx, &mut t).unwrap();
    assert!(s.update_available);
    // A CA that did not issue the server certificate: TLS refuses.
    let mut bad =
        robodr_fleet::client::Https::new(&srv.url(), Some(&tls_data("other-ca.pem")), &[]).unwrap();
    let err = robodr_fleet::ring::fetch(&ctx, &mut bad).unwrap_err();
    assert!(err.starts_with("SOC not reached"), "{err}");
    // A wrong SPKI pin: refused too.
    let mut pinned =
        robodr_fleet::client::Https::new(&srv.url(), Some(&u.cfg.ca_bundle), &["00".repeat(32)])
            .unwrap();
    assert!(robodr_fleet::ring::fetch(&ctx, &mut pinned).is_err());
    // Plain http to a non-loopback host is refused before any connection.
    assert!(robodr_fleet::client::Https::new("http://10.0.0.1/api", None, &[]).is_err());
}

#[test]
fn cli_online_enroll_rotate_and_status() {
    let srv = serve(live_soc());
    let u = unit_with_ca("cli-online");
    let cfgf = u.config_file(Some(&srv.url()));
    let c = cfgf.to_str().unwrap();
    let tok = srv
        .soc
        .lock()
        .unwrap()
        .issue_token("tok-1", ROBOT, Some(SITE), 600_000, [9; 32]);
    let tokf = u.root.join("token.txt");
    std::fs::write(&tokf, format!("{tok}\n")).unwrap();
    let o = run(&["--config", c, "--token-file", tokf.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("enrolled: robot ugv-001"));
    // Replay of the same token through the CLI: refused locally (exit 1).
    let o = run(&["--config", c, "--token", &tok]);
    assert_eq!(code(&o), 1, "{}", txt(&o));
    let o = run(&["rotate", "--config", c, "--role", "finding"]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("systemctl restart robodr-agentd"));
    let o = run(&["status", "--config", c]);
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("rotation rfr1-"),
        "{}",
        txt(&o)
    );
    let o = run(&["rotate", "--config", c, "--role", "finding", "--finish"]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    srv.soc.lock().unwrap().ring(ROBOT, 1, 2, None);
    let o = run(&["ring", "--config", c]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("ring 2"));
    // SOC unreachable: exit 3.
    let dead = u.config_file(Some("https://127.0.0.1:1/api"));
    let o = run(&["ring", "--config", dead.to_str().unwrap()]);
    assert_eq!(code(&o), 3, "{}", txt(&o));
}

#[test]
fn cli_air_gapped_files_and_usage() {
    let u = unit_with_ca("cli-airgap");
    let cfgf = u.config_file(None);
    let c = cfgf.to_str().unwrap();
    let mut soc = live_soc();
    let tok = soc.issue_token("tok-1", ROBOT, Some(SITE), 600_000, [9; 32]);
    let req = u.root.join("req.json");
    let o = run(&[
        "request",
        "--config",
        c,
        "--token",
        &tok,
        "--out",
        req.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    // Online enroll without a URL: usage error.
    let o = run(&["--config", c, "--token", &tok]);
    assert_eq!(code(&o), 2, "{}", txt(&o));
    let h = vec![("Content-Type".to_string(), "application/json".to_string())];
    soc.now_ms = now_ms();
    let a = soc.handle(
        "POST",
        robodr_fleet::wire::PATH_ENROLL,
        &h,
        &std::fs::read(&req).unwrap(),
    );
    assert_eq!(a.status, 200);
    let ans = u.root.join("ans.json");
    std::fs::write(&ans, &a.body).unwrap();
    let o = run(&["accept", "--config", c, "--answer", ans.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    // Rotation with files.
    let rreq = u.root.join("rot-req.json");
    let o = run(&[
        "rotate",
        "--config",
        c,
        "--role",
        "uplink",
        "--request-out",
        rreq.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    // The SOC side processes the carried file (authenticated by the old key
    // as the robot's uplink key in the import tool's own session: here the
    // stub is called with the request authenticated directly).
    let k = robodr_fleet::keys::load("uplink", &u.cfg.uplink_key).unwrap();
    let body = std::fs::read(&rreq).unwrap();
    let mut hh = h.clone();
    let full = format!("{BASE}{}", robodr_fleet::wire::PATH_ROTATE);
    for (a, b) in robodr_fleet::client::auth_headers("POST", &full, &body, &k.signing, soc.now_ms) {
        hh.push((a.to_string(), b));
    }
    let ra = soc.handle("POST", robodr_fleet::wire::PATH_ROTATE, &hh, &body);
    assert_eq!(ra.status, 200);
    let rans = u.root.join("rot-ans.json");
    std::fs::write(&rans, &ra.body).unwrap();
    let o = run(&[
        "rotate",
        "--config",
        c,
        "--role",
        "uplink",
        "--answer",
        rans.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    // Usage errors.
    for args in [
        vec!["rotate", "--config", c],
        vec!["rotate", "--config", c, "--role", "blackbox"],
        vec!["bogus", "--config", c],
        vec!["status", "--config", c, "--role", "uplink"],
        vec!["--token"],
    ] {
        let o = run(&args);
        assert_eq!(code(&o), 2, "{args:?}: {}", txt(&o));
    }
    let o = run(&["--version"]);
    assert_eq!(code(&o), 0);
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("robodr-enroll "));
    let o = run(&["--help"]);
    assert_eq!(code(&o), 0);
}
