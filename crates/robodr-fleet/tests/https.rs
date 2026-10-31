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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-enroll");

/// `fx/<name>`: the shared `fixtures/tls/` (its CRL set, `gen.sh crl`).
fn tls_data(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    match name.strip_prefix("fx/") {
        Some(n) => root.join("../../fixtures/tls").join(n),
        None => root
            .join("../robodr-export/tests/data/uplink-tls")
            .join(name),
    }
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
    serve_as(soc, "server")
}

/// [`serve`] with the certificate `<leaf>.pem` / `<leaf>.key`.
fn serve_as(soc: Soc, leaf: &str) -> Server {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(tls_data(&format!("{leaf}.pem")))
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
    let key = PrivateKeyDer::from_pem_file(tls_data(&format!("{leaf}.key"))).unwrap();
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
    Soc::new(soc_key(), approval_key(), WORKSPACE, now_ms())
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

/// The token in a root-only file (mode 0600).
fn token_file(u: &Unit, tok: &str) -> PathBuf {
    let f = u.root.join("token.txt");
    std::fs::write(&f, format!("{tok}\n")).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    f
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
    let tokf = token_file(&u, &tok);
    let o = run(&["--config", c, "--token-file", tokf.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("enrolled: robot ugv-001"));
    assert!(String::from_utf8_lossy(&o.stdout).contains("shred -u"));
    // Replay of the same token through the CLI: refused locally (exit 1).
    let o = run(&["--config", c, "--token-file", tokf.to_str().unwrap()]);
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
    let tokf = token_file(&u, &tok);
    let tf = tokf.to_str().unwrap();
    let o = run(&[
        "request",
        "--config",
        c,
        "--token-file",
        tf,
        "--out",
        req.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    // Online enroll without a URL: usage error.
    let o = run(&["--config", c, "--token-file", tf]);
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
    // Profile with files: stage, a wrong approval, the genuine one.
    let (prof, sig) = signed_profile(4, Some(ROBOT));
    let pf = u.root.join("offer-profile.json");
    std::fs::write(&pf, &prof).unwrap();
    std::fs::write(u.root.join("offer-profile.json.sig"), &sig).unwrap();
    let o = run(&[
        "profile",
        "stage",
        "--config",
        c,
        "--profile",
        pf.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("STAGED"));
    assert!(!u.etc("profile.json").exists(), "staging never installs");
    let digest = robodr_fleet::wire::digest(&prof);
    let wrong = soc.approval("ap-x", ROBOT, PLATFORM, &digest, 5, &["op-a"], 600_000);
    let wf = u.root.join("approval-wrong.json");
    std::fs::write(&wf, wrong).unwrap();
    let o = run(&[
        "profile",
        "approve",
        "--config",
        c,
        "--approval",
        wf.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 1, "{}", txt(&o));
    assert!(!u.etc("profile.json").exists());
    let good = soc.approval(
        "ap-y",
        ROBOT,
        PLATFORM,
        &digest,
        4,
        &["op-a", "op-b"],
        600_000,
    );
    let gf = u.root.join("approval.json");
    std::fs::write(&gf, good).unwrap();
    let o = run(&[
        "profile",
        "approve",
        "--config",
        c,
        "--approval",
        gf.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert_eq!(std::fs::read(u.etc("profile.json")).unwrap(), prof);
    let o = run(&["profile", "status", "--config", c]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("no staged profile"));
    // Usage errors.
    for args in [
        vec!["rotate", "--config", c],
        vec!["rotate", "--config", c, "--role", "blackbox"],
        vec!["bogus", "--config", c],
        vec!["status", "--config", c, "--role", "uplink"],
        vec![
            "rotate", "--config", c, "--role", "uplink", "--cancel", "--abort",
        ],
        vec![
            "rotate", "--config", c, "--role", "uplink", "--cancel", "--finish",
        ],
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

#[test]
fn cli_never_takes_the_token_from_argv() {
    let srv = serve(live_soc());
    let u = unit_with_ca("cli-token");
    let cfgf = u.config_file(Some(&srv.url()));
    let c = cfgf.to_str().unwrap();
    let tok = srv
        .soc
        .lock()
        .unwrap()
        .issue_token("tok-1", ROBOT, Some(SITE), 600_000, [9; 32]);
    // On argv the token would be in /proc/<pid>/cmdline, sudo logs and the
    // shell history: refused before anything else.
    for args in [
        vec!["--config", c, "--token", tok.as_str()],
        vec![
            "request",
            "--config",
            c,
            "--token",
            tok.as_str(),
            "--out",
            "/dev/null",
        ],
    ] {
        let o = run(&args);
        assert_eq!(code(&o), 2, "{}", txt(&o));
        assert!(txt(&o).contains("command line"), "{}", txt(&o));
        assert!(!u.cfg.uplink_key.exists());
    }
    let o = run(&["--config", c, &format!("--token={tok}")]);
    assert_eq!(code(&o), 2, "{}", txt(&o));
    // A token file readable by group or others: refused.
    let tokf = u.root.join("token.txt");
    std::fs::write(&tokf, format!("{tok}\n")).unwrap();
    std::fs::set_permissions(&tokf, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = run(&["--config", c, "--token-file", tokf.to_str().unwrap()]);
    assert_eq!(code(&o), 1, "{}", txt(&o));
    assert!(txt(&o).contains("group or others"), "{}", txt(&o));
    assert!(!u.cfg.uplink_key.exists());
    // On stdin (`--token -`): accepted.
    let mut child = Command::new(BIN)
        .args(["--config", c, "--token", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{tok}\n").as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("enrolled: robot ugv-001"));
}

/// `soc.crl_files`: a revoked SOC server certificate is refused before any
/// request is sent; the unrevoked server of the same CA is reached.
#[test]
fn crl_files_refuse_a_revoked_soc_server() {
    use robodr_fleet::client::{Https, SocTransport};
    let u = Unit::new("https-crl");
    let ca = u.root.join("crl-ca.pem");
    let crl = u.root.join("crl-ca.crl.pem");
    for (from, to) in [("fx/crl-ca.pem", &ca), ("fx/crl-ca.crl.pem", &crl)] {
        std::fs::copy(tls_data(from), to).unwrap();
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let crls = vec![crl.clone()];
    let revoked = serve_as(live_soc(), "fx/crl-revoked-server");
    let mut t = Https::with_crls(&revoked.url(), Some(&ca), &[], &crls).unwrap();
    let e = t.send("GET", "/x", Vec::new(), b"").unwrap_err();
    assert!(e.to_string().contains("Revoked"), "{e}");
    // Without the CRL the same server is reached (any HTTP answer will do).
    let mut t = Https::new(&revoked.url(), Some(&ca), &[]).unwrap();
    assert!(t.send("GET", "/x", Vec::new(), b"").is_ok());
    let good = serve_as(live_soc(), "fx/crl-server");
    let mut t = Https::with_crls(&good.url(), Some(&ca), &[], &crls).unwrap();
    assert!(t.send("GET", "/x", Vec::new(), b"").is_ok());
    // CRLs make no sense without TLS.
    assert!(Https::with_crls("http://127.0.0.1:1/api", None, &[], &crls).is_err());
    // The configuration takes them (absolute paths only).
    let cfg = robodr_fleet::config::Config::parse(&format!(
        r#"{{"format": "robodr-fleet-config/v1", "soc": {{"crl_files": [{:?}]}}}}"#,
        crl.display().to_string()
    ))
    .unwrap();
    assert_eq!(cfg.crl_files, crls);
    assert!(robodr_fleet::config::Config::parse(
        r#"{"format": "robodr-fleet-config/v1", "soc": {"crl_files": ["rel.crl"]}}"#
    )
    .is_err());
}

/// `robodr-enroll check` (site acceptance): read-only, exit 0 when TLS,
/// the fleet API and request authentication work; exit 3 for a SOC that
/// TLS refuses; exit 1 for a SOC key that does not verify. Then
/// `decommission` over HTTPS: the keys are retired at the SOC, the
/// receipt is written, and `check` finds the unit no longer enrolled.
#[test]
fn cli_check_and_decommission() {
    let srv = serve(live_soc());
    let u = unit_with_ca("cli-check");
    let cfgf = u.config_file(Some(&srv.url()));
    let c = cfgf.to_str().unwrap();
    // Not enrolled: TLS and the fleet API are checked, authentication skipped.
    let o = run(&["check", "--config", c]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("skip request authentication"));
    // The SOC's certificate from another CA: not reached (exit 3).
    std::fs::copy(tls_data("other-ca.pem"), &u.cfg.ca_bundle).unwrap();
    let o = run(&["check", "--config", c]);
    assert_eq!(code(&o), 3, "{}", txt(&o));
    std::fs::copy(tls_data("ca.pem"), &u.cfg.ca_bundle).unwrap();
    // Enrolled: the uplink key authenticates; no ring published yet.
    let tok = srv
        .soc
        .lock()
        .unwrap()
        .issue_token("tok-1", ROBOT, Some(SITE), 600_000, [9; 32]);
    let tokf = token_file(&u, &tok);
    let o = run(&["--config", c, "--token-file", tokf.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    let o = run(&["check", "--config", c]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("the SOC accepts the uplink key"));
    // A published ring document is verified, not recorded; nothing is
    // written to the journal either.
    srv.soc.lock().unwrap().ring(ROBOT, 1, 0, None);
    let journal_len = |u: &Unit| {
        std::fs::read_dir(u.cfg.state_dir.join("journal"))
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum::<u64>()
    };
    let before = journal_len(&u);
    let o = run(&["check", "--config", c]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("verifies under SOC fleet key"));
    assert!(!u.cfg.state_dir.join("ring.json").exists());
    assert_eq!(journal_len(&u), before);
    // A configured SOC fleet key that is not the SOC's: the ring signature
    // does not verify (exit 1).
    let wrong = u.etc("wrong-soc.pub");
    write_public_key(&wrong, &profile_key());
    let o = run(&["check", "--config", c, "--soc-key", wrong.to_str().unwrap()]);
    assert_eq!(code(&o), 1, "{}", txt(&o));

    // Decommission: --reason is required; then online.
    let o = run(&["decommission", "--config", c]);
    assert_eq!(code(&o), 2, "{}", txt(&o));
    let receipt = u.root.join("receipt.json");
    let o = run(&[
        "decommission",
        "--config",
        c,
        "--reason",
        "end_of_life",
        "--receipt-out",
        receipt.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("decommissioned: robot ugv-001"));
    let r: serde_json::Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(r["format"], "robodr-fleet-decommission-receipt/v1");
    assert!(srv
        .soc
        .lock()
        .unwrap()
        .keys
        .values()
        .all(|k| k.retired_at.is_some()));
    let o = run(&["status", "--config", c]);
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("Done"),
        "{}",
        txt(&o)
    );
    // Re-running shows the receipt again (exit 0); check now finds no
    // enrollment and passes the unauthenticated part only.
    let o = run(&["decommission", "--config", c]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    let o = run(&["check", "--config", c]);
    assert_eq!(code(&o), 0, "{}", txt(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("not enrolled"));
}
