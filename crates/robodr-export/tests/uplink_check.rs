//! `robodr-uplink --check` (site acceptance, T13): the library check
//! against the reference ingest consumer (`tests/common/ingest.rs`) plus a
//! minimal fleet §2.5 authenticator, and the binary end to end over plain
//! HTTP to loopback. The check never sends a finding, never stores a batch
//! and never writes the state directory.

mod common;
#[path = "common/ingest.rs"]
mod ingest;

use common::*;
use ingest::{Consumer, Registry, Role};
use robodr_blackbox::sign_ed25519::Ed25519SigningKey;
use robodr_blackbox::Signer;
use robodr_export::uplink::check::{self, Outcome, Probe};
use robodr_export::uplink::http::{HttpRequest, HttpResponse, TransportError};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

fn sender() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed_with_derived_id(&[0x61; 32])
}

/// How the fake SOC treats the fleet ring request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fleet {
    /// Fleet API served, no ring published (`404 no_ring` once authenticated).
    Served,
    /// No fleet API at all (`404 not_found`).
    Absent,
}

struct Soc {
    consumer: Consumer,
    fleet: Fleet,
    /// Fleet keys: key id -> public key.
    fleet_keys: Vec<(String, [u8; 32])>,
    now_ms: u64,
    /// Answer the ingest path as if it were another service.
    wrong_service: bool,
}

fn json(status: u16, code: &str) -> HttpResponse {
    HttpResponse {
        status,
        retry_after: None,
        body: serde_json::to_vec(&serde_json::json!({"code": code, "detail": ""})).unwrap(),
    }
}

fn header<'a>(h: &'a [(String, String)], n: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(n))
        .map(|(_, v)| v.as_str())
}

impl Soc {
    fn new(fleet: Fleet) -> Self {
        let k = sender();
        Self {
            consumer: Consumer::new(Registry::default().robot(UNIT, false).key(
                k.key_id(),
                Role::Uplink,
                Some(UNIT),
                k.public_key(),
            )),
            fleet,
            fleet_keys: vec![(k.key_id().to_string(), k.public_key())],
            now_ms: NOW,
            wrong_service: false,
        }
    }

    fn handle(
        &mut self,
        method: &str,
        target: &str,
        h: &[(String, String)],
        body: &[u8],
    ) -> HttpResponse {
        if target == "/api/robot-edr/v2/ingest" && method == "POST" {
            if self.wrong_service {
                return json(404, "not_found");
            }
            let a = self.consumer.handle(h, body);
            return HttpResponse {
                status: a.status,
                retry_after: a.retry_after,
                body: a.body,
            };
        }
        if target == "/api/robot-edr/v2/fleet/ring" && method == "GET" {
            if self.fleet == Fleet::Absent {
                return json(404, "not_found");
            }
            let (Some(id), Some(ts), Some(sig)) = (
                header(h, "X-RoboDR-Key-Id"),
                header(h, "X-RoboDR-Timestamp").and_then(|t| t.parse::<u64>().ok()),
                header(h, "X-RoboDR-Signature"),
            ) else {
                return json(400, "bad_header");
            };
            let Some((_, pk)) = self.fleet_keys.iter().find(|(k, _)| k == id) else {
                return json(401, "unknown_key");
            };
            if self.now_ms.abs_diff(ts) > 300_000 {
                return json(401, "stale_timestamp");
            }
            let m = check::fleet_request_message(method, target, id, ts, body);
            let ok = robodr_blackbox::crypto::from_hex(sig)
                .is_some_and(|s| robodr_blackbox::sign_ed25519::verify(pk, &m, &s));
            if !ok {
                return json(401, "bad_signature");
            }
            return json(404, "no_ring");
        }
        json(404, "not_found")
    }
}

struct Fake<'a>(&'a mut Soc);

impl Probe for Fake<'_> {
    fn send(
        &mut self,
        method: &str,
        target: &str,
        req: &HttpRequest<'_>,
    ) -> Result<HttpResponse, TransportError> {
        let h: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        Ok(self.0.handle(method, target, &h, req.body))
    }
    fn ingest_target(&self) -> String {
        "/api/robot-edr/v2/ingest".into()
    }
}

struct Down;

impl Probe for Down {
    fn send(
        &mut self,
        _: &str,
        _: &str,
        _: &HttpRequest<'_>,
    ) -> Result<HttpResponse, TransportError> {
        Err(TransportError("connect: connection refused".into()))
    }
    fn ingest_target(&self) -> String {
        "/api/robot-edr/v2/ingest".into()
    }
}

fn run(soc: &mut Soc, relay: bool, now: u64) -> check::Report {
    check::run(&mut Fake(soc), &sender(), relay, now, [7; 16])
}

#[test]
fn check_passes_without_storing_a_batch_or_a_finding() {
    let mut soc = Soc::new(Fleet::Served);
    let r = run(&mut soc, false, NOW);
    assert_eq!(r.outcome, Outcome::Ok, "{:?}", r.lines);
    assert!(r.lines.iter().any(|l| l.contains("400 empty_batch")));
    assert!(r.lines.iter().any(|l| l.contains("the SOC accepts key")));
    // The consumer saw exactly one request, an empty body refused before
    // authentication: nothing stored, nothing counted.
    assert_eq!(soc.consumer.seen.len(), 1);
    assert_eq!(soc.consumer.seen[0].status, 400);
    assert!(soc.consumer.seen[0].body.is_empty());
    assert_eq!(soc.consumer.finding_count(), 0);
}

#[test]
fn check_reports_each_failure_with_its_cause() {
    // Not reached.
    let r = check::run(&mut Down, &sender(), false, NOW, [7; 16]);
    assert!(matches!(&r.outcome, Outcome::Failed(e) if e.contains("not reached")));
    // Another service behind the URL.
    let mut soc = Soc::new(Fleet::Served);
    soc.wrong_service = true;
    let r = run(&mut soc, false, NOW);
    assert!(matches!(&r.outcome, Outcome::Failed(e) if e.contains("not the RoboDR ingest API")));
    // Key unknown to the SOC.
    let mut soc = Soc::new(Fleet::Served);
    soc.fleet_keys.clear();
    let r = run(&mut soc, false, NOW);
    assert!(
        matches!(&r.outcome, Outcome::Failed(e) if e.contains("unknown_key")),
        "{r:?}"
    );
    // Clock off by more than the skew.
    let mut soc = Soc::new(Fleet::Served);
    let r = run(&mut soc, false, NOW + 300_001);
    assert!(
        matches!(&r.outcome, Outcome::Failed(e) if e.contains("stale_timestamp")),
        "{r:?}"
    );
    // Another public key under the id.
    let mut soc = Soc::new(Fleet::Served);
    let other = Ed25519SigningKey::from_seed_with_derived_id(&[0x62; 32]);
    soc.fleet_keys = vec![(sender().key_id().to_string(), other.public_key())];
    let r = run(&mut soc, false, NOW);
    assert!(
        matches!(&r.outcome, Outcome::Failed(e) if e.contains("bad_signature")),
        "{r:?}"
    );
}

#[test]
fn relay_keys_and_socs_without_the_fleet_api_skip_the_key_step_visibly() {
    let mut soc = Soc::new(Fleet::Served);
    soc.fleet_keys.clear();
    let r = run(&mut soc, true, NOW);
    assert_eq!(r.outcome, Outcome::Ok);
    assert!(r
        .lines
        .iter()
        .any(|l| l.starts_with("skip key registration")));
    let mut soc = Soc::new(Fleet::Absent);
    let r = run(&mut soc, false, NOW);
    assert_eq!(r.outcome, Outcome::Ok);
    assert!(r
        .lines
        .iter()
        .any(|l| l.starts_with("warn key registration not checked")));
}

/// Plain HTTP to loopback in front of [`Soc`] (the binary accepts
/// `http://` to a loopback IP literal without TLS).
fn serve(soc: Soc) -> (u16, Arc<Mutex<Soc>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let soc = Arc::new(Mutex::new(soc));
    let s2 = soc.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut r = BufReader::new(c.try_clone().unwrap());
            let mut start = String::new();
            if r.read_line(&mut start).is_err() {
                continue;
            }
            let mut h = Vec::new();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end().to_string();
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    h.push((k.to_string(), v.trim().to_string()));
                }
            }
            let n: usize = header(&h, "Content-Length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0; n];
            let _ = r.read_exact(&mut body);
            let mut parts = start.split_whitespace();
            let (m, t) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let resp = {
                let mut s = s2.lock().unwrap();
                s.now_ms = robodr_export::now_ms();
                s.handle(m, t, &h, &body)
            };
            let _ = write!(
                c,
                "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                resp.status,
                resp.body.len()
            );
            let _ = c.write_all(&resp.body);
        }
    });
    (port, soc)
}

#[test]
fn binary_check_mode_exits_0_or_1_and_writes_nothing() {
    let tmp = TempDir::new("uplink-check");
    let spool = tmp.path().join("spool");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&spool).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let key = tmp.path().join("uplink.key");
    let kf = robodr_blackbox::KeyFile::ed25519_from_seed(&[0x61; 32], None).unwrap();
    kf.write_new(&key).unwrap();
    let (port, soc) = serve(Soc::new(Fleet::Served));
    let url = format!("http://127.0.0.1:{port}/api");
    let bin = env!("CARGO_BIN_EXE_robodr-uplink");
    let run = |extra: &[&str]| {
        std::process::Command::new(bin)
            .args([
                "--url",
                &url,
                "--key-file",
                key.to_str().unwrap(),
                "--state-dir",
            ])
            .arg(&state)
            .arg("--spool")
            .arg(&spool)
            .args(extra)
            .output()
            .unwrap()
    };
    let o = run(&["--check"]);
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{out}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(out.contains("check passed"), "{out}");
    // Nothing written: no status file, no lock file, no spool state.
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    assert_eq!(soc.lock().unwrap().consumer.finding_count(), 0);
    // The key unknown to the SOC: exit 1.
    soc.lock().unwrap().fleet_keys.clear();
    let o = run(&["--check"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stdout).contains("unknown_key"));
    // --check with --once: usage error.
    let o = run(&["--check", "--once"]);
    assert_eq!(o.status.code(), Some(2));
    // Nothing listening: exit 1, "not reached".
    let o = std::process::Command::new(bin)
        .args([
            "--url",
            "http://127.0.0.1:1/api",
            "--key-file",
            key.to_str().unwrap(),
        ])
        .arg("--state-dir")
        .arg(&state)
        .arg("--spool")
        .arg(&spool)
        .arg("--check")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stdout).contains("not reached"));
}
