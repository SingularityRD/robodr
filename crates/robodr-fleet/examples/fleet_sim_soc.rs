//! Fleet capacity simulator, SOC side (sales-readiness T71): the reference
//! SOC of `docs/contracts/robodr.fleet-api.md` (`tests/common/soc.rs`)
//! behind a TLS listener, plus the per-unit configuration for N simulated
//! units. Driven by `tools/fleet-sim/run.sh`, which runs the real
//! `robodr-enroll` binary for every unit (in its own network namespace with
//! `--netns`) through enroll, uplink rotation and decommission.
//!
//! ```text
//! cargo run -p robodr-fleet --example fleet_sim_soc -- \
//!     --units N --dir DIR --listen IP:PORT --url https://IP:PORT/api \
//!     --cert server.pem --key server.key --ca ca.pem
//! ```
//!
//! It writes `DIR/units/<robot>/` for every unit (fleet.json, agentd.json,
//! the SOC public keys, the CA bundle, a 0600 token file, an empty 0700
//! key directory), prints `ready <N>` on stdout once listening, and serves
//! until killed. `GET /_sim/stats` (outside the fleet API) answers the
//! SOC's counts as JSON. **Test keys and test PKI only: never point a real
//! unit at it.**

#[path = "../tests/common/soc.rs"]
mod soc;

use robodr_blackbox::{Ed25519SigningKey, KeyFile};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use soc::{Soc, BASE};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const WORKSPACE: &str = "ws-fleet-sim";
const SITE: &str = "sim-site";
const MAX_UNITS: usize = 5000;

fn now_ms() -> u64 {
    robodr_fleet::state::system_now_ms()
}

fn die(m: &str) -> ! {
    eprintln!("fleet_sim_soc: {m}");
    std::process::exit(2)
}

fn arg(args: &[String], name: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| die(&format!("{name} is required")))
}

fn write_mode(p: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(p, bytes).unwrap_or_else(|e| die(&format!("{}: {e}", p.display())));
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| die(&format!("{}: {e}", p.display())));
}

fn mkdir(p: &Path, mode: u32) {
    std::fs::create_dir_all(p).unwrap_or_else(|e| die(&format!("{}: {e}", p.display())));
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| die(&format!("{}: {e}", p.display())));
}

fn public_file(p: &Path, k: &Ed25519SigningKey) {
    let kf = KeyFile::ed25519_public(&k.public_key(), None).unwrap_or_else(|e| die(&e.to_string()));
    write_mode(p, kf.to_json().as_bytes(), 0o644);
}

/// One unit's directory and token.
fn prepare_unit(dir: &Path, robot: &str, url: &str, ca: &Path, token: &str, soc: &Soc) {
    let u = dir.join("units").join(robot);
    let etc = u.join("etc");
    mkdir(&etc, 0o755);
    mkdir(&etc.join("keys"), 0o700);
    mkdir(&u.join("var"), 0o755);
    public_file(&etc.join("fleet-soc.pub"), &soc.soc_key);
    public_file(&etc.join("fleet-approval.pub"), &soc.approval_key);
    std::fs::copy(ca, etc.join("soc-ca.pem")).unwrap_or_else(|e| die(&e.to_string()));
    write_mode(
        &etc.join("agentd.json"),
        serde_json::json!({"robot": {"id": robot, "site": SITE}})
            .to_string()
            .as_bytes(),
        0o644,
    );
    let cfg = serde_json::json!({
        "format": "robodr-fleet-config/v1",
        "state_dir": u.join("var/fleet"),
        "agentd_config": etc.join("agentd.json"),
        "soc": {"url": url, "ca_bundle": etc.join("soc-ca.pem"),
                "keys": [etc.join("fleet-soc.pub")],
                "approval_keys": [etc.join("fleet-approval.pub")]},
        "workspace": WORKSPACE,
        "keys": {"uplink": etc.join("keys/uplink.key"),
                 "finding": etc.join("keys/agentd-finding.key"),
                 "blackbox": etc.join("keys/agentd-blackbox.key")},
    });
    write_mode(&etc.join("fleet.json"), cfg.to_string().as_bytes(), 0o644);
    write_mode(&u.join("token.txt"), format!("{token}\n").as_bytes(), 0o600);
}

fn stats(s: &Soc, requests: u64) -> Vec<u8> {
    let active = s.keys.values().filter(|k| k.retired_at.is_none()).count();
    let enrolled = s.tokens.values().filter(|t| t.consumed.is_some()).count();
    let fprs: std::collections::BTreeSet<&str> =
        s.keys.values().map(|k| k.fingerprint.as_str()).collect();
    serde_json::to_vec(&serde_json::json!({
        "units_enrolled": enrolled,
        "keys_registered": s.keys.len(),
        "keys_distinct_fingerprints": fprs.len(),
        "keys_active": active,
        "rotations": s.rotations.len(),
        "rotations_open": s.rotations.values().filter(|r| r.open()).count(),
        "decommissioned": s.decommissions.len(),
        "requests": requests,
    }))
    .unwrap_or_default()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let units: usize = arg(&args, "--units")
        .parse()
        .unwrap_or_else(|_| die("--units N"));
    if units == 0 || units > MAX_UNITS {
        die(&format!("--units must be 1..={MAX_UNITS}"));
    }
    let dir = PathBuf::from(arg(&args, "--dir"));
    let listen = arg(&args, "--listen");
    let url = arg(&args, "--url");
    let ca = PathBuf::from(arg(&args, "--ca"));
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(arg(&args, "--cert"))
        .unwrap_or_else(|e| die(&format!("--cert: {e}")))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| die(&format!("--cert: {e}")));
    let key = PrivateKeyDer::from_pem_file(arg(&args, "--key"))
        .unwrap_or_else(|e| die(&format!("--key: {e}")));
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| die(&e.to_string()))
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap_or_else(|e| die(&e.to_string())),
    );
    // Fresh SOC keys per run (test keys; the units get their public halves).
    let mut seed = [0u8; 32];
    robodr_blackbox::crypto::fill_random(&mut seed).unwrap_or_else(|e| die(&e.to_string()));
    let fleet_key = Ed25519SigningKey::from_seed_with_derived_id(&seed);
    robodr_blackbox::crypto::fill_random(&mut seed).unwrap_or_else(|e| die(&e.to_string()));
    let approval_key = Ed25519SigningKey::from_seed_with_derived_id(&seed);
    let mut soc = Soc::new(fleet_key, approval_key, WORKSPACE, now_ms());
    for i in 1..=units {
        let robot = format!("ugv-{i:04}");
        let mut nonce = [0u8; 32];
        robodr_blackbox::crypto::fill_random(&mut nonce).unwrap_or_else(|e| die(&e.to_string()));
        soc.now_ms = now_ms();
        // Bulk issue: one token per unit, valid 24 h.
        let tok = soc.issue_token(
            &format!("tok-{i:04}"),
            &robot,
            Some(SITE),
            86_400_000,
            nonce,
        );
        prepare_unit(&dir, &robot, &url, &ca, &tok, &soc);
    }
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| die(&format!("{listen}: {e}")));
    println!("ready {units}");
    let _ = std::io::stdout().flush();
    let soc = Arc::new(Mutex::new(soc));
    let requests = Arc::new(AtomicU64::new(0));
    for conn in listener.incoming() {
        let Ok(tcp) = conn else { continue };
        let (tls, soc, requests) = (tls.clone(), soc.clone(), requests.clone());
        std::thread::spawn(move || {
            let Ok(c) = rustls::ServerConnection::new(tls) else {
                return;
            };
            let mut s = rustls::StreamOwned::new(c, tcp);
            let mut r = BufReader::new(&mut s);
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
                if let Some((k, v)) = l.split_once(':') {
                    headers.push((k.to_string(), v.trim().to_string()));
                }
            }
            let n: usize = soc::header(&headers, "Content-Length")
                .first()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
                .min(1 << 20);
            let mut body = vec![0u8; n];
            if r.read_exact(&mut body).is_err() {
                return;
            }
            drop(r);
            let mut parts = start.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let target = parts.next().unwrap_or("").to_string();
            let n = requests.fetch_add(1, Ordering::Relaxed) + 1;
            let (status, body) = {
                let mut g = soc.lock().unwrap_or_else(|p| p.into_inner());
                g.now_ms = now_ms();
                if target == "/_sim/stats" {
                    (200, stats(&g, n))
                } else {
                    match target.strip_prefix(BASE) {
                        Some(t) => {
                            let r = g.handle(&method, t, &headers, &body);
                            (r.status, r.body)
                        }
                        None => (404, br#"{"code":"not_found","detail":""}"#.to_vec()),
                    }
                }
            };
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
            let _ = s.flush();
            s.conn.send_close_notify();
            let _ = s.conn.complete_io(&mut s.sock);
        });
    }
}
