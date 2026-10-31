//! The demo SOC binary over real TCP: signed batches are accepted and
//! shown; bad batch signatures, tampered or unsigned findings and replays
//! are refused or not stored twice; the viewer never builds HTML from data.

use robodr_blackbox::keys::KeyFile;
use robodr_events::{Deviation, Severity};
use robodr_export::uplink::wire;
use robodr_ocsf::{
    sign_value, to_json, FindingBuilder, FirmwareRef, Mode, PlatformFamily, ProfileRef,
    RobotContext, RobotInfo,
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Soc {
    child: Child,
    addr: String,
    dir: PathBuf,
}

impl Drop for Soc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn request(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let text = String::from_utf8_lossy(&out).to_string();
    let status: u16 = text[9..12].parse().unwrap();
    let body_at = text.find("\r\n\r\n").unwrap() + 4;
    (status, out[body_at..].to_vec())
}

fn get_json(addr: &str, path: &str) -> Value {
    let (s, b) = request(addr, "GET", path, &[], b"");
    assert_eq!(s, 200);
    serde_json::from_slice(&b).unwrap()
}

fn start(dir: &Path, uplink: &KeyFile, finding: &KeyFile) -> Soc {
    uplink
        .to_public()
        .unwrap()
        .write_new(&dir.join("uplink.pub"))
        .unwrap();
    finding
        .to_public()
        .unwrap()
        .write_new(&dir.join("finding.pub"))
        .unwrap();
    let cfg = json!({
        "robots": [{"id": "ugv-007", "site": "lab", "require_finding_signature": true}],
        "keys": [{"role": "uplink", "robot": "ugv-007", "pub": dir.join("uplink.pub")},
                 {"role": "finding", "robot": "ugv-007", "pub": dir.join("finding.pub")}],
    });
    std::fs::write(dir.join("soc.json"), cfg.to_string()).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_robodr-demo-soc"))
        .args([
            "--config",
            dir.join("soc.json").to_str().unwrap(),
            "--listen",
            &addr,
        ])
        .args(["--store", dir.join("store.ndjson").to_str().unwrap()])
        .spawn()
        .unwrap();
    let t = Instant::now();
    while TcpStream::connect(&addr).is_err() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "demo SOC did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Soc {
        child,
        addr,
        dir: dir.to_path_buf(),
    }
}

fn ctx() -> RobotContext {
    RobotContext::new(
        RobotInfo {
            id: "ugv-007".into(),
            model: "lab-ugv".into(),
            platform_family: PlatformFamily::LinuxRos2,
            site: "lab".into(),
            firmware: Some(FirmwareRef {
                version: "1".into(),
                sha256: "1f".repeat(32),
            }),
        },
        ProfileRef {
            version: "1".into(),
            sha256: "c0".repeat(32),
        },
        Mode::Enforce,
    )
}

fn finding(rule: &str, t_ms: u64) -> String {
    let dev = Deviation::new(rule.to_string(), Severity::High, "demo");
    to_json(
        &FindingBuilder::from_deviation(&dev, &ctx())
            .seen(t_ms, t_ms)
            .build()
            .unwrap(),
    )
    .unwrap()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn post(soc: &Soc, uplink: &KeyFile, batch: &str, lines: &[Value], bad_sig: bool) -> (u16, Value) {
    let body = lines
        .iter()
        .map(|l| l.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let key = uplink.ed25519_signing_key().unwrap();
    let key_id = wire::expected_key_id(&uplink.public_key().unwrap());
    let ts = now_ms();
    let mut sig = wire::sign_batch(&key, &key_id, batch, ts, body.as_bytes());
    if bad_sig {
        sig = sig.replacen(&sig[..2], if &sig[..2] == "00" { "11" } else { "00" }, 1);
    }
    let (s, b) = request(
        &soc.addr,
        "POST",
        wire::INGEST_PATH,
        &[
            ("Content-Type", wire::CONTENT_TYPE.into()),
            (wire::H_KEY_ID, key_id),
            (wire::H_BATCH_ID, batch.into()),
            (wire::H_TIMESTAMP, ts.to_string()),
            (wire::H_SIGNATURE, sig),
        ],
        body.as_bytes(),
    );
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

#[test]
fn signed_batches_are_stored_and_everything_else_is_refused() {
    let dir = std::env::temp_dir().join(format!("robodr-demo-soc-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let uplink = KeyFile::generate_ed25519(None).unwrap();
    let fkey = KeyFile::generate_ed25519(Some("finding:ugv-007:1")).unwrap();
    let soc = start(&dir, &uplink, &fkey);
    let signer = fkey.ed25519_signing_key().unwrap();
    let signed = |v: &str| json!({"value": v, "sig": serde_json::to_value(sign_value(v, &signer).unwrap()).unwrap()});

    let t = now_ms() - 250;
    let a = finding("robot.ros2.unknown_participant", t);
    let b = finding("robot.motion.linear_over_envelope", t);
    let tampered = {
        let mut l = signed(&finding("robot.ros2.discovery_flood", t));
        // Same finding, one byte more (a trailing space): still valid JSON,
        // no longer the signed bytes.
        let v = format!("{} ", l["value"].as_str().unwrap());
        l["value"] = v.into();
        l
    };
    let unsigned = json!({"value": finding("robot.rtps.malformed_discovery", t), "sig": null});
    let (s, ans) = post(
        &soc,
        &uplink,
        "rdu1-demo-1",
        &[signed(&a), signed(&b), tampered, unsigned],
        false,
    );
    assert_eq!(s, 200, "{ans}");
    assert_eq!(ans["accepted"], 2, "{ans}");
    let codes: Vec<&str> = ans["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["code"].as_str().unwrap())
        .collect();
    assert_eq!(
        codes,
        ["bad_finding_signature", "missing_finding_signature"]
    );

    // Bad batch signature: refused whole.
    let (s, ans) = post(
        &soc,
        &uplink,
        "rdu1-demo-2",
        &[signed(&finding("robot.ros2.unknown_reader", t))],
        true,
    );
    assert_eq!((s, ans["code"].as_str()), (401, Some("bad_signature")));
    // Replay of the first batch: answered, not stored again.
    let (s, ans) = post(
        &soc,
        &uplink,
        "rdu1-demo-1",
        &[signed(&a), signed(&b)],
        false,
    );
    assert_eq!(s, 409, "same batch id, other body: {ans}");

    let m = get_json(&soc.addr, "/api/metrics");
    assert_eq!(m["findings"], 2, "{m}");
    assert_eq!(m["by_verification"]["verified"], 2);
    let tts = m["time_to_soc_ms"]["p50"].as_u64().unwrap();
    assert!((200..60_000).contains(&tts), "{tts}");
    let list = get_json(&soc.addr, "/api/findings?limit=10");
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!(
        std::fs::read_to_string(dir.join("store.ndjson"))
            .unwrap()
            .lines()
            .count(),
        2
    );

    // The viewer: strict CSP, no inline script, no HTML built from data.
    let (s, html) = request(&soc.addr, "GET", "/", &[], b"");
    assert_eq!(s, 200);
    assert!(!String::from_utf8_lossy(&html).contains("<script>"));
    let (_, js) = request(&soc.addr, "GET", "/app.js", &[], b"");
    let js = String::from_utf8_lossy(&js);
    assert!(
        js.contains("textContent")
            && !js.contains("innerHTML")
            && !js.contains("insertAdjacentHTML")
    );
    assert_eq!(
        request(&soc.addr, "DELETE", "/api/findings", &[], b"").0,
        405
    );
    assert_eq!(request(&soc.addr, "GET", "/nope", &[], b"").0, 404);
}
