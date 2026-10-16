//! `TpmNvCounterAnchor` under a real `Recorder`: a cut log tail plus rolled
//! back state files (`head.json`, `checkpoint.json`, the anchor's sidecar)
//! is reported as `TruncationDetected`, while the same attack is invisible
//! without the anchor.
//!
//! The scenarios run against an in-process fake TPM always, and against a
//! real software TPM (`swtpm` + `tpm2-tools`) when `ROBODR_SWTPM=1`
//! (`scripts/swtpm-anchor-it.sh`).
mod common;
use common::*;
use robodr_blackbox::record::{ResumePayload, TruncationPayload};
use robodr_blackbox::store::{segment_file_name, CHECKPOINT_FILE, EXTERNAL_ANCHOR, HEAD_FILE};
use robodr_blackbox::tpm_anchor::{attr, format_nv_index, ToolOutput, TpmTools};
use robodr_blackbox::*;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const INDEX: u32 = 0x0150_0020;

// ---------------------------------------------------------------------------
// A minimal fake TPM (one counter index).
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeState {
    written: bool,
    value: u64,
}

#[derive(Debug, Clone, Default)]
struct FakeTpm(Arc<Mutex<FakeState>>);

impl TpmTools for FakeTpm {
    fn run(&self, tool: &str, args: &[String]) -> Result<ToolOutput, String> {
        let mut s = self.0.lock().unwrap();
        assert!(args.iter().any(|a| a == &format_nv_index(INDEX)));
        let out = |stdout: Vec<u8>| ToolOutput {
            status: Some(0),
            stdout,
            stderr: Vec::new(),
        };
        let attrs = 0x0204_0014 | if s.written { attr::WRITTEN } else { 0 };
        Ok(match tool {
            "tpm2_nvreadpublic" => out(format!(
                "{INDEX:#x}:\n  attributes:\n    friendly: x\n    value: {attrs:#x}\n  size: 8\n"
            )
            .into_bytes()),
            "tpm2_nvread" if s.written => out(s.value.to_be_bytes().to_vec()),
            "tpm2_nvincrement" => {
                s.written = true;
                s.value += 1;
                out(Vec::new())
            }
            _ => ToolOutput {
                status: Some(1),
                stdout: Vec::new(),
                stderr: b"ERROR: fake".to_vec(),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Scenario helpers
// ---------------------------------------------------------------------------

fn base_cfg(dir: &Path) -> RecorderConfig {
    let mut c = cfg(dir, big());
    c.max_segment_bytes = 1 << 20;
    c.head_mark_every_records = 4;
    c.head_mark_interval_ns = 0;
    c
}

fn snapshot(dir: &Path, names: &[&str]) -> Vec<(String, Option<Vec<u8>>)> {
    names
        .iter()
        .map(|n| (n.to_string(), std::fs::read(dir.join(n)).ok()))
        .collect()
}

fn restore(dir: &Path, snap: &[(String, Option<Vec<u8>>)]) {
    for (n, b) in snap {
        match b {
            Some(b) => std::fs::write(dir.join(n), b).unwrap(),
            None => {
                let _ = std::fs::remove_file(dir.join(n));
            }
        }
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

fn truncations(dir: &Path) -> Vec<TruncationPayload> {
    all_records(dir)
        .iter()
        .filter(|r| r.kind == RecordKind::TruncationDetected)
        .filter_map(|r| r.payload_json())
        .collect()
}

fn verify_dir_intact(dir: &Path) -> bool {
    robodr_blackbox::verify::verify_dir(dir, &verifier(), &VerifyOptions::default())
        .unwrap()
        .is_intact()
}

/// Record, snapshot the state an attacker keeps, record more, then cut the
/// tail back to the snapshot and restore every state file (the anchor's
/// sidecar included). Without the anchor the open is clean; with it the
/// cut is reported.
fn rollback_scenario(tag: &str, make: &dyn Fn(&Path) -> Arc<dyn HeadAnchor>) {
    let d = TestDir::new(tag);
    let log = d.sub("log");
    let side = d.sub("anchor");
    std::fs::create_dir_all(&side).unwrap();
    let sidecar = side.join("tpm-sidecar.json");
    let mut c = base_cfg(&log);
    c.head_anchor = Some(make(&sidecar));

    let mut r = open(c.clone());
    for i in 0..4 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let kept = r.head_mark().unwrap();
    assert!(sidecar.exists(), "the anchor wrote its sidecar");
    let state = snapshot(&log, &[HEAD_FILE, CHECKPOINT_FILE]);
    let old_sidecar = std::fs::read(&sidecar).unwrap();
    for i in 4..24 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    assert_eq!(r.anchor_failures(), 0, "{:?}", r.last_anchor_error());
    let last = r.close().unwrap().seq;
    assert!(last > kept + 16);

    // The attack: whole frames after `kept` removed, state rolled back.
    let p = log.join(segment_file_name(0));
    let b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    let pos = fr.iter().position(|(_, _, x)| x.seq == kept + 1).unwrap();
    std::fs::write(&p, &b[..fr[pos].0]).unwrap();
    restore(&log, &state);
    std::fs::write(&sidecar, &old_sidecar).unwrap();

    // Control: without the anchor the cut log opens clean.
    let ctl = d.sub("control");
    copy_dir(&log, &ctl);
    let mut cc = base_cfg(&ctl);
    cc.head_anchor = None;
    let r = open(cc);
    assert!(
        !r.open_incidents()
            .iter()
            .any(|i| matches!(i, OpenIncident::TruncationDetected { .. })),
        "{:?}",
        r.open_incidents()
    );
    drop(r);
    assert!(truncations(&ctl).is_empty());

    // With the anchor: the counter moved on, the sidecar did not.
    let r = open(c.clone());
    assert!(
        r.open_incidents()
            .iter()
            .any(|i| matches!(i, OpenIncident::TruncationDetected { .. })),
        "{:?}",
        r.open_incidents()
    );
    assert!(r.head().unwrap().0 > kept + 1);
    drop(r);
    let td = truncations(&log);
    assert_eq!(td.len(), 1);
    let ev = td[0]
        .evidence
        .iter()
        .find(|e| e.file == EXTERNAL_ANCHOR)
        .expect("anchor evidence");
    assert!(
        ev.seq > kept && ev.seq <= last,
        "bound {} in ({kept}, {last}]",
        ev.seq
    );
    assert!(!verify_dir_intact(&log));

    // Wiped store (the sidecar lives elsewhere): reported too.
    std::fs::remove_dir_all(&log).unwrap();
    let r = open(c.clone());
    assert!(r
        .open_incidents()
        .iter()
        .any(|i| matches!(i, OpenIncident::TruncationDetected { .. })));
    r.close().unwrap();

    // Deleted sidecar: no bound, but an anchor failure on the record.
    std::fs::remove_file(&sidecar).unwrap();
    let r = open(c);
    assert!(r.anchor_failures() > 0);
    drop(r);
    let rs: Vec<ResumePayload> = all_records(&log)
        .iter()
        .filter(|r| r.kind == RecordKind::Resume)
        .filter_map(|r| r.payload_json())
        .collect();
    assert!(rs
        .last()
        .unwrap()
        .rejected_state
        .iter()
        .any(|s| s.contains(EXTERNAL_ANCHOR) && s.contains("missing")));
}

fn anchor_cfg(sidecar: &Path) -> TpmAnchorConfig {
    let mut c = TpmAnchorConfig::new(INDEX, sidecar);
    c.min_increment_interval = Duration::ZERO;
    c
}

#[test]
fn fake_tpm_rollback_and_cut_is_reported() {
    let tpm = FakeTpm::default();
    rollback_scenario("tpm-fake", &|sidecar| {
        Arc::new(
            TpmNvCounterAnchor::with_tools(&anchor_cfg(sidecar), Box::new(tpm.clone()), signer())
                .unwrap(),
        )
    });
}

// ---------------------------------------------------------------------------
// Real software TPM
// ---------------------------------------------------------------------------

struct Swtpm {
    child: std::process::Child,
    port: u16,
    _state: TestDir,
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_swtpm() -> Swtpm {
    let state = TestDir::new("swtpm-state");
    let port: u16 = std::env::var("ROBODR_SWTPM_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(20_000 + (std::process::id() % 10_000) as u16 * 2);
    let child = std::process::Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--server",
            &format!("type=tcp,port={port}"),
            "--ctrl",
            &format!("type=tcp,port={}", port + 1),
            "--tpmstate",
            &format!("dir={}", state.path().display()),
            "--flags",
            "not-need-init,startup-clear",
        ])
        .spawn()
        .expect("swtpm (apt install swtpm)");
    let t0 = std::time::Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "swtpm did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Swtpm {
        child,
        port,
        _state: state,
    }
}

fn tools_dir() -> PathBuf {
    std::env::var_os("ROBODR_TPM2_TOOLS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/usr/bin".into())
}

fn cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_robodr-blackbox"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn swtpm_rollback_and_cut_is_reported() {
    if std::env::var("ROBODR_SWTPM").as_deref() != Ok("1") {
        eprintln!("skipped: set ROBODR_SWTPM=1 (needs swtpm and tpm2-tools)");
        return;
    }
    let tpm = start_swtpm();
    let tcti = format!("swtpm:host=127.0.0.1,port={}", tpm.port);
    let tools = tools_dir();
    let tools_s = tools.to_str().unwrap().to_string();
    let idx = format_nv_index(INDEX);
    let auth_dir = TestDir::new("swtpm-auth");
    let auth = auth_dir.sub("index.auth");
    std::fs::write(&auth, b"anchor-index-secret").unwrap();
    let auth_s = auth.to_str().unwrap().to_string();
    let base = ["--index", &idx, "--tcti", &tcti, "--tools-dir", &tools_s];

    // Provision (with an index password, read from a file).
    let mut args = vec!["tpm-anchor-init"];
    args.extend(base);
    args.extend(["--index-auth-file", &auth_s]);
    let o = cli(&args);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // A second init refuses to touch it.
    let mut args = vec!["tpm-anchor-init"];
    args.extend(base);
    let o = cli(&args);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("already defined"));
    let check = |want_written: bool| {
        let mut args = vec!["tpm-anchor-check"];
        args.extend(base);
        args.extend(["--index-auth-file", &auth_s]);
        let o = cli(&args);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(v["counter"], true);
        assert_eq!(v["written"], want_written, "{v}");
        v
    };
    check(false);

    let mk = |sidecar: &Path| -> Arc<dyn HeadAnchor> {
        let mut c = anchor_cfg(sidecar);
        c.tcti = tcti.clone();
        c.tools_dir = tools.clone();
        c.auth_file = Some(auth.clone());
        c.timeout = Duration::from_secs(10);
        Arc::new(TpmNvCounterAnchor::new(&c, signer()).unwrap())
    };
    rollback_scenario("tpm-swtpm", &mk);
    let v = check(true);
    let n: u64 = v["value"].as_str().unwrap().parse().unwrap();
    assert!(n >= 6, "{v}");

    // A wrong index password: the anchor fails (counted), never panics.
    let d = TestDir::new("swtpm-wrongauth");
    let wrong = d.sub("wrong.auth");
    std::fs::write(&wrong, b"not-the-secret").unwrap();
    let mut c = anchor_cfg(&d.sub("sidecar.json"));
    c.tcti = tcti.clone();
    c.tools_dir = tools.clone();
    c.auth_file = Some(wrong);
    let a = TpmNvCounterAnchor::new(&c, signer()).unwrap();
    let mark = Checkpoint {
        chain_id: [1; 32],
        seq: 1,
        hash: [2; 32],
        key_id: KEY_ID.into(),
        sig: vec![1],
    };
    let e = a.advance(&mark).unwrap_err();
    assert!(e.contains("tpm2_nvincrement failed"), "{e}");

    // An ordinary (non-counter) index is refused by the anchor and the CLI.
    let other = format_nv_index(INDEX + 1);
    let o = std::process::Command::new(tools.join("tpm2_nvdefine"))
        .args([
            other.as_str(),
            "-C",
            "o",
            "-s",
            "8",
            "-a",
            "authread|authwrite",
        ])
        .env("TPM2TOOLS_TCTI", &tcti)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = cli(&[
        "tpm-anchor-check",
        "--index",
        &other,
        "--tcti",
        &tcti,
        "--tools-dir",
        &tools_s,
    ]);
    assert_eq!(o.status.code(), Some(1));
    let mut c = anchor_cfg(&d.sub("sidecar2.json"));
    c.nv_index = INDEX + 1;
    c.tcti = tcti.clone();
    c.tools_dir = tools.clone();
    let a = TpmNvCounterAnchor::new(&c, signer()).unwrap();
    let e = a.current().unwrap_err();
    assert!(e.contains("not a counter"), "{e}");
}
