//! `blackbox.head_anchor` kind `tpm_nv_counter`: configuration checks, a
//! daemon whose TPM is unreachable keeps recording (failures counted), and,
//! with `ROBODR_SWTPM=1`, a daemon run against a real software TPM.

mod common;

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use std::path::Path;
use std::time::Duration;

fn replay_cfg(s: &Setup) -> serde_json::Value {
    let pcap = s.pcap(&scenario_frames(1));
    s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    )
}

fn tpm_anchor(sidecar: &Path, tools_dir: &Path, tcti: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": "tpm_nv_counter",
        "nv_index": "0x01500020",
        "sidecar_path": sidecar,
        "tcti": tcti,
        "tools_dir": tools_dir,
        "min_increment_interval_ms": 0,
        "timeout_ms": 5000
    })
}

#[test]
fn tpm_anchor_config_is_checked() {
    let s = setup("tpm-anchor-cfg", &robot_profile(true));
    let adir = s.dir.join("anchor");
    std::fs::create_dir_all(&adir).unwrap();
    let mut cfg = replay_cfg(&s);
    cfg["blackbox"]["head_anchor"] = tpm_anchor(
        &adir.join("sidecar.json"),
        Path::new("/usr/bin"),
        "device:/dev/tpmrm0",
    );
    // Loading never touches the TPM.
    let r = s.resolve(&cfg);
    assert!(
        !r.warnings.iter().any(|w| w.contains("head_anchor")),
        "{:?}",
        r.warnings
    );
    // Only the required fields.
    let mut min = cfg.clone();
    min["blackbox"]["head_anchor"] = serde_json::json!({
        "kind": "tpm_nv_counter", "nv_index": "0x01500020",
        "sidecar_path": adir.join("sidecar.json")
    });
    assert!(robodr_agentd::load(&s.write_config(&min)).is_ok());

    let refused = |field: &str, v: serde_json::Value, want: &str| {
        let mut bad = cfg.clone();
        bad["blackbox"]["head_anchor"][field] = v;
        let e = robodr_agentd::load(&s.write_config(&bad)).unwrap_err();
        assert!(e.contains(want), "{field}: {e}");
    };
    refused("nv_index", "0x81000001".into(), "nv_index");
    refused("nv_index", "1500020".into(), "nv_index");
    refused(
        "sidecar_path",
        s.blackbox.join("sidecar.json").to_str().into(),
        "must not be inside blackbox.dir",
    );
    refused(
        "sidecar_path",
        s.spool.join("sidecar.json").to_str().into(),
        "must not be inside spool.dir",
    );
    refused("sidecar_path", "rel/sidecar.json".into(), "absolute");
    refused("tools_dir", "usr/bin".into(), "absolute");
    refused("auth_file", "index.auth".into(), "absolute");
    refused("timeout_ms", 50.into(), "timeout_ms");
    refused(
        "min_increment_interval_ms",
        86_400_001u64.into(),
        "min_increment",
    );
    refused("tcti", "a\nb".into(), "TCTI");
    refused("bogus", 1.into(), "bogus");
}

#[test]
fn unreachable_tpm_never_stops_recording() {
    let s = setup("tpm-anchor-down", &robot_profile(true));
    let adir = s.dir.join("anchor");
    let empty = s.dir.join("no-tools");
    std::fs::create_dir_all(&adir).unwrap();
    std::fs::create_dir_all(&empty).unwrap();
    let mut cfg = replay_cfg(&s);
    cfg["blackbox"]["head_anchor"] = tpm_anchor(&adir.join("sidecar.json"), &empty, "mssim");
    let r = s.resolve(&cfg);
    robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
    let st = status(&s.spool).expect("status.json");
    assert_eq!(st["blackbox"]["anchored"], true, "{st}");
    assert_eq!(st["blackbox"]["anchor_kind"], "tpm_nv_counter");
    assert!(
        st["blackbox"]["anchor_failures"].as_u64().unwrap() > 0,
        "{st}"
    );
    assert!(!adir.join("sidecar.json").exists());
}

#[test]
fn daemon_anchors_on_a_software_tpm() {
    if std::env::var("ROBODR_SWTPM").as_deref() != Ok("1") {
        eprintln!("skipped: set ROBODR_SWTPM=1 (needs swtpm and tpm2-tools)");
        return;
    }
    let s = setup("tpm-anchor-swtpm", &robot_profile(true));
    let state = s.dir.join("swtpm-state");
    std::fs::create_dir_all(&state).unwrap();
    let port: u16 = std::env::var("ROBODR_SWTPM_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .map(|p| p + 10)
        .unwrap_or(30_000 + (std::process::id() % 10_000) as u16 * 2);
    let mut child = std::process::Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--server",
            &format!("type=tcp,port={port}"),
            "--ctrl",
            &format!("type=tcp,port={}", port + 1),
            "--tpmstate",
            &format!("dir={}", state.display()),
            "--flags",
            "not-need-init,startup-clear",
        ])
        .spawn()
        .expect("swtpm");
    let t0 = std::time::Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "swtpm did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let tcti = format!("swtpm:host=127.0.0.1,port={port}");
    let res = std::panic::catch_unwind(|| {
        let o = std::process::Command::new("/usr/bin/tpm2_nvdefine")
            .args([
                "0x01500020",
                "-C",
                "o",
                "-s",
                "8",
                "-a",
                robodr_blackbox::tpm_anchor::PROVISION_ATTRIBUTES,
            ])
            .env("TPM2TOOLS_TCTI", &tcti)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let adir = s.dir.join("anchor");
        std::fs::create_dir_all(&adir).unwrap();
        let sidecar = adir.join("sidecar.json");
        let mut cfg = replay_cfg(&s);
        cfg["blackbox"]["head_anchor"] = tpm_anchor(&sidecar, Path::new("/usr/bin"), &tcti);
        let r = s.resolve(&cfg);
        robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
        let st = status(&s.spool).expect("status.json");
        assert_eq!(st["blackbox"]["anchor_kind"], "tpm_nv_counter", "{st}");
        assert_eq!(st["blackbox"]["anchor_failures"], 0, "{st}");
        let side: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert!(side["seq"].as_u64().unwrap() > 0, "{side}");
        assert!(side["counter"].as_u64().unwrap() >= 1, "{side}");
        // A second run opens clean against the anchor.
        robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
        let st = status(&s.spool).expect("status.json");
        assert_eq!(st["blackbox"]["anchor_failures"], 0, "{st}");
    });
    let _ = child.kill();
    let _ = child.wait();
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}
