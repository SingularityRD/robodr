//! Sales-readiness WP2 end to end: the periodic `robot.agent.health` record
//! (T5) and the disk early warning (T40, with a real full filesystem).

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::pcap::robot_profile;
use common::*;
use serde_json::json;

type Run = std::thread::JoinHandle<(Result<robodr_agentd::Summary, String>, String)>;

fn spawn(r: robodr_agentd::Resolved) -> (Arc<AtomicBool>, Run) {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    (stop, h)
}

fn finish(stop: Arc<AtomicBool>, h: Run) -> String {
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    log
}

/// T5: one Low, observe-only `robot.agent.health` finding per period, an
/// Update of the same finding each time, carrying the record (state,
/// inputs, versions, reachability, clock, disks); `status.json` shows the
/// same probes; the record is never fed to the correlator.
#[test]
fn t5_health_record_is_periodic_and_carries_the_agent_state() {
    let s = setup("health-record", &robot_profile(true));
    let sock = s.dir.join("ev.sock");
    let cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": sock}]),
        json!({"silence_ms": 400, "self_health": {
            "health_record_ms": 1000,
            "disk_warn_percent": 1, "disk_critical_percent": 0,
            "clock_unsynced_grace_ms": 86_400_000,
        }}),
    );
    let (stop, h) = spawn(s.resolve(&cfg));
    let st = wait_for(15, "two health records", || {
        let st = status(&s.spool)?;
        (st["self_health"]["health_records"].as_u64()? >= 2).then_some(st)
    });
    let log = finish(stop, h);
    assert_eq!(st["self_health"]["health_record_ms"], 1000, "{st}");
    let reach = st["self_health"]["reachability"].as_array().unwrap();
    assert!(reach
        .iter()
        .any(|r| r["component"] == "executor" && r["state"] == "not_configured"));
    assert!(!st["self_health"]["disks"].as_array().unwrap().is_empty());

    let found = spooled(&s.spool);
    let recs: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.agent.health")
        .map(|(_, e)| e)
        .collect();
    assert!(recs.len() >= 2, "{log}");
    let (a, b) = (recs[0], recs[1]);
    assert_eq!(a.finding_id, b.finding_id, "one finding per robot, updated");
    assert_eq!(a.severity, robodr_events::Severity::Low);
    assert_eq!(a.entity_context.mode, robodr_ocsf::Mode::Observe);
    let (ha, hb) = (
        a.entity_context.agent_health.as_ref().unwrap(),
        b.entity_context.agent_health.as_ref().unwrap(),
    );
    assert_eq!((ha.seq, hb.seq), (1, 2));
    assert_eq!(ha.interval_ms, 1000);
    // The input is silent: the record says so.
    assert_eq!(ha.state, robodr_ocsf::HealthLabel::Unknown);
    assert!(
        ha.reasons.iter().any(|r| r.contains("no data yet")),
        "{ha:?}"
    );
    assert_eq!(ha.inputs.len(), 1);
    assert!(ha.inputs[0].name.starts_with("socket:"));
    assert!(ha
        .versions
        .iter()
        .any(|v| v.component == "robodr-agentd" && !v.version.is_empty()));
    assert!(ha
        .versions
        .iter()
        .any(|v| v.component == "robodr.findings" && v.version == robodr_ocsf::CONTRACT_VERSION));
    let names: Vec<&str> = ha.disks.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["blackbox", "spool"]);
    assert_eq!(ha.reachability.len(), 3);
    assert!(hb.counters.health_findings >= 1, "the silence finding");
}

/// The record can be switched off (replay, tests); the early warnings stay.
#[test]
fn t5_health_record_off_emits_none() {
    let s = setup("health-off", &robot_profile(true));
    let cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        json!({"self_health": {"health_record_ms": 0,
            "disk_warn_percent": 1, "disk_critical_percent": 0,
            "clock_unsynced_grace_ms": 86_400_000}}),
    );
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(10, "ticks", || {
        (status(&s.spool)?["daemon"]["ticks"].as_u64()? >= 30).then_some(())
    });
    finish(stop, h);
    assert!(!rules(&spooled(&s.spool))
        .iter()
        .any(|r| r == "robot.agent.health"));
}

/// T40 fault injection: the spool on a small tmpfs that is nearly full is
/// a High `robot.agent.disk_low` before anything is dropped. Needs root
/// (mount); skipped otherwise.
#[test]
fn t40_a_nearly_full_spool_filesystem_is_reported_before_it_fills() {
    if !is_root() {
        eprintln!("skipped: needs root to mount a tmpfs");
        return;
    }
    let s = setup("disk-low", &robot_profile(true));
    let mnt = s.dir.join("small-spool");
    std::fs::create_dir_all(&mnt).unwrap();
    let ok = std::process::Command::new("mount")
        .args(["-t", "tmpfs", "-o", "size=4m,mode=0700", "tmpfs"])
        .arg(&mnt)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipped: mount -t tmpfs failed");
        return;
    }
    struct Umount(std::path::PathBuf);
    impl Drop for Umount {
        fn drop(&mut self) {
            let _ = std::process::Command::new("umount").arg(&self.0).status();
        }
    }
    let _guard = Umount(mnt.clone());
    // Leave about 2 % free (High below 3 %).
    std::fs::write(mnt.join("ballast"), vec![0u8; 4 * 1024 * 1024 - 80 * 1024]).unwrap();
    let spool = mnt.join("spool");
    std::fs::create_dir_all(&spool).unwrap();
    std::fs::set_permissions(&spool, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        json!({"self_health": {"disk_warn_percent": 10, "disk_critical_percent": 3,
            "clock_unsynced_grace_ms": 86_400_000}}),
    );
    cfg["spool"]["dir"] = json!(spool);
    let r = s.resolve(&cfg);
    let (stop, h) = spawn(r);
    wait_for(10, "disk_low spooled", || {
        rules(&spooled(&spool))
            .iter()
            .any(|r| r == "robot.agent.disk_low")
            .then_some(())
    });
    let log = finish(stop, h);
    let found = spooled(&spool);
    let f: Vec<_> = found
        .iter()
        .filter(|(_, e)| {
            e.entity_context.rule_id == "robot.agent.disk_low"
                && e.entity_context
                    .detail
                    .value
                    .contains("the spool filesystem")
        })
        .map(|(_, e)| e)
        .collect();
    // One finding for the spool (the black box is on the machine's own
    // disk, which may be full too): it does not repeat while the level
    // holds.
    assert_eq!(f.len(), 1, "{log}");
    assert_eq!(f[0].severity, robodr_events::Severity::High);
    let st = status(&spool).unwrap();
    let d = st["self_health"]["disks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "spool")
        .unwrap()
        .clone();
    assert!(d["free_bytes"].as_u64().unwrap() * 100 < 3 * d["total_bytes"].as_u64().unwrap());
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .map(|l| l.split_whitespace().nth(1) == Some("0"))
        })
        .unwrap_or(false)
}
