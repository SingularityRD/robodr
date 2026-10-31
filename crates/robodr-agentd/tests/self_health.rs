//! Sales-readiness WP2 end to end: the periodic `robot.agent.health` record
//! (T5), the disk early warning and a real ENOSPC on the spool and the
//! black box (T40, on a small tmpfs), and the producer cap (T38).

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
        .any(|v| v.component == "robodr.findings" && v.version == a.contract_version));
    assert_eq!(a.contract_version, robodr_ocsf::CONTRACT_VERSION);
    let names: Vec<&str> = ha.disks.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["blackbox", "spool"]);
    assert_eq!(ha.reachability.len(), 3);
    assert!(hb.counters.health_findings >= 1, "the silence finding");
}

/// Refuse `adjtimex(2)` and `clock_adjtime(2)` with EPERM on the calling
/// thread and the threads it starts, as the shipped unit's
/// `ProtectClock=yes` / `SystemCallFilter=~@clock` does. `false` where this
/// test cannot install the filter.
#[allow(unsafe_code)]
fn deny_clock_syscalls_like_the_unit() -> bool {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        use std::ffi::{c_int, c_ulong};
        #[repr(C)]
        struct SockFilter {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }
        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *const SockFilter,
        }
        extern "C" {
            fn prctl(
                option: c_int,
                arg2: c_ulong,
                arg3: c_ulong,
                arg4: c_ulong,
                arg5: c_ulong,
            ) -> c_int;
        }
        // (AUDIT_ARCH_*, __NR_adjtimex, __NR_clock_adjtime)
        #[cfg(target_arch = "x86_64")]
        const ARCH: (u32, u32, u32) = (0xC000_003E, 159, 305);
        #[cfg(target_arch = "aarch64")]
        const ARCH: (u32, u32, u32) = (0xC000_00B7, 171, 266);
        const LD_ABS_W: u16 = 0x20;
        const JEQ_K: u16 = 0x15;
        const RET_K: u16 = 0x06;
        let f = |code, jt, jf, k| SockFilter { code, jt, jf, k };
        let prog = [
            f(LD_ABS_W, 0, 0, 4),            // 0: arch
            f(JEQ_K, 0, 3, ARCH.0),          // 1: other arch -> allow
            f(LD_ABS_W, 0, 0, 0),            // 2: syscall nr
            f(JEQ_K, 2, 0, ARCH.1),          // 3: adjtimex -> EPERM
            f(JEQ_K, 1, 0, ARCH.2),          // 4: clock_adjtime -> EPERM
            f(RET_K, 0, 0, 0x7fff_0000),     // 5: allow
            f(RET_K, 0, 0, 0x0005_0000 | 1), // 6: errno EPERM
        ];
        let fprog = SockFprog {
            len: prog.len() as u16,
            filter: prog.as_ptr(),
        };
        // SAFETY: plain prctl(2) calls; `fprog` and `prog` outlive them
        // (the kernel copies the program).
        unsafe {
            prctl(38, 1, 0, 0, 0) == 0 // PR_SET_NO_NEW_PRIVS
                && prctl(22, 2, &fprog as *const SockFprog as c_ulong, 0, 0) == 0
            // PR_SET_SECCOMP, FILTER
        }
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        false
    }
}

/// T7 under the shipped unit: its seccomp filter refuses `adjtimex(2)`, so
/// the kernel clock is not known. The record and `status.json` must say
/// the probe was refused (`adjtimex_errno` 1) instead of looking like a
/// platform without one, and claim no synchronisation state from it.
#[test]
fn t7_refused_clock_probe_is_reported() {
    let s = setup("clock-refused", &robot_profile(true));
    let cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        json!({"self_health": {"health_record_ms": 1000,
            "disk_warn_percent": 1, "disk_critical_percent": 0,
            "clock_unsynced_grace_ms": 0}}),
    );
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h: Run = std::thread::spawn(move || {
        if !deny_clock_syscalls_like_the_unit() {
            return (Err("seccomp filter not installed".into()), String::new());
        }
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    let st = wait_for(15, "a health record", || {
        let st = status(&s.spool)?;
        (st["self_health"]["health_records"].as_u64()? >= 1).then_some(st)
    });
    let log = finish(stop, h);
    let clock = &st["self_health"]["clock"];
    assert_eq!(clock["adjtimex_errno"], 1, "{st}");
    assert!(clock.get("max_error_ms").is_none(), "{clock}");
    // Without a fresh timesyncd marker nothing is claimed.
    if clock.get("timesync_age_ms").is_none() {
        assert!(clock.get("synchronized").is_none(), "{clock}");
    }
    let found = spooled(&s.spool);
    let rec = found
        .iter()
        .find_map(|(_, e)| e.entity_context.agent_health.as_ref())
        .unwrap_or_else(|| panic!("no health record\n{log}"));
    assert_eq!(rec.clock.adjtimex_errno, Some(1));
    // A refused probe never raises clock_unsynced (grace 0 here).
    assert!(!rules(&found)
        .iter()
        .any(|r| r == "robot.agent.clock_unsynced"));
}

/// T38: `findings.max_contract_minor: 4` makes agentd emit contract 2.4.0
/// findings a 2.4 SOC accepts, without a 2.5 `agent_health` record. The
/// `robot.agent.health` heartbeat (a 2.5 finding no 2.4 producer sent) is
/// switched off, and the log and `status.json` say so. A cap above this
/// build's contract is refused at load.
#[test]
fn t38_producer_cap_emits_the_older_contract() {
    let s = setup("contract-cap", &robot_profile(true));
    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        // The silent input gives a finding that does not depend on the
        // machine (robot.agent.input_silent, catalogued since 2.0).
        json!({"silence_ms": 400, "self_health": {"health_record_ms": 1000,
            "disk_warn_percent": 1, "disk_critical_percent": 0,
            "clock_unsynced_grace_ms": 86_400_000}}),
    );
    cfg["findings"] = json!({"max_contract_minor": robodr_ocsf::CONTRACT_MINOR + 1});
    let err = robodr_agentd::load(&s.write_config(&cfg))
        .unwrap_err()
        .to_string();
    assert!(err.contains("max_contract_minor"), "{err}");
    cfg["findings"] = json!({"max_contract_minor": 4});
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(15, "an input_silent finding", || {
        rules(&spooled(&s.spool))
            .iter()
            .any(|r| r == "robot.agent.input_silent")
            .then_some(())
    });
    // Three health periods (60 ticks of 50 ms) go by without a record.
    let st = wait_for(15, "60 ticks", || {
        let st = status(&s.spool)?;
        (st["daemon"]["ticks"].as_u64()? >= 60).then_some(st)
    });
    let log = finish(stop, h);
    assert_eq!(st["self_health"]["health_record_ms"], 0, "{st}");
    assert_eq!(st["self_health"]["health_records"], 0, "{st}");
    assert!(
        log.contains("findings.max_contract_minor 4: the robot.agent.health record is off"),
        "{log}"
    );
    let found = spooled(&s.spool);
    assert!(!found.is_empty(), "{log}");
    for (_, e) in &found {
        assert_eq!(e.contract_version, "2.4.0", "{}", e.entity_context.rule_id);
        assert!(e.entity_context.agent_health.is_none());
        assert_ne!(e.entity_context.rule_id, "robot.agent.health", "{log}");
    }
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
/// a High `robot.agent.disk_low` before anything is dropped. Mounting needs
/// root: as root the test mounts directly, otherwise through passwordless
/// `sudo -n` (CI runners), owned by the test's own user; it is skipped
/// (with a message) only where neither works.
#[test]
fn t40_a_nearly_full_spool_filesystem_is_reported_before_it_fills() {
    let Some(as_root) = privileged() else {
        eprintln!("skipped: needs root or passwordless sudo to mount a tmpfs");
        return;
    };
    let s = setup("disk-low", &robot_profile(true));
    let mnt = s.dir.join("small-spool");
    std::fs::create_dir_all(&mnt).unwrap();
    let (uid, gid) = ids();
    let ok = as_root("mount")
        .args(["-t", "tmpfs", "-o"])
        .arg(format!("size=4m,mode=0700,uid={uid},gid={gid}"))
        .arg("tmpfs")
        .arg(&mnt)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipped: mount -t tmpfs failed");
        return;
    }
    struct Umount(std::path::PathBuf, fn(&str) -> std::process::Command);
    impl Drop for Umount {
        fn drop(&mut self) {
            let _ = (self.1)("umount").arg(&self.0).status();
        }
    }
    let _guard = Umount(mnt.clone(), as_root);
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

/// T40 fault injection, real ENOSPC: the spool and the black box share a
/// small tmpfs that is then filled to the last byte. agentd keeps running
/// (no panic, no exit), counts the lost spool writes and the black-box
/// errors, reports the evidence as degraded, and once space is freed it
/// writes again: the black box recovers and new findings are spooled.
#[test]
fn t40_a_full_filesystem_is_survived_and_recovered_from() {
    let Some(as_root) = privileged() else {
        eprintln!("skipped: needs root or passwordless sudo to mount a tmpfs");
        return;
    };
    let s = setup("enospc", &robot_profile(true));
    let mnt = s.dir.join("small-fs");
    std::fs::create_dir_all(&mnt).unwrap();
    let (uid, gid) = ids();
    let ok = as_root("mount")
        .args(["-t", "tmpfs", "-o"])
        .arg(format!("size=8m,mode=0700,uid={uid},gid={gid}"))
        .arg("tmpfs")
        .arg(&mnt)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipped: mount -t tmpfs failed");
        return;
    }
    struct Umount(std::path::PathBuf, fn(&str) -> std::process::Command);
    impl Drop for Umount {
        fn drop(&mut self) {
            let _ = (self.1)("umount").arg(&self.0).status();
        }
    }
    let _guard = Umount(mnt.clone(), as_root);
    let (spool, bb) = (mnt.join("spool"), mnt.join("blackbox"));
    for d in [&spool, &bb] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::set_permissions(d, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    }
    let mut cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": s.dir.join("ev.sock")}]),
        // A health record (a spooled finding, black-box records) every
        // second, whatever the input does.
        json!({"self_health": {"health_record_ms": 1000,
            "disk_warn_percent": 1, "disk_critical_percent": 0,
            "clock_unsynced_grace_ms": 86_400_000}}),
    );
    cfg["spool"]["dir"] = json!(spool);
    cfg["blackbox"]["dir"] = json!(bb);
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(15, "a first health record", || {
        (status(&spool)?["self_health"]["health_records"].as_u64()? >= 1).then_some(())
    });
    // Fill the filesystem to the last byte.
    let ballast = mnt.join("ballast");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&ballast).unwrap();
        let chunk = vec![0u8; 4096];
        loop {
            match f.write(&chunk) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    assert_eq!(e.raw_os_error(), Some(28), "{e}");
                    break;
                }
            }
        }
    }
    // Three health periods on a full filesystem.
    std::thread::sleep(std::time::Duration::from_millis(3_500));
    assert!(!h.is_finished(), "agentd stopped on a full filesystem");
    let before = spooled(&spool).len();
    std::fs::remove_file(&ballast).unwrap();
    let st = wait_for(20, "recovery: evidence written, findings spooled", || {
        let st = status(&spool)?;
        let recovered = st["evidence_degraded"] == false
            && st["spool"]["write_errors"].as_u64()? >= 1
            && st["agent"]["evidence_errors"].as_u64()? >= 1;
        (recovered && spooled(&spool).len() > before).then_some(st)
    });
    let log = finish(stop, h);
    assert_eq!(st["running"], true, "{st}\n{log}");
}

/// The test's real uid and gid.
fn ids() -> (u32, u32) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(u32::MAX)
    };
    (field("Uid:"), field("Gid:"))
}

/// How to run a command as root: directly, or through `sudo -n`.
fn privileged() -> Option<fn(&str) -> std::process::Command> {
    fn direct(c: &str) -> std::process::Command {
        std::process::Command::new(c)
    }
    fn sudo(c: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new("sudo");
        cmd.args(["-n", c]);
        cmd
    }
    if ids().0 == 0 {
        return Some(direct as fn(&str) -> std::process::Command);
    }
    let ok = sudo("true").status().is_ok_and(|s| s.success());
    ok.then_some(sudo as fn(&str) -> std::process::Command)
}
