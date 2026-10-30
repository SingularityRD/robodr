//! Soak of the secure-delivery path with the **shipped unit agent binary**
//! (`robodr-deliverd run`), against the depot's LAN server
//! (`robodr_depot::serve::serve`, what `robodr-depot serve` runs) and a
//! software TPM (`ROBODR_SWTPM=1`). Ignored by default:
//!
//! ```text
//! ROBODR_SWTPM=1 ROBODR_SOAK_ROLLOUTS=20 cargo test --release -p robodr-depot \
//!     --test soak_binaries -- --ignored --nocapture
//! ```
//!
//! One lease-gated unit in the `lab` ring. `ROBODR_SOAK_ROLLOUTS` releases
//! (default 5), each a new bundle chained to the previous one, imported
//! with its entry report, rolled out and approved; every third release
//! also carries a sealed model (unsealed only under the site lease the
//! depot renews with each report). The binary pulls (once a minute),
//! installs, reports. Measured per release: seconds until installed, the
//! agent's RSS, state / black-box bytes. Then, still through the binary:
//! erase-trigger spoofing on its trigger socket (another uid, a person's
//! trigger, garbage), a real tamper input while moving fast (deferred),
//! then idle (executed: nothing unseals any more), and an older lease
//! replayed with `robodr-deliverd lease` after the erase.

mod common;

use common::*;
use robodr_depot::depot::{Depot, RolloutParams};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn bin(name: &str) -> PathBuf {
    // target/<profile>/deps/<test> -> target/<profile>/<name>
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join(name)
}

fn rss_kib(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find(|l| l.starts_with("VmRSS"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn du(p: &Path) -> u64 {
    let mut t = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let m = match e.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if m.is_dir() {
                t += du(&e.path());
            } else {
                t += m.len();
            }
        }
    }
    t
}

fn wait(secs: u64, mut f: impl FnMut() -> bool) -> Option<f64> {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if f() {
            return Some(t.elapsed().as_secs_f64());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
}

fn spawn(cfg: &Path, log: &Path) -> Child {
    Command::new(bin("robodr-deliverd"))
        .args(["run", "--config"])
        .arg(cfg)
        .stdout(Stdio::from(
            std::fs::File::create(log.with_extension("out")).unwrap(),
        ))
        .stderr(Stdio::from(std::fs::File::create(log).unwrap()))
        .spawn()
        .expect("robodr-deliverd binary (cargo build --release -p robodr-deliverd)")
}

#[test]
#[ignore = "needs swtpm + tpm2-tools (ROBODR_SWTPM=1) and the release robodr-deliverd binary"]
fn rollouts_and_erase_through_the_deliverd_binary() {
    if !swtpm_enabled("soak_binaries") {
        return;
    }
    let n: u64 = std::env::var("ROBODR_SOAK_ROLLOUTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let mut site = Site::new("soak14");
    // The files RPK's health check probes this marker (as exit_14a).
    std::fs::write(site.hw.join("nav-stack-ok"), b"sensor").unwrap();
    let mut u = UnitH::new(&site, "ugv-07", &site.ca, true);
    site.write_trust(&[("lab", &["ugv-07"])]);
    u.anchor(&site);
    let cfg = site.depot_config(true, None);
    Depot::init(&cfg, &site.trust_path, now()).unwrap();
    let mut d = Depot::open(cfg, now()).unwrap();
    enrol(&site, &mut d, &u);
    let served = Served::start(d);
    u.connect(served.port);
    let sock = u.dir.join("erase.sock");
    u.cfg_json["erase"] = serde_json::json!({"trigger_socket": sock, "feeder_uids": []});
    u.cfg_json["interval_ms"] = 500.into();
    let cfg_path = u.dir.join("deliverd.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&u.cfg_json).unwrap()).unwrap();
    let st = Command::new(bin("robodr-deliverd"))
        .args(["check-config", "--config"])
        .arg(&cfg_path)
        .status()
        .unwrap();
    assert!(st.success(), "check-config");
    let log = u.dir.join("deliverd.log");
    let mut child = spawn(&cfg_path, &log);
    let pid = child.id();
    let p = RolloutParams {
        soak_s: 0,
        ..Default::default()
    };
    let mut prev: Option<String> = None;
    let mut first_lease: Option<Vec<u8>> = None;
    let mut rows = Vec::new();
    let t_all = Instant::now();
    for i in 1..=n {
        u.safety("idle");
        let mut rpks = vec![site.files_rpk("nav-stack", i)];
        let sealed = i % 3 == 1;
        if sealed {
            rpks.push(site.sealed_model(
                "nav-model",
                i,
                format!("ROBODR-SOAK-MODEL-{i}").as_bytes(),
            ));
        }
        let b = site.bundle(i, prev.clone(), &rpks);
        prev = Some(bundle_hash(&b));
        let r = site.entry_report(&b);
        served.with(|d| d.import(&b, &r, now())).unwrap();
        let digests: Vec<String> = rpks.iter().map(|r| digest(r)).collect();
        let seq = served
            .with(|d| d.rollout_create(&format!("r{i}"), &digests, &["lab".into()], &p, now()))
            .unwrap();
        assert!(served
            .with(|d| d.deploy_approve(seq, &site.ops[0], now()))
            .unwrap());
        let want = i.to_string();
        let secs = wait(240, || {
            u.current("files", "nav-stack").as_deref() == Some(want.as_str())
                && (!sealed
                    || u.current("runtime/model", "nav-model").as_deref() == Some(want.as_str()))
        });
        let alive = child.try_wait().unwrap().is_none();
        let row = serde_json::json!({
            "release": i, "sealed_model": sealed, "installed_after_s": secs,
            "agent_alive": alive, "agent_rss_kib": rss_kib(pid),
            "state_bytes": du(&u.dir.join("state")), "blackbox_bytes": du(&u.dir.join("blackbox")),
            "spool_files": std::fs::read_dir(u.dir.join("spool/ready")).map(|r| r.count()).unwrap_or(0),
        });
        println!("SOAK {row}");
        rows.push(row);
        assert!(
            alive,
            "agent died: {}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
        assert!(
            secs.is_some(),
            "release {i} not installed: {}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
        if first_lease.is_none() {
            first_lease = std::fs::read_dir(u.dir.join("seal")).ok().and_then(|rd| {
                rd.flatten()
                    .find(|e| e.file_name().to_string_lossy().contains("lease"))
                    .and_then(|e| std::fs::read(e.path()).ok())
            });
        }
    }
    println!(
        "SOAK_SUMMARY {}",
        serde_json::json!({"releases": n, "total_s": t_all.elapsed().as_secs(),
            "rules": u.rules().len(), "lease_file_seen": first_lease.is_some()})
    );

    // --- erase-trigger spoofing, through the binary's trigger socket ------
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();
    let as_nobody = Command::new(bin("robodr-deliverd"))
        .args(["tamper", "--socket"])
        .arg(&sock)
        .args(["--trigger", "tamper"])
        .uid(65534)
        .gid(65534)
        .output()
        .unwrap();
    println!(
        "SPOOF nobody tamper: {:?} {}",
        as_nobody.status,
        String::from_utf8_lossy(&as_nobody.stderr)
    );
    for line in [
        &b"{\"format\":\"robodr-erase-trigger/1\",\"trigger\":\"operator\"}\n"[..],
        b"{\"format\":\"robodr-erase-trigger/1\",\"trigger\":\"signed_command\"}\n",
        b"{\"format\":\"robodr-erase-trigger/2\",\"trigger\":\"tamper\"}\n",
        b"{\"format\":\"robodr-erase-trigger/1\",\"trigger\":\"tamper\",\"x\":1}\n",
        b"not json at all\n",
    ] {
        use std::io::Write;
        let mut c = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        let _ = c.write_all(line);
    }
    // A finding with the tamper rule id dropped into the spool.
    std::fs::write(
        u.dir.join("spool/ready/00000000000000099999.json"),
        br#"{"rule_id":"robot.seal.tamper"}"#,
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(3));
    let _ = std::fs::remove_file(u.dir.join("spool/ready/00000000000000099999.json"));
    assert!(
        child.try_wait().unwrap().is_none(),
        "agent alive after spoofing"
    );
    u.seal().probe().expect("no erase from any spoofed trigger");
    println!("SPOOF result: unit still unseals after 7 spoofed triggers");

    // --- a real tamper input while moving fast: deferred; idle: erased -----
    u.safety("moving_fast");
    let t = Command::new(bin("robodr-deliverd"))
        .args(["tamper", "--socket"])
        .arg(&sock)
        .args(["--trigger", "tamper"])
        .status()
        .unwrap();
    assert!(t.success());
    std::thread::sleep(Duration::from_secs(3));
    u.seal().probe().expect("deferred while moving fast");
    let rules = u.rules();
    assert!(
        rules.iter().any(|r| r == "robot.seal.erase_deferred"),
        "{rules:?}"
    );
    u.safety("idle");
    let erased = wait(
        30,
        || matches!(u.seal().probe(), Err(e) if e.kind == robodr_seal::ErrorKind::Erased),
    );
    println!("ERASE executed {erased:?} s after idle");
    assert!(erased.is_some());

    // --- an older lease replayed after the erase ---------------------------
    if let Some(l) = &first_lease {
        let lp = u.dir.join("old-lease.json");
        std::fs::write(&lp, l).unwrap();
        child.kill().ok();
        let _ = child.wait();
        let o = Command::new(bin("robodr-deliverd"))
            .args(["lease", "--config"])
            .arg(&cfg_path)
            .arg("--lease")
            .arg(&lp)
            .output()
            .unwrap();
        println!(
            "LEASE replay after erase: {:?} {}{}",
            o.status,
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(
            matches!(u.seal().probe(), Err(e) if e.kind == robodr_seal::ErrorKind::Erased),
            "an old lease does not revive an erased unit"
        );
    } else {
        child.kill().ok();
        let _ = child.wait();
    }
    let rules = u.rules();
    for want in [
        "robot.seal.tamper",
        "robot.seal.erase_deferred",
        "robot.seal.erased",
    ] {
        assert!(rules.iter().any(|r| r == want), "{want}: {rules:?}");
    }
    println!(
        "RULES {}",
        serde_json::json!(rules.iter().fold(
            std::collections::BTreeMap::<&str, u32>::new(),
            |mut m, r| {
                *m.entry(r.as_str()).or_default() += 1;
                m
            }
        ))
    );
}
