//! robodr-setup: preflight against prepared host trees, key generation,
//! role configuration from the shipped examples, fingerprints, the CLI.

mod common;

use common::*;
use robodr_ops::preflight::{self, Level, Options, Probe, Variant};
use robodr_ops::setup::{self, ConfigRequest, KeyKind, Role};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-setup");

/// A healthy standard host.
fn good_host(t: &Tmp) {
    t.put("/sys/kernel/btf/vmlinux", "btf");
    t.put("/proc/self/mounts", "bpf /sys/fs/bpf bpf rw 0 0\n");
    t.put("/proc/sys/kernel/osrelease", "6.8.0-45-generic\n");
    t.put("/proc/1/comm", "systemd\n");
    std::fs::create_dir_all(t.path("/sys/module/nf_tables")).unwrap();
    std::fs::create_dir_all(t.path("/var/lib/robodr")).unwrap();
    mkdir_mode(&t.path("/etc/robodr/keys"), 0o700);
}

fn good_runner() -> Fake {
    Fake::default()
        .with("systemctl --version", 0, "systemd 255 (255.4-1ubuntu8)\n+PAM +AUDIT\n")
        .with("getconf GNU_LIBC_VERSION", 0, "glibc 2.39\n")
        .with("dpkg-query -W -f=${Depends} robodr", 0, "libc6 (>= 2.39), libgcc-s1, systemd (>= 247)")
        .with("timedatectl show -p NTPSynchronized --value", 0, "yes\n")
        .with(
            "df",
            0,
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000000 1 50000000 1% /\n",
        )
}

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_793_408_003)
}

fn opts() -> Options {
    Options {
        build_epoch: 1_790_000_000,
        ..Default::default()
    }
}

fn level(checks: &[preflight::Check], id: &str) -> Level {
    checks.iter().find(|c| c.id == id).unwrap().level
}

#[test]
fn preflight_passes_on_a_good_host() {
    let t = Tmp::new("pf-good");
    good_host(&t);
    let r = good_runner();
    let p = Probe {
        root: t.0.clone(),
        runner: &r,
        now: now(),
    };
    let c = preflight::run(&p, &opts());
    for x in &c {
        assert_eq!(x.level, Level::Ok, "{x:?}");
    }
    assert_eq!(c.len(), 8);
}

#[test]
fn preflight_finds_each_problem() {
    let t = Tmp::new("pf-bad");
    good_host(&t);
    // No kernel BTF, external BTF of another kernel.
    std::fs::remove_file(t.path("/sys/kernel/btf/vmlinux")).unwrap();
    t.put("/etc/robodr/btf/vmlinux", "x");
    t.put(
        "/etc/robodr/btf/vmlinux.kernel",
        "5.15.148-tegra\n#1 SMP\nabc\n",
    );
    // bpffs not mounted, nf_tables nowhere.
    t.put("/proc/self/mounts", "proc /proc proc rw 0 0\n");
    std::fs::remove_dir(t.path("/sys/module/nf_tables")).unwrap();
    t.put(
        "/lib/modules/6.8.0-45-generic/modules.dep",
        "kernel/fs/ext4/ext4.ko:\n",
    );
    // Keys readable by the group.
    mkdir_mode(&t.path("/etc/robodr/keys"), 0o750);
    let r = Fake::default()
        .with("systemctl --version", 0, "systemd 245 (245.4)\n")
        .with("getconf GNU_LIBC_VERSION", 0, "glibc 2.35\n")
        .with("dpkg-query -W -f=${Depends} robodr", 0, "libc6 (>= 2.39)")
        .with("timedatectl show -p NTPSynchronized --value", 0, "no\n")
        .with("df", 0, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1 1 1024000 1% /\n");
    let p = Probe {
        root: t.0.clone(),
        runner: &r,
        now: now(),
    };
    let c = preflight::run(&p, &opts());
    assert_eq!(level(&c, "kernel.btf"), Level::Fail, "{c:?}");
    assert_eq!(level(&c, "bpffs"), Level::Warn);
    assert_eq!(level(&c, "nf_tables"), Level::Warn);
    assert_eq!(level(&c, "systemd"), Level::Fail);
    assert_eq!(level(&c, "glibc"), Level::Fail);
    assert_eq!(level(&c, "clock"), Level::Warn);
    assert_eq!(level(&c, "disk"), Level::Fail); // 1000 MiB < 2048
    assert_eq!(level(&c, "keys.dir"), Level::Fail);
    assert_eq!(preflight::worst(&c), Level::Fail);

    // The clock before the build date fails whatever NTP says.
    let early = Probe {
        root: t.0.clone(),
        runner: &r,
        now: UNIX_EPOCH + Duration::from_secs(1_000_000_000),
    };
    assert_eq!(
        level(&preflight::run(&early, &opts()), "clock"),
        Level::Fail
    );
    // nf_tables as a compressed module, a matching external BTF stamp.
    t.put(
        "/lib/modules/6.8.0-45-generic/modules.dep",
        "kernel/net/netfilter/nf_tables.ko.zst: x\n",
    );
    t.put(
        "/etc/robodr/btf/vmlinux.kernel",
        "6.8.0-45-generic\n#1 SMP\nabc\n",
    );
    let c = preflight::run(&p, &opts());
    assert_eq!(level(&c, "nf_tables"), Level::Ok);
    assert_eq!(level(&c, "kernel.btf"), Level::Ok);
    // No module tree at all, but the kernel answers nft: usable.
    std::fs::remove_dir_all(t.path("/lib/modules")).unwrap();
    assert_eq!(
        level(&preflight::run(&p, &opts()), "nf_tables"),
        Level::Warn
    );
    let r2 = Fake::default().with("nft list tables", 0, "table ip filter\n");
    let p2 = Probe {
        root: t.0.clone(),
        runner: &r2,
        now: now(),
    };
    assert_eq!(level(&preflight::run(&p2, &opts()), "nf_tables"), Level::Ok);
    // No BTF at all: a warning (agentd still runs), not a failure.
    std::fs::remove_dir_all(t.path("/etc/robodr/btf")).unwrap();
    assert_eq!(
        level(&preflight::run(&p, &opts()), "kernel.btf"),
        Level::Warn
    );
}

#[test]
fn preflight_focal_variant() {
    let t = Tmp::new("pf-focal");
    good_host(&t);
    std::fs::remove_file(t.path("/sys/kernel/btf/vmlinux")).unwrap();
    t.put("/usr/lib/robodr/robodr-load-credential", "#!/bin/sh\n");
    assert_eq!(preflight::detect_variant(&t.0), Variant::Focal);
    let r = good_runner().with("systemctl --version", 0, "systemd 245 (245.4-4ubuntu3)\n");
    let p = Probe {
        root: t.0.clone(),
        runner: &r,
        now: now(),
    };
    let o = Options {
        variant: Variant::Focal,
        ..opts()
    };
    let c = preflight::run(&p, &o);
    assert_eq!(level(&c, "kernel.btf"), Level::Skip);
    assert_eq!(level(&c, "bpffs"), Level::Skip);
    assert_eq!(level(&c, "glibc"), Level::Skip);
    assert_eq!(level(&c, "systemd"), Level::Ok, "{c:?}");
    // Not systemd as PID 1.
    t.put("/proc/1/comm", "bash\n");
    assert_eq!(level(&preflight::run(&p, &o), "systemd"), Level::Fail);
}

#[test]
fn keys_are_generated_once_bound_and_never_overwritten() {
    let t = Tmp::new("keys");
    mkdir_mode(&t.path("/etc/robodr/keys"), 0o700);
    let out = setup::generate_keys(
        &t.0,
        "/etc/robodr/keys",
        &[KeyKind::Blackbox, KeyKind::Uplink],
        "ugv-007",
    )
    .unwrap();
    assert_eq!(out.len(), 2);
    assert!(out
        .iter()
        .all(|k| k.action == "created" && k.key_id.starts_with("ed25519:")));
    let sk = t.path("/etc/robodr/keys/agentd-blackbox.key");
    assert_eq!(mode(&sk), 0o600);
    assert_eq!(
        mode(&t.path("/etc/robodr/keys/agentd-blackbox.key.pub")),
        0o644
    );
    let k = robodr_blackbox::KeyFile::load(&sk).unwrap();
    assert_eq!(k.device_id.as_deref(), Some("ugv-007"));
    let u = robodr_blackbox::KeyFile::load(&t.path("/etc/robodr/keys/uplink.key")).unwrap();
    assert_eq!(u.device_id, None);
    let before = std::fs::read(&sk).unwrap();
    // Again: kept, same key.
    let again =
        setup::generate_keys(&t.0, "/etc/robodr/keys", &[KeyKind::Blackbox], "ugv-007").unwrap();
    assert_eq!(again[0].action, "kept");
    assert_eq!(again[0].key_id, out[0].key_id);
    assert_eq!(std::fs::read(&sk).unwrap(), before);
    // A stray public key without its secret is refused (no half pair).
    t.put("/etc/robodr/keys/diode.key.pub", "{}");
    assert!(setup::generate_keys(&t.0, "/etc/robodr/keys", &[KeyKind::Diode], "ugv-007").is_err());
    assert!(!t.path("/etc/robodr/keys/diode.key").exists());
    // A group-readable key directory is refused.
    let t2 = Tmp::new("keys-open");
    mkdir_mode(&t2.path("/etc/robodr/keys"), 0o755);
    let e = setup::generate_keys(&t2.0, "/etc/robodr/keys", &[KeyKind::Blackbox], "x").unwrap_err();
    assert!(e.contains("group/other"), "{e}");
    assert!(std::fs::read_dir(t2.path("/etc/robodr/keys"))
        .unwrap()
        .next()
        .is_none());
    // A bad unit id never reaches a file name.
    assert!(setup::generate_keys(&t.0, "/etc/robodr/keys", &[KeyKind::Blackbox], "../x").is_err());
}

#[test]
fn fingerprints_match_the_commission_definition() {
    let t = Tmp::new("fp");
    mkdir_mode(&t.path("/etc/robodr/keys"), 0o700);
    setup::generate_keys(
        &t.0,
        "/etc/robodr/keys",
        &[KeyKind::Blackbox, KeyKind::Finding],
        "g1-01",
    )
    .unwrap();
    let f = setup::fingerprints(&t.0, "/etc/robodr/keys").unwrap();
    assert_eq!(f.len(), 2);
    for fp in &f {
        let k = robodr_blackbox::KeyFile::load_public(&t.path(&fp.file)).unwrap();
        assert_eq!(fp.key_id, k.key_id);
        assert_eq!(
            fp.key_sha256,
            robodr_commission::trust::revocation::key_fingerprint(&k.public_key().unwrap())
        );
        assert!(fp.file.ends_with(".pub"));
    }
    // Secret files are never listed or opened.
    assert!(f.iter().all(|x| !x.file.ends_with(".key")));
}

fn example(name: &str) -> String {
    std::fs::read_to_string(repo().join("config").join(name)).unwrap()
}

#[test]
fn every_role_renders_a_config_agentd_parses() {
    for role in Role::ALL {
        let Some(ex) = role.agentd_example() else {
            continue;
        };
        let req = ConfigRequest {
            role,
            unit_id: "unit-42".into(),
            site: Some("plant-7".into()),
            interfaces: vec!["enp3s0".into()],
        };
        let (v, review) = setup::render_config(&example(ex), &req).unwrap();
        assert_eq!(v["robot"]["id"], "unit-42");
        assert_eq!(v["robot"]["site"], "plant-7");
        assert_eq!(v["sensor"]["profile_trust"]["expect_unit_id"], "unit-42");
        assert_eq!(v["sensor"]["capture"]["interfaces"][0], "enp3s0");
        robodr_agentd::config::parse(&v.to_string()).unwrap();
        if role == Role::UnitreeSensorBox {
            // Its example operator PC is flagged for review.
            assert!(
                review.iter().any(|p| p.contains("command_senders")),
                "{review:?}"
            );
        }
    }
    let bad = ConfigRequest {
        role: Role::Robot,
        unit_id: "ok".into(),
        site: None,
        interfaces: vec!["eth0; rm -rf /".into()],
    };
    assert!(setup::render_config(&example("agentd.example.json"), &bad).is_err());
}

#[test]
fn config_is_written_once_0640() {
    let t = Tmp::new("cfg");
    std::fs::create_dir_all(t.path("/etc/robodr")).unwrap();
    let root_run = robodr_blackbox::keys::effective_uid() == 0;
    if root_run {
        // As root the file goes to group robodr, which must exist first:
        // without it nothing is created.
        assert!(setup::write_config(&t.0, "/etc/robodr/agentd.json", "{}").is_err());
        assert!(!t.path("/etc/robodr/agentd.json").exists());
    }
    t.put("/etc/group", "root:x:0:\nrobodr:x:4242:robodr-agentd\n");
    assert_eq!(setup::group_gid(&t.0, "robodr"), Some(4242));
    assert!(setup::write_config(&t.0, "/etc/robodr/agentd.json", "{}").unwrap());
    assert_eq!(mode(&t.path("/etc/robodr/agentd.json")), 0o640);
    if root_run {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(t.path("/etc/robodr/agentd.json")).unwrap();
        assert_eq!((md.uid(), md.gid()), (0, 4242));
    }
    assert!(!setup::write_config(&t.0, "/etc/robodr/agentd.json", "{\"x\":1}").unwrap());
    assert_eq!(
        std::fs::read_to_string(t.path("/etc/robodr/agentd.json")).unwrap(),
        "{}\n"
    );
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(BIN).args(args).output().unwrap()
}

#[test]
fn cli_init_refuses_on_a_failed_preflight_and_writes_nothing() {
    let t = Tmp::new("cli-init");
    // A tree with no systemd as PID 1 (the root's /proc/1/comm): FAIL.
    t.put("/proc/1/comm", "bash\n");
    mkdir_mode(&t.path("/etc/robodr/keys"), 0o700);
    let root = t.0.to_str().unwrap();
    let o = run(&["init", "--root", root, "--role", "robot", "--unit-id", "u1"]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert!(String::from_utf8_lossy(&o.stdout).contains("nothing was generated"));
    assert!(std::fs::read_dir(t.path("/etc/robodr/keys"))
        .unwrap()
        .next()
        .is_none());
    // keys.dir may never be ignored.
    let o = run(&["preflight", "--root", root, "--ignore-check", "keys.dir"]);
    assert_eq!(o.status.code(), Some(2));
    // Usage errors.
    assert_eq!(
        run(&["init", "--root", root, "--role", "drone", "--unit-id", "u"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(run(&["frobnicate"]).status.code(), Some(2));
    assert_eq!(run(&["keys", "--root", "relative"]).status.code(), Some(2));
}

#[test]
fn cli_keys_config_fingerprints() {
    let t = Tmp::new("cli-steps");
    mkdir_mode(&t.path("/etc/robodr/keys"), 0o700);
    let ex = t.path("/usr/share/doc/robodr/examples");
    std::fs::create_dir_all(&ex).unwrap();
    std::fs::copy(
        repo().join("config/agentd.example.json"),
        ex.join("agentd.example.json"),
    )
    .unwrap();
    t.put("/etc/group", "robodr:x:4242:\n");
    let root = t.0.to_str().unwrap();
    let o = run(&[
        "keys",
        "--root",
        root,
        "--unit-id",
        "ugv-9",
        "--key",
        "uplink",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(
        s.contains("blackbox") && s.contains("uplink") && s.contains("created"),
        "{s}"
    );
    let o = run(&[
        "config",
        "--root",
        root,
        "--role",
        "robot",
        "--unit-id",
        "ugv-9",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(t.path("/etc/robodr/agentd.json")).unwrap())
            .unwrap();
    assert_eq!(cfg["robot"]["id"], "ugv-9");
    let o = run(&["fingerprints", "--root", root, "--json"]);
    assert!(o.status.success());
    let f: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(f.as_array().unwrap().len(), 2);
    // The secret never appears on stdout.
    let secret = std::fs::read_to_string(t.path("/etc/robodr/keys/agentd-blackbox.key")).unwrap();
    let sk: serde_json::Value = serde_json::from_str(&secret).unwrap();
    let hexs = sk["secret_hex"].as_str().unwrap();
    for args in [
        vec!["fingerprints", "--root", root],
        vec!["keys", "--root", root, "--unit-id", "ugv-9"],
    ] {
        let o = run(&args);
        assert!(!String::from_utf8_lossy(&o.stdout).contains(hexs));
        assert!(!String::from_utf8_lossy(&o.stderr).contains(hexs));
    }
}
