//! `robodr-replay` argument validation, table-driven: every valued option
//! without a value, switches given a value, repeated options, bad enum and
//! number values, key sources, key/value options, and the accepted forms.
//! Every usage error must exit 2 with a message, never panic (101) and
//! never start a replay.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_robodr-replay"))
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A complete, valid `run` invocation for the demo scenario.
fn base(bb: &Path) -> Vec<String> {
    let ex = examples();
    let p = |x: PathBuf| x.to_string_lossy().into_owned();
    vec![
        "--events".into(),
        p(ex.join("rogue-ugv.jsonl")),
        "--profile".into(),
        p(ex.join("ugv-demo.profile.json")),
        "--trusted-keys".into(),
        p(ex.join("ugv-demo.trust.json")),
        "--policy".into(),
        p(ex.join("policy-oem-validated.json")),
        "--blackbox".into(),
        p(bb.to_path_buf()),
        "--key-file".into(),
        key_arg(),
        "--robot-id".into(),
        ROBOT.into(),
        "--safety-state".into(),
        "moving_slow".into(),
    ]
}

fn run_with(bb: &Path, extra: &[&str]) -> Output {
    bin().args(base(bb)).args(extra).output().unwrap()
}

/// Assert a usage error: exit 2, message contains `needle`, and no black
/// box was created (nothing ran).
fn assert_usage_error(o: &Output, bb: &Path, needle: &str, what: &str) {
    let err = stderr(o);
    assert_eq!(o.status.code(), Some(2), "{what}: {err}");
    assert!(err.contains(needle), "{what}: expected {needle:?} in {err}");
    assert!(!err.contains("panicked"), "{what}: {err}");
    assert!(!bb.exists(), "{what}: a replay started");
}

const VALUED: &[&str] = &[
    "events",
    "profile",
    "policy",
    "blackbox",
    "key-file",
    "robot-id",
    "out",
    "outcomes",
    "safety-state",
    "control",
    "phase",
    "connectivity",
    "site",
    "model",
    "boot-id",
    "trusted-keys",
    "profile-state",
    "allow-profile-rollback",
    "start-ms",
    "step-ms",
    "firewall-allow",
    "firewall-max-angular",
    "monitor-config",
    "feedback-source",
    "partitions",
    "findings",
];

const SWITCHES: &[&str] = &[
    "firewall",
    "monitor",
    "record-all-events",
    "log-plans",
    "no-operator",
    "help",
];

#[test]
fn every_valued_option_needs_a_value() {
    let dir = tmpdir("flags-noval");
    let bb = dir.join("bb");
    for name in VALUED {
        // Trailing, so there is nothing to take as its value.
        let o = run_with(&bb, &[&format!("--{name}")]);
        assert_usage_error(&o, &bb, &format!("--{name} needs a value"), name);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn switches_take_no_value() {
    let dir = tmpdir("flags-sw");
    let bb = dir.join("bb");
    for name in SWITCHES {
        let o = run_with(&bb, &[&format!("--{name}=yes")]);
        assert_usage_error(&o, &bb, &format!("--{name} takes no value"), name);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn single_valued_options_cannot_repeat() {
    let dir = tmpdir("flags-dup");
    let bb = dir.join("bb");
    for (name, v) in [
        ("events", "x"),
        ("robot-id", "other"),
        ("safety-state", "idle"),
        ("control", "teleop"),
        ("phase", "task"),
        ("connectivity", "degraded"),
        ("site", "s"),
        ("model", "m"),
        ("start-ms", "1"),
        ("step-ms", "1"),
        ("partitions", "1"),
        ("key-file", "k"),
        ("out", "x"),
    ] {
        let mut extra = vec![format!("--{name}"), v.to_string()];
        if !["events", "robot-id", "safety-state", "key-file"].contains(&name) {
            extra.extend([format!("--{name}"), v.to_string()]);
        }
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        let o = run_with(&bb, &extra);
        assert_usage_error(&o, &bb, "given more than once", name);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn unknown_options_and_positionals_are_refused() {
    let dir = tmpdir("flags-unk");
    let bb = dir.join("bb");
    for (args, needle) in [
        (vec!["--bogus"], "unknown option --bogus"),
        (vec!["--"], "unknown option --"),
        (vec!["---events", "x"], "unknown option"),
        (vec!["--EVENTS", "x"], "unknown option --EVENTS"),
        (vec!["-e", "x"], "unexpected argument"),
        (vec!["stray"], "unexpected argument"),
        (vec!["verify"], "unexpected argument"), // subcommand only first
    ] {
        let o = run_with(&bb, &args);
        assert_usage_error(&o, &bb, needle, &format!("{args:?}"));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn bad_enum_values_are_refused() {
    let dir = tmpdir("flags-enum");
    let bb = dir.join("bb");
    for (flag, v, needle) in [
        ("--safety-state", "flying", "invalid safety state"),
        ("--safety-state", "Idle", "invalid safety state"),
        ("--safety-state", "e_stop_active", "invalid safety state"),
        ("--safety-state", "", "invalid safety state"),
        ("--control", "remote", "invalid control mode"),
        ("--control", "AUTONOMOUS", "invalid control mode"),
        ("--phase", "cruise", "invalid mission phase"),
        ("--connectivity", "offline", "invalid connectivity"),
        (
            "--feedback-source",
            "/odom=lidar",
            "invalid feedback source",
        ),
    ] {
        // --safety-state is in the base already; replace it.
        let mut args = base(&bb);
        if flag == "--safety-state" {
            args.truncate(args.len() - 2);
        }
        args.extend([flag.to_string(), v.to_string()]);
        let o = bin().args(&args).output().unwrap();
        assert_usage_error(&o, &bb, needle, &format!("{flag} {v:?}"));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn bad_numbers_are_refused() {
    let dir = tmpdir("flags-num");
    let bb = dir.join("bb");
    for (flag, v, needle) in [
        ("--start-ms", "abc", "invalid --start-ms"),
        ("--start-ms", "-1", "invalid --start-ms"),
        ("--start-ms", "18446744073709551616", "invalid --start-ms"),
        ("--start-ms", "1e12", "invalid --start-ms"),
        ("--start-ms", " 1", "invalid --start-ms"),
        ("--step-ms", "0", "--step-ms must be > 0"),
        ("--step-ms", "18446744073710", "--step-ms must be > 0"),
        ("--step-ms", "0x10", "invalid --step-ms"),
        ("--step-ms", "1.5", "invalid --step-ms"),
        ("--partitions", "-1", "invalid --partitions"),
        ("--partitions", "4294967296", "--partitions too large"),
    ] {
        let o = run_with(&bb, &[flag, v]);
        assert_usage_error(&o, &bb, needle, &format!("{flag} {v:?}"));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn key_value_options_are_validated() {
    let dir = tmpdir("flags-kv");
    let bb = dir.join("bb");
    for (args, needle) in [
        (
            vec!["--firewall-allow", "/cmd_vel"],
            "must be CHANNEL=VALUE",
        ),
        (vec!["--firewall-allow", "=abc"], "must be CHANNEL=VALUE"),
        (
            vec!["--firewall-allow", "/cmd_vel="],
            "must be CHANNEL=VALUE",
        ),
        (vec!["--feedback-source", "/odom"], "must be CHANNEL=VALUE"),
        (
            vec!["--firewall-max-angular", "/cmd_vel"],
            "must be CHANNEL=VALUE",
        ),
        (
            vec!["--firewall-max-angular", "/cmd_vel=NaN"],
            "not a finite rad/s",
        ),
        (
            vec!["--firewall-max-angular", "/cmd_vel=inf"],
            "not a finite rad/s",
        ),
        (
            vec!["--firewall-max-angular", "/cmd_vel=-0.1"],
            "not a finite rad/s",
        ),
        (
            vec!["--firewall-max-angular", "/cmd_vel=fast"],
            "not a finite rad/s",
        ),
        (
            vec![
                "--firewall-max-angular",
                "/cmd_vel=1",
                "--firewall-max-angular",
                "/cmd_vel=2",
            ],
            "given more than once",
        ),
    ] {
        let o = run_with(&bb, &args);
        assert_usage_error(&o, &bb, needle, &format!("{args:?}"));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn key_sources_are_validated() {
    let dir = tmpdir("flags-key");
    let bb = dir.join("bb");
    let ex = examples();
    let common: Vec<String> = vec![
        "--events".into(),
        ex.join("rogue-ugv.jsonl").to_string_lossy().into(),
        "--profile".into(),
        ex.join("ugv-demo.profile.json").to_string_lossy().into(),
        "--trusted-keys".into(),
        ex.join("ugv-demo.trust.json").to_string_lossy().into(),
        "--policy".into(),
        ex.join("policy-oem-validated.json")
            .to_string_lossy()
            .into(),
        "--blackbox".into(),
        bb.to_string_lossy().into(),
        "--robot-id".into(),
        ROBOT.into(),
    ];
    let k = |name: &str, text: &str, mode: u32| {
        let p = dir.join(name);
        write_mode(&p, text, mode);
        p
    };
    let good = key_json("hmac-sha256", "site-key-1", &key_hex());
    let big = k("big.key", &"4".repeat(300 * 1024), 0o600);
    let raw_hex = k("raw.key", &format!("{}\n", key_hex()), 0o600);
    let bad_hex = k(
        "badhex.key",
        &key_json("hmac-sha256", "k", &"zz".repeat(32)),
        0o600,
    );
    let short = k(
        "short.key",
        &key_json("hmac-sha256", "k", &"ab".repeat(16)),
        0o600,
    );
    let ed = k(
        "tpm.key",
        &key_json("tpm-ecdsa", "k", &"ab".repeat(32)),
        0o600,
    );
    // An Ed25519 key file is a signing key, but its public half is not.
    let edkf = robodr_blackbox::KeyFile::ed25519_from_seed(&[0x5a; 32], Some("ed")).unwrap();
    let ed_pub = k("ed.pub", &edkf.to_public().unwrap().to_json(), 0o600);
    let unknown = k(
        "unknown.key",
        &good.replace("\"secret_hex\"", "\"extra\":1,\"secret_hex\""),
        0o600,
    );
    let group = k("group.key", &good, 0o640);
    let world = k("world.key", &good, 0o604);
    let link = dir.join("link.key");
    let target = k("target.key", &good, 0o600);
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let missing = dir.join("missing.key");
    let s = |p: &Path| p.to_string_lossy().into_owned();
    for (args, needle) in [
        (vec![], "--key-file is required".to_string()),
        (
            vec!["--key-hex".into(), key_hex()],
            "--key-hex was removed".into(),
        ),
        (
            vec!["--key-id".into(), "k".into()],
            "--key-id was removed".into(),
        ),
        (vec!["--key-file".into(), s(&big)], "exceeds".into()),
        (
            vec!["--key-file".into(), s(&raw_hex)],
            "malformed key file".into(),
        ),
        (
            vec!["--key-file".into(), s(&bad_hex)],
            "secret_hex is not hex".into(),
        ),
        (vec!["--key-file".into(), s(&short)], "at least".into()),
        (
            vec!["--key-file".into(), s(&ed)],
            "unsupported key algorithm".into(),
        ),
        (
            vec!["--key-file".into(), s(&unknown)],
            "malformed key file".into(),
        ),
        (
            vec!["--key-file".into(), s(&ed_pub)],
            "public key file".into(),
        ),
        (vec!["--key-file".into(), s(&group)], "chmod 600".into()),
        (vec!["--key-file".into(), s(&world)], "chmod 600".into()),
        (
            vec!["--key-file".into(), s(&link)],
            "not a regular file".into(),
        ),
        (vec!["--key-file".into(), s(&missing)], "missing.key".into()),
        (
            vec!["--key-file".into(), s(&dir)],
            "not a regular file".into(),
        ),
    ] {
        let o = bin().args(&common).args(&args).output().unwrap();
        assert_usage_error(&o, &bb, &needle, &format!("{args:?}"));
    }
    // A good key file (mode 0600, explicit key id) is accepted, and the key
    // id from the file is the one the chain is bound to.
    let good_file = k("good.key", &good, 0o600);
    let o = bin()
        .args(&common)
        .args(["--key-file".into(), s(&good_file)])
        .args(["--safety-state", "moving_slow"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let o = bin()
        .args([
            "verify",
            "--blackbox",
            &s(&bb),
            "--key-file",
            &s(&good_file),
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn required_options_are_reported_by_name() {
    let dir = tmpdir("flags-req");
    let bb = dir.join("bb");
    let full = base(&bb);
    for name in ["events", "profile", "policy", "blackbox", "robot-id"] {
        let mut args = Vec::new();
        let mut it = full.iter();
        while let Some(a) = it.next() {
            if a == &format!("--{name}") {
                it.next();
                continue;
            }
            args.push(a.clone());
        }
        let o = bin().args(&args).output().unwrap();
        assert_usage_error(&o, &bb, &format!("--{name} is required"), name);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn config_file_errors_exit_2() {
    let dir = tmpdir("flags-cfg");
    let bb = dir.join("bb");
    let junk = dir.join("junk.json");
    std::fs::write(&junk, "{\"not\": \"a config\"}").unwrap();
    let missing = dir.join("missing.json");
    for (flag, path, needle) in [
        ("--monitor-config", &missing, "missing.json"),
        ("--monitor-config", &junk, "not a monitor config"),
    ] {
        let o = run_with(&bb, &[flag, path.to_str().unwrap()]);
        assert_usage_error(&o, &bb, needle, flag);
    }
    // Profile / policy replaced by junk.
    for (flag, needle) in [("--profile", "not a profile"), ("--policy", "policy JSON")] {
        let mut args = base(&bb);
        let i = args.iter().position(|a| a == flag).unwrap();
        args[i + 1] = junk.to_string_lossy().into_owned();
        let o = bin().args(&args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{flag}: {}", stderr(&o));
        assert!(stderr(&o).contains(needle), "{flag}: {}", stderr(&o));
    }
    // --firewall without the angular bound for the Twist channel.
    let o = run_with(&bb, &["--firewall"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    // Allow-listed writer GUIDs must be well-formed.
    for guid in ["a", "zz", "", "0f0f0f0f0f0f0f0f0f0f0f0f0f"] {
        let allow = format!("--firewall-allow=/cmd_vel={guid},{LEGIT_WRITER}");
        let o = run_with(&bb, &[&allow, "--firewall-max-angular", "/cmd_vel=1"]);
        assert_eq!(o.status.code(), Some(2), "{guid:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("invalid firewall config"), "{guid:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn non_empty_blackbox_is_refused_and_left_untouched() {
    let dir = tmpdir("flags-bb");
    let bb = dir.join("bb");
    std::fs::create_dir_all(&bb).unwrap();
    std::fs::write(bb.join("precious"), b"keep me").unwrap();
    let o = bin().args(base(&bb)).output().unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("not empty"), "{}", stderr(&o));
    assert_eq!(std::fs::read(bb.join("precious")).unwrap(), b"keep me");
    assert_eq!(std::fs::read_dir(&bb).unwrap().count(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn accepted_forms_inline_values_explicit_run_and_valid_enums() {
    let dir = tmpdir("flags-ok");
    let ex = examples();
    let out = dir.join("findings.jsonl");
    // `run` subcommand, `--name=value` forms, every enum spelled validly.
    let bb = dir.join("bb1");
    let o = bin()
        .arg("run")
        .arg(format!("--events={}", ex.join("rogue-ugv.jsonl").display()))
        .arg(format!(
            "--profile={}",
            ex.join("ugv-demo.profile.json").display()
        ))
        .arg(format!(
            "--trusted-keys={}",
            ex.join("ugv-demo.trust.json").display()
        ))
        .arg(format!(
            "--policy={}",
            ex.join("policy-oem-validated.json").display()
        ))
        .arg(format!("--blackbox={}", bb.display()))
        .arg(format!("--key-file={}", key_arg()))
        .arg(format!("--robot-id={ROBOT}"))
        .arg("--safety-state=collaborative_human_nearby")
        .arg("--control=teleop")
        .arg("--phase=landing")
        .arg("--connectivity=disconnected")
        .arg("--no-operator")
        .arg("--site=a=b") // only the first '=' splits
        .arg("--partitions=4294967295")
        .arg("--start-ms=1000000000000")
        .arg("--step-ms=18446744073709")
        .arg(format!(
            "--firewall-allow=/cmd_vel={LEGIT_WRITER},01103f5a8c2e00000000010200000203"
        ))
        .arg("--firewall-max-angular=/cmd_vel=0")
        .arg("--record-all-events")
        .arg(format!("--out={}", out.display()))
        .output()
        .unwrap();
    // Valid usage: the run happens (exit 0, 1 or 3, never 2).
    assert!(matches!(o.status.code(), Some(0 | 1 | 3)), "{}", stderr(&o));
    assert!(bb.exists());
    // Every safety state is accepted.
    for (i, s) in [
        "idle",
        "moving_slow",
        "moving_fast",
        "collaborative_human_nearby",
        "estop_active",
        "safe_state_active",
        "unknown",
    ]
    .iter()
    .enumerate()
    {
        let bb = dir.join(format!("bbs{i}"));
        let mut args = base(&bb);
        args.truncate(args.len() - 2);
        args.extend(["--safety-state".to_string(), s.to_string()]);
        let o = bin().args(&args).output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{s}: {}", stderr(&o));
        if *s == "estop_active" || *s == "safe_state_active" {
            // Nothing beyond record while the safety system has authority.
            assert!(!stderr(&o).contains("awaiting_human_approval"), "{s}");
            assert!(!stderr(&o).contains("\"eligible\""), "{s}");
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn help_and_empty_invocations() {
    // --help is not an error: the usage goes to stdout.
    let o = bin().arg("--help").output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stdout).contains("USAGE"));
    assert!(o.stderr.is_empty());
    let o = bin().args(["run", "--help"]).output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    let o = bin().args(["verify", "--help"]).output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    for args in [vec![], vec!["run"], vec!["verify"]] {
        let o = bin().args(&args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(stderr(&o).contains("USAGE"), "{args:?}");
    }
    // `verify` requires its own options.
    let o = bin()
        .args(["verify", "--key-file", &key_arg()])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("--blackbox is required"));
    // A missing black box for verify is an error, not "verified".
    let o = bin()
        .args([
            "verify",
            "--blackbox",
            "/nonexistent/robodr-bb",
            "--key-file",
        ])
        .arg(key_arg())
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0), "{}", stderr(&o));
}

/// An argument that is not valid Unicode is a usage error (exit 2), never
/// a panic (101): `main` reads `std::env::args_os()`.
#[cfg(unix)]
#[test]
fn non_utf8_argument_is_a_usage_error() {
    use std::os::unix::ffi::OsStrExt;
    let arg = std::ffi::OsStr::from_bytes(b"--events=\xff\xfe");
    let o = bin().arg(arg).output().unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("not valid UTF-8"), "{}", stderr(&o));
    assert!(!stderr(&o).contains("panicked"), "{}", stderr(&o));
    // Also in a value position and after the subcommand.
    let o = bin()
        .arg("verify")
        .arg("--blackbox")
        .arg(std::ffi::OsStr::from_bytes(b"/tmp/\xc0"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
}

/// A run whose findings could not all be written (the replay clock ran
/// past what an OCSF finding can carry) is not reported as VERIFIED and
/// exits 3, distinct from a verification failure (1) and an error (2).
#[test]
fn lost_findings_exit_3_and_are_not_verified() {
    let dir = tmpdir("flags-lost");
    let bb = dir.join("bb");
    let mut args = base(&bb);
    args.extend(["--step-ms".to_string(), "18446744073709".to_string()]);
    let o = bin().args(&args).output().unwrap();
    let err = stderr(&o);
    assert_eq!(o.status.code(), Some(3), "{err}");
    assert!(err.contains("finding(s) were lost"), "{err}");
    assert!(
        !err.contains("VERIFIED: evidence chain intact end to end"),
        "{err}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `robodr-replay run` with an Ed25519 key file pair (as
/// `robodr-blackbox keygen` writes it) leaves a black box that verifies with
/// the public key alone: through `robodr-replay verify --key-file FILE.pub`
/// and through the keyring code `robodr-blackbox verify --keyring FILE.pub`
/// uses. The wrong public key fails.
#[test]
fn ed25519_key_file_run_verifies_with_the_public_key_only() {
    use robodr_blackbox::keys::{public_key_path, KeyFile, Keyring};
    use std::os::unix::fs::PermissionsExt;
    let dir = tmpdir("flags-ed25519");
    let bb = dir.join("bb");
    let sk = dir.join("unit.key");
    let kf = KeyFile::generate_ed25519(None).unwrap();
    kf.write_new(&sk).unwrap();
    let pk = public_key_path(&sk);
    kf.to_public().unwrap().write_new(&pk).unwrap();
    std::fs::set_permissions(&pk, std::fs::Permissions::from_mode(0o644)).unwrap();
    let s = |p: &Path| p.to_string_lossy().into_owned();
    let findings = dir.join("findings.jsonl");
    let mut args: Vec<String> = base(&bb)
        .into_iter()
        .filter(|a| a != "--key-file" && a != &key_arg())
        .collect();
    args.extend(["--key-file".into(), s(&sk), "--out".into(), s(&findings)]);
    let o = bin().args(&args).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(!stderr(&o).contains("hmac"), "{}", stderr(&o));
    assert!(std::fs::metadata(&findings).unwrap().len() > 0);

    // robodr-replay verify with the public key file (world-readable).
    let verify = |key: &Path| {
        bin()
            .args(["verify", "--blackbox", &s(&bb), "--key-file", &s(key)])
            .args(["--robot-id", ROBOT, "--findings", &s(&findings)])
            .output()
            .unwrap()
    };
    let o = verify(&pk);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).contains("VERIFIED"));

    // The keyring path of `robodr-blackbox verify --keyring unit.key.pub`.
    let mut ring = Keyring::new();
    ring.load_file(&pk).unwrap();
    let rep = robodr_blackbox::verify::verify_dir(&bb, &ring, &Default::default()).unwrap();
    assert!(rep.is_intact(), "{rep:#?}");
    assert_eq!(rep.identity.as_ref().unwrap().algorithm, "ed25519");
    assert_eq!(rep.identity.as_ref().unwrap().key_id, kf.key_id);

    // Another key's public file (even under the same id) does not verify.
    let other = dir.join("other.pub");
    KeyFile::generate_ed25519(Some(&kf.key_id))
        .unwrap()
        .to_public()
        .unwrap()
        .write_new(&other)
        .unwrap();
    let o = verify(&other);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    std::fs::remove_dir_all(&dir).unwrap();
}
