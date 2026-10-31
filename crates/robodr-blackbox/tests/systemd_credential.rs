//! A secret key handed over by systemd `LoadCredential=` loads (E2E finding
//! F1): on systemd >= 254 with kernel >= 6.4 the credential is `0440 root`
//! on a read-only tmpfs with a POSIX ACL for the service user, which the
//! shared secret-file rule (`robodr_blackbox::secret_file`) must accept.
//!
//! Needs root and a running systemd (PID 1); it is skipped otherwise, with
//! a message. `ROBODR_REQUIRE_SYSTEMD_CREDENTIAL_TEST=1` turns the skip into
//! a failure (CI jobs and the lifecycle containers that do have systemd).
//! `ROBODR_BLACKBOX_BIN` overrides the `robodr-blackbox` binary used (a copy
//! of the test binary run inside a systemd container).

use robodr_blackbox::KeyFile;
use std::path::{Path, PathBuf};
use std::process::Command;

fn skip(why: &str) {
    if std::env::var("ROBODR_REQUIRE_SYSTEMD_CREDENTIAL_TEST").as_deref() == Ok("1") {
        panic!("systemd credential test required but cannot run: {why}");
    }
    eprintln!(
        "SKIP systemd_credential: {why} (set ROBODR_REQUIRE_SYSTEMD_CREDENTIAL_TEST=1 to fail \
         instead)"
    );
}

fn run_unit(unit: &str, key: &Path, cmd: &[&str]) -> std::process::Output {
    Command::new("systemd-run")
        .args(["--quiet", "--wait", "--pipe", "--collect"])
        .arg(format!("--unit={unit}"))
        .args(["-p", "User=nobody"])
        .arg("-p")
        .arg(format!("LoadCredential=k.key:{}", key.display()))
        .args(cmd)
        .output()
        .unwrap()
}

#[test]
fn load_credential_key_loads_under_systemd() {
    if robodr_blackbox::keys::effective_uid() != 0 {
        return skip("not root");
    }
    if !Path::new("/run/systemd/system").is_dir() {
        return skip("systemd is not PID 1 here");
    }
    if Command::new("systemd-run")
        .arg("--version")
        .output()
        .is_err()
    {
        return skip("systemd-run not found");
    }
    let bin = std::env::var_os("ROBODR_BLACKBOX_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_robodr-blackbox")));
    // A world-traversable directory the unit (User=nobody) can execute
    // from: /var/tmp, not /tmp (often a noexec tmpfs in containers).
    let base = std::env::var_os("ROBODR_CREDTEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/tmp"));
    let dir = base.join(format!("robodr-credtest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = dir.join("robodr-blackbox");
    std::fs::copy(&bin, &exe).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    let key = dir.join("secret.key");
    let kf = KeyFile::generate_ed25519(Some("credtest")).unwrap();
    kf.write_new(&key).unwrap(); // 0600 root: only systemd can hand it over
    let unit = format!("robodr-credtest-{}.service", std::process::id());
    let cred = format!("/run/credentials/{unit}/k.key");

    // What the service sees (for the log; the form depends on the systemd
    // and kernel versions).
    let st = run_unit(&unit, &key, &["/bin/ls", "-ln", &cred]);
    let form = String::from_utf8_lossy(&st.stdout).trim().to_string();
    eprintln!("credential as the service sees it: {form}");

    let o = run_unit(&unit, &key, &[exe.to_str().unwrap(), "export-pub", &cred]);
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    let err = String::from_utf8_lossy(&o.stderr).to_string();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        o.status.success(),
        "export-pub of the credential ({form}) failed: {err}{out}"
    );
    let want = kf.to_public().unwrap().to_json();
    assert_eq!(out.trim(), want.trim(), "{err}");
}
