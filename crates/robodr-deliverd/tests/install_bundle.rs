//! `packaging/install-bundle.sh` and the maintainer scripts on the
//! installation path (WP8a):
//!
//! * T9: a package upgrade never restarts the gateway or the executor
//!   unguarded: refused while the live safety state forbids it,
//!   `--defer-restart` / `restart-pending`, `--allow-gateway-restart`,
//!   the maintainer scripts' `gated_restart` block (run for real, inside
//!   the dpkg root) and the one-time gateway migration gate;
//! * T50: the post-install health check, automatic rollback and `--keep`;
//! * T51: the built-in minisign verifier (this crate's binary) replaces
//!   minisign and makes `ROBODR_ALLOW_UNSIGNED` refused.
//!
//! Against the real dpkg of this host in a separate dpkg root
//! (`ROBODR_ROOT`) with stub packages. dpkg runs maintainer scripts
//! chrooted into that root, so the root gets a minimal shell (sh, mkdir,
//! grep, rm and their libraries). systemd is a fake `systemctl` (state
//! under `<root>/fake-sd`), agentd's safety state a fake
//! `robodr-deliverd safety-state` (T9/T50) or the real binary (T51).
//! Needs root, dpkg and ldd; skipped otherwise unless
//! `ROBODR_REQUIRE_DPKG_TEST=1`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "robodr-ib-{}-{}-{tag}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn available(test: &str, extra: &[&str]) -> bool {
    let root = robodr_blackbox::keys::effective_uid() == 0;
    let ok = root
        && ["dpkg", "dpkg-deb", "ldd"]
            .iter()
            .chain(extra)
            .all(|t| have(t));
    if !ok {
        assert!(
            std::env::var("ROBODR_REQUIRE_DPKG_TEST").as_deref() != Ok("1"),
            "{test}: needs root, dpkg, ldd {extra:?} (ROBODR_REQUIRE_DPKG_TEST=1)"
        );
        eprintln!("SKIPPED {test}: needs root, dpkg, ldd {extra:?}");
    }
    ok
}

fn out(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(o: &Output) -> String {
    assert!(o.status.success(), "failed: {}", out(o));
    out(o)
}

fn write_exec(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The fake systemd of the test: `is-active` from `<sd>/active/<unit>`
/// (and neither `<sd>/crashing/<unit>` nor `<sd>/failed/<unit>`), every
/// other verb logged to `<sd>/log`; `try-restart` of a unit in
/// `<sd>/crash-on-restart` makes it crash. A failed unit (one that hit its
/// start limit) is left alone by `try-restart` and comes back only with
/// `start`, as with systemd. Inside the dpkg chroot the state is `/fake-sd`.
const FAKE_SYSTEMCTL: &str = r#"#!/bin/sh
if [ -d /fake-sd ]; then d=/fake-sd; else d=$FAKE_SD; fi
case "$1" in
is-active)
    shift
    [ "$1" != --quiet ] || shift
    [ -e "$d/active/$1" ] && [ ! -e "$d/crashing/$1" ] && [ ! -e "$d/failed/$1" ]
    ;;
is-failed)
    shift
    [ "$1" != --quiet ] || shift
    [ -e "$d/failed/$1" ]
    ;;
*)
    echo "$*" >>"$d/log"
    if [ "$1" = try-restart ] && [ -e "$d/crash-on-restart/$2" ]; then : >"$d/crashing/$2"; fi
    if [ "$1" = start ]; then rm -f "$d/failed/$2"; fi
    ;;
esac
"#;

/// The `robodr-deliverd` of 0.1.0-alpha.1: no `safety-state` command.
const OLD_DELIVERD: &str = r#"#!/bin/sh
case "$1" in
--help) echo "usage: robodr-deliverd run|once|status" ;;
*) echo "robodr-deliverd: unknown command $1" >&2; exit 2 ;;
esac
"#;

/// The post-install script of a release from before the safety-state
/// gate (0.1.0-alpha.1): it try-restarts the gateway and the executor
/// unconditionally.
const LEGACY_POSTINST: &str = "#!/bin/sh\nfor u in robodr-executor.service robodr-firewall-gw.service; do\n    systemctl try-restart \"$u\" || true\ndone\n";

/// A fake `robodr-deliverd` with `safety-state` only: the state from
/// `<sd>/safety`, the heartbeat stale when `<sd>/stale` exists. When
/// `<sd>/safety-then` exists, it becomes `<sd>/safety` after this read
/// (the state changes between two reads).
const FAKE_DELIVERD: &str = r#"#!/bin/sh
d=$FAKE_SD
case "$1" in
--help) echo "usage: robodr-deliverd safety-state" ;;
safety-state)
    st=$(cat "$d/safety" 2>/dev/null || echo unknown)
    if [ -e "$d/safety-then" ]; then mv "$d/safety-then" "$d/safety"; fi
    fr=true
    [ ! -e "$d/stale" ] || fr=false
    printf '{\n  "safety_state": "%s",\n  "agentd_fresh": %s\n}\n' "$st" "$fr"
    case "$st" in idle | safe_state_active) exit 0 ;; esac
    exit 1
    ;;
*) exit 2 ;;
esac
"#;

/// A dpkg root with a minimal shell for the chrooted maintainer scripts.
fn dpkg_root(dir: &Path) -> PathBuf {
    let root = dir.join("root");
    for d in [
        "var/lib/dpkg/info",
        "var/lib/dpkg/updates",
        "var/lib/dpkg/triggers",
        "var/lib/robodr",
        "fake-sd/active",
        "fake-sd/crashing",
        "fake-sd/crash-on-restart",
        "fake-sd/failed",
    ] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("var/lib/dpkg/status"), "").unwrap();
    std::fs::write(root.join("var/lib/dpkg/available"), "").unwrap();
    for tool in ["sh", "mkdir", "grep", "rm"] {
        let host = std::fs::canonicalize(
            String::from_utf8(
                Command::new("sh")
                    .args(["-c", &format!("command -v {tool}")])
                    .output()
                    .unwrap()
                    .stdout,
            )
            .unwrap()
            .trim(),
        )
        .unwrap();
        let dst = root.join("bin").join(tool);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::copy(&host, &dst).unwrap();
        let ldd =
            String::from_utf8(Command::new("ldd").arg(&host).output().unwrap().stdout).unwrap();
        for lib in ldd.split_whitespace().filter(|w| w.starts_with('/')) {
            let d = root.join(lib.trim_start_matches('/'));
            std::fs::create_dir_all(d.parent().unwrap()).unwrap();
            std::fs::copy(lib, &d).unwrap();
        }
    }
    write_exec(&root.join("usr/bin/systemctl"), FAKE_SYSTEMCTL);
    // The /usr/bin tools dpkg's chroot PATH may look in.
    for t in ["mkdir", "grep", "rm"] {
        let l = root.join("usr/bin").join(t);
        let _ = std::os::unix::fs::symlink(format!("/bin/{t}"), l);
    }
    root
}

/// The maintainer scripts' `gated_restart` block (packaging/deb/postinst).
fn gated_block() -> String {
    gated_block_of("packaging/deb/postinst")
}

fn gated_block_of(file: &str) -> String {
    let t = std::fs::read_to_string(repo().join(file)).unwrap();
    let a = t.find("# >>> gated_restart").unwrap();
    let b = t.find("# <<< gated_restart").unwrap();
    t[a..b].to_string()
}

/// The rpm `post` scriptlet carries the very block the tests run (and
/// install-bundle.sh recognises a gate-aware package by it).
#[test]
fn the_rpm_post_scriptlet_carries_the_same_gated_restart_block() {
    let deb = gated_block();
    assert_eq!(gated_block_of("packaging/rpm/post"), deb);
    assert!(deb.contains("\nmark_pending_restart() {"), "{deb}");
}

/// The text between `# >>> NAME` and `# <<< NAME` in `file`.
fn block_of(file: &str, name: &str) -> String {
    let t = std::fs::read_to_string(repo().join(file)).unwrap();
    let a = t
        .find(&format!("# >>> {name}"))
        .unwrap_or_else(|| panic!("{file}: no {name} block"));
    let b = t.find(&format!("# <<< {name}")).unwrap();
    t[a..b].to_string()
}

/// The maintainer scripts' `gateway_migration_gate` block (review L11:
/// in the pre-install scripts too).
fn migration_gate_block() -> String {
    block_of("packaging/deb/postinst", "gateway_migration_gate")
}

/// What the real postinst does on upgrade with the gated units (and,
/// first, the migration gate).
fn upgrade_postinst() -> String {
    format!(
        "#!/bin/sh\nset -e\n{}\n{}\nstopped=\"\"\ngateway_migration_gate\n\
         for u in robodr-executor.service robodr-firewall-gw.service; do\n    mark_pending_restart \"$u\"\ndone\n",
        gated_block(),
        migration_gate_block()
    )
}

/// A stub `robodr` package (formats RBF1:1) with `postinst`.
fn stub_deb(dir: &Path, version: &str, postinst: &str) -> PathBuf {
    stub_deb_with(dir, version, postinst, &[])
}

/// A stub `robodr` package with `postinst` and the executables `files`
/// (path inside the package, content).
fn stub_deb_with(dir: &Path, version: &str, postinst: &str, files: &[(&str, &str)]) -> PathBuf {
    stub_pkg(dir, "robodr", version, "", &[("postinst", postinst)], files)
}

/// A stub package `package` (formats RBF1:1) with the extra control
/// lines `control`, the maintainer scripts `scripts` (name, text) and
/// the executables `files` (path inside the package, content).
fn stub_pkg(
    dir: &Path,
    package: &str,
    version: &str,
    control: &str,
    scripts: &[(&str, &str)],
    files: &[(&str, &str)],
) -> PathBuf {
    let st = dir.join(format!("stage-{package}-{version}"));
    let _ = std::fs::remove_dir_all(&st);
    for (p, text) in files {
        write_exec(&st.join(p), text);
    }
    std::fs::create_dir_all(st.join("DEBIAN")).unwrap();
    std::fs::create_dir_all(st.join("usr/lib/robodr")).unwrap();
    std::fs::create_dir_all(st.join("usr/share/robodr")).unwrap();
    std::fs::write(
        st.join("DEBIAN/control"),
        format!(
            "Package: {package}\nVersion: {version}\nArchitecture: all\nMaintainer: test <t@invalid>\n\
             {control}Description: stub robodr package for the install-bundle test\n"
        ),
    )
    .unwrap();
    for (name, text) in scripts {
        write_exec(&st.join("DEBIAN").join(name), text);
    }
    std::fs::write(st.join("usr/lib/robodr/stub-version"), version).unwrap();
    std::fs::write(
        st.join("usr/share/robodr/formats"),
        "blackbox_write=RBF1:1\nblackbox_read=RBF1:1\n",
    )
    .unwrap();
    let deb = dir.join(format!("{package}_{version}_all.deb"));
    ok(&Command::new("dpkg-deb")
        .args(["--root-owner-group", "-Zxz", "--build"])
        .arg(&st)
        .arg(&deb)
        .output()
        .unwrap());
    deb
}

/// An extracted bundle directory around `deb`.
fn bundle(dir: &Path, deb: &Path, name: &str) -> PathBuf {
    bundle_floor(dir, deb, name, None)
}

/// An extracted bundle directory around `deb`, with a `security-floor`
/// file naming `floor` when given.
fn bundle_floor(dir: &Path, deb: &Path, name: &str, floor: Option<&str>) -> PathBuf {
    let b = dir.join(name);
    std::fs::create_dir_all(&b).unwrap();
    if let Some(f) = floor {
        std::fs::write(b.join("security-floor"), format!("min_version={f}\n")).unwrap();
    }
    std::fs::copy(deb, b.join(deb.file_name().unwrap())).unwrap();
    let s = b.join("install-bundle.sh");
    std::fs::copy(repo().join("packaging/install-bundle.sh"), &s).unwrap();
    std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o755)).unwrap();
    ok(&Command::new("sh")
        .current_dir(&b)
        .args([
            "-c",
            "find . -type f -printf '%P\\n' | LC_ALL=C sort | xargs sha256sum > ../SHA256SUMS.tmp && mv ../SHA256SUMS.tmp SHA256SUMS",
        ])
        .output()
        .unwrap());
    b
}

struct Unit {
    _dir: TempDir,
    dir: PathBuf,
    root: PathBuf,
    sd: PathBuf,
    path: String,
}

impl Unit {
    /// A dpkg root with the fake systemd (when `systemd`) and the fake
    /// safety-state reader.
    fn new(tag: &str, systemd: bool) -> Self {
        let dir = TempDir::new(tag);
        let root = dpkg_root(&dir);
        if systemd {
            std::fs::create_dir_all(root.join("run/systemd/system")).unwrap();
        }
        write_exec(&root.join("usr/sbin/robodr-deliverd"), FAKE_DELIVERD);
        let sd = root.join("fake-sd");
        let path = format!(
            "{}:{}",
            root.join("usr/bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Self {
            dir: dir.to_path_buf(),
            _dir: dir,
            root,
            sd,
            path,
        }
    }

    fn run(&self, b: &Path, args: &[&str], unsigned: bool) -> Output {
        self.run_env(b, args, unsigned, &[])
    }

    fn run_env(&self, b: &Path, args: &[&str], unsigned: bool, env: &[(&str, &str)]) -> Output {
        let mut c = Command::new("sh");
        c.arg(b.join("install-bundle.sh"))
            .args(args)
            .env("ROBODR_ROOT", &self.root)
            .env("FAKE_SD", &self.sd)
            .env("PATH", &self.path)
            .env_remove("ROBODR_GATED_RESTART");
        if unsigned {
            c.env("ROBODR_ALLOW_UNSIGNED", "1");
        } else {
            c.env_remove("ROBODR_ALLOW_UNSIGNED");
        }
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }

    fn installed(&self) -> String {
        std::fs::read_to_string(self.root.join("usr/lib/robodr/stub-version")).unwrap_or_default()
    }
    fn active(&self, u: &str) {
        std::fs::write(self.sd.join("active").join(u), "").unwrap();
    }
    fn safety(&self, s: &str) {
        std::fs::write(self.sd.join("safety"), s).unwrap();
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.sd.join("log")).unwrap_or_default()
    }
    fn clear_log(&self) {
        let _ = std::fs::remove_file(self.sd.join("log"));
    }
    fn pending(&self) -> String {
        std::fs::read_to_string(self.root.join("var/lib/robodr/pending-restart"))
            .unwrap_or_default()
    }
    fn migrated(&self) {
        std::fs::write(
            self.root.join("var/lib/robodr/.exporter-users-migrated"),
            "",
        )
        .unwrap();
    }
}

const GW: &str = "robodr-firewall-gw.service";
const EX: &str = "robodr-executor.service";
const AG: &str = "robodr-agentd.service";

#[test]
fn upgrades_restart_gateway_and_executor_only_through_the_safety_gate() {
    if !available("safety_gate", &[]) {
        return;
    }
    let u = Unit::new("gate", true);
    u.migrated();
    let pi = upgrade_postinst();
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", &pi), "b1");
    let b2 = bundle(&u.dir, &stub_deb(&u.dir, "0.2.0-1", &pi), "b2");
    let b3 = bundle(&u.dir, &stub_deb(&u.dir, "0.3.0-1", &pi), "b3");
    let b4 = bundle(&u.dir, &stub_deb(&u.dir, "0.4.0-1", &pi), "b4");
    // First install: nothing runs, nothing is gated.
    ok(&u.run(&b1, &["install", "--health-timeout", "2"], true));
    assert_eq!(u.installed(), "0.1.0-1");
    // Commissioned: the gateway and the executor run, the robot moves.
    for s in [GW, EX, AG] {
        u.active(s);
    }
    u.safety("moving_fast");
    u.clear_log();
    let o = u.run(&b2, &["install", "--health-timeout", "2"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("REFUSED") && out(&o).contains("moving_fast"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.1.0-1", "nothing changed");
    assert!(!u.log().contains("restart"), "{}", u.log());
    // Unknown state (agentd without a live feed) is closed too.
    u.safety("unknown");
    assert_eq!(u.run(&b2, &["install"], true).status.code(), Some(1));
    // --defer-restart: installed, the two keep running, marked pending by
    // the package's own (real) gated_restart block.
    u.safety("moving_slow");
    let o = u.run(
        &b2,
        &["install", "--defer-restart", "--health-timeout", "2"],
        true,
    );
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    assert_eq!(u.installed(), "0.2.0-1");
    assert!(
        u.pending().contains(GW) && u.pending().contains(EX),
        "{}",
        u.pending()
    );
    assert!(
        !u.log().contains(GW) && !u.log().contains(EX),
        "{}",
        u.log()
    );
    assert!(out(&o).contains("restart-pending"), "{}", out(&o));
    // restart-pending waits for the gate...
    let o = u.run(&b2, &["restart-pending"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(!u.log().contains("try-restart"), "{}", u.log());
    // ...and restarts both once the robot is in its safe state.
    u.safety("safe_state_active");
    ok(&u.run(&b2, &["restart-pending"], true));
    assert!(
        u.log().contains(&format!("try-restart {GW}")),
        "{}",
        u.log()
    );
    assert!(
        u.log().contains(&format!("try-restart {EX}")),
        "{}",
        u.log()
    );
    assert_eq!(u.pending(), "", "cleared");
    // Gate open at install time: installed and restarted at once.
    u.safety("idle");
    u.clear_log();
    let o = ok(&u.run(&b3, &["install", "--health-timeout", "2"], true));
    assert_eq!(u.installed(), "0.3.0-1");
    assert!(
        u.log().contains(&format!("try-restart {GW}")),
        "{o}\n{}",
        u.log()
    );
    assert_eq!(u.pending(), "");
    // --allow-gateway-restart: deliberate, while moving.
    u.safety("moving_fast");
    u.clear_log();
    let o = ok(&u.run(
        &b4,
        &[
            "install",
            "--allow-gateway-restart",
            "--health-timeout",
            "2",
        ],
        true,
    ));
    assert!(o.contains("WARNING"), "{o}");
    assert!(
        u.log().contains(&format!("try-restart {GW}")),
        "{}",
        u.log()
    );
    // Rollback is gated the same way.
    let o = u.run(&b4, &["rollback", "0.3.0-1"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert_eq!(u.installed(), "0.4.0-1");
    // A forged pending entry is never restarted.
    std::fs::write(
        u.root.join("var/lib/robodr/pending-restart"),
        "sshd.service\n",
    )
    .unwrap();
    u.safety("idle");
    u.clear_log();
    let o = ok(&u.run(&b4, &["restart-pending"], true));
    assert!(o.contains("ignoring"), "{o}");
    assert!(!u.log().contains("sshd"), "{}", u.log());
    // The two options exclude each other.
    assert_eq!(
        u.run(
            &b4,
            &["install", "--allow-gateway-restart", "--defer-restart"],
            true
        )
        .status
        .code(),
        Some(2)
    );
}

#[test]
fn the_gateway_user_migration_never_stops_the_gateway_unguarded() {
    if !available("migration_gate", &[]) {
        return;
    }
    let u = Unit::new("migr", true);
    let pi = upgrade_postinst();
    let b1 = bundle(
        &u.dir,
        &stub_deb(&u.dir, "0.1.0-1", "#!/bin/sh\nexit 0\n"),
        "b1",
    );
    let deb2 = stub_deb(&u.dir, "0.2.0-1", &pi);
    let b2 = bundle(&u.dir, &deb2, "b2");
    ok(&u.run(&b1, &["install"], true));
    u.active(GW);
    u.safety("moving_fast");
    // install-bundle refuses to defer it...
    let o = u.run(&b2, &["install", "--defer-restart"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("cannot be deferred"), "{}", out(&o));
    assert_eq!(u.installed(), "0.1.0-1");
    // ...and a raw dpkg upgrade leaves the package unconfigured, nothing
    // stopped (the postinst's gateway_migration_gate).
    let o = Command::new("dpkg")
        .arg(format!("--root={}", u.root.display()))
        .arg("-i")
        .arg(&deb2)
        .env("PATH", &u.path)
        .env_remove("ROBODR_GATED_RESTART")
        .output()
        .unwrap();
    assert!(!o.status.success(), "{}", out(&o));
    assert!(
        out(&o).contains("must stop robodr-firewall-gw"),
        "{}",
        out(&o)
    );
    assert!(!u.log().contains("stop"), "{}", u.log());
    // restart-pending configures it once the gate opens.
    assert_eq!(
        u.run(&b2, &["restart-pending"], true).status.code(),
        Some(1)
    );
    u.safety("idle");
    let o = ok(&u.run(&b2, &["restart-pending"], true));
    assert!(o.contains("deferred configuration"), "{o}");
    let st = Command::new("dpkg-query")
        .arg(format!(
            "--admindir={}",
            u.root.join("var/lib/dpkg").display()
        ))
        .args(["-W", "-f", "${db:Status-Abbrev}", "robodr"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&st.stdout).trim(), "ii");
}

#[test]
fn unhealthy_upgrades_roll_back_and_keep_prunes() {
    if !available("health", &[]) {
        return;
    }
    let u = Unit::new("health", true);
    u.migrated();
    let good = "#!/bin/sh\nrm -f /fake-sd/crashing/robodr-agentd.service\n";
    let bad = "#!/bin/sh\n: >/fake-sd/crashing/robodr-agentd.service\n";
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", good), "b1");
    let b2 = bundle(&u.dir, &stub_deb(&u.dir, "0.2.0-1", bad), "b2");
    let b3 = bundle(&u.dir, &stub_deb(&u.dir, "0.3.0-1", good), "b3");
    let b4 = bundle(&u.dir, &stub_deb(&u.dir, "0.4.0-1", good), "b4");
    let b5 = bundle(&u.dir, &stub_deb(&u.dir, "0.5.0-1", good), "b5");
    ok(&u.run(&b1, &["install"], true));
    u.active(AG);
    u.active("robodr-uplink.service");
    u.safety("idle");
    // 0.2.0 crashes agentd: rolled back to the kept 0.1.0, exit 1, 0.2.0
    // not kept.
    let o = u.run(&b2, &["install", "--health-timeout", "3"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("HEALTH CHECK FAILED") && out(&o).contains("AUTOMATIC ROLLBACK"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.1.0-1");
    let rel = u.root.join("var/lib/robodr/releases");
    assert!(!rel.join("0.2.0-1").exists());
    // --no-auto-rollback only reports.
    let o = u.run(
        &b2,
        &["install", "--health-timeout", "2", "--no-auto-rollback"],
        true,
    );
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert_eq!(u.installed(), "0.2.0-1");
    ok(&u.run(&b1, &["rollback", "0.1.0-1", "--health-timeout", "3"], true));
    assert_eq!(u.installed(), "0.1.0-1");
    // A stale agentd heartbeat is unhealthy too.
    std::fs::write(u.sd.join("stale"), "").unwrap();
    let o = u.run(&b3, &["install", "--health-timeout", "2"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("heartbeat"), "{}", out(&o));
    assert_eq!(u.installed(), "0.1.0-1");
    std::fs::remove_file(u.sd.join("stale")).unwrap();
    // Healthy upgrades; --keep 2 keeps the two newest (and the installed).
    ok(&u.run(&b3, &["install", "--health-timeout", "3"], true));
    ok(&u.run(&b4, &["install", "--health-timeout", "3"], true));
    let o = ok(&u.run(
        &b5,
        &["install", "--health-timeout", "3", "--keep", "2"],
        true,
    ));
    assert!(o.contains("health OK"), "{o}");
    let mut kept: Vec<String> = std::fs::read_dir(&rel)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('0'))
        .collect();
    kept.sort();
    assert_eq!(kept, ["0.4.0-1", "0.5.0-1"]);
    // The pruned releases' formats stay known to the format gate.
    for v in ["0.1.0-1", "0.3.0-1"] {
        assert!(
            rel.join(format!("formats-archive/{v}.formats")).is_file(),
            "{v}"
        );
    }
    // prune keeps the installed release whatever N says.
    ok(&u.run(&b5, &["rollback", "0.4.0-1", "--health-timeout", "3"], true));
    ok(&u.run(&b5, &["prune", "--keep", "1"], true));
    assert!(rel.join("0.4.0-1").is_dir() && rel.join("0.5.0-1").is_dir());
    assert_eq!(u.run(&b5, &["prune"], true).status.code(), Some(2));
    assert_eq!(
        u.run(&b5, &["prune", "--keep", "0"], true).status.code(),
        Some(2)
    );
    assert_eq!(
        u.run(&b5, &["install", "--health-timeout", "x"], true)
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn the_builtin_verifier_replaces_minisign_and_refuses_unsigned() {
    if !available("builtin_verifier", &["minisign"]) {
        return;
    }
    let u = Unit::new("verifier", false);
    // A release with the built-in verifier is installed (the real binary).
    std::fs::copy(
        env!("CARGO_BIN_EXE_robodr-deliverd"),
        u.root.join("usr/sbin/robodr-deliverd"),
    )
    .unwrap();
    let b1 = bundle(
        &u.dir,
        &stub_deb(&u.dir, "0.1.0-1", "#!/bin/sh\nexit 0\n"),
        "robodr-0.1.0-amd64",
    );
    // Unsigned: refused even with the lab override.
    let o = u.run(&b1, &["install"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("built-in verifier"), "{}", out(&o));
    assert_eq!(u.installed(), "");
    // Signed: checked by the built-in verifier, even with a minisign in
    // PATH that would refuse everything.
    let keys = u.dir.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let ms = |args: &[&str]| {
        ok(&Command::new("minisign")
            .args(args)
            .current_dir(&keys)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap())
    };
    ms(&["-G", "-W", "-p", "rel.pub", "-s", "rel.sec"]);
    ms(&["-G", "-W", "-p", "other.pub", "-s", "other.sec"]);
    let pubkey = keys.join("rel.pub");
    let out_dir = u.dir.join("dist");
    std::fs::create_dir_all(&out_dir).unwrap();
    let t = out_dir.join("robodr-0.1.0-amd64-offline.tar.gz");
    ok(&Command::new("tar")
        .arg("-C")
        .arg(&u.dir)
        .arg("-czf")
        .arg(&t)
        .arg("robodr-0.1.0-amd64")
        .output()
        .unwrap());
    ms(&["-S", "-s", "rel.sec", "-m", t.to_str().unwrap()]);
    write_exec(
        &u.root.join("usr/bin/minisign"),
        "#!/bin/sh\necho fake minisign >&2\nexit 9\n",
    );
    let trusted = u.dir.join("trusted-install-bundle.sh");
    std::fs::copy(repo().join("packaging/install-bundle.sh"), &trusted).unwrap();
    let run = |args: &[&str]| {
        let mut a = vec!["install", "--pubkey"];
        a.push(pubkey.to_str().unwrap());
        a.push("--tarball");
        a.extend_from_slice(args);
        Command::new("sh")
            .arg(&trusted)
            .args(&a)
            .env("ROBODR_ROOT", &u.root)
            .env("PATH", &u.path)
            .env("TMPDIR", &u.dir)
            .env_remove("ROBODR_ALLOW_UNSIGNED")
            .output()
            .unwrap()
    };
    let o = run(&[t.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    assert!(out(&o).contains("verifier: built-in"), "{}", out(&o));
    assert_eq!(u.installed(), "0.1.0-1");
    // Signed by another key: refused by the built-in verifier.
    ms(&["-S", "-s", "other.sec", "-m", t.to_str().unwrap()]);
    let o = run(&[t.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("SIGNATURE CHECK FAILED"), "{}", out(&o));
    // A "verifier" that fails its self-test is never trusted.
    ms(&["-S", "-s", "rel.sec", "-m", t.to_str().unwrap()]);
    write_exec(
        &u.root.join("usr/sbin/robodr-deliverd"),
        "#!/bin/sh\ncase \"$1\" in --help) echo verify-minisign; exit 0 ;; esac\nexit 1\n",
    );
    let o = run(&[t.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(out(&o).contains("self-test"), "{}", out(&o));
}

/// Phase 2 review (high): a bundle's `security-floor` used to overwrite the
/// release the automatic rollback goes back to with the old floor value.
#[test]
fn auto_rollback_goes_to_the_replaced_release_when_the_bundle_raises_the_floor() {
    if !available("floor_rollback", &[]) {
        return;
    }
    let u = Unit::new("floorrb", true);
    u.migrated();
    let good = "#!/bin/sh\nrm -f /fake-sd/crashing/robodr-agentd.service\n";
    let bad = "#!/bin/sh\n: >/fake-sd/crashing/robodr-agentd.service\n";
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", good), "b1");
    let b2 = bundle_floor(
        &u.dir,
        &stub_deb(&u.dir, "0.2.0-1", bad),
        "b2",
        Some("0.0.9-1"),
    );
    let b3 = bundle_floor(
        &u.dir,
        &stub_deb(&u.dir, "0.3.0-1", good),
        "b3",
        Some("0.0.9-1"),
    );
    let b4 = bundle_floor(
        &u.dir,
        &stub_deb(&u.dir, "0.4.0-1", bad),
        "b4",
        Some("0.1.0-1"),
    );
    ok(&u.run(&b1, &["install"], true));
    u.active(AG);
    u.safety("idle");
    // No floor recorded before: the bundle's floor is the first one.
    let o = u.run(&b2, &["install", "--health-timeout", "2"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("AUTOMATIC ROLLBACK to 0.1.0-1"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.1.0-1");
    // The bundle raises the recorded floor (0.0.9-1 to 0.1.0-1): the
    // rollback still goes to the replaced 0.3.0-1, not to the old floor.
    ok(&u.run(&b3, &["install", "--health-timeout", "3"], true));
    let o = u.run(&b4, &["install", "--health-timeout", "2"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("AUTOMATIC ROLLBACK to 0.3.0-1")
            && out(&o).contains("rolled back to 0.3.0-1"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.3.0-1");
}

/// Phase 2 review (high): a release from before the safety-state gate
/// restarts the gateway and the executor from its own post-install
/// script, so a rollback to it can never be deferred.
#[test]
fn rollback_to_a_release_without_the_gate_is_never_deferred() {
    if !available("legacy_rollback", &[]) {
        return;
    }
    let u = Unit::new("legacyrb", true);
    u.migrated();
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", LEGACY_POSTINST), "b1");
    let pi = upgrade_postinst();
    let b2 = bundle(&u.dir, &stub_deb(&u.dir, "0.2.0-1", &pi), "b2");
    let bad = format!("{pi}: >/fake-sd/crashing/robodr-agentd.service\n");
    let b3 = bundle(&u.dir, &stub_deb(&u.dir, "0.3.0-1", &bad), "b3");
    ok(&u.run(&b1, &["install"], true));
    for s in [GW, EX, AG] {
        u.active(s);
    }
    u.safety("idle");
    ok(&u.run(&b2, &["install", "--health-timeout", "3"], true));
    assert_eq!(u.installed(), "0.2.0-1");
    // Moving: rollback --defer-restart to the legacy release is refused,
    // nothing installed, nothing restarted.
    u.safety("moving_fast");
    u.clear_log();
    let o = u.run(
        &b2,
        &[
            "rollback",
            "0.1.0-1",
            "--defer-restart",
            "--health-timeout",
            "2",
        ],
        true,
    );
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("REFUSED") && out(&o).contains("predate the safety-state gate"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.2.0-1");
    assert!(!u.log().contains("try-restart"), "{}", u.log());
    // A deferred upgrade whose automatic rollback would land on the legacy
    // release: refused while the state is still closed (the unhealthy
    // release stays, nothing is restarted).
    ok(&u.run(
        &b2,
        &[
            "rollback",
            "0.1.0-1",
            "--allow-gateway-restart",
            "--health-timeout",
            "3",
        ],
        true,
    ));
    assert_eq!(u.installed(), "0.1.0-1");
    u.clear_log();
    let o = u.run(
        &b3,
        &["install", "--defer-restart", "--health-timeout", "2"],
        true,
    );
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("automatic rollback impossible")
            && out(&o).contains("predate the safety-state gate"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.3.0-1");
    assert!(
        !u.log().contains(&format!("try-restart {GW}")),
        "{}",
        u.log()
    );
    // Gate open: the rollback to the legacy release runs (its own
    // postinst restarts the two) and nothing stays pending.
    std::fs::remove_file(u.sd.join("crashing").join(AG)).unwrap();
    u.safety("idle");
    u.clear_log();
    ok(&u.run(&b3, &["rollback", "0.1.0-1", "--health-timeout", "3"], true));
    assert_eq!(u.installed(), "0.1.0-1");
    assert!(
        u.log().contains(&format!("try-restart {GW}")),
        "{}",
        u.log()
    );
    assert_eq!(u.pending(), "");
}

/// Phase 2 review (medium): `restart-pending` checks the unit's health
/// after the restart, and `list` shows what is still pending.
#[test]
fn restart_pending_checks_health_and_list_shows_pending() {
    if !available("pending_health", &[]) {
        return;
    }
    let u = Unit::new("pendhealth", true);
    u.migrated();
    let pi = upgrade_postinst();
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", &pi), "b1");
    let b2 = bundle(&u.dir, &stub_deb(&u.dir, "0.2.0-1", &pi), "b2");
    ok(&u.run(&b1, &["install"], true));
    for s in [GW, EX, AG] {
        u.active(s);
    }
    u.safety("moving_slow");
    ok(&u.run(
        &b2,
        &["install", "--defer-restart", "--health-timeout", "2"],
        true,
    ));
    let o = ok(&u.run(&b2, &["list"], true));
    assert!(
        o.contains("pending restart") && o.contains(GW) && o.contains(EX),
        "{o}"
    );
    assert!(o.contains("installed: 0.2.0-1"), "{o}");
    // The gateway does not come back on the new binaries.
    std::fs::write(u.sd.join("crash-on-restart").join(GW), "").unwrap();
    u.safety("idle");
    let o = u.run(&b2, &["restart-pending", "--health-timeout", "2"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("HEALTH CHECK FAILED") && out(&o).contains(GW),
        "{}",
        out(&o)
    );
}

/// Phase 2 review (low): `prune` never runs without knowing the installed
/// release (it could delete the installed release's kept copy).
#[test]
fn prune_refuses_without_the_installed_version() {
    if !available("prune_unknown", &[]) {
        return;
    }
    let u = Unit::new("pruneunk", false);
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", "#!/bin/sh\n"), "b1");
    let b2 = bundle(&u.dir, &stub_deb(&u.dir, "0.2.0-1", "#!/bin/sh\n"), "b2");
    ok(&u.run(&b1, &["install"], true));
    ok(&u.run(&b2, &["install"], true));
    ok(&u.run(&b2, &["rollback", "0.1.0-1"], true));
    // The package database no longer reports robodr (removed, config
    // files left): the installed version is unknown.
    ok(&Command::new("dpkg")
        .arg(format!("--root={}", u.root.display()))
        .args(["-r", "robodr"])
        .env("PATH", &u.path)
        .output()
        .unwrap());
    let o = u.run(&b2, &["prune", "--keep", "1"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("cannot determine"), "{}", out(&o));
    let rel = u.root.join("var/lib/robodr/releases");
    assert!(rel.join("0.1.0-1").is_dir() && rel.join("0.2.0-1").is_dir());
}

/// Phase 1 not_done T9-alpha1-gate: upgrading from a release whose
/// robodr-deliverd has no `safety-state` reads the gate with the new
/// package's own robodr-deliverd (from the verified bundle).
#[test]
fn an_upgrade_from_alpha1_reads_the_gate_with_the_new_package() {
    if !available("alpha1_gate", &[]) {
        return;
    }
    let u = Unit::new("alpha1", true);
    u.migrated();
    write_exec(&u.root.join("usr/sbin/robodr-deliverd"), OLD_DELIVERD);
    let b1 = bundle(
        &u.dir,
        &stub_deb_with(
            &u.dir,
            "0.1.0-1",
            LEGACY_POSTINST,
            &[("usr/sbin/robodr-deliverd", OLD_DELIVERD)],
        ),
        "b1",
    );
    let pi = upgrade_postinst();
    let b2 = bundle(
        &u.dir,
        &stub_deb_with(
            &u.dir,
            "0.2.0-1",
            &pi,
            &[("usr/sbin/robodr-deliverd", FAKE_DELIVERD)],
        ),
        "b2",
    );
    ok(&u.run(&b1, &["install"], true));
    u.active(GW);
    // Moving: refused, the state named (read by the new package's reader).
    u.safety("moving_fast");
    let o = u.run(&b2, &["install", "--health-timeout", "2"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("REFUSED") && out(&o).contains("moving_fast"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.1.0-1");
    // Idle: installed and the gateway restarted through the gate.
    u.safety("idle");
    u.clear_log();
    let o = ok(&u.run(&b2, &["install", "--health-timeout", "3"], true));
    assert!(o.contains("new package's robodr-deliverd"), "{o}");
    assert_eq!(u.installed(), "0.2.0-1");
    assert!(
        u.log().contains(&format!("try-restart {GW}")),
        "{}",
        u.log()
    );
    assert_eq!(u.pending(), "");
}

/// Phase 3 review (low): for a release whose post-install script predates
/// the gate, the gate is read again right before dpkg runs; if it closed
/// since it was decided open, nothing is installed and nothing restarted.
#[test]
fn a_pre_gate_release_is_refused_when_the_gate_closes_before_dpkg() {
    if !available("legacy_recheck", &[]) {
        return;
    }
    let u = Unit::new("legacyrecheck", true);
    u.migrated();
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", LEGACY_POSTINST), "b1");
    let pi = upgrade_postinst();
    let b2 = bundle(&u.dir, &stub_deb(&u.dir, "0.2.0-1", &pi), "b2");
    ok(&u.run(&b1, &["install"], true));
    ok(&u.run(&b2, &["install"], true));
    for s in [GW, EX] {
        u.active(s);
    }
    // Open when decided, moving by the time dpkg would run.
    u.safety("idle");
    std::fs::write(u.sd.join("safety-then"), "moving_fast").unwrap();
    u.clear_log();
    let o = u.run(&b2, &["rollback", "0.1.0-1", "--health-timeout", "2"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("REFUSED")
            && out(&o).contains("no longer allows")
            && out(&o).contains("moving_fast"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.2.0-1");
    assert!(!u.log().contains("try-restart"), "{}", u.log());
}

/// Phase 3 review (low): a gate-aware package whose post-install script
/// cannot be read (a failing `dpkg-deb --ctrl-tarfile`) keeps its
/// pending-restart record: the gated units are still restarted through
/// the gate, and nothing is lost when the gate is closed.
#[test]
fn an_unreadable_post_install_script_keeps_the_pending_restart_record() {
    if !available("unreadable_postinst", &[]) {
        return;
    }
    let u = Unit::new("unreadpi", true);
    u.migrated();
    let pi = upgrade_postinst();
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", &pi), "b1");
    let b2 = bundle(&u.dir, &stub_deb(&u.dir, "0.2.0-1", &pi), "b2");
    ok(&u.run(&b1, &["install"], true));
    for s in [GW, EX] {
        u.active(s);
    }
    // dpkg-deb that cannot read control archives (dpkg itself does not
    // use --ctrl-tarfile).
    let real = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v dpkg-deb"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let wrap = u.dir.join("wrap");
    write_exec(
        &wrap.join("dpkg-deb"),
        &format!(
            "#!/bin/sh\n[ \"$1\" != --ctrl-tarfile ] || exit 2\nexec {} \"$@\"\n",
            real.trim()
        ),
    );
    let path = format!("{}:{}", wrap.display(), u.path);
    u.safety("idle");
    u.clear_log();
    ok(&u.run_env(
        &b2,
        &[
            "install",
            "--allow-gateway-restart",
            "--health-timeout",
            "3",
        ],
        true,
        &[("PATH", &path)],
    ));
    assert_eq!(u.installed(), "0.2.0-1");
    for s in [GW, EX] {
        assert!(
            u.log().contains(&format!("try-restart {s}")),
            "{s} must be restarted: {}",
            u.log()
        );
    }
    assert_eq!(u.pending(), "");
}

/// Phase 3 review (low): a rollback below the security floor is refused
/// for the floor, also while the safety state is closed (not first for
/// the safety state, then again for the floor).
#[test]
fn a_rollback_below_the_floor_is_refused_for_the_floor_first() {
    if !available("floor_first", &[]) {
        return;
    }
    let u = Unit::new("floorfirst", true);
    u.migrated();
    let pi = upgrade_postinst();
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", &pi), "b1");
    let b2 = bundle_floor(
        &u.dir,
        &stub_deb(&u.dir, "0.2.0-1", &pi),
        "b2",
        Some("0.2.0-1"),
    );
    ok(&u.run(&b1, &["install"], true));
    ok(&u.run(&b2, &["install"], true));
    u.active(GW);
    u.safety("moving_fast");
    let o = u.run(&b2, &["rollback", "0.1.0-1", "--health-timeout", "2"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("below this unit's security floor 0.2.0-1")
            && !out(&o).contains("live safety state"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.2.0-1");
}

/// Review M7: a unit that failed on the bad release (here: hit its start
/// limit, so the rollback's `try-restart` leaves it alone) is started
/// again by the automatic rollback and by `rollback` (reset-failed, then
/// start), so "the previous release is back" holds. A failed gateway is
/// started only while the safety state allows it.
#[test]
fn a_rollback_starts_again_what_failed_on_the_bad_release() {
    if !available("rollback_restore", &[]) {
        return;
    }
    let u = Unit::new("restore", true);
    u.migrated();
    let pi = upgrade_postinst();
    let good = format!("{pi}exit 0\n");
    let bad = format!(
        "{pi}: >/fake-sd/failed/{AG}\n[ ! -e /fake-sd/fail-gw ] || : >/fake-sd/failed/{GW}\n"
    );
    let b1 = bundle(&u.dir, &stub_deb(&u.dir, "0.1.0-1", &good), "b1");
    let b2 = bundle(&u.dir, &stub_deb(&u.dir, "0.2.0-1", &bad), "b2");
    ok(&u.run(&b1, &["install"], true));
    u.active(AG);
    u.safety("idle");
    u.clear_log();
    let o = u.run(&b2, &["install", "--health-timeout", "2"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("AUTOMATIC ROLLBACK to 0.1.0-1")
            && out(&o).contains("rolled back to 0.1.0-1; it is healthy"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.1.0-1");
    let log = u.log();
    assert!(
        log.contains(&format!("reset-failed {AG}\nstart {AG}\n")),
        "{log}"
    );
    // `rollback` after --no-auto-rollback does the same: agentd is failed
    // (not active) when it starts, and comes back.
    let o = u.run(
        &b2,
        &["install", "--health-timeout", "2", "--no-auto-rollback"],
        true,
    );
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(u.sd.join("failed").join(AG).exists());
    ok(&u.run(&b1, &["rollback", "0.1.0-1", "--health-timeout", "2"], true));
    assert!(!u.sd.join("failed").join(AG).exists());
    // A gateway that failed on the bad release while the robot moves: the
    // rollback does not start it (and reports the unit unhealthy).
    u.active(GW);
    std::fs::write(u.sd.join("fail-gw"), "").unwrap();
    let o = u.run(
        &b2,
        &["install", "--no-auto-rollback", "--health-timeout", "1"],
        true,
    );
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(u.sd.join("failed").join(GW).exists());
    u.safety("moving_fast");
    u.clear_log();
    let o = u.run(&b1, &["rollback", "0.1.0-1", "--health-timeout", "1"], true);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains(&format!(
            "{GW} is not running and the safety state does not allow"
        )),
        "{}",
        out(&o)
    );
    assert!(!u.log().contains(&format!("start {GW}")), "{}", u.log());
    assert!(u.log().contains(&format!("start {AG}")), "{}", u.log());
    assert_eq!(u.installed(), "0.1.0-1");
}

/// Review H6: a variant switch (robodr -> robodr-focal, which conflicts
/// with and replaces robodr). dpkg calls the old variant's real prerm
/// with `remove in-favour robodr-focal`: it stops nothing (the gateway is
/// not stopped behind the safety-state gate's back) and records the
/// switch; the new variant's real `variant_switch` block takes the
/// upgrade path. A switch is never deferred.
#[test]
fn a_variant_switch_stops_nothing_and_is_an_upgrade() {
    if !available("variant_switch", &[]) {
        return;
    }
    let u = Unit::new("switch", true);
    u.migrated();
    let prerm = std::fs::read_to_string(repo().join("packaging/deb/prerm")).unwrap();
    let pi = upgrade_postinst();
    let focal_pi = format!(
        "{pi}{}\necho \"from=$from_version\" >/switch-seen\n\
         rm -f /var/lib/robodr/.variant-switch\n",
        block_of("packaging/deb/postinst", "variant_switch")
    );
    let std1 = stub_pkg(
        &u.dir,
        "robodr",
        "0.1.0-1",
        "Conflicts: robodr-focal\nReplaces: robodr-focal\n",
        &[("postinst", &pi), ("prerm", &prerm)],
        &[],
    );
    let focal1 = stub_pkg(
        &u.dir,
        "robodr-focal",
        "0.1.0-1",
        "Conflicts: robodr\nReplaces: robodr\n",
        &[("postinst", &focal_pi), ("prerm", &prerm)],
        &[],
    );
    let b1 = bundle(&u.dir, &std1, "b1");
    let b2 = bundle(&u.dir, &focal1, "b2");
    ok(&u.run(&b1, &["install"], true));
    for s in [GW, EX, AG] {
        u.active(s);
    }
    // Never deferred.
    u.safety("moving_fast");
    let o = u.run(
        &b2,
        &["install", "--allow-variant-switch", "--defer-restart"],
        true,
    );
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("switches the variant"), "{}", out(&o));
    // Through the open gate: nothing stopped, the switch seen as one.
    u.safety("idle");
    u.clear_log();
    let o = ok(&u.run(
        &b2,
        &["install", "--allow-variant-switch", "--health-timeout", "2"],
        true,
    ));
    assert!(o.contains("health OK"), "{o}");
    assert!(!u.log().contains("stop"), "{}", u.log());
    assert_eq!(
        std::fs::read_to_string(u.root.join("switch-seen")).unwrap(),
        "from=variant-switch\n"
    );
    assert!(!u.root.join("var/lib/robodr/.variant-switch").exists());
    // A plain first install of a variant is still one.
    let fresh = Unit::new("switch-fresh", true);
    ok(&fresh.run(&b2, &["install"], true));
    assert_eq!(
        std::fs::read_to_string(fresh.root.join("switch-seen")).unwrap(),
        "from=\n"
    );
}

/// Review L11: the gateway migration gate runs in the pre-install script
/// too. A raw `dpkg -i` that would have to stop the running gateway is
/// refused before a file is unpacked: the installed release stays
/// installed and configured (with the postinst gate alone, the new files
/// were unpacked and left unconfigured, and the gateway failed at the
/// next boot). With the gate's answer (`ROBODR_GATED_RESTART=allow`) it
/// installs.
#[test]
fn the_migration_gate_refuses_before_anything_is_unpacked() {
    if !available("preinst_gate", &[]) {
        return;
    }
    let u = Unit::new("preinst", true);
    let preinst = std::fs::read_to_string(repo().join("packaging/deb/preinst")).unwrap();
    assert!(preinst.contains(&migration_gate_block()));
    let pi = upgrade_postinst();
    let b1 = bundle(
        &u.dir,
        &stub_deb(&u.dir, "0.1.0-1", "#!/bin/sh\nexit 0\n"),
        "b1",
    );
    ok(&u.run(&b1, &["install"], true));
    let deb2 = stub_pkg(
        &u.dir,
        "robodr",
        "0.2.0-1",
        "",
        &[("preinst", &preinst), ("postinst", &pi)],
        &[],
    );
    u.active(GW);
    let dpkg_i = |allow: bool| {
        let mut c = Command::new("dpkg");
        c.arg(format!("--root={}", u.root.display()))
            .arg("-i")
            .arg(&deb2)
            .env("PATH", &u.path);
        if allow {
            c.env("ROBODR_GATED_RESTART", "allow");
        } else {
            c.env_remove("ROBODR_GATED_RESTART");
        }
        c.output().unwrap()
    };
    let o = dpkg_i(false);
    assert!(!o.status.success(), "{}", out(&o));
    assert!(
        out(&o).contains("must stop robodr-firewall-gw"),
        "{}",
        out(&o)
    );
    assert_eq!(u.installed(), "0.1.0-1", "files were unpacked");
    let st = Command::new("dpkg-query")
        .arg(format!(
            "--admindir={}",
            u.root.join("var/lib/dpkg").display()
        ))
        .args(["-W", "-f", "${db:Status-Abbrev}${Version}", "robodr"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&st.stdout).trim(), "ii 0.1.0-1");
    assert!(!u.log().contains("stop"), "{}", u.log());
    ok(&dpkg_i(true));
    assert_eq!(u.installed(), "0.2.0-1");
}
