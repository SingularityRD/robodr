//! Regressions from the third independent review of Sprint 13b
//! (`13b-review3`: H-R3-1, L-R3-2, L-R3-3 and the Info items). Each test
//! reproduces the finding and failed on the code before its fix (the
//! commit message records the runs).
//!
//! Everything runs in temporary roots: dpkg only with `--root` /
//! `--admindir` below the test directory, never the host's database,
//! users or systemd.

mod common;

use common::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// ------------------------------------------------------------- helpers --

fn root_of(u: &Unit) -> PathBuf {
    u.cfg.install.dpkg_root.clone().unwrap()
}

/// `dpkg-query` status abbreviation and version of `package` in the
/// unit's dpkg root (`"ii 2.0"`, or `""` when dpkg does not know it).
fn dpkg_status(u: &Unit, package: &str) -> String {
    let o = Command::new("dpkg-query")
        .arg(format!(
            "--admindir={}",
            root_of(u).join("var/lib/dpkg").display()
        ))
        .args(["-W", "-f", "${db:Status-Abbrev} ${Version}", "--", package])
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn nav_file(u: &Unit) -> String {
    std::fs::read_to_string(root_of(u).join("usr/lib/nav/ok")).unwrap_or_default()
}

/// A merged-/usr dpkg root: `lib -> usr/lib`, `bin -> usr/bin`.
fn merged_usr(u: &Unit) {
    let r = dpkg_root(u);
    for d in ["usr/lib", "usr/bin", "usr/sbin"] {
        std::fs::create_dir_all(r.join(d)).unwrap();
    }
    for (l, t) in [("lib", "usr/lib"), ("bin", "usr/bin"), ("sbin", "usr/sbin")] {
        std::os::unix::fs::symlink(t, r.join(l)).unwrap();
    }
}

/// `nav` serial 2 (floor 2, dpkg 2.0) installed from bundle 1, in a
/// merged-/usr root.
fn nav_installed(u: &Unit) -> (robodr_deliverd::Engine, PathBuf) {
    merged_usr(u);
    let d2 = deb_of(u, "nav", "2.0", "all", "");
    let r2 = u.rpk(
        &deb_spec(u, "nav", 2, 2, "nav"),
        &[("nav.deb", &d2), ("sbom.cdx.json", SBOM)],
    );
    let b1 = u.bundle(1, None, std::slice::from_ref(&r2));
    u.pack("p1", 1, &[r2], std::slice::from_ref(&b1));
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
    assert_eq!(dpkg_status(u, "nav"), "ii 2.0");
    assert_eq!(nav_file(u), "2.0");
    (e, b1)
}

/// Deliver `nav-ng` serial 1 (no floor, no relations) shipping `files`.
fn deliver_nav_ng(
    u: &Unit,
    e: &mut robodr_deliverd::Engine,
    b1: &Path,
    files: &[(&str, &str)],
    ticks: usize,
) -> Vec<robodr_deliverd::engine::TickReport> {
    let mut all: Vec<(&str, &str)> = vec![("usr/lib/nav-ng/ok", "1.0")];
    all.extend_from_slice(files);
    let d = deb_with(u, "nav-ng", "1.0", "all", "", &all);
    let r1 = u.rpk(
        &deb_spec(u, "nav-ng", 1, 1, "nav-ng"),
        &[("nav-ng.deb", &d), ("sbom.cdx.json", SBOM)],
    );
    let b2 = u.bundle(2, Some(bundle_hash(b1)), std::slice::from_ref(&r1));
    u.pack("p2", 2, &[r1], &[b2]);
    u.run(e, ticks)
}

fn wrapper(t: &Tmp, body: &str) -> PathBuf {
    let w = t.path().join("dpkg");
    std::fs::write(&w, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o755)).unwrap();
    w
}

// ------------------------------------------------------------- H-R3-1 --

/// H-R3-1. On a merged-/usr root (`lib -> usr/lib`) a deb RPK under
/// another name that ships `lib/nav/ok` writes through the directory
/// symlink onto `usr/lib/nav/ok`, owned by the floored `nav`. dpkg sees
/// no conflict (it compares names) and nav still reports `ii 2.0`. The
/// agent resolves every path of the `.deb` through the root's symlinks
/// and refuses one owned by another package.
#[test]
fn hr3_a_path_aliased_onto_a_floored_package_is_refused() {
    if !dpkg_ok("hr3_alias") {
        return;
    }
    let u = Unit::new("hr3-alias");
    let (mut e, b1) = nav_installed(&u);
    let reps = deliver_nav_ng(&u, &mut e, &b1, &[("lib/nav/ok", "OLD-nav-1.0-content")], 5);
    assert_eq!(
        (dpkg_status(&u, "nav"), nav_file(&u)),
        ("ii 2.0".to_string(), "2.0".to_string()),
        "floored nav content replaced through an RPK under another name: {reps:?}"
    );
    assert_eq!(dpkg_status(&u, "nav-ng"), "", "{reps:?}");
    assert!(
        reps.iter().any(|x| x
            .refused
            .iter()
            .any(|r| r.contains("usr/lib/nav/ok") && r.contains("nav"))),
        "{reps:?}"
    );
    assert!(!e.state().installed.contains_key("nav-ng"));
}

/// H-R3-1 (a) and L-R3-2. A `.deb` may not ship files below the agent's
/// own trees (here `install.files_root`, inside the dpkg root), RoboDR's
/// install paths, dpkg's or apt's configuration (`force-overwrite` in
/// `/etc/dpkg/dpkg.cfg.d/` would defeat the overwrite check), or dpkg's
/// database, also not through a merged-/usr alias.
#[test]
fn hr3_l3r2_a_deb_into_protected_paths_is_refused() {
    if !dpkg_ok("hr3_protected") {
        return;
    }
    for (i, path) in [
        "srv/delivered/nav/current",
        "etc/robodr/deliverd.json",
        "lib/systemd/system/robodr-deliverd.service.d/x.conf",
        "usr/lib/robodr/robodr-load-credential",
        "bin/robodr-deliverd",
        "etc/dpkg/dpkg.cfg.d/zz-force",
        "etc/apt/apt.conf.d/99-force",
        "var/lib/dpkg/statoverride",
    ]
    .iter()
    .enumerate()
    {
        let u = Unit::with(&format!("hr3-prot{i}"), |v| {
            let r = PathBuf::from(v["install"]["dpkg_root"].as_str().unwrap());
            v["install"]["files_root"] = serde_json::json!(r.join("srv/delivered"));
        });
        let (mut e, b1) = nav_installed(&u);
        let reps = deliver_nav_ng(&u, &mut e, &b1, &[(path, "force-overwrite\n")], 5);
        assert_eq!(dpkg_status(&u, "nav-ng"), "", "{path}: {reps:?}");
        assert!(
            !root_of(&u).join(path).exists(),
            "{path}: written by a deb RPK: {reps:?}"
        );
        assert!(
            reps.iter().any(|x| !x.refused.is_empty()),
            "{path}: {reps:?}"
        );
    }
}

/// H-R3-1 (b) and L-R3-2. Every `dpkg --install` resets the force options
/// on its command line (`--refuse-all`, then `--refuse-overwrite`
/// explicitly), which overrides a `force-*` from `dpkg.cfg.d` (here a
/// wrapper that puts `--force-overwrite` first, as the configuration
/// would). The recorded flags make dpkg itself refuse an overlap.
#[test]
fn hr3_dpkg_runs_with_explicit_refusals() {
    if !dpkg_ok("hr3_refuse") {
        return;
    }
    let t = Tmp::new("hr3-refuse-wrap");
    let log = t.path().join("argv.log");
    let w = wrapper(
        &t,
        &format!(
            "printf '%s\\n' \"$*\" >> {}\nexec /usr/bin/dpkg --force-overwrite \"$@\"\n",
            log.display()
        ),
    );
    let u = Unit::with("hr3-refuse", |v| {
        v["install"]["dpkg"] = serde_json::json!(w);
    });
    let (_e, _b1) = nav_installed(&u);
    let logged = std::fs::read_to_string(&log).unwrap();
    let installs: Vec<&str> = logged.lines().filter(|l| l.contains("--install")).collect();
    assert!(!installs.is_empty(), "{logged}");
    for l in &installs {
        assert!(
            l.contains("--refuse-all") && l.contains("--refuse-overwrite"),
            "dpkg --install without explicit refusals: {l}"
        );
        let refuse = l.find("--refuse-overwrite").unwrap();
        assert!(
            !l[refuse..].contains("--force-overwrite"),
            "a force option after the refusal: {l}"
        );
    }
    // The same flags, after a configuration's --force-overwrite: dpkg
    // refuses a package that overwrites nav's file.
    let over = deb_with(
        &u,
        "nav-over",
        "1.0",
        "all",
        "",
        &[("usr/lib/nav/ok", "OLD")],
    );
    let p = t.path().join("over.deb");
    std::fs::write(&p, over).unwrap();
    let flags: Vec<String> = installs[0]
        .split_whitespace()
        .filter(|a| a.starts_with("--refuse-") || a.starts_with("--force-"))
        .map(str::to_string)
        .collect();
    let o = Command::new("/usr/bin/dpkg")
        .arg(format!("--root={}", root_of(&u).display()))
        .arg("--force-overwrite")
        .args(&flags)
        .arg("--install")
        .arg(&p)
        .output()
        .unwrap();
    assert!(!o.status.success(), "{flags:?}");
    assert_eq!(nav_file(&u), "2.0");
}

/// H-R3-1 (c). After every `dpkg --install` the agent runs `dpkg
/// --verify` for each recorded package and parses its output (dpkg
/// 1.22.6 exits 0 even when it prints `??5??????`): content of a recorded
/// package changed by another package's install (here a wrapper standing
/// in for any aliasing the path check did not foresee) is damage, is
/// restored, and fails the switch.
#[test]
fn hr3_post_install_verify_catches_changed_content() {
    if !dpkg_ok("hr3_verify") {
        return;
    }
    let t = Tmp::new("hr3-verify-wrap");
    let w = t.path().join("dpkg");
    let u = Unit::with("hr3-verify", |v| {
        v["install"]["dpkg"] = serde_json::json!(w);
    });
    wrapper(
        &t,
        &format!(
            "/usr/bin/dpkg \"$@\" || exit $?\nfor a in \"$@\"; do\n  case \"$a\" in\n  \
             */nav-ng.deb) printf OLD > {}/usr/lib/nav/ok ;;\n  esac\ndone\nexit 0\n",
            root_of(&u).display()
        ),
    );
    let (mut e, b1) = nav_installed(&u);
    let reps = deliver_nav_ng(&u, &mut e, &b1, &[], 6);
    assert_eq!(
        nav_file(&u),
        "2.0",
        "changed content not restored: {reps:?}"
    );
    assert!(
        reps.iter().all(|x| x.installed.is_empty()),
        "the switch that changed nav's content counted as installed: {reps:?}"
    );
    let notes = u.notes_of("robodr.deliver.rollback");
    assert!(
        notes
            .iter()
            .any(|n| n["phase"] == "restore" && n["package"] == "nav" && n["restored"] == true),
        "{notes:?}"
    );
}

/// H-R3-1 (c). The file list of every recorded package is compared with
/// the one recorded at its install: a path that moved to another package
/// (as `force-overwrite` does with a partial overlap; here the wrapper
/// edits nav's list) is damage even though nav is still `ii 2.0` and
/// `dpkg --verify nav` has nothing to say.
#[test]
fn hr3_post_install_file_list_change_is_damage() {
    if !dpkg_ok("hr3_list") {
        return;
    }
    let t = Tmp::new("hr3-list-wrap");
    let w = t.path().join("dpkg");
    let u = Unit::with("hr3-list", |v| {
        v["install"]["dpkg"] = serde_json::json!(w);
    });
    let list = root_of(&u).join("var/lib/dpkg/info/nav.list");
    wrapper(
        &t,
        &format!(
            "/usr/bin/dpkg \"$@\" || exit $?\nfor a in \"$@\"; do\n  case \"$a\" in\n  \
             */nav-ng.deb) grep -v '^/usr/lib/nav/ok$' {l} > {l}.new; mv {l}.new {l} ;;\n  \
             esac\ndone\nexit 0\n",
            l = list.display()
        ),
    );
    let (mut e, b1) = nav_installed(&u);
    let reps = deliver_nav_ng(&u, &mut e, &b1, &[], 6);
    assert!(
        reps.iter().all(|x| x.installed.is_empty()),
        "a changed file list of nav went unnoticed: {reps:?}"
    );
    assert!(
        std::fs::read_to_string(&list)
            .unwrap()
            .lines()
            .any(|l| l == "/usr/lib/nav/ok"),
        "nav's list not restored"
    );
}

// ---------------------------------------------------------- Info: apt --

/// Info. A recorded package updated outside the agent (apt,
/// unattended-upgrades) was "restored", i.e. downgraded, by the next
/// unrelated deb install. Now the agent finds the change **before** the
/// switch, reports it (`robot.deliver.refused`, High) and defers deb
/// installs until it is resolved; it never downgrades it on its own.
#[test]
fn info_a_package_updated_outside_the_agent_is_reported_not_downgraded() {
    if !dpkg_ok("info_apt") {
        return;
    }
    let u = Unit::new("info-apt");
    let (mut e, b1) = nav_installed(&u);
    let newer = deb_of(&u, "nav", "2.1", "all", "");
    let p = u.dir().join("nav_2.1.deb");
    std::fs::write(&p, newer).unwrap();
    let o = Command::new("/usr/bin/dpkg")
        .arg(format!("--root={}", root_of(&u).display()))
        .arg("--install")
        .arg(&p)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(dpkg_status(&u, "nav"), "ii 2.1");
    let reps = deliver_nav_ng(&u, &mut e, &b1, &[], 5);
    assert_eq!(
        dpkg_status(&u, "nav"),
        "ii 2.1",
        "the agent downgraded a package apt updated: {reps:?}"
    );
    assert_eq!(dpkg_status(&u, "nav-ng"), "", "{reps:?}");
    let f = u.findings();
    assert!(
        f.iter()
            .any(|(rule, sev, v)| rule == "robot.deliver.refused"
                && sev.eq_ignore_ascii_case("high")
                && v.to_string().contains("outside")),
        "{f:?}"
    );
}

// ---------------------------------------------------------- Info: reaper --

/// Info (L-F). A probe's leftover joined a process group of the agent's
/// session that was not a probe's (here a `sleep` the test process
/// started in a group of its own) and the reaper's group kill took that
/// process with it. Probes now run in a session of their own, so a
/// leftover can join only groups of that session.
#[test]
fn info_the_reaper_never_kills_a_group_outside_the_probe_session() {
    if !robodr_deliverd::users::is_root() || !have("python3") {
        if std::env::var("ROBODR_REQUIRE_DPKG_TEST").is_ok_and(|v| v == "1") {
            panic!("info_reaper: needs root and python3");
        }
        eprintln!("SKIPPED info_reaper: needs root and python3");
        return;
    }
    use std::os::unix::process::CommandExt;
    use std::time::Duration;
    let mut bystander = Command::new("/bin/sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .unwrap();
    let g = bystander.id();
    let probe = format!(
        "python3 -c 'import os, time\ntry:\n    os.setpgid(0, {g})\nexcept OSError:\n    pass\n\
         time.sleep(30)' </dev/null >/dev/null 2>&1 &\nsleep 0.5\nexit 0\n"
    );
    let r = robodr_deliverd::runner::run_probe(
        &["/bin/sh".to_string(), "-c".to_string(), probe],
        robodr_deliverd::runner::RunAs {
            uid: 65_534,
            gid: 65_534,
        },
        robodr_deliverd::runner::Limits {
            timeout: Duration::from_secs(20),
            max_output: 4096,
        },
        robodr_deliverd::runner::ProbeLimits::default(),
    );
    std::thread::sleep(Duration::from_millis(200));
    let alive = bystander.try_wait().unwrap().is_none();
    let _ = bystander.kill();
    let _ = bystander.wait();
    assert!(r.left_processes, "{r:?}");
    assert!(
        alive,
        "the reaper killed a process group outside the probe: {r:?}"
    );
}

// --------------------------------------------------------------- L-R3-3 --

/// L-R3-3. Rotating the black-box key (OPERATIONS §4.3) left the agent
/// unable to open its journal (another key) and its high-water record
/// unverifiable. `robodr-deliverd rekey` verifies the journal and the
/// record with the old key, archives the journal, and starts a new
/// generation signed with the new key that carries the floors, the
/// deployment sequence, the chain heads and the time floor.
#[test]
fn lr3_rekey_carries_the_floors_to_the_new_key() {
    let u = Unit::new("lr3-rekey");
    let (e, b1) = installed_v5_floor_5(&u);
    let seq = e.state().last_deployment.as_ref().unwrap().seq;
    e.close().unwrap();
    let new = u.dir().join("bb-new.key");
    robodr_blackbox::KeyFile::ed25519_from_seed(&[78; 32], Some("unit-bb-2"))
        .unwrap()
        .write_new(&new)
        .unwrap();
    // The new key without rekeying: the agent cannot use its journal.
    let mut cfg2 = u.cfg.clone();
    cfg2.blackbox.key = new.clone();
    let opened = robodr_deliverd::Engine::open(cfg2.clone(), Box::new(u.clock.clone()));
    assert!(
        opened.as_ref().is_err() || opened.as_ref().unwrap().state().locked.is_some(),
        "the new key alone should not open cleanly"
    );
    drop(opened);
    let cfgp = u.dir().join("deliverd.json");
    std::fs::write(&cfgp, serde_json::to_vec_pretty(&u.cfg).unwrap()).unwrap();
    let old = u.dir().join("bb.key");
    let o = Command::new(env!("CARGO_BIN_EXE_robodr-deliverd"))
        .args(["rekey", "--config"])
        .arg(&cfgp)
        .arg("--old-key")
        .arg(&old)
        .arg("--new-key")
        .arg(&new)
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    // The agent opens with the new key, unlocked, with every baseline.
    let e = robodr_deliverd::Engine::open(cfg2.clone(), Box::new(u.clock.clone())).unwrap();
    assert!(e.state().locked.is_none(), "{:?}", e.state().locked);
    assert_eq!(e.state().floor("nav-stack"), 5);
    assert_eq!(e.state().last_deployment.as_ref().unwrap().seq, seq);
    // Deleting the state file: everything comes back from the new record.
    e.close().unwrap();
    std::fs::remove_file(u.cfg.state_path()).unwrap();
    let mut e = robodr_deliverd::Engine::open(cfg2.clone(), Box::new(u.clock.clone())).unwrap();
    assert!(e.state().locked.is_none());
    assert_eq!(e.state().floor("nav-stack"), 5);
    // A lower serial is still refused.
    let mut s = files_spec(&u, "nav-stack", 4, true);
    s.security_floor = 1;
    let r = u.rpk(&s, &[("ok", b"v4")]);
    let b = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r));
    u.pack("p2", 2, &[r], std::slice::from_ref(&b));
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().all(|x| x.installed.is_empty()), "{reps:?}");
    e.close().unwrap();
    // Both chains verify, each with its own key; the old one is archived
    // next to the journal, not deleted.
    let verify = |dir: &Path, seed: u8, id: &str| {
        let k = robodr_blackbox::KeyFile::ed25519_from_seed(&[seed; 32], Some(id)).unwrap();
        robodr_blackbox::verify::verify_dir(
            dir,
            k.verifier().unwrap().as_ref(),
            &Default::default(),
        )
        .unwrap()
        .is_intact()
    };
    assert!(verify(&u.cfg.blackbox.dir, 78, "unit-bb-2"));
    let parent = u.cfg.blackbox.dir.parent().unwrap();
    let archived: Vec<PathBuf> = std::fs::read_dir(parent)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("blackbox.archived-")
        })
        .collect();
    assert_eq!(archived.len(), 1, "{archived:?}");
    assert!(verify(&archived[0], 77, "unit-bb"));
    // Rekeying again with the retired key is refused.
    let o = Command::new(env!("CARGO_BIN_EXE_robodr-deliverd"))
        .args(["rekey", "--config"])
        .arg(&cfgp)
        .arg("--old-key")
        .arg(&old)
        .arg("--new-key")
        .arg(&new)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
}

// --------------------------------------------------- Info: history, I-B --

/// Info. `Journal::history` read every note in the journal directory
/// without checking it: notes written there by anyone without the
/// black-box key (here a chain signed with another key, claiming a newer
/// record generation and a higher floor) counted. Only records that
/// verify with the unit's key count now.
#[test]
fn info_history_counts_only_notes_signed_with_the_units_key() {
    use robodr_deliverd::journal::{kinds, Journal};
    let t = Tmp::new("info-hist");
    let unit_key = t.path().join("unit.key");
    let other_key = t.path().join("other.key");
    robodr_blackbox::KeyFile::ed25519_from_seed(&[11; 32], Some("unit"))
        .unwrap()
        .write_new(&unit_key)
        .unwrap();
    robodr_blackbox::KeyFile::ed25519_from_seed(&[12; 32], Some("other"))
        .unwrap()
        .write_new(&other_key)
        .unwrap();
    let dir = t.path().join("journal");
    let mut j = Journal::open(&dir, UNIT, &other_key).unwrap();
    j.note(kinds::HIGHWATER, serde_json::json!({"generation": 1000}))
        .unwrap();
    j.note(
        kinds::FLOOR_RAISED,
        serde_json::json!({"name": "nav", "to": 99}),
    )
    .unwrap();
    j.close().unwrap();
    let signer = |p: &Path| {
        robodr_blackbox::KeyFile::load_secret(p)
            .unwrap()
            .signer()
            .unwrap()
    };
    let h = Journal::history(&dir, signer(&unit_key).as_ref());
    assert_eq!(h.hw_generation, 0, "a forged generation counted");
    assert!(
        h.floors.is_empty(),
        "a forged floor counted: {:?}",
        h.floors
    );
    let h = Journal::history(&dir, signer(&other_key).as_ref());
    assert_eq!(h.hw_generation, 1000);
    assert_eq!(h.floors.get("nav"), Some(&99));
}

/// Info (I-B). The total `pack_digest` cap was 16 GiB; it is 4 GiB by
/// default and configurable (`pack_digest_max_mb`).
#[test]
fn info_pack_digest_cap_is_proportionate_and_configurable() {
    assert_eq!(
        robodr_deliverd::media::MAX_PACK_DIGEST_BYTES,
        4 * 1024 * 1024 * 1024
    );
    let u = Unit::new("info-cap");
    assert_eq!(u.cfg.pack_digest_max_mb, 4096);
    let u2 = Unit::with("info-cap2", |v| {
        v["pack_digest_max_mb"] = serde_json::json!(64)
    });
    assert_eq!(u2.cfg.pack_digest_max_mb, 64);
    let mut v = serde_json::to_value(&u.cfg).unwrap();
    v["pack_digest_max_mb"] = serde_json::json!(1);
    assert!(robodr_deliverd::config::Config::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    let pack = u.dir().join("pack");
    std::fs::create_dir_all(&pack).unwrap();
    std::fs::write(pack.join("a"), vec![7u8; 4096]).unwrap();
    assert!(robodr_deliverd::media::pack_digest(&pack, 4096).is_some());
    assert_eq!(robodr_deliverd::media::pack_digest(&pack, 4095), None);
}

/// H-R3-1 (c), no false alarm: files a `path-exclude` (dpkg.cfg.d, here
/// on the command line) leaves out are `missing` for `dpkg --verify`
/// from the start. The check compares with what it said right after the
/// install, so they are not damage.
#[test]
fn hr3_path_excluded_files_are_part_of_the_baseline() {
    if !dpkg_ok("hr3_exclude") {
        return;
    }
    let t = Tmp::new("hr3-exclude-wrap");
    let w = wrapper(
        &t,
        "exec /usr/bin/dpkg '--path-exclude=/usr/share/doc/*' \"$@\"\n",
    );
    let u = Unit::with("hr3-exclude", |v| {
        v["install"]["dpkg"] = serde_json::json!(w);
    });
    merged_usr(&u);
    let d2 = deb_with(
        &u,
        "nav",
        "2.0",
        "all",
        "",
        &[
            ("usr/lib/nav/ok", "2.0"),
            ("usr/share/doc/nav/README", "doc"),
        ],
    );
    let r2 = u.rpk(
        &deb_spec(&u, "nav", 2, 2, "nav"),
        &[("nav.deb", &d2), ("sbom.cdx.json", SBOM)],
    );
    let b1 = u.bundle(1, None, std::slice::from_ref(&r2));
    u.pack("p1", 1, &[r2], std::slice::from_ref(&b1));
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
    assert!(!root_of(&u).join("usr/share/doc/nav/README").exists());
    let reps = deliver_nav_ng(&u, &mut e, &b1, &[], 5);
    assert!(
        reps.iter()
            .any(|x| x.installed.iter().any(|i| i == "nav-ng 1")),
        "an excluded file counted as damage: {reps:?}"
    );
    assert_eq!(dpkg_status(&u, "nav"), "ii 2.0");
}
