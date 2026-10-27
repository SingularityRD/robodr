//! Hostile inputs against the unit agent: shell metacharacters in probes,
//! probes that hang or flood, packs for another unit / site / ring, a
//! deployment signed by the depot alone, traversal and symlinks in
//! payloads and install roots, replays, equivocation, expiry, state loss.

mod common;

use common::*;
use robodr_pkg::rpk::{HealthCheck, Kind};
use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

fn probe_spec(
    u: &Unit,
    name: &str,
    serial: u64,
    argv: &[&str],
    timeout_s: u32,
) -> robodr_release::ops::RpkSpec {
    let mut s = files_spec(u, name, serial, true);
    s.health.push(HealthCheck::Probe {
        argv: argv.iter().map(|a| a.to_string()).collect(),
        user: "probe".into(),
        timeout_s,
    });
    s
}

/// A directory anyone may write to (so a probe running as the probe user
/// could create the marker there if a shell ever interpreted its argv).
fn open_dir(u: &Unit) -> std::path::PathBuf {
    let d = u.dir().join("world");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(u.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o1777)).unwrap();
    d
}

#[test]
fn probe_argv_with_shell_metacharacters_is_not_interpreted() {
    let u = Unit::new("meta");
    let w = open_dir(&u);
    let m = |n: &str| format!("{}/{n}", w.display());
    let args = [
        format!("$(touch {})", m("a")),
        format!("`touch {}`", m("b")),
        format!("; touch {}", m("c")),
        format!("| touch {}", m("d")),
        format!("&& touch {} *", m("e")),
    ];
    let mut argv = vec!["/bin/echo"];
    argv.extend(args.iter().map(String::as_str));
    let r = u.rpk(&probe_spec(&u, "nav-stack", 1, &argv, 10), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], std::slice::from_ref(&b));
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    // echo printed its arguments and exited 0: healthy, nothing executed.
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
    for n in ["a", "b", "c", "d", "e"] {
        assert!(!w.join(n).exists(), "argv was interpreted by a shell ({n})");
    }
    let h = u.notes_of("robodr.deliver.health");
    let detail = h[0]["checks"][1]["detail"].as_str().unwrap();
    assert!(detail.starts_with("exit 0"), "{detail}");
    assert!(detail.contains("$(touch"), "{detail}");

    // The same metacharacters in a failing probe: `test -e` of the literal
    // string fails, the release rolls back, and still nothing ran.
    let r2 = u.rpk(
        &probe_spec(
            &u,
            "nav-stack",
            2,
            &["/usr/bin/test", "-e", &format!("x; touch {}", m("f"))],
            10,
        ),
        &[("ok", b"v2")],
    );
    let b2 = u.bundle(2, Some(bundle_hash(&b)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], &[b2]);
    let reps = u.run(&mut e, 5);
    assert!(reps.iter().any(|x| !x.rolled_back.is_empty()), "{reps:?}");
    assert!(!w.join("f").exists());
}

#[test]
fn a_probe_that_hangs_is_killed_and_the_release_rolled_back() {
    let u = Unit::new("hang");
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    // Forks a child that would keep the pipe open, then sleeps.
    let r2 = u.rpk(
        &probe_spec(
            &u,
            "nav-stack",
            2,
            &["/bin/sh", "-c", "sleep 60 & sleep 60"],
            1,
        ),
        &[("ok", b"v2")],
    );
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], &[b2]);
    let t0 = Instant::now();
    let reps = u.run(&mut e, 5);
    assert!(
        t0.elapsed().as_secs() < 20,
        "the hang was not bounded: {:?}",
        t0.elapsed()
    );
    assert!(
        reps.iter()
            .any(|x| x.rolled_back == vec!["nav-stack 2 -> 1".to_string()]),
        "{reps:?}"
    );
    let h = u.notes_of("robodr.deliver.health");
    let d = h.last().unwrap()["checks"][1]["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(d.contains("killed after the timeout"), "{d}");
    assert!(!d.contains("held by an escaped process"), "{d}");
}

#[test]
fn a_probe_that_floods_output_is_bounded() {
    let u = Unit::with("flood", |v| {
        v["health"]["max_output_bytes"] = 2048.into();
    });
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    let r2 = u.rpk(
        &probe_spec(&u, "nav-stack", 2, &["/usr/bin/yes", "flood"], 1),
        &[("ok", b"v2")],
    );
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], &[b2]);
    let reps = u.run(&mut e, 5);
    assert!(reps.iter().any(|x| !x.rolled_back.is_empty()), "{reps:?}");
    let h = u.notes_of("robodr.deliver.health");
    let d = h.last().unwrap()["checks"][1]["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(d.contains("truncated"), "{d}");
    // The evidence carries at most a bounded excerpt.
    assert!(d.len() < 1024, "{}", d.len());
}

#[test]
fn a_probe_user_that_is_privileged_or_unknown_is_refused() {
    for user in ["root", "robodr", "nosuchuser"] {
        let u = Unit::new("probe-user");
        let mut s = files_spec(&u, "nav-stack", 1, true);
        s.health.push(HealthCheck::Probe {
            argv: vec!["/bin/true".into()],
            user: user.into(),
            timeout_s: 5,
        });
        // The builder refuses root itself (robodr-pkg); build as "probe"
        // and rename the user in a re-signed manifest.
        let r = if user == "root" {
            let mut s2 = s.clone();
            s2.health[1] = HealthCheck::Probe {
                argv: vec!["/bin/true".into()],
                user: "probe".into(),
                timeout_s: 5,
            };
            u.rpk(&s2, &[("ok", b"v1")])
        } else {
            u.rpk(&s, &[("ok", b"v1")])
        };
        let b = u.bundle(1, None, std::slice::from_ref(&r));
        if user == "root" {
            // A manifest naming root does not even parse (robodr-pkg).
            let inner = rpk_in(&b);
            tamper_manifest(&inner, &u.keys, |m| {
                m.health[1] = HealthCheck::Probe {
                    argv: vec!["/bin/true".into()],
                    user: "root".into(),
                    timeout_s: 5,
                };
            });
            relist_and_resign(&b, &u.keys);
        }
        let mut d = deployment(1, "ring-1", &[UNIT], &[r]);
        d.items[0].rpk_digest = digest(&rpk_in(&b));
        pack(
            &u.cfg.media_dir,
            "p1",
            &u.trust_path,
            &d,
            &depot_and_ops(&u.keys),
            &[b],
        );
        let mut e = u.open();
        let reps = u.run(&mut e, 5);
        assert!(
            reps.iter().all(|x| x.installed.is_empty()),
            "{user}: {reps:?}"
        );
        assert!(
            reps.iter().any(|x| !x.refused.is_empty()),
            "{user}: {reps:?}"
        );
        assert_eq!(
            u.current(&u.cfg.install.files_root, "nav-stack"),
            None,
            "{user}"
        );
    }
}

fn refused_pack(
    u: &Unit,
    d: &robodr_pkg::deployment::Deployment,
    by: &[&robodr_blackbox::Ed25519SigningKey],
    bundles: &[std::path::PathBuf],
    trust: &std::path::Path,
    code: &str,
) {
    pack(&u.cfg.media_dir, "evil", trust, d, by, bundles);
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    let refused: Vec<&String> = reps.iter().flat_map(|r| r.refused.iter()).collect();
    assert!(
        refused.iter().any(|r| r.contains(code)),
        "expected {code}: {reps:?}"
    );
    assert!(reps.iter().all(|r| r.installed.is_empty()));
    assert!(e.state().deployment.is_none());
    let n = u.notes_of("robodr.deliver.refused");
    assert!(n.iter().any(|x| x["code"] == code), "{n:?}");
    assert!(u
        .rules_found()
        .contains(&"robot.deliver.refused".to_string()));
    // Reported once, not every loop.
    let before = u.notes_of("robodr.deliver.refused").len();
    u.run(&mut e, 3);
    assert_eq!(u.notes_of("robodr.deliver.refused").len(), before);
    let _ = std::fs::remove_dir_all(u.cfg.media_dir.join("evil"));
}

#[test]
fn a_pack_for_another_unit_ring_or_site_is_refused() {
    let u = Unit::new("scope");
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let by = depot_and_ops(&u.keys);
    // Another unit of the same ring.
    refused_pack(
        &u,
        &deployment(1, "ring-1", &["ugv-08"], std::slice::from_ref(&r)),
        &by,
        std::slice::from_ref(&b),
        &u.trust_path,
        "wrong_scope",
    );
    // This unit, but another ring.
    refused_pack(
        &u,
        &deployment(2, "ring-2", &[UNIT], std::slice::from_ref(&r)),
        &by,
        std::slice::from_ref(&b),
        &u.trust_path,
        "wrong_scope",
    );
    // A lab deployment naming the unit (it is not a lab unit): needs the
    // production quorum and is for another ring anyway.
    refused_pack(
        &u,
        &deployment(3, "lab", &[UNIT], std::slice::from_ref(&r)),
        &by,
        std::slice::from_ref(&b),
        &u.trust_path,
        "wrong_scope",
    );
    // Another site's trust file signed by the same roots, and its
    // deployment.
    let mut tb = trust_file(&u.keys);
    tb.site = "site-b".into();
    let tbp = u.dir().join("site-b-trust.json");
    write_trust(&tbp, &tb, &u.keys);
    let mut db = deployment(4, "ring-1", &[UNIT], std::slice::from_ref(&r));
    db.site = "site-b".into();
    refused_pack(&u, &db, &by, std::slice::from_ref(&b), &tbp, "wrong_scope");
    // A production deployment naming the unit only through a group it is
    // not enrolled in.
    let mut dg = deployment(5, "ring-1", &["ugv-08"], std::slice::from_ref(&r));
    dg.targets.groups = vec!["north".into()];
    refused_pack(
        &u,
        &dg,
        &by,
        std::slice::from_ref(&b),
        &u.trust_path,
        "wrong_scope",
    );
    // Rollout larger than the unit's ring.
    let mut dr = deployment(6, "ring-1", &[UNIT], std::slice::from_ref(&r));
    dr.rollout.batch_size = 3;
    refused_pack(
        &u,
        &dr,
        &by,
        std::slice::from_ref(&b),
        &u.trust_path,
        "invalid",
    );
    // Built for another platform / architecture.
    let mut s = files_spec(&u, "nav-other", 1, true);
    s.platform = "ugv-x2".into();
    let rp = u.rpk(&s, &[("ok", b"v1")]);
    let mut s = files_spec(&u, "nav-amd", 1, true);
    s.arch = robodr_pkg::rpk::Arch::Amd64;
    let ra = u.rpk(&s, &[("ok", b"v1")]);
    let b2 = u.bundle(1, None, &[rp.clone(), ra.clone()]);
    refused_pack(
        &u,
        &deployment(7, "ring-1", &[UNIT], &[rp]),
        &by,
        std::slice::from_ref(&b2),
        &u.trust_path,
        "wrong_scope",
    );
    refused_pack(
        &u,
        &deployment(8, "ring-1", &[UNIT], &[ra]),
        &by,
        &[b2],
        &u.trust_path,
        "wrong_scope",
    );
    assert!(u.black_box_verifies());
}

#[test]
fn a_unit_in_a_group_of_a_production_ring_is_targeted() {
    let u = Unit::with("group", |v| {
        v["unit"]["groups"] = serde_json::json!(["north"]);
    });
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let mut d = deployment(1, "ring-1", &["ugv-08"], &[r]);
    d.targets.groups = vec!["north".into()];
    pack(
        &u.cfg.media_dir,
        "p1",
        &u.trust_path,
        &d,
        &depot_and_ops(&u.keys),
        &[b],
    );
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
}

#[test]
fn a_deployment_signed_by_the_depot_alone_is_refused() {
    let u = Unit::new("depot-only");
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let d = deployment(1, "ring-1", &[UNIT], std::slice::from_ref(&r));
    refused_pack(
        &u,
        &d,
        &[&u.keys.depot],
        std::slice::from_ref(&b),
        &u.trust_path,
        "quorum_not_met",
    );
    // Depot + one operator is not the production quorum either.
    let d = deployment(2, "ring-1", &[UNIT], std::slice::from_ref(&r));
    refused_pack(
        &u,
        &d,
        &[&u.keys.depot, &u.keys.ops[0]],
        std::slice::from_ref(&b),
        &u.trust_path,
        "quorum_not_met",
    );
    // Operators without the depot.
    let d = deployment(3, "ring-1", &[UNIT], std::slice::from_ref(&r));
    refused_pack(
        &u,
        &d,
        &[&u.keys.ops[0], &u.keys.ops[1]],
        std::slice::from_ref(&b),
        &u.trust_path,
        "quorum_not_met",
    );
    // Release keys cannot assign.
    let d = deployment(4, "ring-1", &[UNIT], &[r]);
    refused_pack(
        &u,
        &d,
        &[&u.keys.depot, &u.keys.rel[0], &u.keys.rel[1]],
        &[b],
        &u.trust_path,
        "wrong_role",
    );
}

#[test]
fn traversal_paths_in_a_quorum_signed_files_payload_are_refused() {
    let u = Unit::new("traversal");
    for evil in ["../../escape", "/etc/passwd", "a/../../b", ".hidden", "-rf"] {
        let r = u.rpk(
            &files_spec(&u, "nav-stack", 1, true),
            &[("ok", b"v1"), ("bin/x", b"x")],
        );
        let b = u.bundle(1, None, std::slice::from_ref(&r));
        let inner = rpk_in(&b);
        tamper_manifest(&inner, &u.keys, |m| {
            let i = m.content.iter().position(|c| c.path == "bin/x").unwrap();
            m.content[i].path = evil.into();
            m.content.sort_by(|a, b| a.path.cmp(&b.path));
        });
        relist_and_resign(&b, &u.keys);
        let mut d = deployment(1, "ring-1", &[UNIT], &[r]);
        d.items[0].rpk_digest = digest(&inner);
        pack(
            &u.cfg.media_dir,
            "evil",
            &u.trust_path,
            &d,
            &depot_and_ops(&u.keys),
            &[b],
        );
        let mut e = u.open();
        let reps = u.run(&mut e, 3);
        assert!(
            reps.iter()
                .any(|x| x.refused.iter().any(|y| y.contains("invalid"))),
            "{evil}: {reps:?}"
        );
        assert!(!u.dir().join("escape").exists());
        assert!(
            !u.cfg.install.files_root.join("nav-stack").exists(),
            "{evil}"
        );
        drop(e);
        let _ = std::fs::remove_dir_all(u.cfg.media_dir.join("evil"));
    }
}

#[test]
fn a_symlink_in_the_media_pack_is_refused() {
    let u = Unit::new("symlink-media");
    let r = u.rpk(
        &files_spec(&u, "nav-stack", 1, true),
        &[("ok", b"v1"), ("bin/x", b"some payload")],
    );
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let p = u.pack("p1", 1, &[r], &[b]);
    // Replace one chunk of the pack by a symlink to an identical file.
    let chunks = rpk_in(&p.join("bundles/b0")).join("chunks");
    let c = std::fs::read_dir(&chunks)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let copy = u.dir().join("copy-of-chunk");
    std::fs::copy(&c, &copy).unwrap();
    std::fs::remove_file(&c).unwrap();
    std::os::unix::fs::symlink(&copy, &c).unwrap();
    let mut e = u.open();
    let reps = u.run(&mut e, 3);
    assert!(reps.iter().any(|x| !x.refused.is_empty()), "{reps:?}");
    assert!(e.state().deployment.is_none());
    // A symlinked top-level document too.
    std::fs::remove_file(&c).unwrap();
    std::fs::copy(&copy, &c).unwrap();
    let t = p.join("trust.json");
    std::fs::rename(&t, u.dir().join("t.json")).unwrap();
    std::os::unix::fs::symlink(u.dir().join("t.json"), &t).unwrap();
    // A changed pack is judged again (its deployment.json is the same, so
    // rename the entry).
    std::fs::rename(&p, u.cfg.media_dir.join("p2")).unwrap();
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("symlink"))),
        "{reps:?}"
    );
    // A stray file in the pack.
    let p3 = u.cfg.media_dir.join("p2");
    std::fs::remove_file(p3.join("trust.json")).unwrap();
    std::fs::copy(u.dir().join("t.json"), p3.join("trust.json")).unwrap();
    std::fs::write(p3.join("README"), b"x").unwrap();
    std::fs::rename(&p3, u.cfg.media_dir.join("p3")).unwrap();
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("unexpected_file"))),
        "{reps:?}"
    );
    assert!(e.state().deployment.is_none());
}

#[test]
fn a_symlink_in_place_of_an_install_directory_is_never_followed() {
    for kind in [Kind::Files, Kind::Config] {
        let u = Unit::new("symlink-root");
        let outside = u.dir().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let root = if kind == Kind::Files {
            u.cfg.install.files_root.clone()
        } else {
            u.cfg.install.config_root.clone()
        };
        std::os::unix::fs::symlink(&outside, root.join("nav-stack")).unwrap();
        let mut s = spec("nav-stack", 1, kind);
        s.health = vec![];
        let r = u.rpk(&s, &[("ok", b"v1")]);
        let b = u.bundle(1, None, std::slice::from_ref(&r));
        u.pack("p1", 1, &[r], &[b]);
        let mut e = u.open();
        let reps = u.run(&mut e, 3);
        assert!(
            reps.iter().any(|x| !x.refused.is_empty()),
            "{kind:?}: {reps:?}"
        );
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            0,
            "{kind:?}: written through the symlink"
        );
    }
}

#[test]
fn a_config_package_cannot_write_outside_its_root() {
    let u = Unit::new("config-root");
    // Traversal in a re-signed config manifest.
    let r = u.rpk(
        &spec("nav-config", 1, Kind::Config),
        &[("a.yaml", b"a: 1\n")],
    );
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let inner = rpk_in(&b);
    tamper_manifest(&inner, &u.keys, |m| {
        m.content[0].path = "../../files/pwned".into()
    });
    relist_and_resign(&b, &u.keys);
    let mut d = deployment(1, "ring-1", &[UNIT], &[r]);
    d.items[0].rpk_digest = digest(&inner);
    pack(
        &u.cfg.media_dir,
        "evil",
        &u.trust_path,
        &d,
        &depot_and_ops(&u.keys),
        &[b],
    );
    let mut e = u.open();
    let reps = u.run(&mut e, 3);
    assert!(reps.iter().any(|x| !x.refused.is_empty()), "{reps:?}");
    assert!(!u.cfg.install.files_root.join("pwned").exists());
    drop(e);
    // A clean config package: everything below config_root/<name>/<serial>.
    let _ = std::fs::remove_dir_all(u.cfg.media_dir.join("evil"));
    let r = u.rpk(
        &spec("nav-config", 2, Kind::Config),
        &[("a.yaml", b"a: 1\n"), ("d/b.yaml", b"b: 2\n")],
    );
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p2", 2, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
    let mut found = Vec::new();
    let mut stack = vec![u.dir().to_path_buf()];
    while let Some(d) = stack.pop() {
        for x in std::fs::read_dir(&d).unwrap() {
            let p = x.unwrap().path();
            if p.file_name().is_some_and(|n| n == "b.yaml") {
                found.push(p.clone());
            }
            if p.is_dir()
                && !p.is_symlink()
                && !p.starts_with(u.dir().join("state"))
                && !p.starts_with(&u.work)
            {
                stack.push(p);
            }
        }
    }
    assert_eq!(
        found,
        vec![u
            .version_dir(&u.cfg.install.config_root, "nav-config", 2)
            .join("d/b.yaml")]
    );
}

#[test]
fn a_regular_directory_in_place_of_the_current_link_is_not_replaced() {
    let u = Unit::new("current-dir");
    let cur = u.cfg.install.files_root.join("nav-stack/current");
    std::fs::create_dir_all(&cur).unwrap();
    std::fs::write(cur.join("keep"), b"operator data").unwrap();
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    // The switch fails; there is no earlier version: blocked (Critical).
    assert!(reps.iter().any(|x| !x.blocked.is_empty()), "{reps:?}");
    assert_eq!(std::fs::read(cur.join("keep")).unwrap(), b"operator data");
    assert!(u
        .findings()
        .iter()
        .any(|(r, s, _)| r == "robot.deliver.rollback_blocked_floor" && s == "critical"));
}

#[test]
fn replayed_and_equivocating_deployments_are_refused() {
    let u = Unit::new("replay");
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    let r2 = u.rpk(&files_spec(&u, "nav-stack", 2, true), &[("ok", b"v2")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack(
        "p2",
        5,
        std::slice::from_ref(&r2),
        std::slice::from_ref(&b2),
    );
    u.run(&mut e, 4);
    assert_eq!(e.state().installed["nav-stack"].ver.serial, 2);
    // The first pack again under another name: an older deployment.
    let d1 = deployment(1, "ring-1", &[UNIT], std::slice::from_ref(&r2));
    pack(
        &u.cfg.media_dir,
        "old",
        &u.trust_path,
        &d1,
        &depot_and_ops(&u.keys),
        std::slice::from_ref(&b2),
    );
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("replay"))),
        "{reps:?}"
    );
    // Same sequence number, other content.
    let mut d5 = deployment(5, "ring-1", &[UNIT], &[r2]);
    d5.deployment_id = "dep-other".into();
    pack(
        &u.cfg.media_dir,
        "eq",
        &u.trust_path,
        &d5,
        &depot_and_ops(&u.keys),
        &[b2],
    );
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("equivocation"))),
        "{reps:?}"
    );
    assert_eq!(e.state().installed["nav-stack"].ver.serial, 2);
}

#[test]
fn an_equivocating_bundle_is_a_chain_finding_and_a_gap_is_reported() {
    let u = Unit::new("chain");
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    // Another bundle 1 (other content, same sequence number).
    let other = u.rpk(&files_spec(&u, "nav-other", 1, true), &[("ok", b"o")]);
    let b1x = u.bundle(1, None, std::slice::from_ref(&other));
    u.pack("eq", 2, &[other], &[b1x]);
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("equivocation"))),
        "{reps:?}"
    );
    assert!(u
        .rules_found()
        .contains(&"robot.deliver.chain_gap".to_string()));
    // Bundle 4 after 1: accepted (a unit sees only its bundles), reported.
    let r = u.rpk(&files_spec(&u, "nav-stack", 4, true), &[("ok", b"v4")]);
    let b4 = u.bundle(4, Some("ab".repeat(32)), std::slice::from_ref(&r));
    u.pack("gap", 3, &[r], &[b4]);
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
    let chain = u.notes_of("robodr.deliver.chain");
    assert_eq!(chain.len(), 1);
    assert_eq!(
        (chain[0]["gap_after"].as_u64(), chain[0]["seq"].as_u64()),
        (Some(1), Some(4))
    );
    let _ = b1;
}

#[test]
fn an_older_trust_file_is_refused_after_a_rotation() {
    let u = Unit::new("trust-rollback");
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    // Rotation to version 2 revoking release key rel-a... floors grow.
    let mut t2 = with_floor(trust_file(&u.keys), "nav-stack", 1);
    t2.version = 2;
    let t2p = u.dir().join("trust-v2.json");
    write_trust(&t2p, &t2, &u.keys);
    let r2 = u.rpk(&files_spec(&u, "nav-stack", 2, true), &[("ok", b"v2")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    let d = deployment(2, "ring-1", &[UNIT], std::slice::from_ref(&r2));
    pack(
        &u.cfg.media_dir,
        "rot",
        &t2p,
        &d,
        &depot_and_ops(&u.keys),
        std::slice::from_ref(&b2),
    );
    u.run(&mut e, 4);
    assert_eq!(u.notes_of("robodr.deliver.trust_rotated").len(), 1);
    // The anchor moved: version 1 is now a replay.
    let d3 = deployment(3, "ring-1", &[UNIT], &[r2]);
    pack(
        &u.cfg.media_dir,
        "old-trust",
        &u.trust_path,
        &d3,
        &depot_and_ops(&u.keys),
        &[b2],
    );
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("replay"))),
        "{reps:?}"
    );
}

#[test]
fn an_expired_deployment_is_refused_and_staleness_reported() {
    let u = Unit::new("expiry");
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    // 31 days later the deployment has expired: stale (Medium) ...
    u.clock.set(NOW + 31 * 86400);
    let r = e.tick().unwrap();
    assert!(r.stale.is_some(), "{r:?}");
    let f = u.findings();
    assert!(
        f.iter()
            .any(|(r, s, _)| r == "robot.deliver.stale" && s == "medium"),
        "{f:?}"
    );
    // ... and High after the grace period.
    u.clock.set(NOW + 33 * 86400);
    e.tick().unwrap();
    assert!(u
        .findings()
        .iter()
        .any(|(r, s, _)| r == "robot.deliver.stale" && s == "high"));
    // Once, not every loop.
    e.tick().unwrap();
    assert_eq!(u.notes_of("robodr.deliver.stale").len(), 2);
    // After the trust file expired too, a pack is refused as stale.
    u.clock.set(NOW + 91 * 86400);
    let r2 = u.rpk(&files_spec(&u, "nav-stack", 2, true), &[("ok", b"v2")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("late", 2, &[r2], &[b2]);
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("expired"))),
        "{reps:?}"
    );
    assert_eq!(e.state().installed["nav-stack"].ver.serial, 1);
}

#[test]
fn with_an_untrusted_clock_expiry_follows_the_depots_signed_time() {
    let u = Unit::with("untrusted-clock", |v| {
        v["trust"]["clock"] = "untrusted".into();
    });
    // The unit's clock is far in the future (an RTC reset to 2099, say):
    // with a trusted clock everything would have expired.
    u.clock.set(4_000_000_000);
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    assert_eq!(e.state().time_floor, NOW - 60);
    // A deployment the depot signed after the trust file's expiry is
    // refused as stale ("expired by the depot's clock").
    let r2 = u.rpk(&files_spec(&u, "nav-stack", 2, true), &[("ok", b"v2")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    let mut d = deployment(2, "ring-1", &[UNIT], &[r2]);
    d.created_at = NOW + 100 * 86400;
    d.not_before = NOW + 100 * 86400;
    d.expires_at = NOW + 120 * 86400;
    pack(
        &u.cfg.media_dir,
        "late",
        &u.trust_path,
        &d,
        &depot_and_ops(&u.keys),
        &[b2],
    );
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("expired"))),
        "{reps:?}"
    );
    assert!(u.rules_found().contains(&"robot.deliver.stale".to_string()));
    // The refused pack did not move the time floor.
    assert_eq!(e.state().time_floor, NOW - 60);
}

#[test]
fn an_rpk_that_requires_an_operator_waits_for_the_confirmation() {
    let u = Unit::new("operator");
    let mut s = files_spec(&u, "nav-stack", 1, true);
    s.install.requires_operator_present = true;
    let r = u.rpk(&s, &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let rep = e.tick().unwrap();
    assert_eq!(
        rep.deferred.as_deref(),
        Some("nav-stack 1: operator_confirmation")
    );
    let digest = e.state().deployment.as_ref().unwrap().digest.clone();
    // The CLI writes the confirmation.
    let cfgp = u.dir().join("cfg.json");
    std::fs::write(&cfgp, serde_json::to_vec(&u.cfg).unwrap()).unwrap();
    let code = robodr_deliverd::cli::run_deliverd(vec![
        "confirm".into(),
        "--config".into(),
        cfgp.to_string_lossy().into_owned(),
        "--deployment".into(),
        digest.clone(),
        "--package".into(),
        "nav-stack".into(),
    ]);
    assert_eq!(code, 0);
    let rep = e.tick().unwrap();
    assert_eq!(rep.installed, vec!["nav-stack 1".to_string()], "{rep:?}");
    assert_eq!(u.notes_of("robodr.deliver.operator_confirmed").len(), 1);
    // Consumed.
    assert!(!e.confirm_path(&digest, "nav-stack").exists());
}

#[test]
fn outside_the_maintenance_window_the_install_waits() {
    let u = Unit::new("window");
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let mut d = deployment(1, "ring-1", &[UNIT], &[r]);
    d.maintenance_window = Some(closed_window());
    pack(
        &u.cfg.media_dir,
        "p1",
        &u.trust_path,
        &d,
        &depot_and_ops(&u.keys),
        &[b],
    );
    let mut e = u.open();
    let rep = e.tick().unwrap();
    assert_eq!(
        rep.deferred.as_deref(),
        Some("nav-stack 1: maintenance_window")
    );
    // Sunday 00:30 UTC: inside.
    u.clock
        .set(1_790_000_000 - (1_790_000_000 % 86_400) - 86_400 + 30 * 60);
    let rep = e.tick().unwrap();
    assert_eq!(rep.installed, vec!["nav-stack 1".to_string()], "{rep:?}");
}

#[test]
fn a_deleted_state_file_does_not_reopen_a_downgrade() {
    let u = Unit::new("state-loss");
    let mut s = files_spec(&u, "nav-stack", 5, true);
    s.security_floor = 5;
    let r5 = u.rpk(&s, &[("ok", b"v5")]);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r5));
    u.pack("p1", 1, &[r5], std::slice::from_ref(&b1));
    let mut e = u.open();
    u.run(&mut e, 4);
    assert_eq!(e.state().floor("nav-stack"), 5);
    e.close().unwrap();
    // Root deletes the state file (and the anchor stays).
    std::fs::remove_file(u.cfg.state_path()).unwrap();
    let mut e = u.open();
    assert_eq!(
        e.state().floor("nav-stack"),
        5,
        "floor restored from the black box"
    );
    assert_eq!(u.notes_of("robodr.deliver.state_restored").len(), 1);
    assert!(u.rules_found().iter().any(|r| r == "robot.deliver.refused"));
    let r4 = u.rpk(&files_spec(&u, "nav-stack", 4, true), &[("ok", b"v4")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r4));
    u.pack("p2", 2, &[r4], &[b2]);
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("below_floor"))),
        "{reps:?}"
    );
}

#[test]
fn site_floors_and_revocations_of_a_rotated_trust_file_apply() {
    let u = Unit::new("site-floor");
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    let r2 = u.rpk(&files_spec(&u, "nav-stack", 2, true), &[("ok", b"v2")]);
    // Trust v2 revokes serial 2 of nav-stack.
    let mut t2 = trust_file(&u.keys);
    t2.version = 2;
    t2.revoked_serials = vec![robodr_pkg::trust::RevokedSerial {
        name: "nav-stack".into(),
        serial: 2,
    }];
    let t2p = u.dir().join("trust-v2.json");
    write_trust(&t2p, &t2, &u.keys);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    let d = deployment(2, "ring-1", &[UNIT], &[r2]);
    pack(
        &u.cfg.media_dir,
        "rev",
        &t2p,
        &d,
        &depot_and_ops(&u.keys),
        &[b2],
    );
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("revoked"))),
        "{reps:?}"
    );
    assert_eq!(e.state().installed["nav-stack"].ver.serial, 1);
}

#[test]
fn a_second_agent_on_the_same_unit_is_locked_out() {
    let u = Unit::new("lock");
    let _e = u.open();
    assert!(robodr_deliverd::Engine::open(u.cfg.clone(), Box::new(u.clock.clone())).is_err());
}
