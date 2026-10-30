//! Sealed RPKs on the unit (Sprint 13c, `docs/SECURE-DELIVERY.md` §7.3,
//! §7.4): a sealed model delivered in a media pack with the unit's wrapped
//! key is installed only into the runtime volume, in plaintext only there;
//! missing, foreign or tampered wraps, units without a seal configuration
//! and a closed volume are refused or wait; with `ROBODR_SWTPM=1` the same
//! against a TPM unit, a changed PCR (`robot.seal.unseal_failed`) and
//! crypto-erase (`robot.seal.tamper`, `robot.seal.erased`).
//!
//! The runtime volume is a directory here (`volume_check: unchecked`):
//! device-mapper is not available in the test container. The dm-crypt
//! mount check itself is unit-tested (`src/sealing.rs`) and refused below
//! with the default `dm_crypt` check.

mod common;

use common::*;
use robodr_pkg::deployment::WrappedKey;
use robodr_pkg::rpk::{HealthCheck, Kind};
use robodr_release::ops::{self, Target};
use robodr_seal::unit::Unit as SealUnit;
use robodr_seal::wrap::X25519Secret;
use std::path::{Path, PathBuf};

const MARKER: &[u8] = b"ROBODR-TEST-DELIVERED-SEALED-MODEL-c0de";

fn sealed_rpk(u: &Unit, name: &str, serial: u64, depot: &X25519Secret, healthy: bool) -> PathBuf {
    let mut s = spec(name, serial, Kind::Model);
    let probe = if healthy { "weights.onnx" } else { "missing" };
    s.health = vec![HealthCheck::FilePresent {
        path: format!(
            "{}/model/{name}/current/{probe}",
            u.dir().join("runtime").display()
        ),
    }];
    let pl = u.work.join(format!("payload-{name}-{serial}"));
    let _ = std::fs::remove_dir_all(&pl);
    std::fs::create_dir_all(&pl).unwrap();
    std::fs::write(
        pl.join("weights.onnx"),
        [MARKER, format!(" v{serial}").as_bytes()].concat(),
    )
    .unwrap();
    std::fs::write(pl.join("labels.txt"), b"cat\ndog\n").unwrap();
    let out = u.work.join("rpks");
    std::fs::create_dir_all(&out).unwrap();
    let _ = std::fs::remove_dir_all(out.join(robodr_pkg::rpk::dir_name(name, serial, s.arch)));
    let b = ops::build_rpk_with(&s, &pl, &out, Some(&[depot.public()])).unwrap();
    for r in &u.keys.rel[..2] {
        ops::sign(&Target::Rpk(b.dir.clone()), r, Some(&u.trust), NOW).unwrap();
    }
    b.dir
}

fn wrapped_for(
    depot: &X25519Secret,
    rpk: &Path,
    rec: &robodr_seal::unit::UnitRecord,
) -> WrappedKey {
    let mb = std::fs::read(rpk.join("MANIFEST.json")).unwrap();
    let m = robodr_pkg::rpk::parse_manifest(&mb).unwrap();
    robodr_seal::rpk::rewrap_for_unit(depot, &m, &robodr_pkg::rpk::rpk_digest(&mb), rec).unwrap()
}

/// A pack whose deployment carries `wraps`.
fn sealed_pack(
    u: &Unit,
    name: &str,
    seq: u64,
    rpks: &[PathBuf],
    bundles: &[PathBuf],
    wraps: Vec<WrappedKey>,
) -> PathBuf {
    let mut d = deployment(seq, "ring-1", &[UNIT], rpks);
    let mut w = wraps;
    w.sort_by(|a, b| (&a.unit, &a.rpk_digest).cmp(&(&b.unit, &b.rpk_digest)));
    // Wraps for units the deployment does not target need a group target.
    if w.iter().any(|x| x.unit != UNIT) {
        d.targets.groups = vec!["all-ugv".into()];
    }
    d.wrapped_keys = w;
    pack(
        &u.cfg.media_dir,
        name,
        &u.trust_path,
        &d,
        &depot_and_ops(&u.keys),
        bundles,
    )
}

fn seal_cfg(d: &Path, tpm: Option<String>) -> serde_json::Value {
    let mut s = serde_json::json!({
        "seal_dir": d.join("seal"),
        "runtime_root": d.join("runtime"),
        "volume_check": "unchecked"
    });
    if let Some(t) = tpm {
        s["tpm"] = serde_json::json!({"tcti": t});
    }
    s
}

/// A fallback unit (no TPM): its UWK is on the runtime volume.
fn fallback_unit(tag: &str) -> (Unit, SealUnit) {
    let u = Unit::with(tag, |v| {
        let d = PathBuf::from(v["state_dir"].as_str().unwrap())
            .parent()
            .unwrap()
            .to_path_buf();
        v["seal"] = seal_cfg(&d, None);
    });
    let su = SealUnit::enroll_fallback(
        &u.dir().join("seal"),
        UNIT,
        "ugv-x1",
        &u.dir().join("runtime/.robodr-seal/uwk.key"),
    )
    .unwrap();
    (u, su)
}

fn files_containing(roots: &[PathBuf], needle: &[u8]) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    let mut stack: Vec<PathBuf> = roots.to_vec();
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                let b = std::fs::read(e.path()).unwrap_or_default();
                if b.windows(needle.len()).any(|w| w == needle) {
                    hits.push(e.path());
                }
            }
        }
    }
    hits
}

#[test]
fn a_sealed_model_is_installed_only_into_the_runtime_volume() {
    let (u, su) = fallback_unit("sealed-install");
    let depot = X25519Secret::generate().unwrap();
    let r1 = sealed_rpk(&u, "nav-model", 1, &depot, true);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    sealed_pack(
        &u,
        "p1",
        1,
        std::slice::from_ref(&r1),
        std::slice::from_ref(&b1),
        vec![wrapped_for(&depot, &r1, su.record())],
    );
    let mut e = u.open();
    u.run(&mut e, 10);
    let runtime = u.dir().join("runtime");
    assert_eq!(
        u.current(&runtime.join("model"), "nav-model").as_deref(),
        Some("1")
    );
    let vdir = u.version_dir(&runtime.join("model"), "nav-model", 1);
    assert!(std::fs::read(vdir.join("weights.onnx"))
        .unwrap()
        .starts_with(MARKER));
    assert!(
        u.rules_found()
            .contains(&"robot.deliver.installed".to_string()),
        "{:?}",
        u.rules_found()
    );
    // Plaintext only in the runtime volume: not in the store, the media,
    // the journal, the spool, the public install trees.
    // (`work` is the release station's side of this test: its payload
    // directories are the plaintext input.)
    let elsewhere: Vec<PathBuf> = ["state", "media", "blackbox", "spool", "files", "etc"]
        .iter()
        .map(|s| u.dir().join(s))
        .collect();
    assert!(
        files_containing(&elsewhere, MARKER).is_empty(),
        "plaintext outside the volume"
    );
    assert!(!files_containing(std::slice::from_ref(&runtime), MARKER).is_empty());
    let staged = u.notes_of("robodr.deliver.staged");
    assert_eq!(staged.len(), 1);
    // A sealed v2 that fails its health gate rolls back to v1 (still in
    // the volume; no second unwrap needed).
    let r2 = sealed_rpk(&u, "nav-model", 2, &depot, false);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    sealed_pack(
        &u,
        "p2",
        2,
        std::slice::from_ref(&r2),
        &[b2],
        vec![wrapped_for(&depot, &r2, su.record())],
    );
    u.run(&mut e, 10);
    assert_eq!(
        u.current(&runtime.join("model"), "nav-model").as_deref(),
        Some("1")
    );
    assert!(u
        .rules_found()
        .contains(&"robot.deliver.health_failed".to_string()));
    assert!(u.black_box_verifies());
}

#[test]
fn missing_foreign_or_tampered_wraps_are_refused() {
    let (u, su) = fallback_unit("sealed-wraps");
    let depot = X25519Secret::generate().unwrap();
    let r1 = sealed_rpk(&u, "nav-model", 1, &depot, true);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    let runtime = u.dir().join("runtime/model");
    // (a) No wrap at all.
    sealed_pack(
        &u,
        "p1",
        1,
        std::slice::from_ref(&r1),
        std::slice::from_ref(&b1),
        vec![],
    );
    let mut e = u.open();
    u.run(&mut e, 10);
    assert_eq!(u.current(&runtime, "nav-model"), None);
    let refused: Vec<_> = u.notes_of("robodr.deliver.refused");
    assert!(
        refused.iter().any(|n| n["detail"]
            .as_str()
            .unwrap_or("")
            .contains("no wrapped key")),
        "{refused:?}"
    );
    // (b) Only another unit's wrap (ugv-08 with its own UWK).
    let other = SealUnit::enroll_fallback(
        &u.dir().join("seal-08"),
        "ugv-08",
        "ugv-x1",
        &u.dir().join("seal-08/uwk.key"),
    )
    .unwrap();
    sealed_pack(
        &u,
        "p2",
        2,
        std::slice::from_ref(&r1),
        std::slice::from_ref(&b1),
        vec![wrapped_for(&depot, &r1, other.record())],
    );
    u.run(&mut e, 10);
    assert_eq!(u.current(&runtime, "nav-model"), None);
    // (c) ugv-08's wrap relabelled as ugv-07's (a depot that copies
    // wraps between units): does not authenticate.
    let mut stolen = wrapped_for(&depot, &r1, other.record());
    stolen.unit = UNIT.into();
    sealed_pack(
        &u,
        "p3",
        3,
        std::slice::from_ref(&r1),
        std::slice::from_ref(&b1),
        vec![stolen],
    );
    u.run(&mut e, 10);
    assert_eq!(u.current(&runtime, "nav-model"), None);
    // (d) This unit's wrap with a flipped byte.
    let mut t = wrapped_for(&depot, &r1, su.record());
    let mut b = robodr_seal::from_hex(&t.wrap).unwrap();
    b[60] ^= 1;
    t.wrap = robodr_seal::to_hex(&b);
    sealed_pack(
        &u,
        "p4",
        4,
        std::slice::from_ref(&r1),
        std::slice::from_ref(&b1),
        vec![t],
    );
    u.run(&mut e, 10);
    assert_eq!(u.current(&runtime, "nav-model"), None);
    let codes: Vec<String> = u
        .notes_of("robodr.deliver.refused")
        .iter()
        .filter_map(|n| n["code"].as_str().map(String::from))
        .collect();
    assert!(
        codes.iter().filter(|c| *c == "unauthentic_key").count() >= 2,
        "{codes:?}"
    );
    // (e) The right wrap: installed.
    sealed_pack(
        &u,
        "p5",
        5,
        std::slice::from_ref(&r1),
        &[b1],
        vec![wrapped_for(&depot, &r1, su.record())],
    );
    u.run(&mut e, 10);
    assert_eq!(u.current(&runtime, "nav-model").as_deref(), Some("1"));
}

#[test]
fn units_without_sealing_refuse_sealed_rpks_and_models() {
    let u = Unit::new("sealed-unsupported");
    let depot = X25519Secret::generate().unwrap();
    let r1 = sealed_rpk(&u, "nav-model", 1, &depot, true);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    u.pack("p1", 1, std::slice::from_ref(&r1), &[b1]);
    let mut e = u.open();
    u.run(&mut e, 10);
    let codes: Vec<String> = u
        .notes_of("robodr.deliver.refused")
        .iter()
        .filter_map(|n| n["code"].as_str().map(String::from))
        .collect();
    assert!(codes.contains(&"unsupported".to_string()), "{codes:?}");
    assert!(!u.dir().join("runtime").exists());
}

#[test]
fn a_volume_that_is_not_a_mounted_dm_crypt_device_is_never_written() {
    let u = Unit::with("sealed-dmcheck", |v| {
        let d = PathBuf::from(v["state_dir"].as_str().unwrap())
            .parent()
            .unwrap()
            .to_path_buf();
        let mut s = seal_cfg(&d, None);
        s["volume_check"] = "dm_crypt".into();
        v["seal"] = s;
    });
    let su = SealUnit::enroll_fallback(
        &u.dir().join("seal"),
        UNIT,
        "ugv-x1",
        &u.dir().join("runtime/.robodr-seal/uwk.key"),
    )
    .unwrap();
    let depot = X25519Secret::generate().unwrap();
    let r1 = sealed_rpk(&u, "nav-model", 1, &depot, true);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    sealed_pack(
        &u,
        "p1",
        1,
        std::slice::from_ref(&r1),
        &[b1],
        vec![wrapped_for(&depot, &r1, su.record())],
    );
    let mut e = u.open();
    u.run(&mut e, 5);
    // Waits (the volume may be opened later); nothing written into it.
    assert!(!u.dir().join("runtime/model").exists());
    let notes = u.notes_of("robodr.deliver.refused");
    assert!(
        notes.iter().any(|n| n["transient"] == true
            && n["detail"]
                .as_str()
                .unwrap_or("")
                .contains("not a mount point")),
        "{notes:?}"
    );
}

// --------------------------------------------------------------- swtpm --

struct SwTpm {
    child: std::process::Child,
    port: u16,
}

impl Drop for SwTpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn swtpm(state: &Path) -> SwTpm {
    std::fs::create_dir_all(state).unwrap();
    for i in 0..8u16 {
        let port = 46_000 + (std::process::id() % 2000) as u16 * 4 + i * 2;
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
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let t0 = std::time::Instant::now();
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return SwTpm { child, port };
            }
            if child.try_wait().unwrap().is_some() || t0.elapsed().as_secs() > 10 {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
    }
    panic!("swtpm did not start");
}

#[test]
fn a_tpm_unit_installs_refuses_after_a_pcr_change_and_erases() {
    if std::env::var("ROBODR_SWTPM").as_deref() != Ok("1") {
        eprintln!("skipped: set ROBODR_SWTPM=1 (needs swtpm and tpm2-tools)");
        return;
    }
    let tmp = Tmp::new("sealed-tpm-swtpm");
    let sw = swtpm(&tmp.path().join("swtpm"));
    let tcti = format!("swtpm:host=127.0.0.1,port={}", sw.port);
    let t2 = tcti.clone();
    let u = Unit::with("sealed-tpm", move |v| {
        let d = PathBuf::from(v["state_dir"].as_str().unwrap())
            .parent()
            .unwrap()
            .to_path_buf();
        v["seal"] = seal_cfg(&d, Some(t2));
    });
    let cfg = robodr_seal::tpm::TpmConfig {
        tcti: tcti.clone(),
        ..Default::default()
    };
    let tpm =
        || robodr_seal::tpm::Tpm::new(cfg.clone(), Box::new(robodr_seal::cmd::System)).unwrap();
    tpm().provision(None).unwrap();
    let authority = robodr_seal::keys::PolicyKey::generate().unwrap();
    let su = SealUnit::enroll_tpm(
        &u.dir().join("seal"),
        UNIT,
        "ugv-x1",
        &authority.public(),
        tpm(),
    )
    .unwrap();
    // The runtime volume's mount point (a directory here).
    std::fs::create_dir_all(u.dir().join("runtime")).unwrap();
    let read_pcrs = || {
        let t = tpm();
        let out = tmp.path().join("pcrs.bin");
        let o = t
            .run(
                "tpm2_pcrread",
                &["sha256:0,7".into(), "-o".into(), out.display().to_string()],
                None,
            )
            .unwrap();
        assert!(o.ok());
        let b = std::fs::read(&out).unwrap();
        vec![
            (0u8, b[..32].try_into().unwrap()),
            (7u8, b[32..64].try_into().unwrap()),
        ]
    };
    let p = robodr_seal::policy::sign(
        &authority,
        "ugv-x1",
        1,
        &read_pcrs(),
        robodr_seal::tpm::DEFAULT_FLOOR_NV,
    )
    .unwrap();
    su.install_policy(&p).unwrap();
    let depot = X25519Secret::generate().unwrap();
    let r1 = sealed_rpk(&u, "nav-model", 1, &depot, true);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    sealed_pack(
        &u,
        "p1",
        1,
        std::slice::from_ref(&r1),
        std::slice::from_ref(&b1),
        vec![wrapped_for(&depot, &r1, su.record())],
    );
    let mut e = u.open();
    u.run(&mut e, 10);
    let runtime = u.dir().join("runtime/model");
    assert_eq!(
        u.current(&runtime, "nav-model").as_deref(),
        Some("1"),
        "{:?}",
        u.notes()
            .iter()
            .filter(|n| n["kind"] != "robodr.deliver.highwater")
            .collect::<Vec<_>>()
    );
    // The unit boots modified software (PCR 7): the next sealed release
    // is not unsealed.
    let o = tpm()
        .run(
            "tpm2_pcrextend",
            &[format!("7:sha256={}", "ab".repeat(32))],
            None,
        )
        .unwrap();
    assert!(o.ok());
    let r3 = sealed_rpk(&u, "nav-model", 3, &depot, true);
    let b3 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r3));
    sealed_pack(
        &u,
        "p2",
        2,
        std::slice::from_ref(&r3),
        std::slice::from_ref(&b3),
        vec![wrapped_for(&depot, &r3, su.record())],
    );
    u.run(&mut e, 10);
    assert_eq!(u.current(&runtime, "nav-model").as_deref(), Some("1"));
    let f = u.findings();
    let unseal: Vec<_> = f
        .iter()
        .filter(|x| x.0 == "robot.seal.unseal_failed")
        .collect();
    assert_eq!(unseal.len(), 1, "{:?}", u.rules_found());
    assert_eq!(unseal[0].1, "high");
    assert_eq!(
        u.notes_of("robodr.seal.unseal_failed")[0]["reason"],
        "policy_refused"
    );
    // Tamper: crypto-erase. Both Critical findings; the keys are dead.
    let rep = e.erase("tamper", None).unwrap();
    assert!(rep["epoch_after"].as_u64() > rep["epoch_before"].as_u64());
    let rules = u.rules_found();
    assert!(rules.contains(&"robot.seal.tamper".to_string()));
    assert!(rules.contains(&"robot.seal.erased".to_string()));
    for (r, sev, _) in u.findings() {
        if r == "robot.seal.erased" || r == "robot.seal.tamper" {
            assert_eq!(sev, "critical");
        }
    }
    assert_eq!(u.notes_of("robodr.seal.erased").len(), 1);
    // After the erase nothing unseals any more.
    let r4 = sealed_rpk(&u, "nav-model", 4, &depot, true);
    let b4 = u.bundle(3, Some(bundle_hash(&b3)), std::slice::from_ref(&r4));
    sealed_pack(
        &u,
        "p3",
        3,
        std::slice::from_ref(&r4),
        &[b4],
        vec![wrapped_for(&depot, &r4, su.record())],
    );
    u.run(&mut e, 10);
    assert_eq!(u.current(&runtime, "nav-model").as_deref(), Some("1"));
    let reasons: Vec<_> = u
        .notes_of("robodr.seal.unseal_failed")
        .iter()
        .map(|n| n["reason"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(reasons, ["policy_refused", "erased"]);
    drop(sw);
    assert!(u.black_box_verifies());
}
