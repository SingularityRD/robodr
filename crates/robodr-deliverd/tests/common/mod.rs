//! Shared fixture of the robodr-deliverd integration tests: a site (keys,
//! trust file), RPKs and bundles built and signed with the 13a release
//! code, deployments signed by the depot and operators, per-unit media
//! packs, a unit (configuration, directories, fake agentd status) and
//! readers for the black box and the findings spool.
//!
//! Everything lives in a fresh temporary directory; nothing touches the
//! host's dpkg, systemd or /etc.
#![allow(dead_code)]

use robodr_blackbox::{Ed25519SigningKey, KeyFile, Signer};
use robodr_deliverd::clock::FixedClock;
use robodr_deliverd::config::Config;
use robodr_deliverd::engine::{Engine, TickReport};
use robodr_pkg::common::{fingerprint, to_canonical};
use robodr_pkg::deployment::{
    Deployment, Item, MaintenanceWindow, Rollout, Targets, DEPLOYMENT_FORMAT, DEPLOYMENT_SIG_DOMAIN,
};
use robodr_pkg::rpk::{Arch, HealthCheck, Install, Kind, Version};
use robodr_pkg::sig::SignatureSet;
use robodr_pkg::trust::{
    Floor, Programme, Quorum, RingAssignment, TrustFile, TrustKey, VerifiedTrust, TRUST_FORMAT,
    TRUST_SIG_DOMAIN,
};
use robodr_release::ops::{self, BundleOptions, RpkSpec, Target, SPEC_FORMAT};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const NOW: u64 = 1_790_000_000;
pub const SITE: &str = "site-a";
pub const UNIT: &str = "ugv-07";
pub const PROGRAMME: &str = "ugv-x1";
pub const BOOT: &str = "test-boot-0001";

/// A fresh, empty temp directory, removed on drop.
pub struct Tmp(pub PathBuf);

impl Tmp {
    pub fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "robodr-deliverd-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn key(id: &str, seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(id, &[seed; 32]).unwrap()
}

/// Every role's keys (deterministic seeds).
pub struct Keys {
    pub roots: Vec<Ed25519SigningKey>,
    pub rel: Vec<Ed25519SigningKey>,
    pub depot: Ed25519SigningKey,
    pub ops: Vec<Ed25519SigningKey>,
}

pub fn keys() -> Keys {
    Keys {
        roots: (1..=3).map(|i| key(&format!("root-{i}"), i)).collect(),
        rel: ["rel-a", "rel-b", "rel-c"]
            .iter()
            .zip(11..)
            .map(|(n, s)| key(n, s))
            .collect(),
        depot: key("depot-1", 21),
        ops: (1..=3).map(|i| key(&format!("op-{i}"), 30 + i)).collect(),
    }
}

pub fn tk(k: &Ed25519SigningKey) -> TrustKey {
    TrustKey::new(k.key_id(), &k.public_key())
}

pub fn pins(k: &Keys) -> Vec<String> {
    k.roots
        .iter()
        .map(|r| fingerprint(&r.public_key()))
        .collect()
}

/// The site trust file: one programme delivering every package, unit
/// `ugv-07` in `ring-1` (with `ugv-08`), `bench-01` in `lab`.
pub fn trust_file(k: &Keys) -> TrustFile {
    TrustFile {
        format: TRUST_FORMAT.into(),
        site: SITE.into(),
        version: 1,
        issued_at: NOW - 3600,
        expires_at: NOW + 90 * 86400,
        programmes: vec![Programme {
            name: PROGRAMME.into(),
            release_keys: k.rel.iter().map(|r| r.key_id().to_string()).collect(),
            packages: vec!["*".into()],
        }],
        quorum: Quorum {
            root: 2,
            release: 2,
            operator_prod: 2,
            operator_lab: 1,
        },
        roots: k.roots.iter().map(tk).collect(),
        release_keys: k.rel.iter().map(tk).collect(),
        depot_keys: vec![tk(&k.depot)],
        operator_keys: k.ops.iter().map(tk).collect(),
        rings: vec![
            RingAssignment {
                ring: "lab".into(),
                units: vec!["bench-01".into()],
            },
            RingAssignment {
                ring: "ring-1".into(),
                units: vec!["ugv-07".into(), "ugv-08".into()],
            },
        ],
        revoked_keys: vec![],
        revoked_rpks: vec![],
        revoked_serials: vec![],
        floors: vec![],
        entry_keys: vec![],
        depot_wrap_keys: vec![],
        ek_ca_certs: vec![],
    }
}

/// Write `t` to `path` (+ `.sig`) signed by roots 1 and 2.
pub fn write_trust(path: &Path, t: &TrustFile, k: &Keys) {
    let doc = to_canonical(t).unwrap();
    std::fs::write(path, &doc).unwrap();
    let mut s = SignatureSet::empty();
    for r in &k.roots[..2] {
        s.add(r, TRUST_SIG_DOMAIN, &doc).unwrap();
    }
    std::fs::write(ops::sig_path(path), s.to_bytes().unwrap()).unwrap();
}

pub fn verified(t: &TrustFile, k: &Keys) -> VerifiedTrust {
    let doc = to_canonical(t).unwrap();
    let mut s = SignatureSet::empty();
    for r in &k.roots[..2] {
        s.add(r, TRUST_SIG_DOMAIN, &doc).unwrap();
    }
    robodr_pkg::trust::verify_trust_pinned(&doc, &s.to_bytes().unwrap(), &pins(k), &t.site, NOW)
        .unwrap()
}

pub fn spec(name: &str, serial: u64, kind: Kind) -> RpkSpec {
    RpkSpec {
        format: SPEC_FORMAT.into(),
        name: name.into(),
        version: Version {
            serial,
            display: format!("1.{serial}.0"),
        },
        kind,
        platform: "ugv-x1".into(),
        arch: Arch::Arm64,
        hw_compat: vec![],
        requires: vec![],
        conflicts: vec![],
        security_floor: 1,
        install: Install {
            allow_maintainer_scripts: false,
            requires_operator_present: false,
        },
        health: vec![],
        expires_at: None,
        sbom_path: None,
    }
}

/// A minimal CycloneDX SBOM (for `deb`).
pub const SBOM: &[u8] =
    br#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}"#;

/// Build `s` from `files` under `work/rpks` and sign it with release keys
/// `rel[0]` and `rel[1]` (the programme's quorum).
pub fn signed_rpk(
    work: &Path,
    s: &RpkSpec,
    files: &[(&str, &[u8])],
    k: &Keys,
    t: &VerifiedTrust,
) -> PathBuf {
    let pl = work.join(format!("payload-{}-{}", s.name, s.version.serial));
    let _ = std::fs::remove_dir_all(&pl);
    std::fs::create_dir_all(&pl).unwrap();
    for (p, b) in files {
        let f = pl.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b).unwrap();
        let mode = if p.ends_with(".sh") { 0o755 } else { 0o644 };
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
    }
    let out = work.join("rpks");
    std::fs::create_dir_all(&out).unwrap();
    let _ = std::fs::remove_dir_all(out.join(robodr_pkg::rpk::dir_name(
        &s.name,
        s.version.serial,
        s.arch,
    )));
    let built = ops::build_rpk(s, &pl, &out).unwrap();
    for r in &k.rel[..2] {
        ops::sign(&Target::Rpk(built.dir.clone()), r, Some(t), NOW).unwrap();
    }
    built.dir
}

/// The digest of a built RPK.
pub fn digest(rpk: &Path) -> String {
    robodr_pkg::rpk::rpk_digest(&std::fs::read(rpk.join("MANIFEST.json")).unwrap())
}

/// Assemble and sign (release quorum) bundle `seq` of the programme.
pub fn signed_bundle(
    work: &Path,
    t: &VerifiedTrust,
    seq: u64,
    prev: Option<String>,
    rpks: &[PathBuf],
    k: &Keys,
) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let out = work.join(format!("bundle-{seq}-{}", N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&out);
    ops::build_bundle(&BundleOptions {
        programme: PROGRAMME.into(),
        seq,
        prev_hash: prev,
        created_at: NOW,
        rpks: rpks.to_vec(),
        trust: t,
        now: NOW,
        parity: None,
        out: out.clone(),
    })
    .unwrap();
    for r in &k.rel[..2] {
        ops::sign(&Target::Bundle(out.clone()), r, Some(t), NOW).unwrap();
    }
    out
}

/// `bundle_hash` of a bundle directory (the next bundle's prev).
pub fn bundle_hash(dir: &Path) -> String {
    robodr_pkg::bundle::bundle_hash(&std::fs::read(dir.join("bundle.json")).unwrap())
}

/// A deployment of `items` (`(rpk dir)`) to `units` in `ring`.
pub fn deployment(seq: u64, ring: &str, units: &[&str], rpks: &[PathBuf]) -> Deployment {
    let mut items: Vec<Item> = rpks
        .iter()
        .map(|d| {
            let m =
                robodr_pkg::rpk::parse_manifest(&std::fs::read(d.join("MANIFEST.json")).unwrap())
                    .unwrap();
            Item {
                rpk_digest: digest(d),
                name: m.name,
                serial: m.version.serial,
            }
        })
        .collect();
    items.sort_by(|a, b| a.name.cmp(&b.name));
    let mut units: Vec<String> = units.iter().map(|u| u.to_string()).collect();
    units.sort();
    Deployment {
        format: DEPLOYMENT_FORMAT.into(),
        deployment_id: format!("dep-{seq:04}"),
        site: SITE.into(),
        deployment_seq: seq,
        created_at: NOW - 60,
        targets: Targets {
            units,
            groups: vec![],
        },
        ring: ring.into(),
        items,
        not_before: NOW - 60,
        expires_at: NOW + 30 * 86400,
        rollout: Rollout {
            batch_size: 1,
            soak_s: 600,
            max_failures: 0,
        },
        maintenance_window: None,
        wrapped_keys: vec![],
    }
}

/// Signatures of a deployment: depot + the first two operators.
pub fn depot_and_ops(k: &Keys) -> Vec<&Ed25519SigningKey> {
    vec![&k.depot, &k.ops[0], &k.ops[1]]
}

/// A media pack `media/<name>` with `trust` (path of the trust file, its
/// `.sig` next to it), the deployment signed by `by` and the bundles.
pub fn pack(
    media: &Path,
    name: &str,
    trust: &Path,
    d: &Deployment,
    by: &[&Ed25519SigningKey],
    bundles: &[PathBuf],
) -> PathBuf {
    let p = media.join(name);
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("bundles")).unwrap();
    std::fs::copy(trust, p.join("trust.json")).unwrap();
    std::fs::copy(ops::sig_path(trust), p.join("trust.json.sig")).unwrap();
    let doc = to_canonical(d).unwrap();
    std::fs::write(p.join("deployment.json"), &doc).unwrap();
    let mut s = SignatureSet::empty();
    for k in by {
        s.add(*k, DEPLOYMENT_SIG_DOMAIN, &doc).unwrap();
    }
    std::fs::write(p.join("deployment.json.sig"), s.to_bytes().unwrap()).unwrap();
    for (i, b) in bundles.iter().enumerate() {
        copy_tree(b, &p.join("bundles").join(format!("b{i}")));
    }
    p
}

pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let t = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), &t).unwrap();
        }
    }
}

/// One unit under test.
pub struct Unit {
    pub tmp: Tmp,
    pub keys: Keys,
    pub trust: VerifiedTrust,
    pub trust_path: PathBuf,
    pub cfg: Config,
    pub clock: FixedClock,
    pub work: PathBuf,
}

impl Unit {
    /// A unit with `ugv-07`'s configuration, its trust anchor created, and
    /// agentd's status saying `idle`.
    pub fn new(tag: &str) -> Self {
        Self::with(tag, |_| {})
    }

    /// As [`Unit::new`], editing the configuration JSON first.
    pub fn with(tag: &str, edit: impl FnOnce(&mut serde_json::Value)) -> Self {
        Self::with_status(tag, edit, true)
    }

    /// As [`Unit::with`]; `fake_status` writes the fake agentd status
    /// (off when a real agentd writes it).
    pub fn with_status(
        tag: &str,
        edit: impl FnOnce(&mut serde_json::Value),
        fake_status: bool,
    ) -> Self {
        let tmp = Tmp::new(tag);
        let d = tmp.path().to_path_buf();
        let k = keys();
        let tf = trust_file(&k);
        let trust_path = d.join("site-trust.json");
        write_trust(&trust_path, &tf, &k);
        let trust = verified(&tf, &k);
        for s in [
            "state",
            "media",
            "files",
            "etc",
            "rules-active",
            "blackbox",
            "spool/ready",
            "spool/acked",
            "work",
        ] {
            std::fs::create_dir_all(d.join(s)).unwrap();
        }
        KeyFile::ed25519_from_seed(&[77; 32], Some("unit-bb"))
            .unwrap()
            .write_new(&d.join("bb.key"))
            .unwrap();
        std::fs::write(d.join("boot_id"), format!("{BOOT}\n")).unwrap();
        // Probe user: nobody (65534) when root, else this process's user.
        // agentd (`safety.agentd_user`, whose uid besides root's the status
        // file must be owned by): this process's user when not root, since
        // the test writes agentd-status.json itself; when root the file is
        // root's (always trusted) and agentd gets an unrelated uid. Without
        // the line, `safety.passwd` would be the host's /etc/passwd, which
        // has no robodr-agentd: as a non-root user every status read was
        // untrusted (safety_state:unknown).
        let (uid, gid, agentd) = if robodr_deliverd::users::is_root() {
            (65_534, 65_534, 65_533)
        } else {
            let u = robodr_deliverd::users::effective_uid().unwrap();
            (u, u, u)
        };
        std::fs::write(
            d.join("passwd"),
            format!(
                "root:x:0:0:root:/root:/bin/sh\nprobe:x:{uid}:{gid}::/nonexistent:/usr/sbin/nologin\n\
                 robodr-agentd:x:{agentd}:{agentd}::/nonexistent:/usr/sbin/nologin\n"
            ),
        )
        .unwrap();
        let mut v = serde_json::json!({
            "format": "robodr-deliverd-config/1",
            "unit": {"id": UNIT, "site": SITE, "model": "ugv-x1", "platform": "ugv-x1", "arch": "arm64"},
            "trust": {"roots": pins(&k), "clock": "trusted"},
            "state_dir": d.join("state"),
            "media_dir": d.join("media"),
            "install": {
                "files_root": d.join("files"),
                "config_root": d.join("etc"),
                "rules_active": d.join("rules-active"),
                "dpkg_root": d.join("dpkg-root")
            },
            "health": {"passwd": d.join("passwd"), "probe_uid_min": 1, "probe_uid_max": 65534,
                       "systemctl": "/bin/true"},
            "safety": {"agentd_status": d.join("agentd-status.json"), "boot_id": d.join("boot_id"),
                       "passwd": d.join("passwd")},
            "blackbox": {"dir": d.join("blackbox"), "key": d.join("bb.key")},
            "findings": {"spool": d.join("spool")},
            "interval_ms": 100
        });
        edit(&mut v);
        let cfg = Config::parse(&serde_json::to_vec(&v).unwrap()).unwrap();
        robodr_release::ops::init_anchor(
            &trust_path,
            &cfg.anchor_path(),
            &cfg.trust.roots,
            SITE,
            NOW,
        )
        .unwrap();
        let u = Unit {
            work: d.join("work"),
            tmp,
            keys: k,
            trust,
            trust_path,
            cfg,
            clock: FixedClock::new(NOW),
        };
        if fake_status {
            u.safety("idle");
        }
        u
    }

    pub fn dir(&self) -> &Path {
        self.tmp.path()
    }

    /// agentd's status claiming `state`, fresh now.
    pub fn safety(&self, state: &str) {
        let v = serde_json::json!({
            "safety_state": state,
            "safety_feed": {"state": state, "sources": [], "stats": {}},
            "kind": "robodr.agentd_status",
            "robot_id": UNIT,
            "updated_mono_ms": robodr_agentd::notify::monotonic_ms(),
            "boot_id": BOOT,
            "stale_after_ms": 600_000,
            "running": true,
            "state": "ok"
        });
        let p = self.cfg.safety.agentd_status.clone();
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&v).unwrap()).unwrap();
        std::fs::rename(&tmp, &p).unwrap();
    }

    pub fn open(&self) -> Engine {
        Engine::open(self.cfg.clone(), Box::new(self.clock.clone())).unwrap()
    }

    /// Build and sign an RPK.
    pub fn rpk(&self, s: &RpkSpec, files: &[(&str, &[u8])]) -> PathBuf {
        signed_rpk(&self.work, s, files, &self.keys, &self.trust)
    }

    pub fn bundle(&self, seq: u64, prev: Option<String>, rpks: &[PathBuf]) -> PathBuf {
        signed_bundle(&self.work, &self.trust, seq, prev, rpks, &self.keys)
    }

    /// A pack for this unit (ring-1, depot + 2 operators).
    pub fn pack(&self, name: &str, seq: u64, rpks: &[PathBuf], bundles: &[PathBuf]) -> PathBuf {
        let d = deployment(seq, "ring-1", &[UNIT], rpks);
        pack(
            &self.cfg.media_dir,
            name,
            &self.trust_path,
            &d,
            &depot_and_ops(&self.keys),
            bundles,
        )
    }

    /// Tick until nothing changes (at most `n` ticks); the reports.
    pub fn run(&self, e: &mut Engine, n: usize) -> Vec<TickReport> {
        let mut out = Vec::new();
        for _ in 0..n {
            let r = e.tick().unwrap();
            let idle = r == TickReport::default();
            out.push(r);
            if idle {
                break;
            }
        }
        out
    }

    /// The `current` link target serial of a files package (the link
    /// names `<serial>-<digest>`; this is the serial).
    pub fn current(&self, root: &Path, name: &str) -> Option<String> {
        std::fs::read_link(root.join(name).join("current"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .map(|t| t.split('-').next().unwrap_or_default().to_string())
    }

    /// The version directories of `name` under `root` for `serial`
    /// (`<serial>-<digest>`; review M4: one per content).
    pub fn version_dirs(&self, root: &Path, name: &str, serial: u64) -> Vec<PathBuf> {
        let Ok(rd) = std::fs::read_dir(root.join(name)) else {
            return Vec::new();
        };
        let mut v: Vec<PathBuf> = rd
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{serial}-"))
            })
            .map(|e| e.path())
            .collect();
        v.sort();
        v
    }

    /// The single version directory of `name` / `serial` under `root`.
    pub fn version_dir(&self, root: &Path, name: &str, serial: u64) -> PathBuf {
        let v = self.version_dirs(root, name, serial);
        assert_eq!(v.len(), 1, "version directories of {name} {serial}: {v:?}");
        v[0].clone()
    }

    /// Black-box notes (payload JSON) of the delivery journal.
    pub fn notes(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        for seg in robodr_blackbox::verify::read_segments(&self.cfg.blackbox.dir).unwrap() {
            for it in robodr_blackbox::record::scan_frames(&seg.bytes).items {
                if let robodr_blackbox::record::ScanItem::Record(r) = it {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&r.record.payload) {
                        if v.get("kind").is_some() {
                            out.push(v);
                        }
                    }
                }
            }
        }
        out
    }

    pub fn notes_of(&self, kind: &str) -> Vec<serde_json::Value> {
        self.notes()
            .into_iter()
            .filter(|n| n["kind"] == kind)
            .collect()
    }

    /// Findings in the spool: (rule id, severity, full value).
    pub fn findings(&self) -> Vec<(String, String, serde_json::Value)> {
        let mut out = Vec::new();
        let mut files: Vec<PathBuf> = std::fs::read_dir(self.dir().join("spool/ready"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        for f in files {
            let r: robodr_agentd::spool::SpoolRecord =
                serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
            assert_eq!(
                f.file_name().unwrap().to_string_lossy(),
                format!("{:020}.json", r.seq)
            );
            let v = robodr_ocsf::parse_and_validate(&r.value).unwrap_or_else(|e| panic!("{e:?}"));
            let v: serde_json::Value = serde_json::to_value(&v).unwrap();
            let rule = v["entity_context"]["rule_id"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let sev = v["severity"].as_str().unwrap_or("").to_string();
            out.push((rule, sev, v));
        }
        out
    }

    pub fn rules_found(&self) -> Vec<String> {
        self.findings().into_iter().map(|f| f.0).collect()
    }

    /// The black box verifies with the unit's public key.
    pub fn black_box_verifies(&self) -> bool {
        let k = KeyFile::ed25519_from_seed(&[77; 32], Some("unit-bb")).unwrap();
        let v = k.verifier().unwrap();
        robodr_blackbox::verify::verify_dir(&self.cfg.blackbox.dir, v.as_ref(), &Default::default())
            .map(|r| r.is_intact())
            .unwrap_or(false)
    }
}

/// A files RPK whose health check is the file `ok` in its own install.
pub fn files_spec(u: &Unit, name: &str, serial: u64, healthy: bool) -> RpkSpec {
    let mut s = spec(name, serial, Kind::Files);
    let probe = if healthy { "ok" } else { "missing" };
    s.health = vec![HealthCheck::FilePresent {
        path: format!(
            "{}/{name}/current/{probe}",
            u.cfg.install.files_root.display()
        ),
    }];
    s
}

/// A maintenance window that never matches NOW (Monday 14:13 UTC).
pub fn closed_window() -> MaintenanceWindow {
    MaintenanceWindow {
        days: vec![robodr_pkg::deployment::Weekday::Sun],
        start_minute: 0,
        duration_minutes: 60,
    }
}

/// A trust file with `floors`.
pub fn with_floor(mut t: TrustFile, name: &str, f: u64) -> TrustFile {
    t.floors.push(Floor {
        name: name.into(),
        min_serial: f,
    });
    t
}

/// Re-list the files of a bundle directory in its `bundle.json` (sizes,
/// hashes, RPK digests) and re-sign it with release keys 1 and 2 directly:
/// what an attacker holding the release quorum can produce without the
/// release tool's checks.
pub fn relist_and_resign(dir: &Path, k: &Keys) {
    use robodr_pkg::bundle::{parse_bundle, BUNDLE_SIG_DOMAIN};
    let mut m = parse_bundle(&std::fs::read(dir.join("bundle.json")).unwrap()).unwrap();
    for f in m.files.iter_mut() {
        let b = std::fs::read(dir.join(&f.path)).unwrap();
        f.size = b.len() as u64;
        f.sha256 = robodr_pkg::common::sha256_hex(&b);
    }
    for r in m.rpks.iter_mut() {
        r.digest = digest(&dir.join(&r.dir));
    }
    let doc = to_canonical(&m).unwrap();
    std::fs::write(dir.join("bundle.json"), &doc).unwrap();
    let mut s = SignatureSet::empty();
    for r in &k.rel[..2] {
        s.add(r, BUNDLE_SIG_DOMAIN, &doc).unwrap();
    }
    std::fs::write(dir.join("bundle.sig"), s.to_bytes().unwrap()).unwrap();
}

/// Rewrite an RPK's MANIFEST.json with `edit` (canonical bytes) and
/// re-sign it with release keys 1 and 2 directly.
pub fn tamper_manifest(rpk: &Path, k: &Keys, edit: impl FnOnce(&mut robodr_pkg::rpk::Manifest)) {
    use robodr_pkg::rpk::{parse_manifest, MANIFEST_SIG_DOMAIN};
    let mut m = parse_manifest(&std::fs::read(rpk.join("MANIFEST.json")).unwrap()).unwrap();
    edit(&mut m);
    let doc = to_canonical(&m).unwrap();
    std::fs::write(rpk.join("MANIFEST.json"), &doc).unwrap();
    let mut s = SignatureSet::empty();
    for r in &k.rel[..2] {
        s.add(r, MANIFEST_SIG_DOMAIN, &doc).unwrap();
    }
    std::fs::write(rpk.join("MANIFEST.sig"), s.to_bytes().unwrap()).unwrap();
}

/// The single RPK directory inside a bundle directory.
pub fn rpk_in(bundle: &Path) -> PathBuf {
    std::fs::read_dir(bundle)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("rpk_"))
        .unwrap()
}

/// Install `name` serial 1 (healthy files RPK) through pack `p1`; returns
/// the engine and bundle 1.
pub fn installed_v1(u: &Unit, name: &str) -> (Engine, PathBuf) {
    let r = u.rpk(&files_spec(u, name, 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], std::slice::from_ref(&b));
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
    (e, b)
}

// ------------------------------------------------- dpkg and M1 helpers --
// (shared by review_13b.rs and review2_13b.rs)

pub fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

pub fn dpkg_ok(test: &str) -> bool {
    let ok = robodr_deliverd::users::is_root() && have("dpkg") && have("dpkg-deb");
    if !ok {
        if std::env::var("ROBODR_REQUIRE_DPKG_TEST").is_ok_and(|v| v == "1") {
            panic!("{test}: needs root and dpkg (ROBODR_REQUIRE_DPKG_TEST=1)");
        }
        eprintln!("SKIPPED {test}: needs root and dpkg");
    }
    ok
}

pub fn dpkg_root(u: &Unit) -> PathBuf {
    let root = u.cfg.install.dpkg_root.clone().unwrap();
    for d in [
        "var/lib/dpkg/info",
        "var/lib/dpkg/updates",
        "var/lib/dpkg/triggers",
    ] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("var/lib/dpkg/status"), "").unwrap();
    std::fs::write(root.join("var/lib/dpkg/available"), "").unwrap();
    root
}

/// A stub `.deb` of dpkg package `package` (`usr/lib/<package>/ok`).
pub fn deb_of(u: &Unit, package: &str, version: &str, arch: &str, extra: &str) -> Vec<u8> {
    let ok = format!("usr/lib/{package}/ok");
    deb_with(u, package, version, arch, extra, &[(ok.as_str(), version)])
}

/// A stub `.deb` of dpkg package `package` with `extra` control lines and
/// the files `files` (relative path, content).
pub fn deb_with(
    u: &Unit,
    package: &str,
    version: &str,
    arch: &str,
    extra: &str,
    files: &[(&str, &str)],
) -> Vec<u8> {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let st = u.work.join(format!("st-{package}-{version}-{arch}-{n}"));
    let _ = std::fs::remove_dir_all(&st);
    std::fs::create_dir_all(st.join("DEBIAN")).unwrap();
    std::fs::write(
        st.join("DEBIAN/control"),
        format!(
            "Package: {package}\nVersion: {version}\nArchitecture: {arch}\n{extra}\
             Maintainer: RoboDR tests <tests@invalid>\nDescription: stub\n"
        ),
    )
    .unwrap();
    for (rel, body) in files {
        let p = st.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    let out = u.work.join(format!("{package}_{version}_{arch}-{n}.deb"));
    let o = Command::new("dpkg-deb")
        .args(["--root-owner-group", "-Zxz", "--build"])
        .arg(&st)
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    std::fs::read(&out).unwrap()
}

pub fn deb_spec(
    u: &Unit,
    name: &str,
    serial: u64,
    floor: u64,
    checks: &str,
) -> robodr_release::ops::RpkSpec {
    let mut s = spec(name, serial, Kind::Deb);
    s.sbom_path = Some("sbom.cdx.json".into());
    s.security_floor = floor;
    s.health = vec![HealthCheck::FilePresent {
        path: format!(
            "{}/usr/lib/{checks}/ok",
            u.cfg.install.dpkg_root.as_ref().unwrap().display()
        ),
    }];
    s
}

pub fn dpkg_version(u: &Unit, package: &str) -> String {
    let o = Command::new("dpkg-query")
        .arg(format!(
            "--admindir={}",
            u.cfg
                .install
                .dpkg_root
                .as_ref()
                .unwrap()
                .join("var/lib/dpkg")
                .display()
        ))
        .args(["-W", "-f", "${Version}", package])
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Fill the delivery journal past its cyclic retention (16 x 1 MiB).
pub fn flood_journal(u: &Unit) {
    let mut j =
        robodr_deliverd::journal::Journal::open(&u.cfg.blackbox.dir, UNIT, &u.cfg.blackbox.key)
            .unwrap();
    let pad = "x".repeat(60_000);
    for i in 0..300 {
        j.note("robodr.test.flood", serde_json::json!({"i": i, "pad": pad}))
            .unwrap();
    }
    j.close().unwrap();
    assert!(
        robodr_deliverd::journal::Journal::recorded_floors(
            &u.cfg.blackbox.dir,
            robodr_blackbox::KeyFile::load_secret(&u.cfg.blackbox.key)
                .unwrap()
                .signer()
                .unwrap()
                .as_ref()
        )
        .is_empty(),
        "the flood did not evict the floor notes"
    );
}

pub fn remove_named(dir: &Path, prefix: &str) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if e.file_type().unwrap().is_dir() {
            remove_named(&p, prefix);
        } else if e.file_name().to_string_lossy().starts_with(prefix) {
            std::fs::remove_file(&p).unwrap();
        }
    }
}

pub fn installed_v5_floor_5(u: &Unit) -> (robodr_deliverd::Engine, PathBuf) {
    let mut s = files_spec(u, "nav-stack", 5, true);
    s.security_floor = 5;
    let r5 = u.rpk(&s, &[("ok", b"v5")]);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r5));
    u.pack("p1", 1, &[r5], std::slice::from_ref(&b1));
    let mut e = u.open();
    u.run(&mut e, 4);
    assert_eq!(e.state().floor("nav-stack"), 5);
    (e, b1)
}
