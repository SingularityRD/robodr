//! A site for the depot tests: keys of every role, an EK CA (swtpm's
//! local CA), the trust file, a depot, units with software TPMs
//! (manufactured with EK certificates) and a delivery agent each.
//!
//! Everything lives in a fresh temporary directory (removed on drop;
//! `ROBODR_KEEP_TMP=1` keeps it). TPM tests need `ROBODR_SWTPM=1`.
#![allow(dead_code)]

#[path = "../../../robodr-seal/tests/common/mod.rs"]
pub mod seal;

use robodr_blackbox::{Ed25519SigningKey, KeyFile, Signer};
use robodr_depot::config::Config as DepotConfig;
use robodr_depot::depot::Depot;
use robodr_pkg::common::{fingerprint, sha256_hex, to_canonical};
use robodr_pkg::rpk::{Arch, HealthCheck, Install, Kind, Version};
use robodr_pkg::sig::SignatureSet;
use robodr_pkg::trust::{
    Programme, Quorum, RingAssignment, TrustFile, TrustKey, VerifiedTrust, WrapKey, TRUST_FORMAT,
    TRUST_SIG_DOMAIN, X25519,
};
use robodr_release::ops::{self, BundleOptions, RpkSpec, Target, SPEC_FORMAT};
use robodr_seal::keys::PolicyKey;
use robodr_seal::wrap::X25519Secret;
use seal::SwTpm;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const SITE: &str = "site-a";
pub const PROGRAMME: &str = "ugv-x1";
pub const PLATFORM: &str = "ugv-x1";
pub const PCRS: [u8; 2] = [0, 7];

pub fn now() -> u64 {
    robodr_depot::now().unwrap()
}

pub fn swtpm_enabled(t: &str) -> bool {
    seal::swtpm_enabled(t)
}

/// A temp directory removed on drop.
pub struct Tmp(pub PathBuf);

impl Tmp {
    pub fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "robodr-depot-it-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        if std::env::var("ROBODR_KEEP_TMP").as_deref() != Ok("1") {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

pub fn key(id: &str, seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(id, &[seed; 32]).unwrap()
}

pub fn tk(k: &Ed25519SigningKey) -> TrustKey {
    TrustKey::new(k.key_id(), &k.public_key())
}

/// swtpm's local CA, in `dir` (created at the first manufacture).
pub struct EkCa {
    pub dir: PathBuf,
    pub setup_conf: PathBuf,
}

impl EkCa {
    pub fn new(dir: &Path) -> Self {
        std::fs::create_dir_all(dir.join("ca")).unwrap();
        let localca = dir.join("localca.conf");
        std::fs::write(
            &localca,
            format!(
                "statedir = {d}/ca\nsigningkey = {d}/ca/signkey.pem\nissuercert = {d}/ca/issuercert.pem\ncertserial = {d}/ca/certserial\n",
                d = dir.display()
            ),
        )
        .unwrap();
        let setup_conf = dir.join("setup.conf");
        std::fs::write(
            &setup_conf,
            format!(
                "create_certs_tool= /usr/bin/swtpm_localca\ncreate_certs_tool_config = {}\ncreate_certs_tool_options = /etc/swtpm-localca.options\nactive_pcr_banks = sha256\n",
                localca.display()
            ),
        )
        .unwrap();
        Self {
            dir: dir.to_path_buf(),
            setup_conf,
        }
    }

    /// Manufacture a TPM state with an RSA EK certificate from this CA.
    pub fn manufacture(&self, state: &Path) {
        std::fs::create_dir_all(state).unwrap();
        let o = Command::new("swtpm_setup")
            .args(["--tpm2", "--create-ek-cert", "--overwrite", "--tpmstate"])
            .arg(state)
            .arg("--config")
            .arg(&self.setup_conf)
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "swtpm_setup: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }

    pub fn root_pem(&self) -> PathBuf {
        self.dir.join("ca/swtpm-localca-rootca-cert.pem")
    }

    pub fn issuer_pem(&self) -> PathBuf {
        self.dir.join("ca/issuercert.pem")
    }

    /// SHA-256 of the root CA certificate's DER.
    pub fn root_digest(&self) -> String {
        let b = std::fs::read(self.root_pem()).unwrap();
        let der = robodr_depot::x509::certs_of(&b).unwrap();
        sha256_hex(&der[0])
    }
}

/// Every key of the site.
pub struct Site {
    pub tmp: Tmp,
    pub roots: Vec<Ed25519SigningKey>,
    pub rel: Vec<Ed25519SigningKey>,
    pub depot: Ed25519SigningKey,
    pub ops: Vec<Ed25519SigningKey>,
    pub entry: Ed25519SigningKey,
    pub wrap: X25519Secret,
    pub authority: PolicyKey,
    pub lease: PolicyKey,
    pub ca: EkCa,
    pub rogue_ca: EkCa,
    pub trust: Option<TrustFile>,
    pub trust_path: PathBuf,
    pub hw: PathBuf,
}

impl Site {
    pub fn new(tag: &str) -> Self {
        let tmp = Tmp::new(tag);
        let d = tmp.0.clone();
        std::fs::create_dir_all(d.join("keys")).unwrap();
        std::fs::create_dir_all(d.join("hw")).unwrap();
        let wrap = X25519Secret::generate().unwrap();
        robodr_seal::keys::x25519_write(&d.join("keys/wrap.key"), &wrap).unwrap();
        let authority = robodr_seal::keys::policy_generate(
            &d.join("keys/authority.key"),
            &d.join("keys/authority.pub"),
        )
        .unwrap();
        let lease = robodr_seal::keys::policy_generate(
            &d.join("keys/lease.key"),
            &d.join("keys/lease.pub"),
        )
        .unwrap();
        robodr_seal::keys::policy_generate(&d.join("keys/ca.key"), &d.join("keys/ca.pub")).unwrap();
        let depot = key("depot-1", 21);
        KeyFile::ed25519_from_seed(&[21; 32], Some("depot-1"))
            .unwrap()
            .write_new(&d.join("keys/depot.key"))
            .unwrap();
        let ops: Vec<Ed25519SigningKey> =
            (1..=3).map(|i| key(&format!("op-{i}"), 30 + i)).collect();
        for i in 1..=3u8 {
            KeyFile::ed25519_from_seed(&[30 + i; 32], Some(&format!("op-{i}")))
                .unwrap()
                .write_new(&d.join(format!("keys/op-{i}.key")))
                .unwrap();
        }
        KeyFile::ed25519_from_seed(&[41; 32], Some("entry-1"))
            .unwrap()
            .write_new(&d.join("keys/entry.key"))
            .unwrap();
        Self {
            roots: (1..=3).map(|i| key(&format!("root-{i}"), i)).collect(),
            rel: ["rel-a", "rel-b"]
                .iter()
                .zip(11..)
                .map(|(n, s)| key(n, s))
                .collect(),
            depot,
            ops,
            entry: key("entry-1", 41),
            wrap,
            authority,
            lease,
            ca: EkCa::new(&d.join("ekca")),
            rogue_ca: EkCa::new(&d.join("rogue-ekca")),
            trust: None,
            trust_path: d.join("trust.json"),
            hw: d.join("hw"),
            tmp,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.tmp.0
    }

    pub fn pins(&self) -> Vec<String> {
        self.roots
            .iter()
            .map(|r| fingerprint(&r.public_key()))
            .collect()
    }

    /// The trust file: lab bench-01, canary ugv-08, ring-1 ugv-07 and
    /// ugv-09; the entry key, the depot wrap key and the EK CA.
    pub fn write_trust(&mut self, rings: &[(&str, &[&str])]) {
        let now = now();
        let mut rings: Vec<RingAssignment> = rings
            .iter()
            .map(|(r, us)| RingAssignment {
                ring: r.to_string(),
                units: {
                    let mut v: Vec<String> = us.iter().map(|u| u.to_string()).collect();
                    v.sort();
                    v
                },
            })
            .collect();
        rings.sort_by(|a, b| a.ring.cmp(&b.ring));
        let t = TrustFile {
            format: TRUST_FORMAT.into(),
            site: SITE.into(),
            version: 1,
            issued_at: now - 3600,
            expires_at: now + 90 * 86400,
            programmes: vec![Programme {
                name: PROGRAMME.into(),
                release_keys: self.rel.iter().map(|r| r.key_id().to_string()).collect(),
                packages: vec!["*".into()],
            }],
            quorum: Quorum {
                root: 2,
                release: 2,
                operator_prod: 2,
                operator_lab: 1,
            },
            roots: self.roots.iter().map(tk).collect(),
            release_keys: self.rel.iter().map(tk).collect(),
            depot_keys: vec![tk(&self.depot)],
            operator_keys: self.ops.iter().map(tk).collect(),
            rings,
            revoked_keys: vec![],
            revoked_rpks: vec![],
            revoked_serials: vec![],
            floors: vec![],
            entry_keys: vec![tk(&self.entry)],
            depot_wrap_keys: vec![WrapKey {
                key_id: "depot-1-wrap".into(),
                algorithm: X25519.into(),
                public_hex: robodr_seal::to_hex(&self.wrap.public()),
            }],
            ek_ca_certs: vec![self.ca.root_digest()],
        };
        let doc = to_canonical(&t).unwrap();
        std::fs::write(&self.trust_path, &doc).unwrap();
        let mut s = SignatureSet::empty();
        for r in &self.roots[..2] {
            s.add(r, TRUST_SIG_DOMAIN, &doc).unwrap();
        }
        std::fs::write(ops::sig_path(&self.trust_path), s.to_bytes().unwrap()).unwrap();
        self.trust = Some(t);
    }

    pub fn verified(&self) -> VerifiedTrust {
        let (doc, sig) = ops::read_trust_files(&self.trust_path).unwrap();
        robodr_pkg::trust::verify_trust_pinned(&doc, &sig, &self.pins(), SITE, now()).unwrap()
    }

    pub fn site_trust(&self) -> ops::SiteTrust {
        ops::SiteTrust::unanchored(&self.trust_path, &self.pins(), SITE, now()).unwrap()
    }

    /// The depot's configuration (serving on 127.0.0.1; `lease`: issue
    /// leases; `anchor`: the TCTI of the depot's own TPM).
    pub fn depot_config(&self, lease: bool, anchor: Option<String>) -> DepotConfig {
        let d = self.dir();
        std::fs::create_dir_all(d.join("ek-cas")).unwrap();
        std::fs::create_dir_all(d.join("ek-int")).unwrap();
        let _ = std::fs::copy(self.ca.root_pem(), d.join("ek-cas/root.pem"));
        let _ = std::fs::copy(self.rogue_ca.root_pem(), d.join("ek-cas/rogue-root.pem"));
        let _ = std::fs::copy(self.ca.issuer_pem(), d.join("ek-int/issuer.pem"));
        let _ = std::fs::copy(
            self.rogue_ca.issuer_pem(),
            d.join("ek-int/rogue-issuer.pem"),
        );
        let mut v = serde_json::json!({
            "format": "robodr-depot-config/1",
            "site": SITE,
            "depot_id": "depot-1",
            "roots": self.pins(),
            "state_dir": d.join("depot"),
            "keys": {
                "signing": d.join("keys/depot.key"),
                "wrap": d.join("keys/wrap.key"),
                "ca": d.join("keys/ca.key")
            },
            "enrolment": {
                "policy_authority": d.join("keys/authority.pub"),
                "ek_cas": d.join("ek-cas"),
                "ek_intermediates": d.join("ek-int")
            },
            "serve": {"listen": "127.0.0.1:0", "server_name": "depot.site-a", "deadline_s": 60},
            "findings": {"spool": d.join("depot-spool")}
        });
        std::fs::create_dir_all(d.join("depot-spool/ready")).unwrap();
        std::fs::create_dir_all(d.join("depot-spool/acked")).unwrap();
        if lease {
            v["keys"]["lease"] = d.join("keys/lease.key").to_string_lossy().into();
            v["lease"] = serde_json::json!({"lifetime_s": 3600, "reboots": 4});
        }
        if let Some(t) = anchor {
            v["anchor"] = serde_json::json!({"tcti": t, "index": "0x01500050",
                "work_dir": format!("/dev/shm/robodr-depot-it-{}", std::process::id())});
        }
        DepotConfig::parse(&serde_json::to_vec(&v).unwrap()).unwrap()
    }

    pub fn op_key_path(&self, i: usize) -> PathBuf {
        self.dir().join(format!("keys/op-{}.key", i + 1))
    }

    /// A files RPK `name` serial `serial` whose health check is the file
    /// `hw/<name>-ok` of the site directory (removing it makes the release
    /// fail its health gate wherever it is installed next).
    pub fn files_rpk(&self, name: &str, serial: u64) -> PathBuf {
        let mut s = spec(name, serial, Kind::Files);
        s.health = vec![HealthCheck::FilePresent {
            path: self.hw.join(format!("{name}-ok")).display().to_string(),
        }];
        self.build(
            &s,
            &[("bin/app", format!("{name} v{serial}").as_bytes())],
            None,
        )
    }

    /// A sealed model RPK (wrapped to the depot's key only).
    pub fn sealed_model(&self, name: &str, serial: u64, marker: &[u8]) -> PathBuf {
        let s = spec(name, serial, Kind::Model);
        self.build(
            &s,
            &[("weights.onnx", marker), ("labels.txt", b"cat\ndog\n")],
            Some(&[self.wrap.public()]),
        )
    }

    fn build(&self, s: &RpkSpec, files: &[(&str, &[u8])], seal_to: Option<&[[u8; 32]]>) -> PathBuf {
        let work = self.dir().join("release");
        let pl = work.join(format!("payload-{}-{}", s.name, s.version.serial));
        let _ = std::fs::remove_dir_all(&pl);
        for (p, b) in files {
            let f = pl.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, b).unwrap();
            std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o644))
                .unwrap();
        }
        let out = work.join("rpks");
        std::fs::create_dir_all(&out).unwrap();
        let _ = std::fs::remove_dir_all(out.join(robodr_pkg::rpk::dir_name(
            &s.name,
            s.version.serial,
            s.arch,
        )));
        let built = ops::build_rpk_with(s, &pl, &out, seal_to).unwrap();
        let t = self.verified();
        for r in &self.rel {
            ops::sign(&Target::Rpk(built.dir.clone()), r, Some(&t), now()).unwrap();
        }
        built.dir
    }

    /// Bundle `seq` of the programme with `rpks`, release-signed.
    pub fn bundle(&self, seq: u64, prev: Option<String>, rpks: &[PathBuf]) -> PathBuf {
        let out = self.dir().join(format!("release/bundle-{seq}"));
        let _ = std::fs::remove_dir_all(&out);
        let t = self.verified();
        ops::build_bundle(&BundleOptions {
            programme: PROGRAMME.into(),
            seq,
            prev_hash: prev,
            created_at: now(),
            rpks: rpks.to_vec(),
            trust: &t,
            now: now(),
            parity: None,
            out: out.clone(),
        })
        .unwrap();
        for r in &self.rel {
            ops::sign(&Target::Bundle(out.clone()), r, Some(&t), now()).unwrap();
        }
        out
    }

    /// The entry station's signed report for `bundle` (`REPORT.json` +
    /// `.sig` in the bundle's parent).
    pub fn entry_report(&self, bundle: &Path) -> PathBuf {
        let st = self.site_trust();
        let r = robodr_depot::entry::scan(&robodr_depot::entry::ScanInput {
            bundle,
            site: &st,
            station: "entry-1",
            vulndb: None,
            history: &self.dir().join("entry-history"),
            fail_on: robodr_pkg::entry::Severity::High,
            now: now(),
            lifetime_s: 86400,
        })
        .unwrap();
        let (b, s) = robodr_depot::entry::sign(&r, &self.entry).unwrap();
        let p = bundle.with_extension("entry.json");
        std::fs::write(&p, b).unwrap();
        std::fs::write(ops::sig_path(&p), s).unwrap();
        p
    }
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
        platform: PLATFORM.into(),
        arch: Arch::All,
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

pub fn bundle_hash(dir: &Path) -> String {
    robodr_pkg::bundle::bundle_hash(&std::fs::read(dir.join("bundle.json")).unwrap())
}

pub fn digest(rpk: &Path) -> String {
    robodr_pkg::rpk::rpk_digest(&std::fs::read(rpk.join("MANIFEST.json")).unwrap())
}

/// One unit: its software TPM (manufactured with an EK certificate), its
/// seal directory (UWK, AK, identity key, signed policy) and its agent.
pub struct UnitH {
    pub id: String,
    pub dir: PathBuf,
    pub sw: SwTpm,
    pub cfg_json: serde_json::Value,
}

impl UnitH {
    /// `ca`: the EK CA that manufactures its TPM; `lease`: a lease-gated
    /// UWK bound to the site's lease key.
    pub fn new(site: &Site, id: &str, ca: &EkCa, lease: bool) -> Self {
        let dir = site.dir().join("units").join(id);
        std::fs::create_dir_all(&dir).unwrap();
        ca.manufacture(&dir.join("tpm"));
        let sw = SwTpm::start(&dir.join("tpm"));
        sw.provision();
        let lk = site.lease.public();
        robodr_seal::unit::Unit::enroll_tpm_with(
            &dir.join("seal"),
            id,
            PLATFORM,
            &site.authority.public(),
            lease.then_some(&lk),
            sw.tpm(),
        )
        .unwrap();
        let u = robodr_seal::unit::Unit::open(&dir.join("seal"), Some(sw.tpm())).unwrap();
        let p = robodr_seal::policy::sign(
            &site.authority,
            PLATFORM,
            1,
            &sw.pcrs(&PCRS),
            robodr_seal::tpm::DEFAULT_FLOOR_NV,
        )
        .unwrap();
        u.install_policy(&p).unwrap();
        for s in [
            "state",
            "media",
            "files",
            "etc",
            "rules-active",
            "blackbox",
            "spool/ready",
            "spool/acked",
            "runtime",
            "depot",
        ] {
            std::fs::create_dir_all(dir.join(s)).unwrap();
        }
        KeyFile::ed25519_from_seed(&[77; 32], Some(&format!("{id}-bb")))
            .unwrap()
            .write_new(&dir.join("bb.key"))
            .unwrap();
        std::fs::write(dir.join("boot_id"), "test-boot-0001\n").unwrap();
        std::fs::write(dir.join("passwd"), "root:x:0:0:root:/root:/bin/sh\n").unwrap();
        let cfg_json = serde_json::json!({
            "format": "robodr-deliverd-config/1",
            "unit": {"id": id, "site": SITE, "model": PLATFORM, "platform": PLATFORM, "arch": "arm64"},
            "trust": {"roots": site.pins(), "clock": "trusted"},
            "state_dir": dir.join("state"),
            "media_dir": dir.join("media"),
            "install": {"files_root": dir.join("files"), "config_root": dir.join("etc"),
                        "rules_active": dir.join("rules-active"), "dpkg_root": dir.join("dpkg-root")},
            "health": {"passwd": dir.join("passwd"), "probe_uid_min": 1, "probe_uid_max": 65534,
                       "systemctl": "/bin/true"},
            "safety": {"agentd_status": dir.join("agentd-status.json"), "boot_id": dir.join("boot_id")},
            "blackbox": {"dir": dir.join("blackbox"), "key": dir.join("bb.key")},
            "findings": {"spool": dir.join("spool")},
            "interval_ms": 100,
            "seal": {"seal_dir": dir.join("seal"), "runtime_root": dir.join("runtime"),
                     "volume_check": "unchecked",
                     "tpm": {"tcti": sw.tcti(), "work_dir": sw.work_dir()}}
        });
        let h = Self {
            id: id.into(),
            dir,
            sw,
            cfg_json,
        };
        if site.trust_path.exists() {
            h.anchor(site);
        }
        h.safety("idle");
        h
    }

    /// The unit's trust anchor from the site's trust file.
    pub fn anchor(&self, site: &Site) {
        robodr_release::ops::init_anchor(
            &site.trust_path,
            &self.cfg().anchor_path(),
            &site.pins(),
            SITE,
            now(),
        )
        .unwrap();
    }

    pub fn seal(&self) -> robodr_seal::unit::Unit {
        robodr_seal::unit::Unit::open(&self.dir.join("seal"), Some(self.sw.tpm())).unwrap()
    }

    pub fn cfg(&self) -> robodr_deliverd::Config {
        robodr_deliverd::Config::parse(&serde_json::to_vec(&self.cfg_json).unwrap()).unwrap()
    }

    /// Point the agent at the depot (after enrolment exported its files).
    pub fn connect(&mut self, port: u16) {
        self.cfg_json["depot"] = serde_json::json!({
            "address": format!("127.0.0.1:{port}"),
            "server_name": "depot.site-a",
            "ca_file": self.dir.join("depot/depot-ca.pem"),
            "cert_file": self.dir.join("depot/client.pem"),
            "deadline_s": 60
        });
    }

    pub fn open(&self) -> robodr_deliverd::Engine {
        robodr_deliverd::Engine::open(self.cfg(), Box::new(robodr_deliverd::clock::SystemClock))
            .unwrap()
    }

    /// agentd's status claiming `state`, fresh now.
    pub fn safety(&self, state: &str) {
        let v = serde_json::json!({
            "safety_state": state,
            "safety_feed": {"state": state, "sources": [], "stats": {}},
            "kind": "robodr.agentd_status",
            "robot_id": self.id,
            "updated_mono_ms": robodr_agentd::notify::monotonic_ms(),
            "boot_id": "test-boot-0001",
            "stale_after_ms": 600_000,
            "running": true,
            "state": "ok"
        });
        let p = self.dir.join("agentd-status.json");
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&v).unwrap()).unwrap();
        std::fs::rename(&tmp, &p).unwrap();
    }

    /// Tick until idle (at most `n`).
    pub fn run(
        &self,
        e: &mut robodr_deliverd::Engine,
        n: usize,
    ) -> Vec<robodr_deliverd::engine::TickReport> {
        let mut out = Vec::new();
        for _ in 0..n {
            let r = e.tick().unwrap();
            let idle = r == Default::default();
            out.push(r);
            if idle {
                break;
            }
        }
        out
    }

    /// Findings in the unit's spool: rule ids.
    pub fn rules(&self) -> Vec<String> {
        spool_rules(&self.dir.join("spool"))
    }

    /// The installed serial of files package `name`.
    pub fn current(&self, root: &str, name: &str) -> Option<String> {
        std::fs::read_link(self.dir.join(root).join(name).join("current"))
            .ok()
            .map(|p| {
                p.to_string_lossy()
                    .split('-')
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
    }
}

/// Rule ids of the findings in a spool, validated with the contract.
pub fn spool_rules(spool: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(spool.join("ready")) else {
        return out;
    };
    let mut files: Vec<PathBuf> = rd.map(|e| e.unwrap().path()).collect();
    files.sort();
    for f in files {
        let r: robodr_agentd::spool::SpoolRecord =
            serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
        let v = robodr_ocsf::parse_and_validate(&r.value).unwrap_or_else(|e| panic!("{e:?}"));
        let v: serde_json::Value = serde_json::to_value(&v).unwrap();
        out.push(
            v["entity_context"]["rule_id"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        );
    }
    out
}

/// Enrol `u` at the depot with two operators and export its files.
pub fn enrol(site: &Site, d: &mut Depot, u: &UnitH) {
    let n = now();
    let nonce = d.enrol_begin(&u.id, n).unwrap();
    let nonce: [u8; 32] = robodr_seal::from_hex(&nonce).unwrap().try_into().unwrap();
    let req = u.seal().enrol_request(&nonce).unwrap();
    let ch = d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), n)
        .unwrap()
        .expect("a TPM unit gets a challenge");
    let c = robodr_seal::enrol::parse_challenge(&ch).unwrap();
    let resp = u.seal().enrol_activate(&c).unwrap();
    d.enrol_finish(&serde_json::to_vec(&resp).unwrap(), n)
        .unwrap();
    assert!(!d.enrol_approve(&u.id, &site.ops[0], n).unwrap());
    assert!(d.enrol_approve(&u.id, &site.ops[1], n).unwrap());
    d.enrol_export(&u.id, &u.dir.join("depot")).unwrap();
}

/// A depot served on 127.0.0.1 in a thread; stopped on drop.
pub struct Served {
    pub depot: std::sync::Arc<std::sync::Mutex<Depot>>,
    pub port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    th: Option<std::thread::JoinHandle<()>>,
}

impl Served {
    pub fn start(d: Depot) -> Self {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let depot = std::sync::Arc::new(std::sync::Mutex::new(d));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (d2, s2) = (depot.clone(), stop.clone());
        let th = std::thread::spawn(move || {
            robodr_depot::serve::serve(d2, l, s2, std::sync::Arc::new(now)).unwrap();
        });
        Self {
            depot,
            port,
            stop,
            th: Some(th),
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Depot) -> R) -> R {
        f(&mut self.depot.lock().unwrap())
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.th.take() {
            let _ = t.join();
        }
    }
}
