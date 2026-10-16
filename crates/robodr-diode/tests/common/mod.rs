//! Shared fixtures for the diode integration tests.
#![allow(dead_code)]

use robodr_blackbox::{
    FsyncPolicy, HmacSha256Key, Recorder, RecorderConfig, SteppingClock, TimeSource,
};
use robodr_diode::manifest::{manifest_signing_message, MANIFEST_FILE, SIGNATURE_FILE};
use robodr_diode::{ImportConfig, Importer, Keyring, PackConfig, Packer};
use robodr_events::graph::Endpoint;
use robodr_events::{Deviation, RobotEvent, Severity};
use robodr_ocsf::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const T0: u64 = 1_790_000_000_000;
pub const NOW: u64 = 1_790_000_100_000;
pub const UNIT: &str = "ugv-007";
pub const KEY_ID: &str = "diode-ugv-007";
pub const KEY: [u8; 32] = [7; 32];
pub const BB_KEY_ID: &str = "bb-ugv-007";
pub const BB_KEY: [u8; 32] = [0x42; 32];

static N: AtomicU64 = AtomicU64::new(0);

/// A temp directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "robodr-diode-it-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn ctx() -> RobotContext {
    let mut c = RobotContext::new(
        RobotInfo {
            id: UNIT.into(),
            model: "ugv-tracked-v1".into(),
            platform_family: PlatformFamily::LinuxRos2,
            site: "range-north".into(),
            firmware: Some(FirmwareRef {
                version: "2.4.1".into(),
                sha256: "1f".repeat(32),
            }),
        },
        ProfileRef {
            version: "7".into(),
            sha256: "c0".repeat(32),
        },
        Mode::Enforce,
    );
    c.product_version = "0.1.0-alpha.1".into();
    c
}

/// A distinct, valid finding per `i`.
pub fn finding(i: u64) -> FindingEnvelope {
    let topic = format!("rt/topic_{i}");
    let dev = Deviation::new(
        "robot.ros2.unknown_writer_topic",
        Severity::High,
        format!("writer on {topic}"),
    );
    let c = ctx();
    FindingBuilder::from_deviation(&dev, &c)
        .event(&RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: "0102030405060708090a0b0c".into(),
            topic,
            type_name: "std_msgs::msg::dds_::String_".into(),
        }))
        .seen(T0 + i, T0 + i)
        .build()
        .expect("finding builds")
}

pub fn findings(n: u64) -> Vec<FindingEnvelope> {
    (0..n).map(finding).collect()
}

pub fn signer() -> Box<HmacSha256Key> {
    Box::new(HmacSha256Key::new(KEY_ID, &KEY).unwrap())
}

pub fn keyring() -> Keyring {
    let mut k = Keyring::new();
    k.add(UNIT, signer()).unwrap();
    k
}

/// A real black-box export bundle with `n` notes.
pub fn bundle(n: u64) -> Vec<u8> {
    let d = TempDir::new("bb");
    let mut cfg = RecorderConfig::new(d.path().join("bb"), UNIT, "boot-a");
    cfg.fsync = FsyncPolicy::SealsOnly;
    let mut r = Recorder::open(
        cfg,
        Box::new(HmacSha256Key::new(BB_KEY_ID, &BB_KEY).unwrap()),
        Box::new(SteppingClock::new(1_000_000, 1_000, TimeSource::Gps)),
    )
    .unwrap();
    for i in 0..n {
        r.append_note(&serde_json::json!({ "i": i }), false)
            .unwrap();
    }
    r.export_pending(None).unwrap().unwrap().to_bytes()
}

/// Low side (outbox + packer state) and high side (importer dirs).
pub struct Site {
    pub tmp: TempDir,
    pub outbox: PathBuf,
    pub pack_state: PathBuf,
    pub high: PathBuf,
}

impl Site {
    pub fn new(tag: &str) -> Self {
        let tmp = TempDir::new(tag);
        let outbox = tmp.path().join("low/outbox");
        fs::create_dir_all(&outbox).unwrap();
        let high = tmp.path().join("high");
        fs::create_dir_all(high.join("inbox")).unwrap();
        Self {
            outbox,
            pack_state: tmp.path().join("low/pack-state.json"),
            high,
            tmp,
        }
    }

    pub fn packer_cfg(&self, cfg: PackConfig) -> Packer {
        Packer::open(&self.outbox, &self.pack_state, cfg, signer()).unwrap()
    }

    pub fn packer(&self) -> Packer {
        self.packer_cfg(PackConfig::new(UNIT))
    }

    pub fn import_cfg(&self) -> ImportConfig {
        ImportConfig::under(&self.high)
    }

    pub fn importer(&self) -> Importer {
        Importer::open(self.import_cfg(), keyring()).unwrap()
    }

    pub fn inbox(&self) -> PathBuf {
        self.high.join("inbox")
    }

    /// Copy one published batch from the outbox into the inbox (the diode).
    pub fn transfer(&self, name: &str) {
        copy_dir(&self.outbox.join(name), &self.inbox().join(name));
    }

    /// Copy every published batch.
    pub fn transfer_all(&self) {
        for n in self.outbox_batches() {
            self.transfer(&n);
        }
    }

    pub fn outbox_batches(&self) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(&self.outbox)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| !n.starts_with('.'))
            .collect();
        v.sort();
        v
    }

    pub fn inbox_entries(&self) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(self.inbox())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }
}

pub fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// Rewrite a batch's manifest through `f` and re-sign it with the real key
/// (models a buggy or compromised producer that holds the key).
pub fn resign(dir: &Path, f: impl FnOnce(&mut serde_json::Value)) {
    let mut v: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap();
    f(&mut v);
    let bytes = serde_json::to_vec_pretty(&v).unwrap();
    write_signed_manifest(dir, &bytes, &HmacSha256Key::new(KEY_ID, &KEY).unwrap());
}

pub fn write_signed_manifest(dir: &Path, bytes: &[u8], key: &HmacSha256Key) {
    use robodr_blackbox::Signer;
    let sig = key.sign(&manifest_signing_message(bytes)).unwrap();
    fs::write(dir.join(MANIFEST_FILE), bytes).unwrap();
    let s = serde_json::json!({
        "format": "robodr-diode/1",
        "algorithm": key.algorithm(),
        "key_id": Signer::key_id(key),
        "sig": robodr_blackbox::crypto::to_hex(&sig),
    });
    fs::write(dir.join(SIGNATURE_FILE), serde_json::to_vec(&s).unwrap()).unwrap();
}

/// Replace a data file and fix its size/hash in the (re-signed) manifest.
pub fn replace_file_resigned(dir: &Path, name: &str, content: &[u8]) {
    fs::write(dir.join(name), content).unwrap();
    let sha = robodr_diode::manifest::file_sha256(content);
    let len = content.len() as u64;
    resign(dir, |m| {
        for f in m["files"].as_array_mut().unwrap() {
            if f["name"] == name {
                f["size"] = len.into();
                f["sha256"] = sha.clone().into();
            }
        }
    });
}

pub fn reason_code(r: &robodr_diode::QuarantineReason) -> String {
    serde_json::to_value(r).unwrap()["code"]
        .as_str()
        .unwrap()
        .to_string()
}

pub fn read_lines(p: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
