//! Shared helpers: a per-test directory with a sealed profile, the demo
//! policy, a 0600 key file and a daemon config; spool / black-box readers.

#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use robodr_blackbox::record::{scan_frames, ScanItem};
use robodr_blackbox::verify::read_segments;
use robodr_blackbox::{HmacSha256Key, Record};
use robodr_events::profile::Profile;
use robodr_ocsf::FindingEnvelope;

// The synthetic RTPS/pcap builders of the pipeline's own tests (reused, not
// copied).
#[path = "../../../robodr-ros2-pipeline/tests/common/mod.rs"]
pub mod pcap;

pub const ROBOT: &str = "ugv-007";
pub const KEY: [u8; 32] = [0x42; 32];
pub const KEY_ID: &str = "test-key";

pub fn verifier() -> HmacSha256Key {
    HmacSha256Key::new(KEY_ID, &KEY).unwrap()
}

/// A fresh, empty directory.
pub fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-agentd-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Files of one test setup.
pub struct Setup {
    pub dir: PathBuf,
    pub profile: PathBuf,
    pub policy: PathBuf,
    pub key: PathBuf,
    pub blackbox: PathBuf,
    pub spool: PathBuf,
}

/// Write the sealed (locked) lab profile, the OEM-validated demo policy and
/// a 0600 key file.
pub fn setup(tag: &str, profile: &Profile) -> Setup {
    let dir = tmpdir(tag);
    let profile_path = dir.join("profile.json");
    let text = if profile.locked {
        robodr_commission::sealed_text(profile).unwrap()
    } else {
        serde_json::to_string_pretty(profile).unwrap()
    };
    std::fs::write(&profile_path, text).unwrap();
    let policy = dir.join("policy.json");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../robodr-agent/examples/policy-oem-validated.json"),
        &policy,
    )
    .unwrap();
    let key = dir.join("blackbox.key");
    std::fs::write(&key, robodr_blackbox::crypto::to_hex(&KEY)).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    Setup {
        blackbox: dir.join("blackbox"),
        spool: dir.join("spool"),
        dir,
        profile: profile_path,
        policy,
        key,
    }
}

impl Setup {
    /// A config with the given `sensor` extras, event inputs and daemon
    /// section (merged over fast test timings).
    pub fn config(
        &self,
        sensor_extra: serde_json::Value,
        event_inputs: serde_json::Value,
        daemon: serde_json::Value,
    ) -> serde_json::Value {
        let mut sensor = serde_json::json!({
            "profile_path": self.profile,
            "listen_spdp": false,
        });
        merge(&mut sensor, sensor_extra);
        let mut d = serde_json::json!({
            "tick_ms": 50,
            "heartbeat_ms": 200,
            "silence_ms": 60000,
            "lag_ms": 5000,
            "health_report_ms": 0,
        });
        merge(&mut d, daemon);
        serde_json::json!({
            "robot": {"id": ROBOT, "site": "lab", "profile_version": "test-1"},
            "sensor": sensor,
            "policy_path": self.policy,
            "blackbox": {"dir": self.blackbox, "key_file": self.key, "key_id": KEY_ID,
                         "boot_id": "test-boot"},
            "spool": {"dir": self.spool},
            "event_inputs": event_inputs,
            "context": {"safety_state": "moving_slow"},
            "daemon": d,
        })
    }

    pub fn write_config(&self, cfg: &serde_json::Value) -> PathBuf {
        let p = self.dir.join("agentd.json");
        std::fs::write(&p, serde_json::to_vec_pretty(cfg).unwrap()).unwrap();
        p
    }

    pub fn resolve(&self, cfg: &serde_json::Value) -> robodr_agentd::Resolved {
        robodr_agentd::load(&self.write_config(cfg)).unwrap()
    }

    pub fn pcap(&self, frames: &[Vec<u8>]) -> PathBuf {
        let p = self.dir.join("capture.pcap");
        std::fs::write(&p, pcap::pcap(frames)).unwrap();
        p
    }
}

fn merge(a: &mut serde_json::Value, b: serde_json::Value) {
    if let (Some(a), serde_json::Value::Object(b)) = (a.as_object_mut(), b) {
        for (k, v) in b {
            a.insert(k, v);
        }
    }
}

/// Every spooled record in `ready/` (and `acked/`), in order, validated.
pub fn spooled(spool: &Path) -> Vec<(robodr_agentd::SpoolRecord, FindingEnvelope)> {
    let mut out = Vec::new();
    for sub in ["acked", "ready"] {
        let Ok(rd) = std::fs::read_dir(spool.join(sub)) else {
            continue;
        };
        let mut names: Vec<PathBuf> = rd.map(|e| e.unwrap().path()).collect();
        names.sort();
        for p in names {
            let rec: robodr_agentd::SpoolRecord =
                serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            let env = robodr_ocsf::parse_and_validate(&rec.value)
                .unwrap_or_else(|e| panic!("{}: invalid finding: {e:?}", p.display()));
            assert_eq!(env.finding_id, rec.key);
            out.push((rec, env));
        }
    }
    out.sort_by_key(|x| x.0.seq);
    out
}

pub fn rules(found: &[(robodr_agentd::SpoolRecord, FindingEnvelope)]) -> Vec<String> {
    found
        .iter()
        .map(|(_, e)| e.entity_context.rule_id.clone())
        .collect()
}

/// Every decodable black-box record.
pub fn records(dir: &Path) -> Vec<Record> {
    let mut out = Vec::new();
    for seg in read_segments(dir).unwrap() {
        for item in scan_frames(&seg.bytes).items {
            if let ScanItem::Record(r) = item {
                out.push(r.record);
            }
        }
    }
    out
}

/// Records whose payload contains `needle`.
pub fn notes_with(dir: &Path, needle: &str) -> usize {
    records(dir)
        .iter()
        .filter(|r| {
            r.payload
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
        })
        .count()
}

/// Chain intact and every finding's evidence links resolve.
pub fn assert_verified(
    blackbox: &Path,
    checkpoint: Option<robodr_blackbox::Checkpoint>,
    found: &[(robodr_agentd::SpoolRecord, FindingEnvelope)],
) {
    let v = verifier();
    let report = robodr_agent::verify_blackbox(blackbox, &v, checkpoint, Some(ROBOT)).unwrap();
    assert!(report.is_intact(), "{report:#?}");
    let refs: Vec<_> = found
        .iter()
        .flat_map(|(_, e)| robodr_agent::finding_refs(e))
        .collect();
    let links = robodr_agent::resolve_links(blackbox, &v, &refs).unwrap();
    assert!(links.is_ok(), "{links:#?}");
}

/// Poll `f` until it returns `Some`, or panic after `secs`.
pub fn wait_for<T>(secs: u64, what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `status.json` of the spool.
pub fn status(spool: &Path) -> Option<serde_json::Value> {
    let b = std::fs::read(spool.join("status.json")).ok()?;
    serde_json::from_slice(&b).ok()
}
