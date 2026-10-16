//! The black box as the second witness of profile anti-rollback.
//!
//! The anti-rollback state file (`sensor.profile_trust.state_file`) is
//! plain JSON that root can delete. Every accepted locked profile is
//! therefore also recorded in the signed, hash-chained black box: a
//! `robodr.profile_accepted` note at start ([`accepted_note`]) and the same
//! `profile_accepted` object in every heartbeat. At the next start,
//! [`latest_accepted`] finds the newest such record that carries a valid
//! signature under the daemon's own black-box key, and
//! `robodr_ros2_pipeline::profile_trust::load_profile_checked` reconciles it
//! with the state file: a state that is missing or behind the record
//! raises a Critical, observe-only `robot.ros2.profile_state_tampered`
//! finding and the record becomes the rollback baseline.
//!
//! # Trust in what is read
//!
//! A record counts only if its hash matches its fields and its signature
//! verifies under the daemon's current key (`Signer::verify_own`): a forger
//! without the key cannot plant one. Records signed by a key the daemon no
//! longer holds (after a rotation) are skipped and counted; so are frames
//! that do not parse. Chain linkage is not re-verified here (that is
//! `robodr-blackbox verify`'s job): a valid signature by our key already
//! means our recorder wrote the record, and a forged record could only
//! *raise* the baseline (a refusal, never an acceptance).
//!
//! # Limits
//!
//! * Only the newest verified record is used, scanning segments newest
//!   first; segments larger than [`MAX_SEGMENT_READ`] are skipped (counted).
//! * If root deletes the black-box directory as well as the state file,
//!   nothing is left on the unit to compare with (the exported chain shows
//!   the gap off-unit); the trust file's root-signed `min_profile_version`
//!   is then the only floor.
//! * Cyclic retention or export pruning can remove old segments; the
//!   heartbeat re-records the accepted profile so the newest segment
//!   normally carries it.

use std::io::Read;
use std::path::Path;

use robodr_blackbox::record::{scan_frames, signing_message, ScanItem};
use robodr_blackbox::store::list_segments;
use robodr_blackbox::{RecordKind, Signer};
use robodr_commission::trust::{accepted_from_note, AcceptedState};

pub use robodr_commission::trust::accepted_note;

/// Largest segment file read while looking for the record.
pub const MAX_SEGMENT_READ: u64 = 256 << 20;

/// What [`latest_accepted`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainScan {
    /// The newest verified accepted-profile record.
    pub latest: Option<AcceptedState>,
    /// Segments read.
    pub segments_read: usize,
    /// Note records carrying a `profile_accepted` object that did not
    /// verify under the current key (forged, damaged, or an older key).
    pub unverified: usize,
    /// Segments skipped (too large or unreadable).
    pub skipped: Vec<String>,
}

/// The newest accepted-profile record in the black-box directory `dir`
/// signed by `signer`'s key. A missing directory is an empty scan; an
/// unlistable one is an error.
pub fn latest_accepted(dir: &Path, signer: &dyn Signer) -> Result<ChainScan, String> {
    let mut scan = ChainScan::default();
    let segments = match list_segments(dir) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(scan),
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    for (_, path) in segments.iter().rev() {
        let bytes = match read_capped(path) {
            Ok(b) => b,
            Err(e) => {
                scan.skipped.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        scan.segments_read += 1;
        let mut found = None;
        for item in scan_frames(&bytes).items {
            let ScanItem::Record(sr) = item else { continue };
            let rec = sr.record;
            if rec.kind != RecordKind::Note {
                continue;
            }
            let Some(state) = accepted_from_note(&rec.payload) else {
                continue;
            };
            let authentic = rec.compute_hash() == rec.hash
                && signer.verify_own(&signing_message(&rec.hash), &rec.sig) == Some(true);
            if authentic {
                found = Some(state);
            } else {
                scan.unverified += 1;
            }
        }
        if found.is_some() {
            scan.latest = found;
            break;
        }
    }
    Ok(scan)
}

fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let mut b = Vec::new();
    f.take(MAX_SEGMENT_READ + 1).read_to_end(&mut b)?;
    if b.len() as u64 > MAX_SEGMENT_READ {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("larger than {MAX_SEGMENT_READ} bytes"),
        ));
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_blackbox::{
        Ed25519SigningKey, HmacSha256Key, Recorder, RecorderConfig, SteppingClock, TimeSource,
    };
    use robodr_commission::trust::{file_digest, RollbackDecision, STATE_FORMAT};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("robodr-agentd-chain-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn st(v: u64) -> AcceptedState {
        AcceptedState {
            format: STATE_FORMAT.into(),
            model: "ugv".into(),
            platform: "ugv-x1".into(),
            unit_id: None,
            profile_version: v,
            digest: file_digest(format!("{v}").as_bytes()),
            revocation_serial: None,
            revocation_digest: None,
        }
    }

    fn key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed("bb", &[5; 32]).unwrap()
    }

    fn record(dir: &Path, signer: Box<dyn Signer>, notes: &[serde_json::Value]) {
        let mut r = Recorder::open(
            RecorderConfig::new(dir, "ugv-007", "boot"),
            signer,
            Box::new(SteppingClock::new(1, 1_000, TimeSource::Rtc)),
        )
        .unwrap();
        for n in notes {
            r.append_note(n, false).unwrap();
        }
        r.close().unwrap();
    }

    #[test]
    fn finds_the_newest_verified_record() {
        let d = tmpdir("newest");
        assert_eq!(latest_accepted(&d, &key()).unwrap(), ChainScan::default());
        let n = |v: u64| {
            serde_json::to_value(accepted_note(
                &st(v),
                Some("oem"),
                Some(RollbackDecision::Upgrade),
            ))
            .unwrap()
        };
        let hb = |v: u64| serde_json::json!({"kind": "robodr.agentd_heartbeat", "profile_accepted": st(v)});
        record(
            &d,
            Box::new(key()),
            &[n(1), serde_json::json!({"kind": "other"}), n(3), hb(2)],
        );
        let s = latest_accepted(&d, &key()).unwrap();
        // File order, not the highest version: an operator rollback (3 -> 2)
        // is the newest truth.
        assert_eq!(s.latest, Some(st(2)));
        assert_eq!(s.unverified, 0);
        assert!(s.segments_read >= 1);
        // Another key (e.g. a forger's, or after rotation): nothing counts.
        let other = Ed25519SigningKey::from_seed("bb", &[6; 32]).unwrap();
        let s = latest_accepted(&d, &other).unwrap();
        assert_eq!(s.latest, None);
        assert_eq!(s.unverified, 3);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_payload_is_not_trusted_and_hmac_keys_work() {
        let d = tmpdir("tamper");
        let h = || HmacSha256Key::new("h", &[1; 32]).unwrap();
        record(
            &d,
            Box::new(h()),
            &[serde_json::to_value(accepted_note(&st(4), None, None)).unwrap()],
        );
        assert_eq!(latest_accepted(&d, &h()).unwrap().latest, Some(st(4)));
        // Rewrite the version digit in place (same length): hash mismatch.
        let (_, seg) = list_segments(&d).unwrap().pop().unwrap();
        let mut b = std::fs::read(&seg).unwrap();
        let needle = b"\"profile_version\":4";
        let i = b.windows(needle.len()).position(|w| w == needle).unwrap();
        b[i + needle.len() - 1] = b'9';
        std::fs::write(&seg, &b).unwrap();
        let s = latest_accepted(&d, &h()).unwrap();
        assert_eq!(s.latest, None);
        assert_eq!(s.unverified, 1);
        // Garbage segments never panic.
        std::fs::write(&seg, b"\x00\xffgarbage").unwrap();
        assert_eq!(latest_accepted(&d, &h()).unwrap().latest, None);
        let _ = std::fs::remove_dir_all(&d);
    }
}
