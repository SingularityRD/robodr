//! The black box as the second witness of profile anti-rollback.
//!
//! The anti-rollback state file (`sensor.profile_trust.state_file`) is
//! plain JSON that root can delete. Every accepted locked profile is
//! therefore also recorded in the signed, hash-chained black box: a
//! `robodr.profile_accepted` note at start ([`accepted_note`]) and the same
//! `profile_accepted` object in every heartbeat. At the next start,
//! [`latest_accepted`] derives the baseline from **every** such record that
//! carries a valid signature under the daemon's own black-box key, and
//! `robodr_ros2_pipeline::profile_trust::load_profile_checked` reconciles it
//! with the state file: a state that is missing or behind the baseline
//! raises a Critical, observe-only `robot.ros2.profile_state_tampered`
//! finding and the baseline becomes the rollback floor.
//!
//! # The baseline
//!
//! Records are ordered by their **authenticated sequence number** (`seq`,
//! inside the signed hash), never by file or segment order: an old,
//! authentic segment copied under a higher segment index (a replay) keeps
//! its old sequence numbers. Folding them in that order:
//!
//! * the profile part is the highest accepted `profile_version` (same
//!   version: same digest). A later record with a lower version, or the
//!   same version and another digest, is accepted as the new baseline only
//!   if its note records an operator rollback (`decision:
//!   "OperatorRollback"`, which the loader writes only for a rollback the
//!   operator named by digest); any other drop is reported in
//!   [`ChainScan::drops`] (an alarm: a replayed or rewritten record) and
//!   the higher baseline is kept;
//! * the revocation part is the highest serial seen; the trust floor the
//!   highest floor seen (neither is ever lowered by a later record).
//!
//! # Trust in what is read
//!
//! A record counts only if its hash matches its fields and its signature
//! verifies under the daemon's current key (`Signer::verify_own`): a forger
//! without the key cannot plant one. Records signed by a key the daemon no
//! longer holds (after a rotation) are skipped and counted; so are frames
//! that do not parse. Chain linkage is checked where it is available
//! (consecutive hash-valid records in file order: sequence numbers must
//! grow, and `seq + 1` must link by `prev_hash`); breaks are counted in
//! [`ChainScan::linkage_breaks`] (an alarm), the full verification remains
//! `robodr-blackbox verify`'s job.
//!
//! # Limits
//!
//! * Every segment is read (each capped at [`MAX_SEGMENT_READ`]; larger
//!   ones are skipped and counted), so start-up time grows with the size of
//!   the black box.
//! * Deleting the **newest** segments (truncating the chain) lowers what
//!   is found and cannot be told apart, on the unit, from a black box that
//!   never had those records; the exported chain shows the gap off-unit.
//!   If root deletes the black-box directory as well as the state file,
//!   nothing is left on the unit to compare with; the trust file's
//!   root-signed `min_profile_version` is then the only floor.
//! * Cyclic retention or export pruning can remove old segments; the
//!   heartbeat re-records the accepted profile so the newest segment
//!   normally carries it. An operator rollback whose note was pruned while
//!   a record of the higher version survives is reported as a drop.

use std::io::Read;
use std::path::Path;

use robodr_blackbox::record::{scan_frames, signing_message, Hash, ScanItem};
use robodr_blackbox::store::list_segments;
use robodr_blackbox::{RecordKind, Signer};
use robodr_commission::trust::{accepted_from_note, AcceptedState, RollbackDecision};

pub use robodr_commission::trust::accepted_note;

/// Largest segment file read while looking for the record.
pub const MAX_SEGMENT_READ: u64 = 256 << 20;

/// What [`latest_accepted`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainScan {
    /// The baseline derived from every verified accepted-profile record
    /// (see the module docs).
    pub latest: Option<AcceptedState>,
    /// Segments read.
    pub segments_read: usize,
    /// Note records carrying a `profile_accepted` object that did not
    /// verify under the current key (forged, damaged, or an older key).
    pub unverified: usize,
    /// Segments skipped (too large or unreadable).
    pub skipped: Vec<String>,
    /// Verified records that would have lowered the baseline without an
    /// operator rollback decision (replayed or rewritten records): each is
    /// an alarm. The baseline ignores them.
    pub drops: Vec<String>,
    /// Places where the chain does not link (a sequence number that does
    /// not grow, or `seq + 1` with another `prev_hash`, or two different
    /// records with one sequence number): an alarm.
    pub linkage_breaks: usize,
}

impl ChainScan {
    /// Anything that indicates a replayed or rewritten black box.
    pub fn alarms(&self) -> Vec<String> {
        let mut out = self.drops.clone();
        if self.linkage_breaks > 0 {
            out.push(format!(
                "black box chain linkage broken in {} place(s) (segments replayed, reordered or \
                 spliced; run `robodr-blackbox verify`)",
                self.linkage_breaks
            ));
        }
        out
    }
}

/// One verified accepted-profile record.
struct Seen {
    seq: u64,
    hash: Hash,
    state: AcceptedState,
    operator_rollback: bool,
}

/// The accepted-profile baseline from the black-box directory `dir`,
/// counting only records signed by `signer`'s key (see the module docs). A
/// missing directory is an empty scan; an unlistable one is an error.
pub fn latest_accepted(dir: &Path, signer: &dyn Signer) -> Result<ChainScan, String> {
    let mut scan = ChainScan::default();
    let segments = match list_segments(dir) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(scan),
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let mut seen: Vec<Seen> = Vec::new();
    let mut prev: Option<(u64, Hash)> = None;
    for (_, path) in &segments {
        let bytes = match read_capped(path) {
            Ok(b) => b,
            Err(e) => {
                scan.skipped.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        scan.segments_read += 1;
        for item in scan_frames(&bytes).items {
            let ScanItem::Record(sr) = item else { continue };
            let rec = sr.record;
            let hash_ok = rec.compute_hash() == rec.hash;
            if hash_ok {
                if let Some((ps, ph)) = prev {
                    if rec.seq <= ps || (ps.checked_add(1) == Some(rec.seq) && rec.prev_hash != ph)
                    {
                        scan.linkage_breaks += 1;
                    }
                }
                prev = Some((rec.seq, rec.hash));
            }
            if rec.kind != RecordKind::Note {
                continue;
            }
            let Some(state) = accepted_from_note(&rec.payload) else {
                continue;
            };
            let authentic =
                hash_ok && signer.verify_own(&signing_message(&rec.hash), &rec.sig) == Some(true);
            if !authentic {
                scan.unverified += 1;
                continue;
            }
            seen.push(Seen {
                seq: rec.seq,
                hash: rec.hash,
                state,
                operator_rollback: decision_of(&rec.payload)
                    .is_some_and(|d| d == format!("{:?}", RollbackDecision::OperatorRollback)),
            });
        }
    }
    // Authenticated order; the same record twice (a replayed copy) counts
    // once; two different records with one sequence number are a fork.
    seen.sort_by_key(|a| (a.seq, a.hash));
    seen.dedup_by(|b, a| a.seq == b.seq && a.hash == b.hash);
    scan.linkage_breaks += seen
        .iter()
        .zip(seen.iter().skip(1))
        .filter(|(a, b)| a.seq == b.seq)
        .count();
    scan.latest = fold(&seen, &mut scan.drops);
    Ok(scan)
}

/// The baseline of `seen` (in sequence order); see the module docs.
fn fold(seen: &[Seen], drops: &mut Vec<String>) -> Option<AcceptedState> {
    let mut cur: Option<AcceptedState> = None;
    let mut rev: Option<(u64, String)> = None;
    let mut floor: Option<u64> = None;
    for s in seen {
        let st = &s.state;
        if let (Some(n), Some(d)) = (st.revocation_serial, st.revocation_digest.as_ref()) {
            match &rev {
                Some((m, md)) if n == *m && d != md => drops.push(format!(
                    "black box record seq {}: revocation list serial {n} with other content than \
                     an earlier record",
                    s.seq
                )),
                Some((m, _)) if n <= *m => {}
                _ => rev = Some((n, d.clone())),
            }
        }
        floor = floor.max(st.trust_floor);
        cur = match cur {
            None => Some(st.clone()),
            Some(c) => {
                let up = st.profile_version > c.profile_version
                    || (st.profile_version == c.profile_version && st.digest == c.digest);
                if up || s.operator_rollback {
                    Some(st.clone())
                } else {
                    drops.push(format!(
                        "black box record seq {} lowers the accepted profile from version {} ({}) \
                         to {} ({}) without an operator rollback: a replayed or rewritten record; \
                         the higher version stays the baseline",
                        s.seq, c.profile_version, c.digest, st.profile_version, st.digest
                    ));
                    Some(c)
                }
            }
        };
    }
    cur.map(|mut c| {
        c.revocation_serial = rev.as_ref().map(|(n, _)| *n);
        c.revocation_digest = rev.map(|(_, d)| d);
        c.trust_floor = floor;
        c
    })
}

/// The `decision` member of a note payload, if any.
fn decision_of(payload: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    v.get("decision")?.as_str().map(str::to_string)
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
            trust_floor: None,
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

    fn note(v: u64, d: RollbackDecision) -> serde_json::Value {
        serde_json::to_value(accepted_note(&st(v), Some("oem"), Some(d))).unwrap()
    }

    fn hb(v: u64) -> serde_json::Value {
        serde_json::json!({"kind": "robodr.agentd_heartbeat", "profile_accepted": st(v)})
    }

    #[test]
    fn baseline_is_the_highest_version_unless_the_operator_rolled_back() {
        let d = tmpdir("newest");
        assert_eq!(latest_accepted(&d, &key()).unwrap(), ChainScan::default());
        use RollbackDecision::*;
        // A drop to 2 recorded by a heartbeat alone: not a rollback the
        // operator named, so 3 stays the baseline and the drop is an alarm.
        record(
            &d,
            Box::new(key()),
            &[
                note(1, First),
                serde_json::json!({"kind": "other"}),
                note(3, Upgrade),
                hb(2),
            ],
        );
        let s = latest_accepted(&d, &key()).unwrap();
        assert_eq!(s.latest, Some(st(3)));
        assert_eq!(s.drops.len(), 1, "{:?}", s.drops);
        assert!(s.drops[0].contains("without an operator rollback"));
        assert_eq!(s.linkage_breaks, 0);
        assert_eq!(s.alarms().len(), 1);
        assert_eq!(s.unverified, 0);
        assert!(s.segments_read >= 1);
        let _ = std::fs::remove_dir_all(&d);
        // An operator rollback (3 -> 2) is the newest truth; its
        // heartbeats keep it.
        let d = tmpdir("rollback");
        record(
            &d,
            Box::new(key()),
            &[
                note(3, Upgrade),
                note(2, OperatorRollback),
                hb(2),
                note(2, Same),
            ],
        );
        let s = latest_accepted(&d, &key()).unwrap();
        assert_eq!(s.latest, Some(st(2)));
        assert!(s.alarms().is_empty(), "{:?}", s.alarms());
        // Another key (e.g. a forger's, or after rotation): nothing counts.
        let other = Ed25519SigningKey::from_seed("bb", &[6; 32]).unwrap();
        let s = latest_accepted(&d, &other).unwrap();
        assert_eq!(s.latest, None);
        assert_eq!(s.unverified, 4);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn revocation_serial_and_trust_floor_never_go_down() {
        let d = tmpdir("revfloor");
        let with = |v: u64, rev: Option<u64>, floor: Option<u64>| {
            let mut s = st(v);
            s.revocation_serial = rev;
            s.revocation_digest = rev.map(|n| file_digest(format!("list{n}").as_bytes()));
            s.trust_floor = floor;
            serde_json::json!({"kind": "robodr.agentd_heartbeat", "profile_accepted": s})
        };
        record(
            &d,
            Box::new(key()),
            &[
                with(2, Some(3), Some(2)),
                with(2, Some(1), None),
                with(2, None, Some(1)),
            ],
        );
        let s = latest_accepted(&d, &key()).unwrap();
        let l = s.latest.unwrap();
        assert_eq!(l.revocation_serial, Some(3));
        assert_eq!(l.revocation_digest, Some(file_digest(b"list3")));
        assert_eq!(l.trust_floor, Some(2));
        assert!(s.drops.is_empty());
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

    /// Regression (was a PoC): an old, authentic segment (same key) copied
    /// under a higher segment index became "the newest record", lowering
    /// the baseline to the old version; with the state file rewritten to
    /// match, no alarm fired. Records are now ordered by their signed
    /// sequence number, the baseline is the highest accepted version, and
    /// the replay is reported (linkage break) instead of trusted.
    #[test]
    fn replayed_old_segment_does_not_lower_the_chain_baseline() {
        let live = tmpdir("reg-live");
        let n = |v: u64| serde_json::to_value(accepted_note(&st(v), Some("oem"), None)).unwrap();
        // Earlier on this unit: v1 accepted (segment captured by an
        // attacker); then v3 accepted, in the same chain.
        record(&live, Box::new(key()), &[n(1)]);
        let (_, first_seg) = list_segments(&live).unwrap().pop().unwrap();
        let captured = std::fs::read(&first_seg).unwrap();
        record(&live, Box::new(key()), &[n(3)]);
        assert_eq!(latest_accepted(&live, &key()).unwrap().latest, Some(st(3)));
        let (top, _) = list_segments(&live).unwrap().pop().unwrap();
        std::fs::write(
            live.join(robodr_blackbox::store::segment_file_name(top + 100)),
            &captured,
        )
        .unwrap();
        let s = latest_accepted(&live, &key()).unwrap();
        assert_eq!(s.latest, Some(st(3)), "baseline not lowered by a replay");
        assert!(s.linkage_breaks > 0, "the replay is reported");
        assert!(!s.alarms().is_empty());
        // The state rewritten to v1 is behind the chain: alarm, v3 floor.
        let (base, alarm) =
            robodr_commission::trust::reconcile_with_chain(Some(&st(1)), s.latest.as_ref());
        assert_eq!(base, Some(st(3)));
        assert!(alarm.is_some());
        let _ = std::fs::remove_dir_all(&live);
    }

    /// A segment from another (old) chain directory replayed into this one
    /// is caught the same way, and a duplicated record counts once.
    #[test]
    fn foreign_replay_and_duplicates() {
        let live = tmpdir("reg-foreign-live");
        let old = tmpdir("reg-foreign-old");
        let n = |v: u64| serde_json::to_value(accepted_note(&st(v), Some("oem"), None)).unwrap();
        record(&old, Box::new(key()), &[n(1)]);
        record(&live, Box::new(key()), &[n(3)]);
        let (_, old_seg) = list_segments(&old).unwrap().pop().unwrap();
        let (top, top_seg) = list_segments(&live).unwrap().pop().unwrap();
        std::fs::copy(
            &old_seg,
            live.join(robodr_blackbox::store::segment_file_name(top + 100)),
        )
        .unwrap();
        let s = latest_accepted(&live, &key()).unwrap();
        assert_eq!(s.latest, Some(st(3)));
        assert!(!s.alarms().is_empty());
        let _ =
            std::fs::remove_file(live.join(robodr_blackbox::store::segment_file_name(top + 100)));
        // The newest segment duplicated: same records, counted once; the
        // seq regression is a linkage break.
        std::fs::copy(
            &top_seg,
            live.join(robodr_blackbox::store::segment_file_name(top + 1)),
        )
        .unwrap();
        let s = latest_accepted(&live, &key()).unwrap();
        assert_eq!(s.latest, Some(st(3)));
        assert!(s.drops.is_empty());
        assert!(s.linkage_breaks > 0);
        let _ = std::fs::remove_dir_all(&live);
        let _ = std::fs::remove_dir_all(&old);
    }
}
