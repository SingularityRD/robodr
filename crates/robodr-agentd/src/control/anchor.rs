//! Binding the control plane's sealed journals ([`super::journal`]) to the
//! black box: their heads are recorded as signed notes, and at start the
//! newest authentic head decides whether a journal was rolled back.
//!
//! # The head note (`robodr.control_plane_state_head`)
//!
//! ```json
//! {"kind":"robodr.control_plane_state_head","robot_id":"ugv-007","reason":"start"|"heartbeat"|"stop",
//!  "clean":false,"key_id":"hmac-sha256:<16 hex>",
//!  "requests":{"generation":3,"seq":12,"tag":"<64 hex>"},"nonces":{"generation":9,"seq":4,"tag":"<64 hex>"}}
//! ```
//!
//! agentd records it right after the control plane started (after the
//! journals were opened, repaired and compacted), on every heartbeat at
//! which a head moved, and at a clean stop (`clean: true`, after the
//! listener threads were joined: nothing can be appended after it). A
//! critical note: fsynced before it counts.
//!
//! At the next start, [`latest`] scans the black box for the newest such
//! note of this robot whose record hash and signature verify under the
//! black-box key (the same check as the profile anti-rollback witness,
//! [`crate::profile_chain`]); notes that do not verify are counted and
//! ignored. Someone who can write the state directory but not forge
//! black-box records cannot make an older journal pass for the current one.
//! What the comparison means is in [`super::journal::AnchorCheck`].
//!
//! Whether any head note exists at all (authentic or not) decides the
//! one-time upgrade of v1 journals ([`super::journal::Sealing::adopt_legacy`]):
//! once sealing has started, an unsealed journal is a downgrade.

use std::io::{self, Write};
use std::path::Path;

use robodr_blackbox::record::{scan_frames, signing_message, RecordKind, ScanItem};
use robodr_blackbox::{Signer, StateSealKey};
use robodr_events::Severity;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::evidence::SegmentSource;
use super::fsutil;
use super::journal::{Anchor, AnchorCheck, Head, Sealing};
use super::StateStatus;

/// Kind of the head note.
pub const STATE_HEAD_NOTE: &str = "robodr.control_plane_state_head";
/// Kind of the one-time upgrade note (v1 journals adopted).
pub const STATE_UPGRADED_NOTE: &str = "robodr.control_plane_state_upgraded";

/// The heads of both journals.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StateHeads {
    pub requests: Option<Head>,
    pub nonces: Option<Head>,
}

/// What [`latest`] found in the black box.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Found {
    /// The newest authentic head note of this robot.
    pub heads: Option<StateHeads>,
    /// It was recorded at a clean stop.
    pub clean: bool,
    /// Head notes of this robot seen, authentic or not.
    pub seen: usize,
    /// Of those, notes whose record hash or signature did not verify.
    pub unverified: usize,
    /// `segment_dropped` records in the black box (a cyclic store deleted
    /// its oldest segments): a missing head note may have aged out.
    pub segments_dropped: usize,
}

impl Found {
    /// Review of gap 1, finding 3: no authentic head note, but the black
    /// box dropped segments: the newest head may have aged out, so the
    /// journals cannot be taken as they are.
    pub fn anchor_lost(&self) -> bool {
        self.heads.is_none() && self.segments_dropped > 0
    }

    /// The sealing the control plane opens its journals with. A v1 journal
    /// is adopted only while the black box never saw a head note and holds
    /// no sign of having lost one; the caller also refuses it once the
    /// state directory's sealed marker exists ([`sealed_marker_present`]).
    pub fn sealing(&self, key: std::sync::Arc<robodr_blackbox::StateSealKey>) -> Sealing {
        let anchor = |h: Option<&Head>| {
            h.map(|head| Anchor {
                head: head.clone(),
                clean: self.clean,
            })
        };
        let heads = self.heads.as_ref();
        Sealing {
            key,
            requests: anchor(heads.and_then(|h| h.requests.as_ref())),
            nonces: anchor(heads.and_then(|h| h.nonces.as_ref())),
            adopt_legacy: self.seen == 0,
            anchor_lost: self.anchor_lost(),
        }
    }
}

// ---------------------------------------------------------------------------
// Markers in the state directory (review of gap 1, findings 3 and 5)
// ---------------------------------------------------------------------------

/// Written once the journals have been opened sealed: from then on a v1
/// journal is never adopted, even if the black box no longer holds a head
/// note (finding 3).
pub const SEALED_MARKER: &str = "sealed.marker";
/// Requests the control plane could not reconcile with the black box
/// (finding 5): lost request ids and, when the black box could not be read,
/// the reason every new id is refused. Kept until a start reconciles.
pub const UNRECONCILED_MARKER: &str = "unreconciled";
const SEALED_MARKER_FORMAT: &str = "robodr-cp-sealed/v1";
const UNRECONCILED_FORMAT: &str = "robodr-cp-unreconciled/v1";
/// Lost request ids kept in the marker.
pub const MAX_UNRECONCILED_IDS: usize = 4096;

fn seal_file(key: &StateSealKey, format: &str, json: &[u8]) -> Vec<u8> {
    let tag = key.tag(format, &[key.key_id().as_bytes(), json]);
    let mut out = format!(
        "{format} {} {}\n",
        key.key_id(),
        robodr_blackbox::crypto::to_hex(&tag)
    )
    .into_bytes();
    out.extend_from_slice(json);
    out
}

fn unseal_file<'a>(key: &StateSealKey, format: &str, bytes: &'a [u8]) -> Result<&'a [u8], String> {
    let nl = bytes
        .iter()
        .position(|b| *b == b'\n')
        .ok_or("no seal line")?;
    let (line, json) = (
        bytes.get(..nl).ok_or("no seal line")?,
        bytes.get(nl + 1..).ok_or("no seal line")?,
    );
    let line = std::str::from_utf8(line).map_err(|_| "the seal line is not UTF-8")?;
    let mut p = line.split(' ');
    let (Some(f), Some(id), Some(tag), None) = (p.next(), p.next(), p.next(), p.next()) else {
        return Err("malformed seal line".into());
    };
    if f != format || id != key.key_id() {
        return Err(format!(
            "sealed as {} under {} (expected {format} under {})",
            robodr_ros2_pipeline::sanitize(f),
            robodr_ros2_pipeline::sanitize(id),
            key.key_id()
        ));
    }
    let ok = robodr_blackbox::crypto::from_hex(tag)
        .is_some_and(|t| key.check(format, &[key.key_id().as_bytes(), json], &t));
    if ok {
        Ok(json)
    } else {
        Err("the seal does not verify".into())
    }
}

/// Atomically replace `dir/name` (random temporary name, created
/// exclusively, no symlink followed, fsynced, directory fsynced).
fn write_private(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp-{}", fsutil::random_hex16()?));
    let res = (|| -> io::Result<()> {
        let mut f = fsutil::create_new_private(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, dir.join(name))?;
        fsutil::sync_dir(dir)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Whether the sealed marker exists (any content: whoever removed sealing
/// would have to remove it too, and a damaged one still says sealing
/// happened).
pub fn sealed_marker_present(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(SEALED_MARKER)).is_ok()
}

/// The sealing the control plane opens the journals in `dir` with: the
/// black box's heads ([`Found::sealing`]), and no v1 adoption once the
/// sealed marker exists. Returns it and whether the marker was there.
pub fn sealing_for(
    dir: &Path,
    found: &Found,
    key: std::sync::Arc<StateSealKey>,
) -> (Sealing, bool) {
    let mut s = found.sealing(key);
    let marker = sealed_marker_present(dir);
    if marker {
        s.adopt_legacy = false;
    }
    (s, marker)
}

/// Write the sealed marker (idempotent).
pub fn write_sealed_marker(dir: &Path, key: &StateSealKey) -> io::Result<()> {
    if sealed_marker_present(dir) {
        return Ok(());
    }
    let json = serde_json::json!({"format": super::journal::FORMAT, "key_id": key.key_id()});
    write_private(
        dir,
        SEALED_MARKER,
        &seal_file(key, SEALED_MARKER_FORMAT, json.to_string().as_bytes()),
    )
}

/// What the unreconciled marker holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unreconciled {
    /// Request ids whose state is unknown: their resubmission is refused.
    pub lost_ids: Vec<String>,
    /// Every new request id is refused (the black box could not be read).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refuse_new: Option<String>,
}

/// The unreconciled marker: `Ok(None)` when there is none, `Err` when one
/// exists but cannot be read or fails its seal (the caller reconciles and
/// refuses as if it held everything).
pub fn read_unreconciled(dir: &Path, key: &StateSealKey) -> Result<Option<Unreconciled>, String> {
    let p = dir.join(UNRECONCILED_MARKER);
    let bytes = match fsutil::read_capped_nofollow(&p, 1 << 20) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", p.display())),
    };
    let json = unseal_file(key, UNRECONCILED_FORMAT, &bytes)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    serde_json::from_slice(json)
        .map(Some)
        .map_err(|e| format!("{}: {e}", p.display()))
}

/// Persist `u` (or remove the marker when it holds nothing).
pub fn write_unreconciled(dir: &Path, key: &StateSealKey, u: &Unreconciled) -> io::Result<()> {
    if u.lost_ids.is_empty() && u.refuse_new.is_none() {
        return match std::fs::remove_file(dir.join(UNRECONCILED_MARKER)) {
            Ok(()) => fsutil::sync_dir(dir),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
    }
    let mut u = u.clone();
    u.lost_ids.sort();
    u.lost_ids.dedup();
    if u.lost_ids.len() > MAX_UNRECONCILED_IDS {
        let cut = u.lost_ids.len() - MAX_UNRECONCILED_IDS;
        u.lost_ids.drain(..cut);
    }
    let json = serde_json::to_vec(&u).map_err(io::Error::other)?;
    write_private(
        dir,
        UNRECONCILED_MARKER,
        &seal_file(key, UNRECONCILED_FORMAT, &json),
    )
}

/// The newest authentic head note of `robot_id` in the black box (see the
/// module). `signer` is the black-box key (`verify_own`).
pub fn latest(src: &dyn SegmentSource, robot_id: &str, signer: &dyn Signer) -> io::Result<Found> {
    let mut found = Found::default();
    let needle = STATE_HEAD_NOTE.as_bytes();
    for idx in src.list()? {
        let Some(bytes) = src.read(idx)? else {
            continue;
        };
        for item in scan_frames(&bytes).items {
            let ScanItem::Record(r) = item else {
                continue;
            };
            let rec = r.record;
            if rec.kind == RecordKind::SegmentDropped {
                found.segments_dropped += 1;
                continue;
            }
            if rec.kind != RecordKind::Note
                || !rec.payload.windows(needle.len()).any(|w| w == needle)
            {
                continue;
            }
            let Ok(v) = serde_json::from_slice::<Value>(&rec.payload) else {
                continue;
            };
            if v.get("kind").and_then(Value::as_str) != Some(STATE_HEAD_NOTE)
                || v.get("robot_id").and_then(Value::as_str) != Some(robot_id)
            {
                continue;
            }
            found.seen += 1;
            let authentic = rec.compute_hash() == rec.hash
                && signer.verify_own(&signing_message(&rec.hash), &rec.sig) == Some(true);
            let heads = serde_json::from_value::<StateHeads>(v.clone()).ok();
            match (authentic, heads) {
                (true, Some(h)) => {
                    found.clean = v.get("clean").and_then(Value::as_bool) == Some(true);
                    found.heads = Some(h);
                }
                _ => found.unverified += 1,
            }
        }
    }
    Ok(found)
}

/// Kind of the executor's journal head note (review of gap 1, findings 1
/// and 2): `{"kind":"robodr.executor_journal_head","robot_id":..,
/// "reason":..,"epoch":"<32 hex>","next_seq":<n>,"processed_seq":<n>}`,
/// recorded by agentd when the executor's epoch changes, after it recorded
/// executor events, and on heartbeats when the head moved or the black box
/// started a new segment. `processed_seq` (optional; absent while events
/// were still queued) is the last event of that epoch agentd recorded: the
/// next start resumes after it (review 2, M6).
pub const EXECUTOR_HEAD_NOTE: &str = "robodr.executor_journal_head";

/// The newest authentic executor journal head note of `robot_id`: the
/// head, its `processed_seq` if the note has one, and how many such notes
/// did not verify.
pub fn latest_executor_head(
    src: &dyn SegmentSource,
    robot_id: &str,
    signer: &dyn Signer,
) -> io::Result<ExecutorAnchor> {
    let mut newest = None;
    let mut unverified = 0;
    let needle = EXECUTOR_HEAD_NOTE.as_bytes();
    for idx in src.list()? {
        let Some(bytes) = src.read(idx)? else {
            continue;
        };
        for item in scan_frames(&bytes).items {
            let ScanItem::Record(r) = item else {
                continue;
            };
            let rec = r.record;
            if rec.kind != RecordKind::Note
                || !rec.payload.windows(needle.len()).any(|w| w == needle)
            {
                continue;
            }
            let Ok(v) = serde_json::from_slice::<Value>(&rec.payload) else {
                continue;
            };
            if v.get("kind").and_then(Value::as_str) != Some(EXECUTOR_HEAD_NOTE)
                || v.get("robot_id").and_then(Value::as_str) != Some(robot_id)
            {
                continue;
            }
            let head = serde_json::from_value::<robodr_executor::journal::JournalHead>(
                serde_json::json!({"epoch": v.get("epoch"), "next_seq": v.get("next_seq")}),
            )
            .ok();
            let mut processed = v.get("processed_seq").and_then(Value::as_u64);
            match (super::evidence::authentic(&rec, signer), head) {
                (true, Some(h)) => {
                    // A note without it keeps the last one of the same
                    // epoch (a lower bound: events are numbered upwards).
                    if processed.is_none() {
                        processed = newest
                            .as_ref()
                            .filter(|(o, _): &&(robodr_executor::journal::JournalHead, _)| {
                                o.epoch == h.epoch
                            })
                            .and_then(|(_, p)| *p);
                    }
                    newest = Some((h, processed));
                }
                _ => unverified += 1,
            }
        }
    }
    Ok(ExecutorAnchor {
        processed_seq: newest.as_ref().and_then(|(_, p)| *p),
        head: newest.map(|(h, _)| h),
        unverified,
    })
}

/// What [`latest_executor_head`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutorAnchor {
    pub head: Option<robodr_executor::journal::JournalHead>,
    /// The last event of `head`'s epoch agentd recorded.
    pub processed_seq: Option<u64>,
    /// Head notes that did not verify (ignored).
    pub unverified: usize,
}

/// The executor journal head note (`processed_seq`: see
/// [`EXECUTOR_HEAD_NOTE`]).
pub fn executor_head_note(
    robot_id: &str,
    reason: &str,
    head: &robodr_executor::journal::JournalHead,
    processed_seq: Option<u64>,
) -> Value {
    let mut v = serde_json::json!({
        "kind": EXECUTOR_HEAD_NOTE,
        "robot_id": robot_id,
        "reason": reason,
        "epoch": head.epoch,
        "next_seq": head.next_seq,
    });
    if let (Some(p), Some(o)) = (processed_seq, v.as_object_mut()) {
        o.insert("processed_seq".into(), p.into());
    }
    v
}

/// Whether a head note is due on a heartbeat (review of gap 1, finding 3):
/// when the head changed, or when the black box's newest record (the
/// heartbeat just written) is in another segment than the last head note.
/// A cyclic black box drops its oldest segments; re-recording on every
/// segment change keeps a head note in the newest segments, so it is never
/// aged out while agentd runs.
pub fn head_note_due(
    changed: bool,
    note_segment: Option<u64>,
    current_segment: Option<u64>,
) -> bool {
    changed || (current_segment.is_some() && note_segment != current_segment)
}

/// The head note (see the module).
pub fn head_note(robot_id: &str, reason: &str, key_id: &str, heads: &StateHeads) -> Value {
    serde_json::json!({
        "kind": STATE_HEAD_NOTE,
        "robot_id": robot_id,
        "reason": reason,
        "clean": reason == "stop",
        "key_id": key_id,
        "requests": heads.requests,
        "nonces": heads.nonces,
    })
}

fn anchor_problem(what: &str, a: &AnchorCheck, out: &mut Vec<String>) -> bool {
    if let AnchorCheck::RolledBack(why) = a {
        out.push(format!("{what} rolled back: {why}"));
        true
    } else {
        false
    }
}

/// The finding the state at start calls for, if any (gap 1): High for
/// damage, an edit or a journal under another key (storage damage, a
/// rotated black-box key, or tampering); Critical for authentic proof of
/// tampering (a journal older than, or cut short of, the black box's
/// signed head; an unsealed v1 file after sealing started).
pub fn integrity_alarm(st: &StateStatus) -> Option<(Severity, String)> {
    let mut why: Vec<String> = Vec::new();
    let mut critical = false;
    critical |= anchor_problem("the request journal", &st.journal_anchor, &mut why);
    critical |= anchor_problem("the replay store", &st.replay.anchor, &mut why);
    if st.journal_legacy_refused {
        why.push("an unsealed v1 request journal appeared after sealing started".into());
        critical = true;
    }
    if st.replay.legacy_refused {
        why.push("an unsealed v1 replay store appeared after sealing started".into());
        critical = true;
    }
    for (what, key) in [
        ("request journal", &st.journal_wrong_key),
        ("replay store", &st.replay.wrong_key),
    ] {
        if let Some(k) = key {
            why.push(format!(
                "the {what} is sealed under another key ({k}; expected {})",
                st.seal_key_id
            ));
        }
    }
    if st.journal_damaged > 0 {
        why.push(format!(
            "the request journal had {} damaged line(s), {} of them failing their seal",
            st.journal_damaged, st.journal_forged
        ));
    }
    if st.notes_rejected > 0 {
        why.push(format!(
            "{} black-box note(s) of the control plane failed their hash or signature check \
             and were ignored",
            st.notes_rejected
        ));
    }
    if st.dropped_unbacked > 0 {
        why.push(format!(
            "{} request journal entr(ies) had no authentic black-box note and were dropped \
             (their ids are refused)",
            st.dropped_unbacked
        ));
    }
    if let Some(e) = &st.unreconciled_unreadable {
        why.push(format!(
            "the unreconciled-requests marker could not be trusted ({e})"
        ));
    }
    if st.replay.damaged > 0 {
        why.push(format!(
            "the replay store had {} damaged line(s), {} of them failing their seal",
            st.replay.damaged, st.replay.forged
        ));
    }
    if why.is_empty() {
        return None;
    }
    let sev = if critical {
        Severity::Critical
    } else {
        Severity::High
    };
    Some((
        sev,
        format!(
            "the control plane's persistent state failed its integrity check at start: {}; the \
             damaged originals are in {}/quarantine/, requests were reconciled with the black box \
             ({} restored, {} unreadable id(s) refused{}) and the replay store is fenced at {}: \
             nothing was reset silently",
            why.join("; "),
            st.state_dir,
            st.rebuilt_from_blackbox,
            st.lost_request_ids,
            match &st.refusing_new_request_ids {
                Some(_) => "; every new request id is refused: the black box could not be read",
                None => "",
            },
            st.replay
                .fence
                .map_or_else(|| "-".to_string(), |f| f.to_string())
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::auth::ReplayLoad;

    #[test]
    fn the_alarm_is_high_for_damage_and_critical_for_a_rollback() {
        let mut st = StateStatus {
            state_dir: "/var/lib/robodr/control".into(),
            seal_key_id: "hmac-sha256:00".into(),
            ..StateStatus::default()
        };
        assert_eq!(integrity_alarm(&st), None, "clean state: no finding");
        st.journal_anchor = AnchorCheck::Unanchored("after a crash".into());
        assert_eq!(integrity_alarm(&st), None, "a crash is not tampering");
        st.journal_damaged = 2;
        st.journal_forged = 1;
        let (sev, d) = integrity_alarm(&st).unwrap();
        assert_eq!(sev, Severity::High);
        assert!(
            d.contains("2 damaged line(s), 1 of them failing their seal"),
            "{d}"
        );
        st.replay = ReplayLoad {
            anchor: AnchorCheck::RolledBack("entries were cut".into()),
            fence: Some(42),
            ..ReplayLoad::default()
        };
        let (sev, d) = integrity_alarm(&st).unwrap();
        assert_eq!(sev, Severity::Critical);
        assert!(
            d.contains("the replay store rolled back: entries were cut"),
            "{d}"
        );
        assert!(d.contains("fenced at 42"), "{d}");
        let st = StateStatus {
            journal_wrong_key: Some("hmac-sha256:11".into()),
            ..StateStatus::default()
        };
        assert_eq!(integrity_alarm(&st).unwrap().0, Severity::High);
        let st = StateStatus {
            journal_legacy_refused: true,
            ..StateStatus::default()
        };
        assert_eq!(integrity_alarm(&st).unwrap().0, Severity::Critical);
        // Review of gap 1: rejected notes and dropped entries are reported.
        let st = StateStatus {
            notes_rejected: 2,
            dropped_unbacked: 1,
            ..StateStatus::default()
        };
        let (sev, d) = integrity_alarm(&st).unwrap();
        assert_eq!(sev, Severity::High);
        assert!(
            d.contains("2 black-box note(s)") && d.contains("1 request journal"),
            "{d}"
        );
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-cp-anchor-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn v1_requests_journal(dir: &Path) {
        let json = serde_json::to_vec(&serde_json::json!(
            {"t": "header", "format": crate::control::journal::LEGACY_FORMAT, "kind": "requests"}
        ))
        .unwrap();
        let mut l =
            robodr_blackbox::crypto::to_hex(&robodr_blackbox::crypto::sha256(&json)).into_bytes();
        l.push(b' ');
        l.extend_from_slice(&json);
        l.push(b'\n');
        std::fs::write(dir.join(crate::control::state::REQUEST_JOURNAL), l).unwrap();
    }

    /// Review of gap 1, finding 3: a v1 journal is adopted only before the
    /// journals were ever sealed. Once the sealed marker exists it is a
    /// downgrade, even when the black box holds no head note any more (a
    /// cyclic store aged them out).
    #[test]
    fn v1_is_never_adopted_once_sealing_happened() {
        let key = crate::control::journal::tests::key();
        let d = tmp("v1-marker");
        v1_requests_journal(&d);
        let none = Found::default();
        let (s, marker) = sealing_for(&d, &none, key.clone());
        assert!(!marker && s.adopt_legacy, "first sealed start: the upgrade");
        let (_, r) = crate::control::state::open(&d, 16, &s).unwrap();
        assert!(r.upgraded_from_v1);
        write_sealed_marker(&d, &key).unwrap();
        // The v1 file put back; the black box knows of no head.
        v1_requests_journal(&d);
        let (s, marker) = sealing_for(&d, &none, key.clone());
        assert!(marker && !s.adopt_legacy);
        let (_, r) = crate::control::state::open(&d, 16, &s).unwrap();
        assert!(r.legacy_refused && !r.upgraded_from_v1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review of gap 1, finding 3: no head note but dropped segments: the
    /// journals are not taken as they are (Unanchored: fence and
    /// reconciliation).
    #[test]
    fn a_head_note_aged_out_of_the_black_box_is_not_no_anchor() {
        let key = crate::control::journal::tests::key();
        let d = tmp("aged-out");
        let aged = Found {
            segments_dropped: 3,
            ..Found::default()
        };
        assert!(aged.anchor_lost());
        let (s, _) = sealing_for(&d, &aged, key.clone());
        let (_, r) = crate::control::state::open(&d, 16, &s).unwrap();
        assert!(
            matches!(r.anchor, AnchorCheck::Unanchored(_)),
            "{:?}",
            r.anchor
        );
        assert!(r.untrusted());
        let (_, load) =
            crate::control::auth::ReplayGuard::persistent(&d, 30, 64, 1_000, &s).unwrap();
        assert!(matches!(load.anchor, AnchorCheck::Unanchored(_)));
        assert!(load.fence.is_some(), "the replay store is fenced");
        // A fresh black box (nothing dropped) is a first sealed start.
        let (s, _) = sealing_for(&d, &Found::default(), key);
        assert!(!s.anchor_lost);
        // Heads are re-recorded on a segment change even when unchanged.
        assert!(!head_note_due(false, Some(4), Some(4)));
        assert!(head_note_due(false, Some(4), Some(5)));
        assert!(head_note_due(true, Some(4), Some(4)));
        assert!(!head_note_due(false, Some(4), None));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review of gap 1, finding 5: the unreconciled-requests marker is
    /// sealed, survives a restart, and is removed once nothing is left.
    #[test]
    fn the_unreconciled_marker_is_sealed_and_kept_until_reconciled() {
        let key = crate::control::journal::tests::key();
        let d = tmp("unreconciled");
        assert_eq!(read_unreconciled(&d, &key).unwrap(), None);
        let u = Unreconciled {
            lost_ids: vec!["r-2".into(), "r-1".into()],
            refuse_new: Some("black box unreadable".into()),
        };
        write_unreconciled(&d, &key, &u).unwrap();
        let back = read_unreconciled(&d, &key).unwrap().unwrap();
        assert_eq!(back.lost_ids, ["r-1", "r-2"]);
        assert_eq!(back.refuse_new, u.refuse_new);
        // Edited: not believed.
        let p = d.join(UNRECONCILED_MARKER);
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replace("r-1", "r-9")).unwrap();
        assert!(read_unreconciled(&d, &key)
            .unwrap_err()
            .contains("does not verify"));
        // Nothing left: removed.
        write_unreconciled(&d, &key, &Unreconciled::default()).unwrap();
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn found_decides_the_anchors_and_the_upgrade() {
        let key = crate::control::journal::tests::key();
        let none = Found::default().sealing(key.clone());
        assert!(none.adopt_legacy && none.requests.is_none());
        let h = Head {
            generation: 2,
            seq: 5,
            tag: "ab".repeat(32),
        };
        let f = Found {
            heads: Some(StateHeads {
                requests: Some(h.clone()),
                nonces: None,
            }),
            clean: true,
            seen: 3,
            unverified: 1,
            segments_dropped: 0,
        };
        let s = f.sealing(key);
        assert!(!s.adopt_legacy, "sealing has started");
        assert_eq!(
            s.requests,
            Some(Anchor {
                head: h,
                clean: true
            })
        );
        assert_eq!(s.nonces, None);
        // The note round-trips into what `latest` parses.
        let n = head_note(
            "ugv-007",
            "stop",
            "hmac-sha256:00",
            &f.heads.clone().unwrap(),
        );
        assert_eq!(n["clean"], true);
        let back: StateHeads = serde_json::from_value(n).unwrap();
        assert_eq!(Some(back), f.heads);
    }
}
