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

use std::io;

use robodr_blackbox::record::{scan_frames, signing_message, RecordKind, ScanItem};
use robodr_blackbox::Signer;
use robodr_events::Severity;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::evidence::SegmentSource;
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
}

impl Found {
    /// The sealing the control plane opens its journals with.
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
        }
    }
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
