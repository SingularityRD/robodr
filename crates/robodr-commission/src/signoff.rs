//! Operator sign-off: the confirmation list a human must work through
//! before a draft profile can be locked.
//!
//! # Why
//!
//! Commissioning learns "whatever was on the bus" as normal. An attacker (or
//! a forgotten laptop running `ros2 topic pub`) present during the clean run
//! would be baked into the allowlist. The learner already refuses to learn
//! what it cannot justify (see `learner`: quarantined participants, caps,
//! unattributed samples), but some things it must learn and a human must
//! still look at: who is allowed to command motion, participants that
//! appeared late or only briefly, participants seen from several IPs, thin
//! motion statistics, capacity overflow during the run.
//!
//! # How
//!
//! `learn` writes, next to the draft profile, a [`Signoff`] file listing
//! those items, each `"confirmed": false`, bound to the exact draft bytes by
//! SHA-256 (`profile_sha256`). The operator reviews each item, sets
//! `"confirmed": true` and fills `"operator"`. [`crate::ops::lock`] refuses
//! unless the sign-off belongs to this draft (same model, same digest),
//! names an operator and confirms every item.
//!
//! # The item set is bound too
//!
//! Confirming every item is meaningless if items can simply be deleted.
//! Two independent checks stop that at lock:
//!
//! * `items_sha256` is the SHA-256 of the draft digest plus every item's id
//!   and reason ([`items_digest`]), computed when the list is generated.
//!   `lock` recomputes it from the items present: a deleted, added or
//!   reworded item is refused (`SignoffItemsTampered`). Only `confirmed` and
//!   `operator` are outside the digest; they are what the operator edits.
//! * A floor recomputed from the draft alone ([`required_items`]): every
//!   motion channel of the draft must be covered by a confirmed item that
//!   names it (`motion_writer`, `motion_unattributed` or
//!   `motion_channel_unreviewed`), whatever the list says.
//!
//! A draft edited by hand or produced by `merge` no longer matches its
//! learned sign-off. [`Signoff::for_profile`] then builds a conservative
//! list from the profile alone (every participant and every motion channel
//! must be confirmed), because the learner's provenance is gone.
//!
//! # Limits
//!
//! The sign-off is an integrity and process control, not authentication:
//! anyone who can write the files can also write `"confirmed": true`, or
//! recompute `items_sha256` after deleting items (it is a plain hash, not a
//! signature). It forces a named human decision on every risky item and
//! makes a silent skip impossible; it cannot stop a careless or malicious
//! operator.

use crate::to_json;
use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_events::profile::Profile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Value of [`Signoff::format`].
pub const SIGNOFF_FORMAT: &str = "robodr-commission-signoff/1";

/// One item a human must confirm.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignoffItem {
    /// Stable id, `<kind>:<subject>`; unique within a sign-off.
    pub id: String,
    /// e.g. `motion_writer`, `participant_late`.
    pub kind: String,
    pub subject: String,
    /// Why a human must look at it.
    pub reason: String,
    /// Set to `true` by the operator after review.
    pub confirmed: bool,
}

impl SignoffItem {
    pub fn new(kind: &str, subject: &str, reason: impl Into<String>) -> Self {
        Self {
            id: format!("{kind}:{subject}"),
            kind: kind.into(),
            subject: subject.into(),
            reason: reason.into(),
            confirmed: false,
        }
    }
}

/// The confirmation list for one draft profile. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signoff {
    /// Always [`SIGNOFF_FORMAT`].
    pub format: String,
    pub model: String,
    /// Lower-case hex SHA-256 of the draft profile file bytes
    /// ([`draft_digest`]).
    pub profile_sha256: String,
    /// [`items_digest`] of `profile_sha256` and the items as generated:
    /// binds the item set (see the module docs).
    pub items_sha256: String,
    /// Who reviewed it; must be non-empty to lock.
    pub operator: String,
    /// Sorted by id, ids unique.
    pub items: Vec<SignoffItem>,
}

/// SHA-256 (hex) of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&sha256(bytes))
}

/// Digest of the item set: SHA-256 over a domain tag, `profile_sha256` and
/// every item's `(id, reason)`, sorted by id (so reordering the file does
/// not matter, but deleting, adding or rewording an item does).
pub fn items_digest(profile_sha256: &str, items: &[SignoffItem]) -> String {
    let mut by_id: Vec<(&str, &str)> = items
        .iter()
        .map(|i| (i.id.as_str(), i.reason.as_str()))
        .collect();
    by_id.sort_unstable();
    // JSON encoding keeps the framing unambiguous whatever the strings hold.
    let body = serde_json::to_string(&("robodr-commission-signoff-items/1", profile_sha256, by_id))
        .unwrap_or_default();
    sha256_hex(body.as_bytes())
}

/// Item kinds that count as a review of a motion channel for the floor
/// ([`required_items`]).
pub const MOTION_REVIEW_KINDS: [&str; 3] = [
    "motion_writer",
    "motion_unattributed",
    "motion_channel_unreviewed",
];

/// What every sign-off for `profile` must contain, confirmed, whatever list
/// was generated: one item per motion channel `ch` whose kind is in
/// [`MOTION_REVIEW_KINDS`] and whose subject is `ch` or starts with
/// `"<ch> "`. Returns `(channel, why)` for each requirement.
pub fn required_items(profile: &Profile) -> Vec<(String, String)> {
    profile
        .motion_envelopes
        .keys()
        .map(|ch| {
            (
                ch.clone(),
                format!(
                    "motion channel {ch} is in the draft, so a confirmed review of who may \
                     command it ({}) is required",
                    MOTION_REVIEW_KINDS.join(" / ")
                ),
            )
        })
        .collect()
}

/// Does `item` (confirmed) satisfy the floor requirement for `channel`?
pub fn covers(item: &SignoffItem, channel: &str) -> bool {
    item.confirmed
        && MOTION_REVIEW_KINDS.contains(&item.kind.as_str())
        && (item.subject == channel
            || item
                .subject
                .strip_prefix(channel)
                .is_some_and(|rest| rest.starts_with(' ')))
}

/// Digest that binds a sign-off to a draft: SHA-256 of the exact bytes the
/// draft is written as ([`crate::to_json`]).
pub fn draft_digest(profile: &Profile) -> String {
    // Serialising a Profile cannot fail (no maps with non-string keys, and
    // serde_json writes non-finite floats as null).
    sha256_hex(to_json(profile).unwrap_or_default().as_bytes())
}

impl Signoff {
    /// A sign-off for `profile` with the given items (deduplicated by id,
    /// sorted, all unconfirmed).
    pub fn new(profile: &Profile, items: impl IntoIterator<Item = SignoffItem>) -> Self {
        let mut by_id: BTreeMap<String, SignoffItem> = BTreeMap::new();
        for it in items {
            by_id.entry(it.id.clone()).or_insert(it);
        }
        let mut s = Self {
            format: SIGNOFF_FORMAT.into(),
            model: profile.model.clone(),
            profile_sha256: String::new(),
            items_sha256: String::new(),
            operator: String::new(),
            items: by_id.into_values().collect(),
        };
        s.rebind(draft_digest(profile));
        s
    }

    /// Bind the list to other draft bytes (e.g. a hand-edited file whose
    /// bytes differ from the canonical form) and re-seal the item set.
    pub fn rebind(&mut self, profile_sha256: String) {
        self.profile_sha256 = profile_sha256;
        self.items_sha256 = items_digest(&self.profile_sha256, &self.items);
    }

    /// Does `items_sha256` match the items present?
    pub fn items_intact(&self) -> bool {
        self.items_sha256 == items_digest(&self.profile_sha256, &self.items)
    }

    /// Conservative sign-off built from a profile alone (hand-edited or
    /// merged drafts): every participant and every motion channel must be
    /// confirmed individually.
    pub fn for_profile(profile: &Profile) -> Self {
        let mut items = Vec::new();
        for g in &profile.participants {
            items.push(SignoffItem::new(
                "participant_unreviewed",
                g,
                "provenance unknown (edited or merged draft): confirm this participant belongs \
                 on the robot",
            ));
        }
        for (ch, env) in &profile.motion_envelopes {
            items.push(SignoffItem::new(
                "motion_channel_unreviewed",
                ch,
                "provenance unknown (edited or merged draft): confirm this motion channel, its \
                 envelope and every participant allowed to write it",
            ));
            for (dim, b) in [
                ("linear", env.max_linear_speed),
                ("joint", env.max_joint_speed),
            ] {
                if b.is_none() {
                    items.push(SignoffItem::new(
                        "envelope_dimension_unbounded",
                        &format!("{ch} {dim}"),
                        format!(
                            "{ch} has no {dim} bound (null = unlimited): confirm that {dim} \
                             commands on it must not be limited, or set a bound"
                        ),
                    ));
                }
            }
        }
        Self::new(profile, items)
    }

    /// Items not yet confirmed.
    pub fn unconfirmed(&self) -> impl Iterator<Item = &SignoffItem> {
        self.items.iter().filter(|i| !i.confirmed)
    }

    /// Mark everything confirmed by `operator`. For tests and for callers
    /// that collected the confirmations through their own UI; the CLI never
    /// does this on its own.
    pub fn confirm_all(mut self, operator: &str) -> Self {
        self.operator = operator.into();
        for i in &mut self.items {
            i.confirmed = true;
        }
        self
    }

    /// Structural problems (format, duplicate ids). Content checks against a
    /// profile are in [`crate::ops::lock`].
    pub fn check_shape(&self) -> Result<(), String> {
        if self.format != SIGNOFF_FORMAT {
            return Err(format!(
                "sign-off format {:?} is not {SIGNOFF_FORMAT:?}",
                self.format
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for i in &self.items {
            if !seen.insert(i.id.as_str()) {
                return Err(format!("sign-off item id {:?} appears twice", i.id));
            }
            if i.id != format!("{}:{}", i.kind, i.subject) {
                return Err(format!(
                    "sign-off item id {:?} does not match its kind/subject",
                    i.id
                ));
            }
        }
        for (name, v) in [
            ("profile_sha256", &self.profile_sha256),
            ("items_sha256", &self.items_sha256),
        ] {
            if v.len() != 64 || !v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(format!("sign-off {name} is not 64 lower-case hex chars"));
            }
        }
        Ok(())
    }
}

impl fmt::Display for Signoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Operator sign-off required ({} item(s), {} unconfirmed):",
            self.items.len(),
            self.unconfirmed().count()
        )?;
        for i in &self.items {
            writeln!(
                f,
                "  [{}] {}: {}",
                if i.confirmed { "x" } else { " " },
                i.id,
                i.reason
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::profile::Envelope;

    fn prof() -> Profile {
        let mut p = Profile {
            model: "m".into(),
            ..Default::default()
        };
        p.participants.insert("a".repeat(24));
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(1.0),
                max_joint_speed: None,
            },
        );
        p
    }

    #[test]
    fn conservative_signoff_lists_everything_unconfirmed() {
        let s = Signoff::for_profile(&prof());
        // participant, motion channel, and the unbounded joint dimension.
        assert_eq!(s.items.len(), 3);
        assert_eq!(s.unconfirmed().count(), 3);
        assert!(s
            .items
            .iter()
            .any(|i| i.id == "envelope_dimension_unbounded:/cmd_vel joint"));
        assert!(s.items_intact());
        assert!(s.operator.is_empty());
        assert_eq!(s.check_shape(), Ok(()));
        assert_eq!(s.profile_sha256, draft_digest(&prof()));
        let c = s.clone().confirm_all("alice");
        assert_eq!(c.unconfirmed().count(), 0);
        assert!(s.to_string().contains("[ ] participant_unreviewed:"));
        assert!(c.to_string().contains("[x]"));
    }

    #[test]
    fn duplicate_ids_are_merged_and_sorted() {
        let s = Signoff::new(
            &prof(),
            [
                SignoffItem::new("b", "x", "1"),
                SignoffItem::new("a", "y", "2"),
                SignoffItem::new("b", "x", "3"),
            ],
        );
        assert_eq!(
            s.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["a:y", "b:x"]
        );
        assert_eq!(s.items[1].reason, "1");
    }

    #[test]
    fn shape_errors() {
        let good = Signoff::for_profile(&prof());
        let mut s = good.clone();
        s.format = "v0".into();
        assert!(s.check_shape().is_err());
        let mut s = good.clone();
        s.items.push(s.items[0].clone());
        assert!(s.check_shape().unwrap_err().contains("twice"));
        let mut s = good.clone();
        s.items[0].subject = "other".into();
        assert!(s.check_shape().is_err());
        let mut s = good.clone();
        s.profile_sha256 = "ABC".into();
        assert!(s.check_shape().is_err());
        // Unknown fields are rejected on parse (no silent typos such as
        // "confirmd": true).
        let j = serde_json::to_string(&good)
            .unwrap()
            .replace("\"confirmed\":false", "\"confirmd\":true");
        assert!(serde_json::from_str::<Signoff>(&j).is_err());
    }

    #[test]
    fn item_set_is_bound_by_digest() {
        let s = Signoff::for_profile(&prof()).confirm_all("op");
        // Confirming and naming the operator do not touch the digest.
        assert!(s.items_intact());
        let mut del = s.clone();
        del.items.pop();
        assert!(!del.items_intact());
        let mut add = s.clone();
        let mut extra = SignoffItem::new("x", "y", "z");
        extra.confirmed = true;
        add.items.push(extra);
        assert!(!add.items_intact());
        let mut reword = s.clone();
        reword.items[0].reason = "fine".into();
        assert!(!reword.items_intact());
        // Reordering the file is harmless.
        let mut rev = s.clone();
        rev.items.reverse();
        assert!(rev.items_intact());
        // Rebinding to other bytes re-seals; a bare digest swap does not.
        let mut swapped = s.clone();
        swapped.profile_sha256 = "0".repeat(64);
        assert!(!swapped.items_intact());
        let mut rebound = s.clone();
        rebound.rebind("0".repeat(64));
        assert!(rebound.items_intact());
        // Shape: items_sha256 must be hex.
        let mut bad = s.clone();
        bad.items_sha256 = "zz".into();
        assert!(bad.check_shape().unwrap_err().contains("items_sha256"));
        // Ids/reasons with framing characters cannot collide.
        let a = items_digest("d", &[SignoffItem::new("k", "a\",b", "r")]);
        let b = items_digest("d", &[SignoffItem::new("k", "a", "b\",r")]);
        assert_ne!(a, b);
    }

    #[test]
    fn floor_requires_a_review_per_motion_channel() {
        let req = required_items(&prof());
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].0, "/cmd_vel");
        let mut it = SignoffItem::new("motion_writer", "/cmd_vel aaaa", "r");
        assert!(!covers(&it, "/cmd_vel"), "unconfirmed does not cover");
        it.confirmed = true;
        assert!(covers(&it, "/cmd_vel"));
        // Prefix of another channel name does not count.
        assert!(!covers(&it, "/cmd"));
        let mut other = SignoffItem::new("participant_late", "/cmd_vel", "r");
        other.confirmed = true;
        assert!(!covers(&other, "/cmd_vel"), "wrong kind");
        let mut exact = SignoffItem::new("motion_channel_unreviewed", "/cmd_vel", "r");
        exact.confirmed = true;
        assert!(covers(&exact, "/cmd_vel"));
    }
}
