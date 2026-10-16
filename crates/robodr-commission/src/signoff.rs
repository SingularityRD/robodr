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
//! A draft edited by hand or produced by `merge` no longer matches its
//! learned sign-off. [`Signoff::for_profile`] then builds a conservative
//! list from the profile alone (every participant and every motion channel
//! must be confirmed), because the learner's provenance is gone.
//!
//! # Limits
//!
//! The sign-off is an integrity and process control, not authentication:
//! anyone who can write the files can also write `"confirmed": true`. It
//! forces a named human decision on every risky item and makes a silent
//! skip impossible; it cannot stop a careless or malicious operator.

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
    /// Who reviewed it; must be non-empty to lock.
    pub operator: String,
    /// Sorted by id, ids unique.
    pub items: Vec<SignoffItem>,
}

/// SHA-256 (hex) of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&sha256(bytes))
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
        Self {
            format: SIGNOFF_FORMAT.into(),
            model: profile.model.clone(),
            profile_sha256: draft_digest(profile),
            operator: String::new(),
            items: by_id.into_values().collect(),
        }
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
        for ch in profile.motion_envelopes.keys() {
            items.push(SignoffItem::new(
                "motion_channel_unreviewed",
                ch,
                "provenance unknown (edited or merged draft): confirm this motion channel, its \
                 envelope and every participant allowed to write it",
            ));
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
        if self.profile_sha256.len() != 64
            || !self
                .profile_sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err("sign-off profile_sha256 is not 64 lower-case hex chars".into());
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
        assert_eq!(s.items.len(), 2);
        assert_eq!(s.unconfirmed().count(), 2);
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
}
