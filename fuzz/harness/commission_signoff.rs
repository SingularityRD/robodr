//! Harness: operator sign-off parsing (`robodr_commission::Signoff`, read by
//! `robodr-commission lock --signoff FILE`) and `ops::lock` against a fixed
//! draft profile.
//!
//! Input: arbitrary bytes, tried as JSON. Invariants beyond "no panic":
//! `lock` succeeds only for a sign-off whose shape is valid, that is bound
//! to the draft's digest, names an operator and has every item confirmed;
//! a successful lock yields a locked profile.
#![allow(dead_code)]

use robodr_commission::signoff::draft_digest;
use robodr_commission::{lock, Signoff};
use robodr_events::profile::{Envelope, Profile};

/// The draft every sign-off is checked against (also used to build seeds).
pub fn draft() -> Profile {
    let mut p = Profile {
        model: "ugv-fuzz-x1".into(),
        ..Default::default()
    };
    p.participants.insert("01103f5a8c2e000000000101".into());
    p.participants.insert("01103f5a8c2e000000000102".into());
    p.writer_topics.insert("/cmd_vel".into());
    p.writer_topics.insert("/odom".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(0.5),
            max_joint_speed: None,
        },
    );
    p
}

pub fn run(data: &[u8]) {
    let Ok(so) = serde_json::from_slice::<Signoff>(data) else {
        return;
    };
    let shape = so.check_shape();
    let _ = so.to_string();
    let _ = so.unconfirmed().count();
    let p = draft();
    if let Ok(locked) = lock(&p, &so) {
        assert!(locked.locked, "lock returned an unlocked profile");
        assert_eq!(shape, Ok(()), "lock accepted a malformed sign-off");
        assert_eq!(
            so.profile_sha256,
            draft_digest(&p),
            "lock ignored the digest"
        );
        assert!(!so.operator.trim().is_empty(), "lock accepted no operator");
        assert_eq!(
            so.unconfirmed().count(),
            0,
            "lock accepted unconfirmed items"
        );
    }
}
