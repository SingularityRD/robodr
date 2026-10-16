//! Harness: strict profile-file parsing (`robodr_commission::parse_profile_text`,
//! the check the sensor and the commissioning tool run on every profile
//! file) and the lock path built on it.
//!
//! Input: arbitrary bytes, tried as UTF-8. Invariants beyond "no panic":
//!
//! * an accepted *locked* file re-seals to a text that is accepted again
//!   (`sealed_text` and `parse_profile_text` agree on the seal);
//! * an accepted *draft* locked with a fully confirmed conservative sign-off
//!   (`ops::lock`) yields a locked profile whose sealed text is accepted;
//! * a profile accepted as locked also passes `Profile::validate`.
#![allow(dead_code)]

use robodr_commission::{lock, parse_profile_text, sealed_text, Signoff};

pub fn run(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(p) = parse_profile_text(text) else {
        return;
    };
    if p.locked {
        assert!(
            p.validate().is_ok(),
            "locked profile accepted without validating"
        );
        let sealed = sealed_text(&p).expect("sealed_text of an accepted profile");
        let back = parse_profile_text(&sealed)
            .unwrap_or_else(|e| panic!("re-sealed profile refused: {e}\n{sealed}"));
        assert!(back.locked);
        assert_eq!(back.participants, p.participants);
        assert_eq!(back.metadata, p.metadata, "metadata lost by re-sealing");
        // The trust check never panics and never trusts a locked profile
        // without trust anchors.
        let r = robodr_commission::verify_profile_text(
            text,
            Some(text),
            "fuzz.sig",
            &robodr_commission::TrustPolicy::default(),
        );
        assert!(r.is_err(), "locked profile trusted without anchors");
    } else {
        let so = Signoff::for_profile(&p).confirm_all("fuzz-operator");
        assert_eq!(
            so.check_shape(),
            Ok(()),
            "conservative sign-off is malformed"
        );
        if let Ok(locked) = lock(&p, &so) {
            assert!(locked.locked);
            let sealed = sealed_text(&locked).expect("sealed_text of a locked profile");
            if let Err(e) = parse_profile_text(&sealed) {
                panic!("lock() produced a profile file that is refused: {e}\n{sealed}");
            }
        }
    }
}
