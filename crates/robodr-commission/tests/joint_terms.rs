//! The joint-command envelope terms (`max_joint_torque`, `max_joint_kp`,
//! `max_joint_position_step`) through the profile file, lock, merge and
//! diff (review of the Unitree decoders, item 2).

use robodr_commission::ops::{diff, lockable_with_caps, merge_profiles, HardCaps, LockRefusal};
use robodr_commission::profile_file::parse_profile_text;
use robodr_events::profile::{Envelope, Profile};

fn profile(env: Envelope) -> Profile {
    let mut p = Profile {
        model: "g1".into(),
        ..Default::default()
    };
    p.participants.insert("aaaaaaaaaaaaaaaaaaaaaaaa".into());
    p.writer_topics.insert("/lowcmd".into());
    p.motion_envelopes.insert("/lowcmd".into(), env);
    p
}

fn joint_env(tau: f64) -> Envelope {
    Envelope {
        max_joint_speed: Some(2.0),
        max_joint_torque: Some(tau),
        max_joint_kp: Some(100.0),
        max_joint_position_step: Some(0.05),
        ..Default::default()
    }
}

#[test]
fn profile_file_accepts_the_joint_terms() {
    let p = profile(joint_env(20.0));
    let text = serde_json::to_string_pretty(&p).unwrap();
    assert!(text.contains("max_joint_torque"));
    let back = parse_profile_text(&text).unwrap();
    assert_eq!(back.motion_envelopes["/lowcmd"], joint_env(20.0));
    // A non-number is refused like any limit.
    let bad = text.replace("\"max_joint_kp\": 100.0", "\"max_joint_kp\": \"x\"");
    assert_ne!(bad, text);
    assert!(parse_profile_text(&bad).is_err());
}

#[test]
fn lock_refuses_a_joint_term_above_its_hard_cap() {
    let caps = HardCaps::default();
    assert!(lockable_with_caps(&profile(joint_env(20.0)), &caps).is_empty());
    let why = lockable_with_caps(&profile(joint_env(caps.torque * 2.0)), &caps);
    assert!(
        why.iter().any(|w| matches!(
            w,
            LockRefusal::ExceedsHardCap { dimension, .. } if dimension == "joint_torque"
        )),
        "{why:?}"
    );
    let mut nan = joint_env(20.0);
    nan.max_joint_kp = Some(f64::NAN);
    let why = lockable_with_caps(&profile(nan), &caps);
    assert!(
        why.iter().any(|w| matches!(
            w,
            LockRefusal::InvalidBound { dimension, .. } if dimension == "joint_kp"
        )),
        "{why:?}"
    );
}

#[test]
fn merge_and_diff_carry_the_joint_terms() {
    let a = profile(joint_env(20.0));
    let b = profile(joint_env(30.0));
    let m = merge_profiles(&[a.clone(), b.clone()]).unwrap();
    assert_eq!(m.motion_envelopes["/lowcmd"].max_joint_torque, Some(30.0));
    let d = diff(&a, &b);
    assert!(
        d.envelope_changes
            .iter()
            .any(|c| c.dimension == "joint_torque"),
        "{d}"
    );
    assert!(d.to_string().contains("joint_torque"), "{d}");
}
