//! Draft Motion Firewall channel file from a commissioning run
//! (`robodr-commission firewall-draft`).
//!
//! The gateway's `firewall.json` (`robodr_firewall::FirewallConfig`) was
//! written by hand: envelopes copied from the profile, writer GUIDs copied
//! from a capture. This module derives the Twist channel specs from what
//! commissioning learned, so the file starts consistent with the profile
//! it will be compiled against:
//!
//! * one [`ChannelSpec`] per profiled Twist motion channel (by the learned
//!   DDS type name, else by its envelope shape: a linear bound and no joint
//!   bound);
//! * `max_linear_speed`: the profile envelope, lowered to the OEM ceiling
//!   (`ceiling_linear`) when that is lower: the firewall can only tighten.
//!   An envelope without a linear bound takes the ceiling; without either
//!   the channel is reported missing (never drafted unlimited);
//! * `max_angular_speed`: the OEM's yaw-rate ceiling (`max_angular`,
//!   required: the profile has no angular dimension);
//! * `allowed_sources`: the writers the run observed commanding the channel
//!   ([`crate::CommissioningReport`] `motion_channels[ch].sources`), minus
//!   excluded ones, kept only when their participant prefix is profiled
//!   (exactly what `Policy::compile` accepts).
//!
//! What cannot be learned is reported, not invented: low-level joint
//! channels (per-motor tables from the OEM data sheet), joint-velocity
//! channels (joint count), channels without an observed source and Twist
//! channels with no linear limit at all (no envelope bound, no ceiling). The
//! draft is then **incomplete**, does not compile against the profile, and
//! `bind` refuses it until the OEM completes it.
//!
//! The draft is a proposal for review. It becomes authoritative only when
//! it is bound into the profile (`bind --motion-firewall`), confirmed by
//! the motion quorum and locked (see `trust::bound`).

use crate::learner::CommissioningReport;
use robodr_events::profile::Profile;
use robodr_firewall::{ChannelSpec, FirewallConfig, PlatformConfig};
use std::collections::BTreeSet;

/// OEM inputs of [`draft_firewall`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DraftOptions {
    /// Yaw-rate ceiling for every Twist channel (rad/s, finite, >= 0).
    pub max_angular: f64,
    /// Optional linear ceiling (m/s); the spec takes the lower of it and
    /// the envelope.
    pub ceiling_linear: Option<f64>,
    pub platform: PlatformConfig,
}

/// The draft and what the OEM still has to do.
#[derive(Debug, Clone, PartialEq)]
pub struct FirewallDraft {
    pub config: FirewallConfig,
    /// Channels the draft could not specify (the file is incomplete while
    /// this is non-empty).
    pub missing: Vec<String>,
    /// Review notes (sources dropped, ceilings applied).
    pub notes: Vec<String>,
}

fn is_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Is `ch` a Twist channel of `profile`?
fn is_twist(profile: &Profile, ch: &str) -> bool {
    match profile.motion_types.get(ch) {
        Some(t) => {
            let t = t.as_str();
            t.contains("geometry_msgs::msg::dds_::Twist")
        }
        None => profile
            .motion_envelopes
            .get(ch)
            .is_some_and(|e| e.max_linear_speed.is_some() && e.max_joint_speed.is_none()),
    }
}

/// Build the draft (see the module docs). Errors only on bad options; an
/// incomplete draft is a successful result with `missing` non-empty.
pub fn draft_firewall(
    profile: &Profile,
    report: &CommissioningReport,
    opts: &DraftOptions,
) -> Result<FirewallDraft, String> {
    if !opts.max_angular.is_finite() || opts.max_angular < 0.0 {
        return Err("the angular ceiling must be finite and >= 0 (rad/s)".into());
    }
    if let Some(c) = opts.ceiling_linear {
        if !c.is_finite() || c < 0.0 {
            return Err("the linear ceiling must be finite and >= 0 (m/s)".into());
        }
    }
    if report.model != profile.model {
        return Err(format!(
            "the report is for model {:?}, the profile is {:?}",
            report.model, profile.model
        ));
    }
    let mut out = FirewallDraft {
        config: FirewallConfig {
            platform: opts.platform,
            ..Default::default()
        },
        missing: Vec::new(),
        notes: Vec::new(),
    };
    for (ch, env) in &profile.motion_envelopes {
        if !is_twist(profile, ch) {
            out.missing.push(format!(
                "{ch}: not a Twist channel ({}): add its spec by hand (joint_channels for \
                 low-level frames: per-motor limits from the OEM data sheet; channels with kind \
                 joints: the joint count)",
                profile
                    .motion_types
                    .get(ch)
                    .map_or("type unknown", String::as_str)
            ));
            continue;
        }
        let excluded: BTreeSet<&str> = report
            .motion_channels
            .get(ch)
            .map(|m| m.excluded_sources.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let mut sources = Vec::new();
        for src in report
            .motion_channels
            .get(ch)
            .map(|m| m.sources.iter())
            .into_iter()
            .flatten()
        {
            let profiled = (src.len() == 24 || src.len() == 32)
                && is_hex(src)
                && src
                    .get(..24)
                    .is_some_and(|p| profile.participants.contains(p));
            if excluded.contains(src.as_str()) || !profiled {
                out.notes.push(format!(
                    "{ch}: observed source {src:?} not allowed (excluded during the run, or not \
                     a writer GUID of a profiled participant)"
                ));
                continue;
            }
            sources.push(src.clone());
        }
        if sources.is_empty() {
            out.missing.push(format!(
                "{ch}: no observed writer of a profiled participant: add allowed_sources by hand \
                 (endpoint GUIDs or identity:<name>)"
            ));
            continue;
        }
        if !profile.participant_identities.is_empty() {
            out.notes.push(format!(
                "{ch}: allowed_sources are the GUIDs of the commissioning run; DDS draws new \
                 ones per process start, consider identity:<name> entries"
            ));
        }
        let linear = match (env.max_linear_speed, opts.ceiling_linear) {
            (Some(e), Some(c)) if c < e => {
                out.notes.push(format!(
                    "{ch}: linear bound lowered from the envelope {e} to the OEM ceiling {c} m/s"
                ));
                c
            }
            (Some(e), _) => e,
            (None, Some(c)) => {
                out.notes.push(format!(
                    "{ch}: the envelope has no linear bound: the OEM ceiling {c} m/s is the limit"
                ));
                c
            }
            (None, None) => {
                // Review WP6: never draft an unlimited linear speed.
                out.missing.push(format!(
                    "{ch}: the profile envelope has no linear bound and no --ceiling-linear was \
                     given: set max_linear_speed by hand or pass the OEM's linear ceiling"
                ));
                continue;
            }
        };
        out.config.channels.insert(
            ch.clone(),
            ChannelSpec {
                allowed_sources: sources,
                max_linear_speed: Some(linear),
                max_angular_speed: Some(opts.max_angular),
                ..ChannelSpec::default()
            },
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LearnConfig, Learner};
    use robodr_events::graph::{Endpoint, Participant};
    use robodr_events::{MotionCommand, RobotEvent};

    const P: &str = "0102030405060708090a0b0c";

    fn learned() -> (Profile, CommissioningReport) {
        let mut l = Learner::new(LearnConfig {
            model: "ugv".into(),
            min_participant_announcements: 1,
            ..LearnConfig::default()
        })
        .unwrap();
        for _ in 0..3 {
            l.observe(&RobotEvent::Ros2ParticipantDiscovered(Participant {
                guid_prefix: P.into(),
                src_ip: "10.0.0.1".into(),
                locators: vec![],
            }));
        }
        l.observe(&RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: P.into(),
            topic: "rt/cmd_vel".into(),
            type_name: "geometry_msgs::msg::dds_::Twist_".into(),
        }));
        for i in 0..40 {
            l.observe(&RobotEvent::MotionCommand(MotionCommand {
                channel: "/cmd_vel".into(),
                source_guid: Some(P.into()),
                linear_speed: Some(0.5 + f64::from(i) * 0.01),
                ..Default::default()
            }));
        }
        let c = l.finish();
        (c.profile, c.report)
    }

    fn opts() -> DraftOptions {
        DraftOptions {
            max_angular: 1.2,
            ceiling_linear: None,
            platform: PlatformConfig::default(),
        }
    }

    #[test]
    fn draft_compiles_against_the_profile_it_came_from() {
        let (p, r) = learned();
        let d = draft_firewall(&p, &r, &opts()).unwrap();
        assert!(d.missing.is_empty(), "{:?}", d.missing);
        let spec = &d.config.channels["/cmd_vel"];
        assert_eq!(spec.allowed_sources, vec![P.to_string()]);
        assert_eq!(spec.max_angular_speed, Some(1.2));
        assert_eq!(
            spec.max_linear_speed,
            p.motion_envelopes["/cmd_vel"].max_linear_speed
        );
        d.config.compile(&p).unwrap();
    }

    #[test]
    fn ceiling_tightens_and_foreign_sources_are_dropped() {
        let (p, mut r) = learned();
        r.motion_channels
            .get_mut("/cmd_vel")
            .unwrap()
            .sources
            .insert("ffffffffffffffffffffffff".into());
        let d = draft_firewall(
            &p,
            &r,
            &DraftOptions {
                ceiling_linear: Some(0.1),
                ..opts()
            },
        )
        .unwrap();
        let spec = &d.config.channels["/cmd_vel"];
        assert_eq!(spec.max_linear_speed, Some(0.1));
        assert_eq!(spec.allowed_sources.len(), 1);
        assert!(
            d.notes.iter().any(|n| n.contains("ffffffff")),
            "{:?}",
            d.notes
        );
    }

    /// Review (WP6): a Twist channel whose envelope has no linear bound
    /// was drafted with `max_linear_speed: None` (unlimited) when no
    /// ceiling was given, and not reported.
    #[test]
    fn a_twist_channel_without_any_linear_limit_is_incomplete() {
        let (mut p, r) = learned();
        assert!(p.motion_types["/cmd_vel"].contains("Twist"));
        p.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_linear_speed = None;
        let d = draft_firewall(&p, &r, &opts()).unwrap();
        assert!(d.config.channels.is_empty(), "{:?}", d.config.channels);
        assert_eq!(d.missing.len(), 1);
        assert!(d.missing[0].contains("--ceiling-linear"), "{:?}", d.missing);
        assert!(d.config.compile(&p).is_err());
        // With the OEM ceiling it is the limit.
        let d = draft_firewall(
            &p,
            &r,
            &DraftOptions {
                ceiling_linear: Some(0.7),
                ..opts()
            },
        )
        .unwrap();
        assert!(d.missing.is_empty(), "{:?}", d.missing);
        assert_eq!(d.config.channels["/cmd_vel"].max_linear_speed, Some(0.7));
    }

    #[test]
    fn what_cannot_be_learned_is_reported_not_invented() {
        let (mut p, r) = learned();
        p.motion_types
            .insert("/cmd_vel".into(), "unitree_go::msg::dds_::LowCmd_".into());
        let d = draft_firewall(&p, &r, &opts()).unwrap();
        assert!(d.config.channels.is_empty());
        assert_eq!(d.missing.len(), 1);
        assert!(d.config.compile(&p).is_err());
        assert!(draft_firewall(
            &p,
            &r,
            &DraftOptions {
                max_angular: f64::NAN,
                ..opts()
            }
        )
        .is_err());
    }
}
