//! Harness: Motion Firewall policy configuration from a profile JSON and
//! the decision core behind it.
//!
//! The firewall crate itself has no file format: its policy is compiled
//! from the model profile (JSON, parsed by the agent with
//! `robodr_agent::strict_from_str`) plus per-channel specs derived by
//! `robodr_agent::FirewallSettings::from_profile`. This harness drives that
//! exact path, then `Policy::compile`, then `Firewall::check` with a
//! command stream decoded from the rest of the input.
//!
//! Input: `profile JSON` `0x00` `command bytes`. Each command is
//! [`CMD_LEN`] bytes: channel index, source index, flags, a signed stamp
//! offset (i32 LE, ms), a clock step (u16 LE, ms) and three f64 LE values
//! (any bit pattern: NaN, infinities, subnormals). Indices past the policy
//! hit unknown channels/sources. Twist channels get `max_angular = 1 rad/s`.
//!
//! Invariants beyond "no panic": an enforcing firewall never forwards a
//! non-finite command; anything forwarded stays on the input's channel; an
//! observe-only firewall forwards every command on a known channel
//! unchanged; the event buffer stays within its capacity.
#![allow(dead_code)]

use std::collections::BTreeMap;

use robodr_agent::{strict_from_str, FirewallSettings};
use robodr_events::profile::Profile;
use robodr_firewall::{
    ChannelId, ChannelKind, Command, Firewall, JointVelocities, Policy, SourceId, Twist, Vec3,
    Verdict,
};

pub const CMD_LEN: usize = 3 + 4 + 2 + 24;

fn f64_at(b: &[u8], at: usize) -> f64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    f64::from_le_bytes(a)
}

/// Encode one command (seed generation).
pub fn encode_cmd(
    chan: u8,
    src: u8,
    flags: u8,
    stamp_ms: i32,
    step_ms: u16,
    v: [f64; 3],
) -> Vec<u8> {
    let mut o = vec![chan, src, flags];
    o.extend_from_slice(&stamp_ms.to_le_bytes());
    o.extend_from_slice(&step_ms.to_le_bytes());
    for x in v {
        o.extend_from_slice(&x.to_le_bytes());
    }
    o
}

pub fn run(data: &[u8]) {
    let (json, cmds) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let Ok(text) = std::str::from_utf8(json) else {
        return;
    };
    let Ok(profile) = strict_from_str::<Profile>(text) else {
        return;
    };
    // FirewallSettings::from_profile's own kind rule.
    let angular: BTreeMap<String, f64> = profile
        .motion_envelopes
        .iter()
        .filter(|(_, e)| e.max_linear_speed.is_some() || e.max_joint_speed.is_none())
        .map(|(c, _)| (c.clone(), 1.0))
        .collect();
    let Ok(fs) = FirewallSettings::from_profile(&profile, &BTreeMap::new(), &angular) else {
        return;
    };
    let Ok(policy) = Policy::compile(&profile, fs.platform, &fs.channels) else {
        return;
    };
    assert_eq!(policy.profile_locked(), profile.locked);
    let names: Vec<String> = fs.channels.keys().cloned().collect();
    let kinds: Vec<ChannelKind> = fs.channels.values().map(|c| c.kind).collect();
    let mut guids: Vec<String> = fs
        .channels
        .values()
        .flat_map(|c| c.allowed_sources.iter().cloned())
        .collect();
    guids.sort();
    guids.dedup();
    let mut fw = Firewall::new(policy);
    let enforcing = fw.is_enforcing();
    let cap = fw.events().capacity();

    let mut now: u64 = 1_000_000_000_000;
    for c in cmds.chunks_exact(CMD_LEN) {
        let ci = usize::from(c[0]) % (names.len() + 1);
        let si = usize::from(c[1]) % (guids.len() + 1);
        let flags = c[2];
        let stamp_off = i64::from(i32::from_le_bytes([c[3], c[4], c[5], c[6]])) * 1_000_000;
        now = now.saturating_add(u64::from(u16::from_le_bytes([c[7], c[8]])) * 1_000_000);
        let stamp = now.saturating_add_signed(stamp_off);
        let v = [f64_at(c, 9), f64_at(c, 17), f64_at(c, 25)];

        let channel = names
            .get(ci)
            .and_then(|n| fw.channel_id(n))
            .unwrap_or(ChannelId(u16::MAX));
        let source = guids
            .get(si)
            .and_then(|g| fw.source_id(g))
            .unwrap_or(SourceId::UNKNOWN);
        let joints = match kinds.get(ci) {
            Some(ChannelKind::Joints { .. }) => flags & 1 == 0,
            _ => flags & 1 == 1,
        };
        let cmd = if joints {
            let n = usize::from(flags >> 1) % 4;
            Command::joints(
                source,
                channel,
                stamp,
                JointVelocities::from_slice(&v[..n.min(3)]).expect("<= 3 joints"),
            )
        } else {
            Command::twist(
                source,
                channel,
                stamp,
                Twist::new(Vec3::new(v[0], v[1], 0.0), Vec3::new(0.0, 0.0, v[2])),
            )
        };
        let verdict = if flags & 0x80 != 0 {
            fw.fault_verdict(&cmd, now)
        } else {
            fw.check(&cmd, now)
        };
        if let Some(out) = verdict.output() {
            assert_eq!(out.channel, cmd.channel, "output moved to another channel");
            if enforcing {
                assert!(
                    out.motion.is_finite(),
                    "enforcing firewall forwarded a non-finite command: {cmd:?} -> {verdict:?}"
                );
            }
        }
        if !enforcing && flags & 0x80 == 0 && ci < names.len() {
            if let Verdict::Passed { cmd: out, .. } = &verdict {
                // Debug, not ==: NaN must compare equal to itself here.
                assert_eq!(
                    format!("{:?}", out.motion),
                    format!("{:?}", cmd.motion),
                    "observe mode altered a command"
                );
            }
        }
        assert!(fw.events().len() <= cap, "event buffer over capacity");
    }
    let _ = fw.stats();
    let _ = fw.drain_deviations();
}
