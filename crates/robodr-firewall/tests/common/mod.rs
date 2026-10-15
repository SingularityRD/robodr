//! Shared fixtures for the integration tests.
#![allow(dead_code)]

use robodr_events::profile::{Envelope, Profile};
use robodr_firewall::*;
use std::collections::BTreeMap;

pub const PREFIX: &str = "0123456789abcdef01234567";
pub const MS: u64 = 1_000_000;
pub const T0: u64 = 1_000 * MS;

pub const LIN: f64 = 1.0;
pub const ANG: f64 = 2.0;
pub const JOINT: f64 = 1.5;
pub const ARM_JOINTS: usize = 6;

pub fn guid(entity: &str) -> String {
    format!("{PREFIX}{entity}")
}

pub struct Fx {
    pub fw: Firewall,
    pub nav: SourceId,
    pub teleop: SourceId,
    pub arm_src: SourceId,
    pub base: ChannelId,
    pub arm: ChannelId,
}

pub fn profile(locked: bool) -> Profile {
    let mut p = Profile {
        model: "ugv-test".into(),
        locked,
        ..Default::default()
    };
    p.participants.insert(PREFIX.into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(LIN),
            max_joint_speed: None,
        },
    );
    p.motion_envelopes.insert(
        "/arm/cmd".into(),
        Envelope {
            max_linear_speed: None,
            max_joint_speed: Some(JOINT),
        },
    );
    p
}

pub fn base_spec() -> ChannelSpec {
    ChannelSpec {
        kind: ChannelKind::Twist,
        allowed_sources: vec![guid("00000103"), guid("00000203")],
        max_angular_speed: Some(ANG),
        ..Default::default()
    }
}

pub fn arm_spec() -> ChannelSpec {
    ChannelSpec {
        kind: ChannelKind::Joints { count: ARM_JOINTS },
        allowed_sources: vec![guid("00000303")],
        ..Default::default()
    }
}

pub fn build(
    platform: PlatformConfig,
    locked: bool,
    tweak: impl FnOnce(&mut ChannelSpec, &mut ChannelSpec),
) -> Fx {
    let mut b = base_spec();
    let mut a = arm_spec();
    tweak(&mut b, &mut a);
    let specs = BTreeMap::from([("/cmd_vel".to_string(), b), ("/arm/cmd".to_string(), a)]);
    let pol = Policy::compile(&profile(locked), platform, &specs).expect("policy compiles");
    let fw = Firewall::new(pol);
    Fx {
        nav: fw.source_id(&guid("00000103")).unwrap(),
        teleop: fw.source_id(&guid("00000203")).unwrap(),
        arm_src: fw.source_id(&guid("00000303")).unwrap(),
        base: fw.channel_id("/cmd_vel").unwrap(),
        arm: fw.channel_id("/arm/cmd").unwrap(),
        fw,
    }
}

pub fn default_fx() -> Fx {
    build(PlatformConfig::default(), true, |_, _| {})
}

pub fn tw(lx: f64, ly: f64, lz: f64, ax: f64, ay: f64, az: f64) -> Twist {
    Twist::new(Vec3::new(lx, ly, lz), Vec3::new(ax, ay, az))
}

pub fn vx(v: f64) -> Twist {
    tw(v, 0.0, 0.0, 0.0, 0.0, 0.0)
}

pub fn twist_cmd(src: SourceId, ch: ChannelId, stamp: u64, t: Twist) -> Command {
    Command::twist(src, ch, stamp, t)
}

pub fn joint_cmd(src: SourceId, ch: ChannelId, stamp: u64, j: &[f64]) -> Command {
    Command::joints(src, ch, stamp, JointVelocities::from_slice(j).unwrap())
}

pub fn norm3(v: Vec3) -> f64 {
    (v.x * v.x + v.y * v.y + v.z * v.z).sqrt()
}

pub fn out_twist(v: &Verdict) -> Twist {
    match v.output().expect("verdict emits something").motion {
        Motion::Twist(t) => t,
        Motion::Joints(_) => panic!("expected twist"),
    }
}

pub fn out_joints(v: &Verdict) -> Vec<f64> {
    match v.output().expect("verdict emits something").motion {
        Motion::Joints(j) => j.as_slice().to_vec(),
        Motion::Twist(_) => panic!("expected joints"),
    }
}

/// Tiny deterministic PRNG (xorshift64*), std-only.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in [lo, hi).
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        let u = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        lo + (hi - lo) * u
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    pub fn chance(&mut self, p: f64) -> bool {
        self.range(0.0, 1.0) < p
    }
}
