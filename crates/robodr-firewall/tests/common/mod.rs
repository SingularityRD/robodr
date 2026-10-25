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
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(LIN),
            max_joint_speed: None,
            ..Default::default()
        },
    );
    p.writer_topics.insert("/arm/cmd".into());
    p.motion_envelopes.insert(
        "/arm/cmd".into(),
        Envelope {
            max_linear_speed: None,
            max_joint_speed: Some(JOINT),
            ..Default::default()
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

// ------------------------------------------------------------ joint frames

/// Envelope `max_joint_speed` of the low-level channel (tightens `dq_max`).
pub const ENV_DQ: f64 = 30.0;
pub const Q_LIM: f64 = 1.0;
pub const DQ_MAX: f64 = 10.0;
pub const TAU_MAX: f64 = 20.0;
pub const KP_MAX: f64 = 100.0;
pub const KD_MAX: f64 = 5.0;

/// Fixture with a low-level joint channel `/lowcmd` (allowed: `ctl`) next
/// to a twist channel `/cmd_vel` (allowed: `nav`).
pub struct JFx {
    pub fw: Firewall,
    pub ctl: SourceId,
    pub nav: SourceId,
    pub low: ChannelId,
    pub base: ChannelId,
    pub slots: usize,
    pub active: usize,
}

pub fn joint_profile(locked: bool) -> Profile {
    let mut p = Profile {
        model: "legged-test".into(),
        locked,
        ..Default::default()
    };
    p.participants.insert(PREFIX.into());
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(LIN),
            ..Default::default()
        },
    );
    p.writer_topics.insert("/lowcmd".into());
    p.motion_envelopes.insert(
        "/lowcmd".into(),
        Envelope {
            max_joint_speed: Some(ENV_DQ),
            ..Default::default()
        },
    );
    p
}

/// Fixture `max_dq_step`: wider than any in-range move, so only the tests
/// that set their own step bound see one.
pub const STEP_MAX: f64 = 100.0;

/// The fixture rate: 1 kHz, a 1 ns minimum interval (frames 1 ns apart are
/// still accepted) and no practical maximum, so only the tests that set
/// their own rate see the window.
pub fn wide_rate() -> JointRate {
    JointRate {
        expected_hz: 1000.0,
        min_interval_ns: 1,
        max_interval_ns: 60_000 * MS,
    }
}

/// `slots` motor slots, the first `active` enabled with the test limits
/// (gain minimums zero with an explicit `allow_limp`, so the same spec
/// compiles for a humanoid; `max_dq_step` = [`STEP_MAX`]).
pub fn joint_spec(slots: usize, active: usize) -> JointChannelSpec {
    JointChannelSpec {
        allowed_sources: vec![guid("00000103")],
        motors: (0..slots)
            .map(|i| {
                if i < active {
                    MotorLimits {
                        allow_limp: true,
                        max_dq_step: Some(STEP_MAX),
                        ..MotorLimits::enabled((-Q_LIM, Q_LIM), DQ_MAX, TAU_MAX, KP_MAX, KD_MAX)
                    }
                } else {
                    MotorLimits::disabled()
                }
            })
            .collect(),
        rate: Some(wide_rate()),
        ..Default::default()
    }
}

pub fn joint_specs(spec: JointChannelSpec) -> BTreeMap<String, JointChannelSpec> {
    BTreeMap::from([("/lowcmd".to_string(), spec)])
}

pub fn twist_specs() -> BTreeMap<String, ChannelSpec> {
    BTreeMap::from([(
        "/cmd_vel".to_string(),
        ChannelSpec {
            allowed_sources: vec![guid("00000203")],
            max_angular_speed: Some(ANG),
            ..Default::default()
        },
    )])
}

pub fn humanoid() -> PlatformConfig {
    PlatformConfig {
        morphology: Morphology::Humanoid,
        fail_behaviour: FailBehaviour::HoldLast {
            max_hold_ns: 50 * MS,
        },
        fault_policy: FaultPolicy::FailHold,
        ..Default::default()
    }
}

pub fn quadruped(fail_behaviour: FailBehaviour) -> PlatformConfig {
    PlatformConfig {
        morphology: Morphology::Quadruped,
        fail_behaviour,
        ..Default::default()
    }
}

pub fn build_joint(
    platform: PlatformConfig,
    locked: bool,
    slots: usize,
    active: usize,
    tweak: impl FnOnce(&mut JointChannelSpec),
) -> JFx {
    let mut spec = joint_spec(slots, active);
    tweak(&mut spec);
    let pol = Policy::compile_with_joints(
        &joint_profile(locked),
        platform,
        &twist_specs(),
        &joint_specs(spec),
    )
    .expect("joint policy compiles");
    let fw = Firewall::new(pol);
    JFx {
        ctl: fw.source_id(&guid("00000103")).unwrap(),
        nav: fw.source_id(&guid("00000203")).unwrap(),
        low: fw.channel_id("/lowcmd").unwrap(),
        base: fw.channel_id("/cmd_vel").unwrap(),
        fw,
        slots,
        active,
    }
}

/// An in-envelope motor command.
pub fn good() -> MotorCmd {
    MotorCmd::enabled(0.2, 1.0, 2.0, 50.0, 1.0)
}

/// A frame of `slots` slots: `f(i)` for active ones, OFF for the rest.
/// Allocation-free (the allocation test builds frames inside its measured
/// region).
pub fn jframe(slots: usize, active: usize, f: impl Fn(usize) -> MotorCmd) -> JointFrame {
    let mut ms = [MotorCmd::OFF; MAX_MOTORS];
    for (i, m) in ms.iter_mut().enumerate().take(active.min(slots)) {
        *m = f(i);
    }
    JointFrame::from_slice(&ms[..slots], Some(true)).unwrap()
}

impl JFx {
    /// A nominal frame from the allowed source.
    pub fn nominal(&self, stamp: u64) -> JointCommand {
        JointCommand::new(
            self.ctl,
            self.low,
            stamp,
            jframe(self.slots, self.active, |_| good()),
        )
    }

    /// The nominal frame with slot `slot` replaced by `m`.
    pub fn with_slot(&self, stamp: u64, slot: usize, m: MotorCmd) -> JointCommand {
        let mut c = self.nominal(stamp);
        *c.frame.motor_mut(slot).unwrap() = m;
        c
    }
}

pub fn jout(v: &JointVerdict) -> JointFrame {
    v.output().expect("verdict emits a frame").frame
}
