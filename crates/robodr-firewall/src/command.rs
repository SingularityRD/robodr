//! The firewall's own command model.
//!
//! Every type here is `Copy`, fixed-size and heap-free so a [`Command`] can be
//! moved through [`crate::Firewall::check`] without touching the allocator.
//! Strings (endpoint GUIDs, topic names) never reach the hot path: they are
//! interned to [`SourceId`] / [`ChannelId`] when the policy is compiled, and
//! the I/O gateway resolves them once per discovered endpoint, not per message.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

/// Largest joint-velocity vector a [`Command`] can carry. Commands for robots
/// with more joints must be split over several channels.
pub const MAX_JOINTS: usize = 32;

/// Interned identity of a command source (a DDS endpoint GUID).
///
/// Ids are dense, assigned by [`crate::Policy::compile`] and resolved with
/// [`crate::Firewall::source_id`]. The gateway passes [`SourceId::UNKNOWN`]
/// for any writer it could not resolve; that is always rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(pub u16);

impl SourceId {
    /// The source could not be resolved to any configured GUID.
    pub const UNKNOWN: SourceId = SourceId(u16::MAX);
    /// Marks a substitute command the firewall produced itself (zero / hold).
    pub const FIREWALL: SourceId = SourceId(u16::MAX - 1);
}

/// Interned identity of a motion channel (a ROS 2 topic or bus id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(pub u16);

/// A 3-vector (m/s for linear, rad/s for angular).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vec3 {
    pub const ZERO: Vec3 = Vec3 {
        x: 0.0,
        y: 0.0,
        z: 0.0,
    };

    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub(crate) fn to_array(self) -> [f64; 3] {
        [self.x, self.y, self.z]
    }

    pub(crate) fn from_array([x, y, z]: [f64; 3]) -> Self {
        Self { x, y, z }
    }
}

/// A velocity twist, as in `geometry_msgs/Twist`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Twist {
    pub linear: Vec3,
    pub angular: Vec3,
}

impl Twist {
    pub const ZERO: Twist = Twist {
        linear: Vec3::ZERO,
        angular: Vec3::ZERO,
    };

    pub const fn new(linear: Vec3, angular: Vec3) -> Self {
        Self { linear, angular }
    }
}

/// A fixed-capacity joint velocity vector (rad/s or m/s per joint).
///
/// Only the first [`len`](Self::len) entries are meaningful; the rest are
/// kept at zero so that `PartialEq` compares meaningful data only.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JointVelocities {
    len: u8,
    v: [f64; MAX_JOINTS],
}

impl JointVelocities {
    /// Build from a slice. `None` if the slice is longer than [`MAX_JOINTS`].
    pub fn from_slice(values: &[f64]) -> Option<Self> {
        if values.len() > MAX_JOINTS {
            return None;
        }
        let mut v = [0.0; MAX_JOINTS];
        for (dst, src) in v.iter_mut().zip(values) {
            *dst = *src;
        }
        Some(Self {
            len: values.len() as u8,
            v,
        })
    }

    /// A zero vector of `len` joints (clamped to [`MAX_JOINTS`]).
    pub fn zeros(len: usize) -> Self {
        Self {
            len: len.min(MAX_JOINTS) as u8,
            v: [0.0; MAX_JOINTS],
        }
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The meaningful entries.
    pub fn as_slice(&self) -> &[f64] {
        // `len <= MAX_JOINTS` is a type invariant (both constructors clamp),
        // and `get` keeps this panic-free even if it were ever violated.
        self.v.get(..self.len()).unwrap_or(&[])
    }

    pub(crate) fn raw(&self) -> &[f64; MAX_JOINTS] {
        &self.v
    }

    pub(crate) fn from_raw(len: usize, v: [f64; MAX_JOINTS]) -> Self {
        let len = len.min(MAX_JOINTS);
        let mut out = [0.0; MAX_JOINTS];
        for (dst, src) in out.iter_mut().zip(v.iter()).take(len) {
            *dst = *src;
        }
        Self {
            len: len as u8,
            v: out,
        }
    }
}

/// The motion payload of a command.
// Deliberately unboxed: boxing the joint array would put a heap allocation in
// the hot path. The size difference is the price of determinism.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Motion {
    /// Body velocity (mobile base, `cmd_vel`).
    Twist(Twist),
    /// Per-joint velocities (manipulator, legged robot).
    Joints(JointVelocities),
}

impl Motion {
    /// The all-zero motion of the same kind (and joint count).
    pub fn zero_like(&self) -> Motion {
        match self {
            Motion::Twist(_) => Motion::Twist(Twist::ZERO),
            Motion::Joints(j) => Motion::Joints(JointVelocities::zeros(j.len())),
        }
    }

    /// `true` if every component is finite (no NaN, no ±inf).
    pub fn is_finite(&self) -> bool {
        match self {
            Motion::Twist(t) => t
                .linear
                .to_array()
                .iter()
                .chain(t.angular.to_array().iter())
                .all(|c| c.is_finite()),
            Motion::Joints(j) => j.as_slice().iter().all(|c| c.is_finite()),
        }
    }

    /// `true` if every component is exactly zero.
    pub fn is_zero(&self) -> bool {
        match self {
            Motion::Twist(t) => *t == Twist::ZERO,
            Motion::Joints(j) => j.as_slice().iter().all(|c| *c == 0.0),
        }
    }
}

/// One motion command as it reaches the firewall.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Command {
    /// Interned source endpoint ([`SourceId::UNKNOWN`] if unresolved).
    pub source: SourceId,
    /// Interned channel the command arrived on.
    pub channel: ChannelId,
    /// Source-provided timestamp, nanoseconds, in the **same monotonic clock
    /// domain** as the `now` passed to `check` (the gateway converts).
    pub stamp_ns: u64,
    pub motion: Motion,
}

impl Command {
    pub fn twist(source: SourceId, channel: ChannelId, stamp_ns: u64, twist: Twist) -> Self {
        Self {
            source,
            channel,
            stamp_ns,
            motion: Motion::Twist(twist),
        }
    }

    pub fn joints(
        source: SourceId,
        channel: ChannelId,
        stamp_ns: u64,
        joints: JointVelocities,
    ) -> Self {
        Self {
            source,
            channel,
            stamp_ns,
            motion: Motion::Joints(joints),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn joints_from_slice_bounds() {
        assert!(JointVelocities::from_slice(&[0.0; MAX_JOINTS]).is_some());
        assert!(JointVelocities::from_slice(&[0.0; MAX_JOINTS + 1]).is_none());
        let j = JointVelocities::from_slice(&[1.0, 2.0]).unwrap();
        assert_eq!(j.as_slice(), &[1.0, 2.0]);
        assert_eq!(j.len(), 2);
        assert!(!j.is_empty());
        assert!(JointVelocities::zeros(0).is_empty());
        assert_eq!(JointVelocities::zeros(1000).len(), MAX_JOINTS);
    }

    #[test]
    fn from_raw_zeroes_tail() {
        let j = JointVelocities::from_raw(2, [7.0; MAX_JOINTS]);
        assert_eq!(j, JointVelocities::from_slice(&[7.0, 7.0]).unwrap());
    }

    #[test]
    fn finite_and_zero() {
        let mut t = Twist::ZERO;
        assert!(Motion::Twist(t).is_zero());
        t.angular.z = f64::NAN;
        assert!(!Motion::Twist(t).is_finite());
        let j = Motion::Joints(JointVelocities::from_slice(&[0.0, f64::INFINITY]).unwrap());
        assert!(!j.is_finite());
        assert_eq!(j.zero_like(), Motion::Joints(JointVelocities::zeros(2)));
    }
}
