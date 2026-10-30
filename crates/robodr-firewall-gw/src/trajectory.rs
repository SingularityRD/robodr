//! ROS 2 joint trajectories: `trajectory_msgs/msg/JointTrajectory` (the
//! topic of a `joint_trajectory_controller`, e.g.
//! `/arm_controller/joint_trajectory`, DDS topic
//! `rt/arm_controller/joint_trajectory`, type
//! `trajectory_msgs::msg::dds_::JointTrajectory_`) and the goal of a
//! `control_msgs/action/FollowJointTrajectory` (the action's `send_goal`
//! request, DDS topic `rq/<action>/_action/send_goalRequest`, type
//! `control_msgs::action::dds_::FollowJointTrajectory_SendGoal_Request_`).
//!
//! # Strict decode ([`decode_strict`])
//!
//! Plain CDR (XCDR1) only, either endianness, as `rmw_cyclonedds` and
//! `rmw_fastrtps` send it (verified on the real Jazzy captures in
//! `fixtures/captures/ros2-jazzy/*_frag_run*.pcap`, `tests/trajectory.rs`);
//! XCDR2 and parameter lists are undecidable. Canonical means:
//!
//! - every alignment gap (relative to the CDR origin, the octet after the
//!   encapsulation header) is zero octets; an **empty** `float64[]` has no
//!   alignment gap after its count (Fast CDR and Cyclone DDS align only
//!   before the first element);
//! - strings: a `uint32` length including the NUL, 1..=[`MAX_NAME`]
//!   octets, valid UTF-8, no NUL inside, terminated by one;
//! - sequence counts bounded ([`MAX_JOINTS`], [`HARD_MAX_POINTS`]) and
//!   checked against the octets left before anything is allocated;
//! - nothing after the message but the encapsulation padding the options
//!   word announces (zero octets); `Duration.nanosec < 10^9`.
//!
//! The `send_goal` request is the action's `goal_id` (`uint8[16]`) and the
//! `FollowJointTrajectory` goal: the `trajectory`, a
//! `multi_dof_trajectory` that must be **empty** (no joint names, no
//! points: the gateway decides joint trajectories only, so anything it
//! cannot check fails closed), `path_tolerance` / `goal_tolerance`
//! (`control_msgs/JointTolerance[]`: a known joint name, finite
//! tolerances, at most one per joint) and `goal_time_tolerance`. With
//! [`GoalHeader::Cyclone`] the body starts with the 16-octet request header
//! `rmw_cyclonedds` puts in front of a service request (`uint64` client
//! GUID hash, `int64` sequence number); `rmw_fastrtps` carries it in the
//! RTPS inline QoS instead ([`GoalHeader::None`]).
//!
//! # Check ([`check`])
//!
//! Against the channel's [`TrajectoryLimits`] (gateway configuration,
//! velocity bounds capped by the profile envelope's `max_joint_speed` and
//! scaled by an active `restrict_motion`):
//!
//! - joint names: each one configured, none twice, at most the configured
//!   count; a name that differs from a configured one in case, white space
//!   or encoding is unknown (refused);
//! - points: at most `max_points`; every point carries `positions` for
//!   every named joint (velocity-only or effort-only points are
//!   unverifiable and refused); `velocities`, `accelerations`, `effort`
//!   empty or one per joint; every value finite;
//! - time: `time_from_start` non-negative, strictly increasing from point
//!   to point (a time-reversed or repeated stamp asks for an instantaneous
//!   jump), the last one at most `max_duration_s`;
//! - per joint: position inside `[min_position, max_position]`; declared
//!   velocity, the rate implied by consecutive positions, declared
//!   acceleration, the acceleration implied by consecutive velocities and
//!   the one implied by three consecutive positions within
//!   `max_velocity` / `max_acceleration`; effort within `max_effort`.
//!
//! An empty trajectory (no points) is a stop for a
//! `joint_trajectory_controller` (it holds the current position) and
//! passes. A single point at `t = 0` cannot be checked against the robot's
//! current position (not in the message): its position bounds are, its
//! step from the current state is not (README, "Known limits").
//!
//! # Time scaling ([`TrajectoryVerdict::TimeScaled`])
//!
//! With `on_velocity_violation: time_scale`, a trajectory whose only
//! violations are velocity / acceleration bounds is slowed down by the
//! smallest factor `k <= max_time_scale` that brings it within them: every
//! `time_from_start` is multiplied by `k` (rounded up to the nanosecond),
//! every velocity divided by `k` and every acceleration by `k^2`. The path
//! (the positions) is untouched, so a time-scaled trajectory goes through
//! the same configurations, slower. The rewrite is in place (same length,
//! [`write_time_scale`]) and is verified by decoding and checking again.
//! Anything else is refused.

use std::fmt;

use crate::lowcmd::{RewriteError, Undecidable};

/// Longest joint name accepted (octets, NUL included).
pub const MAX_NAME: usize = 256;
/// Most joints per trajectory (the firewall's joint-command maximum).
pub const MAX_JOINTS: usize = 32;
/// Hard cap on points whatever the configuration says.
pub const HARD_MAX_POINTS: usize = 4096;
/// Most tolerances in each of a goal's tolerance sequences.
pub const MAX_TOLERANCES: usize = MAX_JOINTS;

/// Which message a channel carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `trajectory_msgs/msg/JointTrajectory`.
    Trajectory,
    /// `FollowJointTrajectory_SendGoal_Request`.
    Goal(GoalHeader),
}

/// The service request header in front of a `send_goal` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalHeader {
    /// None in the payload (`rmw_fastrtps`: inline QoS).
    None,
    /// `rmw_cyclonedds`: `uint64` client GUID hash + `int64` sequence.
    Cyclone,
}

/// One decoded point and where its values are in the slot.
#[derive(Debug, Clone, PartialEq)]
pub struct WirePoint {
    pub positions: Vec<f64>,
    pub velocities: Vec<f64>,
    pub accelerations: Vec<f64>,
    pub effort: Vec<f64>,
    pub sec: i32,
    pub nanosec: u32,
    /// Slot offset of the first velocity / acceleration (when non-empty)
    /// and of `time_from_start.sec`.
    pub vel_off: usize,
    pub acc_off: usize,
    pub time_off: usize,
}

impl WirePoint {
    /// `time_from_start` in ns (`None` for a negative or malformed one).
    pub fn time_ns(&self) -> Option<i64> {
        if self.sec < 0 || self.nanosec >= 1_000_000_000 {
            return None;
        }
        Some(i64::from(self.sec) * 1_000_000_000 + i64::from(self.nanosec))
    }
}

/// A `control_msgs/JointTolerance`.
#[derive(Debug, Clone, PartialEq)]
pub struct Tolerance {
    pub name: String,
    pub position: f64,
    pub velocity: f64,
    pub acceleration: f64,
}

/// The goal's fields besides the trajectory.
#[derive(Debug, Clone, PartialEq)]
pub struct GoalParts {
    pub goal_id: [u8; 16],
    pub path_tolerance: Vec<Tolerance>,
    pub goal_tolerance: Vec<Tolerance>,
    pub goal_time_tolerance: (i32, u32),
}

/// A strictly decoded trajectory (or goal).
#[derive(Debug, Clone, PartialEq)]
pub struct WireTrajectory {
    pub big: bool,
    pub stamp: (i32, u32),
    pub frame_id: String,
    pub joint_names: Vec<String>,
    pub points: Vec<WirePoint>,
    pub goal: Option<GoalParts>,
}

// ------------------------------------------------------------- decoding

struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
    big: bool,
}

type R<T> = Result<T, Undecidable>;

impl<'a> Cur<'a> {
    fn left(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }

    /// Align to `n` (relative to the origin); the gap must be zero.
    fn align(&mut self, n: usize) -> R<()> {
        let rem = self.pos % n;
        if rem == 0 {
            return Ok(());
        }
        let gap = n - rem;
        let g = self
            .b
            .get(self.pos..self.pos + gap)
            .ok_or(Undecidable::Decode)?;
        if g.iter().any(|x| *x != 0) {
            return Err(Undecidable::NonCanonical);
        }
        self.pos += gap;
        Ok(())
    }

    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        let s = self
            .b
            .get(self.pos..self.pos.checked_add(n).ok_or(Undecidable::Decode)?)
            .ok_or(Undecidable::Decode)?;
        self.pos += n;
        Ok(s)
    }

    fn u32(&mut self) -> R<u32> {
        self.align(4)?;
        let a: [u8; 4] = self.take(4)?.try_into().map_err(|_| Undecidable::Decode)?;
        Ok(if self.big {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        })
    }

    fn i32(&mut self) -> R<i32> {
        Ok(self.u32()? as i32)
    }

    fn f64(&mut self) -> R<f64> {
        self.align(8)?;
        let a: [u8; 8] = self.take(8)?.try_into().map_err(|_| Undecidable::Decode)?;
        Ok(if self.big {
            f64::from_be_bytes(a)
        } else {
            f64::from_le_bytes(a)
        })
    }

    fn string(&mut self) -> R<String> {
        let len = self.u32()? as usize;
        if len == 0 || len > MAX_NAME {
            return Err(Undecidable::Decode);
        }
        let s = self.take(len)?;
        let (text, nul) = s.split_at(len - 1);
        if nul != [0] || text.contains(&0) {
            return Err(Undecidable::NonCanonical);
        }
        std::str::from_utf8(text)
            .map(str::to_string)
            .map_err(|_| Undecidable::NonCanonical)
    }

    /// A sequence count, at most `max`, with at least `min_each` octets per
    /// element left.
    fn count(&mut self, max: usize, min_each: usize) -> R<usize> {
        let n = self.u32()? as usize;
        if n > max || n.saturating_mul(min_each) > self.left() {
            return Err(Undecidable::Decode);
        }
        Ok(n)
    }

    /// `float64[]`: (values, slot offset of the first one).
    fn f64_seq(&mut self, max: usize) -> R<(Vec<f64>, usize)> {
        let n = self.count(max, 8)?;
        if n == 0 {
            return Ok((Vec::new(), 0));
        }
        self.align(8)?;
        let off = self.pos;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.f64()?);
        }
        Ok((v, off))
    }

    fn time(&mut self) -> R<(i32, u32)> {
        let s = self.i32()?;
        let ns = self.u32()?;
        if ns >= 1_000_000_000 {
            return Err(Undecidable::NonCanonical);
        }
        Ok((s, ns))
    }

    fn header(&mut self) -> R<((i32, u32), String)> {
        let stamp = self.time()?;
        Ok((stamp, self.string()?))
    }

    fn names(&mut self) -> R<Vec<String>> {
        let n = self.count(MAX_JOINTS, 5)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.string()?);
        }
        Ok(v)
    }

    fn trajectory(&mut self, max_points: usize) -> R<WireTrajectory> {
        let (stamp, frame_id) = self.header()?;
        let joint_names = self.names()?;
        // A point is at least 4 counts + a Duration.
        let n = self.count(max_points, 24)?;
        let mut points = Vec::with_capacity(n);
        for _ in 0..n {
            let (positions, _) = self.f64_seq(MAX_JOINTS)?;
            let (velocities, vel_off) = self.f64_seq(MAX_JOINTS)?;
            let (accelerations, acc_off) = self.f64_seq(MAX_JOINTS)?;
            let (effort, _) = self.f64_seq(MAX_JOINTS)?;
            self.align(4)?;
            let time_off = self.pos;
            let (sec, nanosec) = self.time()?;
            points.push(WirePoint {
                positions,
                velocities,
                accelerations,
                effort,
                sec,
                nanosec,
                // `+ 4`: the encapsulation header precedes the origin.
                vel_off: vel_off + 4,
                acc_off: acc_off + 4,
                time_off: time_off + 4,
            });
        }
        Ok(WireTrajectory {
            big: self.big,
            stamp,
            frame_id,
            joint_names,
            points,
            goal: None,
        })
    }

    fn tolerances(&mut self) -> R<Vec<Tolerance>> {
        let n = self.count(MAX_TOLERANCES, 5 + 24)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let name = self.string()?;
            v.push(Tolerance {
                name,
                position: self.f64()?,
                velocity: self.f64()?,
                acceleration: self.f64()?,
            });
        }
        Ok(v)
    }
}

/// The encapsulation: `Some(big)` for plain CDR (XCDR1) LE / BE, options
/// word checked. Returns `(big, announced padding)`.
fn encapsulation(slot: &[u8]) -> R<(bool, usize)> {
    let h = slot.get(..4).ok_or(Undecidable::Decode)?;
    let big = match (h[0], h[1]) {
        (0x00, 0x00) => true,
        (0x00, 0x01) => false,
        _ => return Err(Undecidable::Decode),
    };
    if h[2] != 0 || h[3] & !0x03 != 0 {
        return Err(Undecidable::NonCanonical);
    }
    Ok((big, usize::from(h[3] & 0x03)))
}

/// Decode `slot` strictly (module docs). `max_points` bounds the points
/// read (at most [`HARD_MAX_POINTS`]); a longer trajectory is undecidable
/// before anything is allocated for it.
pub fn decode_strict(slot: &[u8], layout: Layout, max_points: usize) -> R<WireTrajectory> {
    let (big, pad) = encapsulation(slot)?;
    let body = slot.get(4..).ok_or(Undecidable::Decode)?;
    let mut c = Cur {
        b: body,
        pos: 0,
        big,
    };
    let max_points = max_points.min(HARD_MAX_POINTS);
    let mut t = match layout {
        Layout::Trajectory => c.trajectory(max_points)?,
        Layout::Goal(h) => {
            if h == GoalHeader::Cyclone {
                // Two 8-octet integers at the origin (opaque here).
                c.take(16)?;
            }
            let id: [u8; 16] = c.take(16)?.try_into().map_err(|_| Undecidable::Decode)?;
            let mut t = c.trajectory(max_points)?;
            // multi_dof_trajectory: must be empty.
            let _ = c.header()?;
            let md_names = c.count(MAX_JOINTS, 5)?;
            if md_names != 0 {
                return Err(Undecidable::Mode);
            }
            let md_points = c.count(HARD_MAX_POINTS, 4)?;
            if md_points != 0 {
                return Err(Undecidable::Mode);
            }
            let path_tolerance = c.tolerances()?;
            let goal_tolerance = c.tolerances()?;
            let goal_time_tolerance = c.time()?;
            t.goal = Some(GoalParts {
                goal_id: id,
                path_tolerance,
                goal_tolerance,
                goal_time_tolerance,
            });
            t
        }
    };
    t.big = big;
    let end = c.pos;
    let want_pad = (4 - end % 4) % 4;
    if pad != want_pad || body.len() != end + pad {
        return Err(Undecidable::Trailing);
    }
    if body.get(end..).is_none_or(|x| x.iter().any(|b| *b != 0)) {
        return Err(Undecidable::Trailing);
    }
    Ok(t)
}

/// Lenient classification for the unknown-writer probe (review finding
/// F2 of the gateway): could `slot` be this channel's message in any
/// encoding a reader might accept? Only decides channel membership (the
/// sample is then decided strictly and fails closed): any CDR
/// representation that is not a parameter list, and either the strict
/// decoder takes it or its first joint-name count and first name look like
/// a trajectory's (a `frame_id` string after an 8-octet stamp, then a count
/// of at most [`MAX_JOINTS`] names).
pub fn plausible(slot: &[u8], layout: Layout) -> bool {
    let Some(h) = slot.get(..2) else {
        return false;
    };
    // CDR_BE/LE, PL_CDR_*, CDR2_*, D_CDR2_*, PL_CDR2_*.
    let id = u16::from_be_bytes([h[0], h[1]]);
    if !matches!(id, 0x0000 | 0x0001 | 0x0006 | 0x0007 | 0x0008 | 0x0009) {
        return false;
    }
    if decode_strict(slot, layout, HARD_MAX_POINTS).is_ok() {
        return true;
    }
    let big = id % 2 == 0;
    let body = slot.get(4..).unwrap_or_default();
    let skip = match layout {
        Layout::Trajectory => 0,
        Layout::Goal(GoalHeader::None) => 16,
        Layout::Goal(GoalHeader::Cyclone) => 32,
    };
    // With or without a leading DHEADER (XCDR2).
    [0usize, 4].iter().any(|&d| {
        let at = skip + d + 8;
        let rd = |o: usize| -> Option<usize> {
            let a: [u8; 4] = body.get(o..o + 4)?.try_into().ok()?;
            Some(if big {
                u32::from_be_bytes(a)
            } else {
                u32::from_le_bytes(a)
            } as usize)
        };
        let Some(flen) = rd(at) else {
            return false;
        };
        if flen == 0 || flen > MAX_NAME {
            return false;
        }
        let names_at = (at + 4 + flen).div_ceil(4) * 4;
        // The names sequence may itself carry a DHEADER (XCDR2).
        [0usize, 4].iter().any(|&e| {
            rd(names_at + e).is_some_and(|n| (1..=MAX_JOINTS).contains(&n))
                && rd(names_at + e + 4).is_some_and(|l| (2..=MAX_NAME).contains(&l))
        })
    })
}

// ------------------------------------------------------------- limits

/// One joint's bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct JointBounds {
    pub name: String,
    pub min_position: f64,
    pub max_position: f64,
    pub max_velocity: f64,
    pub max_acceleration: f64,
    pub max_effort: f64,
}

/// What a channel enforces (built from the gateway configuration).
#[derive(Debug, Clone, PartialEq)]
pub struct TrajectoryLimits {
    pub joints: Vec<JointBounds>,
    pub max_points: usize,
    /// Longest `time_from_start` of the last point (ns).
    pub max_duration_ns: i64,
    /// Slow down instead of refusing a velocity / acceleration violation.
    pub time_scale: bool,
    /// Largest slow-down factor (`>= 1`).
    pub max_time_scale: f64,
}

/// Why a trajectory is refused (stable names: the gateway's finding
/// detail and the status counters use [`Violation::as_str`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Violation {
    UnknownJoint,
    DuplicateJoint,
    TooManyPoints,
    NoJoints,
    /// A point without `positions` for every joint, or a sequence whose
    /// length is neither 0 nor the joint count.
    PointShape,
    NonFinite,
    NegativeTime,
    TimeNotIncreasing,
    TooLong,
    Position,
    Velocity,
    Acceleration,
    Effort,
    /// A goal tolerance for an unknown joint, twice for one joint, or not
    /// finite.
    Tolerance,
}

impl Violation {
    pub fn as_str(self) -> &'static str {
        match self {
            Violation::UnknownJoint => "unknown_joint",
            Violation::DuplicateJoint => "duplicate_joint",
            Violation::TooManyPoints => "too_many_points",
            Violation::NoJoints => "no_joints",
            Violation::PointShape => "point_shape",
            Violation::NonFinite => "non_finite",
            Violation::NegativeTime => "negative_time",
            Violation::TimeNotIncreasing => "time_not_increasing",
            Violation::TooLong => "too_long",
            Violation::Position => "position",
            Violation::Velocity => "velocity",
            Violation::Acceleration => "acceleration",
            Violation::Effort => "effort",
            Violation::Tolerance => "tolerance",
        }
    }

    /// Fixable by slowing the trajectory down.
    pub fn time_scalable(self) -> bool {
        matches!(self, Violation::Velocity | Violation::Acceleration)
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal with the joint it concerns (when one does).
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    pub violation: Violation,
    pub joint: Option<String>,
    pub value: f64,
    pub limit: f64,
}

/// The decision on one trajectory.
#[derive(Debug, Clone, PartialEq)]
pub enum TrajectoryVerdict {
    Pass,
    /// Within the bounds once slowed down by `factor` (`> 1`).
    TimeScaled {
        factor: f64,
        cause: Refused,
    },
    Refused(Refused),
}

fn refused(v: Violation, joint: Option<&str>, value: f64, limit: f64) -> Refused {
    Refused {
        violation: v,
        joint: joint.map(str::to_string),
        value,
        limit,
    }
}

/// The required slow-down (`>= 1`) to satisfy the velocity and
/// acceleration bounds, and the first violation found, or a refusal that
/// time scaling cannot fix.
fn evaluate(t: &WireTrajectory, lim: &TrajectoryLimits) -> Result<(f64, Option<Refused>), Refused> {
    // Joint names.
    let mut map = Vec::with_capacity(t.joint_names.len());
    for (i, n) in t.joint_names.iter().enumerate() {
        if t.joint_names[..i].contains(n) {
            return Err(refused(Violation::DuplicateJoint, Some(n), 0.0, 0.0));
        }
        let Some(b) = lim.joints.iter().find(|j| j.name == *n) else {
            return Err(refused(Violation::UnknownJoint, Some(n), 0.0, 0.0));
        };
        map.push(b);
    }
    if let Some(g) = &t.goal {
        for tols in [&g.path_tolerance, &g.goal_tolerance] {
            for (i, x) in tols.iter().enumerate() {
                let dup = tols[..i].iter().any(|y| y.name == x.name);
                let known = t.joint_names.contains(&x.name);
                let finite =
                    x.position.is_finite() && x.velocity.is_finite() && x.acceleration.is_finite();
                if dup || !known || !finite {
                    return Err(refused(Violation::Tolerance, Some(&x.name), 0.0, 0.0));
                }
            }
        }
        let (s, ns) = g.goal_time_tolerance;
        if s < 0 || ns >= 1_000_000_000 {
            return Err(refused(Violation::NegativeTime, None, f64::from(s), 0.0));
        }
    }
    if t.points.is_empty() {
        // A stop: the controller holds its current position.
        return Ok((1.0, None));
    }
    if t.points.len() > lim.max_points {
        return Err(refused(
            Violation::TooManyPoints,
            None,
            t.points.len() as f64,
            lim.max_points as f64,
        ));
    }
    let n = map.len();
    if n == 0 {
        return Err(refused(Violation::NoJoints, None, 0.0, 0.0));
    }
    let mut prev_t: Option<i64> = None;
    for p in &t.points {
        let shape_ok = p.positions.len() == n
            && [&p.velocities, &p.accelerations, &p.effort]
                .iter()
                .all(|s| s.is_empty() || s.len() == n);
        if !shape_ok {
            return Err(refused(Violation::PointShape, None, 0.0, n as f64));
        }
        if [&p.positions, &p.velocities, &p.accelerations, &p.effort]
            .iter()
            .any(|s| s.iter().any(|x| !x.is_finite()))
        {
            return Err(refused(Violation::NonFinite, None, f64::NAN, 0.0));
        }
        let Some(ts) = p.time_ns() else {
            return Err(refused(
                Violation::NegativeTime,
                None,
                f64::from(p.sec),
                0.0,
            ));
        };
        if prev_t.is_some_and(|pt| ts <= pt) {
            return Err(refused(
                Violation::TimeNotIncreasing,
                None,
                ts as f64 * 1e-9,
                prev_t.unwrap_or(0) as f64 * 1e-9,
            ));
        }
        prev_t = Some(ts);
        for (j, b) in map.iter().enumerate() {
            let q = p.positions[j];
            if q < b.min_position || q > b.max_position {
                let lim_q = if q < b.min_position {
                    b.min_position
                } else {
                    b.max_position
                };
                return Err(refused(Violation::Position, Some(&b.name), q, lim_q));
            }
            if let Some(e) = p.effort.get(j) {
                if e.abs() > b.max_effort {
                    return Err(refused(Violation::Effort, Some(&b.name), *e, b.max_effort));
                }
            }
        }
    }
    if prev_t.is_some_and(|last| last > lim.max_duration_ns) {
        return Err(refused(
            Violation::TooLong,
            None,
            prev_t.unwrap_or(0) as f64 * 1e-9,
            lim.max_duration_ns as f64 * 1e-9,
        ));
    }
    // Velocity / acceleration: the slow-down each needs.
    let mut k: f64 = 1.0;
    let mut first: Option<Refused> = None;
    let mut need = |ratio: f64, v: Violation, b: &JointBounds, value: f64, limit: f64| {
        if ratio > 1.0 {
            let f = if v == Violation::Acceleration {
                ratio.sqrt()
            } else {
                ratio
            };
            k = k.max(f);
            if first.is_none() {
                first = Some(refused(v, Some(&b.name), value, limit));
            }
        }
    };
    let secs = |p: &WirePoint| p.time_ns().unwrap_or(0) as f64 * 1e-9;
    for (i, p) in t.points.iter().enumerate() {
        for (j, b) in map.iter().enumerate() {
            if let Some(v) = p.velocities.get(j) {
                need(
                    v.abs() / b.max_velocity,
                    Violation::Velocity,
                    b,
                    *v,
                    b.max_velocity,
                );
            }
            if let Some(a) = p.accelerations.get(j) {
                need(
                    a.abs() / b.max_acceleration,
                    Violation::Acceleration,
                    b,
                    *a,
                    b.max_acceleration,
                );
            }
            let Some(prev) = i.checked_sub(1).and_then(|x| t.points.get(x)) else {
                continue;
            };
            let dt = secs(p) - secs(prev);
            if dt <= 0.0 {
                return Err(refused(Violation::TimeNotIncreasing, None, dt, 0.0));
            }
            let rate = (p.positions[j] - prev.positions[j]).abs() / dt;
            need(
                rate / b.max_velocity,
                Violation::Velocity,
                b,
                rate,
                b.max_velocity,
            );
            if let (Some(v1), Some(v0)) = (p.velocities.get(j), prev.velocities.get(j)) {
                let acc = (v1 - v0).abs() / dt;
                need(
                    acc / b.max_acceleration,
                    Violation::Acceleration,
                    b,
                    acc,
                    b.max_acceleration,
                );
            }
            if let Some(pp) = i.checked_sub(2).and_then(|x| t.points.get(x)) {
                let dt0 = secs(prev) - secs(pp);
                if dt0 > 0.0 {
                    let v0 = (prev.positions[j] - pp.positions[j]) / dt0;
                    let v1 = (p.positions[j] - prev.positions[j]) / dt;
                    let acc = 2.0 * (v1 - v0).abs() / (dt0 + dt);
                    need(
                        acc / b.max_acceleration,
                        Violation::Acceleration,
                        b,
                        acc,
                        b.max_acceleration,
                    );
                }
            }
        }
    }
    if !k.is_finite() {
        return Err(first.unwrap_or_else(|| refused(Violation::Velocity, None, k, 0.0)));
    }
    Ok((k, first))
}

/// Decide `t` against `lim` (module docs).
pub fn check(t: &WireTrajectory, lim: &TrajectoryLimits) -> TrajectoryVerdict {
    match evaluate(t, lim) {
        Err(r) => TrajectoryVerdict::Refused(r),
        Ok((_, None)) => TrajectoryVerdict::Pass,
        Ok((k, Some(cause))) => {
            // A small margin so rounding never leaves a value a hair over.
            let factor = k * (1.0 + 1e-9);
            let last = t.points.last().and_then(WirePoint::time_ns).unwrap_or(0) as f64;
            if lim.time_scale
                && factor <= lim.max_time_scale
                && last * factor <= lim.max_duration_ns as f64
            {
                TrajectoryVerdict::TimeScaled { factor, cause }
            } else {
                TrajectoryVerdict::Refused(cause)
            }
        }
    }
}

// ------------------------------------------------------------- rewrite

fn put_f64(slot: &mut [u8], off: usize, v: f64, big: bool) -> Result<(), RewriteError> {
    let b = if big {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    };
    slot.get_mut(off..off + 8)
        .ok_or(RewriteError::Length)?
        .copy_from_slice(&b);
    Ok(())
}

fn put_u32(slot: &mut [u8], off: usize, v: u32, big: bool) -> Result<(), RewriteError> {
    let b = if big {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    };
    slot.get_mut(off..off + 4)
        .ok_or(RewriteError::Length)?
        .copy_from_slice(&b);
    Ok(())
}

/// Slow `t` (decoded from `slot`) down by `factor` in place (module docs)
/// and verify: the written slot decodes to the scaled trajectory, which
/// [`check`] passes against `lim`.
pub fn write_time_scale(
    slot: &mut [u8],
    t: &WireTrajectory,
    layout: Layout,
    factor: f64,
    lim: &TrajectoryLimits,
) -> Result<(), RewriteError> {
    if !(factor.is_finite() && factor >= 1.0) {
        return Err(RewriteError::Value);
    }
    let big = t.big;
    // Every interval is scaled up (rounded up to the ns) on its own, so no
    // interval ends shorter than `factor` times the original: rounding the
    // absolute times alone could shorten one by a nanosecond.
    let mut prev: Option<(i64, i64)> = None;
    for p in &t.points {
        let ns = p.time_ns().ok_or(RewriteError::Value)?;
        let at = (ns as f64 * factor).ceil();
        let scaled = match prev {
            None => at,
            Some((pn, ps)) => {
                let gap = ((ns - pn) as f64 * factor).ceil();
                at.max(ps as f64 + gap)
            }
        };
        if !(scaled.is_finite() && scaled >= 0.0 && scaled < (i32::MAX as f64) * 1e9) {
            return Err(RewriteError::Value);
        }
        let scaled = scaled as i64;
        prev = Some((ns, scaled));
        let sec = u32::try_from(scaled / 1_000_000_000).map_err(|_| RewriteError::Value)?;
        let nsec = u32::try_from(scaled % 1_000_000_000).map_err(|_| RewriteError::Value)?;
        put_u32(slot, p.time_off, sec, big)?;
        put_u32(slot, p.time_off + 4, nsec, big)?;
        for (i, v) in p.velocities.iter().enumerate() {
            put_f64(slot, p.vel_off + 8 * i, v / factor, big)?;
        }
        for (i, a) in p.accelerations.iter().enumerate() {
            put_f64(slot, p.acc_off + 8 * i, a / (factor * factor), big)?;
        }
    }
    let back = decode_strict(slot, layout, lim.max_points).map_err(|_| RewriteError::Verify)?;
    if back.joint_names != t.joint_names
        || back.points.len() != t.points.len()
        || back
            .points
            .iter()
            .zip(&t.points)
            .any(|(a, b)| a.positions != b.positions || a.effort != b.effort)
    {
        return Err(RewriteError::Verify);
    }
    match check(&back, lim) {
        TrajectoryVerdict::Pass => Ok(()),
        _ => Err(RewriteError::Verify),
    }
}

// ------------------------------------------------------------- encoding

/// Test / harness helper: one point.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Point {
    pub positions: Vec<f64>,
    pub velocities: Vec<f64>,
    pub accelerations: Vec<f64>,
    pub effort: Vec<f64>,
    pub sec: i32,
    pub nanosec: u32,
}

impl Point {
    /// Positions at `t` seconds.
    pub fn at(t: f64, positions: &[f64]) -> Self {
        let ns = (t * 1e9).round() as i64;
        Point {
            positions: positions.to_vec(),
            sec: (ns / 1_000_000_000) as i32,
            nanosec: (ns % 1_000_000_000) as u32,
            ..Point::default()
        }
    }
}

struct Enc {
    b: Vec<u8>,
    big: bool,
}

impl Enc {
    fn align(&mut self, n: usize) {
        while !self.b.len().is_multiple_of(n) {
            self.b.push(0);
        }
    }
    fn u32(&mut self, v: u32) {
        self.align(4);
        let x = if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        self.b.extend_from_slice(&x);
    }
    fn f64(&mut self, v: f64) {
        self.align(8);
        let x = if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        self.b.extend_from_slice(&x);
    }
    fn string(&mut self, s: &str) {
        self.u32(s.len() as u32 + 1);
        self.b.extend_from_slice(s.as_bytes());
        self.b.push(0);
    }
    fn f64s(&mut self, v: &[f64]) {
        self.u32(v.len() as u32);
        for x in v {
            self.f64(*x);
        }
    }
    fn trajectory(&mut self, names: &[&str], points: &[Point]) {
        self.u32(0); // stamp.sec
        self.u32(0); // stamp.nanosec
        self.string("");
        self.u32(names.len() as u32);
        for n in names {
            self.string(n);
        }
        self.u32(points.len() as u32);
        for p in points {
            self.f64s(&p.positions);
            self.f64s(&p.velocities);
            self.f64s(&p.accelerations);
            self.f64s(&p.effort);
            self.u32(p.sec as u32);
            self.u32(p.nanosec);
        }
    }
}

/// Test / harness helper: a canonical payload (`goal`: a `send_goal`
/// request with this goal id, empty tolerances, and the given header).
pub fn encode(
    names: &[&str],
    points: &[Point],
    big: bool,
    goal: Option<(GoalHeader, [u8; 16])>,
) -> Vec<u8> {
    let mut e = Enc { b: Vec::new(), big };
    if let Some((h, id)) = goal {
        if h == GoalHeader::Cyclone {
            e.b.extend_from_slice(&[0x11; 8]);
            e.b.extend_from_slice(&1i64.to_le_bytes());
        }
        e.b.extend_from_slice(&id);
        e.trajectory(names, points);
        // multi_dof_trajectory: empty header, no names, no points.
        e.u32(0);
        e.u32(0);
        e.string("");
        e.u32(0);
        e.u32(0);
        e.u32(0); // path_tolerance
        e.u32(0); // goal_tolerance
        e.u32(0); // goal_time_tolerance.sec
        e.u32(0);
    } else {
        e.trajectory(names, points);
    }
    let pad = (4 - e.b.len() % 4) % 4;
    let mut out = vec![0x00, if big { 0x00 } else { 0x01 }, 0x00, pad as u8];
    out.extend_from_slice(&e.b);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> TrajectoryLimits {
        TrajectoryLimits {
            joints: ["a", "b"]
                .iter()
                .map(|n| JointBounds {
                    name: (*n).into(),
                    min_position: -1.0,
                    max_position: 1.0,
                    max_velocity: 1.0,
                    max_acceleration: 2.0,
                    max_effort: 5.0,
                })
                .collect(),
            max_points: 16,
            max_duration_ns: 10_000_000_000,
            time_scale: true,
            max_time_scale: 4.0,
        }
    }

    #[test]
    fn round_trip_both_endians_and_layouts() {
        let pts = vec![
            Point::at(0.0, &[0.0, 0.0]),
            Point {
                velocities: vec![0.1, 0.0],
                ..Point::at(1.0, &[0.1, -0.1])
            },
        ];
        for big in [false, true] {
            for layout in [
                Layout::Trajectory,
                Layout::Goal(GoalHeader::None),
                Layout::Goal(GoalHeader::Cyclone),
            ] {
                let goal = match layout {
                    Layout::Goal(h) => Some((h, [7; 16])),
                    Layout::Trajectory => None,
                };
                let p = encode(&["a", "b"], &pts, big, goal);
                let t = decode_strict(&p, layout, 16).unwrap();
                assert_eq!(t.joint_names, ["a", "b"]);
                assert_eq!(t.points.len(), 2);
                assert_eq!(t.points[1].velocities, [0.1, 0.0]);
                assert_eq!(check(&t, &lim()), TrajectoryVerdict::Pass);
                // Trailing octet, truncation and a non-zero alignment gap.
                let mut long = p.clone();
                long.extend_from_slice(&[0; 4]);
                assert!(decode_strict(&long, layout, 16).is_err());
                assert!(decode_strict(&p[..p.len() - 1], layout, 16).is_err());
            }
        }
    }

    #[test]
    fn time_scaling_rewrites_in_place() {
        let pts = vec![Point::at(0.0, &[0.0, 0.0]), Point::at(0.5, &[1.0, 0.0])];
        let p = encode(&["a", "b"], &pts, false, None);
        let t = decode_strict(&p, Layout::Trajectory, 16).unwrap();
        let TrajectoryVerdict::TimeScaled { factor, .. } = check(&t, &lim()) else {
            panic!("{:?}", check(&t, &lim()));
        };
        assert!(factor > 2.0 && factor < 2.1, "{factor}");
        let mut s = p.clone();
        write_time_scale(&mut s, &t, Layout::Trajectory, factor, &lim()).unwrap();
        assert_eq!(s.len(), p.len());
        let back = decode_strict(&s, Layout::Trajectory, 16).unwrap();
        assert!(back.points[1].time_ns().unwrap() >= 1_000_000_000);
        let mut no = lim();
        no.time_scale = false;
        assert!(matches!(check(&t, &no), TrajectoryVerdict::Refused(_)));
    }
}
