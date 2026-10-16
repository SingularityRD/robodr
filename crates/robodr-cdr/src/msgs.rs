//! The ROS 2 message types this crate decodes, and their CDR decoders.
//!
//! Messages borrow from the payload: strings are [`CdrStr`] slices,
//! `float64[]` fields are [`F64Seq`] views and `string[]` fields are
//! [`StringSeq`] views, so decoding allocates nothing except the bounded
//! `points` vector of [`JointTrajectory`].
//!
//! Field order and types follow the `.msg` definitions (ROS 2 Humble through
//! Kilted; these interfaces have been stable since Foxy). Every struct is
//! read with `Reader::structure`, which adds the XCDR2 DHEADER under
//! `D_CDR2_*` (ROS IDL types carry no extensibility annotation, so they are
//! `@appendable` by XTypes default).

use crate::encap::Endian;
use crate::error::DecodeError;
use crate::reader::{f64_from, CdrStr, Reader};
use crate::Limits;

/// `builtin_interfaces/msg/Time` (also the layout of
/// `builtin_interfaces/msg/Duration`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Time {
    pub sec: i32,
    pub nanosec: u32,
}

impl Time {
    /// Nanoseconds since the epoch / zero, if non-negative and representable.
    /// The value comes from the wire: it is a claim, not a clock reading.
    pub fn to_ns(&self) -> Option<u64> {
        let sec = u64::try_from(self.sec).ok()?;
        sec.checked_mul(1_000_000_000)?
            .checked_add(u64::from(self.nanosec))
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(Time {
                sec: r.i32()?,
                nanosec: r.u32()?,
            })
        })
    }
}

/// `builtin_interfaces/msg/Duration` (same layout as [`Time`]).
pub type Duration = Time;

/// `std_msgs/msg/Header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Header<'a> {
    pub stamp: Time,
    pub frame_id: CdrStr<'a>,
}

impl<'a> Header<'a> {
    fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(Header {
                stamp: Time::read(r)?,
                frame_id: r.string()?,
            })
        })
    }
}

/// `geometry_msgs/msg/Vector3` (also used for `Point`, same layout).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Vector3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vector3 {
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(Vector3 {
                x: r.f64()?,
                y: r.f64()?,
                z: r.f64()?,
            })
        })
    }

    /// Euclidean norm. NaN if any component is NaN and none is infinite;
    /// +inf if any component is infinite (IEEE `hypot`).
    pub fn norm(&self) -> f64 {
        self.x.hypot(self.y).hypot(self.z)
    }
}

/// `geometry_msgs/msg/Point`.
pub type Point = Vector3;

/// `geometry_msgs/msg/Quaternion`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Quaternion {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub w: f64,
}

impl Quaternion {
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(Quaternion {
                x: r.f64()?,
                y: r.f64()?,
                z: r.f64()?,
                w: r.f64()?,
            })
        })
    }
}

/// `geometry_msgs/msg/Pose`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Pose {
    pub position: Point,
    pub orientation: Quaternion,
}

impl Pose {
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(Pose {
                position: Vector3::read(r)?,
                orientation: Quaternion::read(r)?,
            })
        })
    }
}

/// `geometry_msgs/msg/Twist`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Twist {
    pub linear: Vector3,
    pub angular: Vector3,
}

impl Twist {
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(Twist {
                linear: Vector3::read(r)?,
                angular: Vector3::read(r)?,
            })
        })
    }
}

/// `geometry_msgs/msg/TwistStamped`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct TwistStamped<'a> {
    pub header: Header<'a>,
    pub twist: Twist,
}

impl<'a> TwistStamped<'a> {
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(TwistStamped {
                header: Header::read(r)?,
                twist: Twist::read(r)?,
            })
        })
    }
}

/// `geometry_msgs/msg/PoseWithCovariance`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PoseWithCovariance {
    pub pose: Pose,
    /// Row-major 6x6 (x, y, z, rot x, rot y, rot z).
    pub covariance: [f64; 36],
}

impl PoseWithCovariance {
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(PoseWithCovariance {
                pose: Pose::read(r)?,
                covariance: r.f64_array::<36>()?,
            })
        })
    }
}

/// `geometry_msgs/msg/TwistWithCovariance`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TwistWithCovariance {
    pub twist: Twist,
    pub covariance: [f64; 36],
}

impl TwistWithCovariance {
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(TwistWithCovariance {
                twist: Twist::read(r)?,
                covariance: r.f64_array::<36>()?,
            })
        })
    }
}

/// `nav_msgs/msg/Odometry`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Odometry<'a> {
    pub header: Header<'a>,
    pub child_frame_id: CdrStr<'a>,
    pub pose: PoseWithCovariance,
    /// Velocity in the `child_frame_id` frame (body frame, REP 105).
    pub twist: TwistWithCovariance,
}

impl<'a> Odometry<'a> {
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(Odometry {
                header: Header::read(r)?,
                child_frame_id: r.string()?,
                pose: PoseWithCovariance::read(r)?,
                twist: TwistWithCovariance::read(r)?,
            })
        })
    }
}

/// `sensor_msgs/msg/Imu`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Imu<'a> {
    pub header: Header<'a>,
    pub orientation: Quaternion,
    pub orientation_covariance: [f64; 9],
    pub angular_velocity: Vector3,
    pub angular_velocity_covariance: [f64; 9],
    pub linear_acceleration: Vector3,
    pub linear_acceleration_covariance: [f64; 9],
}

impl<'a> Imu<'a> {
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(Imu {
                header: Header::read(r)?,
                orientation: Quaternion::read(r)?,
                orientation_covariance: r.f64_array::<9>()?,
                angular_velocity: Vector3::read(r)?,
                angular_velocity_covariance: r.f64_array::<9>()?,
                linear_acceleration: Vector3::read(r)?,
                linear_acceleration_covariance: r.f64_array::<9>()?,
            })
        })
    }
}

/// A zero-copy view of a decoded `float64[]` (unbounded sequence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F64Seq<'a> {
    bytes: &'a [u8],
    endian: Endian,
}

impl<'a> F64Seq<'a> {
    /// An empty sequence.
    pub const EMPTY: F64Seq<'static> = F64Seq {
        bytes: &[],
        endian: Endian::Little,
    };

    fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let n = r.seq_len(r.limits.max_sequence_len, 8)?;
        if n == 0 {
            // No element, no element alignment (XTypes: padding precedes
            // a primitive that is actually serialized).
            return Ok(F64Seq {
                bytes: &[],
                endian: r.endian(),
            });
        }
        r.align(8)?;
        let at = r.pos();
        let len = (n as usize).checked_mul(8).ok_or(DecodeError::Truncated {
            at,
            need: usize::MAX,
        })?;
        Ok(F64Seq {
            bytes: r.bytes(len)?,
            endian: r.endian(),
        })
    }

    pub fn len(&self) -> usize {
        self.bytes.len() / 8
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn get(&self, i: usize) -> Option<f64> {
        let start = i.checked_mul(8)?;
        let b = self.bytes.get(start..start.checked_add(8)?)?;
        let a = <[u8; 8]>::try_from(b).ok()?;
        Some(f64_from(a, self.endian))
    }

    pub fn iter(&self) -> impl Iterator<Item = f64> + 'a {
        let endian = self.endian;
        self.bytes
            .chunks_exact(8)
            .filter_map(move |c| <[u8; 8]>::try_from(c).ok().map(|a| f64_from(a, endian)))
    }

    /// Largest absolute value, propagating non-finite input: NaN if any
    /// element is NaN, else +inf if any is infinite. `None` when empty.
    /// (`f64::max` would silently skip a NaN, which a safety consumer must
    /// never do.)
    pub fn max_abs(&self) -> Option<f64> {
        max_abs(self.iter())
    }
}

/// Max |v| with NaN poisoning (see [`F64Seq::max_abs`]).
pub(crate) fn max_abs(it: impl Iterator<Item = f64>) -> Option<f64> {
    let mut acc: Option<f64> = None;
    for v in it {
        let a = v.abs();
        acc = Some(match acc {
            None => a,
            Some(m) if m.is_nan() || a.is_nan() => f64::NAN,
            Some(m) => {
                if a > m {
                    a
                } else {
                    m
                }
            }
        });
    }
    acc
}

/// A zero-copy view of a decoded `string[]`. Every element was validated
/// (bounds, length cap, terminator) during decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringSeq<'a> {
    /// From the first element's length prefix (4-aligned relative to the
    /// origin) to the last element's terminator.
    region: &'a [u8],
    count: u32,
    endian: Endian,
}

impl<'a> StringSeq<'a> {
    fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let endian = r.endian();
        let buf = r.buf();
        r.nonprimitive_seq(|r| {
            let count = r.seq_len(r.limits.max_sequence_len, 4)?;
            let start = r.pos();
            for _ in 0..count {
                r.string()?;
            }
            let region = buf
                .get(start..r.pos())
                .ok_or(DecodeError::Truncated { at: start, need: 0 })?;
            Ok(StringSeq {
                region,
                count,
                endian,
            })
        })
    }

    pub fn len(&self) -> usize {
        self.count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The elements in order. `region` starts 4-aligned relative to the
    /// CDR origin, so re-reading it from offset 0 sees the same padding.
    pub fn iter(&self) -> impl Iterator<Item = CdrStr<'a>> + 'a {
        let limits = Limits {
            max_string_len: u32::MAX,
            ..Limits::default()
        };
        let mut r = Reader::new(
            self.region,
            self.endian,
            crate::encap::XcdrVersion::Xcdr1,
            false,
            limits,
        );
        let count = self.count;
        (0..count).map_while(move |_| r.string().ok())
    }
}

/// `sensor_msgs/msg/JointState`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JointState<'a> {
    pub header: Header<'a>,
    pub name: StringSeq<'a>,
    pub position: F64Seq<'a>,
    pub velocity: F64Seq<'a>,
    pub effort: F64Seq<'a>,
}

impl<'a> JointState<'a> {
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(JointState {
                header: Header::read(r)?,
                name: StringSeq::read(r)?,
                position: F64Seq::read(r)?,
                velocity: F64Seq::read(r)?,
                effort: F64Seq::read(r)?,
            })
        })
    }
}

/// `trajectory_msgs/msg/JointTrajectoryPoint`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JointTrajectoryPoint<'a> {
    pub positions: F64Seq<'a>,
    pub velocities: F64Seq<'a>,
    pub accelerations: F64Seq<'a>,
    pub effort: F64Seq<'a>,
    pub time_from_start: Duration,
}

impl<'a> JointTrajectoryPoint<'a> {
    fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(JointTrajectoryPoint {
                positions: F64Seq::read(r)?,
                velocities: F64Seq::read(r)?,
                accelerations: F64Seq::read(r)?,
                effort: F64Seq::read(r)?,
                time_from_start: Time::read(r)?,
            })
        })
    }
}

/// `trajectory_msgs/msg/JointTrajectory`. `points` is the only allocation
/// in the crate; its length is capped by
/// [`Limits::max_trajectory_points`].
#[derive(Debug, Clone, PartialEq)]
pub struct JointTrajectory<'a> {
    pub header: Header<'a>,
    pub joint_names: StringSeq<'a>,
    pub points: Vec<JointTrajectoryPoint<'a>>,
}

impl<'a> JointTrajectory<'a> {
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            let header = Header::read(r)?;
            let joint_names = StringSeq::read(r)?;
            let points = r.nonprimitive_seq(|r| {
                // An XCDR1 point is at least 4 counts + Duration = 24 bytes;
                // checking against 4 is a safe lower bound for all encodings.
                let n = r.seq_len(r.limits.max_trajectory_points, 4)?;
                let mut v = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    v.push(JointTrajectoryPoint::read(r)?);
                }
                Ok(v)
            })?;
            Ok(JointTrajectory {
                header,
                joint_names,
                points,
            })
        })
    }

    /// Max |velocity| over every point and joint (NaN-poisoning, see
    /// [`F64Seq::max_abs`]); `None` if no point carries velocities.
    pub fn max_abs_velocity(&self) -> Option<f64> {
        max_abs(self.points.iter().flat_map(|p| p.velocities.iter()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_abs_poisons_on_nan_in_any_position() {
        assert_eq!(max_abs([].into_iter()), None);
        assert_eq!(max_abs([-3.0, 2.0].into_iter()), Some(3.0));
        assert!(max_abs([f64::NAN, 1.0].into_iter()).unwrap().is_nan());
        assert!(max_abs([1.0, f64::NAN].into_iter()).unwrap().is_nan());
        assert!(max_abs([1.0, f64::NAN, 5.0].into_iter()).unwrap().is_nan());
        assert_eq!(
            max_abs([1.0, f64::NEG_INFINITY].into_iter()),
            Some(f64::INFINITY)
        );
    }

    #[test]
    fn time_to_ns() {
        assert_eq!(Time { sec: 1, nanosec: 5 }.to_ns(), Some(1_000_000_005));
        assert_eq!(
            Time {
                sec: -1,
                nanosec: 0
            }
            .to_ns(),
            None
        );
        assert_eq!(
            Time {
                sec: i32::MAX,
                nanosec: u32::MAX
            }
            .to_ns(),
            Some(i32::MAX as u64 * 1_000_000_000 + u32::MAX as u64)
        );
    }

    #[test]
    fn vector_norm_nonfinite() {
        let v = Vector3 {
            x: f64::NAN,
            y: 0.0,
            z: 0.0,
        };
        assert!(v.norm().is_nan());
        let v = Vector3 {
            x: -3.0,
            y: 4.0,
            z: 0.0,
        };
        assert_eq!(v.norm(), 5.0);
    }
}
