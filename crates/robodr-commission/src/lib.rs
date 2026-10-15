//! Observe-mode commissioning for RoboDR.
//!
//! During commissioning the robot does a clean run (one or more missions)
//! while RoboDR only watches. This crate turns what was watched into a draft
//! model profile (`profile.json`, `locked: false`) plus a report, lets the OEM
//! compare drafts ([`diff`]), [`lock`] a reviewed draft, and re-run a locked
//! profile over a recording to prove a clean run gives zero deviations
//! ([`Checker`]).
//!
//! Layers:
//! * [`input`]: where events come from ([`EventSource`] trait; JSONL today,
//!   pcap seam marked `TODO(pcap)`).
//! * [`learner`]: [`Learner`] accumulates observations deterministically and
//!   emits a [`Profile`](robodr_events::profile::Profile) and a
//!   [`CommissioningReport`].
//! * [`ops`]: [`lock`], [`diff`], [`merge_profiles`], [`Checker`].
//! * [`stats`]: nearest-rank percentiles.
//!
//! Scope: protective only. Nothing here talks to the robot or changes its
//! behaviour; the output is a file for a human to review.
//!
//! Limits (honest list):
//! * The learned profile is only as good as the clean run. Anything the run
//!   did not exercise (a rarely used topic, a fast manoeuvre) will deviate
//!   later; merge more missions to widen coverage.
//! * `RobotEvent` has no timestamps, so first/last-seen are positions in the
//!   input (run index + line), not times.
//! * All motion samples are held in memory for percentiles (8 bytes each:
//!   ~1.4 MB per channel-hour at 50 Hz).

pub mod input;
pub mod learner;
pub mod ops;
pub mod stats;

pub use input::{EventSource, InputError, InputSpec, JsonlSource, SourcedEvent, VecSource};
pub use learner::{
    envelope_bound, Commissioning, CommissioningReport, ConfigError, LearnConfig, Learner, SeenAt,
    Warning, WarningLevel,
};
pub use ops::{
    check_event, diff, lock, merge_profiles, CheckReport, Checker, LockRefusal, MergeError,
    ProfileDiff,
};
pub use stats::SpeedStats;

/// Serialise a value as pretty JSON with a trailing newline. All file output
/// goes through here so `learn` twice over the same input is byte-identical.
pub fn to_json<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut s = serde_json::to_string_pretty(value)?;
    s.push('\n');
    Ok(s)
}
