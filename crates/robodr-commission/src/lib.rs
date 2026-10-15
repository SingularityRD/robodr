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
//! * [`input`]: where events come from ([`EventSource`] trait; JSONL event
//!   recordings and pcap/pcapng captures via `robodr-capture` +
//!   `robodr-rtps` with DATA_FRAG reassembly).
//! * [`learner`]: [`Learner`] accumulates observations deterministically and
//!   emits a [`Profile`](robodr_events::profile::Profile) and a
//!   [`CommissioningReport`]. Endpoint names are routed by kind
//!   ([`ProfileSlot`]) into `writer_topics`, `services`, `actions`,
//!   `raw_dds_topics` and (opt-in) `reader_topics`, mirroring
//!   `Profile::evaluate`, so learn -> lock -> check over the same clean run
//!   gives zero deviations (property-tested).
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
//!   input (run index + line or frame ordinal), not times.
//! * A pcap gives discovery only; motion envelopes need the sensor's motion
//!   events (JSONL). Shared-memory transports and DDS-Security protected
//!   discovery are invisible to a capture (see robodr-capture's limits).
//! * Validated against synthetic captures built from the RTPS spec layout,
//!   not yet against captures from real Fast DDS / Cyclone / Connext robots.
//! * All motion samples are held in memory for percentiles (8 bytes each:
//!   ~1.4 MB per channel-hour at 50 Hz).

pub mod input;
pub mod learner;
pub mod ops;
pub mod stats;

pub use input::{
    CaptureDiagnostics, EventSource, InputError, InputSpec, JsonlSource, PcapSource, SourcedEvent,
    VecSource,
};
pub use learner::{
    envelope_bound, Commissioning, CommissioningReport, ConfigError, LearnConfig, Learner,
    ProfileSlot, RawTopicReport, SeenAt, ServiceReport, Warning, WarningLevel, PARAMETER_SERVICES,
    ROS_INTERNAL_RAW_TOPICS,
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
