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
//! * [`signoff`]: the operator confirmation list [`lock`] requires.
//! * [`profile_file`]: strict profile parsing, the lock seal, and
//!   symlink-safe, no-clobber, atomic file writes.
//! * [`stats`]: nearest-rank percentiles and bounded sample buffers.
//!
//! Security review (learning-time poisoning, hostile input, file handling):
//! see the `learner` module docs (anti-poisoning gate, hard caps, memory
//! caps), `input` (hostile captures), `profile_file` (seal, safe writes) and
//! `ops` (lock semantics).
//!
//! Scope: protective only. Nothing here talks to the robot or changes its
//! behaviour; the output is a file for a human to review.
//!
//! Limits (honest list):
//! * The learned profile is only as good as the clean run. Anything the run
//!   did not exercise (a rarely used topic, a fast manoeuvre) will deviate
//!   later; merge more missions to widen coverage.
//! * `RobotEvent` has no timestamps, so first/last-seen are positions in the
//!   input (run index + line or frame ordinal), not times. The gate's
//!   late/brief/duration checks use capture timestamps where the input has
//!   them (pcap); JSONL input falls back to positions and is flagged.
//! * Endpoint provenance (claimed GUID == sender, sender IP commissioned)
//!   is only checkable on packet captures; JSONL events carry no sender.
//! * A pcap gives discovery only; motion envelopes need the sensor's motion
//!   events (JSONL). Shared-memory transports and DDS-Security protected
//!   discovery are invisible to a capture (see robodr-capture's limits).
//! * Validated against synthetic captures built from the RTPS spec layout,
//!   not yet against captures from real Fast DDS / Cyclone / Connext robots.
//! * Memory is bounded by [`Limits`]: motion samples are decimated beyond
//!   `max_samples` per channel and dimension (percentiles become
//!   approximate and say so; envelopes use exact maxima), and maps/sets
//!   stop growing at their caps (dropped entries are reported).
//! * The anti-poisoning gate is heuristic: an intruder present for the
//!   whole run, from the start, behaving like a normal node and not
//!   touching motion topics, can only be caught by the operator reviewing
//!   the participant list. See the `learner` docs.

pub mod input;
pub mod learner;
pub mod ops;
pub mod profile_file;
pub mod signoff;
pub mod stats;

pub use input::{
    CaptureDiagnostics, EventSource, InputError, InputSpec, JsonlSource, Origin, PcapSource,
    SourcedEvent, VecSource,
};
pub use learner::{
    envelope_bound, is_motion_like, Commissioning, CommissioningReport, ConfigError, LearnConfig,
    Learner, Limits, ParticipantStatus, ProfileSlot, RawTopicReport, SeenAt, ServiceReport,
    Warning, WarningLevel, PARAMETER_SERVICES, ROS_INTERNAL_RAW_TOPICS,
};
pub use ops::{
    check_event, diff, lock, lock_draft_text, lock_draft_text_with_caps, lock_with_caps, lockable,
    lockable_with_caps, merge_profiles, merge_profiles_with_caps, CheckReport, Checker, HardCaps,
    LockRefusal, MergeError, ProfileDiff,
};
pub use profile_file::{
    parse_profile_text, sealed_text, write_file_atomic, write_files_atomic, ProfileFileError,
};
pub use signoff::{Signoff, SignoffItem};
pub use stats::{SampleBuffer, SpeedStats};

/// Serialise a value as pretty JSON with a trailing newline. All file output
/// goes through here so `learn` twice over the same input is byte-identical.
pub fn to_json<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut s = serde_json::to_string_pretty(value)?;
    s.push('\n');
    Ok(s)
}
