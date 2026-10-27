//! Pulsar-independent ROS 2 / DDS detection pipeline for RoboDR.
//!
//! This crate is everything the ROS 2 sensor does **except** talking to
//! Pulsar: it depends only on `std`, `robodr-events`, `robodr-rtps`,
//! `robodr-capture`, `robodr-commission` (profile file check) and serde, so
//! it builds and is tested offline, and the
//! same code runs inside the Pulsar module (`robodr-sensor-ros2`), in the lab
//! tool [`robodr-ros2-watch`](#the-robodr-ros2-watch-tool) and in CI.
//!
//! ```text
//!  SPDP multicast socket ─┐            (socket.rs, async glue in the sensor)
//!  live AF_PACKET capture ┼─ Datagram ─► Pipeline ─► Finding ─► threat / JSON line
//!  pcap / pcapng replay ──┘  (source.rs)  (pipeline.rs)
//! ```
//!
//! - [`source`]: the blocking, std-only [`DatagramSource`] seam and
//!   [`CaptureDatagramSource`], an adapter over `robodr-capture`'s
//!   `rtps_datagrams` for live `AF_PACKET` and pcap/pcapng files.
//! - [`pipeline`]: [`Pipeline`] = detailed RTPS parse with one long-lived,
//!   bounded `FragmentReassembler` -> `Profile::evaluate` + removal,
//!   anomaly and fragmentation findings -> bounded dedup -> [`Finding`]s
//!   stamped observe / enforce. The profile is validated at load
//!   (`Profile::validate`) and a locked profile file must pass the
//!   commissioning file check (`robodr_commission::parse_profile_text`:
//!   strict keys and the lock seal, so a locked profile edited after
//!   `robodr-commission lock` is refused); a profile that fails either is
//!   **refused for enforcement** and the pipeline runs observe-only (see
//!   [`pipeline`] for why).
//! - [`motion`]: the live motion decode path: RTPS user DATA on profiled
//!   motion channels and configured feedback topics → `robodr-cdr` →
//!   `MotionCommand` / `MotionFeedback` ([`Pipeline::process_with_motion_at`]),
//!   envelope evaluation and motion-sample findings.
//! - [`profile_trust`]: [`load_profile_with_trust`] adds the trust check
//!   (detached Ed25519 signature from a trusted key, profile metadata,
//!   platform/unit binding, anti-rollback state) configured by the
//!   `profile_trust` sub-table; a locked profile that fails it is refused
//!   for enforcement the same way. The plain [`load_profile`] trusts no key.
//! - [`binding`]: the participant ↔ source-IP binding table. SEDP endpoint
//!   announcements are judged against the IPs and locators their
//!   participant's SPDP came from (or `participant_ips` pins), so a rogue
//!   host announcing a `cmd_vel` writer under a profiled participant's GUID
//!   prefix is caught (`robot.ros2.endpoint_source_mismatch`, Critical).
//! - [`ratelimit`]: per-rule token buckets for `robot.rtps.*` /
//!   `robot.capture.*` findings.
//! - [`config`]: the `[module.robodr-sensor-ros2]` section (incl. the
//!   `capture` sub-table) and its validation: domain id -> SPDP port, capture
//!   [`RtpsPortMap`], default interfaces.
//! - [`socket`]: the receive-only, `SO_REUSEADDR`, group-bound SPDP socket.
//! - [`sanitize()`] and [`dedup`]: attacker-controlled text and memory bounds.
//! - [`watch`]: argument parsing and the run loop of `robodr-ros2-watch`.
//!
//! # Read-only
//!
//! Nothing here transmits on the network. Enforcement (restricting motion,
//! requesting a safe state) is the Motion Firewall's and the responder's job;
//! this crate only reports, and marks what must never be acted upon.
//!
//! # The `robodr-ros2-watch` tool
//!
//! Runs the pipeline over a capture file or (Linux, `CAP_NET_RAW`) a live
//! interface and prints one JSON object per finding (the [`ThreatExtra`]
//! fields) on stdout. See `robodr-ros2-watch --help` and the README.
//!
//! # Limits
//!
//! Shared-memory DDS transports, RTPS over TCP and DDS-Security-protected
//! discovery are invisible or opaque (see `robodr-capture` / `robodr-rtps`).
//! The RTPS parser and this pipeline have only been exercised on synthetic
//! datagrams, not on captures from real DDS stacks yet.

// S10: `unsafe` is denied crate-wide; each item that needs it (FFI to libc
// symbols std already links) carries a local `#[allow(unsafe_code)]` and a
// `// SAFETY:` comment on every block.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
// S10 (R9): release builds use `panic = "abort"`, so any panic kills the
// daemon (systemd restarts it; docs/OPERATIONS.md, "Crashes and restarts").
// Non-test code has no unwrap / expect / panic!-family call; slice indexing
// and arithmetic are left to review and fuzzing (fuzz/README.md).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod binding;
pub mod config;
pub mod dedup;
pub mod identity;
pub mod legacy;
pub mod motion;
pub mod pipeline;
pub mod profile_trust;
pub mod ratelimit;
pub mod sanitize;
pub mod socket;
pub mod source;
pub mod watch;

pub use binding::{BindingOptions, BindingStats, BindingTable, Ingress, QuarantineTarget, Rank};
pub use config::{
    BindingConfig, CaptureConfig, CaptureInput, CaptureSettings, Config, Settings, SpdpSettings,
    UnitreeLegacyConfig,
};
pub use dedup::DedupSet;
pub use identity::{IdentityResolver, IdentityStats, NodeEvidence, Resolution};
pub use legacy::{LegacyOptions, LegacyStats};
pub use motion::{JointCommandSample, MotionOptions, MotionSample, MotionStats, SampleAttribution};
pub use pipeline::{
    load_profile, rules, Finding, LoadedProfile, Pipeline, PipelineOptions, PipelineStats,
    ProcessOutput, ProfileStatus, ThreatExtra, OBSERVE_ONLY_TAG,
};
pub use profile_trust::{
    load_profile_deferred, load_profile_with_trust, ProfileTrustConfig, StateCommit,
};
pub use sanitize::{sanitize, MAX_TEXT_CHARS};
pub use source::{
    CaptureDatagramSource, CaptureHealth, Datagram, DatagramSource, LegacyUdp,
    MergedDatagramSource, SharedHealth, VecDatagramSource,
};

// Re-exported so the Pulsar glue needs no direct dependency on these crates.
pub use robodr_capture::RtpsPortMap;
pub use robodr_events::{Deviation, Mode, Severity};
pub use robodr_rtps::{ReassemblyLimits, UserDataLimits};
