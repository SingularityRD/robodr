//! RoboDR agent: the first end-to-end decision chain, offline.
//!
//! This crate composes the pure RoboDR crates into the Phase 1/2 chain:
//!
//! ```text
//! RobotEvent
//!   → robodr_events::Profile::evaluate          (+ Motion Firewall, + motion monitor)
//!   → Deviation (mode = profile's observe/enforce)
//!   → robodr_responder::Responder::plan         (SafetyState, OperationalContext, ResponsePolicy)
//!   → ResponsePlan + Disposition
//!   → robodr_blackbox::Recorder                 (event, firewall verdict, deviation, plan)
//!   → robodr_ocsf::FindingBuilder               (evidence links = the black-box refs)
//!   → validated robodr.findings record (key + JSON)
//!   → Executor::submit                          (no-op / dry-run log: nothing is executed)
//! ```
//!
//! * [`Agent`] — the chain for one robot ([`agent`] module docs list the
//!   invariants it holds). [`Agent::handle_external`] runs the response
//!   half for deviations raised elsewhere (the ROS 2 pipeline, a daemon's
//!   self-health checks; the latter are always observe-only), and
//!   [`Agent::record_note`] appends a free-form note (e.g. a heartbeat). The
//!   live daemon around it is `robodr-agentd`.
//! * [`Executor`] — the seam for a future executor; [`NoopExecutor`] and
//!   [`LoggingExecutor`] act on nothing. A real executor must re-run
//!   [`robodr_responder::check_invariants`] ([`ExecutionRequest::recheck`]).
//! * [`evidence`] — verify the black box and resolve every finding's
//!   evidence links to signed records.
//! * [`replay`] — JSONL replay used by the `robodr-replay` binary.
//! * [`clock`] — injected time ([`ReplayClock`] for deterministic runs).
//!
//! # Protective scope
//!
//! The agent detects, records and *plans*. It sends nothing to the robot,
//! the network or the safety system. Plans never go beyond
//! `request_safe_state`, and they are only requests for other components.
//!
//! # What is not verified
//!
//! * No real sensor feeds it: input is synthetic JSONL or test vectors. The
//!   ROS 2 sensor (`robodr-sensor-ros2`) and Pulsar glue do not call it yet.
//! * The response policy, motion monitor thresholds and firewall limits are
//!   unvalidated engineering defaults (see each crate's README).
//! * The black box signs with whatever key the caller supplies: Ed25519
//!   (agentd's default, via `ed25519-dalek`) or legacy HMAC-SHA256 (the
//!   `robodr-replay` default, kept for compatibility). Keys are files, not
//!   TPM-held.
//! * Findings are validated by the in-repo OCSF validator only, not by an
//!   OCSF schema server or a running SOC consumer.
//! * `MotionCommand` has no source stamp and no angular/per-joint values, so
//!   the firewall's stale/future checks and angular limits are not exercised
//!   through this path (see [`agent`] for the mapping).
//! * Black-box recovery after a real disk failure (ENOSPC, EIO) is tested
//!   only with simulated failures (a failing signer, a removed directory).

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

pub mod agent;
pub mod clock;
pub mod config;
pub mod evidence;
pub mod executor;
pub mod outcome;
pub mod replay;

pub use agent::{
    guard, ocsf_safety, source_key, Agent, AgentStats, Finished, JointInput,
    BLACKBOX_REOPEN_BACKOFF_NS, MAX_RETAINED_FAULTS,
};
pub use clock::{
    Clock, ClockAnomaly, ReplayClock, TimeGuard, TimeSource, Timestamp,
    DEFAULT_CLOCK_JUMP_TOLERANCE_NS,
};
pub use config::{
    channel_kind, kind_of_type, profile_sha256, strict_from_str, AgentConfig, AgentError,
    FirewallSettings, MonitorSettings, MAX_TRACKED_FINDINGS,
};
pub use evidence::{finding_refs, resolve_links, verify_blackbox, LinkReport};
pub use executor::{ExecutionRequest, Executor, LoggingExecutor, NoopExecutor};
pub use outcome::{
    AgentFault, Detector, Disposition, EvidenceLinks, FaultKind, FindingOutput,
    FirewallVerdictRecord, JointVerdictDetail, Outcome,
};
