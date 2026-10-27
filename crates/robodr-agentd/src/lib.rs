//! `robodr-agentd`: the RoboDR decision chain as a long-running daemon.
//!
//! Until now the chain (pipeline finding -> agent -> firewall / responder /
//! motion monitor -> black box -> OCSF) only ran as an offline JSONL replay
//! (`robodr-replay`). This crate runs it live, with std threads and
//! `std::sync::mpsc` only (no tokio, no Pulsar):
//!
//! ```text
//!  AF_PACKET capture ┐                                  ┌─ Pipeline (robodr-ros2-pipeline)
//!  pcap replay ──────┤ Datagram                         │   tick() 1 Hz, capture_findings(health)
//!  SPDP socket ──────┤──────────┐   bounded queue       │   Finding ─► Agent::handle_external(Sensor)
//!                    │          │                       │   MotionCommand / MotionFeedback (decoded user DATA) ─► Agent::handle
//!                    │          ├─► (try_send, drops ─► main thread ┤
//!  JSONL stdin ──────┤ RobotEvent   counted)            │   RobotEvent ─► Agent::handle
//!  JSONL unix socket ┘                                  │        (profile + firewall + motion monitor)
//!                                                       │   Outcome ─► black box (signed, chained)
//!                                                       │           ─► spool/ready/<seq>.json (OCSF)
//!                                                       └─ self-health ─► Agent::handle_external(SelfHealth)
//!                                                          status.json, heartbeat notes
//! ```
//!
//! * [`config`]: the single JSON configuration (profile, policy, black-box
//!   dir, key **file** with a 0600 check, spool, inputs, context, thresholds);
//!   the `sensor` section is the ROS 2 sensor's own config, validated by it.
//! * [`input`]: the input threads, bounded queue and hostile-input handling.
//! * [`daemon`]: the main loop, housekeeping and ordered shutdown; live
//!   motion data decoded by the pipeline goes to `Agent::handle`, with the
//!   firewall recording only (see [`daemon`]).
//! * [`health`]: self-protection. The robot's state is `unknown` whenever
//!   the agent is blind (an input silent or ended, no data yet, pipeline
//!   lagging), never `ok`; issues become observe-only findings.
//! * [`safety`]: the live safety-state feed (e-stop / mode / odometry
//!   topics decoded passively from the bus, or a safety-PLC gateway's
//!   unix socket): freshness -> `unknown`, conflicts -> the most
//!   conservative state, unprofiled writers ignored and reported,
//!   transitions in the black box. Without it the configured
//!   `context.safety_state` is used.
//! * [`host`]: the optional `host_threats` socket: Pulsar threats handed
//!   over by the `robodr-threat-forward` Pulsar module (peer-uid checked,
//!   strictly parsed, heartbeat liveness) become host-side correlation
//!   signals and `robot.host.pulsar_threat` findings.
//! * [`control`]: the optional control-plane API `robodr-control-plane/v2`
//!   (`control_plane`, off by default): over mutual TLS (or loopback / a
//!   unix socket), a SOC's Ed25519-signed, replay-protected action request
//!   (the seven catalog actions, nothing beyond a safe-state *request*) is
//!   judged with the response policy against the current safety state,
//!   recorded in the black box and a persistent journal and answered
//!   (signed) `refused` or `recorded_not_executed`; black-box evidence is
//!   exported as signed, chunked bundles. Nothing is executed.
//! * [`spool`]: atomic, bounded findings spool; acked records are pruned
//!   oldest first, unacked ones never.
//! * [`notify`]: `sd_notify` (`READY=1`, `WATCHDOG=1` from the main loop,
//!   `STOPPING=1`) with std only, and the `CLOCK_MONOTONIC` stamp that lets
//!   a consumer tell a stale `status.json` from a live one.
//! * [`profile_chain`]: the black box as the second witness of profile
//!   anti-rollback (accepted-profile records; a deleted or rewritten state
//!   file is detected at the next start).
//! * [`signal`]: SIGTERM / SIGINT through `extern "C"` `signal(2)` and an
//!   `AtomicBool`.
//!
//! # Protective scope
//!
//! The daemon reads (passive capture, a receive-only socket, local event
//! streams), records and reports. Plans are produced and recorded but never
//! executed (the agent's `NoopExecutor`); nothing is sent to the robot, the
//! network or the safety system. Self-health findings are observe-only by
//! construction, so neither a fault nor an attacker starving an input can
//! cause a motion request. Control-plane requests from a SOC are judged
//! and recorded the same way and answered `recorded_not_executed`: the
//! control plane's only executor records, it never acts.
//!
//! # Limits (see README)
//!
//! Verified with synthetic pcaps, in-process and with the real binary under
//! SIGTERM; **not** verified on a robot, with real DDS stacks, with live
//! `AF_PACKET` at line rate (needs `CAP_NET_RAW`), or against a real
//! exporter. The safety state comes from the live feed ([`safety`]) when
//! one is configured, else from static configuration; the feed was only
//! run against synthetic traffic, not a real safety PLC or e-stop. The
//! rest of the operational context (control mode, mission phase,
//! connectivity) is still static configuration. The black box uses the
//! HMAC placeholder key.

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

pub mod config;
pub mod control;
pub mod daemon;
/// executor v1 link (robodr-executor process; `executor.enabled`).
pub mod executor_link;
/// Discovery-flood aggregation of pipeline findings (red team F1).
pub mod flood;
pub mod health;
pub mod host;
pub mod input;
pub mod notify;
pub mod profile_chain;
pub mod safety;
pub mod signal;
pub mod spool;

pub use config::{load, DaemonConfig, Resolved};
pub use daemon::{
    agent_profile, effective_state, run, run_with, DaemonError, DaemonStats, StopReason, Summary,
};
pub use health::{HealthState, State};
pub use safety::{SafetyFeed, SafetyReport};
pub use spool::{Spool, SpoolClass, SpoolRecord, SpoolStats};
