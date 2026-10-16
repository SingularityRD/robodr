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
//! * [`spool`]: atomic, bounded findings spool; acked records are pruned
//!   oldest first, unacked ones never.
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
//! cause a motion request.
//!
//! # Limits (see README)
//!
//! Verified with synthetic pcaps, in-process and with the real binary under
//! SIGTERM; **not** verified on a robot, with real DDS stacks, with live
//! `AF_PACKET` at line rate (needs `CAP_NET_RAW`), or against a real
//! exporter. The safety state is static configuration (no live feed). The
//! black box uses the HMAC placeholder key.

pub mod config;
pub mod daemon;
pub mod health;
pub mod input;
pub mod signal;
pub mod spool;

pub use config::{load, DaemonConfig, Resolved};
pub use daemon::{agent_profile, run, DaemonError, DaemonStats, StopReason, Summary};
pub use health::{HealthState, State};
pub use spool::{Spool, SpoolRecord, SpoolStats};
