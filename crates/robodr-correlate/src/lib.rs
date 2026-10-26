//! RoboDR correlation engine: combines weak signals into stronger findings.
//!
//! RoboDR's detection has four parts: model profile, rules, anomaly models
//! and **correlation**, which combines individually weak signals into a
//! stronger one (e.g. new process + new ROS node + the source of the
//! velocity command changed = high severity). This crate is that last
//! part.
//!
//! ```text
//! Deviation (ROS 2 pipeline, agent)  ─┐
//! Pulsar threat (host rule name)     ─┼─► Signal ─► Correlator::observe ─► CorrelatedFinding
//! agentd self-health                 ─┘                                        │ .to_deviation()
//!                                                                              ▼
//!                                                   Agent::handle_external (robodr-agent)
//! ```
//!
//! * [`Signal`] — one detection that was already reported on its own: rule
//!   id, severity, mode, [`Domain`] (network / motion / host / agent),
//!   entities ([`EntityKind`]: participant, ip, process, unit), monotonic
//!   time and an optional evidence reference.
//! * [`RuleSet`] — declarative JSON rules ([`rules`] module docs): sequence,
//!   co-occurrence, threshold, distinct sources; validated at load.
//!   [`RuleSet::default_rules`] is the shipped set (`rules/default.json`).
//! * [`Correlator`] — the engine ([`engine`] module docs: time, memory,
//!   eviction, cooldown). Pure, deterministic, single-threaded, no I/O, no
//!   clock of its own, bounded memory, never panics.
//! * [`CorrelatedFinding`] — rule id `robot.correlate.*`, severity, mode,
//!   and every contributing signal (seq, rule, timestamps, entities,
//!   evidence ref) so the finding can be audited back to its inputs.
//!
//! # Invariants
//!
//! * Output severity is never below any contributor's and never above
//!   Critical.
//! * Output mode is observe if **any** contributor is observe-only, so a
//!   correlation cannot turn observe-only inputs (an unlocked profile,
//!   agent self-health) into an actionable finding.
//! * Correlation outputs (`robot.correlate.*`) are never consumed as input.
//! * The engine only *adds* findings. It never suppresses, rewrites or
//!   delays the individual signals; the integrator keeps reporting those.
//!
//! # Protective scope
//!
//! Detection only. The engine produces findings; what happens next is the
//! responder's decision under its own invariants (at most a safe-state
//! *request*).
//!
//! # Limits (not verified here)
//!
//! * The default rules and windows are engineering judgement grounded in
//!   the in-repo rule ids, not tuned against real fleet data; expect false
//!   positives during commissioning (run them in observe mode first).
//! * Unit-scoped rules (`group_by: null`) correlate signals that share no
//!   entity: host processes and DDS participants cannot be tied together
//!   without a process↔socket mapping that RoboDR does not have yet.
//! * Nothing feeds Pulsar threats into `robodr-agentd` yet; host signals
//!   here are exercised with synthetic input only.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

pub mod catalog;
pub mod engine;
pub mod rules;
pub mod signal;

pub use engine::{
    Contribution, CorrelatedFinding, Correlator, Limits, Stats, EVICTED_RULE_ID, MAX_KNOWN_ENTITIES,
};
pub use rules::{bump, Rule, RuleError, RuleFile, RuleSet, DEFAULT_RULES_JSON, RULE_ID_PREFIX};
pub use signal::{Domain, Entity, EntityKind, Signal};
