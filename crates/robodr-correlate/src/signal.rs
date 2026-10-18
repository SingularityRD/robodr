//! Input to the engine: one timestamped detection ("signal").
//!
//! A signal is what a detector already reported on its own: a
//! [`Deviation`] from the ROS 2 pipeline / agent, or a Pulsar threat from a
//! host rule. The engine never sees raw packets or syscalls; it only
//! combines these verdicts.
//!
//! Entity values (participant GUID prefixes, IP strings, process paths) may
//! be attacker-influenced. They are bounded on entry ([`Limits`]), never
//! interpreted, and only compared for equality.

use robodr_events::{Deviation, Mode, Severity};
use serde::{Deserialize, Serialize};

use crate::engine::Limits;

/// What a signal is about. Correlation rules group and count by these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// A DDS participant, by GUID prefix (as `robodr-events` prints it).
    Participant,
    /// A network source address (the pipeline's `src_ip`).
    Ip,
    /// A host process (robodr-agentd uses the pid; the producer chooses a stable
    /// form and documents it).
    Process,
    /// A robot / unit id (useful when one engine is fed by several units,
    /// e.g. on a gateway; on a robot every signal is from the same unit).
    Unit,
}

impl EntityKind {
    /// Lower-case name as used in rule JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            EntityKind::Participant => "participant",
            EntityKind::Ip => "ip",
            EntityKind::Process => "process",
            EntityKind::Unit => "unit",
        }
    }
}

/// One `(kind, value)` pair attached to a signal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Entity {
    pub kind: EntityKind,
    pub value: String,
}

/// Which side of the robot a signal comes from. Lets a rule demand that a
/// finding is backed by *independent* sensors (host and network).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    /// ROS 2 graph, RTPS discovery, packet capture, DDS (`robot.ros2.*`,
    /// `robot.rtps.*`, `robot.dds.*`, `robot.capture.*`, `robot.sensor.*`,
    /// `robot.bus.*`).
    Network,
    /// Motion commands and feedback (`robot.motion.*`, `robot.firewall.*`).
    Motion,
    /// Host runtime security (Pulsar threats, e.g. `RoboDR: ...` rules).
    Host,
    /// The agent's own health (`robot.agent.*`; observe-only downstream).
    Agent,
    /// Anything else (`robot.profile.*`, unknown `robot.*` ids).
    Other,
}

impl Domain {
    /// The domain implied by a rule id. Ids that do not start with `robot.`
    /// are taken to be Pulsar rule names, i.e. [`Domain::Host`].
    pub fn infer(rule: &str) -> Domain {
        const NET: &[&str] = &[
            "robot.ros2.",
            "robot.rtps.",
            "robot.dds.",
            "robot.capture.",
            "robot.sensor.",
            "robot.bus.",
        ];
        if NET.iter().any(|p| rule.starts_with(p)) {
            Domain::Network
        } else if rule.starts_with("robot.motion.") || rule.starts_with("robot.firewall.") {
            Domain::Motion
        } else if rule.starts_with("robot.agent.") {
            Domain::Agent
        } else if rule.starts_with("robot.") {
            Domain::Other
        } else {
            Domain::Host
        }
    }
}

/// One detection fed to [`crate::Correlator::observe`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    /// Monotonic time of the detection, nanoseconds. The engine only uses
    /// differences; a value smaller than an earlier one is clamped (see
    /// [`crate::Stats::clock_regressions`]).
    pub t_ns: u64,
    /// Rule id (`robot.*` deviation rule or Pulsar rule name).
    pub rule: String,
    pub severity: Severity,
    /// Observe-only inputs make every finding they contribute to
    /// observe-only.
    #[serde(default)]
    pub mode: Mode,
    pub domain: Domain,
    /// What the signal is about. Bounded by [`Limits::max_entities_per_signal`].
    #[serde(default)]
    pub entities: Vec<Entity>,
    /// Opaque evidence reference (e.g. a black-box record ref or finding
    /// uid), copied into every finding the signal contributes to.
    #[serde(default)]
    pub evidence_ref: Option<String>,
}

impl Signal {
    /// A signal with the domain inferred from `rule` and enforce mode.
    pub fn new(t_ns: u64, rule: impl Into<String>, severity: Severity) -> Self {
        let rule = rule.into();
        Signal {
            t_ns,
            domain: Domain::infer(&rule),
            rule,
            severity,
            mode: Mode::Enforce,
            entities: Vec::new(),
            evidence_ref: None,
        }
    }

    /// A signal for a deviation (rule, severity and mode copied).
    pub fn from_deviation(t_ns: u64, dev: &Deviation) -> Self {
        Signal::new(t_ns, dev.rule_str(), dev.severity).with_mode(dev.mode)
    }

    /// A host-side signal for a Pulsar threat raised by rule `rule_name`.
    pub fn host(t_ns: u64, rule_name: impl Into<String>, severity: Severity) -> Self {
        Signal::new(t_ns, rule_name, severity).with_domain(Domain::Host)
    }

    #[must_use]
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub fn with_domain(mut self, domain: Domain) -> Self {
        self.domain = domain;
        self
    }

    /// Attach an entity (bounded later, on entry into the engine).
    #[must_use]
    pub fn with_entity(mut self, kind: EntityKind, value: impl Into<String>) -> Self {
        self.entities.push(Entity {
            kind,
            value: value.into(),
        });
        self
    }

    #[must_use]
    pub fn with_evidence_ref(mut self, r: impl Into<String>) -> Self {
        self.evidence_ref = Some(r.into());
        self
    }
}

/// Truncate `s` to at most `max` bytes on a char boundary. Returns whether
/// anything was cut.
pub(crate) fn truncate_in_place(s: &mut String, max: usize) -> bool {
    if s.len() <= max {
        return false;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    true
}

/// The bounded entity list of a signal: at most
/// `limits.max_entities_per_signal` entries, each value at most
/// `limits.max_value_len` bytes, exact duplicates removed, sorted (so the
/// order a producer attached them in cannot change the outcome).
/// Returns `(entities, dropped, truncated)`.
pub(crate) fn bounded_entities(sig: &Signal, limits: &Limits) -> (Vec<Entity>, u64, u64) {
    let mut out: Vec<Entity> = Vec::new();
    let mut dropped = 0u64;
    let mut truncated = 0u64;
    for e in &sig.entities {
        if out.len() >= limits.max_entities_per_signal {
            dropped += 1;
            continue;
        }
        let mut v = e.value.clone();
        if truncate_in_place(&mut v, limits.max_value_len) {
            truncated += 1;
        }
        let ent = Entity {
            kind: e.kind,
            value: v,
        };
        if !out.contains(&ent) {
            out.push(ent);
        }
    }
    out.sort();
    (out, dropped, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_inference() {
        assert_eq!(
            Domain::infer("robot.ros2.unknown_participant"),
            Domain::Network
        );
        assert_eq!(
            Domain::infer("robot.rtps.discovery_not_inspected"),
            Domain::Network
        );
        assert_eq!(
            Domain::infer("robot.capture.ip_fragment_refused"),
            Domain::Network
        );
        assert_eq!(
            Domain::infer("robot.dds.unknown_raw_writer"),
            Domain::Network
        );
        assert_eq!(
            Domain::infer("robot.motion.uncommanded_motion"),
            Domain::Motion
        );
        assert_eq!(
            Domain::infer("robot.firewall.rejected_stale"),
            Domain::Motion
        );
        assert_eq!(Domain::infer("robot.agent.input_silent"), Domain::Agent);
        assert_eq!(
            Domain::infer("robot.profile.invalid_envelope"),
            Domain::Other
        );
        assert_eq!(
            Domain::infer("RoboDR: Interactive shell started on robot controller"),
            Domain::Host
        );
        assert_eq!(Domain::infer(""), Domain::Host);
    }

    #[test]
    fn from_deviation_copies_mode() {
        let d = Deviation::new("robot.ros2.unknown_participant", Severity::High, "x")
            .with_mode(Mode::Observe);
        let s = Signal::from_deviation(5, &d);
        assert_eq!(s.rule, "robot.ros2.unknown_participant");
        assert_eq!(s.mode, Mode::Observe);
        assert_eq!(s.severity, Severity::High);
        assert_eq!(s.domain, Domain::Network);
        assert_eq!(s.t_ns, 5);
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let mut s = "aé".repeat(10);
        assert!(truncate_in_place(&mut s, 4));
        assert!(s.len() <= 4);
        assert!(s.is_char_boundary(s.len()));
        let mut t = String::from("abc");
        assert!(!truncate_in_place(&mut t, 3));
        let mut u = String::from("é");
        assert!(truncate_in_place(&mut u, 1));
        assert_eq!(u, "");
    }

    #[test]
    fn entities_bounded_dedup_sorted() {
        let limits = Limits {
            max_entities_per_signal: 3,
            max_value_len: 4,
            ..Limits::default()
        };
        let s = Signal::new(0, "robot.x", Severity::Low)
            .with_entity(EntityKind::Process, "zzzzzz")
            .with_entity(EntityKind::Ip, "1.2.3.4")
            .with_entity(EntityKind::Ip, "1.2.3.4")
            .with_entity(EntityKind::Ip, "9")
            .with_entity(EntityKind::Participant, "p");
        let (e, dropped, truncated) = bounded_entities(&s, &limits);
        assert_eq!(dropped, 1);
        assert_eq!(truncated, 3);
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].kind, EntityKind::Ip);
        assert_eq!(e[0].value, "1.2.");
        assert_eq!(e[2].value, "zzzz");
    }
}
