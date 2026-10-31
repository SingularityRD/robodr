//! The gateway's own findings (`robot.gateway.*`, findings contract 2.3):
//! what the gateway decided that the Motion Firewall's deviations
//! (`robot.firewall.*`, drained from the firewall) do not say.
//!
//! The decision path only **counts**: [`GatewayFindings::note`] adds to a
//! bounded table of (rule, channel) slots and keeps the first occurrence's
//! detail. Housekeeping turns each slot into one aggregated
//! [`Deviation`] ([`GatewayFindings::drain`]): "N times since the last
//! report, first: ...". A burst of refused trajectories is one finding per
//! housekeeping period and channel, never a flood. When the table is full
//! further (rule, channel) pairs are counted in
//! [`GatewayFindings::dropped`] and reported once as
//! [`rules::FINDINGS_DROPPED`].
//!
//! The deviations go to the events file and, with `findings_socket`, to
//! agentd's gateway feed (`crate::feed`), which turns them into findings of
//! the normal pipeline (black box, spool, responder).

use robodr_events::{Deviation, Mode, Severity};

/// Rule ids (`docs/contracts/robodr.findings.md` §3b).
pub mod rules {
    /// A joint trajectory (or `FollowJointTrajectory` goal) outside the
    /// channel's bounds was suppressed.
    pub const TRAJECTORY_REJECTED: &str = "robot.gateway.trajectory_rejected";
    /// A joint trajectory was slowed down in place to fit its bounds.
    pub const TRAJECTORY_TIME_SCALED: &str = "robot.gateway.trajectory_time_scaled";
    /// The payload of an enforced channel did not decode strictly: decided
    /// as an integrity failure (fail closed).
    pub const UNDECODABLE_COMMAND: &str = "robot.gateway.undecodable_command";
    /// A DATA_FRAG / key-only / non-standard sample of an enforced channel
    /// (or of an unknown writer the probe cannot read) was suppressed.
    pub const FRAGMENTED_COMMAND: &str = "robot.gateway.fragmented_command";
    /// An authorised writer GUID arrived from another (IP, MAC) than the
    /// one its stream is bound to.
    pub const WRITER_BINDING_CONFLICT: &str = "robot.gateway.writer_binding_conflict";
    /// A sequence-number jump beyond `rtps.max_sn_jump` was held back.
    pub const SEQUENCE_JUMP: &str = "robot.gateway.sequence_jump";
    /// Discovery announced a locator outside every queued port range.
    pub const PORT_BYPASS_RISK: &str = "robot.gateway.port_bypass_risk";
    /// A `restrict_motion` restriction was applied, changed, lifted or
    /// expired on the gateway.
    pub const RESTRICTION_CHANGED: &str = "robot.gateway.restriction_changed";
    /// The gateway's findings table was full: some findings were lost.
    pub const FINDINGS_DROPPED: &str = "robot.gateway.findings_dropped";
    /// Packets read later than `max_queue_delay_ns` over the last
    /// `overload_interval_ms` (findings contract 2.5; Medium, High from
    /// `overload_high_late` packets): decided with the firewall's fault
    /// verdict. Reported instead of one `robot.firewall.internal_fault`
    /// per burst ([`super::Overload`]).
    pub const OVERLOAD: &str = "robot.gateway.overload";

    /// Every id with its (lowest) severity.
    pub const ALL: [(&str, robodr_events::Severity); 10] = [
        (TRAJECTORY_REJECTED, robodr_events::Severity::High),
        (TRAJECTORY_TIME_SCALED, robodr_events::Severity::Medium),
        (UNDECODABLE_COMMAND, robodr_events::Severity::High),
        (FRAGMENTED_COMMAND, robodr_events::Severity::Medium),
        (WRITER_BINDING_CONFLICT, robodr_events::Severity::High),
        (SEQUENCE_JUMP, robodr_events::Severity::Medium),
        (PORT_BYPASS_RISK, robodr_events::Severity::High),
        (RESTRICTION_CHANGED, robodr_events::Severity::Low),
        (FINDINGS_DROPPED, robodr_events::Severity::Medium),
        (OVERLOAD, robodr_events::Severity::Medium),
    ];

    /// The severity of `rule` (`None`: not a gateway rule).
    pub fn severity(rule: &str) -> Option<robodr_events::Severity> {
        ALL.iter().find(|(r, _)| *r == rule).map(|(_, s)| *s)
    }
}

/// Most (rule, channel) slots between two drains.
pub const MAX_SLOTS: usize = 64;
/// Longest detail kept per slot (characters).
pub const MAX_DETAIL: usize = 300;

/// The first occurrence of a slot.
#[derive(Debug, Clone, PartialEq)]
pub struct Detail {
    /// A short stable reason (`unknown_joint`, `data_frag`, ...).
    pub reason: &'static str,
    /// Optional free text (a joint name, a locator), clipped.
    pub what: Option<String>,
    pub value: Option<f64>,
    pub limit: Option<f64>,
}

impl Detail {
    pub fn reason(reason: &'static str) -> Self {
        Detail {
            reason,
            what: None,
            value: None,
            limit: None,
        }
    }
}

#[derive(Debug, Clone)]
struct Slot {
    rule: &'static str,
    severity: Severity,
    /// Channel name (`None`: the whole gateway).
    channel: Option<String>,
    count: u64,
    first: Detail,
}

/// See the module docs.
#[derive(Debug, Default)]
pub struct GatewayFindings {
    slots: Vec<Slot>,
    /// (rule, channel) pairs not recorded since the last drain.
    pub dropped: u64,
    /// Every note ever recorded (status).
    pub total: u64,
}

fn clip(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_DETAIL)
        .collect()
}

impl GatewayFindings {
    /// Count one occurrence of `rule` on `channel`.
    pub fn note(
        &mut self,
        rule: &'static str,
        channel: Option<&str>,
        detail: impl FnOnce() -> Detail,
    ) {
        self.total = self.total.saturating_add(1);
        if let Some(s) = self
            .slots
            .iter_mut()
            .find(|s| s.rule == rule && s.channel.as_deref() == channel)
        {
            s.count = s.count.saturating_add(1);
            return;
        }
        if self.slots.len() >= MAX_SLOTS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let severity = rules::severity(rule).unwrap_or(Severity::Medium);
        let mut first = detail();
        first.what = first.what.as_deref().map(clip);
        self.slots.push(Slot {
            rule,
            severity,
            channel: channel.map(clip),
            count: 1,
            first,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty() && self.dropped == 0
    }

    /// One deviation per slot (and one for the dropped count), in `mode`;
    /// the table is emptied.
    pub fn drain(&mut self, mode: Mode) -> Vec<GatewayDeviation> {
        let mut out: Vec<GatewayDeviation> = self
            .slots
            .drain(..)
            .map(|s| {
                let mut d = format!(
                    "{} time(s) since the last report; first: {}",
                    s.count, s.first.reason
                );
                if let Some(w) = &s.first.what {
                    d.push_str(&format!(" ({w})"));
                }
                if let Some(v) = s.first.value {
                    d.push_str(&format!(", value {v}"));
                }
                if let Some(l) = s.first.limit {
                    d.push_str(&format!(", limit {l}"));
                }
                if let Some(c) = &s.channel {
                    d = format!("channel {c}: {d}");
                }
                GatewayDeviation {
                    deviation: Deviation::new(s.rule, s.severity, d).with_mode(mode),
                    channel: s.channel,
                    count: s.count,
                }
            })
            .collect();
        if self.dropped > 0 {
            out.push(GatewayDeviation {
                deviation: Deviation::new(
                    rules::FINDINGS_DROPPED,
                    Severity::Medium,
                    format!(
                        "{} gateway finding(s) were not recorded: more than {MAX_SLOTS} distinct \
                         (rule, channel) pairs in one housekeeping period",
                        self.dropped
                    ),
                )
                .with_mode(mode),
                channel: None,
                count: self.dropped,
            });
            self.dropped = 0;
        }
        out
    }
}

/// Overload accounting (`robot.gateway.overload`, sales-readiness T8): the
/// decision path counts every packet read later than `max_queue_delay_ns`
/// ([`Overload::note_late`], a counter only); housekeeping
/// ([`Overload::tick`]) opens a window at the first tick that sees one and
/// reports the window once it is `interval_ns` old: one finding per
/// interval at most, Medium, High from `high_late` late packets in it.
/// The packets themselves were decided by the firewall's fault verdict
/// (`fault_policy`); only the reporting changes.
#[derive(Debug, Clone)]
pub struct Overload {
    interval_ns: u64,
    high_late: u64,
    /// Monotonic start of the open window (`None`: none open).
    start_ns: Option<u64>,
    /// Late packets not yet reported.
    late: u64,
    /// The channel of the first of them (`None`: not a channel's).
    first_channel: Option<String>,
    /// Findings reported (status).
    pub reports: u64,
}

impl Overload {
    pub fn new(interval_ms: u64, high_late: u64) -> Self {
        Overload {
            interval_ns: interval_ms.saturating_mul(1_000_000),
            high_late,
            start_ns: None,
            late: 0,
            first_channel: None,
            reports: 0,
        }
    }

    /// Count one late packet (on `channel`).
    pub fn note_late(&mut self, channel: Option<&str>) {
        if self.late == 0 {
            self.first_channel = channel.map(clip);
        }
        self.late = self.late.saturating_add(1);
    }

    /// Late packets counted and not yet reported.
    pub fn pending(&self) -> u64 {
        self.late
    }

    /// Housekeeping at monotonic `now_ns`: the finding of a window that is
    /// `interval_ns` old, in `mode`.
    pub fn tick(&mut self, now_ns: u64, mode: Mode) -> Option<GatewayDeviation> {
        if self.late == 0 {
            return None;
        }
        let start = *self.start_ns.get_or_insert(now_ns);
        if now_ns.saturating_sub(start) < self.interval_ns {
            return None;
        }
        let count = std::mem::take(&mut self.late);
        self.start_ns = None;
        self.reports = self.reports.saturating_add(1);
        let severity = if count >= self.high_late {
            Severity::High
        } else {
            Severity::Medium
        };
        let mut d = format!(
            "{count} packet(s) read later than max_queue_delay_ns in the last {} s, decided \
             with the firewall's fault verdict (fault_policy)",
            now_ns.saturating_sub(start) / 1_000_000_000
        );
        if severity == Severity::High {
            d.push_str(&format!(
                " (at or above overload_high_late {})",
                self.high_late
            ));
        }
        let channel = self.first_channel.take();
        if let Some(c) = &channel {
            d.push_str(&format!("; first on channel {c}"));
        }
        Some(GatewayDeviation {
            deviation: Deviation::new(rules::OVERLOAD, severity, d).with_mode(mode),
            channel,
            count,
        })
    }
}

/// One aggregated gateway deviation.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayDeviation {
    pub deviation: Deviation,
    pub channel: Option<String>,
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_per_rule_and_channel_and_bounds_the_table() {
        let mut f = GatewayFindings::default();
        for _ in 0..1000 {
            f.note(rules::TRAJECTORY_REJECTED, Some("/arm"), || Detail {
                what: Some("joint_1\u{7}".into()),
                value: Some(3.0),
                limit: Some(2.0),
                ..Detail::reason("velocity")
            });
        }
        f.note(rules::SEQUENCE_JUMP, Some("/arm"), || {
            Detail::reason("jump")
        });
        for i in 0..100 {
            let name = format!("/c{i}");
            f.note(rules::UNDECODABLE_COMMAND, Some(&name), || {
                Detail::reason("decode")
            });
        }
        let d = f.drain(Mode::Enforce);
        assert_eq!(d.len(), MAX_SLOTS + 1);
        assert_eq!(d[0].count, 1000);
        assert_eq!(d[0].deviation.severity, Severity::High);
        assert!(
            d[0].deviation.detail.contains("(joint_1)"),
            "{}",
            d[0].deviation.detail
        );
        assert_eq!(d.last().unwrap().deviation.rule, rules::FINDINGS_DROPPED);
        assert!(f.is_empty());
        assert!(f.drain(Mode::Observe).is_empty());
    }

    #[test]
    fn overload_is_one_finding_per_interval_with_a_high_threshold() {
        const S: u64 = 1_000_000_000;
        let mut o = Overload::new(60_000, 100);
        assert!(o.tick(0, Mode::Enforce).is_none());
        for _ in 0..10 {
            o.note_late(Some("/lowcmd"));
        }
        // The window opens at the first tick that sees a late packet.
        assert!(o.tick(5 * S, Mode::Enforce).is_none());
        o.note_late(Some("/other"));
        assert!(o.tick(64 * S, Mode::Enforce).is_none());
        let d = o.tick(65 * S, Mode::Enforce).unwrap();
        assert_eq!(d.deviation.rule_str(), rules::OVERLOAD);
        assert_eq!(d.deviation.severity, Severity::Medium);
        assert_eq!((d.count, d.channel.as_deref()), (11, Some("/lowcmd")));
        assert!(o.tick(200 * S, Mode::Enforce).is_none());
        for _ in 0..100 {
            o.note_late(None);
        }
        assert!(o.tick(300 * S, Mode::Observe).is_none());
        let d = o.tick(360 * S, Mode::Observe).unwrap();
        assert_eq!(d.deviation.severity, Severity::High);
        assert!(d.deviation.is_observe_only());
        assert_eq!(o.reports, 2);
    }
}
