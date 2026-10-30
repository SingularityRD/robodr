//! The in-path gateway's findings feed (`gateway_feed`): `robodr-firewall-gw`
//! writes one JSON line per aggregated gateway finding (`robot.gateway.*`,
//! findings contract 2.3) and per Motion Firewall deviation
//! (`robot.firewall.*`) to this unix socket; agentd turns each into a
//! finding of its normal pipeline (black box, spool, responder,
//! correlation), source `gateway:<channel>`.
//!
//! ```json
//! {"format":"robodr-gateway-finding/v1","rule":"robot.gateway.trajectory_rejected",
//!  "severity":"high","detail":"channel /arm: 3 time(s) ...","mode":"enforce",
//!  "channel":"/arm","count":3}
//! ```
//!
//! The socket has the same shape and peer check as `host_threats`
//! ([`crate::host::bind_host_socket`]: root and `allowed_uids`, the
//! gateway's service user, may connect; the daemon's own uid too). A line
//! is parsed strictly ([`parse_gateway_line`]). An idle gateway also
//! writes a heartbeat line ([`HEARTBEAT_FORMAT`]): valid data on the input
//! (a quiet gateway is not a silent input), never a finding; a gateway
//! that stops writing is still reported silent after `daemon.silence_ms`.
//! For a finding line, unknown keys, another
//! format, a rule outside `robot.gateway.*` / `robot.firewall.*` (the
//! gateway cannot speak for any other detector) or not in the findings
//! catalog (`robodr_ocsf::builder::rule_known`), or oversized fields are
//! malformed and dropped (counted by the input). The detail is kept as the
//! gateway wrote it (sanitized when logged; tainted in the finding).
//!
//! # Trust boundary (red team 2026-10-30, W2-5)
//!
//! The feed is authenticated by the peer's uid only: root and the
//! gateway's service user (`allowed_uids`) are trusted to *report*
//! gateway and Motion Firewall decisions, nothing more. Such a process is
//! already privileged on the robot (it could stop the gateway); what it
//! must not be able to do through this socket is make agentd report
//! findings the gateway never emits, at severities the gateway never uses,
//! or at a rate that drowns everything else. So agentd, not the writer,
//! bounds what a line can become:
//!
//! * **Rule ids**: only catalogued ids of the gateway's own namespaces
//!   ([`parse_gateway_line`], fixed in `2876a46`, G3).
//! * **Severities**: each id has the range its emitter can produce
//!   ([`severity_range`]: the gateway's fixed severities, the firewall's
//!   per-rule ones, the WebRTC monitor's). A line outside it is reported
//!   at the nearest bound (a Critical firewall rule claimed `low` reads
//!   Critical; `robot.gateway.restriction_changed` claimed `critical`
//!   reads Low), counted as `gateway_severity_clamped`, and the detail
//!   says what was claimed (G7).
//! * **Rate**: each rule id has its own budget ([`RULE_BURST`] lines, then
//!   [`RULE_PER_MINUTE`] per minute) and all rules together
//!   [`ALL_BURST`] / [`ALL_PER_MINUTE`]. Lines over it are not reported
//!   one by one but folded: once per [`AGGREGATE_WINDOW_MS`] and rule, one
//!   finding of that rule at the worst severity it suppressed, naming how
//!   many lines (and gateway counts) and which channels (G8 / G9). The
//!   gateway already folds per (rule, channel) and housekeeping period, so
//!   a healthy gateway stays far below these budgets.
//!
//! What remains trusted: the mode (`observe` / `enforce`), the channel
//! name and the detail text of a line, and *that* the event happened. A
//! compromised gateway user can still invent catalogued findings within
//! their severity range and budget, or stay silent (which the silence
//! finding reports).

use std::collections::{BTreeMap, BTreeSet};

use robodr_events::Severity;
use serde::Deserialize;

use crate::host::{HostThreatsSection, HostThreatsSpec};
use crate::input::Payload;

/// Lines of one rule id reported one by one before its rate applies.
pub const RULE_BURST: u32 = 20;
/// Lines of one rule id reported one by one per minute after the burst.
pub const RULE_PER_MINUTE: u32 = 60;
/// Lines of all rules reported one by one before the global rate applies.
pub const ALL_BURST: u32 = 200;
/// Lines of all rules reported one by one per minute after the burst.
pub const ALL_PER_MINUTE: u32 = 600;
/// A rule's suppressed lines are folded into one finding per window.
pub const AGGREGATE_WINDOW_MS: u64 = 60_000;
/// Channel names kept per aggregate.
pub const AGGREGATE_CHANNELS: usize = 8;

/// The severities rule `rule`'s emitter can report (`None`: not a rule
/// the gateway emits). The gateway's own findings have one fixed severity
/// (`robodr_firewall_gw::findings::rules::ALL`), the Motion Firewall's
/// depend on the rule and, for a joint envelope, on whether the frame was
/// limited (High) or rejected (Critical); `events_dropped` carries the
/// worst lost event's (at least Medium); the WebRTC monitor raises an
/// unlisted controller to Critical once its session is established.
pub fn severity_range(rule: &str) -> Option<(Severity, Severity)> {
    use robodr_firewall::rules as fw;
    use robodr_ros2_pipeline::webrtc::rules as wr;
    use Severity::*;
    let fixed = |s| Some((s, s));
    Some(match rule {
        // robodr-firewall-gw's own findings (fixed severities).
        "robot.gateway.trajectory_rejected" => return fixed(High),
        "robot.gateway.trajectory_time_scaled" => return fixed(Medium),
        "robot.gateway.undecodable_command" => return fixed(High),
        "robot.gateway.fragmented_command" => return fixed(Medium),
        "robot.gateway.writer_binding_conflict" => return fixed(High),
        "robot.gateway.sequence_jump" => return fixed(Medium),
        "robot.gateway.port_bypass_risk" => return fixed(High),
        "robot.gateway.restriction_changed" => return fixed(Low),
        "robot.gateway.findings_dropped" => return fixed(Medium),
        // The WebRTC monitor.
        r if r == wr::UNKNOWN_CONTROLLER => (High, Critical),
        r if r == wr::NEW_PEER => (Medium, Medium),
        r if r == wr::CONTROLLER_MAC_MISMATCH => (High, High),
        r if r == wr::SESSION_IN_DENIED_WINDOW => (High, High),
        r if r == wr::CONCURRENT_SESSIONS => (High, High),
        r if r == wr::RELAYED_SESSION => (Medium, Medium),
        r if r == wr::MEDIA_WITHOUT_SIGNALLING => (Medium, Medium),
        // The Motion Firewall (robodr_firewall::reject_rule and
        // the engines' limit / joint records).
        r if r == fw::REJECTED_STALE => (Medium, Medium),
        r if [
            fw::REJECTED_CLOCK_REGRESSION,
            fw::REJECTED_UNKNOWN_CHANNEL,
            fw::REJECTED_RATE_LIMITED,
            fw::REJECTED_KIND_MISMATCH,
            fw::REJECTED_FUTURE_TIMESTAMP,
            fw::REJECTED_OUT_OF_ORDER,
            fw::CRC_INVALID,
            fw::LIMITED_SPEED,
        ]
        .contains(&r) =>
        {
            (High, High)
        }
        r if [
            fw::REJECTED_UNKNOWN_SOURCE,
            fw::REJECTED_UNAUTHORIZED_SOURCE,
            fw::REJECTED_NON_FINITE,
            fw::REJECTED_OVER_HARD_LIMIT,
            fw::INTERNAL_FAULT,
            fw::DISABLED_MOTOR_ENERGISED,
            fw::JOINT_GAIN_BELOW_MINIMUM,
            fw::JOINT_MODE_INCONSISTENT,
            fw::JOINT_MODE_PIN_MISMATCH,
            fw::JOINT_LIMP_FRAME,
            fw::JOINT_HOLD_EXCEEDED,
        ]
        .contains(&r) =>
        {
            (Critical, Critical)
        }
        // Limited (High) or rejected (Critical).
        r if [
            fw::JOINT_POSITION_OUT_OF_ENVELOPE,
            fw::JOINT_VELOCITY_OUT_OF_ENVELOPE,
            fw::JOINT_TORQUE_OUT_OF_ENVELOPE,
            fw::JOINT_GAIN_OUT_OF_ENVELOPE,
            fw::JOINT_STEP_OUT_OF_ENVELOPE,
            fw::JOINT_PD_TORQUE_OUT_OF_ENVELOPE,
        ]
        .contains(&r) =>
        {
            (High, Critical)
        }
        r if r == fw::LIMITED_ACCELERATION || r == fw::LIMITED_JERK => (Medium, Medium),
        r if r == fw::JOINT_RATE_VIOLATION => (Medium, Medium),
        r if r == fw::EVENTS_DROPPED => (Medium, Critical),
        _ => return None,
    })
}

/// The line format tag (`robodr_firewall_gw::feed::FORMAT`).
pub const FORMAT: &str = "robodr-gateway-finding/v1";
/// The heartbeat line's tag (`robodr_firewall_gw::feed::HEARTBEAT_FORMAT`):
/// `{"format":"robodr-gateway-heartbeat/v1","sent":N,"dropped":N}`, written
/// by an idle gateway so that a quiet feed is not read as a silent input.
pub const HEARTBEAT_FORMAT: &str = "robodr-gateway-heartbeat/v1";

/// A gateway heartbeat: the feed's cumulative lines sent and dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayHeartbeat {
    #[serde(rename = "format")]
    _format: HeartbeatTag,
    pub sent: u64,
    pub dropped: u64,
}

/// Only [`HEARTBEAT_FORMAT`] deserializes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeartbeatTag;

impl<'de> Deserialize<'de> for HeartbeatTag {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == HEARTBEAT_FORMAT {
            Ok(HeartbeatTag)
        } else {
            Err(serde::de::Error::custom("not a gateway heartbeat"))
        }
    }
}
/// Longest accepted detail (characters).
pub const MAX_DETAIL: usize = 1024;
/// Longest accepted rule id / channel name.
pub const MAX_RULE: usize = 128;
pub const MAX_CHANNEL: usize = 256;

/// `gateway_feed` in the configuration: the `host_threats` keys
/// (`socket_path`, `allowed_uids`, `socket_mode`, `max_connections`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct GatewayFeedSection(pub HostThreatsSection);

impl GatewayFeedSection {
    pub fn resolve(&self) -> Result<HostThreatsSpec, String> {
        self.0
            .resolve()
            .map_err(|e| e.replace("host_threats", "gateway_feed"))
    }
}

/// One gateway line.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayLine {
    pub format: String,
    pub rule: String,
    pub severity: robodr_events::Severity,
    pub detail: String,
    pub mode: robodr_events::Mode,
    #[serde(default)]
    pub channel: Option<String>,
    pub count: u64,
}

impl GatewayLine {
    /// The deviation this line stands for (rule, severity and mode as the
    /// gateway reported them; the detail names the gateway).
    pub fn deviation(&self) -> robodr_events::Deviation {
        robodr_events::Deviation::new(
            self.rule.clone(),
            self.severity,
            format!("in-path gateway: {}", self.detail),
        )
        .with_mode(self.mode)
    }

    /// The finding's source key.
    pub fn source(&self) -> String {
        format!("gateway:{}", self.channel.as_deref().unwrap_or("-"))
    }
}

fn rule_ok(r: &str) -> bool {
    // Only ids of the findings catalog: a line naming `robot.firewall.` or
    // a made-up id in the two namespaces would otherwise become a finding
    // with the generic catalog entry (red team 2026-10-30, G3).
    ((r.starts_with("robot.gateway.") || r.starts_with("robot.firewall."))
        && robodr_ocsf::builder::rule_known(r)
        // The gateway's WebRTC monitor: exactly its own ids.
        || robodr_ros2_pipeline::webrtc::rules::ALL
            .iter()
            .any(|(id, _)| *id == r))
        && r.len() <= MAX_RULE
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_')
        // W2-5: and a known severity range (every id the gateway emits has
        // one; a drift test keeps it so).
        && severity_range(r).is_some()
}

/// What the limiter decided for one line.
#[derive(Debug, Clone, PartialEq)]
pub enum Admitted {
    /// Report it (severity within the rule's range; `clamped` = the line
    /// claimed another one).
    Report { line: GatewayLine, clamped: bool },
    /// Over the rule's or the feed's budget: folded into the next
    /// aggregate.
    Folded,
}

#[derive(Debug, Clone)]
struct Budget {
    tokens: f64,
    burst: f64,
    per_ms: f64,
    at_ms: u64,
}

impl Budget {
    fn new(burst: u32, per_minute: u32, now_ms: u64) -> Self {
        Self {
            tokens: f64::from(burst),
            burst: f64::from(burst),
            per_ms: f64::from(per_minute) / 60_000.0,
            at_ms: now_ms,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        let dt = now_ms.saturating_sub(self.at_ms) as f64;
        self.tokens = (self.tokens + dt * self.per_ms).min(self.burst);
        self.at_ms = self.at_ms.max(now_ms);
    }
}

#[derive(Debug, Clone)]
struct Folded {
    since_ms: u64,
    lines: u64,
    counts: u64,
    worst: Severity,
    enforce: bool,
    channels: BTreeSet<String>,
    more_channels: bool,
}

#[derive(Debug, Clone)]
struct RuleState {
    budget: Budget,
    folded: Option<Folded>,
}

/// The per-rule rate and aggregation cap of the gateway feed (W2-5; see
/// the module docs). Times are daemon milliseconds.
#[derive(Debug, Clone)]
pub struct GatewayLimiter {
    rules: BTreeMap<String, RuleState>,
    all: Budget,
    /// Lines folded into aggregates so far.
    pub folded: u64,
    /// Aggregate findings reported so far.
    pub aggregates: u64,
    /// Lines whose severity was outside their rule's range.
    pub clamped: u64,
}

impl GatewayLimiter {
    pub fn new(now_ms: u64) -> Self {
        Self {
            rules: BTreeMap::new(),
            all: Budget::new(ALL_BURST, ALL_PER_MINUTE, now_ms),
            folded: 0,
            aggregates: 0,
            clamped: 0,
        }
    }

    /// Decide one parsed line (its rule has a range: [`parse_gateway_line`]).
    pub fn admit(&mut self, line: &GatewayLine, now_ms: u64) -> Admitted {
        let (lo, hi) = severity_range(&line.rule).unwrap_or((Severity::Low, Severity::Critical));
        let severity = line.severity.clamp(lo, hi);
        let clamped = severity != line.severity;
        if clamped {
            self.clamped += 1;
        }
        let st = self
            .rules
            .entry(line.rule.clone())
            .or_insert_with(|| RuleState {
                budget: Budget::new(RULE_BURST, RULE_PER_MINUTE, now_ms),
                folded: None,
            });
        st.budget.refill(now_ms);
        self.all.refill(now_ms);
        if st.budget.tokens >= 1.0 && self.all.tokens >= 1.0 {
            st.budget.tokens -= 1.0;
            self.all.tokens -= 1.0;
            let mut l = line.clone();
            if clamped {
                l.detail = format!(
                    "{} (severity claimed {:?}, outside this rule's range {lo:?}..={hi:?}: \
                     reported as {severity:?})",
                    l.detail, line.severity
                );
                l.severity = severity;
            }
            return Admitted::Report { line: l, clamped };
        }
        self.folded += 1;
        let f = st.folded.get_or_insert_with(|| Folded {
            since_ms: now_ms,
            lines: 0,
            counts: 0,
            worst: severity,
            enforce: false,
            channels: BTreeSet::new(),
            more_channels: false,
        });
        f.lines += 1;
        f.counts = f.counts.saturating_add(line.count);
        f.worst = f.worst.max(severity);
        f.enforce |= line.mode == robodr_events::Mode::Enforce;
        if let Some(c) = &line.channel {
            if f.channels.len() < AGGREGATE_CHANNELS || f.channels.contains(c) {
                f.channels.insert(c.clone());
            } else {
                f.more_channels = true;
            }
        }
        Admitted::Folded
    }

    /// The aggregates whose window ended by `now_ms` (one per rule, at the
    /// worst severity folded; `enforce` if any folded line was). Call it
    /// periodically; it also takes the aggregates when the window has not
    /// ended yet if `flush` (shutdown).
    pub fn drain(&mut self, now_ms: u64, flush: bool) -> Vec<GatewayLine> {
        let mut out = Vec::new();
        for (rule, st) in &mut self.rules {
            let due = st
                .folded
                .as_ref()
                .is_some_and(|f| flush || now_ms.saturating_sub(f.since_ms) >= AGGREGATE_WINDOW_MS);
            if !due {
                continue;
            }
            let Some(f) = st.folded.take() else {
                continue;
            };
            let secs = now_ms.saturating_sub(f.since_ms).div_ceil(1000).max(1);
            let channels = if f.channels.is_empty() {
                "-".to_string()
            } else {
                let mut c = f.channels.iter().cloned().collect::<Vec<_>>().join(", ");
                if f.more_channels {
                    c.push_str(", ...");
                }
                c
            };
            out.push(GatewayLine {
                format: FORMAT.to_string(),
                rule: rule.clone(),
                severity: f.worst,
                detail: format!(
                    "{} further line(s) of this rule ({} gateway occurrence(s)) folded by agentd \
                     in the last {secs} s: more than {RULE_BURST} at once or {RULE_PER_MINUTE} \
                     per minute for one rule ({ALL_PER_MINUTE} for the feed); worst severity \
                     {:?}; channels: {channels}",
                    f.lines, f.counts, f.worst
                ),
                mode: if f.enforce {
                    robodr_events::Mode::Enforce
                } else {
                    robodr_events::Mode::Observe
                },
                channel: None,
                count: f.counts.max(1),
            });
        }
        self.aggregates += out.len() as u64;
        out
    }
}

/// [`crate::input::LineParser`] of the gateway feed.
pub fn parse_gateway_line(t: &str) -> Result<Payload, String> {
    // By the `format` member itself, never by a substring: a finding's
    // detail may quote attacker-chosen text.
    #[derive(Deserialize)]
    struct Tag<'a> {
        #[serde(borrow)]
        format: std::borrow::Cow<'a, str>,
    }
    if serde_json::from_str::<Tag<'_>>(t).is_ok_and(|g| g.format == HEARTBEAT_FORMAT) {
        let h: GatewayHeartbeat =
            serde_json::from_str(t).map_err(|e| format!("not a gateway heartbeat: {e}"))?;
        return Ok(Payload::GatewayHeartbeat(h));
    }
    let l: GatewayLine =
        serde_json::from_str(t).map_err(|e| format!("not a gateway finding: {e}"))?;
    if l.format != FORMAT {
        return Err(format!("format must be {FORMAT}"));
    }
    if !rule_ok(&l.rule) {
        return Err("rule must be a robot.gateway.*, robot.firewall.* or WebRTC monitor id".into());
    }
    if l.detail.chars().count() > MAX_DETAIL
        || l.channel.as_deref().is_some_and(|c| {
            c.is_empty() || c.chars().count() > MAX_CHANNEL || c.chars().any(char::is_control)
        })
        || l.count == 0
    {
        return Err(
            "detail too long, channel empty / too long / with control characters, or \
                    count 0"
                .into(),
        );
    }
    Ok(Payload::Gateway(Box::new(l)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webrtc_findings_of_the_gateway_are_accepted_other_unitree_ids_not() {
        let line = |r: &str| {
            format!(
                r#"{{"format":"robodr-gateway-finding/v1","rule":"{r}","severity":"critical","detail":"x","mode":"enforce","channel":"webrtc","count":1}}"#
            )
        };
        for (id, _) in robodr_ros2_pipeline::webrtc::rules::ALL {
            assert!(parse_gateway_line(&line(id)).is_ok(), "{id}");
        }
        let fake = ["robot", "unitree", "webrtc_anything"].join(".");
        assert!(parse_gateway_line(&line(&fake)).is_err());
        assert!(parse_gateway_line(&line("robot.unitree.legacy_unknown_sender")).is_err());
        assert!(parse_gateway_line(&line(&["robot", "unitree", "webrtc"].join("."))).is_err());
    }

    #[test]
    fn lines_are_strict() {
        let good = r#"{"format":"robodr-gateway-finding/v1","rule":"robot.gateway.trajectory_rejected","severity":"high","detail":"channel /arm: 1","mode":"enforce","channel":"/arm","count":1}"#;
        let Ok(Payload::Gateway(l)) = parse_gateway_line(good) else {
            panic!("good line refused");
        };
        assert_eq!(l.source(), "gateway:/arm");
        let d = l.deviation();
        assert_eq!(d.rule_str(), "robot.gateway.trajectory_rejected");
        assert_eq!(d.severity, robodr_events::Severity::High);
        assert!(d.detail.starts_with("in-path gateway: "));
        let fw = good.replace(
            "robot.gateway.trajectory_rejected",
            "robot.firewall.rejected_stale",
        );
        assert!(parse_gateway_line(&fw).is_ok());
        for bad in [
            good.replace(
                "robot.gateway.trajectory_rejected",
                "robot.ros2.unknown_participant",
            ),
            good.replace("robot.gateway.trajectory_rejected", "robot.gateway.X"),
            good.replace("robodr-gateway-finding/v1", "v2"),
            good.replace("\"count\":1", "\"count\":0"),
            good.replace("\"/arm\",\"count\"", "\"\",\"count\""),
            good.replace("\"count\":1}", "\"count\":1,\"x\":1}"),
            good.replace("channel /arm: 1", &"x".repeat(MAX_DETAIL + 1)),
        ] {
            assert!(parse_gateway_line(&bad).is_err(), "{bad}");
        }
    }

    /// Soak 2026-10-30: the gateway's heartbeat line keeps a quiet feed
    /// alive; it is as strict as a finding line.
    #[test]
    fn heartbeat_lines_are_strict() {
        let hb = r#"{"format":"robodr-gateway-heartbeat/v1","sent":7,"dropped":2}"#;
        match parse_gateway_line(hb) {
            Ok(Payload::GatewayHeartbeat(h)) => assert_eq!((h.sent, h.dropped), (7, 2)),
            other => panic!("{other:?}"),
        }
        // A finding whose detail quotes the heartbeat tag stays a finding.
        let quoted = r#"{"format":"robodr-gateway-finding/v1","rule":"robot.gateway.trajectory_rejected","severity":"high","detail":"robodr-gateway-heartbeat/v1","mode":"enforce","channel":"/arm","count":1}"#;
        assert!(matches!(
            parse_gateway_line(quoted),
            Ok(Payload::Gateway(_))
        ));
        for bad in [
            hb.replace(
                "\"dropped\":2}",
                "\"dropped\":2,\"rule\":\"robot.gateway.x\"}",
            ),
            hb.replace("heartbeat/v1", "heartbeat/v2"),
            hb.replace(",\"dropped\":2", ""),
            hb.replace("7", "-1"),
        ] {
            assert!(parse_gateway_line(&bad).is_err(), "{bad}");
        }
    }

    /// Red team 2026-10-30 (gateway feed spoofing, G3): a line naming
    /// `robot.firewall.` (nothing after the prefix) was accepted and became
    /// a finding with that rule id and the generic catalog entry; so was any
    /// made-up id inside the two namespaces. Only catalogued ids pass now.
    #[test]
    fn only_catalogued_gateway_and_firewall_ids_are_accepted() {
        let line = |r: &str| {
            format!(
                r#"{{"format":"robodr-gateway-finding/v1","rule":"{r}","severity":"high","detail":"x","mode":"enforce","channel":"/x","count":1}}"#
            )
        };
        // Joined at run time: the catalog drift test of robodr-ocsf scans
        // the sources for rule id literals.
        let id = |parts: &[&str]| parts.join(".");
        for bad in [
            id(&["robot", "firewall", ""]),
            id(&["robot", "gateway", ""]),
            id(&["robot", "firewall", "", "rejected_stale"]),
            id(&["robot", "firewall", "made_up_rule"]),
            id(&["robot", "gateway", "trajectory_rejected", "x"]),
            id(&["robot", "gateway", "anything"]),
        ] {
            assert!(parse_gateway_line(&line(&bad)).is_err(), "{bad} accepted");
        }
        // Every id the gateway and its firewall emit stays accepted (a
        // drift guard: an id added there must be catalogued too).
        for (id, _) in robodr_firewall_gw::findings::rules::ALL {
            assert!(parse_gateway_line(&line(id)).is_ok(), "{id}");
        }
        let src = include_str!("../../robodr-firewall/src/events.rs");
        let mut n = 0;
        for part in src.split('"').skip(1).step_by(2) {
            if part.starts_with("robot.firewall.") && part.len() > "robot.firewall.".len() {
                assert!(parse_gateway_line(&line(part)).is_ok(), "{part}");
                n += 1;
            }
        }
        assert!(n >= 25, "firewall rule ids found in events.rs: {n}");
    }

    fn gw_line(rule: &str, sev: &str, channel: &str) -> GatewayLine {
        let t = format!(
            r#"{{"format":"robodr-gateway-finding/v1","rule":"{rule}","severity":"{sev}","detail":"x","mode":"enforce","channel":"{channel}","count":3}}"#
        );
        match parse_gateway_line(&t) {
            Ok(Payload::Gateway(l)) => *l,
            other => panic!("{rule}: {other:?}"),
        }
    }

    /// W2-5 drift guard: every id the gateway, its firewall and its WebRTC
    /// monitor emit has a severity range containing what they emit.
    #[test]
    fn every_emitted_rule_has_a_range_containing_its_severity() {
        for (id, sev) in robodr_firewall_gw::findings::rules::ALL {
            assert_eq!(severity_range(id), Some((sev, sev)), "{id}");
        }
        for (id, sev) in robodr_ros2_pipeline::webrtc::rules::ALL {
            let (lo, hi) = severity_range(id).unwrap_or_else(|| panic!("{id}"));
            assert!(lo <= sev && sev <= hi, "{id}");
        }
        assert_eq!(
            severity_range(robodr_ros2_pipeline::webrtc::rules::UNKNOWN_CONTROLLER),
            Some((Severity::High, Severity::Critical))
        );
        use robodr_firewall::RejectReason::*;
        for r in [
            ClockRegression,
            UnknownChannel,
            UnknownSource,
            UnauthorizedSource,
            RateLimited,
            KindMismatch,
            NonFinite,
            FutureTimestamp,
            Stale,
            OutOfOrder,
            OverHardLimit,
            InternalFault,
            CrcInvalid,
            DisabledMotorEnergised,
            JointPositionOutOfEnvelope,
            JointVelocityOutOfEnvelope,
            JointTorqueOutOfEnvelope,
            JointGainOutOfEnvelope,
            JointGainBelowMinimum,
            JointStepOutOfEnvelope,
            JointPdTorqueOutOfEnvelope,
            JointModeInconsistent,
            JointModePinMismatch,
            JointLimpFrame,
        ] {
            let (id, sev) = robodr_firewall::reject_rule(r);
            let (lo, hi) = severity_range(id).unwrap_or_else(|| panic!("{id}"));
            assert!(lo <= sev && sev <= hi, "{id}");
        }
        // Every robot.firewall.* id of the firewall's sources has a range.
        let src = include_str!("../../robodr-firewall/src/events.rs");
        let mut n = 0;
        for part in src.split('"').skip(1).step_by(2) {
            if part.starts_with("robot.firewall.") && part.len() > "robot.firewall.".len() {
                assert!(severity_range(part).is_some(), "{part}");
                n += 1;
            }
        }
        assert!(n >= 25, "{n}");
    }

    /// W2-5 / G7: a Critical rule claimed `low` reads Critical; a Low one
    /// claimed `critical` reads Low; within the range the claim stands.
    #[test]
    fn severities_are_kept_within_the_rules_range() {
        let mut lim = GatewayLimiter::new(0);
        let fw = robodr_firewall::rules::REJECTED_UNKNOWN_SOURCE;
        let Admitted::Report { line, clamped } = lim.admit(&gw_line(fw, "low", "/cmd_vel"), 0)
        else {
            panic!("folded");
        };
        assert!(clamped);
        assert_eq!(line.severity, Severity::Critical);
        assert!(
            line.detail.contains("severity claimed Low"),
            "{}",
            line.detail
        );
        let Admitted::Report { line, .. } = lim.admit(
            &gw_line("robot.gateway.restriction_changed", "critical", "/x"),
            0,
        ) else {
            panic!("folded");
        };
        assert_eq!(line.severity, Severity::Low);
        let joint = robodr_firewall::rules::JOINT_TORQUE_OUT_OF_ENVELOPE;
        for (claim, want) in [
            ("low", Severity::High),
            ("high", Severity::High),
            ("critical", Severity::Critical),
        ] {
            let Admitted::Report { line, clamped } = lim.admit(&gw_line(joint, claim, "/j"), 0)
            else {
                panic!("folded");
            };
            assert_eq!((line.severity, clamped), (want, claim == "low"));
        }
        assert_eq!(lim.clamped, 3);
    }

    /// W2-5 / G8-G9: 5000 Critical lines of one rule as fast as possible
    /// become RULE_BURST findings, then one aggregate per window that
    /// carries the count and the worst severity; another rule keeps its
    /// own budget; a healthy rate is reported line by line.
    #[test]
    fn a_flood_of_one_rule_is_folded_into_aggregates() {
        let mut lim = GatewayLimiter::new(0);
        let fw = robodr_firewall::rules::REJECTED_UNKNOWN_SOURCE;
        let mut reported = 0;
        for i in 0..5000u64 {
            let ch = format!("/c{}", i % 12);
            if matches!(
                lim.admit(&gw_line(fw, "critical", &ch), i / 100),
                Admitted::Report { .. }
            ) {
                reported += 1;
            }
        }
        // 50 ms elapsed: the burst only.
        assert_eq!(reported, RULE_BURST as usize);
        assert_eq!(lim.folded, 5000 - u64::from(RULE_BURST));
        // Another rule is not starved by the flooded one.
        assert!(matches!(
            lim.admit(&gw_line("robot.gateway.sequence_jump", "medium", "/a"), 60),
            Admitted::Report { .. }
        ));
        // Before the window ends: nothing; at its end: one aggregate.
        assert!(lim.drain(30_000, false).is_empty());
        let agg = lim.drain(60_000, false);
        assert_eq!(agg.len(), 1, "{agg:?}");
        let a = &agg[0];
        assert_eq!((a.rule.as_str(), a.severity), (fw, Severity::Critical));
        assert_eq!(a.count, 3 * (5000 - u64::from(RULE_BURST)));
        assert!(a.detail.contains("4980 further line(s)"), "{}", a.detail);
        assert!(
            a.detail.contains("/c0") && a.detail.contains(", ..."),
            "{}",
            a.detail
        );
        assert!(lim.drain(200_000, false).is_empty());
        assert_eq!(lim.aggregates, 1);
        // A healthy gateway: one line of a rule every 2 s for ten minutes
        // (the gateway folds per period and channel already): all reported.
        let mut lim = GatewayLimiter::new(0);
        let all = (0..300u64)
            .filter(|i| {
                matches!(
                    lim.admit(&gw_line(fw, "critical", "/x"), i * 2000),
                    Admitted::Report { .. }
                )
            })
            .count();
        assert_eq!(all, 300);
        // The feed as a whole: many rules at once stop at ALL_BURST.
        let mut lim = GatewayLimiter::new(0);
        let ids: Vec<&str> = robodr_firewall_gw::findings::rules::ALL
            .iter()
            .map(|(id, _)| *id)
            .chain(
                robodr_ros2_pipeline::webrtc::rules::ALL
                    .iter()
                    .map(|(id, _)| *id),
            )
            .collect();
        let mut n = 0;
        for i in 0..2000usize {
            let id = ids[i % ids.len()];
            let sev = format!("{:?}", severity_range(id).unwrap().0).to_lowercase();
            if matches!(
                lim.admit(&gw_line(id, &sev, "/x"), 0),
                Admitted::Report { .. }
            ) {
                n += 1;
            }
        }
        assert!(n <= ALL_BURST as usize, "{n}");
        assert_eq!(lim.drain(0, true).len(), ids.len());
    }
}
