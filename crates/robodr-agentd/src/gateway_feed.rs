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

use serde::Deserialize;

use crate::host::{HostThreatsSection, HostThreatsSpec};
use crate::input::Payload;

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
}
