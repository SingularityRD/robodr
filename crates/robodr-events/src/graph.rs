//! The ROS 2 / DDS computational graph as RoboDR models it: participants and
//! their endpoints (writers/readers), keyed by DDS GUID, plus ROS 2 name
//! de-mangling.
//!
//! # ROS 2 name mangling (what [`demangle`] undoes)
//!
//! ROS 2 rmw implementations (Fast DDS, Cyclone DDS, Connext) map ROS names
//! onto DDS topic names with a two-letter prefix:
//!
//! | ROS entity                    | DDS topic name                   | [`RosNameKind`]       |
//! |-------------------------------|----------------------------------|-----------------------|
//! | topic `/cmd_vel`              | `rt/cmd_vel`                     | `Topic`               |
//! | service `/add` (request)      | `rq/addRequest`                  | `ServiceRequest`      |
//! | service `/add` (reply)        | `rr/addReply`                    | `ServiceReply`        |
//! | action `/nav` send_goal etc.  | `rq/nav/_action/send_goalRequest`| `ActionPart{..}`      |
//! | action `/nav` feedback/status | `rt/nav/_action/feedback`        | `ActionPart{..}`      |
//! | anything else                 | as is                            | `Raw`                 |
//!
//! Actions are not a DDS concept: an action `/nav` is three services
//! (`/nav/_action/send_goal`, `/nav/_action/cancel_goal`,
//! `/nav/_action/get_result`) and two topics (`/nav/_action/feedback`,
//! `/nav/_action/status`). [`demangle`] recognises them and reports the action
//! name and component; a component that arrives with the wrong transport
//! (e.g. `rt/nav/_action/send_goal`) is *not* an action part and is reported
//! as a plain `Topic`.
//!
//! **Suffix variants.** The `Request` / `Reply` suffixes are what current rmw
//! implementations use (verified against the RTI Connext ROS 2 interop docs and
//! the rmw_fastrtps / rmw_cyclonedds naming code as we know it). The forms with
//! a trailing underscore, `Request_` / `Reply_`, are what DDS *type* names use
//! (`example_interfaces::srv::dds_::AddTwoInts_Request_`); some older or
//! non-conformant stacks have been reported to put them into topic names as
//! well. We accept them defensively and de-mangle them to the same service
//! name. This could not be verified against a live stack here.
//!
//! The other prefixes reserved by the ROS 2 naming design (`rs`, `rp`, `ra`)
//! are not used by any shipping rmw; names using them are `Raw`.
//!
//! **Raw DDS.** A topic without a ROS prefix (e.g. a vendor DDS tool, or a
//! name like `rtfoo` with no slash) is `Raw`, keeps its exact spelling, and is
//! never matched against ROS topic allowlists. ROS nodes cannot receive it as a
//! ROS topic, but it is still traffic on the robot bus and is profiled
//! separately (`Profile::raw_dds_topics`).

use serde::{Deserialize, Serialize};
use std::fmt;

/// A DDS participant: one process on the robot's RTPS bus. The `guid_prefix`
/// (12 bytes, hex) identifies it; the rest is what discovery told us about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    /// 12-byte RTPS GUID prefix, lower-case hex, no separators (24 chars).
    pub guid_prefix: String,
    /// Source IP the SPDP announcement came from, dotted/colon form.
    pub src_ip: String,
    /// Unicast locators (ip:port) the participant advertises, if parsed.
    #[serde(default)]
    pub locators: Vec<String>,
}

/// A DDS endpoint: a writer or reader bound to a topic, owned by a participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub guid_prefix: String,
    /// Topic name as announced on the wire, e.g. `rt/cmd_vel` (ROS 2 mangling).
    pub topic: String,
    /// Type name as announced, e.g. `geometry_msgs::msg::dds_::Twist_`.
    #[serde(default)]
    pub type_name: String,
}

impl Endpoint {
    /// The de-mangled ROS 2 *topic* name: `rt/cmd_vel` -> `/cmd_vel`.
    ///
    /// Only the exact `rt/` prefix is stripped (the leading `/` is kept). Any
    /// other name — services (`rq/…`, `rr/…`) and raw DDS topics such as
    /// `rtfoo` — is returned unchanged. Use [`Endpoint::ros_name`] to classify
    /// services, actions and raw topics properly.
    pub fn ros_topic(&self) -> &str {
        match self.topic.strip_prefix("rt") {
            Some(rest) if rest.starts_with('/') => rest,
            _ => &self.topic,
        }
    }

    /// The fully classified ROS 2 name of this endpoint. See [`demangle`].
    pub fn ros_name(&self) -> RosName {
        demangle(&self.topic)
    }
}

/// Which part of a ROS 2 action an endpoint belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionComponent {
    /// Service `<action>/_action/send_goal`.
    SendGoal,
    /// Service `<action>/_action/cancel_goal`.
    CancelGoal,
    /// Service `<action>/_action/get_result`.
    GetResult,
    /// Topic `<action>/_action/feedback`.
    Feedback,
    /// Topic `<action>/_action/status`.
    Status,
}

impl ActionComponent {
    /// The path segment after `/_action/`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SendGoal => "send_goal",
            Self::CancelGoal => "cancel_goal",
            Self::GetResult => "get_result",
            Self::Feedback => "feedback",
            Self::Status => "status",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "send_goal" => Self::SendGoal,
            "cancel_goal" => Self::CancelGoal,
            "get_result" => Self::GetResult,
            "feedback" => Self::Feedback,
            "status" => Self::Status,
            _ => return None,
        })
    }

    /// `true` for the three service components.
    pub fn is_service(self) -> bool {
        matches!(self, Self::SendGoal | Self::CancelGoal | Self::GetResult)
    }
}

/// The DDS transport an action component travels on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRole {
    /// `rq/…Request` (written by the action client).
    Request,
    /// `rr/…Reply` (written by the action server).
    Reply,
    /// `rt/…` (feedback/status, written by the action server).
    Topic,
}

/// Classification of a DDS topic name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RosNameKind {
    /// A plain ROS 2 topic (`rt/`).
    Topic,
    /// The request topic of a ROS 2 service (`rq/…Request`).
    ServiceRequest,
    /// The reply topic of a ROS 2 service (`rr/…Reply`).
    ServiceReply,
    /// One of the five DDS topics backing a ROS 2 action.
    ActionPart {
        /// Action name, fully qualified (e.g. `/navigate_to_pose`).
        action: String,
        component: ActionComponent,
        role: ActionRole,
    },
    /// Not a ROS 2 name: a raw DDS topic, kept verbatim.
    Raw,
}

/// A de-mangled DDS topic name.
///
/// `name` is the ROS-level name: the topic name for `Topic`, the *service*
/// name (no `Request`/`Reply` suffix) for `ServiceRequest`/`ServiceReply`, the
/// full topic or service name (e.g. `/nav/_action/send_goal`) for
/// `ActionPart`, and the exact wire string for `Raw`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RosName {
    pub kind: RosNameKind,
    pub name: String,
}

impl RosName {
    /// `true` unless this is a raw (non-ROS) DDS name.
    pub fn is_ros(&self) -> bool {
        self.kind != RosNameKind::Raw
    }

    /// Re-apply the canonical ROS 2 mangling (inverse of [`demangle`] for the
    /// canonical `Request`/`Reply` suffixes).
    pub fn mangled(&self) -> String {
        let n = &self.name;
        match &self.kind {
            RosNameKind::Topic => format!("rt{n}"),
            RosNameKind::ServiceRequest => format!("rq{n}Request"),
            RosNameKind::ServiceReply => format!("rr{n}Reply"),
            RosNameKind::ActionPart { role, .. } => match role {
                ActionRole::Request => format!("rq{n}Request"),
                ActionRole::Reply => format!("rr{n}Reply"),
                ActionRole::Topic => format!("rt{n}"),
            },
            RosNameKind::Raw => n.clone(),
        }
    }
}

impl fmt::Display for RosName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            RosNameKind::Topic => write!(f, "topic {}", self.name),
            RosNameKind::ServiceRequest => write!(f, "service {} (request)", self.name),
            RosNameKind::ServiceReply => write!(f, "service {} (reply)", self.name),
            RosNameKind::ActionPart {
                action, component, ..
            } => write!(f, "action {action} ({})", component.as_str()),
            RosNameKind::Raw => write!(f, "raw DDS topic {:?}", self.name),
        }
    }
}

/// Strip a two-letter ROS prefix, requiring the following `/` and a
/// non-empty name after it.
fn strip_ros_prefix<'a>(dds: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = dds.strip_prefix(prefix)?;
    (rest.len() > 1 && rest.starts_with('/')).then_some(rest)
}

/// Strip one of the service suffixes, requiring a non-trivial name remains.
fn strip_service_suffix<'a>(name: &'a str, suffixes: &[&str]) -> Option<&'a str> {
    suffixes
        .iter()
        .find_map(|s| name.strip_suffix(s))
        .filter(|n| n.len() > 1)
}

/// Split `/a/b/_action/send_goal` into (`/a/b`, SendGoal).
fn split_action(name: &str) -> Option<(&str, ActionComponent)> {
    let (action, comp) = name.rsplit_once("/_action/")?;
    if action.len() < 2 || !action.starts_with('/') {
        return None;
    }
    Some((action, ActionComponent::parse(comp)?))
}

/// Classify and de-mangle a DDS topic name as announced in SEDP.
///
/// Never panics; any input that is not a well-formed ROS 2 mangled name is
/// returned as [`RosNameKind::Raw`] with the exact input as `name`.
pub fn demangle(dds: &str) -> RosName {
    let raw = || RosName {
        kind: RosNameKind::Raw,
        name: dds.to_owned(),
    };

    if let Some(topic) = strip_ros_prefix(dds, "rt") {
        let kind = match split_action(topic) {
            Some((action, component)) if !component.is_service() => RosNameKind::ActionPart {
                action: action.to_owned(),
                component,
                role: ActionRole::Topic,
            },
            _ => RosNameKind::Topic,
        };
        return RosName {
            kind,
            name: topic.to_owned(),
        };
    }

    let (rest, suffixes, role, plain) = if let Some(r) = strip_ros_prefix(dds, "rq") {
        (
            r,
            &["Request", "Request_"][..],
            ActionRole::Request,
            RosNameKind::ServiceRequest,
        )
    } else if let Some(r) = strip_ros_prefix(dds, "rr") {
        (
            r,
            &["Reply", "Reply_"][..],
            ActionRole::Reply,
            RosNameKind::ServiceReply,
        )
    } else {
        return raw();
    };

    let Some(service) = strip_service_suffix(rest, suffixes) else {
        return raw();
    };
    let kind = match split_action(service) {
        Some((action, component)) if component.is_service() => RosNameKind::ActionPart {
            action: action.to_owned(),
            component,
            role,
        },
        _ => plain,
    };
    RosName {
        kind,
        name: service.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(topic: &str) -> Endpoint {
        Endpoint {
            guid_prefix: "aa".into(),
            topic: topic.into(),
            type_name: String::new(),
        }
    }

    fn act(action: &str, component: ActionComponent, role: ActionRole) -> RosNameKind {
        RosNameKind::ActionPart {
            action: action.into(),
            component,
            role,
        }
    }

    #[test]
    fn demangle_table() {
        use ActionComponent::*;
        use RosNameKind::*;
        let cases: Vec<(&str, RosNameKind, &str)> = vec![
            ("rt/cmd_vel", Topic, "/cmd_vel"),
            ("rt/ns/robot1/odom", Topic, "/ns/robot1/odom"),
            ("rt/rosout", Topic, "/rosout"),
            ("rq/add_two_intsRequest", ServiceRequest, "/add_two_ints"),
            ("rr/add_two_intsReply", ServiceReply, "/add_two_ints"),
            ("rq/add_two_intsRequest_", ServiceRequest, "/add_two_ints"),
            ("rr/add_two_intsReply_", ServiceReply, "/add_two_ints"),
            (
                "rq/node/get_parametersRequest",
                ServiceRequest,
                "/node/get_parameters",
            ),
            // A service whose own name ends in "Request": only one suffix stripped.
            ("rq/fooRequestRequest", ServiceRequest, "/fooRequest"),
            (
                "rq/nav/_action/send_goalRequest",
                act("/nav", SendGoal, ActionRole::Request),
                "/nav/_action/send_goal",
            ),
            (
                "rr/nav/_action/send_goalReply",
                act("/nav", SendGoal, ActionRole::Reply),
                "/nav/_action/send_goal",
            ),
            (
                "rq/a/b/_action/cancel_goalRequest",
                act("/a/b", CancelGoal, ActionRole::Request),
                "/a/b/_action/cancel_goal",
            ),
            (
                "rr/nav/_action/get_resultReply",
                act("/nav", GetResult, ActionRole::Reply),
                "/nav/_action/get_result",
            ),
            (
                "rt/nav/_action/feedback",
                act("/nav", Feedback, ActionRole::Topic),
                "/nav/_action/feedback",
            ),
            (
                "rt/nav/_action/status",
                act("/nav", Status, ActionRole::Topic),
                "/nav/_action/status",
            ),
            // Wrong transport for the component: not an action part.
            ("rt/nav/_action/send_goal", Topic, "/nav/_action/send_goal"),
            (
                "rq/nav/_action/feedbackRequest",
                ServiceRequest,
                "/nav/_action/feedback",
            ),
            // Unknown component / missing action name: plain names.
            ("rt/nav/_action/bogus", Topic, "/nav/_action/bogus"),
            ("rt/_action/status", Topic, "/_action/status"),
            // Raw DDS: no ROS prefix, or malformed.
            ("rtfoo", Raw, "rtfoo"),
            ("rt", Raw, "rt"),
            ("rt/", Raw, "rt/"),
            ("cmd_vel", Raw, "cmd_vel"),
            ("/cmd_vel", Raw, "/cmd_vel"),
            ("", Raw, ""),
            ("rq/add_two_ints", Raw, "rq/add_two_ints"),
            ("rq/Request", Raw, "rq/Request"),
            ("rr/addRequest", Raw, "rr/addRequest"),
            ("rqfooRequest", Raw, "rqfooRequest"),
            ("rs/foo", Raw, "rs/foo"),
            ("rp/foo", Raw, "rp/foo"),
            ("ra/foo", Raw, "ra/foo"),
            ("RT/cmd_vel", Raw, "RT/cmd_vel"),
            ("DCPSParticipant", Raw, "DCPSParticipant"),
        ];
        for (input, kind, name) in cases {
            let got = demangle(input);
            assert_eq!(got.kind, kind, "kind for {input:?}");
            assert_eq!(got.name, name, "name for {input:?}");
            assert_eq!(got.is_ros(), kind != Raw);
        }
    }

    #[test]
    fn mangled_inverts_demangle_for_canonical_names() {
        for n in [
            "rt/cmd_vel",
            "rq/addRequest",
            "rr/addReply",
            "rq/nav/_action/send_goalRequest",
            "rr/nav/_action/get_resultReply",
            "rt/nav/_action/status",
            "rtfoo",
            "anything at all",
        ] {
            assert_eq!(demangle(n).mangled(), n);
        }
        // Legacy suffix is normalised to the canonical one.
        assert_eq!(demangle("rq/addRequest_").mangled(), "rq/addRequest");
    }

    #[test]
    fn ros_topic_only_strips_rt_slash() {
        assert_eq!(ep("rt/cmd_vel").ros_topic(), "/cmd_vel");
        // Regression: "rtfoo" used to become "foo".
        assert_eq!(ep("rtfoo").ros_topic(), "rtfoo");
        assert_eq!(ep("rt").ros_topic(), "rt");
        assert_eq!(ep("rq/addRequest").ros_topic(), "rq/addRequest");
        assert_eq!(ep("").ros_topic(), "");
    }

    #[test]
    fn demangle_never_panics_on_hostile_input() {
        let nasty = [
            "rt/\u{0}",
            "rq/\u{1F600}Request",
            "rr/é/_action/send_goalReply",
            "rt//",
            "rq//Request",
            "rt/_action/",
            "rt/x/_action/",
            "rq/x/_action/Request",
            "\u{FFFF}\u{FFFF}",
        ];
        for n in nasty {
            let _ = demangle(n);
            let _ = demangle(n).to_string();
        }
        let long = format!("rt/{}", "a/_action/".repeat(10_000));
        assert_eq!(demangle(&long).kind, RosNameKind::Topic);
    }

    #[test]
    fn ros_name_serde_round_trip() {
        for n in ["rt/x", "rq/xRequest", "rr/a/_action/get_resultReply", "zz"] {
            let r = demangle(n);
            let j = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<RosName>(&j).unwrap(), r);
        }
    }
}
