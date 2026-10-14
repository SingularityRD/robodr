//! The ROS 2 / DDS computational graph as RoboDR models it: participants and
//! their endpoints (writers/readers), keyed by DDS GUID.

use serde::{Deserialize, Serialize};

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
    /// Topic name as announced, e.g. `rt/cmd_vel` in ROS 2 mangling.
    pub topic: String,
    /// Type name as announced, e.g. `geometry_msgs::msg::dds_::Twist_`.
    #[serde(default)]
    pub type_name: String,
}

impl Endpoint {
    /// The de-mangled ROS 2 topic (`rt/cmd_vel` -> `/cmd_vel`). DDS prefixes
    /// ROS 2 topics with `rt`, services with `rq`/`rr`; we strip the leading
    /// `rt` so the remaining `/cmd_vel` matches the profile's topic names.
    pub fn ros_topic(&self) -> &str {
        self.topic.strip_prefix("rt").unwrap_or(&self.topic)
    }
}
