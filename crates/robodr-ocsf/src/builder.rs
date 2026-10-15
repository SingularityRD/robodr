//! Building a [`FindingEnvelope`] from a [`Deviation`].
//!
//! ```
//! use robodr_events::{Deviation, Severity, graph::Participant, RobotEvent};
//! use robodr_ocsf::*;
//!
//! let ctx = RobotContext::new(
//!     RobotInfo {
//!         id: "ugv-007".into(),
//!         model: "ugv-tracked-v1".into(),
//!         platform_family: PlatformFamily::LinuxRos2,
//!         site: "site-a".into(),
//!         firmware: None,
//!     },
//!     ProfileRef { version: "3".into(), sha256: "ab".repeat(32) },
//!     Mode::Enforce,
//! );
//! let p = Participant { guid_prefix: "0102030405060708090a0b0c".into(),
//!                       src_ip: "10.0.0.66".into(), locators: vec![] };
//! let dev = Deviation::new("robot.ros2.unknown_participant", Severity::High, "unknown participant");
//! let finding = FindingBuilder::from_deviation(&dev, &ctx)
//!     .event(&RobotEvent::Ros2ParticipantDiscovered(p))
//!     .seen(1_790_000_000_000, 1_790_000_000_000)
//!     .build()
//!     .expect("valid finding");
//! assert_eq!(finding.ocsf.severity_id, 4);
//! let json = to_json(&finding).unwrap();
//! assert!(json.contains("\"data_source\":\"robot_edr\""));
//! ```
//!
//! ## Identity and deduplication
//!
//! * `finding_info.uid` / `finding_id` = `rf1-` + first 128 bits (hex) of
//!   SHA-256 over a length-framed tuple `(robot id, rule id, subject)`, where
//!   the subject is the *raw* (pre-neutralisation) participant GUID, node,
//!   topic, type name and source IP, each marked present/absent. The same
//!   deviation on the same robot about the same subject therefore always maps
//!   to the same finding, across restarts and across producers.
//! * Repeats of the same finding are sent as OCSF activity *Update* (2) with
//!   the same `finding_id`, a larger `count` and a later `last_seen_time`.
//! * `metadata.uid` = `re1-` + hash(finding uid, last_seen, count) identifies
//!   one emission, so a replayed message (e.g. after a diode re-send) is
//!   recognisably the same event.
//! * The AutoSecOps dedup key is `(data_source, external_id)` =
//!   `("robot_edr", "<robot_id>:<finding_id>")` (design doc schema table).
//!
//! ## Trusted vs tainted text
//!
//! `title`, `description` and `message` are built **only** from the trusted
//! rule catalog in this module and from sensor-authored context (robot id,
//! model, site, profile version, mode, safety state). `Deviation::detail` is
//! *not* used for narrative text, because the detection core interpolates
//! attacker-chosen names into it; it is carried as a [`Tainted`] value.

use crate::hash::{framed_sha256, hex};
use crate::model::*;
use crate::taint::{caps, Provenance, Tainted, TAINT_LABEL};
use crate::validate::{self, ValidationError};
use robodr_events::graph::{Endpoint, Participant};
use robodr_events::profile::Envelope;
use robodr_events::{Deviation, MotionCommand, RobotEvent, Severity};

/// Static, sensor-authored context of the robot that produced the deviation.
#[derive(Debug, Clone, PartialEq)]
pub struct RobotContext {
    pub robot: RobotInfo,
    pub profile: ProfileRef,
    pub mode: Mode,
    /// `metadata.product.version`; defaults to this crate's version.
    pub product_version: String,
}

impl RobotContext {
    pub fn new(robot: RobotInfo, profile: ProfileRef, mode: Mode) -> Self {
        Self {
            robot,
            profile,
            mode,
            product_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// What the deviation is *about*: raw, attacker-controlled identifiers.
/// Raw values feed the deterministic uid; neutralised copies go on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subject {
    pub participant_guid: Option<String>,
    pub node: Option<String>,
    pub topic: Option<String>,
    pub type_name: Option<String>,
    pub src_ip: Option<String>,
}

impl Subject {
    pub fn from_participant(p: &Participant) -> Self {
        Self {
            participant_guid: Some(p.guid_prefix.clone()),
            src_ip: Some(p.src_ip.clone()),
            ..Self::default()
        }
    }

    pub fn from_endpoint(e: &Endpoint) -> Self {
        Self {
            participant_guid: Some(e.guid_prefix.clone()),
            topic: Some(e.topic.clone()),
            type_name: (!e.type_name.is_empty()).then(|| e.type_name.clone()),
            ..Self::default()
        }
    }

    pub fn from_command(c: &MotionCommand) -> Self {
        Self {
            participant_guid: c.source_guid.clone(),
            topic: Some(c.channel.clone()),
            ..Self::default()
        }
    }

    fn framed_fields(&self) -> Vec<Vec<u8>> {
        [
            &self.participant_guid,
            &self.node,
            &self.topic,
            &self.type_name,
            &self.src_ip,
        ]
        .iter()
        .map(|f| match f {
            Some(v) => {
                let mut b = Vec::with_capacity(v.len() + 1);
                b.push(1);
                b.extend_from_slice(v.as_bytes());
                b
            }
            None => vec![0],
        })
        .collect()
    }
}

/// Trusted catalog entry for a rule id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    pub title: &'static str,
    pub desc: &'static str,
    pub data_source: &'static str,
    /// ATT&CK for ICS `(id, name)`.
    pub techniques: &'static [(&'static str, &'static str)],
}

const T0855: (&str, &str) = ("T0855", "Unauthorized Command Message");
const T0831: (&str, &str) = ("T0831", "Manipulation of Control");
const T0848: (&str, &str) = ("T0848", "Rogue Master");
const T0801: (&str, &str) = ("T0801", "Monitor Process State");

/// The trusted rule catalog. Unknown rule ids get a generic entry (the rule id
/// itself is a `&'static str` from the detection core and is charset-checked
/// by the validator).
pub fn rule_info(rule: &str) -> RuleInfo {
    const GRAPH: &str = "ros2_dds_discovery";
    const MOTION: &str = "ros2_motion_commands";
    match rule {
        "robot.ros2.unknown_participant" => RuleInfo {
            title: "Unknown DDS participant joined the robot graph",
            desc: "A DDS participant that is not in the locked model profile announced itself on the robot's RTPS discovery bus.",
            data_source: GRAPH,
            techniques: &[T0848],
        },
        "robot.ros2.unauthorized_motion_writer" => RuleInfo {
            title: "Unauthorized publisher on a motion topic",
            desc: "A participant that is not in the locked model profile announced a writer on a motion/control topic.",
            data_source: GRAPH,
            techniques: &[T0855],
        },
        "robot.ros2.unknown_writer_topic" => RuleInfo {
            title: "Writer on a topic outside the model profile",
            desc: "A writer was announced on a topic the locked model profile does not allow anyone to publish to.",
            data_source: GRAPH,
            techniques: &[T0855],
        },
        "robot.ros2.unknown_reader" => RuleInfo {
            title: "Unknown subscriber in the robot graph",
            desc: "A participant that is not in the locked model profile announced a reader; it cannot command but may collect data.",
            data_source: GRAPH,
            techniques: &[T0801],
        },
        "robot.motion.unprofiled_channel" => RuleInfo {
            title: "Motion command on an unprofiled channel",
            desc: "A motion command was observed on a channel that has no envelope in the locked model profile.",
            data_source: MOTION,
            techniques: &[T0855],
        },
        "robot.motion.linear_over_envelope" => RuleInfo {
            title: "Linear speed command exceeds the motion envelope",
            desc: "A commanded linear speed exceeded the maximum allowed by the locked model profile for this channel.",
            data_source: MOTION,
            techniques: &[T0831],
        },
        "robot.motion.joint_over_envelope" => RuleInfo {
            title: "Joint speed command exceeds the motion envelope",
            desc: "A commanded joint speed exceeded the maximum allowed by the locked model profile for this channel.",
            data_source: MOTION,
            techniques: &[T0831],
        },
        _ => RuleInfo {
            title: "RoboDR model-profile deviation",
            desc: "The detection core reported a deviation from the locked model profile for a rule without a catalog entry.",
            data_source: "robodr",
            techniques: &[],
        },
    }
}

/// OCSF `severity_id` for a RoboDR severity.
pub fn ocsf_severity_id(s: Severity) -> u8 {
    match s {
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

/// OCSF `severity` caption for a RoboDR severity.
pub fn ocsf_severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

/// Deterministic finding uid for `(robot id, rule id, subject)`.
pub fn finding_uid(robot_id: &str, rule: &str, subject: &Subject) -> String {
    let sub = subject.framed_fields();
    let mut fields: Vec<&[u8]> = vec![robot_id.as_bytes(), rule.as_bytes()];
    fields.extend(sub.iter().map(|v| v.as_slice()));
    let h = framed_sha256("robodr.finding-uid.v1", &fields);
    format!("rf1-{}", hex(&h[..16]))
}

/// Deterministic per-emission uid (`metadata.uid`).
pub fn event_uid(finding_uid: &str, last_seen_ms: u64, count: u64) -> String {
    let h = framed_sha256(
        "robodr.event-uid.v1",
        &[
            finding_uid.as_bytes(),
            &last_seen_ms.to_be_bytes(),
            &count.to_be_bytes(),
        ],
    );
    format!("re1-{}", hex(&h[..16]))
}

/// RFC 3339 UTC timestamp with millisecond precision for `ms` since the epoch.
pub fn rfc3339_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        d,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60,
        millis
    )
}

fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Observe => "observe",
        Mode::Enforce => "enforce",
    }
}

fn motion_name(m: MotionState) -> &'static str {
    match m {
        MotionState::Moving => "moving",
        MotionState::Stationary => "stationary",
        MotionState::Unknown => "unknown",
    }
}

fn proximity_name(h: HumanProximity) -> &'static str {
    match h {
        HumanProximity::Detected => "detected",
        HumanProximity::NotDetected => "not detected",
        HumanProximity::Unknown => "unknown",
    }
}

fn attestation_name(a: AttestationStatus) -> &'static str {
    match a {
        AttestationStatus::Verified => "verified",
        AttestationStatus::Deviation => "deviation",
        AttestationStatus::Unknown => "unknown",
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CommandObservation {
    channel: String,
    linear_speed: Option<f64>,
    joint_speed: Option<f64>,
    envelope: Option<Envelope>,
}

/// Builder for one [`FindingEnvelope`]. All inputs are explicit (no clock is
/// read), so the output is a pure function of the inputs.
#[derive(Debug, Clone)]
pub struct FindingBuilder<'a> {
    dev: &'a Deviation,
    ctx: &'a RobotContext,
    subject: Subject,
    command: Option<CommandObservation>,
    first_seen: Option<u64>,
    last_seen: Option<u64>,
    count: u64,
    safety: SafetyState,
    attestation: AttestationStatus,
    evidence: Vec<BlackBoxRef>,
    bus_message_id: Option<u32>,
    anomaly_score: Option<f64>,
}

impl<'a> FindingBuilder<'a> {
    /// Start a finding for `dev` raised on the robot described by `ctx`.
    pub fn from_deviation(dev: &'a Deviation, ctx: &'a RobotContext) -> Self {
        Self {
            dev,
            ctx,
            subject: Subject::default(),
            command: None,
            first_seen: None,
            last_seen: None,
            count: 1,
            safety: SafetyState::UNKNOWN,
            attestation: AttestationStatus::Unknown,
            evidence: Vec::new(),
            bus_message_id: None,
            anomaly_score: None,
        }
    }

    /// Set subject (and command, for motion events) from the triggering event.
    pub fn event(mut self, ev: &RobotEvent) -> Self {
        match ev {
            RobotEvent::Ros2ParticipantDiscovered(p) => self.subject = Subject::from_participant(p),
            RobotEvent::Ros2WriterDiscovered(e) | RobotEvent::Ros2ReaderDiscovered(e) => {
                self.subject = Subject::from_endpoint(e)
            }
            RobotEvent::MotionCommand(c) => {
                self.subject = Subject::from_command(c);
                self = self.command(c, None);
            }
            // Feedback has no source endpoint; the channel is the subject.
            RobotEvent::MotionFeedback(f) => {
                self.subject = Subject {
                    topic: Some(f.channel.clone()),
                    ..Subject::default()
                };
            }
        }
        self
    }

    /// Set the subject explicitly.
    pub fn subject(mut self, s: Subject) -> Self {
        self.subject = s;
        self
    }

    /// Attach the commanded values and, if known, the permitted envelope.
    pub fn command(mut self, c: &MotionCommand, envelope: Option<&Envelope>) -> Self {
        self.command = Some(CommandObservation {
            channel: c.channel.clone(),
            linear_speed: c.linear_speed,
            joint_speed: c.joint_speed,
            envelope: envelope.cloned(),
        });
        self
    }

    /// First and last time (ms since epoch) this finding was observed.
    pub fn seen(mut self, first_ms: u64, last_ms: u64) -> Self {
        self.first_seen = Some(first_ms);
        self.last_seen = Some(last_ms);
        self
    }

    /// Number of occurrences aggregated (>= 1). 1 => OCSF Create, else Update.
    pub fn occurrences(mut self, n: u64) -> Self {
        self.count = n;
        self
    }

    pub fn safety_state(mut self, s: SafetyState) -> Self {
        self.safety = s;
        self
    }

    pub fn attestation(mut self, a: AttestationStatus) -> Self {
        self.attestation = a;
        self
    }

    /// Add a black-box evidence reference. Order of calls does not matter.
    pub fn evidence(mut self, r: BlackBoxRef) -> Self {
        self.evidence.push(r);
        self
    }

    pub fn bus_message_id(mut self, id: u32) -> Self {
        self.bus_message_id = Some(id);
        self
    }

    pub fn anomaly_score(mut self, s: f64) -> Self {
        self.anomaly_score = Some(s);
        self
    }

    /// The deterministic finding uid this builder will produce.
    pub fn finding_uid(&self) -> String {
        finding_uid(&self.ctx.robot.id, self.dev.rule_str(), &self.subject)
    }

    /// Assemble and validate. Never panics on hostile input; returns every
    /// validation problem found.
    pub fn build(self) -> Result<FindingEnvelope, Vec<ValidationError>> {
        let (first, last) = match (self.first_seen, self.last_seen) {
            (Some(f), Some(l)) => (f, l),
            _ => return Err(vec![ValidationError::Missing("seen (first/last time)")]),
        };
        let ctx = self.ctx;
        let dev = self.dev;
        let info = rule_info(dev.rule_str());
        let uid = self.finding_uid();
        let robot_id = ctx.robot.id.clone();

        let t = |v: &Option<String>, cap| v.as_deref().map(|s| Tainted::new(s, cap));
        let ros = RosContext {
            participant_guid: t(&self.subject.participant_guid, caps::GUID),
            node: t(&self.subject.node, caps::NODE),
            topic: t(&self.subject.topic, caps::TOPIC),
            type_name: t(&self.subject.type_name, caps::TYPE_NAME),
            src_ip: t(&self.subject.src_ip, caps::IP),
        };
        let command = self.command.as_ref().map(|c| CommandContext {
            channel: Tainted::new(&c.channel, caps::TOPIC),
            linear_speed: c.linear_speed,
            joint_speed: c.joint_speed,
            envelope_max_linear_speed: c.envelope.as_ref().and_then(|e| e.max_linear_speed),
            envelope_max_joint_speed: c.envelope.as_ref().and_then(|e| e.max_joint_speed),
        });

        let entity_context = EntityContext {
            robot: ctx.robot.clone(),
            profile: ctx.profile.clone(),
            rule_id: dev.rule.to_string(),
            mode: ctx.mode,
            safety_state: self.safety,
            attestation: self.attestation,
            ros: ros.clone(),
            command,
            bus_message_id: self.bus_message_id,
            occurrence_count: self.count,
            detail: Tainted::new(&dev.detail, caps::DETAIL),
        };

        let mut evidence = self.evidence;
        evidence.sort();
        evidence.dedup();
        let evidence_links: Vec<String> = evidence.iter().map(|e| e.uri(&robot_id)).collect();
        let evidences: Vec<Evidence> = evidence
            .iter()
            .map(|e| Evidence {
                data: EvidenceData {
                    kind: "robodr.blackbox".into(),
                    segment: e.segment,
                    seq: e.seq,
                    sha256: e.sha256.clone(),
                    uri: e.uri(&robot_id),
                },
            })
            .collect();

        let mut resources = Vec::new();
        let mut push = |type_: &str, uid: Option<&Tainted>, name: Option<&Tainted>| {
            if uid.is_none() && name.is_none() {
                return;
            }
            resources.push(Resource {
                type_: type_.into(),
                uid: uid.map(|t| t.value.clone()),
                name: name.map(|t| t.value.clone()),
                labels: vec![TAINT_LABEL.into()],
            });
        };
        push("ros2.participant", ros.participant_guid.as_ref(), None);
        push("ros2.node", None, ros.node.as_ref());
        push("ros2.topic", None, ros.topic.as_ref());
        push("ip_address", None, ros.src_ip.as_ref());

        let title = info.title.to_string();
        let firmware = match &ctx.robot.firmware {
            Some(f) => format!("firmware {}", f.version),
            None => "firmware unknown".to_string(),
        };
        let description = format!(
            "{} Robot {} (model {}, site {}, {}); profile version {}; mode {}; \
             safety state: motion {}, human proximity {}; attestation {}; occurrences {}.",
            info.desc,
            ctx.robot.id,
            ctx.robot.model,
            ctx.robot.site,
            firmware,
            ctx.profile.version,
            mode_name(ctx.mode),
            motion_name(self.safety.motion),
            proximity_name(self.safety.human_proximity),
            attestation_name(self.attestation),
            self.count,
        );

        let (activity_id, activity_name) = if self.count <= 1 {
            (1u8, "Create")
        } else {
            (2u8, "Update")
        };
        let mitre_predictions = info
            .techniques
            .iter()
            .map(|(id, name)| MitrePrediction {
                technique_id: (*id).into(),
                technique_name: (*name).into(),
                framework: "attack_ics".into(),
                provenance: Provenance::Sensor,
            })
            .collect();
        let attacks = info
            .techniques
            .iter()
            .map(|(id, name)| Attack {
                technique: Technique {
                    uid: (*id).into(),
                    name: (*name).into(),
                },
            })
            .collect();

        let ocsf = DetectionFinding {
            activity_id,
            activity_name: activity_name.into(),
            category_uid: ocsf_ids::CATEGORY_UID,
            category_name: ocsf_ids::CATEGORY_NAME.into(),
            class_uid: ocsf_ids::CLASS_UID,
            class_name: ocsf_ids::CLASS_NAME.into(),
            type_uid: ocsf_ids::CLASS_UID * 100 + activity_id as u32,
            type_name: format!("{}: {}", ocsf_ids::CLASS_NAME, activity_name),
            severity_id: ocsf_severity_id(dev.severity),
            severity: ocsf_severity_name(dev.severity).into(),
            status_id: 1,
            status: "New".into(),
            time: last,
            message: title.clone(),
            count: self.count,
            metadata: Metadata {
                version: OCSF_VERSION.into(),
                product: Product {
                    name: PRODUCT_NAME.into(),
                    vendor_name: VENDOR_NAME.into(),
                    version: ctx.product_version.clone(),
                },
                uid: event_uid(&uid, last, self.count),
                log_name: KAFKA_TOPIC.into(),
            },
            finding_info: FindingInfo {
                uid: uid.clone(),
                title: title.clone(),
                desc: description.clone(),
                types: vec!["robot_deviation".into(), info.data_source.into()],
                first_seen_time: first,
                last_seen_time: last,
                analytic: Analytic {
                    uid: dev.rule_str().into(),
                    name: dev.rule_str().into(),
                    type_id: 1,
                    type_: "Rule".into(),
                },
                attacks,
                data_sources: vec![info.data_source.into()],
            },
            device: Device {
                uid: robot_id.clone(),
                name: robot_id.clone(),
                type_id: 99,
                type_: "Robot".into(),
                model: ctx.robot.model.clone(),
            },
            evidences,
            resources,
            unmapped: Unmapped {
                robodr: entity_context.clone(),
            },
        };

        let mut env = FindingEnvelope {
            contract_version: CONTRACT_VERSION.into(),
            finding_id: uid.clone(),
            external_id: format!("{robot_id}:{uid}"),
            data_source: DATA_SOURCE.into(),
            title,
            description,
            severity: dev.severity,
            timestamp: rfc3339_ms(last),
            entity_context,
            mitre_predictions,
            evidence_links,
            anomaly_score: self.anomaly_score,
            adversary_controlled_fields: Vec::new(),
            ocsf,
        };
        // Pointers are computed from the serialised form, so they can never
        // drift from the actual layout. Non-finite floats would serialise as
        // null; validation below rejects them on the typed struct.
        env.adversary_controlled_fields = validate::tainted_pointers(&env);
        validate::validate(&env)?;
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339_ms(1_790_000_000_123), "2026-09-21T14:13:20.123Z");
        assert_eq!(rfc3339_ms(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
    }

    #[test]
    fn severity_mapping_matches_ocsf() {
        assert_eq!(ocsf_severity_id(Severity::Low), 2);
        assert_eq!(ocsf_severity_id(Severity::Medium), 3);
        assert_eq!(ocsf_severity_id(Severity::High), 4);
        assert_eq!(ocsf_severity_id(Severity::Critical), 5);
        assert_eq!(ocsf_severity_name(Severity::Critical), "Critical");
    }

    #[test]
    fn uid_depends_on_every_identity_component() {
        let s = Subject {
            participant_guid: Some("aa".into()),
            ..Subject::default()
        };
        let base = finding_uid("r1", "rule.a", &s);
        assert_eq!(base, finding_uid("r1", "rule.a", &s));
        assert!(base.starts_with("rf1-") && base.len() == 36);
        assert_ne!(base, finding_uid("r2", "rule.a", &s));
        assert_ne!(base, finding_uid("r1", "rule.b", &s));
        let mut s2 = s.clone();
        s2.topic = Some(String::new());
        assert_ne!(
            base,
            finding_uid("r1", "rule.a", &s2),
            "present-but-empty != absent"
        );
        let s3 = Subject {
            node: Some("aa".into()),
            ..Subject::default()
        };
        assert_ne!(
            base,
            finding_uid("r1", "rule.a", &s3),
            "field position matters"
        );
    }

    #[test]
    fn event_uid_changes_per_emission() {
        let a = event_uid("rf1-x", 1, 1);
        assert_ne!(a, event_uid("rf1-x", 2, 1));
        assert_ne!(a, event_uid("rf1-x", 1, 2));
        assert_eq!(a, event_uid("rf1-x", 1, 1));
    }
}
