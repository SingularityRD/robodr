//! Strict validator for outgoing (and replayed) findings.
//!
//! Every finding is validated before it leaves the producer
//! ([`crate::FindingBuilder::build`], [`crate::to_json`]), and
//! [`parse_and_validate`] re-applies the same rules to bytes coming back in
//! (diode import, replay tooling, tests). The validator never panics and
//! reports *all* problems it finds.
//!
//! Rules (see also the topic contract `docs/contracts/robot-edr.findings.md`):
//!
//! * **Required fields / constants**: OCSF class 2004, category 2, `type_uid =
//!   class_uid*100 + activity_id`, schema/product constants, `data_source`.
//! * **Enums in range** and consistent with their captions (`severity_id` ↔
//!   `severity`, `activity_id` ↔ `activity_name`, `status_id` ↔ `status`).
//! * **Cross-field consistency**: `finding_id == finding_info.uid`,
//!   `external_id == robot_id:finding_id`, `unmapped.robodr == entity_context`,
//!   evidences ↔ `evidence_links`, ATT&CK lists, times.
//! * **Formats**: id charsets, lower-case SHA-256 hex, RFC 3339 timestamp.
//! * **Every string** in the serialised message (keys and values): at most
//!   [`MAX_STRING_BYTES`], no control / Unicode format characters, no raw
//!   `<`, `>` or `` ` `` (SR-TAINT, see [`crate::taint`]).
//! * **Tainted values**: `taint == adversary`, neutral form, per-field caps.
//! * **Floats**: finite, non-negative; `anomaly_score` within `[0, 1]`.
//! * **Size**: serialised message at most [`MAX_FINDING_BYTES`].

use crate::builder::{ocsf_severity_id, ocsf_severity_name, rfc3339_ms};
use crate::model::*;
use crate::taint::{
    caps, is_forbidden_char, is_markup_char, is_neutral, Provenance, Tainted, TAINT_LABEL,
};
use serde_json::Value;
use std::fmt;

/// Hard cap on one serialised finding (Kafka value).
pub const MAX_FINDING_BYTES: usize = 64 * 1024;
/// Hard cap on any single string in a finding.
pub const MAX_STRING_BYTES: usize = 4096;
/// Max black-box references per finding.
pub const MAX_EVIDENCE: usize = 64;
/// Max ATT&CK techniques per finding.
pub const MAX_TECHNIQUES: usize = 16;
/// Max OCSF resources per finding.
pub const MAX_RESOURCES: usize = 8;
/// Max title length.
pub const MAX_TITLE: usize = 256;
/// Max description length.
pub const MAX_DESCRIPTION: usize = 2048;
/// Max length of trusted labels (model, site, versions).
pub const MAX_LABEL: usize = 128;
/// Max robot id length.
pub const MAX_ROBOT_ID: usize = 64;
/// Max rule id length.
pub const MAX_RULE_ID: usize = 128;
/// Earliest accepted time: 2000-01-01T00:00:00Z (ms). Catches unset clocks.
pub const MIN_TIME_MS: u64 = 946_684_800_000;
/// Latest accepted time: 2100-01-01T00:00:00Z (ms).
pub const MAX_TIME_MS: u64 = 4_102_444_800_000;

/// One validation problem. `path` values are JSON Pointers or field names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    Missing(&'static str),
    OutOfRange {
        path: String,
        value: String,
    },
    Mismatch(&'static str),
    BadFormat {
        path: String,
        reason: &'static str,
    },
    TooLong {
        path: String,
        len: usize,
        max: usize,
    },
    ForbiddenChar {
        path: String,
        codepoint: u32,
    },
    TooLarge {
        len: usize,
        max: usize,
    },
    Parse(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(w) => write!(f, "missing: {w}"),
            Self::OutOfRange { path, value } => write!(f, "{path}: out of range ({value})"),
            Self::Mismatch(w) => write!(f, "inconsistent: {w}"),
            Self::BadFormat { path, reason } => write!(f, "{path}: {reason}"),
            Self::TooLong { path, len, max } => write!(f, "{path}: {len} bytes > {max}"),
            Self::ForbiddenChar { path, codepoint } => {
                write!(f, "{path}: forbidden character U+{codepoint:04X}")
            }
            Self::TooLarge { len, max } => write!(f, "finding is {len} bytes > {max}"),
            Self::Parse(e) => write!(f, "parse error: {e}"),
        }
    }
}

impl std::error::Error for ValidationError {}

struct Checker {
    errs: Vec<ValidationError>,
}

impl Checker {
    fn push(&mut self, e: ValidationError) {
        self.errs.push(e);
    }
    fn eq<T: PartialEq>(&mut self, a: T, b: T, what: &'static str) {
        if a != b {
            self.push(ValidationError::Mismatch(what));
        }
    }
    fn len(&mut self, path: &str, s: &str, min: usize, max: usize) {
        if s.len() < min {
            self.push(ValidationError::BadFormat {
                path: path.into(),
                reason: "empty",
            });
        }
        if s.len() > max {
            self.push(ValidationError::TooLong {
                path: path.into(),
                len: s.len(),
                max,
            });
        }
    }
    fn fmt(&mut self, ok: bool, path: &str, reason: &'static str) {
        if !ok {
            self.push(ValidationError::BadFormat {
                path: path.into(),
                reason,
            });
        }
    }
    fn sha(&mut self, path: &str, s: &str) {
        self.fmt(is_sha256_hex(s), path, "expected 64 lower-case hex chars");
    }
    fn float(&mut self, path: &str, v: Option<f64>, max: Option<f64>) {
        if let Some(v) = v {
            let ok = v.is_finite() && v >= 0.0 && max.is_none_or(|m| v <= m);
            if !ok {
                self.push(ValidationError::OutOfRange {
                    path: path.into(),
                    value: format!("{v}"),
                });
            }
        }
    }
    fn tainted(&mut self, path: &str, t: &Tainted, cap: usize) {
        self.eq(
            t.taint,
            Provenance::Adversary,
            "tainted value must carry taint=adversary",
        );
        self.fmt(is_neutral(&t.value), path, "tainted value not neutralised");
        if t.value.len() > cap {
            self.push(ValidationError::TooLong {
                path: path.into(),
                len: t.value.len(),
                max: cap,
            });
        }
        self.sha(&format!("{path}/original_sha256"), &t.original_sha256);
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_prefixed_uid(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|h| h.len() == 32 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// `[A-Za-z0-9._-]{1,64}`.
pub fn is_valid_robot_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ROBOT_ID
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `[a-z0-9._]{1,128}`, starting with a letter.
pub fn is_valid_rule_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_RULE_ID
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_'))
}

fn is_technique_id(s: &str) -> bool {
    let b = s.as_bytes();
    let base = b.len() >= 5 && b[0] == b'T' && b[1..5].iter().all(u8::is_ascii_digit);
    base && (b.len() == 5
        || (b.len() == 9 && b[5] == b'.' && b[6..9].iter().all(u8::is_ascii_digit)))
}

fn same_major(v: &str, ours: &str) -> bool {
    let major = |s: &str| s.split('.').next().map(str::to_owned);
    v.split('.').count() == 3
        && v.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && major(v) == major(ours)
}

/// Validate a typed finding. `Ok(())` or every problem found.
pub fn validate(env: &FindingEnvelope) -> Result<(), Vec<ValidationError>> {
    let mut c = Checker { errs: Vec::new() };
    let o = &env.ocsf;
    let ec = &env.entity_context;
    let fi = &o.finding_info;

    // --- envelope constants & identity
    c.fmt(
        same_major(&env.contract_version, CONTRACT_VERSION),
        "/contract_version",
        "unsupported contract major version",
    );
    c.eq(
        env.data_source.as_str(),
        DATA_SOURCE,
        "data_source must be robot_edr",
    );
    c.fmt(
        is_prefixed_uid(&env.finding_id, "rf1-"),
        "/finding_id",
        "expected rf1-<32 hex>",
    );
    c.eq(
        &env.finding_id,
        &fi.uid,
        "finding_id == ocsf.finding_info.uid",
    );
    c.eq(
        env.external_id.clone(),
        format!("{}:{}", ec.robot.id, env.finding_id),
        "external_id == <robot_id>:<finding_id>",
    );
    c.fmt(
        is_valid_robot_id(&ec.robot.id),
        "/entity_context/robot/id",
        "robot id charset/length",
    );
    c.fmt(
        is_valid_rule_id(&ec.rule_id),
        "/entity_context/rule_id",
        "rule id charset/length",
    );

    // --- trusted text
    c.len("/title", &env.title, 1, MAX_TITLE);
    c.len("/description", &env.description, 1, MAX_DESCRIPTION);
    c.eq(&env.title, &fi.title, "title == finding_info.title");
    c.eq(&env.title, &o.message, "title == ocsf.message");
    c.eq(
        &env.description,
        &fi.desc,
        "description == finding_info.desc",
    );
    c.len("/entity_context/robot/model", &ec.robot.model, 1, MAX_LABEL);
    c.len("/entity_context/robot/site", &ec.robot.site, 1, MAX_LABEL);
    c.len(
        "/entity_context/profile/version",
        &ec.profile.version,
        1,
        MAX_LABEL,
    );
    c.sha("/entity_context/profile/sha256", &ec.profile.sha256);
    if let Some(fw) = &ec.robot.firmware {
        c.len(
            "/entity_context/robot/firmware/version",
            &fw.version,
            1,
            MAX_LABEL,
        );
        c.sha("/entity_context/robot/firmware/sha256", &fw.sha256);
    }

    // --- severity
    c.eq(
        o.severity_id,
        ocsf_severity_id(env.severity),
        "severity_id <-> severity",
    );
    c.eq(
        o.severity.as_str(),
        ocsf_severity_name(env.severity),
        "ocsf.severity caption",
    );

    // --- OCSF class constants and enums
    c.eq(o.class_uid, ocsf_ids::CLASS_UID, "class_uid == 2004");
    c.eq(o.class_name.as_str(), ocsf_ids::CLASS_NAME, "class_name");
    c.eq(o.category_uid, ocsf_ids::CATEGORY_UID, "category_uid == 2");
    c.eq(
        o.category_name.as_str(),
        ocsf_ids::CATEGORY_NAME,
        "category_name",
    );
    let activity = match o.activity_id {
        1 => Some("Create"),
        2 => Some("Update"),
        3 => Some("Close"),
        _ => None,
    };
    match activity {
        None => c.push(ValidationError::OutOfRange {
            path: "/ocsf/activity_id".into(),
            value: o.activity_id.to_string(),
        }),
        Some(name) => {
            c.eq(o.activity_name.as_str(), name, "activity_name caption");
            c.eq(
                o.type_name.clone(),
                format!("{}: {}", ocsf_ids::CLASS_NAME, name),
                "type_name",
            );
        }
    }
    c.eq(
        o.type_uid,
        ocsf_ids::CLASS_UID * 100 + o.activity_id as u32,
        "type_uid == class_uid*100 + activity_id",
    );
    let status = match o.status_id {
        0 => Some("Unknown"),
        1 => Some("New"),
        2 => Some("In Progress"),
        3 => Some("Suppressed"),
        4 => Some("Resolved"),
        99 => Some("Other"),
        _ => None,
    };
    match status {
        None => c.push(ValidationError::OutOfRange {
            path: "/ocsf/status_id".into(),
            value: o.status_id.to_string(),
        }),
        Some(name) => c.eq(o.status.as_str(), name, "status caption"),
    }

    // --- counts & activity
    if o.count == 0 {
        c.push(ValidationError::OutOfRange {
            path: "/ocsf/count".into(),
            value: "0".into(),
        });
    }
    c.eq(
        o.count,
        ec.occurrence_count,
        "ocsf.count == occurrence_count",
    );
    if o.activity_id == 1 && o.count != 1 {
        c.push(ValidationError::Mismatch(
            "activity Create requires count == 1",
        ));
    }
    if o.activity_id == 2 && o.count < 2 {
        c.push(ValidationError::Mismatch(
            "activity Update requires count >= 2",
        ));
    }

    // --- times
    for (p, t) in [
        ("/ocsf/time", o.time),
        ("/ocsf/finding_info/first_seen_time", fi.first_seen_time),
        ("/ocsf/finding_info/last_seen_time", fi.last_seen_time),
    ] {
        if !(MIN_TIME_MS..MAX_TIME_MS).contains(&t) {
            c.push(ValidationError::OutOfRange {
                path: p.into(),
                value: t.to_string(),
            });
        }
    }
    if fi.first_seen_time > fi.last_seen_time {
        c.push(ValidationError::Mismatch(
            "first_seen_time <= last_seen_time",
        ));
    }
    c.eq(o.time, fi.last_seen_time, "time == last_seen_time");
    c.eq(
        env.timestamp.clone(),
        rfc3339_ms(o.time),
        "timestamp == rfc3339(time)",
    );

    // --- metadata
    let m = &o.metadata;
    c.eq(m.version.as_str(), OCSF_VERSION, "metadata.version");
    c.eq(
        m.product.name.as_str(),
        PRODUCT_NAME,
        "metadata.product.name",
    );
    c.eq(
        m.product.vendor_name.as_str(),
        VENDOR_NAME,
        "metadata.product.vendor_name",
    );
    c.len(
        "/ocsf/metadata/product/version",
        &m.product.version,
        1,
        MAX_LABEL,
    );
    c.fmt(
        is_prefixed_uid(&m.uid, "re1-"),
        "/ocsf/metadata/uid",
        "expected re1-<32 hex>",
    );
    c.eq(m.log_name.as_str(), KAFKA_TOPIC, "metadata.log_name");

    // --- finding_info
    c.eq(
        fi.analytic.uid.as_str(),
        ec.rule_id.as_str(),
        "analytic.uid == rule_id",
    );
    c.eq(
        fi.analytic.name.as_str(),
        ec.rule_id.as_str(),
        "analytic.name == rule_id",
    );
    c.eq(fi.analytic.type_id, 1, "analytic.type_id == 1 (Rule)");
    c.eq(fi.analytic.type_.as_str(), "Rule", "analytic.type");
    if fi.types.is_empty() {
        c.push(ValidationError::Missing("finding_info.types"));
    }
    if fi.data_sources.is_empty() {
        c.push(ValidationError::Missing("finding_info.data_sources"));
    }

    // --- ATT&CK
    if env.mitre_predictions.len() > MAX_TECHNIQUES {
        c.push(ValidationError::TooLong {
            path: "/mitre_predictions".into(),
            len: env.mitre_predictions.len(),
            max: MAX_TECHNIQUES,
        });
    }
    c.eq(
        env.mitre_predictions.len(),
        fi.attacks.len(),
        "mitre_predictions <-> attacks",
    );
    for (i, (mp, at)) in env.mitre_predictions.iter().zip(&fi.attacks).enumerate() {
        let p = format!("/mitre_predictions/{i}");
        c.fmt(
            is_technique_id(&mp.technique_id),
            &p,
            "technique id must be Tnnnn[.nnn]",
        );
        c.len(
            &format!("{p}/technique_name"),
            &mp.technique_name,
            1,
            MAX_LABEL,
        );
        c.eq(mp.framework.as_str(), "attack_ics", "mitre framework");
        c.eq(
            mp.provenance,
            Provenance::Sensor,
            "mitre provenance == sensor",
        );
        c.eq(
            &mp.technique_id,
            &at.technique.uid,
            "attacks[].technique.uid",
        );
        c.eq(
            &mp.technique_name,
            &at.technique.name,
            "attacks[].technique.name",
        );
    }

    // --- device
    c.eq(&o.device.uid, &ec.robot.id, "device.uid == robot id");
    c.eq(&o.device.name, &ec.robot.id, "device.name == robot id");
    c.eq(
        &o.device.model,
        &ec.robot.model,
        "device.model == robot model",
    );
    c.eq(o.device.type_id, 99, "device.type_id == 99 (Other)");
    c.eq(o.device.type_.as_str(), "Robot", "device.type");

    // --- evidence
    if o.evidences.len() > MAX_EVIDENCE {
        c.push(ValidationError::TooLong {
            path: "/ocsf/evidences".into(),
            len: o.evidences.len(),
            max: MAX_EVIDENCE,
        });
    }
    c.eq(
        o.evidences.len(),
        env.evidence_links.len(),
        "evidences <-> evidence_links",
    );
    for (i, (e, link)) in o.evidences.iter().zip(&env.evidence_links).enumerate() {
        let d = &e.data;
        c.eq(d.kind.as_str(), "robodr.blackbox", "evidence kind");
        c.sha(&format!("/ocsf/evidences/{i}/data/sha256"), &d.sha256);
        let r = BlackBoxRef {
            segment: d.segment,
            seq: d.seq,
            sha256: d.sha256.clone(),
        };
        let uri = r.uri(&ec.robot.id);
        c.eq(&d.uri, &uri, "evidence uri");
        c.eq(link, &uri, "evidence_links[i] == evidences[i].data.uri");
    }

    // --- resources
    if o.resources.len() > MAX_RESOURCES {
        c.push(ValidationError::TooLong {
            path: "/ocsf/resources".into(),
            len: o.resources.len(),
            max: MAX_RESOURCES,
        });
    }
    for (i, r) in o.resources.iter().enumerate() {
        let p = format!("/ocsf/resources/{i}");
        let cap = match r.type_.as_str() {
            "ros2.participant" => Some(caps::GUID),
            "ros2.node" => Some(caps::NODE),
            "ros2.topic" => Some(caps::TOPIC),
            "ip_address" => Some(caps::IP),
            _ => None,
        };
        let Some(cap) = cap else {
            c.push(ValidationError::OutOfRange {
                path: format!("{p}/type"),
                value: r.type_.clone(),
            });
            continue;
        };
        if !r.labels.iter().any(|l| l == TAINT_LABEL) {
            c.push(ValidationError::Missing(
                "resources[].labels taint:adversary",
            ));
        }
        if r.uid.is_none() && r.name.is_none() {
            c.push(ValidationError::Missing("resources[].uid or name"));
        }
        for (k, v) in [("uid", &r.uid), ("name", &r.name)] {
            if let Some(v) = v {
                c.fmt(
                    is_neutral(v),
                    &format!("{p}/{k}"),
                    "tainted value not neutralised",
                );
                if v.len() > cap {
                    c.push(ValidationError::TooLong {
                        path: format!("{p}/{k}"),
                        len: v.len(),
                        max: cap,
                    });
                }
            }
        }
    }

    // --- entity context
    c.eq(
        &o.unmapped.robodr,
        ec,
        "ocsf.unmapped.robodr == entity_context",
    );
    let ros = &ec.ros;
    for (k, v, cap) in [
        ("participant_guid", &ros.participant_guid, caps::GUID),
        ("node", &ros.node, caps::NODE),
        ("topic", &ros.topic, caps::TOPIC),
        ("type_name", &ros.type_name, caps::TYPE_NAME),
        ("src_ip", &ros.src_ip, caps::IP),
    ] {
        if let Some(t) = v {
            c.tainted(&format!("/entity_context/ros/{k}"), t, cap);
        }
    }
    c.tainted("/entity_context/detail", &ec.detail, caps::DETAIL);
    if let Some(cmd) = &ec.command {
        c.tainted("/entity_context/command/channel", &cmd.channel, caps::TOPIC);
        c.float(
            "/entity_context/command/linear_speed",
            cmd.linear_speed,
            None,
        );
        c.float("/entity_context/command/joint_speed", cmd.joint_speed, None);
        c.float(
            "/entity_context/command/envelope_max_linear_speed",
            cmd.envelope_max_linear_speed,
            None,
        );
        c.float(
            "/entity_context/command/envelope_max_joint_speed",
            cmd.envelope_max_joint_speed,
            None,
        );
    }
    c.float("/anomaly_score", env.anomaly_score, Some(1.0));

    // --- generic string walk, taint pointers, size (on the serialised form)
    match serde_json::to_value(env) {
        Err(e) => c.push(ValidationError::Parse(e.to_string())),
        Ok(v) => {
            walk_strings(&v, &mut String::new(), &mut c);
            let mut expected = Vec::new();
            collect_tainted(&v, &mut String::new(), &mut expected);
            expected.sort();
            if env.adversary_controlled_fields != expected {
                c.push(ValidationError::Mismatch(
                    "adversary_controlled_fields must list every tainted value (sorted)",
                ));
            }
        }
    }
    match serde_json::to_vec(env) {
        Ok(b) if b.len() > MAX_FINDING_BYTES => c.push(ValidationError::TooLarge {
            len: b.len(),
            max: MAX_FINDING_BYTES,
        }),
        _ => {}
    }

    if c.errs.is_empty() {
        Ok(())
    } else {
        Err(c.errs)
    }
}

/// Parse untrusted bytes (size-capped *before* parsing) and validate.
pub fn parse_and_validate(json: &str) -> Result<FindingEnvelope, Vec<ValidationError>> {
    if json.len() > MAX_FINDING_BYTES {
        return Err(vec![ValidationError::TooLarge {
            len: json.len(),
            max: MAX_FINDING_BYTES,
        }]);
    }
    let raw: Value =
        serde_json::from_str(json).map_err(|e| vec![ValidationError::Parse(e.to_string())])?;
    // Unknown fields are tolerated structurally (forward compatibility within
    // a contract major version) but dropped on deserialisation, so the string
    // rules are applied to the *raw* document as well: hostile characters are
    // rejected wherever they appear, including in fields we do not know.
    let mut c = Checker { errs: Vec::new() };
    walk_strings(&raw, &mut String::new(), &mut c);
    if !c.errs.is_empty() {
        return Err(c.errs);
    }
    let env: FindingEnvelope =
        serde_json::from_value(raw).map_err(|e| vec![ValidationError::Parse(e.to_string())])?;
    validate(&env)?;
    Ok(env)
}

fn escape_pointer_token(k: &str) -> String {
    k.replace('~', "~0").replace('/', "~1")
}

fn check_str(path: &str, s: &str, c: &mut Checker) {
    if s.len() > MAX_STRING_BYTES {
        c.push(ValidationError::TooLong {
            path: path.into(),
            len: s.len(),
            max: MAX_STRING_BYTES,
        });
    }
    if let Some(ch) = s
        .chars()
        .find(|&ch| is_forbidden_char(ch) || is_markup_char(ch))
    {
        c.push(ValidationError::ForbiddenChar {
            path: path.into(),
            codepoint: ch as u32,
        });
    }
}

fn walk_strings(v: &Value, path: &mut String, c: &mut Checker) {
    match v {
        Value::String(s) => check_str(path, s, c),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                let len = path.len();
                path.push('/');
                path.push_str(&i.to_string());
                walk_strings(x, path, c);
                path.truncate(len);
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                let len = path.len();
                path.push('/');
                path.push_str(&escape_pointer_token(k));
                check_str(path, k, c);
                walk_strings(x, path, c);
                path.truncate(len);
            }
        }
        _ => {}
    }
}

fn collect_tainted(v: &Value, path: &mut String, out: &mut Vec<String>) {
    match v {
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                let len = path.len();
                path.push('/');
                path.push_str(&i.to_string());
                collect_tainted(x, path, out);
                path.truncate(len);
            }
        }
        Value::Object(m) => {
            let is_tainted_value = m.get("taint").and_then(Value::as_str) == Some("adversary");
            let is_tainted_resource = m
                .get("labels")
                .and_then(Value::as_array)
                .is_some_and(|l| l.iter().any(|x| x.as_str() == Some(TAINT_LABEL)));
            if is_tainted_value || is_tainted_resource {
                out.push(path.clone());
            }
            for (k, x) in m {
                let len = path.len();
                path.push('/');
                path.push_str(&escape_pointer_token(k));
                collect_tainted(x, path, out);
                path.truncate(len);
            }
        }
        _ => {}
    }
}

/// Sorted JSON Pointers of every attacker-controlled object in `env`.
pub fn tainted_pointers(env: &FindingEnvelope) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::to_value(env) {
        collect_tainted(&v, &mut String::new(), &mut out);
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_charsets() {
        assert!(is_valid_robot_id("ugv-007.a_b"));
        assert!(!is_valid_robot_id(""));
        assert!(!is_valid_robot_id("ugv 007"));
        assert!(!is_valid_robot_id("ugv/007"));
        assert!(!is_valid_robot_id(&"a".repeat(65)));
        assert!(is_valid_rule_id("robot.ros2.unknown_participant"));
        assert!(!is_valid_rule_id("Robot.x"));
        assert!(!is_valid_rule_id("1robot"));
        assert!(!is_valid_rule_id("robot x"));
    }

    #[test]
    fn technique_ids() {
        assert!(is_technique_id("T0855"));
        assert!(is_technique_id("T1059.001"));
        assert!(!is_technique_id("T085"));
        assert!(!is_technique_id("X0855"));
        assert!(!is_technique_id("T0855."));
    }

    #[test]
    fn contract_major() {
        assert!(same_major("1.0.0", "1.0.0"));
        assert!(same_major("1.7.3", "1.0.0"));
        assert!(!same_major("2.0.0", "1.0.0"));
        assert!(!same_major("1.0", "1.0.0"));
        assert!(!same_major("1.x.0", "1.0.0"));
    }

    #[test]
    fn oversized_input_rejected_before_parse() {
        let big = " ".repeat(MAX_FINDING_BYTES + 1);
        assert!(matches!(
            parse_and_validate(&big).unwrap_err()[0],
            ValidationError::TooLarge { .. }
        ));
        assert!(matches!(
            parse_and_validate("{not json").unwrap_err()[0],
            ValidationError::Parse(_)
        ));
        assert!(matches!(
            parse_and_validate("[[[[[[[[[[[[").unwrap_err()[0],
            ValidationError::Parse(_)
        ));
    }
}
