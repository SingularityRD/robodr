//! Strict validator for outgoing (and replayed) findings.
//!
//! Every finding is validated before it leaves the producer
//! ([`crate::FindingBuilder::build`], [`crate::to_json`]), and
//! [`parse_and_validate`] re-applies the same rules to bytes coming back in
//! (diode import, replay tooling, tests). The validator never panics and
//! reports *all* problems it finds.
//!
//! Rules (see also the contract `docs/contracts/robodr.findings.md`):
//!
//! * **Contract version**: `2.y.z` is validated in full; `1.y.z` (the
//!   superseded `robot-edr.findings` contract) is accepted on parse with its
//!   own fixed constants and never emitted ([`validate_for_emit`]); any
//!   other major is rejected.
//! * **Required fields / constants**: OCSF class 2004, category 2, `type_uid =
//!   class_uid*100 + activity_id`, schema/product constants. `data_source`
//!   and `ocsf.metadata.log_name` are deployment labels in 2.x
//!   ([`is_valid_data_source`], [`is_valid_topic`]) and the fixed
//!   [`legacy_v1`] values in 1.x.
//! * **Enums in range** and consistent with their captions (`severity_id` ↔
//!   `severity`, `activity_id` ↔ `activity_name`, `status_id` ↔ `status`).
//! * **Cross-field consistency**: `finding_id == finding_info.uid`,
//!   `external_id == robot_id:finding_id`, `unmapped.robodr == entity_context`,
//!   evidences ↔ `evidence_links`, ATT&CK lists, times.
//! * **Formats**: id charsets, lower-case SHA-256 hex, RFC 3339 timestamp.
//! * **Every string** in the serialised message (keys and values): at most
//!   [`MAX_STRING_BYTES`], printable ASCII only (U+0020–U+007E) and no raw
//!   `<`, `>` or `` ` `` (SR-TAINT, see [`crate::taint`]). Trusted config
//!   (robot model, site, versions) is therefore ASCII-only too.
//! * **Tainted values**: `taint == adversary`; the value is in canonical
//!   encoded form for its charset ([`crate::taint::is_encoded`]: ROS-name
//!   charset for `ros.*`, `command.channel` and tainted `resources[]`, text
//!   charset for `detail`); per-field caps (raw characters, escaped bytes).
//!   The value is decoded and everything derivable from it is recomputed:
//!   `escaped`; while not truncated, `original_len`/`original_sha256` (so the
//!   value is proven lossless) and, for contract ≥ 1.1, `non_ascii`,
//!   `mixed_script`, `injection_hint` exactly (only "at least" when
//!   truncated); `display` must be the ASCII-safe rendering of the decoded
//!   value and `suspicious` the OR of the other flags.
//! * **Floats**: finite, non-negative; `anomaly_score` within `[0, 1]`.
//! * **Size**: serialised message at most [`MAX_FINDING_BYTES`].
//! * **Catalog constants**: `title`, the `description` prefix,
//!   `finding_info.types` / `data_sources` and the ATT&CK techniques
//!   (`technique_id`/`technique_name`, `attacks[]`) must be exactly what the
//!   trusted rule catalog ([`crate::rule_info`]) gives for `rule_id`;
//!   `resources[].labels` must be exactly `["taint:adversary"]`. Free prose in
//!   these sensor-provenance fields is rejected. Consequence: a new catalog
//!   entry needs the validator (this crate) updated on both sides.
//! * **Contract 1.0** messages are accepted for replay only if they carry
//!   none of the 1.1 tainted-value fields (`display`, `non_ascii`,
//!   `mixed_script`, `injection_hint`, `suspicious`). No 1.x message is
//!   emitted ([`validate_for_emit`]).
//! * **Raw document** ([`parse_and_validate`]): duplicate object keys are
//!   rejected at any depth (serde_json would silently keep the last one).

use crate::builder::{ocsf_severity_id, ocsf_severity_name, rfc3339_ms, rule_info_for_contract};
use crate::hash::{hex, sha256};
use crate::model::*;
use crate::taint::{
    caps, escaped_cap, is_encoded, is_mixed_script, is_safe_char, looks_like_injection, render,
    unescape, Charset, Provenance, Tainted, TAINT_LABEL,
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
    /// Contract minor >= 1: `display`, `injection_hint`, `suspicious` exist
    /// and the flags must match the value exactly.
    v1_1: bool,
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
    /// Check one [`Tainted`] value. `cap` is the field's cap in raw
    /// characters ([`caps`]). Because `value` is lossless while not
    /// truncated, every flag and the display are *recomputed* from it and
    /// compared, and the hash must match; a truncated value can only be
    /// checked for consistency with its prefix.
    fn tainted(&mut self, path: &str, t: &Tainted, cap: usize, cs: Charset) {
        self.eq(
            t.taint,
            Provenance::Adversary,
            "tainted value must carry taint=adversary",
        );
        if t.value.len() > escaped_cap(cap) {
            self.push(ValidationError::TooLong {
                path: path.into(),
                len: t.value.len(),
                max: escaped_cap(cap),
            });
        }
        self.sha(&format!("{path}/original_sha256"), &t.original_sha256);
        let decoded = if is_encoded(&t.value, cs) {
            unescape(&t.value)
        } else {
            None
        };
        let Some(raw) = decoded else {
            self.fmt(
                false,
                path,
                "tainted value not neutralised (not canonical for its charset)",
            );
            return;
        };
        let p = |k: &str| format!("{path}/{k}");
        self.fmt(
            t.escaped == t.value.contains('\\'),
            &p("escaped"),
            "escaped flag does not match the value",
        );
        let n = raw.chars().count();
        if n > cap {
            self.push(ValidationError::TooLong {
                path: path.into(),
                len: n,
                max: cap,
            });
        }
        let (non_ascii, mixed, hint) = (
            !raw.is_ascii(),
            is_mixed_script(&raw),
            looks_like_injection(&raw),
        );
        // Flags may only be *stronger* than what the kept prefix shows.
        self.fmt(
            t.non_ascii || !non_ascii,
            &p("non_ascii"),
            "value escapes a non-ASCII character but non_ascii is false",
        );
        self.fmt(
            t.non_ascii || !t.mixed_script,
            &p("mixed_script"),
            "mixed_script requires non_ascii",
        );
        if !t.truncated {
            self.fmt(
                t.original_len == raw.len() as u64
                    && t.original_sha256 == hex(&sha256(raw.as_bytes())),
                &p("original_sha256"),
                "untruncated value does not decode to the hashed original",
            );
        }
        if !self.v1_1 {
            // Contract 1.0 had none of the 1.1 fields. A 1.0 message must not
            // carry them: otherwise a downgraded `contract_version` would
            // switch off the checks below while a forged `display` or cleared
            // `suspicious` still reached consumers (rev3 O1).
            self.fmt(
                t.display.is_empty()
                    && !t.non_ascii
                    && !t.mixed_script
                    && !t.injection_hint
                    && !t.suspicious,
                path,
                "contract 1.0 value must not carry 1.1 fields (display/flags)",
            );
            return;
        }
        if t.truncated {
            self.fmt(
                n == cap && t.original_len > raw.len() as u64,
                &p("truncated"),
                "truncated value must keep exactly cap characters of a longer original",
            );
            self.fmt(
                (t.mixed_script || !mixed) && (t.injection_hint || !hint),
                path,
                "hint flags weaker than the kept prefix",
            );
        } else {
            self.fmt(
                t.non_ascii == non_ascii,
                &p("non_ascii"),
                "non_ascii does not match the value",
            );
            self.fmt(
                t.mixed_script == mixed,
                &p("mixed_script"),
                "mixed_script does not match the value",
            );
            self.fmt(
                t.injection_hint == hint,
                &p("injection_hint"),
                "injection_hint does not match the value",
            );
        }
        self.fmt(
            t.display == render(&raw, cs),
            &p("display"),
            "display is not the ASCII-safe rendering of the value",
        );
        self.fmt(
            t.suspicious
                == (t.escaped || t.truncated || t.non_ascii || t.mixed_script || t.injection_hint),
            &p("suspicious"),
            "suspicious must be the OR of escaped/truncated/non_ascii/mixed_script/injection_hint",
        );
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

/// The major of a well-formed `X.Y.Z` version (digits only, each part at
/// most 9 digits), else `None`.
pub fn contract_major(v: &str) -> Option<u64> {
    let parts: Vec<&str> = v.split('.').collect();
    let ok = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()));
    if ok {
        parts[0].parse().ok()
    } else {
        None
    }
}

/// A contract version this crate validates: `2.y.z` (current) or `1.y.z`
/// (legacy, parse-only).
pub fn is_supported_contract_version(v: &str) -> bool {
    matches!(contract_major(v), Some(m) if m == CONTRACT_MAJOR || m == LEGACY_CONTRACT_MAJOR)
}

/// A contract version this crate emits: the current major.
pub fn is_emittable_contract_version(v: &str) -> bool {
    contract_major(v) == Some(CONTRACT_MAJOR)
}

/// `true` for a well-formed 1.x version (the legacy constants apply).
fn is_legacy(v: &str) -> bool {
    contract_major(v) == Some(LEGACY_CONTRACT_MAJOR)
}

/// `true` unless `v` is a well-formed `1.Y.Z` with `Y < min`: the feature
/// level of contract 1.`min` or later (every 2.x has all 1.x features;
/// malformed versions are rejected separately and get the strictest checks).
fn minor_at_least(v: &str, min: u64) -> bool {
    if !is_legacy(v) {
        return true;
    }
    v.split('.')
        .nth(1)
        .and_then(|m| m.parse::<u64>().ok())
        .is_none_or(|m| m >= min)
}

/// The message's contract has `entity_context.agent_health` (2.5 or a
/// later 2.x / major).
fn has_agent_health_field(v: &str) -> bool {
    let mut parts = v.split('.').map(|p| p.parse::<u64>().ok());
    match (parts.next().flatten(), parts.next().flatten()) {
        (Some(major), Some(minor)) => {
            major > CONTRACT_MAJOR
                || (major == CONTRACT_MAJOR && minor >= crate::builder::CATALOG_2_5_MINOR)
        }
        _ => false,
    }
}

/// `entity_context.agent_health`: exactly on a 2.5+ `robot.agent.health`
/// finding, within [`health_limits`]; names and versions non-empty.
fn check_agent_health(env: &FindingEnvelope, c: &mut Checker) {
    use health_limits::{ITEMS, NAME_BYTES, REASONS, REASON_BYTES};
    let ec = &env.entity_context;
    let is_health = ec.rule_id == AGENT_HEALTH_RULE;
    let allowed = has_agent_health_field(&env.contract_version);
    let Some(h) = &ec.agent_health else {
        c.fmt(
            !(is_health && allowed),
            "/entity_context/agent_health",
            "a robot.agent.health finding must carry agent_health",
        );
        return;
    };
    c.fmt(
        is_health && allowed,
        "/entity_context/agent_health",
        "agent_health is only allowed on a 2.5+ robot.agent.health finding",
    );
    let p = "/entity_context/agent_health";
    let count = |name: &str, n: usize, max: usize, c: &mut Checker| {
        if n > max {
            c.push(ValidationError::TooLong {
                path: format!("{p}/{name}"),
                len: n,
                max,
            });
        }
    };
    count("reasons", h.reasons.len(), REASONS, c);
    count("versions", h.versions.len(), ITEMS, c);
    count("inputs", h.inputs.len(), ITEMS, c);
    count("reachability", h.reachability.len(), ITEMS, c);
    count("credentials", h.credentials.len(), ITEMS, c);
    count("disks", h.disks.len(), ITEMS, c);
    for (i, r) in h.reasons.iter().enumerate() {
        c.len(&format!("{p}/reasons/{i}"), r, 1, REASON_BYTES);
    }
    for (i, v) in h.versions.iter().enumerate() {
        c.len(
            &format!("{p}/versions/{i}/component"),
            &v.component,
            1,
            NAME_BYTES,
        );
        c.len(
            &format!("{p}/versions/{i}/version"),
            &v.version,
            1,
            NAME_BYTES,
        );
    }
    for (i, x) in h.inputs.iter().enumerate() {
        c.len(&format!("{p}/inputs/{i}/name"), &x.name, 1, NAME_BYTES);
    }
    for (i, x) in h.reachability.iter().enumerate() {
        c.len(
            &format!("{p}/reachability/{i}/component"),
            &x.component,
            1,
            NAME_BYTES,
        );
    }
    for (i, x) in h.credentials.iter().enumerate() {
        c.len(&format!("{p}/credentials/{i}/name"), &x.name, 1, NAME_BYTES);
    }
    for (i, x) in h.disks.iter().enumerate() {
        c.len(&format!("{p}/disks/{i}/name"), &x.name, 1, NAME_BYTES);
        c.fmt(
            x.free_bytes <= x.total_bytes,
            &format!("{p}/disks/{i}/free_bytes"),
            "free_bytes must not exceed total_bytes",
        );
    }
    c.fmt(h.seq >= 1, &format!("{p}/seq"), "seq starts at 1");
}

/// A topic name a producer may use (also `ocsf.metadata.log_name`): Kafka's
/// rule, 1..=249 characters of `[A-Za-z0-9._-]`, not `.` or `..`.
pub fn is_valid_topic(s: &str) -> bool {
    (1..=249).contains(&s.len())
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A `data_source` label a producer may use: 1..=64 characters of
/// `[a-z0-9._-]`, starting with a letter or digit.
pub fn is_valid_data_source(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Validate a typed finding. `Ok(())` or every problem found.
pub fn validate(env: &FindingEnvelope) -> Result<(), Vec<ValidationError>> {
    let mut c = Checker {
        errs: Vec::new(),
        v1_1: minor_at_least(&env.contract_version, 1),
    };
    let o = &env.ocsf;
    let ec = &env.entity_context;
    let fi = &o.finding_info;

    // --- envelope constants & identity
    c.fmt(
        is_supported_contract_version(&env.contract_version),
        "/contract_version",
        "unsupported contract major version",
    );
    let legacy = is_legacy(&env.contract_version);
    if legacy {
        c.eq(
            env.data_source.as_str(),
            legacy_v1::DATA_SOURCE,
            "data_source must be robot_edr (contract 1.x)",
        );
    } else {
        c.fmt(
            is_valid_data_source(&env.data_source),
            "/data_source",
            "expected [a-z0-9][a-z0-9._-]{0,63}",
        );
    }
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
    if legacy {
        c.eq(
            m.log_name.as_str(),
            legacy_v1::TOPIC,
            "metadata.log_name (contract 1.x)",
        );
    } else {
        c.fmt(
            is_valid_topic(&m.log_name),
            "/ocsf/metadata/log_name",
            "expected a topic name [A-Za-z0-9._-]{1,249}",
        );
    }

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
    // Constant-like fields are derived from the trusted rule catalog by the
    // builder; anything else (e.g. prose aimed at an LLM triage step in a
    // forged or replayed message) is rejected, not merely charset-checked.
    // The catalog of the message's own contract minor (entries added later
    // were not available to its producer).
    let info = rule_info_for_contract(&ec.rule_id, &env.contract_version);
    c.eq(
        env.title.as_str(),
        info.title,
        "title == catalog title of rule_id",
    );
    c.fmt(
        env.description.starts_with(info.desc),
        "/description",
        "description must start with the catalog description of rule_id",
    );
    c.fmt(
        fi.types.len() == 2 && fi.types[0] == "robot_deviation" && fi.types[1] == info.data_source,
        "/ocsf/finding_info/types",
        "expected [\"robot_deviation\", <catalog data source of rule_id>]",
    );
    c.fmt(
        fi.data_sources.len() == 1 && fi.data_sources[0] == info.data_source,
        "/ocsf/finding_info/data_sources",
        "expected [<catalog data source of rule_id>]",
    );

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
    let catalog_ok = env.mitre_predictions.len() == info.techniques.len()
        && env
            .mitre_predictions
            .iter()
            .zip(info.techniques)
            .all(|(mp, (id, name))| mp.technique_id == *id && mp.technique_name == *name);
    c.fmt(
        catalog_ok,
        "/mitre_predictions",
        "ATT&CK techniques must be exactly the catalog entries of rule_id",
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

    // --- agent health record (contract 2.5)
    check_agent_health(env, &mut c);

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
        c.fmt(
            r.labels.len() == 1 && r.labels[0] == TAINT_LABEL,
            &format!("{p}/labels"),
            "labels must be exactly [\"taint:adversary\"]",
        );
        if r.uid.is_none() && r.name.is_none() {
            c.push(ValidationError::Missing("resources[].uid or name"));
        }
        for (k, v) in [("uid", &r.uid), ("name", &r.name)] {
            if let Some(v) = v {
                c.fmt(
                    is_encoded(v, Charset::RosName),
                    &format!("{p}/{k}"),
                    "tainted value not neutralised (not canonical for its charset)",
                );
                if v.len() > escaped_cap(cap) {
                    c.push(ValidationError::TooLong {
                        path: format!("{p}/{k}"),
                        len: v.len(),
                        max: escaped_cap(cap),
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
            c.tainted(
                &format!("/entity_context/ros/{k}"),
                t,
                cap,
                Charset::RosName,
            );
        }
    }
    c.tainted(
        "/entity_context/detail",
        &ec.detail,
        caps::DETAIL,
        Charset::Text,
    );
    if let Some(cmd) = &ec.command {
        c.tainted(
            "/entity_context/command/channel",
            &cmd.channel,
            caps::TOPIC,
            Charset::RosName,
        );
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
    // serde_json keeps the *last* of duplicate keys, so an earlier copy would
    // never be validated while a first-wins parser (or an LLM reading the raw
    // record) sees it. Reject duplicates at any depth (rev3 O2).
    check_duplicate_keys(json).map_err(|e| vec![e])?;
    // Unknown fields are tolerated structurally (forward compatibility within
    // a contract major version) but dropped on deserialisation, so the string
    // rules are applied to the *raw* document as well: hostile characters are
    // rejected wherever they appear, including in fields we do not know.
    let mut c = Checker {
        errs: Vec::new(),
        v1_1: true,
    };
    walk_strings(&raw, &mut String::new(), &mut c);
    // A contract 1.0 message must not carry the 1.1 tainted-value fields at
    // all (presence, not just non-default values): see `Checker::tainted`.
    let legacy = raw
        .get("contract_version")
        .and_then(Value::as_str)
        .is_some_and(|v| !minor_at_least(v, 1));
    if legacy {
        find_v1_1_fields(&raw, &mut String::new(), &mut c);
    }
    if !c.errs.is_empty() {
        return Err(c.errs);
    }
    let env: FindingEnvelope =
        serde_json::from_value(raw).map_err(|e| vec![ValidationError::Parse(e.to_string())])?;
    validate(&env)?;
    Ok(env)
}

/// [`validate`] plus the producer-only rule that a finding being *emitted*
/// (Kafka value, diode export) uses the current contract major: contract
/// 1.x is accepted on parse for replay of old batches but never
/// (re-)emitted (1.0 serialises without a meaningful `display`/flags, and
/// every 1.x message carries the superseded fixed `data_source` / topic).
pub fn validate_for_emit(env: &FindingEnvelope) -> Result<(), Vec<ValidationError>> {
    let mut errs = validate(env).err().unwrap_or_default();
    if !is_emittable_contract_version(&env.contract_version) {
        errs.push(ValidationError::BadFormat {
            path: "/contract_version".into(),
            reason: "contract 1.x findings are parse-only and never emitted",
        });
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Fields that contract 1.1 added to tainted values.
const V1_1_TAINTED_FIELDS: [&str; 5] = [
    "display",
    "non_ascii",
    "mixed_script",
    "injection_hint",
    "suspicious",
];

fn find_v1_1_fields(v: &Value, path: &mut String, c: &mut Checker) {
    match v {
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                let len = path.len();
                path.push('/');
                path.push_str(&i.to_string());
                find_v1_1_fields(x, path, c);
                path.truncate(len);
            }
        }
        Value::Object(m) => {
            if m.contains_key("taint") {
                for k in V1_1_TAINTED_FIELDS {
                    if m.contains_key(k) {
                        c.push(ValidationError::BadFormat {
                            path: format!("{path}/{k}"),
                            reason: "contract 1.0 message must not carry 1.1 fields",
                        });
                    }
                }
            }
            for (k, x) in m {
                let len = path.len();
                path.push('/');
                path.push_str(&escape_pointer_token(k));
                find_v1_1_fields(x, path, c);
                path.truncate(len);
            }
        }
        _ => {}
    }
}

/// Reject duplicate object keys at any depth. `json` must already have been
/// accepted by `serde_json` (so it is well-formed and nesting is bounded by
/// serde_json's recursion limit); this is a byte scanner that only tracks
/// structure and decodes keys (so `"a"` and `"\u0061"` are the same key).
fn check_duplicate_keys(json: &str) -> Result<(), ValidationError> {
    use std::collections::HashSet;
    enum Frame {
        Object {
            keys: HashSet<String>,
            expect_key: bool,
        },
        Array,
    }
    let b = json.as_bytes();
    let mut stack: Vec<Frame> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'{' => stack.push(Frame::Object {
                keys: HashSet::new(),
                expect_key: true,
            }),
            b'[' => stack.push(Frame::Array),
            b'}' | b']' => {
                stack.pop();
            }
            b',' => {
                if let Some(Frame::Object { expect_key, .. }) = stack.last_mut() {
                    *expect_key = true;
                }
            }
            b':' => {
                if let Some(Frame::Object { expect_key, .. }) = stack.last_mut() {
                    *expect_key = false;
                }
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                let end = (i + 1).min(b.len());
                if let Some(Frame::Object { keys, expect_key }) = stack.last_mut() {
                    if *expect_key {
                        *expect_key = false;
                        let key: String = serde_json::from_str(&json[start..end])
                            .map_err(|e| ValidationError::Parse(e.to_string()))?;
                        if !keys.insert(key.clone()) {
                            return Err(ValidationError::BadFormat {
                                path: escape_pointer_token(&key),
                                reason: "duplicate JSON object key",
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
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
    if let Some(ch) = s.chars().find(|&ch| !is_safe_char(ch)) {
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
    fn contract_majors() {
        assert!(is_supported_contract_version("1.0.0"));
        assert!(is_supported_contract_version("1.7.3"));
        assert!(is_supported_contract_version("2.0.0"));
        assert!(is_supported_contract_version(CONTRACT_VERSION));
        assert!(is_emittable_contract_version(CONTRACT_VERSION));
        assert!(!is_emittable_contract_version("1.3.0"));
        for bad in ["3.0.0", "0.9.0", "1.0", "1.x.0", "2.0.0-rc1", "", "02.0.0x"] {
            assert!(!is_supported_contract_version(bad), "{bad}");
        }
        assert_eq!(contract_major("2.1.0"), Some(2));
        assert!(minor_at_least("2.0.0", 1) && minor_at_least("1.1.0", 1));
        assert!(!minor_at_least("1.0.0", 1));
    }

    #[test]
    fn deployment_labels() {
        for ok in ["robodr", "robodr.findings", "site-a_findings.v2", "x"] {
            assert!(is_valid_topic(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a b", "a/b", "kafka:x", &"t".repeat(250)] {
            assert!(!is_valid_topic(bad), "{bad}");
        }
        for ok in ["robodr", "robot_edr", "site-7.robodr", "0x"] {
            assert!(is_valid_data_source(ok), "{ok}");
        }
        for bad in [
            "",
            "RoboDR",
            "-x",
            ".x",
            "a b",
            "kafka:robodr",
            &"d".repeat(65),
        ] {
            assert!(!is_valid_data_source(bad), "{bad}");
        }
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

    #[test]
    fn duplicate_key_scanner() {
        let ok = [
            r#"{}"#,
            r#"{"a":1,"b":{"a":2},"c":[{"a":1},{"a":2}]}"#,
            r#"{"a":"x\"a\":{","b":"}","c":"\\"}"#,
            r#"[{"a":1},{"a":1}]"#,
            r#"{"a":["a","a"],"b":{"x":{"y":{"z":1}}}}"#,
            r#"{"é":1,"e":2}"#,
        ];
        for j in ok {
            assert!(serde_json::from_str::<Value>(j).is_ok(), "{j}");
            assert_eq!(check_duplicate_keys(j), Ok(()), "{j}");
        }
        let bad = [
            r#"{"a":1,"a":1}"#,
            r#"{"x":{"a":1,"b":2,"a":3}}"#,
            r#"[1,{"k":[{"q":1,"q":2}]}]"#,
            r#"{"a":1,"\u0061":2}"#,
            r#"{ "a" : 1 , "a" : 2 }"#,
            r#"{"a\"b":1,"a\u0022b":2}"#,
        ];
        for j in bad {
            assert!(serde_json::from_str::<Value>(j).is_ok(), "{j}");
            assert!(
                matches!(
                    check_duplicate_keys(j),
                    Err(ValidationError::BadFormat { .. })
                ),
                "{j}"
            );
        }
    }
}
