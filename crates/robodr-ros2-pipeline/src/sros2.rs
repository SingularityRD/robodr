//! SROS 2 / DDS-Security policy input (SALES-READINESS T78): what the
//! robot's keystore says, used to judge the DDS-Security claims of SPDP
//! announcements and to tell the operator what the sensor can still see.
//!
//! # Input
//!
//! The `enclaves/` directory of an SROS 2 keystore (`ros2 security
//! create_keystore` / `create_enclave` / `generate_artifacts`), or a copy of
//! its public parts:
//!
//! - `governance.xml`: the domain rules. RoboDR takes the first rule whose
//!   `<domains>` covers the configured `domain_id` (as the DDS stack does;
//!   if none does, all rules combined, most protective, with a warning)
//!   and reads its
//!   `allow_unauthenticated_participants`, `discovery_protection_kind`,
//!   `rtps_protection_kind` and the topic rules' `enable_discovery_protection`
//!   / `metadata_protection_kind` / `data_protection_kind`.
//! - `**/permissions.xml` (one per enclave): each `grant`'s `subject_name`
//!   and its `allow_rule` / `deny_rule` publish and subscribe topic
//!   expressions.
//!
//! Only the plain XML is read, never the signed `.p7s` copies and never a
//! private key. The keystore is operator input (commissioning), but it is
//! still parsed defensively: bounded file size ([`MAX_XML_BYTES`]), bounded
//! counts ([`MAX_GRANTS`], [`MAX_TOPICS_PER_RULE`]), no recursion, no
//! external entities (only the five predefined entities are decoded).
//!
//! # What the pipeline does with it
//!
//! For every SPDP announcement ([`Sros2Policy::judge_spdp`]):
//!
//! | announcement | finding |
//! |---|---|
//! | a certificate subject no grant of the keystore names | [`rules::UNTRUSTED_SECURITY_IDENTITY`], High: a participant from another keystore / CA |
//! | an identity token of class `DDS:Auth:PKI-DH:*` whose subject is granted | nothing |
//! | anything else (no DDS-Security parameter, or only part of one: security info, a permissions token, an identity token without subject or of another class), while the governance rule for `domain_id` has `allow_unauthenticated_participants` false | [`rules::UNTRUSTED_SECURITY_IDENTITY`], Medium: the secured robot will not talk to it, but something unauthenticated is on the robot's DDS domain |
//!
//! The subject is a claim in clear text (see `robodr_rtps::security`): a
//! participant can claim a granted subject without holding its key. The
//! robot's DDS stack then refuses the handshake; the sensor does not see
//! that (it would have to check the certificate presented in the
//! authentication handshake against the keystore, which is not done yet).
//!
//! # Visibility ([`Sros2Policy::visibility`])
//!
//! With the default SROS 2 governance (discovery, liveliness and data
//! `ENCRYPT`, RTPS `SIGN`), SEDP is encrypted: the sensor sees participants
//! (SPDP) and their claimed subjects, but **no topic, no endpoint and no
//! motion sample**. Topic-level enforcement then is the DDS stack's (the
//! permissions); RoboDR's profile checks of writers and the motion
//! envelopes have nothing to work on. The check-config summary says so.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use robodr_events::{Deviation, Severity};
use robodr_rtps::SpdpInfo;

use crate::sanitize::sanitize;

/// Rule ids raised from the policy.
pub mod rules {
    /// A participant's DDS-Security identity does not fit the robot's
    /// SROS 2 keystore: unauthenticated while the governance requires
    /// authentication (Medium), or a certificate subject no grant names
    /// (High).
    pub const UNTRUSTED_SECURITY_IDENTITY: &str = "robot.ros2.untrusted_security_identity";
}

/// Largest XML file read.
pub const MAX_XML_BYTES: u64 = 1024 * 1024;
/// Grants kept (over all permissions files).
pub const MAX_GRANTS: usize = 1024;
/// Topic expressions kept per publish / subscribe list of a rule.
pub const MAX_TOPICS_PER_RULE: usize = 1024;
/// Permissions files read from one keystore.
pub const MAX_PERMISSION_FILES: usize = 1024;
/// Directory depth searched for `permissions.xml`.
pub const MAX_DEPTH: usize = 16;

/// What the governance rule for the robot's domain protects (all rules
/// combined, most protective, when none covers the domain).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Governance {
    pub allow_unauthenticated_participants: bool,
    /// `discovery_protection_kind` other than NONE.
    pub discovery_protected: bool,
    /// Any topic rule with `enable_discovery_protection` true or a
    /// `metadata_protection_kind` other than NONE: SEDP of those topics
    /// is protected.
    pub topic_discovery_protected: bool,
    /// Any topic rule with `data_protection_kind` other than NONE.
    pub data_protected: bool,
    /// `rtps_protection_kind` other than NONE: whole RTPS messages are
    /// protected (SRTPS), even SPDP after authentication.
    pub rtps_protected: bool,
}

/// One topic rule (allow or deny) of a grant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rule {
    pub allow: bool,
    pub publish: Vec<String>,
    pub subscribe: Vec<String>,
}

/// One `grant` of a permissions file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grant {
    /// The grant's `name` attribute (sros2: the enclave path).
    pub name: String,
    /// `subject_name`, normalised ([`normalize_subject`]).
    pub subject: String,
    pub rules: Vec<Rule>,
    /// `default` is ALLOW.
    pub default_allow: bool,
}

impl Grant {
    /// Whether this grant lets its subject publish DDS topic `topic` (the
    /// wire name, e.g. `rt/cmd_vel`): the first matching rule decides, then
    /// the default (DDS-Security §9.4.1.3).
    pub fn may_publish(&self, topic: &str) -> bool {
        for r in &self.rules {
            if r.publish.iter().any(|p| glob(p, topic)) {
                return r.allow;
            }
        }
        self.default_allow
    }
}

/// The parsed keystore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sros2Policy {
    pub governance: Option<Governance>,
    pub grants: Vec<Grant>,
    /// Non-fatal problems met while reading (skipped files, caps hit).
    pub warnings: Vec<String>,
}

impl Sros2Policy {
    /// Read `governance.xml` and every `permissions.xml` under `enclaves`
    /// (an SROS 2 keystore's `enclaves/` directory), with the governance
    /// rule that applies to `domain_id` ([`parse_governance`]). Errors: the
    /// directory cannot be read, `governance.xml` is unreadable or
    /// malformed, or no grant was found.
    pub fn load(enclaves: &Path, domain_id: u32) -> Result<Self, String> {
        let gov_path = enclaves.join("governance.xml");
        let gov = read_xml(&gov_path)?;
        let (governance, gov_warning) = parse_governance(&gov, domain_id)?;
        let mut p = Self {
            governance: Some(governance),
            warnings: gov_warning.into_iter().collect(),
            ..Self::default()
        };
        let mut files = Vec::new();
        find_permissions(enclaves, 0, &mut files, &mut p.warnings);
        files.sort();
        for f in files {
            match read_xml(&f).and_then(|t| parse_permissions(&t)) {
                Ok(grants) => {
                    for g in grants {
                        if p.grants.len() >= MAX_GRANTS {
                            p.warnings
                                .push(format!("more than {MAX_GRANTS} grants: the rest ignored"));
                            break;
                        }
                        p.grants.push(g);
                    }
                }
                Err(e) => p.warnings.push(e),
            }
        }
        if p.grants.is_empty() {
            return Err(format!(
                "{}: no permissions.xml with a grant found",
                sanitize(&enclaves.display().to_string())
            ));
        }
        Ok(p)
    }

    /// The grant for a (normalised or raw) certificate subject.
    pub fn grant_for(&self, subject: &str) -> Option<&Grant> {
        let s = normalize_subject(subject);
        self.grants.iter().find(|g| g.subject == s)
    }

    /// Judge one SPDP announcement (see the module docs).
    pub fn judge_spdp(&self, spdp: &SpdpInfo, src_ip: &str) -> Option<Deviation> {
        let sec = &spdp.security;
        let guid = robodr_rtps::hex12(&spdp.guid_prefix);
        // Any claimed subject no grant names: High, whatever the token
        // class (a subject is never less alarming for a malformed token).
        if let Some(subject) = sec.cert_subject.as_deref() {
            if self.grant_for(subject).is_none() {
                return Some(Deviation::new(
                    rules::UNTRUSTED_SECURITY_IDENTITY,
                    Severity::High,
                    format!(
                        "participant {guid} from {src_ip} claims certificate subject {:?} (CA \
                         {:?}), which no grant of the robot's SROS 2 keystore names: a \
                         participant from another keystore or CA",
                        sanitize(subject),
                        sanitize(sec.ca_subject.as_deref().unwrap_or("?"))
                    ),
                ));
            }
        }
        // A complete identity token (PKI-DH class and a subject) whose
        // subject is granted: nothing.
        if sec.pki_identity_subject().is_some() {
            return None;
        }
        // Anything else cannot authenticate: no security parameter at all,
        // or only part of one (security info, permissions token, an
        // identity token without subject or of another class), which any
        // sender can add to its SPDP.
        let gov = self.governance.as_ref()?;
        if gov.allow_unauthenticated_participants {
            return None;
        }
        let what = if sec.is_secured() {
            "announces DDS-Security parameters but no complete identity token (class \
             DDS:Auth:PKI-DH with a certificate subject)"
        } else {
            "announces no DDS-Security identity"
        };
        Some(Deviation::new(
            rules::UNTRUSTED_SECURITY_IDENTITY,
            Severity::Medium,
            format!(
                "participant {guid} from {src_ip} {what} on a domain whose SROS 2 governance \
                 requires authentication: the secured robot ignores it, but an \
                 unauthenticated DDS participant is on the robot's network"
            ),
        ))
    }

    /// One-line statements of what the sensor can and cannot see under this
    /// governance, for check-config and the learn report.
    pub fn visibility(&self) -> Vec<String> {
        let mut v = Vec::new();
        let Some(g) = &self.governance else {
            return v;
        };
        if g.discovery_protected || g.topic_discovery_protected {
            v.push(
                "SROS 2 governance protects discovery (SEDP): the sensor sees participants and \
                 their claimed certificate subjects, but no topic, endpoint or motion sample; \
                 writer and motion-envelope checks have nothing to inspect (topic access is \
                 enforced by the DDS stack's permissions)"
                    .into(),
            );
        } else if g.data_protected {
            v.push(
                "SROS 2 governance protects user data: topics and endpoints are inspected, \
                 motion samples are not decoded"
                    .into(),
            );
        }
        if g.rtps_protected {
            v.push(
                "SROS 2 governance protects whole RTPS messages (rtps_protection_kind): only the \
                 unprotected announcements before authentication are inspected"
                    .into(),
            );
        }
        if !g.allow_unauthenticated_participants {
            v.push(
                "unauthenticated participants are refused by the robot and reported by the \
                 sensor (robot.ros2.untrusted_security_identity)"
                    .into(),
            );
        }
        v
    }

    /// Per grant: which motion-relevant topics (`rt/...`) it may publish,
    /// as profile input for the operator (wire names, wildcard grants as
    /// written). Grants are listed by name.
    pub fn publish_summary(&self) -> Vec<String> {
        self.grants
            .iter()
            .map(|g| {
                let allowed: BTreeSet<&str> = g
                    .rules
                    .iter()
                    .filter(|r| r.allow)
                    .flat_map(|r| r.publish.iter().map(String::as_str))
                    .filter(|t| t.starts_with("rt/"))
                    .collect();
                format!(
                    "grant {} ({}) may publish {}",
                    sanitize(&g.name),
                    sanitize(&g.subject),
                    if allowed.is_empty() {
                        "no rt/ topic".to_string()
                    } else {
                        sanitize(&allowed.into_iter().collect::<Vec<_>>().join(", "))
                    }
                )
            })
            .collect()
    }
}

fn find_permissions(dir: &Path, depth: usize, out: &mut Vec<PathBuf>, warnings: &mut Vec<String>) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.filter_map(Result::ok) {
        if out.len() >= MAX_PERMISSION_FILES {
            warnings.push(format!(
                "more than {MAX_PERMISSION_FILES} permissions files: the rest ignored"
            ));
            return;
        }
        let Ok(ft) = e.file_type() else { continue };
        let path = e.path();
        if ft.is_dir() {
            find_permissions(&path, depth + 1, out, warnings);
        } else if ft.is_file() && e.file_name() == "permissions.xml" {
            out.push(path);
        }
    }
}

fn read_xml(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let shown = sanitize(&path.display().to_string());
    let f = std::fs::File::open(path).map_err(|e| format!("{shown}: {e}"))?;
    let mut buf = Vec::new();
    f.take(MAX_XML_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{shown}: {e}"))?;
    if buf.len() as u64 > MAX_XML_BYTES {
        return Err(format!("{shown}: larger than {MAX_XML_BYTES} bytes"));
    }
    String::from_utf8(buf).map_err(|_| format!("{shown}: not UTF-8"))
}

/// Remove `<!-- -->` comments, `<? ?>` declarations and CDATA markers.
fn strip_comments(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    loop {
        let next = [rest.find("<!--"), rest.find("<?")]
            .into_iter()
            .flatten()
            .min();
        let Some(i) = next else {
            out.push_str(rest);
            return out;
        };
        out.push_str(rest.get(..i).unwrap_or(""));
        let tail = rest.get(i..).unwrap_or("");
        let end = if tail.starts_with("<!--") {
            "-->"
        } else {
            "?>"
        };
        match tail.find(end) {
            Some(j) => rest = tail.get(j + end.len()..).unwrap_or(""),
            None => return out,
        }
    }
}

/// Inner text of every `<tag ...>...</tag>` (or `<tag/>`, as "") in `xml`,
/// in order. Same-name elements are not nested in the files read here.
fn elements<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = rest.get(i + open.len()..).unwrap_or("");
        // The name must end here (`<topics>` is not `<topic`).
        match after.chars().next() {
            Some('>') | Some(' ') | Some('\t') | Some('\n') | Some('\r') | Some('/') => {}
            _ => {
                rest = after;
                continue;
            }
        }
        let Some(gt) = after.find('>') else { break };
        let head = after.get(..gt).unwrap_or("");
        let body_start = after.get(gt + 1..).unwrap_or("");
        if head.ends_with('/') {
            out.push("");
            rest = body_start;
            continue;
        }
        let Some(end) = body_start.find(&close) else {
            break;
        };
        out.push(body_start.get(..end).unwrap_or(""));
        rest = body_start.get(end + close.len()..).unwrap_or("");
    }
    out
}

/// The value of attribute `name` in the start tag of the first `tag`.
fn attribute(xml: &str, tag: &str, name: &str) -> Option<String> {
    let open = format!("<{tag}");
    let i = xml.find(&open)?;
    let after = xml.get(i + open.len()..)?;
    let head = after.get(..after.find('>')?)?;
    let key = format!("{name}=");
    let j = head.find(&key)?;
    let v = head.get(j + key.len()..)?;
    let q = v.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let v = v.get(1..)?;
    Some(unescape(v.get(..v.find(q)?)?))
}

fn unescape(s: &str) -> String {
    s.trim()
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn text(xml: &str, tag: &str) -> Option<String> {
    elements(xml, tag).first().map(|t| unescape(t))
}

fn not_none(kind: Option<String>) -> bool {
    kind.is_some_and(|k| !k.eq_ignore_ascii_case("NONE"))
}

fn is_true(v: Option<String>) -> bool {
    v.is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1")
}

/// Whether a `domain_rule`'s `<domains>` covers `domain_id` (`<id>`
/// entries and `<id_range>` with `<min>` and an optional `<max>`;
/// DDS-Security §9.4.1.2.3). Unparsable entries cover nothing.
fn rule_covers(rule: &str, domain_id: u32) -> bool {
    let num = |s: &str, tag: &str| text(s, tag).and_then(|v| v.parse::<u32>().ok());
    elements(rule, "domains").into_iter().any(|d| {
        elements(d, "id")
            .into_iter()
            .any(|id| unescape(id).parse::<u32>().ok() == Some(domain_id))
            || elements(d, "id_range").into_iter().any(|r| {
                let Some(min) = num(r, "min") else {
                    return false;
                };
                let max = if elements(r, "max").is_empty() {
                    Some(u32::MAX)
                } else {
                    num(r, "max")
                };
                max.is_some_and(|max| (min..=max).contains(&domain_id))
            })
    })
}

/// Parse `governance.xml` for the robot's `domain_id`: the first
/// `domain_rule` whose `<domains>` covers it applies (DDS-Security
/// §9.4.1.2.4). If none covers it (the robot's secured participants could
/// not be created on that domain with this governance: a wrong keystore or
/// `domain_id`), every rule is combined, most protective first
/// (`allow_unauthenticated_participants` only if all rules allow it), and
/// the second value says so.
pub fn parse_governance(xml: &str, domain_id: u32) -> Result<(Governance, Option<String>), String> {
    let xml = strip_comments(xml);
    let all = elements(&xml, "domain_rule");
    if all.is_empty() {
        return Err("governance.xml: no domain_rule".into());
    }
    let (rules, warning) = match all.iter().find(|r| rule_covers(r, domain_id)) {
        Some(r) => (vec![*r], None),
        None => (
            all,
            Some(format!(
                "governance.xml: no domain_rule covers domain_id {domain_id} (the robot's \
                 secured participants could not join it with this governance; wrong keystore \
                 or domain_id?): judging by all rules combined, most protective"
            )),
        ),
    };
    let g = combine_rules(&rules);
    Ok((g, warning))
}

fn combine_rules(rules: &[&str]) -> Governance {
    // Most protective over the rules; allow_unauthenticated only if every
    // rule allows it.
    let mut g = Governance {
        allow_unauthenticated_participants: true,
        ..Governance::default()
    };
    for r in rules.iter().copied() {
        g.allow_unauthenticated_participants &=
            is_true(text(r, "allow_unauthenticated_participants"));
        g.discovery_protected |= not_none(text(r, "discovery_protection_kind"));
        g.rtps_protected |= not_none(text(r, "rtps_protection_kind"));
        for t in elements(r, "topic_rule") {
            g.topic_discovery_protected |= is_true(text(t, "enable_discovery_protection"))
                || not_none(text(t, "metadata_protection_kind"));
            g.data_protected |= not_none(text(t, "data_protection_kind"));
        }
    }
    g
}

fn topics(rule: &str, list: &str) -> Vec<String> {
    elements(rule, list)
        .into_iter()
        .flat_map(|l| elements(l, "topic"))
        .take(MAX_TOPICS_PER_RULE)
        .map(unescape)
        .collect()
}

/// Parse a `permissions.xml`.
pub fn parse_permissions(xml: &str) -> Result<Vec<Grant>, String> {
    let xml = strip_comments(xml);
    let mut out = Vec::new();
    for (i, g) in elements(&xml, "grant").into_iter().enumerate() {
        let Some(subject) = text(g, "subject_name") else {
            return Err(format!("permissions.xml: grant {i} has no subject_name"));
        };
        // `name` is an attribute of the grant start tag: find it in the
        // whole document at the i-th grant.
        let name = nth_attribute(&xml, "grant", "name", i).unwrap_or_default();
        // Rules apply in document order (DDS-Security 9.4.1.3).
        let base = g.as_ptr() as usize;
        let mut found: Vec<(usize, bool, &str)> = Vec::new();
        for (tag, allow) in [("allow_rule", true), ("deny_rule", false)] {
            for r in elements(g, tag) {
                found.push(((r.as_ptr() as usize).saturating_sub(base), allow, r));
            }
        }
        found.sort_by_key(|(at, _, _)| *at);
        let rules = found
            .into_iter()
            .map(|(_, allow, r)| Rule {
                allow,
                publish: topics(r, "publish"),
                subscribe: topics(r, "subscribe"),
            })
            .collect();
        out.push(Grant {
            name,
            subject: normalize_subject(&subject),
            rules,
            default_allow: text(g, "default").is_some_and(|d| d.eq_ignore_ascii_case("ALLOW")),
        });
    }
    Ok(out)
}

fn nth_attribute(xml: &str, tag: &str, name: &str, n: usize) -> Option<String> {
    let open = format!("<{tag}");
    let mut rest = xml;
    let mut seen = 0;
    while let Some(i) = rest.find(&open) {
        let at = rest.get(i..)?;
        let next = at.get(open.len()..)?.chars().next();
        if matches!(next, Some(' ' | '\t' | '\n' | '\r' | '>')) {
            if seen == n {
                return attribute(at, tag, name);
            }
            seen += 1;
        }
        rest = at.get(open.len()..)?;
    }
    None
}

/// Canonical form of a certificate subject, so the permissions file's
/// `subject_name` (RFC 4514 style, `CN=/lab/teleop_twist`) and the SPDP
/// identity token's `dds.cert.sn` (OpenSSL one-line style as Fast DDS 2.6
/// sends it, `/CN=\/lab\/teleop_twist`) compare equal: attributes split on
/// the unescaped separator (`/` for the one-line form, `,` otherwise),
/// `\x` unescaped, attribute types upper-cased and trimmed, sorted, joined
/// with `,`.
pub fn normalize_subject(s: &str) -> String {
    let s = s.trim();
    let (sep, body) = match s.strip_prefix('/') {
        Some(rest) => ('/', rest),
        None => (',', s),
    };
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                cur.push(n);
            }
        } else if c == sep {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    parts.push(cur);
    let mut attrs: Vec<String> = parts
        .into_iter()
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some(format!("{}={}", k.trim().to_ascii_uppercase(), v.trim()))
        })
        .collect();
    attrs.sort();
    attrs.join(",")
}

/// DDS-Security topic expression match (fnmatch subset: `*`, `?`;
/// iterative, no recursion).
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some(c) if *c == '?' || Some(c) == t.get(ti) => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    while p.get(pi) == Some(&'*') {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOV: &str = include_str!("../../../fixtures/captures/ros2-humble/sros2/governance.xml");
    const PERM: &str = include_str!(
        "../../../fixtures/captures/ros2-humble/sros2/lab/teleop_twist/permissions.xml"
    );

    #[test]
    fn sros2_default_governance() {
        let (g, w) = parse_governance(GOV, 0).unwrap();
        assert_eq!(w, None);
        assert_eq!(
            g,
            Governance {
                allow_unauthenticated_participants: false,
                discovery_protected: true,
                topic_discovery_protected: true,
                data_protected: true,
                rtps_protected: true,
            }
        );
        assert!(parse_governance("<dds/>", 0).is_err());
    }

    /// Review finding (WP7, low): the `<domains>` of each domain_rule were
    /// ignored and every rule combined, so a rule for another domain
    /// changed the verdict on the robot's domain.
    #[test]
    fn governance_rule_is_chosen_by_domain() {
        let xml = r#"<dds><domain_access_rules>
            <domain_rule>
              <domains><id>7</id><id_range><min>20</min><max>29</max></id_range></domains>
              <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
              <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
              <rtps_protection_kind>SIGN</rtps_protection_kind>
              <topic_access_rules><topic_rule><topic_expression>*</topic_expression>
                <data_protection_kind>ENCRYPT</data_protection_kind></topic_rule></topic_access_rules>
            </domain_rule>
            <domain_rule>
              <domains><id_range><min>0</min><max>6</max></id_range></domains>
              <allow_unauthenticated_participants>true</allow_unauthenticated_participants>
              <discovery_protection_kind>NONE</discovery_protection_kind>
              <rtps_protection_kind>NONE</rtps_protection_kind>
              <topic_access_rules><topic_rule><topic_expression>*</topic_expression>
                <data_protection_kind>NONE</data_protection_kind></topic_rule></topic_access_rules>
            </domain_rule>
            <domain_rule>
              <domains><id_range><min>100</min></id_range></domains>
              <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
            </domain_rule>
            <domain_rule>
              <domains><id>0</id></domains>
              <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
            </domain_rule>
          </domain_access_rules></dds>"#;
        // Domain 0: the second rule (the first that covers it) applies, the
        // later one for id 0 does not.
        let (g, w) = parse_governance(xml, 0).unwrap();
        assert_eq!(w, None);
        assert_eq!(
            g,
            Governance {
                allow_unauthenticated_participants: true,
                ..Governance::default()
            }
        );
        for d in [7, 20, 29] {
            let (g, w) = parse_governance(xml, d).unwrap();
            assert_eq!(w, None);
            assert!(!g.allow_unauthenticated_participants && g.discovery_protected);
            assert!(g.rtps_protected && g.data_protected);
        }
        // Open-ended range.
        let (g, _) = parse_governance(xml, 232).unwrap();
        assert!(!g.allow_unauthenticated_participants && !g.discovery_protected);
        // No rule for domain 50: all rules combined, and said so.
        let (g, w) = parse_governance(xml, 50).unwrap();
        assert!(w.is_some_and(|w| w.contains("domain_id 50")));
        assert!(!g.allow_unauthenticated_participants && g.discovery_protected);
    }

    #[test]
    fn sros2_permissions_grant() {
        let g = parse_permissions(PERM).unwrap();
        assert_eq!(g.len(), 1);
        let g = &g[0];
        assert_eq!(g.name, "/lab/teleop_twist");
        assert_eq!(g.subject, "CN=/lab/teleop_twist");
        assert_eq!(g.rules.len(), 2);
        assert!(!g.default_allow);
        assert!(g.may_publish("rt/cmd_vel"));
        assert!(g.may_publish("ros_discovery_info"));
        assert!(!g.may_publish("some_raw_dds_topic"));
    }

    #[test]
    fn deny_rules_and_order() {
        let xml = r#"<dds><permissions><grant name="g">
            <subject_name>CN=x</subject_name>
            <deny_rule><publish><topics><topic>rt/cmd_vel</topic></topics></publish></deny_rule>
            <allow_rule><publish><topics><topic>rt/*</topic></topics></publish></allow_rule>
            <default>DENY</default></grant></permissions></dds>"#;
        let g = &parse_permissions(xml).unwrap()[0];
        // Document order: the deny of rt/cmd_vel comes first and wins.
        assert_eq!(g.rules.len(), 2);
        assert!(!g.rules[0].allow);
        assert!(!g.may_publish("rt/cmd_vel"));
        assert!(g.may_publish("rt/odom"));
    }

    #[test]
    fn subjects_compare_across_formats() {
        // dds.cert.sn as Fast DDS 2.6 announces it (real capture) vs the
        // permissions file's subject_name.
        assert_eq!(
            normalize_subject(r"/CN=\/lab\/teleop_twist"),
            normalize_subject("CN=/lab/teleop_twist")
        );
        assert_eq!(
            normalize_subject("/C=US/O=Acme/CN=robot"),
            normalize_subject("CN=robot, O=Acme, C=US")
        );
        assert_ne!(
            normalize_subject("CN=/lab/teleop_twist"),
            normalize_subject("CN=/lab/teleop")
        );
    }

    #[test]
    fn glob_matches_fnmatch_subset() {
        assert!(glob("rt/*", "rt/cmd_vel"));
        assert!(glob("rq/*Request", "rq/a/b/get_parametersRequest"));
        assert!(glob("rt/?md_vel", "rt/cmd_vel"));
        assert!(!glob("rt/*", "rq/x"));
        assert!(glob("*", ""));
        assert!(!glob("", "x"));
        // Pathological pattern: bounded work.
        let p = "*a".repeat(50);
        assert!(!glob(&p, &"a".repeat(40)));
    }

    #[test]
    fn hostile_xml_is_bounded() {
        for x in [
            "<grant",
            "<grant>",
            "<grant><subject_name>",
            "<!--",
            "<?x",
            "<dds><grant/>",
        ] {
            let _ = parse_permissions(x);
            let _ = parse_governance(x, 0);
        }
        let r = parse_permissions("<grant name='a'><default>ALLOW</default></grant>");
        assert!(r.is_err(), "a grant without subject is refused");
    }

    fn spdp_with(security: robodr_rtps::SpdpSecurity) -> SpdpInfo {
        SpdpInfo {
            guid_prefix: [0xaf; 12],
            attribution: robodr_rtps::Attribution::ParticipantGuid,
            source: [0xaf; 12],
            participant_entity: None,
            protocol_version: None,
            vendor_id: Some([0x01, 0x0f]),
            domain_id: None,
            domain_tag: None,
            entity_name: None,
            user_data: None,
            lease_duration: None,
            metatraffic_unicast: Vec::new(),
            metatraffic_multicast: Vec::new(),
            default_unicast: Vec::new(),
            default_multicast: Vec::new(),
            alternate_guid_prefixes: Vec::new(),
            from_fragments: false,
            security,
        }
    }

    fn fixture_policy() -> Sros2Policy {
        Sros2Policy {
            governance: Some(parse_governance(GOV, 0).unwrap().0),
            grants: parse_permissions(PERM).unwrap(),
            warnings: Vec::new(),
        }
    }

    /// Review finding (WP7, medium): any one DDS-Security parameter made an
    /// announcement "secured", and a secured announcement without a
    /// certificate subject produced no finding. An unauthenticated sender
    /// adding the 8-byte PID_PARTICIPANT_SECURITY_INFO (or an empty
    /// identity token) escaped the Medium finding.
    #[test]
    fn partial_security_claims_are_unauthenticated() {
        use robodr_rtps::SpdpSecurity;
        let p = fixture_policy();
        let partial = [
            SpdpSecurity {
                security_info: Some((0, 0)),
                ..SpdpSecurity::default()
            },
            SpdpSecurity {
                identity_class: Some("DDS:Auth:PKI-DH:1.0".into()),
                ..SpdpSecurity::default()
            },
            SpdpSecurity {
                permissions_ca_subject: Some("CN=sros2CA".into()),
                ..SpdpSecurity::default()
            },
            // A granted subject, but not in a PKI-DH identity token.
            SpdpSecurity {
                identity_class: Some("Vendor:Other:1.0".into()),
                cert_subject: Some("CN=/lab/teleop_twist".into()),
                ..SpdpSecurity::default()
            },
            SpdpSecurity::default(),
        ];
        for sec in partial {
            let d = p
                .judge_spdp(&spdp_with(sec.clone()), "10.0.0.66")
                .unwrap_or_else(|| panic!("no finding for {sec:?}"));
            assert_eq!(d.rule, rules::UNTRUSTED_SECURITY_IDENTITY);
            assert_eq!(d.severity, Severity::Medium, "{sec:?}");
        }
        // A complete, granted identity: nothing. An ungranted one: High.
        let ok = SpdpSecurity {
            identity_class: Some("DDS:Auth:PKI-DH:1.0".into()),
            cert_subject: Some(r"/CN=\/lab\/teleop_twist".into()),
            ..SpdpSecurity::default()
        };
        assert!(p.judge_spdp(&spdp_with(ok.clone()), "10.0.0.11").is_none());
        let foreign = SpdpSecurity {
            cert_subject: Some("CN=/other".into()),
            ..ok
        };
        let d = p.judge_spdp(&spdp_with(foreign), "10.0.0.66").unwrap();
        assert_eq!(d.severity, Severity::High);
        // Where the governance allows unauthenticated participants, a
        // partial claim is not reported.
        let mut open = fixture_policy();
        if let Some(g) = open.governance.as_mut() {
            g.allow_unauthenticated_participants = true;
        }
        let only_info = SpdpSecurity {
            security_info: Some((0, 0)),
            ..SpdpSecurity::default()
        };
        assert!(open
            .judge_spdp(&spdp_with(only_info), "10.0.0.66")
            .is_none());
    }

    #[test]
    fn load_keystore_copy() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/captures/ros2-humble/sros2");
        let p = Sros2Policy::load(&d, 0).unwrap();
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        let names: Vec<&str> = p.grants.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, ["/lab/base_controller", "/lab/teleop_twist"]);
        assert!(p.grant_for(r"/CN=\/lab\/base_controller").is_some());
        assert!(p.visibility()[0].contains("no topic"));
        assert!(p.publish_summary()[1].contains("rt/*"));
        assert!(Sros2Policy::load(Path::new("/nonexistent/robodr"), 0).is_err());
    }
}
