//! Structural check of `robodr-rules` payloads before they are activated:
//! the part of `scripts/validate_rules.py` that decides whether Pulsar's
//! rules engine **loads** a file (steps 1–3 of its docstring), stricter
//! where the script only warns:
//!
//! * the file is UTF-8 TOML (at most [`MAX_RULE_FILE_BYTES`]) whose only
//!   top-level key is `rules`, an array of 1..=[`MAX_RULES`] tables;
//! * each rule has exactly the six string keys of Pulsar's `UserRule`
//!   (`name`, `type`, `condition`, `category`, `severity`,
//!   `description`), no other key;
//! * `category` is a Pulsar `Category`, `severity` a Pulsar `Severity`,
//!   `type` a `PayloadDiscriminant`;
//! * names are unique across the package **and** across every other
//!   installed rules package (`install`, the active versions below
//!   `rules_active`).
//!
//! The condition DSL and its type checking (steps 4–5) are not
//! re-implemented here: the release side runs `validate_rules.py` before
//! signing, and a unit can run it (or any validator) on the staged version
//! through `install.rules_validator`. Pulsar itself refuses a rule that
//! does not compile when it reloads, which fails the health gate (the
//! reload command) and rolls the rules back.

use std::collections::BTreeSet;

/// Largest rules file checked.
pub const MAX_RULE_FILE_BYTES: usize = 1024 * 1024;
/// Most rules in one file.
pub const MAX_RULES: usize = 4096;
/// Longest condition.
pub const MAX_CONDITION_LEN: usize = 16 * 1024;

/// `UserRule`'s keys (rules-engine/src/engine.rs).
pub const REQUIRED_KEYS: [&str; 6] = [
    "name",
    "type",
    "condition",
    "category",
    "severity",
    "description",
];

/// Pulsar `Category` (serde snake_case).
pub const CATEGORIES: [&str; 14] = [
    "command_and_control",
    "credential_access",
    "defense_evasion",
    "discovery",
    "execution",
    "exfiltration",
    "generic",
    "impact",
    "initial_access",
    "lateral_movement",
    "persistence",
    "privilege_escalation",
    "reconnaissance",
    "resource_development",
];

/// Pulsar `Severity` (serde lowercase).
pub const SEVERITIES: [&str; 4] = ["low", "medium", "high", "critical"];

/// Pulsar `PayloadDiscriminant` names (pulsar-core/src/event.rs).
pub const PAYLOAD_TYPES: [&str; 24] = [
    "FileCreated",
    "FileDeleted",
    "DirCreated",
    "DirDeleted",
    "FileOpened",
    "FileLink",
    "FileRename",
    "ElfOpened",
    "Fork",
    "Exec",
    "Exit",
    "ChangeParent",
    "CredentialsChange",
    "Bind",
    "Listen",
    "Connect",
    "Accept",
    "Close",
    "Receive",
    "DnsQuery",
    "DnsResponse",
    "Send",
    "Custom",
    "Empty",
];

/// Check one rules file; `names` collects rule names across files.
pub fn check_file(
    label: &str,
    bytes: &[u8],
    names: &mut BTreeSet<String>,
) -> Result<usize, String> {
    if bytes.len() > MAX_RULE_FILE_BYTES {
        return Err(format!("{label}: larger than {MAX_RULE_FILE_BYTES} bytes"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{label}: not UTF-8"))?;
    let doc: toml::Table = text.parse().map_err(|e: toml::de::Error| {
        format!("{label}: TOML: {}", robodr_pkg::common::trunc(e.message()))
    })?;
    if doc.len() != 1 || !doc.contains_key("rules") {
        return Err(format!("{label}: the only top-level key must be `rules`"));
    }
    let Some(rules) = doc.get("rules").and_then(|r| r.as_array()) else {
        return Err(format!("{label}: `rules` must be an array of tables"));
    };
    if rules.is_empty() || rules.len() > MAX_RULES {
        return Err(format!("{label}: 1..={MAX_RULES} rules"));
    }
    for (i, r) in rules.iter().enumerate() {
        let at = format!("{label}: rule #{}", i + 1);
        let Some(t) = r.as_table() else {
            return Err(format!("{at}: not a table"));
        };
        if t.len() != REQUIRED_KEYS.len() || !REQUIRED_KEYS.iter().all(|k| t.contains_key(*k)) {
            return Err(format!(
                "{at}: exactly the keys {} (strings)",
                REQUIRED_KEYS.join(", ")
            ));
        }
        let s = |k: &str| t.get(k).and_then(|v| v.as_str());
        let mut vals = Vec::new();
        for k in REQUIRED_KEYS {
            match s(k) {
                Some(v) if !v.trim().is_empty() => vals.push(v),
                _ => return Err(format!("{at}: `{k}` must be a non-empty string")),
            }
        }
        let (name, ty, cond, cat, sev) = (vals[0], vals[1], vals[2], vals[3], vals[4]);
        if name.len() > 256 {
            return Err(format!("{at}: name too long"));
        }
        if !PAYLOAD_TYPES.contains(&ty) {
            return Err(format!(
                "{at}: type {:?} is not a Pulsar payload type",
                robodr_pkg::common::trunc(ty)
            ));
        }
        if !CATEGORIES.contains(&cat) {
            return Err(format!(
                "{at}: category {:?} is not a Pulsar category",
                robodr_pkg::common::trunc(cat)
            ));
        }
        if !SEVERITIES.contains(&sev) {
            return Err(format!(
                "{at}: severity {:?} is not a Pulsar severity",
                robodr_pkg::common::trunc(sev)
            ));
        }
        if cond.len() > MAX_CONDITION_LEN {
            return Err(format!("{at}: condition too long"));
        }
        if !names.insert(name.to_string()) {
            return Err(format!(
                "{at}: rule name {:?} is used twice",
                robodr_pkg::common::trunc(name)
            ));
        }
    }
    Ok(rules.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const GOOD: &str = r#"[[rules]]
name = "robodr-test-shell"
type = "Exec"
condition = 'payload.filename ENDS_WITH "/sh"'
category = "execution"
severity = "low"
description = "test rule"
"#;

    #[test]
    fn good_rules_pass_and_bad_ones_do_not() {
        let mut names = BTreeSet::new();
        assert_eq!(
            check_file("a.toml", GOOD.as_bytes(), &mut names).unwrap(),
            1
        );
        // The same name in a second file of the package.
        assert!(check_file("b.toml", GOOD.as_bytes(), &mut names).is_err());
        for (what, bad) in [
            ("bad toml", "[[rules]\n".to_string()),
            ("extra top key", format!("x = 1\n{GOOD}")),
            (
                "extra rule key",
                GOOD.replace("description", "extra = 1\ndescription"),
            ),
            ("missing key", GOOD.replace("severity = \"low\"\n", "")),
            ("bad type", GOOD.replace("\"Exec\"", "\"Shell\"")),
            ("bad category", GOOD.replace("\"execution\"", "\"fun\"")),
            ("bad severity", GOOD.replace("\"low\"", "\"info\"")),
            ("non-string", GOOD.replace("\"low\"", "3")),
            (
                "empty condition",
                GOOD.replace("'payload.filename ENDS_WITH \"/sh\"'", "''"),
            ),
            ("no rules", "rules = []\n".to_string()),
            ("rules not array", "rules = 1\n".to_string()),
        ] {
            let mut n = BTreeSet::new();
            assert!(check_file("x", bad.as_bytes(), &mut n).is_err(), "{what}");
        }
        assert!(check_file("x", b"\xff", &mut BTreeSet::new()).is_err());
        let deep = format!("rules = {}{}", "[".repeat(5000), "]".repeat(5000));
        assert!(check_file("x", deep.as_bytes(), &mut BTreeSet::new()).is_err());
    }
}
