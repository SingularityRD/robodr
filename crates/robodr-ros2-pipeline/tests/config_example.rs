//! `config/robodr.toml.example` stays in sync with [`Config`]: every key of
//! the `[module.robodr-sensor-ros2]` section (and its `capture` and
//! `binding` sub-tables, incl. `binding.participant_ips`, and
//! `profile_trust`), including the
//! commented-out examples, is a known field and the result deserialises and
//! validates.
//!
//! No TOML parser is available offline, so this uses a minimal line parser
//! for the flat `key = value` subset the example uses (strings, integers,
//! booleans, arrays of strings/integers), converted to JSON for serde.

use std::path::Path;

use robodr_ros2_pipeline::{CaptureInput, Config};
use serde_json::{Map, Value};

const TOP_KEYS: &[&str] = &[
    "profile_path",
    "domain_id",
    "spdp_port",
    "spdp_group",
    "interface",
    "listen_spdp",
    "dedup_capacity",
    "report_anomalies",
    "report_fragmentation",
    "max_findings_per_datagram",
    "rate_limit_burst",
    "rate_limit_interval_ms",
];
const BINDING_KEYS: &[&str] = &["enabled", "hold_ms", "max_participants", "discovery_server"];
const TRUST_KEYS: &[&str] = &[
    "trusted_keys",
    "state_file",
    "allow_rollback",
    "expect_platform",
    "expect_unit_id",
];
const CAPTURE_KEYS: &[&str] = &[
    "enabled",
    "interfaces",
    "pcap_replay",
    "domain_ids",
    "read_timeout_ms",
    "queue_capacity",
];

fn toml_value(raw: &str) -> Option<Value> {
    let raw = raw.trim();
    if let Some(s) = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        return (!s.contains('"')).then(|| Value::String(s.to_string()));
    }
    if let Some(inner) = raw.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return inner
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(toml_value)
            .collect::<Option<Vec<_>>>()
            .map(Value::Array);
    }
    match raw {
        "true" => Some(Value::Bool(true)),
        "false" => Some(Value::Bool(false)),
        n => n.parse::<i64>().ok().map(Value::from),
    }
}

#[derive(Default)]
struct Sections {
    top: Map<String, Value>,
    cap: Map<String, Value>,
    binding: Map<String, Value>,
    pins: Map<String, Value>,
    trust: Map<String, Value>,
}

/// (sections, include commented-out `# key = value` lines) -> JSON objects.
fn sections(text: &str, uncomment: bool) -> Sections {
    let mut out = Sections::default();
    let mut current: Option<&str> = None;
    for line in text.lines() {
        let line = line.trim();
        // A commented-out section header (`# [robodr-agent.firewall]`) also
        // ends the current section when uncommenting.
        let header = match line.strip_prefix('#') {
            Some(c) if uncomment && c.trim_start().starts_with('[') => c.trim_start(),
            _ => line,
        };
        if header.starts_with('[') {
            let line = header;
            current = Some(match line {
                "[module.robodr-sensor-ros2]" => "top",
                "[module.robodr-sensor-ros2.capture]" => "capture",
                "[module.robodr-sensor-ros2.binding]" => "binding",
                "[module.robodr-sensor-ros2.binding.participant_ips]" => "pins",
                "[module.robodr-sensor-ros2.profile_trust]" => "trust",
                _ => "other",
            });
            continue;
        }
        let (body, commented) = match line.strip_prefix('#') {
            Some(c) if uncomment => (c.trim(), true),
            Some(_) => continue,
            None => (line, false),
        };
        let Some((k, v)) = body.split_once(" = ") else {
            continue;
        };
        let k = k.trim();
        // Quoted keys (GUID prefixes in participant_ips).
        let k = k
            .strip_prefix('"')
            .and_then(|x| x.strip_suffix('"'))
            .unwrap_or(k);
        if k.contains(' ') || k.is_empty() {
            continue; // prose in a comment
        }
        let v = match toml_value(v.split(" #").next().unwrap()) {
            Some(v) => v,
            None if commented => continue, // prose that happens to contain " = "
            None => panic!("unparseable value in {line:?}"),
        };
        match current {
            Some("top") if k != "enabled" => {
                out.top.insert(k.into(), v);
            }
            Some("capture") => {
                out.cap.insert(k.into(), v);
            }
            Some("binding") => {
                out.binding.insert(k.into(), v);
            }
            Some("pins") => {
                out.pins.insert(k.into(), v);
            }
            Some("trust") => {
                out.trust.insert(k.into(), v);
            }
            _ => {}
        }
    }
    out
}

fn example() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/robodr.toml.example");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn example_keys_are_known_and_parse() {
    let text = example();
    for uncomment in [false, true] {
        let Sections {
            top,
            cap,
            mut binding,
            pins,
            trust,
        } = sections(&text, uncomment);
        for k in trust.keys() {
            assert!(
                TRUST_KEYS.contains(&k.as_str()),
                "unknown profile_trust key {k}"
            );
        }
        assert!(trust.contains_key("trusted_keys") && trust.contains_key("state_file"));
        if uncomment {
            assert_eq!(trust.len(), TRUST_KEYS.len(), "{trust:?}");
        }
        assert!(top.len() >= 11, "{top:?}");
        for k in [
            "max_findings_per_datagram",
            "rate_limit_burst",
            "rate_limit_interval_ms",
        ] {
            assert!(top.contains_key(k), "{k} missing from the example");
        }
        for k in binding.keys() {
            assert!(
                BINDING_KEYS.contains(&k.as_str()),
                "unknown binding key {k}"
            );
        }
        for k in ["enabled", "hold_ms", "max_participants"] {
            assert!(
                binding.contains_key(k),
                "binding.{k} missing from the example"
            );
        }
        for k in top.keys() {
            assert!(TOP_KEYS.contains(&k.as_str()), "unknown key {k}");
        }
        for k in cap.keys() {
            assert!(
                CAPTURE_KEYS.contains(&k.as_str()),
                "unknown capture key {k}"
            );
        }
        if uncomment {
            for k in ["pcap_replay", "interfaces", "domain_ids"] {
                assert!(cap.contains_key(k), "commented example for {k} not seen");
            }
            assert!(top.contains_key("spdp_port"));
            assert!(binding.contains_key("discovery_server"));
            assert_eq!(pins.len(), 1, "commented participant_ips example not seen");
        } else {
            assert!(pins.is_empty());
        }
        binding.insert("participant_ips".into(), Value::Object(pins));
        let mut obj = top.clone();
        obj.insert("capture".into(), Value::Object(cap));
        obj.insert("binding".into(), Value::Object(binding));
        obj.insert("profile_trust".into(), Value::Object(trust));
        let cfg: Config = serde_json::from_value(Value::Object(obj)).unwrap();
        let (settings, _warnings) = cfg.validate_with(|| Some("eth0".into())).unwrap();
        if uncomment {
            // With the lab line uncommented, replay takes over.
            assert!(matches!(
                settings.capture.as_ref().map(|c| &c.input),
                None | Some(CaptureInput::Replay { .. })
            ));
        } else {
            assert!(settings.capture.is_none(), "capture is off in the example");
            assert_eq!(settings.spdp.unwrap().port, 7400);
        }
    }
}
