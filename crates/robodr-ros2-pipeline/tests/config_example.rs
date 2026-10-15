//! `config/robodr.toml.example` stays in sync with [`Config`]: every key of
//! the `[module.robodr-sensor-ros2]` section (and its `capture` sub-table),
//! including the commented-out examples, is a known field and the result
//! deserialises and validates.
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

/// (section, include commented-out `# key = value` lines) -> JSON object.
fn sections(text: &str, uncomment: bool) -> (Map<String, Value>, Map<String, Value>) {
    let (mut top, mut cap) = (Map::new(), Map::new());
    let mut current: Option<&str> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            current = Some(match line {
                "[module.robodr-sensor-ros2]" => "top",
                "[module.robodr-sensor-ros2.capture]" => "capture",
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
                top.insert(k.into(), v);
            }
            Some("capture") => {
                cap.insert(k.into(), v);
            }
            _ => {}
        }
    }
    (top, cap)
}

fn example() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/robodr.toml.example");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn example_keys_are_known_and_parse() {
    let text = example();
    for uncomment in [false, true] {
        let (top, cap) = sections(&text, uncomment);
        assert!(top.len() >= 8, "{top:?}");
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
        }
        let mut obj = top.clone();
        obj.insert("capture".into(), Value::Object(cap));
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
