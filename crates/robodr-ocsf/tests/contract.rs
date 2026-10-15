//! Contract tests: the JSON Schema and the example in docs/contracts must
//! match what the builder produces.
//!
//! No external JSON-Schema validator is available, so this implements the
//! subset the schema file uses: `$ref` (local `#/$defs/...`), `type`,
//! `required`, `properties`, `additionalProperties: false`, `items`, `const`,
//! `enum`, `minLength`/`maxLength`, `minimum`/`maximum`, `maxItems`.
//! `pattern` is *not* evaluated here (no regex engine); the Rust validator
//! enforces those formats.

mod common;

use serde_json::Value;
use std::path::PathBuf;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts")
}

fn load(name: &str) -> String {
    std::fs::read_to_string(contracts_dir().join(name))
        .unwrap_or_else(|e| panic!("cannot read docs/contracts/{name}: {e}"))
}

fn resolve<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let ptr = r.strip_prefix('#').expect("only local refs");
            resolve(
                root,
                root.pointer(ptr).unwrap_or_else(|| panic!("bad $ref {r}")),
            )
        }
        None => schema,
    }
}

fn check(root: &Value, schema: &Value, inst: &Value, path: &str, errs: &mut Vec<String>) {
    let s = resolve(root, schema);
    if let Some(c) = s.get("const") {
        if c != inst {
            errs.push(format!("{path}: expected const {c}, got {inst}"));
        }
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        if !e.contains(inst) {
            errs.push(format!("{path}: {inst} not in enum"));
        }
    }
    if let Some(t) = s.get("type").and_then(Value::as_str) {
        let ok = match t {
            "object" => inst.is_object(),
            "array" => inst.is_array(),
            "string" => inst.is_string(),
            "integer" => inst.is_u64() || inst.is_i64(),
            "number" => inst.is_number(),
            "boolean" => inst.is_boolean(),
            _ => panic!("unsupported type {t}"),
        };
        if !ok {
            errs.push(format!("{path}: expected {t}"));
            return;
        }
    }
    if let Some(st) = inst.as_str() {
        let n = st.chars().count() as u64;
        if s.get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n > m)
        {
            errs.push(format!("{path}: longer than maxLength"));
        }
        if s.get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n < m)
        {
            errs.push(format!("{path}: shorter than minLength"));
        }
    }
    if let Some(x) = inst.as_f64() {
        if s.get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|m| x < m)
        {
            errs.push(format!("{path}: below minimum"));
        }
        if s.get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|m| x > m)
        {
            errs.push(format!("{path}: above maximum"));
        }
    }
    if let Some(obj) = inst.as_object() {
        if let Some(req) = s.get("required").and_then(Value::as_array) {
            for k in req {
                let k = k.as_str().unwrap();
                if !obj.contains_key(k) {
                    errs.push(format!("{path}: missing required key `{k}`"));
                }
            }
        }
        let props = s.get("properties").and_then(Value::as_object);
        for (k, v) in obj {
            let sub = format!("{path}/{k}");
            match props.and_then(|p| p.get(k)) {
                Some(ps) => check(root, ps, v, &sub, errs),
                None => {
                    if s.get("additionalProperties") == Some(&Value::Bool(false)) {
                        errs.push(format!("{sub}: key not declared in schema"));
                    }
                }
            }
        }
    }
    if let Some(arr) = inst.as_array() {
        if s.get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| arr.len() as u64 > m)
        {
            errs.push(format!("{path}: too many items"));
        }
        if let Some(items) = s.get("items") {
            for (i, v) in arr.iter().enumerate() {
                check(root, items, v, &format!("{path}/{i}"), errs);
            }
        }
    }
}

fn schema_errors(inst: &Value) -> Vec<String> {
    let schema: Value = serde_json::from_str(&load("robot-edr-finding.schema.json"))
        .expect("schema file is valid JSON");
    let mut errs = vec![];
    check(&schema, &schema, inst, "", &mut errs);
    errs
}

/// Collect every `required` key list in the schema, to prove the walk above
/// actually visits them (guards against the checker silently skipping).
fn count_required(v: &Value) -> usize {
    match v {
        Value::Object(m) => {
            m.get("required")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
                + m.values().map(count_required).sum::<usize>()
        }
        Value::Array(a) => a.iter().map(count_required).sum(),
        _ => 0,
    }
}

#[test]
fn produced_finding_contains_every_required_schema_key() {
    let f = common::example_finding();
    let inst: Value = serde_json::from_str(&robodr_ocsf::to_json(&f).unwrap()).unwrap();
    let errs = schema_errors(&inst);
    assert!(errs.is_empty(), "schema violations:\n{}", errs.join("\n"));
    let schema: Value = serde_json::from_str(&load("robot-edr-finding.schema.json")).unwrap();
    assert!(
        count_required(&schema) > 80,
        "schema lost its required lists"
    );
}

#[test]
fn minimal_and_maximal_findings_match_schema() {
    use robodr_events::{Deviation, MotionCommand, RobotEvent, Severity};
    let ctx = common::ctx();
    // Minimal: no subject, no evidence, no techniques.
    let dev = Deviation::new("robot.custom.rule", Severity::Low, "x");
    let min = robodr_ocsf::FindingBuilder::from_deviation(&dev, &ctx)
        .seen(common::T0, common::T0)
        .build()
        .unwrap();
    // Maximal-ish: command with envelope, anomaly score, bus id, all ROS ids.
    let cmd = MotionCommand {
        channel: "/cmd_vel".into(),
        source_guid: Some("aa".into()),
        linear_speed: Some(2.0),
        joint_speed: Some(0.5),
    };
    let dev = Deviation::new("robot.motion.linear_over_envelope", Severity::High, "x");
    let env = robodr_events::profile::Envelope {
        max_linear_speed: Some(1.0),
        max_joint_speed: Some(1.0),
    };
    let max = robodr_ocsf::FindingBuilder::from_deviation(&dev, &ctx)
        .event(&RobotEvent::MotionCommand(cmd.clone()))
        .command(&cmd, Some(&env))
        .subject(robodr_ocsf::Subject {
            participant_guid: Some("aa".into()),
            node: Some("/teleop".into()),
            topic: Some("/cmd_vel".into()),
            type_name: Some("Twist".into()),
            src_ip: Some("10.0.0.9".into()),
        })
        .anomaly_score(0.9)
        .bus_message_id(7)
        .seen(common::T0, common::T0)
        .build()
        .unwrap();
    for f in [min, max] {
        let inst = serde_json::to_value(&f).unwrap();
        let errs = schema_errors(&inst);
        assert!(errs.is_empty(), "schema violations:\n{}", errs.join("\n"));
    }
}

#[test]
fn schema_checker_detects_missing_and_undeclared_keys() {
    let f = common::example_finding();
    let mut inst = serde_json::to_value(&f).unwrap();
    inst.as_object_mut().unwrap().remove("finding_id");
    inst["ocsf"]["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("uid");
    inst["ocsf"]["surprise"] = 1.into();
    let errs = schema_errors(&inst);
    assert!(errs.iter().any(|e| e.contains("`finding_id`")));
    assert!(errs
        .iter()
        .any(|e| e.contains("/ocsf/metadata: missing required key `uid`")));
    assert!(errs.iter().any(|e| e.contains("/ocsf/surprise")));
}

#[test]
fn contract_example_file_is_exactly_what_the_builder_produces() {
    let f = common::example_finding();
    let produced = serde_json::to_string_pretty(&f).unwrap() + "\n";
    let on_disk = load("robot-edr-finding.example.json");
    if produced != on_disk {
        eprintln!("---- regenerate docs/contracts/robot-edr-finding.example.json ----\n{produced}");
    }
    assert_eq!(produced, on_disk, "contract example is stale");
    // And the example itself passes the strict validator.
    assert_eq!(robodr_ocsf::parse_and_validate(&on_disk).unwrap(), f);
}
