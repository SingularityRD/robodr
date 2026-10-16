//! Regression tests for the independent review (wave 2, evidence reviewer):
//! the PoCs in `review-evidence/repo/crates/robodr-ocsf/tests/review_poc.rs`
//! passed while the issues existed; these assert the fixed behaviour.
//!
//! * Finding 1 — `poc_observe_only_deviation_reported_as_enforce`.
//! * Finding 2 — `poc_taint_bypasses_survive_validation` and every line of
//!   `review-evidence/ocsf/bypass.txt` (see `common::BYPASS_CASES`).

mod common;

use common::*;
use robodr_events::{Deviation, Mode as EvMode, RobotEvent, Severity};
use robodr_ocsf::taint::{
    self, escaped_cap, is_display, is_encoded, is_neutral, unescape, Charset,
};
use robodr_ocsf::*;

// ---------------------------------------------------------------- finding 1 --

fn participant_finding(dev: &Deviation, c: &RobotContext) -> FindingEnvelope {
    FindingBuilder::from_deviation(dev, c)
        .event(&RobotEvent::Ros2ParticipantDiscovered(participant(
            "aa", "10.0.0.9",
        )))
        .seen(T0, T0)
        .build()
        .unwrap()
}

/// PoC `poc_observe_only_deviation_reported_as_enforce`.
#[test]
fn observe_only_deviation_is_never_published_as_enforce() {
    let dev = Deviation::new("robot.ros2.unknown_participant", Severity::Critical, "x")
        .with_mode(EvMode::Observe);
    assert!(dev.is_observe_only());
    let c = ctx(); // Mode::Enforce
    assert_eq!(c.mode, Mode::Enforce);
    let f = participant_finding(&dev, &c);
    assert_eq!(f.entity_context.mode, Mode::Observe);
    assert_eq!(f.ocsf.unmapped.robodr.mode, Mode::Observe);
    assert!(
        f.description.contains("; mode observe;"),
        "{}",
        f.description
    );
    assert!(!f.description.contains("enforce"));
    assert!(!f.ocsf.finding_info.desc.contains("enforce"));
    let json = to_json(&f).unwrap();
    assert!(
        !json.contains("enforce"),
        "enforce leaked somewhere: {json}"
    );
    let back = parse_and_validate(&json).unwrap();
    assert_eq!(back.entity_context.mode, Mode::Observe);
}

#[test]
fn mode_is_the_stricter_of_context_and_deviation() {
    let enforce = Deviation::new("robot.ros2.unknown_participant", Severity::High, "x");
    let observe = enforce.clone().with_mode(EvMode::Observe);
    let ctx_enf = ctx();
    let mut ctx_obs = ctx();
    ctx_obs.mode = Mode::Observe;
    for (dev, c, want) in [
        (&enforce, &ctx_enf, Mode::Enforce),
        (&observe, &ctx_enf, Mode::Observe),
        (&enforce, &ctx_obs, Mode::Observe),
        (&observe, &ctx_obs, Mode::Observe),
    ] {
        assert_eq!(effective_mode(c.mode, dev), want);
        let f = participant_finding(dev, c);
        assert_eq!(f.entity_context.mode, want);
        let word = if want == Mode::Observe {
            "observe"
        } else {
            "enforce"
        };
        assert!(f.description.contains(&format!("; mode {word};")));
    }
    // Mode does not change identity: same finding id either way.
    assert_eq!(
        participant_finding(&enforce, &ctx_enf).finding_id,
        participant_finding(&observe, &ctx_enf).finding_id
    );
}

// ---------------------------------------------------------------- finding 2 --

/// The bypass corpus covers exactly the 13 lines of `bypass.txt`, in order.
#[test]
fn corpus_covers_every_bypass_txt_line() {
    let names: Vec<&str> = BYPASS_CASES.iter().map(|c| c.name).take(13).collect();
    assert_eq!(
        names,
        [
            "arabic_number_sign_Cf",
            "musical_format_Cf",
            "egyptian_format_Cf",
            "mongolian_fvs",
            "braille_blank",
            "nbsp_and_spaces",
            "private_use",
            "combining_zalgo",
            "cyrillic_homoglyph",
            "markdown_image_exfil",
            "html_entity",
            "json_quote_brace",
            "fake_field_injection",
        ]
    );
}

/// PoC `poc_taint_bypasses_survive_validation`, inverted: the raw value no
/// longer survives anywhere; it is carried as an untrusted field with a
/// lossless escaped original (`value`), an ASCII-safe rendering (`display`)
/// and the right flags.
#[test]
fn review_bypass_corpus_is_neutralised_rendered_and_flagged() {
    for c in BYPASS_CASES {
        let name = c.name;
        let f = build_topic(c.raw);
        let t = f.entity_context.ros.topic.as_ref().unwrap();

        // Untrusted and clearly marked.
        assert_eq!(t.taint, Provenance::Adversary, "{name}");
        assert!(f
            .adversary_controlled_fields
            .contains(&"/entity_context/ros/topic".to_string()));

        // Raw value did not survive (the PoC's `raw_survived=true`).
        assert_ne!(t.value, c.raw, "{name}: raw survived in value");
        assert_ne!(t.display, c.raw, "{name}: raw survived in display");

        // Lossless escaped original: allow-list encoded, reversible, hashed.
        assert!(t.escaped && !t.truncated, "{name}");
        assert!(t.value.is_ascii() && is_neutral(&t.value), "{name}");
        assert!(is_encoded(&t.value, Charset::RosName), "{name}");
        assert_eq!(unescape(&t.value).as_deref(), Some(c.raw), "{name}");
        assert_eq!(t.original_len, c.raw.len() as u64);

        // ASCII-safe rendering, pinned.
        assert_eq!(t.display, c.display, "{name}: display");
        assert!(is_display(&t.display, Charset::RosName), "{name}");

        // Flags.
        assert_eq!(t.non_ascii, c.non_ascii, "{name}: non_ascii");
        assert_eq!(t.mixed_script, c.mixed_script, "{name}: mixed_script");
        assert_eq!(t.injection_hint, c.injection_hint, "{name}: injection_hint");
        assert!(t.suspicious, "{name}: must be flagged suspicious");

        // Same escaped value in the OCSF resource copy.
        let r = f
            .ocsf
            .resources
            .iter()
            .find(|r| r.type_ == "ros2.topic")
            .unwrap();
        assert_eq!(r.name.as_deref(), Some(t.value.as_str()), "{name}");
        assert!(r.labels.iter().any(|l| l == TAINT_LABEL));

        // The detail line (free text) carries no markup either.
        let d = &f.entity_context.detail;
        assert!(is_encoded(&d.value, Charset::Text), "{name}");
        assert!(is_display(&d.display, Charset::Text), "{name}");
        assert_eq!(unescape(&d.value).unwrap(), format!("writer on {}", c.raw));
        assert!(d.suspicious || c.raw.chars().all(|ch| Charset::Text.is_raw(ch)));
        for s in [d.value.replace("\\u{", ""), d.display.clone()] {
            for meta in ["![", "](", "&lt", "&#", "\"", "<", "{}"] {
                assert!(!s.contains(meta), "{name}: {meta} in detail");
            }
        }

        // Narrative fields never carry the attacker text.
        for narrative in [&f.title, &f.description, &f.ocsf.message] {
            assert!(!narrative.contains("evil") && !narrative.contains("SYSTEM"));
        }

        // No raw non-ASCII or markup anywhere in the serialised finding, and
        // the strict parser round-trips it.
        let json = to_json(&f).unwrap();
        assert!(json.is_ascii(), "{name}");
        assert_eq!(parse_and_validate(&json).unwrap(), f, "{name}");
    }
}

#[test]
fn specific_bypass_encodings_are_pinned() {
    let v = |raw: &str| build_topic(raw).entity_context.ros.topic.unwrap().value;
    assert_eq!(v("/cmd\u{0600}vel"), "/cmd\\u{0600}vel");
    assert_eq!(v("/a\u{1D173}b"), "/a\\u{1D173}b");
    assert_eq!(v("/cmd_v\u{0435}l"), "/cmd_v\\u{0435}l");
    assert_eq!(v("/a\u{00A0}b"), "/a\\u{00A0}b");
    assert_eq!(
        v("/x ![s](u)"),
        "/x\\u{0020}\\u{0021}\\u{005B}s\\u{005D}\\u{0028}u\\u{0029}"
    );
    assert_eq!(v("/x &lt;"), "/x\\u{0020}\\u{0026}lt\\u{003B}");
    assert_eq!(v("/x\"}"), "/x\\u{0022}\\u{007D}");
}

/// Benign names are not flagged, so `suspicious` keeps its signal.
#[test]
fn benign_names_are_not_flagged() {
    for raw in ["/cmd_vel", "rt/cmd_vel", "/battery_status", "/ns/node_1"] {
        let t = build_topic(raw).entity_context.ros.topic.unwrap();
        assert_eq!(t.value, raw);
        assert_eq!(t.display, raw);
        assert!(!t.escaped && !t.suspicious && !t.injection_hint, "{raw}");
    }
}

/// Lossless for anything up to the cap, even when every character needs the
/// longest escape; the worst-case finding still fits the size limits.
#[test]
fn escaped_original_is_lossless_up_to_cap_and_worst_case_fits() {
    let raw = "\u{10FFFF}".repeat(taint::caps::TOPIC);
    let t = build_topic(&raw).entity_context.ros.topic.unwrap();
    assert!(!t.truncated);
    assert_eq!(t.value.len(), escaped_cap(taint::caps::TOPIC));
    assert_eq!(unescape(&t.value).unwrap(), raw);

    // Every tainted field at its worst case at once.
    let worst = "\u{10FFFF}".repeat(100_000);
    let dev = Deviation::new(
        "robot.ros2.unauthorized_motion_writer",
        Severity::Critical,
        worst.clone(),
    );
    let c = ctx();
    let f = FindingBuilder::from_deviation(&dev, &c)
        .event(&RobotEvent::Ros2WriterDiscovered(writer(&worst)))
        .event(&RobotEvent::MotionCommand(motion(&worst, Some(1.0))))
        .subject(Subject {
            node: Some(worst.clone()),
            participant_guid: Some(worst.clone()),
            topic: Some(worst.clone()),
            type_name: Some(worst.clone()),
            src_ip: Some(worst.clone()),
        })
        .seen(T0, T0)
        .build()
        .expect("worst case still builds");
    let json = to_json(&f).unwrap();
    assert!(json.len() <= validate::MAX_FINDING_BYTES, "{}", json.len());
    let ec = &f.entity_context;
    for t in [
        ec.ros.node.as_ref().unwrap(),
        ec.ros.topic.as_ref().unwrap(),
        ec.ros.participant_guid.as_ref().unwrap(),
        &ec.detail,
        &ec.command.as_ref().unwrap().channel,
    ] {
        assert!(t.truncated && t.suspicious);
        assert!(t.value.len() <= validate::MAX_STRING_BYTES);
    }
    assert_eq!(parse_and_validate(&json).unwrap(), f);
}

#[test]
fn validator_rejects_raw_bypass_values_and_inconsistent_flags() {
    let good = serde_json::to_value(build_topic("/cmd_v\u{0435}l")).unwrap();
    let sync = |v: &mut serde_json::Value| {
        v["ocsf"]["unmapped"]["robodr"] = v["entity_context"].clone();
    };
    assert!(parse_and_validate(&good.to_string()).is_ok());
    for c in BYPASS_CASES {
        for field in ["value", "display"] {
            let mut v = good.clone();
            v["entity_context"]["ros"]["topic"][field] = c.raw.into();
            sync(&mut v);
            assert!(
                parse_and_validate(&v.to_string()).is_err(),
                "{} in {field}",
                c.name
            );
        }
        let mut v = good.clone();
        v["ocsf"]["resources"][1]["name"] = c.raw.into();
        assert!(
            parse_and_validate(&v.to_string()).is_err(),
            "{} in resource",
            c.name
        );
    }
    type Mutator = fn(&mut serde_json::Value);
    let topic = |v: &mut serde_json::Value, k: &str, x: serde_json::Value| {
        v["entity_context"]["ros"]["topic"][k] = x;
    };
    let cases: &[(&str, Mutator)] = &[
        ("non-canonical escape of a raw char", |v| {
            v["entity_context"]["ros"]["topic"]["value"] = "/cmd_v\\u{0065}l".into()
        }),
        ("lower-case hex", |v| {
            v["entity_context"]["ros"]["topic"]["value"] = "/cmd_v\\u{043a}l".into()
        }),
        ("dangling backslash", |v| {
            v["entity_context"]["ros"]["topic"]["value"] = "/cmd_vel\\".into()
        }),
        ("raw space in a ROS name", |v| {
            v["entity_context"]["ros"]["topic"]["value"] = "/cmd vel".into()
        }),
        ("markdown in detail", |v| {
            v["entity_context"]["detail"]["value"] = "see [here](https://e)".into()
        }),
        ("value swapped for a benign one (hash mismatch)", |v| {
            v["entity_context"]["ros"]["topic"]["value"] = "/cmd_vel".into();
            v["entity_context"]["ros"]["topic"]["display"] = "/cmd_vel".into();
            v["entity_context"]["ros"]["topic"]["escaped"] = false.into();
            v["entity_context"]["ros"]["topic"]["non_ascii"] = false.into();
            v["entity_context"]["ros"]["topic"]["mixed_script"] = false.into();
            v["entity_context"]["ros"]["topic"]["suspicious"] = false.into();
        }),
        ("display hides the substitution", |v| {
            v["entity_context"]["ros"]["topic"]["display"] = "/cmd_vel".into()
        }),
        ("display missing", |v| {
            v["entity_context"]["ros"]["topic"]
                .as_object_mut()
                .unwrap()
                .remove("display");
        }),
        ("non_ascii cleared", |v| {
            v["entity_context"]["ros"]["topic"]["non_ascii"] = false.into();
            v["entity_context"]["ros"]["topic"]["mixed_script"] = false.into();
        }),
        ("mixed_script cleared", |v| {
            v["entity_context"]["ros"]["topic"]["mixed_script"] = false.into();
        }),
        ("mixed_script without non_ascii", |v| {
            v["entity_context"]["ros"]["type_name"]["mixed_script"] = true.into();
        }),
        ("suspicious cleared", |v| {
            v["entity_context"]["ros"]["topic"]["suspicious"] = false.into()
        }),
        ("suspicious on a benign value", |v| {
            v["entity_context"]["ros"]["type_name"]["suspicious"] = true.into()
        }),
        ("injection_hint set on a benign value", |v| {
            v["entity_context"]["ros"]["type_name"]["injection_hint"] = true.into();
            v["entity_context"]["ros"]["type_name"]["suspicious"] = true.into();
        }),
        ("escaped flag cleared", |v| {
            v["entity_context"]["ros"]["topic"]["escaped"] = false.into()
        }),
        ("escaped flag set on plain value", |v| {
            v["entity_context"]["ros"]["type_name"]["escaped"] = true.into()
        }),
        ("truncated claimed on a short value", |v| {
            v["entity_context"]["ros"]["topic"]["truncated"] = true.into()
        }),
    ];
    for (name, m) in cases {
        let mut v = good.clone();
        m(&mut v);
        sync(&mut v);
        assert!(parse_and_validate(&v.to_string()).is_err(), "{name}");
    }

    // Injection hint cleared on a fake-field value.
    let good = serde_json::to_value(build_topic(BYPASS_CASES[12].raw)).unwrap();
    assert!(parse_and_validate(&good.to_string()).is_ok());
    let mut v = good.clone();
    topic(&mut v, "injection_hint", false.into());
    sync(&mut v);
    assert!(parse_and_validate(&v.to_string()).is_err());
}

/// Contract 1.0 messages (no `display` / hint / `suspicious` fields) still
/// parse when ASCII; the 1.1-only consistency checks are skipped for them,
/// while a 1.1 message missing the fields is rejected if they would be set.
#[test]
fn contract_1_0_messages_without_the_new_fields_still_parse_when_ascii() {
    fn strip(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(m) => {
                if m.contains_key("taint") {
                    for k in [
                        "display",
                        "non_ascii",
                        "mixed_script",
                        "injection_hint",
                        "suspicious",
                    ] {
                        m.remove(k);
                    }
                }
                m.values_mut().for_each(strip);
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let mut v = serde_json::to_value(example_finding()).unwrap();
    v["contract_version"] = "1.0.0".into();
    strip(&mut v);
    let f = parse_and_validate(&v.to_string()).unwrap();
    assert!(!f.entity_context.ros.topic.unwrap().non_ascii);

    // Same stripping on a 1.1 message with a flagged value is rejected.
    let mut v = serde_json::to_value(build_topic("/x SYSTEM: y")).unwrap();
    strip(&mut v);
    assert!(parse_and_validate(&v.to_string()).is_err());
}

#[test]
fn hostile_trusted_config_with_non_ascii_is_rejected() {
    // Trusted strings must be printable ASCII now (homoglyph/bidi in config
    // is a configuration bug, not data).
    let dev = Deviation::new("robot.ros2.unknown_reader", Severity::Low, "x");
    for site in ["range-n\u{00F6}rth", "a\u{00A0}b", "a\u{2800}"] {
        let mut c = ctx();
        c.robot.site = site.into();
        assert!(FindingBuilder::from_deviation(&dev, &c)
            .seen(T0, T0)
            .build()
            .is_err());
    }
}
