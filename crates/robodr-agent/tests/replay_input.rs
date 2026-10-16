//! `replay::run` / `replay::verify` on crafted inputs: every line kind the
//! JSONL reader accepts (events of every `RobotEvent` kind, comments, blank
//! lines, CRLF, no trailing newline), malformed and hostile lines, ordering,
//! clock handling (start time, step, saturation) and determinism.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};

use common::*;
use robodr_agent::replay::{self, ReplayError, ReplayOptions, ReplaySummary};
use robodr_agent::Disposition;
use robodr_responder::SafetyState;

const UNKNOWN_PARTICIPANT: &str = "robot.ros2.unknown_participant";

struct Run {
    dir: PathBuf,
    findings: Vec<u8>,
    outcomes: Vec<u8>,
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn opts_for(events: &Path, bb: &Path) -> ReplayOptions {
    let ex = examples();
    let mut o = ReplayOptions::new(
        events,
        ex.join("ugv-demo.profile.json"),
        ex.join("policy-oem-validated.json"),
        bb,
        KEY.to_vec(),
        ROBOT,
    );
    o.safety = SafetyState::MovingSlow;
    o.firewall = true;
    o.firewall_max_angular = demo_angular();
    o.trusted_keys = Some(ex.join("ugv-demo.trust.json"));
    o
}

/// Write `content` as the events file and replay it.
fn replay_bytes(
    tag: &str,
    content: &[u8],
    edit: impl FnOnce(&mut ReplayOptions),
) -> (Run, Result<ReplaySummary, ReplayError>) {
    let dir = tmpdir(tag);
    let events = dir.join("events.jsonl");
    std::fs::write(&events, content).unwrap();
    let mut o = opts_for(&events, &dir.join("bb"));
    edit(&mut o);
    let mut findings = Vec::new();
    let mut outcomes = Vec::new();
    let res = replay::run(&o, &mut findings, Some(&mut outcomes), None);
    (
        Run {
            dir,
            findings,
            outcomes,
        },
        res,
    )
}

fn participant(guid: &str, ip: &str) -> String {
    // serde_json escapes control characters, quotes and backslashes.
    serde_json::json!({
        "kind": "ros2_participant_discovered",
        "guid_prefix": guid,
        "src_ip": ip,
        "locators": [],
    })
    .to_string()
}

fn rogue(k: usize) -> String {
    participant(
        &format!("{k:024x}"),
        &format!("10.9.{}.{}", k / 256, k % 256),
    )
}

fn verify_dir(run: &Run) -> replay::VerifySummary {
    replay::verify(&run.dir.join("bb"), &KEY, None, Some(ROBOT), None).unwrap()
}

fn lines(b: &[u8]) -> Vec<String> {
    String::from_utf8(b.to_vec())
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

// ------------------------------------------------------------ line kinds

#[test]
fn every_event_kind_and_line_kind_is_accepted() {
    let content = [
        "# header comment",
        "",
        "   ",
        "\t# indented comment",
        &participant(LEGIT, "10.42.0.11"),
        // Known participant again (no deviation) with surrounding spaces.
        &format!("   {}   ", participant(LEGIT, "10.42.0.11")),
        &rogue(1),
        &format!(
            r#"{{"kind":"ros2_writer_discovered","guid_prefix":"{ROGUE}","topic":"rt/cmd_vel","type_name":"geometry_msgs::msg::dds_::Twist_"}}"#
        ),
        &format!(
            r#"{{"kind":"ros2_reader_discovered","guid_prefix":"{ROGUE}","topic":"rt/secret","type_name":"std_msgs::msg::dds_::String_"}}"#
        ),
        &format!(
            r#"{{"kind":"motion_command","channel":"/cmd_vel","source_guid":"{LEGIT_WRITER}","linear_speed":0.1,"joint_speed":null}}"#
        ),
        // Optional fields omitted / angular given.
        r#"{"kind":"motion_command","channel":"/cmd_vel","source_guid":null,"linear_speed":0.2,"joint_speed":null,"angular_speed":0.1}"#,
        r#"{"kind":"motion_feedback","channel":"/odom","timestamp_ns":40000000}"#,
        r#"{"kind":"motion_feedback","channel":"/odom","measured_linear_speed":0.1,"measured_joint_speed":null,"linear_velocity":0.1,"angular_velocity":0.0,"publisher_guid":"x","timestamp_ns":60000000}"#,
    ]
    .join("\r\n");
    // No trailing newline: the last line still counts.
    let (run, res) = replay_bytes("kinds", content.as_bytes(), |_| {});
    let sum = res.unwrap();
    assert_eq!(sum.events, 9, "comments and blank lines are not events");
    assert_eq!(sum.stats.events, 9);
    assert!(sum.verified(), "{:?} {:?}", sum.report, sum.links);
    // At least the rogue participant is reported.
    assert!(sum
        .outcomes
        .iter()
        .any(|o| o.deviation.rule == UNKNOWN_PARTICIPANT));
    // Every finding line is a valid finding; one outcome line per outcome.
    for l in lines(&run.findings) {
        robodr_ocsf::parse_and_validate(&l).unwrap();
    }
    assert_eq!(lines(&run.outcomes).len(), sum.outcomes.len());
}

#[test]
fn empty_and_comment_only_inputs_produce_a_verifiable_empty_run() {
    for (i, content) in ["", "\n\n\n", "# only\n# comments\n", "\r\n \r\n"]
        .iter()
        .enumerate()
    {
        let (run, res) = replay_bytes(&format!("empty{i}"), content.as_bytes(), |_| {});
        let sum = res.unwrap();
        assert_eq!(sum.events, 0, "{content:?}");
        assert!(sum.outcomes.is_empty());
        assert!(run.findings.is_empty() && run.outcomes.is_empty());
        assert!(sum.verified());
        assert!(verify_dir(&run).verified());
    }
}

#[test]
fn unknown_fields_in_an_event_are_ignored() {
    // RobotEvent is not deny_unknown_fields: a newer producer's extra field
    // does not stop a replay.
    let line = r#"{"kind":"ros2_participant_discovered","guid_prefix":"0f0f0f0f0f0f0f0f0f0f0f0f","src_ip":"1.2.3.4","locators":[],"extra":{"nested":[1,2,3]}}"#;
    let (_run, res) = replay_bytes("extra", line.as_bytes(), |_| {});
    let sum = res.unwrap();
    assert_eq!(sum.events, 1);
    assert_eq!(sum.outcomes[0].deviation.rule, UNKNOWN_PARTICIPANT);
}

// --------------------------------------------------- malformed / hostile lines

fn deep(n: usize) -> String {
    format!("{}{}", "[".repeat(n), "]".repeat(n))
}

#[test]
fn malformed_lines_abort_with_the_line_number_and_keep_prior_evidence() {
    let deep_obj = format!(
        r#"{{"kind":"ros2_participant_discovered","guid_prefix":"aa","src_ip":"x","locators":{}}}"#,
        deep(100_000)
    );
    let bad: Vec<(&str, Vec<u8>)> = vec![
        ("unknown kind", br#"{"kind":"nope"}"#.to_vec()),
        ("no kind", br#"{"guid_prefix":"aa"}"#.to_vec()),
        ("truncated", br#"{"kind":"ros2_participant_discovered","#.to_vec()),
        ("array", b"[]".to_vec()),
        ("null", b"null".to_vec()),
        ("string", br#""motion_command""#.to_vec()),
        ("number", b"42".to_vec()),
        ("missing field", br#"{"kind":"motion_command"}"#.to_vec()),
        ("wrong type", br#"{"kind":"motion_feedback","channel":"/odom","timestamp_ns":-1}"#.to_vec()),
        ("overflow float", br#"{"kind":"motion_command","channel":"/c","source_guid":null,"linear_speed":1e999,"joint_speed":null}"#.to_vec()),
        ("u64 overflow", br#"{"kind":"motion_feedback","channel":"/odom","timestamp_ns":18446744073709551616}"#.to_vec()),
        ("NaN literal", br#"{"kind":"motion_command","channel":"/c","source_guid":null,"linear_speed":NaN,"joint_speed":null}"#.to_vec()),
        ("trailing garbage", format!("{} x", rogue(9)).into_bytes()),
        ("two objects", format!("{}{}", rogue(9), rogue(10)).into_bytes()),
        ("deep nesting", deep(100_000).into_bytes()),
        ("deep nesting in a field", deep_obj.into_bytes()),
        ("invalid utf-8", b"{\"kind\":\"\xff\xfe\"}".to_vec()),
        ("lone surrogate escape", br#"{"kind":"ros2_participant_discovered","guid_prefix":"\ud800","src_ip":"x","locators":[]}"#.to_vec()),
        ("utf-8 BOM", format!("\u{feff}{}", rogue(9)).into_bytes()),
        ("NUL byte", b"\0".to_vec()),
        ("over-long line", format!(r#"{{"kind":"nope","pad":"{}"}}"#, "a".repeat(1 << 20)).into_bytes()),
    ];
    for (name, line) in bad {
        // Two good events, then the bad one, then one that is never read.
        let mut content = format!("{}\n# c\n{}\n", rogue(1), rogue(2)).into_bytes();
        content.extend_from_slice(&line);
        content.extend_from_slice(format!("\n{}\n", rogue(3)).as_bytes());
        let (run, res) = replay_bytes("bad", &content, |_| {});
        match res {
            Err(ReplayError::Input(msg)) => {
                assert!(msg.contains(":4"), "{name}: line number in {msg:?}");
            }
            other => panic!("{name}: expected an input error, got {other:?}"),
        }
        // The two good events were processed and written before the abort.
        assert_eq!(lines(&run.findings).len(), 2, "{name}");
        assert_eq!(lines(&run.outcomes).len(), 2, "{name}");
        // The black box was sealed and verifies on its own.
        let v = verify_dir(&run);
        assert!(v.verified(), "{name}: {:?}", v.report);
    }
}

#[test]
fn hostile_but_well_formed_values_never_panic_and_stay_verifiable() {
    let long = "A".repeat(200_000);
    let content = [
        participant("\u{202e}evil\u{0}\u{1b}[31m", "\"; DROP TABLE"),
        participant(&long, &long),
        participant("💥", "::ffff:10.0.0.1"),
        participant("", ""),
        format!(r#"{{"kind":"ros2_writer_discovered","guid_prefix":"{ROGUE}","topic":"{long}","type_name":"{long}"}}"#),
        format!(r#"{{"kind":"ros2_writer_discovered","guid_prefix":"{ROGUE}","topic":"rt/../../etc","type_name":""}}"#),
        r#"{"kind":"motion_command","channel":"/cmd_vel","source_guid":"","linear_speed":1.7976931348623157e308,"joint_speed":-1e308}"#.into(),
        r#"{"kind":"motion_command","channel":"/cmd_vel","source_guid":null,"linear_speed":-0.0,"joint_speed":5e-324,"angular_speed":-1e308}"#.into(),
        format!(r#"{{"kind":"motion_command","channel":"{long}","source_guid":"{long}","linear_speed":null,"joint_speed":null}}"#),
        r#"{"kind":"motion_feedback","channel":"/odom","measured_linear_speed":1e308,"timestamp_ns":18446744073709551615}"#.into(),
        r#"{"kind":"motion_feedback","channel":"/odom","timestamp_ns":0}"#.into(),
    ]
    .join("\n");
    for monitor in [false, true] {
        let (run, res) = replay_bytes("hostile", content.as_bytes(), |o| {
            o.record_all_events = true;
            if monitor {
                let mut mc = robodr_motion::MonitorConfig::ugv("ugv-demo-x1");
                mc.command_channels = vec!["/cmd_vel".to_string()];
                o.monitor = Some(mc);
            }
        });
        let sum = res.unwrap();
        assert_eq!(sum.events, 11);
        assert!(sum.verified(), "{:?} {:?}", sum.report, sum.links);
        assert_eq!(sum.stats.guard_violations, 0);
        // Every finding that was written is valid.
        for l in lines(&run.findings) {
            robodr_ocsf::parse_and_validate(&l).unwrap();
        }
        // A replay never asks for anything without approval beyond what the
        // planner allows, and never anything while it cannot act.
        for o in &sum.outcomes {
            robodr_responder::check_invariants_for_deviation(
                &o.plan,
                &o.deviation,
                SafetyState::MovingSlow,
                &context(),
            )
            .unwrap();
        }
    }
}

// ------------------------------------------------------------- ordering

#[test]
fn outputs_follow_input_order() {
    let n = 40;
    let content: String = (1..=n).map(|k| rogue(k) + "\n").collect();
    let (run, res) = replay_bytes("order", content.as_bytes(), |o| o.step_ns = MS);
    let sum = res.unwrap();
    assert_eq!(sum.outcomes.len(), n);
    let mut last_seq = 0;
    for (k, o) in sum.outcomes.iter().enumerate() {
        let k = k + 1;
        assert!(
            o.deviation.detail.contains(&format!("{k:024x}")),
            "outcome {k}: {}",
            o.deviation.detail
        );
        let seq = o.evidence.event.as_ref().unwrap().seq;
        assert!(seq > last_seq, "evidence order");
        last_seq = seq;
    }
    // Findings file and outcomes file are in the same order.
    let f = lines(&run.findings);
    let oc = lines(&run.outcomes);
    assert_eq!(f.len(), n);
    for (k, (fl, ol)) in f.iter().zip(&oc).enumerate() {
        let needle = format!("{:024x}", k + 1);
        assert!(fl.contains(&needle) && ol.contains(&needle), "line {k}");
    }
}

#[test]
fn retained_outcomes_are_capped_but_counted() {
    let content: String = (1..=25).map(|k| rogue(k) + "\n").collect();
    for cap in [0usize, 1, 24, 25, 1000] {
        let (run, res) = replay_bytes("cap", content.as_bytes(), |o| {
            o.max_retained_outcomes = cap;
        });
        let sum = res.unwrap();
        assert_eq!(sum.outcomes.len(), cap.min(25), "cap {cap}");
        assert_eq!(sum.outcomes_dropped as usize, 25 - cap.min(25));
        assert_eq!(sum.by_severity.values().sum::<u64>(), 25);
        assert_eq!(sum.by_disposition.values().sum::<u64>(), 25);
        // Outputs are not capped.
        assert_eq!(lines(&run.findings).len(), 25);
        assert_eq!(lines(&run.outcomes).len(), 25);
        // The retained ones are the first ones.
        if cap > 0 {
            assert!(sum.outcomes[0]
                .deviation
                .detail
                .contains(&format!("{:024x}", 1)));
        }
    }
}

// --------------------------------------------------------------- clock

fn finding_times(findings: &[u8]) -> Vec<u64> {
    lines(findings)
        .iter()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["ocsf"]["time"].as_u64().unwrap()
        })
        .collect()
}

#[test]
fn event_k_is_observed_at_start_plus_k_steps() {
    let content: String = (1..=5).map(|k| rogue(k) + "\n# skip\n\n").collect();
    for (start, step_ms) in [
        (1_767_225_600_000u64, 20u64),
        (1_000_000_000_000, 1),
        (1_000_000_000_000, 3_600_000),
    ] {
        let (run, res) = replay_bytes("clock", content.as_bytes(), |o| {
            o.start_wall_ms = start;
            o.step_ns = step_ms * MS;
        });
        res.unwrap();
        let want: Vec<u64> = (1..=5).map(|k| start + k * step_ms).collect();
        // Comment / blank lines do not advance the clock.
        assert_eq!(
            finding_times(&run.findings),
            want,
            "start {start} step {step_ms}"
        );
    }
    // A start time no finding can carry (the epoch itself) is refused when
    // the agent is built, before any evidence is written.
    let (run, res) = replay_bytes("clock0", content.as_bytes(), |o| o.start_wall_ms = 0);
    assert!(matches!(res, Err(ReplayError::Agent(_))), "{res:?}");
    assert!(run.findings.is_empty());
}

#[test]
fn step_controls_rate_limiting_through_the_monotonic_clock() {
    // The same rogue participant announced 10 times. With a 1 ms step the
    // repeats fall in the policy's 5 s re-issue interval and are rate
    // limited; with a 10 s step none are.
    let content: String = (0..10).map(|_| rogue(7) + "\n").collect();
    let count = |step_ns| {
        let (_run, res) = replay_bytes("rate", content.as_bytes(), |o| o.step_ns = step_ns);
        let sum = res.unwrap();
        assert!(sum.verified());
        sum.outcomes
            .iter()
            .filter(|o| o.disposition == Disposition::Suppressed)
            .count()
    };
    let fast = count(MS);
    let slow = count(10_000 * MS);
    assert!(fast > 0, "fast replay should rate limit repeats");
    assert_eq!(slow, 0, "spaced replay should never rate limit");
}

#[test]
fn step_zero_is_refused_before_anything_is_written() {
    let (run, res) = replay_bytes("step0", rogue(1).as_bytes(), |o| o.step_ns = 0);
    assert!(matches!(res, Err(ReplayError::Config(m)) if m.contains("step")));
    assert!(!run.dir.join("bb").exists());
    assert!(run.findings.is_empty());
}

#[test]
fn saturating_clock_never_panics_and_the_chain_still_verifies() {
    let content: String = (1..=4).map(|k| rogue(k) + "\n").collect();
    for step_ns in [u64::MAX, u64::MAX / 2, u64::MAX / 3] {
        let (_run, res) = replay_bytes("sat", content.as_bytes(), |o| o.step_ns = step_ns);
        let sum = res.unwrap();
        assert_eq!(sum.events, 4);
        assert!(sum.report.is_intact(), "{:?}", sum.report);
        // Every deviation still has its evidence in the black box, even
        // when the finding cannot carry such a timestamp.
        for o in &sum.outcomes {
            assert!(o.evidence.event.is_some() && o.evidence.deviation.is_some());
            assert_eq!(
                o.finding.is_some(),
                o.finding_errors.is_empty(),
                "{:?}",
                o.finding_errors
            );
        }
    }
    // A start time the findings cannot represent is refused up front.
    let (_run, res) = replay_bytes("sat-start", rogue(1).as_bytes(), |o| {
        o.start_wall_ms = u64::MAX;
    });
    assert!(res.is_err());
}

/// When the replay clock runs past what an OCSF finding can carry (large
/// `--step-ms`, or a start time close to the limit), the deviation is
/// recorded in the black box but its finding fails validation and is
/// dropped. Such a run is never reported as verified (`robodr-replay` exits
/// 3, see the CLI test), even though the evidence that was written is sound.
#[test]
fn lost_findings_are_not_reported_as_verified() {
    let (_run, res) = replay_bytes("lost", rogue(1).as_bytes(), |o| {
        o.step_ns = 18_446_744_073_709 * MS;
    });
    let sum = res.unwrap();
    assert_eq!(
        sum.stats.finding_errors, 1,
        "precondition: the finding was lost"
    );
    assert_eq!(sum.findings_lost(), 1);
    assert!(sum.evidence_verified(), "{:?} {:?}", sum.report, sum.links);
    assert!(!sum.verified(), "a run that lost findings must not verify");
}

// --------------------------------------------------------- determinism

fn segments(dir: &Path) -> Vec<Vec<u8>> {
    robodr_blackbox::verify::read_segments(dir)
        .unwrap()
        .into_iter()
        .map(|s| s.bytes)
        .collect()
}

#[test]
fn same_input_gives_byte_identical_outputs_and_evidence() {
    let ex = examples();
    let mut content = std::fs::read(ex.join("rogue-ugv.jsonl")).unwrap();
    content.extend_from_slice(
        std::fs::read(ex.join("motion-injection.jsonl"))
            .unwrap()
            .as_slice(),
    );
    for k in 1..=30 {
        content.extend_from_slice(format!("{}\n", rogue(k)).as_bytes());
    }
    content.extend_from_slice(participant("\u{202e}x", "\u{0}").as_bytes());
    let edit = |o: &mut ReplayOptions| {
        o.record_all_events = true;
        o.kafka_partitions = Some(12);
        o.max_retained_outcomes = 5;
        let mut mc = robodr_motion::MonitorConfig::ugv("ugv-demo-x1");
        mc.command_channels = vec!["/cmd_vel".to_string()];
        o.monitor = Some(mc);
    };
    let (a, ra) = replay_bytes("det-a", &content, edit);
    let (b, rb) = replay_bytes("det-b", &content, edit);
    let (sa, sb) = (ra.unwrap(), rb.unwrap());
    assert!(!a.findings.is_empty() && !a.outcomes.is_empty());
    assert_eq!(a.findings, b.findings, "findings");
    assert_eq!(a.outcomes, b.outcomes, "outcomes");
    assert_eq!(
        segments(&a.dir.join("bb")),
        segments(&b.dir.join("bb")),
        "black box"
    );
    assert_eq!(sa.by_severity, sb.by_severity);
    assert_eq!(sa.by_disposition, sb.by_disposition);
    assert_eq!(sa.report.last_hash, sb.report.last_hash);
    assert_eq!(
        replay::describe_report(&sa.report),
        replay::describe_report(&sb.report)
    );
    // Changing only the boot id changes the evidence (it is bound into the
    // chain), so determinism is not an accident of ignoring inputs.
    let (c, _) = replay_bytes("det-c", &content, |o| {
        edit(o);
        o.boot_id = "other-boot".into();
    });
    assert_ne!(segments(&a.dir.join("bb")), segments(&c.dir.join("bb")));
}

// ------------------------------------------------------- output errors

/// A writer that fails after `ok` lines.
struct FailAfter {
    ok: usize,
    seen: usize,
}

impl Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.contains(&b'\n') {
            self.seen += 1;
        }
        if self.seen > self.ok {
            return Err(std::io::Error::other("disk full"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_write_failure_is_an_io_error_and_the_black_box_is_sealed() {
    let dir = tmpdir("wfail");
    let events = dir.join("e.jsonl");
    let content: String = (1..=10).map(|k| rogue(k) + "\n").collect();
    std::fs::write(&events, content).unwrap();
    let bb = dir.join("bb");
    let o = opts_for(&events, &bb);
    let mut out = FailAfter { ok: 3, seen: 0 };
    let res = replay::run(&o, &mut out, None, None);
    assert!(
        matches!(&res, Err(ReplayError::Io(m)) if m.contains("writing output")),
        "{res:?}"
    );
    let v = replay::verify(&bb, &KEY, None, Some(ROBOT), None).unwrap();
    assert!(v.verified(), "{:?}", v.report);
    // Same through the outcomes writer.
    let bb2 = dir.join("bb2");
    let o2 = opts_for(&events, &bb2);
    let mut outcomes = FailAfter { ok: 0, seen: 0 };
    let res = replay::run(&o2, &mut Vec::new(), Some(&mut outcomes), None);
    assert!(matches!(res, Err(ReplayError::Io(_))));
    assert!(replay::verify(&bb2, &KEY, None, Some(ROBOT), None)
        .unwrap()
        .verified());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn events_path_errors_are_input_errors() {
    let dir = tmpdir("evpath");
    // Missing file.
    let o = opts_for(&dir.join("missing.jsonl"), &dir.join("bb1"));
    assert!(matches!(
        replay::run(&o, &mut Vec::new(), None, None),
        Err(ReplayError::Input(_))
    ));
    // A directory: opening may succeed, reading fails; either way an error,
    // never a panic, and never a silent empty run.
    let o = opts_for(&dir, &dir.join("bb2"));
    assert!(replay::run(&o, &mut Vec::new(), None, None).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn verify_reports_invalid_findings_lines_by_number() {
    let (run, res) = replay_bytes(
        "vf",
        format!("{}\n{}\n", rogue(1), rogue(2)).as_bytes(),
        |_| {},
    );
    res.unwrap();
    let mut text = String::from_utf8(run.findings.clone()).unwrap();
    text.push('\n'); // blank line: skipped
    text.push_str("{\"not\":\"a finding\"}\n");
    text.push_str("garbage\n");
    let path = run.dir.join("findings.jsonl");
    std::fs::write(&path, text).unwrap();
    let v = replay::verify(&run.dir.join("bb"), &KEY, None, Some(ROBOT), Some(&path)).unwrap();
    assert!(!v.verified());
    let nums: Vec<usize> = v.invalid_findings.iter().map(|(n, _)| *n).collect();
    assert_eq!(nums, vec![4, 5]);
    // The valid lines' links still resolve.
    let links = v.links.unwrap();
    assert!(links.is_ok() && links.checked > 0, "{links:?}");
    // Wrong robot id is reported by the verifier.
    let v = replay::verify(&run.dir.join("bb"), &KEY, None, Some("other-robot"), None).unwrap();
    assert!(!v.verified());
    // Missing findings file is an I/O error.
    assert!(matches!(
        replay::verify(
            &run.dir.join("bb"),
            &KEY,
            None,
            None,
            Some(&run.dir.join("nope.jsonl"))
        ),
        Err(ReplayError::Io(_))
    ));
}
