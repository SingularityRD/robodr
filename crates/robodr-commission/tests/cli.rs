//! End-to-end tests of the `robodr-commission` binary.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-commission");

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

/// A fresh temp dir per test (process id + counter keeps parallel tests apart).
fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-commission-test-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(common::with_operator_signature(args))
        .output()
        .expect("run binary")
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

/// Write a profile file, filling every key the strict loader requires.
fn write_profile(path: &Path, partial: serde_json::Value) {
    let mut v = serde_json::json!({
        "model": "m", "locked": false, "participants": [], "writer_topics": [],
        "motion_envelopes": {}, "services": [], "actions": [], "reader_topics": [],
        "raw_dds_topics": []
    });
    for (k, val) in partial.as_object().unwrap() {
        v[k] = val.clone();
    }
    std::fs::write(path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

/// Operator review: confirm every item and sign.
fn confirm(signoff: &Path) {
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(signoff).unwrap()).unwrap();
    v["operator"] = "Test Operator".into();
    for i in v["items"].as_array_mut().unwrap() {
        i["confirmed"] = true.into();
    }
    std::fs::write(signoff, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

/// Sign-off path `learn` writes by default.
fn signoff_of(profile: &Path) -> PathBuf {
    PathBuf::from(format!("{}.signoff.json", profile.display()))
}

/// Confirm the learned sign-off and lock.
fn lock_learned(profile: &Path, out: &Path) -> Output {
    confirm(&signoff_of(profile));
    run(&[
        "lock",
        "--platform",
        "ugv-test",
        "--profile-version",
        "1",
        "--in",
        s(profile),
        "--signoff",
        s(&signoff_of(profile)),
        "--out",
        s(out),
    ])
}

/// Build a conservative sign-off with the `signoff` subcommand, confirm, lock.
fn lock_any(profile: &Path, out: &Path) -> Output {
    let so = PathBuf::from(format!("{}.so.json", out.display()));
    let _ = std::fs::remove_file(&so);
    let o = run(&["signoff", "--in", s(profile), "--out", s(&so)]);
    if code(&o) != 0 {
        return o;
    }
    confirm(&so);
    run(&[
        "lock",
        "--platform",
        "ugv-test",
        "--profile-version",
        "1",
        "--in",
        s(profile),
        "--signoff",
        s(&so),
        "--out",
        s(out),
    ])
}

fn learn_clean(dir: &Path, name: &str) -> PathBuf {
    let out = dir.join(name);
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "ugv-demo-synthetic",
        "--out",
        s(&out),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    out
}

#[test]
fn demo_learn_lock_check_clean_then_rogue() {
    let d = tmpdir("demo");
    let profile = learn_clean(&d, "profile.json");
    let p: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&profile).unwrap()).unwrap();
    assert_eq!(p["locked"], false);
    assert_eq!(p["participants"].as_array().unwrap().len(), 4);

    let locked = d.join("locked.json");
    // Unconfirmed sign-off: refused.
    let o = run(&[
        "lock",
        "--platform",
        "ugv-test",
        "--profile-version",
        "1",
        "--in",
        s(&profile),
        "--signoff",
        s(&signoff_of(&profile)),
        "--out",
        s(&locked),
    ]);
    assert_eq!(code(&o), 1);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("not confirmed by the operator: motion_writer:/cmd_vel"),
        "{err}"
    );
    assert!(!locked.exists());
    let o = lock_learned(&profile, &locked);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));

    // Sprint 3 demo: clean re-run -> zero deviations.
    let o = run(&[
        "check",
        "--profile",
        s(&locked),
        "--events",
        s(&example("clean-run.jsonl")),
    ]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(code(&o), 0, "{out}");
    assert!(out.contains("0 deviation(s)"), "{out}");
    assert!(!out.contains("NOT locked"));

    // With --learn-readers (reader enforcement on) the clean run is still clean.
    let pr = d.join("pr.json");
    let lr = d.join("lr.json");
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "ugv-demo-synthetic",
        "--learn-readers",
        "--out",
        s(&pr),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0);
    assert_eq!(code(&lock_learned(&pr, &lr)), 0);
    let o = run(&[
        "check",
        "--profile",
        s(&lr),
        "--events",
        s(&example("clean-run.jsonl")),
    ]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pr).unwrap()).unwrap();
    assert_eq!(v["reader_topics"].as_array().unwrap().len(), 6);
    assert_eq!(v["services"].as_array().unwrap().len(), 25);
    assert_eq!(v["actions"][0], "/navigate_to_pose");
    assert_eq!(v["raw_dds_topics"][0], "ros_discovery_info");

    // Rogue participant -> deviations, nonzero exit.
    let o = run(&[
        "check",
        "--profile",
        s(&locked),
        "--events",
        s(&example("rogue-participant.jsonl")),
    ]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(code(&o), 1, "{out}");
    assert!(out.contains("robot.ros2.unknown_participant"), "{out}");
    assert!(
        out.contains("robot.ros2.unauthorized_motion_writer"),
        "{out}"
    );

    // JSON output is machine-readable.
    let o = run(&[
        "check",
        "--json",
        "--profile",
        s(&locked),
        "--events",
        s(&example("rogue-participant.jsonl")),
    ]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["deviations_total"], 2);
}

#[test]
fn learn_is_byte_identical_across_runs() {
    let d = tmpdir("determinism");
    let mut outs = Vec::new();
    for i in 0..2 {
        let prof = d.join(format!("p{i}.json"));
        let rep = d.join("report.json");
        let rep_i = d.join(format!("r{i}.json"));
        let o = run(&[
            "learn",
            "--events",
            s(&example("clean-run.jsonl")),
            "--model",
            "m",
            "--out",
            s(&prof),
            "--report",
            s(&rep),
            "--quiet",
        ]);
        assert_eq!(code(&o), 0);
        std::fs::rename(&rep, &rep_i).unwrap();
        outs.push((
            std::fs::read(&prof).unwrap(),
            std::fs::read(&rep_i).unwrap(),
        ));
    }
    assert_eq!(outs[0].0, outs[1].0);
    assert_eq!(outs[0].1, outs[1].1);
    let r: serde_json::Value = serde_json::from_slice(&outs[0].1).unwrap();
    assert_eq!(r["anomalies_total"], 0);
    assert!(r["motion_channels"]["/cmd_vel"]["linear"]["p99"].is_number());
}

#[test]
fn learn_respects_margin_and_ceilings() {
    let d = tmpdir("ceiling");
    let out = d.join("p.json");
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model=m",
        "--margin",
        "1.0",
        "--ceiling-linear",
        "1.0",
        "--ceiling-joint=5",
        "--out",
        s(&out),
    ]);
    assert_eq!(code(&o), 0);
    let p: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(p["motion_envelopes"]["/cmd_vel"]["max_linear_speed"], 1.0);
    assert_eq!(
        p["motion_envelopes"]["/mast/pan_tilt_cmd"]["max_joint_speed"],
        0.749
    );
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("observed_exceeds_ceiling"), "{text}");
}

#[test]
fn learn_multiple_runs_merges() {
    let d = tmpdir("multi");
    let out = d.join("p.json");
    let rep = d.join("r.json");
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--events",
        s(&example("rogue-participant.jsonl")),
        "--model",
        "m",
        "--out",
        s(&out),
        "--report",
        s(&rep),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0);
    let p: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    // The rogue announced once: quarantined, not learned.
    assert_eq!(p["participants"].as_array().unwrap().len(), 4);
    let r: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&rep).unwrap()).unwrap();
    assert_eq!(r["runs"].as_array().unwrap().len(), 2);
    assert_eq!(
        r["participants"]["0f0f0f0f0f0f0f0f0f0f0f0f"]["status"],
        "quarantined"
    );
    let warned = |code: &str| {
        r["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == code)
    };
    assert!(warned("participant_seen_once"));
    assert!(warned("quarantined_participant"));
}

#[test]
fn lock_refuses_bad_profiles_and_relock() {
    let d = tmpdir("lock");
    let empty = d.join("empty.json");
    write_profile(&empty, serde_json::json!({}));
    let out = d.join("locked.json");
    let o = lock_any(&empty, &out);
    assert_eq!(code(&o), 1);
    assert!(String::from_utf8_lossy(&o.stderr).contains("no participants"));
    assert!(!out.exists());

    let noenv = d.join("noenv.json");
    write_profile(
        &noenv,
        serde_json::json!({"participants":["aaaaaaaaaaaaaaaaaaaaaaaa"],"writer_topics":["/cmd_vel"],
           "motion_envelopes":{"/cmd_vel":{"max_linear_speed":null,"max_joint_speed":null}}}),
    );
    let o = lock_any(&noenv, &out);
    assert_eq!(code(&o), 1);
    assert!(String::from_utf8_lossy(&o.stderr).contains("/cmd_vel has no envelope"));

    let good = learn_clean(&d, "p.json");
    assert_eq!(code(&lock_learned(&good, &out)), 0);
    let o = run(&[
        "lock",
        "--platform",
        "ugv-test",
        "--profile-version",
        "1",
        "--in",
        s(&out),
        "--signoff",
        s(&signoff_of(&good)),
        "--out",
        s(&d.join("again.json")),
    ]);
    assert_eq!(code(&o), 1);
    assert!(String::from_utf8_lossy(&o.stderr).contains("already locked"));
    // The signoff subcommand refuses a locked profile.
    let o = run(&["signoff", "--in", s(&out), "--out", s(&d.join("x.json"))]);
    assert_eq!(code(&o), 2);
}

#[test]
fn diff_exit_codes_and_output() {
    let d = tmpdir("diff");
    let a = learn_clean(&d, "a.json");
    let b = learn_clean(&d, "b.json");
    let o = run(&["diff", s(&a), s(&b)]);
    assert_eq!(code(&o), 0);
    assert!(String::from_utf8_lossy(&o.stdout).contains("identical"));

    // The rogue run learns the same profile (rogue quarantined)...
    let c0 = d.join("c0.json");
    let o = run(&[
        "learn",
        "--events",
        s(&example("rogue-participant.jsonl")),
        "--model",
        "ugv-demo-synthetic",
        "--out",
        s(&c0),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0);
    assert_eq!(code(&run(&["diff", s(&a), s(&c0)])), 0);
    // ... unless the operator explicitly accepts it.
    let c = d.join("c.json");
    let o = run(&[
        "learn",
        "--events",
        s(&example("rogue-participant.jsonl")),
        "--model",
        "ugv-demo-synthetic",
        "--accept-participant",
        "0f0f0f0f0f0f0f0f0f0f0f0f",
        "--out",
        s(&c),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0);
    let so = std::fs::read_to_string(signoff_of(&c)).unwrap();
    assert!(
        so.contains("participant_operator_accepted:0f0f0f0f0f0f0f0f0f0f0f0f"),
        "{so}"
    );
    assert!(
        so.contains("motion_writer:/cmd_vel 0f0f0f0f0f0f0f0f0f0f0f0f"),
        "{so}"
    );
    let o = run(&["diff", s(&a), s(&c)]);
    assert_eq!(code(&o), 1);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("+ participant 0f0f0f0f0f0f0f0f0f0f0f0f   [LOOSENS]"),
        "{out}"
    );
    let o = run(&["diff", "--json", s(&a), s(&c)]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["participants_added"][0], "0f0f0f0f0f0f0f0f0f0f0f0f");
}

#[test]
fn merge_subcommand() {
    let d = tmpdir("merge");
    let a = learn_clean(&d, "a.json");
    let b = d.join("b.json");
    write_profile(
        &b,
        serde_json::json!({"model":"ugv-demo-synthetic","participants":["bbbbbbbbbbbbbbbbbbbbbbbb"],
           "writer_topics":["/x", "/cmd_vel"],
           "motion_envelopes":{"/cmd_vel":{"max_linear_speed":9.0,"max_joint_speed":null}}}),
    );
    let m = d.join("m.json");
    let o = run(&["merge", "--out", s(&m), s(&a), s(&b)]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("signoff --in"));
    let p: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&m).unwrap()).unwrap();
    assert_eq!(p["participants"].as_array().unwrap().len(), 5);
    assert_eq!(p["motion_envelopes"]["/cmd_vel"]["max_linear_speed"], 9.0);
    assert_eq!(p["locked"], false);
    // The learned sign-off of `a` does not cover the merged draft...
    let o = run(&[
        "lock",
        "--platform",
        "ugv-test",
        "--profile-version",
        "1",
        "--in",
        s(&m),
        "--signoff",
        s(&signoff_of(&a)),
        "--out",
        s(&d.join("ml.json")),
    ]);
    assert_eq!(code(&o), 1);
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not belong to this draft"));
    // ... a conservative one does, once every participant is confirmed.
    assert_eq!(code(&lock_any(&m, &d.join("ml.json"))), 0);

    let other = d.join("o.json");
    write_profile(&other, serde_json::json!({"model":"different"}));
    let o = run(&["merge", "--force", "--out", s(&m), s(&a), s(&other)]);
    assert_eq!(code(&o), 2);
    // Merging into an existing file without --force: refused.
    let o = run(&["merge", "--out", s(&m), s(&a), s(&b)]);
    assert_eq!(code(&o), 2);
    assert!(String::from_utf8_lossy(&o.stderr).contains("refusing to overwrite"));
}

#[test]
fn usage_and_input_errors_exit_2() {
    let d = tmpdir("errors");
    let out = d.join("p.json");
    let cases: Vec<Vec<String>> = vec![
        vec![],
        vec!["frobnicate".into()],
        vec!["learn".into(), "--out".into(), s(&out).into()],
        vec!["learn".into(), "--events".into()],
        vec![
            "learn".into(),
            "--events".into(),
            "/nonexistent/x.jsonl".into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec![
            "learn".into(),
            "--events".into(),
            s(&example("clean-run.jsonl")).into(),
            "--margin".into(),
            "0.5".into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec![
            "learn".into(),
            "--events".into(),
            s(&example("clean-run.jsonl")).into(),
            "--margin".into(),
            "NaN".into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec![
            "learn".into(),
            "--events".into(),
            s(&example("clean-run.jsonl")).into(),
            "--ceiling-linear".into(),
            "fast".into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec![
            "learn".into(),
            "--bogus".into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec![
            "learn".into(),
            "--pcap".into(),
            "/nonexistent/x.pcap".into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec![
            "learn".into(),
            "--pcap".into(),
            s(&example("clean-run.jsonl")).into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec!["diff".into(), "only-one.json".into()],
        vec![
            "check".into(),
            "--profile".into(),
            "/nonexistent.json".into(),
        ],
        vec![
            "lock".into(),
            "--in".into(),
            "a".into(),
            "--in".into(),
            "b".into(),
        ],
        // lock without --signoff
        vec![
            "lock".into(),
            "--in".into(),
            s(&example("clean-run.jsonl")).into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec![
            "learn".into(),
            "--events".into(),
            s(&example("clean-run.jsonl")).into(),
            "--hard-cap-linear".into(),
            "inf".into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec![
            "learn".into(),
            "--events".into(),
            s(&example("clean-run.jsonl")).into(),
            "--accept-participant".into(),
            "not-a-guid".into(),
            "--out".into(),
            s(&out).into(),
        ],
        vec![
            "learn".into(),
            "--events".into(),
            s(&example("clean-run.jsonl")).into(),
            "--min-duration".into(),
            "-1".into(),
            "--out".into(),
            s(&out).into(),
        ],
    ];
    for c in cases {
        let o = Command::new(BIN).args(&c).output().unwrap();
        assert_eq!(
            code(&o),
            2,
            "args {c:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    assert!(!out.exists(), "no profile may be written on error");
}

#[test]
fn malformed_events_file_is_rejected_with_line() {
    let d = tmpdir("malformed");
    let bad = d.join("bad.jsonl");
    std::fs::write(
        &bad,
        "{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"aaaaaaaaaaaaaaaaaaaaaaaa\",\"src_ip\":\"1.2.3.4\"}\nnot json\n",
    )
    .unwrap();
    let out = d.join("p.json");
    let o = run(&["learn", "--events", s(&bad), "--out", s(&out)]);
    assert_eq!(code(&o), 2);
    assert!(String::from_utf8_lossy(&o.stderr).contains("bad.jsonl:2"));
    assert!(!out.exists());

    let p = d.join("p.json");
    std::fs::write(&p, "{not a profile").unwrap();
    let so = d.join("so.json");
    std::fs::write(&so, "{}").unwrap();
    let o = run(&[
        "lock",
        "--platform",
        "ugv-test",
        "--profile-version",
        "1",
        "--in",
        s(&p),
        "--signoff",
        s(&so),
        "--out",
        s(&d.join("l.json")),
    ]);
    assert_eq!(code(&o), 2);
}

#[test]
fn help_and_version() {
    let o = run(&["--help"]);
    assert_eq!(code(&o), 0);
    assert!(String::from_utf8_lossy(&o.stdout).contains("learn"));
    let o = run(&["--version"]);
    assert_eq!(code(&o), 0);
}

#[test]
fn learn_from_pcap_then_lock_and_check_it() {
    let d = tmpdir("pcap");
    let cap = d.join("discovery.pcap");
    std::fs::write(&cap, common::pcap(&common::talker_listener(false))).unwrap();
    let prof = d.join("p.json");
    let rep = d.join("r.json");
    let o = run(&[
        "learn",
        "--pcap",
        s(&cap),
        "--model",
        "talker-listener",
        "--out",
        s(&prof),
        "--report",
        s(&rep),
    ]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(stdout.contains("Services (12):"), "{stdout}");
    assert!(stdout.contains("/dock  clients"), "{stdout}");
    assert!(stdout.contains("capture: "), "{stdout}");
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("12 services, 1 actions, 1 raw DDS topics"),
        "{stderr}"
    );

    let p: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&prof).unwrap()).unwrap();
    assert_eq!(p["participants"].as_array().unwrap().len(), 2);
    assert!(p["writer_topics"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("/chatter")));
    assert!(p["services"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("/talker/get_parameters")));
    assert_eq!(p["actions"][0], "/dock");
    assert_eq!(p["raw_dds_topics"][0], "ros_discovery_info");
    assert_eq!(p["reader_topics"].as_array().unwrap().len(), 0);
    let r: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&rep).unwrap()).unwrap();
    assert_eq!(r["runs"][0]["capture"]["discovery_frag_completed"], 1);

    let locked = d.join("locked.json");
    let o = lock_learned(&prof, &locked);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let o = run(&["check", "--profile", s(&locked), "--pcap", s(&cap)]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(code(&o), 0, "{out}");
    assert!(out.contains("0 deviation(s)"), "{out}");

    // --learn-readers turns reader enforcement on; diff shows it tightening.
    let prof_r = d.join("pr.json");
    let o = run(&[
        "learn",
        "--pcap",
        s(&cap),
        "--model",
        "talker-listener",
        "--learn-readers",
        "--out",
        s(&prof_r),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0);
    let o = run(&["diff", s(&prof), s(&prof_r)]);
    assert_eq!(code(&o), 1);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("reader-topic enforcement: off -> on   [tightens]"),
        "{out}"
    );
    assert!(out.contains("+ reader topic /chatter\n"), "{out}");

    // A capture that lost a DATA_FRAG: still learns, but warns loudly.
    let lossy = d.join("lossy.pcap");
    std::fs::write(&lossy, common::pcap(&common::talker_listener(true))).unwrap();
    let o = run(&[
        "learn",
        "--pcap",
        s(&lossy),
        "--model",
        "m",
        "--out",
        s(&d.join("l.json")),
    ]);
    assert_eq!(code(&o), 0);
    assert!(String::from_utf8_lossy(&o.stdout).contains("fragmented_discovery_unreassembled"));
}

#[test]
fn lock_and_check_refuse_invalid_profiles() {
    let d = tmpdir("invalid");
    let bad = d.join("bad.json");
    write_profile(
        &bad,
        serde_json::json!({"participants":["aaaaaaaaaaaaaaaaaaaaaaaa"],"writer_topics":["rt/cmd_vel"],
           "services":["get_parameters"]}),
    );
    let out = d.join("locked.json");
    let o = lock_any(&bad, &out);
    assert_eq!(code(&o), 1);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("writer_topics entry \"rt/cmd_vel\""), "{err}");
    assert!(err.contains("services entry \"get_parameters\""), "{err}");
    assert!(!out.exists());
    let o = run(&[
        "check",
        "--profile",
        s(&bad),
        "--events",
        s(&example("clean-run.jsonl")),
    ]);
    assert_eq!(code(&o), 2);
    assert!(String::from_utf8_lossy(&o.stderr).contains("fails validation"));
}

#[test]
fn learn_from_a_zenoh_capture_warns_loudly_on_stderr() {
    // A real rmw_zenoh_cpp robot (fixtures/captures/ros2-jazzy): no RTPS at
    // all. The learner must not present it as a quiet bus.
    let d = tmpdir("zenoh");
    let pcap = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/captures/ros2-jazzy/zenoh_baseline.pcap");
    let o = run(&[
        "learn",
        "--pcap",
        s(&pcap),
        "--model",
        "m",
        "--out",
        s(&d.join("z.json")),
    ]);
    assert_eq!(code(&o), 0);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("robodr-commission: WARNING:") && err.contains("Zenoh"),
        "{err}"
    );
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("unsupported_middleware"), "{out}");
}
