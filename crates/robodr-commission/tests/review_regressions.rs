//! Regression tests for the security review of robodr-commission:
//! learning-time poisoning, memory under flood, hostile captures, CLI path
//! handling, lock/validate/seal semantics and envelope hard caps.

mod common;

use common::*;
use robodr_capture::{LinkType, PcapWriter};
use robodr_commission::input::read_all;
use robodr_commission::{
    lock, lock_draft_text, parse_profile_text, sealed_text, to_json, Checker, EventSource,
    InputError, LearnConfig, Learner, LockRefusal, ParticipantStatus, PcapSource, ProfileFileError,
    Signoff, VecSource,
};
use robodr_events::graph::{Endpoint, Participant};
use robodr_events::profile::Profile;
use robodr_events::{MotionCommand, RobotEvent};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-commission");

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-commission-review-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("run binary")
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn cfg(model: &str) -> LearnConfig {
    LearnConfig {
        model: model.into(),
        ..Default::default()
    }
}

fn learn_cli(dir: &Path, name: &str) -> PathBuf {
    let out = dir.join(name);
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "ugv",
        "--out",
        s(&out),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    out
}

fn signoff_path(p: &Path) -> PathBuf {
    PathBuf::from(format!("{}.signoff.json", p.display()))
}

fn confirm(path: &Path) {
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["operator"] = "Reviewer".into();
    for i in v["items"].as_array_mut().unwrap() {
        i["confirmed"] = true.into();
    }
    std::fs::write(path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

fn lock_cli(draft: &Path, signoff: &Path, out: &Path) -> Output {
    run(&[
        "lock",
        "--in",
        s(draft),
        "--signoff",
        s(signoff),
        "--out",
        s(out),
    ])
}

/// Learn + confirm + lock the clean example; returns the locked path.
fn locked_cli(dir: &Path) -> PathBuf {
    let p = learn_cli(dir, "draft.json");
    confirm(&signoff_path(&p));
    let out = dir.join("locked.json");
    let o = lock_cli(&p, &signoff_path(&p), &out);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    out
}

fn check_cli(profile: &Path) -> Output {
    run(&[
        "check",
        "--profile",
        s(profile),
        "--events",
        s(&example("clean-run.jsonl")),
    ])
}

// ------------------------------------------------------------ poisoning --

/// A pcap with explicit per-frame timestamps (seconds).
fn pcap_at(frames: &[(f64, Vec<u8>)]) -> Vec<u8> {
    let mut wr = PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).unwrap();
    for (t, f) in frames {
        wr.write_packet(
            Duration::from_secs(1_760_000_000) + Duration::from_secs_f64(*t),
            f,
            f.len() as u32,
        )
        .unwrap();
    }
    wr.into_inner()
}

fn learn_pcap(bytes: &[u8], c: LearnConfig) -> Learner {
    let mut l = Learner::new(c).unwrap();
    l.ingest(&mut PcapSource::new("mem.pcap", bytes).unwrap())
        .unwrap();
    l
}

#[test]
fn intruder_in_capture_is_quarantined_by_count_and_by_duration() {
    let intruder = Ipv4Addr::new(10, 42, 0, 66);
    let (once, burst) = (prefix(0xe1), prefix(0xe2));
    let mut frames: Vec<(f64, Vec<u8>)> = talker_listener(false)
        .into_iter()
        .enumerate()
        .map(|(i, f)| (i as f64, f))
        .collect();
    let end = frames.len() as f64;
    // Intruder 1: a single datagram writing /cmd_vel.
    for f in common::frames(intruder, &announce(once, &["W rt/cmd_vel".into()])) {
        frames.push((end / 2.0, f));
    }
    // Intruder 2: ten datagrams within one second near the end, writing
    // /cmd_vel and an exfiltration topic.
    let specs: Vec<String> = (0..10)
        .map(|i| {
            if i == 0 {
                "W rt/cmd_vel".into()
            } else {
                format!("W rt/exfil{i}")
            }
        })
        .collect();
    for (i, f) in common::frames(intruder, &announce(burst, &specs))
        .into_iter()
        .enumerate()
    {
        frames.push((end + 0.1 * i as f64, f));
    }
    // Keep the legit nodes alive to the end (periodic SPDP).
    frames.extend(
        common::frames(TALKER, &announce(prefix(0xa1), &["W rt/rosout".into()]))
            .into_iter()
            .map(|f| (end + 2.0, f)),
    );
    let bytes = pcap_at(&frames);
    let l = learn_pcap(&bytes, cfg("talker-listener"));
    let out = l.finish();
    let p = &out.profile;
    let r = &out.report;
    assert!(!p.participants.contains(&hex(once)), "{r}");
    assert!(!p.participants.contains(&hex(burst)), "{r}");
    assert!(p.participants.contains(&hex(prefix(0xa1))), "{r}");
    assert!(p.participants.contains(&hex(prefix(0xb2))), "{r}");
    assert!(!p.writer_topics.iter().any(|t| t.starts_with("/exfil")));
    assert_eq!(
        r.participants[&hex(once)].status,
        ParticipantStatus::Quarantined
    );
    let why = &r.participants[&hex(burst)].quarantine_reasons;
    assert!(why.iter().any(|w| w.contains("observed for")), "{why:?}");
    assert!(r.participants[&hex(burst)].announcements >= 10);

    // Locked from this capture, a later run flags both intruders.
    let locked = lock(p, &out.signoff.clone().confirm_all("op")).unwrap();
    let mut chk = Checker::new(&locked);
    chk.ingest(&mut PcapSource::new("again.pcap", &bytes[..]).unwrap())
        .unwrap();
    let rep = chk.finish();
    let flagged: std::collections::BTreeSet<String> = rep
        .findings
        .iter()
        .filter(|f| f.deviation.rule == "robot.ros2.unknown_participant")
        .map(|f| f.deviation.detail.clone())
        .filter(|d| d.contains(&hex(once)) || d.contains(&hex(burst)))
        .map(|d| d.split_whitespace().nth(3).unwrap_or_default().to_string())
        .collect();
    assert_eq!(flagged.len(), 2, "{rep}");
    assert!(rep.by_rule["robot.ros2.unknown_writer_topic"] >= 2, "{rep}");
}

#[test]
fn signoff_lists_motion_writers_and_lock_requires_every_confirmation() {
    let l = learn_pcap(&pcap(&talker_listener(false)), cfg("tl"));
    let out = l.finish();
    // The listener joins halfway through the synthetic capture: flagged.
    let li = hex(prefix(0xb2));
    assert!(out
        .signoff
        .items
        .iter()
        .any(|i| i.id == format!("participant_late:{li}")));
    // Refused until every item is confirmed, one by one.
    let mut so = out.signoff.clone();
    so.operator = "op".into();
    for k in 0..so.items.len() {
        let why = lock(&out.profile, &so).unwrap_err();
        assert_eq!(why.len(), so.items.len() - k, "{why:?}");
        so.items[k].confirmed = true;
    }
    assert!(lock(&out.profile, &so).unwrap().locked);
}

#[test]
fn injected_fast_motion_never_widens_envelope_past_cap() {
    let a = "aaaaaaaaaaaaaaaaaaaaaaaa";
    let part = || {
        RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: a.into(),
            src_ip: "10.0.0.1".into(),
            locators: vec![],
        })
    };
    let mv = |v: f64| {
        RobotEvent::MotionCommand(MotionCommand {
            channel: "/cmd_vel".into(),
            source_guid: Some(a.into()),
            linear_speed: Some(v),
            joint_speed: Some(v),
            angular_speed: None,
        })
    };
    let writer = RobotEvent::Ros2WriterDiscovered(Endpoint {
        guid_prefix: a.into(),
        topic: "rt/cmd_vel".into(),
        type_name: "geometry_msgs::msg::dds_::Twist_".into(),
    });
    let mut evs = vec![part(), part(), writer];
    evs.extend((0..50).map(|i| mv(0.01 * f64::from(i))));
    for v in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -3.0,
        1e308,
        f64::MAX,
    ] {
        evs.push(mv(v));
    }
    evs.push(part());
    let mut c = cfg("m");
    c.hard_cap_linear = 1.5;
    c.hard_cap_joint = 0.75;
    let mut l = Learner::new(c).unwrap();
    l.ingest(&mut VecSource::new("v", evs)).unwrap();
    let out = l.finish();
    let env = &out.profile.motion_envelopes["/cmd_vel"];
    assert_eq!(env.max_linear_speed, Some(1.5));
    assert_eq!(env.max_joint_speed, Some(0.75));
    assert_eq!(out.profile.validate(), Ok(()));
    // NaN/inf/negative are anomalies, never samples.
    let kinds: Vec<&str> = out
        .report
        .anomalies
        .iter()
        .map(|a| a.kind.as_str())
        .collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| k.starts_with("non_finite") || k.starts_with("negative"))
            .count(),
        8,
        "{kinds:?}"
    );
    // The report is valid JSON (no NaN leaks) and says the cap held.
    let j = serde_json::to_string(&out.report).unwrap();
    let back: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert!(back["motion_channels"]["/cmd_vel"]["linear"]["max"].is_number());
    assert!(out
        .signoff
        .items
        .iter()
        .any(|i| i.id == "observed_exceeds_cap:/cmd_vel linear"));
}

#[test]
fn hard_cap_flag_applies_through_the_cli() {
    let d = tmpdir("cap");
    let out = d.join("p.json");
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "m",
        "--hard-cap-linear",
        "0.2",
        "--ceiling-linear",
        "5",
        "--out",
        s(&out),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let p = parse_profile_text(&std::fs::read_to_string(&out).unwrap()).unwrap();
    for env in p.motion_envelopes.values() {
        if let Some(v) = env.max_linear_speed {
            assert!(v <= 0.2, "{v}");
        }
    }
}

// --------------------------------------------------------------- flood ---

#[test]
fn discovery_flood_is_bounded_in_memory_and_output() {
    let d = tmpdir("flood");
    let f = d.join("flood.jsonl");
    let mut text = String::new();
    for i in 0..20_000u32 {
        text.push_str(&format!(
            "{{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"{i:024x}\",\"src_ip\":\"10.9.{}.{}\"}}\n",
            i / 250 % 250,
            i % 250
        ));
        text.push_str(&format!(
            "{{\"kind\":\"ros2_writer_discovered\",\"guid_prefix\":\"{i:024x}\",\"topic\":\"rt/flood{i}\",\"type_name\":\"\"}}\n"
        ));
    }
    std::fs::write(&f, text).unwrap();
    let out = d.join("p.json");
    let rep = d.join("r.json");
    let t0 = Instant::now();
    let o = run(&[
        "learn",
        "--events",
        s(&f),
        "--model",
        "m",
        "--out",
        s(&out),
        "--report",
        s(&rep),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(t0.elapsed() < Duration::from_secs(60));
    let r: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&rep).unwrap()).unwrap();
    assert!(r["participants"].as_object().unwrap().len() <= 4096);
    assert!(r["overflow"]["participants"].as_u64().unwrap() > 0);
    // Report size is bounded (no per-entry warning explosion).
    assert!(std::fs::metadata(&rep).unwrap().len() < 64 << 20);
    let so = std::fs::read_to_string(signoff_path(&out)).unwrap();
    assert!(so.contains("capacity_exceeded:participants"), "{so}");
    // Each flood GUID announced once: none learned.
    let p = parse_profile_text(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(p.participants.is_empty());
    assert!(p.writer_topics.is_empty());
}

// ------------------------------------------------------- hostile pcaps ---

fn pcap_header(linktype: u32) -> Vec<u8> {
    let mut v = 0xa1b2_c3d4u32.to_le_bytes().to_vec();
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&[0; 8]);
    v.extend_from_slice(&65535u32.to_le_bytes());
    v.extend_from_slice(&linktype.to_le_bytes());
    v
}

fn ng_block(out: &mut Vec<u8>, t: u32, body: &[u8]) {
    let mut body = body.to_vec();
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let len = (12 + body.len()) as u32;
    out.extend_from_slice(&t.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&len.to_le_bytes());
}

fn ng_shb() -> Vec<u8> {
    let mut out = Vec::new();
    let mut shb = 0x1a2b_3c4du32.to_le_bytes().to_vec();
    shb.extend_from_slice(&[1, 0, 0, 0]);
    shb.extend_from_slice(&[0xff; 8]);
    ng_block(&mut out, 0x0a0d_0d0a, &shb);
    out
}

fn ng_idb(out: &mut Vec<u8>, linktype: u16) {
    let mut idb = linktype.to_le_bytes().to_vec();
    idb.extend_from_slice(&[0, 0]);
    idb.extend_from_slice(&0u32.to_le_bytes());
    ng_block(out, 1, &idb);
}

fn ng_epb(out: &mut Vec<u8>, iface: u32, f: &[u8]) {
    let mut epb = iface.to_le_bytes().to_vec();
    epb.extend_from_slice(&[0; 8]);
    epb.extend_from_slice(&(f.len() as u32).to_le_bytes());
    epb.extend_from_slice(&(f.len() as u32).to_le_bytes());
    epb.extend_from_slice(f);
    ng_block(out, 6, &epb);
}

fn drain(bytes: &[u8]) -> Result<(Vec<RobotEvent>, Learner), InputError> {
    let mut src = PcapSource::new("h.pcap", bytes)?;
    let mut l = Learner::new(cfg("m")).unwrap();
    l.ingest(&mut src)?;
    let evs = read_all(&mut PcapSource::new("h.pcap", bytes)?)?
        .into_iter()
        .map(|e| e.event)
        .collect();
    Ok((evs, l))
}

#[test]
fn wrong_linktype_capture_is_refused_not_learned_empty() {
    // Classic pcap, link type USER0 (147), carrying perfectly good frames.
    let mut bytes = pcap_header(147);
    for f in talker_listener(false) {
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(f.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(f.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&f);
    }
    let e = drain(&bytes).expect_err("refused");
    assert!(matches!(e, InputError::Capture { .. }), "{e}");
    assert!(e.to_string().contains("supported link type"), "{e}");

    // Mixed pcapng: one good Ethernet interface, one unsupported. Learns
    // from the good one and warns about the rest.
    let mut ng = ng_shb();
    ng_idb(&mut ng, 1);
    ng_idb(&mut ng, 147);
    for f in talker_listener(false) {
        ng_epb(&mut ng, 0, &f);
        ng_epb(&mut ng, 1, &f);
    }
    let (_, l) = drain(&ng).unwrap();
    let r = l.report();
    assert!(
        r.warnings.iter().any(|w| w.code == "undecodable_frames"),
        "{r}"
    );
    assert_eq!(l.profile().participants.len(), 2);

    // A capture with no frames at all: learns nothing, warns.
    let (evs, l) = drain(&pcap_header(1)).unwrap();
    assert!(evs.is_empty());
    assert!(l
        .report()
        .warnings
        .iter()
        .any(|w| w.code == "empty_capture"));
}

#[test]
fn huge_lengths_and_truncation_fail_fast_without_allocation() {
    // Classic pcap record claiming ~4 GiB.
    let mut b = pcap_header(1);
    b.extend_from_slice(&[0; 8]);
    b.extend_from_slice(&0xffff_fff0u32.to_le_bytes());
    b.extend_from_slice(&0xffff_fff0u32.to_le_bytes());
    b.extend_from_slice(&[0; 64]);
    let t0 = Instant::now();
    let e = drain(&b).expect_err("refused");
    assert!(matches!(e, InputError::Capture { .. }), "{e}");
    assert!(t0.elapsed() < Duration::from_secs(5));

    // pcapng block length ~2 GiB.
    let mut ng = ng_shb();
    ng.extend_from_slice(&6u32.to_le_bytes());
    ng.extend_from_slice(&0x7fff_fffcu32.to_le_bytes());
    ng.extend_from_slice(&[0; 32]);
    assert!(drain(&ng).is_err());

    // pcapng EPB whose captured length exceeds its block.
    let mut ng = ng_shb();
    ng_idb(&mut ng, 1);
    let mut epb = 0u32.to_le_bytes().to_vec();
    epb.extend_from_slice(&[0; 8]);
    epb.extend_from_slice(&0x0010_0000u32.to_le_bytes());
    epb.extend_from_slice(&0x0010_0000u32.to_le_bytes());
    epb.extend_from_slice(&[0; 16]);
    ng_block(&mut ng, 6, &epb);
    assert!(drain(&ng).is_err());

    // Every truncation of a good capture: error or clean end, never panic.
    let good = pcap(&talker_listener(false));
    for cut in (0..good.len()).step_by(7) {
        match PcapSource::new("t.pcap", &good[..cut]) {
            Err(_) => {}
            Ok(mut src) => {
                let mut n = 0;
                while let Some(r) = src.next_event() {
                    n += 1;
                    assert!(n < 10_000);
                    if r.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

#[test]
fn truncated_capture_aborts_learn_and_writes_nothing() {
    let d = tmpdir("trunc");
    let cap = d.join("t.pcap");
    let mut bytes = pcap(&talker_listener(false));
    bytes.truncate(bytes.len() - 5);
    std::fs::write(&cap, bytes).unwrap();
    let out = d.join("p.json");
    let rep = d.join("r.json");
    let o = run(&[
        "learn",
        "--pcap",
        s(&cap),
        "--model",
        "m",
        "--out",
        s(&out),
        "--report",
        s(&rep),
    ]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(!out.exists() && !rep.exists() && !signoff_path(&out).exists());
    // No temp files left behind either.
    let left: Vec<_> = std::fs::read_dir(&d).unwrap().collect();
    assert_eq!(left.len(), 1);
}

// --------------------------------------------------------- CLI paths -----

#[cfg(unix)]
#[test]
fn outputs_never_follow_symlinks() {
    let d = tmpdir("symlink");
    let victim = d.join("victim.txt");
    std::fs::write(&victim, "precious").unwrap();
    let link = d.join("out.json");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let clean = example("clean-run.jsonl");
    for force in [false, true] {
        let mut args = vec![
            "learn",
            "--events",
            s(&clean),
            "--model",
            "m",
            "--out",
            s(&link),
            "--quiet",
        ];
        if force {
            args.push("--force");
        }
        let o = run(&args);
        assert_eq!(code(&o), 2, "{}", stderr(&o));
        assert!(stderr(&o).contains("symbolic link"), "{}", stderr(&o));
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    }
    // Symlinked sign-off and lock outputs are refused too.
    let draft = learn_cli(&d, "draft.json");
    let so = signoff_path(&draft);
    confirm(&so);
    let lock_link = d.join("locked.json");
    std::os::unix::fs::symlink(&victim, &lock_link).unwrap();
    let o = lock_cli(&draft, &so, &lock_link);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    let so_link = d.join("so-link.json");
    std::os::unix::fs::symlink(&victim, &so_link).unwrap();
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "m",
        "--out",
        s(&d.join("p2.json")),
        "--signoff",
        s(&so_link),
        "--quiet",
    ]);
    assert_eq!(code(&o), 2);
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
}

#[test]
fn outputs_do_not_clobber_and_must_differ_from_inputs() {
    let d = tmpdir("clobber");
    let p = learn_cli(&d, "p.json");
    let before = std::fs::read(&p).unwrap();
    // Same output again: refused without --force.
    let o = run(&[
        "learn",
        "--events",
        s(&example("rogue-participant.jsonl")),
        "--model",
        "m",
        "--out",
        s(&p),
        "--quiet",
    ]);
    assert_eq!(code(&o), 2);
    assert!(
        stderr(&o).contains("refusing to overwrite"),
        "{}",
        stderr(&o)
    );
    assert_eq!(std::fs::read(&p).unwrap(), before);
    // With --force it is replaced (atomically).
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "other",
        "--out",
        s(&p),
        "--quiet",
        "--force",
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(std::fs::read_to_string(&p).unwrap().contains("\"other\""));

    // Output naming an input, even with --force: refused before reading.
    let input = d.join("run.jsonl");
    std::fs::copy(example("clean-run.jsonl"), &input).unwrap();
    let o = run(&[
        "learn",
        "--events",
        s(&input),
        "--model",
        "m",
        "--out",
        s(&d.join(".").join("run.jsonl")),
        "--force",
    ]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("same file"), "{}", stderr(&o));
    assert_eq!(
        std::fs::read(&input).unwrap(),
        std::fs::read(example("clean-run.jsonl")).unwrap()
    );
    // --report equal to --out.
    let o = run(&[
        "learn",
        "--events",
        s(&input),
        "--model",
        "m",
        "--out",
        s(&d.join("x.json")),
        "--report",
        s(&d.join("x.json")),
    ]);
    assert_eq!(code(&o), 2);
    // lock --out == --in.
    let so = signoff_path(&p);
    let o = lock_cli(&p, &so, &p);
    assert_eq!(code(&o), 2);
}

#[cfg(unix)]
#[test]
fn non_utf8_argument_is_an_error_not_a_panic() {
    use std::os::unix::ffi::OsStrExt;
    let o = Command::new(BIN)
        .arg("learn")
        .arg("--out")
        .arg(std::ffi::OsStr::from_bytes(b"\xff\xfe.json"))
        .output()
        .unwrap();
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("not valid UTF-8"), "{}", stderr(&o));
}

#[cfg(unix)]
#[test]
fn profile_inputs_must_be_regular_files() {
    let o = run(&[
        "check",
        "--profile",
        "/dev/zero",
        "--events",
        s(&example("clean-run.jsonl")),
    ]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("not a regular file"), "{}", stderr(&o));
}

// ---------------------------------------------- lock / seal / validate ---

#[test]
fn locked_profile_is_sealed_and_edits_are_refused() {
    let d = tmpdir("seal");
    let locked = locked_cli(&d);
    let text = std::fs::read_to_string(&locked).unwrap();
    assert!(text.starts_with("{\n  \"seal\": \"sha256:"), "{text}");
    // The sensor's lenient loader still reads it.
    let p: Profile = serde_json::from_str(&text).unwrap();
    assert!(p.locked);
    assert_eq!(code(&check_cli(&locked)), 0);

    let edits: Vec<(&str, String)> = vec![
        (
            "participant added",
            text.replacen(
                "\"participants\": [\n",
                "\"participants\": [\n    \"0f0f0f0f0f0f0f0f0f0f0f0f\",\n",
                1,
            ),
        ),
        (
            "envelope widened",
            text.replacen("\"max_linear_speed\": ", "\"max_linear_speed\": 9", 1),
        ),
        ("seal removed", {
            let mut lines: Vec<&str> = text.lines().collect();
            lines.remove(1);
            lines.join("\n") + "\n"
        }),
        (
            "unlocked by hand",
            text.replace("\"locked\": true", "\"locked\": false"),
        ),
        ("truncated", text[..text.len() / 2].to_string()),
        (
            "key dropped",
            text.replace("  \"actions\": [\n", "  \"actionz\": [\n"),
        ),
    ];
    for (what, edited) in edits {
        assert_ne!(edited, text, "{what}: edit did not apply");
        let f = d.join("edited.json");
        std::fs::write(&f, &edited).unwrap();
        let o = check_cli(&f);
        assert_eq!(code(&o), 2, "{what}: {}", stderr(&o));
        assert!(parse_profile_text(&edited).is_err(), "{what}");
        // diff and merge refuse it as well.
        assert_eq!(code(&run(&["diff", s(&locked), s(&f)])), 2, "{what}");
        let o = run(&["merge", "--out", s(&d.join("m.json")), s(&f)]);
        assert_eq!(code(&o), 2, "{what}");
    }
}

#[test]
fn draft_edited_after_signoff_needs_a_new_signoff() {
    let d = tmpdir("edit");
    let draft = learn_cli(&d, "draft.json");
    let so = signoff_path(&draft);
    confirm(&so);
    // Operator removes a participant by hand after the list was made.
    let text = std::fs::read_to_string(&draft).unwrap();
    let edited = text.replacen("    \"01103f5a8c2e000000000103\",\n", "", 1);
    assert_ne!(edited, text);
    std::fs::write(&draft, &edited).unwrap();
    let out = d.join("locked.json");
    let o = lock_cli(&draft, &so, &out);
    // Either the edit made the JSON invalid (exit 2) or the sign-off no
    // longer matches (exit 1); never a lock.
    assert_ne!(code(&o), 0, "{}", stderr(&o));
    assert!(!out.exists());

    // A clean hand edit: drop a whole writer topic with valid JSON.
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["writer_topics"].as_array_mut().unwrap().pop();
    std::fs::write(&draft, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let o = lock_cli(&draft, &so, &out);
    assert_eq!(code(&o), 1);
    assert!(
        stderr(&o).contains("does not belong to this draft"),
        "{}",
        stderr(&o)
    );
    // The conservative list for the edited draft works once confirmed.
    let so2 = d.join("so2.json");
    let o = run(&["signoff", "--in", s(&draft), "--out", s(&so2)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = lock_cli(&draft, &so2, &out);
    assert_eq!(code(&o), 1, "unconfirmed conservative list must refuse");
    confirm(&so2);
    let o = lock_cli(&draft, &so2, &out);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

#[test]
fn signoff_file_is_strict() {
    let d = tmpdir("strict-so");
    let draft = learn_cli(&d, "draft.json");
    let so = signoff_path(&draft);
    confirm(&so);
    let text = std::fs::read_to_string(&so).unwrap();
    let out = d.join("locked.json");
    for bad in [
        text.replace("\"confirmed\": true", "\"confirmd\": true"),
        text.replace("\"operator\": \"Reviewer\"", "\"operator\": \"\""),
        text.replace("robodr-commission-signoff/1", "v0"),
        "[]".to_string(),
    ] {
        std::fs::write(&so, &bad).unwrap();
        let o = lock_cli(&draft, &so, &out);
        assert_ne!(code(&o), 0, "{bad}");
        assert!(!out.exists());
    }
}

#[test]
fn library_lock_paths_agree() {
    let mut l = Learner::new(cfg("m")).unwrap();
    l.ingest(&mut robodr_commission::JsonlSource::open(&example("clean-run.jsonl")).unwrap())
        .unwrap();
    let c = l.finish();
    let so = c.signoff.clone().confirm_all("op");
    let text = to_json(&c.profile).unwrap();
    let a = lock(&c.profile, &so).unwrap();
    let b = lock_draft_text(&text, &so).unwrap();
    assert_eq!(a, b);
    // Sealed text round-trips through the strict loader.
    assert_eq!(parse_profile_text(&sealed_text(&a).unwrap()).unwrap(), a);
    // An unsigned conservative list for another profile does not unlock it.
    let mut other = c.profile.clone();
    other.participants.clear();
    let why = lock(&c.profile, &Signoff::for_profile(&other).confirm_all("op")).unwrap_err();
    assert!(why.contains(&LockRefusal::SignoffDigestMismatch));
    // Strict loader errors are typed.
    assert!(matches!(
        parse_profile_text(&to_json(&a).unwrap()).unwrap_err(),
        ProfileFileError::LockedWithoutSeal
    ));
}

#[test]
fn quarantine_does_not_break_clean_endpoint_learning_from_examples() {
    // The bundled clean run passes the default gate untouched.
    let mut l = Learner::new(cfg("m")).unwrap();
    l.ingest(&mut robodr_commission::JsonlSource::open(&example("clean-run.jsonl")).unwrap())
        .unwrap();
    let r = l.report();
    assert!(r
        .participants
        .values()
        .all(|p| p.status == ParticipantStatus::Accepted));
    assert_eq!(l.profile().participants.len(), 4);
    // And the rogue run's intruder is quarantined.
    let mut l = Learner::new(cfg("m")).unwrap();
    l.ingest(
        &mut robodr_commission::JsonlSource::open(&example("rogue-participant.jsonl")).unwrap(),
    )
    .unwrap();
    let r = l.report();
    assert_eq!(
        r.participants["0f0f0f0f0f0f0f0f0f0f0f0f"].status,
        ParticipantStatus::Quarantined
    );
}
