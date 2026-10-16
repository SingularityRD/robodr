//! Regression tests for independent review #3 (findings F1..F8). Each was a
//! proof-of-concept that passed while the bug existed; here the assertions
//! describe the FIXED behaviour.

mod common;

use common::*;
use robodr_capture::{LinkType, PcapWriter};
use robodr_commission::{
    lock, lock_draft_text, lock_with_caps, merge_profiles, merge_profiles_with_caps,
    parse_profile_text, to_json, write_files_atomic, Checker, ConfigError, HardCaps, LearnConfig,
    Learner, LockRefusal, MergeError, ParticipantStatus, PcapSource, Signoff, VecSource,
};
use robodr_events::graph::{Endpoint, Participant};
use robodr_events::profile::{Envelope, Profile};
use robodr_events::{MotionCommand, RobotEvent};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_robodr-commission");

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

fn learn_pcap(bytes: &[u8]) -> robodr_commission::Commissioning {
    let mut l = Learner::new(LearnConfig {
        model: "tl".into(),
        ..Default::default()
    })
    .unwrap();
    l.ingest(&mut PcapSource::new("mem.pcap", bytes).unwrap())
        .unwrap();
    l.finish()
}

/// Two legit nodes announcing every second for 60 s.
fn legit_run(frames: &mut Vec<(f64, Vec<u8>)>) {
    for (i, f) in talker_listener(false).into_iter().enumerate() {
        frames.push((i as f64 * 0.01, f));
    }
    for s in 1..=60 {
        for f in common::frames(TALKER, &announce(prefix(0xa1), &["W rt/rosout".into()])) {
            frames.push((s as f64, f));
        }
        for f in common::frames(LISTENER, &announce(prefix(0xb2), &["W rt/rosout".into()])) {
            frames.push((s as f64 + 0.5, f));
        }
    }
}

fn signoff_mentions(so: &Signoff, needle: &str) -> bool {
    so.items
        .iter()
        .any(|i| i.subject.contains(needle) || i.reason.contains(needle))
}

fn mismatch_items(so: &Signoff) -> Vec<&robodr_commission::SignoffItem> {
    so.items
        .iter()
        .filter(|i| i.kind == "endpoint_sender_mismatch")
        .collect()
}

// F1 -------------------------------------------------------------------------

/// An intruder (own header prefix, own IP) announces a writer whose
/// PID_ENDPOINT_GUID claims a legit participant: not learned under the
/// legit GUID; an `endpoint_sender_mismatch` item names both GUIDs, the IP
/// and the topic.
#[test]
fn f1_endpoint_claiming_another_guid_is_not_learned() {
    let intruder_ip = Ipv4Addr::new(10, 42, 0, 66);
    let (legit, evil) = (prefix(0xa1), prefix(0xe1));
    let mut frames = Vec::new();
    legit_run(&mut frames);
    let payload = sedp_payload(legit, 0x0000_7703, "rt/exfil", "pkg::msg::dds_::T_", 0);
    let dgram = rtps(evil, &[data(SEDP_PUB_WRITER, 1, &payload)]);
    for f in common::frames(intruder_ip, &[dgram]) {
        frames.push((30.0, f));
    }
    frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let c = learn_pcap(&pcap_at(&frames));
    let r = &c.report;
    assert_eq!(
        r.participants[&hex(evil)].status,
        ParticipantStatus::Quarantined
    );
    assert!(!c.profile.writer_topics.contains("/exfil"), "{r}");
    // Legit traffic is still learned.
    assert!(c.profile.writer_topics.contains("/rosout"));
    assert!(c.profile.participants.contains(&hex(legit)));
    assert!(signoff_mentions(&c.signoff, "exfil"));
    assert!(signoff_mentions(&c.signoff, &hex(evil)));
    let items = mismatch_items(&c.signoff);
    assert_eq!(items.len(), 1, "{:#?}", c.signoff.items);
    let it = items[0];
    assert_eq!(
        it.subject,
        format!("{} sent by {} from {intruder_ip}", hex(legit), hex(evil))
    );
    assert!(it.reason.contains("/exfil"), "{}", it.reason);
    assert!(!it.confirmed);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.code == "endpoint_sender_mismatch"));
    // The draft cannot be locked without someone confirming that item.
    let mut so = c.signoff.clone().confirm_all("op");
    so.items
        .iter_mut()
        .filter(|i| i.kind == "endpoint_sender_mismatch")
        .for_each(|i| i.confirmed = false);
    let why = lock(&c.profile, &so).unwrap_err();
    assert!(why
        .iter()
        .any(|w| matches!(w, LockRefusal::Unconfirmed { id, .. } if id.starts_with("endpoint_sender_mismatch:"))));
}

/// The header itself spoofs the legit prefix, from the intruder's IP, once.
/// Owner == sender, but the intruder IP is not a commissioned IP of the
/// legit participant (one announcement from there): not learned, flagged.
#[test]
fn f1_endpoint_from_uncommissioned_ip_is_not_learned() {
    let intruder_ip = Ipv4Addr::new(10, 42, 0, 66);
    let legit = prefix(0xa1);
    let mut frames = Vec::new();
    legit_run(&mut frames);
    for f in common::frames(intruder_ip, &announce(legit, &["W rt/exfil".into()])) {
        frames.push((30.0, f));
    }
    frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let c = learn_pcap(&pcap_at(&frames));
    assert!(!c.profile.writer_topics.contains("/exfil"), "{}", c.report);
    assert!(c.profile.writer_topics.contains("/rosout"));
    let items = mismatch_items(&c.signoff);
    assert_eq!(items.len(), 1, "{:#?}", c.signoff.items);
    assert_eq!(
        items[0].subject,
        format!("{0} sent by {0} from {intruder_ip}", hex(legit))
    );
    assert!(items[0].reason.contains("/exfil"));
    // Spoofing from a second IP is still flagged as before.
    assert!(c
        .signoff
        .items
        .iter()
        .any(|i| i.kind == "participant_multiple_ips" && i.subject == hex(legit)));
}

/// The operator overriding the gate for a participant accepts all its IPs
/// (and that override is itself a sign-off item); JSONL input, which has no
/// sender, is unaffected by the provenance check.
#[test]
fn f1_operator_accept_and_event_recordings() {
    let legit = prefix(0xa1);
    let ip2 = Ipv4Addr::new(10, 42, 0, 77);
    let mut frames = Vec::new();
    legit_run(&mut frames);
    for f in common::frames(ip2, &announce(legit, &["W rt/extra".into()])) {
        frames.push((30.0, f));
    }
    frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut l = Learner::new(LearnConfig {
        model: "tl".into(),
        accept_participants: [hex(legit)].into_iter().collect(),
        ..Default::default()
    })
    .unwrap();
    l.ingest(&mut PcapSource::new("mem.pcap", &pcap_at(&frames)[..]).unwrap())
        .unwrap();
    // Accepted on its own merits (so the override does not apply): the
    // second IP is still uncommissioned.
    let c = l.finish();
    assert!(!c.profile.writer_topics.contains("/extra"));

    let g = "aaaaaaaaaaaaaaaaaaaaaaaa";
    let evs = vec![
        RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: g.into(),
            src_ip: "10.0.0.1".into(),
            locators: vec![],
        }),
        RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: g.into(),
            topic: "rt/odom".into(),
            type_name: String::new(),
        }),
        RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: g.into(),
            src_ip: "10.0.0.1".into(),
            locators: vec![],
        }),
    ];
    let c = learned(evs);
    assert!(c.profile.writer_topics.contains("/odom"));
    assert!(mismatch_items(&c.signoff).is_empty());
}

// F2 -------------------------------------------------------------------------
fn late_intruder(flood: usize) -> robodr_commission::Commissioning {
    let intruder_ip = Ipv4Addr::new(10, 42, 0, 66);
    let evil = prefix(0xe3);
    let mut frames = Vec::new();
    legit_run(&mut frames);
    let d = announce(evil, &["W rt/exfil2".into()]);
    for t in [54.0, 59.2] {
        for f in common::frames(intruder_ip, &d) {
            frames.push((t, f));
        }
    }
    let junk = common::frames(intruder_ip, &[b"JUNKJUNKJUNKJUNK".to_vec()]);
    for i in 0..flood {
        frames.push((54.1 + 5.0 * i as f64 / flood as f64, junk[0].clone()));
    }
    frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    learn_pcap(&pcap_at(&frames))
}

/// Late/brief use capture time: a junk-frame flood does not hide a late,
/// short-lived participant.
#[test]
fn f2_frame_flood_does_not_hide_late_brief_participant() {
    let evil = hex(prefix(0xe3));
    for flood in [0, 4000] {
        let c = late_intruder(flood);
        for kind in ["participant_late", "participant_brief"] {
            assert!(
                c.signoff
                    .items
                    .iter()
                    .any(|i| i.subject == evil && i.kind == kind),
                "flood {flood}: no {kind}: {:#?}",
                c.signoff.items
            );
        }
        // Timestamped input: no position-fallback note.
        assert!(!c
            .report
            .warnings
            .iter()
            .any(|w| w.code == "presence_measured_by_position"));
    }
}

/// Without timestamps (event recordings) the fallback to positions is
/// used and the report says so.
#[test]
fn f2_timestampless_input_is_flagged() {
    let c = learned(base_run());
    assert!(c
        .report
        .warnings
        .iter()
        .any(|w| w.code == "presence_measured_by_position" && w.subject == "run0"));
}

// F3 -------------------------------------------------------------------------
fn ev_part(g: &str) -> RobotEvent {
    RobotEvent::Ros2ParticipantDiscovered(Participant {
        guid_prefix: g.into(),
        src_ip: "10.0.0.1".into(),
        locators: vec![],
    })
}
fn ev_writer(g: &str, t: &str) -> RobotEvent {
    RobotEvent::Ros2WriterDiscovered(Endpoint {
        guid_prefix: g.into(),
        topic: t.into(),
        type_name: String::new(),
    })
}
fn ev_mv(g: &str, ch: &str, lin: Option<f64>, joint: Option<f64>) -> RobotEvent {
    RobotEvent::MotionCommand(MotionCommand {
        channel: ch.into(),
        source_guid: Some(g.into()),
        linear_speed: lin,
        joint_speed: joint,
        angular_speed: None,
    })
}
const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";

fn learned_with(cfg: LearnConfig, evs: Vec<RobotEvent>) -> robodr_commission::Commissioning {
    let mut l = Learner::new(cfg).unwrap();
    l.ingest(&mut VecSource::new("run", evs)).unwrap();
    l.finish()
}

fn learned(evs: Vec<RobotEvent>) -> robodr_commission::Commissioning {
    learned_with(
        LearnConfig {
            model: "m".into(),
            ..Default::default()
        },
        evs,
    )
}

fn base_run() -> Vec<RobotEvent> {
    let mut evs = vec![ev_part(A), ev_writer(A, "rt/cmd_vel")];
    for _ in 0..100 {
        evs.push(ev_mv(A, "/cmd_vel", Some(0.5), None));
    }
    evs.push(ev_part(A));
    evs
}

/// Deleting sign-off items is refused, and re-sealing the emptied list
/// still fails the floor recomputed from the draft.
#[test]
fn f3_signoff_items_cannot_be_deleted() {
    let c = learned(base_run());
    assert!(c.signoff.items.iter().any(|i| i.kind == "motion_writer"));
    let draft = to_json(&c.profile).unwrap();
    let mut so = c.signoff.clone();
    so.items.clear();
    so.operator = "nobody".into();
    let why = lock_draft_text(&draft, &so).unwrap_err();
    assert!(why.contains(&LockRefusal::SignoffItemsTampered), "{why:?}");
    assert!(why.iter().any(
        |w| matches!(w, LockRefusal::RequiredItemMissing { subject, .. } if subject == "/cmd_vel")
    ));
    assert!(lock(&c.profile, &so).is_err());

    // Forger re-seals the emptied list: the floor still refuses.
    let mut resealed = so.clone();
    resealed.rebind(so.profile_sha256.clone());
    let why = lock(&c.profile, &resealed).unwrap_err();
    assert!(!why.contains(&LockRefusal::SignoffItemsTampered));
    assert!(why
        .iter()
        .any(|w| matches!(w, LockRefusal::RequiredItemMissing { .. })));

    // Deleting a single item (not the motion one) is caught by the digest.
    let mut one = c.signoff.clone().confirm_all("op");
    let n = one.items.len();
    one.items.retain(|i| i.kind == "motion_writer");
    assert!(one.items.len() < n, "{:#?}", c.signoff.items);
    assert_eq!(
        lock(&c.profile, &one).unwrap_err(),
        vec![LockRefusal::SignoffItemsTampered]
    );
    // The intact, confirmed list locks.
    assert!(lock(&c.profile, &c.signoff.clone().confirm_all("op")).is_ok());
}

// F4 -------------------------------------------------------------------------

/// An unobserved dimension is bounded at 0 (deny) and listed for sign-off.
#[test]
fn f4_unobserved_dimension_is_denied_and_signed_off() {
    let c = learned(base_run());
    assert_eq!(
        c.profile.motion_envelopes["/cmd_vel"].max_joint_speed,
        Some(0.0)
    );
    let it = c
        .signoff
        .items
        .iter()
        .find(|i| i.kind == "envelope_dimension_unobserved")
        .expect("item");
    assert_eq!(it.subject, "/cmd_vel joint");
    assert!(it.reason.contains("deny"));
    // The linear dimension was observed: no item for it.
    assert!(!c
        .signoff
        .items
        .iter()
        .any(|i| i.id == "envelope_dimension_unobserved:/cmd_vel linear"));
    let locked = lock(&c.profile, &c.signoff.clone().confirm_all("op")).unwrap();
    let mut chk = Checker::new(&locked);
    chk.observe("run2", 1, &ev_mv(A, "/cmd_vel", Some(0.1), Some(1.0e6)));
    chk.observe("run2", 2, &ev_mv(A, "/cmd_vel", Some(0.1), Some(0.0)));
    chk.observe("run2", 3, &ev_mv(A, "/cmd_vel", Some(0.1), None));
    let r = chk.finish();
    assert_eq!(r.deviations_total, 1, "{r}");
}

/// With an explicit OEM ceiling the unobserved dimension gets the ceiling.
#[test]
fn f4_unobserved_dimension_uses_configured_ceiling() {
    let c = learned_with(
        LearnConfig {
            model: "m".into(),
            ceiling_joint: Some(1.5),
            ..Default::default()
        },
        base_run(),
    );
    assert_eq!(
        c.profile.motion_envelopes["/cmd_vel"].max_joint_speed,
        Some(1.5)
    );
    assert!(c.signoff.items.iter().any(
        |i| i.id == "envelope_dimension_unobserved:/cmd_vel joint" && i.reason.contains("1.5")
    ));
}

// F5 -------------------------------------------------------------------------

/// One outlier far above the p99 raises `envelope_outlier` with the values;
/// the ratio is configurable and validated.
#[test]
fn f5_single_outlier_needs_signoff() {
    let mut evs = base_run();
    evs.insert(50, ev_mv(A, "/cmd_vel", Some(9.0), None));
    let c = learned(evs.clone());
    let it = c
        .signoff
        .items
        .iter()
        .find(|i| i.kind == "envelope_outlier")
        .expect("outlier item");
    assert_eq!(it.subject, "/cmd_vel linear");
    assert!(it.reason.contains("max 9 ") && it.reason.contains("p99 0.5"));
    assert!(c
        .report
        .warnings
        .iter()
        .any(|w| w.code == "envelope_outlier"));
    // A normal run has none.
    assert!(!learned(base_run())
        .signoff
        .items
        .iter()
        .any(|i| i.kind == "envelope_outlier"));
    // A permissive ratio does not flag 18x.
    let loose = learned_with(
        LearnConfig {
            model: "m".into(),
            outlier_ratio: 20.0,
            ..Default::default()
        },
        evs,
    );
    assert!(!loose
        .signoff
        .items
        .iter()
        .any(|i| i.kind == "envelope_outlier"));
    for bad in [0.5, f64::NAN, f64::INFINITY, -1.0] {
        let e = Learner::new(LearnConfig {
            outlier_ratio: bad,
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(e, ConfigError::InvalidOutlierRatio(_)));
    }
}

// F6 -------------------------------------------------------------------------
fn small_profile() -> Profile {
    let mut p = Profile {
        model: "m".into(),
        ..Default::default()
    };
    p.participants.insert(A.into());
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(0.5),
            max_joint_speed: Some(0.0),
        },
    );
    p
}

/// Duplicate keys are refused at every depth, also when spelled with
/// escapes.
#[test]
fn f6_duplicate_keys_refused_at_every_depth() {
    let text = to_json(&small_profile()).unwrap();
    assert!(parse_profile_text(&text).is_ok());
    let entry =
        "\"/cmd_vel\": {\n      \"max_linear_speed\": 0.5,\n      \"max_joint_speed\": 0.0\n    }";
    assert!(text.contains(entry), "{text}");
    let cases = [
        // Channel key twice, once via \u escape.
        text.replace(
            entry,
            &format!(
                "{entry},\n    \"/cmd\\u005fvel\": {{\n      \"max_linear_speed\": 1e300,\n      \
                 \"max_joint_speed\": null\n    }}"
            ),
        ),
        // Plain duplicate channel key.
        text.replace(entry, &format!("{entry},\n    {entry}")),
        // Field duplicated inside an envelope.
        text.replace(
            "\"max_linear_speed\": 0.5,",
            "\"max_linear_speed\": 0.5,\n      \"max_linear_speed\": 9.0,",
        ),
        // Top level, escaped spelling.
        text.replace(
            "\"locked\": false,",
            "\"locked\": false,\n  \"lock\\u0065d\": false,",
        ),
    ];
    for (i, evil) in cases.iter().enumerate() {
        assert_ne!(evil, &text, "case {i}");
        let e = parse_profile_text(evil).unwrap_err();
        assert!(e.to_string().contains("duplicate key"), "case {i}: {e}");
        let mut so = Signoff::for_profile(&small_profile());
        so.rebind(robodr_commission::signoff::sha256_hex(evil.as_bytes()));
        assert!(matches!(
            lock_draft_text(evil, &so.confirm_all("op")).unwrap_err()[..],
            [LockRefusal::UnreadableDraft { .. }]
        ));
    }
}

// F7 -------------------------------------------------------------------------

/// merge and lock enforce the hard cap (configurable).
#[test]
fn f7_merge_and_lock_enforce_hard_cap() {
    let c = learned(base_run());
    let mut edited = c.profile.clone();
    edited
        .motion_envelopes
        .get_mut("/cmd_vel")
        .unwrap()
        .max_linear_speed = Some(1e300);
    let e = merge_profiles(&[c.profile.clone(), edited.clone()]).unwrap_err();
    assert!(
        matches!(&e, MergeError::ExceedsHardCap { index: 1, channel, value, .. }
            if channel == "/cmd_vel" && *value == 1e300),
        "{e:?}"
    );
    let why = lock(&edited, &Signoff::for_profile(&edited).confirm_all("op")).unwrap_err();
    assert!(why.iter().any(|w| matches!(
        w,
        LockRefusal::ExceedsHardCap { dimension, cap, .. } if dimension == "linear" && *cap == 10.0
    )));
    // Joint too, and just above the cap.
    let mut j = c.profile.clone();
    j.motion_envelopes
        .get_mut("/cmd_vel")
        .unwrap()
        .max_joint_speed = Some(10.000001);
    assert!(lock(&j, &Signoff::for_profile(&j).confirm_all("op")).is_err());
    // A platform commissioned with a higher cap passes it explicitly.
    let caps = HardCaps {
        linear: 1e301,
        joint: 10.0,
    };
    let m = merge_profiles_with_caps(&[c.profile.clone(), edited], &caps).unwrap();
    assert!(lock_with_caps(&m, &Signoff::for_profile(&m).confirm_all("op"), &caps).is_ok());
    // A NaN cap (caller bug) refuses rather than admits.
    let nan = HardCaps {
        linear: f64::NAN,
        joint: f64::NAN,
    };
    assert!(lock_with_caps(&m, &Signoff::for_profile(&m).confirm_all("op"), &nan).is_err());
}

// F8 -------------------------------------------------------------------------
fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("robodr-rev3r-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn names(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A learn whose sign-off (or report) path already exists fails before
/// writing anything: no draft, no temp files, the existing file untouched.
#[test]
fn f8_failed_learn_writes_nothing() {
    let ex = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/clean-run.jsonl");
    for blocked in ["signoff", "report"] {
        let d = tmpdir(&format!("f8-{blocked}"));
        let out = d.join("draft.json");
        let so = d.join("draft.json.signoff.json");
        let rep = d.join("report.json");
        let stale = if blocked == "signoff" { &so } else { &rep };
        std::fs::write(stale, b"stale").unwrap();
        let o = Command::new(BIN)
            .args([
                "learn",
                "--events",
                ex.to_str().unwrap(),
                "--model",
                "ugv",
                "--out",
                out.to_str().unwrap(),
                "--report",
                rep.to_str().unwrap(),
                "--quiet",
            ])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{blocked}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("already exists"));
        assert!(
            !out.exists(),
            "{blocked}: draft written although learn failed"
        );
        assert_eq!(std::fs::read(stale).unwrap(), b"stale");
        assert_eq!(names(&d).len(), 1, "{blocked}: {:?}", names(&d));
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// `write_files_atomic`: a failure while preparing any file publishes none
/// and leaves no temps; `--force`-style overwrite replaces all together.
#[test]
fn f8_write_files_atomic_is_all_or_nothing() {
    let d = tmpdir("f8-lib");
    let a = d.join("a.json");
    let missing_dir = d.join("nope").join("b.json");
    let e = write_files_atomic(&[(&a, b"A"), (&missing_dir, b"B")], false).unwrap_err();
    assert!(e.to_string().contains("b.json"), "{e}");
    assert!(names(&d).is_empty(), "{:?}", names(&d));

    let b = d.join("b.json");
    write_files_atomic(&[(&a, b"A1"), (&b, b"B1")], false).unwrap();
    assert_eq!(names(&d), vec!["a.json", "b.json"]);
    // Without overwrite: the second exists, so neither is touched.
    let c = d.join("c.json");
    assert!(write_files_atomic(&[(&c, b"C"), (&b, b"B2")], false).is_err());
    assert!(!c.exists());
    assert_eq!(std::fs::read(&b).unwrap(), b"B1");
    // With overwrite: both replaced, no backups or temps left.
    write_files_atomic(&[(&a, b"A2"), (&b, b"B2")], true).unwrap();
    assert_eq!(std::fs::read(&a).unwrap(), b"A2");
    assert_eq!(std::fs::read(&b).unwrap(), b"B2");
    assert_eq!(names(&d), vec!["a.json", "b.json"]);
    // The same path twice is refused.
    assert!(write_files_atomic(&[(&c, b"1"), (&c, b"2")], false).is_err());
    assert!(!c.exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// CLI: merge and lock refuse bounds above the hard caps unless the caps are
/// raised explicitly; caps must be positive.
#[test]
fn f7_cli_merge_and_lock_take_hard_cap_flags() {
    let d = tmpdir("f7-cli");
    let a = d.join("a.json");
    let b = d.join("b.json");
    let base = learned(base_run()).profile;
    let mut fast = base.clone();
    fast.motion_envelopes
        .get_mut("/cmd_vel")
        .unwrap()
        .max_linear_speed = Some(25.0);
    std::fs::write(&a, to_json(&base).unwrap()).unwrap();
    std::fs::write(&b, to_json(&fast).unwrap()).unwrap();
    let run = |args: &[&str]| {
        Command::new(BIN)
            .args(common::with_operator_signature(args))
            .output()
            .unwrap()
    };
    let s = |p: &Path| p.to_str().unwrap().to_string();
    let m = d.join("m.json");
    let o = run(&["merge", "--out", &s(&m), &s(&a), &s(&b)]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("hard cap"));
    assert!(!m.exists());
    let o = run(&[
        "merge",
        "--hard-cap-linear",
        "0",
        "--out",
        &s(&m),
        &s(&a),
        &s(&b),
    ]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&[
        "merge",
        "--hard-cap-linear",
        "30",
        "--out",
        &s(&m),
        &s(&a),
        &s(&b),
    ]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // Conservative sign-off for the merged draft, confirmed.
    let so = d.join("so.json");
    assert_eq!(
        run(&["signoff", "--in", &s(&m), "--out", &s(&so)])
            .status
            .code(),
        Some(0)
    );
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&so).unwrap()).unwrap();
    v["operator"] = "op".into();
    for it in v["items"].as_array_mut().unwrap() {
        it["confirmed"] = true.into();
    }
    std::fs::write(&so, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let locked = d.join("locked.json");
    let o = run(&[
        "lock",
        "--platform",
        "ugv-test",
        "--profile-version",
        "1",
        "--in",
        &s(&m),
        "--signoff",
        &s(&so),
        "--out",
        &s(&locked),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("exceeds the hard cap"));
    assert!(!locked.exists());
    let o = run(&[
        "lock",
        "--platform",
        "ugv-test",
        "--profile-version",
        "1",
        "--in",
        &s(&m),
        "--signoff",
        &s(&so),
        "--out",
        &s(&locked),
        "--hard-cap-linear",
        "30",
    ]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let _ = std::fs::remove_dir_all(&d);
}
