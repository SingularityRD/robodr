//! Regressions of the S11-lite red team (`tools/e2e/REDTEAM.md`), replayed
//! through the real daemon.
//!
//! F1 (row R2): a GUID spray (one SPDP announcement per random GUID prefix)
//! made one or two findings per prefix, each a separate spool record (and a
//! separate SOC case); about 10 000 announcements filled the default 64 MiB
//! spool, after which every new finding, Critical ones included, was only in
//! the black box (`dropped_full`).

mod common;

use std::net::Ipv4Addr;

use common::pcap::{
    frame, robot_profile, sedp_datagram, spdp_datagram, ROBOT_IP, ROGUE, ROGUE_IP, SPDP_GROUP,
    TWIST,
};
use common::*;
use robodr_blackbox::record::RecordKind;
use robodr_events::Severity;

/// The sprayer: one host announcing a fresh GUID prefix per datagram.
const SPRAY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 77);
/// Prefixes sprayed (the red team sent 3000).
const SPRAY: usize = 3000;

fn spray_prefix(i: usize) -> [u8; 12] {
    let mut p = [0xd1; 12];
    p[8..12].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
    p
}

/// `SPRAY` SPDP announcements from `SPRAY_IP`, each with its own prefix,
/// then a genuine rogue: SPDP, and a `rt/cmd_vel` writer (Critical
/// `unauthorized_motion_writer`).
fn spray_then_rogue() -> Vec<Vec<u8>> {
    let mut f: Vec<Vec<u8>> = (0..SPRAY)
        .map(|i| {
            frame(
                SPRAY_IP,
                SPDP_GROUP,
                7400,
                &spdp_datagram(spray_prefix(i), SPRAY_IP),
            )
        })
        .collect();
    f.push(frame(
        ROGUE_IP,
        SPDP_GROUP,
        7400,
        &spdp_datagram(ROGUE, ROGUE_IP),
    ));
    f.push(frame(
        ROGUE_IP,
        ROBOT_IP,
        7410,
        &sedp_datagram(ROGUE, "rt/cmd_vel", TWIST),
    ));
    f
}

fn run(tag: &str, max_files: u64) -> (Setup, robodr_agentd::Summary, String) {
    let s = setup(tag, &robot_profile(true));
    let pcap = s.pcap(&spray_then_rogue());
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["spool"]["max_files"] = serde_json::json!(max_files);
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut log).unwrap();
    (s, sum, String::from_utf8(log).unwrap())
}

/// Deviation records of `rule` in the black box.
fn recorded(s: &Setup, rule: &str) -> usize {
    let needle = format!("\"rule\":\"{rule}\"");
    records(&s.blackbox)
        .iter()
        .filter(|r| r.kind == RecordKind::Deviation)
        .filter(|r| {
            r.payload
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
        })
        .count()
}

#[test]
fn guid_spray_is_aggregated_and_a_later_critical_still_reaches_the_spool() {
    // A spool that holds far fewer records than the spray has prefixes
    // (the red team's 64 MiB spool held about 10 000).
    let (s, sum, log) = run("rt-f1-spray", 400);
    let found = spooled(&s.spool);
    let r = rules(&found);
    let per_guid = r
        .iter()
        .filter(|x| {
            *x == "robot.ros2.unknown_participant" || *x == "robot.ros2.identity_instances_exceeded"
        })
        .count();

    // Bounded: the first few per-GUID findings one by one (the pipeline
    // dedups per (rule, detail), so each is its own record), then one
    // aggregated discovery-flood finding reported at 1, 2, 4, ... folded
    // findings and once more at the end: never one record per prefix
    // (before the fix: one per prefix until the spool was full).
    assert!(
        found.len() <= 30,
        "{} spool records for {SPRAY} sprayed prefixes: {r:?}\n{log}",
        found.len()
    );
    assert!(per_guid <= 9, "{per_guid} per-GUID findings: {r:?}");
    let flood: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.ros2.discovery_flood")
        .collect();
    assert!(
        !flood.is_empty() && flood.len() <= 14,
        "discovery_flood findings: {r:?}\n{log}"
    );
    // One SOC case: every report of the aggregate carries one finding id
    // (its subject is the sprayer's address), the last one the full count.
    let id = &flood[0].1.finding_id;
    assert!(flood.iter().all(|(_, e)| &e.finding_id == id), "{flood:#?}");
    let last = &flood.last().unwrap().1;
    assert_eq!(last.severity, Severity::High);
    assert_eq!(
        last.title,
        robodr_ocsf::rule_info("robot.ros2.discovery_flood").title
    );
    let detail = last.entity_context.detail.value.as_str();
    let folded = SPRAY - per_guid + 1; // the rogue's own was not folded
    assert!(detail.contains(&SPRAY_IP.to_string()), "{detail}");
    assert!(
        detail.contains(&format!("{folded} per-participant findings"))
            && detail.contains(&format!("unknown_participant x{folded}")),
        "counts: {detail}"
    );
    assert!(
        detail.contains("first seen") && detail.contains("last seen"),
        "{detail}"
    );
    // Sample GUID prefixes are named: the first folded ones.
    assert!(
        detail.contains(&robodr_rtps::hex12(&spray_prefix(per_guid - 1))),
        "{detail}"
    );
    // The genuine rogue after the spray: its Critical motion-writer
    // finding is spooled (and its own unknown_participant, from another
    // source, is not folded into the sprayer's aggregate).
    let crit: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.ros2.unauthorized_motion_writer")
        .collect();
    assert_eq!(crit.len(), 1, "{r:?}\n{log}");
    assert_eq!(crit[0].1.severity, Severity::Critical);
    assert_eq!(s_dropped(&s), 0, "nothing dropped: {log}");

    // Every sprayed announcement is still in the black box.
    assert!(
        recorded(&s, "robot.ros2.unknown_participant") > SPRAY,
        "black box: {} unknown_participant deviations",
        recorded(&s, "robot.ros2.unknown_participant")
    );
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
}

#[test]
fn a_full_spool_still_takes_a_critical_finding() {
    // So small that even the bounded flood output fills the share open to
    // non-Critical findings: the Critical one after it is still spooled
    // (it may use the part of the spool kept for Critical findings).
    let (s, _sum, log) = run("rt-f1-full", 8);
    let found = spooled(&s.spool);
    let r = rules(&found);
    assert!(
        r.contains(&"robot.ros2.unauthorized_motion_writer".to_string()),
        "{r:?}\n{log}"
    );
    assert!(s_dropped(&s) > 0, "the spool did fill: {r:?}");
}

fn s_dropped(s: &Setup) -> u64 {
    status(&s.spool).unwrap()["spool"]["dropped_full"]
        .as_u64()
        .unwrap_or(0)
}

// --- Review of the F1 fix (wt/redfix, H3, H4, L9, L10) ----------------------
// The reviewer's proofs of concept through the real daemon.

use std::time::Duration;

use common::pcap::{datagram, spdp_sub, LEGIT, LEGIT_HEX, ROGUE_HEX};

fn run_frames(
    tag: &str,
    frames: &[Vec<u8>],
    max_files: u64,
    sensor_extra: serde_json::Value,
) -> (Setup, String) {
    let s = setup(tag, &robot_profile(true));
    let pcap = s.pcap_spaced(frames, Duration::from_millis(2));
    let mut sensor = serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}});
    if let (Some(a), serde_json::Value::Object(b)) = (sensor.as_object_mut(), sensor_extra) {
        a.extend(b);
    }
    let mut cfg = s.config(
        sensor,
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["spool"]["max_files"] = serde_json::json!(max_files);
    let mut log = Vec::new();
    robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut log).unwrap();
    (s, String::from_utf8(log).unwrap())
}

fn json_of(e: &robodr_ocsf::FindingEnvelope) -> String {
    serde_json::to_string(e).unwrap()
}

fn spdp_at(src: Ipv4Addr, prefix: [u8; 12]) -> Vec<u8> {
    frame(
        src,
        SPDP_GROUP,
        7400,
        &datagram(prefix, &[spdp_sub(prefix, &[src])]),
    )
}

/// H3: the GUID spray with one `rt/cmd_vel` writer per sprayed prefix made
/// one Critical `unauthorized_motion_writer` per GUID, never folded: the
/// Critical spool share filled and the genuine rogue's Critical finding
/// (from another address) was dropped. (PoC: 600 prefixes, max_files 400.)
#[test]
fn review_h3_a_critical_spray_is_aggregated_and_a_later_rogue_is_spooled() {
    let mut frames = Vec::new();
    for i in 0..600 {
        let g = spray_prefix(i);
        frames.push(spdp_at(SPRAY_IP, g));
        frames.push(frame(
            SPRAY_IP,
            ROBOT_IP,
            7410,
            &sedp_datagram(g, "rt/cmd_vel", TWIST),
        ));
    }
    frames.push(spdp_at(ROGUE_IP, ROGUE));
    frames.push(frame(
        ROGUE_IP,
        ROBOT_IP,
        7410,
        &sedp_datagram(ROGUE, "rt/cmd_vel", TWIST),
    ));
    let (s, log) = run_frames("rv-h3", &frames, 400, serde_json::json!({}));
    let found = spooled(&s.spool);
    let r = rules(&found);
    let rogue_crit = found.iter().any(|(_, e)| {
        e.entity_context.rule_id == "robot.ros2.unauthorized_motion_writer"
            && json_of(e).contains(&ROGUE_IP.to_string())
    });
    assert!(
        rogue_crit,
        "the genuine rogue's Critical finding: {r:?}\n{log}"
    );
    let crit_individual = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.ros2.unauthorized_motion_writer")
        .count();
    assert!(
        crit_individual <= 9,
        "{crit_individual} motion-writer findings one by one: {r:?}"
    );
    assert!(found.len() <= 60, "{} spool records: {r:?}", found.len());
    let crit_agg = found.iter().any(|(_, e)| {
        e.entity_context.rule_id == "robot.ros2.discovery_flood" && e.severity == Severity::Critical
    });
    assert!(crit_agg, "a Critical aggregate: {r:?}");
    assert_eq!(s_dropped(&s), 0, "{r:?}");
    // Each sprayed motion writer is still in the black box.
    assert!(recorded(&s, "robot.ros2.unauthorized_motion_writer") >= 600);
}

/// H4: about 40 packets a minute from a dozen addresses used up the global
/// per-window budget; every later discovery finding robot-wide was folded
/// into a sourceless "many sources" aggregate that named neither a later
/// genuine rogue's address nor its GUID. A pinned participant's
/// impersonation from a flooding source was folded too, and the aggregate
/// said "from more than 32 source addresses" for 12.
#[test]
fn review_h4_a_low_rate_spray_does_not_hide_a_genuine_rogue_or_an_impersonation() {
    let mut frames = Vec::new();
    let mut n = 0usize;
    for src in 0..4u8 {
        for _ in 0..8 {
            frames.push(spdp_at(Ipv4Addr::new(10, 1, 0, src), spray_prefix(n)));
            n += 1;
        }
    }
    for src in 0..8u8 {
        frames.push(spdp_at(Ipv4Addr::new(10, 2, 0, src), spray_prefix(n)));
        n += 1;
    }
    for _ in 0..4 {
        frames.push(spdp_at(Ipv4Addr::new(10, 1, 0, 0), spray_prefix(n)));
        n += 1;
    }
    frames.push(spdp_at(ROGUE_IP, ROGUE));
    // The pinned robot participant's prefix announced from a source that
    // passed its own threshold.
    frames.push(spdp_at(Ipv4Addr::new(10, 1, 0, 0), LEGIT));
    let pins =
        serde_json::json!({"binding": {"participant_ips": {LEGIT_HEX: [ROBOT_IP.to_string()]}}});
    let (s, log) = run_frames("rv-h4", &frames, 1000, pins);
    let found = spooled(&s.spool);
    let r = rules(&found);
    let names_rogue = found.iter().any(|(_, e)| {
        let j = json_of(e);
        j.contains(&ROGUE_IP.to_string()) || j.contains(ROGUE_HEX)
    });
    assert!(
        names_rogue,
        "no spooled finding names the rogue: {r:?}\n{log}"
    );
    let impersonation = found.iter().any(|(_, e)| {
        e.entity_context.rule_id == "robot.ros2.participant_source_mismatch"
            && json_of(e).contains(LEGIT_HEX)
    });
    assert!(impersonation, "the pinned prefix's impersonation: {r:?}");
    for (_, e) in &found {
        let d = &e.entity_context.detail.value;
        assert!(!d.contains("more than 32 source addresses"), "{d}");
    }
}

/// L9: the aggregate's sample GUID prefixes were parsed from the detail
/// text, where an attacker-chosen topic name comes first: a topic of 24 hex
/// digits (here the robot participant's own prefix) became a sample the
/// SOC might copy into a quarantine. Nine SEDP-only announcements from one
/// address: eight pass, the rest (and every "never announced" finding at
/// the end of the replay) are folded.
#[test]
fn review_l9_a_topic_name_never_becomes_a_sample_guid() {
    let mut frames = Vec::new();
    let forged = format!("rt/{LEGIT_HEX}");
    for i in 0..9 {
        frames.push(frame(
            SPRAY_IP,
            ROBOT_IP,
            7410,
            &sedp_datagram(spray_prefix(i), &forged, TWIST),
        ));
    }
    let (s, log) = run_frames("rv-l9", &frames, 1000, serde_json::json!({}));
    let found = spooled(&s.spool);
    let agg: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.ros2.discovery_flood")
        .collect();
    assert!(!agg.is_empty(), "{:?}\n{log}", rules(&found));
    for (_, e) in &agg {
        let d = &e.entity_context.detail.value;
        let samples = d.split("sample GUID prefixes:").nth(1).unwrap_or("");
        assert!(!samples.contains(LEGIT_HEX), "forged sample: {d}");
        assert!(d.contains("black box"), "detail not truncated: {d}");
    }
    // The samples are the sprayed prefixes themselves.
    let last = &agg.last().unwrap().1.entity_context.detail.value;
    let samples = last.split("sample GUID prefixes:").nth(1).unwrap_or("");
    assert!(
        last.contains("endpoint_unannounced_participant") && samples.contains("d1d1d1d1d1d1d1d1"),
        "the real prefixes are named: {last}"
    );
}

/// L10: every flood from one address had the same finding id forever, so a
/// later flood updated a SOC case that may have been closed long ago.
#[test]
fn review_l10_each_flood_episode_is_its_own_finding() {
    let s = setup("rv-l10", &robot_profile(true));
    let mut frames = Vec::new();
    for i in 0..20 {
        frames.push((
            Duration::from_millis(10 * i as u64),
            spdp_at(SPRAY_IP, spray_prefix(i)),
        ));
    }
    for i in 20..40 {
        frames.push((
            Duration::from_secs(600) + Duration::from_millis(10 * i as u64),
            spdp_at(SPRAY_IP, spray_prefix(i)),
        ));
    }
    let pcap = s.pcap_timed(&frames);
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let mut log = Vec::new();
    robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut log).unwrap();
    let found = spooled(&s.spool);
    let ids: std::collections::BTreeSet<String> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.ros2.discovery_flood")
        .map(|(_, e)| e.finding_id.clone())
        .collect();
    assert_eq!(ids.len(), 2, "one finding per flood episode: {ids:?}");
}

/// L10: a spool too small for a Critical reserve (`max_files / 8 == 0`) is
/// refused rather than run without one.
#[test]
fn review_l10_a_spool_without_a_critical_reserve_is_refused() {
    let s = setup("rv-l10-spool", &robot_profile(true));
    let pcap = s.pcap(&[spdp_at(SPRAY_IP, spray_prefix(0))]);
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({}),
    );
    cfg["spool"]["max_files"] = serde_json::json!(4);
    let err = match robodr_agentd::load(&s.write_config(&cfg)) {
        Ok(_) => panic!("a spool of 4 files was accepted"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("spool.max_files"), "{err}");
}
