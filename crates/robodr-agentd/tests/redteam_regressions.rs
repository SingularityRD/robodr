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
