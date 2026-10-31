//! Throughput benchmarks for sizing a RoboDR sensor box (gap T32).
//!
//! * [`agentd`]: `robodr-agentd` end to end (capture replay -> ROS 2
//!   pipeline -> decision chain -> signed black box -> findings spool) on a
//!   synthetic ROS 2 graph: `participants` DDS participants with `topics`
//!   writers each (10 Hz samples), one `/cmd_vel` writer at `motion_hz`, SPDP
//!   beacons every second. The profile is learned from the first seconds of
//!   the same traffic and locked, so a clean run produces no finding; with
//!   `rogue_share > 0` that share of motion commands comes from an unknown
//!   participant at an out-of-envelope speed, so every one of them is
//!   judged, recorded in the black box and spooled.
//!
//!   The replay is not paced: the capture reader runs as fast as it can, so
//!   the pipeline (one thread) is saturated for the whole run and
//!   `datagrams_per_s` (datagrams processed per second of wall time) is its
//!   maximum rate on one core. The input queue is set to its largest size
//!   and each workload's capture is sized to fit in it
//!   ([`MAX_CAPTURE_DATAGRAMS`]), so nothing is dropped: a run that drops
//!   anything is reported `valid: false` and fails the gate. Because the
//!   queue holds most of the capture at the peak, `peak_rss_kib` is an upper
//!   bound for a live sensor at that rate (a live capture's queue stays near
//!   empty below the maximum rate).
//! * [`correlate`]: the correlation engine alone, fed a mix of the signals
//!   its default rules join, spread over `groups` distinct sources.
//!
//! Every workload runs in its own child process (`robodr-bench run-one`), so
//! `peak_rss_kib` (`VmHWM`) is that workload's own.

#![forbid(unsafe_code)]

use robodr_capture::{synth, LinkType, PcapWriter};
use robodr_commission::{LearnConfig, Learner, PcapSource};
use robodr_correlate::{Correlator, EntityKind, Signal};
use robodr_events::Severity;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xc2];
const SEDP_PUB_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xc2];
const TWIST: &str = "geometry_msgs::msg::dds_::Twist_";
const STRING: &str = "std_msgs::msg::dds_::String_";
const SPDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 0, 1);
const ROBOT_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 10);
const T0: u64 = 1_790_000_000;

// ---------------------------------------------------------------- RTPS

fn header(prefix: [u8; 12]) -> Vec<u8> {
    let mut d = b"RTPS".to_vec();
    d.extend_from_slice(&[2, 3, 0x01, 0x0f]);
    d.extend_from_slice(&prefix);
    d
}

fn param(pid: u16, value: &[u8]) -> Vec<u8> {
    let mut v = value.to_vec();
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    let mut p = pid.to_le_bytes().to_vec();
    p.extend_from_slice(&(v.len() as u16).to_le_bytes());
    p.extend_from_slice(&v);
    p
}

fn string_param(pid: u16, s: &str) -> Vec<u8> {
    let mut v = ((s.len() + 1) as u32).to_le_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    param(pid, &v)
}

fn guid(prefix: [u8; 12], entity: [u8; 4]) -> Vec<u8> {
    let mut g = prefix.to_vec();
    g.extend_from_slice(&entity);
    g
}

fn locator(ip: Ipv4Addr, port: u32) -> Vec<u8> {
    let mut v = 1i32.to_le_bytes().to_vec();
    v.extend_from_slice(&port.to_le_bytes());
    v.extend_from_slice(&[0; 12]);
    v.extend_from_slice(&ip.octets());
    v
}

fn pl(params: &[Vec<u8>]) -> Vec<u8> {
    let mut p = vec![0x00, 0x03, 0, 0];
    for x in params {
        p.extend_from_slice(x);
    }
    p.extend_from_slice(&[1, 0, 0, 0]);
    p
}

fn data(writer: [u8; 4], sn: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&writer);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&sn.to_le_bytes());
    body.extend_from_slice(payload);
    let mut s = vec![0x15, 0x05];
    s.extend_from_slice(&(body.len() as u16).to_le_bytes());
    s.extend_from_slice(&body);
    s
}

fn writer_entity(topic: usize) -> [u8; 4] {
    let t = (topic as u16 + 1).to_be_bytes();
    [0, t[0], t[1], 0x03]
}

fn spdp(prefix: [u8; 12], ip: Ipv4Addr) -> Vec<u8> {
    let mut d = header(prefix);
    d.extend(data(
        SPDP_WRITER,
        1,
        &pl(&[
            param(0x0015, &[2, 3, 0, 0]),
            param(0x0016, &[0x01, 0x0f, 0, 0]),
            param(0x0050, &guid(prefix, [0, 0, 1, 0xc1])),
            param(0x0032, &locator(ip, 7410)),
            param(0x0031, &locator(ip, 7411)),
        ]),
    ));
    d
}

fn sedp(prefix: [u8; 12], entity: [u8; 4], topic: &str, type_name: &str) -> Vec<u8> {
    let mut d = header(prefix);
    d.extend(data(
        SEDP_PUB_WRITER,
        1,
        &pl(&[
            param(0x005a, &guid(prefix, entity)),
            string_param(0x0005, topic),
            string_param(0x0007, type_name),
        ]),
    ));
    d
}

fn sample(prefix: [u8; 12], entity: [u8; 4], sn: u32, payload: &[u8]) -> Vec<u8> {
    let mut d = header(prefix);
    d.extend(data(entity, sn, payload));
    d
}

fn twist(vx: f64) -> Vec<u8> {
    let mut p = vec![0x00, 0x01, 0, 0];
    for v in [vx, 0.0, 0.0, 0.0, 0.0, 0.1] {
        p.extend_from_slice(&v.to_le_bytes());
    }
    p
}

fn frame(src: Ipv4Addr, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    synth::ethernet(0x0800, &synth::ipv4_udp(src, dst, 49152, dport, payload))
}

// ---------------------------------------------------------------- agentd

/// One agentd workload.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentdLoad {
    pub participants: usize,
    pub topics: usize,
    pub motion_hz: u32,
    pub seconds: u32,
    /// Share of motion commands from a rogue participant, `0.0..=1.0`.
    pub rogue_share: f64,
}

impl AgentdLoad {
    pub fn name(&self) -> String {
        format!(
            "agentd/p{}-t{}-m{}hz-rogue{}",
            self.participants,
            self.topics,
            self.motion_hz,
            (self.rogue_share * 100.0).round()
        )
    }
}

fn prefix_of(i: usize) -> [u8; 12] {
    let mut p = [0x11u8; 12];
    p[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    p
}

fn ip_of(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 88, 1 + (i / 250) as u8, 1 + (i % 250) as u8)
}

/// The workload's frames (time offset, frame); `learn` = the first 3 s only,
/// always clean.
pub fn agentd_frames(l: &AgentdLoad, learn: bool) -> Vec<(Duration, Vec<u8>)> {
    let mut out: Vec<(Duration, Vec<u8>)> = Vec::new();
    let secs = if learn { 3 } else { l.seconds };
    let robot = [0x22u8; 12];
    let rogue = [0xeeu8; 12];
    let rogue_ip = Ipv4Addr::new(10, 88, 9, 66);
    let cmd_entity = writer_entity(0);
    // Discovery at t = 0: the robot's controller (the /cmd_vel writer) and
    // every participant's writers.
    out.push((
        Duration::ZERO,
        frame(ROBOT_IP, SPDP_GROUP, 7400, &spdp(robot, ROBOT_IP)),
    ));
    out.push((
        Duration::from_millis(1),
        frame(
            ROBOT_IP,
            ROBOT_IP,
            7410,
            &sedp(robot, cmd_entity, "rt/cmd_vel", TWIST),
        ),
    ));
    for i in 0..l.participants {
        let (p, ip) = (prefix_of(i), ip_of(i));
        out.push((
            Duration::from_millis(2),
            frame(ip, SPDP_GROUP, 7400, &spdp(p, ip)),
        ));
        for t in 0..l.topics {
            let topic = format!("rt/bench/p{i}/t{t}");
            out.push((
                Duration::from_millis(3),
                frame(
                    ip,
                    ROBOT_IP,
                    7410,
                    &sedp(p, writer_entity(t + 1), &topic, STRING),
                ),
            ));
        }
    }
    let rogue_on = !learn && l.rogue_share > 0.0;
    if rogue_on {
        out.push((
            Duration::from_millis(500),
            frame(rogue_ip, SPDP_GROUP, 7400, &spdp(rogue, rogue_ip)),
        ));
        out.push((
            Duration::from_millis(501),
            frame(
                rogue_ip,
                ROBOT_IP,
                7410,
                &sedp(rogue, cmd_entity, "rt/cmd_vel", TWIST),
            ),
        ));
    }
    let string_payload = {
        let mut p = vec![0x00, 0x01, 0, 0];
        p.extend_from_slice(&13u32.to_le_bytes());
        p.extend_from_slice(b"bench sample\0\0\0\0");
        p
    };
    let mut sn = 0u32;
    let rogue_every = if rogue_on {
        (1.0 / l.rogue_share).round().max(1.0) as u64
    } else {
        0
    };
    for s in 0..u64::from(secs) {
        let base = Duration::from_secs(s) + Duration::from_millis(10);
        // SPDP beacons, once a second.
        out.push((
            base,
            frame(ROBOT_IP, SPDP_GROUP, 7400, &spdp(robot, ROBOT_IP)),
        ));
        for i in 0..l.participants {
            out.push((
                base,
                frame(ip_of(i), SPDP_GROUP, 7400, &spdp(prefix_of(i), ip_of(i))),
            ));
        }
        // Motion at motion_hz.
        for k in 0..u64::from(l.motion_hz) {
            sn = sn.wrapping_add(1);
            let at = base + Duration::from_nanos(k * 1_000_000_000 / u64::from(l.motion_hz));
            let n = s * u64::from(l.motion_hz) + k;
            let f = if rogue_every > 0 && n % rogue_every == 0 {
                frame(
                    rogue_ip,
                    ROBOT_IP,
                    7411,
                    &sample(rogue, cmd_entity, sn, &twist(3.0)),
                )
            } else {
                let vx = 0.3 + 0.01 * (n % 3) as f64;
                frame(
                    ROBOT_IP,
                    ROBOT_IP,
                    7411,
                    &sample(robot, cmd_entity, sn, &twist(vx)),
                )
            };
            out.push((at, f));
        }
        // Every other topic at 10 Hz.
        for tick in 0..10u64 {
            let at = base + Duration::from_millis(tick * 100 + 5);
            for i in 0..l.participants {
                for t in 0..l.topics {
                    out.push((
                        at,
                        frame(
                            ip_of(i),
                            ROBOT_IP,
                            7411,
                            &sample(
                                prefix_of(i),
                                writer_entity(t + 1),
                                (s * 10 + tick) as u32 + 1,
                                &string_payload,
                            ),
                        ),
                    ));
                }
            }
        }
    }
    out.sort_by_key(|(t, _)| *t);
    out
}

fn pcap_bytes(frames: &[(Duration, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut w =
        PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).map_err(|e| e.to_string())?;
    for (at, f) in frames {
        w.write_packet(Duration::from_secs(T0) + *at, f, f.len() as u32)
            .map_err(|e| e.to_string())?;
    }
    Ok(w.into_inner())
}

fn tmpdir(tag: &str) -> Result<PathBuf, String> {
    let d = std::env::temp_dir().join(format!("robodr-bench-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

fn write_locked_profile(dir: &Path, learn_pcap: &[u8]) -> Result<(), String> {
    let mut l = Learner::new(LearnConfig {
        model: "bench".into(),
        ..LearnConfig::default()
    })
    .map_err(|e| format!("{e:?}"))?;
    let mut src = PcapSource::new("learn", learn_pcap).map_err(|e| format!("{e:?}"))?;
    l.ingest(&mut src).map_err(|e| format!("{e:?}"))?;
    let mut p = l.finish().profile;
    p.locked = true;
    p.metadata = Some(robodr_events::profile::ProfileMetadata {
        schema_version: robodr_events::profile::PROFILE_SCHEMA_VERSION,
        profile_version: 1,
        platform: "bench".into(),
        unit_id: Some("bench-001".into()),
        locked_by: "Bench".into(),
        locked_at: T0,
        parent_digest: None,
        attestation: None,
    });
    let key = robodr_blackbox::Ed25519SigningKey::from_seed("bench-profile", &[0x31; 32])
        .map_err(|e| format!("{e:?}"))?;
    let text = robodr_commission::sealed_text(&p).map_err(|e| format!("{e:?}"))?;
    let path = dir.join("profile.json");
    let sig = robodr_commission::ProfileSignature::create(text.as_bytes(), &key)
        .map_err(|e| format!("{e:?}"))?;
    std::fs::write(robodr_commission::sig_path_for(&path), sig.to_text())
        .map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("profile-trust.json"),
        robodr_commission::trust::trust_keys_text(&[key.verifying_key()]),
    )
    .map_err(|e| e.to_string())
}

/// Peak resident set of this process (`VmHWM`, KiB).
pub fn peak_rss_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

/// Run one agentd workload in this process; JSON result.
pub fn run_agentd(l: &AgentdLoad) -> Result<Value, String> {
    let dir = tmpdir("agentd")?;
    write_locked_profile(&dir, &pcap_bytes(&agentd_frames(l, true))?)?;
    let frames = agentd_frames(l, false);
    let pcap = dir.join("run.pcap");
    std::fs::write(&pcap, pcap_bytes(&frames)?).map_err(|e| e.to_string())?;
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        include_str!("../../crates/robodr-agent/examples/policy-oem-validated.json"),
    )
    .map_err(|e| e.to_string())?;
    let key = dir.join("blackbox.key");
    std::fs::write(&key, robodr_blackbox::crypto::to_hex(&[0x42; 32]))
        .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let cfg = json!({
        "robot": {"id": "bench-001", "site": "bench"},
        "sensor": {
            "profile_path": dir.join("profile.json"),
            "listen_spdp": false,
            "profile_trust": {"trusted_keys": dir.join("profile-trust.json"),
                              "state_file": dir.join("profile-state.json")},
            "capture": {"enabled": true, "pcap_replay": pcap},
        },
        "policy_path": policy,
        "blackbox": {"dir": dir.join("blackbox"), "key_file": key, "key_id": "bench-key",
                     "boot_id": "bench", "allow_hmac": true},
        "spool": {"dir": dir.join("spool")},
        "event_inputs": [],
        "context": {"safety_state": "moving_slow"},
        "correlation": {"enabled": true, "include_default_rules": true},
        "daemon": {"tick_ms": 100, "heartbeat_ms": 1000, "silence_ms": 600000, "lag_ms": 600000,
                   "health_report_ms": 0, "exit_when_inputs_end": true,
                   "queue_capacity": 65_536, "queue_bytes": 256 << 20},
    });
    let cfg_path = dir.join("agentd.json");
    std::fs::write(
        &cfg_path,
        serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let r = robodr_agentd::load(&cfg_path)?;
    let mut log = Vec::new();
    let t = Instant::now();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).map_err(|e| e.to_string())?;
    let wall = t.elapsed().as_secs_f64();
    let _ = std::fs::remove_dir_all(&dir);
    let processed = sum.stats.datagrams;
    let dropped = (frames.len() as u64).saturating_sub(processed);
    Ok(json!({
        "valid": dropped == 0,
        "workload": l.name(),
        "participants": l.participants,
        "topics_per_participant": l.topics,
        "motion_hz": l.motion_hz,
        "virtual_seconds": l.seconds,
        "rogue_share": l.rogue_share,
        "datagrams_in_capture": frames.len(),
        "datagrams_processed": processed,
        "dropped_at_input": dropped,
        "motion_events": sum.stats.motion_events,
        "findings_spooled": sum.stats.findings_spooled,
        "wall_s": wall,
        "datagrams_per_s": processed as f64 / wall.max(1e-9),
        "realtime_factor": f64::from(l.seconds) / wall.max(1e-9),
        "peak_rss_kib": peak_rss_kib(),
    }))
}

// ---------------------------------------------------------------- correlate

/// One correlation workload.
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelateLoad {
    pub signals: u64,
    /// Distinct sources (participants / addresses / processes).
    pub groups: u64,
}

impl CorrelateLoad {
    pub fn name(&self) -> String {
        format!("correlate/s{}-g{}", self.signals, self.groups)
    }
}

/// Run one correlation workload in this process; JSON result.
pub fn run_correlate(l: &CorrelateLoad) -> Result<Value, String> {
    const MIX: &[(&str, Severity)] = &[
        ("robot.ros2.unknown_participant", Severity::High),
        ("robot.ros2.unauthorized_motion_writer", Severity::Critical),
        ("robot.ros2.participant_source_mismatch", Severity::High),
        ("robot.motion.linear_over_envelope", Severity::High),
        ("robot.firewall.rejected_unknown_source", Severity::High),
        ("robot.rtps.discovery_not_inspected", Severity::Medium),
        ("robot.capture.ip_fragment_refused", Severity::Medium),
        (
            "RoboDR: Interactive shell started on robot controller",
            Severity::Medium,
        ),
        (
            "RoboDR: SROS 2 private key read outside the ROS stack",
            Severity::High,
        ),
    ];
    let mut c = Correlator::with_defaults();
    let mut found = 0u64;
    let t = Instant::now();
    for n in 0..l.signals {
        let (rule, sev) = MIX[(n % MIX.len() as u64) as usize];
        let g = (n / MIX.len() as u64) % l.groups.max(1);
        let sig = Signal::new(n * 1_000_000, rule, sev)
            .with_entity(EntityKind::Participant, format!("{g:024x}"))
            .with_entity(
                EntityKind::Ip,
                format!("10.{}.{}.{}", g >> 16 & 255, g >> 8 & 255, g & 255),
            )
            .with_entity(EntityKind::Process, format!("{}", 1000 + g));
        found += c.observe(&sig).len() as u64;
    }
    let wall = t.elapsed().as_secs_f64();
    Ok(json!({
        "workload": l.name(),
        "signals": l.signals,
        "groups": l.groups,
        "correlated_findings": found,
        "pending_groups": c.pending_groups(),
        "wall_s": wall,
        "signals_per_s": l.signals as f64 / wall.max(1e-9),
        "peak_rss_kib": peak_rss_kib(),
    }))
}

// ---------------------------------------------------------------- suites

/// Most datagrams in one workload's capture: below the daemon's largest
/// input queue (65 536), so a saturated run drops nothing.
pub const MAX_CAPTURE_DATAGRAMS: u64 = 60_000;

/// Virtual seconds that keep a workload under [`MAX_CAPTURE_DATAGRAMS`]
/// (at most `cap`, at least 2).
fn seconds_for(participants: usize, topics: usize, motion_hz: u32, cap: u32) -> u32 {
    let per_s =
        u64::from(motion_hz) + (participants as u64 + 1) + participants as u64 * topics as u64 * 10;
    let fit =
        (MAX_CAPTURE_DATAGRAMS - 1_000 - participants as u64 * (topics as u64 + 1)) / per_s.max(1);
    u32::try_from(fit).unwrap_or(u32::MAX).clamp(2, cap)
}

/// The standard suite (sizing curve). `quick` is the CI-sized subset.
pub fn suite(quick: bool) -> (Vec<AgentdLoad>, Vec<CorrelateLoad>) {
    let a = |p, t, cap, r| AgentdLoad {
        participants: p,
        topics: t,
        motion_hz: 1000,
        seconds: seconds_for(p, t, 1000, cap),
        rogue_share: r,
    };
    if quick {
        return (
            vec![a(10, 5, 10, 0.0), a(10, 5, 10, 0.01)],
            vec![CorrelateLoad {
                signals: 200_000,
                groups: 100,
            }],
        );
    }
    (
        vec![
            a(1, 5, 30, 0.0),
            a(10, 5, 30, 0.0),
            a(50, 5, 30, 0.0),
            a(200, 5, 30, 0.0),
            a(50, 20, 30, 0.0),
            a(10, 5, 30, 0.01),
            a(10, 5, 30, 0.1),
        ],
        vec![
            CorrelateLoad {
                signals: 1_000_000,
                groups: 10,
            },
            CorrelateLoad {
                signals: 1_000_000,
                groups: 1_000,
            },
            CorrelateLoad {
                signals: 1_000_000,
                groups: 100_000,
            },
        ],
    )
}

/// Compare `results` with `baseline` (both suite outputs). A workload fails
/// when its rate is below `(1 - tolerance)` × baseline or its peak RSS above
/// `(1 + tolerance)` × baseline. Workloads missing on either side are
/// reported, not failed.
pub fn gate(results: &[Value], baseline: &[Value], tolerance: f64) -> Vec<String> {
    let mut problems = Vec::new();
    for r in results {
        let name = r["workload"].as_str().unwrap_or("?");
        let Some(b) = baseline.iter().find(|b| b["workload"] == r["workload"]) else {
            continue;
        };
        for rate in ["datagrams_per_s", "signals_per_s"] {
            if let (Some(x), Some(y)) = (r[rate].as_f64(), b[rate].as_f64()) {
                if x < y * (1.0 - tolerance) {
                    problems.push(format!(
                        "{name}: {rate} {x:.0} < {:.0} (baseline {y:.0})",
                        y * (1.0 - tolerance)
                    ));
                }
            }
        }
        if r["valid"] == false {
            problems.push(format!(
                "{name}: dropped datagrams at input (run not valid)"
            ));
        }
        if let (Some(x), Some(y)) = (r["peak_rss_kib"].as_f64(), b["peak_rss_kib"].as_f64()) {
            if x > y * (1.0 + tolerance) {
                problems.push(format!(
                    "{name}: peak_rss_kib {x:.0} > {:.0} (baseline {y:.0})",
                    y * (1.0 + tolerance)
                ));
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_shape() {
        let l = AgentdLoad {
            participants: 3,
            topics: 2,
            motion_hz: 100,
            seconds: 2,
            rogue_share: 0.1,
        };
        let f = agentd_frames(&l, false);
        // discovery 2 + 3 + 6, rogue 2, per second: 4 beacons + 100 motion + 10 * 6 samples.
        assert_eq!(f.len(), 2 + 3 + 6 + 2 + 2 * (4 + 100 + 60));
        assert!(f.windows(2).all(|w| w[0].0 <= w[1].0));
        assert_eq!(
            agentd_frames(&l, true).len(),
            2 + 3 + 6 + 3 * (4 + 100 + 60)
        );
    }

    #[test]
    fn suite_workloads_fit_the_queue() {
        for l in suite(false).0.iter().chain(suite(true).0.iter()) {
            let n = agentd_frames(l, false).len() as u64;
            assert!(n <= MAX_CAPTURE_DATAGRAMS, "{}: {n}", l.name());
        }
    }

    #[test]
    fn gate_flags_slower_and_bigger() {
        let base = vec![json!({"workload": "a", "datagrams_per_s": 1000.0, "peak_rss_kib": 1000})];
        let ok = vec![json!({"workload": "a", "datagrams_per_s": 800.0, "peak_rss_kib": 1200})];
        assert!(gate(&ok, &base, 0.25).is_empty());
        let bad = vec![json!({"workload": "a", "datagrams_per_s": 700.0, "peak_rss_kib": 1300})];
        assert_eq!(gate(&bad, &base, 0.25).len(), 2);
        let other = vec![json!({"workload": "b", "datagrams_per_s": 1.0})];
        assert!(gate(&other, &base, 0.25).is_empty());
    }

    #[test]
    fn correlate_runs() {
        let r = run_correlate(&CorrelateLoad {
            signals: 5_000,
            groups: 10,
        })
        .unwrap();
        assert!(r["signals_per_s"].as_f64().unwrap() > 0.0);
    }
}
