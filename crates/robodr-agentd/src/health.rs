//! Self-health: turn input counters, queue latency, spool and black-box
//! state into a robot **state** and into health deviations.
//!
//! Design rule (black box and self-protection): when the agent is blind its
//! robot is **Unknown**, never OK: a monitor that cannot see must not
//! report all clear. [`HealthState`] is therefore
//! `ok` only when every input has delivered **valid** data within
//! `silence_ms`, none has ended, the pipeline is not lagging and nothing was
//! lost since the last evaluation. Before an input has delivered anything
//! the state is `unknown` too ("no data yet"); a finding is raised only
//! after `silence_ms`. Malformed items are not data: an input that sends
//! only junk goes silent like one that sends nothing (the finding says how
//! many malformed items were skipped meanwhile). When every input thread is
//! gone ([`DaemonSnapshot::all_inputs_gone`]) and that was not expected, the
//! state is `unknown` too.
//!
//! | Issue | Rule | Severity | Raised |
//! |---|---|---|---|
//! | input delivered nothing for `silence_ms` | [`rules::INPUT_SILENT`] | High | once per silence episode |
//! | input ended (EOF / error) while the daemon runs | [`rules::INPUT_ENDED`] | High | once |
//! | queue full, items dropped | [`rules::QUEUE_OVERFLOW`] | Medium | on increase, at most every `health_report_ms` |
//! | malformed input lines | [`rules::INPUT_MALFORMED`] | Low | on increase, at most every `health_report_ms` |
//! | queue latency or tick delay > `lag_ms` | [`rules::PIPELINE_LAG`] | Medium | once per lag episode |
//! | spool full / spool write errors | [`rules::SPOOL_FULL`] | High | on increase, at most every `health_report_ms` |
//! | black box failing (evidence lost) | [`rules::EVIDENCE_DEGRADED`] | High | once per outage |
//! | black box quarantined evidence at open | [`rules::EVIDENCE_QUARANTINED`] | the recorder's (High / Critical) | once per recorder open (daemon) |
//! | black box found its tail cut at open | [`rules::EVIDENCE_TRUNCATED`] | Critical | once per recorder open (daemon) |
//!
//! The daemon hands these to `Agent::handle_external` as
//! `Detector::SelfHealth`, which stamps them observe-only: a health problem
//! (possibly caused by an attacker flooding or starving an input) is
//! recorded and reported but never feeds a motion request.
//!
//! Everything here is a pure function of its inputs (times are milliseconds
//! since the daemon started), so it is unit-tested without threads.

use robodr_events::{Deviation, Severity};
use serde::Serialize;

/// Health rule ids (OCSF `rule_id`s; `[a-z0-9._]`).
pub mod rules {
    pub const INPUT_SILENT: &str = "robot.agent.input_silent";
    pub const INPUT_ENDED: &str = "robot.agent.input_ended";
    pub const QUEUE_OVERFLOW: &str = "robot.agent.queue_overflow";
    pub const INPUT_MALFORMED: &str = "robot.agent.input_malformed";
    pub const PIPELINE_LAG: &str = "robot.agent.pipeline_lag";
    pub const SPOOL_FULL: &str = "robot.agent.spool_full";
    pub const EVIDENCE_DEGRADED: &str = "robot.agent.evidence_degraded";
    /// The black box quarantined damaged segments (or damage in its active
    /// segment) when it was opened; severity is the recorder's.
    pub const EVIDENCE_QUARANTINED: &str = "robot.agent.evidence_quarantined";
    /// The black box found authentic proof that its newest records were cut
    /// (`TruncationDetected`) when it was opened. Always Critical.
    pub const EVIDENCE_TRUNCATED: &str = "robot.agent.evidence_truncated";
    /// The correlation engine evicted or refused pending state.
    pub const CORRELATION_PRESSURE: &str = "robot.agent.correlation_pressure";
    /// Control-plane requests that failed authentication (bad or missing
    /// signature, unknown key, stale timestamp, replayed nonce).
    pub const CONTROL_PLANE_UNAUTHENTICATED: &str = "robot.agent.control_plane_unauthenticated";
    /// Authenticated control-plane requests refused as invalid (unknown
    /// action, a parameter the class does not take, an override).
    pub const CONTROL_PLANE_INVALID: &str = "robot.agent.control_plane_invalid";
    /// The control plane's TCP listener is under handshake pressure:
    /// pre-authentication connections evicted, cut for lack of progress,
    /// timed out or refused by the handshake rate limit (W2-4).
    pub const CONTROL_PLANE_PRESSURE: &str = "robot.agent.control_plane_pressure";
}

/// Thresholds (milliseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    pub silence_ms: u64,
    pub lag_ms: u64,
    pub report_ms: u64,
    /// An input that ends is expected (replay mode): no finding, and the
    /// state does not turn unknown because of it.
    pub ends_expected: bool,
}

/// One input's counters at evaluation time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputSnapshot {
    pub name: String,
    pub last_rx_ms: Option<u64>,
    pub dropped: u64,
    pub malformed: u64,
    pub last_malformed: Option<String>,
    pub ended: bool,
    pub end_error: Option<String>,
}

/// Everything else evaluated at a tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DaemonSnapshot {
    /// Largest queue latency seen since the last evaluation (ms).
    pub max_queue_age_ms: u64,
    /// How late this tick ran (ms).
    pub tick_delay_ms: u64,
    pub spool_dropped: u64,
    pub spool_write_errors: u64,
    pub evidence_degraded: bool,
    /// The profile is not enforced (observe-only, refused or file check
    /// failed).
    pub profile_not_enforced: bool,
    /// Every input thread has exited (the queue's senders are all gone):
    /// nothing can arrive any more.
    pub all_inputs_gone: bool,
    /// Packets of a middleware the capture cannot decode (Zenoh) seen on
    /// the bus so far (`CaptureHealth::zenoh` of the capture source).
    pub capture_zenoh: u64,
    /// Datagrams the capture accepted as RTPS so far.
    pub capture_rtps: u64,
}

/// The robot's monitoring state, as a console should show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Every input live, nothing lost, enforcing.
    Ok,
    /// Inputs live but something is reduced (drops, observe-only profile,
    /// spool or black-box trouble).
    Degraded,
    /// The agent is (partly) blind: an input is silent or ended, no data
    /// yet, or the pipeline lags. Never shown as OK.
    Unknown,
}

/// State plus the reasons for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthState {
    pub state: State,
    pub reasons: Vec<String>,
}

/// A health problem worth a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    InputSilent {
        input: String,
        for_ms: u64,
        never: bool,
        /// Malformed items skipped on the input so far (they do not count
        /// as data).
        malformed: u64,
    },
    InputEnded {
        input: String,
        error: Option<String>,
    },
    QueueOverflow {
        input: String,
        delta: u64,
        total: u64,
    },
    InputMalformed {
        input: String,
        delta: u64,
        total: u64,
        last: Option<String>,
    },
    PipelineLag {
        lag_ms: u64,
    },
    SpoolTrouble {
        dropped_delta: u64,
        errors_delta: u64,
        dropped_total: u64,
    },
    EvidenceDegraded,
}

/// A transition worth a black-box note but not a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Recovery {
    InputRecovered { input: String },
    LagCleared,
    EvidenceRecovered,
}

impl Issue {
    /// The input the issue is about (`None` for daemon-wide issues).
    pub fn input(&self) -> Option<&str> {
        match self {
            Issue::InputSilent { input, .. }
            | Issue::InputEnded { input, .. }
            | Issue::QueueOverflow { input, .. }
            | Issue::InputMalformed { input, .. } => Some(input),
            _ => None,
        }
    }

    /// The deviation for this issue (mode is set to observe by the agent).
    pub fn deviation(&self) -> Deviation {
        match self {
            Issue::InputSilent {
                input,
                for_ms,
                never,
                malformed,
            } => {
                let junk = if *malformed > 0 {
                    format!(" ({malformed} malformed item(s) skipped on it so far)")
                } else {
                    String::new()
                };
                Deviation::new(
                    rules::INPUT_SILENT,
                    Severity::High,
                    if *never {
                        format!(
                            "input {input} has delivered no valid data since the agent started \
                             {for_ms} ms ago{junk}; the agent is blind on it (robot state unknown)"
                        )
                    } else {
                        format!(
                            "input {input} has delivered no valid data for {for_ms} ms{junk}; the \
                             agent is blind on it (robot state unknown)"
                        )
                    },
                )
            }
            Issue::InputEnded { input, error } => Deviation::new(
                rules::INPUT_ENDED,
                Severity::High,
                match error {
                    Some(e) => format!(
                        "input {input} ended with an error: {e}; the agent is blind on it \
                         (robot state unknown)"
                    ),
                    None => format!(
                        "input {input} ended; the agent is blind on it (robot state unknown)"
                    ),
                },
            ),
            Issue::QueueOverflow {
                input,
                delta,
                total,
            } => Deviation::new(
                rules::QUEUE_OVERFLOW,
                Severity::Medium,
                format!(
                    "{delta} item(s) from input {input} dropped because a queue was full (the \
                     agent's input queue, or for a forwarded input the producer's own) \
                     ({total} since start); they were not inspected"
                ),
            ),
            Issue::InputMalformed {
                input,
                delta,
                total,
                last,
            } => Deviation::new(
                rules::INPUT_MALFORMED,
                Severity::Low,
                format!(
                    "{delta} malformed item(s) on input {input} skipped ({total} since start){}",
                    last.as_ref()
                        .map(|l| format!("; last: {l}"))
                        .unwrap_or_default()
                ),
            ),
            Issue::PipelineLag { lag_ms } => Deviation::new(
                rules::PIPELINE_LAG,
                Severity::Medium,
                format!(
                    "the pipeline lags: input waited {lag_ms} ms before inspection; detections \
                     are late (robot state unknown while it lasts)"
                ),
            ),
            Issue::SpoolTrouble {
                dropped_delta,
                errors_delta,
                dropped_total,
            } => Deviation::new(
                rules::SPOOL_FULL,
                Severity::High,
                format!(
                    "{dropped_delta} finding(s) not spooled because the spool is full of \
                     unexported records and {errors_delta} spool write error(s) \
                     ({dropped_total} dropped since start); they are in the black box only"
                ),
            ),
            Issue::EvidenceDegraded => Deviation::new(
                rules::EVIDENCE_DEGRADED,
                Severity::High,
                "the black box is failing: findings are produced without evidence links",
            ),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct InputTrack {
    silent: bool,
    ended_reported: bool,
    dropped_reported: u64,
    dropped_last_report: Option<u64>,
    malformed_reported: u64,
    malformed_last_report: Option<u64>,
}

/// Stateful evaluator (one per daemon).
#[derive(Debug, Clone)]
pub struct HealthMonitor {
    cfg: HealthConfig,
    inputs: Vec<InputTrack>,
    lagging: bool,
    evidence_down: bool,
    spool_dropped_reported: u64,
    spool_errors_reported: u64,
    spool_last_report: Option<u64>,
}

/// `true` if a counter report is due (first report, or `report_ms` passed).
fn due(last: Option<u64>, now: u64, every: u64) -> bool {
    last.is_none_or(|t| now.saturating_sub(t) >= every)
}

impl HealthMonitor {
    pub fn new(cfg: HealthConfig, inputs: usize) -> Self {
        Self {
            cfg,
            inputs: vec![InputTrack::default(); inputs],
            lagging: false,
            evidence_down: false,
            spool_dropped_reported: 0,
            spool_errors_reported: 0,
            spool_last_report: None,
        }
    }

    /// Evaluate at `now_ms` (since daemon start). Returns the state, the
    /// issues to report now, and recoveries to note.
    pub fn evaluate(
        &mut self,
        now_ms: u64,
        inputs: &[InputSnapshot],
        d: &DaemonSnapshot,
    ) -> (HealthState, Vec<Issue>, Vec<Recovery>) {
        let mut state = State::Ok;
        let mut reasons = Vec::new();
        let mut issues = Vec::new();
        let mut recoveries = Vec::new();
        let mut raise = |s: State, why: String, state: &mut State| {
            *state = (*state).max(s);
            reasons.push(why);
        };
        if self.inputs.len() < inputs.len() {
            self.inputs.resize(inputs.len(), InputTrack::default());
        }
        if inputs.is_empty() {
            raise(State::Unknown, "no inputs".into(), &mut state);
        }
        for (snap, tr) in inputs.iter().zip(self.inputs.iter_mut()) {
            let name = &snap.name;
            // Ended.
            if snap.ended {
                let bad = !self.cfg.ends_expected || snap.end_error.is_some();
                if bad {
                    raise(State::Unknown, format!("input {name} ended"), &mut state);
                    if !tr.ended_reported {
                        tr.ended_reported = true;
                        issues.push(Issue::InputEnded {
                            input: name.clone(),
                            error: snap.end_error.clone(),
                        });
                    }
                }
            } else {
                // Silence.
                let idle = now_ms.saturating_sub(snap.last_rx_ms.unwrap_or(0));
                if snap.last_rx_ms.is_none() {
                    raise(
                        State::Unknown,
                        if snap.malformed > 0 {
                            format!(
                                "input {name}: no valid data yet ({} malformed)",
                                snap.malformed
                            )
                        } else {
                            format!("input {name}: no data yet")
                        },
                        &mut state,
                    );
                } else if idle >= self.cfg.silence_ms {
                    raise(
                        State::Unknown,
                        format!("input {name} silent for {idle} ms"),
                        &mut state,
                    );
                }
                let silent_now = idle >= self.cfg.silence_ms;
                if silent_now && !tr.silent {
                    tr.silent = true;
                    issues.push(Issue::InputSilent {
                        input: name.clone(),
                        for_ms: idle,
                        never: snap.last_rx_ms.is_none(),
                        malformed: snap.malformed,
                    });
                } else if !silent_now && tr.silent {
                    tr.silent = false;
                    recoveries.push(Recovery::InputRecovered {
                        input: name.clone(),
                    });
                }
            }
            // Drops.
            if snap.dropped > tr.dropped_reported {
                raise(
                    State::Degraded,
                    format!("input {name}: queue drops"),
                    &mut state,
                );
                if due(tr.dropped_last_report, now_ms, self.cfg.report_ms) {
                    issues.push(Issue::QueueOverflow {
                        input: name.clone(),
                        delta: snap.dropped - tr.dropped_reported,
                        total: snap.dropped,
                    });
                    tr.dropped_reported = snap.dropped;
                    tr.dropped_last_report = Some(now_ms);
                }
            }
            // Malformed input (not a state change by itself: hostile peers
            // can send garbage, the agent still sees the rest; junk alone
            // does not keep an input from going silent, above).
            if snap.malformed > tr.malformed_reported
                && due(tr.malformed_last_report, now_ms, self.cfg.report_ms)
            {
                issues.push(Issue::InputMalformed {
                    input: name.clone(),
                    delta: snap.malformed - tr.malformed_reported,
                    total: snap.malformed,
                    last: snap.last_malformed.clone(),
                });
                tr.malformed_reported = snap.malformed;
                tr.malformed_last_report = Some(now_ms);
            }
        }
        if d.all_inputs_gone && !self.cfg.ends_expected {
            raise(
                State::Unknown,
                "every input has ended: the agent receives nothing".into(),
                &mut state,
            );
        }
        // Lag: raise above lag_ms, clear below half of it (hysteresis).
        let lag = d.max_queue_age_ms.max(d.tick_delay_ms);
        if lag > self.cfg.lag_ms {
            raise(State::Unknown, format!("pipeline lag {lag} ms"), &mut state);
            if !self.lagging {
                self.lagging = true;
                issues.push(Issue::PipelineLag { lag_ms: lag });
            }
        } else if self.lagging && lag <= self.cfg.lag_ms / 2 {
            self.lagging = false;
            recoveries.push(Recovery::LagCleared);
        } else if self.lagging {
            raise(
                State::Unknown,
                format!("pipeline lag {lag} ms (recovering)"),
                &mut state,
            );
        }
        // Spool.
        let sd = d.spool_dropped.saturating_sub(self.spool_dropped_reported);
        let se = d
            .spool_write_errors
            .saturating_sub(self.spool_errors_reported);
        if sd > 0 || se > 0 {
            raise(State::Degraded, "spool full or failing".into(), &mut state);
            if due(self.spool_last_report, now_ms, self.cfg.report_ms) {
                issues.push(Issue::SpoolTrouble {
                    dropped_delta: sd,
                    errors_delta: se,
                    dropped_total: d.spool_dropped,
                });
                self.spool_dropped_reported = d.spool_dropped;
                self.spool_errors_reported = d.spool_write_errors;
                self.spool_last_report = Some(now_ms);
            }
        }
        // Black box.
        if d.evidence_degraded {
            raise(
                State::Degraded,
                "black box failing: evidence is being lost".into(),
                &mut state,
            );
            if !self.evidence_down {
                self.evidence_down = true;
                issues.push(Issue::EvidenceDegraded);
            }
        } else if self.evidence_down {
            self.evidence_down = false;
            recoveries.push(Recovery::EvidenceRecovered);
        }
        if d.profile_not_enforced {
            raise(
                State::Degraded,
                "profile not enforced (observe-only)".into(),
                &mut state,
            );
        }
        // A bus the sensor cannot read is never "ok" (the finding itself is
        // robot.capture.unsupported_middleware, from the pipeline).
        if d.capture_zenoh > 0 && d.capture_rtps == 0 {
            raise(
                State::Unknown,
                format!(
                    "capture sees {} Zenoh packet(s) and no RTPS: the robot's middleware \
                     (rmw_zenoh) is not inspected, the agent is blind to its bus",
                    d.capture_zenoh
                ),
                &mut state,
            );
        } else if d.capture_zenoh > 0 {
            raise(
                State::Degraded,
                format!(
                    "capture sees {} Zenoh packet(s) besides RTPS: that part of the bus is not \
                     inspected",
                    d.capture_zenoh
                ),
                &mut state,
            );
        }
        (HealthState { state, reasons }, issues, recoveries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: HealthConfig = HealthConfig {
        silence_ms: 1_000,
        lag_ms: 500,
        report_ms: 2_000,
        ends_expected: false,
    };

    fn snap(name: &str, last: Option<u64>) -> InputSnapshot {
        InputSnapshot {
            name: name.into(),
            last_rx_ms: last,
            ..Default::default()
        }
    }

    #[test]
    fn never_ok_before_data_then_silent_once_then_recovered() {
        let mut h = HealthMonitor::new(CFG, 1);
        let d = DaemonSnapshot::default();
        let (s, i, _) = h.evaluate(100, &[snap("capture", None)], &d);
        assert_eq!(s.state, State::Unknown);
        assert!(i.is_empty(), "no finding before silence_ms");
        let (s, i, _) = h.evaluate(1_200, &[snap("capture", None)], &d);
        assert_eq!(s.state, State::Unknown);
        assert_eq!(
            i,
            vec![Issue::InputSilent {
                input: "capture".into(),
                for_ms: 1_200,
                never: true,
                malformed: 0,
            }]
        );
        let dev = i[0].deviation();
        assert_eq!(dev.rule_str(), rules::INPUT_SILENT);
        assert_eq!(dev.severity, Severity::High);
        // Still silent: no repeat.
        let (_, i, _) = h.evaluate(5_000, &[snap("capture", None)], &d);
        assert!(i.is_empty());
        // Data arrives: OK again, recovery noted.
        let (s, i, r) = h.evaluate(5_100, &[snap("capture", Some(5_050))], &d);
        assert_eq!(s.state, State::Ok, "{s:?}");
        assert!(i.is_empty());
        assert_eq!(
            r,
            vec![Recovery::InputRecovered {
                input: "capture".into()
            }]
        );
        // Silent again later: a new episode, reported again.
        let (_, i, _) = h.evaluate(7_000, &[snap("capture", Some(5_050))], &d);
        assert!(matches!(&i[..], [Issue::InputSilent { never: false, .. }]));
    }

    #[test]
    fn ended_inputs() {
        let mut h = HealthMonitor::new(CFG, 2);
        let mut a = snap("stdin", Some(10));
        a.ended = true;
        let b = snap("capture", Some(10));
        let d = DaemonSnapshot::default();
        let (s, i, _) = h.evaluate(20, &[a.clone(), b.clone()], &d);
        assert_eq!(s.state, State::Unknown);
        assert!(matches!(&i[..], [Issue::InputEnded { error: None, .. }]));
        assert!(h.evaluate(30, &[a.clone(), b.clone()], &d).1.is_empty());
        // Expected end (replay): fine, unless it ended with an error.
        let mut h = HealthMonitor::new(
            HealthConfig {
                ends_expected: true,
                ..CFG
            },
            2,
        );
        assert_eq!(
            h.evaluate(20, &[a.clone(), b.clone()], &d).0.state,
            State::Ok
        );
        a.end_error = Some("truncated pcap".into());
        let (s, i, _) = h.evaluate(30, &[a, b], &d);
        assert_eq!(s.state, State::Unknown);
        assert!(i[0].deviation().detail.contains("truncated pcap"));
    }

    #[test]
    fn counters_are_reported_as_deltas_and_rate_limited() {
        let mut h = HealthMonitor::new(CFG, 1);
        let d = DaemonSnapshot::default();
        let mut s = snap("sock", Some(0));
        s.dropped = 5;
        s.malformed = 2;
        s.last_malformed = Some("not a RobotEvent".into());
        let (st, i, _) = h.evaluate(10, &[s.clone()], &d);
        assert_eq!(st.state, State::Degraded);
        assert_eq!(i.len(), 2);
        assert!(matches!(
            i[0],
            Issue::QueueOverflow {
                delta: 5,
                total: 5,
                ..
            }
        ));
        assert!(i[1].deviation().detail.contains("not a RobotEvent"));
        s.dropped = 9;
        s.malformed = 3;
        s.last_rx_ms = Some(500);
        // Within report_ms: state degraded, no new finding.
        let (st, i, _) = h.evaluate(600, &[s.clone()], &d);
        assert_eq!(st.state, State::Degraded);
        assert!(i.is_empty());
        s.last_rx_ms = Some(2_100);
        let (_, i, _) = h.evaluate(2_100, &[s.clone()], &d);
        assert!(matches!(
            i[0],
            Issue::QueueOverflow {
                delta: 4,
                total: 9,
                ..
            }
        ));
        assert!(matches!(
            i[1],
            Issue::InputMalformed {
                delta: 1,
                total: 3,
                ..
            }
        ));
        // No new drops: OK.
        let (st, _, _) = h.evaluate(2_200, &[s], &d);
        assert_eq!(st.state, State::Ok);
    }

    #[test]
    fn a_zenoh_bus_is_never_ok() {
        let mut h = HealthMonitor::new(CFG, 1);
        let s = [snap("capture", Some(0))];
        let blind = DaemonSnapshot {
            capture_zenoh: 40,
            ..Default::default()
        };
        let (st, i, _) = h.evaluate(10, &s, &blind);
        assert_eq!(st.state, State::Unknown);
        assert!(st.reasons.iter().any(|r| r.contains("40 Zenoh")), "{st:?}");
        assert!(i.is_empty(), "the finding comes from the pipeline");
        let mixed = DaemonSnapshot {
            capture_zenoh: 40,
            capture_rtps: 7,
            ..Default::default()
        };
        assert_eq!(h.evaluate(20, &s, &mixed).0.state, State::Degraded);
        let rtps_only = DaemonSnapshot {
            capture_rtps: 7,
            ..Default::default()
        };
        assert_eq!(h.evaluate(30, &s, &rtps_only).0.state, State::Ok);
    }

    #[test]
    fn lag_with_hysteresis_spool_and_evidence() {
        let mut h = HealthMonitor::new(CFG, 1);
        let s = [snap("x", Some(0))];
        let lag = |ms| DaemonSnapshot {
            max_queue_age_ms: ms,
            ..Default::default()
        };
        let (st, i, _) = h.evaluate(10, &s, &lag(800));
        assert_eq!(st.state, State::Unknown);
        assert_eq!(i, vec![Issue::PipelineLag { lag_ms: 800 }]);
        let (st, i, r) = h.evaluate(20, &s, &lag(400));
        assert_eq!(
            st.state,
            State::Unknown,
            "between lag/2 and lag: still lagging"
        );
        assert!(i.is_empty() && r.is_empty());
        let (st, _, r) = h.evaluate(30, &s, &lag(100));
        assert_eq!(st.state, State::Ok);
        assert_eq!(r, vec![Recovery::LagCleared]);
        let tick_late = DaemonSnapshot {
            tick_delay_ms: 900,
            ..Default::default()
        };
        assert_eq!(h.evaluate(40, &s, &tick_late).1.len(), 1);

        let mut h = HealthMonitor::new(CFG, 1);
        let d = DaemonSnapshot {
            spool_dropped: 3,
            spool_write_errors: 1,
            evidence_degraded: true,
            profile_not_enforced: true,
            ..Default::default()
        };
        let (st, i, _) = h.evaluate(10, &s, &d);
        assert_eq!(st.state, State::Degraded);
        assert_eq!(i.len(), 2);
        assert!(i.iter().all(|x| x.input().is_none()));
        assert!(i[0].deviation().detail.contains("3 finding(s)"));
        assert_eq!(i[1], Issue::EvidenceDegraded);
        let ok = DaemonSnapshot {
            spool_dropped: 3,
            spool_write_errors: 1,
            ..Default::default()
        };
        let (st, i, r) = h.evaluate(20, &s, &ok);
        assert_eq!(st.state, State::Ok);
        assert!(i.is_empty());
        assert_eq!(r, vec![Recovery::EvidenceRecovered]);
    }

    /// Malformed-only input is blind: unknown, then a silence finding that
    /// counts the junk; never ok.
    #[test]
    fn malformed_only_input_is_never_ok() {
        let mut h = HealthMonitor::new(CFG, 1);
        let d = DaemonSnapshot::default();
        let mut s = snap("sock", None);
        s.malformed = 50;
        s.last_malformed = Some("not a RobotEvent".into());
        let (st, i, _) = h.evaluate(500, &[s.clone()], &d);
        assert_eq!(st.state, State::Unknown);
        assert!(st.reasons[0].contains("no valid data yet (50 malformed)"));
        assert!(matches!(&i[..], [Issue::InputMalformed { .. }]));
        s.malformed = 90;
        let (st, i, _) = h.evaluate(1_500, &[s.clone()], &d);
        assert_eq!(st.state, State::Unknown);
        let silent = i
            .iter()
            .find(|x| matches!(x, Issue::InputSilent { .. }))
            .unwrap();
        let dev = silent.deviation();
        assert_eq!(dev.severity, Severity::High);
        assert!(dev.detail.contains("90 malformed"), "{}", dev.detail);
        // Valid data then junk only: silent again after silence_ms.
        s.last_rx_ms = Some(1_600);
        assert_eq!(h.evaluate(1_700, &[s.clone()], &d).0.state, State::Ok);
        s.malformed = 500;
        let (st, i, _) = h.evaluate(2_700, &[s], &d);
        assert_eq!(st.state, State::Unknown);
        assert!(i.iter().any(|x| matches!(
            x,
            Issue::InputSilent {
                never: false,
                malformed: 500,
                ..
            }
        )));
    }

    #[test]
    fn all_inputs_gone_is_unknown_unless_expected() {
        let s = [snap("x", Some(0))];
        let gone = DaemonSnapshot {
            all_inputs_gone: true,
            ..Default::default()
        };
        let mut h = HealthMonitor::new(CFG, 1);
        let (st, _, _) = h.evaluate(10, &s, &gone);
        assert_eq!(st.state, State::Unknown);
        assert!(st.reasons.iter().any(|r| r.contains("every input")));
        let mut h = HealthMonitor::new(
            HealthConfig {
                ends_expected: true,
                ..CFG
            },
            1,
        );
        assert_eq!(h.evaluate(10, &s, &gone).0.state, State::Ok);
    }

    #[test]
    fn health_rule_ids_are_valid_ocsf_rule_ids() {
        for r in [
            rules::INPUT_SILENT,
            rules::INPUT_ENDED,
            rules::QUEUE_OVERFLOW,
            rules::INPUT_MALFORMED,
            rules::PIPELINE_LAG,
            rules::SPOOL_FULL,
            rules::EVIDENCE_DEGRADED,
        ] {
            assert!(robodr_ocsf::validate::is_valid_rule_id(r), "{r}");
        }
        let mut h = HealthMonitor::new(CFG, 0);
        assert_eq!(
            h.evaluate(0, &[], &DaemonSnapshot::default()).0.state,
            State::Unknown
        );
    }
}
