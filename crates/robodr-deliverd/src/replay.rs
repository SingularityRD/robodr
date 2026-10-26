//! Replay recorded safety reports into agentd's live `safety_feed` socket
//! (`robodr-safety-replay`, `docs/SECURE-DELIVERY.md` §10, 13b): the
//! test and demo stand-in for a safety-PLC gateway.
//!
//! Input: JSON lines `{"at_ms": N, "state": "<safety state>"}` with
//! `at_ms` (milliseconds from the start of the replay) non-decreasing and
//! the states agentd's socket accepts (`idle`, `moving_slow`,
//! `moving_fast`, `collaborative_human_nearby`, `estop_active`,
//! `safe_state_active`, `unknown`). Unknown members, blank lines and
//! anything else are refused (the whole file, before anything is sent).
//!
//! Output: agentd's socket lines `{"state":"..."}`. Each recorded state is
//! sent at its time and then **repeated** every `repeat_ms` until the next
//! one (a gateway that falls silent goes stale in agentd and reads
//! `unknown`), and the last one for `hold_ms` more.
//!
//! This is a test tool. agentd's safety socket is mode 0600 (its own user
//! and root); whoever can write to it decides the safety state agentd and
//! `robodr-deliverd` act on, so the tool is not shipped in the packages.

use robodr_responder::SafetyState;
use serde::Deserialize;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

/// Largest recording read.
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
/// Most records.
pub const MAX_RECORDS: usize = 100_000;
/// Most lines sent in one replay.
pub const MAX_SENDS: usize = 1_000_000;
/// Shortest repeat interval.
pub const MIN_REPEAT_MS: u64 = 10;

/// One recorded report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub at_ms: u64,
    pub state: SafetyState,
}

/// Parse a recording.
pub fn parse(bytes: &[u8]) -> Result<Vec<Report>, String> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(format!("recording larger than {MAX_FILE_BYTES} bytes"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "recording is not UTF-8".to_string())?;
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() {
        return Err("empty recording".into());
    }
    let mut out = Vec::new();
    let mut last = 0u64;
    for (n, line) in body.split('\n').enumerate() {
        if out.len() >= MAX_RECORDS {
            return Err(format!("more than {MAX_RECORDS} records"));
        }
        let r: Report = serde_json::from_str(line).map_err(|e| {
            format!(
                "line {}: {}",
                n + 1,
                robodr_pkg::common::trunc(&e.to_string())
            )
        })?;
        if r.at_ms > robodr_pkg::MAX_SAFE_INTEGER {
            return Err(format!("line {}: at_ms out of range", n + 1));
        }
        if r.at_ms < last {
            return Err(format!("line {}: at_ms goes backwards", n + 1));
        }
        last = r.at_ms;
        out.push(r);
    }
    Ok(out)
}

/// The send schedule `(at_ms, state)` of `reports`.
pub fn schedule(
    reports: &[Report],
    repeat_ms: u64,
    hold_ms: u64,
) -> Result<Vec<(u64, SafetyState)>, String> {
    if repeat_ms < MIN_REPEAT_MS {
        return Err(format!("repeat interval below {MIN_REPEAT_MS} ms"));
    }
    let mut out = Vec::new();
    for (i, r) in reports.iter().enumerate() {
        let end = match reports.get(i + 1) {
            Some(n) => n.at_ms,
            None => r.at_ms.saturating_add(hold_ms).saturating_add(1),
        };
        let mut t = r.at_ms;
        loop {
            if out.len() >= MAX_SENDS {
                return Err(format!("more than {MAX_SENDS} lines to send"));
            }
            out.push((t, r.state));
            t = t.saturating_add(repeat_ms);
            if t >= end {
                break;
            }
        }
    }
    Ok(out)
}

/// The socket line for `s`.
pub fn line(s: SafetyState) -> String {
    format!("{{\"state\":\"{}\"}}\n", crate::safety::state_name(s))
}

/// Connect to agentd's socket (retrying for up to `wait`) and send the
/// schedule in real time. Returns the lines sent.
pub fn run(socket: &Path, sched: &[(u64, SafetyState)], wait: Duration) -> Result<usize, String> {
    let deadline = Instant::now() + wait;
    let mut s = loop {
        match std::os::unix::net::UnixStream::connect(socket) {
            Ok(s) => break s,
            Err(e) if Instant::now() >= deadline => {
                return Err(format!("{}: {e}", socket.display()))
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    let start = Instant::now();
    let mut sent = 0;
    for (at, st) in sched {
        let due = start + Duration::from_millis(*at);
        let now = Instant::now();
        if due > now {
            std::thread::sleep(due - now);
        }
        s.write_all(line(*st).as_bytes())
            .map_err(|e| format!("{}: {e}", socket.display()))?;
        sent += 1;
    }
    s.flush().map_err(|e| e.to_string())?;
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_schedule() {
        let r =
            parse(b"{\"at_ms\":0,\"state\":\"moving_slow\"}\n{\"at_ms\":100,\"state\":\"idle\"}\n")
                .unwrap();
        assert_eq!(r.len(), 2);
        let s = schedule(&r, 40, 50).unwrap();
        let times: Vec<u64> = s.iter().map(|x| x.0).collect();
        assert_eq!(times, vec![0, 40, 80, 100, 140]);
        assert_eq!(s[2].1, SafetyState::MovingSlow);
        assert_eq!(s[3].1, SafetyState::Idle);
        assert_eq!(
            line(SafetyState::EStopActive),
            "{\"state\":\"estop_active\"}\n"
        );
    }

    #[test]
    fn hostile_recordings_are_refused() {
        for bad in [
            &b""[..],
            b"\n",
            b"{\"at_ms\":0,\"state\":\"parked\"}",
            b"{\"at_ms\":0,\"state\":\"idle\",\"x\":1}",
            b"{\"at_ms\":5,\"state\":\"idle\"}\n{\"at_ms\":4,\"state\":\"idle\"}",
            b"{\"at_ms\":0,\"state\":\"idle\"}\n\n{\"at_ms\":1,\"state\":\"idle\"}",
            b"{\"at_ms\":-1,\"state\":\"idle\"}",
            b"{\"at_ms\":9007199254740992,\"state\":\"idle\"}",
            b"\xff",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let r = parse(b"{\"at_ms\":0,\"state\":\"idle\"}").unwrap();
        assert!(schedule(&r, 1, 0).is_err());
        assert!(schedule(&r, 10, 100_000_000).is_err());
    }
}
