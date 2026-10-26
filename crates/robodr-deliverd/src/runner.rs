//! Bounded execution of a command given as an **argv**, never a shell
//! string (§10, 13b requirements 1 and 2).
//!
//! * `argv[0]` must be an absolute path: `execve(2)` is called on it
//!   directly (std's `Command` does no `PATH` lookup for a name with a
//!   `/`), and the other elements are passed as they are, so `;`, `|`,
//!   `$(...)`, backticks and globs reach the program as literal bytes.
//! * A fixed minimal environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`,
//!   `LC_ALL=C`), working directory `/`, stdin from `/dev/null`.
//! * Optionally as another user: `setgid`, `setgroups(0)` (std drops every
//!   supplementary group when it changes the UID of a root process) and
//!   `setuid` before `execve` (tested: `tests` below runs `id`).
//! * Its own process group; on timeout the **whole group** gets `SIGKILL`,
//!   so a probe that forks a child to keep running is killed with it.
//! * stdout and stderr are read concurrently; at most `max_output` bytes
//!   are kept, the rest is read and discarded (a flood never blocks the
//!   child, never grows memory). Readers that are still blocked after the
//!   kill (a process escaped the group with `setsid` and holds the pipe)
//!   are abandoned and the run counts as failed.

use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The environment every command gets (nothing is inherited).
pub const FIXED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Run as this user and group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

/// Limits of one run.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub timeout: Duration,
    /// Bytes of stdout + stderr kept (each stream keeps at most this).
    pub max_output: usize,
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    /// Exit code, when the process exited normally.
    pub code: Option<i32>,
    /// Signal that ended it.
    pub signal: Option<i32>,
    pub timed_out: bool,
    /// Bytes of output read in total (kept or discarded).
    pub output_bytes: u64,
    /// More output than `max_output` arrived.
    pub truncated: bool,
    /// The first bytes of stdout then stderr (lossy UTF-8).
    pub output: String,
    /// The program could not be started (the reason).
    pub spawn_error: Option<String>,
    /// A pipe was still held open after the kill (escaped process).
    pub pipes_held: bool,
    pub elapsed_ms: u64,
}

impl RunResult {
    /// Exit 0, in time, nothing escaped.
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out && self.spawn_error.is_none() && !self.pipes_held
    }

    /// One line for evidence: outcome and at most 256 printable bytes of
    /// output.
    pub fn summary(&self) -> String {
        let how = if let Some(e) = &self.spawn_error {
            format!("not started: {e}")
        } else if self.timed_out {
            format!("killed after the timeout ({} ms)", self.elapsed_ms)
        } else if let Some(c) = self.code {
            format!("exit {c}")
        } else if let Some(s) = self.signal {
            format!("signal {s}")
        } else {
            "unknown end".into()
        };
        let out: String = robodr_pkg::common::trunc(&self.output)
            .chars()
            .take(256)
            .collect();
        format!(
            "{how}{}{}; output {} bytes{}: {out}",
            if self.pipes_held {
                ", output pipe held by an escaped process"
            } else {
                ""
            },
            if self.truncated { ", truncated" } else { "" },
            self.output_bytes,
            if self.truncated {
                " (kept the first part)"
            } else {
                ""
            },
        )
    }
}

const SIGKILL: i32 = 9;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

/// `SIGKILL` the process group `pgid` (`kill(-pgid, SIGKILL)`).
// FFI: std can signal one child (`Child::kill`), not a process group.
#[allow(unsafe_code)]
fn kill_group(pgid: u32) {
    let Ok(pid) = i32::try_from(pgid) else { return };
    if pid <= 1 {
        return;
    }
    // SAFETY: `kill` is libc's `int kill(pid_t, int)` (pid_t is i32 on
    // every Linux target); it takes plain integers and has no memory
    // effects. A negative pid addresses the process group the child was
    // put in (`process_group(0)`), never this process's group, and pids
    // 0 / 1 (which would address our own group or init) are excluded above.
    unsafe {
        kill(-pid, SIGKILL);
    }
}

fn reader(mut r: impl Read + Send + 'static, max: usize) -> mpsc::Receiver<(Vec<u8>, u64)> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut total: u64 = 0;
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n as u64;
                    let room = max.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        let _ = tx.send((kept, total));
    });
    rx
}

/// Run `argv` under `limits`, optionally as `user`.
pub fn run(argv: &[String], user: Option<RunAs>, limits: Limits) -> RunResult {
    let start = Instant::now();
    let mut res = RunResult {
        code: None,
        signal: None,
        timed_out: false,
        output_bytes: 0,
        truncated: false,
        output: String::new(),
        spawn_error: None,
        pipes_held: false,
        elapsed_ms: 0,
    };
    let Some(prog) = argv.first() else {
        res.spawn_error = Some("empty argv".into());
        return res;
    };
    if !prog.starts_with('/') {
        res.spawn_error = Some("argv[0] is not an absolute path".into());
        return res;
    }
    let mut cmd = Command::new(prog);
    cmd.args(&argv[1..])
        .env_clear()
        .env("PATH", FIXED_PATH)
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(u) = user {
        cmd.gid(u.gid).uid(u.uid);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            res.spawn_error = Some(robodr_pkg::common::trunc(&e.to_string()));
            res.elapsed_ms = start.elapsed().as_millis() as u64;
            return res;
        }
    };
    let pgid = child.id();
    let out_rx = child.stdout.take().map(|s| reader(s, limits.max_output));
    let err_rx = child.stderr.take().map(|s| reader(s, limits.max_output));
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(_) => break None,
        }
        if start.elapsed() >= limits.timeout {
            res.timed_out = true;
            kill_group(pgid);
            let _ = child.kill();
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // A child that exited normally may have left grandchildren in its group
    // holding the pipes: they die with the group too.
    kill_group(pgid);
    if let Some(st) = status {
        res.code = st.code();
        res.signal = st.signal();
    }
    let grace = Duration::from_millis(1000);
    let mut kept = Vec::new();
    for rx in [out_rx, err_rx].into_iter().flatten() {
        match rx.recv_timeout(grace) {
            Ok((b, total)) => {
                res.output_bytes += total;
                if total > b.len() as u64 {
                    res.truncated = true;
                }
                let room = limits.max_output.saturating_sub(kept.len());
                kept.extend_from_slice(&b[..b.len().min(room)]);
            }
            Err(_) => res.pipes_held = true,
        }
    }
    res.output = String::from_utf8_lossy(&kept).into_owned();
    res.elapsed_ms = start.elapsed().as_millis() as u64;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim(ms: u64) -> Limits {
        Limits {
            timeout: Duration::from_millis(ms),
            max_output: 4096,
        }
    }

    fn sv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn metacharacters_reach_the_program_literally() {
        let marker = std::env::temp_dir().join(format!("deliverd-pwned-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let evil = format!("x; touch {} | `id` $(id) *", marker.display());
        let r = run(&sv(&["/bin/echo", &evil]), None, lim(5000));
        assert!(r.success(), "{r:?}");
        assert_eq!(r.output.trim_end(), evil);
        assert!(!marker.exists(), "a shell interpreted the argv");
    }

    #[test]
    fn relative_program_and_empty_argv_are_refused() {
        assert!(run(&sv(&["sh", "-c", "true"]), None, lim(1000))
            .spawn_error
            .is_some());
        assert!(run(&[], None, lim(1000)).spawn_error.is_some());
        assert!(!run(&sv(&["/nonexistent/x"]), None, lim(1000)).success());
    }

    #[test]
    fn environment_is_fixed() {
        let r = run(&sv(&["/usr/bin/env"]), None, lim(5000));
        assert!(r.success());
        let mut lines: Vec<&str> = r.output.lines().collect();
        lines.sort();
        assert_eq!(
            lines,
            vec!["LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"]
        );
    }

    #[test]
    fn hang_is_killed_with_its_children() {
        // The shell forks a sleeper that would keep the pipe open.
        let r = run(
            &sv(&["/bin/sh", "-c", "sleep 30 & sleep 30; echo never"]),
            None,
            lim(300),
        );
        assert!(r.timed_out, "{r:?}");
        assert!(!r.success());
        assert!(
            !r.pipes_held,
            "the group kill must also free the pipe: {r:?}"
        );
        assert!(r.elapsed_ms < 5000, "{r:?}");
    }

    #[test]
    fn output_flood_is_bounded() {
        let r = run(&sv(&["/usr/bin/yes", "flood"]), None, lim(500));
        assert!(r.timed_out);
        assert!(r.truncated);
        assert!(r.output.len() <= 4096, "{}", r.output.len());
        assert!(r.output_bytes > 4096);
    }

    #[test]
    fn exit_codes() {
        assert_eq!(run(&sv(&["/bin/false"]), None, lim(5000)).code, Some(1));
        assert!(run(&sv(&["/bin/true"]), None, lim(5000)).success());
    }

    #[test]
    fn drops_to_the_user_and_its_group_only() {
        if !crate::users::is_root() {
            eprintln!("SKIPPED drops_to_the_user: needs root");
            return;
        }
        let r = run(
            &sv(&["/usr/bin/id"]),
            Some(RunAs {
                uid: 65_534,
                gid: 65_534,
            }),
            lim(5000),
        );
        assert!(r.success(), "{r:?}");
        let out = r.output.trim();
        assert!(out.starts_with("uid=65534"), "{out}");
        assert!(out.contains("gid=65534"), "{out}");
        // No supplementary group of root survives (groups= lists only the
        // primary group).
        let groups = out.split("groups=").nth(1).unwrap_or("");
        assert!(!groups.contains(','), "supplementary groups kept: {out}");
        assert!(!groups.contains("(root)"), "{out}");
    }
}
