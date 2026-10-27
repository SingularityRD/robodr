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
//!   so a probe that forks a child to keep running is killed with it. A
//!   probe gets a **session** of its own (`setsid`, which also makes it a
//!   group leader), so nothing it leaves behind can join a process group
//!   of the agent's session (Info of review 3: the reaper's group kill
//!   reached the agent's own non-probe descendants that a leftover had
//!   joined).
//! * stdout and stderr are read concurrently; at most `max_output` bytes
//!   are kept, the rest is read and discarded (a flood never blocks the
//!   child, never grows memory). A probe that exits but leaves processes
//!   holding its output fails, and those left in its group are killed;
//!   readers still blocked after that (a process escaped the group with
//!   `setsid` and holds the pipe) are abandoned and the run fails too.
//! * The group is signalled before the child is reaped (timeout), or only
//!   while members of it still hold the pipes (after a normal exit), so
//!   the group id cannot have been reused by an unrelated process.
//!
//! A **probe** (a run as another user) also gets (review L1):
//!
//! * **A reaper.** While a probe runs, this process is a child subreaper
//!   (`PR_SET_CHILD_SUBREAPER`): whatever the probe leaves behind, even a
//!   process that started its own session and closed every descriptor,
//!   is re-parented here instead of to init. After the probe exits, every
//!   such process (child of this process, running as the probe's UID, not
//!   a run in progress; found through this process's own `children`
//!   lists, which `ProtectProc=invisible` does not hide) is killed and
//!   reaped, together with their process groups (only groups of a
//!   session other than the agent's, i.e. created by the probe or its
//!   descendants), until none is left or
//!   [`REAP_DEADLINE`] passes (review L-F), and the probe fails
//!   (`left_processes`). They can be told apart
//!   safely: a process cannot change its UID without privileges (and the
//!   unit sets `NoNewPrivileges=`), and a child's pid cannot be reused
//!   before it is reaped.
//! * **Resource limits** of its own, set in the child before `execve`
//!   ([`ProbeLimits`]): CPU seconds (the timeout plus one), address space,
//!   open files and processes of its UID, so a probe cannot starve the
//!   agent that shares its unit's `TasksMax=` and `MemoryMax=`.

use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex};
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

/// Resource limits of a probe (`setrlimit(2)` in the child; soft and hard
/// alike, so the probe cannot raise them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeLimits {
    /// `RLIMIT_AS`, bytes.
    pub address_space: u64,
    /// `RLIMIT_NOFILE`.
    pub open_files: u64,
    /// `RLIMIT_NPROC` (processes of the probe's UID, system-wide).
    pub processes: u64,
}

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            address_space: 1024 * 1024 * 1024,
            open_files: 256,
            processes: 64,
        }
    }
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
    /// The probe exited but left processes holding its output (killed).
    pub left_processes: bool,
    /// A pipe was still held open after the kill (escaped process).
    pub pipes_held: bool,
    pub elapsed_ms: u64,
}

impl RunResult {
    /// Exit 0, in time, nothing escaped.
    pub fn success(&self) -> bool {
        self.code == Some(0)
            && !self.timed_out
            && self.spawn_error.is_none()
            && !self.left_processes
            && !self.pipes_held
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
            "{how}{}{}{}; output {} bytes{}: {out}",
            if self.left_processes {
                ", left processes behind (killed)"
            } else {
                ""
            },
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
const PR_SET_CHILD_SUBREAPER: i32 = 36;
const WNOHANG: i32 = 1;
const RLIMIT_CPU: i32 = 0;
const RLIMIT_NPROC: i32 = 6;
const RLIMIT_NOFILE: i32 = 7;
const RLIMIT_AS: i32 = 9;

#[repr(C)]
struct RLimit {
    cur: std::ffi::c_ulong,
    max: std::ffi::c_ulong,
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn prctl(option: i32, ...) -> i32;
    fn setrlimit(resource: i32, rlim: *const RLimit) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn getpgid(pid: i32) -> i32;
    fn getsid(pid: i32) -> i32;
    fn setsid() -> i32;
}

/// Children of this process spawned by [`run`] and not yet reaped (never
/// taken for leftovers by a concurrent run).
static LIVE: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());
/// Probe runs in progress (the subreaper attribute is on while > 0).
static REAPING: Mutex<usize> = Mutex::new(0);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `PR_SET_CHILD_SUBREAPER` on (`on`) or off for this process.
// FFI: std has no prctl.
#[allow(unsafe_code)]
fn set_subreaper(on: bool) {
    // SAFETY: prctl(PR_SET_CHILD_SUBREAPER, 0|1) takes integers only and
    // changes one process attribute; no memory is passed.
    unsafe {
        prctl(PR_SET_CHILD_SUBREAPER, std::ffi::c_ulong::from(on));
    }
}

fn reaper_acquire() {
    let mut n = lock(&REAPING);
    if *n == 0 {
        set_subreaper(true);
    }
    *n += 1;
}

fn reaper_release() {
    let mut n = lock(&REAPING);
    *n = n.saturating_sub(1);
    if *n == 0 {
        set_subreaper(false);
    }
}

/// The pids of this process's children, from its own
/// `/proc/<pid>/task/<tid>/children` lists (readable even under
/// `ProtectProc=invisible`, which hides the probe user's `/proc/<pid>`
/// from root without `CAP_SYS_PTRACE`). `None`: the kernel has no such
/// lists (`CONFIG_PROC_CHILDREN`).
fn children() -> Option<Vec<u32>> {
    let rd = std::fs::read_dir(format!("/proc/{}/task", std::process::id())).ok()?;
    let mut any = false;
    let mut out = Vec::new();
    for t in rd.flatten() {
        if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
            any = true;
            out.extend(s.split_whitespace().filter_map(|p| p.parse::<u32>().ok()));
        }
    }
    out.sort_unstable();
    out.dedup();
    any.then_some(out)
}

/// `(pid, zombie)` of this process's children that run as `uid` and are
/// not a run in progress: what a probe left behind (re-parented here).
/// A child whose `/proc` entry this process may not read is another
/// user's: with `ProtectProc=invisible` that is how the probe user's
/// processes look to root, and only a probe re-parents processes here.
fn leftovers(uid: u32) -> Vec<(i32, bool)> {
    let me = std::process::id();
    let live = lock(&LIVE).clone();
    let (cands, listed) = match children() {
        Some(c) => (c, true),
        None => (
            std::fs::read_dir("/proc")
                .map(|rd| {
                    rd.flatten()
                        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
                        .collect()
                })
                .unwrap_or_default(),
            false,
        ),
    };
    let mut out = Vec::new();
    for pid in cands {
        if live.contains(&pid) || pid == me {
            continue;
        }
        let Ok(p) = i32::try_from(pid) else {
            continue;
        };
        let Ok(st) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            if listed {
                out.push((p, false));
            }
            continue;
        };
        let field = |k: &str| {
            st.lines()
                .find_map(|l| l.strip_prefix(k))
                .map(str::trim)
                .unwrap_or("")
                .to_string()
        };
        let ppid = field("PPid:").parse::<u32>().ok();
        let ruid = field("Uid:")
            .split_whitespace()
            .next()
            .and_then(|u| u.parse::<u32>().ok());
        if ppid == Some(me) && ruid == Some(uid) {
            out.push((p, field("State:").starts_with('Z')));
        }
    }
    out
}

/// How long the reaper keeps killing a probe's leftovers before it gives
/// up (review L-F); the probe has failed by then either way.
pub const REAP_DEADLINE: Duration = Duration::from_secs(10);

/// Kill and reap everything a probe running as `uid` left behind, until
/// none is left or [`REAP_DEADLINE`] passes (review L-F: a fixed number of
/// rounds let a deep tree or a fork-and-exit chain outlast it). Each round
/// signals every leftover **and its process group**: the members of a
/// tree or chain share a group (unless each one calls `setsid`), so one
/// signal reaches those not yet re-parented here too; then every leftover
/// is reaped without waiting on any one of them. Returns the number of
/// live processes killed and whether none is left.
// FFI: std can signal and wait only for the `Child` it spawned.
#[allow(unsafe_code)]
fn reap_leftovers(uid: u32) -> (usize, bool) {
    let deadline = Instant::now() + REAP_DEADLINE;
    // SAFETY: getpgid(0) takes an integer and returns this process's
    // process group; no memory is passed.
    let own_group = unsafe { getpgid(0) };
    // SAFETY: as above (getsid(0): this process's session).
    let own_session = unsafe { getsid(0) };
    let mut killed = 0;
    loop {
        let l = leftovers(uid);
        if l.is_empty() {
            return (killed, true);
        }
        if Instant::now() >= deadline {
            return (killed, false);
        }
        let live = lock(&LIVE).clone();
        for (pid, zombie) in &l {
            if *zombie || *pid <= 1 {
                continue;
            }
            // SAFETY: integers only. `pid` is a child of this process that
            // is not reaped yet, so neither it nor its process group (of
            // which it is a member) can have been reused by an unrelated
            // process. The group is never this process's own, nor that of
            // a run in progress, and only a group of another session than
            // this process's: a probe starts a session of its own, and a
            // process can join only groups of its own session, so such a
            // group holds only the probe's descendants (review 3, Info).
            unsafe {
                let g = getpgid(*pid);
                let s = getsid(*pid);
                if g > 1
                    && g != own_group
                    && s > 0
                    && s != own_session
                    && u32::try_from(g).is_ok_and(|g| !live.contains(&g))
                {
                    kill(-g, SIGKILL);
                }
                kill(*pid, SIGKILL);
            }
            killed += 1;
        }
        for (pid, _) in &l {
            let mut st: i32 = 0;
            // SAFETY: `st` is a valid, writable i32 for the call.
            unsafe {
                waitpid(*pid, &mut st, WNOHANG);
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
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

/// Run `argv` under `limits`, optionally as `user` (a probe, with
/// [`ProbeLimits::default`] and the reaper).
pub fn run(argv: &[String], user: Option<RunAs>, limits: Limits) -> RunResult {
    match user {
        Some(u) => run_probe(argv, u, limits, ProbeLimits::default()),
        None => run_inner(argv, None, limits),
    }
}

/// Run `argv` (as this process's user, in a process group of its own,
/// with the fixed environment) and hand its **stdout** to `read` as it
/// arrives, so output of any size is consumed without being kept (stderr
/// is discarded). The whole group is killed after `timeout` (`read` then
/// sees the end of the stream). `Err`: `read` failed, the program could
/// not start, timed out, or did not exit 0.
pub fn run_reader<T>(
    argv: &[String],
    timeout: Duration,
    read: impl FnOnce(&mut dyn Read) -> Result<T, String>,
) -> Result<T, String> {
    let start = Instant::now();
    let prog = argv.first().ok_or("empty argv")?;
    if !prog.starts_with('/') {
        return Err("argv[0] is not an absolute path".into());
    }
    let mut cmd = Command::new(prog);
    cmd.args(&argv[1..])
        .env_clear()
        .env("PATH", FIXED_PATH)
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut live = lock(&LIVE);
    let mut child = cmd.spawn().map_err(|e| {
        format!(
            "{prog}: not started: {}",
            robodr_pkg::common::trunc(&e.to_string())
        )
    })?;
    live.insert(child.id());
    drop(live);
    let pgid = child.id();
    let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<()>();
    let f2 = fired.clone();
    // Kills the group if `read` is still reading at the deadline. Joined
    // before the child is reaped, so the group id is still the child's.
    let watchdog = std::thread::spawn(move || {
        if let Err(mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(timeout) {
            f2.store(true, std::sync::atomic::Ordering::SeqCst);
            kill_group(pgid);
        }
    });
    let res = match child.stdout.take() {
        Some(mut out) => read(&mut out),
        None => Err("no stdout".into()),
    };
    let _ = tx.send(());
    let _ = watchdog.join();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(_) => break None,
        }
        if start.elapsed() >= timeout {
            fired.store(true, std::sync::atomic::Ordering::SeqCst);
            kill_group(pgid);
            let _ = child.kill();
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    lock(&LIVE).remove(&pgid);
    if fired.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(format!(
            "{prog}: killed after the timeout ({} ms)",
            timeout.as_millis()
        ));
    }
    let v = res?;
    match status {
        Some(st) if st.success() => Ok(v),
        Some(st) => Err(format!("{prog}: {st}")),
        None => Err(format!("{prog}: lost")),
    }
}

/// Run `argv` as the probe user `user` with `rl` (see the module docs).
pub fn run_probe(argv: &[String], user: RunAs, limits: Limits, rl: ProbeLimits) -> RunResult {
    reaper_acquire();
    let r = run_inner(argv, Some((user, rl)), limits);
    reaper_release();
    r
}

fn run_inner(argv: &[String], user: Option<(RunAs, ProbeLimits)>, limits: Limits) -> RunResult {
    let start = Instant::now();
    let mut res = RunResult {
        code: None,
        signal: None,
        timed_out: false,
        output_bytes: 0,
        truncated: false,
        output: String::new(),
        spawn_error: None,
        left_processes: false,
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
        .stderr(Stdio::piped());
    if let Some((u, rl)) = user {
        // A session of its own (`setsid` in `set_limits`; it makes the
        // probe the leader of a new group too, so `process_group` is not
        // set: setsid fails in a group leader).
        cmd.gid(u.gid).uid(u.uid);
        let cpu = limits.timeout.as_secs().saturating_add(1);
        set_limits(&mut cmd, cpu, rl);
    } else {
        cmd.process_group(0);
    }
    // Registered before it can exit, so no concurrent run takes it for a
    // leftover.
    let mut live = lock(&LIVE);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            drop(live);
            res.spawn_error = Some(robodr_pkg::common::trunc(&e.to_string()));
            res.elapsed_ms = start.elapsed().as_millis() as u64;
            return res;
        }
    };
    live.insert(child.id());
    drop(live);
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
    lock(&LIVE).remove(&pgid);
    if let Some(st) = status {
        res.code = st.code();
        res.signal = st.signal();
    }
    // The child is reaped. Readers that do not finish within the grace
    // period mean something still holds the pipes: processes the probe
    // left behind. Those that stayed in its group keep the group id in use
    // (Linux does not reuse a pid while a process group of that id has
    // members), so signalling the group now reaches only them. The run
    // fails either way: a probe must not leave processes behind.
    let grace = Duration::from_millis(1000);
    let rxs: Vec<_> = [out_rx, err_rx].into_iter().flatten().collect();
    let mut got: Vec<Option<(Vec<u8>, u64)>> =
        rxs.iter().map(|rx| rx.recv_timeout(grace).ok()).collect();
    if got.iter().any(Option::is_none) {
        res.left_processes = true;
        kill_group(pgid);
    }
    // A probe's leftovers, wherever they went (own session, no pipes):
    // re-parented here by the subreaper, killed and reaped.
    if let Some((u, _)) = user {
        let (killed, gone) = reap_leftovers(u.uid);
        if killed > 0 || !gone {
            res.left_processes = true;
        }
    }
    if got.iter().any(Option::is_none) {
        for (g, rx) in got.iter_mut().zip(&rxs) {
            if g.is_none() {
                *g = rx.recv_timeout(grace).ok();
            }
        }
    }
    let mut kept = Vec::new();
    for g in got {
        match g {
            Some((b, total)) => {
                res.output_bytes += total;
                if total > b.len() as u64 {
                    res.truncated = true;
                }
                let room = limits.max_output.saturating_sub(kept.len());
                kept.extend_from_slice(&b[..b.len().min(room)]);
            }
            None => res.pipes_held = true,
        }
    }
    res.output = String::from_utf8_lossy(&kept).into_owned();
    res.elapsed_ms = start.elapsed().as_millis() as u64;
    res
}

/// Start a new session and set the probe's limits in the child, after it
/// dropped to the probe user and before `execve`.
// FFI: std has no setrlimit; `pre_exec` is unsafe by contract.
#[allow(unsafe_code)]
fn set_limits(cmd: &mut Command, cpu_s: u64, rl: ProbeLimits) {
    let set = [
        (RLIMIT_CPU, cpu_s),
        (RLIMIT_AS, rl.address_space),
        (RLIMIT_NOFILE, rl.open_files),
        (RLIMIT_NPROC, rl.processes),
    ];
    // SAFETY: the closure runs in the forked child before `execve`; it
    // only calls setsid(2) and setrlimit(2) (async-signal-safe) on values
    // computed before the fork, allocates nothing and takes no lock.
    unsafe {
        cmd.pre_exec(move || {
            if setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for (res, v) in set {
                let v = std::ffi::c_ulong::try_from(v).unwrap_or(std::ffi::c_ulong::MAX);
                let l = RLimit { cur: v, max: v };
                if setrlimit(res, &l) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
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
    fn a_probe_that_exits_but_leaves_a_child_fails_and_the_child_dies() {
        let r = run(
            &sv(&["/bin/sh", "-c", "sleep 30 & exit 0"]),
            None,
            lim(5000),
        );
        assert_eq!(r.code, Some(0));
        assert!(r.left_processes, "{r:?}");
        assert!(!r.pipes_held, "{r:?}");
        assert!(!r.success());
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
