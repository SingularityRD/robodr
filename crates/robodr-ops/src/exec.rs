//! Running host commands for the preflight and the support bundle.
//!
//! Every command runs with a fixed search path ([`SAFE_PATH`]; the caller's
//! `PATH` is never used, so a writable directory early in an operator's
//! `PATH` cannot substitute `systemctl`), an otherwise empty environment
//! (`LC_ALL=C` for parseable output, no pager, no colours), stdin from
//! `/dev/null`, at most `cap` bytes of each output kept (the rest is read
//! and discarded, so the child never blocks on a full pipe), and a
//! timeout after which the child is killed.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The only directories commands are looked up in.
pub const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// What a command produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Exit code; `None` when killed (timeout or signal).
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    /// An output was longer than the cap and was cut.
    pub truncated: bool,
}

impl Output {
    /// Exited 0.
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// stdout as (lossy) UTF-8.
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// Something that runs commands: the host ([`Host`]) or a test double.
pub trait Runner {
    /// Run `prog` with `args`. `Err` when it could not be started (not
    /// installed); a non-zero exit is an `Ok` with its code.
    fn run(&self, prog: &str, args: &[&str]) -> std::io::Result<Output>;

    /// stdout of a successful run, or `None`.
    fn stdout(&self, prog: &str, args: &[&str]) -> Option<String> {
        self.run(prog, args)
            .ok()
            .filter(Output::ok)
            .map(|o| o.stdout_text())
    }
}

/// The real host.
#[derive(Debug, Clone, Copy)]
pub struct Host {
    pub timeout: Duration,
    pub cap: usize,
}

impl Default for Host {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            cap: 32 << 20,
        }
    }
}

/// Read all of `r`, keeping at most `cap` bytes.
fn drain(mut r: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let chunk = buf.get(..n).unwrap_or_default();
                let room = cap.saturating_sub(kept.len());
                if chunk.len() > room {
                    truncated = true;
                }
                kept.extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or_default());
            }
        }
    }
    (kept, truncated)
}

impl Runner for Host {
    fn run(&self, prog: &str, args: &[&str]) -> std::io::Result<Output> {
        let mut child = Command::new(prog)
            .args(args)
            .env_clear()
            .env("PATH", SAFE_PATH)
            .env("LC_ALL", "C")
            .env("SYSTEMD_PAGER", "")
            .env("SYSTEMD_COLORS", "0")
            .env("SYSTEMD_LESS", "")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let cap = self.cap;
        let out = child
            .stdout
            .take()
            .map(|o| std::thread::spawn(move || drain(o, cap)));
        let err = child
            .stderr
            .take()
            .map(|e| std::thread::spawn(move || drain(e, cap)));
        let deadline = Instant::now() + self.timeout;
        let mut timed_out = false;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break Some(st);
            }
            if Instant::now() >= deadline {
                timed_out = true;
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let (stdout, t1) = out
            .and_then(|h| h.join().ok())
            .unwrap_or((Vec::new(), false));
        let (stderr, t2) = err
            .and_then(|h| h.join().ok())
            .unwrap_or((Vec::new(), false));
        Ok(Output {
            code: status.and_then(|s| s.code()),
            stdout,
            stderr,
            timed_out,
            truncated: t1 || t2,
        })
    }
}

/// A command found in [`SAFE_PATH`] (absolute path), or `None`.
pub fn which(prog: &str) -> Option<std::path::PathBuf> {
    SAFE_PATH
        .split(':')
        .map(|d| std::path::Path::new(d).join(prog))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_is_cleared_and_path_fixed() {
        std::env::set_var("ROBODR_OPS_SECRET_ENV", "leak");
        let o = Host::default().run("env", &[]).unwrap();
        let t = o.stdout_text();
        assert!(o.ok());
        assert!(!t.contains("ROBODR_OPS_SECRET_ENV"), "{t}");
        assert!(t.contains(&format!("PATH={SAFE_PATH}")), "{t}");
    }

    #[test]
    fn output_is_capped_and_the_child_is_not_blocked() {
        let h = Host {
            timeout: Duration::from_secs(20),
            cap: 1000,
        };
        let o = h.run("sh", &["-c", "head -c 300000 /dev/zero"]).unwrap();
        assert!(o.ok());
        assert_eq!(o.stdout.len(), 1000);
        assert!(o.truncated);
    }

    #[test]
    fn a_hung_command_is_killed() {
        let h = Host {
            timeout: Duration::from_millis(200),
            cap: 1000,
        };
        let t = Instant::now();
        let o = h.run("sleep", &["30"]).unwrap();
        assert!(o.timed_out);
        assert!(!o.ok());
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_missing_program_is_an_error() {
        assert!(Host::default()
            .run("robodr-no-such-program-xyz", &[])
            .is_err());
    }
}
