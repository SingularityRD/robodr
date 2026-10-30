//! Bounded subprocess runner for `tpm2_*`, `cryptsetup` and `clevis`.
//!
//! A program runs from an absolute path with a cleared environment (plus
//! the variables the caller names, e.g. `TPM2TOOLS_TCTI`), `/` as working
//! directory, the given bytes on stdin (secrets go through a pipe, never a
//! file or the command line), stdout and stderr captured up to
//! [`MAX_OUTPUT`] into buffers that are wiped when dropped, and a hard
//! timeout after which it is killed. A program that ran and failed is
//! `Ok` with its status.

use crate::{ErrorKind, SealError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Cap on captured stdout / stderr.
pub const MAX_OUTPUT: usize = 256 * 1024;

/// What a program produced.
#[derive(Debug)]
pub struct Output {
    /// Exit code (`None`: killed by a signal or the timeout).
    pub status: Option<i32>,
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Zeroizing<Vec<u8>>,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }

    /// A short printable summary of stderr (last meaningful line).
    pub fn error_line(&self) -> String {
        let text = String::from_utf8_lossy(&self.stderr);
        let line = text
            .lines()
            .rev()
            .find(|l| l.contains("ERROR") && !l.contains("Unable to run"))
            .or_else(|| text.lines().rev().find(|l| !l.trim().is_empty()))
            .unwrap_or("");
        line.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(240)
            .collect::<String>()
            .trim()
            .to_string()
    }
}

/// Runs programs. The seam for tests (fault injection) and for other
/// transports.
pub trait Runner: Send + Sync + std::fmt::Debug {
    fn run(
        &self,
        program: &Path,
        args: &[String],
        env: &[(&str, &str)],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Output, SealError>;
}

/// The real runner.
#[derive(Debug, Clone, Default)]
pub struct System;

fn reader<R: Read + Send + 'static>(r: R) -> mpsc::Receiver<Zeroizing<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut r = r;
        let mut buf = Zeroizing::new(Vec::with_capacity(4096));
        let _ = Read::by_ref(&mut r)
            .take(MAX_OUTPUT as u64)
            .read_to_end(&mut buf);
        let _ = std::io::copy(&mut r, &mut std::io::sink());
        let _ = tx.send(buf);
    });
    rx
}

impl Runner for System {
    fn run(
        &self,
        program: &Path,
        args: &[String],
        env: &[(&str, &str)],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Output, SealError> {
        if !program.is_absolute() {
            return Err(crate::invalid(format!(
                "{}: programs run by absolute path only",
                program.display()
            )));
        }
        let mut c = Command::new(program);
        c.args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .current_dir("/")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            c.env(k, v);
        }
        let mut child = c.spawn().map_err(|e| {
            SealError::new(
                ErrorKind::Unavailable,
                format!("{}: {e}", program.display()),
            )
        })?;
        if let (Some(data), Some(mut w)) = (stdin, child.stdin.take()) {
            // Small inputs (keys); a child that does not read gets EPIPE.
            let _ = w.write_all(data);
        }
        let out_rx = child.stdout.take().map(reader);
        let err_rx = child.stderr.take().map(reader);
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s.code(),
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SealError::new(
                        ErrorKind::Unavailable,
                        format!("{}: wait: {e}", program.display()),
                    ));
                }
            }
            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SealError::new(
                    ErrorKind::Unavailable,
                    format!(
                        "{}: timed out after {} ms (killed)",
                        program.display(),
                        timeout.as_millis()
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        let collect = |rx: Option<mpsc::Receiver<Zeroizing<Vec<u8>>>>| {
            let left = timeout
                .saturating_sub(start.elapsed())
                .max(Duration::from_millis(100));
            rx.and_then(|rx| rx.recv_timeout(left).ok())
                .unwrap_or_default()
        };
        Ok(Output {
            status,
            stdout: collect(out_rx),
            stderr: collect(err_rx),
        })
    }
}

/// A program in a tools directory (names are fixed by this crate).
pub fn tool(dir: &Path, name: &str) -> Result<PathBuf, SealError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(crate::invalid(format!("invalid tool name {name:?}")));
    }
    if !dir.is_absolute() {
        return Err(crate::invalid(format!(
            "tools directory {} must be absolute",
            dir.display()
        )));
    }
    Ok(dir.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_stdout_timeout() {
        let r = System;
        let o = r
            .run(
                Path::new("/bin/cat"),
                &[],
                &[],
                Some(b"secret"),
                Duration::from_secs(5),
            )
            .unwrap();
        assert!(o.ok());
        assert_eq!(&o.stdout[..], b"secret");
        let e = r
            .run(
                Path::new("/bin/sleep"),
                &["5".into()],
                &[],
                None,
                Duration::from_millis(100),
            )
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unavailable);
        assert!(r
            .run(Path::new("cat"), &[], &[], None, Duration::from_secs(1))
            .is_err());
        // The environment is cleared.
        let o = r
            .run(
                Path::new("/usr/bin/env"),
                &[],
                &[("X_SEAL", "1")],
                None,
                Duration::from_secs(5),
            )
            .unwrap();
        let env = String::from_utf8_lossy(&o.stdout).to_string();
        assert!(env.contains("X_SEAL=1") && !env.contains("HOME="), "{env}");
        assert!(tool(Path::new("/usr/bin"), "../x").is_err());
    }
}
