//! Field acceptance self-test (sales-readiness T13; findings contract 2.5,
//! `robot.agent.selftest`): prove that a finding travels from the running
//! agentd through its spool and the installed exporter, without waiting
//! for an attack.
//!
//! ```text
//! robodr-agentd selftest           <spool>/selftest.request  (nonce)
//!        │  write tmp, rename ──────────►│
//!        │                               │ robodr-agentd, next tick:
//!        │                               │ take + delete the request,
//!        │                               │ build the Low, observe-only
//!        │                               │ robot.agent.selftest finding
//!        │                               │ (nonce in its detail), spool it
//!        │◄──────── <spool>/selftest.answer {nonce, record | error}
//!        │
//!        │ wait for ready/<record> to move: acked/ = passed,
//!        │ rejected/ = failed, still in ready/ at the deadline = failed
//! ```
//!
//! # What "acked" proves
//!
//! The exporter renames a record into `acked/` only after its own
//! delivery: `robodr-uplink` after the SOC's ingest API answered `200` and
//! accepted the line, `robodr-kafka-publish` after the broker acknowledged
//! it, `robodr-spool-export` after it was committed into the diode
//! packer's outbox (the far side of an air gap is not proven here: the SOC
//! operator finds the finding by the nonce the command prints). A record in
//! `rejected/` was refused by the exporter or the SOC.
//!
//! # Trust
//!
//! The request carries only a nonce (32 lowercase hex digits). Anyone who
//! can write the request can already write records into `ready/` (the
//! spool belongs to agentd's user), so the request adds no capability; the
//! daemon still takes at most one request per [`MIN_INTERVAL_MS`] and
//! reads at most [`MAX_REQUEST_BYTES`], never through a symlink. The
//! command (run as root) never follows a symlink in the spool either: it
//! creates its request exclusively (`O_EXCL | O_NOFOLLOW`), reads the
//! answer with `O_NOFOLLOW | O_NONBLOCK` from a regular file only, and
//! looks at record names with `lstat`.
//!
//! The finding is observe-only self-health: it never causes a response and
//! is not fed to the correlator.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::control::fsutil::{open_read_nofollow, O_NOFOLLOW};

/// The rule id (findings contract 2.5, §3g).
pub const RULE: &str = "robot.agent.selftest";
/// The request file in the spool root.
pub const REQUEST_FILE: &str = "selftest.request";
/// The daemon's answer in the spool root (atomically replaced).
pub const ANSWER_FILE: &str = "selftest.answer";
/// Length of the nonce (hex digits: 128 bits).
pub const NONCE_LEN: usize = 32;
/// Largest request the daemon reads.
pub const MAX_REQUEST_BYTES: u64 = 128;
/// Largest answer the command reads.
pub const MAX_ANSWER_BYTES: u64 = 4096;
/// The daemon takes at most one request per this many ms.
pub const MIN_INTERVAL_MS: u64 = 1000;

/// The daemon's answer to one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    pub nonce: String,
    /// The spooled record's file name (`<seq:020>.json`), if spooled.
    pub record: Option<String>,
    /// Why the finding was not spooled.
    pub error: Option<String>,
}

/// `true` for exactly [`NONCE_LEN`] lowercase hex digits.
pub fn valid_nonce(s: &str) -> bool {
    s.len() == NONCE_LEN && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The nonce of a request file's bytes (one line; the newline is optional).
pub fn parse_request(bytes: &[u8]) -> Result<String, String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "request is not UTF-8".to_string())?;
    let s = s.strip_suffix('\n').unwrap_or(s);
    if valid_nonce(s) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "request is not a nonce of {NONCE_LEN} lowercase hex digits"
        ))
    }
}

/// The daemon's side: take (read and delete) a pending request from the
/// spool root. `None` when there is none. A request that is not valid is
/// deleted too (and reported as an error), so it cannot block later ones.
pub fn take_request(spool: &Path) -> Option<Result<String, String>> {
    let path = spool.join(REQUEST_FILE);
    let read = match open_read_nofollow(&path) {
        Ok(f) => {
            let mut buf = Vec::new();
            f.take(MAX_REQUEST_BYTES + 1)
                .read_to_end(&mut buf)
                .map(|_| buf)
                .map_err(|e| format!("cannot read {REQUEST_FILE}: {e}"))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => Err(format!("cannot open {REQUEST_FILE}: {e}")),
    };
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Some(Err(format!("cannot remove {REQUEST_FILE}: {e}"))),
    }
    Some(read.and_then(|b| {
        if b.len() as u64 > MAX_REQUEST_BYTES {
            Err(format!(
                "{REQUEST_FILE} is larger than {MAX_REQUEST_BYTES} bytes"
            ))
        } else {
            parse_request(&b)
        }
    }))
}

/// The detail of the self-test finding (the nonce is what the SOC looks
/// for).
pub fn detail(nonce: &str) -> String {
    format!(
        "field acceptance self-test {nonce}, requested by an operator with \
         `robodr-agentd selftest` to prove the path to the SOC; not a detection"
    )
}

/// A fresh nonce from the kernel's random source.
pub fn new_nonce() -> io::Result<String> {
    let mut b = [0u8; NONCE_LEN / 2];
    fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Options of the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientOptions {
    /// Overall deadline (request taken, finding spooled, record acked).
    pub timeout: Duration,
    /// How often the spool is looked at.
    pub poll: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            poll: Duration::from_millis(100),
        }
    }
}

/// How the self-test ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The exporter acknowledged the record (`acked/<record>`).
    Acked { nonce: String, record: String },
    /// Not proven; the reason is in the message (and was printed).
    Failed(String),
}

fn create_request(spool: &Path, nonce: &str) -> io::Result<()> {
    let target = spool.join(REQUEST_FILE);
    if fs::symlink_metadata(&target).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} exists: another self-test is pending, or robodr-agentd is not running",
                target.display()
            ),
        ));
    }
    let tmp = spool.join(format!(".{REQUEST_FILE}.{nonce}"));
    // 0644: agentd's user reads it (the command usually runs as root).
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(O_NOFOLLOW)
        .open(&tmp)?;
    let res = f
        .write_all(format!("{nonce}\n").as_bytes())
        .and_then(|()| f.sync_all())
        .and_then(|()| fs::rename(&tmp, &target));
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

fn read_answer(spool: &Path) -> Option<Answer> {
    let f = open_read_nofollow(&spool.join(ANSWER_FILE)).ok()?;
    let mut buf = Vec::new();
    f.take(MAX_ANSWER_BYTES).read_to_end(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

/// `true` if `path` exists (as anything; never followed).
fn present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// The command's side: request a self-test from the daemon whose spool is
/// `spool`, then follow the finding to the exporter's acknowledgement,
/// printing one line per step (`ok` / `FAIL`) to `out`.
pub fn run_client(spool: &Path, opts: ClientOptions, out: &mut dyn Write) -> Outcome {
    match new_nonce() {
        Ok(n) => run_client_with(spool, &n, opts, out),
        Err(e) => fail(out, format!("no random nonce: {e}")),
    }
}

fn fail(out: &mut dyn Write, msg: String) -> Outcome {
    let _ = writeln!(out, "FAIL {msg}");
    Outcome::Failed(msg)
}

fn run_client_with(spool: &Path, nonce: &str, opts: ClientOptions, out: &mut dyn Write) -> Outcome {
    let start = Instant::now();
    let deadline = start.checked_add(opts.timeout).unwrap_or(start);
    let request = spool.join(REQUEST_FILE);
    if let Err(e) = create_request(spool, nonce) {
        return fail(out, format!("request not written: {e}"));
    }
    let _ = writeln!(out, "ok request {nonce} written to {}", request.display());
    // 1. The daemon takes the request and answers.
    let answer = loop {
        if let Some(a) = read_answer(spool).filter(|a| a.nonce == nonce) {
            break a;
        }
        if Instant::now() >= deadline {
            // Withdraw it, so a daemon that starts later does not spool a
            // self-test nobody waits for (it may already be taken).
            let taken = !present(&request);
            let _ = fs::remove_file(&request);
            return fail(
                out,
                if taken {
                    "robodr-agentd took the request but did not answer in time".into()
                } else {
                    "robodr-agentd did not take the request in time (is it running with \
                     this configuration?)"
                        .into()
                },
            );
        }
        std::thread::sleep(opts.poll);
    };
    let record = match (answer.record, answer.error) {
        (Some(r), None) if is_record_name(&r) => r,
        (_, Some(e)) => {
            return fail(
                out,
                format!(
                    "robodr-agentd did not spool the self-test finding: {}",
                    robodr_ros2_pipeline::sanitize(&e)
                ),
            )
        }
        _ => return fail(out, "robodr-agentd's answer names no record".into()),
    };
    let _ = writeln!(
        out,
        "ok {RULE} finding spooled by robodr-agentd as ready/{record}"
    );
    // 2. The exporter delivers it.
    let (ready, acked, rejected) = (
        spool.join("ready").join(&record),
        spool.join("acked").join(&record),
        spool.join("rejected").join(&record),
    );
    loop {
        if present(&acked) {
            let _ = writeln!(
                out,
                "ok acknowledged by the exporter (acked/{record}); the SOC finds it as \
                 {RULE} with {nonce} in its detail"
            );
            return Outcome::Acked {
                nonce: nonce.to_string(),
                record,
            };
        }
        if present(&rejected) {
            return fail(
                out,
                format!("the exporter or the SOC rejected it (rejected/{record}, see its .reason.json or the exporter's dead letters)"),
            );
        }
        if !present(&ready) && !present(&acked) {
            // Moved between the two looks: look once more before failing.
            std::thread::sleep(opts.poll);
            if !present(&acked) && !present(&rejected) {
                return fail(
                    out,
                    format!("ready/{record} left the spool without an acknowledgement"),
                );
            }
            continue;
        }
        if Instant::now() >= deadline {
            return fail(
                out,
                format!(
                    "not acknowledged in time: ready/{record} is still waiting for the \
                     exporter (is it running, and does it reach its far side?)"
                ),
            );
        }
        std::thread::sleep(opts.poll);
    }
}

fn is_record_name(name: &str) -> bool {
    name.len() == 25 && name.ends_with(".json") && name.bytes().take(20).all(|b| b.is_ascii_digit())
}

/// The `spool.dir` of the daemon configuration at `path`, parsed strictly
/// ([`crate::config::parse`]) without reading any file it names.
pub fn spool_of_config(path: &Path) -> Result<PathBuf, String> {
    let text = crate::config::read_capped(path, crate::config::MAX_CONFIG_BYTES)?;
    let dir = crate::config::parse(&text)?.spool.dir;
    if !dir.is_absolute() {
        return Err(format!(
            "spool.dir must be an absolute path, got {:?}",
            dir.display().to_string()
        ));
    }
    Ok(dir)
}

/// Path of the answer file of a spool root (for the daemon).
pub fn answer_path(spool: &Path) -> PathBuf {
    spool.join(ANSWER_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "robodr-agentd-selftest-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&d);
        for s in ["ready", "acked", "rejected"] {
            fs::create_dir_all(d.join(s)).unwrap();
        }
        d
    }

    const N: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn nonces_and_requests() {
        assert!(valid_nonce(N));
        assert!(!valid_nonce(&N.to_uppercase()));
        assert!(!valid_nonce(&N[1..]));
        assert_eq!(parse_request(format!("{N}\n").as_bytes()).unwrap(), N);
        assert_eq!(parse_request(N.as_bytes()).unwrap(), N);
        assert!(parse_request(format!("{N}\n\n").as_bytes()).is_err());
        assert!(parse_request(b"../../etc").is_err());
        let a = new_nonce().unwrap();
        assert!(valid_nonce(&a), "{a}");
        assert_ne!(a, new_nonce().unwrap());
    }

    #[test]
    fn the_daemon_takes_a_request_once_and_drops_bad_ones() {
        let d = tmp("take");
        assert!(take_request(&d).is_none());
        create_request(&d, N).unwrap();
        // A second request while one is pending is refused.
        assert!(create_request(&d, N).is_err());
        assert_eq!(take_request(&d), Some(Ok(N.to_string())));
        assert!(take_request(&d).is_none(), "deleted when taken");
        fs::write(d.join(REQUEST_FILE), vec![b'a'; 200]).unwrap();
        assert!(take_request(&d).unwrap().is_err());
        assert!(!present(&d.join(REQUEST_FILE)), "a bad request is deleted");
        // Never read through a symlink.
        std::os::unix::fs::symlink("/etc/hostname", d.join(REQUEST_FILE)).unwrap();
        assert!(take_request(&d).unwrap().is_err());
        assert!(!present(&d.join(REQUEST_FILE)));
    }

    fn answer(d: &Path, a: &Answer) {
        fs::write(answer_path(d), serde_json::to_vec(a).unwrap()).unwrap();
    }

    fn opts(ms: u64) -> ClientOptions {
        ClientOptions {
            timeout: Duration::from_millis(ms),
            poll: Duration::from_millis(5),
        }
    }

    /// A fake daemon and exporter: take the request, answer, and move the
    /// record to `dest` (or leave it in `ready/`).
    fn serve(d: PathBuf, dest: Option<&'static str>, error: Option<&'static str>) {
        std::thread::spawn(move || {
            let nonce = loop {
                if let Some(r) = take_request(&d) {
                    break r.unwrap();
                }
                std::thread::sleep(Duration::from_millis(2));
            };
            let rec = "00000000000000000042.json";
            fs::write(d.join("ready").join(rec), b"{}").unwrap();
            answer(
                &d,
                &Answer {
                    nonce,
                    record: error.is_none().then(|| rec.to_string()),
                    error: error.map(str::to_string),
                },
            );
            if let Some(dest) = dest {
                std::thread::sleep(Duration::from_millis(20));
                fs::rename(d.join("ready").join(rec), d.join(dest).join(rec)).unwrap();
            }
        });
    }

    #[test]
    fn acked_passes_rejected_and_waiting_fail() {
        let d = tmp("acked");
        serve(d.clone(), Some("acked"), None);
        let mut out = Vec::new();
        let o = run_client_with(&d, N, opts(5000), &mut out);
        assert!(matches!(o, Outcome::Acked { .. }), "{o:?}");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("ok acknowledged"), "{text}");

        let d = tmp("rejected");
        serve(d.clone(), Some("rejected"), None);
        let o = run_client_with(&d, N, opts(5000), &mut Vec::new());
        assert!(
            matches!(&o, Outcome::Failed(m) if m.contains("rejected")),
            "{o:?}"
        );

        let d = tmp("waiting");
        serve(d.clone(), None, None);
        let o = run_client_with(&d, N, opts(300), &mut Vec::new());
        assert!(
            matches!(&o, Outcome::Failed(m) if m.contains("still waiting")),
            "{o:?}"
        );

        let d = tmp("full");
        serve(
            d.clone(),
            None,
            Some("spool full of unacknowledged records"),
        );
        let o = run_client_with(&d, N, opts(5000), &mut Vec::new());
        assert!(
            matches!(&o, Outcome::Failed(m) if m.contains("spool full")),
            "{o:?}"
        );
    }

    #[test]
    fn no_daemon_fails_in_time_and_withdraws_the_request() {
        let d = tmp("nodaemon");
        let o = run_client_with(&d, N, opts(100), &mut Vec::new());
        assert!(
            matches!(&o, Outcome::Failed(m) if m.contains("did not take")),
            "{o:?}"
        );
        assert!(!present(&d.join(REQUEST_FILE)), "withdrawn");
        // An answer to another nonce is not this one's.
        answer(
            &d,
            &Answer {
                nonce: "f".repeat(32),
                record: Some("00000000000000000001.json".into()),
                error: None,
            },
        );
        let o = run_client_with(&d, N, opts(100), &mut Vec::new());
        assert!(matches!(o, Outcome::Failed(_)), "{o:?}");
    }
}
