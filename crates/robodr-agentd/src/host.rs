//! Host-side (Pulsar) threats: the `host_threats` input.
//!
//! `robodr-threat-forward`, a Pulsar module registered by `robodr-pulsard`,
//! writes every Pulsar threat (except the ROS 2 sensor's own, which agentd
//! sees through its own pipeline) to a unix stream socket this daemon
//! binds, one JSON object per line ([`parse_host_line`]):
//!
//! ```json
//! {"kind":"threat","v":1,"rule":"RoboDR: Interactive shell started on robot controller",
//!  "source":"rules-engine","severity":"medium","category":"execution","ts_ms":1790000000000,
//!  "pid":4242,"ppid":1,"uid":0,"gid":0,"image":"/usr/bin/bash","container":false}
//! {"kind":"heartbeat","v":1,"sent":17,"dropped":0,"skipped_own":3}
//! ```
//!
//! # What a threat becomes
//!
//! 1. A correlation signal `Signal::host(rule, severity)` (domain `host`,
//!    the Pulsar rule name as its id, so the shipped host-dependent rules
//!    match it), with the entity `process = "<pid>"` and the
//!    finding's black-box record as evidence reference, in the finding's
//!    (already stricter) mode.
//! 2. A finding through `Agent::handle_external(Detector::Sensor,
//!    "host:<module>", ..)` with the single catalog rule id
//!    [`HOST_THREAT_RULE`] (`robot.host.pulsar_threat`, data source
//!    `host_runtime`): the Pulsar rule name is not an OCSF rule id
//!    (`[a-z0-9._]`), so it travels in the finding's detail. Severity is the
//!    rule's (`low`..`critical`), Medium when the producer gave none.
//!
//! A threat whose `source` is `robodr-sensor-ros2` is dropped and counted
//! (`daemon.host_threats_own_skipped`): the forwarder should already skip it.
//!
//! # Liveness
//!
//! A heartbeat line counts as valid data on the input, a threat too; the
//! forwarder writes one right after connecting and whenever it has been
//! idle for its `heartbeat_ms` (default 5 s; keep it well below
//! `daemon.silence_ms`). A configured host input whose forwarder is not
//! connected therefore reads "no data yet" / silent, and the daemon's state
//! is `unknown`, never `ok`. The heartbeat's cumulative `dropped` count
//! (threats the forwarder could not queue or deliver) is added to the
//! input's `upstream_dropped`, which health reports like queue drops.
//!
//! # Hostile input
//!
//! * The socket's parent directory must be a directory owned by root or
//!   this daemon's user and not writable by group or others; an existing
//!   path must be a socket owned by this daemon's user (stale: replaced;
//!   live: refused). The socket is created mode `0600` (default) or `0660`
//!   (`socket_mode`).
//! * Every connection's peer is checked with `SO_PEERCRED`: only uid 0
//!   and `allowed_uids` may send; others are closed and counted
//!   (`rejected_connections`, and a malformed-input note so health reports
//!   it, rate-limited).
//! * Lines are at most [`MAX_HOST_LINE_BYTES`]; every field is known
//!   (unknown or duplicate keys refuse the line), strings are bounded and
//!   must not contain control characters, `v` must be
//!   [`HOST_PROTOCOL_VERSION`]. A refused line is counted as malformed (the
//!   rate-limited `robot.agent.input_malformed` health finding) and never
//!   counts as activity.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use robodr_events::Deviation;
/// Severity of a host threat (re-exported for producers' tests).
pub use robodr_events::Severity;
use serde::Deserialize;

use crate::input::{EventSocket, Payload};

/// OCSF rule id of a forwarded host threat's finding.
pub const HOST_THREAT_RULE: &str = "robot.host.pulsar_threat";
/// Threats of this Pulsar module are not taken (agentd has them already).
pub const SENSOR_MODULE: &str = "robodr-sensor-ros2";
/// Line protocol version.
pub const HOST_PROTOCOL_VERSION: u32 = 1;
/// Longest accepted line (bytes, newline excluded).
pub const MAX_HOST_LINE_BYTES: usize = 4096;
/// Bound of `rule` (bytes).
pub const MAX_RULE_BYTES: usize = 256;
/// Bound of `image` (bytes).
pub const MAX_IMAGE_BYTES: usize = 256;
/// Bound of `source` (bytes).
pub const MAX_SOURCE_BYTES: usize = 64;
/// Bound of `category` (bytes).
pub const MAX_CATEGORY_BYTES: usize = 64;
/// Most concurrent forwarder connections.
pub const MAX_HOST_CONNECTIONS: usize = 8;
/// Most entries of `allowed_uids`.
pub const MAX_ALLOWED_UIDS: usize = 16;

fn default_mode() -> String {
    "0600".into()
}
fn default_connections() -> usize {
    2
}

/// `host_threats` (optional): the socket `robodr-threat-forward` writes to.
///
/// ```json
/// "host_threats": { "socket_path": "/run/robodr-agentd/host-threats.sock",
///                   "socket_mode": "0660", "allowed_uids": [], "max_connections": 2 }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostThreatsSection {
    /// Absolute path of the unix stream socket this daemon binds.
    pub socket_path: PathBuf,
    /// Peer uids allowed besides root (uid 0 is always allowed: Pulsar
    /// runs as root).
    #[serde(default)]
    pub allowed_uids: Vec<u32>,
    /// `"0600"` (default) or `"0660"`. A forwarder running as root without
    /// `CAP_DAC_OVERRIDE` (the shipped `robodr-pulsard` unit) can only
    /// connect to a socket owned by another user through its group:
    /// use `"0660"` and give `robodr-pulsard` the daemon's group
    /// (`SupplementaryGroups=robodr`). The peer check applies either way.
    #[serde(default = "default_mode")]
    pub socket_mode: String,
    /// Concurrent connections, 1..=[`MAX_HOST_CONNECTIONS`] (default 2: a
    /// reconnecting forwarder may overlap its old connection briefly).
    #[serde(default = "default_connections")]
    pub max_connections: usize,
}

/// A validated [`HostThreatsSection`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostThreatsSpec {
    pub path: PathBuf,
    /// Sorted, deduplicated, always contains 0.
    pub allowed_uids: Vec<u32>,
    pub mode: u32,
    pub max_connections: usize,
}

impl HostThreatsSection {
    pub fn resolve(&self) -> Result<HostThreatsSpec, String> {
        let p = &self.socket_path;
        if p.as_os_str().is_empty() || !p.is_absolute() {
            return Err(format!(
                "host_threats.socket_path must be an absolute path, got {:?}",
                robodr_ros2_pipeline::sanitize(&p.display().to_string())
            ));
        }
        if p.file_name().is_none() || p.parent().is_none() {
            return Err("host_threats.socket_path must name a file in a directory".into());
        }
        let mode = match self.socket_mode.as_str() {
            "0600" => 0o600,
            "0660" => 0o660,
            other => {
                return Err(format!(
                    "host_threats.socket_mode {:?}: must be \"0600\" or \"0660\"",
                    robodr_ros2_pipeline::sanitize(other)
                ))
            }
        };
        if !(1..=MAX_HOST_CONNECTIONS).contains(&self.max_connections) {
            return Err(format!(
                "host_threats.max_connections must be 1..={MAX_HOST_CONNECTIONS}"
            ));
        }
        if self.allowed_uids.len() > MAX_ALLOWED_UIDS {
            return Err(format!(
                "host_threats.allowed_uids: at most {MAX_ALLOWED_UIDS} entries"
            ));
        }
        let mut allowed_uids = self.allowed_uids.clone();
        allowed_uids.push(0);
        allowed_uids.sort_unstable();
        allowed_uids.dedup();
        Ok(HostThreatsSpec {
            path: p.clone(),
            allowed_uids,
            mode,
            max_connections: self.max_connections,
        })
    }
}

/// One validated host threat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostThreat {
    /// Pulsar rule name (the threat's description), e.g. `RoboDR: ...`.
    pub rule: String,
    /// Pulsar module that raised it (`rules-engine`, ...).
    pub source: String,
    pub severity: Option<Severity>,
    pub category: Option<String>,
    /// Wall-clock time of the event (Unix ms), as Pulsar stamped it.
    pub ts_ms: Option<u64>,
    pub pid: i32,
    pub ppid: Option<i32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Executable path (attacker-influenced, bounded, no control chars).
    pub image: String,
    pub container: bool,
}

/// The forwarder's liveness line (cumulative counters of that forwarder).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostHeartbeat {
    pub sent: u64,
    pub dropped: u64,
    pub skipped_own: u64,
}

/// One parsed line of the host-threat socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostLine {
    Threat(Box<HostThreat>),
    Heartbeat(HostHeartbeat),
}

impl HostThreat {
    /// Severity used for the finding and the signal (Medium if absent).
    pub fn severity(&self) -> Severity {
        self.severity.unwrap_or(Severity::Medium)
    }

    /// From the ROS 2 sensor module (already seen by agentd).
    pub fn is_own_sensor(&self) -> bool {
        self.source == SENSOR_MODULE
    }

    /// The correlation `process` entity: the pid alone. Not the image:
    /// an `execve` keeps the process (and the pid) but changes the image,
    /// and Pulsar reports an empty image when its process tracker has not
    /// caught up yet (seen live: the same shell once with and once without
    /// its image). A pid reused within a rule's window can join two
    /// processes, which can only add a finding.
    pub fn process_entity(&self) -> String {
        self.pid.to_string()
    }

    /// The finding's deviation ([`HOST_THREAT_RULE`]).
    pub fn deviation(&self) -> Deviation {
        let mut ctx = format!("module {}", self.source);
        if let Some(c) = &self.category {
            ctx.push_str(&format!(", category {c}"));
        }
        let image = if self.image.is_empty() {
            "image unknown"
        } else {
            self.image.as_str()
        };
        let mut who = format!("pid {} ({image})", self.pid);
        if let Some(u) = self.uid {
            who.push_str(&format!(", uid {u}"));
        }
        if self.container {
            who.push_str(", in a container");
        }
        Deviation::new(
            HOST_THREAT_RULE,
            self.severity(),
            format!("Pulsar host rule {:?} ({ctx}) fired for {who}", self.rule),
        )
    }
}

/// Every key either line kind may carry; anything else refuses the line,
/// and so does a duplicate key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLine {
    kind: String,
    v: u32,
    rule: Option<String>,
    source: Option<String>,
    severity: Option<Severity>,
    category: Option<String>,
    ts_ms: Option<u64>,
    pid: Option<i32>,
    ppid: Option<i32>,
    uid: Option<u32>,
    gid: Option<u32>,
    image: Option<String>,
    container: Option<bool>,
    sent: Option<u64>,
    dropped: Option<u64>,
    skipped_own: Option<u64>,
}

fn text(what: &str, v: Option<String>, max: usize, required: bool) -> Result<String, String> {
    let s = match v {
        Some(s) => s,
        None if required => return Err(format!("{what} missing")),
        None => return Ok(String::new()),
    };
    if required && s.is_empty() {
        return Err(format!("{what} is empty"));
    }
    if s.len() > max {
        return Err(format!("{what} longer than {max} bytes"));
    }
    if s.chars().any(char::is_control) {
        return Err(format!("{what} contains control characters"));
    }
    Ok(s)
}

/// Parse one host-threat line (trimmed, non-empty, not a comment).
pub fn parse_host(t: &str) -> Result<HostLine, String> {
    if t.len() > MAX_HOST_LINE_BYTES {
        return Err(format!(
            "host-threat line longer than {MAX_HOST_LINE_BYTES} bytes"
        ));
    }
    let r: RawLine = serde_json::from_str(t).map_err(|e| format!("not a host-threat line: {e}"))?;
    if r.v != HOST_PROTOCOL_VERSION {
        return Err(format!(
            "host-threat line version {} (expected {HOST_PROTOCOL_VERSION})",
            r.v
        ));
    }
    match r.kind.as_str() {
        "threat" => {
            if r.sent.is_some() || r.dropped.is_some() || r.skipped_own.is_some() {
                return Err("heartbeat counters in a threat line".into());
            }
            let pid = r.pid.ok_or("threat line: pid missing")?;
            if pid < 0 {
                return Err("threat line: negative pid".into());
            }
            Ok(HostLine::Threat(Box::new(HostThreat {
                rule: text("rule", r.rule, MAX_RULE_BYTES, true)?,
                source: text("source", r.source, MAX_SOURCE_BYTES, true)?,
                severity: r.severity,
                category: match r.category {
                    Some(c) => Some(text("category", Some(c), MAX_CATEGORY_BYTES, true)?),
                    None => None,
                },
                ts_ms: r.ts_ms,
                pid,
                ppid: r.ppid,
                uid: r.uid,
                gid: r.gid,
                image: text("image", r.image, MAX_IMAGE_BYTES, false)?,
                container: r.container.unwrap_or(false),
            })))
        }
        "heartbeat" => {
            let threat_field = r.rule.is_some()
                || r.source.is_some()
                || r.severity.is_some()
                || r.category.is_some()
                || r.ts_ms.is_some()
                || r.pid.is_some()
                || r.ppid.is_some()
                || r.uid.is_some()
                || r.gid.is_some()
                || r.image.is_some()
                || r.container.is_some();
            if threat_field {
                return Err("threat fields in a heartbeat line".into());
            }
            Ok(HostLine::Heartbeat(HostHeartbeat {
                sent: r.sent.unwrap_or(0),
                dropped: r.dropped.unwrap_or(0),
                skipped_own: r.skipped_own.unwrap_or(0),
            }))
        }
        other => Err(format!(
            "host-threat line kind {:?} (expected threat or heartbeat)",
            robodr_ros2_pipeline::sanitize(other)
        )),
    }
}

/// [`crate::input::LineParser`] of the host-threat socket.
pub fn parse_host_line(t: &str) -> Result<Payload, String> {
    parse_host(t).map(Payload::Host)
}

/// Refuse a socket directory another user could swap the socket in: it
/// must be a directory owned by root or `euid`, without group / other write
/// permission.
pub fn check_socket_dir(dir: &Path, euid: u32) -> io::Result<()> {
    let m = std::fs::metadata(dir)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", dir.display())))?;
    if !m.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if m.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is writable by group or others (mode {:o}): another user could replace \
                 the socket; use a private directory such as /run/robodr-agentd",
                dir.display(),
                m.mode() & 0o7777
            ),
        ));
    }
    if m.uid() != 0 && m.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, neither root nor this daemon (uid {euid})",
                dir.display(),
                m.uid()
            ),
        ));
    }
    Ok(())
}

/// Bind the host-threat socket: directory check ([`check_socket_dir`]), an
/// existing path must be a socket owned by `euid` (then the usual stale /
/// live handling of [`crate::input::bind_event_socket`]), then `spec.mode`.
pub fn bind_host_socket(spec: &HostThreatsSpec, euid: u32) -> io::Result<EventSocket> {
    let dir = spec.path.parent().unwrap_or(Path::new("/"));
    check_socket_dir(dir, euid)?;
    match std::fs::symlink_metadata(&spec.path) {
        Ok(m) if m.file_type().is_socket() && m.uid() != euid => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is a socket owned by uid {}, not by this daemon (uid {euid})",
                    spec.path.display(),
                    m.uid()
                ),
            ))
        }
        Ok(m) if !m.file_type().is_socket() => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", spec.path.display()),
            ))
        }
        _ => {}
    }
    let sock = crate::input::bind_event_socket(&spec.path)?;
    if let Err(e) = std::fs::set_permissions(&spec.path, std::fs::Permissions::from_mode(spec.mode))
    {
        sock.remove_if_ours();
        return Err(e);
    }
    Ok(sock)
}

#[repr(C)]
struct UCred {
    pid: i32,
    uid: u32,
    gid: u32,
}

extern "C" {
    fn getsockopt(
        fd: std::ffi::c_int,
        level: std::ffi::c_int,
        name: std::ffi::c_int,
        value: *mut std::ffi::c_void,
        len: *mut u32,
    ) -> std::ffi::c_int;
}

#[cfg(any(target_arch = "mips", target_arch = "mips64", target_arch = "sparc64"))]
const SOL_SOCKET: std::ffi::c_int = 0xffff;
#[cfg(not(any(target_arch = "mips", target_arch = "mips64", target_arch = "sparc64")))]
const SOL_SOCKET: std::ffi::c_int = 1;
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
const SO_PEERCRED: std::ffi::c_int = 21;
#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
const SO_PEERCRED: std::ffi::c_int = 18;
#[cfg(target_arch = "sparc64")]
const SO_PEERCRED: std::ffi::c_int = 0x40;
#[cfg(not(any(
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "sparc64"
)))]
const SO_PEERCRED: std::ffi::c_int = 17;

/// The connected peer's uid (`SO_PEERCRED`: the credentials of the process
/// that connected, taken by the kernel at `connect`).
// FFI: `UnixStream::peer_cred` is still unstable in std.
#[allow(unsafe_code)]
pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let mut cred = UCred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<UCred>() as u32;
    // SAFETY: `cred` is a properly aligned, writable `struct ucred` of
    // `len` bytes that outlives the call; the fd is a live socket borrowed
    // from `s`. The kernel writes at most `len` bytes and updates `len`.
    let rc = unsafe {
        getsockopt(
            s.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut cred as *mut UCred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<UCred>() {
        return Err(io::Error::other("SO_PEERCRED returned a short struct"));
    }
    Ok(cred.uid)
}

/// The peer policy of a listener: `true` if `uid` may send.
pub fn peer_allowed(uid: u32, allowed: &[u32]) -> bool {
    allowed.contains(&uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    const THREAT: &str = r#"{"kind":"threat","v":1,"rule":"RoboDR: Interactive shell started on robot controller","source":"rules-engine","severity":"medium","category":"execution","ts_ms":1790000000000,"pid":4242,"ppid":1,"uid":0,"gid":0,"image":"/usr/bin/bash","container":false}"#;

    fn threat(t: &str) -> HostThreat {
        match parse_host(t).unwrap() {
            HostLine::Threat(t) => *t,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn forwarder_lines_parse() {
        let t = threat(THREAT);
        assert_eq!(
            t.rule,
            "RoboDR: Interactive shell started on robot controller"
        );
        assert_eq!(t.severity(), Severity::Medium);
        assert_eq!(t.process_entity(), "4242");
        assert!(!t.is_own_sensor());
        let d = t.deviation();
        assert_eq!(d.rule_str(), HOST_THREAT_RULE);
        assert!(
            d.detail.contains("RoboDR: Interactive shell"),
            "{}",
            d.detail
        );
        assert!(
            d.detail.contains("pid 4242 (/usr/bin/bash), uid 0"),
            "{}",
            d.detail
        );
        // Minimal threat: severity defaults to Medium, image unknown.
        let t = threat(r#"{"kind":"threat","v":1,"rule":"x","source":"m","pid":1}"#);
        assert_eq!(t.severity(), Severity::Medium);
        assert!(t.deviation().detail.contains("image unknown"));
        assert_eq!(
            parse_host(r#"{"kind":"heartbeat","v":1,"sent":3,"dropped":2,"skipped_own":1}"#)
                .unwrap(),
            HostLine::Heartbeat(HostHeartbeat {
                sent: 3,
                dropped: 2,
                skipped_own: 1
            })
        );
        assert_eq!(
            parse_host(r#"{"kind":"heartbeat","v":1}"#).unwrap(),
            HostLine::Heartbeat(HostHeartbeat::default())
        );
    }

    #[test]
    fn malformed_lines_are_refused_with_a_reason() {
        let long_rule = format!(
            r#"{{"kind":"threat","v":1,"rule":"{}","source":"m","pid":1}}"#,
            "r".repeat(MAX_RULE_BYTES + 1)
        );
        let long_line = format!(
            r#"{{"kind":"heartbeat","v":1,"sent":1{}}}"#,
            " ".repeat(MAX_HOST_LINE_BYTES)
        );
        let cases: &[(&str, &str)] = &[
            ("not json", "not a host-threat line"),
            ("[]", "not a host-threat line"),
            (
                r#"{"kind":"threat","v":2,"rule":"x","source":"m","pid":1}"#,
                "version",
            ),
            (
                r#"{"kind":"threat","rule":"x","source":"m","pid":1}"#,
                "missing field `v`",
            ),
            (r#"{"kind":"alert","v":1}"#, "kind"),
            (
                r#"{"kind":"threat","v":1,"rule":"x","source":"m","pid":1,"x":1}"#,
                "unknown field",
            ),
            (
                r#"{"kind":"threat","v":1,"rule":"x","rule":"y","source":"m","pid":1}"#,
                "duplicate field",
            ),
            (
                r#"{"kind":"threat","v":1,"source":"m","pid":1}"#,
                "rule missing",
            ),
            (
                r#"{"kind":"threat","v":1,"rule":"","source":"m","pid":1}"#,
                "rule is empty",
            ),
            (
                r#"{"kind":"threat","v":1,"rule":"x","pid":1}"#,
                "source missing",
            ),
            (
                r#"{"kind":"threat","v":1,"rule":"x","source":"m"}"#,
                "pid missing",
            ),
            (
                r#"{"kind":"threat","v":1,"rule":"x","source":"m","pid":-5}"#,
                "negative pid",
            ),
            (
                r#"{"kind":"threat","v":1,"rule":"a\u001b[31m","source":"m","pid":1}"#,
                "control",
            ),
            (
                r#"{"kind":"threat","v":1,"rule":"x","source":"m","pid":1,"image":"/x\n"}"#,
                "control",
            ),
            (
                r#"{"kind":"threat","v":1,"rule":"x","source":"m","pid":1,"severity":"fatal"}"#,
                "not a host-threat line",
            ),
            (
                r#"{"kind":"threat","v":1,"rule":"x","source":"m","pid":1,"sent":1}"#,
                "heartbeat counters",
            ),
            (r#"{"kind":"heartbeat","v":1,"rule":"x"}"#, "threat fields"),
            (
                r#"{"kind":"threat","v":1,"rule":"x","source":"m","pid":99999999999}"#,
                "not a host-threat line",
            ),
            (&long_rule, "rule longer"),
            (&long_line, "longer than 4096"),
        ];
        for (line, why) in cases {
            let e = parse_host(line).expect_err(line);
            assert!(e.contains(why), "{line}: {e}");
            assert!(parse_host_line(line).is_err());
        }
    }

    #[test]
    fn section_validation() {
        let base = HostThreatsSection {
            socket_path: "/run/robodr-agentd/host-threats.sock".into(),
            allowed_uids: vec![1000, 0, 1000],
            socket_mode: "0660".into(),
            max_connections: 2,
        };
        let s = base.resolve().unwrap();
        assert_eq!(s.allowed_uids, vec![0, 1000]);
        assert_eq!(s.mode, 0o660);
        let def: HostThreatsSection =
            serde_json::from_str(r#"{"socket_path":"/run/x/h.sock"}"#).unwrap();
        let d = def.resolve().unwrap();
        assert_eq!((d.mode, d.max_connections), (0o600, 2));
        assert_eq!(d.allowed_uids, vec![0]);
        for bad in [
            HostThreatsSection {
                socket_path: "rel.sock".into(),
                ..base.clone()
            },
            HostThreatsSection {
                socket_mode: "0666".into(),
                ..base.clone()
            },
            HostThreatsSection {
                max_connections: 0,
                ..base.clone()
            },
            HostThreatsSection {
                max_connections: MAX_HOST_CONNECTIONS + 1,
                ..base.clone()
            },
            HostThreatsSection {
                allowed_uids: (0..=MAX_ALLOWED_UIDS as u32).collect(),
                ..base.clone()
            },
        ] {
            assert!(bad.resolve().is_err(), "{bad:?}");
        }
        assert!(serde_json::from_str::<HostThreatsSection>(
            r#"{"socket_path":"/x/h.sock","mode":"0600"}"#
        )
        .is_err());
        assert!(peer_allowed(0, &d.allowed_uids));
        assert!(!peer_allowed(1000, &d.allowed_uids));
    }

    fn tmp(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("robodr-agentd-host-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn socket_permissions_are_checked() {
        let euid = crate::config::effective_uid();
        let dir = tmp("perm");
        let spec = |name: &str, mode: u32| HostThreatsSpec {
            path: dir.join(name),
            allowed_uids: vec![0],
            mode,
            max_connections: 1,
        };
        // Private directory: bound with the requested mode.
        let s = bind_host_socket(&spec("a.sock", 0o660), euid).unwrap();
        let m = std::fs::metadata(dir.join("a.sock")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o660);
        assert!(m.file_type().is_socket());
        // A live socket is not stolen.
        assert!(bind_host_socket(&spec("a.sock", 0o600), euid).is_err());
        assert!(s.remove_if_ours());
        // A regular file in the way is refused.
        std::fs::write(dir.join("f.sock"), b"x").unwrap();
        let e = bind_host_socket(&spec("f.sock", 0o600), euid).unwrap_err();
        assert!(e.to_string().contains("not a socket"), "{e}");
        // A socket owned by someone else is refused (checked as if this
        // daemon had another uid).
        drop(UnixListener::bind(dir.join("o.sock")).unwrap());
        let other = euid.wrapping_add(1);
        let e = bind_host_socket(&spec("o.sock", 0o600), other);
        let msg = e.err().map(|e| e.to_string()).unwrap_or_default();
        // (As root the directory check passes for any uid; otherwise the
        // directory, owned by us, is refused first.)
        assert!(msg.contains("owned by uid"), "{msg}");
        // ... while our own stale socket is replaced.
        let s = bind_host_socket(&spec("o.sock", 0o600), euid).unwrap();
        assert!(s.remove_if_ours());
        // Group- or world-writable directory: refused.
        for mode in [0o770, 0o707, 0o1777] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = bind_host_socket(&spec("b.sock", 0o600), euid).unwrap_err();
            assert!(e.to_string().contains("writable by group or others"), "{e}");
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A directory owned by another user (seen from a different euid,
        // unless it is root's).
        let r = check_socket_dir(&dir, other);
        assert_eq!(r.is_ok(), euid == 0, "{r:?}");
        // Missing directory.
        assert!(check_socket_dir(&dir.join("nope"), euid).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_uid_is_ours() {
        let dir = tmp("peer");
        let p = dir.join("p.sock");
        let l = UnixListener::bind(&p).unwrap();
        let c = UnixStream::connect(&p).unwrap();
        let (srv, _) = l.accept().unwrap();
        let euid = crate::config::effective_uid();
        assert_eq!(peer_uid(&srv).unwrap(), euid);
        assert_eq!(peer_uid(&c).unwrap(), euid);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
