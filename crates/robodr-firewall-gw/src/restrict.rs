//! `restrict_motion` on the gateway: a **restriction file** written by
//! `robodr-executor` (its gateway adapter) and read by the gateway at every
//! housekeeping tick (`restriction_path` in the gateway configuration).
//!
//! ```json
//! {"format": "robodr-gw-restriction/v1", "id": "robot_restrict_motion:ugv-007:3f2a",
//!  "max_linear_speed": 0.5, "max_joint_speed": 0.8, "factor": 0.5,
//!  "expires_unix_ms": 1792357924051}
//! ```
//!
//! A restriction can only **tighten** what the gateway forwards: on the
//! twist channels (ROS 2 `Twist` / `TwistStamped`, sport `Move`, loco
//! `SetVelocity`) the linear speed is capped at `max_linear_speed` and at
//! `factor` × the channel's own linear limit, the angular speed at
//! `factor` × its angular limit; on the trajectory channels every joint's
//! `max_velocity` becomes at most `max_joint_speed` and `factor` × its
//! configured value (a faster trajectory is then time-scaled or refused as
//! the channel says). Low-level joint channels (`LowCmd_`, arm SDK, hands)
//! are **not** restricted: scaling a balance controller's joint targets is
//! not a speed limit (README, "restrict_motion").
//!
//! The gateway enforces `expires_unix_ms` itself (wall clock): a
//! restriction ends at its TTL even when the executor that wrote it is
//! down. A file that is a symlink, writable by others, larger than
//! [`MAX_FILE`], malformed, or that would not tighten anything (a factor
//! outside `(0, 1]`, a cap that is not finite and `> 0`) is ignored with a
//! warning, never applied as "no restriction" silently: the gateway status
//! reports `restriction_error`. The status file reports the restriction in
//! force (`restriction.id`), which is what the executor reads back to
//! verify that its order took effect.

use std::path::Path;

use serde::Deserialize;

/// The file format tag.
pub const FORMAT: &str = "robodr-gw-restriction/v1";
/// Largest restriction file read.
pub const MAX_FILE: u64 = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    format: String,
    id: String,
    #[serde(default)]
    max_linear_speed: Option<f64>,
    #[serde(default)]
    max_joint_speed: Option<f64>,
    #[serde(default)]
    factor: Option<f64>,
    expires_unix_ms: u64,
}

/// A validated restriction.
#[derive(Debug, Clone, PartialEq)]
pub struct Restriction {
    pub id: String,
    pub max_linear_speed: Option<f64>,
    pub max_joint_speed: Option<f64>,
    pub factor: Option<f64>,
    pub expires_unix_ms: u64,
}

impl Restriction {
    /// The linear and angular caps of a twist channel whose own limits are
    /// `lin` / `ang` (`f64::INFINITY` when it has none).
    pub fn twist_caps(&self, lin: f64, ang: f64) -> (f64, f64) {
        let f = self.factor.unwrap_or(1.0);
        let l = (lin * f).min(self.max_linear_speed.unwrap_or(f64::INFINITY));
        (l, ang * f)
    }

    /// The velocity cap of a joint whose configured bound is `v`.
    pub fn joint_cap(&self, v: f64) -> f64 {
        (v * self.factor.unwrap_or(1.0)).min(self.max_joint_speed.unwrap_or(f64::INFINITY))
    }

    pub fn expired(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.expires_unix_ms
    }
}

/// Parse and validate the file's text.
pub fn parse(text: &str) -> Result<Restriction, String> {
    let f: File = serde_json::from_str(text).map_err(|e| format!("restriction file: {e}"))?;
    if f.format != FORMAT {
        return Err(format!("restriction file: format must be {FORMAT}"));
    }
    if f.id.is_empty()
        || f.id.len() > 128
        || !f
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
    {
        return Err("restriction file: id must match [A-Za-z0-9._:-]{1,128}".into());
    }
    let cap = |v: Option<f64>| v.is_none_or(|x| x.is_finite() && x > 0.0);
    if !cap(f.max_linear_speed) || !cap(f.max_joint_speed) {
        return Err("restriction file: caps must be finite and > 0".into());
    }
    if f.factor
        .is_some_and(|x| !(x.is_finite() && x > 0.0 && x <= 1.0))
    {
        return Err("restriction file: factor must be in (0, 1]".into());
    }
    if f.max_linear_speed.is_none() && f.max_joint_speed.is_none() && f.factor.is_none() {
        return Err("restriction file: restricts nothing".into());
    }
    Ok(Restriction {
        id: f.id,
        max_linear_speed: f.max_linear_speed,
        max_joint_speed: f.max_joint_speed,
        factor: f.factor,
        expires_unix_ms: f.expires_unix_ms,
    })
}

/// `O_NOFOLLOW` (Linux; differs between architectures).
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
const O_NOFOLLOW: i32 = 0o400000;
/// `O_NONBLOCK` (Linux).
const O_NONBLOCK: i32 = 0o4000;

/// Read the restriction file: `Ok(None)` when it does not exist.
///
/// Review F4: the file is opened **once**, without following a symlink
/// (`O_NOFOLLOW`) and without blocking (`O_NONBLOCK`: a FIFO or device put
/// in its place cannot stall the caller), and every check is made on the
/// open descriptor (`fstat`): a regular file, not writable by group or
/// others, owned by root or by the owner of its directory (the
/// executor's user, which owns the restriction directory). The gateway
/// calls it from its I/O thread, never from the packet path
/// (`crate::runtime`).
pub fn load(path: &Path) -> Result<Option<Restriction>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e} (a symlink is refused)", path.display())),
    };
    let meta = f
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!("{}: writable by group or others", path.display()));
    }
    let dir_owner = path
        .parent()
        .and_then(|d| std::fs::metadata(d).ok())
        .map(|m| m.uid());
    if meta.uid() != 0 && Some(meta.uid()) != dir_owner {
        return Err(format!(
            "{}: owned by uid {}, neither root nor the directory's owner",
            path.display(),
            meta.uid()
        ));
    }
    let mut s = String::new();
    f.take(MAX_FILE + 1)
        .read_to_string(&mut s)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if s.len() as u64 > MAX_FILE {
        return Err(format!("{}: larger than {MAX_FILE} bytes", path.display()));
    }
    parse(&s).map(Some)
}

/// One read of the restriction file: absent (`Ok(None)`), a restriction,
/// or why it was ignored.
pub type LoadResult = Result<Option<Restriction>, String>;
type Slot = std::sync::Mutex<Option<LoadResult>>;

/// The restriction file read on its own thread (review F4): the packet
/// path only takes the latest result ([`Watcher::latest`]).
#[derive(Debug)]
pub struct Watcher {
    slot: std::sync::Arc<Slot>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Watcher {
    /// Read `path` every `period` on a new thread.
    pub fn spawn(path: std::path::PathBuf, period: std::time::Duration) -> std::io::Result<Self> {
        let slot: std::sync::Arc<Slot> = std::sync::Arc::default();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (s2, st2) = (std::sync::Arc::clone(&slot), std::sync::Arc::clone(&stop));
        std::thread::Builder::new()
            .name("gw-restriction".into())
            .spawn(move || {
                while !st2.load(std::sync::atomic::Ordering::Relaxed) {
                    let r = load(&path);
                    if let Ok(mut g) = s2.lock() {
                        *g = Some(r);
                    }
                    std::thread::sleep(period);
                }
            })?;
        Ok(Self { slot, stop })
    }

    /// The latest result, if one arrived since the last call.
    pub fn latest(&self) -> Option<LoadResult> {
        self.slot.lock().ok().and_then(|mut g| g.take())
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tightening_restrictions_parse() {
        let ok = parse(
            r#"{"format":"robodr-gw-restriction/v1","id":"a:b","factor":0.5,"expires_unix_ms":5}"#,
        )
        .unwrap();
        assert_eq!(ok.twist_caps(1.0, 2.0), (0.5, 1.0));
        assert_eq!(ok.joint_cap(2.0), 1.0);
        assert!(ok.expired(5) && !ok.expired(4));
        for bad in [
            r#"{"format":"robodr-gw-restriction/v1","id":"a","factor":1.5,"expires_unix_ms":5}"#,
            r#"{"format":"robodr-gw-restriction/v1","id":"a","factor":0,"expires_unix_ms":5}"#,
            r#"{"format":"robodr-gw-restriction/v1","id":"a","max_linear_speed":-1,"expires_unix_ms":5}"#,
            r#"{"format":"robodr-gw-restriction/v1","id":"a","expires_unix_ms":5}"#,
            r#"{"format":"robodr-gw-restriction/v1","id":"a b","factor":0.5,"expires_unix_ms":5}"#,
            r#"{"format":"x","id":"a","factor":0.5,"expires_unix_ms":5}"#,
            r#"{"format":"robodr-gw-restriction/v1","id":"a","factor":0.5,"expires_unix_ms":5,"x":1}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
