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

/// Read the restriction file: `Ok(None)` when it does not exist.
pub fn load(path: &Path) -> Result<Option<Restriction>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if !meta.file_type().is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if meta.permissions().mode() & 0o002 != 0 {
        return Err(format!("{}: writable by others", path.display()));
    }
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut s = String::new();
    f.take(MAX_FILE + 1)
        .read_to_string(&mut s)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if s.len() as u64 > MAX_FILE {
        return Err(format!("{}: larger than {MAX_FILE} bytes", path.display()));
    }
    parse(&s).map(Some)
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
