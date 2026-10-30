//! Probe users (§10, 13b requirement 2). `health[].probe.user` is a name;
//! it is resolved once, at staging, to a UID and GID from the configured
//! user database (`/etc/passwd` format, files only: no NSS modules are
//! consulted, so an LDAP or `systemd-userdb` user is not a probe user).
//! The pair is recorded with the staged version and resolved again before
//! every probe run: a name that now resolves differently fails the probe.
//!
//! Refused: UID 0 or GID 0, a UID outside the configured range (default
//! `1000..=59999`: no system account, review L2), the always-denied names
//! (`root`, `robodr`, `robodr-agentd`, `robodr-exec`) and the configured
//! ones, a name listed twice in the database (ambiguous), and a database
//! that is not a plain regular file of bounded size.

use crate::config::Config;
use robodr_release::fsio::read_capped;

/// Largest user database read.
pub const MAX_PASSWD_BYTES: usize = 4 * 1024 * 1024;

/// A resolved probe user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ids {
    pub uid: u32,
    pub gid: u32,
}

/// Look `name` up in passwd-format `text`. Errors on a malformed line for
/// that name, a name listed twice, or no entry.
pub fn lookup(text: &str, name: &str) -> Result<Ids, String> {
    let mut found: Option<Ids> = None;
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split(':');
        let Some(n) = f.next() else { continue };
        if n != name {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        let &[_, _, uid_s, gid_s, _, _, _] = parts.as_slice() else {
            return Err(format!("user {name}: malformed database line"));
        };
        let uid: u32 = uid_s.parse().map_err(|_| format!("user {name}: bad uid"))?;
        let gid: u32 = gid_s.parse().map_err(|_| format!("user {name}: bad gid"))?;
        // A leading '+' or '0' variant ("01") would be accepted by parse
        // differently than by libc; require the canonical decimal form.
        if uid_s != uid.to_string() || gid_s != gid.to_string() {
            return Err(format!("user {name}: non-canonical uid or gid"));
        }
        if found.is_some() {
            return Err(format!("user {name} is listed twice (ambiguous)"));
        }
        found = Some(Ids { uid, gid });
    }
    found.ok_or_else(|| format!("user {name} does not exist"))
}

/// Resolve and judge a probe user under `cfg`.
pub fn resolve(cfg: &Config, name: &str) -> Result<Ids, String> {
    if cfg.is_denied_user(name) {
        return Err(format!("user {name} may never run a probe"));
    }
    let b = read_capped(&cfg.health.passwd, MAX_PASSWD_BYTES).map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(&b).map_err(|_| "user database is not UTF-8".to_string())?;
    let ids = lookup(text, name)?;
    let h = &cfg.health;
    if ids.uid == 0 || ids.gid == 0 {
        return Err(format!("user {name} has UID or GID 0"));
    }
    if ids.uid < h.probe_uid_min || ids.uid > h.probe_uid_max {
        return Err(format!(
            "user {name} has UID {} outside the probe range {}..={}",
            ids.uid, h.probe_uid_min, h.probe_uid_max
        ));
    }
    Ok(ids)
}

/// Whether this process runs as root (effective UID 0).
pub fn is_root() -> bool {
    effective_uid() == Some(0)
}

/// The effective UID from `/proc/self/status`.
pub fn effective_uid() -> Option<u32> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB: &str = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1::/:/usr/sbin/nologin\n\
                      probe:x:1500:1500::/nonexistent:/usr/sbin/nologin\n\
                      twice:x:1600:1600::/:/bin/false\n\
                      twice:x:1601:1601::/:/bin/false\n\
                      zero:x:1700:0::/:/bin/false\n\
                      odd:x:+1800:1800::/:/bin/false\n\
                      short:x:1900\n";

    #[test]
    fn lookups() {
        assert_eq!(
            lookup(DB, "probe").unwrap(),
            Ids {
                uid: 1500,
                gid: 1500
            }
        );
        assert!(lookup(DB, "twice").unwrap_err().contains("twice"));
        assert!(lookup(DB, "nobody-here").is_err());
        assert!(lookup(DB, "odd").is_err());
        assert!(lookup(DB, "short").is_err());
        assert_eq!(lookup(DB, "zero").unwrap().gid, 0);
    }

    #[test]
    fn resolve_applies_the_policy() {
        let d = std::env::temp_dir().join(format!("deliverd-users-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("passwd"), DB).unwrap();
        let mut v = crate::config::test_support::minimal();
        v["health"] = serde_json::json!({"passwd": d.join("passwd"), "probe_uid_min": 1000,
                                         "deny_users": ["probe2"]});
        let cfg = Config::parse(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(resolve(&cfg, "probe").unwrap().uid, 1500);
        assert!(resolve(&cfg, "root").is_err());
        assert!(resolve(&cfg, "robodr").is_err());
        assert!(resolve(&cfg, "probe2").is_err());
        assert!(resolve(&cfg, "daemon").unwrap_err().contains("outside"));
        assert!(resolve(&cfg, "zero").unwrap_err().contains("GID 0"));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
