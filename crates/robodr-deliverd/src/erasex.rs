//! Executed crypto-erase triggers (`docs/SECURE-DELIVERY.md` §7.6, Sprint
//! 14b): the platform's trigger socket.
//!
//! The platform wires its enclosure tamper input (GPIO / bus signal), its
//! attestation monitor and its local authentication to a small feeder
//! that connects to `erase.trigger_socket` and writes one line:
//!
//! ```text
//! {"format":"robodr-erase-trigger/1","trigger":"tamper"}
//! ```
//!
//! Only `tamper`, `attestation_failed` and `auth_failures` are accepted
//! here (the triggers a person issues are two-person and do not come over
//! this socket). The peer is identified by the kernel (`SO_PEERCRED`,
//! `SO_PEERGROUPS`, taken at `connect`): root, a uid in `feeder_uids` or a
//! member of a group in `feeder_gids`; anyone else is refused and noted,
//! nothing is planned. A finding named `robot.seal.tamper` arriving
//! through any other path (agentd's spool, a network sensor) triggers
//! nothing: only this socket does. The trigger is then planned by the
//! responder ([`robodr_responder::erase::plan_erase`]) and executed by the
//! engine when the live safety state allows it (`Engine::erase_trigger`).

use crate::config::EraseCfg;
use robodr_responder::erase::EraseTrigger;
use serde::Deserialize;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

pub const TRIGGER_FORMAT: &str = "robodr-erase-trigger/1";
const MAX_LINE: u64 = 512;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    format: String,
    trigger: String,
}

/// Parse one trigger line (a platform input only).
pub fn parse_line(b: &[u8]) -> Result<EraseTrigger, String> {
    let t = std::str::from_utf8(b).map_err(|_| "not UTF-8".to_string())?;
    let l: Line = serde_json::from_str(t.trim_end_matches('\n')).map_err(|e| {
        format!(
            "not a trigger line: {}",
            robodr_pkg::common::trunc(&e.to_string())
        )
    })?;
    if l.format != TRIGGER_FORMAT {
        return Err("unsupported format".into());
    }
    let tr = EraseTrigger::parse(&l.trigger).ok_or_else(|| {
        format!(
            "unknown trigger {:?}",
            robodr_pkg::common::trunc(&l.trigger)
        )
    })?;
    if !tr.is_platform_input() {
        return Err(format!(
            "{} is not a platform input (people's erases are two-person, not on this socket)",
            tr.as_str()
        ));
    }
    Ok(tr)
}

/// What one accepted connection brought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Trigger { trigger: EraseTrigger, uid: u32 },
    Refused { uid: Option<u32>, why: String },
}

/// The listening socket.
#[derive(Debug)]
pub struct TriggerSocket {
    listener: UnixListener,
    cfg: EraseCfg,
}

impl TriggerSocket {
    /// Bind `cfg.trigger_socket` (a stale socket there is replaced; any
    /// other file refuses), mode 0660, non-blocking.
    pub fn bind(cfg: &EraseCfg) -> Result<Self, String> {
        let p = &cfg.trigger_socket;
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_socket() => {
                std::fs::remove_file(p).map_err(|e| format!("{}: {e}", p.display()))?
            }
            Ok(_) => return Err(format!("{}: exists and is not a socket", p.display())),
            Err(_) => {}
        }
        let listener = UnixListener::bind(p).map_err(|e| format!("{}: {e}", p.display()))?;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o660))
            .map_err(|e| format!("{}: {e}", p.display()))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        Ok(Self {
            listener,
            cfg: cfg.clone(),
        })
    }

    fn allowed(&self, s: &UnixStream) -> Result<u32, (Option<u32>, String)> {
        let (uid, gid) = robodr_agentd::host::peer_cred(s)
            .map_err(|e| (None, format!("peer credentials unreadable: {e}")))?;
        if uid == 0 || self.cfg.feeder_uids.contains(&uid) || self.cfg.feeder_gids.contains(&gid) {
            return Ok(uid);
        }
        let groups = robodr_agentd::host::peer_groups(s).unwrap_or_default();
        if groups.iter().any(|g| self.cfg.feeder_gids.contains(g)) {
            return Ok(uid);
        }
        Err((
            Some(uid),
            format!("uid {uid} is not an erase-trigger feeder"),
        ))
    }

    /// Accept every pending connection (one line each, bounded, 1 s).
    pub fn poll(&self) -> Vec<Event> {
        let mut out = Vec::new();
        for _ in 0..16 {
            let s = match self.listener.accept() {
                Ok((s, _)) => s,
                Err(_) => break,
            };
            let _ = s.set_nonblocking(false);
            let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
            match self.allowed(&s) {
                Err((uid, why)) => out.push(Event::Refused { uid, why }),
                Ok(uid) => {
                    let mut b = Vec::new();
                    let _ = (&s).take(MAX_LINE).read_to_end(&mut b);
                    match parse_line(&b) {
                        Ok(trigger) => out.push(Event::Trigger { trigger, uid }),
                        Err(why) => out.push(Event::Refused {
                            uid: Some(uid),
                            why,
                        }),
                    }
                }
            }
        }
        out
    }
}

/// Send one trigger (the platform feeder's side; `robodr-deliverd tamper`).
pub fn send(socket: &std::path::Path, trigger: EraseTrigger) -> Result<(), String> {
    use std::io::Write;
    let mut s = UnixStream::connect(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    let line = format!(
        "{{\"format\":\"{TRIGGER_FORMAT}\",\"trigger\":\"{}\"}}\n",
        trigger.as_str()
    );
    s.write_all(line.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines() {
        assert_eq!(
            parse_line(br#"{"format":"robodr-erase-trigger/1","trigger":"tamper"}"#).unwrap(),
            EraseTrigger::Tamper
        );
        for bad in [
            &br#"{"format":"robodr-erase-trigger/1","trigger":"operator"}"#[..],
            br#"{"format":"robodr-erase-trigger/1","trigger":"signed_command"}"#,
            br#"{"format":"robodr-erase-trigger/2","trigger":"tamper"}"#,
            br#"{"format":"robodr-erase-trigger/1","trigger":"tamper","x":1}"#,
            br#"{"rule_id":"robot.seal.tamper"}"#,
            b"\xff",
        ] {
            assert!(parse_line(bad).is_err());
        }
    }
}
