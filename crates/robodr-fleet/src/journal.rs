//! The fleet journal: a robodr-blackbox recorder of its own
//! (`<state_dir>/journal/`), signed with the unit's black-box key, that
//! records every fleet lifecycle step (enrollment, each rotation phase,
//! revocation lists, profile staging / approval / install, ring info).
//!
//! It is a separate chain from agentd's black box because the recorder is
//! single-writer (`flock`) and agentd holds its own directory while it
//! runs; a rotation must not need agentd stopped. Both chains are signed
//! by the same unit key and verify with the same tools
//! (`robodr-blackbox verify /var/lib/robodr/fleet/journal --keyring
//! agentd-blackbox.key.pub`).
//!
//! Key continuity (contract §5.4): when a role key is swapped, the
//! `robodr.fleet.key_handover` note carries two signatures over the same
//! statement — by the **old** key ("I hand over to the new key") and by the
//! **new** key ("I take over from the old key") — and the statement names
//! the journal head hash it follows, so the key transition is bound to the
//! chain. The note is written critical (fsynced) and followed by a seal.
//!
//! Black-box key rotation (`docs/OPERATIONS.md` 4.3): the black-box key is
//! not rotated by the fleet API, it is rotated in place with
//! `robodr-blackbox rotate`. The fleet journal is a log of its own, so the
//! procedure rotates it too (`robodr-blackbox rotate
//! /var/lib/robodr/fleet/journal ...`, the same old and new key), and the
//! journal is then opened with the retired keys' public files that agentd
//! lists in `blackbox.previous_keys` (the same unit, the same keys). A
//! journal still keyed by the retired key is refused with the command that
//! rotates it (`Error::KeyMismatch`), never reset or rewritten.

use robodr_blackbox::{
    Error, FsyncPolicy, KeyFile, Recorder, RecorderConfig, RetentionMode, SystemClock, TimeSource,
    Verifier,
};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Note kinds.
pub const K_ENROLL_REQUESTED: &str = "robodr.fleet.enroll_requested";
pub const K_ENROLLED: &str = "robodr.fleet.enrolled";
pub const K_ROTATION: &str = "robodr.fleet.key_rotation";
pub const K_HANDOVER: &str = "robodr.fleet.key_handover";
pub const K_REVOCATIONS: &str = "robodr.fleet.revocations_installed";
pub const K_PROFILE: &str = "robodr.fleet.profile";
pub const K_RING: &str = "robodr.fleet.ring_info";
pub const K_REFUSED: &str = "robodr.fleet.refused";
pub const K_DECOMMISSION: &str = "robodr.fleet.decommission";

/// An open fleet journal.
pub struct Journal {
    rec: Recorder,
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control))
        .unwrap_or_else(|| "unknown-boot".into())
}

/// The error of [`Journal::open`]; a journal still keyed by a retired
/// black-box key names the rotation that brings it onto the current key.
fn open_error(dir: &Path, robot_id: &str, key_path: &Path, e: Error) -> String {
    match e {
        Error::KeyMismatch {
            log_key_id,
            signer_key_id,
        } => format!(
            "fleet journal {d}: it is signed by black-box key {log_key_id}, but {k} holds \
             {signer_key_id}: the black-box key was rotated without the fleet journal. \
             Rotate the journal onto the current key with the retired secret key \
             (robodr-blackbox rotate {d} --device {robot_id} --old-key <retired .key> \
             --new-key {k}) and list the retired key's .pub in agentd's \
             blackbox.previous_keys (docs/OPERATIONS.md 4.3)",
            d = dir.display(),
            k = key_path.display(),
        ),
        e => format!("fleet journal {}: {e}", dir.display()),
    }
}

impl Journal {
    /// Open (or create) the journal in `dir` for `robot_id`, signed with the
    /// black-box key file at `key_path`. `previous_keys` are the public files
    /// of the unit's retired black-box keys (agentd's
    /// `blackbox.previous_keys`): they authenticate the records signed
    /// before a rotation of the journal, with the checks agentd applies
    /// (public files only, bound to `robot_id` if bound, not the current
    /// key; legacy HMAC keys are refused: fleet keys are Ed25519).
    pub fn open(
        dir: &Path,
        robot_id: &str,
        key_path: &Path,
        previous_keys: &[PathBuf],
    ) -> Result<Self, String> {
        let kf = KeyFile::load_secret(key_path)
            .map_err(|e| format!("black-box key {}: {e}", key_path.display()))?;
        let signer = kf
            .signer()
            .map_err(|e| format!("black-box key {}: {e}", key_path.display()))?;
        let previous: Option<Box<dyn Verifier>> = if previous_keys.is_empty() {
            None
        } else {
            let paths: Vec<&Path> = previous_keys.iter().map(PathBuf::as_path).collect();
            let current = signer.key_id().to_string();
            let mut warnings = Vec::new();
            let keys = robodr_blackbox::keys::load_previous_keys(
                "blackbox.previous_keys (agentd configuration)",
                &paths,
                robot_id,
                &[(current.as_str(), "the current black-box key")],
                false,
                &mut warnings,
            )?;
            Some(Box::new(keys))
        };
        let mut cfg = RecorderConfig::new(dir, robot_id, boot_id());
        cfg.mode = RetentionMode::Cyclic { max_segments: 8 };
        cfg.max_segment_bytes = 1024 * 1024;
        cfg.fsync = FsyncPolicy::Every(1);
        let rec = Recorder::open_with_keys(
            cfg,
            signer,
            None,
            previous,
            Box::new(SystemClock::new(TimeSource::Rtc)),
        )
        .map_err(|e| open_error(dir, robot_id, key_path, e))?;
        Ok(Self { rec })
    }

    /// Append a critical (fsynced) note.
    pub fn note<T: Serialize>(&mut self, note: &T) -> Result<(), String> {
        self.rec
            .append_note(note, true)
            .map(|_| ())
            .map_err(|e| format!("fleet journal: {e}"))
    }

    /// The head hash (hex) the next record chains onto (`"genesis"` when
    /// empty).
    pub fn head_hex(&self) -> String {
        self.rec
            .head()
            .map(|(_, h)| robodr_blackbox::crypto::to_hex(&h))
            .unwrap_or_else(|| "genesis".into())
    }

    /// Seal (checkpoint) the journal.
    pub fn seal(&mut self) -> Result<(), String> {
        self.rec
            .seal()
            .map(|_| ())
            .map_err(|e| format!("fleet journal seal: {e}"))
    }

    pub fn close(self) -> Result<(), String> {
        self.rec
            .close()
            .map(|_| ())
            .map_err(|e| format!("fleet journal close: {e}"))
    }
}
