//! Loading a profile **with trust**: detached signature, trust anchors,
//! platform/unit binding and anti-rollback, on top of the commissioning
//! file check. The checks themselves live in `robodr_commission::trust`
//! (the crate that owns the profile file format); this module wires them
//! to the sensor configuration ([`ProfileTrustConfig`], the `profile_trust`
//! sub-table of `[module.robodr-sensor-ros2]` / agentd's `sensor` section)
//! and to [`LoadedProfile`].
//!
//! ```toml
//! [module.robodr-sensor-ros2.profile_trust]
//! trusted_keys = "/etc/robodr/profile-trust.json"   # robodr-profile-trust/v1
//! state_file = "/var/lib/robodr/profile-state.json" # anti-rollback
//! expect_platform = "ugv-x1"                        # optional
//! expect_unit_id = "ugv-007"                        # optional
//! # allow_rollback = "sha256:<digest of the one older file to accept>"
//! ```
//!
//! # Decisions
//!
//! * **Fail closed.** Without `trusted_keys` no locked profile can be
//!   authenticated, so none is enforced: the sensor runs observe-only and
//!   reports one `robot.ros2.profile_refused` finding. The same holds for a
//!   missing / malformed / forged signature, a key not in the trust file,
//!   a legacy locked profile without metadata, a platform or unit mismatch
//!   and a refused rollback. Refusal never stops the sensor (a broken
//!   profile must not blind it, nor be escalated into a safe-state request).
//! * **Anti-rollback** needs `state_file`. On acceptance of a locked
//!   profile with a new version (or the first one) the state is rewritten
//!   atomically: at load time by [`load_profile_with_trust`], or when the
//!   caller says so with [`load_profile_deferred`] + [`StateCommit::commit`]
//!   (agentd: never on `--check-config`; a failed write means the profile is
//!   not enforced). A refused profile never touches the state. A lower
//!   version, the same version with different bytes, or a draft replacing
//!   a locked profile is refused unless `allow_rollback` names that file's
//!   exact digest (`robodr-commission verify-profile` prints it). After a
//!   permitted rollback the state records the older version, so the flag
//!   can (and should) be removed again.
//! * Drafts (unlocked) need no signature: they are observe-only anyway.
//!
//! Limits: see `robodr_commission::trust` (unaudited Ed25519, state file
//! resettable by root, no revocation list).

use std::path::{Path, PathBuf};

use robodr_commission::trust::{
    check_rollback, load_state, load_trust_keys, read_optional_sig, sig_path_for, store_state,
    validate_rollback_flag, verify_profile_text, AcceptedState, ProfileTrustError, TrustPolicy,
};
use robodr_commission::ProfileFileError;
use serde::Deserialize;

use crate::pipeline::{read_profile_lenient, LoadedProfile};

/// The `profile_trust` configuration. Every field is optional; the default
/// (nothing configured) refuses every locked profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ProfileTrustConfig {
    /// `robodr-profile-trust/v1` file of trusted Ed25519 profile keys.
    pub trusted_keys: Option<PathBuf>,
    /// Anti-rollback state file (`robodr-profile-state/v1`).
    pub state_file: Option<PathBuf>,
    /// Operator rollback flag: the exact digest (`sha256:<hex>`) of the one
    /// profile file that may be accepted although it is older than (or a
    /// draft replacing) the last accepted one.
    pub allow_rollback: Option<String>,
    /// `metadata.platform` must equal this.
    pub expect_platform: Option<String>,
    /// `metadata.unit_id` must be null (fleet-wide) or equal this.
    pub expect_unit_id: Option<String>,
}

impl ProfileTrustConfig {
    /// Check the configuration (paths absolute, rollback flag a digest,
    /// expectations well-formed labels). Non-fatal problems are reported by
    /// [`ProfileTrustConfig::warnings`].
    pub fn validate(&self) -> Result<(), String> {
        for (what, p) in [
            ("profile_trust.trusted_keys", &self.trusted_keys),
            ("profile_trust.state_file", &self.state_file),
        ] {
            if let Some(p) = p {
                if p.as_os_str().is_empty() || !p.is_absolute() {
                    return Err(format!(
                        "{what} must be an absolute path, got {:?}",
                        p.display().to_string()
                    ));
                }
            }
        }
        if let Some(f) = &self.allow_rollback {
            validate_rollback_flag(f).map_err(|e| format!("profile_trust.{e}"))?;
        }
        for (what, v) in [
            ("expect_platform", &self.expect_platform),
            ("expect_unit_id", &self.expect_unit_id),
        ] {
            if let Some(v) = v {
                if v.is_empty()
                    || v.len() > robodr_events::profile::MAX_LABEL_LEN
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                {
                    return Err(format!(
                        "profile_trust.{what} must match [A-Za-z0-9._-]{{1,64}}"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Operator warnings for this configuration (log them at start): no
    /// trust anchors (observe-only), no anti-rollback state, a rollback
    /// flag left set.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if self.trusted_keys.is_none() {
            w.push(
                "profile_trust.trusted_keys is not set: no locked profile can be authenticated, \
                 the sensor will run observe-only"
                    .into(),
            );
        } else if self.state_file.is_none() {
            w.push(
                "profile_trust.state_file is not set: anti-rollback is OFF (an older signed \
                 profile would be accepted)"
                    .into(),
            );
        }
        if let Some(f) = &self.allow_rollback {
            w.push(format!(
                "profile_trust.allow_rollback is set ({f}): an older profile with exactly this \
                 digest will be accepted; remove the flag once it has loaded"
            ));
            if self.state_file.is_none() {
                w.push(
                    "profile_trust.allow_rollback has no effect without profile_trust.state_file"
                        .into(),
                );
            }
        }
        w
    }
}

/// Read a profile file, run the commissioning file check and the trust
/// check (see the module docs), and record the result in
/// [`LoadedProfile::file_check`] (`Err(ProfileFileError::Untrusted)` for a
/// trust refusal). Neither check makes this fail: [`crate::Pipeline::from_loaded`]
/// decides, so a profile we cannot enforce still yields an observe-only
/// pipeline. An unreadable or unparseable profile file is an error.
///
/// Side effect: with `state_file` set, accepting a new locked version
/// rewrites the state file atomically.
pub fn load_profile_with_trust(
    path: &Path,
    trust: &ProfileTrustConfig,
) -> Result<LoadedProfile, String> {
    let (mut loaded, commit) = load_profile_deferred(path, trust)?;
    if let Some(c) = commit {
        if let Err(e) = c.commit() {
            loaded.file_check = Err(e);
        }
    }
    Ok(loaded)
}

/// An accepted profile's anti-rollback state, not yet written. Produced by
/// [`load_profile_deferred`] so a caller can validate a configuration
/// without side effects (agentd `--check-config`) and persist the state
/// only when it really starts enforcing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateCommit {
    pub path: PathBuf,
    pub state: AcceptedState,
}

impl StateCommit {
    /// Write the state atomically. On error the profile must not be
    /// enforced (the error is the `file_check` to use).
    pub fn commit(&self) -> Result<(), ProfileFileError> {
        store_state(&self.path, &self.state).map_err(ProfileFileError::from)
    }
}

/// [`load_profile_with_trust`] without writing the anti-rollback state:
/// every check (including the rollback decision against the current state
/// file) is made, and the state change an acceptance implies is returned
/// for the caller to [`StateCommit::commit`].
pub fn load_profile_deferred(
    path: &Path,
    trust: &ProfileTrustConfig,
) -> Result<(LoadedProfile, Option<StateCommit>), String> {
    let (raw, profile) = read_profile_lenient(path)?;
    let (file_check, commit) = match trust_check(path, &raw, trust) {
        Ok(c) => (Ok(()), c),
        Err(e) => (Err(e), None),
    };
    Ok((
        LoadedProfile {
            profile,
            file_check,
        },
        commit,
    ))
}

/// The file + trust + rollback decision for `raw` (the exact bytes of
/// `path`); `Ok` carries the state write an acceptance implies.
fn trust_check(
    path: &Path,
    raw: &str,
    trust: &ProfileTrustConfig,
) -> Result<Option<StateCommit>, ProfileFileError> {
    // A broken trust file only matters for a locked profile.
    let (anchors, anchor_err) = match &trust.trusted_keys {
        None => (None, None),
        Some(p) => match load_trust_keys(p) {
            Ok(k) => (Some(k), None),
            Err(e) => (None, Some(e)),
        },
    };
    let policy = TrustPolicy {
        anchors,
        expect_platform: trust.expect_platform.clone(),
        expect_unit_id: trust.expect_unit_id.clone(),
    };
    let sig_path = sig_path_for(path);
    let sig_name = sig_path.display().to_string();
    let verified = match read_optional_sig(&sig_path) {
        Ok(sig) => verify_profile_text(raw, sig.as_deref(), &sig_name, &policy),
        Err(e) => match verify_profile_text(raw, None, &sig_name, &policy) {
            Err(ProfileFileError::Untrusted {
                reason: ProfileTrustError::MissingSignature { .. },
            }) if policy.anchors.is_some() => Err(ProfileTrustError::MalformedSignature {
                detail: format!("{sig_name}: {e}"),
            }
            .into()),
            other => other,
        },
    };
    let verified = match (verified, anchor_err) {
        (
            Err(ProfileFileError::Untrusted {
                reason: ProfileTrustError::NoTrustAnchors,
            }),
            Some(e),
        ) => return Err(e.into()),
        (v, _) => v?,
    };
    let Some(state_path) = &trust.state_file else {
        return Ok(None);
    };
    let current = load_state(state_path)?;
    let decision = check_rollback(current.as_ref(), &verified, trust.allow_rollback.as_deref())?;
    Ok(decision
        .writes_state(&verified)
        .then(|| AcceptedState::of(&verified))
        .flatten()
        .map(|state| StateCommit {
            path: state_path.clone(),
            state,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Pipeline, PipelineOptions, ProfileStatus};
    use robodr_blackbox::Ed25519SigningKey;
    use robodr_commission::trust::{file_digest, trust_keys_text, ProfileSignature};
    use robodr_events::profile::{Envelope, Profile, ProfileMetadata, PROFILE_SCHEMA_VERSION};
    use robodr_events::Mode;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-pl-trust-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed("oem", &[3; 32]).unwrap()
    }

    fn profile(version: u64, locked: bool) -> Profile {
        let mut p = Profile {
            model: "ugv".into(),
            locked,
            metadata: locked.then(|| ProfileMetadata {
                schema_version: PROFILE_SCHEMA_VERSION,
                profile_version: version,
                platform: "ugv-x1".into(),
                unit_id: None,
                locked_by: "op".into(),
                locked_at: 1_790_000_000,
                parent_digest: None,
            }),
            ..Default::default()
        };
        p.participants.insert("a".repeat(24));
        p.writer_topics.insert("/cmd_vel".into());
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(1.0),
                max_joint_speed: None,
            },
        );
        p
    }

    /// Write `p` (sealed if locked) and, if `sign`, its signature.
    fn write(dir: &Path, name: &str, p: &Profile, sign: bool) -> (PathBuf, String) {
        let text = if p.locked {
            robodr_commission::sealed_text(p).unwrap()
        } else {
            robodr_commission::to_json(p).unwrap()
        };
        let path = dir.join(name);
        std::fs::write(&path, &text).unwrap();
        if sign {
            let sig = ProfileSignature::create(text.as_bytes(), &key()).unwrap();
            std::fs::write(sig_path_for(&path), sig.to_text()).unwrap();
        }
        (path, file_digest(text.as_bytes()))
    }

    fn trust(dir: &Path, state: bool) -> ProfileTrustConfig {
        let t = dir.join("trust.json");
        std::fs::write(&t, trust_keys_text(&[key().verifying_key()])).unwrap();
        ProfileTrustConfig {
            trusted_keys: Some(t),
            state_file: state.then(|| dir.join("state.json")),
            ..Default::default()
        }
    }

    fn status(path: &Path, t: &ProfileTrustConfig) -> ProfileStatus {
        let l = load_profile_with_trust(path, t).unwrap();
        Pipeline::from_loaded(l, PipelineOptions::default())
            .status()
            .clone()
    }

    fn refused_because(st: ProfileStatus, what: &str) {
        match st {
            ProfileStatus::FileRejected(why) => assert!(why.contains(what), "{why}"),
            other => panic!("expected refusal ({what}), got {other:?}"),
        }
    }

    #[test]
    fn signed_profile_is_enforced_unsigned_is_refused() {
        let d = tmpdir("basic");
        let t = trust(&d, false);
        let (good, _) = write(&d, "good.json", &profile(1, true), true);
        assert_eq!(status(&good, &t), ProfileStatus::Enforcing);
        // Default loader (no anchors) refuses it, observe-only + finding.
        let p = Pipeline::from_loaded(crate::load_profile(&good).unwrap(), Default::default());
        assert_eq!(p.mode(), Mode::Observe);
        assert_eq!(p.status_findings().len(), 1);
        assert!(p
            .status_message()
            .unwrap()
            .contains("no trusted profile keys"));
        let (unsigned, _) = write(&d, "unsigned.json", &profile(1, true), false);
        refused_because(status(&unsigned, &t), "no signature file");
        // Legacy: sealed, signed, but no metadata.
        let mut legacy = profile(1, true);
        legacy.metadata = None;
        let (lp, _) = write(&d, "legacy.json", &legacy, true);
        refused_because(status(&lp, &t), "migrate-legacy");
        // A forged signature (other key, same key id).
        let (forged, _) = write(&d, "forged.json", &profile(1, true), false);
        let text = std::fs::read_to_string(&forged).unwrap();
        let evil = Ed25519SigningKey::from_seed("oem", &[4; 32]).unwrap();
        let sig = ProfileSignature::create(text.as_bytes(), &evil).unwrap();
        std::fs::write(sig_path_for(&forged), sig.to_text()).unwrap();
        refused_because(status(&forged, &t), "does not verify");
        // Platform expectation.
        let mut tp = t.clone();
        tp.expect_platform = Some("drone".into());
        refused_because(status(&good, &tp), "platform");
        // Broken trust file: reported for a locked profile, ignored for a
        // draft.
        let mut bad = t.clone();
        bad.trusted_keys = Some(d.join("missing-trust.json"));
        refused_because(status(&good, &bad), "trusted profile keys");
        let (draft, _) = write(&d, "draft.json", &profile(0, false), false);
        assert_eq!(status(&draft, &bad), ProfileStatus::Observing);
        // A directory at the .sig path is a malformed signature.
        let (dirsig, _) = write(&d, "dirsig.json", &profile(1, true), false);
        std::fs::create_dir(sig_path_for(&dirsig)).unwrap();
        refused_because(status(&dirsig, &t), "signature file");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn anti_rollback_through_the_loader() {
        let d = tmpdir("rollback");
        let mut t = trust(&d, true);
        let state = t.state_file.clone().unwrap();
        let (v2, v2d) = write(&d, "v2.json", &profile(2, true), true);
        let (v1, v1d) = write(&d, "v1.json", &profile(1, true), true);
        assert_eq!(status(&v2, &t), ProfileStatus::Enforcing);
        assert_eq!(load_state(&state).unwrap().unwrap().digest, v2d);
        // Older version: refused, state untouched.
        let before = std::fs::read(&state).unwrap();
        refused_because(status(&v1, &t), "rollback refused");
        assert_eq!(std::fs::read(&state).unwrap(), before);
        // A draft replacing the locked profile: refused too (with finding).
        let (draft, dd) = write(&d, "draft.json", &profile(0, false), false);
        let l = load_profile_with_trust(&draft, &t).unwrap();
        let p = Pipeline::from_loaded(l, PipelineOptions::default());
        assert!(matches!(p.status(), ProfileStatus::FileRejected(_)));
        assert_eq!(p.status_findings().len(), 1);
        t.allow_rollback = Some(dd);
        assert_eq!(status(&draft, &t), ProfileStatus::Observing);
        assert_eq!(std::fs::read(&state).unwrap(), before);
        // Explicit rollback to v1 by digest.
        t.allow_rollback = Some(v1d.clone());
        assert_eq!(status(&v1, &t), ProfileStatus::Enforcing);
        assert_eq!(load_state(&state).unwrap().unwrap().profile_version, 1);
        // The flag can now go; v1 stays accepted, v2 upgrades again.
        t.allow_rollback = None;
        assert_eq!(status(&v1, &t), ProfileStatus::Enforcing);
        assert_eq!(status(&v2, &t), ProfileStatus::Enforcing);
        assert_eq!(load_state(&state).unwrap().unwrap().profile_version, 2);
        // A corrupt state file fails closed.
        std::fs::write(&state, "{").unwrap();
        refused_because(status(&v2, &t), "anti-rollback state");
        let _ = v1d;
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn deferred_load_writes_nothing_until_commit() {
        let d = tmpdir("deferred");
        let t = trust(&d, true);
        let state = t.state_file.clone().unwrap();
        let (v1, _) = write(&d, "v1.json", &profile(1, true), true);
        let (l, c) = load_profile_deferred(&v1, &t).unwrap();
        assert!(l.file_check.is_ok());
        assert!(!state.exists());
        let c = c.expect("first acceptance writes state");
        c.commit().unwrap();
        assert_eq!(load_state(&state).unwrap().unwrap().profile_version, 1);
        // Same profile again: nothing to write.
        let (_, c) = load_profile_deferred(&v1, &t).unwrap();
        assert!(c.is_none());
        // A commit that cannot be written is an error (the caller refuses).
        let bad = StateCommit {
            path: d.join("no-such-dir").join("state.json"),
            state: load_state(&state).unwrap().unwrap(),
        };
        assert!(matches!(
            bad.commit(),
            Err(ProfileFileError::Untrusted {
                reason: ProfileTrustError::State { .. }
            })
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn config_validation() {
        assert!(ProfileTrustConfig::default().validate().is_ok());
        assert!(ProfileTrustConfig::default().warnings()[0].contains("observe-only"));
        let rel = ProfileTrustConfig {
            trusted_keys: Some("trust.json".into()),
            ..Default::default()
        };
        assert!(rel.validate().is_err());
        let mut ok = ProfileTrustConfig {
            trusted_keys: Some("/etc/robodr/trust.json".into()),
            ..Default::default()
        };
        ok.validate().unwrap();
        assert!(ok.warnings()[0].contains("anti-rollback is OFF"));
        ok.allow_rollback = Some("v1".into());
        assert!(ok.validate().is_err());
        ok.allow_rollback = Some(format!("sha256:{}", "a".repeat(64)));
        ok.state_file = Some("/var/lib/robodr/state.json".into());
        ok.validate().unwrap();
        assert_eq!(ok.warnings().len(), 1);
        assert!(ok.warnings()[0].contains("allow_rollback is set"));
        ok.state_file = None;
        assert_eq!(ok.warnings().len(), 3);
        ok.expect_platform = Some("bad platform".into());
        assert!(ok.validate().is_err());
        let c: ProfileTrustConfig = serde_json::from_str(r#"{"trusted_keys":"/t.json"}"#).unwrap();
        assert_eq!(c.trusted_keys.as_deref(), Some(Path::new("/t.json")));
    }
}
