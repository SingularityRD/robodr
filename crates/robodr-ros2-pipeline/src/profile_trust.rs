//! Loading a profile **with trust**: detached signature, trust anchors,
//! trust roots (signed floor, revocation list), platform/unit binding and
//! anti-rollback, on top of the commissioning file check. The checks
//! themselves live in `robodr_commission::trust` (the crate that owns the
//! profile file format; one decision function,
//! `evaluate_profile_trust`); this module wires them to the sensor
//! configuration ([`ProfileTrustConfig`], the `profile_trust` sub-table of
//! `[module.robodr-sensor-ros2]` / agentd's `sensor` section) and to
//! [`LoadedProfile`].
//!
//! ```toml
//! [module.robodr-sensor-ros2.profile_trust]
//! trusted_keys = "/etc/robodr/profile-trust.json"   # robodr-profile-trust/v1
//! state_file = "/var/lib/robodr/profile-state.json" # anti-rollback
//! expect_platform = "ugv-x1"                        # optional
//! expect_unit_id = "ugv-007"                        # optional
//! trust_roots = "/etc/robodr/trust-roots.json"      # robodr-trust-roots/v1
//! revocation_list = "/etc/robodr/revocations.json"  # robodr-profile-revocations/v2
//! revocation_policy = "optional"                    # or "required"
//! # allow_rollback = "sha256:<digest of the one older file to accept>"
//! ```
//!
//! # Decisions
//!
//! * **Fail closed.** Without `trusted_keys` no locked profile can be
//!   authenticated, so none is enforced: the sensor runs observe-only and
//!   reports one `robot.ros2.profile_refused` finding. The same holds for a
//!   missing / malformed / forged signature, a key not in the trust file,
//!   a legacy locked profile without metadata, a platform or unit mismatch,
//!   a refused rollback, a revoked profile or signing key, a profile below
//!   the trust file's root-signed `min_profile_version`, and a revocation
//!   list that is invalid, older than the accepted one, or (with
//!   `revocation_policy = "required"`, or after one was accepted) missing.
//!   Refusal never stops the sensor (a broken profile must not blind it,
//!   nor be escalated into a safe-state request).
//! * **Anti-rollback** needs `state_file`. On acceptance of a locked
//!   profile with a new version (or the first one, or a newer revocation
//!   list) the state is rewritten atomically: at load time by
//!   [`load_profile_with_trust`], or when the caller says so with
//!   [`load_profile_deferred`] / [`load_profile_checked`] +
//!   [`StateCommit::commit`] (agentd: never on `--check-config`; a failed
//!   write means the profile is not enforced). A refused profile never
//!   touches the state. A lower version, the same version with different
//!   bytes, or a draft replacing a locked profile is refused unless
//!   `allow_rollback` names that file's exact digest (`robodr-commission
//!   verify-profile` prints it). After a permitted rollback the state
//!   records the older version, so the flag can (and should) be removed
//!   again.
//! * **Black-box witness.** A caller with a black box (agentd) passes the
//!   latest accepted-profile record of its chain to
//!   [`load_profile_checked`]: a state file that is missing or behind that
//!   record is reported as a [`StateAlarm`] (agentd: Critical, observe-only
//!   finding [`PROFILE_STATE_TAMPERED`]) and the record is the rollback
//!   baseline, so deleting the state file no longer resets anti-rollback.
//!   Callers without a black box (the Pulsar sensor, `robodr-ros2-watch`)
//!   have only the state file and the signed floor.
//! * Drafts (unlocked) need no signature: they are observe-only anyway.
//!
//! Limits: see `robodr_commission::trust` (file-held keys, a root who
//! deletes both state and black box leaves only the signed floor, trust
//! files can be replayed, no expiry).

use std::path::{Path, PathBuf};

use robodr_commission::trust::{
    evaluate_profile_trust, store_state, validate_rollback_flag, AcceptedState, RevocationPolicy,
    RollbackDecision, StateAlarm, TrustInputs,
};
use robodr_commission::ProfileFileError;
use serde::Deserialize;

use crate::pipeline::{read_profile_lenient, LoadedProfile};

/// Rule id of the finding raised for a [`StateAlarm`]: the anti-rollback
/// state file is missing or behind the black box's record (deleted or
/// rewritten). Critical, always observe-only: it never requests an action.
pub const PROFILE_STATE_TAMPERED: &str = "robot.ros2.profile_state_tampered";

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
    /// `robodr-trust-roots/v1` file: the keys that sign the revocation list
    /// and a trust-file `min_profile_version` (disjoint from the profile
    /// keys).
    pub trust_roots: Option<PathBuf>,
    /// `robodr-profile-revocations/v2` file (needs `trust_roots`).
    pub revocation_list: Option<PathBuf>,
    /// What a missing `revocation_list` file means: `"optional"` (default)
    /// or `"required"` (every locked profile refused).
    pub revocation_policy: RevocationPolicy,
}

impl ProfileTrustConfig {
    /// Check the configuration (paths absolute, rollback flag a digest,
    /// expectations well-formed labels, a revocation list only with trust
    /// roots, `required` only with a list). Non-fatal problems are reported
    /// by [`ProfileTrustConfig::warnings`].
    pub fn validate(&self) -> Result<(), String> {
        for (what, p) in [
            ("profile_trust.trusted_keys", &self.trusted_keys),
            ("profile_trust.state_file", &self.state_file),
            ("profile_trust.trust_roots", &self.trust_roots),
            ("profile_trust.revocation_list", &self.revocation_list),
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
        if self.revocation_list.is_some() && self.trust_roots.is_none() {
            return Err(
                "profile_trust.revocation_list needs profile_trust.trust_roots (the keys that \
                 sign it)"
                    .into(),
            );
        }
        if self.revocation_policy == RevocationPolicy::Required && self.revocation_list.is_none() {
            return Err("profile_trust.revocation_policy = \"required\" needs \
                 profile_trust.revocation_list"
                .into());
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
    /// flag left set, no revocation list.
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
        if self.trusted_keys.is_some() && self.revocation_list.is_none() {
            w.push(
                "profile_trust.revocation_list is not set: a revoked profile or signing key can \
                 only be withdrawn by editing the trust file"
                    .into(),
            );
        }
        w
    }

    fn inputs<'a>(&'a self, chain: Option<&'a AcceptedState>) -> TrustInputs<'a> {
        TrustInputs {
            trusted_keys: self.trusted_keys.as_deref(),
            trust_roots: self.trust_roots.as_deref(),
            revocation_list: self.revocation_list.as_deref(),
            revocation_policy: self.revocation_policy,
            expect_platform: self.expect_platform.as_deref(),
            expect_unit_id: self.expect_unit_id.as_deref(),
            state_file: self.state_file.as_deref(),
            allow_rollback: self.allow_rollback.as_deref(),
            chain,
        }
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
    let t = load_profile_checked(path, trust, None)?;
    Ok((t.loaded, t.commit))
}

/// Everything [`load_profile_checked`] decided.
#[derive(Debug, Clone)]
pub struct TrustLoad {
    /// The profile and its file + trust check.
    pub loaded: LoadedProfile,
    /// The state write an acceptance implies (commit before enforcing).
    pub commit: Option<StateCommit>,
    /// The state file disagrees with the black-box record (reported
    /// whatever the outcome).
    pub alarm: Option<StateAlarm>,
    /// The accepted locked profile to record in the black box once
    /// enforcing (`robodr_commission::trust::accepted_note`); `None` when
    /// refused or a draft.
    pub accepted: Option<AcceptedState>,
    /// Key that signed the accepted profile.
    pub signed_by: Option<String>,
    /// The rollback decision (`None`: no state file, or refused).
    pub decision: Option<RollbackDecision>,
}

/// [`load_profile_deferred`] with the black box's latest accepted-profile
/// record (`chain`, see the module docs), returning the alarm and the
/// record to append as well.
pub fn load_profile_checked(
    path: &Path,
    trust: &ProfileTrustConfig,
    chain: Option<&AcceptedState>,
) -> Result<TrustLoad, String> {
    let (raw, profile) = read_profile_lenient(path)?;
    let eval = evaluate_profile_trust(path, &raw, &trust.inputs(chain));
    let mut t = TrustLoad {
        loaded: LoadedProfile {
            profile,
            file_check: Ok(()),
        },
        commit: None,
        alarm: eval.alarm,
        accepted: None,
        signed_by: None,
        decision: None,
    };
    match eval.result {
        Ok(a) => {
            t.commit = match (a.state_write, &trust.state_file) {
                (Some(state), Some(p)) => Some(StateCommit {
                    path: p.clone(),
                    state,
                }),
                _ => None,
            };
            t.accepted = a.record;
            t.signed_by = a.verified.signed_by;
            t.decision = a.decision;
        }
        Err(e) => t.loaded.file_check = Err(e),
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Pipeline, PipelineOptions, ProfileStatus};
    use robodr_blackbox::Ed25519SigningKey;
    use robodr_commission::trust::{
        file_digest, load_state, sig_path_for, trust_keys_text, ProfileSignature, ProfileTrustError,
    };
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
                attestation: None,
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
                ..Default::default()
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
        assert_eq!(ok.warnings().len(), 2);
        assert!(ok.warnings()[0].contains("allow_rollback is set"));
        assert!(ok.warnings()[1].contains("revocation_list is not set"));
        ok.state_file = None;
        assert_eq!(ok.warnings().len(), 4);
        ok.expect_platform = Some("bad platform".into());
        assert!(ok.validate().is_err());
        let c: ProfileTrustConfig = serde_json::from_str(r#"{"trusted_keys":"/t.json"}"#).unwrap();
        assert_eq!(c.trusted_keys.as_deref(), Some(Path::new("/t.json")));
        assert_eq!(c.revocation_policy, RevocationPolicy::Optional);
        // Revocation settings.
        let mut r = ProfileTrustConfig {
            trusted_keys: Some("/t.json".into()),
            revocation_list: Some("/r.json".into()),
            ..Default::default()
        };
        assert!(r.validate().unwrap_err().contains("trust_roots"));
        r.trust_roots = Some("roots.json".into());
        assert!(r.validate().unwrap_err().contains("absolute"));
        r.trust_roots = Some("/roots.json".into());
        r.validate().unwrap();
        r.revocation_policy = RevocationPolicy::Required;
        r.validate().unwrap();
        r.revocation_list = None;
        assert!(r.validate().unwrap_err().contains("required"));
        let c: ProfileTrustConfig =
            serde_json::from_str(r#"{"revocation_policy":"required"}"#).unwrap();
        assert_eq!(c.revocation_policy, RevocationPolicy::Required);
        assert!(
            serde_json::from_str::<ProfileTrustConfig>(r#"{"revocation_policy":"maybe"}"#).is_err()
        );
    }

    fn root() -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed("root", &[9; 32]).unwrap()
    }

    /// `trust` plus roots and a revocation list path.
    fn with_revocations(dir: &Path, mut t: ProfileTrustConfig) -> ProfileTrustConfig {
        let r = dir.join("roots.json");
        std::fs::write(
            &r,
            robodr_commission::trust::trust_roots_text(&[root().verifying_key()]),
        )
        .unwrap();
        t.trust_roots = Some(r);
        t.revocation_list = Some(dir.join("revocations.json"));
        // With roots the trust file must be root-signed; these hand-made
        // profiles carry no operator attestation, so the file opts out.
        let tf = robodr_commission::trust::trust_file_text_with(
            &[key().verifying_key()],
            &robodr_commission::trust::TrustFileOptions {
                require_attestation: Some(false),
                ..Default::default()
            },
        );
        let tp = t.trusted_keys.clone().unwrap();
        std::fs::write(&tp, &tf).unwrap();
        let sig = ProfileSignature::create_for(
            robodr_commission::trust::SigKind::TrustFile,
            tf.as_bytes(),
            &root(),
        )
        .unwrap();
        std::fs::write(sig_path_for(&tp), sig.to_text()).unwrap();
        t
    }

    /// A list for "ugv-x1"; `keys` name keys ("oem" is `key()`), revoked
    /// by fingerprint.
    fn write_list(t: &ProfileTrustConfig, serial: u64, digests: &[&str], keys: &[&str]) {
        let fp = |k: &str| match k {
            "oem" => robodr_commission::trust::key_fingerprint(key().verifying_key().as_bytes()),
            other => file_digest(other.as_bytes()),
        };
        let l = robodr_commission::trust::RevocationList::create(
            serial,
            1,
            "ugv-x1",
            digests.iter().map(|s| s.to_string()),
            keys.iter().map(|k| fp(k)),
            &root(),
        )
        .unwrap();
        std::fs::write(t.revocation_list.as_ref().unwrap(), l.to_text()).unwrap();
    }

    #[test]
    fn revocations_through_the_loader() {
        let d = tmpdir("revoke");
        let t = with_revocations(&d, trust(&d, true));
        let (v1, v1d) = write(&d, "v1.json", &profile(1, true), true);
        // Optional and absent: enforced.
        assert_eq!(status(&v1, &t), ProfileStatus::Enforcing);
        // Required and absent: refused.
        let mut req = t.clone();
        req.revocation_policy = RevocationPolicy::Required;
        refused_because(status(&v1, &req), "missing");
        // Revoked digest / revoked key: observe-only + one finding.
        write_list(&t, 1, &[&v1d], &[]);
        let p = Pipeline::from_loaded(
            load_profile_with_trust(&v1, &t).unwrap(),
            PipelineOptions::default(),
        );
        assert_eq!(p.mode(), Mode::Observe);
        assert_eq!(p.status_findings().len(), 1);
        assert!(p.status_message().unwrap().contains("revoked"));
        write_list(&t, 2, &[], &["oem"]);
        refused_because(status(&v1, &t), "signing key \"oem\" (sha256:");
        // The trust file without its root signature: refused.
        let tp = t.trusted_keys.clone().unwrap();
        let sig = std::fs::read(sig_path_for(&tp)).unwrap();
        std::fs::remove_file(sig_path_for(&tp)).unwrap();
        refused_because(status(&v1, &t), "must be signed");
        std::fs::write(sig_path_for(&tp), sig).unwrap();
        // A clean newer list: enforced, serial recorded.
        write_list(&t, 3, &[], &[]);
        assert_eq!(status(&v1, &t), ProfileStatus::Enforcing);
        let st = load_state(t.state_file.as_ref().unwrap()).unwrap().unwrap();
        assert_eq!(st.revocation_serial, Some(3));
        // An older list is refused; so is removing it.
        write_list(&t, 2, &[], &[]);
        refused_because(status(&v1, &t), "revocation list rollback");
        std::fs::remove_file(t.revocation_list.as_ref().unwrap()).unwrap();
        refused_because(status(&v1, &t), "now missing");
        // A tampered list.
        write_list(&t, 4, &[], &[]);
        let lp = t.revocation_list.clone().unwrap();
        let text = std::fs::read_to_string(&lp).unwrap();
        std::fs::write(&lp, text.replace("\"serial\": 4", "\"serial\": 5")).unwrap();
        refused_because(status(&v1, &t), "does not verify");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn chain_record_detects_a_deleted_state_file() {
        let d = tmpdir("chain");
        let t = trust(&d, true);
        let state = t.state_file.clone().unwrap();
        let (v2, _) = write(&d, "v2.json", &profile(2, true), true);
        let (v1, _) = write(&d, "v1.json", &profile(1, true), true);
        let first = load_profile_checked(&v2, &t, None).unwrap();
        assert!(first.alarm.is_none());
        assert_eq!(first.decision, Some(RollbackDecision::First));
        assert_eq!(first.signed_by.as_deref(), Some("oem"));
        first.commit.unwrap().commit().unwrap();
        let rec = first.accepted.unwrap();
        // State deleted, v1 offered: refused, alarm, nothing written.
        std::fs::remove_file(&state).unwrap();
        let l = load_profile_checked(&v1, &t, Some(&rec)).unwrap();
        assert!(l.loaded.file_check.is_err());
        assert!(l.commit.is_none() && l.accepted.is_none());
        let alarm = l.alarm.unwrap();
        assert!(alarm.to_string().contains("missing"), "{alarm}");
        assert!(!state.exists());
        let p = Pipeline::from_loaded(l.loaded, PipelineOptions::default());
        assert!(p.status_message().unwrap().contains("rollback refused"));
        // v2 again: enforced, state restored from the record.
        let l = load_profile_checked(&v2, &t, Some(&rec)).unwrap();
        assert!(l.loaded.file_check.is_ok() && l.alarm.is_some());
        l.commit.unwrap().commit().unwrap();
        assert_eq!(load_state(&state).unwrap(), Some(rec.clone()));
        let l = load_profile_checked(&v2, &t, Some(&rec)).unwrap();
        assert!(l.alarm.is_none() && l.commit.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
