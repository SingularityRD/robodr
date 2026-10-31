//! Commissioned configuration: agentd honours the response policy's
//! `oem_validated` (and treats the Motion Firewall joint file as
//! commissioned) only when the file is bound into the trusted locked
//! profile (`robodr_commission::trust::bound`, sales-readiness T11 / T12).
//!
//! # Decision
//!
//! At configuration time, after the profile trust check:
//!
//! * **response policy**: its exact bytes must be the `response_policy`
//!   the trusted locked profile binds. Otherwise `oem_validated` is
//!   **treated as false** (every plan observe-only, every control-plane
//!   action refused with `observe_mode`), a warning names why, and, when
//!   the file claimed `oem_validated: true` under a trusted locked profile,
//!   a High, observe-only `robot.agent.config_unattested` finding is
//!   raised at start. A policy that does not claim validation changes
//!   nothing.
//! * **`firewall.joint_config`**: must be the bound `joint_firewall` file.
//!   agentd's firewall verdicts are recording-only, so nothing is
//!   disabled; the mismatch is a warning and the same finding (the gateway,
//!   which enforces, refuses `enforce` on an unbound file: WP11).
//! * A **lab-only** trust chain (`robodr-commission poc-init`) is accepted
//!   and warned about at every start.
//!
//! Without a trusted locked profile (draft, refused, no trust configured)
//! the policy is treated as not validated too; the profile's own refusal
//! finding already reports that state, so no second finding is raised.

use std::path::Path;

use robodr_commission::trust::bound::{
    bytes_digest, check_binding, BindingRefusal, ROLE_JOINT_FIREWALL, ROLE_RESPONSE_POLICY,
};
use robodr_events::profile::Profile;
use robodr_responder::ResponsePolicy;

/// Rule id of the finding for a safety configuration file that claims
/// more than the commissioning signed (observe-only, High).
pub const CONFIG_UNATTESTED: &str = "robot.agent.config_unattested";

/// The outcome of [`apply`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Commissioned {
    /// Details of the `robot.agent.config_unattested` findings to raise at
    /// start (one per file).
    pub findings: Vec<String>,
    /// Warnings to log.
    pub warnings: Vec<String>,
}

/// Apply the decision (see the module docs). `trusted` is `Some(profile)`
/// for a trusted locked profile (the trust check accepted it), `None`
/// otherwise. `policy` is downgraded in place.
pub fn apply(
    trusted: Option<&Profile>,
    policy_path: &Path,
    policy_text: &str,
    policy: &mut ResponsePolicy,
    joint: Option<(&Path, &str)>,
) -> Commissioned {
    let mut out = Commissioned::default();
    let check = |role: &str, text: &str| -> Result<(), BindingRefusal> {
        let digest = bytes_digest(text.as_bytes());
        match trusted {
            Some(p) => check_binding(p, role, &digest).map(|_| ()),
            None => Err(BindingRefusal::NoTrustedProfile {
                why: "the profile is not a trusted locked profile".into(),
            }),
        }
    };
    if policy.oem_validated {
        if let Err(e) = check(ROLE_RESPONSE_POLICY, policy_text) {
            policy.oem_validated = false;
            let detail = format!(
                "response policy {} says oem_validated: true, but {e}; it is treated as NOT \
                 OEM-validated (every plan observe-only)",
                policy_path.display()
            );
            out.warnings.push(detail.clone());
            if trusted.is_some() {
                out.findings.push(detail);
            }
        }
    }
    if let Some((path, text)) = joint {
        if let Err(e) = check(ROLE_JOINT_FIREWALL, text) {
            let detail = format!(
                "firewall.joint_config {}: {e}; its envelope is not the commissioned one \
                 (recorded verdicts only; a gateway must not enforce it)",
                path.display()
            );
            out.warnings.push(detail.clone());
            if trusted.is_some() {
                out.findings.push(detail);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::profile::{ProfileMetadata, PROFILE_SCHEMA_VERSION};
    use robodr_responder::PlatformFamily;

    fn policy(validated: bool) -> (ResponsePolicy, String) {
        let mut p = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        p.morphology = robodr_responder::Morphology::WheeledMobile;
        p.oem_validated = validated;
        let t = serde_json::to_string_pretty(&p).unwrap();
        (ResponsePolicy::from_json(&t).unwrap(), t)
    }

    fn locked(bind: &[(&str, &str)]) -> Profile {
        let mut p = Profile {
            model: "m".into(),
            locked: true,
            ..Default::default()
        };
        p.metadata = Some(ProfileMetadata {
            schema_version: PROFILE_SCHEMA_VERSION,
            profile_version: 2,
            platform: "ugv".into(),
            unit_id: None,
            locked_by: "alice".into(),
            locked_at: 1,
            parent_digest: None,
            attestation: None,
        });
        for (r, t) in bind {
            p.bound_config
                .insert((*r).into(), bytes_digest(t.as_bytes()));
        }
        p
    }

    #[test]
    fn unbound_validation_is_downgraded_and_reported() {
        let (mut pol, text) = policy(true);
        let prof = locked(&[]);
        let c = apply(Some(&prof), Path::new("/p.json"), &text, &mut pol, None);
        assert!(!pol.oem_validated);
        assert_eq!(c.findings.len(), 1, "{c:?}");
        assert!(c.findings[0].contains("binds no response_policy"), "{c:?}");
    }

    #[test]
    fn bound_validation_is_honoured_and_an_edit_is_not() {
        let (mut pol, text) = policy(true);
        let prof = locked(&[(ROLE_RESPONSE_POLICY, &text)]);
        let c = apply(Some(&prof), Path::new("/p.json"), &text, &mut pol, None);
        assert!(pol.oem_validated);
        assert_eq!(c, Commissioned::default());
        // One byte more: not the commissioned file.
        let edited = format!("{text} ");
        let mut pol = ResponsePolicy::from_json(&edited).unwrap();
        let c = apply(Some(&prof), Path::new("/p.json"), &edited, &mut pol, None);
        assert!(!pol.oem_validated);
        assert!(
            c.findings[0].contains("edited, replaced or rolled back"),
            "{c:?}"
        );
    }

    #[test]
    fn without_a_trusted_profile_nothing_is_validated_and_no_extra_finding() {
        let (mut pol, text) = policy(true);
        let c = apply(None, Path::new("/p.json"), &text, &mut pol, None);
        assert!(!pol.oem_validated);
        assert!(c.findings.is_empty());
        assert_eq!(c.warnings.len(), 1);
        // A policy that claims nothing changes nothing.
        let (mut pol, text) = policy(false);
        let c = apply(
            Some(&locked(&[])),
            Path::new("/p.json"),
            &text,
            &mut pol,
            None,
        );
        assert_eq!(c, Commissioned::default());
    }

    #[test]
    fn joint_config_must_be_the_bound_file() {
        let (mut pol, text) = policy(false);
        let joint = "{\"joint_channels\": {}}";
        let prof = locked(&[(ROLE_JOINT_FIREWALL, joint)]);
        let c = apply(
            Some(&prof),
            Path::new("/p.json"),
            &text,
            &mut pol,
            Some((Path::new("/j.json"), joint)),
        );
        assert_eq!(c, Commissioned::default());
        let c = apply(
            Some(&prof),
            Path::new("/p.json"),
            &text,
            &mut pol,
            Some((Path::new("/j.json"), "{}")),
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].contains("firewall.joint_config"));
    }
}
