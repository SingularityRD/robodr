//! Safety-relevant configuration bound into the commissioning chain
//! (`Profile::bound_config`).
//!
//! # Why
//!
//! A locked profile is a signed, versioned, quorum-attested artifact (see
//! the parent module). The files that decide what RoboDR may *do* with it
//! were not: the response policy's `oem_validated` flag, the executor's
//! per-adapter `oem_validated` flags and the Motion Firewall envelope
//! (`firewall.json`, `allowed_sources`) were plain JSON that anyone able to
//! edit `/etc/robodr` could flip, with no record of who validated them, no
//! version and no rollback protection.
//!
//! # How
//!
//! `robodr-commission bind` writes the digest of each such file into the
//! draft profile's **content** (`bound_config`: role -> `sha256:<hex>`) and
//! adds one sign-off item per binding (`bound_config:<role> <digest>`, a
//! motion item: the two-person rule applies). From there the existing chain
//! covers it:
//!
//! * **signed**: the profile signature covers the content, so the digests;
//! * **attested**: the operators' sign-off is bound to the content digest,
//!   and the sign-off floor (`signoff::required_items`) requires a
//!   confirmed item for every binding, signed by `motion_quorum` distinct
//!   operators;
//! * **versioned / anti-rollback**: a binding changes only with a new
//!   `profile_version`; an older profile (with its older bindings) is
//!   refused by the profile's anti-rollback, and an older *file* under the
//!   current profile no longer matches its digest.
//!
//! A loader then honours such a file only through [`check_binding`]: the
//! profile must be a **trusted locked** profile (every check of
//! [`super::evaluate_profile_trust`] passed) and the file's digest must be
//! the bound one. Anything else is a [`BindingRefusal`]; callers fail
//! closed (agentd and the executor treat the policy and the adapters as
//! not OEM-validated; the gateway must refuse `enforce`).
//!
//! The executor's `motion` section lives inside `executor.json` next to
//! site settings that change without an OEM review (network allow-lists),
//! so it is bound by the digest of its canonical JSON
//! ([`canonical_json_digest`]: object keys sorted, no whitespace), not by
//! the file's bytes.
//!
//! # Limits
//!
//! * Changing a bound file needs a re-lock (new `profile_version`, new
//!   sign-off with the quorum). That is the point; it is also slower than
//!   editing a flag.
//! * A binding proves the operators signed *this* file; it cannot prove
//!   the OEM validation behind it was thorough.
//! * The executor, which has no black box, checks the binding without the
//!   anti-rollback state (agentd owns it and reports `profile_locked` in
//!   every order; a rolled-back profile is refused there).

use super::{evaluate_profile_trust, file_digest, TrustInputs};
use crate::profile_file::{read_regular_file, MAX_PROFILE_BYTES};
use robodr_events::profile::{Profile, BOUND_CONFIG_ROLES};
use serde_json::Value;
use std::fmt;
use std::path::Path;

/// Role of the response policy file.
pub const ROLE_RESPONSE_POLICY: &str = "response_policy";
/// Role of the Motion Firewall channel file (`robodr-firewall-gw`).
pub const ROLE_MOTION_FIREWALL: &str = "motion_firewall";
/// Role of agentd's `firewall.joint_config` file.
pub const ROLE_JOINT_FIREWALL: &str = "joint_firewall";
/// Role of the executor configuration's `motion` section.
pub const ROLE_EXECUTOR_MOTION: &str = "executor_motion";

/// Is `role` one a binding may have?
pub fn is_role(role: &str) -> bool {
    BOUND_CONFIG_ROLES.contains(&role)
}

/// A binding that holds: the file is the one the trusted profile binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub role: String,
    pub digest: String,
    /// `profile_version` of the profile that binds it.
    pub profile_version: u64,
    /// `locked_by` of that profile (the sign-off operator).
    pub locked_by: String,
}

/// Why a file is not honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingRefusal {
    /// No trusted locked profile: refused by the trust check (`why`), a
    /// draft, or no profile configured.
    NoTrustedProfile { why: String },
    /// The trusted profile binds no file for this role.
    NotBound { role: String },
    /// The trusted profile binds another file for this role.
    Mismatch {
        role: String,
        bound: String,
        found: String,
    },
}

impl fmt::Display for BindingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrustedProfile { why } => write!(
                f,
                "no trusted locked profile to bind it ({why}): it is not part of a signed \
                 commissioning"
            ),
            Self::NotBound { role } => write!(
                f,
                "the locked profile binds no {role} file (`robodr-commission bind`, then re-lock \
                 with the operators' sign-off)"
            ),
            Self::Mismatch { role, bound, found } => write!(
                f,
                "this {role} file is {found}, the locked profile binds {bound}: edited, replaced \
                 or rolled back since commissioning"
            ),
        }
    }
}

impl std::error::Error for BindingRefusal {}

/// Is the file with digest `digest` the one `profile` binds for `role`?
/// `profile` must be a **trusted locked** profile (the caller's trust
/// check accepted it); a draft is refused here as well.
pub fn check_binding(profile: &Profile, role: &str, digest: &str) -> Result<Bound, BindingRefusal> {
    let Some(meta) = profile.metadata.as_ref().filter(|_| profile.locked) else {
        return Err(BindingRefusal::NoTrustedProfile {
            why: "the profile is a draft".into(),
        });
    };
    match profile.bound_config.get(role) {
        None => Err(BindingRefusal::NotBound { role: role.into() }),
        Some(b) if b != digest => Err(BindingRefusal::Mismatch {
            role: role.into(),
            bound: b.clone(),
            found: digest.into(),
        }),
        Some(b) => Ok(Bound {
            role: role.into(),
            digest: b.clone(),
            profile_version: meta.profile_version,
            locked_by: meta.locked_by.clone(),
        }),
    }
}

/// Run the full trust check on the profile at `profile_path` (read-only:
/// nothing is written) and [`check_binding`] each `(role, digest)`. One
/// result per binding, in order. For a loader without the anti-rollback
/// state (the executor); a loader that already evaluated the profile calls
/// [`check_binding`] directly.
pub fn verify_bindings(
    profile_path: &Path,
    inputs: &TrustInputs<'_>,
    bindings: &[(&str, &str)],
) -> Vec<Result<Bound, BindingRefusal>> {
    let refuse_all = |why: String| {
        bindings
            .iter()
            .map(|_| Err(BindingRefusal::NoTrustedProfile { why: why.clone() }))
            .collect()
    };
    let raw = match read_regular_file(profile_path, MAX_PROFILE_BYTES) {
        Ok(t) => t,
        Err(e) => return refuse_all(format!("{}: {e}", profile_path.display())),
    };
    let ev = evaluate_profile_trust(profile_path, &raw, inputs);
    match ev.result {
        Err(e) => refuse_all(format!("{}: {e}", profile_path.display())),
        Ok(acc) if !acc.verified.profile.locked => {
            refuse_all(format!("{}: a draft profile", profile_path.display()))
        }
        Ok(acc) => bindings
            .iter()
            .map(|(role, digest)| check_binding(&acc.verified.profile, role, digest))
            .collect(),
    }
}

/// `sha256:<hex>` of a file's exact bytes (the digest `bind` records for
/// every role except [`ROLE_EXECUTOR_MOTION`]).
pub fn bytes_digest(bytes: &[u8]) -> String {
    file_digest(bytes)
}

/// Deepest JSON nesting [`canonical_json`] follows (deeper values are
/// refused rather than recursed into).
pub const MAX_CANONICAL_DEPTH: usize = 64;

/// The canonical JSON text of `v`: object keys sorted (byte order), no
/// insignificant whitespace, strings and numbers as serde_json writes them.
/// Independent of serde_json's map ordering feature. `None` when nested
/// deeper than [`MAX_CANONICAL_DEPTH`].
pub fn canonical_json(v: &Value) -> Option<String> {
    let mut out = String::new();
    write_canonical(v, &mut out, 0).then_some(out)
}

fn write_canonical(v: &Value, out: &mut String, depth: usize) -> bool {
    if depth > MAX_CANONICAL_DEPTH {
        return false;
    }
    match v {
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if !write_canonical(x, out, depth + 1) {
                    return false;
                }
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                match m.get(k) {
                    Some(x) if write_canonical(x, out, depth + 1) => {}
                    _ => return false,
                }
            }
            out.push('}');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
    true
}

/// `sha256:<hex>` of [`canonical_json`]`(v)` (the [`ROLE_EXECUTOR_MOTION`]
/// digest). `None` when too deep.
pub fn canonical_json_digest(v: &Value) -> Option<String> {
    canonical_json(v).map(|t| file_digest(t.as_bytes()))
}

/// The digest `bind` records for a file of `role` with text `text`: the
/// exact bytes, or for [`ROLE_EXECUTOR_MOTION`] the canonical JSON of the
/// executor configuration's `motion` member (`text` is the whole
/// `executor.json`).
pub fn digest_for_role(role: &str, text: &str) -> Result<String, String> {
    if role != ROLE_EXECUTOR_MOTION {
        return Ok(bytes_digest(text.as_bytes()));
    }
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let m = v
        .get("motion")
        .ok_or("the executor configuration has no `motion` section to bind")?;
    canonical_json_digest(m).ok_or_else(|| "the `motion` section is nested too deeply".into())
}

fn flag(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => "absent".into(),
        Some(other) => other.to_string(),
    }
}

/// What a file of `role` says, in one line, for the sign-off item the
/// operators sign (they must still open the file: this is a reminder, not
/// a review). Never fails: an unparsable file is summarised as such.
pub fn summarize(role: &str, text: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return "not JSON".into();
    };
    match role {
        ROLE_RESPONSE_POLICY => format!(
            "oem_validated: {}, platform: {}, morphology: {}",
            flag(&v, "oem_validated"),
            flag(&v, "platform"),
            flag(&v, "morphology")
        ),
        ROLE_EXECUTOR_MOTION => {
            let Some(m) = v.get("motion").and_then(Value::as_object) else {
                return "no motion section".into();
            };
            let parts: Vec<String> = m
                .iter()
                .map(|(k, a)| format!("{k} oem_validated: {}", flag(a, "oem_validated")))
                .collect();
            format!("adapters: [{}]", parts.join(", "))
        }
        _ => {
            let chans = |key: &str| -> Vec<String> {
                v.get(key)
                    .and_then(Value::as_object)
                    .map(|o| {
                        o.iter()
                            .map(|(c, s)| {
                                let n = s
                                    .get("allowed_sources")
                                    .and_then(Value::as_array)
                                    .map_or(0, Vec::len);
                                format!("{c} ({n} allowed source(s))")
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            format!(
                "channels: [{}], joint channels: [{}]",
                chans("channels").join(", "),
                chans("joint_channels").join(", ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::profile::{ProfileMetadata, PROFILE_SCHEMA_VERSION};

    fn locked(bound: &[(&str, &str)]) -> Profile {
        let mut p = Profile {
            model: "m".into(),
            locked: true,
            ..Default::default()
        };
        p.metadata = Some(ProfileMetadata {
            schema_version: PROFILE_SCHEMA_VERSION,
            profile_version: 3,
            platform: "ugv".into(),
            unit_id: None,
            locked_by: "op-a".into(),
            locked_at: 1,
            parent_digest: None,
            attestation: None,
        });
        for (r, d) in bound {
            p.bound_config.insert((*r).into(), (*d).into());
        }
        p
    }

    #[test]
    fn binding_must_match_exactly() {
        let d = bytes_digest(b"{\"oem_validated\": true}\n");
        let other = bytes_digest(b"{\"oem_validated\": true} \n");
        let p = locked(&[(ROLE_RESPONSE_POLICY, &d)]);
        let ok = check_binding(&p, ROLE_RESPONSE_POLICY, &d).unwrap();
        assert_eq!(ok.profile_version, 3);
        assert_eq!(ok.locked_by, "op-a");
        assert!(matches!(
            check_binding(&p, ROLE_RESPONSE_POLICY, &other),
            Err(BindingRefusal::Mismatch { .. })
        ));
        assert!(matches!(
            check_binding(&p, ROLE_MOTION_FIREWALL, &d),
            Err(BindingRefusal::NotBound { .. })
        ));
    }

    #[test]
    fn a_draft_never_binds() {
        let d = bytes_digest(b"x");
        let mut p = locked(&[(ROLE_RESPONSE_POLICY, &d)]);
        p.locked = false;
        assert!(matches!(
            check_binding(&p, ROLE_RESPONSE_POLICY, &d),
            Err(BindingRefusal::NoTrustedProfile { .. })
        ));
        p.locked = true;
        p.metadata = None;
        assert!(check_binding(&p, ROLE_RESPONSE_POLICY, &d).is_err());
    }

    #[test]
    fn canonical_json_ignores_order_and_whitespace_but_not_values() {
        let a: Value =
            serde_json::from_str(r#"{"b": {"y": 1, "x": [true, "s"]}, "a": null}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":null,"b":{"x":[true,"s"],"y":1}}"#).unwrap();
        let c: Value = serde_json::from_str(r#"{"a":null,"b":{"x":[true,"s"],"y":2}}"#).unwrap();
        assert_eq!(
            canonical_json(&a).unwrap(),
            r#"{"a":null,"b":{"x":[true,"s"],"y":1}}"#
        );
        assert_eq!(canonical_json_digest(&a), canonical_json_digest(&b));
        assert_ne!(canonical_json_digest(&a), canonical_json_digest(&c));
        let mut deep = Value::Null;
        for _ in 0..(MAX_CANONICAL_DEPTH + 2) {
            deep = Value::Array(vec![deep]);
        }
        assert!(canonical_json(&deep).is_none());
    }

    #[test]
    fn executor_motion_digest_is_of_the_section_only() {
        let a =
            r#"{"schema": "x", "network": {"a": 1}, "motion": {"nav2": {"oem_validated": true}}}"#;
        let b =
            r#"{"motion": {"nav2": {"oem_validated": true}}, "schema": "x", "network": {"a": 2}}"#;
        let c = r#"{"motion": {"nav2": {"oem_validated": false}}, "schema": "x"}"#;
        let da = digest_for_role(ROLE_EXECUTOR_MOTION, a).unwrap();
        assert_eq!(da, digest_for_role(ROLE_EXECUTOR_MOTION, b).unwrap());
        assert_ne!(da, digest_for_role(ROLE_EXECUTOR_MOTION, c).unwrap());
        assert!(digest_for_role(ROLE_EXECUTOR_MOTION, r#"{"schema": "x"}"#).is_err());
        // Every other role: the exact bytes.
        assert_ne!(
            digest_for_role(ROLE_RESPONSE_POLICY, a).unwrap(),
            digest_for_role(ROLE_RESPONSE_POLICY, b).unwrap()
        );
    }

    #[test]
    fn summaries_name_the_flags() {
        let s = summarize(
            ROLE_RESPONSE_POLICY,
            r#"{"oem_validated": true, "platform": "ugv", "morphology": "quadruped"}"#,
        );
        assert!(
            s.contains("oem_validated: true") && s.contains("quadruped"),
            "{s}"
        );
        let s = summarize(
            ROLE_EXECUTOR_MOTION,
            r#"{"motion": {"gateway": {"oem_validated": true}, "nav2": {}}}"#,
        );
        assert!(
            s.contains("gateway oem_validated: true") && s.contains("nav2 oem_validated: absent"),
            "{s}"
        );
        let s = summarize(
            ROLE_MOTION_FIREWALL,
            r#"{"channels": {"/cmd_vel": {"allowed_sources": ["a", "b"]}}, "joint_channels": {}}"#,
        );
        assert!(s.contains("/cmd_vel (2 allowed source(s))"), "{s}");
        assert_eq!(summarize(ROLE_RESPONSE_POLICY, "{"), "not JSON");
    }
}
