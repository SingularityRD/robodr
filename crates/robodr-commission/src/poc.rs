//! Lab / proof-of-concept signing chain (`robodr-commission poc-init`).
//!
//! A production commissioning has a trust root kept offline, a profile
//! signing key held by the OEM and at least two operators with their own
//! keys (two-person rule). Setting that up is the first hour of every
//! proof of concept, and the temptation is to skip it: run with an unlocked
//! (observe-only) profile, or hand-edit trust files. `poc-init` builds the
//! **complete** chain in one step, so a POC exercises exactly the
//! production path (`learn` -> `bind` -> sign-off -> `lock` -> loaders
//! verify), but with:
//!
//! * a **single-operator** quorum (`motion_quorum` 1),
//! * every key generated on one workstation, in one directory,
//! * the root-signed trust file marked `lab_only: true`, every key id
//!   prefixed `lab-only-` and the operator name suffixed `[LAB-ONLY]` (so
//!   `locked_by` in every locked profile, every `verify-profile` line and
//!   every agentd start says so).
//!
//! Loaders accept such a chain (it is cryptographically complete), and
//! report it loudly: `verify-profile` prints [`LAB_ONLY_BANNER`], agentd and
//! the executor (with `commissioning`) warn at every start. Moving to
//! production means a new chain (`keygen --roots`, `keygen`, `operators`
//! with two or more people, `trust-keys --sign-key`): nothing of a lab
//! chain is reusable, by design.

use crate::signoff::OperatorTrust;
use crate::trust::{
    new_signing_key, signing_key_from_file, trust_file_text_with, trust_roots_text,
    ProfileSignature, SigKind, TrustFileOptions,
};
use robodr_blackbox::{Ed25519SigningKey, Ed25519VerifyingKey};
use std::path::{Path, PathBuf};

/// What loaders print for a lab-only chain.
pub const LAB_ONLY_BANNER: &str = "LAB-ONLY TRUST CHAIN (robodr-commission poc-init): one \
     operator, every key generated on one workstation. Acceptable for a proof of concept, \
     NEVER for a production unit: commission again with an offline trust root and a two-person \
     operator quorum.";

/// Suffix of the operator name in a lab chain.
pub const LAB_OPERATOR_SUFFIX: &str = " [LAB-ONLY]";

/// The files a lab chain consists of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocChain {
    pub dir: PathBuf,
    /// Secret keys (mode 0600): root, profile signing, operator.
    pub root_key: PathBuf,
    pub profile_key: PathBuf,
    pub operator_key: PathBuf,
    /// `robodr-operators/v1` list (one operator, quorum 1).
    pub operators: PathBuf,
    /// To install on the unit: roots, root-signed trust file and its sig.
    pub trust_roots: PathBuf,
    pub trust_file: PathBuf,
    pub trust_sig: PathBuf,
    pub readme: PathBuf,
    /// The operator name as it appears in sign-offs and `locked_by`.
    pub operator_name: String,
}

fn check_operator(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
    {
        return Err(format!(
            "operator name {name:?} must be 1..=64 of [A-Za-z0-9._@-]"
        ));
    }
    Ok(())
}

/// Create the lab chain in `dir`, which must not exist yet (nothing is
/// overwritten; on error the partly written directory is removed).
pub fn init(dir: &Path, operator: &str) -> Result<PocChain, String> {
    check_operator(operator)?;
    if std::fs::symlink_metadata(dir).is_ok() {
        return Err(format!(
            "{}: already exists (poc-init never overwrites a chain; pick a new directory)",
            dir.display()
        ));
    }
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let r = build(dir, operator);
    if r.is_err() {
        let _ = std::fs::remove_dir_all(dir);
    }
    r
}

fn build(dir: &Path, operator: &str) -> Result<PocChain, String> {
    let operator_name = format!("{operator}{LAB_OPERATOR_SUFFIX}");
    let key = |id: &str,
               file: &str|
     -> Result<(PathBuf, (Ed25519SigningKey, Ed25519VerifyingKey)), String> {
        let (kf, vk) = new_signing_key(Some(id))?;
        let p = dir.join(file);
        kf.write_new(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        let public = kf.to_public().map_err(|e| e.to_string())?;
        let pp = robodr_blackbox::keys::public_key_path(&p);
        public
            .write_new(&pp)
            .map_err(|e| format!("{}: {e}", pp.display()))?;
        let sk = signing_key_from_file(&kf)?;
        Ok((p, (sk, vk)))
    };
    let (root_key, (root_sk, root_vk)) = key("lab-only-root", "lab-only-root.key")?;
    let (profile_key, (_, profile_vk)) = key("lab-only-profile", "lab-only-profile.key")?;
    let (operator_key, (_, op_vk)) = key("lab-only-operator", "lab-only-operator.key")?;
    let ops = OperatorTrust::new(vec![(operator_name.clone(), op_vk)], 1)?;
    let operators = dir.join("operators.json");
    let trust_roots = dir.join("trust-roots.json");
    let trust_file = dir.join("profile-trust.json");
    let trust_sig = crate::trust::sig_path_for(&trust_file);
    let readme = dir.join("LAB-ONLY-README.txt");
    let trust_text = trust_file_text_with(
        &[profile_vk],
        &TrustFileOptions {
            require_attestation: Some(true),
            operators: Some(&ops),
            lab_only: true,
            ..Default::default()
        },
    );
    // What a unit will check: roots-signed, operators listed, lab-marked.
    let sig = ProfileSignature::create_for(SigKind::TrustFile, trust_text.as_bytes(), &root_sk)
        .map_err(|e| e.to_string())?;
    let roots_text = trust_roots_text(&[root_vk]);
    let roots = crate::trust::parse_trust_roots(&roots_text).map_err(|e| e.to_string())?;
    let tf =
        crate::trust::parse_trust_file(&trust_text, Some(&sig.to_text()), "(new)", Some(&roots))
            .map_err(|e| e.to_string())?;
    if !tf.lab_only {
        return Err("internal: lab marking lost".into());
    }
    let readme_text = readme_text(dir, &operator_name);
    let ops_text = ops.to_text();
    let sig_text = sig.to_text();
    let files: Vec<(&Path, &[u8])> = vec![
        (&operators, ops_text.as_bytes()),
        (&trust_roots, roots_text.as_bytes()),
        (&trust_file, trust_text.as_bytes()),
        (&trust_sig, sig_text.as_bytes()),
        (&readme, readme_text.as_bytes()),
    ];
    crate::write_files_atomic(&files, false).map_err(|e| e.to_string())?;
    Ok(PocChain {
        dir: dir.to_path_buf(),
        root_key,
        profile_key,
        operator_key,
        operators,
        trust_roots,
        trust_file,
        trust_sig,
        readme,
        operator_name,
    })
}

fn readme_text(dir: &Path, operator_name: &str) -> String {
    let d = dir.display();
    format!(
        "{LAB_ONLY_BANNER}\n\n\
         Files\n\
         - lab-only-root.key (+ .pub): trust root. Signs profile-trust.json. In production it is \
         kept offline.\n\
         - lab-only-profile.key (+ .pub): profile signing key (lock --sign-key).\n\
         - lab-only-operator.key (+ .pub): the single operator, named \"{operator_name}\".\n\
         - operators.json: operators trust list (motion_quorum 1).\n\
         - trust-roots.json, profile-trust.json, profile-trust.json.sig: install these on the \
         unit (sensor.profile_trust.trust_roots / trusted_keys); lab_only is set in the \
         root-signed trust file and cannot be removed without the root key.\n\n\
         Proof-of-concept path (the production path, one operator)\n\
         1. robodr-commission learn --pcap run.pcapng --out draft.json --report report.json\n\
         2. robodr-commission report-html --report report.json --out report.html\n\
         3. robodr-commission firewall-draft --in draft.json --report report.json \
         --out firewall.json --max-angular <OEM yaw ceiling>\n\
         4. robodr-commission bind --in draft.json --out bound.json --signoff \
         draft.json.signoff.json --response-policy response-policy.json \
         [--motion-firewall firewall.json] [--executor-config executor.json]\n\
         5. review bound.json.signoff.json, set \"confirmed\": true on every item and \
         \"operator\": \"{operator_name}\"\n\
         6. robodr-commission signoff --signoff bound.json.signoff.json --sign-key \
         {d}/lab-only-operator.key --operators {d}/operators.json\n\
         7. robodr-commission lock --in bound.json --signoff bound.json.signoff.json \
         --operators {d}/operators.json --out profile.json --platform <P> \
         --profile-version 1 --sign-key {d}/lab-only-profile.key\n\
         8. robodr-commission verify-profile --profile profile.json --trusted-keys \
         {d}/profile-trust.json --trust-roots {d}/trust-roots.json\n\n\
         For production: discard this directory and build a new chain with an offline root and \
         two or more operators (docs: crates/robodr-commission/README.md).\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{load_trust_file, load_trust_roots};

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-poc-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn chain_is_complete_root_signed_and_marked() {
        let d = tmp("ok");
        let c = init(&d, "alice").unwrap();
        let roots = load_trust_roots(&c.trust_roots).unwrap();
        let tf = load_trust_file(&c.trust_file, Some(&roots)).unwrap();
        assert!(tf.lab_only);
        assert!(tf.require_attestation);
        let ops = tf.operators.unwrap();
        assert_eq!(ops.motion_quorum(), 1);
        assert_eq!(
            ops.operators().into_iter().collect::<Vec<_>>(),
            vec!["alice [LAB-ONLY]"]
        );
        assert_eq!(c.operator_name, "alice [LAB-ONLY]");
        let readme = std::fs::read_to_string(&c.readme).unwrap();
        assert!(readme.starts_with("LAB-ONLY TRUST CHAIN"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&c.root_key).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "secret key readable by others");
        // Never overwrites.
        assert!(init(&d, "alice").unwrap_err().contains("already exists"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn stripping_the_mark_breaks_the_root_signature() {
        let d = tmp("strip");
        let c = init(&d, "bob").unwrap();
        let t = std::fs::read_to_string(&c.trust_file).unwrap();
        let stripped = t.replace("  \"lab_only\": true,\n", "");
        assert_ne!(t, stripped, "{t}");
        std::fs::write(&c.trust_file, stripped).unwrap();
        let roots = load_trust_roots(&c.trust_roots).unwrap();
        assert!(load_trust_file(&c.trust_file, Some(&roots)).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bad_operator_names_are_refused_before_anything_is_written() {
        let d = tmp("bad");
        assert!(init(&d, "").is_err());
        assert!(init(&d, "a b").is_err());
        assert!(!d.exists());
    }
}
