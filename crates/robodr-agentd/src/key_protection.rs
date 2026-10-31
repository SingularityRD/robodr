//! How the robot's private keys are protected at rest (SALES-READINESS
//! T66): reported in `status.json` (`key_protection`) and, with
//! `key_protection.require: "tpm2"`, enforced at start.
//!
//! ```json
//! "key_protection": {
//!   "require": "tpm2",
//!   "credentials_dir": "/run/credentials/robodr-agentd.service",
//!   "encrypted_dir": "/etc/robodr/credstore.encrypted"
//! }
//! ```
//!
//! All members are optional (defaults shown; `require` defaults to
//! `"none"`), and the section itself is optional: without it every key is
//! still classified and reported, nothing is refused.
//!
//! The recommended deployment seals each key to the TPM with systemd
//! (`systemd-creds encrypt --with-key=host+tpm2 --name=<name> <key>
//! <encrypted_dir>/<name>`, then `LoadCredentialEncrypted=<name>:
//! <encrypted_dir>/<name>` in the unit; see `docs/OPERATIONS.md`, "Robot
//! keys sealed to the TPM"). systemd decrypts the credential at service
//! start into the service's private ramfs (`credentials_dir`), where the
//! configuration's `key_file` points.
//!
//! Each private key the configuration names (`blackbox.key_file`,
//! `finding_signing.key_file`, `blackbox.head_anchor.tls.key_file`,
//! `control_plane.tls.key_file`, `executor.key_file`) is classified:
//!
//! | `protection`        | meaning                                                         |
//! |---------------------|-----------------------------------------------------------------|
//! | `tpm2`, `host+tpm2` | a credential whose sealed source in `encrypted_dir` needs this machine's TPM |
//! | `host`              | sealed with the host key file only (a disk copy decrypts it)    |
//! | `null`              | sealed with the null key: no confidentiality                    |
//! | `unknown`           | a sealed source that is unreadable or not recognised            |
//! | `plain-credential`  | a credential with no sealed source (`LoadCredential=` from a plain file) |
//! | `file`              | a plain key file outside `credentials_dir` (the file fallback), or any key when `credentials_dir` is not the directory systemd gave this process (`$CREDENTIALS_DIRECTORY`) |
//!
//! Only `tpm2` and `host+tpm2` count as TPM-held; anything else is a
//! **fallback** and is flagged (`fallback: true` per key and overall).
//!
//! When systemd started the process with credentials it sets
//! `$CREDENTIALS_DIRECTORY`; a `credentials_dir` that differs from it is
//! not where this service's credentials are, so nothing in it counts as a
//! credential (`file`, with a `detail`). Without the variable (e.g.
//! `--check-config` from a shell) the configured directory is trusted for
//! the report, but the daemon itself refuses to start under
//! `require: "tpm2"` ([`check_daemon_start`]): a process systemd did not
//! give credentials to has no TPM-sealed key, whatever a directory holds.
//!
//! Limits (stated in `docs/OPERATIONS.md` 4.7): the report trusts the
//! unit's layout (a credential named `blackbox.key` is matched to
//! `<encrypted_dir>/blackbox.key` by name; the unit file is not read).
//! systemd puts a `LoadCredential=` copy of a plain file and a
//! `LoadCredentialEncrypted=` decryption in the same place, identically,
//! and the unit makes the plain key directory inaccessible to the service
//! (`InaccessiblePaths=`), so from inside the service the two cannot be
//! told apart: if a sealed source of that name exists but the unit still
//! loads the plain file (the `15-` drop-in removed or overridden), the key
//! is reported as sealed. The report detects a missing or weaker seal, not
//! a unit that loads a different source than the sealed one. TPM sealing
//! protects keys at rest: at run time the decrypted key is in the
//! service's credential ramfs and memory, and the TPM does not perform the
//! signatures.

use std::path::{Path, PathBuf};

use robodr_signer::credential::{classify_file, CredentialSeal};
use serde::{Deserialize, Serialize};

use crate::config::DaemonConfig;

/// Default `credentials_dir`: where systemd puts this unit's credentials.
pub const DEFAULT_CREDENTIALS_DIR: &str = "/run/credentials/robodr-agentd.service";
/// Default `encrypted_dir`: where the sealed credential sources live.
pub const DEFAULT_ENCRYPTED_DIR: &str = "/etc/robodr/credstore.encrypted";

/// `key_protection.require`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// Report only (the default).
    #[default]
    None,
    /// Refuse to start unless every private key is TPM-sealed.
    Tpm2,
}

/// `key_protection` as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyProtectionSection {
    #[serde(default)]
    pub require: Requirement,
    #[serde(default)]
    pub credentials_dir: Option<PathBuf>,
    #[serde(default)]
    pub encrypted_dir: Option<PathBuf>,
}

/// One private key's classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyEntry {
    /// Which key: `blackbox`, `finding_signing`, `anchor_tls`,
    /// `control_plane_tls`, `executor`.
    pub role: &'static str,
    pub path: PathBuf,
    /// See the module docs.
    pub protection: &'static str,
    /// Decrypting it needs this machine's TPM.
    pub tpm2: bool,
    /// Not TPM-held: the file fallback (or a weaker seal).
    pub fallback: bool,
    /// The sealed source the classification read, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_source: Option<PathBuf>,
    /// Why a sealed source could not be classified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The `status.json` `key_protection` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyReport {
    pub require: Requirement,
    /// Every private key is TPM-sealed (`false` when there is none).
    pub all_tpm2: bool,
    /// At least one key is not TPM-held.
    pub fallback: bool,
    pub keys: Vec<KeyEntry>,
}

/// The private keys `config` names, with their role.
pub fn private_keys(config: &DaemonConfig) -> Vec<(&'static str, PathBuf)> {
    let mut v = vec![("blackbox", config.blackbox.key_file.clone())];
    if let Some(f) = &config.finding_signing {
        v.push(("finding_signing", f.key_file.clone()));
    }
    if let Some(crate::config::HeadAnchorConfig::Remote { tls: Some(t), .. }) =
        &config.blackbox.head_anchor
    {
        if let Some(k) = &t.key_file {
            v.push(("anchor_tls", k.clone()));
        }
    }
    if let Some(t) = config.control_plane.as_ref().and_then(|c| c.tls.as_ref()) {
        v.push(("control_plane_tls", t.key_file.clone()));
    }
    if let Some(e) = config.executor.as_ref().filter(|e| e.enabled) {
        if let Some(k) = &e.key_file {
            v.push(("executor", k.clone()));
        }
    }
    v
}

/// Classify one key path. `systemd_credentials` is `$CREDENTIALS_DIRECTORY`
/// when systemd set it for this process.
pub fn classify_key(
    role: &'static str,
    path: &Path,
    credentials_dir: &Path,
    encrypted_dir: &Path,
    systemd_credentials: Option<&Path>,
) -> KeyEntry {
    let entry = |protection: &'static str, tpm2: bool, src: Option<PathBuf>, detail| KeyEntry {
        role,
        path: path.to_path_buf(),
        protection,
        tpm2,
        fallback: !tpm2,
        sealed_source: src,
        detail,
    };
    // A credential is a direct child of the credentials directory (systemd
    // credential names have no '/').
    let name = match (path.parent(), path.file_name()) {
        (Some(dir), Some(n)) if dir == credentials_dir => n,
        _ => return entry("file", false, None, None),
    };
    if let Some(real) = systemd_credentials.filter(|r| *r != credentials_dir) {
        return entry(
            "file",
            false,
            None,
            Some(format!(
                "key_protection.credentials_dir {} is not this service's credentials directory \
                 ($CREDENTIALS_DIRECTORY is {})",
                credentials_dir.display(),
                real.display()
            )),
        );
    }
    let src = encrypted_dir.join(name);
    match std::fs::symlink_metadata(&src) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return entry("plain-credential", false, None, None)
        }
        Err(e) => return entry("unknown", false, Some(src), Some(e.to_string())),
        Ok(md) if !md.file_type().is_file() => {
            return entry(
                "unknown",
                false,
                Some(src),
                Some("not a regular file".into()),
            )
        }
        Ok(_) => {}
    }
    match classify_file(&src) {
        Ok(seal) => {
            let p = match seal {
                CredentialSeal::Tpm2 => "tpm2",
                CredentialSeal::HostAndTpm2 => "host+tpm2",
                CredentialSeal::Host => "host",
                CredentialSeal::Null => "null",
                CredentialSeal::Unknown => "unknown",
            };
            entry(p, seal.tpm2_bound(), Some(src), None)
        }
        Err(e) => entry("unknown", false, Some(src), Some(e)),
    }
}

/// `$CREDENTIALS_DIRECTORY`, when systemd set it for this process.
pub fn systemd_credentials_dir() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The daemon's own start check (not `--check-config`): under
/// `require: "tpm2"` the process must have been started by systemd with
/// credentials (`systemd_credentials` is `$CREDENTIALS_DIRECTORY`).
/// Without it, `credentials_dir` is just a directory, and a plain key copy
/// in it next to a sealed file of the same name would pass [`assess`].
pub fn check_daemon_start(
    report: &KeyReport,
    systemd_credentials: Option<&Path>,
) -> Result<(), String> {
    if report.require == Requirement::Tpm2 && systemd_credentials.is_none() {
        return Err(
            "key_protection.require is \"tpm2\" but $CREDENTIALS_DIRECTORY is not set: systemd \
             did not start this process with credentials, so no key can be a TPM-sealed \
             credential (start agentd from its unit with LoadCredentialEncrypted=; see \
             docs/OPERATIONS.md)"
                .into(),
        );
    }
    Ok(())
}

/// Classify every private key of `config` and apply `require`.
pub fn assess(config: &DaemonConfig) -> Result<KeyReport, String> {
    let s = config.key_protection.clone().unwrap_or_default();
    let cred = s
        .credentials_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CREDENTIALS_DIR));
    let enc = s
        .encrypted_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ENCRYPTED_DIR));
    for (what, p) in [
        ("key_protection.credentials_dir", &cred),
        ("key_protection.encrypted_dir", &enc),
    ] {
        if !p.is_absolute() {
            return Err(format!("{what} must be an absolute path"));
        }
    }
    let systemd_creds = systemd_credentials_dir();
    let keys: Vec<KeyEntry> = private_keys(config)
        .into_iter()
        .map(|(role, p)| classify_key(role, &p, &cred, &enc, systemd_creds.as_deref()))
        .collect();
    let all_tpm2 = !keys.is_empty() && keys.iter().all(|k| k.tpm2);
    if s.require == Requirement::Tpm2 && !all_tpm2 {
        let weak: Vec<String> = keys
            .iter()
            .filter(|k| !k.tpm2)
            .map(|k| format!("{} ({}: {})", k.role, k.path.display(), k.protection))
            .collect();
        return Err(format!(
            "key_protection.require is \"tpm2\" but these keys are not TPM-sealed \
             credentials: {} (seal them with systemd-creds --with-key=host+tpm2 into {} and \
             load them with LoadCredentialEncrypted=; see docs/OPERATIONS.md)",
            weak.join(", "),
            enc.display()
        ));
    }
    Ok(KeyReport {
        require: s.require,
        all_tpm2,
        fallback: keys.iter().any(|k| k.fallback),
        keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct D(PathBuf);
    impl Drop for D {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn dir(n: &str) -> D {
        let p = std::env::temp_dir().join(format!("agentd-keyprot-{n}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(p.join("creds")).unwrap();
        fs::create_dir_all(p.join("enc")).unwrap();
        D(p)
    }

    fn header(id: &str) -> Vec<u8> {
        let mut v = robodr_blackbox::crypto::from_hex(id).unwrap();
        for n in [32u32, 1, 12, 16] {
            v.extend_from_slice(&n.to_le_bytes());
        }
        v.extend_from_slice(&[0; 32]);
        v
    }

    #[test]
    fn classification() {
        let d = dir("cls");
        let (c, e) = (d.0.join("creds"), d.0.join("enc"));
        fs::write(e.join("bb.key"), header("0c7cc07b117645919c4b0bea08bc20fe")).unwrap();
        fs::write(e.join("fs.key"), header("93a894094874449090caf2fc93cab553")).unwrap();
        fs::write(e.join("h.key"), header("5a1c6a86df9d4096b1d5a65e0862f19a")).unwrap();
        fs::write(e.join("n.key"), header("058469daf6f54324800549da0f8ea2fb")).unwrap();
        fs::write(
            e.join("junk.key"),
            b"{\"format\":\"robodr-blackbox-key/v2\"}",
        )
        .unwrap();
        let k = |n: &str| classify_key("x", &c.join(n), &c, &e, None);
        assert_eq!((k("bb.key").protection, k("bb.key").tpm2), ("tpm2", true));
        assert_eq!(k("fs.key").protection, "host+tpm2");
        assert!(!k("fs.key").fallback);
        assert_eq!((k("h.key").protection, k("h.key").fallback), ("host", true));
        assert_eq!(k("n.key").protection, "null");
        // A plain key copied into the store is not a sealed credential.
        assert_eq!(k("junk.key").protection, "unknown");
        assert!(k("junk.key").detail.is_some());
        // A credential without a sealed source: LoadCredential= from a
        // plain file.
        assert_eq!(k("other.key").protection, "plain-credential");
        assert!(k("other.key").fallback);
        // Outside the credentials directory: the file fallback, even when a
        // sealed source of that name exists.
        let f = classify_key("x", &d.0.join("bb.key"), &c, &e, None);
        assert_eq!((f.protection, f.fallback), ("file", true));
        // A nested path under the credentials dir is not a credential.
        let n = classify_key("x", &c.join("sub/bb.key"), &c, &e, None);
        assert_eq!(n.protection, "file");
        // A directory as sealed source.
        fs::create_dir(e.join("dir.key")).unwrap();
        assert_eq!(k("dir.key").protection, "unknown");
    }

    /// Review finding (WP15 phase 3): with `$CREDENTIALS_DIRECTORY` unset
    /// the configured directory cannot be shown to be systemd's; the
    /// daemon refuses to start under `require: "tpm2"`.
    #[test]
    fn daemon_start_needs_systemd_credentials_under_tpm2() {
        let report = |require| KeyReport {
            require,
            all_tpm2: true,
            fallback: false,
            keys: vec![],
        };
        let e = check_daemon_start(&report(Requirement::Tpm2), None).unwrap_err();
        assert!(e.contains("CREDENTIALS_DIRECTORY"), "{e}");
        let c = Path::new("/run/credentials/robodr-agentd.service");
        assert!(check_daemon_start(&report(Requirement::Tpm2), Some(c)).is_ok());
        assert!(check_daemon_start(&report(Requirement::None), None).is_ok());
    }

    /// Review finding (WP15): a `credentials_dir` pointed at any directory
    /// (say a plain one on disk holding a copy of the key) next to a sealed
    /// file of the same name was reported as TPM-sealed. When systemd says
    /// where this service's credentials are, nothing elsewhere counts.
    #[test]
    fn a_credentials_dir_that_is_not_systemds_is_not_trusted() {
        let d = dir("realcreds");
        let (c, e) = (d.0.join("creds"), d.0.join("enc"));
        fs::write(e.join("bb.key"), header("0c7cc07b117645919c4b0bea08bc20fe")).unwrap();
        let real = Path::new("/run/credentials/robodr-agentd.service");
        let k = classify_key("x", &c.join("bb.key"), &c, &e, Some(real));
        assert_eq!((k.protection, k.tpm2, k.fallback), ("file", false, true));
        assert!(k.detail.unwrap().contains("CREDENTIALS_DIRECTORY"));
        // The matching directory (trailing slash or not) is trusted.
        for same in [c.clone(), PathBuf::from(format!("{}/", c.display()))] {
            let k = classify_key("x", &c.join("bb.key"), &c, &e, Some(&same));
            assert_eq!((k.protection, k.tpm2), ("tpm2", true));
        }
    }
}
