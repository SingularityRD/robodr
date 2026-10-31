//! `--check-config` before the service has run (review 2, M18).
//!
//! The configuration names its keys where systemd puts them while the unit
//! runs (`/run/credentials/robodr-agentd.service/<name>`, the unit's
//! `LoadCredential=`). Before the first start, or while the service is
//! stopped, that directory does not exist, so the documented pre-start
//! check (`robodr-agentd --config ... --check-config`, quick start and
//! SITE-ACCEPTANCE row 1) failed on every fresh install.
//!
//! When the check runs outside the unit (`$CREDENTIALS_DIRECTORY` unset)
//! and the configured credentials directory is missing, the check reads
//! the unit file and its drop-ins the way systemd orders them, maps every
//! credential name to its source (`LoadCredential=name:path`; on
//! `robodr-focal`, the `robodr-load-credential load ... name:path`
//! arguments of `ExecStartPre=`), and checks the configuration against
//! those source files. The running daemon never does this: it reads only
//! what systemd handed it.
//!
//! A credential sealed to the TPM (`LoadCredentialEncrypted=`) cannot be
//! read outside the unit: the check says so and names the command that
//! runs it with the unit's credentials (`systemd-run`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The unit whose credentials the configuration names.
pub const UNIT: &str = "robodr-agentd.service";

/// systemd's unit search path, most important first.
pub const UNIT_DIRS: [&str; 4] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

/// Largest unit file or drop-in read.
const MAX_UNIT_BYTES: u64 = 256 * 1024;
/// Most drop-ins read per directory.
const MAX_DROPINS: usize = 256;

/// Where a credential comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `LoadCredential=` (or focal's `robodr-load-credential`): a plain file.
    Plain(PathBuf),
    /// `LoadCredentialEncrypted=`: sealed, readable only by systemd.
    Encrypted(PathBuf),
}

/// The credential sources of the unit texts `texts` (the unit file first,
/// then its drop-ins in systemd's order): a later assignment of a name
/// wins, an empty `LoadCredential=` / `LoadCredentialEncrypted=` resets the
/// entries of that kind before it.
pub fn parse_sources(texts: &[String]) -> BTreeMap<String, Source> {
    let mut out: BTreeMap<String, Source> = BTreeMap::new();
    for text in texts {
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("LoadCredential=") {
                if v.trim().is_empty() {
                    out.retain(|_, s| !matches!(s, Source::Plain(_)));
                } else if let Some((n, p)) = name_path(v) {
                    out.insert(n, Source::Plain(p));
                }
            } else if let Some(v) = line.strip_prefix("LoadCredentialEncrypted=") {
                if v.trim().is_empty() {
                    out.retain(|_, s| !matches!(s, Source::Encrypted(_)));
                } else if let Some((n, p)) = name_path(v) {
                    out.insert(n, Source::Encrypted(p));
                }
            } else if let Some(v) = line.strip_prefix("ExecStartPre=") {
                // robodr-focal (systemd 245): `+/usr/lib/robodr/
                // robodr-load-credential load <unit> <user> name:path...`.
                let words: Vec<&str> = v.split_whitespace().collect();
                let is_loader = words
                    .first()
                    .is_some_and(|w| w.ends_with("/robodr-load-credential"));
                if is_loader && words.get(1) == Some(&"load") {
                    for w in words.iter().skip(4) {
                        if let Some((n, p)) = name_path(w) {
                            out.insert(n, Source::Plain(p));
                        }
                    }
                }
            }
        }
    }
    out
}

/// `name:/absolute/path` (a name without `/`, an absolute path).
fn name_path(v: &str) -> Option<(String, PathBuf)> {
    let (n, p) = v.trim().split_once(':')?;
    let p = Path::new(p);
    (!n.is_empty() && !n.contains('/') && p.is_absolute()).then(|| (n.to_string(), p.into()))
}

/// The texts of `unit` and its drop-ins under `dirs` (most important
/// first), in the order systemd applies them: the unit file from the first
/// directory that has it, then every `<unit>.d/*.conf` sorted by file name,
/// a name in a more important directory hiding the same name in a less
/// important one. Unreadable files are skipped.
pub fn read_unit_texts(dirs: &[&Path], unit: &str) -> Vec<String> {
    let read = |p: &Path| -> Option<String> {
        let md = std::fs::metadata(p).ok()?;
        if !md.is_file() || md.len() > MAX_UNIT_BYTES {
            return None;
        }
        std::fs::read_to_string(p).ok()
    };
    let mut out = Vec::new();
    if let Some(t) = dirs.iter().find_map(|d| read(&d.join(unit))) {
        out.push(t);
    }
    let mut dropins: BTreeMap<String, PathBuf> = BTreeMap::new();
    for d in dirs.iter().rev() {
        let Ok(entries) = std::fs::read_dir(d.join(format!("{unit}.d"))) else {
            continue;
        };
        for e in entries.take(MAX_DROPINS).flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".conf") {
                // Less important directories first: a later insert (more
                // important) replaces the same name.
                dropins.insert(name, e.path());
            }
        }
    }
    out.extend(dropins.values().filter_map(|p| read(p)));
    out
}

/// The configuration text `text` with every string that names a file in
/// `credentials_dir` replaced by that credential's source, and one line
/// per replacement (for the check's report). A sealed credential, or a
/// name the unit does not load, is an error that says what to do.
pub fn rewrite(
    text: &str,
    credentials_dir: &Path,
    sources: &BTreeMap<String, Source>,
) -> Result<(String, Vec<String>), String> {
    let mut v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("config: {e}"))?;
    let mut notes = Vec::new();
    let mut err = None;
    walk(&mut v, &mut |s: &mut String| {
        let p = Path::new(s.as_str());
        if p.parent() != Some(credentials_dir) {
            return;
        }
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        match sources.get(&name) {
            Some(Source::Plain(src)) => {
                notes.push(format!(
                    "credential {name}: checked at its source {} ({UNIT} is not running, {} \
                     does not exist)",
                    src.display(),
                    credentials_dir.display()
                ));
                *s = src.display().to_string();
            }
            Some(Source::Encrypted(src)) => {
                err.get_or_insert(format!(
                    "credential {name} is sealed ({}, LoadCredentialEncrypted=): it can only be \
                     read inside the unit. Check with the unit's credentials: sudo systemd-run \
                     --wait --pipe --collect -p LoadCredentialEncrypted={name}:{} \
                     /usr/sbin/robodr-agentd --config <agentd.json> --check-config (one -p per \
                     credential), or after systemctl start robodr-agentd",
                    src.display(),
                    src.display()
                ));
            }
            None => {
                err.get_or_insert(format!(
                    "{s} is a credential of {UNIT}, but neither the unit nor its drop-ins load \
                     a credential named {name} (LoadCredential={name}:<file>): add the drop-in \
                     that provides it"
                ));
            }
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    let text = serde_json::to_string(&v).map_err(|e| format!("config: {e}"))?;
    Ok((text, notes))
}

fn walk(v: &mut serde_json::Value, f: &mut dyn FnMut(&mut String)) {
    match v {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| walk(x, f)),
        serde_json::Value::Object(m) => m.values_mut().for_each(|x| walk(x, f)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(t: &str) -> String {
        t.to_string()
    }

    #[test]
    fn sources_follow_systemd_order_and_resets() {
        let unit =
            s("[Service]\nLoadCredential=blackbox.key:/etc/robodr/keys/agentd-blackbox.key\n");
        let finding =
            s("[Service]\nLoadCredential=finding.key:/etc/robodr/keys/agentd-finding.key\n");
        let sealed = s("[Service]\nLoadCredential=\n\
             LoadCredentialEncrypted=blackbox.key:/etc/robodr/credstore.encrypted/blackbox.key\n");
        let m = parse_sources(&[unit.clone(), finding.clone()]);
        assert_eq!(
            m.get("blackbox.key"),
            Some(&Source::Plain(
                "/etc/robodr/keys/agentd-blackbox.key".into()
            ))
        );
        assert_eq!(m.len(), 2);
        // The TPM drop-in resets the plain credentials and seals the key.
        let m = parse_sources(&[unit, sealed, finding]);
        assert_eq!(
            m.get("blackbox.key"),
            Some(&Source::Encrypted(
                "/etc/robodr/credstore.encrypted/blackbox.key".into()
            ))
        );
        assert!(matches!(m.get("finding.key"), Some(Source::Plain(_))));
        // robodr-focal's loader.
        let focal = s(
            "ExecStartPre=+/usr/lib/robodr/robodr-load-credential clear robodr-agentd.service\n\
             ExecStartPre=+/usr/lib/robodr/robodr-load-credential load robodr-agentd.service \
             robodr-agentd blackbox.key:/etc/robodr/keys/agentd-blackbox.key\n",
        );
        let m = parse_sources(&[focal]);
        assert_eq!(
            m.get("blackbox.key"),
            Some(&Source::Plain(
                "/etc/robodr/keys/agentd-blackbox.key".into()
            ))
        );
        // Malformed entries are ignored.
        assert!(
            parse_sources(&[s("LoadCredential=x:relative\nLoadCredential=a/b:/x\n")]).is_empty()
        );
    }

    #[test]
    fn the_shipped_units_load_the_example_key() {
        for unit in [
            "../../packaging/systemd/robodr-agentd.service",
            "../../packaging/systemd/focal/robodr-agentd.service",
        ] {
            let t =
                std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(unit)).unwrap();
            let m = parse_sources(&[t]);
            assert_eq!(
                m.get("blackbox.key"),
                Some(&Source::Plain(
                    "/etc/robodr/keys/agentd-blackbox.key".into()
                )),
                "{unit}"
            );
        }
    }

    #[test]
    fn drop_ins_are_ordered_and_hidden_by_name() {
        let root = std::env::temp_dir().join(format!("robodr-unitcred-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (etc, lib) = (root.join("etc"), root.join("lib"));
        for d in [&etc, &lib] {
            std::fs::create_dir_all(d.join(format!("{UNIT}.d"))).unwrap();
        }
        std::fs::write(lib.join(UNIT), "LoadCredential=a.key:/lib/a\n").unwrap();
        std::fs::write(
            etc.join(format!("{UNIT}.d/20-b.conf")),
            "LoadCredential=b.key:/etc/b\n",
        )
        .unwrap();
        std::fs::write(
            lib.join(format!("{UNIT}.d/20-b.conf")),
            "LoadCredential=b.key:/lib/b\n",
        )
        .unwrap();
        std::fs::write(
            lib.join(format!("{UNIT}.d/10-a.conf")),
            "LoadCredential=a.key:/lib/a2\n",
        )
        .unwrap();
        std::fs::write(lib.join(format!("{UNIT}.d/x.txt")), "LoadCredential=x:/x\n").unwrap();
        let texts = read_unit_texts(&[etc.as_path(), lib.as_path()], UNIT);
        let m = parse_sources(&texts);
        assert_eq!(m.get("a.key"), Some(&Source::Plain("/lib/a2".into())));
        assert_eq!(m.get("b.key"), Some(&Source::Plain("/etc/b".into())));
        assert_eq!(m.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rewrite_maps_credentials_and_explains_what_it_cannot() {
        let dir = Path::new("/run/credentials/robodr-agentd.service");
        let mut m = BTreeMap::new();
        m.insert(
            s("blackbox.key"),
            Source::Plain("/etc/robodr/keys/bb.key".into()),
        );
        let text = r#"{"blackbox":{"key_file":"/run/credentials/robodr-agentd.service/blackbox.key",
            "dir":"/var/lib/robodr/blackbox/agentd"}}"#;
        let (t, notes) = rewrite(text, dir, &m).unwrap();
        assert!(t.contains("\"/etc/robodr/keys/bb.key\""), "{t}");
        assert!(t.contains("/var/lib/robodr/blackbox/agentd"));
        assert_eq!(notes.len(), 1);
        m.insert(
            s("blackbox.key"),
            Source::Encrypted("/etc/robodr/credstore.encrypted/blackbox.key".into()),
        );
        let e = rewrite(text, dir, &m).unwrap_err();
        assert!(
            e.contains("systemd-run") && e.contains("LoadCredentialEncrypted=blackbox.key:"),
            "{e}"
        );
        let e = rewrite(text, dir, &BTreeMap::new()).unwrap_err();
        assert!(e.contains("LoadCredential=blackbox.key:"), "{e}");
    }
}
