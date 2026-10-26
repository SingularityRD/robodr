//! Installers per kind (`docs/SECURE-DELIVERY.md` §4.2). Each prepares a
//! version next to the running one (no effect on the robot), switches to
//! it atomically, and can tell which version is active (crash recovery).
//!
//! | kind | prepared at | switch | active version |
//! |---|---|---|---|
//! | `files` | `<files_root>/<name>/<serial>/` | `<files_root>/<name>/current` symlink swap | the link target |
//! | `config` | `<config_root>/<name>/<serial>/` | `current` symlink swap | the link target |
//! | `robodr-rules` | `<state_dir>/rules/<name>/<serial>/` (checked, [`crate::rules`]) | `<rules_active>/<name>` symlink swap, then `rules_reload` | the link target |
//! | `deb` | `<state_dir>/debs/<digest>/<file>.deb` (inspected with `dpkg-deb`) | `dpkg -i` | `dpkg-query` status and version |
//!
//! Content paths were validated by `robodr-pkg` (relative, no `.`/`..`,
//! no hidden or option-like component); they are checked again here and
//! every file is created exclusively in a freshly made directory tree, so
//! no payload can write outside its version directory or through a
//! symlink, and a `config` RPK can write only below `config_root`. A
//! symlink or a non-directory where the agent expects its own directory
//! (`<root>`, `<root>/<name>`) refuses the install.
//!
//! A `deb` with maintainer scripts (`preinst`, `postinst`, `prerm`,
//! `postrm`, `config`) or `triggers` is refused unless the release quorum
//! set `install.allow_maintainer_scripts`; its `Package` must stay the same
//! across serials and its `Architecture` must be the unit's or `all`.

use crate::config::Config;
use crate::fsx;
use crate::runner::{self, Limits};
use crate::state::{DebInfo, Ver};
use crate::store::Store;
use robodr_pkg::common::is_safe_rel_path;
use robodr_pkg::rpk::{Kind, Manifest};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Why a version could not be prepared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepError {
    /// The content is not acceptable (refuse the item).
    Refused(String),
    /// A problem of this host (retry later).
    Io(String),
}

impl std::fmt::Display for PrepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrepError::Refused(s) => write!(f, "refused: {s}"),
            PrepError::Io(s) => write!(f, "error: {s}"),
        }
    }
}

fn io(p: &Path, e: impl std::fmt::Display) -> PrepError {
    PrepError::Io(format!("{}: {e}", p.display()))
}

/// The kinds this agent installs (13b).
pub fn supported(k: Kind) -> bool {
    matches!(
        k,
        Kind::Files | Kind::Config | Kind::Deb | Kind::RobodrRules
    )
}

/// Maintainer-script members of a `.deb`'s control area.
pub const MAINTAINER_SCRIPTS: [&str; 6] = [
    "preinst", "postinst", "prerm", "postrm", "config", "triggers",
];

/// The installers, bound to a configuration and the store.
#[derive(Debug)]
pub struct Installer<'a> {
    pub cfg: &'a Config,
    pub store: &'a Store,
}

impl Installer<'_> {
    fn versions_root(&self, kind: Kind) -> PathBuf {
        match kind {
            Kind::Config => self.cfg.install.config_root.clone(),
            Kind::RobodrRules => self.cfg.state_dir.join("rules"),
            Kind::Deb => self.cfg.state_dir.join("debs"),
            _ => self.cfg.install.files_root.clone(),
        }
    }

    /// The prepared version directory of `name` / `serial` (not `deb`).
    pub fn version_dir(&self, kind: Kind, name: &str, serial: u64) -> PathBuf {
        self.versions_root(kind).join(name).join(serial.to_string())
    }

    fn link(&self, kind: Kind, name: &str) -> PathBuf {
        match kind {
            Kind::RobodrRules => self.cfg.install.rules_active.join(name),
            _ => self.versions_root(kind).join(name).join("current"),
        }
    }

    fn deb_dir(&self, digest: &str) -> PathBuf {
        self.cfg.state_dir.join("debs").join(digest)
    }

    /// Prepare version `v` of `m` (idempotent; the active version is never
    /// touched). Fills `v.deb` for a `deb`.
    pub fn prepare(&self, m: &Manifest, v: &mut Ver) -> Result<(), PrepError> {
        if !supported(m.kind) {
            return Err(PrepError::Refused(format!(
                "kind {:?} is not installed by this agent",
                m.kind
            )));
        }
        if m.kind == Kind::Deb {
            return self.prepare_deb(m, v);
        }
        let root = self.versions_root(m.kind);
        if !fsx::is_real_dir(&root) {
            // The roots are created by the package (tmpfiles); a missing
            // one is created, a symlink or file in its place refuses.
            fsx::ensure_dir(&root, 0o755)
                .map_err(|e| PrepError::Refused(format!("{}: {e}", root.display())))?;
        }
        let pdir = root.join(&m.name);
        fsx::ensure_dir(&pdir, 0o755)
            .map_err(|e| PrepError::Refused(format!("{}: {e}", pdir.display())))?;
        let vdir = pdir.join(m.version.serial.to_string());
        if self.active_serial(m.kind, &m.name).ok().flatten() == Some(m.version.serial) {
            return Ok(());
        }
        fsx::remove_any(&vdir).map_err(|e| io(&vdir, e))?;
        let stage = fsx::temp_sibling(&vdir, "stage");
        fsx::ensure_dir(&stage, 0o755).map_err(|e| io(&stage, e))?;
        let res = self.write_tree(m, &stage).and_then(|()| {
            if m.kind == Kind::RobodrRules {
                self.check_rules(m, &stage)?;
            }
            fsx::sync_dir(&stage).map_err(|e| io(&stage, e))?;
            fs::rename(&stage, &vdir).map_err(|e| io(&vdir, e))?;
            fsx::sync_dir(&pdir).map_err(|e| io(&pdir, e))
        });
        if res.is_err() {
            let _ = fsx::remove_any(&stage);
        }
        res
    }

    /// Materialise the payload files of `m` under `dir` (a fresh tree).
    fn write_tree(&self, m: &Manifest, dir: &Path) -> Result<(), PrepError> {
        for f in m.payload_files() {
            // Defence in depth: robodr-pkg refused these already.
            if !is_safe_rel_path(&f.path) {
                return Err(PrepError::Refused(format!(
                    "unsafe content path {:?}",
                    robodr_pkg::common::trunc(&f.path)
                )));
            }
            let mut cur = dir.to_path_buf();
            let parts: Vec<&str> = f.path.split('/').collect();
            for p in &parts[..parts.len().saturating_sub(1)] {
                cur.push(p);
                match fs::symlink_metadata(&cur) {
                    Ok(md) if md.file_type().is_dir() => {}
                    Ok(_) => {
                        return Err(PrepError::Refused(format!(
                            "{}: path is both a file and a directory",
                            f.path
                        )))
                    }
                    Err(_) => fsx::ensure_dir(&cur, 0o755).map_err(|e| io(&cur, e))?,
                }
            }
            let dest = dir.join(&f.path);
            if !dest.starts_with(dir) {
                return Err(PrepError::Refused(format!(
                    "{} escapes its version directory",
                    f.path
                )));
            }
            self.store.materialize(m, f, &dest).map_err(PrepError::Io)?;
        }
        Ok(())
    }

    fn check_rules(&self, m: &Manifest, dir: &Path) -> Result<(), PrepError> {
        let mut names = BTreeSet::new();
        for f in m.payload_files() {
            let p = dir.join(&f.path);
            let b = robodr_release::fsio::read_capped(&p, crate::rules::MAX_RULE_FILE_BYTES)
                .map_err(|e| PrepError::Refused(e.to_string()))?;
            crate::rules::check_file(&f.path, &b, &mut names).map_err(PrepError::Refused)?;
        }
        if let Some(v) = &self.cfg.install.rules_validator {
            let mut argv = v.clone();
            argv.push(dir.to_string_lossy().into_owned());
            let r = runner::run(
                &argv,
                None,
                Limits {
                    timeout: Duration::from_secs(120),
                    max_output: 16 * 1024,
                },
            );
            if !r.success() {
                return Err(PrepError::Refused(format!(
                    "rules validator: {}",
                    r.summary()
                )));
            }
        }
        Ok(())
    }

    fn dpkg_query_argv(&self, package: &str) -> Vec<String> {
        let mut a = vec![self.cfg.install.dpkg_query.to_string_lossy().into_owned()];
        if let Some(r) = &self.cfg.install.dpkg_root {
            a.push(format!("--admindir={}", r.join("var/lib/dpkg").display()));
        }
        a.extend([
            "-W".to_string(),
            "-f".to_string(),
            "${db:Status-Status}\\t${Version}".to_string(),
            "--".to_string(),
            package.to_string(),
        ]);
        a
    }

    fn tool(&self, argv: &[String], secs: u64) -> runner::RunResult {
        runner::run(
            argv,
            None,
            Limits {
                timeout: Duration::from_secs(secs),
                max_output: 64 * 1024,
            },
        )
    }

    fn deb_field(&self, deb: &Path, field: &str) -> Result<String, PrepError> {
        let r = self.tool(
            &[
                self.cfg.install.dpkg_deb.to_string_lossy().into_owned(),
                "--field".into(),
                deb.to_string_lossy().into_owned(),
                field.into(),
            ],
            60,
        );
        if !r.success() || r.truncated {
            return Err(PrepError::Refused(format!(
                "dpkg-deb --field {field}: {}",
                r.summary()
            )));
        }
        let v = r.output.trim().to_string();
        let ok = !v.is_empty()
            && v.len() <= 128
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.~:_".contains(&b));
        if !ok {
            return Err(PrepError::Refused(format!("dpkg-deb: bad {field} field")));
        }
        Ok(v)
    }

    fn prepare_deb(&self, m: &Manifest, v: &mut Ver) -> Result<(), PrepError> {
        let files: Vec<_> = m.payload_files().collect();
        let [f] = files.as_slice() else {
            return Err(PrepError::Refused(
                "a deb RPK carries exactly one .deb".into(),
            ));
        };
        let base = self.cfg.state_dir.join("debs");
        fsx::ensure_dir(&base, 0o700).map_err(|e| io(&base, e))?;
        let dir = self.deb_dir(&v.digest);
        let name = f.path.rsplit('/').next().unwrap_or("package.deb");
        let deb = dir.join(name);
        if !deb.is_file() {
            fsx::remove_any(&dir).map_err(|e| io(&dir, e))?;
            let stage = fsx::temp_sibling(&dir, "stage");
            fsx::ensure_dir(&stage, 0o700).map_err(|e| io(&stage, e))?;
            let res = self
                .store
                .materialize(m, f, &stage.join(name))
                .map_err(PrepError::Io)
                .and_then(|()| fs::rename(&stage, &dir).map_err(|e| io(&dir, e)));
            if res.is_err() {
                let _ = fsx::remove_any(&stage);
            }
            res?;
        }
        let package = self.deb_field(&deb, "Package")?;
        let version = self.deb_field(&deb, "Version")?;
        let arch = self.deb_field(&deb, "Architecture")?;
        if arch != "all" && arch != self.cfg.unit.arch.as_str() {
            return Err(PrepError::Refused(format!(
                "the .deb is for {arch}, this unit is {}",
                self.cfg.unit.arch.as_str()
            )));
        }
        // Maintainer scripts: listed from the control area.
        let ctl = fsx::temp_sibling(&dir.join("control"), "ctl");
        let r = self.tool(
            &[
                self.cfg.install.dpkg_deb.to_string_lossy().into_owned(),
                "--control".into(),
                deb.to_string_lossy().into_owned(),
                ctl.to_string_lossy().into_owned(),
            ],
            60,
        );
        let listed: Result<Vec<String>, PrepError> = if r.success() {
            fs::read_dir(&ctl).map_err(|e| io(&ctl, e)).map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
        } else {
            Err(PrepError::Refused(format!(
                "dpkg-deb --control: {}",
                r.summary()
            )))
        };
        let _ = fsx::remove_any(&ctl);
        let scripts: Vec<String> = listed?
            .into_iter()
            .filter(|n| MAINTAINER_SCRIPTS.contains(&n.as_str()))
            .collect();
        if !scripts.is_empty() && !m.install.allow_maintainer_scripts {
            return Err(PrepError::Refused(format!(
                "the .deb has maintainer scripts ({}) and the release did not allow them",
                scripts.join(", ")
            )));
        }
        v.deb = Some(DebInfo { package, version });
        Ok(())
    }

    /// Switch to the prepared version `v` of `name`.
    pub fn activate(&self, name: &str, v: &Ver, m: &Manifest) -> Result<(), String> {
        match v.kind {
            Kind::Deb => {
                let deb = self.deb_path(m, v)?;
                let mut a = vec![self.cfg.install.dpkg.to_string_lossy().into_owned()];
                if let Some(r) = &self.cfg.install.dpkg_root {
                    a.push(format!("--root={}", r.display()));
                }
                a.extend([
                    "--force-confdef".into(),
                    "--force-confold".into(),
                    "--install".into(),
                    deb.to_string_lossy().into_owned(),
                ]);
                let r = self.tool(&a, u64::from(self.cfg.install.dpkg_timeout_s));
                if r.success() {
                    Ok(())
                } else {
                    Err(format!("dpkg --install: {}", r.summary()))
                }
            }
            kind => {
                let vdir = self.version_dir(kind, name, v.serial);
                if !fsx::is_real_dir(&vdir) {
                    return Err(format!("{}: version not prepared", vdir.display()));
                }
                let link = self.link(kind, name);
                if let Some(parent) = link.parent() {
                    if kind == Kind::RobodrRules {
                        fsx::ensure_dir(parent, 0o755)
                            .map_err(|e| format!("{}: {e}", parent.display()))?;
                    }
                }
                let target = match kind {
                    // Absolute: the link lives outside the versions tree.
                    Kind::RobodrRules => vdir,
                    _ => PathBuf::from(v.serial.to_string()),
                };
                fsx::swap_symlink(&link, &target)
                    .map_err(|e| format!("{}: {e}", link.display()))?;
                if kind == Kind::RobodrRules {
                    self.reload_rules()?;
                }
                Ok(())
            }
        }
    }

    /// Run `rules_reload` (if configured).
    pub fn reload_rules(&self) -> Result<(), String> {
        if let Some(a) = &self.cfg.install.rules_reload {
            let r = self.tool(a, 120);
            if !r.success() {
                return Err(format!("rules reload: {}", r.summary()));
            }
        }
        Ok(())
    }

    fn deb_path(&self, m: &Manifest, v: &Ver) -> Result<PathBuf, String> {
        let f = m
            .payload_files()
            .next()
            .ok_or_else(|| "deb RPK without payload".to_string())?;
        let name = f.path.rsplit('/').next().unwrap_or("package.deb");
        let p = self.deb_dir(&v.digest).join(name);
        if !p.is_file() {
            return Err(format!("{}: not prepared", p.display()));
        }
        Ok(p)
    }

    /// The active serial of a non-`deb` package (from its link).
    pub fn active_serial(&self, kind: Kind, name: &str) -> Result<Option<u64>, String> {
        let link = self.link(kind, name);
        let Some(t) = fsx::read_link(&link).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let s = t
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or_else(|| format!("{}: unexpected link target", link.display()))?;
        if kind == Kind::RobodrRules && t != self.version_dir(kind, name, s) {
            return Err(format!(
                "{}: link points outside the rules versions",
                link.display()
            ));
        }
        Ok(Some(s))
    }

    /// Which of `known` is active for `name` (recovery). `Ok(None)`: none
    /// of them (absent, or a state none of them explains).
    pub fn active_of(&self, name: &str, kind: Kind, known: &[&Ver]) -> Result<Option<u64>, String> {
        if kind != Kind::Deb {
            return self.active_serial(kind, name);
        }
        let Some(pkg) = known
            .iter()
            .find_map(|v| v.deb.as_ref().map(|d| d.package.clone()))
        else {
            return Ok(None);
        };
        let r = self.tool(&self.dpkg_query_argv(&pkg), 60);
        if !r.success() {
            return Ok(None);
        }
        let out = r.output.trim();
        let Some((status, version)) = out.split_once('\t') else {
            return Ok(None);
        };
        if status != "installed" {
            return Ok(None);
        }
        Ok(known
            .iter()
            .find(|v| v.deb.as_ref().is_some_and(|d| d.version == version))
            .map(|v| v.serial))
    }

    /// Remove a prepared version that is neither active nor kept.
    pub fn remove(&self, name: &str, v: &Ver) -> Result<(), String> {
        let p = match v.kind {
            Kind::Deb => self.deb_dir(&v.digest),
            k => {
                if self.active_serial(k, name).ok().flatten() == Some(v.serial) {
                    return Ok(());
                }
                self.version_dir(k, name, v.serial)
            }
        };
        fsx::remove_any(&p).map_err(|e| format!("{}: {e}", p.display()))
    }
}
