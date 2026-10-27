//! Installers per kind (`docs/SECURE-DELIVERY.md` §4.2). Each prepares a
//! version next to the running one (no effect on the robot), switches to
//! it atomically, and can tell which version is active (crash recovery).
//!
//! | kind | prepared at | switch | active version |
//! |---|---|---|---|
//! | `files` | `<files_root>/<name>/<serial>-<digest>/` | `<files_root>/<name>/current` symlink swap | the link target |
//! | `config` | `<config_root>/<name>/<serial>-<digest>/` | `current` symlink swap | the link target |
//! | `robodr-rules` | `<state_dir>/rules/<name>/<serial>-<digest>/` (checked, [`crate::rules`]) | `<rules_active>/<name>` symlink swap, then `rules_reload` | the link target |
//! | `deb` | `<state_dir>/debs/<digest>/<file>.deb` (inspected with `dpkg-deb`) | `dpkg -i` | `dpkg-query` status and version |
//!
//! Version directories are named by serial **and RPK digest** (review M4):
//! two RPKs with the same serial but other content (a release re-signed
//! into another manifest) can never share, overwrite or be mistaken for
//! each other's directory, so a kept rollback target always activates
//! exactly the content the state records. (The engine also refuses such an
//! RPK outright while either is installed, kept or in a switch.) A link
//! written by an earlier version (`current -> <serial>`) is still read.
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
//! set `install.allow_maintainer_scripts`.
//!
//! # The dpkg identity of a `deb` RPK (review H2)
//!
//! `dpkg --install` acts on the `.deb`'s own `Package`, not on the RPK
//! name that floors and "one item per package" are keyed on. The RPK
//! therefore **declares** the dpkg identity in its release-signed manifest:
//! for kind `deb`, the RPK `name` is the dpkg `Package` and the RPK `arch`
//! is the dpkg `Architecture` (an RPK for `amd64` or `arm64` may also carry
//! an `Architecture: all` package; an RPK for `all` only that). A `.deb`
//! whose control fields say anything else is refused ([`DebInfo`] records
//! the package, version and relations), so a floor on an RPK name is a
//! floor on that dpkg package and an RPK under another name cannot carry
//! an older `.deb` **of that package**. The engine also refuses a
//! `Package` the state already records under another RPK name, a higher
//! serial carrying a lower dpkg `Version`, and a `.deb` that is, conflicts
//! with, breaks, replaces or provides one of RoboDR's own packages
//! ([`ROBODR_PACKAGES`]) unless the RPK came in a bundle of the designated
//! RoboDR programme (`install.robodr_programme`).
//!
//! # The files of a `deb` RPK (review H-R3-1, L-R3-2)
//!
//! A `.deb` under another name could still carry older *files* of a
//! floored package: dpkg detects conflicts by path name, and on a
//! merged-/usr system `lib/nav/ok` lands on `/usr/lib/nav/ok` through the
//! `/lib -> usr/lib` symlink without a conflict. So, right before every
//! `dpkg --install` ([`Installer::check_deb_paths`], [`crate::debfs`]):
//! every path of the `.deb` is resolved through the target root's
//! symlinks and refused if another package owns it, or it lies below the
//! agent's own trees, RoboDR's install paths, `/etc/dpkg`, `/etc/apt` or
//! `/var/lib/dpkg`. dpkg runs with every force option reset on its command
//! line ([`DPKG_INSTALL_FLAGS`]: `--refuse-all`, then only what the agent
//! needs, then `--refuse-overwrite` explicitly), which overrides any
//! `force-*` in `dpkg.cfg.d`. After the install the engine checks every
//! other recorded package with `dpkg --verify` (its **output**, not its
//! exit status: [`Installer::deb_verify`]) and against the file list
//! recorded at its install ([`Installer::deb_files_digest`]).
//!
//! What this does not cover (release signers are root-equivalent for
//! `deb`, `docs/SECURE-DELIVERY.md` §6.7): maintainer scripts (when the
//! release allowed them) and files a `.deb` adds that change the system's
//! behaviour elsewhere (units, cron, setuid files).

use crate::config::Config;
use crate::debfs;
use crate::fsx;
use crate::runner::{self, Limits};
use crate::state::{DebInfo, Ver};
use crate::store::Store;
use robodr_pkg::common::is_safe_rel_path;
use robodr_pkg::rpk::{Kind, Manifest};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
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

/// RoboDR's own Debian packages (`packaging/build-deb.sh`). A `deb` RPK
/// that is one of them, or whose `Conflicts`, `Breaks`, `Replaces` or
/// `Provides` names one, would remove, replace or impersonate the
/// software that guards the unit (agentd, the black box, this agent):
/// refused unless the RPK came in a bundle of the designated RoboDR
/// programme (`install.robodr_programme`; review H2).
pub const ROBODR_PACKAGES: [&str; 2] = ["robodr", "robodr-focal"];

/// The `.deb` control fields whose package names are recorded as
/// relations ([`DebInfo::relations`]).
pub const RELATION_FIELDS: [&str; 4] = ["Conflicts", "Breaks", "Replaces", "Provides"];

/// Package names of a dpkg relation field value (`a (>= 1), b | c:any`).
/// `None`: not a relation field dpkg would write.
pub fn relation_names(v: &str) -> Option<Vec<String>> {
    let ok = v.len() <= 8192
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" \t\n,|()<>=.+-~:_[]!".contains(&b));
    if !ok {
        return None;
    }
    let mut out = Vec::new();
    for alt in v.split([',', '|']) {
        let name: String = alt
            .trim()
            .chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, '(' | ':' | '['))
            .collect();
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    Some(out)
}

/// The options of every `dpkg --install` (review H-R3-1, L-R3-2), after
/// `--root`. Options on the command line override `dpkg.cfg.d`, read
/// first: `--refuse-all` resets every force option a configuration file
/// (or a `.deb` that shipped one) may have set, then only what the agent
/// needs is forced again (`security-mac` and `downgrade` are dpkg's
/// defaults; a rollback installs an older version; conffiles keep local
/// changes), and `--refuse-overwrite` is repeated explicitly.
pub const DPKG_INSTALL_FLAGS: [&str; 8] = [
    "--refuse-all",
    "--force-security-mac",
    "--force-downgrade",
    "--force-confdef",
    "--force-confold",
    "--refuse-overwrite",
    "--refuse-overwrite-dir",
    "--refuse-overwrite-diverted",
];

/// Maintainer-script members of a `.deb`'s control area.
pub const MAINTAINER_SCRIPTS: [&str; 6] = [
    "preinst", "postinst", "prerm", "postrm", "config", "triggers",
];

/// The directory name of a version: `<serial>-<digest>` (review M4).
pub fn version_name(serial: u64, digest: &str) -> String {
    format!("{serial}-{digest}")
}

/// Parse a version directory name: `<serial>-<64 hex>`, or a bare
/// `<serial>` written before review M4 (no digest).
pub fn parse_version_name(n: &str) -> Option<(u64, Option<String>)> {
    let canonical = |s: &str| s.parse::<u64>().ok().filter(|v| v.to_string() == s);
    match n.split_once('-') {
        Some((s, d)) if robodr_pkg::common::is_hex64(d) => Some((canonical(s)?, Some(d.into()))),
        Some(_) => None,
        None => Some((canonical(n)?, None)),
    }
}

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

    /// The prepared version directory of `name` at `serial` with RPK
    /// `digest` (not `deb`): `<root>/<name>/<serial>-<digest>`.
    pub fn version_dir(&self, kind: Kind, name: &str, serial: u64, digest: &str) -> PathBuf {
        self.versions_root(kind)
            .join(name)
            .join(version_name(serial, digest))
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
        let vdir = pdir.join(version_name(m.version.serial, &v.digest));
        if self.is_active(m.kind, &m.name, v) {
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
        // Rule names are unique across every installed rules package, not
        // only within one: Pulsar would refuse the reload, or let one rule
        // shadow another's detection.
        let others = self.active_rule_names(&m.name)?;
        if let Some((n, pkg)) = names.iter().find_map(|n| others.get(n).map(|p| (n, p))) {
            return Err(PrepError::Refused(format!(
                "rule name {:?} is already used by the installed rules package {pkg}",
                robodr_pkg::common::trunc(n)
            )));
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

    /// Rule names of the active versions of every other rules package
    /// (below `rules_active`), name -> package. Files that do not parse
    /// are skipped (they passed this check when they were installed).
    fn active_rule_names(
        &self,
        except: &str,
    ) -> Result<std::collections::BTreeMap<String, String>, PrepError> {
        fn files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
            let Ok(rd) = fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                if out.len() >= robodr_pkg::rpk::MAX_CONTENT_FILES {
                    return;
                }
                let Ok(t) = e.file_type() else { continue };
                if t.is_dir() && depth < 16 {
                    files(&e.path(), depth + 1, out);
                } else if t.is_file() {
                    out.push(e.path());
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        let dir = &self.cfg.install.rules_active;
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(io(dir, e)),
        };
        for e in rd.flatten() {
            let Some(pkg) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if pkg == except || !robodr_pkg::common::is_pkg_name(&pkg) {
                continue;
            }
            let vdir = match self.active_version(Kind::RobodrRules, &pkg) {
                Ok(Some((serial, Some(d)))) => {
                    self.version_dir(Kind::RobodrRules, &pkg, serial, &d)
                }
                Ok(Some((serial, None))) => self
                    .versions_root(Kind::RobodrRules)
                    .join(&pkg)
                    .join(serial.to_string()),
                _ => continue,
            };
            let mut list = Vec::new();
            files(&vdir, 0, &mut list);
            for f in list {
                let Ok(b) =
                    robodr_release::fsio::read_capped(&f, crate::rules::MAX_RULE_FILE_BYTES)
                else {
                    continue;
                };
                let mut names = BTreeSet::new();
                if crate::rules::check_file("installed", &b, &mut names).is_ok() {
                    for n in names {
                        out.entry(n).or_insert_with(|| pkg.clone());
                    }
                }
            }
        }
        Ok(out)
    }

    /// The root dpkg installs into (`install.dpkg_root`, or `/`).
    pub fn dpkg_root(&self) -> PathBuf {
        self.cfg
            .install
            .dpkg_root
            .clone()
            .unwrap_or_else(|| PathBuf::from("/"))
    }

    /// dpkg's database directory, always passed explicitly (never taken
    /// from a configuration file).
    pub fn admindir(&self) -> PathBuf {
        self.dpkg_root().join("var/lib/dpkg")
    }

    fn dpkg_query_argv(&self, package: &str) -> Vec<String> {
        let mut a = vec![self.cfg.install.dpkg_query.to_string_lossy().into_owned()];
        a.push(format!("--admindir={}", self.admindir().display()));
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
        // The RPK declares the dpkg identity (review H2): its name is the
        // Package, its arch the Architecture (or the .deb is `all`).
        if package != m.name {
            return Err(PrepError::Refused(format!(
                "the .deb is dpkg package {package}, but a deb RPK's name is its dpkg Package \
                 ({})",
                m.name
            )));
        }
        if arch != "all" && arch != m.arch.as_str() {
            return Err(PrepError::Refused(format!(
                "the .deb is for {arch}, the RPK declares {}",
                m.arch.as_str()
            )));
        }
        if arch != "all" && arch != self.cfg.unit.arch.as_str() {
            return Err(PrepError::Refused(format!(
                "the .deb is for {arch}, this unit is {}",
                self.cfg.unit.arch.as_str()
            )));
        }
        let mut relations: Vec<String> = Vec::new();
        for field in RELATION_FIELDS {
            for n in self.deb_relation(&deb, field)? {
                if !relations.contains(&n) {
                    relations.push(n);
                }
            }
        }
        if relations.len() > 256 {
            return Err(PrepError::Refused(
                "the .deb declares more than 256 relations".into(),
            ));
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
        v.deb = Some(DebInfo {
            package,
            version,
            relations,
            files: None,
            verify: None,
        });
        Ok(())
    }

    /// The package names of relation field `field` of `deb` (empty when
    /// the field is absent).
    fn deb_relation(&self, deb: &Path, field: &str) -> Result<Vec<String>, PrepError> {
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
        relation_names(r.output.trim())
            .ok_or_else(|| PrepError::Refused(format!("dpkg-deb: bad {field} field")))
    }

    /// dpkg's status (`installed`, `not-installed`, `half-configured`, ...)
    /// and version of `package` (`dpkg-query`). `None`: dpkg does not know
    /// the package, or the query failed.
    pub fn deb_state(&self, package: &str) -> Option<(String, String)> {
        let r = self.tool(&self.dpkg_query_argv(package), 60);
        if !r.success() {
            return None;
        }
        let (status, version) = r.output.trim().split_once('\t')?;
        Some((status.to_string(), version.to_string()))
    }

    /// Review H-R3-1 (a): where every path of the prepared `.deb` of `v`
    /// would land, refused when another package owns it or it is
    /// protected ([`crate::debfs`]). `robodr_own`: the `.deb` is one of
    /// RoboDR's own packages from the designated programme. Run right
    /// before the switch (the owners can change between passes).
    pub fn check_deb_paths(
        &self,
        m: &Manifest,
        v: &Ver,
        robodr_own: bool,
    ) -> Result<(), PrepError> {
        let Some(d) = &v.deb else {
            return Ok(());
        };
        // A .deb that is not prepared is not installed either: the switch
        // fails on it (`activate`), as it did before this check.
        let Ok(deb) = self.deb_path(m, v) else {
            return Ok(());
        };
        let argv = [
            self.cfg.install.dpkg_deb.to_string_lossy().into_owned(),
            "--fsys-tarfile".into(),
            deb.to_string_lossy().into_owned(),
        ];
        let entries = runner::run_reader(
            &argv,
            Duration::from_secs(u64::from(self.cfg.install.dpkg_timeout_s)),
            |r| {
                let e = debfs::parse_tar(r)?;
                // The rest is padding; read it so dpkg-deb exits cleanly.
                std::io::copy(&mut r.take(1024 * 1024), &mut std::io::sink())
                    .map_err(|e| e.to_string())?;
                Ok(e)
            },
        )
        .map_err(|e| PrepError::Refused(format!("listing the .deb's files: {e}")))?;
        // Nothing below one of its own symlinks.
        let links: BTreeSet<&str> = entries
            .iter()
            .filter(|e| e.kind == debfs::EntryKind::Symlink)
            .map(|e| e.path.as_str())
            .collect();
        for e in &entries {
            let mut p = e.path.as_str();
            while let Some((parent, _)) = p.rsplit_once('/') {
                if links.contains(parent) {
                    return Err(PrepError::Refused(format!(
                        "the .deb ships {} below its own symlink {parent}",
                        robodr_pkg::common::trunc(&e.path)
                    )));
                }
                p = parent;
            }
        }
        let root = self.dpkg_root();
        let host_root = fs::canonicalize(&root).map_err(|e| io(&root, e))?;
        let mut roots: Vec<(&str, PathBuf)> = Vec::new();
        for (what, p) in [
            ("state_dir", &self.cfg.state_dir),
            ("media_dir", &self.cfg.media_dir),
            ("install.files_root", &self.cfg.install.files_root),
            ("install.config_root", &self.cfg.install.config_root),
            ("install.rules_active", &self.cfg.install.rules_active),
            ("blackbox.dir", &self.cfg.blackbox.dir),
            ("findings.spool", &self.cfg.findings.spool),
        ] {
            roots.push((what, p.clone()));
            if let Ok(c) = fs::canonicalize(p) {
                if c != *p {
                    roots.push((what, c));
                }
            }
        }
        let mut res = debfs::Resolver::new(&root);
        let mut wanted: std::collections::BTreeMap<String, String> = Default::default();
        for e in entries.iter().filter(|e| e.kind != debfs::EntryKind::Dir) {
            let c = res
                .canonical(&e.path)
                .map_err(|x| PrepError::Refused(format!("{}: {x}", e.path)))?;
            if let Some(why) = debfs::protected(&c, &host_root.join(&c), &roots, robodr_own) {
                return Err(PrepError::Refused(format!(
                    "the .deb's {} lands on /{}: {why}",
                    robodr_pkg::common::trunc(&e.path),
                    robodr_pkg::common::trunc(&c)
                )));
            }
            wanted.entry(c).or_insert_with(|| e.path.clone());
        }
        let keys: BTreeSet<String> = wanted.keys().cloned().collect();
        let mut ignore: BTreeSet<String> = BTreeSet::from([d.package.clone()]);
        if robodr_own {
            ignore.extend(
                d.relations
                    .iter()
                    .filter(|r| ROBODR_PACKAGES.contains(&r.as_str()))
                    .cloned(),
            );
        }
        let owned =
            debfs::owners(&self.admindir(), &mut res, &keys, &ignore).map_err(PrepError::Io)?;
        if !owned.is_empty() {
            let what: Vec<String> = owned
                .iter()
                .take(8)
                .map(|(c, pkgs)| {
                    format!(
                        "{} lands on /{c}, a file of package {}",
                        wanted.get(c).map_or(c.as_str(), String::as_str),
                        pkgs.iter().cloned().collect::<Vec<_>>().join(", ")
                    )
                })
                .collect();
            return Err(PrepError::Refused(format!(
                "the .deb writes files of other packages ({} path(s)): {}",
                owned.len(),
                what.join("; ")
            )));
        }
        Ok(())
    }

    /// Review H-R3-1 (c): what `dpkg --verify` reports for `package`,
    /// conffiles excepted (an operator may edit those). dpkg 1.22 exits 0
    /// even when it reports changed files, so the **output** decides:
    /// every other line (a changed or missing file, a warning) is
    /// returned. `Err`: dpkg could not verify it.
    pub fn deb_verify(&self, package: &str) -> Result<Vec<String>, String> {
        let r = runner::run(
            &[
                self.cfg.install.dpkg.to_string_lossy().into_owned(),
                format!("--root={}", self.dpkg_root().display()),
                "--verify".into(),
                package.into(),
            ],
            None,
            Limits {
                timeout: Duration::from_secs(u64::from(self.cfg.install.dpkg_timeout_s)),
                max_output: 64 * 1024,
            },
        );
        if !r.success() {
            return Err(format!("dpkg --verify {package}: {}", r.summary()));
        }
        let mut out: Vec<String> = r
            .output
            .lines()
            .filter(|l| !l.trim().is_empty())
            // `<9 check characters> <attribute> <path>`; attribute `c`:
            // a conffile.
            .filter(|l| !(l.len() > 11 && l.as_bytes()[10] == b'c' && l.as_bytes()[9] == b' '))
            .map(robodr_pkg::common::trunc)
            .collect();
        if r.truncated {
            out.push("(more output)".into());
        }
        Ok(out)
    }

    /// Review H-R3-1 (c): SHA-256 (hex) of `dpkg-query -L package` (its
    /// files, conffiles and diversions as dpkg lists them).
    pub fn deb_files_digest(&self, package: &str) -> Result<String, String> {
        let r = runner::run(
            &[
                self.cfg.install.dpkg_query.to_string_lossy().into_owned(),
                format!("--admindir={}", self.admindir().display()),
                "-L".into(),
                "--".into(),
                package.into(),
            ],
            None,
            Limits {
                timeout: Duration::from_secs(120),
                max_output: 64 * 1024 * 1024,
            },
        );
        if !r.success() || r.truncated {
            return Err(format!("dpkg-query -L {package}: {}", r.summary()));
        }
        let mut lines: Vec<&str> = r.output.lines().collect();
        lines.sort_unstable();
        let mut h = robodr_blackbox::crypto::Sha256::new();
        for l in lines {
            h.update(l.as_bytes());
            h.update(b"\n");
        }
        Ok(robodr_blackbox::crypto::to_hex(&h.finalize()))
    }

    /// `a` is an earlier dpkg version than `b` (`dpkg --compare-versions`).
    pub fn deb_version_lt(&self, a: &str, b: &str) -> Result<bool, String> {
        let r = self.tool(
            &[
                self.cfg.install.dpkg.to_string_lossy().into_owned(),
                "--compare-versions".into(),
                a.into(),
                "lt".into(),
                b.into(),
            ],
            60,
        );
        match r.code {
            Some(0) if r.success() => Ok(true),
            Some(1) if r.spawn_error.is_none() && !r.timed_out => Ok(false),
            _ => Err(format!("dpkg --compare-versions: {}", r.summary())),
        }
    }

    /// Switch to the prepared version `v` of `name`.
    pub fn activate(&self, name: &str, v: &Ver, m: &Manifest) -> Result<(), String> {
        match v.kind {
            Kind::Deb => {
                let deb = self.deb_path(m, v)?;
                let mut a = vec![
                    self.cfg.install.dpkg.to_string_lossy().into_owned(),
                    format!("--root={}", self.dpkg_root().display()),
                ];
                a.extend(DPKG_INSTALL_FLAGS.iter().map(|f| f.to_string()));
                a.extend(["--install".into(), deb.to_string_lossy().into_owned()]);
                let r = self.tool(&a, u64::from(self.cfg.install.dpkg_timeout_s));
                if r.success() {
                    Ok(())
                } else {
                    Err(format!("dpkg --install: {}", r.summary()))
                }
            }
            kind => {
                let vdir = self.version_dir(kind, name, v.serial, &v.digest);
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
                    _ => PathBuf::from(version_name(v.serial, &v.digest)),
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

    /// The active version of a non-`deb` package (from its link): the
    /// serial and, unless the link predates review M4, the RPK digest.
    pub fn active_version(
        &self,
        kind: Kind,
        name: &str,
    ) -> Result<Option<(u64, Option<String>)>, String> {
        let link = self.link(kind, name);
        let Some(t) = fsx::read_link(&link).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let file = t.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let (s, d) = parse_version_name(file)
            .ok_or_else(|| format!("{}: unexpected link target", link.display()))?;
        if kind == Kind::RobodrRules
            && t.parent() != Some(self.versions_root(kind).join(name).as_path())
        {
            return Err(format!(
                "{}: link points outside the rules versions",
                link.display()
            ));
        }
        Ok(Some((s, d)))
    }

    /// The active serial of a non-`deb` package (from its link).
    pub fn active_serial(&self, kind: Kind, name: &str) -> Result<Option<u64>, String> {
        Ok(self.active_version(kind, name)?.map(|(s, _)| s))
    }

    /// `v` is exactly the active version of `name` (serial and digest).
    fn is_active(&self, kind: Kind, name: &str, v: &Ver) -> bool {
        matches!(
            self.active_version(kind, name),
            Ok(Some((s, Some(d)))) if s == v.serial && d == v.digest
        )
    }

    /// Which of `known` is active for `name` (recovery). `Ok(None)`: none
    /// of them (absent, or a state none of them explains).
    pub fn active_of(&self, name: &str, kind: Kind, known: &[&Ver]) -> Result<Option<u64>, String> {
        if kind != Kind::Deb {
            return Ok(match self.active_version(kind, name)? {
                None => None,
                // A link naming a digest is the known version with that
                // digest, or none of them.
                Some((s, Some(d))) => known
                    .iter()
                    .find(|v| v.serial == s && v.digest == d)
                    .map(|v| v.serial),
                Some((s, None)) => Some(s),
            });
        }
        let Some(pkg) = known
            .iter()
            .find_map(|v| v.deb.as_ref().map(|d| d.package.clone()))
        else {
            return Ok(None);
        };
        let Some((status, version)) = self.deb_state(&pkg) else {
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
                if self.is_active(k, name, v) {
                    return Ok(());
                }
                self.version_dir(k, name, v.serial, &v.digest)
            }
        };
        fsx::remove_any(&p).map_err(|e| format!("{}: {e}", p.display()))
    }
}
