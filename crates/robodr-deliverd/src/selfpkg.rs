//! RoboDR's own package (`robodr` / `robodr-focal`) delivered as a `deb`
//! RPK (the designated programme, `install.robodr_programme`): the rules
//! `packaging/install-bundle.sh` applies to every RoboDR install, so the
//! agent's self-upgrade cannot get around them (review H6, M8, M9):
//!
//! * no variant switch: `robodr` and `robodr-focal` conflict, and the
//!   removal of the installed one runs its `prerm` (in releases before the
//!   fix: every RoboDR unit stopped behind the safety-state gate's back,
//!   the agent's own unit included, and the executor's nft table deleted).
//!   A switch is an operator action (`install-bundle.sh install
//!   --allow-variant-switch`);
//! * no dpkg downgrade below what dpkg has installed, and nothing in a
//!   state other than `installed` (an unconfigured package is
//!   `install-bundle.sh restart-pending`'s to finish);
//! * the first delivery of the package (the agent has no earlier version
//!   of its own, so nothing to roll back to) must be the version dpkg has
//!   installed: the agent then holds it as an RPK in its store, and every
//!   later delivery has a rollback target (review M8);
//! * the unit's security floor: `/var/lib/robodr/releases/security-floor`
//!   (install-bundle.sh's record) and the SOC ring information's minimum
//!   (`/var/lib/robodr/fleet/ring.env`, robodr-enroll). Neither has an
//!   override (review M9);
//! * the black-box format gate: a segment whose first frame is in a format
//!   a release installed on this unit writes (verified, as install-bundle
//!   judges it) and the new package does not read refuses the package.
//!   Unverified or unknown frames do not block (a compromised agentd
//!   cannot block updates). There is no `--accept-unreadable` here: that
//!   decision is the operator's, with install-bundle.sh.
//!
//! The paths are below the dpkg root (`install.dpkg_root`, `/` on a unit).

use std::path::{Path, PathBuf};

/// The black-box format every release reads and writes (a release without
/// a formats file is a legacy release).
pub const LEGACY_FORMAT: &str = "RBF1:1";
/// The formats file in a package.
pub const FORMATS_MEMBER: &str = "usr/share/robodr/formats";
/// Most segment files and directories the format gate looks at.
const MAX_WALK: usize = 200_000;
/// Deepest directory level the format gate descends to.
const MAX_DEPTH: usize = 16;

/// The black-box directories the format gate reads (install-bundle.sh's
/// default `--blackbox-dir`s).
pub fn blackbox_dirs(root: &Path) -> [PathBuf; 2] {
    [
        root.join("var/lib/robodr/blackbox"),
        root.join("var/lib/robodr/fleet/journal"),
    ]
}

/// The values of `key=` in a formats file (comma separated), in order.
pub fn formats_values(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

/// What a package reads (`blackbox_read=`, the legacy format without it).
pub fn reads_of(formats: Option<&str>) -> Vec<String> {
    let r = formats
        .map(|t| formats_values(t, "blackbox_read"))
        .unwrap_or_default();
    if r.is_empty() {
        vec![LEGACY_FORMAT.to_string()]
    } else {
        r
    }
}

fn read_small(p: &Path) -> Option<String> {
    let md = std::fs::symlink_metadata(p).ok()?;
    if !md.file_type().is_file() || md.len() > 64 * 1024 {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

/// The formats releases installed on this unit write: the legacy format,
/// the installed package's formats file and every kept release's
/// (install-bundle.sh's `written_formats`; root-owned records agentd
/// cannot write).
pub fn written_formats(root: &Path) -> Vec<String> {
    let mut files = vec![root.join(FORMATS_MEMBER)];
    let rel = root.join("var/lib/robodr/releases");
    if let Ok(rd) = std::fs::read_dir(&rel) {
        for e in rd.flatten() {
            files.push(e.path().join("formats"));
        }
    }
    if let Ok(rd) = std::fs::read_dir(rel.join("formats-archive")) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().ends_with(".formats") {
                files.push(e.path());
            }
        }
    }
    let mut out = vec![LEGACY_FORMAT.to_string()];
    for f in files {
        if let Some(t) = read_small(&f) {
            out.extend(formats_values(&t, "blackbox_write"));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The format of a segment file's first frame: `RBF1:<record format
/// version>`, `None` for anything else (not a RoboDR frame, too short).
pub fn segment_format(p: &Path) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(p).ok()?;
    let mut h = [0u8; 9];
    f.read_exact(&mut h).ok()?;
    let (magic, rest) = h.split_at(4);
    if magic != b"RBF1" {
        return None;
    }
    rest.get(4).map(|v| format!("RBF1:{v}"))
}

/// Every segment file (`seg-*.rbb`, more than 8 bytes, no symlink
/// followed) below `dirs`.
pub fn segments(dirs: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut stack: Vec<(PathBuf, usize)> = dirs
        .iter()
        .filter(|d| std::fs::symlink_metadata(d).is_ok_and(|m| m.is_dir()))
        .map(|d| (d.clone(), 0))
        .collect();
    while let Some((d, depth)) = stack.pop() {
        let rd = std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        for e in rd.flatten() {
            seen += 1;
            if seen > MAX_WALK {
                return Err(format!(
                    "more than {MAX_WALK} entries in the black-box directories"
                ));
            }
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((p, depth + 1));
                }
            } else if ft.is_file() {
                let n = e.file_name();
                let n = n.to_string_lossy();
                if n.starts_with("seg-")
                    && n.ends_with(".rbb")
                    && e.metadata().is_ok_and(|m| m.len() > 8)
                {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The format gate: the first segment (and how many) that is in a format
/// this unit's releases write (verified) and `reads` does not include.
pub fn unreadable(
    reads: &[String],
    written: &[String],
    segs: &[PathBuf],
) -> Option<(String, PathBuf, usize)> {
    let bad: Vec<(String, &PathBuf)> = segs
        .iter()
        .filter_map(|s| segment_format(s).map(|f| (f, s)))
        .filter(|(f, _)| !reads.contains(f) && written.contains(f))
        .collect();
    let n = bad.len();
    bad.into_iter().next().map(|(f, s)| (f, s.clone(), n))
}

/// An upstream version (ring information) as a Debian version: a
/// pre-release `-` sorts before the release with `~` (install-bundle.sh
/// `deb_of`).
pub fn deb_of(v: &str) -> String {
    v.replacen('-', "~", 1)
}

/// The security floors on record: `(where, minimum dpkg version)`.
pub fn floors(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let value = |t: &str| {
        t.lines()
            .find_map(|l| l.strip_prefix("min_version="))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let floor = root.join("var/lib/robodr/releases/security-floor");
    if let Some(v) = read_small(&floor).as_deref().and_then(value) {
        out.push((
            "the unit's security floor (install-bundle.sh)".to_string(),
            v,
        ));
    }
    let ring = root.join("var/lib/robodr/fleet/ring.env");
    if let Some(v) = read_small(&ring).as_deref().and_then(value) {
        out.push((
            "the SOC ring information's minimum (robodr-enroll)".to_string(),
            deb_of(&v),
        ));
    }
    out
}

/// dpkg states in which a package is not installed.
pub fn absent(status: &str) -> bool {
    matches!(status, "not-installed" | "config-files")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-selfpkg-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn formats_and_reads() {
        let t = "blackbox_write=RBF1:2\nblackbox_read=RBF1:1,RBF1:2\n";
        assert_eq!(formats_values(t, "blackbox_write"), ["RBF1:2"]);
        assert_eq!(reads_of(Some(t)), ["RBF1:1", "RBF1:2"]);
        assert_eq!(reads_of(None), [LEGACY_FORMAT]);
        assert_eq!(reads_of(Some("x=y\n")), [LEGACY_FORMAT]);
        assert_eq!(deb_of("0.3.0-rc.1"), "0.3.0~rc.1");
    }

    #[test]
    fn the_gate_blocks_only_verified_formats() {
        let d = tmp("gate");
        let bb = d.join("var/lib/robodr/blackbox/agentd");
        std::fs::create_dir_all(&bb).unwrap();
        let mut frame = b"RBF1\0\0\0\0".to_vec();
        frame.push(2);
        frame.extend_from_slice(b"rest");
        std::fs::write(bb.join("seg-000001.rbb"), &frame).unwrap();
        std::fs::write(bb.join("seg-000002.rbb"), b"XXXXXXXXXXXX").unwrap();
        std::fs::write(bb.join("other.rbb"), &frame).unwrap();
        let segs = segments(&blackbox_dirs(&d)).unwrap();
        assert_eq!(segs.len(), 2, "{segs:?}");
        let reads = vec![LEGACY_FORMAT.to_string()];
        // RBF1:2 written by no release here: unverified, does not block.
        assert_eq!(unreadable(&reads, &written_formats(&d), &segs), None);
        // Once the installed package writes it, it blocks.
        std::fs::create_dir_all(d.join("usr/share/robodr")).unwrap();
        std::fs::write(
            d.join(FORMATS_MEMBER),
            "blackbox_write=RBF1:2\nblackbox_read=RBF1:1,RBF1:2\n",
        )
        .unwrap();
        let w = written_formats(&d);
        let (f, s, n) = unreadable(&reads, &w, &segs).unwrap();
        assert_eq!((f.as_str(), n), ("RBF1:2", 1));
        assert!(s.ends_with("seg-000001.rbb"));
        assert_eq!(
            unreadable(&reads_of(Some("blackbox_read=RBF1:2\n")), &w, &segs),
            None
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn floors_come_from_the_floor_file_and_the_ring() {
        let d = tmp("floors");
        assert!(floors(&d).is_empty());
        std::fs::create_dir_all(d.join("var/lib/robodr/releases")).unwrap();
        std::fs::create_dir_all(d.join("var/lib/robodr/fleet")).unwrap();
        std::fs::write(
            d.join("var/lib/robodr/releases/security-floor"),
            "min_version=0.2.0-1\nsource=x\n",
        )
        .unwrap();
        std::fs::write(
            d.join("var/lib/robodr/fleet/ring.env"),
            "ring=1\nmin_version=0.3.0-rc.1\n",
        )
        .unwrap();
        let f = floors(&d);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].1, "0.2.0-1");
        assert_eq!(f[1].1, "0.3.0~rc.1");
        let _ = std::fs::remove_dir_all(&d);
    }
}
