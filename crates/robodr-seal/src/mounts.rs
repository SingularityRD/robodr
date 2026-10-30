//! Which file system a path is on, from `/proc/self/mountinfo` (no libc
//! crate: `statfs` is not reachable from std). Used to keep TPM session
//! files on tmpfs (never on a disk) and the fallback UWK and installed
//! plaintext on a dm-crypt volume.

use crate::{invalid, io_err, SealError};
use std::path::{Path, PathBuf};

/// One line of mountinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// `major:minor` of the mounted device.
    pub dev: String,
    pub point: PathBuf,
    pub fstype: String,
}

fn unescape(s: &str) -> String {
    // mountinfo escapes space, tab, newline and backslash as \ooo.
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0')
                .wrapping_mul(64)
                .wrapping_add((b[i + 2] - b'0') * 8)
                .wrapping_add(b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse mountinfo text (`id parent major:minor root point opts ... - fstype
/// source superopts`). Malformed lines are skipped.
pub fn parse(mountinfo: &str) -> Vec<Mount> {
    mountinfo
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let sep = f.iter().position(|x| *x == "-")?;
            if f.len() < 5 || sep < 6 {
                return None;
            }
            Some(Mount {
                dev: f[2].to_string(),
                point: PathBuf::from(unescape(f[4])),
                fstype: f.get(sep + 1)?.to_string(),
            })
        })
        .collect()
}

/// The mount exactly at `point` (the last one: mounts stack).
pub fn at<'a>(mounts: &'a [Mount], point: &Path) -> Option<&'a Mount> {
    mounts.iter().rev().find(|m| m.point == point)
}

/// The mount that holds `path` (longest mount point that is a prefix of
/// it; the last of equals). `path` must be canonical.
pub fn holding<'a>(mounts: &'a [Mount], path: &Path) -> Option<&'a Mount> {
    let mut best: Option<&Mount> = None;
    for m in mounts {
        if path.starts_with(&m.point)
            && best.is_none_or(|b| m.point.as_os_str().len() >= b.point.as_os_str().len())
        {
            best = Some(m);
        }
    }
    best
}

fn system() -> Result<Vec<Mount>, SealError> {
    let p = Path::new("/proc/self/mountinfo");
    Ok(parse(
        &std::fs::read_to_string(p).map_err(|e| io_err(p, e))?,
    ))
}

/// Whether block device `dev` (`major:minor`) is a dm-crypt mapping.
pub fn is_dm_crypt(dev: &str) -> bool {
    std::fs::read_to_string(format!("/sys/dev/block/{dev}/dm/uuid"))
        .is_ok_and(|u| u.starts_with("CRYPT-"))
}

/// `dir` (an existing directory) is on tmpfs or ramfs, never a disk.
pub fn check_tmpfs(dir: &Path) -> Result<(), SealError> {
    let c = dir.canonicalize().map_err(|e| io_err(dir, e))?;
    let ms = system()?;
    match holding(&ms, &c) {
        Some(m) if m.fstype == "tmpfs" || m.fstype == "ramfs" => Ok(()),
        Some(m) => Err(invalid(format!(
            "{} is on {} ({}), not tmpfs: TPM session files must never reach a disk",
            dir.display(),
            m.point.display(),
            m.fstype
        ))),
        None => Err(invalid(format!("{}: no mount found", dir.display()))),
    }
}

/// `dir` (an existing directory) is on a mounted dm-crypt mapping.
pub fn check_on_dm_crypt(dir: &Path) -> Result<(), SealError> {
    let c = dir.canonicalize().map_err(|e| io_err(dir, e))?;
    let ms = system()?;
    let m =
        holding(&ms, &c).ok_or_else(|| invalid(format!("{}: no mount found", dir.display())))?;
    if is_dm_crypt(&m.dev) {
        Ok(())
    } else {
        Err(invalid(format!(
            "{} is on {} (device {}), which is not a dm-crypt mapping: the runtime volume is \
             not open there",
            dir.display(),
            m.point.display(),
            m.dev
        )))
    }
}

/// `point` is itself a mount point whose device is a dm-crypt mapping.
pub fn check_mounted_dm_crypt(point: &Path) -> Result<(), String> {
    let ms = system().map_err(|e| e.to_string())?;
    let m = at(&ms, point).ok_or_else(|| {
        format!(
            "{} is not a mount point: the sealed runtime volume is not open",
            point.display()
        )
    })?;
    if std::fs::metadata(format!("/sys/dev/block/{}/dm/uuid", m.dev)).is_err() {
        return Err(format!(
            "{} is mounted from {}, which is not a device-mapper device",
            point.display(),
            m.dev
        ));
    }
    if is_dm_crypt(&m.dev) {
        Ok(())
    } else {
        Err(format!(
            "{} is mounted from a device-mapper device that is not dm-crypt",
            point.display()
        ))
    }
}

/// Whether `point` is a mount point now.
pub fn is_mount_point(point: &Path) -> bool {
    system().is_ok_and(|ms| at(&ms, point).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MI: &str = "\
22 1 252:0 / / rw,relatime shared:1 - ext4 /dev/vda rw
30 22 0:25 / /run rw,nosuid shared:5 - tmpfs tmpfs rw,mode=755
31 30 0:26 / /run/robodr-seal rw shared:6 - tmpfs tmpfs rw,mode=700
40 22 253:3 / /run\\040sealed rw - ext4 /dev/mapper/robodr-sealed rw
41 22 7:0 / /mnt/x rw - ext4 /dev/loop0 rw
42 41 7:1 / /mnt/x rw - xfs /dev/loop1 rw
bad line
";

    #[test]
    fn parse_and_lookup() {
        let ms = parse(MI);
        assert_eq!(ms.len(), 6);
        assert_eq!(at(&ms, Path::new("/run sealed")).unwrap().dev, "253:3");
        assert_eq!(at(&ms, Path::new("/mnt/x")).unwrap().fstype, "xfs");
        assert!(at(&ms, Path::new("/mnt")).is_none());
        let h = |p: &str| holding(&ms, Path::new(p)).unwrap().point.clone();
        assert_eq!(
            h("/run/robodr-seal/.work-1"),
            PathBuf::from("/run/robodr-seal")
        );
        assert_eq!(h("/run/robodr-sealx"), PathBuf::from("/run"));
        assert_eq!(h("/var/lib/robodr-seal"), PathBuf::from("/"));
        assert_eq!(holding(&ms, Path::new("/mnt/x/y")).unwrap().fstype, "xfs");
        assert_eq!(unescape("a\\134b"), "a\\b");
    }

    #[test]
    fn the_system_temp_dir_is_checked_not_assumed() {
        // Whatever /tmp is here, the check answers from mountinfo; a path
        // on the root file system of this test host is not dm-crypt.
        let d = std::env::temp_dir();
        let _ = check_tmpfs(&d);
        assert!(check_on_dm_crypt(Path::new("/proc")).is_err());
    }
}
