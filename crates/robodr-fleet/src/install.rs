//! Installing a file agentd reads (profile, `.sig`, revocation list):
//! atomic replace, keeping the existing file's owner, group and mode
//! (minus any group/other write bit, which agentd's trust loaders refuse);
//! a new file is 0644.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::fsx;

/// Atomically replace `path` with `bytes` (see the module docs).
pub fn install_public(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let prev = match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(format!("{} is a symlink (refused)", path.display()))
        }
        Ok(md) => Some((md.uid(), md.gid(), md.permissions().mode() & 0o7777)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    // Write a temp file next to it with the final owner and mode, then
    // rename: readers see the old or the new file, never a partial one, and
    // never a file with the wrong mode.
    let tmp = fsx::with_suffix(path, ".robodr-enroll.tmp");
    let _ = std::fs::remove_file(&tmp);
    robodr_commission::write_file_atomic(&tmp, bytes, false)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    let res = (|| {
        let mode = prev.map_or(0o644, |(_, _, m)| (m & 0o755) | 0o600);
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        if let Some((uid, gid, _)) = prev {
            std::os::unix::fs::chown(&tmp, Some(uid), Some(gid))?;
        }
        fsx::rename_durable(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{}: {e}", path.display()));
    }
    Ok(())
}
