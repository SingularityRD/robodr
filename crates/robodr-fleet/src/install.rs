//! Installing a file agentd reads (profile, `.sig`, revocation list):
//! atomic replace, keeping the existing file's owner, group and mode
//! (minus any group/other write bit, which agentd's trust loaders refuse);
//! a new file is 0644. The directory must not be writable by group or
//! others, and owner and mode are set on the temp file's descriptor
//! (fchown, fchmod) before the rename: a reader never sees the file with
//! another owner or mode.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::fsx;

/// Owner and mode the replacement of `path` gets.
fn target_attrs(path: &Path) -> Result<(u32, Option<(u32, u32)>), String> {
    fsx::check_parent_not_shared(path, "directory")
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => {
            Err(format!("{} is a symlink (refused)", path.display()))
        }
        Ok(md) => Ok((
            (md.permissions().mode() & 0o755) | 0o600,
            Some((md.uid(), md.gid())),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((0o644, None)),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn stage(path: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    let (mode, owner) = target_attrs(path)?;
    fsx::stage_file(path, bytes, mode, owner).map_err(|e| format!("{}: {e}", path.display()))
}

/// Atomically replace `path` with `bytes` (see the module docs).
pub fn install_public(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = stage(path, bytes)?;
    fsx::commit(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Install a profile and its `.sig` as one step, as far as two files
/// allow: both are written completely (owner, mode, fsync) as temp files
/// first, then renamed back to back, `.sig` first and the profile last. A
/// crash between the two renames leaves the new `.sig` next to the old
/// profile, a pair that does not verify (agentd refuses it: observe-only,
/// fail closed); re-running the same approval completes the install.
pub fn install_pair(sig_path: &Path, sig: &[u8], path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tsig = stage(sig_path, sig)?;
    let tprof = match stage(path, bytes) {
        Ok(t) => t,
        Err(e) => {
            let _ = std::fs::remove_file(&tsig);
            return Err(e);
        }
    };
    if let Err(e) = fsx::commit(&tsig, sig_path) {
        let _ = std::fs::remove_file(&tprof);
        return Err(format!("{}: {e}", sig_path.display()));
    }
    fsx::commit(&tprof, path).map_err(|e| format!("{}: {e}", path.display()))
}
