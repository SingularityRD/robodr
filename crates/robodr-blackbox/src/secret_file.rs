//! The one access rule for files that hold secret key material, shared by
//! every RoboDR daemon and tool that loads one (agentd, the executor and
//! its agentd link, spool-export, diode-pack, uplink, kafka-publish,
//! deliverd, the anchor receiver, the fleet tools, robodr-seal).
//!
//! # The rule
//!
//! A secret file must be a regular file (never a symlink) owned by root or
//! the effective user. Then **either**
//!
//! 1. **private file** (every ordinary path): no group or other permission
//!    bits at all (`mode & 0o077 == 0`, i.e. `chmod 600` or `400`); **or**
//! 2. **systemd credential** (`LoadCredential=`): the file's real parent
//!    directory (read back from the opened descriptor, so a symlinked path
//!    cannot pose as one) is `$CREDENTIALS_DIRECTORY` or
//!    `/run/credentials/<name>/`, that directory is owned by root and on
//!    the same **read-only** mount as the file, the file has no write bit
//!    for anyone and no bit for others, and its POSIX access ACL
//!    (`system.posix_acl_access`) lets **no principal other than root and
//!    the effective user** read it: the owning group, every named group and
//!    every named user other than the euid have no effective read or write
//!    permission (named entries and the owning group are taken through the
//!    ACL mask, as the kernel does).
//!
//! Why the second branch: systemd >= 254 on kernel >= 6.4 (Ubuntu 24.04,
//! Debian 13) puts credentials on a read-only tmpfs, owned by root, and
//! grants the service user read access with an ACL entry
//! `user:<service uid>:r--`. `stat` then shows `-r--r-----+ root root`:
//! the "group" bits are the ACL mask, not the owning group's access. The
//! strict mode rule alone would refuse every such credential, and
//! `chmod 600` is impossible on the read-only mount. Older systemd chowns
//! the credential to the service user with mode 0400, which the first
//! branch accepts.
//!
//! When the file's ACL cannot be read (no xattr support, a kernel without
//! POSIX ACLs) or it has none at all (the group bits are then real), the
//! strict mode rule applies and the refusal says why.

use std::fmt;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};

/// The name of the POSIX access ACL extended attribute.
pub const ACL_XATTR: &str = "system.posix_acl_access";
/// The only POSIX ACL xattr format version Linux writes.
pub const ACL_VERSION: u32 = 2;

/// ACL entry tags (`<linux/posix_acl.h>`).
pub const ACL_USER_OBJ: u16 = 0x01;
pub const ACL_USER: u16 = 0x02;
pub const ACL_GROUP_OBJ: u16 = 0x04;
pub const ACL_GROUP: u16 = 0x08;
pub const ACL_MASK: u16 = 0x10;
pub const ACL_OTHER: u16 = 0x20;
/// Permission bits of an ACL entry.
pub const ACL_READ: u16 = 0x04;
pub const ACL_WRITE: u16 = 0x02;

/// Upper bound on the ACL xattr this module reads (a credential's ACL has
/// four or five entries; 4 KiB is ~500).
const MAX_ACL_BYTES: usize = 4096;

/// How a secret file passed [`check_secret_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretAccess {
    /// No group or other permission bits.
    Private,
    /// A systemd credential readable only by root and this user through
    /// its ACL, in the given credential directory.
    SystemdCredential { dir: PathBuf },
}

/// Why a secret file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretFileError {
    /// Opening or inspecting the file failed.
    Io(String),
    /// A symlink, directory, FIFO or other non-regular file.
    NotRegular,
    /// Owned by neither root nor the effective user.
    Owner { uid: u32, euid: u32 },
    /// An ordinary path whose mode gives group/others access.
    Mode { mode: u32 },
    /// A file in a systemd credential directory that fails the credential
    /// rule (module docs); `reason` says which part.
    Credential {
        mode: u32,
        dir: PathBuf,
        reason: String,
    },
}

impl fmt::Display for SecretFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretFileError::Io(e) => write!(f, "{e}"),
            SecretFileError::NotRegular => {
                write!(f, "not a regular file (symlinks are refused)")
            }
            SecretFileError::Owner { uid, euid } => write!(
                f,
                "owned by uid {uid}, not by root or this process's uid {euid}"
            ),
            SecretFileError::Mode { mode } => write!(
                f,
                "mode {mode:04o} lets group/others access this secret file; chmod 600 (a systemd \
                 LoadCredential= file under /run/credentials/ is accepted when only root and \
                 this user can read it)"
            ),
            SecretFileError::Credential { mode, dir, reason } => write!(
                f,
                "mode {mode:04o} in the systemd credential directory {}: refused because {reason}",
                dir.display()
            ),
        }
    }
}

impl std::error::Error for SecretFileError {}

/// One entry of a POSIX ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclEntry {
    pub tag: u16,
    pub perm: u16,
    /// uid for [`ACL_USER`], gid for [`ACL_GROUP`], unused otherwise.
    pub id: u32,
}

/// Parse the binary `system.posix_acl_access` value (little-endian:
/// a 4-byte version, which must be 2, then 8-byte entries of tag u16,
/// perm u16, id u32).
pub fn parse_acl(bytes: &[u8]) -> Result<Vec<AclEntry>, String> {
    let (head, rest) = bytes
        .split_first_chunk::<4>()
        .ok_or_else(|| format!("ACL of {} bytes has no header", bytes.len()))?;
    let version = u32::from_le_bytes(*head);
    if version != ACL_VERSION {
        return Err(format!("ACL version {version} (only 2 is known)"));
    }
    if rest.len() % 8 != 0 {
        return Err(format!(
            "ACL body of {} bytes is not a whole number of entries",
            rest.len()
        ));
    }
    let mut out = Vec::with_capacity(rest.len() / 8);
    for chunk in rest.chunks_exact(8) {
        let (tag, r) = chunk
            .split_first_chunk::<2>()
            .ok_or_else(|| "short ACL entry".to_string())?;
        let (perm, r) = r
            .split_first_chunk::<2>()
            .ok_or_else(|| "short ACL entry".to_string())?;
        let (id, _) = r
            .split_first_chunk::<4>()
            .ok_or_else(|| "short ACL entry".to_string())?;
        out.push(AclEntry {
            tag: u16::from_le_bytes(*tag),
            perm: u16::from_le_bytes(*perm),
            id: u32::from_le_bytes(*id),
        });
    }
    Ok(out)
}

fn perm_text(p: u16) -> String {
    let r = if p & ACL_READ != 0 { 'r' } else { '-' };
    let w = if p & ACL_WRITE != 0 { 'w' } else { '-' };
    let x = if p & 0x01 != 0 { 'x' } else { '-' };
    format!("{r}{w}{x}")
}

/// Decide whether an access ACL lets nobody but root and `euid` read or
/// write the file (`owner_uid`/`gid`: the file's owner and group, for the
/// `user::` and `group::` entries). `Err` names the first principal that
/// has access it must not have.
pub fn check_acl(entries: &[AclEntry], owner_uid: u32, gid: u32, euid: u32) -> Result<(), String> {
    let mask = entries.iter().find(|e| e.tag == ACL_MASK).map(|e| e.perm);
    // Named entries and the owning group are limited by the mask; without
    // a mask (a minimal ACL) the group entry applies as is.
    let through_mask = |p: u16| mask.map_or(p, |m| p & m);
    let mut seen = 0u16;
    for e in entries {
        seen |= e.tag;
        match e.tag {
            ACL_USER_OBJ => {
                if e.perm & ACL_WRITE != 0 {
                    return Err(format!(
                        "the ACL gives the owner (uid {owner_uid}) write access (user::{})",
                        perm_text(e.perm)
                    ));
                }
                if e.perm & ACL_READ != 0 && owner_uid != 0 && owner_uid != euid {
                    return Err(format!(
                        "the ACL grants read to the owner uid {owner_uid}, which is neither root \
                         nor this process's uid {euid}"
                    ));
                }
            }
            ACL_USER => {
                let eff = through_mask(e.perm);
                if eff & ACL_WRITE != 0 {
                    return Err(format!(
                        "the ACL grants write to uid {} (user:{}:{})",
                        e.id,
                        e.id,
                        perm_text(e.perm)
                    ));
                }
                if eff & ACL_READ != 0 && e.id != euid && e.id != 0 {
                    return Err(format!(
                        "the ACL grants read to uid {} (user:{}:{}), which is not this \
                         process's uid {euid}",
                        e.id,
                        e.id,
                        perm_text(e.perm)
                    ));
                }
            }
            ACL_GROUP_OBJ => {
                let eff = through_mask(e.perm);
                if eff & (ACL_READ | ACL_WRITE) != 0 {
                    return Err(format!(
                        "the ACL grants {} to the owning group gid {gid} (group::{})",
                        if eff & ACL_WRITE != 0 {
                            "write"
                        } else {
                            "read"
                        },
                        perm_text(e.perm)
                    ));
                }
            }
            ACL_GROUP => {
                let eff = through_mask(e.perm);
                if eff & (ACL_READ | ACL_WRITE) != 0 {
                    return Err(format!(
                        "the ACL grants {} to group gid {} (group:{}:{})",
                        if eff & ACL_WRITE != 0 {
                            "write"
                        } else {
                            "read"
                        },
                        e.id,
                        e.id,
                        perm_text(e.perm)
                    ));
                }
            }
            ACL_MASK => {}
            ACL_OTHER => {
                if e.perm & (ACL_READ | ACL_WRITE) != 0 {
                    return Err(format!(
                        "the ACL grants access to others (other::{})",
                        perm_text(e.perm)
                    ));
                }
            }
            t => return Err(format!("the ACL has an unknown entry tag {t:#x}")),
        }
    }
    let required = ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_OTHER;
    if seen & required != required {
        return Err("the ACL lacks a user::, group:: or other:: entry (malformed)".into());
    }
    Ok(())
}

/// Whether `dir` is a systemd credential directory: equal to `env_dir`
/// (`$CREDENTIALS_DIRECTORY`, canonicalised) or directly under
/// `/run/credentials/`.
pub fn is_credential_dir(dir: &Path, env_dir: Option<&Path>) -> bool {
    if env_dir.is_some_and(|e| e == dir) {
        return true;
    }
    dir.parent() == Some(Path::new("/run/credentials"))
        && dir
            .file_name()
            .is_some_and(|n| !n.is_empty() && n != "." && n != "..")
}

/// `$CREDENTIALS_DIRECTORY`, canonicalised, when set.
fn credentials_env_dir() -> Option<PathBuf> {
    let d = std::env::var_os("CREDENTIALS_DIRECTORY")?;
    std::fs::canonicalize(PathBuf::from(d)).ok()
}

/// Check an opened secret file (`md`: its `fstat`) against the rule in the
/// module docs.
pub fn check_secret_file(file: &File, md: &Metadata) -> Result<SecretAccess, SecretFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !md.file_type().is_file() {
            return Err(SecretFileError::NotRegular);
        }
        let euid = crate::keys::effective_uid();
        let uid = md.uid();
        if uid != 0 && uid != euid {
            return Err(SecretFileError::Owner { uid, euid });
        }
        let mode = md.mode() & 0o7777;
        if mode & 0o077 == 0 {
            return Ok(SecretAccess::Private);
        }
        let Some(dir) = sys::opened_parent(file) else {
            return Err(SecretFileError::Mode { mode });
        };
        if !is_credential_dir(&dir, credentials_env_dir().as_deref()) {
            return Err(SecretFileError::Mode { mode });
        }
        let refuse = |reason: String| SecretFileError::Credential {
            mode,
            dir: dir.clone(),
            reason,
        };
        let dmd = std::fs::symlink_metadata(&dir)
            .map_err(|e| refuse(format!("its directory cannot be inspected: {e}")))?;
        if !dmd.is_dir() || dmd.uid() != 0 {
            return Err(refuse(format!(
                "the directory is owned by uid {}, not root",
                dmd.uid()
            )));
        }
        if dmd.dev() != md.dev() {
            return Err(refuse("the file is not on the directory's mount".into()));
        }
        match sys::read_only_mount(file) {
            Ok(true) => {}
            Ok(false) => {
                return Err(refuse(
                    "the credential mount is not read-only (chmod 600 the source file or \
                     check the systemd version)"
                        .into(),
                ))
            }
            Err(e) => return Err(refuse(format!("statvfs failed: {e}"))),
        }
        if mode & 0o222 != 0 {
            return Err(refuse("the file has a write permission bit".into()));
        }
        if mode & 0o007 != 0 {
            return Err(refuse("others have permission bits on it".into()));
        }
        let acl = match sys::access_acl(file) {
            Ok(Some(b)) => b,
            Ok(None) => {
                return Err(refuse(format!(
                    "it has no POSIX ACL, so its group bits are real: group gid {} can read it",
                    md.gid()
                )))
            }
            Err(e) => {
                return Err(refuse(format!(
                    "its ACL cannot be read ({e}), so the strict rule applies (no group/other \
                     bits)"
                )))
            }
        };
        let entries = parse_acl(&acl).map_err(|e| refuse(format!("its ACL is malformed: {e}")))?;
        check_acl(&entries, uid, md.gid(), euid).map_err(refuse)?;
        Ok(SecretAccess::SystemdCredential { dir })
    }
    #[cfg(not(unix))]
    {
        let _ = (file, md);
        Ok(SecretAccess::Private)
    }
}

/// Open `path` read-only without following a final symlink (and without
/// blocking on a FIFO), then [`check_secret_file`] it. For callers that
/// only check a path that another component reads.
pub fn check_secret_path(path: &Path) -> Result<SecretAccess, SecretFileError> {
    let (f, md) = open_secret_file(path)?;
    let r = check_secret_file(&f, &md);
    drop(f);
    r
}

/// Open `path` read-only without following a final symlink and without
/// blocking on a FIFO; returns the file and its `fstat` (not yet checked
/// against the rule: call [`check_secret_file`]).
pub fn open_secret_file(path: &Path) -> Result<(File, Metadata), SecretFileError> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(crate::store::sys::O_NOFOLLOW | sys::O_NONBLOCK);
    }
    let f = match o.open(path) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(SecretFileError::NotRegular),
        Err(e) => return Err(SecretFileError::Io(e.to_string())),
    };
    let md = f
        .metadata()
        .map_err(|e| SecretFileError::Io(e.to_string()))?;
    if !md.file_type().is_file() {
        return Err(SecretFileError::NotRegular);
    }
    Ok((f, md))
}

#[cfg(target_os = "linux")]
mod sys {
    use std::fs::File;
    use std::io;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;

    pub const O_NONBLOCK: i32 = libc::O_NONBLOCK;

    /// The directory the opened file lives in, from `/proc/self/fd`.
    pub fn opened_parent(file: &File) -> Option<PathBuf> {
        let p = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()?;
        if !p.is_absolute() {
            return None;
        }
        p.parent().map(PathBuf::from)
    }

    /// Whether the opened file is on a read-only mount (`fstatvfs`).
    #[allow(unsafe_code)] // FFI: no std API for statvfs.
    pub fn read_only_mount(file: &File) -> io::Result<bool> {
        let mut st = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
        // SAFETY: the fd is open for the lifetime of `file`; `st` points
        // to writable memory of the size fstatvfs fills.
        let r = unsafe { libc::fstatvfs(file.as_raw_fd(), st.as_mut_ptr()) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fstatvfs succeeded, so it initialised the struct (and it
        // was zeroed before, which is a valid statvfs anyway).
        let st = unsafe { st.assume_init() };
        Ok(st.f_flag & libc::ST_RDONLY != 0)
    }

    /// The file's `system.posix_acl_access` value; `None` when it has none.
    #[allow(unsafe_code)] // FFI: no std API for extended attributes.
    pub fn access_acl(file: &File) -> io::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; super::MAX_ACL_BYTES];
        let name = c"system.posix_acl_access";
        // SAFETY: `name` is NUL-terminated; `buf` is writable for
        // `buf.len()` bytes; the fd is open for the lifetime of `file`.
        let n = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENODATA) {
                return Ok(None);
            }
            return Err(e);
        }
        let n = usize::try_from(n).map_err(|_| io::Error::other("negative xattr length"))?;
        buf.truncate(n);
        Ok(Some(buf))
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod sys {
    use std::fs::File;
    use std::io;
    use std::path::PathBuf;

    pub const O_NONBLOCK: i32 = 0;

    pub fn opened_parent(_: &File) -> Option<PathBuf> {
        None
    }
    pub fn read_only_mount(_: &File) -> io::Result<bool> {
        Ok(false)
    }
    pub fn access_acl(_: &File) -> io::Result<Option<Vec<u8>>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut v = ACL_VERSION.to_le_bytes().to_vec();
        for (t, p, id) in entries {
            v.extend_from_slice(&t.to_le_bytes());
            v.extend_from_slice(&p.to_le_bytes());
            v.extend_from_slice(&id.to_le_bytes());
        }
        v
    }

    const U: u32 = u32::MAX; // ACL_UNDEFINED_ID

    /// What systemd 255 writes for a credential of a unit running as uid
    /// 998: `user::r--, user:998:r--, group::---, mask::r--, other::---`.
    fn systemd_acl(svc: u32) -> Vec<u8> {
        acl(&[
            (ACL_USER_OBJ, 4, U),
            (ACL_USER, 4, svc),
            (ACL_GROUP_OBJ, 0, U),
            (ACL_MASK, 4, U),
            (ACL_OTHER, 0, U),
        ])
    }

    #[test]
    fn parses_systemd_acl() {
        let e = parse_acl(&systemd_acl(998)).unwrap();
        assert_eq!(e.len(), 5);
        assert_eq!(
            e[1],
            AclEntry {
                tag: ACL_USER,
                perm: 4,
                id: 998
            }
        );
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse_acl(&[]).unwrap_err().contains("header"));
        assert!(parse_acl(&[2, 0, 0]).is_err());
        let mut v = systemd_acl(1);
        v[0] = 1;
        assert!(parse_acl(&v).unwrap_err().contains("version 1"));
        let mut v = systemd_acl(1);
        v.push(0);
        assert!(parse_acl(&v).unwrap_err().contains("whole number"));
        assert_eq!(parse_acl(&acl(&[])).unwrap(), vec![]);
    }

    #[test]
    fn systemd_acl_accepted_for_its_user_only() {
        let e = parse_acl(&systemd_acl(998)).unwrap();
        assert!(check_acl(&e, 0, 0, 998).is_ok());
        // A root daemon must not accept a key another user can read.
        assert!(check_acl(&e, 0, 0, 0).unwrap_err().contains("uid 998"));
        // systemd's ACL for a unit running as root: owner only.
        let root_only = parse_acl(&acl(&[
            (ACL_USER_OBJ, 4, U),
            (ACL_GROUP_OBJ, 0, U),
            (ACL_OTHER, 0, U),
        ]))
        .unwrap();
        assert!(check_acl(&root_only, 0, 0, 0).is_ok());
        let err = check_acl(&e, 0, 0, 1000).unwrap_err();
        assert!(err.contains("uid 998"), "{err}");
    }

    #[test]
    fn group_read_refused() {
        // group::r-- with mask r--: the owning group (gid 0) can read.
        let e = parse_acl(&acl(&[
            (ACL_USER_OBJ, 4, U),
            (ACL_USER, 4, 998),
            (ACL_GROUP_OBJ, 4, U),
            (ACL_MASK, 4, U),
            (ACL_OTHER, 0, U),
        ]))
        .unwrap();
        let err = check_acl(&e, 0, 0, 998).unwrap_err();
        assert!(err.contains("owning group gid 0"), "{err}");
        // A named group.
        let e = parse_acl(&acl(&[
            (ACL_USER_OBJ, 4, U),
            (ACL_USER, 4, 998),
            (ACL_GROUP_OBJ, 0, U),
            (ACL_GROUP, 4, 44),
            (ACL_MASK, 4, U),
            (ACL_OTHER, 0, U),
        ]))
        .unwrap();
        let err = check_acl(&e, 0, 0, 998).unwrap_err();
        assert!(err.contains("group gid 44"), "{err}");
        // Minimal ACL without mask: group:: applies directly.
        let e = parse_acl(&acl(&[
            (ACL_USER_OBJ, 4, U),
            (ACL_GROUP_OBJ, 4, U),
            (ACL_OTHER, 0, U),
        ]))
        .unwrap();
        assert!(check_acl(&e, 998, 5, 998).is_err());
    }

    #[test]
    fn mask_limits_named_entries() {
        // group:44:rw- but mask ---: nobody in group 44 can read.
        let e = parse_acl(&acl(&[
            (ACL_USER_OBJ, 4, U),
            (ACL_GROUP_OBJ, 4, U),
            (ACL_GROUP, 6, 44),
            (ACL_USER, 6, 7),
            (ACL_MASK, 0, U),
            (ACL_OTHER, 0, U),
        ]))
        .unwrap();
        assert!(check_acl(&e, 998, 5, 998).is_ok());
    }

    #[test]
    fn others_writes_and_foreign_owner_refused() {
        let other = parse_acl(&acl(&[
            (ACL_USER_OBJ, 4, U),
            (ACL_USER, 4, 998),
            (ACL_GROUP_OBJ, 0, U),
            (ACL_MASK, 4, U),
            (ACL_OTHER, 4, U),
        ]))
        .unwrap();
        assert!(check_acl(&other, 0, 0, 998).unwrap_err().contains("others"));
        let write = parse_acl(&acl(&[
            (ACL_USER_OBJ, 4, U),
            (ACL_USER, 6, 998),
            (ACL_GROUP_OBJ, 0, U),
            (ACL_MASK, 6, U),
            (ACL_OTHER, 0, U),
        ]))
        .unwrap();
        assert!(check_acl(&write, 0, 0, 998).unwrap_err().contains("write"));
        let owner = parse_acl(&systemd_acl(998)).unwrap();
        assert!(check_acl(&owner, 1234, 0, 998)
            .unwrap_err()
            .contains("owner uid 1234"));
        let incomplete = parse_acl(&acl(&[(ACL_USER_OBJ, 4, U)])).unwrap();
        assert!(check_acl(&incomplete, 0, 0, 998)
            .unwrap_err()
            .contains("malformed"));
        let unknown = parse_acl(&acl(&[
            (ACL_USER_OBJ, 4, U),
            (ACL_GROUP_OBJ, 0, U),
            (ACL_OTHER, 0, U),
            (0x40, 4, U),
        ]))
        .unwrap();
        assert!(check_acl(&unknown, 0, 0, 998)
            .unwrap_err()
            .contains("unknown"));
    }

    #[test]
    fn credential_dir_detection() {
        assert!(is_credential_dir(
            Path::new("/run/credentials/robodr-agentd.service"),
            None
        ));
        assert!(!is_credential_dir(Path::new("/run/credentials"), None));
        assert!(!is_credential_dir(Path::new("/run/credentials/a/b"), None));
        assert!(!is_credential_dir(Path::new("/etc/robodr/keys"), None));
        assert!(is_credential_dir(
            Path::new("/run/creds-x"),
            Some(Path::new("/run/creds-x"))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_paths_keep_the_strict_rule() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("robodr-secret-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k");
        std::fs::write(&p, b"x").unwrap();
        for (m, ok) in [
            (0o600, true),
            (0o400, true),
            (0o640, false),
            (0o440, false),
            (0o604, false),
        ] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(m)).unwrap();
            let r = check_secret_path(&p);
            assert_eq!(r.is_ok(), ok, "{m:o}: {r:?}");
            if !ok {
                let e = r.unwrap_err();
                assert!(matches!(e, SecretFileError::Mode { .. }), "{e:?}");
                assert!(e.to_string().contains("chmod 600"), "{e}");
            }
        }
        let link = dir.join("l");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(check_secret_path(&link), Err(SecretFileError::NotRegular));
        assert_eq!(check_secret_path(&dir), Err(SecretFileError::NotRegular));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
