//! Directory-file-descriptor I/O (review M2): `openat`, `linkat` and
//! `unlinkat` relative to a directory the agent holds open, never a path
//! re-resolved through a directory another user can change.
//!
//! The agent runs as root and writes into directories that belong to a
//! less privileged user (agentd's findings spool) and reads files that
//! user's directory holds. A path-based `link(2)`, `unlink(2)` or
//! `open(2)` there acts on whatever the name means at that moment, which
//! that user decides (a swapped directory or a symlink makes root create,
//! link or remove something elsewhere). Here every name is a single
//! component (no `/`), looked up in a directory held by descriptor,
//! opened with `O_NOFOLLOW`, and a file is linked into place from its own
//! descriptor (an `O_TMPFILE`, which has no name before the link).
//!
//! std has no `*at` calls; they are declared here from libc (which std
//! links), with the flag values of the supported architectures, like
//! `robodr_agentd::host`'s `SO_PEERCRED`.

use std::ffi::{c_char, c_int, c_uint, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;

// The generic Linux values (x86, x86_64, riscv, loongarch64, s390x) and
// the arm / powerpc family. Other architectures use other numbers for some
// of them and are not supported.
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "loongarch64",
    target_arch = "s390x",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64"
)))]
compile_error!("robodr-deliverd::fdio: open(2) flag values of this architecture are not defined");

const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 0o1;
const O_CREAT: c_int = 0o100;
const O_EXCL: c_int = 0o200;
const O_NONBLOCK: c_int = 0o4000;
const O_CLOEXEC: c_int = 0o2000000;
const O_TMPFILE_BASE: c_int = 0o20000000;
#[cfg(any(
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64"
))]
const O_DIRECTORY: c_int = 0o40000;
#[cfg(any(
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64"
))]
const O_NOFOLLOW: c_int = 0o100000;
#[cfg(not(any(
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64"
)))]
const O_DIRECTORY: c_int = 0o200000;
#[cfg(not(any(
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64"
)))]
const O_NOFOLLOW: c_int = 0o400000;
const O_TMPFILE: c_int = O_TMPFILE_BASE | O_DIRECTORY;
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_FOLLOW: c_int = 0x400;

extern "C" {
    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn linkat(
        olddirfd: c_int,
        oldpath: *const c_char,
        newdirfd: c_int,
        newpath: *const c_char,
        flags: c_int,
    ) -> c_int;
    fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
}

/// A single path component: not empty, not `.` / `..`, no `/`, no NUL.
fn component(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not a single file name"),
        ));
    }
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in a name"))
}

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in a path"))
}

/// `openat(2)`; the new descriptor as a `File`.
#[allow(unsafe_code)]
fn open_raw(dir: RawFd, path: &CString, flags: c_int, mode: c_uint) -> io::Result<File> {
    // SAFETY: `path` is a valid NUL-terminated string that outlives the
    // call; `dir` is a descriptor borrowed from a live `File` (or
    // AT_FDCWD); the variadic mode is passed as an unsigned int, as
    // openat(2) reads it. No memory is shared with the kernel after return.
    let fd = unsafe { openat(dir, path.as_ptr(), flags | O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nothing
    // else; the `File` becomes its only owner and closes it.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open the directory at `path` (its last component must not be a
/// symlink).
pub fn open_dir(path: &Path) -> io::Result<File> {
    open_raw(
        AT_FDCWD,
        &cpath(path)?,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
        0,
    )
}

/// Open the directory `name` inside `dir` (not a symlink).
pub fn open_dir_at(dir: &File, name: &str) -> io::Result<File> {
    open_raw(
        dir.as_raw_fd(),
        &component(name)?,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
        0,
    )
}

/// Open the file at `path` for reading: its last component must not be a
/// symlink, and a FIFO does not block the open.
pub fn open_read(path: &Path) -> io::Result<File> {
    open_raw(
        AT_FDCWD,
        &cpath(path)?,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK,
        0,
    )
}

/// Open the file `name` inside `dir` for reading (not a symlink; a FIFO
/// does not block the open).
pub fn open_read_at(dir: &File, name: &str) -> io::Result<File> {
    open_raw(
        dir.as_raw_fd(),
        &component(name)?,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK,
        0,
    )
}

/// Create the new file `name` inside `dir` (`O_EXCL`, never through a
/// symlink), mode `mode`.
pub fn create_at(dir: &File, name: &str, mode: u32) -> io::Result<File> {
    open_raw(
        dir.as_raw_fd(),
        &component(name)?,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
        mode,
    )
}

/// An unnamed file in `dir` (`O_TMPFILE`), mode `mode`. Fails where the
/// file system or kernel has no `O_TMPFILE` (`EOPNOTSUPP`, `EISDIR`).
pub fn tmpfile_in(dir: &File, mode: u32) -> io::Result<File> {
    open_raw(
        dir.as_raw_fd(),
        &component_dot(),
        O_TMPFILE | O_WRONLY,
        mode,
    )
}

fn component_dot() -> CString {
    CString::from(c".")
}

/// Give the unnamed file `f` the name `name` in `dir` (`linkat` of
/// `/proc/self/fd/<f>` with `AT_SYMLINK_FOLLOW`). Fails with
/// `AlreadyExists` when the name is taken: nothing is ever replaced.
#[allow(unsafe_code)]
pub fn link_fd_at(f: &File, dir: &File, name: &str) -> io::Result<()> {
    let from = cpath(Path::new(&format!("/proc/self/fd/{}", f.as_raw_fd())))?;
    let to = component(name)?;
    // SAFETY: both strings are valid NUL-terminated and outlive the call;
    // the descriptors are borrowed from live `File`s.
    let rc = unsafe {
        linkat(
            AT_FDCWD,
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            AT_SYMLINK_FOLLOW,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Hard-link `from` to `to`, both names in `dir` (no symlink is followed:
/// a symlink at `from` is linked itself). Never replaces `to`.
#[allow(unsafe_code)]
pub fn link_at(dir: &File, from: &str, to: &str) -> io::Result<()> {
    let (a, b) = (component(from)?, component(to)?);
    // SAFETY: valid NUL-terminated strings outliving the call; the
    // descriptor is borrowed from a live `File`.
    let rc = unsafe { linkat(dir.as_raw_fd(), a.as_ptr(), dir.as_raw_fd(), b.as_ptr(), 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Remove the (non-directory) entry `name` of `dir`.
#[allow(unsafe_code)]
pub fn unlink_at(dir: &File, name: &str) -> io::Result<()> {
    let n = component(name)?;
    // SAFETY: valid NUL-terminated string outliving the call; the
    // descriptor is borrowed from a live `File`.
    let rc = unsafe { unlinkat(dir.as_raw_fd(), n.as_ptr(), 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn names_are_single_components_and_symlinks_are_not_followed() {
        let d = std::env::temp_dir().join(format!("deliverd-fdio-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub")).unwrap();
        let outside = d.join("outside");
        std::fs::write(&outside, b"victim").unwrap();
        std::os::unix::fs::symlink(&outside, d.join("sub/link")).unwrap();
        std::os::unix::fs::symlink(d.join("sub"), d.join("dirlink")).unwrap();
        let root = open_dir(&d).unwrap();
        assert!(open_dir(&d.join("dirlink")).is_err());
        assert!(open_dir_at(&root, "dirlink").is_err());
        assert!(open_dir_at(&root, "../x").is_err());
        let sub = open_dir_at(&root, "sub").unwrap();
        assert!(open_read_at(&sub, "link").is_err());
        assert!(create_at(&sub, "link", 0o600).is_err());
        // An unnamed file linked into place; a taken name is never replaced.
        let mut f = match tmpfile_in(&sub, 0o640) {
            Ok(f) => f,
            Err(_) => create_at(&sub, "t", 0o640).unwrap(),
        };
        f.write_all(b"record").unwrap();
        link_fd_at(&f, &sub, "r.json").unwrap();
        assert_eq!(
            link_fd_at(&f, &sub, "link").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let mut s = String::new();
        open_read_at(&sub, "r.json")
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "record");
        // link_at links the symlink itself, unlink_at removes the name only.
        link_at(&sub, "link", "link2").unwrap();
        assert!(std::fs::symlink_metadata(d.join("sub/link2"))
            .unwrap()
            .file_type()
            .is_symlink());
        unlink_at(&sub, "link2").unwrap();
        unlink_at(&sub, "link").unwrap();
        assert_eq!(std::fs::read(&outside).unwrap(), b"victim");
        assert_eq!(std::fs::metadata(&outside).unwrap().nlink(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
