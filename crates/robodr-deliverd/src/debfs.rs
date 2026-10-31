//! What a `.deb` would write, and where it would really land (review
//! H-R3-1, L-R3-2).
//!
//! dpkg detects file conflicts by path **name**. On a merged-/usr system
//! (`/lib -> usr/lib`, `/bin -> usr/bin`, ...) a package that ships
//! `lib/nav/ok` writes through the directory symlink onto
//! `/usr/lib/nav/ok`, which another package owns, and dpkg sees no
//! conflict (the DEP17 aliasing problem). Before every `dpkg --install`
//! the agent therefore:
//!
//! 1. lists the `.deb`'s paths from `dpkg-deb --fsys-tarfile` (a strict
//!    tar reader: [`parse_tar`]);
//! 2. resolves each path's parent directories through the symlinks of the
//!    target root, never leaving it (an absolute link target is taken
//!    relative to the root, `..` stops at it: [`Resolver`]); the last
//!    component is not followed (dpkg replaces it);
//! 3. resolves every other package's file list
//!    (`<admindir>/info/<package>.list`) the same way and refuses a path
//!    whose canonical form another package owns ([`owners`]);
//! 4. refuses a path below the agent's own trees, RoboDR's install paths,
//!    dpkg's and apt's configuration and dpkg's database
//!    ([`protected`]).
//!
//! A `.deb` that ships a path below one of its own symlinks is refused
//! too (the resolution would depend on the order dpkg extracts in).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Most entries read from one `.deb`.
pub const MAX_ENTRIES: usize = 200_000;
/// Longest path (bytes).
pub const MAX_PATH: usize = 4096;
/// The largest member [`parse_tar_grab`] reads into memory.
pub const MAX_GRAB: u64 = 64 * 1024;
/// Most bytes of dpkg file lists read for [`owners`].
pub const MAX_LIST_BYTES: u64 = 512 * 1024 * 1024;
/// Most file lists read for [`owners`].
pub const MAX_LISTS: usize = 100_000;
/// Most symlinks followed while resolving one path.
const MAX_LINKS: usize = 40;

/// What a tar entry creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File,
    Symlink,
    Hardlink,
    /// Character or block device, FIFO.
    Other,
}

/// One entry of a `.deb`'s data archive: its normalised relative path
/// (no leading `./` or `/`, no trailing `/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
}

fn octal(field: &[u8]) -> Result<u64, String> {
    if let Some((&first, tail)) = field.split_first().filter(|(b, _)| *b & 0x80 != 0) {
        // GNU base-256.
        let mut v: u64 = u64::from(first & 0x7f);
        for b in tail {
            v = v
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(*b)))
                .ok_or("tar: number too large")?;
        }
        return Ok(v);
    }
    let s: Vec<u8> = field
        .iter()
        .copied()
        .take_while(|b| *b != 0)
        .filter(|b| *b != b' ')
        .collect();
    if s.is_empty() {
        return Ok(0);
    }
    let s = std::str::from_utf8(&s).map_err(|_| "tar: bad number")?;
    u64::from_str_radix(s, 8).map_err(|_| "tar: bad number".to_string())
}

fn cstr(b: &[u8]) -> &[u8] {
    b.split(|c| *c == 0).next().unwrap_or(b)
}

fn read_block(r: &mut dyn Read, buf: &mut [u8; 512]) -> Result<bool, String> {
    let mut got = 0;
    while got < 512 {
        match r.read(buf.get_mut(got..).unwrap_or_default()) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err("tar: truncated block".into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("tar: {e}")),
        }
    }
    Ok(true)
}

fn read_data(r: &mut dyn Read, size: u64, max: u64) -> Result<Vec<u8>, String> {
    if size > max {
        return Err("tar: extended header too large".into());
    }
    let padded = size.div_ceil(512) * 512;
    let mut v = Vec::new();
    r.take(padded)
        .read_to_end(&mut v)
        .map_err(|e| format!("tar: {e}"))?;
    if v.len() as u64 != padded {
        return Err("tar: truncated data".into());
    }
    v.truncate(size as usize);
    Ok(v)
}

fn skip(r: &mut dyn Read, size: u64) -> Result<(), String> {
    let padded = size.div_ceil(512) * 512;
    let n = std::io::copy(&mut r.take(padded), &mut std::io::sink())
        .map_err(|e| format!("tar: {e}"))?;
    if n != padded {
        return Err("tar: truncated data".into());
    }
    Ok(())
}

/// The `path` of a pax extended header, if any.
fn pax_path(data: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut rest = data;
    let mut path = None;
    while !rest.is_empty() {
        let sp = rest
            .iter()
            .position(|b| *b == b' ')
            .ok_or("tar: bad pax record")?;
        let len: usize = rest
            .get(..sp)
            .and_then(|d| std::str::from_utf8(d).ok())
            .and_then(|s| s.parse().ok())
            .filter(|l| *l > sp + 1)
            .ok_or("tar: bad pax record length")?;
        let (record, next) = rest
            .split_at_checked(len)
            .ok_or("tar: bad pax record length")?;
        let rec = record.get(sp + 1..).ok_or("tar: bad pax record")?;
        let rec = rec.strip_suffix(b"\n").ok_or("tar: bad pax record")?;
        let eq = rec
            .iter()
            .position(|b| *b == b'=')
            .ok_or("tar: bad pax record")?;
        let (key, value) = rec.split_at_checked(eq).ok_or("tar: bad pax record")?;
        if key == b"path" {
            path = Some(value.get(1..).unwrap_or_default().to_vec());
        }
        rest = next;
    }
    Ok(path)
}

/// Normalise a member name: strip `./` and `/` prefixes and a trailing
/// `/`. `Ok(None)`: the archive root. `..`, `.` or empty components are
/// refused (dpkg would not write them where the name says).
pub fn normalise(name: &[u8]) -> Result<Option<String>, String> {
    let s = std::str::from_utf8(name).map_err(|_| "tar: a member name is not UTF-8")?;
    let mut s = s;
    loop {
        if let Some(r) = s.strip_prefix("./") {
            s = r;
        } else if let Some(r) = s.strip_prefix('/') {
            s = r;
        } else {
            break;
        }
    }
    let s = s.trim_end_matches('/');
    if s.is_empty() || s == "." {
        return Ok(None);
    }
    if s.len() > MAX_PATH
        || s.contains('\0')
        || s.split('/').any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!(
            "tar: member name {:?} is not a plain relative path",
            robodr_pkg::common::trunc(s)
        ));
    }
    Ok(Some(s.to_string()))
}

/// Read the entries of a tar stream (ustar, GNU long names, pax), strictly:
/// a bad checksum, a truncated archive, an unknown entry type or a link /
/// directory / device entry with data is an error.
pub fn parse_tar(r: &mut dyn Read) -> Result<Vec<Entry>, String> {
    parse_tar_grab(r, None).map(|(e, _)| e)
}

/// [`parse_tar`], and the content of the regular file `want` (a
/// normalised member name, at most [`MAX_GRAB`] bytes; a larger one is an
/// error) when the archive has it.
pub fn parse_tar_grab(
    r: &mut dyn Read,
    want: Option<&str>,
) -> Result<(Vec<Entry>, Option<Vec<u8>>), String> {
    let mut grabbed = None;
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    let mut long_name: Option<Vec<u8>> = None;
    let mut pax: Option<Vec<u8>> = None;
    loop {
        if !read_block(r, &mut buf)? {
            return Err("tar: no end-of-archive marker".into());
        }
        if buf.iter().all(|b| *b == 0) {
            return Ok((out, grabbed));
        }
        let sum = octal(&buf[148..156])?;
        let calc: u64 = buf
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        if sum != calc {
            return Err("tar: header checksum mismatch".into());
        }
        let size = octal(&buf[124..136])?;
        let flag = buf[156];
        match flag {
            b'L' => {
                long_name = Some(cstr(&read_data(r, size, MAX_PATH as u64 + 1)?).to_vec());
                continue;
            }
            b'K' => {
                read_data(r, size, MAX_PATH as u64 + 1)?;
                continue;
            }
            b'x' => {
                pax = pax_path(&read_data(r, size, 1024 * 1024)?)?;
                continue;
            }
            b'g' => {
                read_data(r, size, 1024 * 1024)?;
                continue;
            }
            _ => {}
        }
        let name = if let Some(n) = long_name.take().or(pax.take()) {
            n
        } else {
            let n = cstr(&buf[0..100]);
            if &buf[257..263] == b"ustar\0" {
                let p = cstr(&buf[345..500]);
                if p.is_empty() {
                    n.to_vec()
                } else {
                    [p, b"/", n].concat()
                }
            } else {
                n.to_vec()
            }
        };
        let kind = match flag {
            b'0' | 0 | b'7' => EntryKind::File,
            b'1' => EntryKind::Hardlink,
            b'2' => EntryKind::Symlink,
            b'5' => EntryKind::Dir,
            b'3' | b'4' | b'6' => EntryKind::Other,
            other => {
                return Err(format!(
                    "tar: unsupported entry type {:?}",
                    char::from(other)
                ))
            }
        };
        let path = normalise(&name)?;
        if kind == EntryKind::File {
            if want.is_some() && path.as_deref() == want {
                if size > MAX_GRAB {
                    return Err(format!(
                        "tar: {} is larger than {MAX_GRAB} bytes",
                        want.unwrap_or_default()
                    ));
                }
                grabbed = Some(read_data(r, size, MAX_GRAB)?);
            } else {
                skip(r, size)?;
            }
        } else if size != 0 {
            return Err("tar: a link, directory or device entry with data".into());
        }
        if let Some(path) = path {
            if out.len() >= MAX_ENTRIES {
                return Err(format!("tar: more than {MAX_ENTRIES} entries"));
            }
            out.push(Entry { path, kind });
        }
    }
}

/// Resolves paths relative to a root through the symlinks below it,
/// never leaving it, with a cache of resolved directories.
#[derive(Debug)]
pub struct Resolver {
    root: PathBuf,
    cache: HashMap<String, String>,
}

impl Resolver {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            cache: HashMap::new(),
        }
    }

    /// The canonical form of `rel` (relative to the root, no leading `/`):
    /// its parent directories resolved through the root's symlinks, its
    /// last component kept as it is.
    pub fn canonical(&mut self, rel: &str) -> Result<String, String> {
        let rel = rel.trim_start_matches('/');
        let (parent, last) = rel.rsplit_once('/').unwrap_or(("", rel));
        let p = self.dir(parent)?;
        Ok(if p.is_empty() {
            last.to_string()
        } else {
            format!("{p}/{last}")
        })
    }

    fn dir(&mut self, rel: &str) -> Result<String, String> {
        if let Some(c) = self.cache.get(rel) {
            return Ok(c.clone());
        }
        if self.cache.len() > 1_000_000 {
            self.cache.clear();
        }
        let c = self.resolve(rel)?;
        self.cache.insert(rel.to_string(), c.clone());
        Ok(c)
    }

    fn resolve(&self, rel: &str) -> Result<String, String> {
        let mut out: Vec<String> = Vec::new();
        let mut pending: VecDeque<String> = rel
            .split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
        let mut links = 0;
        while let Some(c) = pending.pop_front() {
            match c.as_str() {
                "." => continue,
                ".." => {
                    out.pop();
                    continue;
                }
                _ => {}
            }
            let mut cand = self.root.clone();
            cand.extend(&out);
            cand.push(&c);
            match std::fs::symlink_metadata(&cand) {
                Ok(md) if md.file_type().is_symlink() => {
                    links += 1;
                    if links > MAX_LINKS {
                        return Err(format!("{rel}: too many levels of symbolic links"));
                    }
                    let t = std::fs::read_link(&cand)
                        .map_err(|e| format!("{}: {e}", cand.display()))?;
                    let t = t
                        .to_str()
                        .ok_or_else(|| format!("{}: link target is not UTF-8", cand.display()))?;
                    if t.starts_with('/') {
                        out.clear();
                    }
                    let mut next: VecDeque<String> = t
                        .split('/')
                        .filter(|c| !c.is_empty())
                        .map(str::to_string)
                        .collect();
                    next.extend(pending.drain(..));
                    pending = next;
                }
                _ => out.push(c),
            }
        }
        Ok(out.join("/"))
    }
}

/// Packages other than those in `ignore` (the `.deb`'s own package, and
/// for RoboDR's own pair the other one it replaces) whose files (from
/// `<admindir>/info/*.list`, resolved with `res`) have one of the
/// canonical paths `wanted`: canonical path -> packages.
pub fn owners(
    admindir: &Path,
    res: &mut Resolver,
    wanted: &BTreeSet<String>,
    ignore: &BTreeSet<String>,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let info = admindir.join("info");
    let rd = std::fs::read_dir(&info).map_err(|e| format!("{}: {e}", info.display()))?;
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut total: u64 = 0;
    let mut lists = 0usize;
    for e in rd {
        let e = e.map_err(|e| format!("{}: {e}", info.display()))?;
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(".list") else {
            continue;
        };
        let pkg = stem.split(':').next().unwrap_or(stem);
        if ignore.contains(pkg) {
            continue;
        }
        lists += 1;
        if lists > MAX_LISTS {
            return Err(format!(
                "{}: more than {MAX_LISTS} file lists",
                info.display()
            ));
        }
        let p = e.path();
        let md = std::fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        if !md.file_type().is_file() {
            continue;
        }
        total = total.saturating_add(md.len());
        if total > MAX_LIST_BYTES {
            return Err(format!(
                "{}: the file lists are larger than {MAX_LIST_BYTES} bytes",
                info.display()
            ));
        }
        let b = robodr_release::fsio::read_capped(&p, MAX_LIST_BYTES as usize)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        for line in String::from_utf8_lossy(&b).lines() {
            let l = line.trim_start_matches('/');
            if l.is_empty() || l == "." {
                continue;
            }
            let c = res.canonical(l)?;
            if wanted.contains(&c) {
                out.entry(c).or_default().insert(pkg.to_string());
            }
        }
    }
    Ok(out)
}

/// System directories where a RoboDR file is any entry whose name starts
/// with `robodr` (binaries, units and their drop-ins, tmpfiles, sysusers).
const ROBODR_NAMED_IN: [&str; 12] = [
    "bin",
    "sbin",
    "usr/bin",
    "usr/sbin",
    "lib/systemd/system",
    "usr/lib/systemd/system",
    "etc/systemd/system",
    "usr/lib/tmpfiles.d",
    "usr/lib/sysusers.d",
    "etc/tmpfiles.d",
    "etc/sysusers.d",
    "etc",
];

/// RoboDR's own trees.
const ROBODR_TREES: [&str; 8] = [
    "var/lib/robodr",
    "usr/lib/robodr",
    "usr/libexec/robodr",
    "usr/share/robodr",
    "usr/share/doc/robodr",
    "var/log/robodr",
    "run/robodr",
    "opt/robodr",
];

/// dpkg's and apt's configuration and database: a file there changes how
/// every later package is handled (`force-overwrite` in `dpkg.cfg.d`).
const PACKAGING_TREES: [&str; 3] = ["etc/dpkg", "etc/apt", "var/lib/dpkg"];

fn below(path: &str, tree: &str) -> bool {
    path == tree || path.strip_prefix(tree).is_some_and(|r| r.starts_with('/'))
}

/// Why the canonical path `canon` may not be written by a `.deb`, or
/// `None`. `robodr_own`: the `.deb` is one of RoboDR's own packages (from
/// the designated programme), which may write RoboDR's install paths.
/// `host` is where the path lands on this host; `roots` the agent's own
/// trees (host paths).
pub fn protected(
    canon: &str,
    host: &Path,
    roots: &[(&str, PathBuf)],
    robodr_own: bool,
) -> Option<String> {
    if let Some(t) = PACKAGING_TREES.iter().find(|t| below(canon, t)) {
        return Some(format!(
            "below /{t} (dpkg's or apt's configuration or database)"
        ));
    }
    for (what, r) in roots {
        if host.starts_with(r) {
            return Some(format!("below the agent's {what} ({})", r.display()));
        }
    }
    if !robodr_own {
        if let Some(t) = ROBODR_TREES.iter().find(|t| below(canon, t)) {
            return Some(format!("below RoboDR's /{t}"));
        }
        for d in ROBODR_NAMED_IN {
            if let Some(rest) = canon.strip_prefix(d).and_then(|r| r.strip_prefix('/')) {
                if rest.starts_with("robodr") {
                    return Some(format!("one of RoboDR's files in /{d}"));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, flag: u8, size: u64) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        let s = format!("{size:011o}");
        h[124..135].copy_from_slice(s.as_bytes());
        h[156] = flag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        h
    }

    fn archive(parts: &[([u8; 512], &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        for (h, data) in parts {
            v.extend_from_slice(h);
            v.extend_from_slice(data);
            v.resize(v.len().div_ceil(512) * 512, 0);
        }
        v.extend_from_slice(&[0u8; 1024]);
        v
    }

    #[test]
    fn tar_entries_are_read_strictly() {
        let a = archive(&[
            (header("./", b'5', 0), b""),
            (header("./usr/lib/x/", b'5', 0), b""),
            (header("./usr/lib/x/ok", b'0', 3), b"abc"),
            (header("./lib", b'2', 0), b""),
        ]);
        let e = parse_tar(&mut a.as_slice()).unwrap();
        assert_eq!(
            e,
            vec![
                Entry {
                    path: "usr/lib/x".into(),
                    kind: EntryKind::Dir
                },
                Entry {
                    path: "usr/lib/x/ok".into(),
                    kind: EntryKind::File
                },
                Entry {
                    path: "lib".into(),
                    kind: EntryKind::Symlink
                },
            ]
        );
        // GNU long name.
        let long = format!("./{}/f", "d".repeat(150));
        let a = archive(&[
            (
                header("././@LongLink", b'L', long.len() as u64 + 1),
                format!("{long}\0").as_bytes(),
            ),
            (header("trunc", b'0', 0), b""),
        ]);
        assert_eq!(parse_tar(&mut a.as_slice()).unwrap()[0].path, &long[2..]);
        // A bad checksum, `..`, an unknown type, a symlink with data, a
        // missing end marker.
        let mut bad = header("./a", b'0', 0);
        bad[0] = b'b';
        for a in [
            archive(&[(bad, b"")]),
            archive(&[(header("./a/../b", b'0', 0), b"")]),
            archive(&[(header("./a", b'S', 0), b"")]),
            archive(&[(header("./a", b'2', 3), b"abc")]),
            header("./a", b'0', 0).to_vec(),
        ] {
            assert!(parse_tar(&mut a.as_slice()).is_err());
        }
    }

    #[test]
    fn paths_resolve_through_the_roots_symlinks_only() {
        let d = std::env::temp_dir().join(format!("deliverd-debfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("usr/lib/nav")).unwrap();
        std::os::unix::fs::symlink("usr/lib", d.join("lib")).unwrap();
        std::os::unix::fs::symlink("/usr/lib/nav", d.join("abs")).unwrap();
        std::os::unix::fs::symlink("../../../../usr/lib", d.join("usr/up")).unwrap();
        std::os::unix::fs::symlink("loop", d.join("loop")).unwrap();
        std::os::unix::fs::symlink("/etc", d.join("usr/lib/nav/last")).unwrap();
        let mut r = Resolver::new(&d);
        assert_eq!(r.canonical("lib/nav/ok").unwrap(), "usr/lib/nav/ok");
        assert_eq!(r.canonical("abs/ok").unwrap(), "usr/lib/nav/ok");
        assert_eq!(r.canonical("usr/up/nav/ok").unwrap(), "usr/lib/nav/ok");
        assert_eq!(r.canonical("missing/x/y").unwrap(), "missing/x/y");
        // The last component is not followed.
        assert_eq!(r.canonical("lib/nav/last").unwrap(), "usr/lib/nav/last");
        assert!(r.canonical("loop/x").is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn protected_paths() {
        let roots = [("state_dir", PathBuf::from("/var/lib/robodr/deliverd"))];
        let p = |c: &str, own: bool| protected(c, &Path::new("/").join(c), &roots, own);
        assert!(p("etc/dpkg/dpkg.cfg.d/x", true).is_some());
        assert!(p("etc/apt/apt.conf.d/x", false).is_some());
        assert!(p("var/lib/dpkg/info/nav.list", false).is_some());
        assert!(p("var/lib/robodr/deliverd/state.json", true).is_some());
        assert!(p("usr/bin/robodr-deliverd", false).is_some());
        assert!(p("usr/bin/robodr-deliverd", true).is_none());
        assert!(p("etc/systemd/system/robodr-agentd.service.d/x.conf", false).is_some());
        assert!(p("etc/robodr-delivered/x", false).is_some());
        assert!(p("usr/lib/nav/ok", false).is_none());
        assert!(p("etc/dpkgx", false).is_none());
        assert!(p("usr/bin/nav", false).is_none());
    }
}
