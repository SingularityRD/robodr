//! Shared helpers: a software TPM (swtpm) per test, a Tang server, temp
//! directories, plaintext scanning.
#![allow(dead_code)]

use robodr_seal::tpm::{Tpm, TpmConfig};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// A fresh directory under the system temp dir, removed on drop (kept
/// with `ROBODR_KEEP_TMP=1` for inspection).
pub struct Tmp(PathBuf);

impl std::ops::Deref for Tmp {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Tmp {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        if std::env::var("ROBODR_KEEP_TMP").as_deref() != Ok("1") {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

pub fn tmp(name: &str) -> Tmp {
    let d = std::env::temp_dir().join(format!("robodr-seal-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Tmp(d)
}

pub fn have(prog: &str) -> bool {
    ["/usr/bin", "/usr/sbin", "/usr/libexec"]
        .iter()
        .any(|d| Path::new(d).join(prog).exists())
}

/// `ROBODR_SWTPM=1` and the tools present, else a printed skip.
pub fn swtpm_enabled(test: &str) -> bool {
    if std::env::var("ROBODR_SWTPM").as_deref() != Ok("1") {
        eprintln!("{test}: skipped: set ROBODR_SWTPM=1 (needs swtpm and tpm2-tools)");
        return false;
    }
    assert!(
        have("swtpm") && have("tpm2_createprimary"),
        "ROBODR_SWTPM=1 but swtpm / tpm2-tools are missing"
    );
    true
}

/// `ROBODR_TANG=1` and tangd, clevis, cryptsetup present.
pub fn tang_enabled(test: &str) -> bool {
    if std::env::var("ROBODR_TANG").as_deref() != Ok("1") {
        eprintln!("{test}: skipped: set ROBODR_TANG=1 (needs tang, clevis, cryptsetup)");
        return false;
    }
    assert!(
        have("tangd") && have("clevis") && have("cryptsetup"),
        "ROBODR_TANG=1 but tangd / clevis / cryptsetup are missing"
    );
    true
}

/// `cryptsetup` present (LUKS2 headers on image files; no device-mapper).
pub fn cryptsetup_enabled(test: &str) -> bool {
    if !have("cryptsetup") {
        eprintln!("{test}: skipped: cryptsetup not installed");
        return false;
    }
    true
}

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);
static PCRS_N: AtomicU16 = AtomicU16::new(0);

/// A TCP port for a test server (swtpm, Tang). With `ROBODR_SWTPM_PORT`
/// set, the next one counting up from it (two apart); otherwise one the
/// kernel reports free right now (bind to port 0, then release).
///
/// It used to be `40_000 + pid % 5000 * 4` counting up by two: the test
/// binaries of another process (pid one higher, base four higher) walked
/// the same ports, so with two TPM test binaries running at once swtpm
/// failed with "Address already in use" on all eight attempts ("swtpm did
/// not start", T24 of docs/SALES-READINESS.md;
/// `two_processes_get_disjoint_ports` below).
pub fn port() -> u16 {
    if let Some(base) = std::env::var("ROBODR_SWTPM_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
    {
        return base + NEXT_PORT.fetch_add(2, Ordering::SeqCst);
    }
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a free loopback port")
}

/// Two consecutive free ports `(p, p + 1)`: swtpm's server and control
/// channels (the TSS `swtpm` TCTI reaches the control channel at the
/// server port + 1). With `ROBODR_SWTPM_PORT` set, the next pair counting
/// up from it.
pub fn port_pair() -> (u16, u16) {
    if std::env::var("ROBODR_SWTPM_PORT").is_ok() {
        let p = port();
        return (p, p + 1);
    }
    for _ in 0..64 {
        let Ok(a) = std::net::TcpListener::bind(("127.0.0.1", 0)) else {
            continue;
        };
        let Some(p) = a.local_addr().ok().map(|x| x.port()) else {
            continue;
        };
        if p < u16::MAX && std::net::TcpListener::bind(("127.0.0.1", p + 1)).is_ok() {
            return (p, p + 1);
        }
    }
    panic!("no two consecutive free loopback ports");
}

/// Something listens on `port` (not a TCP self-connection: a connect to a
/// free port in the ephemeral range can be answered by the connecting
/// socket itself).
pub fn listening(port: u16) -> bool {
    std::net::TcpStream::connect(("127.0.0.1", port))
        .is_ok_and(|s| s.local_addr().ok() != s.peer_addr().ok())
}

/// The inodes of the sockets listening on TCP `port` (any address, IPv4
/// or IPv6), from `/proc/net/tcp{,6}` of this network namespace.
fn listening_inodes(port: u16) -> Vec<String> {
    let want = format!("{port:04X}");
    let mut out = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(st), Some(inode)) = (f.get(1), f.get(3), f.get(9)) else {
                continue;
            };
            // st 0A: TCP_LISTEN.
            if *st == "0A" && local.rsplit(':').next() == Some(want.as_str()) {
                out.push((*inode).to_string());
            }
        }
    }
    out
}

/// Process `pid` itself holds a socket listening on `port`: not merely
/// "something answers on the port" (another process may have taken it
/// between [`port_pair`] releasing its probe sockets and swtpm binding).
pub fn listens_on(pid: u32, port: u16) -> bool {
    let inodes = listening_inodes(port);
    if inodes.is_empty() {
        return false;
    }
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    fds.filter_map(Result::ok).any(|e| {
        std::fs::read_link(e.path()).is_ok_and(|l| {
            let l = l.to_string_lossy();
            inodes.iter().any(|i| l == format!("socket:[{i}]"))
        })
    })
}

/// Wait until the swtpm `child` itself listens on both of its ports.
/// `Err` (with the reason) when it exits first or after 10 s.
fn wait_owned(child: &mut Child, port: u16, ctrl: u16) -> Result<(), String> {
    let t0 = Instant::now();
    loop {
        if listens_on(child.id(), port) && listens_on(child.id(), ctrl) {
            return Ok(());
        }
        if let Some(st) = child.try_wait().unwrap() {
            return Err(format!(
                "swtpm exited ({st}) before listening on {port}/{ctrl}"
            ));
        }
        if t0.elapsed() > Duration::from_secs(10) {
            return Err(format!("swtpm did not listen on {port}/{ctrl} within 10 s"));
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}

fn wait_port(port: u16, what: &str) {
    let t0 = Instant::now();
    while !listening(port) {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "{what} did not start"
        );
        std::thread::sleep(Duration::from_millis(30));
    }
}

/// The owner and lockout authorization of every test TPM.
pub const OWNER_AUTH: &[u8] = b"test-owner-auth";

/// A running software TPM, killed on drop. Its state directory survives
/// [`SwTpm::restart`] (a reboot: PCRs reset, NV kept).
pub struct SwTpm {
    child: Child,
    pub port: u16,
    /// The control channel's port.
    ctrl: u16,
    pub state: PathBuf,
}

impl SwTpm {
    pub fn start(state: &Path) -> Self {
        std::fs::create_dir_all(state).unwrap();
        // A port may be taken by another process: swtpm then exits, and
        // the next pair of ports is tried. Ready means our swtpm process
        // holds both listening sockets ([`listens_on`]), so another
        // listener on the port can never pass for it.
        for _ in 0..8 {
            let (port, ctrl) = port_pair();
            let mut child = Self::spawn(state, port, ctrl);
            if wait_owned(&mut child, port, ctrl).is_ok() {
                return Self {
                    child,
                    port,
                    ctrl,
                    state: state.to_path_buf(),
                };
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        let log = std::fs::read_to_string(state.join("swtpm.log")).unwrap_or_default();
        let tail: Vec<&str> = log.lines().rev().take(8).collect();
        panic!("swtpm did not start (swtpm.log, newest first: {tail:?})");
    }

    fn spawn(state: &Path, port: u16, ctrl: u16) -> Child {
        Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--server",
                &format!("type=tcp,port={port}"),
                "--ctrl",
                &format!("type=tcp,port={ctrl}"),
                "--tpmstate",
                &format!("dir={}", state.display()),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .stdout(Stdio::null())
            .stderr(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(state.join("swtpm.log"))
                    .map(Stdio::from)
                    .unwrap_or_else(|_| Stdio::null()),
            )
            .spawn()
            .expect("swtpm")
    }

    /// Set the owner and lockout authorizations ([`OWNER_AUTH`]), as a
    /// site does before provisioning (OPERATIONS §12.1).
    pub fn take_ownership(&self) {
        for h in ["o", "l"] {
            let o = self.tool("tpm2_changeauth", &["-c", h, "file:-"], Some(OWNER_AUTH));
            assert!(o.ok(), "{}", o.error_line());
        }
    }

    /// Take ownership and provision RoboDR's indices and SRK.
    pub fn provision(&self) -> robodr_seal::tpm::Provisioned {
        self.take_ownership();
        self.tpm().provision(OWNER_AUTH).unwrap()
    }

    /// Power-cycle: PCRs back to their reset values, NV and keys kept.
    pub fn restart(&mut self) {
        // An orderly shutdown first: a TPM that loses power without one
        // counts it against dictionary-attack protection, and a few in a
        // row lock out the (DA-protected) SRK. `-c`: Shutdown(CLEAR), as
        // the kernel sends at reboot, so the next start is a TPM Reset.
        let _ = self.tool("tpm2_shutdown", &["-c"], None);
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The port may linger briefly.
        std::thread::sleep(Duration::from_millis(200));
        self.child = Self::spawn(&self.state, self.port, self.ctrl);
        // Same ports (the TCTI and work directory derive from them): our
        // swtpm must hold them again, not whatever took them meanwhile.
        if let Err(why) = wait_owned(&mut self.child, self.port, self.ctrl) {
            let log = std::fs::read_to_string(self.state.join("swtpm.log")).unwrap_or_default();
            let tail: Vec<&str> = log.lines().rev().take(8).collect();
            panic!("swtpm did not restart: {why} (swtpm.log, newest first: {tail:?})");
        }
    }

    pub fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    /// The TPM work directory of this test (tmpfs: `/dev/shm`).
    pub fn work_dir(&self) -> PathBuf {
        PathBuf::from(format!("/dev/shm/robodr-seal-it-work-{}", self.port))
    }

    pub fn cfg(&self) -> TpmConfig {
        TpmConfig {
            tcti: self.tcti(),
            work_dir: self.work_dir(),
            ..TpmConfig::default()
        }
    }

    pub fn tpm(&self) -> Tpm {
        Tpm::new(self.cfg(), Box::new(robodr_seal::cmd::System)).unwrap()
    }

    /// Run a tpm2 tool directly (test setup and attacks).
    pub fn tool(
        &self,
        name: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> robodr_seal::cmd::Output {
        let t = self.tpm();
        let o = t
            .run(
                name,
                &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                stdin,
            )
            .unwrap();
        let _ = t.run("tpm2_flushcontext", &["-t".into()], None);
        o
    }

    /// Current SHA-256 values of `pcrs`.
    pub fn pcrs(&self, pcrs: &[u8]) -> Vec<(u8, [u8; 32])> {
        let list: Vec<String> = pcrs.iter().map(|p| p.to_string()).collect();
        let out = self.state.join(format!(
            "pcrs-{}.bin",
            PCRS_N.fetch_add(1, Ordering::SeqCst)
        ));
        let o = self.tool(
            "tpm2_pcrread",
            &[
                &format!("sha256:{}", list.join(",")),
                "-o",
                out.to_str().unwrap(),
            ],
            None,
        );
        assert!(o.ok(), "{}", o.error_line());
        let b = std::fs::read(&out).unwrap();
        let _ = std::fs::remove_file(&out);
        assert_eq!(b.len(), 32 * pcrs.len());
        pcrs.iter()
            .enumerate()
            .map(|(i, p)| {
                let mut v = [0u8; 32];
                v.copy_from_slice(&b[i * 32..i * 32 + 32]);
                (*p, v)
            })
            .collect()
    }

    /// Extend a PCR (a changed boot measurement).
    pub fn extend(&self, pcr: u8, digest: [u8; 32]) {
        let o = self.tool(
            "tpm2_pcrextend",
            &[&format!("{pcr}:sha256={}", robodr_seal::to_hex(&digest))],
            None,
        );
        assert!(o.ok(), "{}", o.error_line());
    }
}

impl Drop for SwTpm {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.work_dir());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Whether a Tang server answers `GET /adv` on `port` with a JWS.
fn tang_adv(port: u16) -> bool {
    use std::io::{Read, Write};
    let Ok(mut c) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
    if c.write_all(b"GET /adv HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut b = Vec::new();
    let _ = c.take(1 << 16).read_to_end(&mut b);
    let t = String::from_utf8_lossy(&b);
    t.starts_with("HTTP/1.") && t.contains(" 200 ") && t.contains("\"payload\"")
}

/// A Tang server (tangd -l), killed on drop.
pub struct Tang {
    child: Option<Child>,
    pub port: u16,
    pub db: PathBuf,
    pub thp: String,
}

impl Tang {
    pub fn start(dir: &Path) -> Self {
        let db = dir.join("tang-db");
        std::fs::create_dir_all(&db).unwrap();
        let st = Command::new("/usr/libexec/tangd-keygen")
            .arg(&db)
            .status()
            .unwrap();
        assert!(st.success());
        let port = port();
        let mut t = Self {
            child: None,
            port,
            db,
            thp: String::new(),
        };
        t.up();
        let o = Command::new("tang-show-keys")
            .arg(port.to_string())
            .output()
            .unwrap();
        t.thp = String::from_utf8_lossy(&o.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        assert!(!t.thp.is_empty(), "no Tang thumbprint");
        t
    }

    pub fn up(&mut self) {
        if self.child.is_some() {
            return;
        }
        // After a `down`, the port may still be held for a moment (tangd
        // then exits at once): respawn until it listens.
        let t0 = Instant::now();
        loop {
            let mut c = Command::new("/usr/libexec/tangd")
                .args(["-l", "-p", &self.port.to_string()])
                .arg(&self.db)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("tangd");
            let t1 = Instant::now();
            while t1.elapsed() < Duration::from_secs(10) {
                // Our tangd, not another process on the port: alive, and
                // /adv answers with a JWS.
                if c.try_wait().unwrap().is_some() {
                    break;
                }
                if tang_adv(self.port) {
                    self.child = Some(c);
                    return;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            let _ = c.kill();
            let _ = c.wait();
            assert!(
                t0.elapsed() < Duration::from_secs(120),
                "tangd did not start"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    pub fn down(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for Tang {
    fn drop(&mut self) {
        self.down();
    }
}

/// Every regular file under `root` (no symlinks followed).
pub fn files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                out.push(e.path());
            }
        }
    }
    out
}

/// Files under `roots` that contain `needle`.
pub fn files_containing(roots: &[&Path], needle: &[u8]) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    for r in roots {
        for f in files(r) {
            let b = std::fs::read(&f).unwrap_or_default();
            if b.windows(needle.len()).any(|w| w == needle) {
                hits.push(f);
            }
        }
    }
    hits
}

/// Build an (unsigned) sealed RPK directory of `files` (each one chunk
/// or more, cut at 4 MiB) for `platform` under `parent`, kind `model`.
/// Returns the directory, the manifest and its digest.
pub fn sealed_rpk(
    parent: &Path,
    name: &str,
    platform: &str,
    files: &[(&str, Vec<u8>)],
    depots: &[[u8; 32]],
) -> (PathBuf, robodr_pkg::rpk::Manifest, String) {
    use robodr_pkg::common::{sha256_hex, to_canonical};
    use robodr_pkg::rpk::*;
    let sealer = robodr_seal::rpk::Sealer::new().unwrap();
    let mut sorted = files.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let dir = parent.join(dir_name(name, 3, Arch::All));
    std::fs::create_dir_all(dir.join(CHUNKS_DIR)).unwrap();
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut per_file = Vec::new();
    let mut content = Vec::new();
    for (fi, (path, bytes)) in sorted.iter().enumerate() {
        let pieces: Vec<&[u8]> = bytes.chunks(CHUNK_SIZE as usize).collect();
        let mut d = sealer.file_digest();
        let mut hs = Vec::new();
        for (pos, p) in pieces.iter().enumerate() {
            let c = sealer
                .seal_piece(fi as u32, pos as u32, pieces.len() as u32, p)
                .unwrap();
            d.update(p);
            let h = sha256_hex(&c);
            std::fs::write(dir.join(CHUNKS_DIR).join(&h), &c).unwrap();
            chunks.push(Chunk {
                sha256: h.clone(),
                size: c.len() as u64,
            });
            hs.push(h);
        }
        per_file.push(hs);
        content.push(ContentFile {
            path: (*path).into(),
            mode: 0o640,
            size: bytes.len() as u64,
            sha256: robodr_seal::to_hex(&d.finalize()),
            chunks: vec![],
        });
    }
    chunks.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    for (c, hs) in content.iter_mut().zip(&per_file) {
        c.chunks = hs
            .iter()
            .map(|h| chunks.iter().position(|x| &x.sha256 == h).unwrap() as u32)
            .collect();
    }
    let m = Manifest {
        format: RPK_FORMAT.into(),
        name: name.into(),
        version: Version {
            serial: 3,
            display: "3".into(),
        },
        kind: Kind::Model,
        platform: platform.into(),
        arch: Arch::All,
        hw_compat: vec![],
        requires: vec![],
        conflicts: vec![],
        security_floor: 1,
        confidentiality: Confidentiality::Sealed,
        content,
        chunks,
        sbom: None,
        install: Install {
            allow_maintainer_scripts: false,
            requires_operator_present: false,
        },
        health: vec![],
        expires_at: None,
        seal: Some(sealer.seal_member(depots).unwrap()),
    };
    let bytes = to_canonical(&m).unwrap();
    let parsed = parse_manifest(&bytes).unwrap();
    std::fs::write(dir.join(MANIFEST_FILE), &bytes).unwrap();
    (dir, parsed, rpk_digest(&bytes))
}

/// Open every sealed file of `m` from `rpk_dir` with `ck` into `out`.
pub fn install_plaintext(
    ck: &robodr_seal::chunk::ContentKey,
    m: &robodr_pkg::rpk::Manifest,
    rpk_dir: &Path,
    out: &Path,
) -> Result<(), robodr_seal::SealError> {
    std::fs::create_dir_all(out).unwrap();
    for (i, f) in m.content.iter().enumerate() {
        let mut buf = Vec::new();
        robodr_seal::rpk::open_file(
            ck,
            m,
            i,
            &mut |c| {
                std::fs::read(rpk_dir.join("chunks").join(&c.sha256)).map_err(|e| {
                    robodr_seal::SealError::new(robodr_seal::ErrorKind::Io, e.to_string())
                })
            },
            &mut |p| {
                buf.extend_from_slice(p);
                Ok(())
            },
        )?;
        std::fs::write(out.join(&f.path), &buf).unwrap();
    }
    Ok(())
}
