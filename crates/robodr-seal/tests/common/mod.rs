//! Shared helpers: a software TPM (swtpm) per test, a Tang server, temp
//! directories, plaintext scanning.
#![allow(dead_code)]

use robodr_seal::tpm::{Tpm, TpmConfig};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// A fresh directory under the system temp dir.
pub fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("robodr-seal-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
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

pub fn port() -> u16 {
    let base: u16 = std::env::var("ROBODR_SWTPM_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(40_000 + (std::process::id() % 5000) as u16 * 4);
    base + NEXT_PORT.fetch_add(2, Ordering::SeqCst)
}

fn wait_port(port: u16, what: &str) {
    let t0 = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "{what} did not start"
        );
        std::thread::sleep(Duration::from_millis(30));
    }
}

/// A running software TPM, killed on drop. Its state directory survives
/// [`SwTpm::restart`] (a reboot: PCRs reset, NV kept).
pub struct SwTpm {
    child: Child,
    pub port: u16,
    pub state: PathBuf,
}

impl SwTpm {
    pub fn start(state: &Path) -> Self {
        std::fs::create_dir_all(state).unwrap();
        // A port may be taken by another process: swtpm then exits at
        // once, and the next pair of ports is tried.
        for _ in 0..8 {
            let port = port();
            let mut child = Self::spawn(state, port);
            let t0 = Instant::now();
            loop {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Self {
                        child,
                        port,
                        state: state.to_path_buf(),
                    };
                }
                if child.try_wait().unwrap().is_some() || t0.elapsed() > Duration::from_secs(10) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        }
        panic!("swtpm did not start");
    }

    fn spawn(state: &Path, port: u16) -> Child {
        Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--server",
                &format!("type=tcp,port={port}"),
                "--ctrl",
                &format!("type=tcp,port={}", port + 1),
                "--tpmstate",
                &format!("dir={}", state.display()),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("swtpm")
    }

    /// Power-cycle: PCRs back to their reset values, NV and keys kept.
    pub fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The port may linger briefly.
        std::thread::sleep(Duration::from_millis(200));
        self.child = Self::spawn(&self.state, self.port);
        wait_port(self.port, "swtpm");
    }

    pub fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    pub fn cfg(&self) -> TpmConfig {
        TpmConfig {
            tcti: self.tcti(),
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
        let out = self.state.join(format!("pcrs-{}.bin", port()));
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
        let c = Command::new("/usr/libexec/tangd")
            .args(["-l", "-p", &self.port.to_string()])
            .arg(&self.db)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("tangd");
        self.child = Some(c);
        wait_port(self.port, "tangd");
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
