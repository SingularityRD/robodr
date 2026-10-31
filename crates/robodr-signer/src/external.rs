//! The external signer command (`robodr-signer/v1` protocol; see the
//! crate docs): run it, hand it the message on stdin, read one Ed25519
//! signature from stdout, under a deadline.
//!
//! The caller ([`crate::KeySigner`]) verifies every signature against the
//! pinned public key; this module only runs the command and parses its
//! output.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use robodr_blackbox::sign_ed25519::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// `PATH` the command runs with (the caller's `PATH` is not inherited).
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Default deadline: long enough for a touch (or a slow network HSM).
pub const DEFAULT_TIMEOUT_MS: u64 = 120_000;
/// Longest deadline a signer file may set.
pub const MAX_TIMEOUT_MS: u64 = 600_000;
/// Most stdout bytes read from the command (a hex signature is 129).
pub const MAX_OUTPUT_BYTES: usize = 4096;
/// Most arguments in `command`.
pub const MAX_ARGS: usize = 64;
/// Longest single argument.
pub const MAX_ARG_LEN: usize = 4096;
/// Most `pass_env` names.
pub const MAX_PASS_ENV: usize = 32;

/// Environment names the protocol sets itself or that change how the
/// command is loaded; `pass_env` cannot name them.
const RESERVED_ENV: &[&str] = &["PATH", "LC_ALL", "IFS", "ENV", "BASH_ENV", "SHELLOPTS"];

/// A validated external signer: command, pinned key, environment, deadline.
#[derive(Debug, Clone)]
pub struct ExternalSigner {
    key_id: String,
    public: [u8; PUBLIC_KEY_LEN],
    program: PathBuf,
    args: Vec<String>,
    pass_env: Vec<String>,
    timeout: Duration,
}

impl ExternalSigner {
    /// Check the pieces of a signer file. `command[0]` must be an absolute
    /// path that passes [`check_trusted_executable`] (checked again before
    /// every run).
    pub fn new(
        key_id: String,
        public: [u8; PUBLIC_KEY_LEN],
        command: Vec<String>,
        pass_env: Vec<String>,
        timeout_ms: Option<u64>,
    ) -> Result<Self, String> {
        let mut it = command.into_iter();
        let program = PathBuf::from(it.next().ok_or("signer file: command is empty")?);
        let args: Vec<String> = it.collect();
        if args.len() >= MAX_ARGS {
            return Err(format!(
                "signer file: command has more than {MAX_ARGS} parts"
            ));
        }
        for a in std::iter::once(program.to_string_lossy().as_ref())
            .chain(args.iter().map(String::as_str))
        {
            if a.len() > MAX_ARG_LEN || a.contains('\0') {
                return Err(format!(
                    "signer file: a command part is longer than {MAX_ARG_LEN} bytes or holds NUL"
                ));
            }
        }
        if !program.is_absolute() {
            return Err(format!(
                "signer file: command[0] {:?} must be an absolute path",
                program.display().to_string()
            ));
        }
        check_trusted_executable(&program)?;
        if pass_env.len() > MAX_PASS_ENV {
            return Err(format!(
                "signer file: more than {MAX_PASS_ENV} pass_env names"
            ));
        }
        for n in &pass_env {
            if !is_env_name(n)
                || RESERVED_ENV.contains(&n.as_str())
                || n.starts_with("LD_")
                || n.starts_with("ROBODR_SIGNER_")
            {
                return Err(format!(
                    "signer file: pass_env {n:?} is not allowed ([A-Z_][A-Z0-9_]*, not PATH, \
                     LD_*, ROBODR_SIGNER_* or a shell start-up variable)"
                ));
            }
        }
        let ms = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        if ms == 0 || ms > MAX_TIMEOUT_MS {
            return Err(format!(
                "signer file: timeout_ms must be 1..={MAX_TIMEOUT_MS}, got {ms}"
            ));
        }
        Ok(Self {
            key_id,
            public,
            program,
            args,
            pass_env,
            timeout: Duration::from_millis(ms),
        })
    }

    /// The pinned key id.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The pinned public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// Run the command once and return the 64-byte signature it printed
    /// (not yet verified: [`crate::KeySigner`] does that).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let program = check_trusted_executable(&self.program)?;
        let what = format!("external signer {}", self.program.display());
        let mut cmd = Command::new(&program);
        cmd.args(&self.args)
            .env_clear()
            .env("PATH", SAFE_PATH)
            .env("LC_ALL", "C")
            .env("ROBODR_SIGNER_PROTOCOL", "1")
            .env("ROBODR_SIGNER_ALGORITHM", "ed25519")
            .env("ROBODR_SIGNER_KEY_ID", &self.key_id)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // Its own process group (pgid = its pid), so that a timeout
            // kills everything it started (the adapter shell *and* the
            // pkcs11-tool it runs), not only the direct child. The price:
            // it is not in the terminal's foreground group, so it cannot
            // read the terminal (PINs come through `pass_env` or a file).
            .process_group(0);
        for n in &self.pass_env {
            if let Some(v) = std::env::var_os(n) {
                cmd.env(n, v);
            }
        }
        let mut child = cmd.spawn().map_err(|e| format!("{what}: {e}"))?;
        let deadline = Instant::now() + self.timeout;

        // Writer and reader run on their own threads so a large message
        // cannot deadlock against a full stdout pipe, and so a command that
        // never reads or never closes stdout cannot block past the
        // deadline. They are detached: a background process that keeps a
        // pipe open only keeps its thread, never the caller.
        if let Some(mut stdin) = child.stdin.take() {
            let msg = message.to_vec();
            std::thread::spawn(move || {
                // A signer that stops reading early is caught by the
                // signature check; the write error itself is not fatal.
                let _ = stdin.write_all(&msg);
            });
        }
        let (tx, rx) = mpsc::channel();
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let r = stdout
                    .take(MAX_OUTPUT_BYTES as u64 + 1)
                    .read_to_end(&mut out)
                    .map(|_| out);
                let _ = tx.send(r);
            });
        }

        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() >= deadline => {
                    // The group first, while the unreaped child still
                    // holds its id; then the child itself, should the
                    // group kill have failed.
                    kill_process_group(child.id());
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{what}: no answer within {} ms (killed)",
                        self.timeout.as_millis()
                    ));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(format!("{what}: {e}")),
            }
        };
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(500));
        let out = match rx.recv_timeout(wait) {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => return Err(format!("{what}: reading its output: {e}")),
            Err(_) => {
                // Whatever it left behind is in its process group (the
                // id stays reserved while the group has members).
                kill_process_group(child.id());
                return Err(format!(
                    "{what}: exited but its stdout stayed open (a background process?)"
                ));
            }
        };
        // Checked before the exit status: a flood stopped by the cap ends
        // the command with SIGPIPE, and the flood is the error to report.
        if out.len() > MAX_OUTPUT_BYTES {
            return Err(format!(
                "{what}: more than {MAX_OUTPUT_BYTES} bytes on stdout"
            ));
        }
        if !status.success() {
            return Err(format!("{what}: failed ({status})"));
        }
        parse_signature(&out).map_err(|e| format!("{what}: {e}"))
    }
}

/// SIGKILL to process group `pgid` (the signer command's, see
/// [`ExternalSigner::sign`]). This crate has no `unsafe` (no `kill(2)`
/// binding), so the shell's `kill` builtin sends it. Best effort: a group
/// that is already gone is not an error.
fn kill_process_group(pgid: u32) {
    let _ = Command::new("/bin/sh")
        .args(["-c", "kill -s KILL -- \"-$1\" 2>/dev/null", "sh"])
        .arg(pgid.to_string())
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// `[A-Z_][A-Z0-9_]*`, at most 64 bytes.
fn is_env_name(n: &str) -> bool {
    let mut b = n.bytes();
    n.len() <= 64
        && b.next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == b'_')
        && b.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// The command's stdout: exactly 64 raw bytes, or 128 hex digits followed
/// by optional ASCII whitespace.
pub fn parse_signature(out: &[u8]) -> Result<Vec<u8>, String> {
    if out.len() > MAX_OUTPUT_BYTES {
        return Err(format!("more than {MAX_OUTPUT_BYTES} bytes on stdout"));
    }
    if out.len() == SIGNATURE_LEN {
        return Ok(out.to_vec());
    }
    let text = std::str::from_utf8(out)
        .map_err(|_| "stdout is neither 64 raw bytes nor 128 hex digits".to_string())?;
    let hex = text.trim_end_matches(|c: char| c.is_ascii_whitespace());
    match robodr_blackbox::crypto::from_hex(hex) {
        Some(b) if b.len() == SIGNATURE_LEN => Ok(b),
        _ => Err(format!(
            "stdout is neither 64 raw bytes nor 128 hex digits ({} bytes)",
            out.len()
        )),
    }
}

/// Resolve `program` (symlinks followed) and check that the file is a
/// regular executable and that it and **every** directory above it are
/// owned by root or the effective user and not group/other-writable:
/// whoever could replace any of them would choose what runs with the
/// operator's signing rights. Returns the resolved path, which is what is
/// executed.
pub fn check_trusted_executable(program: &Path) -> Result<PathBuf, String> {
    let real = std::fs::canonicalize(program)
        .map_err(|e| format!("signer command {}: {e}", program.display()))?;
    let md =
        std::fs::metadata(&real).map_err(|e| format!("signer command {}: {e}", real.display()))?;
    if !md.is_file() || md.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "signer command {}: not an executable regular file",
            real.display()
        ));
    }
    crate::check_owner_mode(
        md.uid(),
        md.permissions().mode(),
        &format!("signer command {}", real.display()),
    )?;
    let mut dir = real.parent();
    while let Some(d) = dir {
        let m = std::fs::metadata(d).map_err(|e| format!("{}: {e}", d.display()))?;
        crate::check_owner_mode(
            m.uid(),
            m.permissions().mode(),
            &format!("directory {} of the signer command", d.display()),
        )?;
        dir = d.parent();
    }
    Ok(real)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_output_forms() {
        let raw = [7u8; 64];
        assert_eq!(parse_signature(&raw).unwrap(), raw.to_vec());
        let hex = robodr_blackbox::crypto::to_hex(&raw);
        assert_eq!(parse_signature(hex.as_bytes()).unwrap(), raw.to_vec());
        assert_eq!(
            parse_signature(format!("{hex}\n").as_bytes()).unwrap(),
            raw.to_vec()
        );
        assert_eq!(
            parse_signature(hex.to_uppercase().as_bytes()).unwrap(),
            raw.to_vec()
        );
        // Leading noise, a short signature, two signatures, too much output.
        assert!(parse_signature(format!("sig: {hex}").as_bytes()).is_err());
        assert!(parse_signature(&hex.as_bytes()[..126]).is_err());
        assert!(parse_signature(format!("{hex}\n{hex}\n").as_bytes()).is_err());
        assert!(parse_signature(&[b'a'; MAX_OUTPUT_BYTES + 1]).is_err());
        assert!(parse_signature(&[0xff; 63]).is_err());
        assert!(parse_signature(b"").is_err());
    }

    #[test]
    fn env_names() {
        assert!(is_env_name("ROBODR_PKCS11_PIN"));
        assert!(is_env_name("_X1"));
        assert!(!is_env_name("1X"));
        assert!(!is_env_name("x"));
        assert!(!is_env_name("A=B"));
        assert!(!is_env_name(&"A".repeat(65)));
    }

    #[test]
    fn system_binaries_are_trusted_and_relative_or_missing_are_not() {
        // /bin/true is root-owned under root-owned, non-writable dirs on
        // every supported build host.
        assert!(check_trusted_executable(Path::new("/bin/true")).is_ok());
        assert!(check_trusted_executable(Path::new("/nonexistent/signer")).is_err());
        // A directory is not an executable file.
        assert!(check_trusted_executable(Path::new("/usr/bin")).is_err());
        // /tmp is world-writable (sticky or not): never trusted.
        let p = std::env::temp_dir().join(format!("robodr-signer-ut-{}", std::process::id()));
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        if std::env::temp_dir() == Path::new("/tmp") {
            assert!(check_trusted_executable(&p).is_err());
        }
        let _ = std::fs::remove_file(&p);
    }
}
