//! A [`HeadAnchor`] backed by a TPM 2.0 NV monotonic counter
//! ([`TpmNvCounterAnchor`]), driven through `tpm2-tools`.
//!
//! # What the TPM gives, and what it does not
//!
//! A TPM NV index of type *counter* (`TPM_NT_COUNTER`) holds a 64-bit value
//! that can only be incremented by one (`TPM2_NV_Increment`) and can never
//! be set or decreased. Even an index that is undefined and redefined starts,
//! at its first increment, at the highest value any counter on that TPM has
//! ever held. Nothing on the unit, root included, can wind it back. It holds
//! no `seq`, no chain id and no hash, and it cannot be set to a `seq`.
//!
//! # Mapping: the counter counts marks
//!
//! Every [`HeadAnchor::advance`] (one per high-water mark, already fsynced,
//! with strictly increasing `seq`) increments the counter at most once, then
//! writes a small **sidecar** file binding
//! `(nv_index, counter value c, chain_id, seq s, hash)`, **signed with the
//! recorder's key** under a domain-separated message ([`sidecar_message`]).
//! At open, [`HeadAnchor::current`] reads the counter `T` and the sidecar:
//!
//! - `T == c`: the sidecar is the newest mark the TPM knows of; its full
//!   position (chain, seq, hash) is returned, so the recorder both detects a
//!   cut below it (`TruncationDetected`) and refuses a rewritten history
//!   (another hash at that seq).
//! - `T > c`: `T - c` increments happened after this sidecar was written,
//!   each inside an `advance` of a later, already durable mark with a larger
//!   `seq` than every earlier one, so the head reached at least
//!   `s + (T - c)`. That lower bound is returned (`chain_id` and `hash`
//!   unknown); if the log's head is below it, the recorder reports
//!   `TruncationDetected`. This is the case of an attacker who restored an
//!   older, authentic sidecar together with a cut log tail.
//! - `T < c`: the authentic sidecar names a count the TPM never reached: the
//!   TPM was cleared or replaced. Error (see below).
//!
//! **Why the sidecar is signed.** The attacker this anchor is for can write
//! the unit. An unsigned sidecar could be edited to claim `c = T` and
//! `(seq, hash)` of any record still in a cut log (records are readable):
//! the open would then look clean, and the truncation would be hidden. With
//! the signature the attacker can only present sidecars the recorder wrote,
//! and an older one is exposed by the counter. (Editing an unsigned sidecar
//! to a *higher* seq would only raise a false alarm; the hiding direction is
//! what forces the signature.)
//!
//! **What cannot be bounded** (errors: counted by the recorder as anchor
//! failures and named in the signed `Resume` record's `rejected_state`, so
//! they are on the record, but not classified as truncation):
//!
//! - the counter is written but the sidecar is missing, unreadable, forged,
//!   signed by another key or for another index. `T` alone is not a bound:
//!   the counter's starting value is the TPM's highest count ever (unknown,
//!   possibly large), and storing that base on the unit would be as
//!   forgeable as the sidecar. The honest recorder never loses the sidecar
//!   (atomic replace) except by a crash between the very first increment and
//!   the first sidecar write;
//! - the index is unwritten while a sidecar exists: the index was undefined
//!   and redefined, or the TPM cleared (both need owner/lockout
//!   authorization, see the provisioning notes in `docs/OPERATIONS.md`);
//! - `T < c`, as above; the index is not a counter; the TPM or the tools
//!   fail or time out.
//!
//! An index that is defined but unwritten with no sidecar is a fresh anchor
//! (`Ok(None)`).
//!
//! # Increment rate (NV endurance)
//!
//! A non-orderly counter increment is an NV write. TPM vendors specify NV
//! write endurance and may rate-limit NV writes (`TPM_RC_NV_RATE`); check the
//! datasheet of the part you deploy. To keep the write rate bounded, at most
//! one increment happens per [`TpmAnchorConfig::min_increment_interval`]
//! (default 60 s: about 0.53 million increments a year); marks in between
//! only rewrite the sidecar with the current count. Skipping never lowers
//! anything: it only widens the window in which an attacker who restores an
//! older sidecar *with the same count* goes unnoticed, to at most that
//! interval of recording (plus what `head.json` already leaves open). An
//! orderly counter (`TPMA_NV_ORDERLY`) would avoid NV wear, but jumps
//! forward after every power loss, which would read as a truncation; the
//! provisioning command does not set it.
//!
//! # Limits
//!
//! Rollback and truncation become *detectable*, not prevented. Root on the
//! unit can still use the index (increment it: that can only cause a false
//! truncation report), and with the owner/lockout authorization it can
//! undefine it or clear the TPM (reported, see above). Tested against a
//! software TPM (swtpm), not yet on a hardware TPM.

use crate::crypto::{from_hex, hash_from_hex, to_hex};
use crate::export::Checkpoint;
use crate::record::{Hash, MAX_SIG_LEN};
use crate::sign::Signer;
use crate::store::{atomic_write, read_state, AnchoredHead, Error, HeadAnchor};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

/// Default TCTI (the kernel's TPM resource manager).
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";
/// Default directory of the `tpm2_*` binaries.
pub const DEFAULT_TOOLS_DIR: &str = "/usr/bin";
/// Default bound on one tool invocation.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
/// Default minimum interval between two counter increments.
pub const DEFAULT_MIN_INCREMENT_INTERVAL: Duration = Duration::from_secs(60);
/// Attributes the provisioning command gives the index (`tpm2_nvdefine -a`).
pub const PROVISION_ATTRIBUTES: &str = "authread|authwrite|nt=counter|no_da";
/// Sidecar format tag.
pub const SIDECAR_FORMAT: &str = "robodr-blackbox-tpm-anchor/v1";

const SIDECAR_DOMAIN: &[u8] = b"robodr-blackbox/tpm-nv-anchor/v1\0";
/// Cap on what is kept of a tool's stdout / stderr.
const MAX_TOOL_OUTPUT: u64 = 64 * 1024;

/// `TPMA_NV` bits used here (TPM 2.0 Part 2, 13.4).
pub mod attr {
    /// `TPM_NT` field (bits 7:4).
    pub const TPM_NT_MASK: u32 = 0x0000_00F0;
    pub const TPM_NT_SHIFT: u32 = 4;
    /// `TPM_NT_COUNTER`.
    pub const TPM_NT_COUNTER: u32 = 1;
    pub const AUTHWRITE: u32 = 1 << 2;
    pub const AUTHREAD: u32 = 1 << 18;
    pub const NO_DA: u32 = 1 << 25;
    pub const ORDERLY: u32 = 1 << 26;
    pub const WRITTEN: u32 = 1 << 29;
}

/// Parse an NV index handle: `0x` followed by 1..=8 hex digits, within the
/// NV index range `0x01000000..=0x01FFFFFF`.
pub fn parse_nv_index(s: &str) -> Result<u32, String> {
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| format!("NV index {s:?}: expected 0x followed by hex digits"))?;
    if h.is_empty() || h.len() > 8 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "NV index {s:?}: expected 0x followed by 1..=8 hex digits"
        ));
    }
    let v = u32::from_str_radix(h, 16).map_err(|e| format!("NV index {s:?}: {e}"))?;
    if v >> 24 != 0x01 {
        return Err(format!(
            "NV index {s:?}: not an NV index handle (0x01000000..=0x01FFFFFF)"
        ));
    }
    Ok(v)
}

/// `0x01500020` form.
pub fn format_nv_index(v: u32) -> String {
    format!("0x{v:08x}")
}

// ---------------------------------------------------------------------------
// Running the tools
// ---------------------------------------------------------------------------

/// What a tool invocation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// Exit code (`None`: killed by a signal).
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Runs one `tpm2_*` tool. The seam for tests (a fake TPM) and for
/// alternative transports. `tool` is one of the fixed names this module
/// uses (`tpm2_nvreadpublic`, `tpm2_nvread`, `tpm2_nvincrement`,
/// `tpm2_nvdefine`). An `Err` means the tool could not be run to completion
/// (not found, timed out); a tool that ran and failed is `Ok` with a
/// non-zero status.
pub trait TpmTools: Send + Sync + fmt::Debug {
    fn run(&self, tool: &str, args: &[String]) -> Result<ToolOutput, String>;
}

/// [`TpmTools`] that executes the real binaries from a fixed directory with
/// a cleared environment plus `TPM2TOOLS_TCTI`, stdin closed, and a bounded
/// wait: a tool still running after the timeout is killed.
#[derive(Debug, Clone)]
pub struct Tpm2Tools {
    tools_dir: PathBuf,
    tcti: String,
    timeout: Duration,
}

impl Tpm2Tools {
    /// `tools_dir` must be absolute; `tcti` is passed as `TPM2TOOLS_TCTI`
    /// (e.g. `device:/dev/tpmrm0`, `swtpm:host=127.0.0.1,port=2321`).
    pub fn new(
        tools_dir: impl Into<PathBuf>,
        tcti: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let tools_dir = tools_dir.into();
        let tcti = tcti.into();
        if !tools_dir.is_absolute() {
            return Err(format!(
                "tpm2-tools directory {} must be absolute",
                tools_dir.display()
            ));
        }
        if tcti.is_empty() || tcti.len() > 512 || tcti.chars().any(char::is_control) {
            return Err("TCTI must be 1..=512 printable characters".into());
        }
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err("tool timeout must be in (0, 60 s]".into());
        }
        Ok(Self {
            tools_dir,
            tcti,
            timeout,
        })
    }
}

fn spawn_reader<R: Read + Send + 'static>(r: R) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut r = r;
        let mut buf = Vec::new();
        let _ = Read::by_ref(&mut r)
            .take(MAX_TOOL_OUTPUT)
            .read_to_end(&mut buf);
        // Drain the rest so the child never blocks on a full pipe.
        let _ = std::io::copy(&mut r, &mut std::io::sink());
        let _ = tx.send(buf);
    });
    rx
}

impl TpmTools for Tpm2Tools {
    fn run(&self, tool: &str, args: &[String]) -> Result<ToolOutput, String> {
        if tool.is_empty() || !tool.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(format!("invalid tool name {tool:?}"));
        }
        let path = self.tools_dir.join(tool);
        let mut child = Command::new(&path)
            .args(args)
            .env_clear()
            .env("TPM2TOOLS_TCTI", &self.tcti)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let out_rx = child.stdout.take().map(spawn_reader);
        let err_rx = child.stderr.take().map(spawn_reader);
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{tool}: waiting: {e}"));
                }
            }
            if start.elapsed() >= self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{tool}: timed out after {} ms (killed)",
                    self.timeout.as_millis()
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        // The pipes close when the tool exits; bound the wait anyway (a
        // grandchild could hold them open).
        let collect = |rx: Option<mpsc::Receiver<Vec<u8>>>| -> Vec<u8> {
            let left = self
                .timeout
                .saturating_sub(start.elapsed())
                .max(Duration::from_millis(50));
            rx.and_then(|rx| rx.recv_timeout(left).ok())
                .unwrap_or_default()
        };
        let stdout = collect(out_rx);
        let stderr = collect(err_rx);
        Ok(ToolOutput {
            status: status.code(),
            stdout,
            stderr,
        })
    }
}

/// A short, printable summary of a failed tool's stderr (the last
/// `ERROR:` line if any).
fn tool_error(tool: &str, o: &ToolOutput) -> String {
    let text = String::from_utf8_lossy(&o.stderr);
    let line = text
        .lines()
        .rev()
        .find(|l| l.contains("ERROR") && !l.contains("Unable to run"))
        .or_else(|| text.lines().rev().find(|l| !l.trim().is_empty()))
        .unwrap_or("");
    let clean: String = line
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(240)
        .collect();
    match o.status {
        Some(c) => format!("{tool} failed (exit {c}): {}", clean.trim()),
        None => format!("{tool} killed by a signal: {}", clean.trim()),
    }
}

// ---------------------------------------------------------------------------
// The counter
// ---------------------------------------------------------------------------

/// Public area of an NV index, as far as this module needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvPublic {
    pub attributes: u32,
    pub size: u16,
}

impl NvPublic {
    pub fn is_counter(&self) -> bool {
        (self.attributes & attr::TPM_NT_MASK) >> attr::TPM_NT_SHIFT == attr::TPM_NT_COUNTER
    }
    pub fn written(&self) -> bool {
        self.attributes & attr::WRITTEN != 0
    }
}

/// Strict parser of `tpm2_nvreadpublic <index>` output (tpm2-tools 5.x
/// YAML): the first line must name `index`, and it must carry exactly one
/// `attributes: value: 0x...` and one `size:`.
pub fn parse_nvreadpublic(out: &[u8], index: u32) -> Result<NvPublic, String> {
    let text = std::str::from_utf8(out).map_err(|_| "nvreadpublic: output is not UTF-8")?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let head = lines.next().ok_or("nvreadpublic: empty output")?;
    if head.trim_end() != format!("{index:#x}:") {
        return Err(format!(
            "nvreadpublic: output is for {:?}, expected {index:#x}",
            head.trim()
        ));
    }
    let (mut in_attr, mut attrs, mut size) = (false, None, None);
    for l in lines {
        let indent = l.len() - l.trim_start().len();
        let t = l.trim();
        if indent == 0 {
            return Err("nvreadpublic: more than one index in the output".into());
        }
        if indent == 2 {
            in_attr = t == "attributes:";
            if let Some(v) = t.strip_prefix("size:") {
                if size.is_some() {
                    return Err("nvreadpublic: two size lines".into());
                }
                size = Some(
                    v.trim()
                        .parse::<u16>()
                        .map_err(|_| format!("nvreadpublic: bad size {:?}", v.trim()))?,
                );
            }
        } else if in_attr && indent == 4 {
            if let Some(v) = t.strip_prefix("value:") {
                if attrs.is_some() {
                    return Err("nvreadpublic: two attribute values".into());
                }
                let h = v
                    .trim()
                    .strip_prefix("0x")
                    .ok_or_else(|| format!("nvreadpublic: bad attributes {:?}", v.trim()))?;
                attrs = Some(
                    u32::from_str_radix(h, 16)
                        .map_err(|_| format!("nvreadpublic: bad attributes {:?}", v.trim()))?,
                );
            }
        }
    }
    match (attrs, size) {
        (Some(attributes), Some(size)) => Ok(NvPublic { attributes, size }),
        _ => Err("nvreadpublic: attributes or size missing from the output".into()),
    }
}

/// One NV counter index reached through [`TpmTools`].
#[derive(Debug)]
pub struct NvCounter {
    index: u32,
    auth_file: Option<PathBuf>,
    tools: Box<dyn TpmTools>,
}

impl NvCounter {
    /// `auth_file`: the index's authorization value (`-P file:...`); `None`
    /// = empty auth.
    pub fn new(index: u32, auth_file: Option<PathBuf>, tools: Box<dyn TpmTools>) -> Self {
        Self {
            index,
            auth_file,
            tools,
        }
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    fn idx(&self) -> String {
        format_nv_index(self.index)
    }

    fn auth_args(&self, a: &mut Vec<String>) {
        if let Some(f) = &self.auth_file {
            a.push("-P".into());
            a.push(format!("file:{}", f.display()));
        }
    }

    fn ok(&self, tool: &str, args: &[String]) -> Result<ToolOutput, String> {
        let o = self.tools.run(tool, args)?;
        if o.status != Some(0) {
            return Err(tool_error(tool, &o));
        }
        Ok(o)
    }

    /// The index's public area (fails if it is not defined).
    pub fn read_public(&self) -> Result<NvPublic, String> {
        let o = self.ok("tpm2_nvreadpublic", &[self.idx()])?;
        parse_nvreadpublic(&o.stdout, self.index)
    }

    /// [`NvCounter::read_public`], refusing an index that is not a counter.
    pub fn check_counter(&self) -> Result<NvPublic, String> {
        let p = self.read_public()?;
        if !p.is_counter() {
            return Err(format!(
                "NV index {} is not a counter (attributes {:#010x}, TPM_NT {}): refusing to use it",
                self.idx(),
                p.attributes,
                (p.attributes & attr::TPM_NT_MASK) >> attr::TPM_NT_SHIFT
            ));
        }
        if p.size != 8 {
            return Err(format!(
                "NV index {} has size {}, a counter has 8",
                self.idx(),
                p.size
            ));
        }
        Ok(p)
    }

    /// The counter value (the index must be written).
    pub fn read(&self) -> Result<u64, String> {
        let mut a = vec![self.idx(), "-C".into(), self.idx(), "-s".into(), "8".into()];
        self.auth_args(&mut a);
        let o = self.ok("tpm2_nvread", &a)?;
        let b: [u8; 8] = o.stdout.as_slice().try_into().map_err(|_| {
            format!(
                "tpm2_nvread: expected 8 bytes of counter, got {}",
                o.stdout.len()
            )
        })?;
        Ok(u64::from_be_bytes(b))
    }

    /// Increment by one.
    pub fn increment(&self) -> Result<(), String> {
        let mut a = vec!["-C".into(), self.idx()];
        self.auth_args(&mut a);
        a.push(self.idx());
        self.ok("tpm2_nvincrement", &a).map(|_| ())
    }

    /// Define the index as a counter with [`PROVISION_ATTRIBUTES`] under
    /// the owner hierarchy. `owner_auth_file`: the owner hierarchy's
    /// authorization; `index_auth_file`: the new index's authorization
    /// (also what [`NvCounter::new`] gets as `auth_file`).
    pub fn define(
        &self,
        owner_auth_file: Option<&Path>,
        index_auth_file: Option<&Path>,
    ) -> Result<(), String> {
        let mut a = vec![
            self.idx(),
            "-C".into(),
            "o".into(),
            "-s".into(),
            "8".into(),
            "-a".into(),
            PROVISION_ATTRIBUTES.into(),
        ];
        if let Some(f) = owner_auth_file {
            a.push("-P".into());
            a.push(format!("file:{}", f.display()));
        }
        if let Some(f) = index_auth_file {
            a.push("-p".into());
            a.push(format!("file:{}", f.display()));
        }
        self.ok("tpm2_nvdefine", &a).map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// The anchor
// ---------------------------------------------------------------------------

/// Settings of a [`TpmNvCounterAnchor`].
#[derive(Debug, Clone)]
pub struct TpmAnchorConfig {
    /// NV index of the counter (provisioned with
    /// `robodr-blackbox tpm-anchor-init`).
    pub nv_index: u32,
    /// Sidecar file (absolute; its directory must exist). Keep it outside
    /// the log directory, so a wiped store alone is classified as one.
    pub sidecar: PathBuf,
    pub tcti: String,
    pub tools_dir: PathBuf,
    /// Index authorization file (`None`: empty auth).
    pub auth_file: Option<PathBuf>,
    /// At most one increment per this interval (0 = every mark).
    pub min_increment_interval: Duration,
    /// Bound on one tool invocation.
    pub timeout: Duration,
}

impl TpmAnchorConfig {
    /// Defaults: [`DEFAULT_TCTI`], [`DEFAULT_TOOLS_DIR`], empty auth,
    /// [`DEFAULT_MIN_INCREMENT_INTERVAL`], [`DEFAULT_TIMEOUT`].
    pub fn new(nv_index: u32, sidecar: impl Into<PathBuf>) -> Self {
        Self {
            nv_index,
            sidecar: sidecar.into(),
            tcti: DEFAULT_TCTI.into(),
            tools_dir: DEFAULT_TOOLS_DIR.into(),
            auth_file: None,
            min_increment_interval: DEFAULT_MIN_INCREMENT_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// The message the sidecar signature covers:
/// `"robodr-blackbox/tpm-nv-anchor/v1\0" || u32_be(nv_index) ||
/// u64_be(counter) || chain_id || u64_be(seq) || hash`. Domain-separated
/// from record, cursor and ack signatures.
pub fn sidecar_message(
    nv_index: u32,
    counter: u64,
    chain_id: &Hash,
    seq: u64,
    hash: &Hash,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIDECAR_DOMAIN.len() + 4 + 8 + 32 + 8 + 32);
    m.extend_from_slice(SIDECAR_DOMAIN);
    m.extend_from_slice(&nv_index.to_be_bytes());
    m.extend_from_slice(&counter.to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(hash);
    m
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarJson {
    format: String,
    nv_index: String,
    counter: u64,
    chain_id: String,
    seq: u64,
    hash: String,
    key_id: String,
    sig: String,
}

/// An authenticated sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sidecar {
    counter: u64,
    chain_id: Hash,
    seq: u64,
    hash: Hash,
}

#[derive(Debug, Default)]
struct State {
    /// Counter value read right after this process's last increment (and
    /// the index checked to be a counter). `None` = unknown: the next mark
    /// checks the index and increments.
    counter: Option<u64>,
    last_increment: Option<Instant>,
}

/// [`HeadAnchor`] on a TPM 2.0 NV counter plus a signed sidecar file. See
/// the module docs for the mapping, the security argument and the limits.
pub struct TpmNvCounterAnchor {
    counter: NvCounter,
    dir: PathBuf,
    name: String,
    signer: Mutex<Box<dyn Signer>>,
    min_interval: Duration,
    state: Mutex<State>,
}

impl fmt::Debug for TpmNvCounterAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TpmNvCounterAnchor")
            .field("nv_index", &format_nv_index(self.counter.index))
            .field("sidecar", &self.sidecar_path())
            .field("min_interval", &self.min_interval)
            .finish_non_exhaustive()
    }
}

impl TpmNvCounterAnchor {
    /// Anchor driving the real `tpm2-tools`. `signer` must be the
    /// recorder's key (it signs and authenticates the sidecar) and must be
    /// able to verify its own signatures ([`Signer::verify_own`]). Does not
    /// touch the TPM.
    pub fn new(cfg: &TpmAnchorConfig, signer: Box<dyn Signer>) -> Result<Self, Error> {
        let tools =
            Tpm2Tools::new(&cfg.tools_dir, &cfg.tcti, cfg.timeout).map_err(Error::Config)?;
        Self::with_tools(cfg, Box::new(tools), signer)
    }

    /// [`TpmNvCounterAnchor::new`] with another [`TpmTools`] (tests).
    pub fn with_tools(
        cfg: &TpmAnchorConfig,
        tools: Box<dyn TpmTools>,
        signer: Box<dyn Signer>,
    ) -> Result<Self, Error> {
        if cfg.nv_index >> 24 != 0x01 {
            return Err(Error::Config(format!(
                "{} is not an NV index handle",
                format_nv_index(cfg.nv_index)
            )));
        }
        let p = &cfg.sidecar;
        if !p.is_absolute() {
            return Err(Error::Config(format!(
                "TPM anchor sidecar {} must be an absolute path",
                p.display()
            )));
        }
        let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
            return Err(Error::Config(format!(
                "TPM anchor sidecar {} has no directory or UTF-8 file name",
                p.display()
            )));
        };
        if let Some(a) = &cfg.auth_file {
            if !a.is_absolute() {
                return Err(Error::Config(format!(
                    "TPM index auth file {} must be an absolute path",
                    a.display()
                )));
            }
        }
        let probe = b"robodr-blackbox/tpm-nv-anchor/self-test";
        let ok = signer
            .sign(probe)
            .ok()
            .and_then(|s| signer.verify_own(probe, &s));
        if ok != Some(true) {
            return Err(Error::Config(
                "the TPM anchor needs a signer that can verify its own signatures".into(),
            ));
        }
        Ok(Self {
            counter: NvCounter::new(cfg.nv_index, cfg.auth_file.clone(), tools),
            dir: dir.to_path_buf(),
            name: name.to_string(),
            signer: Mutex::new(signer),
            min_interval: cfg.min_increment_interval,
            state: Mutex::new(State::default()),
        })
    }

    /// The sidecar's path.
    pub fn sidecar_path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    /// The NV index.
    pub fn nv_index(&self) -> u32 {
        self.counter.index
    }

    fn write_sidecar(&self, counter: u64, mark: &Checkpoint) -> Result<(), String> {
        let msg = sidecar_message(
            self.counter.index,
            counter,
            &mark.chain_id,
            mark.seq,
            &mark.hash,
        );
        let signer = self
            .signer
            .lock()
            .map_err(|_| "anchor signer lock poisoned".to_string())?;
        let sig = signer.sign(&msg).map_err(|e| e.to_string())?;
        let j = SidecarJson {
            format: SIDECAR_FORMAT.into(),
            nv_index: format_nv_index(self.counter.index),
            counter,
            chain_id: to_hex(&mark.chain_id),
            seq: mark.seq,
            hash: to_hex(&mark.hash),
            key_id: signer.key_id().to_string(),
            sig: to_hex(&sig),
        };
        drop(signer);
        let data = serde_json::to_vec(&j).map_err(|e| e.to_string())?;
        atomic_write(&self.dir, &self.name, &data)
            .map_err(|e| format!("{}: {e}", self.sidecar_path().display()))
    }

    /// `Ok(None)`: no sidecar file. `Err`: present but not authentic.
    fn read_sidecar(&self) -> Result<Option<Sidecar>, String> {
        let path = self.sidecar_path();
        let Some(s) = read_state(&self.dir, &self.name).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let bad = |why: &str| format!("sidecar {}: {why}", path.display());
        let j: SidecarJson = serde_json::from_str(&s).map_err(|_| bad("unparseable"))?;
        if j.format != SIDECAR_FORMAT {
            return Err(bad("unknown format"));
        }
        if parse_nv_index(&j.nv_index).ok() != Some(self.counter.index) {
            return Err(bad("written for another NV index"));
        }
        let chain_id = hash_from_hex(&j.chain_id).ok_or_else(|| bad("malformed chain_id"))?;
        let hash = hash_from_hex(&j.hash).ok_or_else(|| bad("malformed hash"))?;
        let sig = from_hex(&j.sig)
            .filter(|s| !s.is_empty() && s.len() <= MAX_SIG_LEN)
            .ok_or_else(|| bad("malformed signature"))?;
        let msg = sidecar_message(self.counter.index, j.counter, &chain_id, j.seq, &hash);
        let signer = self
            .signer
            .lock()
            .map_err(|_| "anchor signer lock poisoned".to_string())?;
        if j.key_id != signer.key_id() || signer.verify_own(&msg, &sig) != Some(true) {
            return Err(bad("signature does not verify under the recorder's key"));
        }
        Ok(Some(Sidecar {
            counter: j.counter,
            chain_id,
            seq: j.seq,
            hash,
        }))
    }
}

impl HeadAnchor for TpmNvCounterAnchor {
    fn advance(&self, mark: &Checkpoint) -> Result<(), String> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| "anchor lock poisoned".to_string())?;
        let now = Instant::now();
        let due = match (st.counter, st.last_increment) {
            (Some(_), Some(t)) => now.saturating_duration_since(t) >= self.min_interval,
            _ => true,
        };
        let counter = if due {
            let prev = st.counter.take();
            if prev.is_none() {
                self.counter.check_counter()?;
            }
            // Increment first, sidecar second: a crash in between leaves
            // an older sidecar and a higher count, which bounds the head
            // from below (sound), never the reverse.
            self.counter.increment()?;
            st.last_increment = Some(now);
            let t = self.counter.read()?;
            if prev.is_some_and(|p| t <= p) {
                return Err(format!(
                    "TPM counter {} read {t} after an increment from {}: not monotonic",
                    format_nv_index(self.counter.index),
                    prev.unwrap_or(0)
                ));
            }
            st.counter = Some(t);
            t
        } else {
            // Within the interval: refresh the sidecar only.
            st.counter.unwrap_or(0)
        };
        self.write_sidecar(counter, mark)
    }

    fn current(&self) -> Result<Option<AnchoredHead>, String> {
        let _st = self
            .state
            .lock()
            .map_err(|_| "anchor lock poisoned".to_string())?;
        let idx = format_nv_index(self.counter.index);
        let public = self.counter.check_counter()?;
        let sidecar = self.read_sidecar();
        if !public.written() {
            return match sidecar {
                Ok(None) => Ok(None),
                _ => Err(format!(
                    "TPM counter {idx} has never been incremented but a sidecar exists: the \
                     index was redefined or the TPM cleared; the head cannot be bounded"
                )),
            };
        }
        let t = self.counter.read()?;
        let sc = match sidecar {
            Ok(Some(sc)) => sc,
            Ok(None) => {
                return Err(format!(
                    "TPM counter {idx} is at {t} but the sidecar {} is missing (deleted?): the \
                     head cannot be bounded",
                    self.sidecar_path().display()
                ))
            }
            Err(e) => {
                return Err(format!(
                    "TPM counter {idx} is at {t}, {e}: the head cannot be bounded"
                ))
            }
        };
        if t == sc.counter {
            return Ok(Some(AnchoredHead {
                chain_id: Some(sc.chain_id),
                seq: sc.seq,
                hash: Some(sc.hash),
            }));
        }
        if t < sc.counter {
            return Err(format!(
                "TPM counter {idx} is at {t}, below the authentic sidecar's {}: the TPM was \
                 cleared or replaced",
                sc.counter
            ));
        }
        // Each increment after the sidecar belongs to a later durable mark
        // with a larger seq.
        let seq = sc
            .seq
            .checked_add(t - sc.counter)
            .ok_or_else(|| format!("TPM counter {idx}: bound overflows"))?;
        Ok(Some(AnchoredHead {
            chain_id: None,
            seq,
            hash: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::HmacSha256Key;
    use std::sync::Arc;

    #[derive(Debug, Default)]
    struct FakeTpm {
        defined: Option<u32>,
        value: u64,
        /// Tool name -> canned output replacing the real behaviour.
        garble: Option<(String, ToolOutput)>,
        /// Tool name -> runner error (e.g. a timeout).
        fail: Option<(String, String)>,
        calls: Vec<String>,
    }

    #[derive(Debug, Clone, Default)]
    struct Fake(Arc<Mutex<FakeTpm>>);

    fn ok(stdout: Vec<u8>) -> ToolOutput {
        ToolOutput {
            status: Some(0),
            stdout,
            stderr: Vec::new(),
        }
    }
    fn fail(msg: &str) -> ToolOutput {
        ToolOutput {
            status: Some(1),
            stdout: Vec::new(),
            stderr: format!("WARNING:esys: noise\nERROR: {msg}\nERROR: Unable to run x\n")
                .into_bytes(),
        }
    }

    impl TpmTools for Fake {
        fn run(&self, tool: &str, args: &[String]) -> Result<ToolOutput, String> {
            let mut t = self.0.lock().unwrap();
            t.calls.push(tool.to_string());
            if let Some((n, e)) = &t.fail {
                if n == tool {
                    return Err(e.clone());
                }
            }
            if let Some((n, o)) = &t.garble {
                if n == tool {
                    return Ok(o.clone());
                }
            }
            let idx = 0x0150_0020u32;
            let named = args.iter().any(|a| a == &format_nv_index(idx));
            if !named {
                return Ok(fail("the handle is not correct for the use"));
            }
            match tool {
                "tpm2_nvreadpublic" => match t.defined {
                    None => Ok(fail("Failed to read the public part")),
                    Some(a) => Ok(ok(format!(
                        "{idx:#x}:\n  name: 000b00\n  hash algorithm:\n    friendly: sha256\n    \
                         value: 0xB\n  attributes:\n    friendly: x\n    value: {a:#X}\n  size: 8\n\n"
                    )
                    .replace("0X", "0x")
                    .into_bytes())),
                },
                "tpm2_nvread" => match t.defined {
                    Some(a) if a & attr::WRITTEN != 0 => Ok(ok(t.value.to_be_bytes().to_vec())),
                    _ => Ok(fail("an NV Index is used before being initialized")),
                },
                "tpm2_nvincrement" => match t.defined {
                    Some(a) if (a & attr::TPM_NT_MASK) >> 4 == 1 => {
                        t.value += 1;
                        t.defined = Some(a | attr::WRITTEN);
                        Ok(ok(Vec::new()))
                    }
                    _ => Ok(fail("the attributes are not correct")),
                },
                _ => Ok(fail("unexpected tool")),
            }
        }
    }

    const COUNTER_ATTRS: u32 = 0x0204_0014;

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "robodr-bb-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Env {
        _dir: TmpDir,
        fake: Fake,
        anchor: TpmNvCounterAnchor,
        sidecar: PathBuf,
    }

    fn key() -> Box<dyn Signer> {
        Box::new(HmacSha256Key::new("unit", &[7; 32]).unwrap())
    }

    fn env(tag: &str, interval: Duration) -> Env {
        let dir = TmpDir::new(tag);
        let sidecar = dir.0.join("tpm-sidecar.json");
        let fake = Fake::default();
        fake.0.lock().unwrap().defined = Some(COUNTER_ATTRS);
        let mut c = TpmAnchorConfig::new(0x0150_0020, &sidecar);
        c.min_increment_interval = interval;
        let anchor = TpmNvCounterAnchor::with_tools(&c, Box::new(fake.clone()), key()).unwrap();
        Env {
            _dir: dir,
            fake,
            anchor,
            sidecar,
        }
    }

    fn mark(seq: u64) -> Checkpoint {
        Checkpoint {
            chain_id: [3; 32],
            seq,
            hash: [seq as u8; 32],
            key_id: "unit".into(),
            sig: vec![1],
        }
    }

    #[test]
    fn index_parsing_is_strict() {
        assert_eq!(parse_nv_index("0x01500020"), Ok(0x0150_0020));
        assert_eq!(parse_nv_index("0x1500020"), Ok(0x0150_0020));
        for bad in [
            "01500020",
            "0x",
            "0x0150002g",
            "0x101500020",
            "0x81000001",
            "0x 1",
        ] {
            assert!(parse_nv_index(bad).is_err(), "{bad}");
        }
        assert_eq!(format_nv_index(0x0150_0020), "0x01500020");
    }

    #[test]
    fn nvreadpublic_parser_accepts_real_output_and_rejects_garbage() {
        let real = "0x1500020:\n  name: 000be1\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n  attributes:\n    friendly: authwrite|nt=0x1|authread|no_da|written\n    value: 0x22040014\n  size: 8\n\n";
        let p = parse_nvreadpublic(real.as_bytes(), 0x0150_0020).unwrap();
        assert!(p.is_counter() && p.written());
        assert_eq!(p.size, 8);
        // The hash algorithm's `value` must not be taken for the attributes.
        let no_attr = "0x1500020:\n  hash algorithm:\n    value: 0xB\n  size: 8\n";
        assert!(parse_nvreadpublic(no_attr.as_bytes(), 0x0150_0020).is_err());
        assert!(parse_nvreadpublic(real.as_bytes(), 0x0150_0021).is_err());
        assert!(parse_nvreadpublic(b"", 0x0150_0020).is_err());
        assert!(parse_nvreadpublic(&[0xff, 0xfe], 0x0150_0020).is_err());
        let two = format!("{real}0x1500021:\n  size: 8\n");
        assert!(parse_nvreadpublic(two.as_bytes(), 0x0150_0020).is_err());
        let bad_val = real.replace("0x22040014", "22040014");
        assert!(parse_nvreadpublic(bad_val.as_bytes(), 0x0150_0020).is_err());
        let ordinary = real.replace("0x22040014", "0x40004");
        let p = parse_nvreadpublic(ordinary.as_bytes(), 0x0150_0020).unwrap();
        assert!(!p.is_counter() && !p.written());
    }

    #[test]
    fn fresh_counter_then_round_trip() {
        let e = env("tpm-fresh", Duration::ZERO);
        assert_eq!(e.anchor.current(), Ok(None));
        e.anchor.advance(&mark(5)).unwrap();
        assert_eq!(e.fake.0.lock().unwrap().value, 1);
        let h = e.anchor.current().unwrap().unwrap();
        assert_eq!(h.seq, 5);
        assert_eq!(h.chain_id, Some([3; 32]));
        assert_eq!(h.hash, Some([5; 32]));
        e.anchor.advance(&mark(9)).unwrap();
        assert_eq!(e.fake.0.lock().unwrap().value, 2);
        assert_eq!(e.anchor.current().unwrap().unwrap().seq, 9);
    }

    #[test]
    fn rolled_back_sidecar_yields_a_lower_bound() {
        let e = env("tpm-rollback", Duration::ZERO);
        e.anchor.advance(&mark(10)).unwrap();
        let old = std::fs::read(&e.sidecar).unwrap();
        for s in [20, 30, 40] {
            e.anchor.advance(&mark(s)).unwrap();
        }
        std::fs::write(&e.sidecar, old).unwrap();
        // 3 increments after the old sidecar: head >= 10 + 3.
        let h = e.anchor.current().unwrap().unwrap();
        assert_eq!(
            h,
            AnchoredHead {
                chain_id: None,
                seq: 13,
                hash: None
            }
        );
    }

    #[test]
    fn forged_or_missing_sidecar_is_an_error_not_a_clean_open() {
        let e = env("tpm-forged", Duration::ZERO);
        e.anchor.advance(&mark(10)).unwrap();
        e.anchor.advance(&mark(20)).unwrap();
        // The attacker claims the current count for an older position.
        let s = std::fs::read_to_string(&e.sidecar).unwrap();
        let mut j: serde_json::Value = serde_json::from_str(&s).unwrap();
        j["seq"] = 10.into();
        std::fs::write(&e.sidecar, j.to_string()).unwrap();
        let err = e.anchor.current().unwrap_err();
        assert!(err.contains("signature does not verify"), "{err}");
        // Garbled.
        std::fs::write(&e.sidecar, b"{not json").unwrap();
        assert!(e.anchor.current().unwrap_err().contains("unparseable"));
        // Deleted.
        std::fs::remove_file(&e.sidecar).unwrap();
        let err = e.anchor.current().unwrap_err();
        assert!(err.contains("missing"), "{err}");
        // The next mark writes a fresh one; the count goes on.
        e.anchor.advance(&mark(30)).unwrap();
        assert_eq!(e.anchor.current().unwrap().unwrap().seq, 30);
    }

    #[test]
    fn sidecar_from_another_key_or_index_is_refused() {
        let e = env("tpm-otherkey", Duration::ZERO);
        e.anchor.advance(&mark(10)).unwrap();
        let mut c = TpmAnchorConfig::new(0x0150_0020, &e.sidecar);
        c.min_increment_interval = Duration::ZERO;
        let other = TpmNvCounterAnchor::with_tools(
            &c,
            Box::new(e.fake.clone()),
            Box::new(HmacSha256Key::new("unit", &[8; 32]).unwrap()),
        )
        .unwrap();
        assert!(other.current().is_err());
        let s = std::fs::read_to_string(&e.sidecar).unwrap();
        std::fs::write(&e.sidecar, s.replace("0x01500020", "0x01500021")).unwrap();
        assert!(e.anchor.current().unwrap_err().contains("another NV index"));
    }

    #[test]
    fn unwritten_index_with_a_sidecar_and_counter_behind_are_errors() {
        let e = env("tpm-reset", Duration::ZERO);
        e.anchor.advance(&mark(10)).unwrap();
        e.anchor.advance(&mark(11)).unwrap();
        // Redefined: unwritten.
        e.fake.0.lock().unwrap().defined = Some(COUNTER_ATTRS);
        assert!(e.anchor.current().unwrap_err().contains("redefined"));
        // Written again, but behind the sidecar.
        {
            let mut t = e.fake.0.lock().unwrap();
            t.defined = Some(COUNTER_ATTRS | attr::WRITTEN);
            t.value = 1;
        }
        assert!(e
            .anchor
            .current()
            .unwrap_err()
            .contains("cleared or replaced"));
    }

    #[test]
    fn non_counter_index_is_refused() {
        let e = env("tpm-ordinary", Duration::ZERO);
        e.fake.0.lock().unwrap().defined = Some(0x0004_0004 | attr::WRITTEN);
        let err = e.anchor.current().unwrap_err();
        assert!(err.contains("not a counter"), "{err}");
        let err = e.anchor.advance(&mark(1)).unwrap_err();
        assert!(err.contains("not a counter"), "{err}");
        assert!(!e.sidecar.exists());
        // Undefined index.
        e.fake.0.lock().unwrap().defined = None;
        let err = e.anchor.current().unwrap_err();
        assert!(
            err.contains("tpm2_nvreadpublic failed (exit 1): ERROR: Failed"),
            "{err}"
        );
    }

    #[test]
    fn garbled_tool_output_and_timeouts_are_errors() {
        let e = env("tpm-garbled", Duration::ZERO);
        e.anchor.advance(&mark(1)).unwrap();
        e.fake.0.lock().unwrap().garble = Some(("tpm2_nvread".into(), ok(vec![0; 7])));
        assert!(e.anchor.current().unwrap_err().contains("expected 8 bytes"));
        // An increment whose read-back is garbled writes no sidecar.
        let before = std::fs::read(&e.sidecar).unwrap();
        assert!(e.anchor.advance(&mark(2)).is_err());
        assert_eq!(std::fs::read(&e.sidecar).unwrap(), before);
        e.fake.0.lock().unwrap().garble = Some((
            "tpm2_nvreadpublic".into(),
            ok(b"0x1500020:\n  attributes:\n    value: zz\n".to_vec()),
        ));
        assert!(e.anchor.current().unwrap_err().contains("bad attributes"));
        {
            let mut t = e.fake.0.lock().unwrap();
            t.garble = None;
            t.fail = Some((
                "tpm2_nvincrement".into(),
                "tpm2_nvincrement: timed out".into(),
            ));
        }
        assert!(e
            .anchor
            .advance(&mark(3))
            .unwrap_err()
            .contains("timed out"));
        // The rolled-forward count still bounds the head soundly: 1 (sidecar)
        // + 1 increment whose sidecar was never written.
        e.fake.0.lock().unwrap().fail = None;
        assert_eq!(e.anchor.current().unwrap().unwrap().seq, 2);
    }

    #[test]
    fn increments_are_rate_limited_but_the_sidecar_follows() {
        let e = env("tpm-rate", Duration::from_secs(3600));
        for s in [1, 2, 3, 4] {
            e.anchor.advance(&mark(s)).unwrap();
        }
        assert_eq!(
            e.fake.0.lock().unwrap().value,
            1,
            "one increment per interval"
        );
        assert_eq!(e.anchor.current().unwrap().unwrap().seq, 4);
        let calls = e.fake.0.lock().unwrap().calls.clone();
        assert_eq!(
            calls.iter().filter(|c| *c == "tpm2_nvincrement").count(),
            1,
            "{calls:?}"
        );
    }

    #[test]
    fn signer_without_self_verification_is_refused() {
        #[derive(Debug)]
        struct Opaque;
        impl Signer for Opaque {
            fn algorithm(&self) -> &str {
                "x"
            }
            fn key_id(&self) -> &str {
                "x"
            }
            fn sign(&self, _: &[u8]) -> Result<Vec<u8>, crate::sign::SignError> {
                Ok(vec![1])
            }
        }
        let c = TpmAnchorConfig::new(0x0150_0020, "/tmp/x.json");
        assert!(
            TpmNvCounterAnchor::with_tools(&c, Box::new(Fake::default()), Box::new(Opaque))
                .is_err()
        );
        let c = TpmAnchorConfig::new(0x0150_0020, "rel.json");
        assert!(TpmNvCounterAnchor::with_tools(&c, Box::new(Fake::default()), key()).is_err());
        let c = TpmAnchorConfig::new(0x8100_0001, "/tmp/x.json");
        assert!(TpmNvCounterAnchor::with_tools(&c, Box::new(Fake::default()), key()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn real_runner_kills_a_hanging_tool_and_reads_output() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TmpDir::new("tpm-runner");
        let write = |name: &str, body: &str| {
            let p = dir.0.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        write("tpm2_nvreadpublic", "exec /bin/sleep 30");
        write(
            "tpm2_nvread",
            "printf '\\000\\000\\000\\000\\000\\000\\001\\002'; echo \"$TPM2TOOLS_TCTI\" >&2",
        );
        let t = Tpm2Tools::new(&dir.0, "swtpm:port=1", Duration::from_millis(300)).unwrap();
        let start = Instant::now();
        let e = t.run("tpm2_nvreadpublic", &[]).unwrap_err();
        assert!(e.contains("timed out"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
        let o = t.run("tpm2_nvread", &[]).unwrap();
        assert_eq!(o.status, Some(0));
        assert_eq!(o.stdout, vec![0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(String::from_utf8_lossy(&o.stderr).trim(), "swtpm:port=1");
        assert!(t.run("tpm2_missing", &[]).is_err());
        assert!(t.run("../sh", &[]).is_err());
        assert!(Tpm2Tools::new("rel", "x", Duration::from_secs(1)).is_err());
        assert!(Tpm2Tools::new("/usr/bin", "a\nb", Duration::from_secs(1)).is_err());
    }
}
