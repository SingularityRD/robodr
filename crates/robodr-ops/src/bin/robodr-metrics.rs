//! `robodr-metrics`: Prometheus textfile exporter of RoboDR's status files
//! (sales-readiness T70). See `man robodr-metrics` and `robodr_ops::metrics`.

#![forbid(unsafe_code)]

use robodr_ops::args::{argv, Args};
use robodr_ops::metrics::{self, Inputs, AGENTD_STATUS, DEFAULT_OUT, UPLINK_STATUS};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
usage: robodr-metrics [--agentd-status FILE | --no-agentd] [--uplink-status FILE | --no-uplink]
                      [--out FILE | --stdout]
Renders robodr-agentd's status.json and robodr-uplink's uplink-status.json as
Prometheus text (node_exporter textfile collector). Defaults:
  --agentd-status /var/lib/robodr/spool/agentd/status.json
  --uplink-status /var/lib/robodr/export/uplink/uplink-status.json (skipped when absent)
  --out /run/robodr-metrics/robodr.prom (written atomically, mode 0644)
A missing or unreadable agentd status is exported as robodr_agentd_status_readable 0.
Exit: 0 written, 1 write error, 2 usage.";

/// Largest status file read.
const MAX_STATUS: u64 = 4 << 20;

fn read_json(p: &Path) -> Result<serde_json::Value, String> {
    use std::io::Read;
    let f = std::fs::File::open(p).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.take(MAX_STATUS + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > MAX_STATUS {
        return Err("larger than 4 MiB".into());
    }
    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

/// Write `text` to `out` atomically (temporary file in the same directory,
/// fsync, rename): the collector never reads a half-written file.
fn write_atomic(out: &Path, text: &str) -> std::io::Result<()> {
    let dir = out.parent().unwrap_or(Path::new("."));
    let name = out
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // node_exporter reads *.prom only: the temporary name never matches.
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, out)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            eprintln!("robodr-metrics: {msg}");
            if code == 2 {
                eprintln!("{USAGE}");
            }
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<(), (u8, String)> {
    let raw = argv().map_err(|e| (2, e))?;
    if raw.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    if raw.iter().any(|a| a == "-V" || a == "--version") {
        println!("robodr-metrics {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let a = Args::parse(
        &raw,
        &["agentd-status", "uplink-status", "out"],
        &["stdout", "no-agentd", "no-uplink"],
    )
    .map_err(|e| (2, e))?;
    if let Some(p) = a.positional.first() {
        return Err((2, format!("unexpected argument {p:?}")));
    }
    let one = |n: &str| a.one(n).map_err(|e| (2, e));
    if a.flag("stdout") && one("out")?.is_some() {
        return Err((2, "--out and --stdout are exclusive".into()));
    }
    if a.flag("no-agentd") && one("agentd-status")?.is_some() {
        return Err((2, "--agentd-status and --no-agentd are exclusive".into()));
    }
    if a.flag("no-uplink") && one("uplink-status")?.is_some() {
        return Err((2, "--uplink-status and --no-uplink are exclusive".into()));
    }
    let agentd = (!a.flag("no-agentd")).then(|| {
        let p = one("agentd-status").ok().flatten().unwrap_or(AGENTD_STATUS);
        read_json(Path::new(p))
    });
    let uplink = if a.flag("no-uplink") {
        None
    } else {
        match one("uplink-status")? {
            // Given explicitly: a missing file is reported.
            Some(p) => Some(read_json(Path::new(p))),
            // Default: only where the uplink is installed and has run.
            None => Path::new(UPLINK_STATUS)
                .exists()
                .then(|| read_json(Path::new(UPLINK_STATUS))),
        }
    };
    let inputs = Inputs {
        agentd,
        uplink,
        now_mono_ms: robodr_agentd::notify::monotonic_ms(),
        boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap_or_default()
            .trim()
            .to_string(),
        now_wall_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
    };
    let text = metrics::render(&inputs);
    if a.flag("stdout") {
        print!("{text}");
        return Ok(());
    }
    let out = PathBuf::from(one("out")?.unwrap_or(DEFAULT_OUT));
    if !out.is_absolute() || out.extension().and_then(|e| e.to_str()) != Some("prom") {
        return Err((2, "--out must be an absolute path ending in .prom".into()));
    }
    write_atomic(&out, &text).map_err(|e| (1, format!("{}: {e}", out.display())))
}
