//! Writes the shared `robodr.fleet-api` contract test vectors:
//!
//! ```text
//! cargo run -p robodr-fleet --example fleet_vectors [-- OUT_DIR]
//! ```
//!
//! Default `OUT_DIR`: `docs/contracts/fixtures/fleet/` of this checkout. The
//! output is deterministic; `tests/fleet_vectors.rs` fails when the committed
//! files differ from it. `keys/`, `tokens/`, `cases/` and `manifest.json`
//! under `OUT_DIR` are replaced; nothing else there is touched. It also
//! refreshes the fuzz seed corpora `fuzz/corpus/fleet_token/` and
//! `fuzz/corpus/fleet_envelope/` (default output only).

#[path = "../tests/common/soc.rs"]
mod soc;
#[path = "../tests/common/vectors.rs"]
mod vectors;

use std::fs;
use std::path::{Path, PathBuf};

fn reset(dir: &Path) -> std::io::Result<()> {
    match fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn main() -> std::io::Result<()> {
    let arg = std::env::args_os().nth(1).map(PathBuf::from);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = arg
        .clone()
        .unwrap_or_else(|| root.join("docs/contracts/fixtures/fleet"));
    fs::create_dir_all(&out)?;
    for d in ["keys", "tokens", "cases"] {
        reset(&out.join(d))?;
    }
    let files = vectors::files();
    for (rel, bytes) in &files {
        let p = out.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&p, bytes)?;
    }
    println!("{} files written to {}", files.len(), out.display());
    if arg.is_none() {
        let (tok, env) = vectors::fuzz_seeds();
        for (name, seeds) in [("fleet_token", tok), ("fleet_envelope", env)] {
            let d = root.join("fuzz/corpus").join(name);
            reset(&d)?;
            fs::create_dir_all(&d)?;
            for (f, b) in seeds {
                fs::write(d.join(f), b)?;
            }
        }
        println!("fuzz seeds refreshed");
    }
    Ok(())
}
