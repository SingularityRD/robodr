//! Writes the shared `robodr.ingest` contract test vectors:
//!
//! ```text
//! cargo run -p robodr-export --example ingest_vectors [-- OUT_DIR]
//! ```
//!
//! Default `OUT_DIR`: `docs/contracts/fixtures/ingest/` of this checkout.
//! The output is deterministic; `tests/ingest_vectors.rs` fails when the
//! committed files differ from it. `keys/`, `cases/` and `manifest.json`
//! under `OUT_DIR` are replaced; nothing else there is touched.

#[path = "../tests/common/vectors.rs"]
mod vectors;

use std::fs;
use std::path::{Path, PathBuf};

fn main() -> std::io::Result<()> {
    let out = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts/fixtures/ingest")
        });
    fs::create_dir_all(&out)?;
    for d in ["keys", "cases"] {
        match fs::remove_dir_all(out.join(d)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
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
    Ok(())
}
