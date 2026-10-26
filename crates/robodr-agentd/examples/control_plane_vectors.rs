//! Writes the shared `robodr-control-plane/v2` contract test vectors:
//!
//! ```text
//! cargo run -p robodr-agentd --example control_plane_vectors [-- OUT_DIR]
//! ```
//!
//! Default `OUT_DIR`: `docs/contracts/fixtures/control-plane-v2/` of this
//! checkout. The output is deterministic; `tests/control_plane_vectors.rs`
//! fails when the committed files differ from it. `OUT_DIR` is replaced as
//! a whole (it holds nothing else).

#[path = "../tests/common/cp_vectors.rs"]
mod cp_vectors;

use std::fs;
use std::path::{Path, PathBuf};

fn main() -> std::io::Result<()> {
    let out = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/contracts/fixtures/control-plane-v2")
        });
    match fs::remove_dir_all(&out) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let files = cp_vectors::files();
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
