//! The unit's content-addressed store (`<state_dir>/store/`):
//!
//! ```text
//! store/chunks/<sha256>              payload chunks, 0600, named by their hash
//! store/rpks/<digest>/MANIFEST.json  the signed manifest (its digest is the dir name)
//! store/rpks/<digest>/MANIFEST.sig
//! ```
//!
//! It is filled only from the **verified copy** of an imported pack
//! (`media`), and every chunk is hashed again as it is written: a chunk
//! whose bytes are not its name is never stored (§10, 13b requirement 7).
//! Installers materialise files from here, hashing every chunk and every
//! file again on the way out, so nothing is installed from bytes that were
//! not checked at the moment of use. Rollback targets stay here until
//! garbage collection drops versions no longer kept.

use crate::fsx;
use robodr_pkg::rpk::{
    self, check_chunk, ContentFile, Manifest, CHUNKS_DIR, MANIFEST_FILE, MAX_MANIFEST_BYTES,
    SIGNATURE_FILE,
};
use robodr_pkg::sig::MAX_SIGSET_BYTES;
use robodr_release::fsio::read_capped;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The store under a state directory.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

fn io(p: &Path, e: impl std::fmt::Display) -> String {
    format!("{}: {e}", p.display())
}

impl Store {
    /// Open (create) `<state_dir>/store`.
    pub fn open(state_dir: &Path) -> Result<Self, String> {
        let root = state_dir.join("store");
        for d in [root.clone(), root.join("chunks"), root.join("rpks")] {
            fsx::ensure_dir(&d, 0o700).map_err(|e| io(&d, e))?;
        }
        Ok(Self { root })
    }

    fn chunk_path(&self, sha: &str) -> PathBuf {
        self.root.join("chunks").join(sha)
    }

    fn rpk_dir(&self, digest: &str) -> PathBuf {
        self.root.join("rpks").join(digest)
    }

    /// Whether the store holds the RPK `digest` (manifest and every chunk).
    pub fn has_rpk(&self, digest: &str) -> bool {
        match self.manifest(digest) {
            Ok(m) => m.chunks.iter().all(|c| {
                fs::symlink_metadata(self.chunk_path(&c.sha256)).is_ok_and(|x| x.is_file())
            }),
            Err(_) => false,
        }
    }

    /// Copy the RPK in `src` (a directory of the verified pack copy) into
    /// the store. `MANIFEST.json` must have `digest`; every chunk is read
    /// bounded by its listed size and hash-checked before it is stored.
    pub fn put_rpk(&self, src: &Path, digest: &str) -> Result<Manifest, String> {
        let mbytes =
            read_capped(&src.join(MANIFEST_FILE), MAX_MANIFEST_BYTES).map_err(|e| e.to_string())?;
        if rpk::rpk_digest(&mbytes) != digest {
            return Err(format!(
                "{}: MANIFEST.json is not RPK {digest}",
                src.display()
            ));
        }
        let sbytes =
            read_capped(&src.join(SIGNATURE_FILE), MAX_SIGSET_BYTES).map_err(|e| e.to_string())?;
        let m = rpk::parse_manifest(&mbytes).map_err(|e| e.to_string())?;
        for c in &m.chunks {
            let dst = self.chunk_path(&c.sha256);
            if fs::symlink_metadata(&dst).is_ok_and(|x| x.is_file()) {
                continue;
            }
            let bytes = read_capped(&src.join(CHUNKS_DIR).join(&c.sha256), c.size as usize)
                .map_err(|e| e.to_string())?;
            check_chunk(c, &bytes).map_err(|e| e.to_string())?;
            let tmp = fsx::temp_sibling(&dst, "in");
            fsx::write_new(&tmp, &bytes, 0o600).map_err(|e| io(&tmp, e))?;
            fs::rename(&tmp, &dst).map_err(|e| {
                let _ = fs::remove_file(&tmp);
                io(&dst, e)
            })?;
        }
        fsx::sync_dir(&self.root.join("chunks")).map_err(|e| io(&self.root, e))?;
        let dir = self.rpk_dir(digest);
        if !fsx::is_real_dir(&dir) {
            let tmp = fsx::temp_sibling(&dir, "in");
            fsx::ensure_dir(&tmp, 0o700).map_err(|e| io(&tmp, e))?;
            fsx::write_new(&tmp.join(MANIFEST_FILE), &mbytes, 0o600).map_err(|e| io(&tmp, e))?;
            fsx::write_new(&tmp.join(SIGNATURE_FILE), &sbytes, 0o600).map_err(|e| io(&tmp, e))?;
            fsx::sync_dir(&tmp).map_err(|e| io(&tmp, e))?;
            fs::rename(&tmp, &dir).map_err(|e| {
                let _ = fsx::remove_any(&tmp);
                io(&dir, e)
            })?;
            fsx::sync_dir(&self.root.join("rpks")).map_err(|e| io(&self.root, e))?;
        }
        Ok(m)
    }

    /// The manifest of a stored RPK (its bytes must still have `digest`).
    pub fn manifest(&self, digest: &str) -> Result<Manifest, String> {
        let p = self.rpk_dir(digest).join(MANIFEST_FILE);
        let b = read_capped(&p, MAX_MANIFEST_BYTES).map_err(|e| e.to_string())?;
        if rpk::rpk_digest(&b) != digest {
            return Err(format!(
                "store: {} no longer has digest {digest}",
                p.display()
            ));
        }
        rpk::parse_manifest(&b).map_err(|e| e.to_string())
    }

    /// Write content file `f` of `m` to `dest` (created exclusively, never
    /// through a symlink), mode `f.mode`, from stored chunks; every chunk
    /// and the whole file are hash-checked.
    pub fn materialize(&self, m: &Manifest, f: &ContentFile, dest: &Path) -> Result<(), String> {
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dest)
            .map_err(|e| io(dest, e))?;
        let r = self.fill(m, f, dest, &mut out);
        if r.is_err() {
            // Never leave a partial or unverified file behind (this call
            // created it: an existing path fails at the open above).
            drop(out);
            let _ = fs::remove_file(dest);
        }
        r
    }

    fn fill(
        &self,
        m: &Manifest,
        f: &ContentFile,
        dest: &Path,
        out: &mut fs::File,
    ) -> Result<(), String> {
        let mut h = robodr_blackbox::crypto::Sha256::new();
        let mut n: u64 = 0;
        for &ci in &f.chunks {
            let c = m
                .chunks
                .get(ci as usize)
                .ok_or_else(|| "manifest: chunk index out of range".to_string())?;
            let bytes = read_capped(&self.chunk_path(&c.sha256), c.size as usize)
                .map_err(|e| format!("store: {e}"))?;
            check_chunk(c, &bytes).map_err(|e| format!("store: {e}"))?;
            h.update(&bytes);
            n += bytes.len() as u64;
            out.write_all(&bytes).map_err(|e| io(dest, e))?;
        }
        if n != f.size || robodr_blackbox::crypto::to_hex(&h.finalize()) != f.sha256 {
            return Err(format!(
                "store: {} does not hash to its manifest entry",
                f.path
            ));
        }
        out.set_permissions(fs::Permissions::from_mode(f.mode))
            .map_err(|e| io(dest, e))?;
        out.sync_all().map_err(|e| io(dest, e))
    }

    /// Drop every stored RPK not in `keep`, then every chunk no kept RPK
    /// uses. Returns the number of RPKs removed.
    pub fn gc(&self, keep: &BTreeSet<String>) -> Result<usize, String> {
        let rpks = self.root.join("rpks");
        let mut removed = 0;
        let mut used: BTreeSet<String> = BTreeSet::new();
        for e in fs::read_dir(&rpks).map_err(|e| io(&rpks, e))? {
            let e = e.map_err(|e| io(&rpks, e))?;
            let name = e.file_name().to_string_lossy().into_owned();
            if keep.contains(&name) {
                if let Ok(m) = self.manifest(&name) {
                    used.extend(m.chunks.iter().map(|c| c.sha256.clone()));
                }
                continue;
            }
            fsx::remove_any(&e.path()).map_err(|x| io(&e.path(), x))?;
            removed += 1;
        }
        let chunks = self.root.join("chunks");
        for e in fs::read_dir(&chunks).map_err(|e| io(&chunks, e))? {
            let e = e.map_err(|e| io(&chunks, e))?;
            let name = e.file_name().to_string_lossy().into_owned();
            if !used.contains(&name) {
                fsx::remove_any(&e.path()).map_err(|x| io(&e.path(), x))?;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_pkg::rpk::{Arch, Chunk, Confidentiality, Install, Kind, Version, RPK_FORMAT};

    fn manifest_for(files: &[(&str, &[u8])]) -> (Manifest, Vec<Vec<u8>>) {
        let mut chunks: Vec<Chunk> = Vec::new();
        let mut blobs = Vec::new();
        for (_, b) in files {
            chunks.push(Chunk {
                sha256: robodr_pkg::common::sha256_hex(b),
                size: b.len() as u64,
            });
            blobs.push(b.to_vec());
        }
        let mut order: Vec<usize> = (0..chunks.len()).collect();
        order.sort_by(|a, b| chunks[*a].sha256.cmp(&chunks[*b].sha256));
        let sorted: Vec<Chunk> = order.iter().map(|i| chunks[*i].clone()).collect();
        let content = files
            .iter()
            .map(|(p, b)| ContentFile {
                path: (*p).into(),
                mode: 0o644,
                size: b.len() as u64,
                sha256: robodr_pkg::common::sha256_hex(b),
                chunks: vec![sorted
                    .iter()
                    .position(|c| c.sha256 == robodr_pkg::common::sha256_hex(b))
                    .unwrap() as u32],
            })
            .collect();
        (
            Manifest {
                format: RPK_FORMAT.into(),
                name: "nav".into(),
                version: Version {
                    serial: 1,
                    display: "1".into(),
                },
                kind: Kind::Files,
                platform: "p".into(),
                arch: Arch::All,
                hw_compat: vec![],
                requires: vec![],
                conflicts: vec![],
                security_floor: 1,
                confidentiality: Confidentiality::Public,
                content,
                chunks: sorted,
                sbom: None,
                install: Install {
                    allow_maintainer_scripts: false,
                    requires_operator_present: false,
                },
                health: vec![],
                expires_at: None,
            },
            blobs,
        )
    }

    #[test]
    fn a_tampered_chunk_is_never_materialised() {
        let d = std::env::temp_dir().join(format!("deliverd-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let s = Store::open(&d).unwrap();
        let (m, blobs) = manifest_for(&[("a", b"hello")]);
        // Put the chunk by hand, then corrupt it.
        let c = &m.chunks[0];
        fs::write(s.chunk_path(&c.sha256), &blobs[0]).unwrap();
        s.materialize(&m, &m.content[0], &d.join("ok")).unwrap();
        assert_eq!(fs::read(d.join("ok")).unwrap(), b"hello");
        fs::write(s.chunk_path(&c.sha256), b"hellx").unwrap();
        assert!(s.materialize(&m, &m.content[0], &d.join("bad")).is_err());
        assert!(!d.join("bad").exists(), "partial file left behind");
        // Never through an existing path or symlink.
        std::os::unix::fs::symlink(d.join("ok"), d.join("link")).unwrap();
        fs::write(s.chunk_path(&c.sha256), &blobs[0]).unwrap();
        assert!(s.materialize(&m, &m.content[0], &d.join("link")).is_err());
        assert_eq!(fs::read(d.join("ok")).unwrap(), b"hello");
        fs::remove_dir_all(&d).unwrap();
    }
}
