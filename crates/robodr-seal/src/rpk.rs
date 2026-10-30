//! Sealed RPKs end to end: what `robodr-release build rpk --seal-to`
//! does per file ([`Sealer`]), what the depot does per unit
//! ([`rewrap_for_unit`], §7.3; `robodr-depot` from 14a, the
//! `robodr-seal rewrap` command until then), and what the unit does per
//! file ([`open_file`]).

use crate::chunk::{self, ChunkPlace, ContentKey, FileDigest};
use crate::unit::{seal_id, UnitRecord};
use crate::wrap::{self, Recipient, Unwrapper, WrapContext};
use crate::{invalid, unauthentic, SealError};
use robodr_pkg::deployment::WrappedKey;
use robodr_pkg::rpk::{Chunk, DepotWrap, Manifest, Seal, SEAL_SCHEME};

/// The sealing side of one RPK build: a fresh content key and `seal_id`.
#[derive(Debug)]
pub struct Sealer {
    ck: ContentKey,
    seal_id: [u8; 32],
}

impl Sealer {
    pub fn new() -> Result<Self, SealError> {
        Ok(Self {
            ck: ContentKey::generate()?,
            seal_id: *crate::random32()?,
        })
    }

    /// Seal the piece at `pos` of `count` of file `file_index`.
    pub fn seal_piece(
        &self,
        file_index: u32,
        pos: u32,
        count: u32,
        pt: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        chunk::seal_chunk(
            &self.ck,
            &self.seal_id,
            ChunkPlace {
                file_index,
                pos,
                count,
            },
            pt,
        )
    }

    /// The keyed digest of a file's plaintext (its `sha256` member).
    pub fn file_digest(&self) -> FileDigest {
        self.ck.file_digest(&self.seal_id)
    }

    /// The manifest's `seal` member: the content key wrapped to each depot
    /// key (X25519), sorted by fingerprint. The key itself is dropped with
    /// the sealer: only the depots can recover it.
    pub fn seal_member(&self, depots: &[[u8; 32]]) -> Result<Seal, SealError> {
        if depots.is_empty() || depots.len() > robodr_pkg::rpk::MAX_DEPOT_WRAPS {
            return Err(invalid(format!(
                "1..={} depot wrapping keys",
                robodr_pkg::rpk::MAX_DEPOT_WRAPS
            )));
        }
        let ctx = WrapContext::Depot {
            seal_id: self.seal_id,
        };
        let mut wraps = Vec::with_capacity(depots.len());
        for d in depots {
            let r = Recipient::X25519(*d);
            wraps.push(DepotWrap {
                recipient: r.fingerprint(),
                wrap: crate::to_hex(&wrap::wrap(&r, self.ck.expose(), &ctx)?),
            });
        }
        wraps.sort_by(|a, b| a.recipient.cmp(&b.recipient));
        if wraps.windows(2).any(|w| w[0].recipient == w[1].recipient) {
            return Err(invalid("the same depot key twice"));
        }
        Ok(Seal {
            scheme: SEAL_SCHEME.into(),
            seal_id: crate::to_hex(&self.seal_id),
            ck_commit: crate::to_hex(&self.ck.commit(&self.seal_id)),
            depot_wraps: wraps,
        })
    }
}

fn seal_of(m: &Manifest) -> Result<&Seal, SealError> {
    m.seal
        .as_ref()
        .filter(|_| m.is_sealed())
        .ok_or_else(|| invalid(format!("{} is not a sealed RPK", m.name)))
}

/// The depot side (§7.3): recover the content key of sealed RPK
/// `rpk_digest` from the manifest's wrap to `depot` (checked against the
/// key commitment) and wrap it to `unit`'s UWK, bound to that unit and
/// that RPK.
pub fn rewrap_for_unit(
    depot: &dyn Unwrapper,
    m: &Manifest,
    rpk_digest: &str,
    unit: &UnitRecord,
) -> Result<WrappedKey, SealError> {
    let seal = seal_of(m)?;
    if unit.platform != m.platform {
        return Err(invalid(format!(
            "unit {} is platform {}, the RPK is for {}",
            unit.unit, unit.platform, m.platform
        )));
    }
    let me = depot.recipient().fingerprint();
    let dw = seal
        .depot_wraps
        .iter()
        .find(|w| w.recipient == me)
        .ok_or_else(|| unauthentic("the RPK carries no wrap for this depot key"))?;
    let w = crate::from_hex(&dw.wrap).ok_or_else(|| invalid("bad depot wrap hex"))?;
    let sid = seal_id(seal)?;
    let k = wrap::unwrap(depot, &w, &WrapContext::Depot { seal_id: sid })?;
    let ck = ContentKey::from_bytes(&k[..])?;
    let commit = crate::from_hex(&seal.ck_commit).ok_or_else(|| invalid("bad ck_commit"))?;
    ck.check_commit(&sid, &commit)?;
    let uw = wrap::wrap(
        &unit.recipient()?,
        ck.expose(),
        &WrapContext::Unit {
            unit: unit.unit.clone(),
            rpk_digest: rpk_digest.into(),
        },
    )?;
    Ok(WrappedKey {
        unit: unit.unit.clone(),
        rpk_digest: rpk_digest.into(),
        wrap: crate::to_hex(&uw),
    })
}

/// Open content file `file_index` of sealed manifest `m` with `ck`:
/// `chunk` supplies each chunk's stored bytes (checked against the
/// manifest entry here), `out` receives each plaintext piece only after it
/// authenticated. At the end the size and the keyed file digest must
/// match; on any error the caller must discard what `out` received.
pub fn open_file(
    ck: &ContentKey,
    m: &Manifest,
    file_index: usize,
    chunk: &mut dyn FnMut(&Chunk) -> Result<Vec<u8>, SealError>,
    out: &mut dyn FnMut(&[u8]) -> Result<(), SealError>,
) -> Result<(), SealError> {
    let seal = seal_of(m)?;
    let sid = seal_id(seal)?;
    let f = m
        .content
        .get(file_index)
        .ok_or_else(|| invalid("content index out of range"))?;
    if !m.is_sealed_file(f) {
        return Err(invalid(format!("{} is not a sealed file", f.path)));
    }
    let count = u32::try_from(f.chunks.len()).map_err(|_| invalid("too many chunks"))?;
    let fi = u32::try_from(file_index).map_err(|_| invalid("too many files"))?;
    let mut digest = ck.file_digest(&sid);
    let mut n: u64 = 0;
    for (pos, &ci) in f.chunks.iter().enumerate() {
        let c = m
            .chunks
            .get(ci as usize)
            .ok_or_else(|| invalid("chunk index out of range"))?;
        let bytes = chunk(c)?;
        robodr_pkg::rpk::check_chunk(c, &bytes).map_err(|e| unauthentic(e.to_string()))?;
        let pt = chunk::open_chunk(
            ck,
            &sid,
            ChunkPlace {
                file_index: fi,
                pos: pos as u32,
                count,
            },
            &bytes,
        )?;
        digest.update(&pt);
        n += pt.len() as u64;
        out(&pt)?;
    }
    let want = crate::from_hex(&f.sha256).ok_or_else(|| invalid("bad content digest"))?;
    if n != f.size || !crate::ct_eq(&digest.finalize(), &want) {
        return Err(unauthentic(format!(
            "{}: plaintext does not match its keyed digest",
            f.path
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wrap::{p256_random, P256Secret, X25519Secret};
    use robodr_pkg::common::sha256_hex;
    use robodr_pkg::rpk::{
        Arch, Confidentiality, ContentFile, Install, Kind, Version, CHUNK_SIZE, RPK_FORMAT,
    };
    use std::collections::BTreeMap;

    /// A sealed manifest of `files` (each 1..=2 small pieces) and its
    /// chunk store.
    pub fn build(
        sealer: &Sealer,
        depots: &[[u8; 32]],
        files: &[(&str, Vec<Vec<u8>>)],
    ) -> (Manifest, BTreeMap<String, Vec<u8>>) {
        let mut store = BTreeMap::new();
        let mut content = Vec::new();
        let mut per_file = Vec::new();
        let mut sorted: Vec<_> = files.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (fi, (path, pieces)) in sorted.iter().enumerate() {
            let mut d = sealer.file_digest();
            let mut hashes = Vec::new();
            let mut size = 0u64;
            for (pos, p) in pieces.iter().enumerate() {
                let c = sealer
                    .seal_piece(fi as u32, pos as u32, pieces.len() as u32, p)
                    .unwrap();
                d.update(p);
                size += p.len() as u64;
                let h = sha256_hex(&c);
                hashes.push((h.clone(), c.len() as u64));
                store.insert(h, c);
            }
            per_file.push(hashes);
            content.push(ContentFile {
                path: (*path).into(),
                mode: 0o640,
                size,
                sha256: crate::to_hex(&d.finalize()),
                chunks: vec![],
            });
        }
        let mut chunks: Vec<Chunk> = per_file
            .iter()
            .flatten()
            .map(|(h, s)| Chunk {
                sha256: h.clone(),
                size: *s,
            })
            .collect();
        chunks.sort_by(|a, b| a.sha256.cmp(&b.sha256));
        for (c, hashes) in content.iter_mut().zip(&per_file) {
            c.chunks = hashes
                .iter()
                .map(|(h, _)| chunks.iter().position(|x| &x.sha256 == h).unwrap() as u32)
                .collect();
        }
        let m = Manifest {
            format: RPK_FORMAT.into(),
            name: "nav-model".into(),
            version: Version {
                serial: 3,
                display: "3".into(),
            },
            kind: Kind::Model,
            platform: "ugv-x1".into(),
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
        (m, store)
    }

    fn unit_rec(name: &str, r: &Recipient) -> UnitRecord {
        let (mode, tpm) = match r {
            Recipient::P256(_) => (crate::unit::Mode::Tpm, None),
            Recipient::X25519(_) => (crate::unit::Mode::Fallback, None),
        };
        UnitRecord {
            format: crate::unit::UNIT_FORMAT.into(),
            unit: name.into(),
            platform: "ugv-x1".into(),
            mode,
            uwk_public: crate::to_hex(r.public_bytes()),
            tpm,
            fallback_key: None,
        }
    }

    fn read_all(
        ck: &ContentKey,
        m: &Manifest,
        fi: usize,
        store: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>, SealError> {
        let mut out = Vec::new();
        open_file(
            ck,
            m,
            fi,
            &mut |c| {
                store
                    .get(&c.sha256)
                    .cloned()
                    .ok_or_else(|| invalid("missing"))
            },
            &mut |p| {
                out.extend_from_slice(p);
                Ok(())
            },
        )?;
        Ok(out)
    }

    fn unit_ck(
        u: &P256Secret,
        m: &Manifest,
        wk: &WrappedKey,
        name: &str,
    ) -> Result<ContentKey, SealError> {
        let k = wrap::unwrap(
            u,
            &crate::from_hex(&wk.wrap).unwrap(),
            &WrapContext::Unit {
                unit: name.into(),
                rpk_digest: wk.rpk_digest.clone(),
            },
        )?;
        let ck = ContentKey::from_bytes(&k[..])?;
        let s = m.seal.as_ref().unwrap();
        ck.check_commit(&seal_id(s)?, &crate::from_hex(&s.ck_commit).unwrap())?;
        Ok(ck)
    }

    #[test]
    fn release_depot_unit_end_to_end() {
        let depot = X25519Secret::generate().unwrap();
        let sealer = Sealer::new().unwrap();
        let (m, store) = build(
            &sealer,
            &[depot.public()],
            &[
                ("weights.onnx", vec![b"layer one".to_vec(), b"two".to_vec()]),
                ("labels.txt", vec![b"cat\ndog\n".to_vec()]),
            ],
        );
        drop(sealer);
        // (Pieces are tiny, so the manifest is not a valid 4 MiB-chunked
        // one; open_file judges only what it needs.)
        let digest = "ab".repeat(32);
        let u7 = P256Secret(p256_random().unwrap());
        let wk =
            rewrap_for_unit(&depot, &m, &digest, &unit_rec("ugv-07", &u7.recipient())).unwrap();
        let ck = unit_ck(&u7, &m, &wk, "ugv-07").unwrap();
        // content[] is sorted: labels.txt is file 0.
        assert_eq!(read_all(&ck, &m, 0, &store).unwrap(), b"cat\ndog\n");
        assert_eq!(read_all(&ck, &m, 1, &store).unwrap(), b"layer onetwo");
        // Another unit cannot use ugv-07's wrap (a moved media pack).
        let u8_ = P256Secret(p256_random().unwrap());
        assert!(unit_ck(&u8_, &m, &wk, "ugv-08").is_err());
        assert!(unit_ck(&u8_, &m, &wk, "ugv-07").is_err());
        // Nor ugv-07 with the wrap relabelled for another RPK.
        let mut other = wk.clone();
        other.rpk_digest = "cd".repeat(32);
        assert!(unit_ck(&u7, &m, &other, "ugv-07").is_err());
        // A tampered wrap.
        let mut t = wk.clone();
        let mut b = crate::from_hex(&t.wrap).unwrap();
        b[70] ^= 1;
        t.wrap = crate::to_hex(&b);
        assert!(unit_ck(&u7, &m, &t, "ugv-07").is_err());
        // Another depot cannot re-wrap.
        let d2 = X25519Secret::generate().unwrap();
        assert!(rewrap_for_unit(&d2, &m, &digest, &unit_rec("ugv-07", &u7.recipient())).is_err());
        // A unit of another platform is refused by the depot.
        let mut rec = unit_rec("ugv-07", &u7.recipient());
        rec.platform = "arm-x2".into();
        assert!(rewrap_for_unit(&depot, &m, &digest, &rec).is_err());
    }

    #[test]
    fn chunk_reorder_truncation_and_cross_rpk_swap_are_refused() {
        let depot = X25519Secret::generate().unwrap();
        let s1 = Sealer::new().unwrap();
        let files = [(
            "w.bin",
            vec![b"AAAA".to_vec(), b"BBBB".to_vec(), b"CC".to_vec()],
        )];
        let (m, store) = build(&s1, &[depot.public()], &files);
        let ck1 = ContentKey::from_bytes(s1.ck.expose()).unwrap();
        assert_eq!(read_all(&ck1, &m, 0, &store).unwrap(), b"AAAABBBBCC");
        // Reorder: swap the first two chunk indices of the file (as if the
        // manifest had been re-signed with them swapped).
        let mut r = m.clone();
        r.content[0].chunks.swap(0, 1);
        assert!(read_all(&ck1, &r, 0, &store).is_err());
        // Truncate the file by its last chunk (size adjusted).
        let mut t = m.clone();
        t.content[0].chunks.pop();
        t.content[0].size -= 2;
        assert!(read_all(&ck1, &t, 0, &store).is_err());
        // Swap a chunk's bytes for those of the same place in another
        // sealed build of the same files (another unit's or another
        // release's copy): the stored hash no longer matches, and with
        // the hash rewritten the AEAD refuses it.
        let s2 = Sealer::new().unwrap();
        let (m2, store2) = build(&s2, &[depot.public()], &files);
        let mut swapped = store.clone();
        let h1 = &m.chunks[m.content[0].chunks[0] as usize].sha256;
        let h2 = &m2.chunks[m2.content[0].chunks[0] as usize].sha256;
        swapped.insert(h1.clone(), store2[h2].clone());
        assert!(read_all(&ck1, &m, 0, &swapped).is_err());
        let mut m_rehashed = m.clone();
        let i = m.content[0].chunks[0] as usize;
        m_rehashed.chunks[i].sha256 = h2.clone();
        let mut s = store.clone();
        s.insert(h2.clone(), store2[h2].clone());
        let e = read_all(&ck1, &m_rehashed, 0, &s).unwrap_err();
        assert_eq!(e.kind, crate::ErrorKind::Unauthentic);
        // The wrong content key (another RPK's) opens nothing.
        let ck2 = ContentKey::from_bytes(s2.ck.expose()).unwrap();
        assert!(read_all(&ck2, &m, 0, &store).is_err());
        let _ = CHUNK_SIZE;
    }
}
