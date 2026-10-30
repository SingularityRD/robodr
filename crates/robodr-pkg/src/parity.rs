//! Bundle parity: Reed-Solomon erasure coding of bundle files with
//! `robodr-diode`'s code (`rs-gf256-0x11d/1`, [`robodr_diode::fec`]).
//!
//! # Layout (decision, `docs/SECURE-DELIVERY.md` §3.5)
//!
//! The **data files** are every entry of `bundle.json` `files` that is not
//! under `parity/`, in listed (path) order. They are cut into consecutive
//! groups of `k` = `data_shards` files (the last group may be shorter).
//! Group `g` (1-based) carries `m` = `parity_shards` parity files
//! `parity/g<gggg>-p<jj>.rbpar`, each the group's largest data file rounded
//! up to a multiple of `shard_size` (diode's [`parity_len`]). Byte `o` of
//! the group's data files (zero-padded) and parity files is one RS
//! codeword, exactly as a diode batch: so any `m` missing or damaged files
//! of one group can be rebuilt. Damage is found by SHA-256 against
//! `bundle.json`, which turns every corruption into an erasure; a rebuilt
//! file is accepted only if its hash then matches. Groups bound the code
//! length (`k + m <= 255`) for bundles with thousands of chunk files and
//! keep memory to one stripe (`(k + m) * shard_size`).
//!
//! Parity files are listed in `bundle.json` like any other file, so they are
//! signed; they protect against loss and corruption in transit, never
//! against forgery (that is the signatures' job, checked after repair).

use crate::bundle::{BundleManifest, PathKind};
use crate::common::{invalid, Code, Refusal};
use robodr_diode::fec::{FecError, ReedSolomon, MAX_SHARDS};
use robodr_diode::manifest::{parity_len, MAX_PARITY_SHARDS, MAX_SHARD_SIZE, MIN_SHARD_SIZE};

pub use robodr_diode::manifest::PARITY_SCHEME;

/// Directory of the parity files.
pub const PARITY_DIR: &str = "parity";
/// Most groups (4-digit group number).
pub const MAX_GROUPS: usize = 9999;

/// File name of parity file `j` (1-based) of group `g` (1-based).
pub fn parity_name(g: usize, j: usize) -> String {
    format!("g{g:04}-p{j:02}.rbpar")
}

/// Bundle path of parity file `j` of group `g`.
pub fn parity_path(g: usize, j: usize) -> String {
    format!("{PARITY_DIR}/{}", parity_name(g, j))
}

/// Inverse of [`parity_name`]: `(group, index)`, both >= 1, canonical form only.
pub fn parse_parity_name(s: &str) -> Option<(u32, u32)> {
    let r = s.strip_prefix('g')?.strip_suffix(".rbpar")?;
    let (g, j) = r.split_once("-p")?;
    let digits = |x: &str, n: usize| x.len() == n && x.bytes().all(|b| b.is_ascii_digit());
    if !digits(g, 4) || !digits(j, 2) {
        return None;
    }
    let (g, j): (u32, u32) = (g.parse().ok()?, j.parse().ok()?);
    (g >= 1 && j >= 1).then_some((g, j))
}

/// One parity group: indices into `files`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Data files of the group, in order.
    pub data: Vec<usize>,
    /// Parity files of the group, in order (`p01`..).
    pub parity: Vec<usize>,
    /// Length of every parity file (and of the zero-padded codeword rows).
    pub len: u64,
}

impl Group {
    /// Members in codeword order: data, then parity.
    pub fn members(&self) -> Vec<usize> {
        self.data.iter().chain(&self.parity).copied().collect()
    }
}

/// Check parity parameters.
pub fn check_params(k: usize, m: usize, shard_size: u64) -> Result<(), Refusal> {
    if !(1..=MAX_PARITY_SHARDS).contains(&m) || k == 0 || k + m > MAX_SHARDS {
        return Err(invalid(format!(
            "parity: need 1..={MAX_PARITY_SHARDS} parity files per group and k + m <= {MAX_SHARDS}"
        )));
    }
    if !(MIN_SHARD_SIZE..=MAX_SHARD_SIZE).contains(&shard_size) {
        return Err(invalid(format!(
            "parity: shard_size must be in {MIN_SHARD_SIZE}..={MAX_SHARD_SIZE}"
        )));
    }
    Ok(())
}

/// Group ranges (over data-file positions `0..n`) and parity lengths for
/// data files of `sizes`, used by the builder before parity entries exist.
pub fn layout(
    sizes: &[u64],
    k: usize,
    m: usize,
    shard_size: u64,
) -> Result<Vec<(std::ops::Range<usize>, u64)>, Refusal> {
    check_params(k, m, shard_size)?;
    if sizes.is_empty() {
        return Err(invalid("parity: no data files"));
    }
    let groups = sizes.len().div_ceil(k);
    if groups > MAX_GROUPS {
        return Err(invalid(format!(
            "parity: more than {MAX_GROUPS} groups; raise data_shards"
        )));
    }
    // k >= 1 (check_params), so `chunks` cannot panic.
    Ok(sizes
        .chunks(k)
        .enumerate()
        .map(|(g, group)| {
            let r = g * k..g * k + group.len();
            let max = group.iter().copied().max().unwrap_or(0);
            (r, parity_len(max, shard_size))
        })
        .collect())
}

/// The parity groups of a bundle whose `parity` section is set, checking
/// that exactly the expected parity files are listed with the right sizes.
pub fn plan(b: &BundleManifest) -> Result<Vec<Group>, Refusal> {
    let p = b
        .parity
        .as_ref()
        .ok_or_else(|| invalid("parity: bundle has no parity section"))?;
    if p.scheme != PARITY_SCHEME {
        return Err(Refusal::new(
            Code::Unsupported,
            "parity: unsupported scheme",
        ));
    }
    let (k, m) = (p.data_shards as usize, p.parity_shards as usize);
    let mut data = Vec::new();
    let mut sizes: Vec<u64> = Vec::new();
    let mut parity = std::collections::BTreeMap::new();
    for (i, f) in b.files.iter().enumerate() {
        match crate::bundle::classify(&f.path) {
            Some(PathKind::Parity { group, index }) => {
                parity.insert((group as usize, index as usize), (i, f));
            }
            Some(_) => {
                data.push(i);
                sizes.push(f.size);
            }
            None => return Err(invalid("parity: unclassifiable path")),
        }
    }
    let lay = layout(&sizes, k, m, p.shard_size)?;
    if lay.len() != p.groups as usize {
        return Err(invalid(format!(
            "parity: {} groups declared, {} needed",
            p.groups,
            lay.len()
        )));
    }
    let mut out = Vec::with_capacity(lay.len());
    for (g, (r, len)) in lay.into_iter().enumerate() {
        let mut pf = Vec::with_capacity(m);
        for j in 1..=m {
            let (i, f) = parity.remove(&(g + 1, j)).ok_or_else(|| {
                invalid(format!("parity: {} is not listed", parity_path(g + 1, j)))
            })?;
            if f.size != len {
                return Err(invalid(format!("parity: {} must be {len} bytes", f.path)));
            }
            pf.push(i);
        }
        // `layout` ranges cover `0..sizes.len()` == `0..data.len()`.
        let group_data = data
            .get(r)
            .ok_or_else(|| invalid("parity: group out of range"))?;
        out.push(Group {
            data: group_data.to_vec(),
            parity: pf,
            len,
        });
    }
    if let Some(((g, j), _)) = parity.into_iter().next() {
        return Err(invalid(format!(
            "parity: {} does not belong to the layout",
            parity_path(g, j)
        )));
    }
    Ok(out)
}

fn fec(e: FecError) -> Refusal {
    invalid(format!("parity: {e}"))
}

/// Reads one block of a group member: `buf.len()` bytes at `offset` of
/// codeword position `pos` (data `0..k`, parity `k..k+m`); bytes past the
/// member's end must read as zero.
pub type ReadBlock<'a> = dyn FnMut(usize, u64, &mut [u8]) -> Result<(), Refusal> + 'a;
/// Writes one block of a member: `bytes` at `offset` of position `pos`.
pub type WriteBlock<'a> = dyn FnMut(usize, u64, &[u8]) -> Result<(), Refusal> + 'a;

/// Compute the `m` parity members of a group of `k` data members whose
/// parity length is `len`, stripe by stripe (`shard_size` rows).
pub fn encode_group(
    k: usize,
    m: usize,
    len: u64,
    shard_size: u64,
    read: &mut ReadBlock<'_>,
    write: &mut WriteBlock<'_>,
) -> Result<(), Refusal> {
    let rs = ReedSolomon::new(k, m).map_err(fec)?;
    let mut off = 0u64;
    while off < len {
        let n = usize::try_from((len - off).min(shard_size)).map_err(|_| invalid("block size"))?;
        let mut data = vec![vec![0u8; n]; k];
        for (i, d) in data.iter_mut().enumerate() {
            read(i, off, d)?;
        }
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let parity = rs.encode(&refs, n).map_err(fec)?;
        for (j, p) in parity.iter().enumerate() {
            write(k + j, off, p)?;
        }
        off += n as u64;
    }
    Ok(())
}

/// Rebuild the members at `erased` codeword positions of a group (`k` data,
/// `m` parity, parity length `len`) from the others, stripe by stripe.
/// The caller checks each rebuilt member's hash before trusting it; for a
/// data member it must keep only the first `size` bytes (the rest is the
/// zero padding of the codeword).
pub fn rebuild_group(
    k: usize,
    m: usize,
    len: u64,
    shard_size: u64,
    erased: &[usize],
    read: &mut ReadBlock<'_>,
    write: &mut WriteBlock<'_>,
) -> Result<(), Refusal> {
    let rs = ReedSolomon::new(k, m).map_err(fec)?;
    let dec = rs.decoder(erased).map_err(|e| match e {
        FecError::TooManyErasures { erased, max } => Refusal::new(
            Code::FileMismatch,
            format!("parity: {erased} damaged files in one group, at most {max} can be rebuilt"),
        ),
        e => fec(e),
    })?;
    let mut off = 0u64;
    while off < len {
        let n = usize::try_from((len - off).min(shard_size)).map_err(|_| invalid("block size"))?;
        let mut known = vec![vec![0u8; n]; dec.known().len()];
        for (buf, &pos) in known.iter_mut().zip(dec.known()) {
            read(pos, off, buf)?;
        }
        let mut out = vec![vec![0u8; n]; erased.len()];
        {
            let krefs: Vec<&[u8]> = known.iter().map(Vec::as_slice).collect();
            let mut orefs: Vec<&mut [u8]> = out.iter_mut().map(Vec::as_mut_slice).collect();
            dec.reconstruct(&krefs, &mut orefs).map_err(fec)?;
        }
        for (buf, &pos) in out.iter().zip(dec.erased()) {
            write(pos, off, buf)?;
        }
        off += n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(parity_path(1, 2), "parity/g0001-p02.rbpar");
        assert_eq!(parse_parity_name("g0001-p02.rbpar"), Some((1, 2)));
        for bad in [
            "g0000-p01.rbpar",
            "g1-p1.rbpar",
            "g0001-p00.rbpar",
            "g0001-p01.rbpa",
            "x",
            "g0001-p01.rbpar/",
        ] {
            assert_eq!(parse_parity_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn layout_groups() {
        let l = layout(&[1, 2, 3, 4, 5], 2, 1, 512).unwrap();
        assert_eq!(l, vec![(0..2, 512), (2..4, 512), (4..5, 512)]);
        assert!(layout(&[1], 0, 1, 512).is_err());
        assert!(layout(&[1], 1, 0, 512).is_err());
        assert!(layout(&[1], 250, 6, 512).is_err());
        assert!(layout(&[1], 1, 33, 512).is_err());
        assert!(layout(&[1], 1, 1, 511).is_err());
        assert!(layout(&[], 1, 1, 512).is_err());
        assert!(layout(&vec![1; MAX_GROUPS + 1], 1, 1, 512).is_err());
    }

    #[test]
    fn encode_then_rebuild_every_pattern() {
        let files: Vec<Vec<u8>> = vec![
            (0..1500u32).map(|i| (i * 7) as u8).collect(),
            b"short".to_vec(),
            vec![],
        ];
        let (k, m, shard) = (3usize, 2usize, 512u64);
        let len = parity_len(1500, shard);
        let mut members: Vec<Vec<u8>> = files.clone();
        members.resize(k + m, Vec::new());
        {
            let src = files.clone();
            let mut par = vec![vec![0u8; len as usize]; m];
            encode_group(
                k,
                m,
                len,
                shard,
                &mut |pos, off, buf| {
                    let f = &src[pos];
                    for (i, b) in buf.iter_mut().enumerate() {
                        *b = *f.get(off as usize + i).unwrap_or(&0);
                    }
                    Ok(())
                },
                &mut |pos, off, bytes| {
                    par[pos - k][off as usize..off as usize + bytes.len()].copy_from_slice(bytes);
                    Ok(())
                },
            )
            .unwrap();
            members[k..].clone_from_slice(&par);
        }
        let all = members.clone();
        for a in 0..k + m {
            for b in a..k + m {
                let erased: Vec<usize> = if a == b { vec![a] } else { vec![a, b] };
                let mut rebuilt = vec![vec![0u8; len as usize]; k + m];
                rebuild_group(
                    k,
                    m,
                    len,
                    shard,
                    &erased,
                    &mut |pos, off, buf| {
                        assert!(!erased.contains(&pos), "read an erased member");
                        let f = &all[pos];
                        for (i, x) in buf.iter_mut().enumerate() {
                            *x = *f.get(off as usize + i).unwrap_or(&0);
                        }
                        Ok(())
                    },
                    &mut |pos, off, bytes| {
                        rebuilt[pos][off as usize..off as usize + bytes.len()]
                            .copy_from_slice(bytes);
                        Ok(())
                    },
                )
                .unwrap();
                for &e in &erased {
                    let want = &all[e];
                    assert_eq!(
                        &rebuilt[e][..want.len()],
                        &want[..],
                        "member {e} of {erased:?}"
                    );
                    assert!(rebuilt[e][want.len()..].iter().all(|&x| x == 0));
                }
            }
        }
        let e = rebuild_group(
            k,
            m,
            len,
            shard,
            &[0, 1, 2],
            &mut |_, _, _| Ok(()),
            &mut |_, _, _| Ok(()),
        )
        .unwrap_err();
        assert_eq!(e.code, Code::FileMismatch);
    }
}
