//! Batch manifest and signature file: wire format, limits and checks.
//!
//! A batch is one directory named [`batch_dir_name`]`(unit, seq)` holding:
//!
//! * data files listed in the manifest (`findings.jsonl`,
//!   `bundle-NNNN.rbbx`), each with its exact size and SHA-256;
//! * [`MANIFEST_FILE`]: the manifest JSON. Its **raw bytes** are what is
//!   signed and hashed, so no JSON canonicalisation is needed;
//! * [`SIGNATURE_FILE`]: a small JSON object with the algorithm, key id and
//!   the signature over [`manifest_signing_message`].
//!
//! The batch hash ([`batch_hash`]) is a domain-separated SHA-256 of the raw
//! manifest bytes. Because the manifest commits to every file's hash and to
//! the previous batch's hash, the batch hashes form a per-unit hash chain.
//!
//! ## Optional parity (forward error correction)
//!
//! A manifest may carry `parity` ([`ParitySpec`]) and list `m` parity files
//! `parity-01.rbpar` … after the data files. The data files (in manifest
//! order) are the `k` data shards and the parity files the `m` parity shards
//! of a Reed-Solomon code over GF(2^8) ([`crate::fec`], scheme
//! [`PARITY_SCHEME`]): byte `o` of every shard forms one codeword, data
//! shards are zero-padded to the parity length, and the parity length is
//! the largest data file rounded up to a multiple of `shard_size` (the
//! stripe height). Parity files are listed with size and SHA-256 like any
//! other file, so they are covered by the signature. A manifest without
//! parity serialises exactly as before the field existed.

use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_ocsf::validate::{is_valid_robot_id, MAX_TIME_MS, MIN_TIME_MS};
use serde::{Deserialize, Serialize};

/// Format identifier in every manifest and signature file.
pub const FORMAT: &str = "robodr-diode/1";
/// Manifest file name inside a batch directory.
pub const MANIFEST_FILE: &str = "MANIFEST.json";
/// Signature file name inside a batch directory.
pub const SIGNATURE_FILE: &str = "MANIFEST.sig";
/// The (single, optional) findings file of a batch.
pub const FINDINGS_FILE: &str = "findings.jsonl";
/// Hard cap on the manifest size; checked before the file is read.
pub const MAX_MANIFEST_BYTES: usize = 128 * 1024;
/// Hard cap on the signature file size; checked before the file is read.
pub const MAX_SIGNATURE_FILE_BYTES: usize = 4096;
/// Hard cap on the number of data files in one batch.
pub const MAX_FILES: usize = 256;
/// Hard cap on a signature (matches the black-box record format).
pub const MAX_SIG_LEN: usize = robodr_blackbox::record::MAX_SIG_LEN;
/// Hard cap on key ids (matches the black-box signer).
pub const MAX_KEY_ID_LEN: usize = robodr_blackbox::sign::MAX_KEY_ID_LEN;
/// Most parity files a batch may carry.
pub const MAX_PARITY_SHARDS: usize = 32;
/// Smallest / largest `shard_size` (stripe height) of a parity batch.
pub const MIN_SHARD_SIZE: u64 = 512;
pub const MAX_SHARD_SIZE: u64 = 16 * 1024 * 1024;
/// The only parity scheme: RS over GF(2^8)/0x11D, generator roots
/// `α^0..α^(m-1)`, codeword = data files then parity files (manifest order).
pub const PARITY_SCHEME: &str = "rs-gf256-0x11d/1";
/// Longest data file name accepted.
pub const MAX_FILE_NAME: usize = 64;
/// Largest `batch_seq` (the 16 decimal digits of [`batch_dir_name`]). Keeps
/// `seq + 1` far from overflow on both sides.
pub const MAX_BATCH_SEQ: u64 = 9_999_999_999_999_999;

const MANIFEST_DOMAIN: &[u8] = b"robodr-diode/manifest/v1\0";
const BATCH_HASH_DOMAIN: &[u8] = b"robodr-diode/batch-hash/v1\0";

/// What a data file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// JSON Lines of findings values (`robodr.findings` contract, compact
    /// JSON, `\n`-terminated).
    Findings,
    /// A `robodr-blackbox` export bundle (`RBBXBND1` bytes).
    BlackboxBundle,
    /// A Reed-Solomon parity shard (`parity-NN.rbpar`); see [`ParitySpec`].
    Parity,
}

/// Parity parameters of a batch (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParitySpec {
    /// [`PARITY_SCHEME`].
    pub scheme: String,
    /// `k`: number of data files.
    pub data_shards: u32,
    /// `m`: number of parity files (`1..=`[`MAX_PARITY_SHARDS`], `k + m <= 255`).
    pub parity_shards: u32,
    /// Stripe height in bytes: every parity file is the largest data file
    /// rounded up to a multiple of this.
    pub shard_size: u64,
}

/// Length of every parity file for data files of at most `max_data_len`
/// bytes (rounded up to a multiple of `shard_size`, which must be > 0).
pub fn parity_len(max_data_len: u64, shard_size: u64) -> u64 {
    max_data_len.div_ceil(shard_size).saturating_mul(shard_size)
}

/// Name of the `j`-th (1-based) parity file: `parity-01.rbpar`.
pub fn parity_file_name(j: usize) -> String {
    format!("parity-{j:02}.rbpar")
}

/// One data file of a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub name: String,
    pub kind: FileKind,
    pub size: u64,
    /// Lower-case hex SHA-256 of the file bytes.
    pub sha256: String,
}

/// The signed description of one batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// [`FORMAT`].
    pub format: String,
    /// Findings contract version of the findings inside (see
    /// [`is_supported_contract_version`]).
    pub contract_version: String,
    /// Exporting unit (robot or air-gapped site console), `[A-Za-z0-9._-]{1,64}`.
    pub unit_id: String,
    /// 1-based, strictly increasing per unit.
    pub batch_seq: u64,
    /// [`batch_hash`] of batch `batch_seq - 1`; `None` iff `batch_seq == 1`.
    pub prev_batch_hash: Option<String>,
    /// RFC 3339 UTC (ms) rendering of `created_at_ms`.
    pub created_at: String,
    pub created_at_ms: u64,
    /// Signing key id / algorithm (must match the signature file).
    pub key_id: String,
    pub algorithm: String,
    /// Number of lines in `findings.jsonl` (0 when there is no findings file).
    pub finding_count: u64,
    /// Min / max `ocsf.time` of the findings, `None` when there are none.
    pub first_time: Option<u64>,
    pub last_time: Option<u64>,
    /// Data files, then (with `parity`) the parity files in order.
    pub files: Vec<FileEntry>,
    /// Reed-Solomon parity over the data files; absent (not `null`) when
    /// the batch has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parity: Option<ParitySpec>,
}

/// Contents of [`SIGNATURE_FILE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureFile {
    pub format: String,
    pub algorithm: String,
    pub key_id: String,
    /// Lower-case hex signature over [`manifest_signing_message`].
    pub sig: String,
}

/// Directory name of batch `seq` of `unit`: `rdd_<unit>_<seq, 16 digits>`.
pub fn batch_dir_name(unit_id: &str, seq: u64) -> String {
    format!("rdd_{unit_id}_{seq:016}")
}

/// Name of the `i`-th (1-based) bundle file of a batch: `bundle-0001.rbbx`.
pub fn bundle_file_name(i: usize) -> String {
    format!("bundle-{i:04}.rbbx")
}

/// Message signed by the exporter: `"robodr-diode/manifest/v1\0" || manifest bytes`.
pub fn manifest_signing_message(manifest_bytes: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(MANIFEST_DOMAIN.len() + manifest_bytes.len());
    m.extend_from_slice(MANIFEST_DOMAIN);
    m.extend_from_slice(manifest_bytes);
    m
}

/// Batch hash: hex SHA-256 of `"robodr-diode/batch-hash/v1\0" || manifest bytes`.
pub fn batch_hash(manifest_bytes: &[u8]) -> String {
    let mut m = Vec::with_capacity(BATCH_HASH_DOMAIN.len() + manifest_bytes.len());
    m.extend_from_slice(BATCH_HASH_DOMAIN);
    m.extend_from_slice(manifest_bytes);
    to_hex(&sha256(&m))
}

/// Hex SHA-256 of `bytes`.
pub fn file_sha256(bytes: &[u8]) -> String {
    to_hex(&sha256(bytes))
}

/// 64 lower-case hex characters.
pub fn is_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// 1..=128 printable, non-space ASCII characters.
pub fn is_valid_key_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_KEY_ID_LEN && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Allow-list for data file names: `[a-z0-9][a-z0-9._-]{0,63}`, no `..`.
/// This alone rules out absolute paths, separators (`/`, `\`), `..`, NUL,
/// control characters and hidden files; [`FileKind`]-specific names are then
/// required on top ([`Manifest::check`]).
pub fn is_safe_file_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_FILE_NAME
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
        && !s.contains("..")
}

fn is_bundle_name(s: &str) -> bool {
    s.strip_prefix("bundle-")
        .and_then(|r| r.strip_suffix(".rbbx"))
        .is_some_and(|d| d.len() == 4 && d.bytes().all(|b| b.is_ascii_digit()) && d != "0000")
}

/// Accepts a findings contract version whose findings this crate packs and
/// imports: the major [`robodr_ocsf`] emits (`2.y.z`). The check is on the
/// contract version only; the topic and `data_source` the findings name are
/// deployment labels, validated per finding. Contract 1.x batches
/// (`robot-edr.findings`) are refused here with a clear reason: 1.x
/// findings are parse-only and can no longer be published.
pub fn is_supported_contract_version(v: &str) -> bool {
    robodr_ocsf::validate::is_emittable_contract_version(v)
}

/// A contract 1.x version: batches a 1.x packer published before the
/// upgrade. The importer still takes them (it authenticates and chains
/// them like any batch and upgrades their findings to contract 2.0, see
/// `crate::unpack`); the packer never writes one.
pub fn is_legacy_contract_version(v: &str) -> bool {
    robodr_ocsf::upgrade::is_legacy_version(v)
}

impl Manifest {
    /// Structural checks that need nothing but the manifest itself, for a
    /// manifest this crate writes (contract 2.x only). Returns a
    /// human-readable reason on failure.
    pub fn check(&self) -> Result<(), String> {
        self.check_with(false)
    }

    /// [`check`](Self::check) for a manifest the importer reads: also
    /// accepts a contract 1.x batch published before an upgrade.
    pub fn check_import(&self) -> Result<(), String> {
        self.check_with(true)
    }

    fn check_with(&self, allow_legacy: bool) -> Result<(), String> {
        if self.format != FORMAT {
            return Err(format!("unsupported format {:?}", trunc(&self.format)));
        }
        let legacy_ok = allow_legacy && is_legacy_contract_version(&self.contract_version);
        if !is_supported_contract_version(&self.contract_version) && !legacy_ok {
            return Err(format!(
                "unsupported contract_version {:?}",
                trunc(&self.contract_version)
            ));
        }
        if !is_valid_robot_id(&self.unit_id) {
            return Err("invalid unit_id".into());
        }
        if self.batch_seq == 0 {
            return Err("batch_seq must be >= 1".into());
        }
        if self.batch_seq > MAX_BATCH_SEQ {
            return Err(format!("batch_seq > {MAX_BATCH_SEQ}"));
        }
        match (&self.prev_batch_hash, self.batch_seq) {
            (None, 1) => {}
            (Some(h), s) if s > 1 && is_hex_digest(h) => {}
            (None, _) => return Err("prev_batch_hash missing for batch_seq > 1".into()),
            (Some(_), 1) => return Err("prev_batch_hash present on batch_seq 1".into()),
            (Some(_), _) => return Err("prev_batch_hash is not a hex SHA-256".into()),
        }
        if !(MIN_TIME_MS..MAX_TIME_MS).contains(&self.created_at_ms) {
            return Err("created_at_ms out of range".into());
        }
        if self.created_at != robodr_ocsf::builder::rfc3339_ms(self.created_at_ms) {
            return Err("created_at does not match created_at_ms".into());
        }
        if !is_valid_key_id(&self.key_id) || !is_valid_key_id(&self.algorithm) {
            return Err("invalid key_id or algorithm".into());
        }
        if self.files.is_empty() {
            return Err("batch has no data files".into());
        }
        if self.files.len() > MAX_FILES {
            return Err(format!("{} files > {MAX_FILES}", self.files.len()));
        }
        let mut names = std::collections::BTreeSet::new();
        let mut findings_files = 0;
        let mut parity_files = 0usize;
        for f in &self.files {
            if !is_safe_file_name(&f.name) {
                return Err(format!("unsafe file name {:?}", trunc(&f.name)));
            }
            let ok = match f.kind {
                FileKind::Findings => f.name == FINDINGS_FILE,
                FileKind::BlackboxBundle => is_bundle_name(&f.name),
                FileKind::Parity => {
                    parity_files += 1;
                    f.name == parity_file_name(parity_files)
                }
            };
            if !ok {
                return Err(format!("file name {:?} does not match its kind", f.name));
            }
            if !names.insert(f.name.as_str()) {
                return Err(format!("duplicate file name {:?}", f.name));
            }
            if !is_hex_digest(&f.sha256) {
                return Err(format!("bad sha256 for {:?}", f.name));
            }
            if f.kind != FileKind::Parity && parity_files > 0 {
                return Err("data file listed after a parity file".into());
            }
            if f.kind == FileKind::Findings {
                findings_files += 1;
                if f.size == 0 {
                    return Err("empty findings file".into());
                }
            }
        }
        match (findings_files, self.finding_count) {
            (0, 0) => {
                if self.first_time.is_some() || self.last_time.is_some() {
                    return Err("time range given without findings".into());
                }
            }
            (1, n) if n > 0 => match (self.first_time, self.last_time) {
                (Some(a), Some(b)) if a <= b => {}
                _ => return Err("bad first_time/last_time".into()),
            },
            _ => return Err("finding_count does not match the findings file".into()),
        }
        self.check_parity(parity_files)
    }

    fn check_parity(&self, parity_files: usize) -> Result<(), String> {
        let Some(p) = &self.parity else {
            return if parity_files == 0 {
                Ok(())
            } else {
                Err("parity files without a parity section".into())
            };
        };
        if p.scheme != PARITY_SCHEME {
            return Err(format!("unsupported parity scheme {:?}", trunc(&p.scheme)));
        }
        let k = self.files.len() - parity_files;
        let m = parity_files;
        if p.parity_shards as usize != m || p.data_shards as usize != k {
            return Err("parity shard counts do not match the listed files".into());
        }
        if !(1..=MAX_PARITY_SHARDS).contains(&m) || k == 0 || k + m > crate::fec::MAX_SHARDS {
            return Err(format!(
                "parity needs 1..={MAX_PARITY_SHARDS} parity files and k + m <= {}",
                crate::fec::MAX_SHARDS
            ));
        }
        if !(MIN_SHARD_SIZE..=MAX_SHARD_SIZE).contains(&p.shard_size) {
            return Err(format!(
                "shard_size must be in {MIN_SHARD_SIZE}..={MAX_SHARD_SIZE}"
            ));
        }
        let max_data = self.data_files().map(|f| f.size).max().unwrap_or(0);
        let plen = parity_len(max_data, p.shard_size);
        if self.parity_files().any(|f| f.size != plen) {
            return Err(format!("parity files must be {plen} bytes"));
        }
        Ok(())
    }

    /// The data files (everything but parity), in manifest order.
    pub fn data_files(&self) -> impl Iterator<Item = &FileEntry> {
        self.files.iter().filter(|f| f.kind != FileKind::Parity)
    }

    /// The parity files, in manifest order.
    pub fn parity_files(&self) -> impl Iterator<Item = &FileEntry> {
        self.files.iter().filter(|f| f.kind == FileKind::Parity)
    }

    /// Sum of declared file sizes, parity included (saturating).
    pub fn total_size(&self) -> u64 {
        self.files
            .iter()
            .fold(0u64, |a, f| a.saturating_add(f.size))
    }
}

/// At most 128 characters of untrusted text (non-printables as `?`), for messages.
pub(crate) fn trunc(s: &str) -> String {
    let t: String = s
        .chars()
        .take(128)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect();
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> Manifest {
        Manifest {
            format: FORMAT.into(),
            contract_version: robodr_ocsf::CONTRACT_VERSION.into(),
            unit_id: "ugv-007".into(),
            batch_seq: 1,
            prev_batch_hash: None,
            created_at: robodr_ocsf::builder::rfc3339_ms(1_790_000_000_000),
            created_at_ms: 1_790_000_000_000,
            key_id: "k".into(),
            algorithm: "hmac-sha256".into(),
            finding_count: 2,
            first_time: Some(1),
            last_time: Some(2),
            files: vec![FileEntry {
                name: FINDINGS_FILE.into(),
                kind: FileKind::Findings,
                size: 10,
                sha256: "ab".repeat(32),
            }],
            parity: None,
        }
    }

    fn with_parity(np: u32) -> Manifest {
        let mut x = m();
        x.files[0].size = 1000;
        for j in 1..=np as usize {
            x.files.push(FileEntry {
                name: parity_file_name(j),
                kind: FileKind::Parity,
                size: 1024,
                sha256: "cd".repeat(32),
            });
        }
        x.parity = Some(ParitySpec {
            scheme: PARITY_SCHEME.into(),
            data_shards: 1,
            parity_shards: np,
            shard_size: 512,
        });
        x
    }

    #[test]
    fn parity_manifests() {
        with_parity(1).check().unwrap();
        with_parity(MAX_PARITY_SHARDS as u32).check().unwrap();
        assert_eq!(parity_len(1000, 512), 1024);
        assert_eq!(parity_len(1024, 512), 1024);
        assert_eq!(parity_len(0, 512), 0);
        assert_eq!(parity_file_name(3), "parity-03.rbpar");
        // A manifest without parity has no `parity` key at all (byte
        // compatible with batches written before the field existed).
        let v = serde_json::to_value(m()).unwrap();
        assert!(v.get("parity").is_none());
        let back: Manifest = serde_json::from_value(v).unwrap();
        assert_eq!(back.parity, None);
        let cases: Vec<(&str, Mutation)> = vec![
            (
                "scheme",
                Box::new(|m| m.parity.as_mut().unwrap().scheme = "x".into()),
            ),
            (
                "k",
                Box::new(|m| m.parity.as_mut().unwrap().data_shards = 2),
            ),
            (
                "m",
                Box::new(|m| m.parity.as_mut().unwrap().parity_shards = 3),
            ),
            (
                "shard small",
                Box::new(|m| m.parity.as_mut().unwrap().shard_size = 511),
            ),
            (
                "shard big",
                Box::new(|m| m.parity.as_mut().unwrap().shard_size = MAX_SHARD_SIZE + 1),
            ),
            ("parity len", Box::new(|m| m.files[1].size = 1000)),
            (
                "parity name",
                Box::new(|m| m.files[1].name = "parity-02.rbpar".into()),
            ),
            ("order", Box::new(|m| m.files.swap(0, 1))),
            ("no section", Box::new(|m| m.parity = None)),
            (
                "too many",
                Box::new(|m| {
                    for j in 3..=MAX_PARITY_SHARDS + 1 {
                        m.files.push(FileEntry {
                            name: parity_file_name(j),
                            kind: FileKind::Parity,
                            size: 1024,
                            sha256: "cd".repeat(32),
                        });
                    }
                    m.parity.as_mut().unwrap().parity_shards = MAX_PARITY_SHARDS as u32 + 1;
                }),
            ),
            (
                "data after parity",
                Box::new(|m| {
                    m.files.push(FileEntry {
                        name: bundle_file_name(1),
                        kind: FileKind::BlackboxBundle,
                        size: 1,
                        sha256: "ab".repeat(32),
                    });
                    m.parity.as_mut().unwrap().data_shards = 2;
                }),
            ),
        ];
        for (name, f) in cases {
            let mut x = with_parity(2);
            f(&mut x);
            assert!(x.check().is_err(), "{name} accepted");
        }
        // Parity files without a section.
        let mut x = with_parity(1);
        x.parity = None;
        assert!(x.check().is_err());
        // Unknown fields inside the parity section are rejected.
        let mut v = serde_json::to_value(with_parity(1)).unwrap();
        v["parity"]["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Manifest>(v).is_err());
    }

    #[test]
    fn valid_manifest_passes() {
        m().check().unwrap();
    }

    #[test]
    fn file_names_are_allow_listed() {
        for bad in [
            "",
            "../x",
            "..",
            "a/b",
            "/etc/passwd",
            "a\\b",
            ".hidden",
            "A.jsonl",
            "a\0b",
            "a..b",
            "x\n",
            "é",
            &"a".repeat(65),
        ] {
            assert!(!is_safe_file_name(bad), "{bad:?}");
        }
        for good in ["findings.jsonl", "bundle-0001.rbbx", "a", "0-_.x"] {
            assert!(is_safe_file_name(good), "{good:?}");
        }
        assert!(is_bundle_name("bundle-0001.rbbx"));
        assert!(!is_bundle_name("bundle-0000.rbbx"));
        assert!(!is_bundle_name("bundle-1.rbbx"));
        assert!(!is_bundle_name("bundle-00a1.rbbx"));
    }

    type Mutation = Box<dyn Fn(&mut Manifest)>;

    #[test]
    fn check_rejects_bad_manifests() {
        let cases: Vec<(&str, Mutation)> = vec![
            ("format", Box::new(|m| m.format = "x".into())),
            ("major", Box::new(|m| m.contract_version = "3.0.0".into())),
            (
                "legacy major",
                Box::new(|m| m.contract_version = "1.3.0".into()),
            ),
            ("semver", Box::new(|m| m.contract_version = "2.0".into())),
            ("unit", Box::new(|m| m.unit_id = "a/b".into())),
            ("seq0", Box::new(|m| m.batch_seq = 0)),
            (
                "seq max",
                Box::new(|m| {
                    m.batch_seq = u64::MAX;
                    m.prev_batch_hash = Some("ab".repeat(32))
                }),
            ),
            (
                "prev on 1",
                Box::new(|m| m.prev_batch_hash = Some("ab".repeat(32))),
            ),
            ("no prev", Box::new(|m| m.batch_seq = 2)),
            (
                "bad prev",
                Box::new(|m| {
                    m.batch_seq = 2;
                    m.prev_batch_hash = Some("zz".into())
                }),
            ),
            ("time", Box::new(|m| m.created_at_ms = 0)),
            ("time text", Box::new(|m| m.created_at = "now".into())),
            ("key id", Box::new(|m| m.key_id = "a b".into())),
            ("no files", Box::new(|m| m.files.clear())),
            (
                "traversal",
                Box::new(|m| m.files[0].name = "../findings.jsonl".into()),
            ),
            (
                "kind name",
                Box::new(|m| m.files[0].name = "bundle-0001.rbbx".into()),
            ),
            (
                "dup",
                Box::new(|m| {
                    let f = m.files[0].clone();
                    m.files.push(f)
                }),
            ),
            ("sha", Box::new(|m| m.files[0].sha256 = "AB".repeat(32))),
            ("count", Box::new(|m| m.finding_count = 0)),
            ("range", Box::new(|m| m.first_time = Some(3))),
            ("empty", Box::new(|m| m.files[0].size = 0)),
            (
                "too many",
                Box::new(|m| {
                    for i in 1..=MAX_FILES {
                        m.files.push(FileEntry {
                            name: bundle_file_name(i),
                            kind: FileKind::BlackboxBundle,
                            size: 1,
                            sha256: "ab".repeat(32),
                        })
                    }
                }),
            ),
        ];
        for (name, f) in cases {
            let mut x = m();
            f(&mut x);
            assert!(x.check().is_err(), "{name} accepted");
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut v = serde_json::to_value(m()).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Manifest>(v).is_err());
    }

    #[test]
    fn hashes_are_domain_separated() {
        assert_ne!(
            batch_hash(b"x"),
            file_sha256(&manifest_signing_message(b"x"))
        );
        assert_ne!(batch_hash(b"x"), file_sha256(b"x"));
        assert_eq!(batch_dir_name("u", 7), "rdd_u_0000000000000007");
    }

    #[test]
    fn importer_also_takes_legacy_batches() {
        let mut x = m();
        x.contract_version = "1.3.0".into();
        assert!(x.check().is_err(), "the packer never writes 1.x");
        x.check_import().unwrap();
        for bad in ["3.0.0", "0.9.0", "1.3", "1.3.0-rc1"] {
            x.contract_version = bad.into();
            assert!(x.check_import().is_err(), "{bad}");
        }
        assert!(is_legacy_contract_version("1.0.0"));
        assert!(!is_legacy_contract_version("2.0.0"));
    }

    #[test]
    fn contract_versions() {
        assert!(is_supported_contract_version("2.0.0"));
        assert!(is_supported_contract_version("2.4.1"));
        assert!(is_supported_contract_version(robodr_ocsf::CONTRACT_VERSION));
        for v in [
            "1.1.0",
            "1.0.0",
            "3.0.0",
            "2.0",
            "2.0.0-rc1",
            "",
            "2..0",
            "02.0.0x",
        ] {
            assert!(!is_supported_contract_version(v), "{v}");
        }
    }
}
