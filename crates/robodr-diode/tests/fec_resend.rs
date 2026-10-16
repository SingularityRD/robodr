//! Single-instance locks, parity repair end to end, and packer resend.

mod common;

use common::*;
use robodr_diode::manifest::{
    batch_dir_name, FileKind, Manifest, MANIFEST_FILE, MAX_PARITY_SHARDS, SIGNATURE_FILE,
};
use robodr_diode::pack::{archive_dir, MIN_BATCH_BYTES};
use robodr_diode::unpack::RECORDS_FILE;
use robodr_diode::{ImportError, Importer, PackConfig, PackError, Packer};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

fn codes(r: &robodr_diode::ImportReport) -> Vec<String> {
    r.quarantined
        .iter()
        .map(|q| reason_code(&q.reason))
        .collect()
}

fn manifest_of(dir: &Path) -> Manifest {
    serde_json::from_slice(&fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap()
}

/// Every file of a directory, by name.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().into_string().unwrap(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

fn parity_cfg(m: usize, shard: u64) -> PackConfig {
    let mut cfg = PackConfig::new(UNIT);
    cfg.parity_shards = m;
    cfg.shard_size = shard;
    cfg
}

// ------------------------------------------------------------------ locks

#[test]
fn second_packer_or_importer_on_the_same_state_is_refused() {
    let site = Site::new("lock");
    let p = site.packer();
    match Packer::open(
        &site.outbox,
        &site.pack_state,
        PackConfig::new(UNIT),
        signer(),
    ) {
        Err(PackError::Locked(path)) => {
            assert_eq!(path, site.tmp.path().join("low/pack-state.json.lock"));
            let msg = PackError::Locked(path).to_string();
            assert!(msg.contains("another robodr-diode-pack instance"), "{msg}");
        }
        other => panic!("expected Locked, got {:?}", other.err()),
    }
    // A resend also needs the lock.
    assert!(matches!(
        Packer::open_for_resend(&site.outbox, &site.pack_state, UNIT),
        Err(PackError::Locked(_))
    ));
    drop(p);
    let p = site.packer();
    drop(p);

    let imp = site.importer();
    match Importer::open(site.import_cfg(), keyring()) {
        Err(ImportError::Locked(path)) => {
            assert_eq!(path, site.high.join("state.json.lock"));
            assert!(ImportError::Locked(path)
                .to_string()
                .contains("another robodr-diode-unpack instance"));
        }
        Err(e) => panic!("expected Locked, got {e}"),
        Ok(_) => panic!("second importer opened"),
    }
    drop(imp);
    site.importer();
    // The lock file stays (removing it would race); it is not state.
    assert!(site.high.join("state.json.lock").is_file());
}

#[test]
fn lock_file_symlink_is_refused() {
    let site = Site::new("lock-sym");
    let target = site.tmp.path().join("elsewhere");
    fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, site.tmp.path().join("low/pack-state.json.lock")).unwrap();
    assert!(matches!(
        Packer::open(
            &site.outbox,
            &site.pack_state,
            PackConfig::new(UNIT),
            signer()
        ),
        Err(PackError::Io(_))
    ));
    assert_eq!(fs::read(&target).unwrap(), b"x");
}

#[test]
fn state_inside_the_outbox_is_refused() {
    let site = Site::new("state-in-outbox");
    assert!(matches!(
        Packer::open(
            &site.outbox,
            site.outbox.join("pack-state.json"),
            PackConfig::new(UNIT),
            signer()
        ),
        Err(PackError::Config(_))
    ));
}

// ----------------------------------------------------------------- parity

/// One parity batch with a findings file and three bundles of different
/// sizes (k = 4), small shards so there are several stripes.
struct ParityBatch {
    site: Site,
    name: String,
    manifest: Manifest,
    /// Records and bundles of a clean import, for comparison.
    clean: BTreeMap<String, Vec<u8>>,
}

impl ParityBatch {
    fn new(tag: &str, m: usize) -> Self {
        let site = Site::new(tag);
        let bundles = vec![bundle(3), bundle(1), bundle(7)];
        let b = site
            .packer_cfg(parity_cfg(m, 512))
            .pack(&findings(20), &bundles, NOW)
            .unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].parity_files, m);
        let name = b[0].name.clone();
        let manifest = manifest_of(&site.outbox.join(&name));
        // Clean import on a separate high side.
        let clean_site = Site::new(&format!("{tag}-clean"));
        copy_dir(&site.outbox.join(&name), &clean_site.inbox().join(&name));
        let r = clean_site.importer().run(NOW).unwrap();
        assert!(r.is_clean(), "{r:?}");
        assert!(r.accepted[0].repaired.is_empty());
        let clean = snapshot(&r.accepted[0].output);
        Self {
            site,
            name,
            manifest,
            clean,
        }
    }

    fn names(&self) -> Vec<String> {
        self.manifest.files.iter().map(|f| f.name.clone()).collect()
    }

    /// Deliver the batch to a fresh high side, damage `victims` (`how`
    /// cycles through delete / flip / truncate / extend), import.
    fn import_damaged(&self, tag: &str, victims: &[usize]) -> (Site, robodr_diode::ImportReport) {
        let high = Site::new(tag);
        let dir = high.inbox().join(&self.name);
        copy_dir(&self.site.outbox.join(&self.name), &dir);
        for (i, &v) in victims.iter().enumerate() {
            damage(&dir.join(&self.manifest.files[v].name), v + i);
        }
        let r = high.importer().run(NOW).unwrap();
        (high, r)
    }
}

fn damage(p: &Path, how: usize) {
    match how % 4 {
        0 => fs::remove_file(p).unwrap(),
        1 => {
            let mut b = fs::read(p).unwrap();
            let mid = b.len() / 2;
            b[mid] ^= 0x40;
            fs::write(p, b).unwrap();
        }
        2 => {
            let b = fs::read(p).unwrap();
            fs::write(p, &b[..b.len() / 3]).unwrap();
        }
        _ => {
            let mut b = fs::read(p).unwrap();
            b.extend_from_slice(b"trailing garbage");
            fs::write(p, b).unwrap();
        }
    }
}

#[test]
fn parity_batch_format() {
    let pb = ParityBatch::new("par-format", 2);
    let m = &pb.manifest;
    let spec = m.parity.as_ref().unwrap();
    assert_eq!((spec.data_shards, spec.parity_shards), (4, 2));
    assert_eq!(spec.shard_size, 512);
    let kinds: Vec<FileKind> = m.files.iter().map(|f| f.kind).collect();
    assert_eq!(
        kinds,
        vec![
            FileKind::Findings,
            FileKind::BlackboxBundle,
            FileKind::BlackboxBundle,
            FileKind::BlackboxBundle,
            FileKind::Parity,
            FileKind::Parity
        ]
    );
    let max = m.data_files().map(|f| f.size).max().unwrap();
    for p in m.parity_files() {
        assert_eq!(p.size, max.div_ceil(512) * 512);
        assert!(p.size > 512, "several stripes");
    }
    // Parity files are delivered but never emitted.
    assert!(!pb.clean.keys().any(|n| n.starts_with("parity-")));
    assert!(pb.clean.contains_key(RECORDS_FILE));

    // Without parity the manifest has no `parity` key (old format).
    let site = Site::new("par-none");
    let b = site.packer().pack(&findings(2), &[], NOW).unwrap();
    let text = fs::read_to_string(site.outbox.join(&b[0].name).join(MANIFEST_FILE)).unwrap();
    assert!(!text.contains("parity"), "{text}");
    assert_eq!(b[0].parity_files, 0);
}

/// Every set of up to m damaged files (data or parity, any damage kind) is
/// rebuilt and the batch imports exactly as a clean one.
#[test]
fn up_to_m_damaged_files_are_repaired_exhaustively() {
    let pb = ParityBatch::new("par-ok", 2);
    let n = pb.manifest.files.len();
    let mut sets: Vec<Vec<usize>> = (0..n).map(|a| vec![a]).collect();
    for a in 0..n {
        for b in a + 1..n {
            sets.push(vec![a, b]);
        }
    }
    for (i, set) in sets.iter().enumerate() {
        let (high, r) = pb.import_damaged(&format!("par-ok-{i}"), set);
        assert!(r.is_clean(), "{set:?}: {r:?}");
        let a = &r.accepted[0];
        let want: Vec<String> = set.iter().map(|&v| pb.names()[v].clone()).collect();
        assert_eq!(a.repaired, want, "{set:?}");
        assert_eq!(snapshot(&a.output), pb.clean, "{set:?}");
        // The processed copy is whole again (rebuilt files installed, no temps).
        let processed = high.high.join("processed").join(&pb.name);
        let mut files: Vec<String> = snapshot(&processed).into_keys().collect();
        files.sort();
        let mut expect = pb.names();
        expect.push(MANIFEST_FILE.into());
        expect.push(SIGNATURE_FILE.into());
        expect.sort();
        assert_eq!(files, expect, "{set:?}");
        assert_eq!(
            snapshot(&processed),
            snapshot(&pb.site.outbox.join(&pb.name)),
            "{set:?}"
        );
    }
}

/// m + 1 damaged files: quarantined with the damaged names, state
/// untouched, nothing emitted; an intact resend is then accepted.
#[test]
fn more_than_m_damaged_files_are_quarantined_then_resend_heals() {
    let pb = ParityBatch::new("par-bad", 2);
    let (high, r) = pb.import_damaged("par-bad-hi", &[0, 2, 5]);
    assert!(r.accepted.is_empty());
    assert_eq!(codes(&r), vec!["fec_unrecoverable"], "{r:?}");
    let reason = serde_json::to_value(&r.quarantined[0].reason).unwrap();
    assert_eq!(reason["parity_shards"], 2);
    let names = pb.names();
    assert_eq!(
        reason["damaged"],
        serde_json::json!([names[0], names[2], names[5]])
    );
    let rf: serde_json::Value = serde_json::from_slice(
        &fs::read(
            r.quarantined[0]
                .moved_to
                .parent()
                .unwrap()
                .join("reason.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(rf["reason"]["code"], "fec_unrecoverable");
    assert!(fs::read_dir(high.high.join("out"))
        .unwrap()
        .next()
        .is_none());

    // Low side: the operator re-emits the batch from the archive.
    fs::remove_dir_all(pb.site.outbox.join(&pb.name)).unwrap();
    let mut p = Packer::open_for_resend(&pb.site.outbox, &pb.site.pack_state, UNIT).unwrap();
    let rs = p.resend(1).unwrap();
    assert!(!rs.already_present);
    copy_dir(&rs.path, &high.inbox().join(&pb.name));
    let mut imp = high.importer();
    assert!(imp.state().units.is_empty(), "state did not advance");
    let r = imp.run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(snapshot(&r.accepted[0].output), pb.clean);
}

/// A parity file that matches its (signed) hash but not the data — a buggy
/// or malicious producer — makes reconstruction produce wrong bytes; they
/// are never installed or accepted.
#[test]
fn reconstruction_that_misses_the_manifest_hash_is_never_accepted() {
    let pb = ParityBatch::new("par-wrong", 2);
    let high = Site::new("par-wrong-hi");
    let dir = high.inbox().join(&pb.name);
    copy_dir(&pb.site.outbox.join(&pb.name), &dir);
    let p1 = pb.manifest.parity_files().next().unwrap().clone();
    let mut junk = fs::read(dir.join(&p1.name)).unwrap();
    for b in junk.iter_mut().step_by(7) {
        *b ^= 0x5a;
    }
    replace_file_resigned(&dir, &p1.name, &junk);
    fs::remove_file(dir.join("findings.jsonl")).unwrap();
    let r = high.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["fec_failed"], "{r:?}");
    let q = &r.quarantined[0].moved_to;
    assert!(!q.join("findings.jsonl").exists(), "nothing installed");
    assert!(
        !fs::read_dir(q).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fec-")),
        "temps removed"
    );
}

#[test]
fn repair_does_not_touch_symlinks_and_cleans_stale_temps() {
    let pb = ParityBatch::new("par-sym", 2);
    // A symlink in place of a data file is hostile, not loss: not repaired.
    let high = Site::new("par-sym-hi");
    let dir = high.inbox().join(&pb.name);
    copy_dir(&pb.site.outbox.join(&pb.name), &dir);
    let target = high.tmp.path().join("t");
    fs::copy(dir.join("findings.jsonl"), &target).unwrap();
    fs::remove_file(dir.join("findings.jsonl")).unwrap();
    std::os::unix::fs::symlink(&target, dir.join("findings.jsonl")).unwrap();
    let r = high.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["not_regular_file"], "{r:?}");

    // A temp file left by an interrupted repair is removed, the batch repaired.
    let high = Site::new("par-stale-hi");
    let dir = high.inbox().join(&pb.name);
    copy_dir(&pb.site.outbox.join(&pb.name), &dir);
    fs::write(dir.join(".fec-bundle-0001.rbbx"), b"half written").unwrap();
    fs::remove_file(dir.join("bundle-0001.rbbx")).unwrap();
    let r = high.importer().run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.accepted[0].repaired, vec!["bundle-0001.rbbx".to_string()]);
}

/// Regression: a directory planted at the old, predictable repair temp
/// name (`.fec-<file>`) made every repair fail with an I/O error, so the
/// batch stuck in the inbox for good. Temps now have unique names; the
/// batch is repaired, and the planted entry gets it quarantined (an
/// unexpected file), once, instead of an error on every run.
#[test]
fn planted_fec_directory_cannot_block_repair() {
    let pb = ParityBatch::new("par-plant", 2);
    let high = Site::new("par-plant-hi");
    let dir = high.inbox().join(&pb.name);
    copy_dir(&pb.site.outbox.join(&pb.name), &dir);
    fs::create_dir(dir.join(".fec-bundle-0001.rbbx")).unwrap();
    fs::write(dir.join(".fec-bundle-0001.rbbx").join("x"), b"x").unwrap();
    fs::remove_file(dir.join("bundle-0001.rbbx")).unwrap();
    let r = high.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["unexpected_file"], "{r:?}");
    assert!(!dir.exists(), "moved out of the inbox, not stuck");
    // Nothing left to retry.
    let r = high.importer().run(NOW).unwrap();
    assert!(r.quarantined.is_empty() && r.accepted.is_empty(), "{r:?}");
    let q = high.importer().run(NOW).unwrap();
    assert!(q.is_clean(), "{q:?}");
}

/// A damaged re-delivery of an already accepted batch is repaired and
/// filed as a duplicate, not quarantined.
#[test]
fn damaged_duplicate_is_repaired_and_filed() {
    let pb = ParityBatch::new("par-dup", 1);
    let high = Site::new("par-dup-hi");
    copy_dir(&pb.site.outbox.join(&pb.name), &high.inbox().join(&pb.name));
    assert_eq!(high.importer().run(NOW).unwrap().accepted.len(), 1);
    let dir = high.inbox().join(&pb.name);
    copy_dir(&pb.site.outbox.join(&pb.name), &dir);
    damage(&dir.join("bundle-0002.rbbx"), 1);
    let r = high.importer().run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.duplicates.len(), 1);
    // Two damaged files with m = 1 is still reported.
    copy_dir(&pb.site.outbox.join(&pb.name), &dir);
    damage(&dir.join("bundle-0002.rbbx"), 1);
    damage(&dir.join("parity-01.rbpar"), 0);
    let r = high.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["fec_unrecoverable"]);
}

#[test]
fn parity_counts_against_the_batch_size_and_config_is_checked() {
    // Each batch's data + parity stays within max_batch_bytes.
    let site = Site::new("par-size");
    let mut cfg = parity_cfg(3, 4096);
    cfg.max_batch_bytes = 512 * 1024;
    let mut p = site.packer_cfg(cfg);
    let bundles: Vec<Vec<u8>> = (0..6).map(|i| bundle(200 + i * 50)).collect();
    let pubd = p.pack(&findings(300), &bundles, NOW).unwrap();
    assert!(pubd.len() > 1);
    for b in &pubd {
        let m = manifest_of(&b.path);
        assert!(m.total_size() <= 512 * 1024, "{}", m.total_size());
        assert_eq!(m.parity_files().count(), 3);
        assert_eq!(b.data_bytes, m.data_files().map(|f| f.size).sum::<u64>());
    }
    drop(p);
    site.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.accepted.len(), pubd.len());

    // A bundle whose parity would not fit is refused up front.
    let site = Site::new("par-big");
    let big = bundle(1500);
    let len = big.len() as u64;
    assert!(len * 2 >= 3 * MIN_BATCH_BYTES, "fixture too small: {len}");
    let mut cfg = parity_cfg(2, 512);
    // Room for the bundle alone, not for it plus two parity copies of it.
    cfg.max_batch_bytes = len * 2;
    let mut p = site.packer_cfg(cfg);
    assert!(matches!(
        p.pack(&[], &[big], NOW),
        Err(PackError::BundleTooLarge { .. })
    ));
    drop(p);

    // Bad parity configurations.
    let bad = [
        parity_cfg(MAX_PARITY_SHARDS + 1, 512),
        parity_cfg(1, 511),
        parity_cfg(1, 16 * 1024 * 1024 + 1),
        {
            let mut c = parity_cfg(4, 512);
            c.max_batch_bytes = MIN_BATCH_BYTES * 2;
            c
        },
    ];
    for cfg in bad {
        assert!(matches!(
            Packer::open(&site.outbox, &site.pack_state, cfg, signer()),
            Err(PackError::Config(_))
        ));
    }
}

#[test]
fn many_files_with_parity_stay_within_the_code_length() {
    // k + m <= 255: with m = 32 a batch holds at most 223 data files.
    let site = Site::new("par-many");
    let mut cfg = parity_cfg(32, 512);
    cfg.archive_keep = 0;
    let mut p = site.packer_cfg(cfg);
    let one = bundle(1);
    let bundles = vec![one; 230];
    let pubd = p.pack(&[], &bundles, NOW).unwrap();
    assert_eq!(pubd.len(), 2);
    assert_eq!(pubd[0].bundle_count, 223);
    assert!(!archive_dir(&site.pack_state).exists(), "archive disabled");
    drop(p);
    site.transfer_all();
    // Lose 32 of the first batch's files: still accepted.
    let dir = site.inbox().join(&pubd[0].name);
    for i in 1..=32 {
        fs::remove_file(dir.join(format!("bundle-{i:04}.rbbx"))).unwrap();
    }
    let r = site.importer().run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.accepted[0].repaired.len(), 32);
}

// ----------------------------------------------------------------- resend

fn published(site: &Site, n: usize, cfg: PackConfig) -> Vec<robodr_diode::PublishedBatch> {
    let mut cfg = cfg;
    cfg.max_findings_per_batch = 1;
    site.packer_cfg(cfg)
        .pack(&findings(n as u64), &[], NOW)
        .unwrap()
}

#[test]
fn resend_reemits_the_same_bytes_and_is_idempotent() {
    let site = Site::new("resend");
    let pubd = published(&site, 3, parity_cfg(1, 512));
    let originals: Vec<_> = pubd.iter().map(|b| snapshot(&b.path)).collect();
    // The transfer agent moved everything away.
    for b in &pubd {
        fs::remove_dir_all(&b.path).unwrap();
    }
    let mut p = Packer::open_for_resend(&site.outbox, &site.pack_state, UNIT).unwrap();
    for (i, b) in pubd.iter().enumerate() {
        let r = p.resend(b.seq).unwrap();
        assert!(!r.already_present);
        assert_eq!(
            (r.seq, &r.batch_hash, &r.name),
            (b.seq, &b.batch_hash, &b.name)
        );
        assert_eq!(snapshot(&r.path), originals[i], "same bytes");
        // Again: a no-op.
        let again = p.resend(b.seq).unwrap();
        assert!(again.already_present);
        assert_eq!(snapshot(&r.path), originals[i]);
    }
    // No staging leftovers in the outbox.
    assert_eq!(site.outbox_batches().len(), 3);
    assert_eq!(fs::read_dir(&site.outbox).unwrap().count(), 3);
    // A key-less packer cannot pack.
    assert!(matches!(
        p.pack(&findings(1), &[], NOW),
        Err(PackError::Config(_))
    ));
    drop(p);

    // Importing the resent batches after the originals: duplicates.
    site.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.accepted.len(), 3);
    for b in &pubd {
        site.transfer(&b.name);
    }
    let r = site.importer().run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.duplicates.len(), 3);
}

#[test]
fn resend_refuses_what_it_cannot_reproduce() {
    let site = Site::new("resend-bad");
    let mut cfg = PackConfig::new(UNIT);
    cfg.archive_keep = 2;
    let pubd = published(&site, 4, cfg);
    let archive = archive_dir(&site.pack_state);
    // Only the newest two are kept.
    let mut kept: Vec<String> = fs::read_dir(&archive)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    kept.sort();
    assert_eq!(kept, vec![pubd[2].name.clone(), pubd[3].name.clone()]);

    let mut p = Packer::open_for_resend(&site.outbox, &site.pack_state, UNIT).unwrap();
    let e = p.resend(1).unwrap_err();
    assert!(matches!(e, PackError::Resend(_)) && e.to_string().contains("not in the archive"));
    assert!(matches!(p.resend(5), Err(PackError::Resend(_))));
    assert!(matches!(p.resend(0), Err(PackError::Resend(_))));

    // The outbox holds something else under the batch's name.
    fs::remove_dir_all(&pubd[2].path).unwrap();
    fs::create_dir(&pubd[2].path).unwrap();
    fs::write(pubd[2].path.join("x"), b"y").unwrap();
    let e = p.resend(3).unwrap_err();
    assert!(e.to_string().contains("is not this batch"), "{e}");
    fs::remove_dir_all(&pubd[2].path).unwrap();

    // A damaged archive copy is detected while copying; nothing is left.
    let f = archive.join(&pubd[2].name).join("findings.jsonl");
    let mut b = fs::read(&f).unwrap();
    b[3] ^= 1;
    fs::write(&f, b).unwrap();
    let e = p.resend(3).unwrap_err();
    assert!(e.to_string().contains("archive damaged"), "{e}");
    assert!(!pubd[2].path.exists());
    assert_eq!(fs::read_dir(&site.outbox).unwrap().count(), 3);

    // A tampered archived manifest breaks the chain to the state.
    fs::remove_dir_all(&pubd[3].path).unwrap();
    let mf = archive.join(&pubd[3].name).join(MANIFEST_FILE);
    let mut text = fs::read(&mf).unwrap();
    text.push(b'\n');
    fs::write(&mf, text).unwrap();
    let e = p.resend(4).unwrap_err();
    assert!(e.to_string().contains("does not chain"), "{e}");
    let e = p.resend(3).unwrap_err();
    assert!(e.to_string().contains("does not chain"), "{e}");
}

#[test]
fn interrupted_resend_and_uncommitted_archive_entries_are_cleaned_on_open() {
    let site = Site::new("resend-recover");
    published(&site, 1, PackConfig::new(UNIT));
    let archive = archive_dir(&site.pack_state);
    // Leftovers: a half-copied resend, an archive temp, and an archive copy
    // of a batch that was never committed (crash before the state write).
    let resend_tmp = site
        .outbox
        .join(format!(".resend-{}", batch_dir_name(UNIT, 1)));
    fs::create_dir(&resend_tmp).unwrap();
    fs::write(resend_tmp.join("findings.jsonl"), b"partial").unwrap();
    let arch_tmp = archive.join(format!(".tmp-{}", batch_dir_name(UNIT, 2)));
    fs::create_dir(&arch_tmp).unwrap();
    let uncommitted = archive.join(batch_dir_name(UNIT, 2));
    fs::create_dir(&uncommitted).unwrap();
    // Other units' entries are none of our business.
    let foreign = archive.join(batch_dir_name("ugv-008", 9));
    fs::create_dir(&foreign).unwrap();
    let p = site.packer();
    assert!(!resend_tmp.exists() && !arch_tmp.exists() && !uncommitted.exists());
    assert!(foreign.exists());
    assert!(archive.join(batch_dir_name(UNIT, 1)).is_dir());
    drop(p);
    // The next batch gets seq 2 and archives cleanly.
    let b = site.packer().pack(&findings(1), &[], NOW).unwrap();
    assert_eq!(b[0].seq, 2);
    assert!(archive.join(batch_dir_name(UNIT, 2)).is_dir());
}

// -------------------------------------------------------------------- CLI

#[test]
fn cli_parity_resend_and_lock() {
    use robodr_blackbox::KeyFile;
    let site = Site::new("fec-cli");
    let key_file = site.tmp.path().join("unit.key");
    let kf = KeyFile::generate_ed25519(Some(KEY_ID)).unwrap();
    kf.write_new(&key_file).unwrap();
    kf.to_public()
        .unwrap()
        .write_new(&site.tmp.path().join("unit.pub"))
        .unwrap();
    let ring = site.tmp.path().join("keyring");
    fs::write(&ring, format!("{UNIT} unit.pub\n")).unwrap();
    let input = site.tmp.path().join("findings.jsonl");
    let lines: Vec<String> = findings(5)
        .iter()
        .map(|f| robodr_ocsf::to_json(f).unwrap())
        .collect();
    fs::write(&input, lines.join("\n")).unwrap();
    let bb = site.tmp.path().join("b.rbbx");
    fs::write(&bb, bundle(4)).unwrap();

    let pack = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_robodr-diode-pack"))
            .args(["--outbox", site.outbox.to_str().unwrap()])
            .args(["--state", site.pack_state.to_str().unwrap()])
            .args(["--unit", UNIT])
            .args(["--key-file", key_file.to_str().unwrap()])
            .args(["--findings", input.to_str().unwrap()])
            .args(["--bundle", bb.to_str().unwrap()])
            .args(["--now-ms", &NOW.to_string()])
            .args(extra)
            .output()
            .unwrap()
    };
    let resend = |seq: &str| {
        Command::new(env!("CARGO_BIN_EXE_robodr-diode-pack"))
            .args(["resend", "--outbox", site.outbox.to_str().unwrap()])
            .args(["--state", site.pack_state.to_str().unwrap()])
            .args(["--unit", UNIT, "--seq", seq])
            .output()
            .unwrap()
    };
    let h = &site.high;
    let unpack = || {
        Command::new(env!("CARGO_BIN_EXE_robodr-diode-unpack"))
            .args(["--inbox", h.join("inbox").to_str().unwrap()])
            .args(["--out", h.join("out").to_str().unwrap()])
            .args(["--quarantine", h.join("quarantine").to_str().unwrap()])
            .args(["--processed", h.join("processed").to_str().unwrap()])
            .args(["--state", h.join("state.json").to_str().unwrap()])
            .args(["--keyring", ring.to_str().unwrap()])
            .output()
            .unwrap()
    };

    let out = pack(&["--parity", "2", "--shard-size", "1024"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let name = batch_dir_name(UNIT, 1);
    let original = snapshot(&site.outbox.join(&name));
    assert!(original.contains_key("parity-02.rbpar"));

    // Lose two files on the way: repaired.
    site.transfer(&name);
    fs::remove_file(site.inbox().join(&name).join("findings.jsonl")).unwrap();
    fs::remove_file(site.inbox().join(&name).join("parity-01.rbpar")).unwrap();
    let out = unpack();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rep: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        rep["accepted"][0]["repaired"],
        serde_json::json!(["findings.jsonl", "parity-01.rbpar"])
    );

    // Resend by seq: same bytes; a second resend is a no-op.
    fs::remove_dir_all(site.outbox.join(&name)).unwrap();
    let out = resend("1");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["already_present"], false);
    assert_eq!(snapshot(&site.outbox.join(&name)), original);
    let r: serde_json::Value = serde_json::from_slice(&resend("1").stdout).unwrap();
    assert_eq!(r["already_present"], true);
    let out = resend("9");
    assert_eq!(out.status.code(), Some(1));
    let out = resend("x");
    assert_eq!(
        out.status.code(),
        Some(1),
        "bad number: error like other flags"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_robodr-diode-pack"))
        .args(["resend", "--key-file", "k"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "unknown flag: usage");

    // A second instance while one holds the state: clear error, exit 1.
    let held = Packer::open_for_resend(&site.outbox, &site.pack_state, UNIT).unwrap();
    let out = pack(&[]);
    assert_eq!(out.status.code(), Some(1));
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(
        e.contains("another robodr-diode-pack instance holds"),
        "{e}"
    );
    let out = resend("1");
    assert_eq!(out.status.code(), Some(1));
    drop(held);
    let imp = site.importer();
    let out = unpack();
    assert_eq!(out.status.code(), Some(1));
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(
        e.contains("another robodr-diode-unpack instance holds"),
        "{e}"
    );
    drop(imp);
    assert!(unpack().status.success());
}
