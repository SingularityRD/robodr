//! Sprint 13c exit criteria (`docs/SECURE-DELIVERY.md` §10):
//!
//! * a disk image of an enrolled (swtpm) unit yields no plaintext;
//! * a changed PCR: unseal refused;
//! * an epoch increment: every sealed key dead;
//! * a fallback unit cannot unlock without Tang.
//!
//! The TPM tests run against a real software TPM with `ROBODR_SWTPM=1`
//! (swtpm + tpm2-tools); the Tang test with `ROBODR_TANG=1` (tangd, clevis,
//! cryptsetup). Without them they print a skip, like
//! `crates/robodr-agentd/tests/tpm_head_anchor.rs`.

mod common;

use common::*;
use robodr_seal::keys::PolicyKey;
use robodr_seal::luks::Luks;
use robodr_seal::policy;
use robodr_seal::tpm::DEFAULT_FLOOR_NV;
use robodr_seal::unit::Unit;
use robodr_seal::wrap::{self, WrapContext, X25519Secret};
use robodr_seal::ErrorKind;
use std::path::{Path, PathBuf};

pub const PLATFORM: &str = "ugv-x1";
pub const PCRS: [u8; 2] = [0, 7];

/// A provisioned swtpm with one enrolled unit and a signed policy (v1)
/// for its current PCRs installed.
pub struct Enrolled {
    pub sw: SwTpm,
    pub dir: PathBuf,
    pub seal: PathBuf,
    pub authority: PolicyKey,
    pub unit: Unit,
}

pub fn enrolled(name: &str) -> Enrolled {
    let dir = tmp(name);
    let sw = SwTpm::start(&dir.join("swtpm"));
    sw.tpm().provision(None).unwrap();
    let authority = PolicyKey::generate().unwrap();
    let seal = dir.join("seal");
    let unit = Unit::enroll_tpm(&seal, "ugv-07", PLATFORM, &authority.public(), sw.tpm()).unwrap();
    let p = policy::sign(&authority, PLATFORM, 1, &sw.pcrs(&PCRS), DEFAULT_FLOOR_NV).unwrap();
    unit.install_policy(&p).unwrap();
    Enrolled {
        sw,
        dir,
        seal,
        authority,
        unit,
    }
}

const MARKERS: [&[u8]; 3] = [
    b"ROBODR-TEST-SECRET-MODEL-WEIGHTS-7f3a",
    b"ROBODR-TEST-SECRET-MISSION-CONFIG-91c2",
    b"ROBODR-TEST-SECRET-BIG-FILE-0d44",
];

fn payload() -> Vec<(&'static str, Vec<u8>)> {
    // The third file spans two 4 MiB chunks, its marker in the second.
    let mut big = vec![0x5au8; 4 * 1024 * 1024 + 100];
    big[4 * 1024 * 1024 + 10..4 * 1024 * 1024 + 10 + MARKERS[2].len()].copy_from_slice(MARKERS[2]);
    vec![
        ("weights.onnx", [MARKERS[0], b" layer data"].concat()),
        ("mission.yaml", [b"route: ".as_slice(), MARKERS[1]].concat()),
        ("big.bin", big),
    ]
}

#[test]
fn a_disk_image_of_an_enrolled_unit_yields_no_plaintext() {
    if !swtpm_enabled("disk_image") {
        return;
    }
    let mut e = enrolled("disk-image");
    // Release: a sealed RPK wrapped to the depot only.
    let depot = X25519Secret::generate().unwrap();
    let release = e.dir.join("release");
    let (rpk_dir, m, digest) = sealed_rpk(
        &release,
        "nav-model",
        PLATFORM,
        &payload(),
        &[depot.public()],
    );
    // Depot: re-wrap for this unit (the deployment's wrapped_keys entry).
    let wk = robodr_seal::rpk::rewrap_for_unit(&depot, &m, &digest, e.unit.record()).unwrap();
    // The unit's persistent storage: the store (chunks, manifest), the
    // deployment's wrap, the seal directory, the LUKS2 runtime-volume
    // image (formatted with the TPM-wrapped volume key).
    let disk = e.dir.join("disk");
    let store = disk.join("store");
    std::fs::create_dir_all(&store).unwrap();
    let st = std::process::Command::new("cp")
        .args(["-a", rpk_dir.to_str().unwrap(), store.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(st.success());
    let stored = store.join(rpk_dir.file_name().unwrap());
    std::fs::write(
        disk.join("deployment-wrap.json"),
        serde_json::to_vec(&wk).unwrap(),
    )
    .unwrap();
    let volume_key = e.unit.create_volume_key().unwrap();
    let img = disk.join("runtime.img");
    let luks = cryptsetup_enabled("disk_image volume").then(Luks::system);
    if let Some(l) = &luks {
        std::fs::File::create(&img)
            .unwrap()
            .set_len(32 << 20)
            .unwrap();
        l.format(&img, &volume_key[..], "robodr-sealed").unwrap();
    }
    // Install: unwrap through the TPM and open into the runtime volume
    // (here a directory standing in for the mounted dm-crypt mapping,
    // which is not part of the disk image: its bytes on disk are the
    // LUKS2 image above).
    let ck = e
        .unit
        .unwrap_content_key(
            &robodr_seal::from_hex(&wk.wrap).unwrap(),
            &digest,
            m.seal.as_ref().unwrap(),
        )
        .unwrap();
    let runtime = e.dir.join("runtime-mounted");
    install_plaintext(&ck, &m, &stored, &runtime).unwrap();
    for mk in MARKERS {
        assert!(!files_containing(&[&runtime], mk).is_empty(), "installed");
    }
    // The image: no plaintext, no content key, no volume key, anywhere.
    let seal = e.seal.clone();
    let image: [&Path; 2] = [&disk, &seal];
    for mk in MARKERS {
        assert!(files_containing(&image, mk).is_empty(), "plaintext on disk");
    }
    assert!(
        files_containing(&image, ck.expose()).is_empty(),
        "content key on disk"
    );
    assert!(
        files_containing(&image, &volume_key[..]).is_empty(),
        "volume key on disk"
    );
    assert!(
        files_containing(&image, &robodr_seal::to_hex(ck.expose()).into_bytes()).is_empty(),
        "content key (hex) on disk"
    );
    drop(ck);

    // Attacker A: the image on another machine (another TPM, provisioned
    // the same way, same handles): the UWK blob does not load there.
    let a_dir = tmp("disk-image-attacker");
    let other = SwTpm::start(&a_dir.join("swtpm"));
    other.tpm().provision(None).unwrap();
    let copy = a_dir.join("seal");
    let st = std::process::Command::new("cp")
        .args(["-a", seal.to_str().unwrap(), copy.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(st.success());
    let stolen = Unit::open(&copy, Some(other.tpm())).unwrap();
    let w = robodr_seal::from_hex(&wk.wrap).unwrap();
    let err = stolen
        .unwrap_content_key(&w, &digest, m.seal.as_ref().unwrap())
        .unwrap_err();
    assert!(
        matches!(
            err.kind,
            ErrorKind::Unavailable | ErrorKind::Erased | ErrorKind::PolicyRefused
        ),
        "{err}"
    );
    assert!(stolen.volume_key().is_err());
    // Attacker B: the unit itself, booted with modified software.
    e.sw.extend(7, [0xAA; 32]);
    let err = e
        .unit
        .unwrap_content_key(&w, &digest, m.seal.as_ref().unwrap())
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PolicyRefused, "{err}");
    assert_eq!(
        e.unit.volume_key().unwrap_err().kind,
        ErrorKind::PolicyRefused
    );
    // The legitimate boot again (power cycle: PCRs reset): everything
    // unseals, and the volume key opens the LUKS2 header.
    e.sw.restart();
    let k = e.unit.volume_key().unwrap();
    if let Some(l) = &luks {
        assert!(l.test_key(&img, &k[..]).unwrap());
        assert!(l.is_luks2(&img).unwrap());
    }
    let ck = e
        .unit
        .unwrap_content_key(&w, &digest, m.seal.as_ref().unwrap())
        .unwrap();
    let again = e.dir.join("runtime-again");
    install_plaintext(&ck, &m, &stored, &again).unwrap();
    assert_eq!(
        std::fs::read(again.join("weights.onnx")).unwrap(),
        payload()[0].1
    );
}

#[test]
fn a_changed_pcr_refuses_unseal() {
    if !swtpm_enabled("changed_pcr") {
        return;
    }
    let mut e = enrolled("changed-pcr");
    let ctx = WrapContext::Unit {
        unit: "ugv-07".into(),
        rpk_digest: "ab".repeat(32),
    };
    let w = wrap::wrap(&e.unit.record().recipient().unwrap(), &[7u8; 32], &ctx).unwrap();
    assert_eq!(*e.unit.unwrap(&w, &ctx).unwrap(), [7u8; 32]);
    // A PCR outside the policy's selection changes nothing.
    e.sw.extend(3, [0x11; 32]);
    assert_eq!(*e.unit.unwrap(&w, &ctx).unwrap(), [7u8; 32]);
    // Each selected PCR changed: refused by the TPM (PolicyAuthorize).
    for pcr in PCRS {
        e.sw.restart();
        e.unit.unwrap(&w, &ctx).unwrap();
        e.sw.extend(pcr, [0x22; 32]);
        let err = e.unit.unwrap(&w, &ctx).unwrap_err();
        assert_eq!(err.kind, ErrorKind::PolicyRefused, "pcr {pcr}: {err}");
        assert!(err.detail.contains("PCR"), "{err}");
    }
    // A policy signed for the changed values by another key does not
    // help: install refuses it, and the TPM refuses it too.
    let rogue = PolicyKey::generate().unwrap();
    let p = policy::sign(&rogue, PLATFORM, 1, &e.sw.pcrs(&PCRS), DEFAULT_FLOOR_NV).unwrap();
    assert!(e.unit.install_policy(&p).is_err());
    std::fs::write(e.seal.join("policy.json"), &p).unwrap();
    assert!(e.unit.unwrap(&w, &ctx).is_err());
    // The authority signing the new measurements (an authorised update)
    // makes it unseal again.
    let p = policy::sign(
        &e.authority,
        PLATFORM,
        2,
        &e.sw.pcrs(&PCRS),
        DEFAULT_FLOOR_NV,
    )
    .unwrap();
    e.unit.install_policy(&p).unwrap();
    assert_eq!(*e.unit.unwrap(&w, &ctx).unwrap(), [7u8; 32]);
}

#[test]
fn an_epoch_increment_kills_every_sealed_key() {
    if !swtpm_enabled("epoch") {
        return;
    }
    let e = enrolled("epoch");
    let rec = e.unit.record().clone();
    let r = rec.recipient().unwrap();
    let ctxs: Vec<WrapContext> = (0..3)
        .map(|i| WrapContext::Unit {
            unit: "ugv-07".into(),
            rpk_digest: format!("{i:02x}").repeat(32),
        })
        .collect();
    let wraps: Vec<Vec<u8>> = ctxs
        .iter()
        .map(|c| wrap::wrap(&r, &[9u8; 32], c).unwrap())
        .collect();
    let vk = e.unit.create_volume_key().unwrap();
    for (w, c) in wraps.iter().zip(&ctxs) {
        e.unit.unwrap(w, c).unwrap();
    }
    assert_eq!(e.unit.volume_key().unwrap(), vk);
    // Keep a copy of the blobs (a disk backup taken before the erase).
    let backup = e.dir.join("backup");
    std::fs::create_dir_all(&backup).unwrap();
    for f in [
        "uwk.pub",
        "uwk.priv",
        "volume.wrap",
        "unit.json",
        "policy.json",
    ] {
        std::fs::copy(e.seal.join(f), backup.join(f)).unwrap();
    }
    let t0 = std::time::Instant::now();
    let rep = e.unit.erase("operator", None).unwrap();
    let took = t0.elapsed();
    assert!(rep.epoch_after.unwrap() > rep.epoch_before.unwrap());
    eprintln!("erase took {took:?} (one NV increment plus reads)");
    for (w, c) in wraps.iter().zip(&ctxs) {
        assert_eq!(e.unit.unwrap(w, c).unwrap_err().kind, ErrorKind::Erased);
    }
    assert_eq!(e.unit.volume_key().unwrap_err().kind, ErrorKind::Erased);
    // Restoring the backup changes nothing: the TPM itself refuses (the
    // pre-check of the epoch is bypassed by talking to the TPM directly).
    let pol = policy::parse(&std::fs::read(backup.join("policy.json")).unwrap()).unwrap();
    let t = rec.tpm.as_ref().unwrap();
    let authority: [u8; 65] = robodr_seal::from_hex(&t.policy_authority)
        .unwrap()
        .try_into()
        .unwrap();
    let name = robodr_seal::from_hex(&t.policy_authority_name).unwrap();
    let pu = std::fs::read(backup.join("uwk.pub")).unwrap();
    let pr = std::fs::read(backup.join("uwk.priv")).unwrap();
    let tpm = e.sw.tpm();
    let w = robodr_seal::tpm::WorkDir::new(&e.dir).unwrap();
    let eph = wrap::p256_public_bytes(&wrap::p256_random().unwrap().public_key());
    let err = tpm
        .ecdh(&w, &pu, &pr, &pol, &authority, &name, t.epoch, &eph)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Erased, "{err}");
    // Epoch rollback: undefine the counter (owner authorization is empty
    // in this test) and define it again. A counter never starts below the
    // highest value any counter of the TPM held: still dead.
    let idx = format!("0x{:08x}", robodr_seal::tpm::DEFAULT_EPOCH_NV);
    let o = e.sw.tool("tpm2_nvundefine", &[&idx, "-C", "o"], None);
    assert!(o.ok(), "{}", o.error_line());
    tpm.provision(None).unwrap();
    let now = tpm.epoch().unwrap();
    assert!(
        now > t.epoch,
        "redefined counter at {now}, enrolled {}",
        t.epoch
    );
    let err = tpm
        .ecdh(&w, &pu, &pr, &pol, &authority, &name, t.epoch, &eph)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Erased, "{err}");
    // And the unit stays erased.
    let reopened = Unit::open(&e.seal, Some(e.sw.tpm())).unwrap();
    assert!(reopened.status().erased);
}

#[test]
fn a_fallback_unit_cannot_unlock_without_tang() {
    if !tang_enabled("fallback_tang") {
        return;
    }
    let dir = tmp("fallback-tang");
    let mut tang = Tang::start(&dir);
    let luks = Luks::system();
    let img = dir.join("runtime.img");
    std::fs::File::create(&img)
        .unwrap()
        .set_len(32 << 20)
        .unwrap();
    luks.format_tang(&img, &tang.url(), &tang.thp).unwrap();
    // With Tang reachable: the volume key is recovered and opens the
    // header; the unit's UWK is enrolled inside the (stand-in) volume.
    let pass = luks.tang_pass(&img, 1).unwrap();
    assert!(luks.test_key(&img, &pass).unwrap());
    let runtime = dir.join("runtime-mounted");
    let seal = dir.join("seal");
    let unit = Unit::enroll_fallback(
        &seal,
        "ugv-09",
        PLATFORM,
        &runtime.join(".robodr-seal/uwk.key"),
    )
    .unwrap();
    let depot = X25519Secret::generate().unwrap();
    let (rpk, m, digest) = sealed_rpk(
        &dir.join("rel"),
        "nav-model",
        PLATFORM,
        &payload()[..2],
        &[depot.public()],
    );
    let wk = robodr_seal::rpk::rewrap_for_unit(&depot, &m, &digest, unit.record()).unwrap();
    let w = robodr_seal::from_hex(&wk.wrap).unwrap();
    unit.unwrap_content_key(&w, &digest, m.seal.as_ref().unwrap())
        .unwrap();
    // Nothing on the unit's storage (image + seal directory) is the
    // volume passphrase, or the UWK.
    let uwk = robodr_seal::keys::x25519_load(&runtime.join(".robodr-seal/uwk.key")).unwrap();
    let disk: [&Path; 2] = [&seal, &img];
    let _ = rpk;
    assert!(files_containing(&[&dir.join("seal")], &pass).is_empty());
    assert!(!std::fs::read(&img)
        .unwrap()
        .windows(pass.len())
        .any(|x| x == &pass[..]));
    assert!(files_containing(&disk[..1], uwk.expose()).is_empty());
    // Tang unreachable (the unit off site): no volume key, so no UWK
    // either (it is inside the closed volume: modelled by its absence).
    tang.down();
    let err = luks.tang_pass(&img, 1).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unavailable, "{err}");
    std::fs::remove_dir_all(&runtime).unwrap();
    assert_eq!(
        unit.unwrap_content_key(&w, &digest, m.seal.as_ref().unwrap())
            .unwrap_err()
            .kind,
        ErrorKind::Unavailable
    );
    // Back on site: unlocks again.
    tang.up();
    assert!(luks
        .test_key(&img, &luks.tang_pass(&img, 1).unwrap())
        .unwrap());
    // Crypto-erase of a fallback unit with its volume: the header's
    // keyslots are wiped, so even Tang cannot unlock it any more.
    unit.erase("tamper", Some((&luks, &img))).unwrap();
    assert!(luks.tang_pass(&img, 1).is_err());
    assert!(!luks.test_key(&img, &pass).unwrap());
}
