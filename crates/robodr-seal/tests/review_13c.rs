//! Regression tests for the adversarial review of Sprint 13c (H1, H2, M2,
//! L1). Each failed before its fix. The TPM tests need `ROBODR_SWTPM=1`.

mod common;

use common::*;
use robodr_seal::keys::PolicyKey;
use robodr_seal::luks::Luks;
use robodr_seal::policy;
use robodr_seal::tpm::{DEFAULT_EPOCH_NV, DEFAULT_FLOOR_NV, DEFAULT_SRK};
use robodr_seal::unit::{EraseTarget, KeyLocation, Unit};

const PLATFORM: &str = "ugv-x1";

/// H1: a TPM whose owner authorization is empty is not provisioned: with
/// it, root on the unit could undefine and redefine the policy floor and
/// revive every revoked policy.
#[test]
fn h1_provision_refuses_an_empty_owner_authorization() {
    if !swtpm_enabled("h1_provision") {
        return;
    }
    let d = tmp("review-h1-provision");
    let sw = SwTpm::start(&d.join("swtpm"));
    assert!(
        sw.tpm().provision(OWNER_AUTH).is_err(),
        "provisioned a TPM whose owner authorization is empty"
    );
    assert!(
        !sw.tool("tpm2_nvreadpublic", &["0x01500041"], None).ok(),
        "the floor was defined anyway"
    );
}

/// The review's PoC, on a unit provisioned without an owner authorization
/// (by hand, or by a release before the fix): committing a policy there
/// is refused, because the floor it writes protects nothing.
#[test]
fn h1_commit_refuses_while_the_owner_authorization_is_empty() {
    if !swtpm_enabled("h1_commit") {
        return;
    }
    let d = tmp("review-h1-commit");
    let sw = SwTpm::start(&d.join("swtpm"));
    legacy_provision_without_owner_auth(&sw);
    let authority = PolicyKey::generate().unwrap();
    let unit = Unit::enroll_tpm(
        &d.join("seal"),
        "ugv-07",
        PLATFORM,
        &authority.public(),
        sw.tpm(),
    )
    .unwrap();
    let v1 = policy::sign(&authority, PLATFORM, 1, &sw.pcrs(&[0, 7]), DEFAULT_FLOOR_NV).unwrap();
    unit.install_policy(&v1).unwrap();
    sw.extend(7, [0x42; 32]);
    let v2 = policy::sign(&authority, PLATFORM, 2, &sw.pcrs(&[0, 7]), DEFAULT_FLOOR_NV).unwrap();
    unit.install_policy(&v2).unwrap();
    let r = unit.commit_policy();
    assert!(r.is_err(), "committed a revocation that root can undo");
    let st = unit.status();
    assert_eq!(st.owner_auth_set, Some(false));
    assert!(!st.warnings.is_empty(), "status does not warn");
    // The attack the commit would have pretended to prevent works here.
    let o = sw.tool("tpm2_nvundefine", &["0x01500041", "-C", "o"], None);
    assert!(o.ok(), "{}", o.error_line());
}

/// Defines the indices and the SRK the way `provision` did before the
/// fix, without an owner authorization.
fn legacy_provision_without_owner_auth(sw: &SwTpm) {
    let hx = |v: u32| format!("0x{v:08x}");
    for (i, a) in [
        (DEFAULT_EPOCH_NV, policy::EPOCH_NV_DEFINE),
        (DEFAULT_FLOOR_NV, policy::FLOOR_NV_DEFINE),
    ] {
        let o = sw.tool(
            "tpm2_nvdefine",
            &[&hx(i), "-C", "o", "-s", "8", "-a", a],
            None,
        );
        assert!(o.ok(), "{}", o.error_line());
    }
    let e = hx(DEFAULT_EPOCH_NV);
    assert!(sw.tool("tpm2_nvincrement", &[&e, "-C", &e], None).ok());
    let f = hx(DEFAULT_FLOOR_NV);
    assert!(sw
        .tool("tpm2_nvsetbits", &[&f, "-C", &f, "-i", "0"], None)
        .ok());
    let ctx = sw.state.join("srk.ctx");
    let c = ctx.to_str().unwrap();
    let o = sw.tool(
        "tpm2_createprimary",
        &["-C", "o", "-g", "sha256", "-G", "ecc256", "-c", c],
        None,
    );
    assert!(o.ok(), "{}", o.error_line());
    let o = sw.tool(
        "tpm2_evictcontrol",
        &["-C", "o", "-c", c, &hx(DEFAULT_SRK)],
        None,
    );
    assert!(o.ok(), "{}", o.error_line());
}

/// H2 (the review's PoC): a unit without a TPM whose runtime volume is
/// not open (its UWK file is inside it) was "erased" without destroying
/// anything. Without the volume's device, nothing is erased and nothing
/// says so.
#[test]
fn h2_a_fallback_erase_without_the_device_is_never_reported_as_done() {
    let d = tmp("review-h2");
    let key = d.join("runtime/.robodr-seal/uwk.key");
    let unit = Unit::enroll_fallback(
        &d.join("seal"),
        "ugv-09",
        PLATFORM,
        &key,
        KeyLocation::Unchecked,
    )
    .unwrap();
    // The volume is closed: the key lives on inside it.
    std::fs::rename(d.join("runtime"), d.join("closed")).unwrap();
    std::fs::create_dir(d.join("runtime")).unwrap();
    let r = unit.erase("tamper", &Luks::system(), &EraseTarget::default());
    assert!(
        r.is_err(),
        "reported an erase that destroyed nothing: {r:?}"
    );
    assert!(r.unwrap_err().detail.contains("nothing was destroyed"));
    assert!(!unit.is_erased());
    assert!(d.join("closed/.robodr-seal/uwk.key").exists());
}

/// M2: TPM session contexts were written to `.work-*` directories in the
/// persistent seal directory, and a killed process left them there. Such
/// leftovers are removed when the seal directory is opened.
#[test]
fn m2_stale_work_directories_in_the_seal_dir_are_swept() {
    let d = tmp("review-m2");
    let key = d.join("runtime/uwk.key");
    let _ = Unit::enroll_fallback(
        &d.join("seal"),
        "ugv-09",
        PLATFORM,
        &key,
        KeyLocation::Unchecked,
    );
    let stale = d.join("seal/.work-0011223344556677");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("session.ctx"), b"session key material").unwrap();
    let _ = Unit::open(&d.join("seal"), None);
    assert!(
        !stale.exists(),
        "a killed process's session context survived"
    );
}

/// L1: the fallback UWK must be on the encrypted runtime volume; a path on
/// a plain file system is refused.
#[test]
fn l1_the_fallback_key_must_be_on_a_dm_crypt_volume() {
    let d = tmp("review-l1");
    let r = Unit::enroll_fallback(
        &d.join("seal"),
        "ugv-09",
        PLATFORM,
        &d.join("plain/uwk.key"),
        KeyLocation::DmCrypt,
    );
    assert!(r.is_err(), "wrote the UWK to an unencrypted file system");
    assert!(!d.join("plain").exists());
}

/// H2 with the device (gated on cryptsetup): the keyslot wipe is the
/// erase, and an absent UWK file is reported as not destroyed.
#[test]
fn h2_a_fallback_erase_with_the_device_wipes_the_keyslots() {
    if !cryptsetup_enabled("h2_device") {
        return;
    }
    let d = tmp("review-h2-device");
    let img = d.join("runtime.img");
    std::fs::write(&img, vec![0u8; 32 << 20]).unwrap();
    let luks = Luks::system();
    luks.format(&img, &[7u8; 32], "robodr-sealed").unwrap();
    let key = d.join("runtime/.robodr-seal/uwk.key");
    let unit = Unit::enroll_fallback(
        &d.join("seal"),
        "ugv-09",
        PLATFORM,
        &key,
        KeyLocation::Unchecked,
    )
    .unwrap();
    std::fs::rename(d.join("runtime"), d.join("closed")).unwrap();
    // A symlink where the key was never makes erase write elsewhere (L3).
    std::fs::create_dir_all(d.join("runtime/.robodr-seal")).unwrap();
    std::fs::write(d.join("victim"), b"precious").unwrap();
    std::os::unix::fs::symlink(d.join("victim"), &key).unwrap();
    let rep = unit
        .erase(
            "operator",
            &luks,
            &EraseTarget {
                device: Some(&img),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(rep.destroyed, ["volume_keyslots"]);
    assert!(rep.volume_header_erased);
    assert_eq!(std::fs::read(d.join("victim")).unwrap(), b"precious");
    assert!(!luks.test_key(&img, &[7u8; 32]).unwrap());
    assert!(unit.is_erased());
}

/// M2: TPM work directories only on tmpfs; a disk directory is refused.
#[test]
fn m2_the_tpm_work_directory_must_be_tmpfs() {
    let d = tmp("review-m2-disk");
    // Where the system temp dir is tmpfs this proves nothing: skip.
    if robodr_seal::mounts::check_tmpfs(&d).is_ok() {
        eprintln!("skipped: the temp dir is tmpfs here");
        return;
    }
    let cfg = robodr_seal::tpm::TpmConfig {
        work_dir: d.join("work"),
        ..Default::default()
    };
    let t = robodr_seal::tpm::Tpm::new(cfg, Box::new(robodr_seal::cmd::System)).unwrap();
    let e = t.work().err().expect("a work directory on a disk");
    assert!(e.detail.contains("not tmpfs"), "{e}");
    assert!(std::fs::read_dir(d.join("work")).unwrap().next().is_none());
}
