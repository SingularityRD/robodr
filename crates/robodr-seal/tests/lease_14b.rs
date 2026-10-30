//! Sprint 14b: site leases enforced by the TPM (`docs/SECURE-DELIVERY.md`
//! §7.5) and the anti-rollback NV counter, against a software TPM
//! (`ROBODR_SWTPM=1`).
//!
//! * no lease, an expired lease (TPM clock moved forward with
//!   `tpm2_setclock`, then a reboot), a used-up reboot budget: unseal
//!   refused (`LeaseExpired`), by the unit's pre-check and, with the
//!   pre-check bypassed, by the TPM itself;
//! * lease replay (an older lease), extension (an edited limit), a lease
//!   of another unit or signed by another key: refused;
//! * clock rollback: the TPM clock cannot be set back;
//! * erase still kills a lease-gated unit;
//! * the NV counter: unwritten, written, undefined and defined again.

mod common;

use common::*;
use robodr_seal::keys::PolicyKey;
use robodr_seal::lease::{self, Lease, LeaseGrant};
use robodr_seal::nvcounter::{judge, Verdict};
use robodr_seal::policy;
use robodr_seal::tpm::DEFAULT_FLOOR_NV;
use robodr_seal::tpm_ident::Counter;
use robodr_seal::unit::Unit;
use robodr_seal::ErrorKind;

const PLATFORM: &str = "ugv-x1";
const UNIT: &str = "ugv-07";

struct Leased {
    sw: SwTpm,
    _dir: Tmp,
    seal: std::path::PathBuf,
    authority: PolicyKey,
    lease_key: PolicyKey,
    unit: Unit,
}

fn leased(name: &str) -> Leased {
    let dir = tmp(name);
    let sw = SwTpm::start(&dir.join("swtpm"));
    sw.provision();
    let authority = PolicyKey::generate().unwrap();
    let lease_key = PolicyKey::generate().unwrap();
    let seal = dir.join("seal");
    let unit = Unit::enroll_tpm_with(
        &seal,
        UNIT,
        PLATFORM,
        &authority.public(),
        Some(&lease_key.public()),
        sw.tpm(),
    )
    .unwrap();
    let p = policy::sign(&authority, PLATFORM, 1, &sw.pcrs(&[0, 7]), DEFAULT_FLOOR_NV).unwrap();
    unit.install_policy(&p).unwrap();
    Leased {
        sw,
        _dir: dir,
        seal,
        authority,
        lease_key,
        unit,
    }
}

impl Leased {
    fn reopen(&self) -> Unit {
        Unit::open(&self.seal, Some(self.sw.tpm())).unwrap()
    }

    fn grant(
        &self,
        unit: &str,
        seq: u64,
        lifetime_ms: u64,
        reboots: u32,
        key: &PolicyKey,
    ) -> Lease {
        let name = policy::external_p256_name(&self.authority.public());
        lease::issue(
            &LeaseGrant {
                site: "site-a",
                unit,
                platform: PLATFORM,
                authority_name: &name,
                lease_seq: seq,
                issued_at: 1_790_000_000,
                now: self.unit.tpm_time().unwrap(),
                lifetime_ms,
                reboots,
            },
            key,
        )
        .unwrap()
    }

    fn set_clock(&self, ms: u64) -> bool {
        self.sw
            .tool(
                "tpm2_setclock",
                &["-c", "o", "-p", "file:-", &ms.to_string()],
                Some(OWNER_AUTH),
            )
            .ok()
    }

    /// Unwrap through the TPM with whatever `lease.json` holds, without
    /// the unit's own pre-check: what the TPM alone decides.
    fn tpm_decides(&self, u: &Unit) -> Result<(), robodr_seal::SealError> {
        let l = match u.lease() {
            Ok(Some(l)) => l,
            _ => panic!("no lease file"),
        };
        let rec = u.record().tpm.clone().unwrap();
        let key: [u8; 65] = robodr_seal::from_hex(rec.lease_key.as_deref().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let key_name = robodr_seal::from_hex(rec.lease_key_name.as_deref().unwrap()).unwrap();
        let aname = robodr_seal::from_hex(&rec.policy_authority_name).unwrap();
        let gate = robodr_seal::tpm::LeaseGate {
            lease: &l,
            key: &key,
            key_name: &key_name,
            approved: l.approved(&aname, PLATFORM),
            policy_ref: policy::lease_ref(UNIT),
        };
        let pol = u.policy().unwrap();
        let tpm = self.sw.tpm();
        let w = tpm.work().unwrap();
        // A wrap of a random key to the UWK, unwrapped by ECDH in the TPM.
        let eph = robodr_seal::wrap::p256_random().unwrap();
        let p = robodr_seal::wrap::p256_public_bytes(&eph.public_key());
        let pu = std::fs::read(self.seal.join("uwk.pub")).unwrap();
        let pr = std::fs::read(self.seal.join("uwk.priv")).unwrap();
        let auth: [u8; 65] = self.authority.public();
        tpm.ecdh(
            &w,
            &pu,
            &pr,
            &pol,
            &auth,
            &aname,
            rec.epoch,
            &p,
            Some(&gate),
        )
        .map(|_| ())
    }
}

fn kind(r: Result<(), robodr_seal::SealError>) -> Option<ErrorKind> {
    r.err().map(|e| e.kind)
}

#[test]
fn lease_expiry_blocks_unseal_after_reboot() {
    if !swtpm_enabled("lease_expiry") {
        return;
    }
    let mut l = leased("lease-expiry");
    // No lease: nothing unseals.
    assert_eq!(kind(l.unit.probe()), Some(ErrorKind::LeaseExpired));
    // A lease of one hour of TPM time and one reboot.
    let first = l.grant(UNIT, 1, 3_600_000, 1, &l.lease_key);
    l.unit.install_lease(&first.to_bytes().unwrap()).unwrap();
    l.unit.probe().unwrap();
    // Reboot within the lease: still unseals.
    l.sw.restart();
    let u = l.reopen();
    u.probe().unwrap();
    // Time passes (the TPM clock moves forward), then a reboot: refused,
    // by the unit and by the TPM itself.
    let t = u.tpm_time().unwrap();
    assert!(l.set_clock(t.clock + 3_600_000 + 1000));
    assert_eq!(kind(u.probe()), Some(ErrorKind::LeaseExpired));
    l.sw.restart();
    let u = l.reopen();
    assert_eq!(kind(u.probe()), Some(ErrorKind::LeaseExpired));
    assert_eq!(kind(l.tpm_decides(&u)), Some(ErrorKind::LeaseExpired));
    // Clock rollback: the TPM does not set its clock back (whether or not
    // the tool reports an error), so the lease stays expired.
    let before = u.tpm_time().unwrap().clock;
    let _ = l.set_clock(1000);
    assert!(u.tpm_time().unwrap().clock >= before);
    assert_eq!(kind(u.probe()), Some(ErrorKind::LeaseExpired));
    assert_eq!(kind(l.tpm_decides(&u)), Some(ErrorKind::LeaseExpired));
    // A fresh lease opens again.
    let second = l.grant(UNIT, 2, 3_600_000, 0, &l.lease_key);
    u.install_lease(&second.to_bytes().unwrap()).unwrap();
    u.probe().unwrap();
    // Reboot budget: zero reboots allowed; after one, refused (the TPM too).
    l.sw.restart();
    let u = l.reopen();
    assert_eq!(kind(u.probe()), Some(ErrorKind::LeaseExpired));
    let r = l.tpm_decides(&u);
    assert_eq!(
        r.as_ref().err().map(|e| e.kind),
        Some(ErrorKind::LeaseExpired),
        "{r:?}"
    );
}

#[test]
fn lease_replay_extension_and_foreign_leases_are_refused() {
    if !swtpm_enabled("lease_forgery") {
        return;
    }
    let l = leased("lease-forgery");
    let short = l.grant(UNIT, 1, 60_000, 0, &l.lease_key);
    let long = l.grant(UNIT, 2, 3_600_000, 4, &l.lease_key);
    l.unit.install_lease(&long.to_bytes().unwrap()).unwrap();
    // Replay of the older (shorter) lease is refused at install.
    assert!(l.unit.install_lease(&short.to_bytes().unwrap()).is_err());
    // A lease of another unit: refused at install, and by the TPM when
    // written in place.
    let other = l.grant("ugv-08", 3, 3_600_000, 4, &l.lease_key);
    assert!(l.unit.install_lease(&other.to_bytes().unwrap()).is_err());
    std::fs::write(l.seal.join("lease.json"), other.to_bytes().unwrap()).unwrap();
    assert!(l.tpm_decides(&l.unit).is_err());
    // Signed by another key (a rogue depot): refused, also by the TPM.
    let rogue = PolicyKey::generate().unwrap();
    let forged = l.grant(UNIT, 4, 3_600_000, 4, &rogue);
    assert!(l.unit.install_lease(&forged.to_bytes().unwrap()).is_err());
    std::fs::write(l.seal.join("lease.json"), forged.to_bytes().unwrap()).unwrap();
    assert!(l.tpm_decides(&l.unit).is_err());
    // Extension by editing the limit: the unit's pre-check passes, the
    // TPM refuses (the signature covers the limit through the policy).
    let mut ext = short.clone();
    ext.clock_before += 10 * 3_600_000;
    std::fs::write(l.seal.join("lease.json"), ext.to_bytes().unwrap()).unwrap();
    assert!(l.tpm_decides(&l.unit).is_err());
    assert!(l.unit.probe().is_err());
    // The genuine lease still works.
    std::fs::write(l.seal.join("lease.json"), long.to_bytes().unwrap()).unwrap();
    l.unit.probe().unwrap();
    // Erase kills a lease-gated unit too.
    let rep = l
        .unit
        .erase(
            "operator",
            &robodr_seal::luks::Luks::system(),
            &Default::default(),
        )
        .unwrap();
    assert!(rep.destroyed.contains(&"tpm_erase_epoch".to_string()));
    assert_eq!(kind(l.unit.probe()), Some(ErrorKind::Erased));
}

#[test]
fn nv_counter_cannot_be_rolled_back_or_recreated() {
    if !swtpm_enabled("nv_counter") {
        return;
    }
    let dir = tmp("nv-counter");
    let sw = SwTpm::start(&dir.join("swtpm"));
    sw.provision();
    let t = sw.tpm();
    let idx = 0x0150_0042;
    assert_eq!(t.counter(idx).unwrap(), Counter::Undefined);
    // Defining needs the owner authorization.
    assert!(t.define_counter(idx, b"wrong").is_err());
    assert!(t.define_counter(idx, OWNER_AUTH).unwrap());
    assert_eq!(t.counter(idx).unwrap(), Counter::Unwritten);
    assert_eq!(judge(None, t.counter(idx).unwrap()), Verdict::Migrate);
    t.increment_counter(idx).unwrap();
    let Counter::Value(v) = t.counter(idx).unwrap() else {
        panic!("not written")
    };
    assert_eq!(judge(Some(v), Counter::Value(v)), Verdict::Current);
    t.increment_counter(idx).unwrap();
    // A record anchored at the old value is a rollback now.
    assert!(matches!(
        judge(Some(v), t.counter(idx).unwrap()),
        Verdict::Locked(_)
    ));
    // Undefine (owner authorization) and define again: unwritten, and its
    // first increment starts above everything it held.
    let o = sw.tool(
        "tpm2_nvundefine",
        &["0x01500042", "-C", "o", "-P", "file:-"],
        Some(OWNER_AUTH),
    );
    assert!(o.ok(), "{}", o.error_line());
    assert!(t.define_counter(idx, OWNER_AUTH).unwrap());
    assert!(matches!(
        judge(Some(v + 1), t.counter(idx).unwrap()),
        Verdict::Locked(_)
    ));
    t.increment_counter(idx).unwrap();
    let Counter::Value(w) = t.counter(idx).unwrap() else {
        panic!("not written")
    };
    assert!(w > v + 1, "recreated counter starts at {w}, held {}", v + 1);
    // Another kind of index at that handle is refused, never used.
    let o = sw.tool(
        "tpm2_nvundefine",
        &["0x01500042", "-C", "o", "-P", "file:-"],
        Some(OWNER_AUTH),
    );
    assert!(o.ok());
    let o = sw.tool(
        "tpm2_nvdefine",
        &[
            "0x01500042",
            "-C",
            "o",
            "-s",
            "8",
            "-a",
            "authread|authwrite",
            "-P",
            "file:-",
        ],
        Some(OWNER_AUTH),
    );
    assert!(o.ok(), "{}", o.error_line());
    assert!(t.counter(idx).is_err());
}
