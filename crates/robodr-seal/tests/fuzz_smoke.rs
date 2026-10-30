//! Std-only smoke runs of the `seal_*` libFuzzer targets
//! (`fuzz/fuzz_targets/`): the same harness code (`fuzz/harness/seal_*.rs`,
//! included by path) driven by the deterministic mutator in
//! `fuzz/harness/smoke.rs` over the committed seed corpora. See
//! `fuzz/README.md`. `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the runs.
//!
//! `regenerate_seeds` (run with `--ignored`) writes the seeds; the policy
//! and record seeds are deterministic, the wrap seeds are not (a fresh
//! ephemeral key per wrap), so `seeds_take_the_success_paths` checks what
//! the committed seeds reach rather than their bytes.

#[path = "../../../fuzz/harness/seal_policy.rs"]
mod seal_policy;
#[path = "../../../fuzz/harness/seal_wrap.rs"]
mod seal_wrap;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

type Seeds = fn() -> Vec<(&'static str, Vec<u8>)>;

const TARGETS: [(&str, Seeds); 2] = [
    ("seal_policy", seal_policy::seeds),
    ("seal_wrap", seal_wrap::seeds),
];

#[test]
#[ignore = "writes fuzz/corpus/seal_*; run after a format change"]
fn regenerate_seeds() {
    for (t, seeds) in TARGETS {
        let dir = smoke::corpus_dir(DIR, t);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in seeds() {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
    }
}

#[test]
fn seeds_take_the_success_paths() {
    use robodr_seal::wrap::Unwrapper;
    let p = smoke::corpus(DIR, "seal_policy");
    assert_eq!(p.len(), 4);
    let auth = seal_policy::authority().public();
    let verified = p
        .iter()
        .filter(|d| d[0] == 0)
        .filter(|d| {
            robodr_seal::policy::verify(
                &d[1..],
                &auth,
                seal_policy::PLATFORM,
                seal_policy::FLOOR_NV,
            )
            .is_ok()
        })
        .count();
    assert_eq!(
        verified, 1,
        "one seed is signed by the authority, one by a rogue key"
    );
    for d in p.iter().filter(|d| d[0] == 1) {
        robodr_seal::unit::UnitRecord::parse(&d[1..]).unwrap();
    }
    let w = smoke::corpus(DIR, "seal_wrap");
    assert_eq!(w.len(), 3);
    let ctx = robodr_seal::wrap::WrapContext::Unit {
        unit: "ugv-07".into(),
        rpk_digest: "ab".repeat(32),
    };
    let (x, k) = (seal_wrap::x25519(), seal_wrap::p256());
    let mut unwrapped = 0;
    for d in w.iter().filter(|d| d[0] == 0) {
        let by: &dyn Unwrapper = if d.len() - 1 == robodr_seal::wrap::X25519_WRAP_LEN {
            &x
        } else {
            &k
        };
        robodr_seal::wrap::unwrap(by, &d[1..], &ctx).unwrap();
        unwrapped += 1;
    }
    assert_eq!(unwrapped, 2);
    let c = w.iter().find(|d| d[0] & 1 == 1).unwrap();
    let at = robodr_seal::chunk::ChunkPlace {
        file_index: u32::from(c[0] >> 4),
        pos: u32::from((c[0] >> 1) & 3),
        count: 4,
    };
    robodr_seal::chunk::open_chunk(&seal_wrap::ck(), &seal_wrap::SEAL_ID, at, &c[1..]).unwrap();
}

#[test]
fn seal_policy_smoke() {
    let seeds = smoke::corpus(DIR, "seal_policy");
    smoke::run("seal_policy", &seeds, 0x5ea1_0001, &seal_policy::run);
}

#[test]
fn seal_wrap_smoke() {
    let seeds = smoke::corpus(DIR, "seal_wrap");
    smoke::run("seal_wrap", &seeds, 0x5ea1_0002, &seal_wrap::run);
}
