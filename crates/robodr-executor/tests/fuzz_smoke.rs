//! Std-only smoke runs of the `executor_proto` and `executor_soc`
//! libFuzzer targets (`fuzz/fuzz_targets/`): the same harness code
//! (`fuzz/harness/executor_*.rs`, included by path) driven by the
//! deterministic mutator in `fuzz/harness/smoke.rs` over the committed seed
//! corpora (`fuzz/corpus/executor_*/`). The seeds are written by
//! `regenerate_seeds` (`--ignored`); `seeds_are_current` fails when the
//! committed files differ, `*_seeds_take_the_success_paths` check they
//! still reach the accepting paths. See `fuzz/README.md`.

#[path = "../../../fuzz/harness/executor_proto.rs"]
mod executor_proto;
#[path = "../../../fuzz/harness/executor_soc.rs"]
mod executor_soc;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use robodr_executor::order::Order;
use robodr_executor::proto::{open, Key, Msg};
use robodr_executor::soc::{verify, verify_revert, Context, ReplayStore, SocKey, SocRequest};

const DIR: &str = env!("CARGO_MANIFEST_DIR");

type Seeds = fn() -> Vec<(&'static str, Vec<u8>)>;

const TARGETS: [(&str, Seeds); 2] = [
    ("executor_proto", executor_proto::seeds),
    ("executor_soc", executor_soc::seeds),
];

#[test]
#[ignore = "writes fuzz/corpus/executor_*; run after a format change"]
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
fn seeds_are_current() {
    for (t, seeds) in TARGETS {
        for (name, bytes) in seeds() {
            let p = smoke::corpus_dir(DIR, t).join(name);
            let on_disk = std::fs::read(&p)
                .unwrap_or_else(|e| panic!("{}: {e} (run regenerate_seeds)", p.display()));
            assert!(
                on_disk == bytes,
                "{} is stale: run regenerate_seeds",
                p.display()
            );
        }
    }
}

#[test]
fn proto_seeds_take_the_success_paths() {
    let key = Key::from_bytes(executor_proto::KEY);
    for (name, seed) in executor_proto::seeds() {
        let (&sel, body) = seed.split_first().unwrap();
        let ok = match sel % 4 {
            0 => open(&key, body, executor_proto::NOW_MS, None).is_ok(),
            1 => serde_json::from_slice::<Msg>(body).is_ok(),
            2 => body.contains(&b'\n'),
            _ => Key::parse(std::str::from_utf8(body).unwrap()).is_ok(),
        };
        assert!(
            ok,
            "executor_proto seed {name} does not take its success path"
        );
    }
}

#[test]
fn soc_seeds_take_the_success_paths() {
    use executor_soc::{ACTION, KEY_ID, NOW_S, ROBOT, SEED, SKEW_S};
    let keys = [SocKey {
        key_id: KEY_ID.into(),
        public: robodr_blackbox::sign_ed25519::public_key_from_seed(&SEED),
    }];
    let cx = Context {
        keys: &keys,
        robot_id: ROBOT,
        max_skew_s: SKEW_S,
        now_ms: NOW_S * 1000,
    };
    let tmp =
        std::env::temp_dir().join(format!("robodr-executor-soc-seeds-{}", std::process::id()));
    let mut accepted = 0;
    for (name, seed) in executor_soc::seeds() {
        let (&sel, body) = seed.split_first().unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let mut replay = ReplayStore::open(&tmp, NOW_S, SKEW_S, false);
        let ok = match sel % 4 {
            0 => {
                let o: Order = serde_json::from_slice(body).unwrap();
                let o = robodr_executor::soc::testing::sign_order(
                    o,
                    &SEED,
                    ROBOT,
                    NOW_S,
                    "seed-nonce-0000001",
                );
                verify(&o, &cx, &mut replay).is_ok()
            }
            1 => {
                let o: Order = serde_json::from_slice(body).unwrap();
                verify(&o, &cx, &mut replay).is_ok()
            }
            2 => {
                let r: SocRequest = serde_json::from_slice(body).unwrap();
                let r = SocRequest::sign(
                    &SEED,
                    ROBOT,
                    &r.key_id,
                    &r.method,
                    &r.target,
                    r.timestamp,
                    &r.nonce,
                    &r.body,
                );
                verify_revert(ACTION, Some(&r), &cx, &mut replay).is_ok()
            }
            _ => {
                let r: SocRequest = serde_json::from_slice(body).unwrap();
                verify_revert(ACTION, Some(&r), &cx, &mut replay).is_ok()
            }
        };
        // The planner seed exercises the refusal: it must never verify.
        assert_eq!(ok, !name.contains("planner"), "executor_soc seed {name}");
        accepted += usize::from(ok);
    }
    let _ = std::fs::remove_dir_all(&tmp);
    assert_eq!(accepted, executor_soc::seeds().len() - 1);
}

/// A request signed for this robot but tampered after signing (body,
/// target, timestamp, robot) never verifies through the harness.
#[test]
fn soc_tampered_requests_are_refused() {
    let seeds = executor_soc::seeds();
    let (_, signed) = seeds
        .iter()
        .find(|(n, _)| *n == "1-signed-quarantine")
        .unwrap();
    let text = std::str::from_utf8(&signed[1..]).unwrap();
    for (from, to) in [
        ("req-quarantine-1", "req-quarantine-2"),
        ("\"ttl_s\":60", "\"ttl_s\":6000"),
        ("analyst", "analyse"),
        ("robot-fuzz", "robot-fuzy"),
    ] {
        assert!(text.contains(from), "{from}");
        let mut input = vec![1u8];
        input.extend_from_slice(text.replacen(from, to, 1).as_bytes());
        executor_soc::run(&input);
    }
}

#[test]
fn executor_proto_smoke() {
    let seeds = smoke::corpus(DIR, "executor_proto");
    smoke::run("executor_proto", &seeds, 0x6578_7072, &executor_proto::run);
}

#[test]
fn executor_soc_smoke() {
    let seeds = smoke::corpus(DIR, "executor_soc");
    smoke::run("executor_soc", &seeds, 0x6578_736f, &executor_soc::run);
}
