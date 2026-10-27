//! Std-only smoke runs of the `deliverd_*` libFuzzer targets
//! (`fuzz/fuzz_targets/`): the same harness code (`fuzz/harness/*.rs`,
//! included by path) driven by the deterministic mutator in
//! `fuzz/harness/smoke.rs` over the committed seed corpora (see
//! `fuzz/README.md`; `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the
//! runs). The seeds are written by `regenerate_seeds` (`--ignored`);
//! `seeds_are_current` fails when the committed files differ and
//! `seeds_take_the_success_paths` checks they still reach the accepting
//! paths, so a format change cannot silently empty the corpus.

#[path = "../../../fuzz/harness/deliverd_inputs.rs"]
mod deliverd_inputs;
#[path = "../../../fuzz/harness/deliverd_state.rs"]
mod deliverd_state;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

type Seeds = fn() -> Vec<(&'static str, Vec<u8>)>;

const TARGETS: [(&str, Seeds); 2] = [
    ("deliverd_state", deliverd_state::seeds),
    ("deliverd_inputs", deliverd_inputs::seeds),
];

#[test]
#[ignore = "writes fuzz/corpus/deliverd_*; run after a format change"]
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
fn seeds_take_the_success_paths() {
    use robodr_deliverd::{config::Config, replay, rules, safety, state::State, users};
    let s = deliverd_state::seeds();
    assert!(Config::parse(&s[0].1[1..]).is_ok());
    assert!(State::parse(&s[1].1[1..]).is_ok());
    let i = deliverd_inputs::seeds();
    let idle = safety::judge(
        &i[0].1[1..],
        deliverd_inputs::NOW_MONO,
        deliverd_inputs::BOOT,
    );
    assert!(idle.allows_install(), "{idle:?}");
    let moving = safety::judge(
        &i[1].1[1..],
        deliverd_inputs::NOW_MONO,
        deliverd_inputs::BOOT,
    );
    assert_eq!(safety::state_name(moving.state), "moving_slow");
    assert!(users::lookup(std::str::from_utf8(&i[2].1[1..]).unwrap(), "probe").is_ok());
    assert_eq!(replay::parse(&i[3].1[1..]).unwrap().len(), 2);
    assert_eq!(
        rules::check_file("x", &i[4].1[1..], &mut Default::default()).unwrap(),
        1
    );
}

#[test]
fn deliverd_state_smoke() {
    let seeds = smoke::corpus(DIR, "deliverd_state");
    smoke::run("deliverd_state", &seeds, 0xde1_0001, &deliverd_state::run);
}

#[test]
fn deliverd_inputs_smoke() {
    let seeds = smoke::corpus(DIR, "deliverd_inputs");
    smoke::run("deliverd_inputs", &seeds, 0xde1_0002, &deliverd_inputs::run);
}
