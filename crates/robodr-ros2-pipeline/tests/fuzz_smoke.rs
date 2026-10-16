//! Std-only smoke run of the `pipeline_config` libFuzzer target
//! (`fuzz/fuzz_targets/`): the same harness code (`fuzz/harness/*.rs`,
//! included by path) driven by the deterministic mutator in
//! `fuzz/harness/smoke.rs` over the committed seed corpus. See
//! `fuzz/README.md`. `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the run.

#[path = "../../../fuzz/harness/pipeline_config.rs"]
mod pipeline_config;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use robodr_ros2_pipeline::config::default_route_interface;
use robodr_ros2_pipeline::Config;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn pipeline_config_seeds_validate() {
    let mut configs = 0;
    for seed in smoke::corpus(DIR, "pipeline_config") {
        let text = std::str::from_utf8(&seed).unwrap();
        if let Ok(cfg) = serde_json::from_str::<Config>(text) {
            cfg.validate_with(|| Some("eth0".into()))
                .expect("seed config validates");
            configs += 1;
        } else {
            assert_eq!(default_route_interface(text).as_deref(), Some("eth0"));
        }
    }
    assert!(configs >= 3);
}

#[test]
fn pipeline_config_smoke() {
    let seeds = smoke::corpus(DIR, "pipeline_config");
    smoke::run(
        "pipeline_config",
        &seeds,
        0x919e_0001,
        &pipeline_config::run,
    );
}
