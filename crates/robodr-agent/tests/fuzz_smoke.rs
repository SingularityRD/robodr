//! Std-only smoke run of the `firewall_policy` libFuzzer target
//! (`fuzz/fuzz_targets/`): the same harness code (`fuzz/harness/*.rs`,
//! included by path) driven by the deterministic mutator in
//! `fuzz/harness/smoke.rs` over the committed seed corpus. See
//! `fuzz/README.md`. `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the run.
//!
//! It lives here, not in `robodr-firewall`: the firewall crate has no file
//! format (and no serde); its policy is compiled from the profile JSON that
//! this crate parses (`strict_from_str`) and turns into channel specs
//! (`FirewallSettings::from_profile`).

#[path = "../../../fuzz/harness/firewall_policy.rs"]
mod firewall_policy;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use std::collections::BTreeMap;

use robodr_agent::{strict_from_str, FirewallSettings};
use robodr_events::profile::Profile;
use robodr_firewall::Policy;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn firewall_seeds_compile_to_a_policy() {
    for seed in smoke::corpus(DIR, "firewall_policy") {
        let end = seed
            .iter()
            .position(|&b| b == 0)
            .expect("seed has commands");
        let p: Profile = strict_from_str(std::str::from_utf8(&seed[..end]).unwrap()).unwrap();
        let ang: BTreeMap<String, f64> = p
            .motion_envelopes
            .iter()
            .filter(|(_, e)| e.max_linear_speed.is_some())
            .map(|(c, _)| (c.clone(), 1.0))
            .collect();
        let fs = FirewallSettings::from_profile(&p, &BTreeMap::new(), &ang).unwrap();
        Policy::compile(&p, fs.platform, &fs.channels).expect("seed policy compiles");
        assert!((seed.len() - end - 1) % firewall_policy::CMD_LEN == 0);
    }
}

#[test]
fn firewall_policy_smoke() {
    let seeds = smoke::corpus(DIR, "firewall_policy");
    smoke::run(
        "firewall_policy",
        &seeds,
        0xf1e0_0001,
        &firewall_policy::run,
    );
}
