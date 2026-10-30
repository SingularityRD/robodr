//! Harness: deployment document and its signature set
//! (`robodr_pkg::deployment`).
//!
//! Input: `deployment.json \0 deployment.json.sig`. Invariants beyond "no
//! panic":
//!
//! * a deployment that parses is exactly its canonical encoding, has
//!   `not_before < expires_at`, at least one target and item, and every
//!   wrapped key names one of its items (and a targeted unit when it
//!   targets no group);
//! * a deployment that verifies against the harness site is for its site,
//!   carries a depot signature and the production operator quorum unless
//!   the lab quorum applies (a `lab` / `canary` ring, units only, each
//!   assigned to that ring by the trust file, a canary of one unit), and
//!   is valid at the harness time;
//! * `check_seq` without history is `Newer`; against itself it is
//!   `AlreadyAccepted`; against a higher sequence number a replay.
//!
//! Shared via `#[path]` with `crates/robodr-pkg/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

#[path = "pkg_common.rs"]
mod pkg_common;

use pkg_common::*;
use robodr_pkg::common::to_canonical;
use robodr_pkg::deployment::{
    self, check_seq, is_prod_ring, lab_quorum_applies, LastDeployment, SeqStep,
};
use robodr_pkg::sig::Role;
use robodr_pkg::Code;

pub fn run(data: &[u8]) {
    let parts = split(data, 2);
    let doc = parts[0];
    if let Ok(d) = deployment::parse_deployment(doc) {
        assert_eq!(to_canonical(&d).expect("ser"), doc);
        assert!(d.not_before < d.expires_at);
        assert!(!d.items.is_empty());
        assert!(d.targets.units.len() + d.targets.groups.len() > 0);
        for w in &d.wrapped_keys {
            assert!(d.items.iter().any(|i| i.rpk_digest == w.rpk_digest));
            assert!(!d.targets.groups.is_empty() || d.targets.units.contains(&w.unit));
        }
    }
    let Some(sig) = parts.get(1) else {
        return;
    };
    if let Ok(v) = deployment::verify_deployment(doc, sig, trust(), NOW) {
        let d = &v.deployment;
        assert_eq!(d.site, SITE);
        assert!(v.signers.count(Role::Depot) >= 1);
        let q = trust().file().quorum;
        let lab = lab_quorum_applies(d, trust());
        let need = if lab { q.operator_lab } else { q.operator_prod };
        assert!(v.signers.count(Role::Operator) >= need as usize);
        if v.signers.count(Role::Operator) < q.operator_prod as usize {
            assert!(!is_prod_ring(&d.ring) && d.targets.groups.is_empty());
            for u in &d.targets.units {
                assert_eq!(trust().ring_of_unit(u), Some(d.ring.as_str()));
            }
        }
        assert!(d.not_before <= NOW && NOW < d.expires_at);
        assert_eq!(check_seq(None, &v).expect("no history"), SeqStep::Newer);
        let me = LastDeployment {
            deployment_seq: d.deployment_seq,
            digest: v.digest.clone(),
        };
        assert_eq!(
            check_seq(Some(&me), &v).expect("itself"),
            SeqStep::AlreadyAccepted
        );
        let later = LastDeployment {
            deployment_seq: d.deployment_seq + 1,
            digest: v.digest.clone(),
        };
        assert_eq!(check_seq(Some(&later), &v).unwrap_err().code, Code::Replay);
    }
}

/// Seeds: a lab deployment to a lab unit signed by the depot and one
/// operator, and a production one (a unit and a group) signed by the depot
/// and one operator (short of quorum).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    use robodr_pkg::deployment::*;
    let mk = |ring: &str, groups: Vec<String>| Deployment {
        format: DEPLOYMENT_FORMAT.into(),
        deployment_id: "dep-0001".into(),
        site: SITE.into(),
        deployment_seq: 4,
        created_at: 1_790_000_000,
        targets: Targets {
            units: vec!["ugv-07".into()],
            groups,
        },
        ring: ring.into(),
        items: vec![Item {
            rpk_digest: "ab".repeat(32),
            name: "nav-stack".into(),
            serial: 7,
        }],
        not_before: 1_790_000_000,
        expires_at: 1_790_000_000 + 30 * 86400,
        rollout: Rollout {
            batch_size: 1,
            soak_s: 600,
            max_failures: 0,
        },
        maintenance_window: Some(MaintenanceWindow {
            days: vec![Weekday::Mon, Weekday::Thu],
            start_minute: 60,
            duration_minutes: 120,
        }),
        wrapped_keys: vec![],
    };
    let ops = operators();
    let lab = to_canonical(&mk("lab", vec![])).expect("ser");
    let lab_sig = sign(&lab, DEPLOYMENT_SIG_DOMAIN, &[&depot(), &ops[0]]);
    let prod = to_canonical(&mk("ring-1", vec!["ring-1-all".into()])).expect("ser");
    let prod_sig = sign(&prod, DEPLOYMENT_SIG_DOMAIN, &[&depot(), &ops[1]]);
    vec![
        ("seed-lab.bin", join(&[&lab, &lab_sig])),
        ("seed-prod-short.bin", join(&[&prod, &prod_sig])),
    ]
}
