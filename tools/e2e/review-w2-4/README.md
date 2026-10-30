# W2-4 / W2-5 review proofs of concept

From the independent adversarial review of the connection-admission change
(commits 54e1e95, aeb6ca5, a71c048). Not part of the workspace; kept so the
fixes can be test-first. Turn each into a regression test in the owning crate
(`robodr-blackbox` admission tests, `robodr-agentd` gateway_feed tests) and
delete this directory once the findings are fixed.

Run (release, one thread):

    CARGO_TARGET_DIR=<target> cargo test --release \
      --manifest-path tools/e2e/review-w2-4/Cargo.toml \
      --test admission_poc -- --nocapture --test-threads 1

Each `admission_poc` test passing means its finding still reproduces.
`gateway_poc.rs` (W2-5) was written but not run by the reviewer.
Findings: see `docs/HANDOFF.md`, package P0.
