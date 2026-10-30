# Handoff: finish every remaining software gap in RoboDR + AutoSecOps

Paste this whole file as the first message of a new Claude Code session that
has both repositories. It is self-contained. The user communicates in simple
Turkish; reply to them in Turkish, keep code, commits and docs in English
unless a doc is already Turkish (GA-ROADMAP status notes are Turkish).

## 0. State at handoff (2026-10-30)

| Repo | Default branch head | Work branch | Notes |
|---|---|---|---|
| `SingularityRD/robodr` (Rust, proprietary robot EDR) | `main` = `b05b271` (PR #3 merged) | `claude/determined-brahmagupta-80baq3` (= main + W2-4/W2-5, `8d064e2`) | GitHub Actions is **blocked by billing**: every job fails in 2–6 s before any step. Verify locally; say so in PRs. |
| `SingularityRD/AutoSecOps1` (Python/TS SOAR) | `main` = `056e2fb` (PR #33 merged) | `claude/robodr-ingest` | CI works and is required green before merge. |

**W2-4 (control-plane TLS slowloris) + W2-5 (gateway feed trust)** are
implemented and merged into the RoboDR work branch (`8d064e2`), **not yet into
`main`**: shared `crates/robodr-blackbox/src/admission.rs` used by the control
plane, `robodr-anchor-receiver` and `robodr-depot serve`; new finding
`robot.agent.control_plane_pressure` (`catalog_2_3_agent`, findings §3f);
gateway_feed severity ranges and per-rule cap. Red-team before/after numbers
are in `tools/e2e/RESULTS.md`. An independent adversarial review found real
defects (below, P0); they are **not fixed yet**, so do not merge this to
`main` before P0 is done. Its proofs of concept are in
`tools/e2e/review-w2-4/`.

Key docs to read first (RoboDR): `docs/GA-ROADMAP.md` (Turkish),
`docs/SECURE-DELIVERY.md` (§7 sealing, §10 sprint table and 13a–14b status
blocks, §11 open questions), `docs/OPERATIONS.md`, `docs/UNITREE.md`,
`docs/contracts/robodr.findings.md` (contract 2.3.0, §3b gateway, §3c seal,
§3d unitree, §3e depot), `docs/contracts/robodr.control-plane.md`,
`tools/e2e/RESULTS.md` (latest soak/red-team, defects W2-1…W2-5),
`docs/BUILD.md` (S10 policy: `deny(unsafe_code)` with local allows, no
panicking calls in library code, MSRV 1.87, toolchain 1.98.1).
AutoSecOps: `CLAUDE.md` and nested `AGENTS.md` files (they are binding),
`.github/CLAUDE.md` (Actions security rules).

## 1. Rules that always apply

- Develop on the work branches above; integration happens there, then a PR to
  `main`. Never push `wt/*` branches. When a PR merges, restart the work branch
  from the new `main` before more work.
- Commits are SSH-signed. Never `--no-verify` / `--no-gpg-sign`; if signing
  fails, stop and ask the user. Every commit ends with the session's
  `Co-Authored-By` / `Claude-Session` trailers. No model names elsewhere.
- AutoSecOps: conventional PR titles validated with
  `scripts/check_pr_title.py`; PR body follows `.github/PULL_REQUEST_TEMPLATE.md`
  and includes the LOC table (Logic, Tests, Infra/config, Docs, Generated;
  from `git diff --numstat origin/main...HEAD`); exact dependency pins;
  expand-only migrations with a single alembic head; regenerate the client
  (`pnpm -C frontend generate-client-ci` then `pnpm -C frontend check`) and
  tool docs (`scripts/generate_tool_docs.py`) when schemas/descriptions change;
  registry action descriptions must stay ≤ 1000 characters (the prebuild
  enforces it). Never add `pull_request_target`. Never copy customer
  identifiers anywhere.
- Never delete things you didn't create without asking (`/tmp/robodr-*`
  leftovers need the user's OK; the auto-mode classifier denies sweeping the
  shared `/tmp`). Never re-do an action a subagent was denied — surface it.
- Local AutoSecOps tests: there is no docker daemon by default; start
  PostgreSQL 16 + pgvector, Redis and an S3 stand-in (moto via `uvx`) yourself
  and stop them after. The local `.env` still uses `TRACECAT__*` names: map
  them to `AUTOSECOPS__*` for the test process only (keep base64 `=`
  padding); never edit `.env`. Run basedpyright alone with
  `NODE_OPTIONS=--max-old-space-size=6144`.
- **Disk is the bottleneck** (~10–12 GB free). One worktree per agent under
  `/home/user/wt/<name>`, its own `CARGO_TARGET_DIR=/home/user/wt/target-<name>`
  (never shared), `-p` builds, one big test target at a time, at most 2–3 Rust
  agents at once; delete a target dir as soon as its branch is merged. Copy
  `vendor/pulsar` into each new RoboDR worktree
  (`cp -a /home/user/robodr/vendor/pulsar/. <wt>/vendor/pulsar/`).
- swtpm, tpm2-tools, tangd, clevis, cryptsetup are installed; TPM tests are
  gated by `ROBODR_SWTPM=1`, Tang by `ROBODR_TANG=1`; there is no
  device-mapper (dm-crypt open/mount tests stay gated).

## 2. Process per work package (what worked in waves 1–2)

1. Create the worktree from the current integration head.
2. Launch an implementation agent with a precise brief: scope, files, spec
   sections, tests-first (including adversarial cases), docs to update,
   fmt/clippy `-D warnings`/tests, self-review, report format.
3. When it reports, launch an **independent adversarial review** agent
   (read-only, PoCs in the scratchpad, report in its final message; give it
   the code, not the implementer's conclusions).
4. Send the findings back to the **original** implementation agent
   (SendMessage keeps its context); each finding becomes a regression test
   that fails before the fix.
5. Merge into the work branch (`--no-ff`, signed, trailers). Resolve
   `Cargo.lock` conflicts by re-resolving offline
   (`cargo metadata --offline`) and checking the package set is exactly the
   union; resolve contract catalog conflicts by keeping each feature's block
   (`catalog_2_3_*` chained in `catalog_2_3`), the correlate catalog
   `NETWORK_AND_AGENT_RULES` and `catalog_versions` tests. Re-run the affected
   crates' clippy/tests on the merged tree, push.
6. Any new finding id or control-plane change → an AutoSecOps sync package
   (byte-identical catalog block, parity test against RoboDR `builder.rs`).

## 3. Work packages

Order: P0 → (P1, P2, P3 in parallel) → (P4, P5, P6) → (P7, P8) → P9 → P10.
Each has acceptance criteria (AC); record honestly what is verified only
synthetically.

### P0 — W2-4 / W2-5: fix the review findings, then PR
Already implemented on the work branch (see section 0). The independent
review (unit-level PoCs against the public API, release build; the live
red-team rerun was not done) found the following. PoCs:
`tools/e2e/review-w2-4/` (`admission_poc.rs` tests f1, f2, f2b, f3, f4 pass =
defect reproduces; `gateway_poc.rs` written, not run). Fix all test-first
(each PoC becomes a regression test in the owning crate), then delete that
directory.

- **F1 (Medium) progress floor bypassed by one complete ClientHello.**
  `crates/robodr-blackbox/src/admission.rs` ~344-355: deadline = accept +
  hello_timeout + bytes_in*1000/floor with cumulative, uncapped `bytes_in`
  from accept, so a 1400 B hello buys ~12 s, 4 KiB ~33 s (receiver
  `io_timeout` up to 60 s). Fix: measure the floor from the server's answer,
  counting only bytes received after it (or cap credited bytes and require
  post-answer bytes within an RTT budget).
- **F2 (Medium/High for unlisted SOCs) padded-hello churn evicts unfinished
  SOC handshakes.** `rank` (~385-399) credits up to 4096 B over ≥100 ms, so a
  fresh padded attacker outranks a SOC waiting one RTT for its certificate
  flight; the newcomer is always admitted and the worst cut (~712-728)
  without comparing ranks. A SOC accepted before its hello is queued
  (`seen = 0`) is the first victim. Fix: evict only if the victim ranks below
  the newcomer's expected rank, else refuse the newcomer; protection window
  of about one RTT budget after the server answered; cap hello credit near
  512 B; recommend `priority_sources` for the SOC by default.
- **F3 (Medium) quiet-source exemption lifts the global budget.**
  `take_token` (~786-831): any source unseen for 1 s bypasses an empty global
  bucket; 2000 IPv6 /64s got ~1900/s vs 100/s configured. Fix: a second
  bucket capping quiet admissions and/or key quiet state per IPv6 /48 and
  IPv4 /24.
- **F4 (Medium) per-source bucket map saturation locks out an unlisted SOC.**
  When `sources` holds `MAX_SOURCE_BUCKETS` (4096) busy entries a new source
  gets no bucket and is not quiet; the SOC's idle entry was dropped after
  1 s, so two hammering sources keep it `RateLimited` (0/3 admitted). Fix: LRU
  eviction of the map, or treat bucketless sources as quiet under the F3
  bucket, or pin recently successful SOC entries longer.
- **W2-5 (Medium) a feed-wide budget flood delays an unrelated Critical
  finding up to 60 s and drops its channel.** `GatewayLimiter::admit` needs a
  rule token and a feed token; ten noisy rules exhaust the feed burst, the
  first `robot.firewall.rejected_over_hard_limit` is folded, surfaces only at
  the window end with `channel: None`. Fix: exempt Critical (and possibly
  High) from the feed-wide budget or reserve budget per severity; emit a
  rule's first folded line immediately; keep the channel when the aggregate
  has one.
- **L1** plain (no-TLS) loopback control plane and receiver with
  `allow_plaintext`: the 1 s hello timeout now bounds the whole request
  (was 5 s); fix or document. **L2** a connection whose `promote` failed
  stays evictable mid-request (depot pack download under load); keep it
  protected. **L3** `priority_sources` accepts `0.0.0.0/0` / `::/0`; refuse
  /0 and warn on very short prefixes. **L4** receiver/depot handshake rate
  limit defaults to 0 (off) and admission does linear scans under the mutex
  (pool up to 4096+4096); consider defaults and complexity.
- **Docs overclaims to correct:** module docs, agentd README, OPERATIONS §6.4
  and RESULTS.md claim a trickled handshake is cut after ~1 s, padding does
  not buy rank, and a quiet SOC cannot be starved of budget (contradicted by
  F1–F4); RESULTS.md says `adversarial_14a` covered the depot scenario but
  it skips without `ROBODR_SWTPM=1`.
- **Checked sound by the review:** pool separation (no pre-auth connection
  reaches the authenticated pool without authenticating on all three
  servers), slot accounting on every path including panics, IPv4-mapped IPv6
  canonicalisation, CIDR parsing bounds, arithmetic, finding counters,
  `control_plane_pressure` catalog consistency, W2-5 severity clamping.

After the fixes: rerun the red-team S2/S3 with the release binaries
(`tools/e2e/redteam2-slowloris.sh`) and the depot test with `ROBODR_SWTPM=1`,
update RESULTS.md, a second independent review, then the RoboDR PR (CI
blocked → comment + merge on the user's request) and the AutoSecOps sync of
`robot.agent.control_plane_pressure` (catalog block byte-identical; CI green,
then merge).

### P1 — Depot keys in TPM / HSM (SECURE-DELIVERY §5.1)
`robodr-depot` signing, wrapping, lease and CA keys are files today. Add a
key backend abstraction: file (current), TPM 2.0 (tpm2-tools, keys created
non-exportable, policy-bound), PKCS#11 (HSM; test with SoftHSM2 if
installable). AC: every depot key operation works with each backend; keys
never written to disk in TPM/PKCS#11 mode; migration path documented; swtpm
tests; adversarial review.

### P2 — Erase triggers (SECURE-DELIVERY §11 item 7)
Route (a) lease expiry → crypto-erase per site policy and (b) a signed remote
erase command from the SOC through the control plane (two-person, same gates
as other executed actions: safety state, journalling, deferral while moving).
AC: both paths end-to-end with swtpm, spoofing/replay refused, findings
`robot.seal.*` emitted; control-plane contract revision documented →
AutoSecOps sync (P9).

### P3 — Anti-rollback floor hardening (13b carry-over)
Root holding the black-box key can sign a new high-water record with lower
floors. Bind floors to TPM NV counters only (record carries no authority the
unit can mint), or require a depot/operator-signed floor-lowering
re-anchor. AC: lowering floors without depot/operator quorum is impossible
even as root with the black-box key; migration from current records.

### P4 — 14c OS A/B update (software part)
`os-image` RPK kind and one A/B updater (decide per §11: RAUC-style or
systemd-boot/UKI; document the choice), signed policy update so sealing
survives an authorised OS update and fails for an unauthorised one, forced
boot-failure fallback. AC: demonstrated in a VM (qemu if available; else
loop-device + simulated bootloader state with honest limits); real hardware
remains a non-software item.

### P5 — Measured boot event-log verification
Depot attestation compares PCR values only. Parse and replay the TCG event
log (UEFI + IMA where present) against the quote, with a reference-value
policy. AC: tampered/omitted events detected; tests with recorded logs
(generate with swtpm + a synthetic log).

### P6 — Multi-depot / redundant depot
One depot per site today. Design and implement an active/standby (or
sharded) depot with consistent NV-anchored state, or document precisely why
not and the operational failover. AC: failover test, no double-serving of
deployments, rollback protection preserved.

### P7 — Unitree and gateway coverage
- Go1 compressed `LowState` (807 bytes) decode (layout from the SDK binary
  as was done for `LowCmd`).
- agentd passive capture feeds the Go2 WebRTC monitor (not only the inline
  gateway).
- Gateway: trajectories split over several DATA packets / DATA_FRAG
  reassembly for the motion channels with bounded memory; Fast DDS service
  requests for the adapters; MAVLink 2 signed frames (verify with configured
  key) instead of refusing; ACKNACK handling.
- `restrict_motion` also on low-level `LowCmd`, arm-SDK and hand channels;
  Unitree revert restores the previous `SpeedLevel` (read it first).
- Nav2 / PX4 pause as a latch (re-assert while active, finding on override).
AC: tests + fuzz targets for new parsers; adversarial review.

### P8 — Packaging, release, fuzzing, small fixes
- RPM OpenPGP signing hook (`rpmsign`) and an RPM offline bundle; extend the
  release dry-run harness to container jobs.
- `robodr-pulsard` for JetPack 5 via external BTF (glibc 2.31 build or musl
  where possible) — or document precisely why not.
- Long libFuzzer campaign on every target (hours each, nightly toolchain
  `nightly-2026-09-01`), fix crashes, commit corpora/results to `fuzz/README.md`.
- Rename the overload "late packet" finding away from `internal_fault`
  (new catalog id if needed); soften agentd's 30 s startup anti-replay refusal
  finding (not attack-worded); approver names: normalise plus-addressing /
  dots per a documented rule in the executor and AutoSecOps, or require
  `user-<id>` names only.

### P9 — AutoSecOps follow-ups
- Sync every new RoboDR finding id / control-plane revision from P0–P8
  (catalog block byte-identical, parity test, vectors, skills/docs).
- GitHub reports 4 Dependabot alerts on AutoSecOps `main` (1 high, 2
  moderate, 1 low): fix with exact pins (`rm uv.lock && uv sync` only if
  CLAUDE.md requires; prefer targeted upgrades), keep Trivy/pip-audit green.
- Re-run the AutoSecOps end-to-end ingest (red-team R7) against a running API
  (`just cluster` if docker works, else local services).

### P10 — Final soak, review, PRs, docs
- 72 h soak if the session allows (else the longest practical, with honest
  scaling), including Kafka SASL, broker restart, `robodr-depot serve` binary,
  pulsard where possible; update `tools/e2e/RESULTS.md`.
- One final cross-cutting adversarial review of the integration branch.
- PRs: AutoSecOps (CI must be green, then merge); RoboDR (CI blocked → comment
  stating local verification, merge at the user's request).
- Update `docs/GA-ROADMAP.md` statuses (Turkish), CHANGELOGs, and the
  internal notes file `robodr-satis-ic-notlar.md` + the remaining-gaps list.

## 4. Not software (do not attempt; list in the final report)

Actions billing / self-hosted runner; real robots (Go2 EDU, G1 EDU, Nav2
AMR), sensor box, RT kernel, Jetson/arm64 hardware runs, hardware TPM and
vendor EK chains, real data diode and tamper sensor; field latency and
false-alarm measurements; Unitree OEM confirmations; release key ceremony and
production licence key; legal (EULA/SLA/PSIRT, CRA owner, support term,
pricing); certification and human pentest; vendor partnerships; product
decisions (monitor tolerances, enabling irreversible actions by default).
Separate products with no code yet (Sentinel Box, Bus Tap, Lite SDK,
Zenoh/SROS 2, AI Guard, MSSP/OEM, Keylime attestation) are out of scope unless
the user asks for one explicitly.

## 5. Final report to the user (Turkish, plain)

What was done per package, what was verified really vs synthetically, PR
links (as full URLs), anything left open and why, and decisions the user must
make.
