# RoboDR red team, S11-lite (task #10b)

Run on 2026-10-26, about 18:43 to 18:55 UTC, at robodr `0a1b040` (release
build).

**Target:** the robot `rt-ugv-001` in network namespace `rdr-rob`. It runs:

- `robodr-agentd`, capturing live on veth `rob-rt`, with:
  - the commissioned Gazebo lab profile;
  - control plane v2 on mutual TLS at 127.0.0.1:8787 inside the namespace,
    plus a unix socket;
  - a live safety feed (`/odom` from `identity:gz_bridge` plus a 0600 PLC
    socket);
  - executor v1 enabled.
- `robodr-executor`, which writes real nftables rules inside `rdr-rob` only.

**Attacker:** namespace `rdr-gen` on the veth peer `gen-rt`. The
control-plane and ingest attacks use AutoSecOps's own SOC and ingest wire
code, so the positive controls send exactly what the product sends.

Scripts: `redteam-setup.sh`, `redteam_net.py`, `redteam_cp.py`,
`redteam_ingest.py`. Test keys only.

At the end:

- agentd stopped cleanly: `6402 datagrams, 225 findings spooled` in its
  last run, black box sealed at seq 13699, `robodr-blackbox verify` gives
  `RESULT: INTACT, CLEAN` across both runs.
- No crash in any step.
- The nftables ruleset is empty again after the TTL revert.

## Results

| # | Attack | Expected | Observed | Verdict |
|---|---|---|---|---|
| R1 | **Rogue DDS participant**: lab capture `fastrtps_gz_rogue_cmd_vel.pcap` replayed live at 1x after the baseline. A foreign participant publishes `/cmd_vel` at 3 m/s | Unknown participant + unauthorized motion writer; firewall rejects its commands | `unknown_participant` x3 (High), `unauthorized_motion_writer` x1 (Critical), `rejected_unknown_source` x34 and `linear_over_envelope` x34 (Critical), `correlate.motion_hijack` x1 (Critical), `feedback_divergence` x1. RSS 8.1 to 9.2 MiB | **PASS** |
| R2 | **GUID spray**: 3000 SPDP announcements, each with a random GUID prefix, at 876 pps | Detected; daemon stays bounded and alive | Detected: `unknown_participant` x2528 and `identity_instances_exceeded` x2529 (High), `pipeline_lag` x1. Binding table bounded (`evicted: 1982`), RSS 9.2 to 11.3 MiB, no input drops. **But** each GUID makes 1 to 2 separate findings with no aggregation: 3000 packets gave about 5000 spool files (spool 43.9 MB of the 64 MiB default cap after the run) | **PASS (detection) / ISSUE (amplification, see F1)** |
| R3 | **Oversized / malformed RTPS**: 190 truncated RTPS headers; 100 frames whose first submessage length runs past the datagram; 1000 frames of random bytes after a valid header; 1000 frames with 8 random bytes flipped; 20 x 60 KiB IP-fragmented RTPS datagrams; 1 fragment train never completed; one 64 KiB-1 non-RTPS datagram | No crash, bounded memory, malformed input reported, nothing trusted | Alive. RSS 11.3 to 12.1 MiB. `malformed_discovery` x3, `discovery_not_inspected` x20 (the oversized fragmented discovery), `fragmented_discovery` x1, `ambiguous_discovery` x1, `participant_source_mismatch` x134. The mutated-but-parseable SPDP frames also yielded `unknown_participant` x503 | **PASS** |
| R4a | **Safety-state spoof over the bus**: the robot's own `gz_bridge` traffic (including `/odom`) replayed from a foreign source IP (10.99.3.66) after the real participant was learned | Sample ignored; `untrusted_source`; safety state not changed by the spoof | `robot.safety_state.untrusted_source` (High) x1, plus `participant_source_mismatch` x4, `motion.sample_source_mismatch` x2 and `uncommanded_motion` x1. The feed counts `untrusted: 1514` against `applied: 813`, and the combined state stayed `unknown`, never taken from the spoof | **PASS** |
| R4b | **Safety socket from an unprivileged user** (uid 65534) sending `{"state":"idle"}` | Refused | `PermissionError: [Errno 13] Permission denied` (socket mode 0600) | **PASS** |
| R4c | **Malformed and unknown states on the safety socket as root**: an extra field, `"teleport"`, and a non-JSON line | Counted, never applied | `malformed: 3`, `robot.agent.input_malformed` x1, `safety_feed.socket.claim = unknown` | **PASS** |
| R5 | **Replayed control-plane request**: the exact bytes of a valid, accepted, SOC-signed request sent again | 401 replay | `401 replayed_nonce` "this nonce was already used" | **PASS** |
| R5b | Forged CP request: the real SOC key id, signed by another key | 401 | `401 bad_signature` | **PASS** |
| R5c | CP request with an unknown key id | 401 | `401 unknown_key` | **PASS** |
| R5d | Body altered after signing | 401 | `401 bad_signature` | **PASS** |
| R5e | Valid signature, timestamp 1 h old | 401 | `401 stale_timestamp` | **PASS** |
| R5f | Request addressed to another robot id | Refused | `404 unknown_robot` | **PASS** |
| R5g | Ruleset after R5 to R5f | Unchanged | Unchanged (no extra table or rule); `control_plane.unauthenticated = 20`, `control_plane_unauthenticated` findings (High) raised | **PASS** |
| R6a | **Executor, forged envelope**: `ping` with a wrong HMAC key sent directly to the executor socket | Refused | Connection closed with no answer; no state change | **PASS** |
| R6b | **Executor, forged order from a compromised agentd**: correct HMAC, a well-formed `isolate_network` order claiming `human_approved: true` / origin `control_plane`, without the SOC-signed request | Refused | `outcome: refused, soc_signature_invalid` "the order claims a SOC request but carries no signed request". Ruleset unchanged | **PASS** |
| R6c | Positive control: valid SOC-signed `isolate_network`, ttl 120 s, with a fresh `idle` from the PLC socket | Executed with management, uplink and motion path kept | `Applied ... table inet robodr, ttl 120 s`, `Verified ... read-back matches`. The rules keep 10.99.3.0/24 tcp/22, 127.0.0.1 tcp/8000, the motion path 10.77.10.10 udp 7400-7600 and the exempt control bus `rob-go2`. Then `Expired ... TTL expired` / `Reverted ... automatic revert`, and the table is gone | **PASS** |
| R6d | Valid SOC `quarantine_node` while the safety state is unknown | Not executed | `safety_state_unavailable: ... nothing is executed` | **PASS** (fail-safe) |
| R6e | Valid SOC `quarantine_node` of the live rogue participant, safety `idle` | Executed (quarantine) | **Refused `locators_required`**: agentd sent the order without the rogue's SPDP unicast locators, both with the rogue live and after it left (F3) | **NOT DEMONSTRATED** |
| R7 | **Forged / replayed batches to ingest** (`redteam_ingest.py`, live API) | 401 + audit; replay harmless | Unregistered key: `401 unknown_key`. Attacker signing as the robot's key id: `401 bad_signature`. Genuine key but 10 min old: `401 stale_timestamp`. Same signed batch twice: second `replayed:true`, no new effects. 5 MiB body: `413 body_too_large`. Wrong content type: `415`. Malformed lines: `200` with per-line `invalid_finding`. Audit sink got 3 FAILURE events (`unknown_key`, `bad_signature`, `stale_timestamp`) | **PASS** |

## Issues from the red team

- **F1 (robodr, Medium): GUID-spray finding amplification.** Every new
  random GUID prefix produces its own `unknown_participant` finding and
  usually an `identity_instances_exceeded` finding, each with a distinct
  finding id. 3000 packets made about 5000 spool records of about 6.8 KB
  each.
  - A spray of roughly 9000 to 10000 announcements fills the default 64 MiB
    spool. After that, new findings, legitimate ones included, are only in
    the black box (`dropped_full`).
  - With the uplink running, each one becomes a separate AutoSecOps case.
  - The pipeline's `rate_limited` (123) did not bound this.
  - Suggested fix: aggregate `unknown_participant` per source IP / vendor
    and time window once a threshold is passed, and raise one
    `discovery_flood` finding.
  - **Fixed** (after this run): agentd folds a flooding source's
    per-participant discovery findings into one `robot.ros2.discovery_flood`
    finding (every folded one stays in the black box), and the spool keeps
    1/8 of its bounds for Critical findings. Replayed in
    `crates/robodr-agentd/tests/redteam_regressions.rs`: 3000 sprayed
    prefixes give 23 spool records and the later Critical finding is
    spooled.
- **F2:** listed in SOAK.md (live-capture timestamps). It also affects any
  red-team step timed on a 500 Hz channel.
- **F3 (robodr, needs investigation): no locators on control-plane
  quarantines.** The order is sent at
  `crates/robodr-agentd/src/daemon.rs:2512`
  (`link.with_locators(o, |g| binding.spdp_unicast(g, now))`).
  `crates/robodr-ros2-pipeline/src/binding.rs:695` returns empty for
  contested or expired entries. Either the rogue (which shares its
  identity's IP range and triggered `identity_instances_exceeded`) is
  marked contested, or its entry is not kept. In both cases a SOC cannot
  quarantine the most typical rogue. The executor's refusal is the safe
  behavior; the gap is upstream.
  - **Root cause and fix** (after this run): not the contested case. The
    rogue is bound with its own locators while live, but agentd asked only
    the *live* binding; by the time a SOC order arrives the rogue has
    disposed itself, its lease has run out, or the GUID spray (R2) has
    evicted it. The binding table now remembers each prefix's own last
    trusted locators (bounded, 24 h, never a locator another live or
    profiled participant claims, none for a contested or pinned prefix).
    Replayed on `fastrtps_gz_rogue_cmd_vel.pcap` in
    `crates/robodr-ros2-pipeline/tests/redteam_regressions.rs`, and
    through agentd and the executor in
    `crates/robodr-agentd/tests/executor_link.rs`.

## Review of the F1 / F3 fixes

An independent adversarial review of the fixes above (branch `wt/redfix`)
found ten issues; each now has a regression test that replays the
reviewer's proof of concept and failed before the fix.

| # | Sev | Attack | Fix | Regression |
|---|-----|--------|-----|------------|
| H1 | High | One SPDP for the profiled prefix after its lease ran out, from the attacker's host, overwrote its remembered locators silently; the SOC's quarantine of a decoy announcing the robot's address then cut the robot participant (executor `verified`). | A profiled prefix with no live binding, announced from an address its remembered evidence never saw, becomes contested (Critical `participant_source_mismatch`); its locators are never written by a foreign host. Locators are handed out only on addresses the participant was seen sending from. | `crates/robodr-ros2-pipeline/tests/review_redfix.rs` `h1_*`; `crates/robodr-agentd/tests/executor_link.rs` `review_h1_*` |
| H2a | High | A live decoy prefix announcing the rogue's locators made them "claimed by another participant": `locators_required`. | Another prefix takes an ip:port away only if it was seen at that address (live, or remembered later). A decoy spoofing the rogue's own address contests the locator, and agentd vouches for a GUID-prefix-only quarantine (`guid_only`). | `review_redfix.rs` `h2a_*`; `executor_link.rs` `review_h2a_*` (both variants) |
| H2b | High | One locator outside the quarantine scope, on the motion path or loopback in the rogue's SPDP: the executor refused the whole order. | Unobserved and loopback locators never leave the binding table; the executor leaves any out-of-scope, other-family or motion-path locator out (listed with the reason) and quarantines the rest; it still refuses when every locator is on the motion path. | `review_redfix.rs` `h2b_*`; `executor_link.rs` `review_h2b_*`; executor `review_guid_only_quarantine_keeps_every_refusal` |
| H3 | High | 600 sprayed prefixes with a `cmd_vel` writer each: 600 Critical findings, the Critical spool share full, a later genuine rogue's Critical finding dropped. | Critical per-participant findings are aggregated per source after the first 8 (a Critical `discovery_flood`); one source may hold at most a quarter of the Critical spool share. | `crates/robodr-agentd/tests/redteam_regressions.rs` `review_h3_*` |
| H4 | High | ~40 packets a minute from 12 addresses used up the global budget: a later rogue's `unknown_participant` and a pinned prefix's impersonation were folded into a sourceless aggregate. | Only a source past its own share is folded; a late source still reports its first finding; findings about profiled / pinned participants are never folded. | `redteam_regressions.rs` `review_h4_*` |
| M5 | Medium | An absent unprofiled legitimate host's address announced by the rogue was in the rogue's quarantine set. | Observed-source evidence (the rogue never sent from it). | `review_redfix.rs` `m5_*` |
| M6 | Medium | 1100 active prefixes (SPDP + SEDP) evicted the rogue's remembered locators. | Ranked eviction (SPDP-only < active < High < Critical < SOC-named < profiled) and at most 128 remembered prefixes per source address. | `review_redfix.rs` `m6_*` |
| M7 | Medium | A JSONL participant event filled the locators the binding table deliberately withheld (contested prefix). | Events are used only for prefixes the table does not know, through the same filters. | `executor_link.rs` `review_m7_*` |
| M8 | Medium | The AutoSecOps catalog mirror lacked `robot.ros2.discovery_flood`. | Mirrored on the AutoSecOps side; the contract (`docs/contracts/robodr.findings.md` §10) states the rule's final semantics. | (AutoSecOps) |
| L9 | Low | A 24-hex-digit topic name became an aggregate "sample GUID"; the detail was cut; "more than 32 source addresses" was printed for 12. | Samples from the structured prefix only; the detail is built to fit 400 characters; the text names the sources. | `redteam_regressions.rs` `review_l9_*` |
| L10 | Low | One finding id per source forever; no Critical reserve below 8 files. | One finding per flood episode (subject node); `spool.max_files` below 8 refused. | `redteam_regressions.rs` `review_l10_*` |

Still open (documented limits): the evidence is source addresses, which
can be forged (a rogue spoofing an absent unprofiled participant's
address and announcing its exact ip:port gets it); the binding memory and
flood state are not persisted across an agentd restart.

