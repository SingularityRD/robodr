# robodr-executor — executor v1 (reversible actions)

`robodr-executor` carries out the **reversible** actions of the catalog
(`robodr_responder::actions`) on the robot host. It runs as its own
process and systemd unit, holds `CAP_NET_ADMIN` and no other capability,
and changes only one nftables table, `inet robodr`. It is **off by
default**: agentd hands it nothing unless `executor.enabled` is `true` in
`agentd.json`. Without that setting, every accepted request stays
`recorded_not_executed`.

| Action | Adapter | Effect | Revert | TTL |
|---|---|---|---|---|
| `isolate_network` | nftables | drops all traffic in, out and forwarded, except loopback, IPv6 neighbour discovery, the management and uplink allow-list, the robot's control buses (configurable) and the motion control path | exact inverse | always (`ttl.default_s` if the request names none) |
| `quarantine_node` | nftables | drops RTPS whose header carries the participant's GUID prefix (raw payload match, from any address); drops UDP from and to its SPDP unicast locators (IP and port) | exact inverse | always |
| `record_evidence` | black box (runs inside agentd) | a signed, fsynced `robodr.evidence_mark` note naming the evidence bundle (the request's black-box reference) | not applicable: evidence is never reverted | none |
| `restrict_motion` | none in v1 | recorded as advisory for the Motion Firewall; no gateway exists yet, so nothing changes on the robot (request state `recorded_not_executed`) | — | — |
| `safe_pause`, `request_safe_state`, `rollback_config` | none | refused (`not_executor_action`): these may de-energise the robot or are plan-only | — | — |

## Life of an action

Every adapter follows the same sequence:

```
precheck ── safety re-check ── journal intent ── apply ── read back ── commit
(own policy,  (state NOW from    (applying,         (nft -j -f -,  (nft -j list   (active,
 own config)   agentd, ≤ 500 ms)  fsynced)           one atomic     table, exact   deadline
                                                     transaction)   comparison)    persisted)
revert / TTL expiry ── journal (reverting) ── re-render without it ── read back ── remove
```

1. **Precheck** (`decision::precheck`, pure). The executor checks the order
   against its **own** response policy (morphology, `fall_safe_restrict`,
   OEM validation) and its own configuration (allow-lists, motion control
   path, TTL limits). Rules 1–13 are in the module docs. In summary:
   * Replays are refused.
   * Only actions with `GaExecution::Executor` that never de-energise are
     executed.
   * The morphology of the order's context and plan must equal the
     executor's own.
   * In observe mode, or while the safety system is engaged, nothing
     happens.
   * Targets must be participants: never a process, never a node name.
   * On a robot that falls when de-energised (humanoid, unspecified), the
     action must be listed in `fall_safe_restrict` and approved by a
     human. A quarantine on any robot that balances actively also needs a
     human.
   * The motion control path is never cut, unless `fall_safe_restrict`
     names that target class and the entry is not `low_level`. A
     `low_level` entry is never cut.
   * Isolation needs a configured management channel.
   * The TTL must be within `1..=ttl.max_s`.
2. **Safety re-check immediately before apply.** This is executor rule 4 of
   `robodr_agent::executor`. Over the open connection, the executor asks
   agentd for the safety state at that moment. agentd answers from a cell
   that its main loop refreshes on every iteration (normally every 50 ms or
   less), together with the state's age. The executor refuses the action
   in these cases:
   * the state is unknown or stale (`safety_state_unavailable`,
     `safety_state_stale`; older than `max_safety_age_ms`, round trip
     included);
   * the safety system is engaged (`safety_system_engaged`);
   * the state differs from the one the action was judged in
     (`safety_state_changed`). The request must then be judged again.
3. **Journal intent.** The action is written as `applying` and fsynced
   before anything changes.
4. **Apply.** One `nft -j -f -` transaction deletes and re-creates
   `inet robodr` with the rules of every active action plus the new one.
   The table is a pure function of the active set (`nft::render`). The
   kernel switches atomically between two rendered states, so a revert
   restores exactly the earlier state, and repeating one changes nothing.
5. **Verify.** `nft -j list table inet robodr` is compared with the
   rendering (`nft::verify`). The comparison covers the three base chains
   (type, hook, priority, policy), every rule's expressions and comment in
   order, and the absence of any other object. Counter values are ignored.
   If the read-back differs, or apply failed, the action is rolled back
   (re-rendered without it) and reported `failed`.
6. **Commit.** The action becomes `active` with a persisted deadline
   (`applied + ttl`).
7. **Revert** on request, at TTL expiry, or by `revert-all`. The action is
   written as `reverting`, the table is re-rendered without it and read
   back, and the action is removed. Reverting an action that is already
   finished answers its final state. A revert that does not verify is
   retried on every tick and reported (event `revert_failed`).
8. **Housekeeping.** Every 500 ms the executor reverts expired actions and
   retries failed reverts. Every `verify_interval_s` it reads the table
   back:
   * **Drift**, meaning any difference such as a rule deleted by hand: the
     executor re-applies the rendering.
   * **Table missing while actions are active**: an operator's emergency
     disable. The executor honours it. Every action is dropped as
     `removed_externally` and nothing is re-installed.

## Restart, crash and reboot

Writes to `journal.json` are atomic and write-ahead. At start
(`Engine::open`) the executor reconciles the table with the journal:

| Journal entry | At restart |
|---|---|
| `applying` | its transaction may or may not have run (crash between `nft -f` and the commit): re-rendered **without** it (reverted), reported `failed` |
| `reverting` | re-rendered without it: the revert completes |
| `active`, deadline passed | reverted (TTL expired while down) |
| `active`, deadline ahead, same boot, table present | re-applied and verified (no change) |
| `active`, deadline ahead, **new boot** | re-applied (the kernel ruleset was empty) and verified |
| `active`, same boot, **table missing** | operator emergency disable: dropped, not re-applied |
| journal unreadable | table deleted, start empty (`journal_reset`) |

**Clock steps.** If an action has more TTL left than it was ever given
(the wall clock moved back), it is treated as expired. A clock step can
never make an action outlive its TTL.

Because of this design the process needs no signal handler. SIGTERM, or a
crash at any point, is recovered at the next start.

## Safety argument

* **Never de-energises, never actuates.** The executor has no code path to
  the platform, actuators, e-stop or power. Actions that may de-energise
  (`safe_pause`, `request_safe_state`, `rollback_config`) are refused by
  the catalog check. `restrict_motion` is recorded only.
* **Can only remove traffic.** In nftables an `accept` ends only the chain
  it is in, while a `drop` is final at its hook. A table that adds
  `accept` and `drop` rules therefore cannot open anything another table
  drops. Each transaction names only `inet robodr`; nothing flushes the
  ruleset or edits another table. The tests check that two foreign tables
  stay byte-identical.
* **Keeps the robot controllable.**
  * Loopback, the management and uplink allow-lists and the control buses
    (default) are never isolated.
  * Isolation is refused without a management channel.
  * The motion control path is never cut. The only exception is a
    humanoid whose OEM listed the target in `fall_safe_restrict`, and even
    then `low_level` entries such as Unitree `rt/lowcmd` are never cut.
* **Humanoids.**
  * With an empty `fall_safe_restrict` (the Unitree G1 example), neither
    action is executed (`fall_hazard`).
  * Anything listed still needs a human's approval, so planner orders are
    refused (`needs_approval`).
* **Bounded in time.** Every rule set has a deadline. The deadline
  survives restarts, a clock step back cannot extend it, and
  `Restart=always` keeps TTL enforcement running.
* **Decided twice, with the robot's state now.** agentd judges the
  request. The executor then re-checks against its own policy and
  configuration, and against the safety state milliseconds before the
  transaction. A compromised agentd can at most request what the
  executor's own checks allow: a reversible, TTL-bounded network
  restriction that keeps management and the motion path open.
* **Fails towards doing nothing.** Each of the following leaves the robot
  without the rule set, never with a partial one:
  * a journal write that fails before apply;
  * an nft error;
  * a read-back mismatch;
  * an unreachable agentd at the safety re-check;
  * a stale safety state;
  * an unreadable journal;
  * a re-apply failure at restart.
* **Least privilege.**
  * agentd keeps `CAP_NET_RAW` only.
  * The executor has `CAP_NET_ADMIN` only, no IP sockets
    (`RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any`),
    and writes only to its journal directory.
  * It runs `nft` from an absolute path, with an argument vector, an empty
    environment, and JSON built from validated types on stdin. No shell is
    involved and no request text reaches a rule: comments carry a hash of
    the order id.

## Protocol (agentd ↔ executor)

The transport is a unix stream socket at `/run/robodr-executor/executor.sock`
(mode `0660`, group `robodr`). Messages are newline-delimited JSON
envelopes authenticated with HMAC-SHA-256 under a shared 32-byte key
(`robodr-executor keygen`, delivered to both units through systemd
credentials). The MAC covers the version, the timestamp (±30 s), a nonce
(cached, fails closed when the cache is full), `reply_to` (which binds a
reply to its request) and the exact message text. One connection carries
one exchange: `submit` → `confirm` → `safety` → `outcome`, or `revert`,
`status`, `events` or `ping`. Details are in `src/proto.rs`.

The connection is served one at a time, and each message has a 5 s read
deadline, so a peer that stalls delays housekeeping by at most about
10 s per connection. Only members of group `robodr` can connect.

## nftables details

* The table is `inet robodr`, with base chains `input`, `forward` and
  `output` (`type filter`, priority `filter - 5`, policy `accept`).
  Quarantine rules come first, then the isolation rules, each in order of
  their order id. Rule comments read
  `robodr <action> <12 hex of sha256(order id)>`.
* GUID match: `meta l4proto udp`, `@th,64,32 == "RTPS"`, then
  `@th,128,32`, `@th,160,32` and `@th,192,32` against the 12-byte prefix
  in network byte order.
* Locator rules: `ip[6] saddr <ip> udp sport <port> drop` (traffic from the
  participant), `ip[6] daddr <ip> udp dport <port> drop` (traffic to it),
  and both in `forward`.
* Requires the `nft` binary with JSON support. Tested with nftables 1.0.9
  (Ubuntu 24.04).

## Configuration

`/etc/robodr/executor.json` uses schema `robodr-executor-config/v1`. See
`config/executor.example.json` and `config/executor.unitree-g1.example.json`,
and `src/config.rs` for every field and its limits. agentd's side is the
`executor` section of `agentd.json` (`crates/robodr-agentd/src/executor_link.rs`).

## Tests

* **Unit tests** (`src/tests.rs`, `src/*`):
  * the full decision matrix: 7 actions × 7 morphologies × 7 safety
    states × 2 validation states × 4 `fall_safe_restrict` sets × approval,
    against an independent statement of the rules;
  * motion path, target and TTL rules, and the safety re-check;
  * the engine against an nftables model: apply, verify, revert,
    idempotency, conflicts, failed apply or verify or journal write, TTL,
    clock step, restart, reboot, operator removal, drift, crash after
    apply and after revert intent, a corrupt journal, humanoid refusals
    and the evidence adapter;
  * the protocol (MAC, tamper, replay, reply binding).
* **Real nftables in network namespaces** (`tests/netns.rs`, needs root,
  `ip` and `nft`). These send real UDP between veth peers:
  * Isolation blocks another host in both directions and keeps
    management, the motion path port range and loopback open.
  * Quarantine drops by GUID prefix from any address and by locator, and
    passes other participants and other ports.
  * Revert restores the exact earlier ruleset, compared handle-free with
    `nft -j list ruleset`, both alone and with another action still
    active.
  * TTL expiry, restart re-verification, reboot re-apply, operator
    removal (running and stopped), drift repair, and a crash between
    apply and journal commit are all recovered.
  * Foreign tables stay byte-identical.
  * Humanoid refusals install nothing.
  * The protocol works end to end over the unix socket, including a
    wrong key and a changed safety state.

  Without root, these tests print `SKIPPED`. `ROBODR_REQUIRE_NETNS=1`
  turns a skip into a failure.
* **Shipped examples** (`tests/examples.rs`).
* **agentd end to end** (`crates/robodr-agentd/tests/executor_link.rs`):
  the real daemon with signed SOC requests and an in-process executor.

## Limits (v1)

* **Not run on a robot or under systemd.** The unit passes
  `systemd-analyze verify` (systemd 255); its syscall filter and
  `ProtectKernelModules=` have not been exercised with `nft` under
  systemd. On a minimal kernel, load the nf_tables modules at boot.
* **Quarantine by GUID** only matches RTPS over UDP whose message header
  carries the prefix. The following are **not** covered:
  * RTPS over TCP or shared memory (Cyclone iceoryx, Fast DDS SHM), which
    never reaches nftables;
  * a sender that changes its GUID prefix (it then appears as a new,
    unknown participant);
  * a rogue participant on the same host that talks over loopback with
    another GUID.

  Locator rules assume the participant sends from its unicast locator
  port (Cyclone DDS does; Fast DDS uses ephemeral send ports, so only the
  GUID rule and the to-locator rule apply to it).
* **No locators from agentd yet.** The control plane's `quarantine_node`
  names a GUID only, and the planner orders carry the plan's source GUID.
  Neither attaches SPDP locators, so v1 quarantines by GUID prefix and the
  locator rules are used only when an order carries locators. A
  `node`-named quarantine is refused (`unsupported_target`).
* **`restrict_motion`** is advisory: there is no Motion Firewall gateway
  yet (Sprint 8).
* **No High finding for a failed revert yet.** A failed revert is reported
  through:
  * the request state;
  * a critical (fsynced) `robodr.executor_event` note in the black box;
  * `status.json` `executor.revert_failures`;
  * the executor's journal and log.

  A `robot.agent.executor_*` finding needs a catalog entry, which is a
  findings-contract minor bump (2.2) coordinated with the diode validator
  and the SOC.
* **Isolation is stateless by address and port.** DNS, NTP and DHCP keep
  working only if their servers are in an allow-list.
* **Emergency disable** is `nft delete table inet robodr`.
  `systemctl stop robodr-executor` alone keeps the active actions until
  their revert or TTL at the next start. On package removal, `prerm`
  deletes the table.
