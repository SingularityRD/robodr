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
| `isolate_network` | nftables | drops all traffic in, out and forwarded, except loopback, the management and uplink allow-list, the robot's control buses (configurable), the motion control path, the robot's DDS discovery (SPDP multicast, IGMP), and what any host needs: DHCP / DHCPv6 client, path MTU discovery (ICMP "fragmentation needed", ICMPv6 "packet too big"), IPv6 neighbour / router discovery and MLD | exact inverse | always (`ttl.default_s` if the request names none) |
| `quarantine_node` | nftables | drops RTPS whose header carries the participant's GUID prefix (raw payload match), and UDP from and to its SPDP unicast locators (IP and port); never inside the motion control path it may not cut (accepted before any drop). Needs the locators, each provably outside that path | exact inverse | always |
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
   path, TTL limits), both **re-read from disk before every order** (an
   unreadable file refuses: `config_unavailable`; no reload signal is
   needed or used). Rules 1–13 are in the module docs. In summary:
   * Replays are refused.
   * Only actions with `GaExecution::Executor` that never de-energise are
     executed.
   * The morphology of the order's context and plan must equal the
     executor's own.
   * In observe mode, while the safety system is engaged, or when the
     action was judged in an `unknown` safety state, nothing happens.
   * Targets must be participants: never a process, never a node name.
   * On a robot that falls when de-energised (humanoid, unspecified), the
     action must be listed in `fall_safe_restrict` and approved by a
     human. A quarantine on any robot that balances actively also needs a
     human.
   * The motion control path is never cut, unless `fall_safe_restrict`
     names that target class and the entry is not `low_level`. A
     `low_level` entry is never cut.
   * A quarantine needs the participant's SPDP unicast locators
     (`locators_required`; agentd attaches them, see below), and each must
     lie outside the `cidr` of every motion-path entry the quarantine may
     not cut (`motion_path`). Such an entry with an `interface` and no
     `cidr` refuses every quarantine: no locator can be proven outside
     it. A matching GUID prefix refuses too. **A quarantine cannot act
     inside a low-level network**: the entries it may not cut are rendered
     as accepts before its drops, so traffic there passes even when it
     carries the quarantined GUID prefix (GUIDs change on restart and can
     be forged).
   * Isolation needs a configured management channel.
   * The TTL must be within `1..=ttl.max_s`.
2. **Safety re-check immediately before apply.** This is executor rule 4 of
   `robodr_agent::executor`. Over the open connection, the executor asks
   agentd for the safety state at that moment. agentd answers from a cell
   that its main loop refreshes on every iteration (normally every 50 ms or
   less), together with the state's age. The executor refuses the action
   in these cases:
   * the state is unavailable, reported `unknown`, or stale
     (`safety_state_unavailable`, `safety_state_stale`; older than
     `max_safety_age_ms`, round trip included);
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
   retried on every tick and reported (event `revert_failed`). A revert is
   reported `reverted` **only once the journal records it**: when the
   write fails (disk full), the rules are lifted all the same, the action
   stays `reverting` (event `journal_error`, once) and the write is
   retried every tick.
8. **Housekeeping.** Every 500 ms, on its own thread (no peer can delay
   it), the executor reverts expired actions and retries failed reverts.
   TTLs run on CLOCK_BOOTTIME within a boot: a wall-clock step neither
   extends nor shortens an action. Every `verify_interval_s` it reads the
   table back:
   * **Drift**, meaning any difference such as a rule deleted by hand: the
     executor re-applies the rendering.
   * **Table missing while actions are active**: an operator's emergency
     disable (below).
9. **Emergency disable.** `nft delete table inet robodr` is detected
   before every transaction (a new order, a revert, a retry) and by the
   periodic read-back. Every action is dropped as `removed_externally`,
   nothing is re-installed, and **every order is refused**
   (`operator_disabled`), also across restarts, until the operator runs
   `robodr-executor rearm --config /etc/robodr/executor.json`. So the next
   order or revert can never re-create the table the operator removed.

## Restart, crash and reboot

Writes to `journal.json` are atomic and write-ahead. At start
(`Engine::open`) the executor reconciles the table with the journal:

| Journal entry | At restart |
|---|---|
| `applying` | its transaction may or may not have run (crash between `nft -f` and the commit): re-rendered **without** it (reverted), reported `failed` |
| `reverting` | re-rendered without it: the revert completes |
| `active`, deadline passed | reverted (TTL expired while down) |
| `active`, deadline ahead, same boot, table present | re-applied and verified (no change) |
| `active`, deadline ahead, **new boot** | **held**: re-validated against the current configuration and policy (the precheck of its stored order; refused → reverted), not installed. It is re-applied only when agentd's next event poll supplies a fresh, known safety state that is not engaged; it expires at its deadline like any action |
| `active`, same boot, **table missing** | operator emergency disable: dropped, not re-applied, orders refused until `rearm` |
| journal unreadable | table deleted, start empty: event `journal_reset` (detail `HIGH: ...`) and the status flag `journal_reset_ms` until `rearm` |

**Clock.** Within a boot, expiry is decided on CLOCK_BOOTTIME
(`/proc/uptime`): NTP or an operator stepping the wall clock changes
nothing. Across a reboot only the wall-clock deadline exists; an action
with more TTL left than it was ever given (the clock moved back) counts as
expired. A clock step can never make an action outlive its TTL.

**A failed start leaves no rule.** Any error while the executor starts
(configuration, key, journal write after the re-apply, socket) deletes
table `inet robodr` before the process exits, and the unit's
`ExecStopPost=robodr-executor stop-cleanup` does the same (and marks the
journal) after every run that did not end in success: a crash, a
watchdog kill, a failed start, the start limit. Nothing would enforce the
TTL of a rule left behind. A clean `systemctl stop` keeps the actions for
the next start's reconciliation.

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
  * Its entries are rendered as accepts **before any drop** of any
    action, in every chain, so no quarantine reaches them.
  * A motion-path entry always names an address and/or an interface; a
    `guid_prefix` only narrows it (configuration validation refuses a
    GUID-only entry, the renderer ignores one from an old journal): anyone
    can write any prefix into an RTPS header.
  * The robot's DDS discovery keeps working during isolation (SPDP
    multicast out, IGMP, SPDP in from the protected networks), so the
    motion stack does not lose its peers' leases.
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
  restriction that keeps management and the motion path open (see
  "Trust boundary").
* **Fails towards doing nothing.** Each of the following leaves the robot
  without the rule set, never with a partial one:
  * a journal write that fails before apply;
  * an nft error;
  * a read-back mismatch;
  * an unreachable agentd at the safety re-check;
  * a stale or unknown safety state;
  * an unreadable journal, configuration or policy;
  * a re-apply failure at restart, any failed start, a run that ends in
    anything but success.
* **Least privilege.**
  * agentd keeps `CAP_NET_RAW` only.
  * The executor has `CAP_NET_ADMIN` only, no IP sockets
    (`RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any`),
    and writes only to its journal directory.
  * It runs `nft` from an absolute path, with an argument vector, an empty
    environment, and JSON built from validated types on stdin. No shell is
    involved and no request text reaches a rule: comments carry a hash of
    the order id.

## Trust boundary

The executor trusts agentd for **what was judged**: the order's
`human_approved` flag, the origin (`control_plane` with the SOC key id,
or `planner`), the judged safety state and operational context, and the
participant's locators. It re-checks everything it can know itself (its
own policy and configuration, the safety state at apply time, the motion
control path), but it cannot tell whether a human really approved an
order: **a compromised agentd (with the protocol key) can assert
`human_approved`** and so obtain what the executor's own rules allow with
a human's approval. That is still bounded by those rules: reversible,
TTL-bounded network restrictions only; nothing on a humanoid outside
`fall_safe_restrict`; never a `low_level` entry or a motion-path entry
the policy does not list; never an action that may de-energise; never
while the safety system is engaged.

Planned with the control plane v2: agentd forwards the SOC-signed request
itself, and the executor verifies the SOC signature and the approval with
its own copy of the SOC keys before it accepts `human_approved`, so a
compromised agentd can no longer assert an approval. This is not in
executor v1.

## Protocol (agentd ↔ executor)

The transport is a unix stream socket at `/run/robodr-executor/executor.sock`
(mode `0660`, group `robodr`). Messages are newline-delimited JSON
envelopes authenticated with HMAC-SHA-256 under a shared 32-byte key
(`robodr-executor keygen`, delivered to both units through systemd
credentials). The MAC covers the version, the timestamp (±30 s), a nonce
(cached, fails closed when the cache is full), `reply_to` (which binds a
reply to its request) and the exact message text. One connection carries
one exchange: `submit` → `confirm` → `safety` → `outcome`, or `revert`,
`status`, `events` or `ping`. While actions are held after a reboot,
`events` (agentd polls every second) is answered with a `confirm` first:
agentd's safety state then decides whether they are re-armed. The
operator's `rearm` (CLI) has its own message. Details are in
`src/proto.rs`.

Housekeeping (TTL, revert retries, read-back) runs on its own thread,
independent of every connection. At most 8 connections are served at
once (more are closed at once). A request line must arrive whole within
5 s, an absolute deadline (a peer sending one byte at a time cannot
stretch it), and it is read without holding the engine. Inside a
`submit`, agentd's safety answer must arrive within 2 s; only then is the
engine held while a key holder waits. Nonces are remembered on the
monotonic clock, so a wall-clock step back neither fills the cache nor
drops entries early. Only members of group `robodr` can connect.

## nftables details

* The table is `inet robodr`, with base chains `input`, `forward` and
  `output` (`type filter`, priority `filter - 5`, policy `accept`). Each
  chain holds, in this order:
  1. the **protected preamble** (comment
     `robodr protected motion_control_path`): accepts for every
     motion-path entry any active action may not cut (the union of the
     entries frozen into the active isolations and quarantines);
  2. the quarantine rules, in order of their order id;
  3. the isolation rules, ending in a counted `drop`.

  Other rule comments read `robodr <action> <12 hex of sha256(order id)>`.
* **Ports match by direction.** A packet from outside (`input`, `forward`)
  matches a port rule when it is addressed **to** the port (a request to
  a service). It matches the **source** port only as a reply: a TCP
  segment that is not a bare SYN, or (UDP) a datagram of a flow conntrack
  has seen both ways (`ct state established`). Protected `udp_ports` have
  no reply form: an inbound packet must be addressed to a port in the
  range. The robot's own packets (`output`) match either port. A UDP
  allow-list entry with a port therefore turns conntrack on in the
  robot's network namespace while an isolation is active.
* **Fragments.** Non-first IP fragments carry no transport header, so no
  port or GUID match sees them: for every entry narrowed by a port or a
  GUID they are accepted by the entry's address or interface
  (`ip frag-off & 0x1fff != 0`, `frag frag-off != 0`). The first fragment
  is matched as usual, so a datagram whose first fragment is dropped is
  never reassembled.
* GUID match: `meta l4proto udp`, `@th,64,32 == "RTPS"`, then
  `@th,128,32`, `@th,160,32` and `@th,192,32` against the 12-byte prefix
  in network byte order (in a rule that also matches a UDP port, after it
  and without the redundant `meta l4proto udp`, which nft lists away).
* Locator rules: `ip[6] saddr <ip> udp sport <port> drop` (traffic from the
  participant), `ip[6] daddr <ip> udp dport <port> drop` (traffic to it),
  and both in `forward`.
* Isolation also keeps: `ip[6] daddr <groups> udp dport <ports>` out
  (the robot's SPDP and user multicast; on the interfaces of the
  protected and control-bus entries, or any interface when one of them
  names only an address), the same in from each protected entry, IGMP in
  and out on those interfaces; DHCP (`udp sport 67 dport 68` in,
  `68 → 67` out) and DHCPv6 (`547 → 546`, `546 → 547`); ICMP
  `destination-unreachable` / `frag-needed` and ICMPv6 `packet-too-big`
  in every chain; ICMPv6 neighbour solicitation / advertisement, router
  advertisement (in) / solicitation (out) and MLD.
* Anonymous sets are compared order-free at read-back (nft lists them in
  its own order).
* Requires the `nft` binary with JSON support. Tested with nftables 1.0.9
  (Ubuntu 24.04).

## Configuration

`/etc/robodr/executor.json` uses schema `robodr-executor-config/v1`. See
`config/executor.example.json` and `config/executor.unitree-g1.example.json`,
and `src/config.rs` for every field and its limits. agentd's side is the
`executor` section of `agentd.json` (`crates/robodr-agentd/src/executor_link.rs`).

* `network.motion_control_path[]` entries need `cidr` and/or `interface`;
  `guid_prefix` and `udp_ports` only narrow them.
* `network.discovery` (default `{"multicast_groups": ["239.255.0.1"],
  "domains": [0]}`): the SPDP multicast groups and DDS domains whose
  multicast ports (`7400 + 250 d`, `7401 + 250 d`) stay open during an
  isolation. `"multicast_groups": []` keeps none.
* **Locators from agentd.** For a `quarantine_node` order agentd attaches
  the participant's SPDP unicast locators (metatraffic and default, IP and
  port): from the pipeline's binding table (what the participant
  announced through a path the binding trusts; none for a contested or
  expired prefix), else from `ros2_participant_discovered` events of a
  JSONL input. Without them the executor refuses (`locators_required`).

## Tests

* **Unit tests** (`src/tests.rs`, `src/*`):
  * the full decision matrix, against an independent statement of the
    rules: 7 actions × 7 morphologies × 7 safety states × 2 validation
    states × 4 `fall_safe_restrict` sets × 2 approval states (the v1
    matrix: 5 488 cases) × 4 quarantine targets (unprotected GUID with a
    locator outside / inside the robot bus, the protected GUID, no
    locators) × 4 motion paths (bus + low-level writer, a low-level
    network, none, an interface-only entry) × 2 profile-lock states × 3
    TTLs = **526 848 cases**, with invariants (what may not be cut is
    frozen into the effect; a quarantine's locators lie outside it);
  * motion path, target, locator and TTL rules, the safety re-check, the
    re-arm check and `unknown` safety states;
  * the engine against an nftables model: apply, verify, revert,
    idempotency, conflicts, failed apply or verify or journal write, TTL
    on CLOCK_BOOTTIME (wall-clock steps both ways), restart, reboot hold
    and re-arm (with re-validation against a changed configuration),
    operator removal through every path and `rearm`, a revert whose
    journal write fails, drift, crash after apply and after revert
    intent, a corrupt journal (High flag), the policy re-read per order,
    humanoid refusals and the evidence adapter;
  * the server under slow clients (a 3 s TTL expires on time while
    three clients trickle one byte per 900 ms, and another client is
    served meanwhile);
  * the protocol (MAC, tamper, replay, reply binding, the nonce cache on
    the monotonic clock).
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
    wrong key and a changed safety state; held actions are re-armed only
    through an event poll with a fresh safety state; `rearm` ends an
    emergency disable.
  * Review regressions (`h1_*` … `m6_*`, `l2_*`, `l5_*`): a GUID-only
    protected entry opens nothing (RTPS with that prefix from a host
    outside every allow-list is dropped both ways); a quarantine never
    cuts a low-level host even when its traffic carries the quarantined
    prefix; the robot's SPDP multicast (239.255.0.1:7400/7401) leaves
    and SPDP from the protected network arrives, real UDP multicast
    between namespaces; 4000-byte datagrams of a protected flow are
    routed through the robot in fragments; DHCP client exchange and path
    MTU discovery work (a router behind a 1280-byte link, the robot
    learns `mtu 1280`); port rules match by direction; an operator's
    table delete is not undone by the next order or revert; a failed
    start on a full tmpfs, a failed start of the real binary and
    `stop-cleanup` leave no rule; a revert on a full tmpfs is not
    reported `reverted` until it is journalled.
  * IPv6, interface-bound and shipped-example renderings are loaded into
    the kernel and read back exactly (the test kernel has no IPv6
    networking, so IPv6 rules are verified as rendered and listed, not
    with traffic).

  Without root, these tests print `SKIPPED`. `ROBODR_REQUIRE_NETNS=1`
  turns a skip into a failure.
* **Shipped examples** (`tests/examples.rs`).
* **agentd end to end** (`crates/robodr-agentd/tests/executor_link.rs`):
  the real daemon with signed `robodr-control-plane/v2` requests (unix
  socket and mutual TLS, every answer's signature verified) and an
  in-process executor; the executor states survive agentd restarts (v2
  request journal).

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
* **Quarantine needs locators** agentd has seen (binding table or
  participant events). A participant whose SPDP agentd never saw cannot
  be quarantined (`locators_required`). A `node`-named quarantine is
  refused (`unsupported_target`).
* **A quarantine cannot act inside a low-level network** (or inside any
  motion-path entry it may not cut), and none is possible while such an
  entry names only an interface.
* **GUID matches read the RTPS header only.** A message whose submessages
  use `INFO_SRC` to name another source prefix is matched by its header
  prefix. A GUID-narrowed protected entry keeps only RTPS **sent by**
  that participant (in either direction); traffic to it is kept by
  address / port entries.
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
* **A corrupt journal is a High notice, not a finding.** No existing
  finding id fits (the `robot.agent.evidence_*` ids are about the black
  box), so an unreadable journal (table deleted, history lost) is
  reported as: the executor event `journal_reset` with detail `HIGH: ...`,
  recorded by agentd as a **critical** (fsynced) `robodr.executor_event`
  note; `status.json` `executor.journal_resets`; the executor's status flag
  `journal_reset_ms` (`robodr-executor status`, `ping`, the unit's
  `STATUS=`) until the operator acknowledges it with `rearm`. It becomes a
  finding with the same 2.2 catalog bump.
* **Isolation keeps the host basics, not services.** The DHCP / DHCPv6
  client exchange, path MTU discovery (ICMP / ICMPv6 errors from any
  address), IPv6 neighbour / router discovery and MLD stay open by
  default. DNS and NTP keep working only if their servers are in an
  allow-list. A router advertisement or an MTU error from any host is
  accepted, as the host would without the isolation.
* **Bridged traffic** (the robot as an L2 bridge) passes the `inet`
  hooks only with `br_netfilter` loaded and
  `net.bridge.bridge-nf-call-iptables=1`; without it, frames bridged
  through the robot are not isolated.
* **IPv6** rules are rendered, loaded and read back in the tests, but no
  IPv6 traffic was exercised (the test kernel has no IPv6 networking).
* **Cyclone DDS / Fast DDS** were not run in the tests (not installable
  offline); discovery was tested with real UDP multicast to
  239.255.0.1:7400/7401 between namespaces.
* **Emergency disable** is `nft delete table inet robodr`, followed by
  `robodr-executor rearm` to execute orders again.
  `systemctl stop robodr-executor` alone keeps the active actions until
  their revert or TTL at the next start. A failed run deletes the table
  (`stop-cleanup`). On package removal, `prerm` deletes the table; a
  purge removes the executor's journal.
