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
| `quarantine_node` | nftables | drops RTPS whose header carries the participant's GUID prefix (raw payload match), all UDP from and to the source addresses it was seen sending from on the robot's DDS ports (any source port; review R3-1), and UDP from and to its SPDP unicast locators (IP and port); never inside the motion control path it may not cut (accepted before any drop). Needs addresses or locators, each provably outside that path | exact inverse | always |
| `record_evidence` | black box (runs inside agentd) | a signed, fsynced `robodr.evidence_mark` note naming the evidence bundle (the request's black-box reference) | not applicable: evidence is never reverted | none |
| `restrict_motion` | none in v1 | recorded as advisory: the in-path Motion Firewall gateway (`robodr-firewall-gw`) is a separate unit with its own static configuration, and the executor does not drive it, so nothing changes on the robot (request state `recorded_not_executed`) | — | — |
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
   * A quarantine acts on the participant's SPDP unicast locators (agentd
     attaches them, see below) and on RTPS sent by its GUID prefix. It acts
     only on a locator that lies outside the `cidr` of every motion-path
     entry the quarantine may not cut **and** is in scope (review F4):
     inside a `network.quarantine.cidrs` entry, on one of the robot's DDS
     ports (`network.quarantine.udp_ports`, default the RTPS port ranges of
     `network.discovery.domains`), not loopback, one address family. Any
     other locator is **left out** (review of the F3 fix, H2b: listed with
     its reason in the plan, the `applied` event, and the state the
     executor answers agentd (`note`, and `quarantine.excluded`, which
     agentd passes on to the SOC as `state.quarantine`, contract §6a);
     nothing is rendered for it) instead of refusing the whole order, so
     one bad locator in a rogue's own SPDP cannot make it unquarantinable.
     **Still refused**: a GUID prefix of a motion-path entry it may not cut,
     or such an entry with an `interface` and no `cidr` (nothing can be
     proven outside it) (`motion_path`); an order whose every locator lies
     on the motion path (`motion_path`: the participant may be on it); no
     `network.quarantine.cidrs` (`locator_out_of_scope`); and an order with
     no locator left that agentd did not vouch for (`guid_only`, see
     below): `locator_out_of_scope` when it had some, `locators_required`
     when it had none. **A quarantine cannot act inside a low-level
     network**: the entries it may not cut are rendered as accepts before
     its drops (the GUID-prefix drop included), so traffic there passes
     even when it carries the quarantined GUID prefix. The locators are
     SPDP claims nobody signed; this bounds what a forged one can name to
     a DDS endpoint of a network the site declared quarantinable (GUIDs
     change on restart and can be forged).
   * **Source addresses** (review R3-1). The order also carries the
     addresses agentd saw the participant send from (`addresses`). Each
     one is cut **whole**: `meta iifname != "lo" ip saddr <addr> udp dport
     <the robot's DDS ports> drop` in `input` / `forward`, and `meta
     oifname != "lo" ip daddr <addr> udp dport <those ports> drop` in
     `output` / `forward`, whatever the source port. The DDS ports are
     `network.quarantine.udp_ports` (default the RTPS port ranges
     `7400 + 250 d ..= +249` of `network.discovery.domains`), merged and
     frozen into the action. An address gets the same checks as a locator
     (not loopback, inside a `network.quarantine.cidrs` entry, outside every
     management / uplink entry, outside every motion-path entry it may not
     cut, one address family) and is otherwise **left out**
     (`quarantine.excluded_addresses`, with the reason). An address and
     no locator is enough to act on. **Shared host:** cutting an address
     cuts every DDS participant on that host, including a legitimate,
     unprofiled process that happens to run there (agentd never hands out
     this host's own address, an address pinned to another participant, or
     a profiled participant's host address; the motion control path is
     accepted before any drop).
   * **`containment`** (`quarantine.containment` in the state answer; the
     SOC's `containment`, contract §6a): `full` only when at least one
     address is cut whole, no announced locator and no observed address
     was left out or forgotten, and every cut locator lies on a cut
     address; `guid_only` when no address and no locator is cut (only the
     GUID-prefix drop); `partial` otherwise. One definition
     (`decision::containment_of`) serves the executor and agentd.
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
7. **Revert** on request, at TTL expiry, or by `revert-all`. A requested
   revert of an action the SOC approved needs the SOC's own signed revert
   request (review F3, "Trust boundary"). The action is
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
  request. The executor then verifies the SOC's signed approval itself
  and re-checks against its own policy and configuration, and against
  the safety state milliseconds before the transaction. A compromised
  agentd cannot assert an approval no SOC key holder signed; it can at
  most request what the executor's own checks allow without one (see
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

**Executor M1: the executor verifies the SOC's approval itself**
(`src/soc.rs`). agentd forwards, with every order that comes from the
control plane, the SOC's original `robodr-control-plane/v2` request
exactly as it was signed (method, target, key id, timestamp, nonce,
signature, body; `Order.soc`). The order's `human_approved` is only
agentd's claim: before the executor accepts it, it checks, with its **own**
copy of the SOC public keys (`soc.keys` in `executor.json`: the same
`robodr-blackbox keygen` public key files as agentd's
`control_plane.soc_keys`, absolute paths, regular files owned by root or
the executor's user, not group/other-writable, public Ed25519 only,
`device_id` if set = this robot; re-read before every order):

| Check | Refusal |
|---|---|
| the order carries a SOC request at all; it is well formed; its key id is configured (no key configured refuses every control-plane order) | `soc_signature_invalid` |
| the Ed25519 signature verifies over the contract's signing message (§2) with the **executor's own** robot id | `soc_signature_invalid` |
| the timestamp is within `soc.max_clock_skew_s` (default 30 s) of the executor's clock, and not fenced | `soc_request_stale` |
| the (key, nonce) pair was never presented to the executor while its timestamp is in the window: the executor's **own** replay store, `<state_dir>/soc_nonces.json`, written atomically (fsync) before the order goes further, so a replay is refused **across restarts** and even after the journal is lost | `soc_nonce_replayed` |
| the store can record the pair (at most 8192 live pairs; a write that fails refuses) | `soc_replay_store_unavailable` |
| the request is `POST /api/v2/robots/<own robot id>/action-requests`; the order's id, action, TTL and target equal the signed `request_id`, `action`, `ttl_seconds` and `participant_guid` / `node`; the origin's key id and `requested_by` equal the signed ones; the signed body parses strictly (unknown / duplicate fields refuse) | `order_mismatch` |
| the approval evidence the contract requires is in the signed body: `authority: "request"`, `requested_by` (1..=100 characters), `source` (`[a-z0-9_-]{1,32}`), `reason` (≤ 500 characters) | `approval_missing` |

A replay store that is missing while the executor's journal exists, or
unreadable, **fences**: every request signed at or before that start
**plus `soc.max_clock_skew_s`** is refused (`soc_request_stale`; review F8:
a request signed up to the skew ahead of the clock was inside the window
before the start and may have been presented to the lost store); the SOC
signs again after the fence. The event log records it (`reconciled`,
detail "SOC replay store untrusted"). The store also persists a wall-clock
high-water mark (the latest second it dropped dead pairs, `high_water_s`):
a clock that reads below it, at start or while running, fences every
request signed up to the mark **plus** the skew, since the dropped pairs'
timestamps would be in the window again (as agentd's `ReplayGuard`,
control plane v2 review finding 5). Unlike agentd, a store created on a
first start (no executor journal either) does not fence.

**Reverts** (review F3). An action the SOC approved (control-plane origin)
is lifted on request **only with the SOC's signed revert request**:
agentd forwards the SOC's `POST /api/v2/robots/<robot>/action-requests/
<id>/revert` exactly as signed (`Msg::Revert.soc`), and the executor
checks it like a submit (configured key, signature for its own robot id,
timestamp window, the same replay store) plus: the target is the revert
of **this** action, and the body is the contract's strict revert body
(`requested_by` 1..=100 characters, optional `reason` ≤ 500; unknown
fields refuse). A refused revert leaves the action in force and answers
its status with the refusal (`soc_signature_invalid`, `soc_request_stale`,
`soc_nonce_replayed`, `order_mismatch`, `approval_missing`); the journal
records a `refused` event for it. **Without a signature** the executor
still reverts: planner actions (nobody approved them), TTL expiry,
restart reconciliation (and a held action the re-validation refuses), and
the operator's `robodr-executor revert-all` (root, on the host).

**Keys** (review F9). `soc.robot_keys[]` names the robot's **own** public
keys (its black-box and finding signing keys, agentd's public key files,
read only): a SOC key equal to one of them is refused, so whoever holds
the robot's key cannot approve containment. One key file that cannot be
read or is refused (permissions, owner, secret material, device binding)
refuses **every** control-plane order with `soc_keys_unavailable` rather
than dropping to the other keys (integrity first: a silently shorter key
list changes who can approve; the start log and `check` say which file).
An action held after a reboot is re-armed only while the SOC key that
approved it is still configured (`approval_key_removed` otherwise:
reverted).

**Site option** `require_approval_for_all_containment` (default `false`;
`true` in the G1 example): every containment needs the SOC's approval on
every morphology, so on-robot planner orders are refused
(`needs_approval`) even where the morphology rules would allow them.

**Planner orders** (no SOC request) can never claim an approval
(`approval_missing` when one does), so they stay limited to what the
policy allows without a human: nothing on a humanoid or an unspecified
body (`needs_approval`), no quarantine on any robot that balances
actively (humanoid, quadruped, unspecified; `needs_approval`). A
quadruped's network isolation without a human stays possible, as the
response policy plans it (the motion control path is kept open by every
isolation).

The verified order is journalled without the request, with
`human_approved` as the executor established it; a held order is
re-validated after a reboot from that verified copy (its SOC timestamp
would be stale by then).

**What a compromised agentd (with the protocol key) can still do:** refuse
or delay to forward an order (denial of service), and lie about what only
agentd knows: the safety state and the operational context the request
was judged in (the executor has no safety feed; it re-checks agentd's live
state immediately before apply), and the participant's locators (re-checked
against the motion control path and the configured quarantine scope: a
wrong locator can only make a quarantine miss, refuse, or drop a DDS
endpoint inside `network.quarantine.cidrs`). It **cannot** obtain an
action no SOC key holder approved, change what was approved (action,
target, TTL), use an approval twice, use one signed for another robot,
turn a planner order into an approved one, or lift an action the SOC
approved without the SOC's signed revert (F3). It can still let a TTL run
out (it cannot shorten one) and run the planner's own actions. Everything stays bounded by the executor's own rules
(reversible, TTL-bounded network restrictions; never a `low_level` entry;
never an action that may de-energise; never while the safety system is
engaged).

Deployment: give the executor the SOC public key files (root-owned, 0644)
alongside agentd's, and keep `soc.max_clock_skew_s` at least agentd's
`max_clock_skew_s` (agentd hands an order over within milliseconds of
accepting it).

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

* `soc.keys[]` (SOC public key files), `soc.max_clock_skew_s`
  (default 30, 1..=300) and `soc.robot_keys[]` (the robot's own public
  keys, never accepted as SOC keys): see "Trust boundary". Without keys
  every control-plane order is refused; one bad key file refuses them all
  (`soc_keys_unavailable`).
* `network.quarantine` (`cidrs`, `udp_ports`): where a quarantine may act
  (review F4). `cidrs` may not be `/0` nor overlap a management / uplink
  entry; empty refuses every quarantine.
* `require_approval_for_all_containment` (default `false`): see "Trust
  boundary".
* `network.motion_control_path[]` entries need `cidr` and/or `interface`;
  `guid_prefix` and `udp_ports` only narrow them.
* `network.discovery` (default `{"multicast_groups": ["239.255.0.1"],
  "domains": [0]}`): the SPDP multicast groups and DDS domains whose
  multicast ports (`7400 + 250 d`, `7401 + 250 d`) stay open during an
  isolation. `"multicast_groups": []` keeps none.
* **Addresses from agentd** (review R3-1). With the locators, agentd
  attaches the source addresses the prefix was seen sending from (its own
  SPDP and accepted endpoint announcements; at most 8 remembered, newest
  kept; `evidence_truncated` when one was forgotten), leaving out loopback,
  this host's addresses, an address pinned to another prefix, a profiled
  participant's pinned address, a profile identity's `ips`, and any
  address a profiled participant was learned at (each with its reason in
  `excluded_addresses`): an address-wide drop there could cut the robot's
  own participants. Addresses beyond the order's 16 are listed as left
  out, never dropped silently.
* **Locators from agentd.** For a `quarantine_node` order agentd attaches
  the participant's SPDP unicast locators (metatraffic and default, IP and
  port) from the pipeline's binding table (`robodr_ros2_pipeline::binding`,
  "Quarantine locators"): what the participant itself last announced
  through a path the binding trusts, also after it left, its lease expired
  or a prefix flood evicted it (kept 24 h), **only on addresses it was seen
  sending from**; never a locator a profiled participant announces, any
  port on this host's address or an address pinned to a profiled
  participant (for a non-profiled target; review R3-6: an address a
  profiled participant was only *learned* at, first-come, may be an
  attacker's, so it no longer shields other ports, but is never cut
  whole), or an address pinned to another prefix; none for a contested
  or pinned prefix. Another prefix seen at the same address announcing the
  same ip:port does not take it away (review R2-3: the rogue's own second
  prefix is the same host, no spoofing needed). It
  also sets `guid_only` when the binding table saw the prefix and it is not
  one of the robot's own (profiled, pinned, contested): with no locator
  left the executor then quarantines by the GUID-prefix drop alone (it
  matches RTPS sent by that prefix only). The locators agentd left out are
  listed in the order (`excluded`, with the reason; locators beyond the
  order's 16 too, review R2-6). A
  `ros2_participant_discovered` event of a JSONL input is used only for a
  prefix the binding table does not know at all, through the same filters
  with the event's `src_ip` as the only evidence (review M7). Without any
  locator and without `guid_only` the executor refuses
  (`locators_required`).

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
    the monotonic clock);
  * trust boundary M1 (`m1_*`): forged orders refused (no SOC request,
    another key, signed for another robot, body changed after signing,
    truncated signature, stale timestamp, another path, a quarantine's
    approval used for an isolation, a stretched TTL, approval evidence
    missing, an unknown body field); a planner order claiming an
    approval; planner orders never on a balancing robot; a matching order
    applied; a SOC request replayed under another id, and after a restart
    with the journal lost; a removed or corrupt replay store fences; no
    SOC key, a group-writable or secret key file;
  * review of M1 (each test written first and seen failing): F3 an
    unsigned revert of a SOC-approved action refused over the real socket,
    reverts signed for another action / as a submit / by another key /
    with a non-strict body refused, the signed revert lifts it, the same
    revert replayed on another action refused, a planner action reverted
    unsigned; F4 locators outside `network.quarantine` (not a DDS port,
    outside the CIDRs, mixed families, no scope configured); F8 the fence
    covers the skew window; F9 a SOC key equal to a robot key, re-arm after
    the approving key was removed, one bad key file
    (`soc_keys_unavailable`); the `require_approval_for_all_containment`
    option. Over real nftables the protocol test also checks that an
    unsigned revert leaves the isolation in force and the signed one
    restores traffic.
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
    wrong key and a changed safety state; orders a key holder forges
    (no SOC request, another SOC key, a stretched TTL) change nothing in
    the kernel's ruleset and the matching signed order is applied; held actions are re-armed only
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

  Locator rules match the participant's announced ports only (Cyclone DDS
  sends from its unicast locator port; Fast DDS uses ephemeral send
  ports). Since review R3-1 the **address** rules cover any source port:
  a participant is contained against ephemeral-port senders and `INFO_SRC`
  re-attribution only where its addresses are cut whole, i.e. with
  `containment: "full"`. A participant whose address is left out (e.g. on
  a profiled participant's host) is `partial`: from there only its
  announced ports and the GUID-prefix drop apply.
* **Quarantine needs locators** agentd has seen (binding table or
  participant events), or agentd's `guid_only` vouch (a participant it saw
  and that is not one of the robot's own; then by GUID prefix only, which
  `INFO_SRC` re-attribution or a new prefix evades: the state answer's
  `quarantine` (no address, no locator) lets agentd tell the SOC
  `containment: "guid_only"`). A rogue that announces its locators only
  on addresses it never sends from has its observed source addresses cut
  whole (`partial`: the announced ones are left out). A
  participant whose SPDP agentd never saw cannot be quarantined
  (`locators_required`). A `node`-named quarantine is refused
  (`unsupported_target`).
* **Shared hosts.** An address cut whole cuts every DDS participant on
  that host, a legitimate unprofiled one included (above). Source
  addresses are not authenticated: a decoy whose SPDP is spoofed to a
  present unprofiled host's address gets that address cut when the decoy
  is quarantined (within `network.quarantine.cidrs`; never this host, a
  pinned, identity or learned profiled host, or the motion control path).
* **A quarantine cannot act inside a low-level network** (or inside any
  motion-path entry it may not cut), and none is possible while such an
  entry names only an interface.
* **GUID matches read the RTPS header only.** A message whose submessages
  use `INFO_SRC` to name another source prefix is matched by its header
  prefix. A GUID-narrowed protected entry keeps only RTPS **sent by**
  that participant (in either direction); traffic to it is kept by
  address / port entries.
* **`restrict_motion`** is advisory: the in-path Motion Firewall gateway
  (`robodr-firewall-gw`) exists as a separate unit, but it enforces its own
  static envelope and the executor does not drive it (no interface to
  tighten its limits at run time).
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
