# robodr-firewall-gw — in-path Motion Firewall gateway

The first RoboDR component that **enforces** in the robot's motion command
path. It runs on the sensor box as an **inline bridge**: two NICs bridged
(controller side / robot side); every UDP datagram of a configured motion
channel that enters from the controller side is handed by the kernel to a
Linux NFQUEUE, decided with `robodr-firewall`, and answered with

- **ACCEPT** (forwarded byte-identical),
- **ACCEPT with a rewritten payload** (same length: a limited frame, a
  substitute written into the sample, or a sample removed as a PAD), or
- **DROP** (malformed datagrams; legacy UDP frames that must not pass).

> **Not a safety-rated device.** This is a cyber-security control. It does
> not implement and does not replace any safety function (ISO 10218,
> ISO 13849, IEC 61508). The robot's own safety functions — e-stop, safety
> controller, the motor drivers' protections and command timeouts — remain
> primary and must be designed to be sufficient on their own. The gateway
> can only pass, reduce, hold or remove commands that cross the bridge; it
> never originates a datagram, it does not see traffic that does not cross
> the bridge (Wi-Fi, cellular, the robot's internal links), and a fault in
> it is covered by the queue's `on_gateway_down` behaviour and the robot's
> own command timeout, not by the gateway.
>
> **Status: not validated on a robot.** Everything below was run against
> synthetic traffic in network namespaces on a development VM. Run it in
> `mode: observe` on the real robot first.

## Architecture

```
 controller (PC2 / operator)          sensor box (bridge br0)                 robot
 ─────────────────────────┐   ┌──────────────────────────────────────┐   ┌──────────
  rt/lowcmd, rt/api/...   │──►│ controller_port ─► br_netfilter ─┐   │   │
  Go1 UDP 8082 / 8007     │   │                  iptables FORWARD │   │   │
                          │   │   NFQUEUE n ◄────── ROBODR_GW ◄───┘   │   │
                          │   │      │ robodr-firewall-gw             │   │
                          │   │      ▼ ACCEPT / rewrite / DROP        │   │
                          │   │   robot_port ─────────────────────────┼──►│ DDS reader / motor board
 ─────────────────────────┘   └──────────────────────────────────────┘   └──────────
```

Only traffic **entering from the controller port** is queued; the robot's
own traffic (state, discovery) is bridged untouched. SEDP / SPDP
announcements from the controller side are queued too (always accepted) so
the gateway learns which writer writes which topic.

### Decision pipeline (`Gateway::process`)

| Step | Module | Refuses (→) |
|---|---|---|
| IPv4 / UDP framing, both checksums, no IP fragment, exact lengths | `ip` | → DROP (a rewrite must never resurrect a datagram the receiver would drop) |
| Port: legacy Go1 port → legacy codec; DDS port range of a configured domain → RTPS | `gateway` | other ports → ACCEPT (the ruleset does not queue them) |
| Strict RTPS walk with offsets (header, every submessage, INFO_SRC, inline QoS, DATA / DATA_FRAG) | `rtps` | truncated / malformed / DDS-Security / > 256 samples → `rtps.malformed_datagram` (default DROP) |
| SEDP / SPDP of builtin writers → writer → channel map, participant identities | `discovery` | — |
| Per user DATA: writer → enforced channel (SEDP, persisted map, or a content probe for unknown writers) | `gateway` | not an enforced channel → untouched; an **unknown** writer's DATA_FRAG / key-only / non-standard sample (cannot be probed) → suppressed |
| Source: writer GUID / prefix / identity, `allowed_src_ips`, `allowed_src_macs` | `gateway` | not allowed → foreign (decided, never touches the stream's state, never emitted under an authorised GUID) |
| Writer binding: the GUID's stream is bound to the (IP, MAC) it was last forwarded from | `gateway` | same GUID from another (IP, MAC) while the bound side is live → suppressed (`binding_conflicts`) |
| Sequence number not newer than the last forwarded one → re-emit the cached decision (a lower one after an SEDP re-announcement from the bound side = writer restart) | `gateway` | not cached → suppressed |
| Sequence number more than `rtps.max_sn_jump` ahead → held until the next sample of the same binding confirms it | `gateway` | → suppressed (`sn_jumps`) |
| Strict decode: `robodr-cdr` decode **and** canonical re-encode must equal the bytes; ≤ 3 zero trailing octets | `lowcmd`, `sport`, `legacy` | → integrity failure (below) |
| Non-motor `LowCmd_` fields: go `bms_cmd.off` must be 0 unless `allow_battery_off` | `lowcmd` | → integrity failure (substitute carries the last accepted frame's non-motor fields) |
| `check_joint` / `check` (or the fault verdict when the packet waited > `max_queue_delay_ns`) | `robodr-firewall` | — |
| Pass → bytes untouched; Limited / substitute → rewrite in place + verify; nothing → PAD | `lowcmd`, `sport`, `legacy`, `rtps` | a rewrite that fails verification → PAD |
| UDP checksum recomputed if anything changed (a zero checksum stays zero) | `ip` | — |

### Per-sample verdicts

| Firewall verdict | RTPS channel (`LowCmd_`, sport `Request_`) | Go1 legacy UDP |
|---|---|---|
| Passed | forwarded byte-identical | ACCEPT |
| Limited | rewritten in place: same submessage, same writer / SN / `INFO_TS` / inline QoS, same representation and length, new values, CRC recomputed, verified by decoding again | rewritten in place, CRC recomputed |
| Rejected + substitute | the substitute (hold / damping / zero twist) written **into the rejected sample** the same way | the substitute written over the **last accepted** frame's bytes; none yet → DROP |
| Rejected, nothing to emit | sample **suppressed**: its submessage becomes a PAD of the same length | DROP |

`LowCmd_` rewrites keep every mode octet (a limit never changes a mode) and,
for a substitute, take the non-motor fields (head, level flag, `sn`,
`version`, bandwidth, BMS, wireless remote, LED, fan, GPIO, reserve words,
`mode_pr` / `mode_machine` unless pinned) from the last frame forwarded as
accepted, never from the rejected one; with none yet, SDK defaults (head
`FE EF`, level `0xFF`, BMS `off = 0`, the rest zero). Sport rewrites replace
only the `Move` parameter text (`{"x":..,"y":..,"z":..}` padded with spaces
to the same length, numbers truncated toward zero and parsed back so the
robot's JSON reader cannot read more speed than the firewall allowed);
request id, api id, lease, priority, `noreply` and `binary` are kept.

## What "hold" means on the wire (safety argument)

The firewall's humanoid rule says a rejection holds the last accepted frame
(`dq = 0`; `tau = 0` past `max_hold_ns`) and never damps. At the packet
level the gateway writes that hold **into the rejected sample itself**:
same RTPS submessage, writer GUID, sequence number, `INFO_TS` and inline
QoS, same payload length and representation, new content with the Unitree
CRC recomputed. The robot's DDS reader delivers it as that writer's next
sample. Why this, and not a replay:

- **Replaying the last accepted datagram does nothing.** Its sequence number
  was already delivered; the reader discards it as a duplicate (best-effort
  and reliable readers alike).
- **Re-sending it with a new sequence number corrupts the stream.** The
  gateway would have to invent `SN = last + 1`: the writer's own next sample
  then carries the same number and is discarded as a duplicate (the gateway
  would cause exactly the loss it means to avoid), and a reliable writer's
  HEARTBEAT / GAP state would contradict what the reader holds.
- **So the gateway never originates a datagram.** A hold rides on a sample
  of the protected stream: at most one per incoming frame, never while the
  stream is silent.

When the firewall emits **nothing** (a foreign source with
`foreign_source_action: drop`, a frame inside the minimum interval, a
humanoid channel with no frame accepted yet, a substitute suppressed by the
substitute interval) the sample is **suppressed**: its submessage becomes a
PAD of the same length, which every receiver skips, so the sample is gone as
if it had been lost in transit. The gateway does **not** forge a GAP: a GAP
for a spoofed high sequence number could make a best-effort reader skip the
real writer's later samples. A reliable reader NACKs the missing number; the
retransmission is decided from the cache (below) and suppressed again until
the writer's history moves on.

Invariant on a humanoid joint channel in enforce mode: **every `LowCmd_`
the gateway forwards is either an accepted (passed or limited) frame or a
hold of the last accepted frame.** When a tick is suppressed, the robot
keeps the last frame it received, which is one of those. Persistent silence
(the controller stops, or the gateway is down with `fail_closed`) is covered
by the robot's own command timeout, as when the controller itself fails.
The gateway does not know what the Unitree motor board does after that
timeout; that is the OEM's safety case.

## Sequence numbers and writer binding

Per writer GUID and enforced channel the gateway keeps the stream's state
as the robot's DDS reader sees it: the highest sequence number forwarded
under that GUID (passed, limited or a substitute), the payload forwarded
for the last 8 numbers, and the **binding**: the source IP and source MAC
(`NFQA_HWADDR`, reported by the kernel for bridged frames) the stream was
last forwarded from. The writer GUID is attacker-controlled (no
DDS-Security), so **nothing but a sample of an authorised source from the
bound (IP, MAC) ever changes that state**, and nothing is forwarded that
could move the robot reader's expected sequence number past the genuine
writer's (review finding F1: one spoofed DATA with the motion writer's GUID
and a far-future sequence number used to make every later genuine frame
look like a replay — suppressed, command timeout, fall).

- **Replays / retransmissions.** A sample of the bound stream whose number
  is not newer than the last forwarded one (or that is still cached as
  suppressed) is not decided again: the cached output is re-emitted byte
  for byte if the slot has the same length, otherwise it is suppressed. A
  replay of an old number with new content delivers what was decided for
  that number the first time. Sequence number `<= 0` is suppressed.
- **Foreign samples** (unknown GUID, or an authorised GUID from an IP / MAC
  the channel does not allow) are decided (the firewall records them) but
  never touch the stream's state, and with `foreign_source_action:
  substitute` the substitute is only written into a foreign sample whose
  GUID is neither authorised nor carrying an authorised stream (under such
  a GUID it would ride on the spoofer's sequence number).
- **Binding conflicts.** An authorised GUID from another (IP, MAC) than the
  bound one is suppressed while the bound side is live (it sent anything
  within `rtps.binding_takeover_ns`, default 1 s); after that silence the
  other side may continue the stream, above the numbers already forwarded.
- **Jumps.** A number more than `rtps.max_sn_jump` (default 64) ahead of the
  last forwarded one is suppressed and the state does not move; if the
  next sample of the same binding follows it within the window (real loss,
  a cable unplugged while the controller kept writing) the jump is adopted
  (one tick lost). A writer increments its sequence number by one per
  sample, so a genuine stream only jumps by what was lost on the wire.
- **Writer restart.** A DDS writer that restarts with the same GUID (rare:
  most stacks draw a new GUID prefix per participant) re-announces itself
  (SEDP) before its numbers start again at 1. An SEDP announcement or
  removal of the writer from the bound IP (and MAC) arms a restart: the
  next lower number `<= max_sn_jump` from the bound side starts a fresh
  stream. The arm is cleared by the next forwarded newer sample, and an
  announcement from any other source does not arm it, so a captured
  datagram replayed later is still a replay.

What the gateway **cannot** do: an attacker who can send from the
controller's IP **and** MAC on the controller-side segment is
indistinguishable from the controller. It can then send frames the
firewall accepts (within the envelope), push the robot reader's sequence
number forward by up to `max_sn_jump` per forwarded frame, race the
controller's stream, and arm a restart with a spoofed SEDP. Against that,
the controller-side port of the bridge must carry only the controller (a
point-to-point cable, or a switch port with port security), which is part
of the deployment requirements. With `allowed_src_ips` empty, the first
(IP, MAC) to have a sample forwarded after a gateway start owns the
stream until it falls silent: set `allowed_src_ips` (and, on a shared
segment, `allowed_src_macs`) on every channel.

## Undecidable samples, fragments, malformed datagrams

- A payload of an enforced channel that does not decode **strictly**
  (truncated, non-canonical CDR, non-zero padding, oversized XCDR2
  DHEADER, NUL inside the sport parameter, trailing junk) is decided as an
  **integrity failure**: the firewall gets a frame whose CRC is reported
  invalid (`crc_invalid`), so its source, rate and substitute rules apply.
  A foreign writer's garbage is suppressed; an authorised writer's is
  replaced by the hold / damping substitute if the slot can carry one, else
  suppressed. Strict decoding is what makes the bytes forwarded exactly the
  canonical encoding of the values decided on (no parser differential with
  the robot's CDR reader).
- **DATA_FRAG, key-only and non-standard samples** of an enforced channel
  are suppressed. The Unitree SDK does not fragment `LowCmd_` (≈ 1 KB) at
  Cyclone DDS's default 1344-octet fragment size; a fragmented one is a
  misconfiguration or an attack. Fragmented SEDP is reassembled (bounded).
- **The same samples from an unknown writer** (no SEDP seen, not in the
  state file) are suppressed too in enforce mode with `unknown_writers:
  probe` (review finding F2): the content probe needs a whole payload, so
  such a sample could be a motion command nobody checked (for instance one
  the robot matched to `rt/lowcmd` through an announcement the gateway did
  not see). Writers classified by SEDP on another topic are not affected;
  `unknown_writers: pass` opts out (unknown writers unchecked). The gateway
  does **not** reassemble user fragments to probe them: the fragments
  before the last one would already have been forwarded, a fragment can
  only be passed or suppressed (not rewritten), and a bounded reassembler
  that evicts a sample the robot's reassembler still holds would forward
  the completing fragment unchecked. No legitimate controller-side writer
  of this deployment sends the robot fragmented samples without an SEDP
  announcement.
- **IP fragments** never reach the decision: the ruleset enables IPv4
  defragmentation in front of the queue and drops any fragment that still
  arrives; the gateway also drops one.
- A datagram that is not decidable **as a whole** follows
  `rtps.malformed_datagram` (default `drop`): deciding on part of it could
  forward a sample the gateway never saw the way the receiver sees it.

## Channels

| `codec` | Wire | Firewall channel | Notes |
|---|---|---|---|
| `unitree_hg_lowcmd` | RTPS DATA `unitree_hg::msg::dds_::LowCmd_` on `rt/lowcmd` (G1, H1-2) | joint, 35 slots | `mode_pr` / `mode_machine` passed through (pinnable) |
| `unitree_go_lowcmd` | RTPS DATA `unitree_go::msg::dds_::LowCmd_` (Go2, B2, H1) | joint, 20 slots | |
| `unitree_sport_request` | RTPS DATA `unitree_api::msg::dds_::Request_` on `rt/api/sport/request` | twist | `Move` (1008) decided as `(vx, vy, 0)/(0, 0, vyaw)`; a malformed `Move` as non-finite; `StopMove` always allowed; other calls: `allowed_api_ids`, then a zero-velocity check (source, rate); an api id outside `i32` (aliasing) is suppressed |
| `go1_high_cmd` | UDP `HighCmd` (129 octets), default port 8082 | twist | mode 2 decided on `velocity` / `yawSpeed`; other modes: `allowed_high_modes`, then a zero-velocity check |
| `go1_low_cmd` | UDP uncompressed `LowCmd` (734 octets), default port 8007 | joint, 20 slots | the 614-octet compressed form of v3.8.6 is undecidable (dropped): do not configure this channel for compressed traffic |

Every representation the decoder reads is rewritten in kind (CDR / CDR2 /
D_CDR2, either endianness). Only the plain Unitree CRC is supported for Go1
(a fleet using the SDK's unpublished `encryptCRC` cannot be enforced).

## Non-motor `LowCmd_` fields

A `LowCmd_` carries fields besides the motor slots. Review finding F3: the
go `bms_cmd.off = 0xA5` turns the robot's battery off. Each field, what the
SDK says about it, and what the gateway does (SDK checkouts:
`unitree_legged_sdk` 4539a6c, `unitree_sdk2` d1abf00):

| Field (`unitree_go` unless noted) | SDK evidence | Gateway |
|---|---|---|
| `bms_cmd.off` | "set 0xA5 to turn off the battery" (`unitree_legged_sdk` `include/unitree_legged_sdk/comm.h:28`; `unitree_sdk2` `example/state_machine/comm.h:28`); no SDK example sets it (`LowCmd_.hpp` default 0) | **refused unless 0** (any non-zero value; the firmware's exact test is not published), unless the channel sets `allow_battery_off: true`. A refused frame is decided as an integrity failure: the platform's substitute (hold / damping) is written with the last accepted frame's non-motor fields (`off = 0`), or the SDK defaults when none was accepted yet |
| `bms_cmd.reserve[3]` | `reserve` (`comm.h:29`) | forwarded as sent |
| `head[2]`, `level_flag`, `frame_reserve`, `sn[2]`, `version[2]` | all marked `// reserve` in the legacy `LowCmd` (`comm.h:116-121`); SDK2 examples set `head = FE EF`, `level_flag = 0xFF` (`example/go2/go2_low_level.cpp:111-113`) | forwarded as sent (reserve; no effect documented) |
| `bandwidth` | no documented use; not set by any example | forwarded as sent |
| `wireless_remote[40]` | `// reserve` in `LowCmd` (`comm.h:125`; it is joystick data only in `LowState`) | forwarded as sent |
| `led[12]`, `fan[2]`, `gpio` | Go2 additions (`example/state_machine/comm.h:137-139`, copied through by `conversion.hpp:79-81`); examples set `gpio = 0` (`go2_low_level.cpp:114`); semantics not published | forwarded as sent — **residual risk**: not motion, but not shown inert either; verify on the robot in `mode: observe` and report |
| `reserve`, motor `reserve[3]` | reserve | forwarded as sent |
| hg `mode_pr`, `mode_machine` | parallel / serial ankle mode, machine type | firewall pins (`pinned_mode_pr` / `pinned_mode_machine`) |
| hg `reserve[4]` | reserve | forwarded as sent |

Whatever is forwarded as sent in an accepted frame is also what a later
substitute carries (copied from the last accepted frame, never from the
rejected one).

## Source identity

The firewall's `allowed_sources` are resolved per sample: exact writer GUID,
then participant prefix, then `identity:<name>` (participant identity from
the SPDP the participant sent itself: source IP, vendor, enclave; identities
that require ROS node evidence are refused at start). **The writer GUID is a
claim** (no DDS-Security): set `allowed_src_ips` on every channel so a
datagram from any other source IP is a foreign source whatever GUID it
claims. On a flat L2 segment IP and MAC can be spoofed too; the
`controller_port` side of the bridge should carry only the controller.

Writers are classified by the SEDP announcements that cross the bridge (any
reading of a duplicated topic parameter counts), persisted in
`rtps.state_file` so a restarted gateway, which will not see the robot's
earlier SEDP again, keeps classifying them. A writer with no announcement is
**probed** (`rtps.unknown_writers: probe`, default): a `LowCmd_` must decode
and carry a valid Unitree CRC (the motor board ignores an invalid one), a
request must be in the sport id range (1001..=1199) or alias it; a match is
decided as that channel (and is then a foreign source unless its GUID is
allowed).

## Clock

The firewall's clock is the packet's **arrival time** on the box: the
kernel receive timestamp (`NFQA_TIMESTAMP`, enabled by `SO_TIMESTAMP` on the
queue's netlink socket) mapped into `CLOCK_MONOTONIC`, never decreasing. A
backlog drained after a scheduling stall therefore keeps the sender's
spacing (otherwise its frames would be refused as "too early"). Without a
timestamp the processing time is used. A sender's own timestamps
(`INFO_TS`) are never used. A packet read more than `max_queue_delay_ns`
(default 5 ms) after its arrival gets the firewall's **fault verdict**
(`fault_policy`; a humanoid holds) instead of a check.

## Values: `f64` decisions on an `f32` wire

A clamped value is generally not an `f32`, and the nearest `f32` can lie
just outside the bound (`23.7_f32 = 23.700000763`). Limited fields are
rounded **away from the input** (a clamped magnitude rounds inward, a
stepped position toward the previous target); a held field is copied
bit-exact from the frame last forwarded; a value the firewall synthesised
(the damping `kd`) rounds toward zero. Every forwarded field is within one
`f32` ulp of the firewall's output and on the safe side of every static
bound.

## When the gateway itself fails

| Situation | Behaviour |
|---|---|
| Gateway process down (crash, restart, stopped) | the kernel applies the rule's flag: **`fail_closed` (default)** drops the queued datagrams (the robot's command timeout applies, as for a controller failure); `bypass` (`--queue-bypass`) forwards them **unchecked**. `bypass` is **refused for a humanoid with a low-level joint channel** (the firewall refuses `fail_open` there for the same reason). Per channel class: the flag is per queue rule, so per-channel policies need separate queues. |
| Kernel queue full (`queue.max_len`) | same choice (`NFQA_CFG_F_FAIL_OPEN` only with `bypass`) |
| Loop stalled | systemd `WatchdogSec=2s` (the loop pings every `housekeeping_ms`, also when idle); restart after 200 ms |
| Packet decided late (> `max_queue_delay_ns`) | firewall fault verdict (hold on a humanoid) |
| Profile fails its trust checks in enforce mode | the gateway does not start (exit 2); the queue's flag applies |
| A rewrite the firewall asked for fails verification | the sample is suppressed (counted `rewrite_failed`) |

The ruleset is **not** removed when the gateway stops (it lives in its own
oneshot unit), or `fail_closed` would mean nothing.

## Configuration

`robodr-firewall-gw.json` (unknown keys refused; examples
`config/firewall-gw.unitree-{g1,go2}.example.json`):

| Key | Default | Meaning |
|---|---|---|
| `mode` | — | `enforce` (requires a locked, trusted profile and an enforcing platform) or `observe` (decide, record would-haves, forward everything unchanged) |
| `profile`, `profile_trust` | — | as agentd's `sensor.profile_path` / `sensor.profile_trust`; the anti-rollback state is read, never written |
| `firewall` | — | `robodr_firewall::FirewallConfig` JSON (channels, joint channels, platform: morphology, `fail_behaviour`, `fault_policy`, `foreign_source_action`) |
| `queue.num`, `queue.max_len` | —, 1024 | NFQUEUE number and kernel queue length |
| `queue.on_gateway_down` | `fail_closed` | see above |
| `queue.controller_port`, `queue.robot_port` | — | bridge port names (ruleset) |
| `rtps.domain_ids` | `[0]` | queued DDS port ranges (7400 + 250·d .. +249) |
| `rtps.malformed_datagram` | `drop` | whole-datagram policy |
| `rtps.unknown_writers` | `probe` | `probe` or `pass` |
| `rtps.max_writers`, `rtps.max_writers_per_channel` | 4096, 16 | bounds (oldest / least recently used evicted) |
| `rtps.state_file` | none | persisted writer → channel map |
| `rtps.max_sn_jump` | 64 | largest sequence-number step decided at once (larger: held until confirmed) |
| `rtps.binding_takeover_ns` | 1 s | silence after which another (IP, MAC) may continue an authorised GUID's stream |
| `channels[]` | — | `firewall_channel`, `codec`, `topic`, `udp_ports`, `allowed_src_ips`, `allowed_src_macs` (RTPS), `legacy_sources` (IP → firewall source), `allowed_api_ids`, `allowed_high_modes`, `allow_battery_off` (go `LowCmd_`, default `false`) |
| `max_queue_delay_ns` | 5 ms | late packets get the fault verdict |
| `events_path`, `events_max_bytes` | none, 64 MiB | firewall deviations as JSON lines |
| `status_path` | none | counters, firewall stats, recv→verdict latency |
| `housekeeping_ms` | 100 | events, status, state file, watchdog |

The Go2 example's `allowed_api_ids` (and the test fixture's) include
`Damp` (1001, `ROBOT_SPORT_API_ID_DAMP`, `unitree_sdk2`
`include/unitree/robot/go2/sport/sport_api.hpp:19`), which makes the robot
go limp and settle to the ground: it is kept as the operator's soft stop,
but anyone who can present an allowed source can send it. List only the
calls the site's controller uses.

The Go2 example's sport channel needs a twist channel
`/api/sport/request` (with `max_angular_speed`) in the firewall
configuration; `config/firewall.unitree-go2.example.json` has only
`/lowcmd`.

`robodr-firewall-gw check-config --config <json>` validates everything
(configuration, profile with its trust checks, firewall compile, channel ↔
codec ↔ slot count ↔ profile `motion_types`, the humanoid / bypass rule)
without touching the network.

## Deployment

1. Bridge the two NICs (systemd-networkd or netplan), no IP needed on the
   bridge.
2. `robodr-firewall-gw ruleset --config /etc/robodr/firewall-gw.json`
   renders the idempotent setup script (`br_netfilter` sysctls; an nft
   `bridge` table that bridges only IPv4 and ARP from the controller port;
   untracked traffic plus a no-op conntrack match so IPv4 defragmentation
   runs before the queue; the `ROBODR_GW` chain that drops fragments and
   queues the DDS / legacy ports). `robodr-firewall-gw-rules.service`
   (oneshot, before `network-pre.target`) applies it at boot.
3. `robodr-firewall-gw.service` (`Type=notify`, `CAP_NET_ADMIN` only, no
   IP sockets, FIFO priority 40, watchdog 2 s). Focal (systemd 245)
   variants in `packaging/systemd/focal/`.

Kernel requirements: `nfnetlink_queue`, the xtables `NFQUEUE`, `physdev`,
`CT` and `conntrack` modules (or their `nf_tables` compat), `br_netfilter`,
`nf_tables` with the `bridge` family. The rendered ruleset uses iptables
(nf_tables backend by default): **`nft`'s own `queue` statement is not
used** — the `ip` family cannot match the bridge port natively and the
development kernel here has no `CONFIG_NFT_QUEUE`. A native `bridge`-family
`queue` ruleset is possible on kernels that support it but was not tested.

Operations (status, maintenance bypass, troubleshooting):
[`docs/OPERATIONS.md`](../../docs/OPERATIONS.md), section 6.6.

## Tests

| What | Where |
|---|---|
| IPv4 / UDP framing, checksums, fragments | `src/ip.rs` |
| Strict RTPS walker, PAD suppression (cross-checked with `robodr-rtps`'s passive walker) | `src/rtps.rs` |
| `LowCmd_` encoder agrees with the independent decoder in all 6 representations; non-canonical / trailing refused; rewrite length / verification | `src/lowcmd.rs` |
| `f32` rounding never crosses a bound | `src/round.rs` |
| Sport parameter rewrite never rounds up; length fit; refusals | `src/sport.rs` |
| Go1 offsets agree with `robodr-cdr`'s decoder | `src/legacy.rs` |
| NFQUEUE message codec, malformed input | `src/nfq.rs` |
| Review findings F1–F3 (each test written first and seen failing): far-future sequence number with the writer's GUID from another IP / the controller IP with another MAC / a pinned MAC, jump held until confirmed, binding takeover only after silence, no foreign substitute under an authorised GUID, writer restart after SEDP without a replay hole; unknown-writer DATA_FRAG (single, several, out of order, oversized, foreign), key-only, non-standard suppressed, SEDP-classified / `pass` / observe unaffected; `bms_cmd.off` refused, substitute carries the last accepted non-motor fields, `allow_battery_off` | `tests/hardening.rs` |
| Every verdict path on synthetic packets: byte-identical pass; limited rewrite equals a reference firewall's output (≤ 1 ulp, bound kept), CRC valid, length unchanged, other submessages untouched; humanoid hold for six kinds of violation and never damping / limp, suppression when nothing was accepted, hold past `max_hold_ns`; quadruped damping after the hold; foreign writer; source-IP binding; too-early; two samples in one datagram; retransmission / replay; undecidable payloads; DATA_FRAG; malformed / bad checksum / IP fragment; SEDP classification; late packet → fault verdict; sport limit / substitute / allowlist / alias; Go1 high and low; observe mode; configuration refusals; 3000-frame random stream against a reference firewall; shipped examples | `tests/gateway.rs` (21 tests) |
| Real kernel: 3 network namespaces, bridge, rendered ruleset, NFQUEUE, the binary's run loop; pass byte-identical, hold on violation, foreign suppressed, `fail_closed` while down; latency. F1: an attacker namespace on the controller segment (macvlan, own MAC) injects the writer's GUID with SN 2^40 from its IP and then from the controller's IP; every genuine frame before and after arrives byte-identical, the kernel's `NFQA_HWADDR` tells the spoofed-IP frame apart; SEDP is queued, learned and forwarded unchanged | `tests/netns_e2e.rs` (`#[ignore]`: root; `cargo test -p robodr-firewall-gw --release --test netns_e2e -- --ignored --nocapture --test-threads 1`) |
| Fuzz: packet path + NFQUEUE parser, invariants (no panic; accept = unchanged; rewrite = same length, valid checksums; no forwarded enforced sample that does not decode strictly / with a valid CRC; no forwarded unprobeable sample of an unknown writer; no forwarded go `LowCmd_` with `bms_cmd.off != 0`) | `fuzz/fuzz_targets/firewall_gw_packet.rs`, smoke run `tests/fuzz_smoke.rs` |

## Latency

Measured 2026-10-26 in the development sandbox: 4-vCPU VM (Intel Xeon),
release build, no RT kernel, no CPU pinning, **shared with other work
(load average 5–20 during the runs)**: the tails are the environment's,
not the algorithm's. Ranges are over two runs each.

**Decision path** (`examples/gw_latency.rs`: packet bytes in → verdict,
pre-built packets, ~3 % limited, ~1 % rejected (hold), ~1 % foreign; heap
allocations inside the timed calls: 52 per scenario, all at stream start
(writer state, caches), none per frame):

| Scenario | Mode | p50 | p99 | p99.9 |
|---|---|---|---|---|
| G1, 35 slots @ 1 kHz | paced | 10.2–13.8 µs | 35–36 µs | 57 µs–0.36 ms |
| G1, 35 slots @ 500 Hz | paced | 13.3–15.7 µs | 38 µs | 40–62 µs |
| Go2, 20 slots @ 1 kHz | paced | 9.3–11.4 µs | 30–35 µs | 37 µs–0.97 ms |
| Go2, 20 slots @ 500 Hz | paced | 12.1–14.7 µs | 37–42 µs | 0.13–0.14 ms |
| G1, 35 slots | back to back | 7.9–10.9 µs | 25–37 µs | 54–74 µs |
| Go2, 20 slots | back to back | 6.4–8.3 µs | 23–33 µs | 39 µs–0.31 ms |

(Before the Unitree CRC in `robodr-cdr` became table-driven in this change,
the G1 paced p50 was 28 µs: the bitwise CRC ran ~8 000 branches per frame,
once per decode and twice more per rewrite.)

**End to end through the kernel** (`tests/netns_e2e.rs`: controller
namespace → veth → bridge with br_netfilter + NFQUEUE + gateway → veth →
robot namespace; send-to-receive time on `CLOCK_MONOTONIC`; G1 35-slot
frames, every 33rd limited; baseline = the same stream with the queue rule
removed, measured right after):

| Stream | Frames delivered | p50 | p99 | max | baseline p50 / p99 |
|---|---|---|---|---|---|
| 1 kHz | 3000 / 3000 | 79–98 µs | 1.0–2.0 ms | 5.6–6.6 ms | 35–57 µs / 0.14–0.98 ms |
| 500 Hz | 1500 / 1500 | 89–109 µs | 0.31–15.7 ms | 5.6–30 ms | 39–40 µs / 0.32–1.6 ms |

Added median latency ≈ 20–70 µs (queue round trip + decision + verdict
send) against a 1 000 µs (1 kHz) / 2 000 µs (500 Hz) control period; in the
quieter run the added p99 was ≈ 60 µs at 1 kHz and within the noise at
500 Hz. The loop's own recv → verdict time was p50 35–53 µs, p99
108–171 µs. **The p99 / max figures are not a budget**: on this
oversubscribed VM the baseline itself reaches ms-scale tails. The S8
acceptance criterion (p99 added latency < 1 ms) must be measured on the
target sensor box (RT kernel, pinned core, the unit's FIFO priority) with
these two harnesses; `gw_latency` takes `--budget-p99-ns` /
`--budget-max-ns` (exit 1 when exceeded) for that gate.

## Known limits

- **Not run against a real robot, a real Cyclone DDS stack or a real
  sensor box.** The RTPS / CDR layouts follow the published IDL and the
  repository's decoders; the e2e test uses synthetic datagrams.
- **QoS not known**: whether Unitree's `rt/lowcmd` writer is best-effort or
  reliable is not confirmed; both are handled (PAD suppression, cached
  retransmissions), the reliable NACK path only by analysis.
- **Unauthenticated identity**: writer GUIDs, INFO_SRC and (on one L2
  segment) source IPs can be spoofed; the gateway's position on the
  controller-side port is what keeps robot-side traffic out of its scope.
- **Discovery differential: classification needs every SEDP the robot
  sees.** A writer the gateway learned (from SEDP) as writing another
  topic is not decided on, which is what lets same-type channels such as
  G1's `rt/arm_sdk` pass. If the robot ever matched that writer on
  `rt/lowcmd` through an announcement the gateway did not see (a discovery
  path around the bridge, a fragmented SEDP the gateway's bounded
  reassembler dropped), its DATA would pass unchecked. Unknown writers are
  probed (and their unprobeable samples suppressed); set
  `rtps.state_file` so a restart does not forget the robot's writers.
  Deployment rule: **all SEDP / SPDP between controller-side participants
  and the robot must cross the bridge** — the robot must have no other
  link (Wi-Fi, a second NIC, a cellular modem) that reaches controller-side
  participants. Unicast SEDP from the controller side to the robot is
  covered: it enters on the controller port and lies in the queued DDS
  port range, as does SPDP multicast (`ruleset` unit test; the F1 netns
  e2e sends SEDP through the bridge and checks it was learned and
  forwarded unchanged). Test harness note: an e2e for a real differential
  needs a second path into the robot namespace that bypasses the bridge;
  the gateway cannot see it by construction, so the check belongs to the
  site's network review, not to the gateway's tests.
- **DDS ports outside the queued range are not inspected.** The ruleset
  queues the RTPS well-known port range of each `rtps.domain_ids` entry
  (7400 + 250·d .. +249: participant indexes 0..119). A DDS stack
  configured for other ports (Cyclone DDS `Discovery/Ports`, or a
  `ParticipantIndex` setting that makes it use kernel-chosen unicast
  ports) would send its unicast SEDP and `rt/lowcmd` around the queue.
  Verify the robot's and the controller's Cyclone DDS configuration (and
  capture the ports in use) before relying on the gateway.
- **No new finding types**: gateway-only conditions (malformed datagrams,
  replays, fragmented motion samples, rewrite failures) are counters in the
  status file, not findings; the firewall's own rules (`crc_invalid`,
  `rejected_*`, `joint_*`, `internal_fault`, ...) are written to
  `events_path`. Feeding that file into agentd and dedicated rule ids
  (contract 2.2) are follow-ups.
- **Non-motor fields**: only `bms_cmd.off` is refused (see "Non-motor
  `LowCmd_` fields"); `led` / `fan` / `gpio` are forwarded as sent, and so
  are the sport API's non-velocity calls in `allowed_api_ids` (`Damp`
  included when listed).
- **Spoofed IP and MAC**: see "Sequence numbers and writer binding" — the
  gateway bounds, but cannot prevent, the effect of an attacker that sends
  with the controller's own IP and MAC on the controller-side segment.
- **Loco `SetVelocity` (humanoid high-level), arm SDK, hand SDK channels**
  are not decided yet.
- **Go1 compressed low-level frames** cannot be decided (dropped if the
  channel is configured).
- **IPv4 only**: the ruleset drops IPv6 (and VLAN-tagged, PPPoE, other
  ethertypes) from the controller port; a site that needs them through the
  bridge must route them around the gateway explicitly.
