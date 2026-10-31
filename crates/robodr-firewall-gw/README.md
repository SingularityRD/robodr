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
the gateway learns which writer writes which topic. A **copy** of the
robot's UDP traffic goes to the gateway through NFLOG (never queued, never
dropped; "Robot-side observation" below): the robot's `rt/lowstate` and its
own discovery.

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
| `unitree_sport_request` | RTPS DATA `unitree_api::msg::dds_::Request_` on `rt/api/sport/request` | twist | `Move` (1008) decided as `(vx, vy, 0)/(0, 0, vyaw)`; a malformed `Move` as non-finite; `StopMove` always allowed, queries pass; other calls only if listed in `allowed_api_ids` (**required**; `[]` = velocity, stop and queries only), then a zero-velocity check (source, rate); an api id outside `i32` (aliasing) is suppressed |
| `go1_high_cmd` | UDP `HighCmd` (129 octets), default port 8082 | twist | mode 2 decided on `velocity` / `yawSpeed`; other modes only if listed in `allowed_high_modes` (**required**; `[0]` = idle only), then a zero-velocity check; under a `restrict_motion` restriction only mode 2 (velocity capped) and mode 0 (if listed) pass, every other listed mode is refused; `bms.off` non-zero refused |
| `go1_low_cmd` | UDP uncompressed `LowCmd` (734 octets), default port 8007 | joint, 20 slots | `bms.off` non-zero refused (integrity failure); any other length is undecidable (dropped) |
| `go1_low_cmd_compressed` | UDP compressed `LowCmd` (614 octets, `LOW_CMD_LENGTH` of `unitree_legged_sdk` v3.8.6: what a real Go1 client sends), default port 8007 | joint, 20 slots | layout from the library's `refineCmd` (below, "Go1 compressed `LowCmd`"); `tau` / `Kp` / `Kd` are `i16` fixed point (÷256 / ÷32 / ÷16), a limited value is written as the step on the safe side of the bound and one beyond `i16` is refused (suppressed); holds ride on the last accepted 614-octet frame; any other length is dropped. Cannot share its port with `go1_low_cmd` |
| `unitree_a2_lowcmd` | RTPS DATA on an A2 / AS2 `rt/lowcmd`, **inferred** `unitree_go::msg::dds_::LowCmd_` | joint, 20 slots | decided exactly as `unitree_go_lowcmd`; refused at start unless the firewall channel has `require_crc`, the profile records the channel's type (learned from the robot's SEDP; any other type than the go `LowCmd_` is refused), and `on_gateway_down` is not `bypass`; `allow_battery_off` refused (below, "A2 / AS2") |
| `unitree_loco_request` | RTPS DATA `Request_` of a humanoid's locomotion client: `robot_model` `g1` / `h2` / `r1` on `rt/api/sport/request` (ids 7xxx), `h1` on `rt/api/loco/request` (ids 8xxx) | twist | `SetVelocity` limited, duration capped; `SetFsmId` other than `Start` refused unless allowlisted (below, "Loco requests") |
| `unitree_hg_arm_sdk`, `unitree_go_arm_sdk` | RTPS DATA `LowCmd_` on `rt/arm_sdk` (G1 / H1-2 / H2 / R1 `hg`, H1 `go`) | joint, 35 / 20 slots | every slot with gains or torque decided whatever its mode octet; `weight_slot` bounded, its step and rate limited, its rise from 0 checked against `rt/lowstate` (below, "Arm SDK") |
| `unitree_dex3_hand_cmd` | RTPS DATA `unitree_hg::msg::dds_::HandCmd_` on `rt/dex3/{left,right}/cmd` (topic required) | joint, one slot per finger motor (`balance_critical: false`) | mode octets checked; decided; passed byte-identical or suppressed (below, "Hands") |
| `unitree_hand_sdk` | RTPS DATA `unitree_go::msg::dds_::MotorCmds_` on `rt/hand_sdk` | joint, one slot per element (`balance_critical: false`) | as Dex3; the blend weight (`cmds[0].mode`) bounded and step / rate limited |
| `unitree_arm_request` | RTPS DATA `Request_` of the G1 / H2 arm action service on `rt/api/arm/request` (`robot_model` `g1` / `h2`) | twist (source / rate only) | `ExecuteAction` 7106, `ExecuteCustomAction` 7108, `StopCustomAction` 7113 refused unless in `allowed_api_ids`; `GetActionList` passes |
| `ros2_twist`, `ros2_twist_stamped` | RTPS DATA ROS 2 `geometry_msgs/msg/Twist` / `TwistStamped` on `rt/cmd_vel` (XCDR1) | twist (6 DoF) | limited / substitute values written in place (`float64`, no rounding); a `TwistStamped`'s non-zero `header.stamp` is zeroed in every forwarded command (`twist_stamp_zeroed`: `diff_drive_controller` ages a command by its stamp, so a far-future one outlived `cmd_vel_timeout`; zero means "now") |
| `unitree_obstacles_avoid_request` | RTPS DATA `Request_` on Go2 `rt/api/obstacles_avoid/request` | twist | decoded for the `obstacles_avoid` service (never as sport: its 1003 is `Move`, sport's `StopMove`): `Move` with `mode` 0 limited and rewritten as `{"x","y","yaw","mode":0}`; `mode` 1 / 2 (position targets), `SwitchSet`, `UseRemoteCommandFromApi` refused unless in `allowed_api_ids`; `SwitchGet` passes |
| `unitree_uwbswitch_request` | RTPS DATA `Request_` on Go2 `rt/api/uwbswitch/request` | twist (source / rate only) | `SwitchSet` (the robot follows the UWB remote) refused unless in `allowed_api_ids`; the queries pass |

In enforce mode a Go2 (`robot_model` `go2` / `go2w`, or no `robot_model`
and a `unitree_sport_request` channel) must have channels for all three of
its motion services (`sport`, `obstacles_avoid`, `uwbswitch`), a B2
(`b2` / `b2w`) one for `sport`; otherwise the gateway refuses to start (a
service without a channel is a motion path nobody decides).

Every representation the decoder reads is rewritten in kind (CDR / CDR2 /
D_CDR2, either endianness). Only the plain Unitree CRC is supported for Go1
(a fleet using the SDK's unpublished `encryptCRC` cannot be enforced).

## Go1 compressed `LowCmd` (`go1_low_cmd_compressed`)

`unitree_legged_sdk` v3.8.6 never sends the `comm.h` `LowCmd`:
`UDP::SetSend(LowCmd&)` runs `refineCmd(LowCmd_refine&, LowCmd&)` and
sends `LOW_CMD_LENGTH` = 614 octets. No header declares that struct; its
layout is read from the machine code of the shipped static library
(`lib/cpp/amd64/libunitree_legged_sdk.a`, `udp.cpp.o`) and pinned in
`robodr_cdr::unitree_legacy::compressed_layout`: the `comm.h` 22-octet
header, 20 motors of 27 octets (`mode` u8 at +0, `q` f32 +1, `dq` f32 +5,
`tau` i16 +9 = `(int)(tau * 256)`, `Kp` i16 +11 = `(int)(Kp * 32)`, `Kd`
i16 +13 = `(int)(Kd * 16)`, `reserve[3]` +15), `bms` 562, `wirelessRemote`
566, `reserve` 606, CRC 610 over the first 152 words. The tests compare the
decoder with a transcription of `refineCmd` and check every offset; the
gateway's writer is cross-checked against `robodr-cdr`'s decoder.

Fixed point changes two things against the declared form: a limited
`tau` / `Kp` / `Kd` is written as the 1/256, 1/32 or 1/16 step on the safe
side of the firewall's value (`round::fixed_away_from`; a substitute
truncates toward zero), and a value outside `i16` (|tau| ≥ 128 N·m,
|Kp| ≥ 1024, |Kd| ≥ 2048) cannot be written, so such a frame is
suppressed rather than wrapped. The SDK wraps such values on the sender:
an operator's `Kp = 1100` arrives as a negative gain and is refused by the
envelope. NaN cannot reach the fixed-point fields (`cvttss2si` makes it 0
on the sender); `q` / `dq` stay `f32` and a NaN there is refused.

## A2 / AS2 (`unitree_a2_lowcmd`)

`unitree_sdk2`, `unitree_sdk2_python` and `unitree_ros2` ship **no** A2 /
AS2 low-level type, example or topic: only their sport client and sport
state (`rt/lf/sportmodestate`, `unitree_go::msg::dds_::SportModeState_`).
The low-level command is therefore **inferred** to be the `unitree_go`
`LowCmd_` on `rt/lowcmd` (`robodr_cdr::unitree::ModelInfo::inferred_idl`),
never assumed silently: the codec starts only when the locked profile
records the channel's type as learned from the robot's own SEDP and that
type is the go `LowCmd_`. A 35-slot `hg` frame (another model's layout)
or anything else on the writer does not decode and is decided as an
integrity failure. Its motor count is unknown: list the actuated slots
as enabled in the firewall channel; an energised disabled slot is
refused (`disabled_motor_energised`).

## Go2 WebRTC sessions (`webrtc`)

The Go2 app and community clients control the robot over WebRTC
(DTLS-SRTP): the gateway cannot read or limit a command inside a session
and does not try. With a `webrtc` section it:

- copies controller-side signalling (TCP to `signalling_ports`, default
  8081 / 9991) and unqueued controller-side UDP to the robot to NFLOG group
  `webrtc.nflog_group` (default 4175), adds the robot's signalling answers
  to the observe group, and feeds both sides to
  `robodr_ros2_pipeline::webrtc::WebRtcMonitor` (STUN / TURN, DTLS record
  headers, SRTP demultiplexing, the legacy `/offer` plaintext SDP metadata,
  the `con_notify` / `con_ing_*` steps). Its `robot.unitree.webrtc_*`
  findings (contract 2.3, §3d) go to the events file and agentd's feed
  (channel `webrtc`). The copies are never queued or dropped;
- with `action: block_unlisted`, drops TCP to the signalling ports from
  any source that is not in `controllers`, and from a MAC-bound
  controller's IP with another source MAC (nft table `bridge
  robodr_gw_rtc`, `ip saddr` and `ether saddr . ip saddr` sets). Each drop
  is first logged to the WebRTC NFLOG group (`log group`), so the refused
  host is still reported: its SYN is a `TcpConnect` attempt;
- checks a controller's MAC binding on every copied packet: the NFLOG
  copy's `NFULA_HWADDR` is the source MAC the monitor compares;
- always creates the quarantine sets `blocked_peers` (an address; both
  directions) and `blocked_flows` (`peer . peer port . robot . robot
  port`, UDP, both directions), with timeouts.
  `robodr-firewall-gw webrtc-block --peer <ip> [--flow
  <peer_port>,<robot_ip>,<robot_port>] [--timeout-s N]` prints the `nft add
  element` command for the flows a finding names (run it as root, or let
  the executor run it). Re-applying the ruleset forgets the elements.

```json
"webrtc": {
  "action": "block_unlisted",
  "robot_addresses": ["192.168.123.161"],
  "controllers": [{ "ip": "192.168.123.20", "mac": "02:00:00:00:00:20", "label": "operator tablet" }],
  "deny_windows": ["mon-fri 19:00-07:00", "sat,sun 00:00-23:59"],
  "max_sessions": 1
}
```

Findings are reported once per peer session (forgotten when it ends or is
evicted, so a returning peer is reported again), at most 32 non-Critical
findings per minute with the rest aggregated per rule (reported by the
gateway's housekeeping as soon as the minute is over, also when no further
packet arrives); an unlisted controller's established session (Critical)
is never rate limited.

A top-level `robot_model` (optional) cross-checks the channels: an A2 /
AS2 `rt/lowcmd` must use `unitree_a2_lowcmd`, `allow_battery_off` is
refused on it, and `unitree_a2_lowcmd` is refused for any other model.

`observe.enabled` is required. The nft table (with the MAC and `log
group` rules) was loaded and its set elements added in a network
namespace; whether the kernel fills `NFULA_HWADDR` for every bridged copy
and delivers bridge-family `log group` packets to the gateway was not
exercised on a real bridge; the full session path is tested on
synthetic frames only. What a quarantine does to a robot mid-motion (its
reaction to a lost controller) is not published by Unitree.

## Loco requests (`unitree_loco_request`)

A humanoid's high-level locomotion client sends `unitree_api` requests to
its service: **`sport`** on G1, H2 and R1 (`LOCO_SERVICE_NAME = "sport"`,
`unitree_sdk2` `include/unitree/robot/g1/loco/g1_loco_api.hpp:11`,
`h2/loco/h2_loco_api.hpp:11`, `r1/loco/r1_loco_api.hpp:10`), so the DDS
topic is `rt/api/sport/request` with ids 7xxx, and **`loco`** on H1
(`h1/loco/h1_loco_api.hpp:11`, topic `rt/api/loco/request`, ids 8xxx).
H1-2 has no locomotion client in the SDK (its examples are low-level and
arm SDK only). A humanoid configured with `unitree_sport_request` is
refused at start: that codec would pass a `SetVelocity` or a `Damp` it
does not interpret. Requests are decoded strictly (as sport requests) and
interpreted with `robodr-cdr`'s api tables for the configured model.

| SDK call (G1 file:line; H1 / H2 / R1 equivalents) | Request | Gateway |
|---|---|---|
| `SetVelocity(vx, vy, omega, duration = 1.f)` (`g1/loco/g1_loco_client.hpp:164`; H1 `h1_loco_client.hpp:178`, H2 `h2_loco_client.hpp:209`, R1 `r1_loco_client.hpp:69`) | 7105 / 8105 `{"velocity":[vx,vy,ω],"duration":d}` | firewall twist check `(vx, vy, 0) / (0, 0, ω)`; limited or substitute velocity written in place (numbers truncated toward zero, read back); **duration capped** at `max_velocity_duration_s` (default 1 s) |
| `Move(vx, vy, vyaw, continous_move)` (`g1_loco_client.hpp:232-233`; H1 `:239`, H2 `:261`, R1 `:97`) | `SetVelocity` with duration **864000 s** when continuous | as `SetVelocity`: the duration is rewritten to the cap, so a controller that stops sending stops the robot within it |
| `StopMove()` (`g1_loco_client.hpp:226`; H1 `:232`, H2 `:254`, R1 `:94`) | `SetVelocity(0, 0, 0)` | passes (zero velocity) |
| `Start()` = `SetFsmId(500)` (`g1_loco_client.hpp:216`; H1 204 `:226`, H2 601 `:244`, R1 811 `:84`) | 7101 / 8101 `{"data":id}` | **refused** unless `allowed_fsm_ids` lists it (review finding F10 e): it hands the robot to the walking controller from **any** state, also a damped or lying one, which makes the whole body move; a site whose controller starts the walking controller lists the model's id |
| `ZeroTorque()` = `SetFsmId(0)` (`g1_loco_client.hpp:224`; H1 `:230`, H2 `:252`, R1 `:92`) | 7101 / 8101 `{"data":0}` | **refused** unless `allowed_fsm_ids` lists 0: motors limp, the humanoid falls |
| `Damp()` = `SetFsmId(1)` (`g1_loco_client.hpp:214`; H1 `:224`, H2 `:242`, R1 `:82`) | `{"data":1}` | **refused** unless allowlisted: damping only, the humanoid collapses |
| `Squat()` = 2, `Sit()` = 3 (`g1_loco_client.hpp:218,220`; H2 `:246,248`; R1 commented out `:86,88`), `StandUp()` = 4 (`g1_loco_client.hpp:222`; H1 2 `:228`, H2 `:250`, R1 `:90`); Python-only 702 / 706 | `{"data":id}` | **refused** unless allowlisted: whole-body posture transitions |
| any other `SetFsmId` value | | refused unless allowlisted |
| `SwitchToUserCtrl` 7110 / `SwitchToInternalCtrl` 7111 (`g1_loco_api.hpp:32-33`), `SetArmSdkStatus` 7109 (`h2_loco_api.hpp:34`) | | refused unless `allowed_api_ids` lists them: they hand the motors to another channel |
| `SetArmTask` 7106 / 8107, `FsmApi` 7100, `SetPunchApi` 7108, `SetStandHeight` 7104 / 8104, `SetBalanceMode`, `SetSwingHeight`, `SetSpeedMode`, `SetTargetPosition` 8204, ... | | refused unless in `allowed_api_ids` |
| `Get*` queries (7001..7008, 8001..8006, `GetOdom`) | | pass (source / rate check only: a query never changes the twist state the next velocity is ramped from, F10 b) |
| unknown id for the model, a malformed parameter, an id outside `i32` | | refused (suppressed) |

Refusals are suppressions (PAD) and counted (`loco_refused`); a capped
duration counts `duration_capped`. The content probe classifies an
unknown writer's request with a loco id (7001..7199, 8001..8299) as the
loco channel.

- **A `SetVelocity` lasts its duration** (F10 a): the robot stops on its
  own when it ends. The gateway remembers when the last forwarded one ends
  (`now + duration`, the capped duration) and, once that time has passed,
  tells the firewall the platform is at rest (`Firewall::twist_at_rest`):
  the next velocity is acceleration limited from zero, and a hold can no
  longer hold the old velocity (`velocity_expired`).
- **Non-velocity calls feed no twist** (F10 b): an allowlisted call or a
  query is checked for its source, rate and timestamp only
  (`Firewall::check_access`); before, it was checked as a zero twist, which
  reset the reference of the next velocity command. `StopMove` on the sport
  channel is still decided as the zero velocity it commands.
- **A malformed `SetVelocity`** (unreadable velocity, negative / non-finite
  duration) **or `Move`** is recorded as a non-finite command and
  **suppressed** (F10 c); it is never turned into a substitute, which would
  have forwarded a well-formed velocity the controller never sent.
- **Numbers are written for `float`** (F10 d): the SDK clients parse the
  JSON number as a `double` and keep a `float`. A rewritten number is
  truncated toward zero and moved one digit further toward zero until
  neither its `double` nor its nearest `float` is larger in magnitude than
  the firewall's value. A `SetVelocity` the firewall **passes** is forwarded
  byte-identical: the controller's own text, read as `float`, can exceed a
  limit it equals by at most half a `float` ulp (about 3·10⁻⁸ at 0.8 m/s).

## Arm actions (`unitree_arm_request`)

The G1 / H2 arm action client (`unitree_sdk2`
`include/unitree/robot/g1/arm/g1_arm_action_api.hpp`; ROS 2
`g1_arm_action_client.hpp:57`, service `arm`, topic `rt/api/arm/request`)
plays pre-programmed arm gestures whose motion nothing in the request
bounds. Before review finding F10 (f) it had no codec (a deployment could
neither enforce nor list it). Now: `GetActionList` (7107) passes the source
/ rate check; `ExecuteAction` (7106, `{"action_id": n}`),
`ExecuteCustomAction` (7108) and `StopCustomAction` (7113), unknown ids and
malformed parameters are refused unless `allowed_api_ids` lists them
(`arm_request_refused`). The firewall channel is a twist channel used for
source / rate only. The probe classifies an unknown writer's request with
an id in 7106..=7113 as this channel (after the loco channel, which shares
the ids on another service).

## Arm SDK (`unitree_hg_arm_sdk`, `unitree_go_arm_sdk`)

`rt/arm_sdk` carries a `LowCmd_` the robot's locomotion service blends into
its own arm (and waist) commands. The SDK examples set `q`, `dq`, `kp`,
`kd`, `tau` of the arm joints and **never their mode**
(`example/g1/high_level/g1_arm7_sdk_dds_example.cpp:156-160`), so those
slots arrive with mode 0, and they put the blend weight in one slot's `q`:
`msg.motor_cmd().at(JointIndex::kNotUsedJoint).q(weight)`
(`g1_arm7_sdk_dds_example.cpp:150`, `kNotUsedJoint = 29` on G1
`g1_arm5_sdk_dds_example.cpp:51`; 27 on H1-2
`h1/high_level/h1_2_arm_sdk_dds_example.cpp:51`; 9 on H1
`h1_arm_sdk_dds_example.cpp:32`; `kArmSdkWeightJoint = 31` on H2
`h2/high_level/h2_arm_sdk_dds_example.cpp:32`). Hence:

- **Every slot that carries gains or torque (or a non-finite value) is
  decided as enabled**, whatever its mode octet: the channel's joint
  envelope (position, speed, gains, torque, step) applies to it. A slot
  the firewall channel has disabled (legs on the G1 fixture) must stay
  inert. The mode octets are forwarded as sent.
- **`weight_slot` (required) is not a motor**: it must be a disabled motor
  of the firewall channel, is left out of the joint check, and must be
  finite in `[0, max_weight]` (default 1) with every other field zero and
  mode 0. Anything else is an integrity failure (`arm_weight_rejected`):
  the firewall's substitute applies, which on a humanoid is a hold.
- **The weight's dynamics** (review finding F1): a bounded weight still let
  `0 → 1 → 0 → 1` on consecutive frames snap the arms between the
  locomotion pose and the SDK's targets at full gains. Relative to the last
  **accepted** frame's weight (0 when none):
  - `|Δw| <= max_weight_step` (default 0.02 per frame) and
    `|Δw| <= max_weight_rate_per_s · Δt` (default 0.5 /s; the SDK
    examples ramp at 0.2 /s, `g1_arm7_sdk_dds_example.cpp:106`), in both
    directions (`arm_weight_step_rejected`, `arm_weight_rate_rejected`);
  - **engagement** (the weight rising from 0): when the robot's measured
    joint positions are known (`rt/lowstate`, observed on the robot side
    within `lowstate_max_age_ms`, default 50 ms; "Robot-side observation"),
    every weighted slot (`kp > 0`) must target a `q` within
    `engage_max_q_error` (default 0.1 rad) of the measured one: the
    hand-over starts where the arm is, which is how the SDK example
    engages (`g1_arm7_sdk_dds_example.cpp:132-160`: it reads `rt/lowstate`
    and sets the weight to 1 at once). Without a fresh `rt/lowstate`, the
    weight may leave 0 only up to `engage_first_step` (default 0.02) and
    rise beyond it only after `engage_stable_frames` (default 50) accepted
    frames whose weighted targets moved by at most `engage_stable_q`
    (default 0.01 rad), i.e. once the arms settled at the small blend
    (`arm_engage_rejected`);
  - after a **gateway start**, the first frame with a weight above 0 is
    accepted only if `rt/lowstate` confirms its targets (any weight up to
    `max_weight`: the stream was engaged before the restart) or it stays
    within the first step; otherwise the channel stays suppressed until the
    controller re-engages from 0.

  Beyond these rules the frame is an integrity failure: the humanoid holds
  the last accepted frame (its weight included). The defaults refuse the
  SDK example's one-frame engagement **unless** `rt/lowstate` confirms it
  and `max_weight_step` / `max_weight_rate_per_s` are opened up for it
  (`config/firewall-gw.unitree-g1.channels.example.json` explains the
  choice). The weight dynamics apply in `observe` mode too (would-haves).
- **Rewrites**: a limited frame keeps the input's weight slot bit-exact; a
  hold copies the last accepted frame (motors, mode octets and weight); with
  no accepted frame yet a humanoid emits nothing (suppressed). A hold never
  damps.
- The content probe prefers `rt/lowcmd` for an unknown writer's valid
  `LowCmd_` (the stricter channel: an arm-SDK frame decided there is
  refused, since a mode-0 slot with gains is not inert).

## Hands (`unitree_dex3_hand_cmd`, `unitree_hand_sdk`)

**Mode octets and the hand-SDK weight** (review finding F5). Dex3: each
element's mode is `id | status << 4 | timeout << 7`
(`g1_dex3_example.cpp:112-121`) with `id` the element's index and status 1
in every SDK helper; an element addressing another motor or with another
status is refused (`hand_mode_rejected`). Hand SDK: `cmds[0].mode` is the
weight × 100 (at most 100), every other mode octet 0, and the weight moves
at most `max_weight_step` (default 0.02, i.e. 2 units) per forwarded frame
and `max_weight_rate_per_s` (default 0.5 /s) from the last forwarded frame
(from 0 when none: the SDK example's `set_weight(1.0)` on the first frame
needs `max_weight_step: 1.0`).

**Hands may be released** (review finding F6): the SDK's `stopMotors`
sends `kp = kd = 0` on every finger, which the humanoid all-limp rule
refused. A hand is not in the balance loop: its firewall joint channel
sets `balance_critical: false` (only that rule is lifted; per-slot
`allow_limp`, `max_dq_step` and hold-only substitutes stay), and the
gateway refuses `balance_critical: false` on any channel that is not a
hand codec.

The Dex3 hand (`HandCmd_` on `rt/dex3/{left,right}/cmd`,
`example/g1/dex3/g1_dex3_example.cpp:34,269`) and the G1 hand SDK
(`MotorCmds_` on `rt/hand_sdk`, `example/g1/high_level/g1_hand_sdk_example.cpp:27`,
the blend weight × 100 in `cmds[0].mode`) are **decided and then passed
byte-identical or suppressed**: the finger joints are checked against the
firewall joint channel (one motor per element; every element decided as
enabled, since the Dex3 mode octet is a bitfield and `rt/hand_sdk` reuses
it for the weight), a frame the firewall passes is forwarded unchanged,
anything else (limited, rejected, a substitute, an undecodable or
non-canonical frame, a wrong element count) is suppressed: the hand keeps
its last command. There is no hand rewrite (no encoder for these types);
a hand is not part of the balance loop. Counters `hand_passed`,
`hand_suppressed`. Strictness: the elements are fixed-size and 4-aligned,
so the 3 padding octets after each mode octet must be zero, the message
must end where the decoder stops (at most 3 zero octets after it).

## ROS 2 `/cmd_vel` (`ros2_twist`, `ros2_twist_stamped`)

`geometry_msgs/msg/Twist` and `TwistStamped` on `rt/cmd_vel` (XCDR1, either
endianness; XCDR2 is undecidable), decided with the same firewall twist
path as the sport `Move`, all six components. The layout is fixed, so the
strict decode checks the exact length, a `frame_id` with one terminating
NUL and zero padding to the `float64` alignment. A limited or substitute
twist overwrites the six `float64` in place (exact `f64`, no rounding; the
stamp and frame id untouched) and is read back. Content probe: an unknown
writer's sample that decodes exactly as the configured layout is decided
as `/cmd_vel` (and is then a foreign source unless its GUID is allowed);
`rtps.unknown_writers: pass` opts out.

## ROS 2 joint trajectories (`ros2_joint_trajectory`, `ros2_follow_joint_trajectory_goal`)

The topic of a `joint_trajectory_controller`
(`trajectory_msgs/msg/JointTrajectory`, e.g.
`rt/arm_controller/joint_trajectory`) and the `send_goal` request of its
`control_msgs/action/FollowJointTrajectory` action
(`rq/<action>/_action/send_goalRequest`). Both need a `trajectory`
section (example: `config/firewall-gw.ros2-arm.example.json`): the joints
by name with `min_position` / `max_position`, `max_velocity`,
`max_acceleration`, `max_effort`, plus `max_points` (default 256),
`max_duration_s` (default 60), `on_velocity_violation` (`reject`, the
default, or `time_scale` with `max_time_scale`, default 4) and, for the
goal, `request_header` (`none` for `rmw_fastrtps`, `cyclone` for
`rmw_cyclonedds`). The firewall channel is `kind: {"joints": {"count":
<n>}}` (one per trajectory joint): it decides the **source, rate and
fault policy** (`check_access`); the profile envelope's `max_joint_speed`
caps every joint's `max_velocity`.

* **Strict decode** (`src/trajectory.rs`): plain CDR (XCDR1) either
  endianness, canonical (zero alignment gaps, no gap after an empty
  `float64[]`, strings 1..=256 octets UTF-8 without inner NUL, nothing
  after the message but the announced padding), counts bounded before
  anything is allocated. The real Jazzy captures of both RMWs
  (`fixtures/captures/ros2-jazzy/*_frag_run1.pcap`, 40-point 6-joint
  trajectories) decode strictly (`tests/trajectory.rs`). The goal's
  multi-DOF trajectory must be empty and its tolerances must name the
  trajectory's joints, at most once, with finite values. Anything else is
  undecidable: suppressed, `robot.gateway.undecodable_command`, and a
  non-finite command for the firewall (its source rules apply).
* **Bounds**: joint names known and unique (a name differing in case,
  white space or encoding is unknown), positions on every point for every
  joint, `velocities` / `accelerations` / `effort` empty or one per
  joint, every value finite, `time_from_start` non-negative and strictly
  increasing, the last at most `max_duration_s`; positions within their
  range; declared velocities and the rate between consecutive positions
  within `max_velocity`; declared accelerations, the change of declared
  velocities and the acceleration of three consecutive positions within
  `max_acceleration`; efforts within `max_effort`. An empty trajectory
  (a stop: the controller holds) passes.
* **Between points** (review F2): the segment the controller interpolates
  is bounded too, not only the waypoints. Assumed interpolation:
  `joint_trajectory_controller`'s default `splines`, per joint and
  segment, a quintic when both points carry accelerations, a cubic
  Hermite when both carry velocities, linear otherwise. Position,
  velocity and acceleration are checked at the polynomial's extremes on
  the segment. A segment that leaves the position range is refused (no
  time scaling fixes a path); one that only exceeds velocity /
  acceleration is time-scaled when `time_scale` is configured. Another
  `interpolation_method` (`none`) or a vendor scheme is not modelled.
* **Start time** (review F1): a non-zero `header.stamp` makes the
  controller start the trajectory at that time (a past stamp skips into
  the middle of it: a jump the checks never saw). The gateway zeroes it
  in place (the controller starts on receipt), verified by decoding
  again: outcome rewritten, status counter `trajectory_stamp_zeroed`.
* **Outcomes**: pass unchanged; with `time_scale`, a trajectory whose only
  violations are velocity / acceleration is **slowed down in place** by
  the smallest factor that fits (every interval scaled up and rounded up
  to the ns, velocities divided by the factor, accelerations by its
  square; positions and efforts untouched; verified by decoding and
  checking again), `robot.gateway.trajectory_time_scaled`; anything else
  is **suppressed** (PAD), `robot.gateway.trajectory_rejected`. Nothing is
  substituted: the gateway has no trajectory it knows to be safe (the
  robot's current position is not in the message), so the controller
  keeps executing (or holding at the end of) the last accepted one.
* **DATA_FRAG**: suppressed as on every motion channel. A trajectory must
  fit one RTPS DATA: the lab's 40-point, 6-joint trajectory is 5220
  octets, above Cyclone DDS's default 1344-octet fragment size; raise the
  DDS message / fragment size on the controller (Cyclone
  `General/MaxMessageSize` and `FragmentSize`, Fast DDS
  `maxMessageSize`) or bound `max_points` (README "Known limits").

## Gateway findings and the agentd feed

The gateway counts its own decisions (`src/findings.rs`, findings contract
2.3 `robot.gateway.*`: `trajectory_rejected`, `trajectory_time_scaled`,
`undecodable_command`, `fragmented_command`, `writer_binding_conflict`,
`sequence_jump`, `port_bypass_risk`, `restriction_changed`,
`findings_dropped`) per (rule, channel) on the decision path (no I/O, no
allocation for repeats) and reports one aggregated deviation per
housekeeping period.

Late packets (read more than `max_queue_delay_ns` after arrival) are
reported as `robot.gateway.overload` (findings contract 2.5,
sales-readiness T8): the decision path counts them, and housekeeping
reports one finding per `overload_interval_ms` (default 60 s) at most,
opened at the first tick that sees a late packet: Medium, High when the
interval held `overload_high_late` (default 1000) or more, with the count
and the first late packet's channel. The packets themselves still get the
firewall's fault verdict (`fault_policy`); only the report changes: the
gateway decides them with the firewall's `late_verdict` /
`joint_late_verdict`, which apply the fault policy and count `faults` in
the status file but record no `robot.firewall.internal_fault`; before, an
overloaded box sent one Critical `internal_fault` per burst (RESULTS O1:
1,364 in a 2 h soak). An `internal_fault` the firewall raises itself (a
defensive post-condition failing after a check: non-finite output, output
over the speed limits, an invalid joint frame after acceptance) is still
written to the events file and the feed as a Critical finding. **Shed**
packets go into the same finding and count toward `overload_high_late`:
the run loop watches the kernel's NFQUEUE packet ids, which number a
queue's packets in order, and a gap means packets the kernel numbered but
never delivered to the gateway (a full netlink receive buffer: dropped,
or accepted unchecked with `on_gateway_down: bypass`). A packet the kernel
drops because the queue already holds `queue.max_len` packets may not
leave a gap and is then not counted; the gateway does not read the
kernel's own counters (`/proc/net/netfilter/nfnetlink_queue`, which the
unit's `ProcSubset=pid` hides). Status: `overload.late_pending`, `overload.shed_pending`,
`overload.shed_total`, `overload.reports`, `gateway.late`.

Decision summaries (sales-readiness T19, `src/summary.rs`): over the same
feed the gateway writes a `robodr-gateway-summary/v1` line at start, every
60 s and at a clean stop: the mode, `on_gateway_down`, the `sha256:`
digests of the configuration, firewall and profile files as read at start,
the decision counters since the previous line (`packets`, `accepted`,
`modified`, `dropped`, `samples`, `passed`, `limited`, `substituted`,
`suppressed`, `late`, `undecidable`), the firewall's fault verdicts and the
id of the restriction in force. agentd appends each as a black-box note
(signed and chained; start and stop critical), so what agentd received as
the gateway's summary is in the signed record. The signature proves
receipt, not authorship: the feed socket checks the peer's uid (root
and `allowed_uids`) but the lines carry no signature of the gateway, so any
process allowed on the socket can write a summary claiming enforce mode
and the expected digests. The individual
verdicts stay in the status and events files. A stop that is not clean (a
crash, SIGKILL) writes no stop line; the next start line shows the
restart. Lines that wait while agentd is away share the feed's bounded
backlog. With `findings_socket` (agentd's `gateway_feed`
socket) those and the Motion Firewall's own deviations (`robot.firewall.*`)
go to agentd as JSON lines (`robodr-gateway-finding/v1`, `src/feed.rs`),
which turns each into a finding of its normal pipeline (black box, spool,
responder, correlation). The socket is connected, and written with a
50 ms timeout, on a dedicated thread (`gw-feed`, review F5): the packet
thread only hands lines over a bounded channel (256, non-blocking; a full
channel drops the line, counted), so agentd being slow or away never
delays a decision. While agentd is away up to 1024 lines wait on the feed
thread (oldest dropped, counted: status `findings_feed`). At stop the
feed thread writes what waits for 500 ms at most (a slow agentd cannot
hold the shutdown); the rest is lost to the feed. The events file keeps
everything either way.

## `restrict_motion` (restriction file)

With `restriction_path`, `robodr-executor`'s gateway adapter writes a
restriction (`src/restrict.rs`, `robodr-gw-restriction/v1`: `id`,
`max_linear_speed`, `max_joint_speed`, `factor`, `expires_unix_ms`) that
the gateway reads on a dedicated thread (`gw-restriction`, review F4: no
file I/O on the packet thread) and applies at the next housekeeping tick.
The file is opened with `O_NOFOLLOW | O_NONBLOCK` (a symlink or a FIFO
fails at once instead of being followed or blocking) and checked on the
open descriptor: a regular file, not group- or world-writable, owned by
root or by the owner of its directory. It only **tightens**: twist
channels (ROS 2 twist, sport `Move`, loco `SetVelocity`, Go1 `HighCmd`)
are capped at `max_linear_speed` and `factor` × the channel's own linear
limit, angular speed at `factor` × its angular limit (a forwarded output
above the caps becomes a limited one, direction kept); trajectory
channels get `max_velocity` ≤ `max_joint_speed` and `factor` × the
configured value. A twist command is capped **before** the Motion
Firewall decides (review F3), so the firewall's ramp state follows the
capped speed and lifting the restriction ramps up from it at the
channel's acceleration limit. While a restriction is active, the sport
API's `SpeedLevel` (1015) is refused (review F8): the firmware's speed
range must not be raised under a restriction. Gateway review, finding 6:
so is every other non-velocity motion call whatever the allowlist says
(sport / `obstacles_avoid` / `uwbswitch` / loco / arm-action requests
other than stops and queries, Go1 `HighCmd` modes other than 0 and 2;
`restriction_refused`): a restriction must not be answered with a flip or
a posture change. Velocity calls are capped, stops pass. A restriction applies to
commands decided after it; a trajectory the controller already accepted
keeps executing at its accepted speeds (review F9; `safe_pause` stops
it). Low-level joint channels (`LowCmd_`, arm SDK, hands) are
**not** restricted (scaling a balance controller's targets is not a speed
limit). The gateway lifts it at its TTL itself, so a restriction ends even
with the executor down: `expires_unix_ms` (wall clock) is converted once,
when the restriction is applied, into a deadline on the monotonic clock,
and only that deadline ends it (gateway review, finding 8: a wall-clock
step forward used to lift it at once; re-reading the same file does not
move the deadline); a malformed,
symlinked, non-regular, wrongly owned or group / world-writable file is ignored with a warning and status
`restriction_error` (the restriction in force keeps its own expiry). The
status file's `restriction.id` is what the executor reads back to verify.
A forged restriction can only slow the robot down, and on a robot that
balances (platform morphology humanoid, quadruped or other) never below
the floor: a restriction whose `factor` is below 0.05, or whose absolute
cap is below 0.05 × a twist channel's linear limit or a trajectory
joint's velocity bound (or applies to a channel without a finite limit,
where it cannot be converted to a factor), is ignored the same way
(`restriction_error`; executor review finding 3, ADR-0012 rule 4: a
near-stop of a balancing robot's commands makes it fall).

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
earlier SEDP again, keeps classifying them (writers announced on another
topic are persisted too, as "not enforced"). A writer with no announcement
is **probed** (`rtps.unknown_writers: probe`, default). The probe is
**lenient** (review finding F2): it decides channel membership only, in any
representation a DDS reader might accept, so a non-canonical encoding of a
motion command cannot slip through as "nothing"; the sample is then decided
**strictly** on that channel and fails closed (a foreign source, or an
integrity failure). A `LowCmd_` must decode (any representation, trailing
octets allowed) and carry a valid Unitree CRC (the motor board ignores an
invalid one); a request must be in the sport id range (1001..=1199), the
humanoid locomotion ranges (7001..=7199, 8001..=8299), the arm action range
(7106..=7113) or alias one; a hand frame matches when its sequence count, or
its length (non-zero padding, a `DHEADER` and trailing octets allowed),
gives the channel's element count; a `Twist` matches any CDR / CDR2 body of
at least 48 octets (trailing octets a reader ignores included: a padded
twist used to miss the probe and pass), a `TwistStamped` a stamp, a
`frame_id` of 1..=256 octets and at least six `float64`; the twist probe
ranks after the trajectory probe. A request that two configured services
read with the same priority (Go2 sport and `obstacles_avoid` /
`uwbswitch` share ids 1001..=1004 with different meanings) is suppressed
(`ambiguous_api_request`): without the writer's SEDP topic its service is
not known. The probe classifies the writer until it is evicted (least
recently used; its later samples are decided on that channel). Cost: an
unknown writer's non-motion sample of plausible shape (any CDR sample of
48 octets or more when a `ros2_twist` channel is configured) is suppressed
as a foreign `/cmd_vel` command; every controller-side writer the robot
uses must therefore be announced through the bridge (deployment rule
below) or persisted in `rtps.state_file`.

A writer the gateway **knows** as writing another topic is not decided,
but its samples are still probed for the strong motion shapes: a
CRC-valid `LowCmd_`, a hand frame or a joint trajectory from such a writer
is suppressed (`suspicious_writer`, finding `fragmented_command` with
reason `unenforced_writer_motion_payload`); so is a twist when the writer
announced a twist type, and a request when its announcement's INFO_DST
could not be checked. This is the shape of a discovery differential (the
robot matched the writer on the motion topic through an announcement the
gateway did not see). A same-type topic the robot acts on (`rt/arm_sdk`
next to `rt/lowcmd`) therefore needs its own channel.

## Robot-side observation (NFLOG)

The ruleset copies every UDP datagram entering the bridge from the robot
port to NFLOG group `observe.nflog_group` (default 4174; `observe.enabled`,
default `true`). `NFLOG` is not a terminating target: the original is
forwarded at once, nothing is queued or dropped, and a stopped or slow
gateway changes nothing on that path (a full socket buffer loses copies,
`observe_overruns`). The run loop drains the group without blocking before
every NFQUEUE receive and right before a received batch is decided
(`Gateway::observe`; the copy's IP checksum is not checked, offloaded
packets may carry a partial one). It uses:

- **`rt/lowstate`** (`lowstate_topic` of an arm-SDK channel): taken from a
  robot writer the robot's SEDP announced on that topic, or, when the
  announcement was not seen (gateway restart), from any robot writer whose
  payload decodes as the channel's `LowState_` with a valid Unitree CRC;
  fragmented samples (Cyclone sends the 2 KB `hg` `LowState_` as
  DATA_FRAG) are reassembled (bounded, per writer). The arrival time is the
  kernel's timestamp mapped to the decision clock. Counters
  `lowstate_samples`, `observer.lowstate_bad`.
- **The robot's discovery**: the unqueued-locator check (Known limits, "DDS
  ports outside the queued ranges") on every robot participant's locators
  and on every robot reader / writer of an enforced topic
  (`discovery.robot_unqueued_locators`). Robot-side announcements never
  change the controller-side writer map.

If the group cannot be bound (no `nfnetlink_log`) the gateway runs without
observation, prints a WARNING and reports `observe_unavailable` in its
status: the arm-SDK engagement then uses its conservative first-step rule
and the robot-side locator check does not run. Only traffic entering from
the robot port is observed, so a controller-side sender cannot feed the
gateway a joint state.

## Clock

The firewall's clock is the packet's **arrival time** on the box: the
kernel receive timestamp (`NFQA_TIMESTAMP`, enabled by `SO_TIMESTAMP` on the
queue's netlink socket) mapped into `CLOCK_MONOTONIC`, never decreasing. A
backlog drained after a scheduling stall therefore keeps the sender's
spacing (otherwise its frames would be refused as "too early"). Without a
timestamp the processing time is used. A sender's own timestamps
(`INFO_TS`) are never used. A packet read more than `max_queue_delay_ns`
(default 5 ms) after its arrival gets the firewall's **fault verdict**
(`fault_policy`; a humanoid holds) instead of a check. So does a packet
whose receive timestamp lies after the wall clock (the clock was stepped
back while it waited): its delay is unknown, so it counts as late
(gateway review, finding 8; it used to count as "no timestamp").

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
| `firewall` | — | `robodr_firewall::FirewallConfig` JSON (channels, joint channels, platform: morphology, `fail_behaviour`, `fault_policy`, `foreign_source_action`). In `enforce` mode `<firewall>.sig` is required (below, "Signed envelope") |
| `queue.num`, `queue.max_len` | —, 1024 | NFQUEUE number and kernel queue length |
| `queue.on_gateway_down` | `fail_closed` | see above |
| `queue.controller_port`, `queue.robot_port` | — | bridge port names (ruleset) |
| `queue.vlan_ids` | none | 802.1Q VLAN ids (`1..=4094`, at most 16) whose single-tagged IPv4 / ARP frames are bridged from the controller port; their IPv4 is queued and decided like untagged traffic (`bridge-nf-filter-vlan-tagged`). Other ids, stacked tags (QinQ), IPv6 and PPPoE stay dropped (T44; `tests/netns_e2e.rs::vlan_pass_through_end_to_end`) |
| `rtps.domain_ids` | `[0]` | queued DDS port ranges (7400 + 250·d .. +249) |
| `rtps.malformed_datagram` | `drop` | whole-datagram policy |
| `rtps.unknown_writers` | `probe` | `probe` or `pass` |
| `rtps.max_writers`, `rtps.max_writers_per_channel` | 4096, 16 | not-enforced writers remembered (least recently used evicted: it is then unknown and probed again); per-channel sequence state |
| `rtps.max_enforced_writers` | 1024 | writers classified as enforced (`1..=65536`); **never downgraded or removed** by discovery (a dispose, an unregister or an announcement on another topic keeps them enforced); when full, a new enforced writer replaces the one seen longest ago (by a sample or an announcement) if that one has been idle for `rtps.enforced_idle_evict_s` (`discovery.enforced_evicted`), else it is refused (finding `fragmented_command`, reason `enforced_writer_table_full`; `discovery.enforced_refused`) and probed. A full table stays full, so unknown writers (an evicted one included) are probed, also with `unknown_writers: pass` |
| `rtps.enforced_idle_evict_s` | 3600 | how long an enforced writer must have sent no sample and had no announcement before a new enforced writer may take its place in a full table; `0` = never (`60..=31536000` otherwise). An active writer is never evicted; a flood of fresh forged announcements on an enforced topic can still hold the table, and a new writer is then refused and probed |
| `rtps.state_file` | none | persisted writer → channel map (format `robodr-firewall-gw-writers/v2`, v1 still read): the enforced table and the not-enforced writers. Read only if a regular file (symlinks refused), owned by root or the directory's owner and not group / world writable; written through an `O_EXCL` 0600 temporary file |
| `rtps.max_sn_jump` | 64 | largest sequence-number step decided at once (larger: held until confirmed) |
| `rtps.binding_takeover_ns` | 1 s | silence after which another (IP, MAC) may continue an authorised GUID's stream |
| `rtps.extra_port_ranges` | none | further `[lo, hi]` UDP port ranges queued and decided as RTPS (non-default DDS ports; at most 16) |
| `observe.enabled`, `observe.nflog_group` | `true`, 4174 | robot-side NFLOG copies ("Robot-side observation") |
| `channels[]` | — | `firewall_channel`, `codec`, `topic`, `udp_ports`, `allowed_src_ips`, `allowed_src_macs` (RTPS), `legacy_sources` (IP → firewall source), `allowed_api_ids` (sport, loco, arm actions), `allowed_high_modes`, `allow_battery_off` (go `LowCmd_`, default `false`), `robot_model` / `allowed_fsm_ids` / `max_velocity_duration_s` (loco; `robot_model` also for arm actions), `weight_slot` / `max_weight` / `engage_max_q_error` / `lowstate_max_age_ms` / `lowstate_topic` / `engage_first_step` / `engage_stable_frames` / `engage_stable_q` (arm SDK), `max_weight_step` / `max_weight_rate_per_s` (arm SDK, hand SDK), `note` (free text) |
| `max_queue_delay_ns` | 5 ms | late packets get the fault verdict |
| `overload_interval_ms`, `overload_high_late` | 60000, 1000 | late packets reported as one `robot.gateway.overload` per interval at most (`1000..=3600000` ms); High from this many late packets in one interval (at least 1) |
| `events_path`, `events_max_bytes` | none, 64 MiB | firewall deviations as JSON lines |
| `status_path` | none | counters, firewall stats, recv→verdict latency |
| `housekeeping_ms` | 100 | events, status, state file, watchdog |

The Go2 example's `allowed_api_ids` (and the test fixture's) include
`Damp` (1001, `ROBOT_SPORT_API_ID_DAMP`, `unitree_sdk2`
`include/unitree/robot/go2/sport/sport_api.hpp:19`), which makes the robot
go limp and settle to the ground: it is kept as the operator's soft stop,
but anyone who can present an allowed source can send it. While a
`restrict_motion` restriction is in force it is refused like every other
non-velocity call; `StopMove` (1003) still passes. List only the
calls the site's controller uses.

The Go2 example's sport channel needs a twist channel
`/api/sport/request` (with `max_angular_speed`) in the firewall
configuration; `config/firewall.unitree-go2.example.json` has only
`/lowcmd`.

`config/firewall-gw.unitree-{g1,go2}.channels.example.json` (with
`config/firewall.unitree-{g1,go2}.channels.example.json`) enable the
channels added after S8 (G1: arm SDK, loco, both Dex3 hands, arm actions;
Go2: sport, ROS 2 `/cmd_vel`); every channel carries a `note` explaining
its choices. They are tested to build (`tests/gateway.rs`
`shipped_channel_examples_build`) against a profile listing their channels.

`robodr-firewall-gw check-config --config <json>` validates everything
(configuration, profile with its trust checks, the firewall file's
signature in enforce mode, firewall compile, channel ↔ codec ↔ slot count ↔
profile `motion_types`, the humanoid / bypass rule) without touching the
network.

**Signed envelope (sales-readiness T11).** The firewall file holds the
envelope the gateway enforces (joint limits, steps, allowed sources); it
used to be read as plain JSON, so whoever could write it could widen every
limit. In `enforce` mode the gateway now refuses to start unless
`<firewall>.sig` (`robodr-firewall-config-sig/v1`, written by
`robodr-commission sign-firewall --firewall <file> --profile <locked
profile> --sign-key <key>`) is a valid Ed25519 signature, **by the key that
signed the accepted profile**, verified against `profile_trust.trusted_keys`
(authenticated by `trust_roots` when configured), over the profile file's
digest and the firewall file's exact bytes. An edited file, a signature
made for another profile (an older envelope cannot be paired with a newer
profile, so the profile's anti-rollback covers it) or another key is
refused. When the accepted profile also binds a `motion_firewall` file
(`robodr-commission bind`), the firewall file must be exactly that one:
another envelope the same key signed for the same profile (an older or a
lab one) is refused in `enforce` mode and warned about in `observe` mode.
A profile that binds none relies on the signature alone. `observe` mode
starts without a signature and warns. The signature is
checked at start (and by `check-config`); the decision summaries record the
digests (above). Not covered: the gateway configuration itself
(`firewall-gw.json`: channels, allowlists, ports) is not signed, and
agentd still reads its `firewall.joint_config` unsigned (its verdicts
there are recording-only). **Migration:** an existing enforcing
installation must sign its firewall file before the upgrade, or the
gateway does not start (`on_gateway_down` then applies; `fail_closed`
stops motion traffic).

## Deployment

1. Bridge the two NICs (systemd-networkd or netplan), no IP needed on the
   bridge.
2. `robodr-firewall-gw ruleset --config /etc/robodr/firewall-gw.json`
   renders the idempotent setup script (`br_netfilter` sysctls; an nft
   `bridge` table that bridges only IPv4 and ARP from the controller port;
   untracked traffic plus a no-op conntrack match so IPv4 defragmentation
   runs before the queue; the `ROBODR_GW` chain that drops fragments and
   queues the DDS / legacy ports; the `ROBODR_GW_OBS` chain that copies
   the robot side's UDP to NFLOG). `robodr-firewall-gw-rules.service`
   (oneshot, before `network-pre.target`) applies it at boot.
3. `robodr-firewall-gw.service` (`Type=notify`, `CAP_NET_ADMIN` only, no
   IP sockets, FIFO priority 40, watchdog 2 s). Focal (systemd 245)
   variants in `packaging/systemd/focal/`.

**Commissioning capture (required step, review finding F7).** The
unqueued-locator check sees the discovery that crosses the bridge (queued
from the controller side, observed from the robot side) while the gateway
runs. Before enforcing, capture both bridge ports during a full robot
start-up and controller start-up (`tcpdump -i <port> -w ... udp`), and
confirm that every UDP port the robot or the controller receives RTPS on
lies in a queued range (or add it to `rtps.extra_port_ranges`), and that
the gateway's status shows `port_bypass_risk: false` with
`observe_unavailable: false`. Repeat after any DDS configuration change.

Kernel requirements: `nfnetlink_queue`, `nfnetlink_log` (observation), the
xtables `NFQUEUE`, `NFLOG`, `physdev`,
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
| Loco, arm SDK, hands, ROS 2 twist, extra port ranges and the unqueued-locator warning: `SetVelocity` limited and duration-capped (`Move(..., true)` = 864000 s), every G1 / H1 FSM helper but `Start` refused (`Damp`, `ZeroTorque`, posture), allowlists, hand-over / trick / unknown ids refused, H1's own service, the sport codec refused on a humanoid; arm frames with mode-0 gains passed, limited with modes and weight kept, weight out of range / leg gains → hold of the last accepted frame, nothing accepted → suppressed; hands passed or suppressed; ROS 2 `Twist` / `TwistStamped` limited in place; 6000 mutated packets with invariants (no forwarded `SetFsmId` but `Start`, no forwarded velocity / duration above the limits, no forwarded weight outside `[0, 1]` or leg gains, hands only unchanged and inside the envelope) | `tests/channels.rs`, unit tests in `src/{sport,armsdk,hand,ros2,config,ruleset}.rs` |
| Real kernel, new channels (`new_channels_and_extra_ports_end_to_end`): loco `SetVelocity` limited and capped, `Damp` removed, `Start` byte-identical, arm frame byte-identical, Dex3 out of envelope removed, twist limited; `ZeroTorque` on an extra port range removed, on a port outside every range delivered unchecked; an SEDP reader announcing that port sets `port_bypass_risk` in the status file | `tests/netns_e2e.rs` |
| Review of `f27e02d` (each test written first and seen failing): F1 weight flapping / rate / engagement without `rt/lowstate`; F2 XCDR2 and trailing-zero twists and Dex3 with non-zero padding / trailing octets from a foreign GUID suppressed; F5 Dex3 mode octet, hand-SDK weight; F6 `stopMotors` passes, `balance_critical: false` refused on body channels; F10 SetVelocity expiry, queries feed no twist, malformed `SetVelocity` suppressed, `Start` allowlisted, arm action service, `float` rounding | `tests/exec_gw_review.rs`, `robodr-firewall/tests/exec_gw_review.rs`, `src/sport.rs` |
| Review of the motion branch (each test written first and seen failing): F1 a past `header.stamp` zeroed; F2 cubic overshoot / acceleration and quintic interior acceleration refused, time-scaled until the spline fits; F3 lifting a restriction ramps from the capped speed; F4 FIFO / symlink / group-writable restriction file refused without blocking, the watcher thread; F5 the feed hand-off never blocks; F8 `SpeedLevel` refused while restricted; too many points reported as `too_many_points` | `tests/review_motion.rs` |
| Robot side (NFLOG copies): engagement checked against `rt/lowstate` (close / far / stale / restart), fragmented `LowState_` reassembled, bad CRC ignored; robot reader of `rt/lowcmd` and robot participant at unqueued ports flagged | `tests/robot_side.rs`, `src/{observe,nflog}.rs` |
| Real kernel (`new_channels_and_extra_ports_end_to_end`): the arm engagement removed without `rt/lowstate` and byte-identical once the robot namespace publishes it (500 Hz, fragmented, through the NFLOG rule), the robot's own reader of `rt/lowcmd` at an unqueued port flagged in the status file | `tests/netns_e2e.rs` |
| Fuzz: packet path + NFQUEUE / NFLOG parsers + robot-side observation, invariants (no panic; accept = unchanged; rewrite = same length, valid checksums; no forwarded enforced sample that does not decode strictly / with a valid CRC; no forwarded unprobeable sample of an unknown writer; no forwarded go `LowCmd_` with `bms_cmd.off != 0`; channels fixture: arm weight within `[0, 1]` and stepped by at most 0.02, no forwarded loco `SetFsmId` / malformed call / duration above 1 s, hand frames with the SDK's mode octets, canonical twists) | `fuzz/fuzz_targets/firewall_gw_packet.rs`, smoke run `tests/fuzz_smoke.rs` |

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

- **Go1 compressed `LowCmd`, A2 / AS2, WebRTC** (Unitree gaps): the
  compressed layout is read from the shipped library's machine code, not
  a header or a capture; the A2 / AS2 low-level type is inferred and must
  be confirmed by the profile; WebRTC sessions are detected and
  quarantined by flow, never inspected. None of it has run against a real
  Go1, A2 / AS2 or Go2.

- **Joint trajectories** (Sprint 8): verified on real Fast DDS and
  Cyclone DDS captures for the decode only, and with synthetic frames for
  the gateway path; not against a real `joint_trajectory_controller`. A
  trajectory must fit one RTPS DATA (fragments are suppressed). The first
  point's step from the robot's current position is not checked (it is
  not in the message): a single point at `t = 0` far from the current
  position is a jump the controller executes; bound it with the
  controller's own `constraints` / `allow_nonzero_velocity_at_trajectory_end`
  and the profile envelope. A refused trajectory is removed, not replaced.
  `restrict_motion` does not restrict low-level joint channels, nor a
  trajectory the controller accepted before it was applied. Segment
  checks assume the controller's default spline interpolation (see
  "Joint trajectories").
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
  sees.** Gateway review, findings 1 / 2 / 7, closed the paths the gateway
  itself opened: an announcement or removal addressed by INFO_DST to
  anyone but the robot's participants (learned from the robot's observed
  SPDP / SEDP; `discovery.misaddressed`) is ignored, as the robot ignores
  it; a not-enforced announcement or a removal sent by another participant
  than the writer's own is ignored (`discovery.relayed_ignored`); a writer
  ever classified as enforced stays enforced (own table, persisted;
  `discovery.enforced_kept`; evicted only from a full table, idle for
  `rtps.enforced_idle_evict_s`, to make room for a new enforced writer,
  after which it is probed); the not-enforced table evicts the
  least recently used; only the standard builtin entity ids are discovery
  (a user writer with builtin kind bits is decided). Until the robot's
  participants are known (observation off, or its SPDP not seen yet) an
  INFO_DST cannot be checked: such an announcement is learned but marked
  unverified (its requests and twists are then probed as suspicious) and
  such a removal is ignored. What remains: if the robot ever matched a
  writer the gateway knows on another topic through an announcement the
  gateway did not see at all (a discovery path around the bridge, a
  fragmented SEDP the bounded reassembler dropped), only the suspicious-
  payload probe stands between its samples and the robot (strong shapes
  always, twists / requests as above). Unknown writers are probed (and
  their unprobeable samples suppressed); set `rtps.state_file` so a
  restart does not forget the robot's writers.
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
- **DDS ports outside the queued ranges are not inspected.** The ruleset
  queues the RTPS well-known port range of each `rtps.domain_ids` entry
  (7400 + 250·d .. +249: participant indexes 0..119) and every
  `rtps.extra_port_ranges` entry. A DDS stack configured for other ports
  (Cyclone DDS `Discovery/Ports`, a `ParticipantIndex` of `none` that
  makes it use kernel-chosen unicast ports, Fast DDS) sends its unicast
  SEDP and motion samples around the queue. **Deployment check:** the
  gateway compares every locator announced in the discovery it sees (SPDP
  participants: metatraffic / default, unicast / multicast; SEDP writers
  and readers of an enforced topic: their own locators) with the queued
  ranges. A UDPv4 locator outside all of them is counted
  (`discovery.unqueued_locators`), sets the status flag
  `port_bypass_risk` with the first such locator (`port_bypass`), and is
  logged once as a WARNING. Fix it by adding the ports to
  `rtps.extra_port_ranges` (regenerate and re-apply the ruleset) or by
  pinning the DDS ports. The same check runs on the robot's own SPDP /
  SEDP (observed NFLOG copies, review finding F7): the robot's participant
  locators and its readers / writers of enforced topics — a robot reader
  of `rt/lowcmd` at an unqueued port is exactly where a controller-side
  stack would send unchecked motion samples. The check only sees
  discovery while it runs and only what crosses the bridge: the
  commissioning capture (Deployment) is a required step.
- **Counters, not findings**: malformed datagrams, replays and rewrite
  failures are counters in the status file only; the findings the gateway
  does report are listed in "Gateway findings and the agentd feed".
- **Non-motor fields**: only `bms_cmd.off` is refused (see "Non-motor
  `LowCmd_` fields"); `led` / `fan` / `gpio` are forwarded as sent, and so
  are the sport API's non-velocity calls listed in `allowed_api_ids`
  (`Damp` included when listed; the list is required and only what it
  names passes, gateway review finding 6).
- **Spoofed IP and MAC**: see "Sequence numbers and writer binding" — the
  gateway bounds, but cannot prevent, the effect of an attacker that sends
  with the controller's own IP and MAC on the controller-side segment.
- **Hand frames are not rewritten**: a hand frame the firewall would limit
  is suppressed instead (the hand keeps its last command). The hand
  decoders are strict on padding and length, not by a full re-encode.
- **Arm-SDK engagement trusts `rt/lowstate`** as the robot reports it on
  the robot side of the bridge; a compromised robot-side process could
  report a pose that matches a malicious target. It is not a substitute
  for the joint envelope (which still applies to every slot).
- **ROS 2 `/cmd_vel` has no duration**: unlike `SetVelocity`, the gateway
  cannot know when the robot stops on its own; the firewall's
  `state_reset_after_ns` applies.
- **Loco / arm SDK / hand / ROS 2 channels** were tested on synthetic
  frames built from the SDK headers and examples, not against a robot.
- **H1-2** has no locomotion client in the SDK; only its `rt/lowcmd` and
  `rt/arm_sdk` (`hg`, weight slot 27) are enforceable.
- **Go1 compressed low-level frames** cannot be decided (dropped if the
  channel is configured).
- **No configuration reload** (sales-readiness T43, open): there is no
  reload signal; a changed configuration, profile or firewall file takes
  effect at the next start, and the restart is time without decisions
  (`on_gateway_down`). The per-writer sequence state and the firewall's
  hold references start empty after it (the enforced-writer table survives
  in `rtps.state_file`).
- **IPv4 only**: the ruleset drops IPv6, PPPoE, stacked VLAN tags and
  every other ethertype from the controller port (the gateway decides
  IPv4 only, so nothing else could carry a command past it unchecked).
  Single-tagged 802.1Q frames are bridged for the ids in `queue.vlan_ids`
  (T44) and decided like untagged traffic. A site that needs IPv6 or PPPoE
  through the bridge must route it around the gateway explicitly.
