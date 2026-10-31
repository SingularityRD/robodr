# Support matrix

> **Pre-release draft (refreshed 2026-10-30).** This lists what RoboDR targets and,
> for each row, **how far it has actually been verified**. The GA targets
> come from GA-ROADMAP Sprint 0 and are not yet confirmed by the product
> owner. **No row is field-verified. Nothing has run on a customer or
> design-partner robot.**

## Verification levels

| Level | Meaning |
|---|---|
| **V3 field** | Ran on real target hardware in the stated configuration (soak, real traffic). |
| **V2 lab** | Ran with real software of that kind in a lab: real captures, real binaries, a real broker, or a real kernel. Not on a robot. |
| **V1 synthetic** | Tests with spec-derived or IDL-derived vectors, hand-built captures, emulation (qemu-user, swtpm) or a container. |
| **V0 none** | Targeted or expected to work, but not exercised. |
| **Not supported** | Known not to work, or out of scope. |

## Platform requirements

This is the one requirements table; the other documents link here. The
levels below say how far each platform has been verified.

| Item | `robodr` `.deb` | `robodr` `.rpm` | `robodr-focal` `.deb` |
|---|---|---|---|
| Distributions | Ubuntu 22.04 / 24.04, NVIDIA JetPack 6, Debian 12 / 13 | RHEL / Rocky / Alma 9, Fedora | Ubuntu 20.04, NVIDIA JetPack 5; also installs on 22.04 and newer |
| Architectures | amd64, arm64 | x86_64, aarch64 | amd64, arm64 |
| glibc | **2.35 or newer** (`Depends: libc6 (>= 2.35)`, read from the binaries; the release is built in an Ubuntu 22.04 container) | **2.34 or newer** (built in a Rocky Linux 9 container) | none (static musl) |
| systemd | **247 or newer** (`LoadCredential=`, `ProtectProc=`) | 247 or newer (RHEL 9 has 252) | **245 or newer** |
| Other libraries | libgcc-s1, libsqlite3-0 (declared by the package) | openssl-libs, sqlite-libs (generated requirements) | none |
| Host monitoring (`robodr-pulsard`, eBPF) | Linux 5.5 or newer with BTF (`/sys/kernel/btf/vmlinux`) or, on JetPack 6, an external BTF file for exactly the running kernel; bpffs at `/sys/fs/bpf` | same | **not shipped** |
| Offline bundle | `robodr-<ver>-<arch>-offline.tar.gz` (`install-bundle.sh`, `dpkg`) | `robodr-<ver>-<arch>-rpm-offline.tar.gz` (same `install-bundle.sh`, `rpm -U`) | `robodr-focal-<ver>-<arch>-offline.tar.gz` |
| Tools to install | `sha256sum`, and `minisign` wherever the bundle signature is checked (`install-bundle.sh` refuses to install without a signature check) | same | same |

Optional components need more from the kernel:

| Component | Needs |
|---|---|
| `robodr-agentd` live capture | `CAP_NET_RAW` (the unit grants only that) and the capture interface; a mirror port or tap on a sensor box |
| `robodr-executor` (off by default) | nf_tables (`nft`), `CAP_NET_ADMIN`; `br_netfilter` to isolate bridged traffic |
| `robodr-firewall-gw` (inline gateway, sensor box) | two NICs bridged, `br_netfilter`, `nfnetlink_queue` (NFQUEUE), `CAP_NET_ADMIN`; IPv4 only |
| Black-box TPM anchor, sealed delivery | TPM 2.0 and `tpm2-tools` (verified with swtpm only) |

Not supported: glibc older than 2.35 or systemd older than 247 with the
`robodr` `.deb` (use `robodr-focal`), RHEL 8, SUSE, 32-bit architectures,
non-systemd init systems.

## Operating system and architecture

| Platform | Package | Level | Evidence / notes |
|---|---|---|---|
| Ubuntu 22.04 / 24.04, amd64 | `robodr` (built for glibc ≥ 2.35, systemd ≥ 247, with `robodr-pulsard`) | V1 | amd64: built in an Ubuntu 22.04 container and installed with apt in Ubuntu 22.04 and 24.04 containers (2026-10-30): dependencies resolved, maintainer scripts ran, every program started, units verified by that systemd, remove/purge kept evidence. No booted systemd, no target host. |
| Ubuntu 22.04 / 24.04, arm64, incl. NVIDIA JetPack 6 | `robodr` (arm64) | V0 | The current build (native arm64 runner, Ubuntu 22.04 container) is configured in CI but has not produced a package yet. An earlier configuration was cross-built and its tests run under qemu-user ([`docs/BUILD.md`](../BUILD.md), "arm64 (cross-compiled, 2026-10-18)"); never run on arm64 hardware. Host rules on JetPack 6 additionally need BTF or an external BTF file ([`docs/UNITREE.md`](../UNITREE.md) 3.2.1). |
| Ubuntu 20.04 / JetPack 5, amd64 + arm64 (also usable on 22.04) | `robodr-focal` (static musl, systemd ≥ 245, **no `robodr-pulsard`**) | V1 | Built, reproduced, smoke-run (arm64 under qemu-user), and installed with dpkg in a container. Not run on a Jetson or under a real systemd 245. The arm64 binaries are non-PIE. |
| Debian 12, amd64 | `robodr` | V1 | The Ubuntu 22.04 build installed with apt in a Debian 12 container (2026-10-30), same checks as above. arm64: CI configuration only. |
| Debian 13 | `robodr` expected to work | V0 | Same package names and a newer glibc than Debian 12; not installed there. |
| RHEL / Rocky / Alma 9, Fedora 42, x86_64 | `robodr` `.rpm` (built on Rocky Linux 9, glibc ≥ 2.34) | V1 | Built in a Rocky Linux 9 container and installed with dnf in Rocky Linux 9.8 and Fedora 42 containers (2026-10-30), same checks as above. Offline: the RPM offline bundle (`install-bundle.sh` with `rpm -U`), tested against `rpm` in a separate root only; or verify the minisign signature and `dnf install` the `.rpm`. aarch64: CI configuration only. |
| Other RPM distributions (SUSE, RHEL 8) | — | Not supported | |

## Kernel and host monitoring (`robodr-pulsard`, eBPF)

| Item | Level | Notes |
|---|---|---|
| Linux ≥ 5.5 with BTF, amd64 | V2 | Ran as root with eBPF probes loaded under WSL2 (kernel 6.18). Not on a robot. Multicast and DDS coexistence on the robot are open. |
| arm64 kernels | V0 | Pulsar's probes have never been loaded on arm64. |
| Kernels without BTF (NVIDIA L4T) | V0 (JetPack 6) / Not supported (JetPack 5) | JetPack 6 with the `robodr` package: an external BTF file generated for exactly the running kernel ([`docs/UNITREE.md`](../UNITREE.md) 3.2.1); the unit refuses a file of another kernel build. Never tried on an L4T kernel. JetPack 5: `robodr-focal`, agentd only, no host rules. |
| `rules/robodr/*.toml` in a running rules engine | V0 | Checked by `scripts/validate_rules.py` only. |

## ROS 2 and middleware

| Item | Level | Notes |
|---|---|---|
| ROS 2 Jazzy | V2 | Real captures: robot, teleop and a rogue `/cmd_vel` publisher; Gazebo Harmonic; DATA_FRAG ([`fixtures/captures/ros2-jazzy/`](../../fixtures/captures/ros2-jazzy/README.md)). |
| ROS 2 Humble | V2 (Fast DDS) / V1 (Cyclone DDS) | Real Fast DDS 2.6 captures: robot, teleop and a rogue `/cmd_vel` publisher, three same-host processes, DATA_FRAG, default shared-memory transports, SROS 2 ([`fixtures/captures/ros2-humble/`](../../fixtures/captures/ros2-humble/README.md)). Cyclone DDS on Humble: synthetic fixtures only. GA target. |
| ROS 2 Foxy (Unitree's pairing on Ubuntu 20.04) | V1 | EOL. Network-passive or agentd-only. Unitree SDK2 vectors only. |
| Kilted, Rolling | V0 | Same message definitions. Not tested. |
| Fast DDS 2.14 | V2 | Real captures. GA target "2.14+". |
| Fast DDS 2.6 (Humble) | V2 | Real captures. Its default shared-memory transport is invisible to the capture and reported (`robot.capture.unsupported_transport`); commission with UDP only ([`docs/DDS-TRANSPORTS.md`](../DDS-TRANSPORTS.md)). |
| Cyclone DDS 0.10 | V2 | Real captures (and Unitree's DDS). GA target "0.10+". |
| RTI Connext | V0 | Vendor id recognised. No traffic tested. |
| DDS-Security / SROS2 | Participants only (V2 on Fast DDS 2.6) | With sros2's default governance only participants and their claimed certificate subjects are visible: no topic, endpoint or motion sample. Unauthenticated participants and subjects outside the keystore are reported (`sros2_keystore`). Not detected by its certificate: a participant from a foreign CA that claims a granted subject (for example with sros2's default CA name); the authentication handshake is not inspected, so it is caught only as an unknown participant by its address. Cyclone DDS with DDS-Security: not captured. Real captures; see [`docs/DDS-TRANSPORTS.md`](../DDS-TRANSPORTS.md). |
| Zenoh (`rmw_zenoh_cpp`) | Detected, **not decoded** | Detected by port on real captures and reported (`robot.capture.unsupported_middleware`). The sensor is blind to its content. |
| XCDR1 `Twist` decode | V2 | Confirmed on real Fast DDS and Cyclone samples. |
| XCDR2 and the other motion types | V1 | Hand-built vectors. |

## Unitree robots

The per-model decode details are in
[`crates/robodr-cdr/README.md`](../../crates/robodr-cdr/README.md), "Model
matrix". Deployment modes are in [`docs/UNITREE.md`](../UNITREE.md).

| Model / generation | Level | Notes |
|---|---|---|
| Go2, Go2-W, B2, B2-W, H1, H1-2, H2, G1, R1 (SDK2 / DDS) | V1 | Decoders, joint envelopes, rules and the live path are tested with synthetic traffic and IDL-derived vectors. **No real Unitree capture.** Go2 EDU and G1 EDU are the GA design-partner targets. |
| A2, AS2 | V1 (partial) | Sport state and client. Low-level command enforced only as the inferred `unitree_go` layout once confirmed by the learned profile; motor count unknown. |
| Go1 (legacy UDP, `unitree_legged_sdk` v3.8.6) | V1 | High-level frames and low-level commands (declared and compressed). Compressed state frames are reported, not decoded. Out of GA scope. |
| A1, Aliengo, B1 | V0 | Known by frame layout only. |
| Air / Pro variants | Sensor box only | Nothing can be installed on them. |
| Go2 app channel (WebRTC) | Detect / block only (inline gateway) | Encrypted: content never decoded. Sessions on the Ethernet link are detected, attributed and can be quarantined by flow; Wi-Fi / cellular sessions are not on the link. |
| Sensor-box mode (any model) | V1 | Example configuration only. Not field-tested. The reference image is planned (S7). |

## SOC and export paths

| Item | Level | Notes |
|---|---|---|
| AutoSecOps ingest API (`robodr-uplink`) | V1 | Tested against an in-repository reference consumer and the shared vectors, and by hand against a Python TLS server. The AutoSecOps ingest module exists on its development branch and passes the same 26 vectors against its real endpoint (AutoSecOps `918363d2`, `68e3d2d5`); its benchmark reached p95 ≈ 1.27 s per 1000-line batch on a loaded 4-vCPU VM (AutoSecOps `09133dc0`). `robodr-uplink` ran against it end to end in one container, over TLS and loopback HTTP (`tools/e2e/RESULTS.md`); that branch is not released. |
| Fleet API, robot side (`robodr-enroll`) | V1 | Enrollment, key rotation, revocation lists, SOC profiles, ring information; tested against an in-repository reference SOC over HTTPS and the shared vectors. The AutoSecOps side is built on its unreleased development branch; fleet enrollment ran end to end against it in one container (`tools/e2e/RESULTS.md`), not across a real network. |
| Kafka export (`robodr-kafka-publish`) | V2 | Single-node Apache Kafka 3.9.1 and 4.1.0. TLS (required unless plain TCP is explicitly allowed), mutual TLS and SASL/SCRAM-SHA-256/512 verified against 3.9.1 only. Multi-broker behaviour tested only against a fake broker. |
| Diode export and import | V1 | In-process and integration tests. No physical diode tested. |
| Control-plane action API (`robodr-control-plane/v2`) | V1 | Mutual TLS and signed requests and answers, persistent state, evidence API; tested with an in-process signing client and a local test PKI, not across a real network. The AutoSecOps client speaks v2 and verifies the shared vectors (AutoSecOps `a9fca839`); its registry actions exported and verified evidence from a robot in one container on 2026-10-26, after an in-process scope fix on the AutoSecOps side (`tools/e2e/RESULTS.md`, defect D1), and its SOC client code drove the 2-hour lab soak on 2026-10-30. Executes nothing unless executor v1 is enabled. |
| Executor v1 (`robodr-executor`) | see [Response actions](#response-actions) | Verifies the SOC's signed request itself (own SOC keys, own replay store) before it executes a control-plane order. **Off by default.** Not run on a robot or under a real systemd. |
| Inline gateway (`robodr-firewall-gw`): Unitree `rt/lowcmd` (`unitree_go`, `unitree_hg`), sport `Move`, loco requests (`SetVelocity`, `SetFsmId`), arm SDK (`rt/arm_sdk`), Dex3 / hand SDK, arm action requests, ROS 2 `Twist` / `TwistStamped` on `rt/cmd_vel`, ROS 2 `JointTrajectory` and `FollowJointTrajectory` goals, Go1 legacy UDP | V2 | Real kernel: three network namespaces, a bridge with br_netfilter and NFQUEUE, the binary's run loop, synthetic datagrams (the loco, arm, hand and ROS 2 channels from frames built after the SDK headers and examples). Ran for 2 hours in the lab soak (LowCmd 500 Hz, sport `Move`, joint trajectories) and in the red team (`tools/e2e/RESULTS.md`). IPv4 only. Not run on a robot, a real Cyclone DDS stack or a real sensor box. |
| Black-box TPM NV anchor | V1 | swtpm only. |
| Black-box remote anchor | V1 | Over loopback against a real receiver process. |

## Response actions

What `robodr-executor` can carry out, through which adapter, behind which
gate, and how far each is verified. **Everything here is off by default**
(`executor.enabled: false` in `agentd.json`); with the executor off every
accepted request is recorded, not executed. Every action also needs the
executor's own response policy marked OEM-validated, a locked profile, a
known safety state that the safety system does not own, and (from the
SOC) a valid SOC-signed request; the safety state is checked again right
before apply. Adapter names are the keys of `motion` in `executor.json`
(example: `config/executor.motion.example.json`); details and refusal
codes: [`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md).

| Action | Without a `motion` section | Adapter | Extra gate | Revert | Level |
|---|---|---|---|---|---|
| `isolate_network` | executed (nftables) | built in | humanoid / unspecified morphology: only with a human's approval and an OEM `fall_safe_restrict` entry | exact inverse, at TTL or on request | **V2**: real nftables in network namespaces, red team R6c |
| `quarantine_node` | executed (nftables) | built in | as above; needs addresses or locators agentd saw (else GUID prefix only, reported `containment: guid_only`) | exact inverse | **V2**: red team R6e (GUID prefix only on a shared host) |
| `record_evidence` | executed (black-box mark, in agentd) | built in | — | not applicable | **V2** |
| `restrict_motion` | recorded only (`advisory`) | `gateway`: restriction file read by `robodr-firewall-gw` | `motion.gateway.oem_validated: true`; on a robot that falls when de-energised (either adapter) a human's approval | file removed; the gateway also lifts it at the TTL | **V2**: lab soak (5 applied and reverted at TTL) and red team M0–M3, with the real gateway binary |
| | | `unitree_sport`: sport `SpeedLevel` request | `motion.unitree_sport.oem_validated: true`; advisory unless the gateway is also listed (it then refuses other `SpeedLevel` requests) | `SpeedLevel(0)`, not necessarily the level before | **V1**: in-process simulated peer; never a real Unitree robot |
| `safe_pause` | refused (`not_executor_action`) | `nav2`: cancel every goal, zero `Twist` | `motion.nav2.oem_validated: true`; **two distinct human approvers**, neither the requester; by default not while `moving_fast` (an OEM may list `allowed_states`); never on a humanoid | nothing to undo (goals are not restored); not a latch: a new goal moves the robot | **V1**: in-process simulated peer; the lab red team reached the adapter (A0), with no Nav2 peer |
| | | `ros2_control`: `SwitchController` STRICT to a hold controller | as above (`motion.ros2_control.oem_validated`) | inverse switch only on a two-person signed revert | **V1**: in-process simulated peer |
| | | `px4`: MAVLink 2 `DO_SET_MODE` AUTO.LOITER | as above (`motion.px4.oem_validated`); MAVLink signing not supported | none: the vehicle stays in hold until its operator switches | **V1**: in-process simulated peer |
| `request_safe_state` | refused (`not_executor_action`) | `px4` (hold, or RTL with policy `return_to_launch`), `nav2`, `ros2_control` | as `safe_pause` | not reversible | **V1** |
| `rollback_config` | refused (`not_executor_action`) | `rollback`: the site's OEM-validated program, then its `--verify` | `motion.rollback.oem_validated: true`; two approvers; robot `idle`; never on a robot that balances; `config: profile` always refused | not reversible | **V1**: test programs only |

ROS 2 service and action requests from the executor (Nav2 `CancelGoal`,
`SwitchController`) are implemented for `rmw_cyclonedds` only. No adapter
has run against a real Nav2, ros2_control, PX4 or Unitree robot, or on a
robot at all. `oem_validated` defaults to `false` and every shipped
example leaves it `false`: the integrator sets it only after the OEM has
validated that adapter on its platform.

## Hardware resources and performance

No CPU, memory or latency budget has been measured on target hardware.
The measured lab values (a shared 4-vCPU VM without a real-time kernel:
agentd 1.9 % CPU and about 12 MiB RSS during a 2-hour soak, inline
gateway decision p99 129 µs in that soak) are in the
[performance data sheet](performance.md), with their method and
environment. The GA targets (< 5 % CPU and < 150 MB RSS on the robot,
added gateway latency p99 < 1 ms) are open until measured on a robot and
a sensor box. The units' `MemoryMax=` limits (agentd 512M, gateway 128M,
executor 64M) are caps, not measurements.

## Contract and AutoSecOps compatibility

Which contract versions this RoboDR build speaks, and which SOC side they
have been run against. Upgrade the SOC side (and both sides of a diode)
**before** the robots: a consumer rejects a finding whose rule id only a
newer contract minor catalogues
([`robodr.findings.md`](../contracts/robodr.findings.md) §5).

| RoboDR | `robodr.findings` | Ingest API | Control plane | Fleet API | AutoSecOps |
|---|---|---|---|---|---|
| `0.1.0-alpha.1` (current `main`) | **2.4.0** produced; 1.x parse-only | draft v1 (`POST /api/robot-edr/v2/ingest`) | `robodr-control-plane/v2` (v1 removed) | draft v1 | **No released AutoSecOps version yet.** A SOC must accept findings **2.4** for the three `robot.agent.*` ids added in 2.4 (`control_plane_state_untrusted`, `executor_revert_failed`, `executor_journal_reset`); not yet run against AutoSecOps |
| robodr `682461b` (2026-10-26 end-to-end run) | 2.1.0 | draft v1 | v2 | draft v1 | AutoSecOps development branch `claude/robodr-ingest` at `7990c9a1`: ingest, fleet enrollment and evidence export ran end to end in one container (`tools/e2e/RESULTS.md`; evidence export needed an AutoSecOps-side scope fix, D1) |

The producer always writes the current minor; there is no setting yet
to hold it at an older minor for an older SOC, so match the SOC to the
robots. The ingest and fleet contracts are drafts and may still change
before they are frozen at GA. The minimum AutoSecOps version for each
RoboDR release will be stated here and in the release notes once
AutoSecOps ships the module.
