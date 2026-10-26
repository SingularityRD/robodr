# Support matrix

> **Pre-release draft (2026-10-26).** This lists what RoboDR targets and,
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

## Operating system and architecture

| Platform | Package | Level | Evidence / notes |
|---|---|---|---|
| Ubuntu 24.04, amd64 | `robodr` (glibc ≥ 2.39, systemd ≥ 247) | V1 | Built, packaged and bundled in the local CI run of 2026-10-17 ([`docs/BUILD.md`](../BUILD.md)). Install, upgrade and rollback have not been rehearsed on a target host. |
| Ubuntu 24.04, arm64 | `robodr` | V1 | Cross-built, tests run under qemu-user (2026-10-18). Not run on arm64 hardware. |
| Ubuntu 22.04 / 20.04, amd64 + arm64 (incl. NVIDIA JetPack 6 / 5) | `robodr-focal` (static musl, systemd ≥ 245, **no `robodr-pulsard`**) | V1 | Built, reproduced, smoke-run (arm64 under qemu-user), and installed with dpkg in a container. Not run on a Jetson or under a real systemd 245. The arm64 binaries are non-PIE. |
| Debian 12 | `robodr` does **not** install (glibc 2.36 < 2.39). `robodr-focal` expected to work. | V0 | The GA target names Debian 12. Today only the agentd-only package fits it. |
| Debian 13 | `robodr` expected to work | V1 | The test suites ran on Debian 13 under WSL2 (development host). Packages were not installed there. |
| Other distributions, RPM-based | — | Not supported | Packaging is `.deb` only. |

## Kernel and host monitoring (`robodr-pulsard`, eBPF)

| Item | Level | Notes |
|---|---|---|
| Linux ≥ 5.5 with BTF, amd64 | V2 | Ran as root with eBPF probes loaded under WSL2 (kernel 6.18). Not on a robot. Multicast and DDS coexistence on the robot are open. |
| arm64 kernels | V0 | Pulsar's probes have never been loaded on arm64. |
| Kernels without BTF (for example JetPack 5 L4T) | Not supported | Use `robodr-focal`: agentd only, no host rules. |
| `rules/robodr/*.toml` in a running rules engine | V0 | Checked by `scripts/validate_rules.py` only. |

## ROS 2 and middleware

| Item | Level | Notes |
|---|---|---|
| ROS 2 Jazzy | V2 | Real captures: robot, teleop and a rogue `/cmd_vel` publisher; Gazebo Harmonic; DATA_FRAG ([`fixtures/captures/ros2-jazzy/`](../../fixtures/captures/ros2-jazzy/README.md)). |
| ROS 2 Humble | V1 | Protocol-faithful synthetic discovery fixtures. Message definitions are unchanged from Humble to Kilted. GA target. |
| ROS 2 Foxy (Unitree's pairing on Ubuntu 20.04) | V1 | EOL. Network-passive or agentd-only. Unitree SDK2 vectors only. |
| Kilted, Rolling | V0 | Same message definitions. Not tested. |
| Fast DDS 2.14 | V2 | Real captures. GA target "2.14+". |
| Cyclone DDS 0.10 | V2 | Real captures (and Unitree's DDS). GA target "0.10+". |
| RTI Connext | V0 | Vendor id recognised. No traffic tested. |
| DDS-Security / SROS2 | Not supported (payload) | Encrypted payloads cannot be inspected. Discovery visibility depends on the protection settings. Not tested. |
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
| A2, AS2 | V1 (partial) | Sport state and client only. Motor count and low-level layout are unknown. |
| Go1 (legacy UDP, `unitree_legged_sdk` v3.8.6) | V1 | High-level frames. Compressed low-level frames are undecodable and are reported. Out of GA scope. |
| A1, Aliengo, B1 | V0 | Known by frame layout only. |
| Air / Pro variants | Sensor box only | Nothing can be installed on them. |
| Go2 app channel (WebRTC) | Not supported | Encrypted. Not on the Ethernet link. |
| Sensor-box mode (any model) | V1 | Example configuration only. Not field-tested. The reference image is planned (S7). |

## SOC and export paths

| Item | Level | Notes |
|---|---|---|
| AutoSecOps ingest API (`robodr-uplink`) | V1 | Tested against an in-repository reference consumer and the shared vectors, and by hand against a Python TLS server. **The AutoSecOps side does not exist yet** (S3). |
| Fleet API, robot side (`robodr-enroll`) | V1 | Enrollment, key rotation, revocation lists, SOC profiles, ring information; tested against an in-repository reference SOC over HTTPS and the shared vectors. **The AutoSecOps side does not exist yet** (S9). |
| Kafka export (`robodr-kafka-publish`) | V2 | Single-node Apache Kafka 3.9.1 and 4.1.0. No TLS or SASL. Multi-broker behaviour tested only against a fake broker. |
| Diode export and import | V1 | In-process and integration tests. No physical diode tested. |
| Control-plane action API | V1 | In-process signing client over loopback. Executes nothing. No TLS. |
| Black-box TPM NV anchor | V1 | swtpm only. |
| Black-box remote anchor | V1 | Over loopback against a real receiver process. |

## Hardware resources

No CPU, memory or latency budget has been measured on target hardware.
The unit's `MemoryMax=512M` is an estimate. The GA goals (< 5 % CPU and
< 150 MB RSS on the robot) are measured in Sprint 11. The Motion Firewall
joint check measured p99 ≈ 7–9 µs per frame at 1 kHz **in a VM**
(GA-ROADMAP §3a). That figure is not from a robot or an RT kernel.
