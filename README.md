<div align="center">
  <h1>RoboDR</h1>
  <b>Robot Detection &amp; Response</b><br/>
  <i>The security layer for the next generation of industrial and physical-AI robots.</i>
</div>

---

RoboDR is a detection-and-response platform for robots: industrial arms, AMRs,
humanoids, drones and defence UGVs. It watches what a robot's software *and its
motion* are actually doing, catches deviation from a locked model profile, and
responds in a way that is aware of the robot's physical safety state — never by
blindly killing a process on a machine that is mid-motion.

It is built on [Pulsar](https://github.com/exein-io/pulsar) (eBPF runtime
security for Linux), vendored under `vendor/pulsar`. RoboDR adds the robot layer
Pulsar does not have: the ROS 2 / DDS graph, the motion envelope, device
attestation, and a safety-aware responder (*Cyber-Jidoka*).

> **Status: alpha, under active development.** The pure detection core
> (`robodr-events`) and the RTPS parser are unit-tested. The ROS 2 sensor module
> compiles against Pulsar's module ABI; end-to-end bring-up on a controller is
> in progress. This is a frontier research codebase, not yet a product release.

## Why not just Pulsar, Exein or Alias?

Pulsar, Exein Runtime and Alias RIS all secure the robot's **Linux host** —
processes, files, network. That is necessary and RoboDR inherits it from Pulsar.
It is not sufficient: a host can look clean while an authenticated-but-spoofed
ROS 2 participant publishes a manipulated motion command, or a jailbroken LLM
planner issues a legal-looking but unsafe command. Recent work shows both are
real (see [`docs/ROADMAP.md`](docs/ROADMAP.md) §0). RoboDR's differentiators:

- **ROS 2 / DDS graph awareness** — who is on the bus, who may publish motion.
- **Motion Firewall** — every motion command checked against a physical
  envelope before it reaches the motors.
- **Cyber-Jidoka** — response graded by the robot's safety state, borrowing the
  Toyota *jidoka* idea: stop safely, surface the fault, fix it fleet-wide.
- **One core, every robot kind** — including closed controllers (via the
  agentless Sentinel Box) and air-gapped fleets.

## Repository layout

```
crates/
  robodr-events/        Pure robot event taxonomy + model-profile detection
                        logic. No I/O, no Pulsar. Unit-tested anywhere.
  robodr-sensor-ros2/   ROS 2 / DDS discovery sensor, as a Pulsar module.
                        Wraps the RTPS parser + profile check onto the bus.
rules/robodr/           Robot detection rules in Pulsar rules-engine TOML format
                        (validate: scripts/validate_rules.py; see rules/README.md).
config/                 Profile and daemon config examples.
docs/ROADMAP.md         The engineering plan: phases, components, research.
vendor/pulsar/          Pulsar, as a git submodule (the base we build on).
```

## Build

RoboDR needs the Pulsar submodule and a Rust toolchain with crates.io access.

```bash
git clone --recurse-submodules https://github.com/SingularityRD/robodr.git
cd robodr
# or, if already cloned:  git submodule update --init --recursive

# The pure core builds and tests with no kernel and no robot:
cargo test -p robodr-events
cargo test -p robodr-sensor-ros2   # RTPS parser tests

# The full module links against Pulsar (needs its eBPF build toolchain; see
# vendor/pulsar/README.md for kernel 5.5+, BTF, clang requirements):
cargo build -p robodr-sensor-ros2
```

## License

Apache-2.0 for userspace, GPL-2.0 for any eBPF probe code, matching Pulsar. See
[`LICENSE`](LICENSE).
