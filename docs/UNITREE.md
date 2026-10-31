# RoboDR on Unitree robots

This guide covers protecting Unitree robots (Go2, B2, G1, H1 and their
relatives) with RoboDR: which models and generations are covered, the two
deployment modes, installation, commissioning, what the Unitree rules
detect, and what is not covered yet. General procedures (verifying a
release, keys, the full commissioning flow, upgrades, evidence export) are
in [`OPERATIONS.md`](OPERATIONS.md); this guide refers to them by section.

> **Scope: protective only.** RoboDR detects, records signed evidence and
> *requests* a safe state through the platform's own interface. It never
> overrides the robot's safety system, e-stop or command authority. On a
> Unitree robot it is in the path of `rt/lowcmd` only in the optional
> **inline gateway** mode (section 5.1), where it can pass, limit, hold or
> remove commands that cross the sensor box's bridge, and never originates
> one; it is not a safety-rated device, and the robot's own safety
> functions remain primary.

> **Status (2026-10-26): not validated on a real robot.** The decoders,
> rules and examples below are built from Unitree's published SDK sources
> and IDL, and checked against hand-built and reviewer vectors. The inline
> gateway (section 5.1) and executor v1 (section 6.1) have run only in
> network namespaces on a development VM. None of it has run against a
> real Go2 or G1 yet (see [Known limits](#known-limits)). Run the first
> field period observe-only: executor disabled, gateway in `mode: observe`.

---

## 1. Supported models and generations

RoboDR decodes two generations of Unitree traffic:

* **SDK2 / DDS** (`unitree_sdk2`, `unitree_ros2`, Cyclone DDS 0.10.x): Go2,
  Go2-W, B2, B2-W, A2, AS2, H1, H1-2, H2, G1, R1. The low-level loop is a DDS
  writer of `rt/lowcmd`; high-level control is the request/response API on
  `rt/api/<service>/request`.
* **Legacy UDP** (`unitree_legged_sdk` v3.8.6): Go1 high-level frames and
  low-level commands in both forms: the `comm.h` struct (734 bytes) and the
  compressed form (614 bytes) that a v3.8.6 client actually sends. The
  compressed layout was read from the shipped library. A1, Aliengo and B1
  are known by frame layout only.

**Coverage by model** (decode = content read; enforce = the inline
gateway can limit / hold / remove it; detect = findings only):

| Model | Low-level command | High-level / API | App channel (WebRTC) |
|---|---|---|---|
| Go2, Go2-W, B2, B2-W | decode + enforce (`unitree_go_lowcmd`) | decode + enforce (sport `Request_`, `/cmd_vel`) | Go2: detect + attribute + block unlisted signalling + quarantine by flow (inline gateway `webrtc`); content never decoded |
| A2, AS2 | decode + enforce (`unitree_a2_lowcmd`) **only if** the robot announces the inferred `unitree_go` `LowCmd_` (type recorded in the profile); motor count unknown | decode + enforce (sport `Request_`) | not covered (no WebRTC information for these models) |
| H1 | decode + enforce (`unitree_go_lowcmd`, `rt/arm_sdk`) | decode + enforce (`loco`) | — |
| H1-2, H2, G1, R1 | decode + enforce (`unitree_hg_lowcmd`, `rt/arm_sdk`, hands) | decode + enforce (loco / arm) | — |
| Go1 | decode + enforce, declared (`go1_low_cmd`) and compressed (`go1_low_cmd_compressed`) | decode + enforce (`go1_high_cmd`) | — |
| A1, Aliengo, B1 | detect only (sender check by length; layout not in the sources) | detect only | — |

All of it is built from the SDK sources, the shipped Go1 library and
RFCs, and tested on synthetic frames; none of it has run against a real
robot (see [Known limits](#known-limits)).

What is decoded per model (IDL family, motor slots, morphology, topics and
API services) is the model matrix in
[`crates/robodr-cdr/README.md`, "Model matrix"](../crates/robodr-cdr/README.md#model-matrix).
That table is the single source; this guide does not repeat its numbers.

Example configurations for Unitree robots (installed under
`/usr/share/doc/robodr/examples/`):

| File | Purpose |
|---|---|
| `config/profile.unitree-<model>.example.json` | model profile template (participants, topics, motion envelopes) for a model, e.g. `profile.unitree-go2.example.json`, `profile.unitree-g1.example.json`. A starting point for review only: the locked profile is always learned from your own robot (section 4). |
| `config/agentd.unitree-sensor-box.example.json` | `robodr-agentd` on a passive sensor box (section 3.1) |
| `config/agentd.unitree-edu.example.json` | `robodr-agentd` on the EDU development computer (section 3.2) |
| `config/firewall.unitree-g1.example.json`, `config/firewall.unitree-go2.example.json` | joint envelopes for the low-level frames (section 5) |
| `config/response-policy.unitree-g1.example.json`, `config/response-policy.unitree-go2.example.json` | response policies with the humanoid / quadruped safety rules (section 6) |

The limits, gains and writer identities in these files are illustrative and
synthetic. Take the real values from Unitree's data for the exact hardware
revision and from your own commissioning captures.

## 2. Deployment modes

| | Sensor box (default) | EDU agent |
|---|---|---|
| Where it runs | A separate arm64 or amd64 box with two NICs, on a tap or switch mirror port of the robot network (192.168.123.0/24) | The EDU development computer inside the robot (Jetson, arm64): today the static `robodr-focal` package, agentd only (section 3.2) |
| Touches the robot | No: no software on the robot, no firmware change | Installs a package on the development computer |
| Models | **All**, and the **only** option for Air / Pro and any model whose computers you cannot install software on | EDU models only (the main motion controller is closed) |
| Sees | DDS discovery and data on the mirrored link: participants, writers of `rt/lowcmd` and the other profiled topics, API requests, decoded motion where the channel is wired | The same for the development computer's own interface, **plus**, only where `robodr-pulsard` can run (a BTF kernel and a matching build, section 3.2), host behaviour on the development computer (the Pulsar rules, section 7). Agentd-only mode, the only option on current Unitree images, has no host view. |
| Privileges | `robodr-agentd` with `CAP_NET_RAW` only, all IP denied | `robodr-agentd` as above, plus `robodr-pulsard` (root, bounded capabilities, eBPF) where the kernel has BTF |

Both modes can run together: an EDU agent on the development computer and a
sensor box on the robot's uplink.

**Inline gateway (in-path, optional, S8).** The sensor box can instead sit
**in** the cable between the controller (operator / companion PC) and the
robot as a two-port bridge, with `robodr-firewall-gw` deciding every motion
datagram that enters from the controller side (section 5.1). This is the
only mode in which RoboDR blocks anything. It needs the box's two NICs in
the cable, not on a tap, and the same placement caveats apply: it acts only
on what crosses that cable, never on the robot's internal links, Wi-Fi or
cellular.

**Where to attach the sensor box.** The box sees only what reaches its
capture NIC:

* A passive tap (preferred: it cannot transmit) or a mirror port on a switch
  you control, in the cable between the robot's Ethernet port and the
  operator or site network, sees every frame that enters or leaves the robot
  over Ethernet. This is where foreign commands arrive.
* Plugged into a free port of the robot's own network without a mirror, the
  box sees only broadcast and multicast traffic (DDS discovery, multicast
  data) and frames addressed to it. Unicast `rt/lowcmd` between the robot's
  internal computers is then invisible.
* Traffic over the robot's Wi-Fi or cellular links (the mobile app, cloud
  services) never crosses the Ethernet link and is not seen.

Check coverage during commissioning: the learn report lists every
participant and writer the box saw.

## 3. Installation

Verify the release at the entry station first ([OPERATIONS.md section 2](OPERATIONS.md#2-verify-a-release-entry-station)).

### 3.1 Sensor box

1. **Prepare the box.** Ubuntu 24.04 for the regular `robodr` package: as
   released it is built on Ubuntu 24.04 and needs glibc 2.39 (the libc6
   floor in its `Depends:`, read from the binaries) and systemd 247 or
   newer. On Ubuntu 20.04 or 22.04 use the static `robodr-focal` package
   (section 3.2): no glibc dependency, systemd 245 or newer. `Promiscuous=`
   in systemd-networkd needs 248 (22.04 and later); on 20.04 set promiscuous
   mode with the oneshot alternative named in the networkd example. Install
   with full-disk encryption. Work
   through the [hardening checklist](#sensor-box-hardening-checklist) before
   connecting it to the robot.
2. **Install the bundle** ([OPERATIONS.md section 3](OPERATIONS.md#3-install-on-an-air-gapped-host)):

   ```sh
   minisign -V -p /etc/robodr-trust/robodr-release.pub -m robodr-$V-$A-offline.tar.gz
   sudo mkdir -m 0700 /root/robodr-$V && sudo tar -xzf robodr-$V-$A-offline.tar.gz -C /root/robodr-$V
   sudo sh /root/robodr-$V/robodr-$V-$A/install-bundle.sh install \
       --pubkey /etc/robodr-trust/robodr-release.pub \
       --tarball robodr-$V-$A-offline.tar.gz
   ```

   Verify before extracting; upgrades run `/usr/lib/robodr/install-bundle.sh`
   (OPERATIONS.md section 3).

   The units are installed disabled. `robodr-pulsard` is not needed for the
   robot (it watches the host it runs on); enabling it on the box to watch
   the box itself is optional.
3. **Capture NIC: silent and promiscuous.** Copy the networkd example, set
   the interface name, and apply it. The examples (networkd file, nftables,
   drop-in, `agentd.unitree-sensor-box.example.json`) all name the capture
   NIC `eth1` and the uplink `eth0`; use your box's names (`ip link`) in
   every one of them:

   ```sh
   E=/usr/share/doc/robodr/examples
   sudo install -D -m 0644 $E/sensor-box/10-robodr-capture.network.example \
       /etc/systemd/network/10-robodr-capture.network
   sudoedit /etc/systemd/network/10-robodr-capture.network   # [Match] Name=
   sudo networkctl reload && sudo networkctl reconfigure eth1
   ip -d link show eth1        # PROMISC and NOARP, state UP
   ip addr show eth1           # no inet / inet6 lines
   ```

   `robodr-agentd` never enables promiscuous mode itself and has no
   `CAP_NET_ADMIN`; without it the NIC drops the mirrored frames that are
   addressed to other hosts.
4. **Host firewall.** Copy `$E/sensor-box/nftables.conf.example` to
   `/etc/nftables.conf`, set the interface names, the Kafka broker set, the
   NTP server and the admin network, check it with `sudo nft -c -f
   /etc/nftables.conf`, then `sudo systemctl enable --now nftables`. The
   capture NIC is dropped in both directions (this does not affect capture:
   AF_PACKET sees frames before netfilter), the uplink only reaches the
   brokers, NTP and admin SSH, and nothing is forwarded. List **every**
   broker of the Kafka cluster, not one collector address: the publisher
   connects to the leader of each partition at the address the cluster
   advertises, so a missing broker stalls its partitions after the next
   leader change. The box resolves no DNS, so the brokers must advertise
   IP-literal listeners (or be in `/etc/hosts`). A diode site exports files
   (`robodr-spool-export`) and needs no Kafka rule at all.
5. **Keys** as in [OPERATIONS.md section 4](OPERATIONS.md#4-keys).
6. **agentd configuration.** Start from
   `$E/agentd.unitree-sensor-box.example.json`: capture enabled on the
   capture NIC only, no `control_plane`, no `event_inputs` from a local
   Pulsar. Install it as `/etc/robodr/agentd.json` (`0640 root:robodr`) and
   check it:

   ```sh
   sudo robodr-agentd --config /etc/robodr/agentd.json --check-config
   ```

   For a Go1 (legacy UDP), list the hosts allowed to command the robot in
   `sensor.unitree_legacy.command_senders`, each as `{ "ip": …, "mac": …,
   "label": … }` (`mac` and `label` optional). A command from an unlisted IP
   is Critical (`robot.unitree.legacy_unknown_sender`; more than 16 distinct
   unknown senders are aggregated into `legacy_sender_flood`); a listed IP
   seen with another MAC is High (`legacy_sender_mac_mismatch`) and is not
   attributed. A MAC can still be forged by a host on the same L2 segment.
   Legacy ports that fall inside a configured DDS domain's RTPS port range
   are refused at `--check-config`; an RTPS-looking datagram on a legacy
   port is inspected on both paths and raises `legacy_port_rtps`.

7. **Sensor-box drop-in.** It restates the `CAP_NET_RAW`-only floor, resets
   any `IPAddressAllow=` so agentd has no IP access at all, and orders agentd
   after the writable data mount (`RequiresMountsFor=/var/lib/robodr`):

   ```sh
   sudo install -D -m 0644 $E/robodr-agentd.service.d/40-sensor-box.conf.example \
       /etc/systemd/system/robodr-agentd.service.d/40-sensor-box.conf
   sudo systemctl daemon-reload
   systemd-analyze security robodr-agentd.service
   ```

   Optionally uncomment its `BindsTo=` / `After=` lines for the capture NIC.
8. **Commission** (section 4), then enable: `sudo systemctl enable --now
   robodr-agentd`.
9. **Export** (section 8): on a connected site `robodr-kafka-publish.service`
   (settings in `/etc/robodr/kafka-publish.env`, the broker set in its
   `50-brokers.conf` drop-in, the same set as in the nftables file); on a
   diode site `robodr-spool-export.service`. Enable one of them, never both
   (they conflict: one consumer per spool).

#### Sensor box hardening checklist

- [ ] **Separate NICs.** One capture NIC (tap / mirror), one uplink NIC (SOC
      export, NTP, admin). Never bridge or route between them
      (`net.ipv4.ip_forward=0`, `net.ipv6.conf.all.forwarding=0`; the
      nftables example drops forwarding as well).
- [ ] **No IP on the capture NIC**: no IPv4, no IPv6 (not even link-local),
      no DHCP, no router advertisements, no ARP, no LLDP (networkd example).
      For defence in depth also set
      `net.ipv6.conf.<capture>.disable_ipv6=1`.
- [ ] **Promiscuous mode on the capture NIC** (networkd example), verified
      with `ip -d link show`.
- [ ] **Passive tap preferred** over a SPAN port: a tap cannot transmit into
      the robot network even if the box is compromised. With a SPAN port,
      make the mirror destination port receive-only on the switch.
- [ ] **Uplink firewall**: default drop; out only to the Kafka broker set
      and NTP by address (no DNS); in only SSH from the admin network
      (nftables example).
- [ ] **Full-disk encryption** (LUKS) for the root and the data partition
      holding `/var/lib/robodr` (black box, spool, profile state); unlock
      with a TPM-bound key or at boot by an operator, per site policy.
- [ ] **Read-only root file system** where possible. Keep `/var/lib/robodr`
      on a writable, encrypted mount (the drop-in waits for it), and `/tmp`
      and `/var/tmp` writable (tmpfs): `PrivateTmp=yes` needs them.
- [ ] **Signed updates only.** Update RoboDR only from minisign-verified
      bundles (`install-bundle.sh install --pubkey ... --tarball ...`), with
      the release key pinned out of band ([OPERATIONS.md section 2](OPERATIONS.md#2-verify-a-release-entry-station)).
      Update the OS from a vetted mirror, never directly from the Internet.
- [ ] **Minimal image**: no desktop, no compilers, no Bluetooth or Wi-Fi
      (disable or remove the radios), SSH keys only, no password logins.
- [ ] **Time**: NTP over the uplink to the site server; evidence
      timestamps depend on it.
- [ ] **Physical security**: the box can see all robot traffic. Seal the
      case and the tap, and log who has access.

### 3.2 EDU agent (development computer)

**Which package.** What the development computer can run depends on its
NVIDIA JetPack image, not on the robot model:

| Image on the Jetson | glibc / systemd / kernel | Package | What runs |
|---|---|---|---|
| JetPack 5 (L4T 35.x, Ubuntu 20.04): reported as the stock image of current Go2 / G1 EDU units (check yours) | 2.31 / 245 / 5.10, usually **no BTF** | `robodr-focal` (static musl binaries, systemd 245 units) | **agentd-only EDU mode**: `robodr-agentd` and the tools; no `robodr-pulsard`, no host rules |
| JetPack 6 (L4T 36.x, Ubuntu 22.04) | 2.35 / 249 / 5.15, BTF depends on the image | `robodr` (arm64, built in Ubuntu 22.04: `Depends: libc6 (>= 2.35)`), or `robodr-focal` | with `robodr`: `robodr-pulsard` and the host rules **if** the kernel has BTF (check below) **or** an external BTF file for the running kernel is installed (section 3.2.1); otherwise agentd-only, as with `robodr-focal` |

Since 2026-10-30 the release builds `robodr` in an Ubuntu 22.04 userland
(glibc 2.35, both architectures, `robodr-pulsard` included;
[BUILD.md, "Release build userlands"](BUILD.md#release-build-userlands)),
so it installs on JetPack 6. It does **not** install on JetPack 5: its
units use `LoadCredential=` (systemd 247) and its binaries need glibc
2.35. A `robodr-pulsard` for JetPack 5 (glibc 2.31, systemd 245) is not
built.

`robodr-pulsard` loads eBPF programs that need the kernel's BTF type information
(`CONFIG_DEBUG_INFO_BTF=y`, `/sys/kernel/btf/vmlinux`); NVIDIA's L4T
kernels are normally built without it. Without it the daemon can use an
**external BTF file** generated for exactly the running kernel
(section 3.2.1): Pulsar's `[pulsar] btf_path` reads the kernel types from
that file instead, and the unit accepts either. Rebuilding the L4T kernel
with BTF is the other way, but it changes the robot's image (and possibly
Unitree's support terms). Neither the BTF status of Unitree's JetPack 6
images, nor an external BTF on an L4T kernel, nor any RoboDR package has
been checked on a real Unitree Jetson yet: run the checks below on your
unit.

1. **Check the development computer**:

   ```sh
   lsb_release -ds; ldd --version | head -1; systemctl --version | head -1
   cat /etc/nv_tegra_release                 # R35 = JetPack 5, R36 = JetPack 6
   test -e /sys/kernel/btf/vmlinux && echo "BTF ok (robodr-pulsard possible)"
   findmnt -t bpf /sys/fs/bpf
   ```

   Check with Unitree whether installing software on the development
   computer affects warranty or support terms.
2. **Install the bundle** as in step 2 of section 3.1, with the
   `robodr-focal-<version>-arm64-offline.tar.gz` bundle on JetPack 5, or
   the `robodr-<version>-arm64-offline.tar.gz` bundle on JetPack 6 (same
   `install-bundle.sh install --pubkey ... --tarball ...`; it installs
   whichever package the bundle holds). `robodr` and `robodr-focal`
   conflict and replace each other, so a later move to the regular package
   is one bundle install; configuration, keys and evidence stay.
3. **Keys** as in [OPERATIONS.md section 4](OPERATIONS.md#4-keys): the
   black-box key is `/etc/robodr/keys/agentd-blackbox.key`, `0600
   root:root`, in both packages. On systemd 245 the `robodr-focal` units
   replace `LoadCredential=` with `/usr/lib/robodr/robodr-load-credential`
   (run as root with the `+` prefix in `ExecStartPre=`): it copies the key
   to the same `/run/credentials/robodr-agentd.service/blackbox.key` path,
   `0400` owned by `robodr` in a root-owned directory, and removes it when
   the unit stops. The `0640 root:robodr` group-readable fallback is **not**
   used: agentd refuses a key file with any group or other permission bit.
   Differences to `LoadCredential=`: the copy is on `/run` (tmpfs, can be
   swapped: encrypt swap or run without it) instead of a private ramfs.
4. **agentd configuration.** Start from `$E/agentd.unitree-edu.example.json`:
   capture on the development computer's interface on 192.168.123.0/24 (TUNE
   the name). Install and check it as in step 6 of section 3.1. Do **not**
   install the sensor-box drop-in here. The configuration is the same for
   both packages.
5. **Host rules (only where `robodr-pulsard` runs: the regular package
   and a BTF kernel or an external BTF file, section 3.2.1).** `robodr-pulsard` loads every
   rule under `/usr/share/robodr/rules`, including `robodr/unitree.toml`.
   Set the TUNE values (section 7) in the rule source, validate it
   (`python3 scripts/validate_rules.py --strict --pulsar-src vendor/pulsar`)
   and ship it in a signed bundle. Do not edit the installed rule files: the
   edit fires the self-protection rules and the next upgrade replaces it.
   To get Pulsar's threats into agentd's findings and correlation, enable
   the host-threat input ([OPERATIONS.md section 6.4](OPERATIONS.md#64-agentd-features-etcrobodragentdjson), "Host threats").
6. **SDK locations (with host rules).** The library-load and
   Python-import rules (`runtime_hooking.toml`) fire when an rclpy node or
   `python3` loads code from outside the allowlisted trees, which includes
   `unitree_sdk2_python` and a `unitree_ros2` workspace in a home directory.
   Install the SDKs into the image at commissioning (system site-packages,
   `/opt/unitree_robotics`) or add their directories to those rules' TUNE
   lists.
7. **Commission** (section 4), then enable: `sudo systemctl enable --now
   robodr-pulsard robodr-agentd` (with host rules), or `sudo systemctl
   enable --now robodr-agentd` (agentd-only mode).

**Agentd-only EDU mode covers** what agentd sees on the
development computer's interface: new or unknown DDS participants,
unauthorised writers of `rt/lowcmd` and of the API request topics,
off-profile topics, the decoded motion checks and the joint envelopes
(recording), with signed evidence and the export units. It **does not
cover** anything on the host itself: no process, file or connection
events, so none of the section 7 rules (UniPwn script, tunnels,
persistence, outbound connections, library tampering) run. A compromise of
the development computer is visible only through what it then sends on the
robot network. Pair it with a sensor box on the robot's uplink where
possible.

**systemd 245 differences** (`robodr-focal` units, `packaging/systemd/focal/`;
`scripts/check-focal-units.py` keeps them identical to the regular units
otherwise): no `ProtectProc=` / `ProcSubset=` (247), so the services see
every process in `/proc`; on Ubuntu 20.04's default hybrid cgroup layout
`MemoryHigh=` has no effect and `MemoryMax=` becomes the v1 memory limit;
`IPAddressDeny=` needs the kernel's cgroup BPF support: if the journal
says "Proceeding WITHOUT firewalling in effect!" after the first start, it
is not enforced on that kernel (agentd still opens no IP connection itself,
and `robodr-spool-export` uses `PrivateNetwork=yes`, which does not depend
on it). These units have been checked with `systemd-analyze verify` on
systemd 255 and their start sequence simulated without systemd; they have
**not** run under a real systemd 245 or on a Jetson yet.

**Static binaries.** `robodr-focal` contains static musl executables
(`scripts/build-static.sh`; docs/BUILD.md "Static (musl) build"): no
program interpreter and no shared library, so they run on any glibc. Both
the arm64 and the amd64 ones are static-pie (the executable image is
address-randomised like the stack, heap and mappings; arm64 is linked
through `scripts/static-pie-ld`, since Rust's target alone links it
non-PIE). The musl resolver does not read `nsswitch.conf`: give
`robodr-kafka-publish` IP literals (it then needs no resolver at all).

#### 3.2.1 External BTF for an L4T kernel (JetPack 6, `robodr` package)

Only for a kernel without `/sys/kernel/btf/vmlinux`. The file must
describe **exactly** the running kernel build: Pulsar relocates its probes
(CO-RE) with the field offsets it reads there, and a file from another
build or configuration can give wrong offsets, so the probes may load and
report garbage without any error. BTFHub does not cover NVIDIA's L4T
kernels; the file is generated from the kernel's DWARF debug information
with `pahole`, on a build host, from NVIDIA's sources for that L4T release.

1. **On the Jetson**, record what identifies the kernel build:

   ```sh
   cat /etc/nv_tegra_release        # e.g. R36 (release), REVISION: 4.3
   uname -r; uname -v; cat /proc/version   # release, build stamp, compiler
   zcat /proc/config.gz > l4t.config       # the kernel's configuration
   grep -E 'CONFIG_DEBUG_INFO_BTF|CONFIG_BPF_SYSCALL|CONFIG_BPF_EVENTS|CONFIG_KPROBE_EVENTS' l4t.config
   ```

   `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS` and `CONFIG_KPROBE_EVENTS`
   must be `y`; otherwise no BTF file helps.
2. **On a build host**, unpack the kernel source of exactly that L4T
   release (NVIDIA's "Driver Package (BSP) Sources",
   `public_sources.tbz2` → `kernel_src.tbz2`; for a vendor image, the
   vendor's kernel source of that image) and use the cross toolchain NVIDIA
   documents for it (the compiler in `/proc/version`). Build `vmlinux`
   with the Jetson's own configuration plus DWARF only:

   ```sh
   cp l4t.config .config
   scripts/config --enable DEBUG_INFO --enable DEBUG_INFO_DWARF4 \
       --disable DEBUG_INFO_REDUCED --disable DEBUG_INFO_SPLIT --disable DEBUG_INFO_BTF
   make ARCH=arm64 CROSS_COMPILE=aarch64-buildroot-linux-gnu- olddefconfig
   diff <(grep -v DEBUG_INFO l4t.config) <(grep -v DEBUG_INFO .config)   # must be empty
   make ARCH=arm64 CROSS_COMPILE=aarch64-buildroot-linux-gnu- vmlinux
   ```

   Debug information does not change type layouts; the `diff` makes sure
   `olddefconfig` changed nothing else (if it did, the source or the
   toolchain is not the one the image was built with: stop).
3. **Encode the BTF** (pahole 1.22 or newer):

   ```sh
   pahole --btf_encode_detached=vmlinux.btf vmlinux
   bpftool btf dump file vmlinux.btf format raw | head    # parses
   printf '%s\n%s\n%s\n' "<uname -r of the Jetson>" "<uname -v of the Jetson>" \
       "$(sha256sum vmlinux.btf | cut -d' ' -f1)" > vmlinux.kernel
   ```

   `vmlinux.kernel` is the stamp the unit checks: exactly the lines
   `uname -r` and `uname -v` print on the Jetson, then the SHA-256 of the
   BTF file, so a file replaced without a new stamp is refused too.
4. **Install** (through the site's vetted media, like any other file that
   reaches the unit) and point Pulsar at it:

   ```sh
   sudo install -d -m 0755 -o root -g root /etc/robodr/btf
   sudo install -m 0644 -o root -g root vmlinux.btf /etc/robodr/btf/vmlinux
   sudo install -m 0644 -o root -g root vmlinux.kernel /etc/robodr/btf/vmlinux.kernel
   # /etc/robodr/pulsar.toml, [pulsar]: uncomment
   #   btf_path = "/etc/robodr/btf/vmlinux"
   sudo systemctl restart robodr-pulsard
   ```

   The unit starts when `/sys/kernel/btf/vmlinux` **or**
   `/etc/robodr/btf/vmlinux` exists. Its `ExecStartPre=`
   (`/usr/lib/robodr/robodr-btf-check`) reads `btf_path` from
   `pulsar.toml`: any other path than `/etc/robodr/btf/vmlinux` is refused,
   and with that path the daemon does not start when the file or
   `vmlinux.kernel` is missing, or the stamp names another kernel or
   another file hash than the running kernel and the installed file: after an L4T update (OTA) the daemon stays down, visibly in the
   journal, until the file is regenerated (steps 1 to 4) for the new
   kernel.
5. **Check that the probes see the truth**, not only that they load:
   `journalctl -u robodr-pulsard` shows the modules starting without
   relocation errors; then run a known command (e.g. `sudo -u nobody
   /usr/bin/true`) and confirm the process event Pulsar reports (threat
   logger / `pulsar` CLI on `/run/robodr-pulsard/pulsar.sock`) carries the
   right image path, PID and parent. Wrong offsets show up as nonsense
   paths, PIDs or arguments.

Without BTF, eBPF LSM programs cannot be used (Pulsar's LSM feature
check reads the kernel's own BTF and disables them); L4T kernels do not
enable BPF LSM anyway. **Not verified:** no external BTF has been
generated for or loaded on an L4T kernel yet; the procedure follows
Pulsar's loader (`btf_path` → aya `Btf::parse_file`, raw BTF as `pahole
--btf_encode_detached` writes it) and the kernel build documentation.

## 4. Commissioning: learn, then lock

The full procedure, with the two-person sign-off and profile signing, is
[OPERATIONS.md section 5](OPERATIONS.md#5-commissioning-learn-sign-off-lock).
For Unitree:

1. **Record clean runs** on an isolated network, covering every mode the
   robot uses (stand, walk, sport modes, arm or hand use, docking). On the
   sensor box capture on the capture NIC; on the EDU computer capture on its
   robot-network interface:

   ```sh
   sudo tcpdump -i eth1 -w run1.pcapng udp
   ```

2. **Learn** with the model name you use across the fleet, e.g.:

   ```sh
   robodr-commission learn --pcap run1.pcapng --pcap run2.pcapng \
       --model unitree-go2-edu --out draft.json --report report.json
   ```

   Compare the draft with `profile.unitree-<model>.example.json`. Every
   writer of `rt/lowcmd`, `rt/arm_sdk`, `rt/user_lowcmd` and the
   `rt/api/*/request` topics must be one you can account for (the robot's
   own controller, your SDK program, the remote you use).
3. **Review, sign off and lock** exactly as in OPERATIONS.md section 5
   (`signoff`, `lock --operators ...`, `verify-profile`), then **check** the
   locked profile against a run not used for learning.
4. **Install** the profile, its signature and the trust file, then run the
   first field period observe-only: findings are marked `[observe-only]` and
   nothing is acted on until the response policy is `oem_validated`.

Recommission whenever the firmware, the SDK programs or the network change.

## 5. Joint envelopes (Motion Firewall)

`config/firewall.unitree-{g1,go2}.example.json` define per-motor limits for
the low-level frames: position, velocity, torque, gains, per-frame step, the
LowCmd CRC, the allowed writer of `rt/lowcmd`, the frame rate, and on G1 the
pinned ankle mode; a humanoid frame that commands every joint limp is
rejected. The decision logic and its tables are in
[`crates/robodr-firewall/README.md`](../crates/robodr-firewall/README.md).

**In the passive modes (tap, mirror port, EDU agent) the envelopes only
record.** agentd evaluates every decoded frame and reports a frame outside
the envelope (`robot.firewall.joint_*`, `crc_invalid`,
`disabled_motor_energised` findings, contract 2.1), but the frame still
reaches the motors. Treat them as detection and evidence. Take the limits
from Unitree's data for your hardware revision; the example values are
illustrative.

### 5.1 Inline gateway mode (`robodr-firewall-gw`)

With the sensor box bridged into the controller cable, the same envelopes
**enforce**. Design, safety argument and measurements:
[`crates/robodr-firewall-gw/README.md`](../crates/robodr-firewall-gw/README.md);
installation and operation: [OPERATIONS.md section 6.6](OPERATIONS.md#66-inline-motion-firewall-gateway-robodr-firewall-gw).
In short:

| Channel | Codec | What the gateway does |
|---|---|---|
| `rt/lowcmd` (G1, H1-2) | `unitree_hg_lowcmd` | `check_joint` per frame: a valid frame passes byte-identical, an out-of-envelope one is limited in place (CRC recomputed), a rejected one is replaced **in the same sample** by the hold of the last accepted frame (never damping, never limp, on a humanoid) or removed if there is none yet |
| `rt/lowcmd` (Go2, B2, H1) | `unitree_go_lowcmd` | as above; a quadruped may damp after the hold (`fail_behaviour`) |
| `rt/api/sport/request` | `unitree_sport_request` | `Move` speed limited (parameter rewritten), a rejected `Move` replaced by the hold / zero; other calls only if `allowed_api_ids` lists them (`StopMove` always) |
| Go1 UDP 8082 / 8007 | `go1_high_cmd` / `go1_low_cmd` or `go1_low_cmd_compressed` | `HighCmd` velocity limited / held, other modes by `allowed_high_modes`; `LowCmd` as `rt/lowcmd`, in the declared (734 B) or, with `go1_low_cmd_compressed`, the compressed (614 B, what v3.8.6 clients send) form (fixed-point `tau` / `Kp` / `Kd` rounded to the safe side); a non-zero `bms.off` (battery off) is refused on both |
| `rt/lowcmd` (A2, AS2) | `unitree_a2_lowcmd` | as `unitree_go_lowcmd`, for the **inferred** go `LowCmd_`: starts only with `require_crc`, the type recorded in the locked profile (learned on the robot) and without `bypass`; set the gateway's top-level `robot_model: a2` / `as2` so that a `unitree_go_lowcmd` or `allow_battery_off` configuration is refused |
| Go2 WebRTC (TCP 8081 / 9991, ICE / DTLS) | `webrtc` section (not a codec) | sessions detected and attributed from NFLOG copies (findings `robot.unitree.webrtc_*`); `block_unlisted` drops signalling from non-controllers; `webrtc-block` quarantines a peer or flow; the encrypted content is never decoded or limited (section 5.2) |
| `rt/api/sport/request` (G1, H2, R1: ids 7xxx), `rt/api/loco/request` (H1: ids 8xxx) | `unitree_loco_request` (`robot_model` required) | `SetVelocity` / `Move` limited and their duration capped (`max_velocity_duration_s`); every `SetFsmId` (`Damp`, `ZeroTorque`, posture changes, **and `Start`**) and the hand-over calls refused unless `allowed_fsm_ids` / `allowed_api_ids` list them; queries pass. A humanoid configured with `unitree_sport_request` is refused at start |
| `rt/arm_sdk` (G1, H1-2, H2, R1 `hg`; H1 `go`) | `unitree_hg_arm_sdk` / `unitree_go_arm_sdk` | every slot with gains or torque decided whatever its mode octet; the blend weight (`weight_slot`) bounded, step and rate limited, and its rise from 0 checked against the robot's `rt/lowstate` (below) |
| `rt/dex3/{left,right}/cmd`, `rt/hand_sdk` | `unitree_dex3_hand_cmd` / `unitree_hand_sdk` | mode octets must be the SDK's, the hand-SDK weight bounded and step / rate limited; a frame the firewall passes is forwarded byte-identical, anything else is suppressed (no hand rewrite). The hand's firewall channel sets `balance_critical: false`, so `stopMotors` (`kp = kd = 0`) is allowed |
| `rt/api/arm/request` (G1, H2 arm actions) | `unitree_arm_request` | `ExecuteAction`, `ExecuteCustomAction`, `StopCustomAction` refused unless `allowed_api_ids` lists them; `GetActionList` passes |
| `rt/cmd_vel` (ROS 2) | `ros2_twist` / `ros2_twist_stamped` | `geometry_msgs` `Twist` / `TwistStamped` (XCDR1) limited in place, all six components; a `TwistStamped`'s `header.stamp` is zeroed ("now") so a far-future stamp cannot outlive `diff_drive_controller`'s `cmd_vel_timeout` |
| `rt/api/obstacles_avoid/request` (Go2) | `unitree_obstacles_avoid_request` | `Move` (1003) with `mode` 0 limited like the sport `Move`; position targets (`mode` 1 / 2), `SwitchSet`, `UseRemoteCommandFromApi` refused unless `allowed_api_ids` lists them; `SwitchGet` passes |
| `rt/api/uwbswitch/request` (Go2) | `unitree_uwbswitch_request` | `SwitchSet` (follow the UWB remote) refused unless `allowed_api_ids` lists it; queries pass |

**What "hold" means on the wire.** The gateway never sends a datagram of
its own: re-sending an old `LowCmd` is discarded by the robot's DDS reader
as a duplicate, and inventing a new sequence number would make it discard
the controller's next real frame instead. A hold is written into the
rejected sample (same writer, same sequence number), so it is delivered
like the frame it replaces. A sample the firewall emits nothing for
(foreign writer, too early) is removed from the datagram as if lost in
transit; the robot keeps its last received frame, which in enforce mode is
always an accepted frame or a hold.

**When the gateway is down** (`queue.on_gateway_down`): `fail_closed`
(default) drops the queued commands, so the robot's own command timeout
applies, as when the controller fails; `bypass` forwards them unchecked and
is refused for a humanoid's `rt/lowcmd`. Check what the robot does on a
lost `rt/lowcmd` stream (Unitree's motor-board timeout behaviour) with the
OEM before enabling enforce mode on a humanoid.

Channel details, SDK sources and counters:
[`crates/robodr-firewall-gw/README.md`](../crates/robodr-firewall-gw/README.md)
("Loco requests", "Arm actions", "Arm SDK", "Hands", "ROS 2 `/cmd_vel`").

**Robot-side observation.** The rendered ruleset copies every UDP datagram
entering the bridge from the robot port to NFLOG group 4174
(`observe.enabled`, default `true`; `observe.nflog_group`; chain
`ROBODR_GW_OBS`). The copy is never queued or dropped: a stopped gateway
changes nothing on the robot's path. The gateway reads two things from it:

* the robot's `rt/lowstate` (`lowstate_topic` of the arm-SDK channel),
  which the arm-SDK engagement check compares the targets with;
* the robot's own SPDP / SEDP, which runs through the DDS port check
  below.

It needs `nfnetlink_log` and the xtables `NFLOG` target. Without them the
gateway starts, prints a WARNING and reports `observe_unavailable` in its
status; the arm SDK then engages only by the conservative first-step rule.

**DDS ports.** The gateway queues the RTPS port range of each
`rtps.domain_ids` entry and every `rtps.extra_port_ranges` entry (at most
16 `[lo, hi]` ranges, for a DDS stack on non-default ports). A locator in
the discovery it sees that lies outside every queued range sets
`port_bypass_risk` in the status file and is logged once as a WARNING:
RTPS to that port crosses the bridge unchecked. Add the ports and re-apply
the ruleset. **Commissioning capture (required):** record both bridge
ports (`tcpdump -i <port> -w ... udp`) through a full robot and controller
start-up and confirm every port either side receives RTPS on is queued.

**Upgrading an existing gateway configuration:**

* **Sign the firewall file before upgrading an enforcing gateway**
  (sales-readiness T11): `robodr-commission sign-firewall --firewall
  firewall.json --profile <locked profile> --sign-key <the profile's key>`
  writes `firewall.json.sig`; an enforcing gateway without a valid one,
  by the key that signed the profile, does not start. Re-sign after every
  change of the firewall file or of the profile.
* **802.1Q VLANs** (T44): tagged frames from the controller port are
  dropped unless their id is in `queue.vlan_ids`; the listed VLANs' IPv4
  is decided like untagged traffic. IPv6 and PPPoE stay dropped.
* **Overload is `robot.gateway.overload`** (T8): late packets are no longer
  reported as Critical `robot.firewall.internal_fault`; one finding per
  `overload_interval_ms` (60 s), High from `overload_high_late` (1000).
* **Go2 / B2 in enforce mode need a channel for every motion service**
  (gateway review, finding 3): a Go2 (`robot_model: go2` / `go2w`, or no
  `robot_model` and a sport channel) adds `unitree_obstacles_avoid_request`
  and `unitree_uwbswitch_request` channels (and twist channels of the same
  names in `firewall.json`), a B2 (`robot_model: b2` / `b2w`) a sport
  channel; otherwise the gateway does not start. See the Go2 examples.
* **A same-type topic needs its own channel.** A writer the gateway knows
  on another topic that sends a CRC-valid `LowCmd_` (a G1 `rt/arm_sdk`
  without a `unitree_hg_arm_sdk` channel), a hand frame or a trajectory is
  now suppressed (`suspicious_writer`).
* **Joint step bound across `kp = 0` frames.** A slot's previous target
  now survives frames in which it holds no position and expires after
  `step_reference_ttl_ns` (joint channel, default 500 ms). A controller
  that re-engages a released joint far from its last target within that
  time is held / limited; raise it with care or lower the TTL.
* **`TwistStamped` stamps are zeroed** in forwarded commands.
* **Allowlists are required** (gateway review, finding 6): a
  `unitree_sport_request`, `unitree_obstacles_avoid_request` or
  `unitree_uwbswitch_request` channel without `allowed_api_ids`, or a
  `go1_high_cmd` channel without `allowed_high_modes`, is refused (it used
  to forward every call / mode). `[]` / `[0]` mean velocity, stop and
  queries only. Under a `restrict_motion` restriction every non-velocity
  motion call is refused whatever the list says (stops and queries pass).

* **G1 / H1 / H2 / R1 `Start` is refused** (`SetFsmId` 500 / 204 / 601 /
  811) unless the loco channel's `allowed_fsm_ids` lists it. List it only
  if your controller starts the walking controller: it makes the whole
  body move from any state.
* **One-frame arm engagement is refused by default.** The arm-SDK weight
  moves at most `max_weight_step` (0.02 per frame) and
  `max_weight_rate_per_s` (0.5 /s). The SDK example
  (`g1_arm7_sdk_dds_example`) sets the weight to 1 at once from the
  measured pose: it works only with robot-side observation running (a
  fresh `rt/lowstate`, `lowstate_max_age_ms` 50) and the step and rate
  opened up (`max_weight_step: 1.0`, `max_weight_rate_per_s: 1000`, as the
  G1 channels example explains). A weight beyond these rules makes the
  humanoid hold its last accepted arm frame (`arm_weight_step_rejected`,
  `arm_weight_rate_rejected`, `arm_engage_rejected`).
* Re-render and re-apply the ruleset (new `ROBODR_GW_OBS` chain) and load
  `nfnetlink_log`.

Start in `mode: observe` (decides and records, forwards everything
unchanged), compare the would-have verdicts with the robot's behaviour,
then switch to `enforce`. Examples:
`config/firewall-gw.unitree-{g1,go2}.example.json`; with the newer
channels `config/firewall-gw.unitree-{g1,go2}.channels.example.json` and
`config/firewall.unitree-{g1,go2}.channels.example.json` (G1: arm SDK,
loco, both Dex3 hands, arm actions; Go2: sport, ROS 2 `/cmd_vel`; each
channel carries a `note` explaining its values).

### 5.2 Go2 WebRTC (app channel)

The Go2 app (and community clients) control the robot over WebRTC. The
content of a session is DTLS-SRTP encrypted and **cannot be read by a
sensor that does not hold the keys**; RoboDR does not try. With a
`webrtc` section in the inline gateway's configuration
([`crates/robodr-firewall-gw/README.md`](../crates/robodr-firewall-gw/README.md),
"Go2 WebRTC sessions") it:

* detects and classifies sessions to the robot: signalling on the robot's
  HTTP ports (8081 `POST /offer` with a plaintext SDP on older firmware;
  9991 `con_notify` / `con_ing_*` with an encrypted SDP on newer firmware;
  as used by community clients, not documented by Unitree), ICE (STUN)
  checks, TURN relaying, the DTLS handshake, SRTP;
* attributes the peer (IP, MAC where the copy has it) and reports, contract
  2.3 §3d: `webrtc_unknown_controller` (High; Critical once established),
  `webrtc_new_peer` (no list configured), `webrtc_controller_mac_mismatch`,
  `webrtc_session_in_denied_window` (`deny_windows`, UTC),
  `webrtc_concurrent_sessions` (`max_sessions`), `webrtc_relayed_session`
  (TURN or a non-local peer: remote control via a cloud relay),
  `webrtc_media_without_signalling` (signalled over Wi-Fi / another path);
  each once per peer session (a peer that comes back is reported again),
  non-Critical ones rate limited per minute with an aggregate count; the
  MAC binding is checked on every packet the gateway copies;
* from the plaintext legacy offer, keeps metadata only (ICE user fragment,
  fingerprint hash, candidates, media kinds; the `token` by length);
* blocks: `action: block_unlisted` drops signalling from hosts that are not
  `controllers` and from a MAC-bound controller's IP with another MAC
  (each drop logged first, so the refused host is still reported); a
  running session is quarantined by peer or by flow
  (`robodr-firewall-gw webrtc-block --peer ... --flow ...` prints the
  `nft` command; the findings name the flows).

On a passive sensor box the same monitor is a library
(`robodr_ros2_pipeline::webrtc`); agentd's live capture does not feed it
yet (UDP / RTPS-only capture). What the Go2 does when its controller's
session is cut mid-motion is not published: test a quarantine with the
robot at rest first.

## 6. Humanoid and quadruped safety rules

A humanoid stays upright only while its joint controllers actively balance
it; most "pause" or "safe state" implementations on such a platform damp the
joints or cut motor power, and the robot falls. A quadruped also balances
actively. The response planner therefore enforces, in code and whatever the
policy says (details in
[`crates/robodr-responder/README.md`](../crates/robodr-responder/README.md),
"Invariants"):

* **No de-energising actions on a humanoid.** `safe_pause` and
  `request_safe_state` are never executed on G1 / H1 / H2 / R1; they are
  advisory only, for the operator and the platform's own safety function.
* **Substitutes need approval.** The substitute containment
  (`limit_motion`, plus only the restrict targets in the policy's
  `fall_safe_restrict`) always waits for a human. On Unitree the low-level
  loop is a DDS writer of `rt/lowcmd`: isolating the network or quarantining
  that participant trips the motor watchdog and the robot falls, so
  `fall_safe_restrict` is empty in the G1 example. (The Go2 example, a
  quadruped, has no `fall_safe_restrict`: the no-termination and
  approval rules below apply to it.)
* **Minimum motion factor.** `limit_motion` never goes below the policy's
  `min_motion_factor` (0.3 in the G1 example, 0.2 in the Go2 example; hard
  floor 0.05).
* **No process termination on balancing robots**, a process quarantine
  always needs approval (it may be the balance controller), and the control
  plane refuses `rollback_config` (a controller restart) with `fall_hazard`.

Response-policy overrides match a finding's rule id exactly. Every Pulsar
(host) detection reaches the planner as `robot.host.pulsar_threat`, so a
policy cannot single out one host rule (the example policies therefore carry
no host-egress override).

Start from `config/response-policy.unitree-{g1,go2}.example.json`; both are
`oem_validated: false`, so every response is recorded, not acted on, until
the policy is validated with Unitree's safety data.

### 6.1 Executor v1 on a Unitree robot

The executor (`robodr-executor`,
[OPERATIONS.md section 6.5](OPERATIONS.md#65-executor-v1-robodr-executor-reversible-actions))
is off by default. It installs nftables rules on the host it runs on, so
it can only act where it runs **in the path**. Two consequences follow:

* **On a sensor box (tap or mirror) it protects nothing**, because the box
  is not in the path. Leave it disabled there.
* **On an inline gateway box (section 5.1)** leave it disabled too: the
  gateway is the enforcement there, and the executor has not been tested
  next to the gateway's bridge ruleset (with `br_netfilter` loaded, its
  `forward` chain also sees the bridged traffic).
* **On the EDU development computer** it can isolate that computer or
  quarantine a participant whose traffic crosses it. It never reaches the
  closed motion controller.

Rules for Unitree, all enforced in code:

* **Never cut `rt/lowcmd` on a humanoid.** The balance loop of G1, H1, H2
  and R1 is a DDS writer of `rt/lowcmd` on the robot network
  (192.168.123.0/24). In `/etc/robodr/executor.json`, list that network
  (and, narrowed by its GUID prefix, the `rt/lowcmd` writer: a GUID
  prefix always comes with the `cidr`) in `network.motion_control_path`
  with `"low_level": true`, as `config/executor.unitree-g1.example.json`
  does:
  * A `low_level` entry is never cut, whatever the response policy says.
    Isolation keeps it open, and it is accepted before any quarantine
    drop, so no quarantine acts inside the robot network, even on
    traffic that carries the quarantined GUID prefix.
  * A quarantine of a participant whose SPDP locators all lie on it (or
    that agentd has no locators for and does not vouch for) is refused
    (`motion_path`, `locators_required`); a locator on it next to others
    outside is left out, never acted on.
  * During an isolation the robot's DDS discovery (SPDP to
    239.255.0.1:7400/7401, IGMP) keeps working, so the motion stack does
    not lose its peers.
* **G1 example policy: nothing is executed.** `fall_safe_restrict` is
  empty, so on a humanoid both `isolate_network` and `quarantine_node` are
  refused (`fall_hazard`) before any rule is written. Even an OEM that
  lists them gets no execution without a human's approval: planner
  orders are refused with `needs_approval`. The G1 executor example also
  sets `require_approval_for_all_containment: true`, which refuses the
  planner's containment orders on every morphology.
* **The approval is verified by the executor itself.** A human approval
  counts only when the SOC's signed request, forwarded by agentd,
  verifies with the executor's **own** copy of the SOC public keys
  (`soc.keys` in `executor.json`, the same files as agentd's
  `control_plane.soc_keys`) for this robot's id, inside the timestamp
  window and never seen before (the executor's own replay store). A
  compromised agentd cannot approve containment on its own. List the
  robot's own public keys in `soc.robot_keys` (they are never accepted as
  SOC keys). An action the SOC approved is lifted on request only by the
  SOC's signed revert; TTL expiry and `robodr-executor revert-all` on the
  robot still lift it.
* **Quarantine scope.** A quarantine acts only on participants whose
  SPDP locators lie in `network.quarantine.cidrs` and on the robot's DDS
  ports; with none configured every quarantine is refused
  (`locator_out_of_scope`). The SOC's answer says how far an applied
  quarantine reaches (`containment`: `full` only when every source
  address the participant was seen sending from and every locator it
  announced is cut whole, any source port; `partial`; or `guid_only`
  when only the GUID-prefix drop is in force, which a sender can evade by
  re-attributing its traffic or changing its prefix). Cutting an address
  cuts every DDS participant on that host. The scope may not be `/0` or overlap the
  management or uplink networks. On a humanoid the robot network stays a
  `low_level` motion path, so a quarantine never acts there anyway.
* **Quadrupeds (Go2, B2).**
  * A `quarantine_node` always needs a human's approval, because it may
    cut a balance-relevant participant.
  * List `rt/lowcmd` as `low_level` there too.
  * `isolate_network` keeps the robot network open as long as it is
    listed in `control_buses` or `motion_control_path`.
* **What is never sent.** `safe_pause`, `request_safe_state` and
  `rollback_config` (damp, stand-down, controller restart) are never sent
  through the Unitree SDK: there is no SDK adapter for them, and on a
  humanoid (and, for `rollback_config`, a quadruped) they are refused
  `fall_hazard` anyway. `restrict_motion` is advisory unless the executor
  has a `motion` section (Sprint 8): then it goes through the in-path
  gateway (`gateway` adapter: sport `Move` / loco `SetVelocity` caps on the
  sensor box; `LowCmd_` is never restricted) and / or the sport API
  (`unitree_sport` adapter: `SpeedLevel(-1)`, reverted to `SpeedLevel(0)`
  at the TTL, not to the level before; Go2-family sport service only,
  verified against a simulated robot only), each with the site's
  `oem_validated`. On a quadruped a restriction factor is never below the
  policy's `min_motion_factor`.
* **Quarantine coverage.** Quarantine matches RTPS over UDP by GUID
  prefix. Traffic between processes on the same computer over shared
  memory is not covered.

Take every address, port range and GUID prefix from your own
commissioning captures (section 4). The example values are synthetic.

**New executor refusal codes** (contract §6a): `soc_signature_invalid`,
`soc_request_stale`, `soc_nonce_replayed`, `soc_replay_store_unavailable`,
`order_mismatch`, `approval_missing` (the signed approval does not
verify or does not match the order), `soc_keys_unavailable` (a key file
in `soc.keys` cannot be read or is one of the robot's own keys: every
control-plane order is refused until it is fixed), `approval_key_removed`
(after a reboot, a held action whose approving key is no longer listed is
not re-armed) and `locator_out_of_scope`.

**Upgrade order: the executor before agentd.** Since the red-team fixes
an agentd order may carry `guid_only` and `excluded` (contract §6a). An
older `robodr-executor` does not understand them and drops the order
unanswered; the request then reads `failed` ("executor unreachable") and
nothing is applied. Upgrade `robodr-executor` first, then
`robodr-agentd` (the newer executor also reports how far a quarantine
reaches, `containment` in the SOC's answer; with an older executor it
reads `unknown`).

**Upgrading an existing executor configuration:** add `soc.keys` (without
it every control-plane order is refused, `soc_signature_invalid`) and
`network.quarantine.cidrs` (without it every quarantine is refused). When
you rotate the SOC key, change agentd's `soc_keys` and the executor's
`soc.keys` together, and keep the old key listed until the actions it
approved have expired, or they are not re-armed after a reboot.

## 7. What the Unitree rules detect

`rules/robodr/unitree.toml` (Pulsar host rules; they run only where
`robodr-pulsard` runs, i.e. not in agentd-only EDU mode, section 3.2)
complements `radio_provisioning.toml` (Bluetooth / Wi-Fi tools and wireless
configuration files) and the generic rule files. The full table with false
positives is in [`rules/README.md`](../rules/README.md#unitreetoml-unitree-hosts-unipwn-2025-g1-telemetry-go1-tunnel).

**Where the UniPwn rules apply, honestly.** UniPwn attacks the BLE Wi-Fi
provisioning service. On the robots studied that service is very likely on
the **closed main controller**, not on the EDU Jetson; nobody has shown it
running on the Jetson. The five rules about the provisioning script and
bluetoothd (script executed, script opened, bluetoothd or the script
connecting out, pairing keys written or moved in) therefore fire **only if
the provisioning service (or a copy of it) runs on the host where pulsard
runs**. On an EDU computer without it they stay silent, and their silence
says nothing about the controller. What covers a closed controller is the
**network view**, from agentd on the EDU computer or a sensor box: a new or
unknown DDS participant, an unauthorised writer of `rt/lowcmd` or of an API
request topic, off-profile topics, and motion outside the envelopes, i.e.
what a compromised controller or a wormed neighbour does on the robot
network. If the attacker pivots from the controller onto the EDU computer,
the generic host rules (tunnels, persistence, outbound connections from
writable directories, library tampering) apply there.

| Threat (public research) | What fires |
|---|---|
| **UniPwn** (Makris & Finisterre, Sept 2025, CVE-2025-35027): hardcoded keys in the BLE Wi-Fi provisioning service and command injection into `wpa_supplicant_restart.sh`, giving root; wormable across Go2, B2, G1 and H1 | *If the provisioning service runs on this host* (see above): the provisioning script executed or opened by an interpreter (medium: audit trail of every BLE re-provisioning; the open covers `sh /path/wpa_supplicant_restart.sh` and `system()` strings); the script's own process or bluetoothd opening an IP connection (critical: an injected `/dev/tcp` reverse shell); planted Bluetooth bonding keys or a relaxed pairing policy; plus the BlueZ / Wi-Fi tool and wireless-config rules in `radio_provisioning.toml`. *On a closed controller*: only the network detections (agentd / sensor box) |
| Reported **G1 telemetry** to external servers | a Unitree process (under `/unitree/`, `/opt/unitree_robotics/` or an SDK tree) connecting outside the destination allowlist |
| The earlier **Go1 remote-tunnel backdoor** (a CloudSail-like vendor tunnel) and post-exploitation tunnels | reverse-tunnel clients (frpc, cloudflared, bore, rathole, ...), `ssh` / `dbclient` reverse or SOCKS tunnels in bundled form and overlay VPNs, all **by name**; and, whatever the name, any program in a writable directory (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, home directories) connecting to a public address. Persistence: new, replaced or enabled systemd units (also under `/usr/local/lib/systemd`) and generators, init scripts, `rc.local`, autostart entries, udev rules (`RUN+=`), ifupdown / NetworkManager dispatcher / dhclient / ppp hooks, and shell startup files (`/etc/profile.d`, `~/.bashrc`, `/etc/environment`, ...) |
| Tampering with the robot's middleware | writes, renames and links of Cyclone DDS configuration (`*cyclonedds.xml`, the `unitree_ros2` setup scripts that set `CYCLONEDDS_URI`, and the shell startup files where `CYCLONEDDS_URI` is often exported) and of the Unitree SDK and Cyclone DDS libraries, including a pip wheel's vendored `cyclonedds.libs/libddsc-*.so` (what `unitree_sdk2_python` loads) |

Network-side detections (both modes) come from `robodr-agentd`: a new or
unknown DDS participant, an unauthorised writer of `rt/lowcmd` or of an API
request topic, off-profile topics, and the decoded motion checks.

**TUNE at commissioning** (all marked in the rule file): the outbound
destination allowlist (default: loopback, RFC 1918 including
192.168.123.0/24, link-local, multicast; narrow it to the robot's real
networks and add the fleet gateway if it is outside private space), the
Unitree image scope, the provisioning script name if your firmware differs,
the commissioned `CYCLONEDDS_URI` file if it is not named `*cyclonedds.xml`,
the bluetoothd image path, and any overlay VPN the fleet uses on purpose.

**Assumptions.** Firmware-specific paths are not assumed: the provisioning
script is matched by file name, not directory. `/unitree/` is the reported
onboard layout and is unverified; it only widens which processes the
outbound rule watches. Pulsar's `Exec` event carries no parent image, so "a
shell spawned by the BLE daemon" cannot be a rule; the rules watch the
script being run or opened and what its own process does, and the SOC
correlates `parent_pid`. The tunnel, VPN and SSH rules match names and
options only; a renamed tool is caught by the writable-directory outbound
rule only if it runs from such a directory, and interpreted code (a script
run by `/usr/bin/python3`) is not caught by that rule at all.

## 8. How findings reach the SOC

Findings use the `robodr.findings` contract, version **2.1.0**
([`docs/contracts/robodr.findings.md`](contracts/robodr.findings.md)).

* **Host rules (EDU agent).** `robodr-pulsard` raises a threat named
  `RoboDR: ...`; with the host-threat input enabled
  ([OPERATIONS.md section 6.4](OPERATIONS.md#64-agentd-features-etcrobodragentdjson)), agentd turns it into a
  `robot.host.pulsar_threat` finding (the rule name and the process in its
  detail, severity from the rule) and a correlation signal.
* **Network detections (both modes)** are agentd's own findings
  (`robot.ros2.*`, `robot.motion.*`, `robot.firewall.*`; the joint-frame
  and `robot.motion.api_id_out_of_range` entries are new in 2.1).
* **Transport.** agentd writes signed findings to its spool and black box.
  Three units, shipped disabled in both packages, carry them off the host
  ([OPERATIONS.md sections 8.3 and 8.5](OPERATIONS.md#83-findings-batches));
  enable exactly one (they conflict):
  * air-gapped site: `robodr-spool-export.service` packs them into signed
    diode batches in `/var/lib/robodr/export/diode` (no network at all:
    `PrivateNetwork=yes`); `robodr-uplink --diode-out` (or
    `robodr-kafka-publish`) then runs on the SOC (high) side after
    `robodr-diode-unpack`;
  * connected site (for example the sensor box's uplink), to the SOC's
    AutoSecOps: `robodr-uplink.service` runs **on the unit or sensor box**
    and sends agentd's spool to the ingest API over TLS (signed batches,
    CA bundle plus optional key pin; its `50-soc.conf` drop-in allows
    exactly the SOC address,
    [OPERATIONS.md section 8.5](OPERATIONS.md#85-findings-to-the-soc-ingest-api-robodr-uplink)).
    A sensor box that watches several robots sends findings naming each of
    them, so register its key as a `relay` key (an `uplink` key is bound to
    one robot and gets `robot_mismatch` for the others);
  * connected site to a Kafka-based SIEM instead:
    `robodr-kafka-publish.service` runs **on the unit or sensor box** and
    publishes agentd's spool to the `robodr.findings` topic. Its
    `50-brokers.conf` drop-in allows exactly the Kafka broker set (every
    broker, IP literals) and nothing else.

  agentd itself never opens an IP connection.

A consumer must accept contract 2.1 to validate the 2.1 rule entries; see
the contract's section 5.


## Known limits

* **No real-robot validation yet.** Decoders, rules, firewall examples and
  policies are built from Unitree's published sources and checked against
  synthetic vectors only. Captures from a real Go2 and G1, a 72-hour soak and
  a UniPwn-style red-team exercise are planned
  ([`GA-ROADMAP.md` section 3a](GA-ROADMAP.md)).
* **The sensor box mode is not field-tested**: capture of mirrored frames
  addressed to other hosts on a promiscuous NIC, and the drop-in under a
  real systemd, have not run on hardware.
* **No host rules on JetPack 5; on JetPack 6 only with BTF.** JetPack 5
  (Ubuntu 20.04, glibc 2.31, systemd 245, L4T kernel without BTF) runs
  agentd only (`robodr-focal`): no `robodr-pulsard` is built for it.
  JetPack 6 runs the regular `robodr` package (built for glibc 2.35 since
  2026-10-30) with `robodr-pulsard` when the kernel has BTF or an external
  BTF file is installed (section 3.2.1); neither has been tried on a real
  Jetson.
* **`robodr-focal` has not run on a Jetson or under a real systemd 245.**
  Its static binaries were built and smoke-run (amd64 natively, arm64 under
  qemu-user: `--version`, `--check-config`, a short agentd run, black-box
  verification), its units pass `systemd-analyze verify` (systemd 255) and
  their credential start sequence was simulated without systemd. (Since
  2026-10-31 the arm64 binaries are static-pie; that build was smoke-run
  under qemu-user, not on a Jetson.)
* **The UniPwn script and bluetoothd rules prove nothing about a closed
  controller.** They fire only where the provisioning service runs on the
  pulsard host (section 7); the controller itself is covered only by the
  network detections.
* **Go2 app channel (WebRTC) content is not decoded, and cannot be.** The
  channel is DTLS-SRTP encrypted; RoboDR detects, attributes and can
  quarantine sessions on the Ethernet link at the inline gateway
  (section 5.2), never what they command. On Wi-Fi or cellular it is not
  on the Ethernet link at all (a cloud-relayed session shows as the
  robot's flows to the relay). The signalling formats come from community
  clients and may change with firmware. agentd's passive capture does not
  run the WebRTC monitor yet.
* **Telemetry over Wi-Fi or cellular** is not on the Ethernet link the
  sensor box watches, and agentd's capture analyses DDS (and legacy Unitree
  UDP) only, not general IP flows. The host rule sees outbound connections
  only on the EDU computer. Watch the site's Wi-Fi / firewall logs for the
  robot's own external traffic.
* **Live safety state and context from Unitree topics** (agentd
  `safety_feed`: sport mode, `LowState_`, the remote, ROS 2 lifecycle; see
  `crates/robodr-agentd/README.md`) have seen synthetic traffic only. The
  sport mode codes and joint-speed thresholds in
  `config/agentd.unitree-go2.example.json` must be checked on the robot. The
  `LowState_` CRC is unkeyed and detects corruption only, not forgery. A
  lifecycle (Nav2) state is held for at most one SPDP lease (up to 10 min)
  after its participant's last announcement; a hung node, or one that dies
  while its participant lives on, is not detected.
* **Legacy Go1 "compressed" frames** (`unitree_legged_sdk` v3.8.6): the
  614-byte `LowCmd` is decoded and enforced using the layout read from the
  shipped library's machine code (`refineCmd`), not a header. It has not
  been compared with a capture from a real Go1, and a fleet using the
  library's `encryptCRC` cannot be enforced. The 807-byte `LowState` is
  still reported as not inspected. A1 / Aliengo / B1 layouts are not in
  the sources.
* **A2 / AS2**: no low-level type, example or topic is published. Their
  low-level command is **inferred** to be `unitree_go` `LowCmd_` on
  `rt/lowcmd`, because their sport state is a `unitree_go` type. It is
  enforced (`unitree_a2_lowcmd`) only when the profile learned that type
  from the robot itself. Their motor count and model-specific API ids are
  unknown.
* **The inline gateway (section 5.1) is new and not field-tested**: run
  on synthetic traffic through real network namespaces only; latency on the
  target sensor box, Unitree's `rt/lowcmd` QoS and the motor board's
  behaviour on a lost stream are still to be measured / confirmed. In the
  passive modes the joint envelopes record, they do not block. There is no
  `restrict_motion` control-plane adapter for the sport API yet (the
  gateway's sport limit is configuration, not a SOC action). Its deployment
  rules must be checked on site before enforce mode
  ([`crates/robodr-firewall-gw/README.md`](../crates/robodr-firewall-gw/README.md),
  "Known limits"):
  * **all SPDP / SEDP between controller-side participants and the robot
    must cross the bridge**; a writer matched on `rt/lowcmd` through an
    announcement the gateway never saw (Wi-Fi, a second NIC, a modem)
    passes unchecked;
  * **DDS ports outside the queued range are not inspected**: check that
    the robot's and the controller's Cyclone DDS configuration uses the
    default port mapping of the configured domains;
  * **IP and MAC spoofing on the controller segment**: the gateway binds a
    writer's stream to its source IP and MAC (`e85471c`), but a host on the
    controller-side segment that sends with the controller's own IP and
    MAC cannot be told apart; keep only the controller on that port;
  * the loco, arm SDK, arm action, hand and ROS 2 channels have been
    tested on synthetic frames built from the SDK headers and examples
    only; hand frames are never rewritten (a frame the firewall would
    limit is suppressed); the arm-SDK engagement trusts the robot's
    `rt/lowstate`; `/cmd_vel` has no duration (the firewall's
    `state_reset_after_ns` applies, not a known stop time);
  * the gateway's events file does not reach agentd or the SOC yet.
* **Executor v1 is untested on a Unitree robot.** It has run against real
  nftables in network namespaces only. On a passive sensor box it has no
  effect, because the box is not in the path. On a humanoid with the
  shipped policy it executes nothing (section 6.1).
* **Bluetooth is invisible to Pulsar** (no HCI or AF_BLUETOOTH events): the
  rules see user-space tools, files and the processes around them, not BLE
  traffic. A worm that talks to bluetoothd over D-Bus from an interpreter
  shows up only through the other rules.
