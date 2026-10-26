# RoboDR on Unitree robots

This guide covers protecting Unitree robots (Go2, B2, G1, H1 and their
relatives) with RoboDR: which models and generations are covered, the two
deployment modes, installation, commissioning, what the Unitree rules
detect, and what is not covered yet. General procedures (verifying a
release, keys, the full commissioning flow, upgrades, evidence export) are
in [`OPERATIONS.md`](OPERATIONS.md); this guide refers to them by section.

> **Scope: protective only.** RoboDR detects, records signed evidence and
> *requests* a safe state through the platform's own interface. It never
> overrides the robot's safety system, e-stop or command authority, and on a
> Unitree robot it is never in the path of `rt/lowcmd`.

> **Status: not validated on a real robot.** The decoders, rules and
> examples below are built from Unitree's published SDK sources and IDL, and
> checked against hand-built and reviewer vectors. None of it has run against
> a real Go2 or G1 yet (see [Known limits](#known-limits)). Run the first
> field period observe-only.

---

## 1. Supported models and generations

RoboDR decodes two generations of Unitree traffic:

* **SDK2 / DDS** (`unitree_sdk2`, `unitree_ros2`, Cyclone DDS 0.10.x): Go2,
  Go2-W, B2, B2-W, A2, AS2, H1, H1-2, H2, G1, R1. The low-level loop is a DDS
  writer of `rt/lowcmd`; high-level control is the request/response API on
  `rt/api/<service>/request`.
* **Legacy UDP** (`unitree_legged_sdk` v3.8.6): Go1 high-level frames.
  A1, Aliengo and B1 are known by frame layout only.

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
| Where it runs | A separate arm64 or amd64 box with two NICs, on a tap or switch mirror port of the robot network (192.168.123.0/24) | The EDU development computer inside the robot (Jetson, arm64) |
| Touches the robot | No: no software on the robot, no firmware change | Installs a package on the development computer |
| Models | **All**, and the **only** option for Air / Pro and any model whose computers you cannot install software on | EDU models only (the main motion controller is closed) |
| Sees | DDS discovery and data on the mirrored link: participants, writers of `rt/lowcmd` and the other profiled topics, API requests, decoded motion where the channel is wired | The same for the development computer's own interface, **plus** host behaviour on the development computer (the Pulsar rules, section 7) |
| Privileges | `robodr-agentd` with `CAP_NET_RAW` only, all IP denied | `robodr-agentd` as above, plus `robodr-pulsard` (root, bounded capabilities, eBPF) |

Both modes can run together: an EDU agent on the development computer and a
sensor box on the robot's uplink.

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

1. **Prepare the box.** Ubuntu 22.04 or 24.04 (the package needs glibc 2.35
   and systemd 247 or newer; `Promiscuous=` in systemd-networkd needs 248),
   installed with full-disk encryption. Work through the
   [hardening checklist](#sensor-box-hardening-checklist) before connecting
   it to the robot.
2. **Install the bundle** ([OPERATIONS.md section 3](OPERATIONS.md#3-install-on-an-air-gapped-host)):

   ```sh
   sudo ./install-bundle.sh install \
       --pubkey /etc/robodr-trust/robodr-release.pub \
       --tarball ../robodr-$V-$A-offline.tar.gz
   ```

   The units are installed disabled. `robodr-pulsard` is not needed for the
   robot (it watches the host it runs on); enabling it on the box to watch
   the box itself is optional.
3. **Capture NIC: silent and promiscuous.** Copy the networkd example, set
   the interface name, and apply it:

   ```sh
   E=/usr/share/doc/robodr/examples
   sudo install -D -m 0644 $E/sensor-box/10-robodr-capture.network.example \
       /etc/systemd/network/10-robodr-capture.network
   sudoedit /etc/systemd/network/10-robodr-capture.network   # [Match] Name=
   sudo networkctl reload && sudo networkctl reconfigure enp2s0
   ip -d link show enp2s0      # PROMISC and NOARP, state UP
   ip addr show enp2s0         # no inet / inet6 lines
   ```

   `robodr-agentd` never enables promiscuous mode itself and has no
   `CAP_NET_ADMIN`; without it the NIC drops the mirrored frames that are
   addressed to other hosts.
4. **Host firewall.** Copy `$E/sensor-box/nftables.conf.example` to
   `/etc/nftables.conf`, set the interface names, the SOC collector, the NTP
   server and the admin network, check it with `sudo nft -c -f
   /etc/nftables.conf`, then `sudo systemctl enable --now nftables`. The
   capture NIC is dropped in both directions (this does not affect capture:
   AF_PACKET sees frames before netfilter), the uplink only reaches the
   collector, NTP and admin SSH, and nothing is forwarded.
5. **Keys** as in [OPERATIONS.md section 4](OPERATIONS.md#4-keys).
6. **agentd configuration.** Start from
   `$E/agentd.unitree-sensor-box.example.json`: capture enabled on the
   capture NIC only, no `control_plane`, no `event_inputs` from a local
   Pulsar. Install it as `/etc/robodr/agentd.json` (`0640 root:robodr`) and
   check it:

   ```sh
   sudo robodr-agentd --config /etc/robodr/agentd.json --check-config
   ```

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
- [ ] **Uplink firewall**: default drop; out only to the SOC collector and
      NTP by address (no DNS); in only SSH from the admin network
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

1. **Check the development computer.** The package needs arm64 Ubuntu with
   **glibc 2.35 and systemd 247 or newer** (Ubuntu 22.04 or later), a kernel
   with BTF for `robodr-pulsard`, and bpffs:

   ```sh
   lsb_release -ds; ldd --version | head -1; systemctl --version | head -1
   test -e /sys/kernel/btf/vmlinux && echo BTF ok
   findmnt -t bpf /sys/fs/bpf
   ```

   Development computers on an Ubuntu 20.04-based image (glibc 2.31,
   systemd 245) cannot install the package; use a sensor box for them. A
   kernel without BTF cannot run `robodr-pulsard`; `robodr-agentd` still
   works. Check with Unitree whether installing software on the development
   computer affects warranty or support terms.
2. **Install the bundle** as in step 2 of section 3.1.
3. **agentd configuration.** Start from `$E/agentd.unitree-edu.example.json`:
   capture on the development computer's interface on 192.168.123.0/24 (TUNE
   the name). Install and check it as in step 6 of section 3.1. Do **not**
   install the sensor-box drop-in here.
4. **Host rules.** `robodr-pulsard` loads every rule under
   `/usr/share/robodr/rules`, including `robodr/unitree.toml`. Set the
   TUNE values (section 7) in the rule source, validate it
   (`python3 scripts/validate_rules.py --strict --pulsar-src vendor/pulsar`)
   and ship it in a signed bundle. Do not edit the installed rule files: the
   edit fires the self-protection rules and the next upgrade replaces it.
   To get Pulsar's threats into agentd's findings and correlation, enable
   the host-threat input ([OPERATIONS.md section 6.4](OPERATIONS.md#64-agentd-features-etcrobodragentdjson), "Host threats").
5. **SDK locations.** The library-load and Python-import rules
   (`runtime_hooking.toml`) fire when an rclpy node or `python3` loads code
   from outside the allowlisted trees, which includes `unitree_sdk2_python`
   and a `unitree_ros2` workspace in a home directory. Install the SDKs into
   the image at commissioning (system site-packages, `/opt/unitree_robotics`)
   or add their directories to those rules' TUNE lists.
6. **Commission** (section 4), then enable: `sudo systemctl enable --now
   robodr-pulsard robodr-agentd`.

## 4. Commissioning: learn, then lock

The full procedure, with the two-person sign-off and profile signing, is
[OPERATIONS.md section 5](OPERATIONS.md#5-commissioning-learn-sign-off-lock).
For Unitree:

1. **Record clean runs** on an isolated network, covering every mode the
   robot uses (stand, walk, sport modes, arm or hand use, docking). On the
   sensor box capture on the capture NIC; on the EDU computer capture on its
   robot-network interface:

   ```sh
   sudo tcpdump -i enp2s0 -w run1.pcapng udp
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

## 5. Joint envelopes (Motion Firewall): recording only

`config/firewall.unitree-{g1,go2}.example.json` define per-motor limits for
the low-level frames: position, velocity, torque, gains, per-frame step, the
LowCmd CRC, the allowed writer of `rt/lowcmd`, the frame rate, and on G1 the
pinned ankle mode; a humanoid frame that commands every joint limp is
rejected. The decision logic and its tables are in
[`crates/robodr-firewall/README.md`](../crates/robodr-firewall/README.md).

**There is no in-path gateway yet.** Nothing subscribes to `rt/lowcmd` and
republishes filtered frames, so a frame outside the envelope is **reported**
(`robot.firewall.joint_*`, `crc_invalid`, `disabled_motor_energised`
findings, contract 2.1) but still reaches the motors. Treat the envelopes as
detection and evidence, never as protection. Take the limits from Unitree's
data for your hardware revision; the example values are illustrative.

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

Start from `config/response-policy.unitree-{g1,go2}.example.json`; both are
`oem_validated: false`, so every response is recorded, not acted on, until
the policy is validated with Unitree's safety data.

## 7. What the Unitree rules detect

`rules/robodr/unitree.toml` (Pulsar host rules, EDU agent mode only)
complements `radio_provisioning.toml` (Bluetooth / Wi-Fi tools and wireless
configuration files) and the generic rule files. The full table with false
positives is in [`rules/README.md`](../rules/README.md#unitreetoml-unitree-hosts-unipwn-2025-g1-telemetry-go1-tunnel).

| Threat (public research) | What fires |
|---|---|
| **UniPwn** (Makris & Finisterre, Sept 2025, CVE-2025-35027): hardcoded keys in the BLE Wi-Fi provisioning service and command injection into `wpa_supplicant_restart.sh`, giving root; wormable across Go2, B2, G1 and H1 | the provisioning script running at all (medium: audit trail of every BLE re-provisioning); the script's own process or bluetoothd opening an IP connection (critical: an injected `/dev/tcp` reverse shell); planted Bluetooth bonding keys or a relaxed pairing policy; plus the BlueZ / Wi-Fi tool and wireless-config rules in `radio_provisioning.toml` |
| Reported **G1 telemetry** to external servers | a Unitree process (under `/unitree/`, `/opt/unitree_robotics/` or an SDK tree) connecting outside the destination allowlist |
| The earlier **Go1 remote-tunnel backdoor** (a CloudSail-like vendor tunnel) and post-exploitation tunnels | reverse-tunnel clients (frpc, cloudflared, bore, rathole, ...), `ssh` / `dbclient` reverse or SOCKS tunnels in bundled form, overlay VPNs, and new, replaced or enabled systemd units, init scripts, `rc.local` and autostart entries |
| Tampering with the robot's middleware | writes, renames and links of Cyclone DDS configuration (`*cyclonedds.xml`, the `unitree_ros2` setup scripts that set `CYCLONEDDS_URI`) and of the Unitree SDK and Cyclone DDS libraries |

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
script being run and what its own process does, and the SOC correlates
`parent_pid`. Running the script as `sh /full/path/wpa_supplicant_restart.sh`
is a known gap of the script rule.

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
  On an air-gapped site, `robodr-spool-export` packs them into signed diode
  batches ([OPERATIONS.md section 8](OPERATIONS.md#8-log-and-evidence-export-via-the-diode)); on a connected
  site (for example the sensor box's uplink), `robodr-kafka-publish` sends
  them to the `robodr.findings` topic. agentd itself never opens an IP
  connection; restrict the exporter to the collector address.

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
* **Go2 app channel (WebRTC) is not decoded.** The mobile app's channel is
  encrypted media/data over WebRTC; RoboDR does not see its content, and on
  Wi-Fi or cellular it is not on the Ethernet link at all.
* **Telemetry over Wi-Fi or cellular** is not on the Ethernet link the
  sensor box watches, and agentd's capture analyses DDS (and legacy Unitree
  UDP) only, not general IP flows. The host rule sees outbound connections
  only on the EDU computer. Watch the site's Wi-Fi / firewall logs for the
  robot's own external traffic.
* **Legacy Go1 "compressed" low-level frames** (`unitree_legged_sdk`
  v3.8.6, 614 / 807 bytes) have no published layout and are reported as
  undecodable; A1 / Aliengo / B1 layouts are not in the sources.
* **A2 / AS2**: no low-level example is published, so their motor count,
  IDL family and model-specific API ids are unknown; only the sport state
  and sport client are covered.
* **No in-path gateway**: joint envelopes record, they do not block
  (section 5). There is no `restrict_motion` adapter for the sport API yet.
* **Bluetooth is invisible to Pulsar** (no HCI or AF_BLUETOOTH events): the
  rules see user-space tools, files and the processes around them, not BLE
  traffic. A worm that talks to bluetoothd over D-Bus from an interpreter
  shows up only through the other rules.
