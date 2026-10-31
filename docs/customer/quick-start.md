# RoboDR quick start

> **Pre-release draft (refreshed 2026-10-30).** RoboDR is alpha software
> (`0.1.0-alpha`). No signed release has been published yet, and nothing
> has run on a customer robot. The SOC side of the connected path (the
> AutoSecOps ingest module, control-plane client, robot pages and fleet
> API) exists on an unreleased AutoSecOps development branch.
> This page gives the order of steps. The authoritative procedures are in
> [`docs/OPERATIONS.md`](../OPERATIONS.md), and for Unitree robots in
> [`docs/UNITREE.md`](../UNITREE.md). Check what your build supports in
> [`support-matrix.md`](support-matrix.md) and
> [`known-limitations.md`](known-limitations.md) first.

RoboDR detects, records signed evidence and *requests* a safe state. It
never overrides the robot's safety system. Install it so that **nothing in
the motion stack depends on it**, and run the first field period
**observe-only**.

## 0. Choose a deployment

| | Connected site | Air-gapped site |
|---|---|---|
| Findings to the SOC | `robodr-uplink` sends signed batches over TLS from the robot or sensor box to the SOC's ingest API | `robodr-spool-export` packs signed diode batches on the robot. You carry them across the diode or on media. On the SOC side, `robodr-diode-unpack` imports them, then `robodr-uplink` forwards them under a `relay` key. |
| SIEM instead of AutoSecOps | `robodr-kafka-publish` (TLS with the brokers' CA; optional mutual TLS or SCRAM) | `robodr-kafka-publish` on the SOC side after `robodr-diode-unpack` |

| | On-robot agent | Passive sensor box |
|---|---|---|
| Where | The robot's companion computer: `robodr` on Ubuntu 22.04 / 24.04, JetPack 6, Debian 12 / 13 or EL9; `robodr-focal` on Ubuntu 20.04 / JetPack 5 ([platform requirements](support-matrix.md#platform-requirements)) | A separate box on a tap or mirror port |
| Sees | DDS traffic on that computer's interfaces, plus host behaviour if `robodr-pulsard` can run (a BTF kernel) | DDS traffic on the mirrored link. Installs nothing on the robot. |

## 1. Entry station: verify the release

Do this once per release, on the vetted machine where media enter the
site ([OPERATIONS section 2](../OPERATIONS.md)).

1. Get the RoboDR **release public key** through a channel you trust (a
   signed letter, an in-person handover, or your PKI). Never take it from
   the download or from the bundle.
2. Check `SHA256SUMS` and the offline tarball with `minisign -V`, then
   check the hashes with `sha256sum -c`.
3. Optional: scan the CycloneDX SBOM, or rebuild the pure binaries and
   compare hashes ([`docs/BUILD.md`](../BUILD.md), "Reproducible builds").

## 2. Robot or sensor box: install

Verify the tarball **before** extracting it, then run the installer from
the verified extraction (upgrades: from `/usr/lib/robodr/install-bundle.sh`,
installed by the previous release). It installs from its own private copy
of the signed tarball and refuses an extracted directory that was modified
([OPERATIONS section 3](../OPERATIONS.md)).

```sh
minisign -V -p /etc/robodr-trust/robodr-release.pub -m robodr-$V-$A-offline.tar.gz
sudo mkdir -m 0700 /root/robodr-$V && sudo tar -xzf robodr-$V-$A-offline.tar.gz -C /root/robodr-$V
sudo sh /root/robodr-$V/robodr-$V-$A/install-bundle.sh install \
    --pubkey /etc/robodr-trust/robodr-release.pub \
    --tarball robodr-$V-$A-offline.tar.gz
```

Units are installed **disabled**. Before installing, check the
[platform requirements](support-matrix.md#platform-requirements): for the
`robodr` package glibc 2.35+ and systemd 247+ (`robodr-focal`: systemd
245+), a kernel with BTF for `robodr-pulsard`, and `minisign` where the
signature is checked. RHEL / Rocky / Alma 9 use the RPM offline bundle
(`robodr-$V-$A-rpm-offline.tar.gz`) with the same commands. On a sensor
box, also follow the hardening checklist in
[UNITREE.md section 3.1](../UNITREE.md).

## 3. Keys

On the robot, generate the black-box signing key, and optionally the
finding key and the uplink or diode key:

```sh
sudo robodr-blackbox keygen --out /etc/robodr/keys/agentd-blackbox.key --key-id <robot>-bb-<date>
```

Copy only the **`.pub`** files to the SOC and the evidence verifiers, on
vetted media. Secret keys never leave the robot. The profile-signing and
trust-root keys live on an offline commissioning station, **never on the
robot** ([OPERATIONS section 4](../OPERATIONS.md)).

## 4. Commission: learn, sign off, lock

1. Capture several clean runs of every mission on an isolated network.
2. Learn a draft: `robodr-commission learn --pcap run1.pcapng ... --out draft.json`.
3. Review every sign-off item against the OEM documentation. Each operator
   signs. Motion items need the configured quorum.
4. Lock, seal and sign the profile on the commissioning station, then
   install it with the trust file
   ([OPERATIONS section 5](../OPERATIONS.md)).

Until the profile is locked and the response policy is OEM-validated,
every finding is observe-only and every response is recorded, not acted
on.

## 4a. POC fast path: observe on a draft profile

For a POC or a lab evaluation ([`poc-guide.md`](poc-guide.md)) you do not
need the full commissioning ceremony to see findings. The agent runs on a
**draft** (learned, unlocked) profile in `observe` mode; locking can wait
until the false positives on clean operation have been reviewed. Effort
figures are estimates, not timed on a customer site.

| Step | Effort | What |
|---|---|---|
| 1 | 30 min | Install (section 2) and generate the black-box key (section 3). |
| 2 | one clean run of each mission (at least 30 min each) | Capture the robot bus on the mirror port or the companion computer: `sudo tcpdump -i <if> -w run1.pcapng udp`. |
| 3 | 10 min | Learn a draft: `robodr-commission learn --pcap run1.pcapng [--pcap run2.pcapng ...] --model <model> --out /etc/robodr/profile.json --report learn-report.json`. For Unitree models, compare the draft with the matching example under `/usr/share/doc/robodr/examples/` (`robodr-commission diff profile.unitree-<model>.example.json /etc/robodr/profile.json`). |
| 4 | 30 min | Write `/etc/robodr/agentd.json` (section 5) **without** `sensor.profile_trust`, check it, start the agent. Its profile status reads `observing`; every finding carries `mode: observe`. |
| 5 | 5 min | Read the findings: from the SOC path (section 6) or the local spool (`/var/lib/robodr/spool/agentd`). |
| 6 | half a day, after the review | Lock: create a one-operator trust list for the lab (`robodr-blackbox keygen --out op.key`, then `robodr-commission operators --out operators.json --operator <name>=op.key.pub --motion-quorum 1`), confirm the sign-off items, sign them (`robodr-commission signoff ... --sign-key op.key`), then `lock`, `trust-keys`, add `sensor.profile_trust` and restart ([OPERATIONS section 5](../OPERATIONS.md)). A single operator is acceptable for a lab or POC only; production motion items need the site's quorum. |

What reports from the first minute, and what needs the draft or more
configuration, is in the [detection catalog](detection-catalog.md#what-each-detection-needs):
packet and discovery health, agent self-health and (where
`robodr-pulsard` runs) host detections need no profile content; graph and
motion rules report against the draft. There is no `poc-init` helper yet;
the steps above are manual.

## 5. Start the agent

Write `/etc/robodr/agentd.json` from the examples under
`/usr/share/doc/robodr/examples/`, check it, then start:

```sh
sudo robodr-agentd --config /etc/robodr/agentd.json --check-config
sudo systemctl enable --now robodr-agentd
```

Health: `systemctl status robodr-agentd` (STATUS line) and the daemon's
`status.json` ([OPERATIONS section 6](../OPERATIONS.md)).

**Leave `executor.enabled` at `false`** for the first field period. The
executor ([OPERATIONS section 6.5](../OPERATIONS.md)) is off by default and
should be enabled only after the response policy is OEM-validated and the
robot's motion control path, management and control buses are listed in
its configuration (examples: `config/executor.example.json`,
`config/executor.unitree-g1.example.json`; with the G1 example it runs no
network action on the humanoid).

## 6. Deliver findings to the SOC

Enable **exactly one** spool consumer. The units conflict.

**Connected** ([OPERATIONS section 8.5](../OPERATIONS.md)):

1. `sudo robodr-blackbox keygen --out /etc/robodr/keys/uplink.key`.
   Register the printed `ed25519:<16 hex>` key id in the SOC:
   - as an `uplink` key for one robot, or
   - as a `relay` key for a sensor box that watches several robots.
2. Install the SOC's CA certificate. Optionally pin the server key
   (`--spki-sha256`).
3. Fill in `/etc/robodr/uplink.env` and the `50-soc.conf` drop-in (it
   allows exactly the SOC address). Put the SOC host name in
   `/etc/hosts`, because the unit allows no DNS.
4. `sudo systemctl enable --now robodr-uplink`. Check
   `uplink-status.json` and the service STATUS for a blocked queue.

**Air-gapped** ([OPERATIONS section 8.3](../OPERATIONS.md)):

1. Robot (low side): `robodr-spool-export.service` writes signed batches
   to `/var/lib/robodr/export/diode`. It has no network at all.
2. Move the batches across the diode or on media.
3. SOC (high side): `robodr-diode-unpack` verifies them against the unit's
   public key and imports them. Then `robodr-uplink --diode-out ...`
   sends them to the ingest API under a `relay` key.

## 7. SOC side

- **AutoSecOps** receives findings at `POST /api/robot-edr/v2/ingest`
  ([`docs/contracts/robodr.ingest-api.md`](../contracts/robodr.ingest-api.md)).
  Register each robot and its keys in the workspace. The module is on an
  unreleased AutoSecOps branch; `robodr-uplink` has run against it end to
  end in one container (`tools/e2e/RESULTS.md`), not across a real
  network.
- **Enrollment** (optional): `robodr-enroll` registers the unit's keys
  with the SOC using a single-use token
  ([OPERATIONS section 8.6](../OPERATIONS.md)). The AutoSecOps side is on
  its unreleased development branch (enrollment ran end to end against it
  in one container, `tools/e2e/RESULTS.md`); until it is released,
  register keys by hand.
- **Evidence:** export black-box bundles
  ([OPERATIONS section 8.2](../OPERATIONS.md)), or through the control
  plane's evidence API, and verify them with `robodr-blackbox verify`
  (`verify BUNDLE` for an export) against the robot's `.pub`.
- **Control plane** (optional, off by default): it lets the SOC request
  the seven catalog actions over mutual TLS, with signed requests and
  answers. It **executes nothing** unless executor v1 is enabled (off by
  default; OPERATIONS section 6.5)
  ([`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md)).

## 7a. Optional: inline Motion Firewall gateway (Unitree)

The gateway puts a bridged sensor box into the controller cable and
enforces the joint and sport envelopes
([OPERATIONS section 6.6](../OPERATIONS.md),
[UNITREE.md section 5.1](../UNITREE.md),
[`crates/robodr-firewall-gw/README.md`](../../crates/robodr-firewall-gw/README.md)).
It is not validated on a robot. Before you install it:

1. **All discovery crosses the bridge.** The robot must have no other
   link (Wi-Fi, a second NIC, a cellular modem) that reaches
   controller-side participants: every SPDP / SEDP must cross the bridge,
   or a writer the gateway never classified passes unchecked.
2. **DDS ports.** Capture the ports the robot and the controller use and
   check they are inside the queued range of the configured
   `rtps.domain_ids` (7400 + 250·d .. +249). A non-default Cyclone DDS
   port or participant-index setting bypasses the queue.
3. **Controller segment.** Only the controller on the controller-side
   port. Set `allowed_src_ips` and `allowed_src_macs` on every channel; a
   host on that segment that spoofs the controller's IP and MAC cannot be
   told apart.
4. **Loss of the command stream.** Confirm with the OEM what the robot
   does when commands stop: with `fail_closed` (default) a stopped
   gateway hands over to the robot's own command timeout. `bypass` is
   refused for a humanoid joint channel.
5. **Humanoid rules.** On a humanoid joint channel the gateway forwards
   only accepted frames or holds of the last accepted one, never damping
   or limp frames. List in `allowed_api_ids` only the sport calls your
   controller uses (`Damp` makes a Go2 go limp).
6. **Latency.** Measure on your box with the gateway's latency harness
   (`crates/robodr-firewall-gw/examples/gw_latency.rs`, `--budget-p99-ns`);
   the published figures are from a development VM.
7. Run `robodr-firewall-gw check-config`, start in `mode: observe`,
   compare the would-have verdicts with the robot's behaviour, and only
   then switch to `enforce`.

## 8. Before you rely on it

- Run observe-only for the first field period (executor disabled,
  gateway in `mode: observe`), and review false positives with your
  RoboDR contact.
- Read [`known-limitations.md`](known-limitations.md) and the
  [`security-whitepaper.md`](security-whitepaper.md).
- Report vulnerabilities as described in [`SECURITY.md`](../../SECURITY.md)
  and [`psirt-process.md`](psirt-process.md).
