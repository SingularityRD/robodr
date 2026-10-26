# RoboDR quick start

> **Pre-release draft (2026-10-26).** RoboDR is alpha software
> (`0.1.0-alpha`). No signed release has been published yet, and nothing
> has run on a customer robot. The SOC side of the connected path (the
> AutoSecOps ingest module) is not available yet (GA-ROADMAP Sprint 3).
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
| SIEM instead of AutoSecOps | `robodr-kafka-publish` (no TLS: keep it on an isolated segment) | `robodr-kafka-publish` on the SOC side after `robodr-diode-unpack` |

| | On-robot agent | Passive sensor box |
|---|---|---|
| Where | The robot's companion computer (Ubuntu 24.04, or `robodr-focal` on 20.04 / 22.04) | A separate box on a tap or mirror port |
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

```sh
tar -xzf robodr-$V-$A-offline.tar.gz && cd robodr-$V-$A
sudo ./install-bundle.sh install \
    --pubkey /etc/robodr-trust/robodr-release.pub \
    --tarball ../robodr-$V-$A-offline.tar.gz
```

Units are installed **disabled**. Before installing, check the
requirements: kernel with BTF for `robodr-pulsard`, systemd 247+, glibc
2.39 for the regular package ([OPERATIONS section 1](../OPERATIONS.md)). On
a sensor box, also follow the hardening checklist in
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

## 5. Start the agent

Write `/etc/robodr/agentd.json` from the examples under
`/usr/share/doc/robodr/examples/`, check it, then start:

```sh
sudo robodr-agentd --config /etc/robodr/agentd.json --check-config
sudo systemctl enable --now robodr-agentd
```

Health: `systemctl status robodr-agentd` (STATUS line) and the daemon's
`status.json` ([OPERATIONS section 6](../OPERATIONS.md)).

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
  Register each robot and its keys in the workspace. **Not available
  yet** (Sprint 3).
- **Evidence:** export black-box bundles
  ([OPERATIONS section 8.2](../OPERATIONS.md)) and verify them with
  `robodr-blackbox verify` against the robot's `.pub`.
- **Control plane** (optional, off by default): it lets the SOC request
  the seven catalog actions. In this release it **executes nothing** and
  has no TLS. Keep it on loopback or a unix socket, behind a TLS
  terminator ([`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md)).

## 8. Before you rely on it

- Run observe-only for the first field period, and review false
  positives with your RoboDR contact.
- Read [`known-limitations.md`](known-limitations.md) and the
  [`security-whitepaper.md`](security-whitepaper.md).
- Report vulnerabilities as described in [`SECURITY.md`](../../SECURITY.md)
  and [`psirt-process.md`](psirt-process.md).
