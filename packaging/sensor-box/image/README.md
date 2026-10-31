# RoboDR sensor box image recipe

An [mkosi](https://github.com/systemd/mkosi) recipe for the passive
sensor box (docs/UNITREE.md section 3.1): Ubuntu 24.04 with the `robodr`
package from a **signed** offline bundle, a **read-only root**, and keys
**generated on the box at first boot**. It implements the hardening
checklist of UNITREE.md 3.1 as far as an image can.

> **Status:** the recipe, its scripts and the build wrapper are tested in
> the repository (`crates/robodr-ops/tests/sensor_box_image.rs` runs the
> boot scripts and `build-image.sh` against stubs;
> `scripts/check-packages.py` check 12 keeps the invariants below). An image
> has **not yet been built and booted on the reference hardware**: that is
> sales-readiness item B7 (fanless box with two Intel NICs and a passive
> tap). Until then treat it as a starting point, not a product.

## Build

```sh
packaging/sensor-box/image/build-image.sh \
    --bundle robodr-$V-amd64-offline.tar.gz \
    --pubkey /etc/robodr-trust/robodr-release.pub \
    --expect-version $V \
    --out dist/sensor-box
```

`build-image.sh` checks the bundle's minisign signature against the
release key you hold (out of band, never from the download; a key next to
the bundle is refused) **before** extracting anything, and the signature's
signed trusted comment: it must name the bundle's file name (a correctly
signed older bundle renamed to look like a newer one is refused) and, with
`--expect-version`, be exactly `robodr $V <file>` as `release.yml` signs it
(an older release is not built by mistake). Then it checks the bundle's
`SHA256SUMS`, takes its one `robodr_*.deb`, and runs mkosi with it. The
recipe's post-install script checks the package digest again before
installing it. There is no switch to build from an unsigned bundle.

## What is in the image

| | |
|---|---|
| Partitions | ESP (systemd-boot), **root read-only** (GPT read-only flag and `ro`), `/var` writable (label `var`, `nodev,nosuid`, grown to the disk at first boot), `/tmp` tmpfs |
| Packages | kernel, systemd (networkd, timesyncd), nftables, iproute2, minisign, tpm2-tools, tcpdump, `robodr`; no SSH server, no compiler, no desktop |
| RoboDR | `robodr-agentd` with the sensor-box drop-in (`CAP_NET_RAW` only, no IP) active; all RoboDR units **disabled** (see "Boot") |
| Host | no forwarding, no IPv6 autoconfiguration (sysctl), `/etc/nftables.conf` -> `/etc/robodr/nftables.conf`; `nftables.service` loads it through `robodr-nft-load` (drop-in), which falls back to the shipped strict default |
| Not in the image | keys, machine id, SSH host keys, random seed, site configuration (the post-install script fails the build if `/etc/robodr/keys` is not empty) |

## Provisioning

Each box needs a unit id and its capture NIC. Give them either on the
kernel command line of the first boot (for example from the installer or
the boot menu):

```
robodr.unit_id=sensorbox-07 robodr.capture_if=enp2s0 robodr.uplink_if=enp1s0 \
robodr.site=plant-a robodr.ntp=192.0.2.123 robodr.exporter=uplink
```

or as `/etc/robodr/provision.env` (`KEY=VALUE` lines: `ROBODR_UNIT_ID`,
`ROBODR_CAPTURE_IF`, `ROBODR_UPLINK_IF`, `ROBODR_SITE`, `ROBODR_NTP`,
`ROBODR_ROLE` = `unitree-sensor-box` (default) or `robot`,
`ROBODR_EXPORTER` = `none` | `uplink` | `kafka-publish` | `spool-export`).
Every value is validated; the file is parsed, never sourced.

`robodr.ntp` / `ROBODR_NTP` must be an **IP address** (IPv4 dotted quad,
or IPv6 including `::ffff:192.0.2.1`; no zone index), not a host name: the
strict default firewall lets no DNS out, so a name would never resolve and
the clock would never be set. A host name or a malformed address
(`999.1.1.1`, `:::`) is ignored with a message in the journal. The root is read-only, so there is no other
place for an NTP setting on the box.

## Boot

1. `robodr-etc-overlay.service`: `/etc/robodr` becomes writable as an
   overlay whose upper layer is on `/var`
   (`/var/lib/robodr-image/etc-robodr/upper`). Everything the box writes
   (provisioning, configuration, keys, profile, firewall) persists there.
2. `robodr-image-early.service` (before networking): first the **strict
   default firewall** (loopback, DHCP and NTP only; the box records but
   delivers nothing until the site installs its own
   `/etc/robodr/nftables.conf` from the example); then the provisioning
   file from the kernel command line at first boot; the capture NIC's
   networkd file under `/run` (silent, promiscuous, `Name=` from
   provisioning); the uplink by DHCP, or the site's own
   `/etc/robodr/network/*.network`; NTP. It fails (and
   `robodr-image-late` does not run) only when it cannot write, e.g. when
   the `/etc/robodr` overlay is missing.
   `nftables.service` runs after it and loads `/etc/robodr/nftables.conf`
   through `robodr-nft-load`; when that file is missing or `nft` refuses
   it, the shipped strict default is loaded instead and the unit fails
   visibly: the box never comes up without a host firewall. This relies on
   systemd not running `nftables.service`'s `ExecStop=` (`nft flush
   ruleset`) when its `ExecStart=` fails. Checked on 2026-10-31 under
   systemd 255 with Ubuntu 24.04's own `nftables.service`, this drop-in and
   the real `nft` in a container (not yet on a built image, B7): with the
   site file missing or refused the unit is `failed` and the strict default
   stays loaded; a refused file on `systemctl reload` loads the strict
   default, the reload fails and the unit stays `active`.
3. `robodr-image-late.service`: at **first boot**, `robodr-setup init`
   (host preflight, then the black-box key bound to the unit id, then
   `agentd.json` for the role). A failed preflight check stops it with
   nothing written; the unit fails visibly and runs again at the next boot.
   The key fingerprints are printed on the console and kept in
   `/var/lib/robodr-image/fingerprints.txt`: register them with the SOC.
   At **every boot** it starts `robodr-agentd` once the box is
   commissioned (`/etc/robodr/profile.json` installed, OPERATIONS.md
   section 5), and the exporter named by `ROBODR_EXPORTER` once its
   settings file (`/etc/robodr/<exporter>.env`) exists. Units are started
   for the boot, not enabled: `/etc/systemd/system` is on the read-only
   root.

## Updates

The root is never written on the box, so `install-bundle.sh` does not run
there: an update is a new image built from the new signed bundle and
written to the box (or an A/B scheme with `systemd-sysupdate`, not part of
this recipe yet). `/var` (keys, black box, spool, configuration) is kept
across a re-flash of the root and ESP partitions.

## Known gaps (to close on the reference hardware, B7)

* **Encryption.** `/var` holds the keys and the evidence and is not
  encrypted by this recipe; `robodr-image-late` warns when `/var` is not on
  dm-crypt. Bind a LUKS2 `/var` to the box's TPM (`systemd-cryptenroll
  --tpm2-device=auto`) on the reference hardware and record the PCR policy.
* **Measured / verified boot.** No Secure Boot signing and no dm-verity of
  the root yet (mkosi supports both; the keys are a release-process
  decision, C1).
* **Machine id.** With a read-only root and an empty `/etc/machine-id`,
  systemd uses a transient machine id each boot; the persistent journal
  then starts a new directory per boot. Set a persistent id at
  provisioning if the site needs one.
* Not yet built or booted (no mkosi in the development environment).
