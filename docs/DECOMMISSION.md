# Decommissioning a RoboDR unit

This is the end-of-life checklist for one unit (a robot, or its companion
computer, or a sensor box), in the order the steps must run. It also covers
a unit that changes owner (`transfer`) or goes back to the vendor
(`repair`). Each step names what proves it was done; collect those proofs in
the site's decommission record.

The package never deletes evidence or keys by itself, not even on
`apt purge`. Everything below is a deliberate operator act.

Contract of the SOC step: [`contracts/robodr.fleet-api.md`](contracts/robodr.fleet-api.md)
§5.6. Tools: `robodr-enroll(8)`, `robodr-blackbox(1)`, `robodr-depot(8)`,
`robodr-seal(8)`, `robodr-anchor-receiver(8)`.

## 0. Before you start

* Two people: one runs the steps, one records them (site log).
* The unit is in a **safe state** (parked, motors off, e-stop engaged):
  step 3 changes the command path.
* Lost, stolen or suspected-compromised unit: do **not** run this on the
  unit. Retire its keys at the SOC from the SOC side (operator action, no
  request from the unit), revoke it at the depot (step 5) and at the anchor
  receiver (step 6), and treat its last evidence as an incident.

## 1. Export and verify the evidence

Everything the unit recorded must be held, verified, on the far side
before anything is destroyed (OPERATIONS section 8).

1. Let `robodr-uplink` drain: `<state-dir>/uplink-status.json` shows
   `state: ok`, no `pending_batch_id` and an empty `backlog`, and no dead
   letters you still need. After step 4 the unit's keys authenticate
   nothing and undelivered findings can no longer be sent.
2. Export every black-box chain (OPERATIONS 8.2: bundles over the
   control plane, or a copy of the directories on vetted media):
   `/var/lib/robodr/blackbox/agentd`, and where they exist
   `/var/lib/robodr/blackbox/pulsard` and `/var/lib/robodr/blackbox/deliverd`,
   and the fleet journal (`/var/lib/robodr/fleet/journal`). Export with
   them **every black-box public key** that signed part of a chain: the
   current ones and every key retired by a rotation (OPERATIONS 4.3 keeps
   them in `/etc/robodr/keys/retired/`). Step 8 destroys
   `/etc/robodr`, and a chain that spans a rotation verifies only with
   all of its keys:

   ```sh
   mkdir -p /media/vetted/ugv-07-pub
   sudo find /etc/robodr/keys -name '*blackbox*.key.pub' -exec cp -t /media/vetted/ugv-07-pub/ {} +
   ```

   A retired legacy HMAC key has no `.pub`; such a chain verifies only
   with the retired secret key: verify it on the unit before step 8, or
   move that key into the site's key custody with the export.
3. Verify each copy on the far side with all of those keys (each record is
   checked under the key its chain names; extra keys do no harm):

   ```sh
   set --
   for k in ugv-07-pub/*.pub; do set -- "$@" --keyring "$k"; done
   for d in blackbox/agentd blackbox/pulsard blackbox/deliverd fleet/journal; do
     if [ -d "$d" ]; then robodr-blackbox verify "$d" "$@" || echo "FAILED: $d"; fi
   done
   ```

4. Proof: the far side's verification report for each chain (intact, last
   sequence number), signed or countersigned per the site's rules. This is
   the **first** export: steps 2 and 4 still write to the unit's chains
   (the services' shutdown records, the decommission note), and step 4a
   exports them again.

## 2. Stop every RoboDR service

The set of units differs per package and site (`robodr-focal` has no
`robodr-pulsard` or `robodr-anchor-receiver`; `robodr-metrics.timer`
starts `robodr-metrics.service` every 15 s where it is enabled), and
`systemctl disable --now` with a unit that is not installed fails before
it stops anything. So stop what is installed, one unit at a time, timers
first. The inline gateway's two units stay up until step 3 takes it out of
the motion path, and on the sensor-box image the image's own units
(`robodr-etc-overlay`, `robodr-image-*`) stay (`/etc/robodr` lives on its
overlay until step 8):

```sh
for u in $(systemctl list-unit-files 'robodr-*.timer' --no-legend | awk '{print $1}') \
         $(systemctl list-unit-files 'robodr-*.service' --no-legend | awk '{print $1}'); do
  case "$u" in
    robodr-firewall-gw.service|robodr-firewall-gw-rules.service) continue ;;  # step 3
    robodr-etc-overlay.service|robodr-image-*.service) continue ;;            # image, step 8
  esac
  # disable fails on a read-only /etc/systemd/system (image): stop then
  sudo systemctl disable --now "$u" || sudo systemctl stop "$u" || echo "CHECK: $u"
done
# check: prints nothing (inline units: only the two gateway units)
systemctl list-units 'robodr-*' --all --plain --no-legend |
  awk '$3 != "inactive" && $3 != "failed"' |
  grep -v -e '^robodr-firewall-gw' -e '^robodr-etc-overlay' -e '^robodr-image-' || true
```

A host that also serves other units (a site depot, an anchor receiver for
the fleet) keeps those running: take them out of the loop. On the
sensor-box image `disable` fails (`/etc/systemd/system` is on the
read-only root) and the loop only stops the units; `robodr-image-late`
starts agentd and the exporter again at the next boot, so do not reboot
the box before step 8 (or run this step again after a reboot).

The executor removes its own nft table on package removal; stop it here so
no action is still in force (`nft list table inet robodr` must be empty or
absent).

## 3. Take the inline gateway out of the path (inline units only)

Stopping `robodr-firewall-gw` does **not** take it out of the path: its
rules stay and, with `on_gateway_down: fail_closed` (default), the bridge
keeps dropping motion commands; `apt purge` leaves them too (OPERATIONS
6.6). Stopping `robodr-firewall-gw-rules` removes nothing either: it has
no stop action by design, and the package ships no teardown. The ruleset
(`robodr-firewall-gw ruleset --config /etc/robodr/firewall-gw.json` prints
it) installs, in the gateway box's network namespace:

* jumps from `FORWARD` to the chains `ROBODR_GW` (queue), `ROBODR_GW_OBS`
  (observe copies) and, with `webrtc`, `ROBODR_GW_RTC`, and jumps from the
  `raw` table's `PREROUTING` to `ROBODR_GW_RAW`, all matched on the bridge
  ports (`physdev`);
* the nft bridge table `robodr_gw_l2` (drops everything but IPv4 and ARP
  from the controller port: IPv6, VLAN and PPPoE stay blocked while it is
  there) and, with `webrtc`, `robodr_gw_rtc`;
* the `net.bridge.*` sysctls (`bridge-nf-call-iptables`, `-ip6tables`,
  `-arptables`, `bridge-nf-filter-vlan-tagged`, `-pppoe-tagged` set to 1;
  runtime values only, not written to any sysctl file).

A chain cannot be deleted while a jump to it remains, so the jumps go
first. With the unit in a safe state, as root:

```sh
systemctl disable --now robodr-firewall-gw robodr-firewall-gw-rules
# queue.controller_port and queue.robot_port of /etc/robodr/firewall-gw.json:
CTRL=enp2s0 ROBOT=enp3s0
IPT=iptables   # the variant the ruleset ran with (its IPTABLES variable)
while $IPT -D FORWARD -m physdev --physdev-in "$CTRL" -j ROBODR_GW 2>/dev/null; do :; done
while $IPT -D FORWARD -m physdev --physdev-in "$CTRL" -j ROBODR_GW_RTC 2>/dev/null; do :; done
while $IPT -D FORWARD -m physdev --physdev-in "$ROBOT" -j ROBODR_GW_OBS 2>/dev/null; do :; done
for P in "$CTRL" "$ROBOT"; do
  while $IPT -t raw -D PREROUTING -m physdev --physdev-in "$P" -j ROBODR_GW_RAW 2>/dev/null; do :; done
done
for C in ROBODR_GW ROBODR_GW_OBS ROBODR_GW_RTC; do
  if $IPT -n -L "$C" >/dev/null 2>&1; then $IPT -F "$C"; $IPT -X "$C"; fi
done
if $IPT -t raw -n -L ROBODR_GW_RAW >/dev/null 2>&1; then
  $IPT -t raw -F ROBODR_GW_RAW; $IPT -t raw -X ROBODR_GW_RAW
fi
nft delete table bridge robodr_gw_l2 2>/dev/null || true
nft delete table bridge robodr_gw_rtc 2>/dev/null || true
# check: both print 0 (the count of what is left; `|| true` because grep
# exits 1 when it counts nothing, which is the success case here)
$IPT-save | grep -c ROBODR || true
nft list tables | grep -c robodr_gw || true
```

Then remove the bridge / re-cable the motion link as it was before
commissioning (site wiring record), and set the five `net.bridge.*`
sysctls back to the values in that record (or reboot: with the rules unit
disabled nothing sets them again; if `/etc/modules-load.d/robodr.conf`
was installed for the gateway, remove its `br_netfilter` line first).

Proof: the two `0` counts of the checks above, and a motion command reaching
the actuator controller without the gateway (bench test), recorded in the
site log.

## 4. Retire the unit's keys at the SOC

```sh
sudo robodr-enroll check                                   # the SOC is reachable, the key accepted
sudo robodr-enroll decommission --reason end_of_life \
    --receipt-out /media/vetted/ugv-07-decommission.json
```

The request names the unit's registered uplink, finding and black-box keys
and is signed by all three; the SOC retires every key of the unit and
answers with a signed receipt. The command then writes a
`robodr.fleet.decommission` note into the fleet journal (signed by the
black-box key), **shreds the uplink and finding secret keys** and removes
the enrollment. The black-box key stays until step 8.

* `--reason`: `end_of_life`, `transfer` or `repair`.
* Air-gapped unit: `--request-out FILE`, carry it to the SOC, import it
  there, carry the answer back, `robodr-enroll decommission --answer FILE
  --receipt-out FILE`. The request file has no expiry: whoever imports it
  retires the unit's keys. Keep it in custody like the evidence export
  and delete it from the media once the answer is back (fleet-api §5.6,
  "Request age and request files").
* Network down or no answer: run the same command again; the stored
  request is resent unchanged and the SOC answers with its stored answer.
  A request that may have reached the SOC is never dropped on the unit.
* Refused while a key rotation is unfinished: finish it (`robodr-enroll
  rotate --role R --finish`) or cancel it (`--cancel`) first.

Proof: the receipt (`robodr-fleet-decommission-receipt/v1`: the request
signed by the unit's three keys and the answer signed by the SOC fleet
key), archived with the site's records. `robodr-enroll status` shows the
decommission as `Done`.

## 4a. Export the evidence again

Step 1's export predates the services' shutdown records (step 2) and the
`robodr.fleet.decommission` note (step 4), and step 8 destroys both on the
unit. Export the chains and the fleet journal again exactly as in step 1
(the black-box key is still on the unit; the public keys of step 1 still
apply) and verify them on the far side. Then, on the far side,
`robodr-blackbox inspect fleet/journal` must list the note: its payload
names `robodr.fleet.decommission` (`inspect` checks no signature: run it
only on the copy that verified).

Proof: the verification report of this second export, with the last
sequence number of each chain and the decommission note's. **Step 8 does
not start without it.**

## 5. Revoke the unit at the site depot (secure delivery)

If the unit is enrolled at a site depot (SECURE-DELIVERY §6), revoke it so
the depot never builds or serves another pack for it:

```sh
robodr-depot --config /etc/robodr-depot/depot.json unit revoke --unit ugv-07 \
    --key op-a.key --key op-b.key
robodr-depot --config /etc/robodr-depot/depot.json inventory   # the unit shows revoked
```

Proof: the inventory line, and the two operators who signed.

## 6. Remove the unit from the anchor receiver

On the base station / fleet host running `robodr-anchor-receiver`:

1. Remove the unit's entry from `receiver.json` `units`. A running
   receiver reloads its unit list when the file (or a unit key file)
   changes; the log says `unit list reloaded`. From then on marks and
   queries for the unit are refused (`unknown unit`).
2. Archive `<state_dir>/units/<unit>.json` (the last head the receiver
   held: part of the evidence) with the step-1 export, then delete it.
3. Delete the unit's black-box public key from
   `/etc/robodr-anchor-receiver/units/`.
4. If the unit had a TLS client certificate for the receiver: revoke it at
   the units' CA and publish the CRL the receiver reads
   (`tls.crl_files`).

Proof: `robodr-anchor-receiver status --config FILE` no longer lists the
unit; the CRL serial.

## 7. Release the unit's TPM resources

Only on units that use them; the owner hierarchy authorisation is needed
(keep it off the unit, OPERATIONS 4).

* Black-box head anchor NV counter (agentd `blackbox.head_anchor.nv_index`,
  e.g. `0x01500020`):
  `tpm2_nvundefine 0x01500020 -C o -P file:owner.auth`
  and remove its sidecar (`head_anchor.sidecar_path`).
* Sealed delivery keys (SECURE-DELIVERY §7): `robodr-seal erase --seal-dir
  /var/lib/robodr/seal --trigger decommission ...` increments the erase
  epoch, so every key sealed to the unit is dead; then the seal NV indices
  (`--epoch-nv`, `--floor-nv`, defaults `0x01500040`, `0x01500041`) can be
  undefined the same way.
* For a `transfer` or `repair` that leaves the unit's TPM in other hands:
  `tpm2_clear` with the lockout authorisation, as the last TPM step.

Proof: `tpm2_getcap handles-nv-index` no longer lists the indices.

## 8. Remove the package and sanitise the data

Only once step 4a's proof exists.

1. `sudo apt purge robodr` (`robodr-focal`: `apt purge robodr-focal`; or
   `dpkg -P`; RPM: `dnf remove robodr`). This removes binaries and units,
   not data or keys.
2. Following the site's evidence-retention rules: destroy `/var/lib/robodr`
   (black box, spool, fleet state with the receipt: archive the receipt
   first) and `/etc/robodr` (keys, including the black-box key;
   configuration).
3. Sanitise the storage per **NIST SP 800-88 Rev. 1**: `shred` and
   `robodr-enroll`'s key shredding are best effort on flash media (wear
   levelling keeps old blocks), so for SSD / eMMC / SD use the device's
   sanitise or secure-erase command (`nvme sanitize`, `blkdiscard
   --secure`, `hdparm --security-erase` as applicable) or cryptographic
   erase (a LUKS volume whose key is destroyed: the seal erase of step 7
   for a sealed runtime volume), and *Destroy* when the media leaves the
   operator's control and cannot be sanitised.

Proof: the sanitisation certificate / record (method, tool, date, operator)
as SP 800-88 §4.7 describes.

### 8 on the sensor-box image

On a box built from `packaging/sensor-box/image/` the root is read-only,
so `apt purge` fails and there is nothing to remove from it: the image
holds no keys or site data (its build fails if `/etc/robodr/keys` is not
empty). Everything the box wrote is on the writable `/var` partition
(label `var`): `/var/lib/robodr` (black box, spool, fleet state) and
`/var/lib/robodr-image`, which holds the upper layer of the `/etc/robodr`
overlay (`etc-robodr/upper`: the keys, `agentd.json`, the profile, the
firewall and provisioning files) and `fingerprints.txt`. So, after step
4a and with the receipt archived:

1. Power the box off and boot it from external, vetted media (the box's
   own boot would start agentd again and mount the overlay).
2. Sanitise the `var` partition, or the whole disk when the box leaves
   the operator's control, as in item 3 above. Deleting files on the
   overlay is not enough: on flash the old blocks survive.
3. Re-flash the image only for a new commissioning; its first boot
   generates new keys.

Proof: as above.

## Re-commissioning

A decommissioned unit is commissioned again as a new one: after step 8 it
gets fresh keys, an empty `/var/lib/robodr`, a new enrollment token
(`robodr-enroll` refuses to enroll while the fleet state directory holds a
decommission record, `decommission.json`, whatever keys are on disk; and
the SOC never registers a key id twice), a new depot enrolment and a new
anchor-receiver entry.

## What is not covered yet

* The SOC side of `POST …/decommission` exists only as the reference
  implementation in this repository (`crates/robodr-fleet/tests/common/soc.rs`)
  and the contract vectors (case 18); AutoSecOps must implement it before a
  customer can run step 4 online. Until then step 4 is the SOC operator
  retiring the unit's keys by hand, and the unit's uplink and finding keys
  are shredded with step 8.
* Who must confirm a decommission at the SOC, and whether it releases the
  licensed seat, is an AutoSecOps policy decision (ADR-0008).
