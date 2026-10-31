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
2. Export the black box (OPERATIONS 8.2: bundles over the control plane,
   or a copy of the black-box directory on vetted media) and the fleet
   journal (`/var/lib/robodr/fleet/journal`), and verify them on the far
   side with the unit's black-box public key:
   `robodr-blackbox verify DIR --keyring agentd-blackbox.key.pub`.
3. Proof: the far side's verification report (intact, last sequence
   number), signed or countersigned per the site's rules.

## 2. Stop every RoboDR service

```sh
sudo systemctl disable --now robodr-uplink robodr-kafka-publish robodr-spool-export \
    robodr-agentd robodr-pulsard robodr-executor robodr-deliverd
systemctl list-units 'robodr-*' --all     # nothing active except, if inline,
                                          # the gateway (step 3)
```

The executor removes its own nft table on package removal; stop it here so
no action is still in force (`nft list table inet robodr` must be empty or
absent).

## 3. Take the inline gateway out of the path (inline units only)

Stopping `robodr-firewall-gw` does **not** take it out of the path: its
rules stay and, with `on_gateway_down: fail_closed` (default), the bridge
keeps dropping motion commands; `apt purge` leaves them too (OPERATIONS
6.6). With the unit in a safe state:

```sh
sudo systemctl disable --now robodr-firewall-gw robodr-firewall-gw-rules
sudo iptables -F ROBODR_GW && sudo iptables -X ROBODR_GW   # the queue chain
# then remove the bridge / re-cable the motion link as it was before
# commissioning (site wiring record).
```

Proof: a motion command reaches the actuator controller without the
gateway (bench test), recorded in the site log.

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
  --receipt-out FILE`.
* Network down or no answer: run the same command again; the stored
  request is resent unchanged and the SOC answers with its stored answer.
  A request that may have reached the SOC is never dropped on the unit.
* Refused while a key rotation is unfinished: finish it (`robodr-enroll
  rotate --role R --finish`) or cancel it (`--cancel`) first.

Proof: the receipt (`robodr-fleet-decommission-receipt/v1`: the request
signed by the unit's three keys and the answer signed by the SOC fleet
key), archived with the site's records. `robodr-enroll status` shows the
decommission as `Done`.

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

1. `sudo apt purge robodr` (or `dpkg -P robodr`; RPM: `dnf remove
   robodr`). This removes binaries and units, not data or keys.
2. Following the site's evidence-retention rules, and only after step 1's
   proof exists: destroy `/var/lib/robodr` (black box, spool, fleet state
   with the receipt: archive the receipt first) and `/etc/robodr` (keys,
   including the black-box key; configuration).
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

## Re-commissioning

A decommissioned unit is commissioned again as a new one: after step 8 it
gets fresh keys, an empty `/var/lib/robodr`, a new enrollment token
(`robodr-enroll` refuses to enroll on top of a decommissioned state, and
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
