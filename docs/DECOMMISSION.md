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
  request from the unit), revoke it at the depot (step 5), at the anchor
  receiver (step 6) and everywhere else the SOC trusts it (step 6a: diode
  keyring, control-plane certificate, Kafka principal), and treat its last
  evidence as an incident.

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
* **Black-box key rotated in place** (OPERATIONS 4.3, `robodr-blackbox
  rotate`): the fleet API does not rotate the black-box key, so the SOC
  still has the enrollment black-box key registered, and the request must
  be signed by it. `robodr-enroll` finds it by its fingerprint among the
  retired keys in `/etc/robodr/keys/retired/` (where 4.3 step 4 moves it
  and, on an enrolled unit, keeps it) and signs with it. The fleet journal
  must have been rotated with the black-box key (4.3 step 3) and the
  retired `.pub` listed in agentd's `blackbox.previous_keys`; otherwise
  every `robodr-enroll` command is refused with the command that fixes it.
  If the retired secret was destroyed, the command refuses before sending
  anything ("put the retired secret key file back"): the unit can no
  longer prove the registered key, and the SOC operator has to retire its
  keys from the SOC side, as for a lost unit (step 0).

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

## 6a. Revoke the unit's other credentials

Step 4 retires the keys the fleet API knows (uplink, finding, black-box).
Depending on how the unit delivered findings and took requests, the SOC
and the site's CAs trust more of its credentials; each stays valid until
it is revoked here. This matters most for a lost, stolen or compromised
unit (step 0), whose secrets may be in other hands. Skip the items the
unit never had.

1. **Diode signing key** (air-gapped sites, OPERATIONS 4.4 and 8.3): on the
   high side, remove the unit's lines from the keyring file
   `robodr-diode-unpack --keyring` reads, and delete its `diode-<unit>.key.pub`
   next to it (and its `robots` line, if any). From then on a batch signed
   with that key is quarantined as signed by an unknown key.
   Proof: the keyring file without the unit (diff in the site log).
2. **Control-plane server certificate** (OPERATIONS 6.4, control plane
   step 3: `robot.pem`, issued by the CA the SOC uses for robots): revoke
   it at that CA and publish the new CRL to the SOC client that connects to
   robots, and remove the robot's address and its SPKI pin from the SOC's
   list of robots. Without the revocation, whoever holds the unit's
   `agentd-cp-tls.key` can answer as that robot until the certificate
   expires.
   Proof: the CRL serial and the certificate's serial in it; the SOC's
   robot list without the unit.
3. **Kafka principal** (connected sites publishing with
   `robodr-kafka-publish` from the unit, OPERATIONS 8.3): revoke the
   unit's client certificate at the CA the brokers trust (and publish the
   CRL to the brokers), or delete its SCRAM user
   (`kafka-configs.sh --alter --delete-config 'SCRAM-SHA-512' --entity-type
   users --entity-name <user>`), and remove its ACLs
   (`kafka-acls.sh --remove --allow-principal User:<principal>`).
   Proof: `kafka-acls.sh --list --principal User:<principal>` prints
   nothing; the CRL serial or the SCRAM user's absence in
   `kafka-configs.sh --describe --entity-type users`.

The anchor-receiver client certificate is revoked in step 6, the depot
enrolment in step 5.

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
