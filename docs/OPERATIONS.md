# RoboDR operations guide

This guide covers installing, commissioning, running, upgrading and retiring
RoboDR on a robot companion computer, usually on an air-gapped site. It is
written for the operator and the site security officer. Packaging details,
the reasons behind each file mode, and the systemd hardening are in
[`packaging/README.md`](../packaging/README.md).

> **Scope: protective only.** RoboDR detects, refuses trust, records signed
> evidence and *requests* a safe state through the platform's own interface.
> It never overrides the robot's safety system, e-stop or command authority,
> and nothing in the motion stack may depend on a RoboDR service being up.
> Nothing in this guide changes that.

Status labels used below:

- **available**: works in the current release.
- **available from 0.1.0-alpha.2**: being added in parallel work. The command
  names follow the plan, but check them against `--help` on your build.
- **planned**: not implemented. An interim procedure is given.

---

## 1. Requirements

| Item | Requirement |
|---|---|
| Kernel | Linux 5.5 or newer with BPF and **BTF** (`/sys/kernel/btf/vmlinux` must exist). Kernels before 5.8 need the `CAP_SYS_ADMIN` drop-in (section 6.3). |
| bpffs | mounted at `/sys/fs/bpf` (systemd does this at boot) |
| systemd | 247 or newer (`LoadCredential=`). Ubuntu 22.04 and 24.04 qualify. |
| Arch | amd64 or arm64, Debian or Ubuntu (`dpkg`) |
| Runtime libs | glibc, libgcc-s1, libsqlite3-0 (the `.deb` declares them) |
| Tools on the robot | `sha256sum` (coreutils), `dpkg`; `minisign` if signatures are checked on the robot itself |

Check before installing:

```sh
uname -r
test -e /sys/kernel/btf/vmlinux && echo BTF ok
findmnt -t bpf /sys/fs/bpf
systemctl --version | head -1
```

## 2. Verify a release (entry station)

Every release asset has a minisign signature (`<file>.minisig`), and
`SHA256SUMS` lists every asset and is signed too. Verify on the **entry
station**, the vetted machine where media or diode transfers into the
isolated network are scanned, before anything moves inward.

1. **Pin the release public key once**, through a channel you trust: a signed
   letter, an in-person handover, or your PKI. Keep it in the entry station's
   trusted store, for example `/etc/robodr-trust/robodr-release.pub`. **Never
   take the key from the bundle or from the same download as the bundle.**
2. Verify:

   ```sh
   V=0.1.0-alpha.2; A=amd64
   minisign -V -p /etc/robodr-trust/robodr-release.pub -m SHA256SUMS
   sha256sum --ignore-missing -c SHA256SUMS
   minisign -V -p /etc/robodr-trust/robodr-release.pub -m robodr-$V-$A-offline.tar.gz
   ```

3. Optional: inspect the SBOM (`robodr-$V-$A-sbom.tar.gz`, CycloneDX JSON)
   against the site's vulnerability feed.
4. Optional: rebuild and compare. The pure binaries are reproducible. With
   the tagged source, the toolchain pinned in `rust-toolchain.toml` and the
   committed `Cargo.lock`, `scripts/ci-repro.sh` produces the same SHA-256
   values that the release's `.deb` contains. See `docs/BUILD.md`.
   `robodr-pulsard`'s reproducibility is not verified yet.

Move into the isolated network only: the offline tarball, its `.minisig`,
and the public key from your trusted store. The tarball holds the `.deb`,
`install-bundle.sh`, SBOMs, these docs and an inner `SHA256SUMS`.

## 3. Install on an air-gapped host

**available**

```sh
tar -xzf robodr-$V-$A-offline.tar.gz
cd robodr-$V-$A
sudo ./install-bundle.sh install \
    --pubkey /etc/robodr-trust/robodr-release.pub \
    --tarball ../robodr-$V-$A-offline.tar.gz
```

`install-bundle.sh install`:

1. checks the tarball's signature (with `--pubkey` and `--tarball`; without
   them it refuses unless `ROBODR_ALLOW_UNSIGNED=1`, which is for labs only);
2. checks every file against the inner `SHA256SUMS`, and fails if any file is
   not listed;
3. runs `dpkg -i`. The package creates the `robodr` user (sysusers) and the
   directories (tmpfiles), and installs the units **disabled**;
4. keeps the `.deb` under `/var/lib/robodr/releases/<version>/` for
   rollback.

If `minisign` is not on the robot, verify on the entry station (section 2)
and install with `ROBODR_ALLOW_UNSIGNED=1`. Record in the site log that the
signature was checked at the entry station.

After installing, nothing runs yet. Continue with keys (section 4) and
commissioning (section 5).

## 4. Keys

### 4.1 What keys exist

| Key | Where | Used for |
|---|---|---|
| Black-box key of `robodr-agentd` | `/etc/robodr/keys/agentd-blackbox.key` (`0600 root:root`) | signing the evidence chain |
| Black-box key of `robodr-pulsard` | `/etc/robodr/keys/pulsard-blackbox.key` | reserved, used once the Pulsar module records evidence |
| Release key | entry station only | verifying releases (section 2) |

Services never read `/etc/robodr/keys` themselves. systemd hands each one a
private copy (`/run/credentials/<unit>/blackbox.key`). The reasons are in
`packaging/README.md`, "Key material".

> **Important while the authenticator is HMAC-SHA256 (current releases):**
> the black-box key is a *shared secret*. Whoever holds it can verify
> evidence, and can also **forge** it. Keep exactly two copies: one on the
> robot, and one in the verifier's protected store on the high side. Never
> put it in a ticket, a chat, a command line (`--key-hex` is visible in
> `/proc`) or a backup that is not encrypted. An asymmetric backend (Ed25519
> or a TPM-held key) is planned. With it, the verifier holds only a public key.

### 4.2 Generate a key

**available from 0.1.0-alpha.2**: `robodr-blackbox keygen`. Run
`robodr-blackbox keygen --help` for its exact flags. It writes a new random
key in the format the recorder reads, with owner-only permissions:

```sh
sudo sh -c 'umask 077; robodr-blackbox keygen ... > /etc/robodr/keys/agentd-blackbox.key'
```

**0.1.0-alpha.1 (interim, coreutils only)**: the recorder accepts a hex key
of at least 32 bytes. `robodr-replay --key-file` reads hex plus whitespace.

```sh
sudo sh -c 'umask 077; od -An -tx1 -N32 /dev/urandom | tr -d " \n" > /etc/robodr/keys/agentd-blackbox.key'
sudo chown root:root /etc/robodr/keys/agentd-blackbox.key
sudo chmod 0600 /etc/robodr/keys/agentd-blackbox.key
```

Choose a **key id**: printable, no spaces, at most 128 characters, for example
`ugv-07-bb-2026q4`. It is recorded in the chain identity, and the verifier
uses it to pick the right key. Record it in the robot's commissioning file and
set it in the agent config (`/etc/robodr/agentd.json`).

Then copy the key to the verifier's protected store on the high side, using
vetted media. The diode is one-way, so the key cannot cross it.

### 4.3 Rotate a key

The recorder refuses to append to an existing chain with a different key
(`KeyMismatch`). Rotation therefore **closes the old chain and starts a new
one**. No evidence is lost or rewritten.

1. Export all pending evidence (section 8) and confirm on the far side that
   the last bundle verified.
2. Stop the agent: `sudo systemctl stop robodr-agentd`. The recorder writes
   a shutdown seal when it is closed cleanly, and `checkpoint.json` holds the
   final seal. Check the journal for a clean stop.
3. Archive the closed chain and retire the old key:

   ```sh
   ts=$(date -u +%Y%m%dT%H%M%SZ); old=<old-key-id>
   sudo mv /var/lib/robodr/blackbox/agentd /var/lib/robodr/archive/blackbox-agentd-$old-$ts
   sudo mv /etc/robodr/keys/agentd-blackbox.key /etc/robodr/keys/retired/agentd-blackbox-$old.key
   sudo systemd-tmpfiles --create robodr.conf   # recreates blackbox/agentd with the right owner
   ```

4. Generate the new key (4.2), set the new key id in `/etc/robodr/agentd.json`,
   and copy the key to the verifier.
5. `sudo systemctl start robodr-agentd`, then check the journal for the new
   chain's genesis.
6. Verify the archived chain once more with the retired key
   (`robodr-replay verify --blackbox <archive dir> --key-file <retired key>
   --key-id <old>`). Then follow the site's retention rule: keep the retired
   key as long as the archived evidence has to remain verifiable.

**Suspected key compromise:** follow the same steps, but treat every record
signed after the suspected time as unauthenticated. With HMAC, a holder of the
key can forge records. Report it as described in `SECURITY.md`.

## 5. Commissioning: learn, sign off, lock

**available.** `robodr-commission` is an operator tool, not a service. See
`man robodr-commission` and `packaging/README.md` for why nothing re-learns
automatically.

Work in `/var/lib/robodr/commission/<date>/` as root.

1. **Record clean runs.** Run the robot through its normal missions on a
   known-good, isolated network and capture the bus:

   ```sh
   sudo tcpdump -i eth0 -w run1.pcapng udp       # or the OEM's own capture tool
   ```

   Capture several runs covering every mode the robot uses. Whatever is
   present during learning becomes "normal", so make sure nothing foreign is
   on the network.

2. **Learn** a draft profile and its sign-off list:

   ```sh
   robodr-commission learn --pcap run1.pcapng --pcap run2.pcapng \
       --model <MODEL> --out draft.json --report report.json
   ```

   Participants seen too briefly are quarantined, not learned
   (`--min-announcements`, `--min-duration`). Accept one with
   `--accept-participant GUID` only if you can account for it. Every accepted
   participant becomes a sign-off item.

3. **Review and sign off.** Open `draft.json.signoff.json`. For every item,
   check it against the OEM's documentation of the robot (nodes, topics,
   services, motion envelopes), set `"confirmed": true`, and put your name in
   `"operator"`. If you edit `draft.json` by hand or merge drafts
   (`robodr-commission merge`), regenerate the list with
   `robodr-commission signoff --in draft.json --out signoff.json` and review
   it again.

4. **Lock**, which seals the profile:

   ```sh
   robodr-commission lock --in draft.json --signoff draft.json.signoff.json --out locked.json
   ```

   Lock refuses (exit 1) until every item is confirmed by a named operator.

5. **Check** the locked profile against a run that was *not* used for
   learning:

   ```sh
   robodr-commission check --profile locked.json --pcap run3.pcapng
   ```

   Exit 0 means clean. Investigate every deviation before going further.

6. **Install the profile and enable the services:**

   ```sh
   sudo install -m 0640 -o root -g robodr locked.json /etc/robodr/profile.json
   sudoedit /etc/robodr/pulsar.toml      # domain_id, capture interfaces, binding
   sudoedit /etc/robodr/agentd.json      # robot id, key id, policy, paths
   sudo systemctl enable --now robodr-pulsard robodr-agentd
   journalctl -u robodr-pulsard -u robodr-agentd -f
   ```

   An unlocked, missing or invalid profile makes the sensor run observe-only
   (every finding is marked `[observe-only]`) and is reported. This is how to
   run a first field period before enforcing.

**Recommission** whenever the robot's software or network changes. Use
`robodr-commission diff old.json new.json` so the reviewer sees exactly what
changed, then repeat the sign-off and lock steps.

## 6. Running

### 6.1 Health

```sh
systemctl status robodr-pulsard robodr-agentd
journalctl -u robodr-pulsard --since -1h
systemd-analyze security robodr-pulsard robodr-agentd   # exposure report
```

Both units restart on failure, up to 5 times in 300 s, then stay failed. A
failed unit does not affect the robot's operation; it does mean the robot is
not being watched. Alert on it.

`WatchdogSec=` is not configured yet, because the daemons do not send
`sd_notify` keep-alives. A hung, still-alive daemon is therefore not
restarted automatically. Monitor the findings and heartbeat flow on the fleet
side.

### 6.2 Pulsar API / CLI

The API socket is `/run/robodr-pulsard/pulsar.sock`, set in `pulsar.toml`.
The upstream `pulsar` CLI defaults to `/var/run/pulsar.sock`, so point it at
the RoboDR socket explicitly.

### 6.3 Older kernels

If the journal shows probes failing with `EPERM` on a kernel before 5.8,
install the drop-in:

```sh
sudo install -D -m 0644 /usr/share/doc/robodr/examples/robodr-pulsard.service.d/10-cap-sys-admin.conf.example \
    /etc/systemd/system/robodr-pulsard.service.d/10-cap-sys-admin.conf
sudo systemctl daemon-reload && sudo systemctl restart robodr-pulsard
```

Record the reason in the robot's commissioning file. `CAP_SYS_ADMIN` is close
to full root.

## 7. Upgrade and rollback

**Upgrade** (available). Verify the new release (section 2), then run
`install-bundle.sh install` from the new bundle. `dpkg` keeps local edits to
`/etc/robodr/pulsar.toml` (a conffile) and asks before replacing an edited
one. Services that were running are restarted on the new binaries.
`/etc/robodr` (profile, keys, configs) and `/var/lib/robodr` (evidence) are
never touched.

Before upgrading:

- read `CHANGELOG.md` for profile-format or config changes;
- export pending evidence (section 8);
- run `robodr-commission check --profile /etc/robodr/profile.json --pcap <recent run>`
  with the **new** `robodr-commission` from the extracted `.deb`
  (`dpkg-deb -x robodr_*.deb /tmp/new`). This confirms the new version accepts
  the locked profile.

**Rollback** (available):

```sh
sudo /path/to/bundle/install-bundle.sh list          # versions kept on this robot
sudo /path/to/bundle/install-bundle.sh rollback 0.1.0~alpha.1-1
```

Rollback reinstalls the kept `.deb` after re-checking its hashes. Evidence
written by the newer version stays in place. Each black-box record carries a
format version, but whether an older recorder appends safely to a chain
written by a newer one is **not verified**. If `CHANGELOG.md` lists a
black-box format change between the two versions, archive the chain
directory as in a key rotation (section 4.3, step 3) before starting the
rolled-back agent.

## 8. Log and evidence export via the diode

The robot side is the **low side**. Evidence leaves through a one-way data
diode, or through vetted media at the entry station. Nothing returns
through the diode.

### 8.1 What is exported

| Data | Location | Integrity |
|---|---|---|
| Black-box chain | `/var/lib/robodr/blackbox/<service>/` | hash-chained, signed (HMAC placeholder), checkpointed |
| OCSF findings | `/var/lib/robodr/spool/<service>/` | validated by `robodr-ocsf`; carry evidence links into the black box |
| Journal | `journalctl -u 'robodr-*'` | none of its own; corroborating only |

### 8.2 Black-box bundles

**planned (CLI); available as a library API.** `robodr-blackbox`'s
`Recorder::export_pending` produces an `RBBXBND1` bundle of every record after
the authenticated export cursor. The far side's `Receiver::accept` verifies
each bundle on its own and its linkage to the previous one, so a gap,
replay or substitution is detected. There is no command-line exporter in this
release. Once the agent wires it in, bundles will be written to
`/var/lib/robodr/export/` and the diode or media picks them up from there.

**Interim procedure (available):** export a copy of the chain directory and
verify it on the far side.

```sh
ts=$(date -u +%Y%m%dT%H%M%SZ)
sudo tar -C /var/lib/robodr/blackbox -czf /var/lib/robodr/export/blackbox-agentd-$ts.tar.gz agentd
sudo tar -C /var/lib/robodr/spool    -czf /var/lib/robodr/export/spool-agentd-$ts.tar.gz agentd
(cd /var/lib/robodr/export && sha256sum *-$ts.tar.gz | sudo tee SHA256SUMS-$ts)
# hand /var/lib/robodr/export/*-$ts* to the diode / media
```

Far side, with the verifier's copy of the key:

```sh
sha256sum -c SHA256SUMS-$ts
mkdir bb && tar -C bb -xzf blackbox-agentd-$ts.tar.gz
robodr-replay verify --blackbox bb/agentd --key-file /secure/agentd-blackbox.key \
    --key-id <key-id> --robot-id <robot-id>
```

A copy taken while the agent is writing can end in a half-written frame. The
verifier reports this as `TornTail` (a warning, not tampering), and the next
export contains the complete record. Any **tamper** finding (`HashMismatch`,
`BadSignature`, `Deleted`, `ChainBreak`, `Fork`, ...) is an incident. Keep the
copy and report it.

`SHA256SUMS-$ts` only protects against transfer errors. Anyone on the low
side could recompute it. Authenticity comes from the chain's own signatures and
from comparing `checkpoint.json` against the last checkpoint already received.

Do not prune evidence on the robot after an interim export. Without a receiver
acknowledgement the robot cannot tell that the export arrived. Pruning in ack
mode comes with the bundle exporter.

### 8.3 Findings batches

**planned.** The diode batch format (`robot-edr-findings_<site>_<batch_seq>.jsonl`
plus a signed manifest) is specified in
`docs/contracts/robot-edr.findings.md`, section 8. It is not implemented yet.
Until then, the spool tarball above carries the findings, and the importer runs
`robodr_ocsf::parse_and_validate` on every line.

### 8.4 Journal

```sh
sudo journalctl -u 'robodr-*' --since "<last export>" -o export | gzip -9 > /var/lib/robodr/export/journal-$ts.export.gz
```

## 9. Decommissioning

The package never deletes evidence or keys, not even on `apt purge`.

1. Export everything (section 8) and confirm verification on the far side.
2. `sudo systemctl disable --now robodr-agentd robodr-pulsard`
3. `sudo apt purge robodr` (or `dpkg -P robodr`).
4. Following the site's evidence-retention and media-sanitisation rules, and
   only after the far side has confirmed it holds verified copies:
   archive or destroy `/var/lib/robodr`, then destroy `/etc/robodr/keys`
   (`shred -u`). Destroying the keys makes remaining copies of the evidence
   unverifiable on the robot side.

## 10. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `Assertion failed ... /sys/fs/bpf` | bpffs not mounted | `mount -t bpf bpf /sys/fs/bpf`; fix the boot config |
| `Assertion failed ... /sys/kernel/btf/vmlinux` | kernel without BTF | use a kernel with `CONFIG_DEBUG_INFO_BTF=y` |
| `You must run this as root user` | unit edited to set `User=` | Pulsar requires euid 0; remove `User=` |
| probes fail with `EPERM` | kernel < 5.8, or an LSM policy | section 6.3 |
| `Multiple bpf fs mounts detected` | several bpffs mounts in the namespace | report it (unverified interaction with `ProtectKernelTunables=`) |
| agent: `log is keyed X, signer is Y` | key changed without rotation | section 4.3 |
| every finding `[observe-only]` | profile unlocked, missing or invalid | section 5 |
| capture sees only `lo` | no default route on an air-gapped robot | list the DDS interfaces in `[module.robodr-sensor-ros2.capture] interfaces` |
