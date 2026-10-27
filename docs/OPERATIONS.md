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
| systemd | 247 or newer (`LoadCredential=`) for the `robodr` package. |
| Arch | amd64 or arm64, Debian or Ubuntu (`dpkg`) |
| Runtime libs | glibc, libgcc-s1, libsqlite3-0 (the `.deb` declares them). The libc6 floor is read from the binaries: a release built on Ubuntu 24.04 needs **glibc 2.39**, i.e. Ubuntu 24.04 or newer. |
| Older hosts | Ubuntu 20.04 / 22.04 (glibc 2.31 / 2.35, systemd 245 / 249), e.g. NVIDIA JetPack 5 / 6: the **`robodr-focal`** package, static musl binaries with systemd 245 units, **without `robodr-pulsard`** (agentd and the tools only). See [UNITREE.md section 3.2](UNITREE.md#32-edu-agent-development-computer). |
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
optionally the release `SHA256SUMS` with its `.minisig`, and the public key
from your trusted store. The tarball holds the `.deb`, `install-bundle.sh`,
`security-floor`, SBOMs, these docs and an inner `SHA256SUMS`.

## 3. Install on an air-gapped host

**available**

The script that checks a bundle must itself be trusted: a script taken from
an unverified extraction can be modified to skip every check. So **verify
the tarball before extracting it**, and run the verifier from a trusted
copy.

*First installation* (no RoboDR on the unit yet):

```sh
minisign -V -p /etc/robodr-trust/robodr-release.pub -m robodr-$V-$A-offline.tar.gz
sudo mkdir -m 0700 /root/robodr-$V && sudo tar -xzf robodr-$V-$A-offline.tar.gz -C /root/robodr-$V
sudo sh /root/robodr-$V/robodr-$V-$A/install-bundle.sh install \
    --pubkey /etc/robodr-trust/robodr-release.pub \
    --tarball robodr-$V-$A-offline.tar.gz
```

*Upgrades* use the copy the previous, verified release installed:

```sh
sudo sh /usr/lib/robodr/install-bundle.sh install \
    --pubkey /etc/robodr-trust/robodr-release.pub \
    --tarball robodr-$V-$A-offline.tar.gz
```

`install-bundle.sh install --pubkey … --tarball …`:

1. checks the tarball's minisign signature against the pinned key; if the
   release's `SHA256SUMS` and `SHA256SUMS.minisig` lie next to the tarball,
   checks that signature too and that the tarball is listed in it with its
   hash. Without `--pubkey`/`--tarball` it refuses unless
   `ROBODR_ALLOW_UNSIGNED=1` (labs only; the bundle is then the directory
   the script runs from);
2. extracts the verified tarball into a **private** directory (`mktemp -d`,
   0700; removed afterwards) and checks every file there against the inner
   `SHA256SUMS` (any unlisted file fails). Everything below uses that copy,
   never an already extracted directory. If the script runs from an
   extracted bundle directory, that directory must be identical to the
   signed content, otherwise it was modified after extraction and the run
   is **refused**;
3. refuses a **downgrade** (a release older than the installed one) unless
   `--allow-downgrade`, and anything below the unit's **security floor**
   (section 7), with no override;
4. runs the black-box format gate (section 7);
5. runs `dpkg -i`. The package creates the users `robodr` (exporters),
   `robodr-agentd` (agentd), `robodr-exec` and the group `robodr-safety`
   (sysusers) and the
   directories (tmpfiles), installs the units **disabled**, and installs
   `/usr/lib/robodr/install-bundle.sh`, the trusted verifier for the next
   upgrade;
6. keeps the `.deb` under `/var/lib/robodr/releases/<version>/` for
   rollback.

If `minisign` is not on the robot, verify on the entry station (section 2),
extract the verified tarball into a fresh root-only directory on the robot
and install with `ROBODR_ALLOW_UNSIGNED=1`. Record in the site log that the
signature was checked at the entry station.

After installing, nothing runs yet. Continue with keys (section 4) and
commissioning (section 5).

### 3.1 Unitree robots and the passive sensor box

Unitree robots (Go2, B2, G1, H1 and relatives) have their own guide,
[`UNITREE.md`](UNITREE.md): supported models, the two deployment modes, the
Unitree host rules (`rules/robodr/unitree.toml`) and the known limits. In
short:

* **Sensor box (default; the only option for Air / Pro).** A separate box
  watches the robot network (192.168.123.0/24) on a tap or switch mirror
  port and installs nothing on the robot. `robodr-agentd` runs with the
  example drop-in
  `/usr/share/doc/robodr/examples/robodr-agentd.service.d/40-sensor-box.conf.example`
  (install it as
  `/etc/systemd/system/robodr-agentd.service.d/40-sensor-box.conf`):
  `CAP_NET_RAW` only, all IP denied (it also resets any `IPAddressAllow=`),
  started only once the writable `/var/lib/robodr` mount is there. The
  capture NIC is made silent and promiscuous by
  `examples/sensor-box/10-robodr-capture.network.example` (systemd-networkd),
  and the box's firewall comes from
  `examples/sensor-box/nftables.conf.example`. Install the drop-in only on
  a sensor box, never on a robot. Hardening checklist: UNITREE.md section
  3.1.
* **EDU agent.** On the EDU development computer (Jetson, arm64). Current
  Unitree images (JetPack 5, Ubuntu 20.04, kernel without BTF; JetPack 6 is
  Ubuntu 22.04) cannot install the regular package (glibc 2.39, systemd
  247): they take `robodr-focal`, agentd only, no host rules.
  `robodr-pulsard` with the host rules needs a BTF kernel and a `robodr`
  build for the image's glibc (UNITREE.md section 3.2).

## 4. Keys

### 4.1 What keys exist

| Key | Where | Used for |
|---|---|---|
| Black-box key of `robodr-agentd` (Ed25519 secret) | `/etc/robodr/keys/agentd-blackbox.key` (`0600 root:root`) | signing the evidence chain |
| Its public key | `/etc/robodr/keys/agentd-blackbox.key.pub` (`0644`), copied to every verifier | verifying the chain (cannot sign) |
| Diode signing key of the unit (Ed25519 secret) | `/etc/robodr/keys/diode-<unit>.key` (`0600`) | `robodr-diode-pack` batch signatures (4.4) |
| Its public key | SOC importer keyring | `robodr-diode-unpack` (cannot sign) |
| Black-box key of `robodr-pulsard` | `/etc/robodr/keys/pulsard-blackbox.key` | reserved, used once the Pulsar module records evidence |
| Release key | entry station only | verifying releases (section 2) |
| Profile signing key (Ed25519, private) | commissioning station only, **never on the robot** | signing locked profiles (section 4.4, 5) |
| Profile trust file (Ed25519, public) | `/etc/robodr/profile-trust.json` (`0644 root:root`) | the sensor / agentd accept only profiles signed by these keys |
| Trust roots (Ed25519, private) | offline signing station / token, **never on the robot**, separate from the profile key and every operator key | signing the profile trust file (required on a unit with roots) and revocation lists (4.4, 5.3, 5.4) |
| Trust roots file (public) | `/etc/robodr/trust-roots.json` (`0644`) | verifying the trust file's signature, revocation lists and the signed floor |
| Operator sign-off keys (Ed25519, one per operator) | each operator's own token / home on the commissioning station | signing a confirmed sign-off list (section 5, step 3) |
| Operators trust list (public) | commissioning station (`operators.json`, not group/other-writable), and embedded in the root-signed profile trust file on every robot | `lock --operators` accepts only sign-offs signed by these operators; the robot verifies the embedded attestation against them (5.4) |
| Finding key of `robodr-agentd` (Ed25519 secret, optional) | `/etc/robodr/keys/agentd-finding.key` (`0600 root:root`) | per-finding signatures, header `robodr-finding-sig` (6.4) |
| Its public key | SOC finding keyring, bound to the unit id | verifying findings on connected paths (contract §2a) |
| Uplink key (Ed25519 secret) | `/etc/robodr/keys/uplink.key` (`0600 root:root`) | ingest batches and fleet API requests (8.5, 8.6) |
| SOC fleet key (Ed25519, public) | `/etc/robodr/fleet-soc.pub` (`0644`), from the SOC on vetted media | verifying enrollment tokens and answers, rotation answers, profile approvals, ring information (8.6) |

`robodr-enroll` (8.6) generates the uplink, finding and black-box keys on
the unit at enrollment and rotates the uplink and finding keys with the
SOC; the black-box key is rotated as in 4.3.

Services never read `/etc/robodr/keys` themselves. systemd hands each one a
private copy (`/run/credentials/<unit>/blackbox.key`). The reasons are in
`packaging/README.md`, "Key material".

> **Ed25519 (default since this release):** the robot holds the secret seed;
> verifiers (fleet console, SOC, auditors) hold only the **public** key
> file, which can verify but never sign, so it may be distributed freely
> (its integrity still matters: whoever swaps the `.pub` a verifier trusts
> can make it accept their own evidence — copy it on vetted media and
> compare the key id). The secret never leaves the robot. Never put it in a
> ticket, a chat, a command line (argv is visible in `/proc`; no RoboDR tool
> accepts a key on its command line) or a backup that is not encrypted.
>
> **Legacy HMAC-SHA256 keys** (`keygen --alg hmac`, and every key made
> before this release) are a *shared secret*: whoever can verify can also
> **forge**. They still work (the tools print a warning; the diode needs
> `--allow-hmac`), but migrate at the next rotation (4.3). The Ed25519 code
> is the audited `ed25519-dalek` crate; a TPM-held, non-exportable key is
> still planned.

### 4.2 Generate a key

**available**: `robodr-blackbox keygen` (Ed25519 by default). It draws a
32-byte seed from `/dev/urandom` (and fails rather than fall back to weaker
randomness) and writes two files: the secret key file
(`robodr-blackbox-key/v2`, mode `0600`) and the public key file
`<file>.pub` (mode `0644`). It never overwrites an existing file (if either
exists, nothing is written), never writes through a symlink, and prints only
the key id.

Choose a **key id**: printable, no spaces, at most 128 characters, for example
`ugv-07-bb-2026q4`. It is recorded in the chain identity, and the verifier
uses it to pick the right key. Record it in the robot's commissioning file.
Without `--key-id` it is derived from the public key (`ed25519:<16 hex>`).

```sh
sudo robodr-blackbox keygen --out /etc/robodr/keys/agentd-blackbox.key --key-id ugv-07-bb-2026q4
sudo chown root:root /etc/robodr/keys/agentd-blackbox.key   # keygen already sets 0600
# (lost the .pub? re-derive it: robodr-blackbox export-pub /etc/robodr/keys/agentd-blackbox.key --out FILE)
```

`robodr-agentd` reads the secret file directly (`blackbox.key_file`; the key
id comes from the file, so `blackbox.key_id` in `/etc/robodr/agentd.json`
can be left out, and if it is set it must match). `robodr-replay --key-file`
reads it too. Every tool refuses a secret key file that is a symlink, that
group or others can access, or that is owned by another user (root
excepted), and refuses a `.pub` where a signing key is needed. Verifiers
(`robodr-blackbox verify --keyring`, `robodr-replay verify --key-file`)
take the **`.pub`** file, whatever its mode.

*Legacy key files*: HMAC JSON key files (`robodr-blackbox-key/v1`) are still
accepted by `robodr-agentd`, `robodr-replay` and `robodr-blackbox`, with a
warning. Bare hex (0.1.0-alpha.1, made with `od ... /dev/urandom`) is still
accepted by `robodr-agentd` only (key id from `blackbox.key_id`, else derived
from the key). Replace either with an Ed25519 key at the next rotation (4.3);
do not hand-write JSON around an old secret on a shared terminal.

Then copy the **public** key file to each verifier (fleet console, the SOC's
evidence store) using vetted media. The diode is one-way, so nothing comes
back. Only legacy HMAC keys require copying the secret itself to the
verifier's protected store.

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
   sudo mv /etc/robodr/keys/agentd-blackbox.key.pub /etc/robodr/keys/retired/agentd-blackbox-$old.key.pub
   sudo systemd-tmpfiles --create robodr.conf   # recreates blackbox/agentd with the right owner
   ```

4. Generate the new key (4.2) with a new key id (if `blackbox.key_id` is set
   in `/etc/robodr/agentd.json`, update it to match), and copy its `.pub` to
   the verifiers. This is also how an HMAC unit moves to Ed25519.
5. `sudo systemctl start robodr-agentd`, then check the journal for the new
   chain's genesis.
6. **Units running `robodr-deliverd`** (§11): the delivery agent signs its
   journal (`blackbox/deliverd`) and its high-water record with the same
   key. Keep the retired secret key file until this step is done; do not
   move or delete `blackbox/deliverd`. With `robodr-deliverd` stopped:

   ```sh
   sudo systemctl stop robodr-deliverd
   sudo robodr-deliverd rekey --config /etc/robodr/deliverd.json \
       --old-key /etc/robodr/keys/retired/agentd-blackbox-$old.key \
       --new-key /etc/robodr/keys/agentd-blackbox.key
   sudo systemctl start robodr-deliverd
   ```

   It verifies the journal and the record with the old key, archives the
   journal as `blackbox/deliverd.archived-g<N>` and starts a new one and a
   new record, signed with the new key, that carry the floors, the
   deployment sequence, the chain heads and the time floor (§11.3).
   Without it the agent cannot open its journal and locks itself. Verify
   the archive like agentd's (step 7) and keep it with the same retention.
7. Verify the archived chain once more with the retired key
   (`robodr-blackbox verify <archive dir> --keyring <retired key>.pub`, or
   the retired HMAC key file). The key id is read from the key file. Then
   follow the site's retention rule: keep the retired public key (HMAC: the
   key) as long as the archived evidence has to remain verifiable. An
   Ed25519 secret that is retired can be destroyed (`shred -u`); its public
   key still verifies the archive.

**Suspected key compromise:** follow the same steps, but treat every record
signed after the suspected time as unauthenticated. With Ed25519 only the
robot's secret matters (a leaked `.pub` is harmless); with HMAC, any holder of
the key, including a verifier, can forge records. Report it as described in
`SECURITY.md`.

### 4.4 Diode signing keys (`robodr-diode-pack` / `-unpack`)

**available.** Each exporting unit signs its diode batches with its own
Ed25519 key; the SOC importer holds only the units' public keys, so the SOC
**cannot forge** a batch.

```sh
# low side, once per unit
sudo robodr-blackbox keygen --out /etc/robodr/keys/diode-ugv-07.key --key-id diode-ugv-07-2026q4
robodr-diode-pack --outbox OUT --state pack-state.json --unit ugv-07 \
  --key-file /etc/robodr/keys/diode-ugv-07.key --findings findings.jsonl
# carry /etc/robodr/keys/diode-ugv-07.key.pub to the SOC on vetted media
```

`robodr-spool-export.service` (section 8.3) reads its key from the fixed
path `/etc/robodr/keys/diode.key` (handed over by systemd as a credential):
generate it there (`--key-id` as above), or link nothing and copy the unit's
key to that name; symlinks are refused.

SOC keyring file (one line per unit key; several keys per unit during a
rotation are fine):

```text
# unit      public key file (relative to this file)
ugv-07      diode-ugv-07.key.pub
```

`robodr-diode-unpack --keyring <that file> ...` refuses an Ed25519 *secret*
key file in the keyring (or as `--bundle-key`): copy only `.pub` files to
the SOC. The packer refuses a key file with loose permissions or a foreign
owner (it used to only warn) and no longer reads bare hex keys. Legacy HMAC
key files work on either side only with `--allow-hmac` (a warning is printed
each run); migrate by generating an Ed25519 key, adding its `.pub` to the
SOC keyring next to the old key, and switching the packer's `--key-file`: the
batch sequence and chain continue across the key change.

### 4.4 Profile signing key

**available.** Locked profiles are signed (Ed25519) so that a robot enforces
only a profile the OEM issued. This key is asymmetric: the robot holds only
the public half.

```sh
robodr-commission keygen --out /secure/oem-profile.key \
    --trust-out profile-trust.json --key-id oem-ugv-x1-2026
```

`oem-profile.key` is a `robodr-blackbox-key/v2` secret key file with
`"algorithm": "ed25519"` (mode `0600`, never overwritten), the same single
key file format the black box uses (section 4); keygen also writes its public
half `oem-profile.key.pub` (`0644`). A key made with `robodr-blackbox keygen`
signs profiles as well; build the trust file from public key files with
`robodr-commission trust-keys --out profile-trust.json --pub oem-profile.key.pub`
(secret files are refused). Keep it on the
commissioning station (offline, encrypted at rest); it never goes to a robot.
`profile-trust.json` (`robodr-profile-trust/v1`) holds only the public key; it
is installed on every robot of the fleet (section 5, step 6).

**Rotation:** generate a new key, add its public entry to the `keys` list of
the trust file (a trust file may list several keys), roll the new trust file
out, re-sign the current profile with the new key
(`robodr-commission sign --profile locked.json --sign-key new.key --force`),
then remove the old entry. **Revocation** of a key or of a single profile
file is done with a signed revocation list (section 5.3); removing the entry
from the trust file still works but needs a new trust file on every robot.
If a signing key is compromised, revoke it at once (by its public-key
fingerprint, which `keygen` prints and `verify-profile` reports) and re-sign
with a new key: until the list is installed an attacker holding it can make
the robot enforce a profile of their choosing (but only one that also
carries a valid operator attestation, section 5.4). There is no expiry.

**Trust roots** are a second, separate Ed25519 key pair (or several) that
sign only the profile trust file and revocation lists, never profiles.
**Once trust roots are configured on a robot, its profile trust file must
be root-signed** (`profile-trust.json.sig`): an unsigned or badly signed
trust file is refused (fail closed), so whoever can write
`/etc/robodr/profile-trust.json` can neither add a key nor strip the floor
or the operators list. Keep the roots offline, on a different station or
token than the profile signing key; a key that is both a root and a profile
key (or an operator key) is refused by every loader.

```sh
robodr-commission keygen --out /secure/oem-root.key --trust-out trust-roots.json \
    --key-id oem-root-2026 --roots
# the robot's trust file: profile key(s) + operators, signed by a root
robodr-commission trust-keys --out profile-trust.json --pub oem-profile.key.pub \
    --operators operators.json --sign-key /secure/oem-root.key   # .json + .json.sig
```

With roots configured a robot also **requires operator attestation** by
default (section 5.4), so the trust file must carry `--operators` (or,
for a fleet that cannot yet re-commission its profiles, the root-signed
opt-out `--no-require-attestation`; see 5.4 for what that gives up).

The Ed25519 implementation is the audited `ed25519-dalek` crate (strict
verification), wrapped by `robodr-blackbox` and pinned to the RFC 8032 test
vectors; key files, key ids and signatures are unchanged from the earlier
in-crate implementation.

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

   `learn` also writes `draft.json.manifest.json` last (SHA-256 of the
   draft, the report and the sign-off list); `lock` refuses a draft whose
   manifest is missing or does not match (`--no-manifest` only for drafts
   made before manifests existed). If the robot uses a DDS **discovery
   server**, name it (`--discovery-server PREFIX|PREFIX@IP|IP`, or
   `--trusted-discovery-server PREFIX@IP|IP` to learn the endpoints it
   relays for accepted owners); otherwise every relayed announcement is a
   sign-off item. A **trusted** server must be pinned by its IP: a GUID
   prefix alone is refused, because any host can write that prefix into
   its packets and would get its own participants and endpoints learned as
   "relayed". A prefix-only server is accepted as a known server, which
   never gets anything learned on its own.

3. **Review and sign off.** Open `draft.json.signoff.json`. For every item,
   check it against the OEM's documentation of the robot (nodes, topics,
   services, motion envelopes), set `"confirmed": true`, and put your name in
   `"operator"`. If you edit `draft.json` by hand or merge drafts
   (`robodr-commission merge`), regenerate the list with
   `robodr-commission signoff --in draft.json --out signoff.json` and review
   it again. (The list is bound to the draft's *content*, in canonical
   form, which is what the robot re-checks; a list bound to the raw bytes
   of a re-formatted draft is refused by `lock` with "not the canonical
   form": regenerate it with `signoff --in`.)

   Then **sign** the confirmed list with your own operator key. The security
   officer keeps an operators trust list binding each operator's public key
   to a name (once, and on every change of staff):

   ```sh
   robodr-blackbox keygen --out ~/alice.key --key-id op-alice          # each operator, once
   robodr-commission operators --out operators.json \
       --operator Alice=alice.key.pub --operator Bob=bob.key.pub --motion-quorum 2
   robodr-commission signoff --signoff draft.json.signoff.json --sign-key ~/alice.key \
       --in draft.json --operators operators.json                      # writes <list>.sig
   robodr-commission signoff --signoff draft.json.signoff.json --sign-key ~/bob.key \
       --in draft.json --operators operators.json                      # second operator
   ```

   Signing refuses a list that is not fully confirmed, names no operator or
   belongs to another draft. Editing the list afterwards voids every
   signature.

4. **Lock**, which versions, seals and signs the profile:

   ```sh
   robodr-commission lock --in draft.json --signoff draft.json.signoff.json \
       --operators operators.json --out locked.json --platform ugv-x1 --profile-version 1 \
       [--unit-id ugv-007] --sign-key /secure/oem-profile.key
   ```

   `--operators` is **required**. Lock refuses (exit 1) unless every item is
   confirmed, every signature in `<signoff>.sig` verifies under a key in the
   operators list (fail closed; at least one must), the list's `operator` is
   one of the signers, and, when the list has motion items, at least
   `motion_quorum` distinct operators signed (the **two-person rule**;
   `--motion-quorum N` can raise it for one lock, never lower it). A null
   motion dimension also needs its own confirmed
   `envelope_dimension_unbounded` item.
   It stamps `metadata` into the profile: `schema_version`,
   `profile_version` (monotonic, never reuse a number), `platform`,
   `unit_id` (only for a profile made for one robot; leave it out for a
   fleet-wide profile), `locked_by` (the sign-off operator), `locked_at`,
   `parent_digest` and **`attestation`**: the exact confirmed sign-off and
   its operator signatures (`<signoff>.sig`), which the robot verifies at
   load (section 5.4). It writes `locked.json` and the detached signature
   `locked.json.sig` (Ed25519 over the exact sealed bytes) together. On a
   signing station separate from the review station, lock without
   `--sign-key` and sign later with `robodr-commission sign` (add
   `--operators operators.json` to re-verify the attestation before
   signing). `sign` refuses a locked profile that carries no attestation
   (not made by `lock`) unless `--allow-unattested` is given; robots that
   require attestation refuse such a profile anyway.

   **Check the signature** the way the robot will:

   ```sh
   robodr-commission verify-profile --profile locked.json \
       --trusted-keys profile-trust.json --expect-platform ugv-x1 \
       --trust-roots trust-roots.json
   ```

   It prints the profile version, the signing key and its fingerprint, the
   operators who attested it and the file digest (`sha256:...`). Record
   them in the robot's commissioning file.

5. **Check** the locked profile against a run that was *not* used for
   learning:

   ```sh
   robodr-commission check --profile locked.json --pcap run3.pcapng
   ```

   Exit 0 means clean. Investigate every deviation before going further.

6. **Install the profile, its signature and the trust file, and enable
   the services:**

   ```sh
   sudo install -m 0640 -o root -g robodr locked.json /etc/robodr/profile.json
   sudo install -m 0640 -o root -g robodr locked.json.sig /etc/robodr/profile.json.sig
   sudo install -m 0644 -o root -g root profile-trust.json /etc/robodr/profile-trust.json
   # with trust roots the trust file's root signature is mandatory:
   sudo install -m 0644 -o root -g root profile-trust.json.sig /etc/robodr/profile-trust.json.sig
   # with trust roots / revocation (section 5.3):
   sudo install -m 0644 -o root -g root trust-roots.json /etc/robodr/trust-roots.json
   sudo install -m 0644 -o root -g root revocations-N.json /etc/robodr/profile-revocations.json
   # profile-state dirs come from tmpfiles.d/robodr.conf (systemd-tmpfiles --create)
   sudoedit /etc/robodr/pulsar.toml      # domain_id, capture, binding, profile_trust
   sudoedit /etc/robodr/agentd.json      # robot id, policy, paths, sensor.profile_trust
   sudo robodr-agentd --config /etc/robodr/agentd.json --check-config
   sudo systemctl enable --now robodr-pulsard robodr-agentd
   journalctl -u robodr-pulsard -u robodr-agentd -f
   ```

   The signature must sit next to the profile as `<profile_path>.sig`. The
   `profile_trust` settings (`trusted_keys`, `state_file`, optional
   `expect_platform` / `expect_unit_id`, and `trust_roots`,
   `revocation_list`, `revocation_policy` from section 5.3) are in
   `config/agentd.example.json` (`sensor.profile_trust`; the section 5.3
   keys only in `config/agentd.full.example.json`) and
   `config/robodr.toml.example` (`[module.robodr-sensor-ros2.profile_trust]`).
   `robot.profile_version` in `agentd.json` was removed: the version in
   findings is the signed `metadata.profile_version`; delete the key.

   The anti-rollback state file must be writable by the daemon. The package
   creates `/var/lib/robodr/profile-state` (`robodr-agentd:robodr`, agentd's
   `agentd.json`) and `/var/lib/robodr/profile-state-pulsard` (`root:robodr`,
   the Pulsar sensor's `pulsard.json`; separate so the `robodr` user cannot
   rewrite the root daemon's floor), and each unit lists its directory in
   `ReadWritePaths=`. A state path outside them cannot be written; the
   daemon then cannot record the accepted version and, failing closed, runs
   observe-only.

   An unlocked, missing or invalid profile, or a locked profile that is not
   trusted (no or bad signature, key not in the trust file, no metadata,
   wrong platform/unit, older than the last accepted version, below the
   signed floor, revoked, no or an invalid operator attestation where one
   is required, an unsigned trust file while trust roots are configured,
   or a revocation list that is invalid, for another platform, older than
   the accepted one or missing when required) makes the
   sensor run observe-only (every finding is marked `[observe-only]`) and
   is reported as `robot.ros2.profile_refused` with the reason. This is how
   to run a first field period before enforcing.

**Recommission** whenever the robot's software or network changes. Use
`robodr-commission diff old.json new.json` so the reviewer sees exactly what
changed, then repeat the sign-off and lock steps, locking against the
profile it replaces:

```sh
robodr-commission lock --in draft2.json --signoff draft2.json.signoff.json \
    --operators operators.json --out locked2.json --parent locked.json \
    --trusted-keys profile-trust.json --sign-key /secure/oem-profile.key
```

`--parent` sets `profile_version` to the parent's + 1 (an explicit
`--profile-version` must be higher), inherits platform and unit, and records
the parent's file digest in `parent_digest`, so every locked profile names
the one it superseded.

### 5.1 Profile rollback

The robot remembers the last accepted `profile_version` and file digest in
its state file (`profile_trust.state_file`). It refuses, observe-only with a
`robot.ros2.profile_refused` finding:

- a **lower** `profile_version` (rollback to an older, possibly weaker profile);
- the **same** version with different bytes (two profiles issued under one
  number);
- an **unlocked draft** replacing a locked profile.

To roll back deliberately, name the exact file:

```sh
robodr-commission verify-profile --profile old.json --trusted-keys profile-trust.json \
    --state /var/lib/robodr/profile-state/agentd.json      # prints its digest; read-only
# agentd.json: "sensor": { "profile_trust": { "allow_rollback": "sha256:<digest>" } }
```

After the daemon has loaded it, the state records the older version; remove
`allow_rollback` again. `--check-config` evaluates the rollback rule but
never writes the state; only a starting daemon does, atomically.

**The black box is the second witness.** `robodr-agentd` records every
accepted locked profile (version, digest, revocation-list serial, trust
floor) in the signed black-box chain: a `robodr.profile_accepted` note at
start and the same `profile_accepted` object in every heartbeat. At the
next start it reads **every** such record that verifies under the daemon's
own black-box key, in the order of their signed sequence numbers (not file
order), and takes as the baseline the highest accepted version, the
highest revocation serial and the highest floor; a record that lowers the
version is followed only if it records an operator rollback
(`allow_rollback`). Any other drop (a replayed old segment, a rewritten
record) and any break in the chain linkage is logged as a `CRITICAL:`
warning (`--check-config` shows it) and ignored for the baseline. It then
compares the baseline with the state file:

- state file **missing**, or **behind** the record (lower version, other
  digest for the same version, older revocation serial): the record is the
  rollback baseline, so the older profile stays refused, and agentd reports
  a **Critical** finding `robot.ros2.profile_state_tampered` (observe-only:
  it never requests an action) and logs `CRITICAL:`; `--check-config`
  shows it as a `CRITICAL:` warning. If the offered profile is the recorded
  one, it is enforced and the state file is rewritten from the record.
- state file **ahead** of the record (the daemon stopped between writing the
  state and the note): normal, nothing reported.

So deleting the state file no longer resets anti-rollback; a deliberate
rollback always goes through `allow_rollback`. If agentd stops between an
operator rollback and its note, the next start refuses the older profile
again with the alarm: keep `allow_rollback` set until the daemon has run.

**Signed floor.** A trust file may carry `min_profile_version`, honoured
only when the trust file is signed by a trust root (`<trust>.sig`):

```sh
robodr-commission trust-keys --out profile-trust.json --pub oem-profile.key.pub \
    --operators operators.json --min-profile-version 4 \
    --sign-key /secure/oem-root.key                            # writes .json + .json.sig
```

A locked profile below the floor is refused and `allow_rollback` cannot
override it; a floor without a valid root signature (or without
`trust_roots` configured) makes the whole trust file invalid, and with
`trust_roots` configured an unsigned trust file is refused whatever it
holds (so the floor cannot be stripped by deleting it and the `.sig`). The
highest floor ever accepted is also remembered in the state file and the
black-box record (`trust_floor`), so an older root-signed trust file with a
lower floor (a replay) never lowers it. The floor is what remains if root
deletes both the state file and the black box.

Limits: the state file is plain JSON; root can still delete it **and** the
black box directory (the gap is visible off-unit in the exported chain, not
on the unit), leaving only the signed floor of the installed trust file.
An older root-signed trust file still verifies (trust files have no
serial): it cannot lower the remembered floor, but it can bring back a
profile key it listed, so retire keys with the revocation list (5.3), not
only by removing them from the trust file. Deleting the newest black-box
segments (truncation) is not detectable on the unit. Cyclic retention or
export pruning can drop old segments; the heartbeat re-records the profile
so the newest segment carries it. The
Pulsar sensor and `robodr-ros2-watch` have no black box and use the state
file and floor only. A hardware monotonic counter (TPM) is the planned fix.
A corrupt or unreadable state file is not reset silently: the profile is
refused until an operator repairs or removes it.

### 5.2 Legacy profiles (locked before profile versioning)

Profiles locked by an earlier `robodr-commission` have a seal but no
`metadata` and no signature. Every loader now **refuses** them for
enforcement (observe-only, reason "legacy, unversioned"). They still work
with `check`, `diff` and `merge`. Migrate each one on the commissioning
station, after re-reviewing it (migration vouches for it again):

```sh
robodr-commission migrate-legacy --in legacy-locked.json --out locked.json \
    --platform ugv-x1 --profile-version 1 --operator "<your name>" \
    --sign-key /secure/oem-profile.key
```

The content is unchanged; the legacy file's digest becomes
`parent_digest`. Then install as in step 6. A migrated profile carries **no
operator attestation**: a robot that requires attestation (the default with
trust roots, section 5.4) refuses it. Re-commission it (learn, sign off,
lock) for such robots, or ship a root-signed trust file with
`require_attestation: false` until you can.

### 5.3 Revocation list

A revocation list (`robodr-profile-revocations/v2`) withdraws profile files
(by digest) and profile signing keys (by **public-key fingerprint**,
`sha256:` of the 32 raw Ed25519 public-key bytes) without touching the
trust file. It is bound to one `platform` (the `metadata.platform` of the
profiles it governs), signed by a trust root (section 4.4) and carries a
monotonic `serial` and `issued_at` (informational: no expiry). Keys are
revoked by fingerprint, not by key id, because a key id is only a label:
the same key re-listed under another id stays revoked.

```sh
# on the offline signing station
robodr-commission revoke --sign-key /secure/oem-root.key --out revocations-1.json \
    --platform ugv-x1 --revoke-profile locked-v3.json   # or --digest sha256:<hex>
robodr-commission revoke --sign-key /secure/oem-root.key --out revocations-2.json \
    --base revocations-1.json --trust-roots trust-roots.json \
    --revoke-key oem-ugv-x1-2025.key.pub                # or --key-fingerprint sha256:<hex>
robodr-commission verify-revocations --list revocations-2.json --trust-roots trust-roots.json
```

`--base` carries over the previous list's entries and platform (after
verifying it) and the serial defaults to its serial + 1. **Lists in the
old `robodr-profile-revocations/v1` format (key ids) are refused**:
re-issue them with `revoke --platform ... --revoke-key KEY.pub` (one list
per platform) before upgrading the robots. Install the list and the roots
file on every robot of the platform:

```json
"profile_trust": { "trust_roots": "/etc/robodr/trust-roots.json",
                   "revocation_list": "/etc/robodr/profile-revocations.json",
                   "revocation_policy": "optional" }
```

A locked profile whose file digest or signing key fingerprint is listed is
refused (observe-only, `robot.ros2.profile_refused`), and so is every
locked profile when the list is for another platform. The list itself is
anti-rollback protected: its serial and digest are kept in the state file
and the black-box record, and the loaders refuse a list with a **lower**
serial, the **same** serial with other content, or a **missing** list after
one was accepted (to "clear" revocations, issue a newer, shorter list).
`revocation_policy = "required"` refuses every locked profile while no list
file exists; `"optional"` (default) proceeds without one until the first
list has been accepted. An invalid list (bad signature, not a root's key,
malformed) is always refused. `verify-profile --trust-roots ...
--revocations ...` runs the same check offline; `verify-revocations
--state` compares a list with a unit's accepted serial.

Limits: a trust root cannot be revoked by the list it signs (replace the
roots file instead); `issued_at` is not checked against a clock.

### 5.4 Operator attestation (two-person rule on the robot)

`lock` enforces the operator sign-off (every item confirmed, valid operator
signatures, `motion_quorum` distinct operators for motion items) on the
commissioning station. A profile signing key alone could otherwise build a
locked profile by hand, seal it and sign it, and the robot would never know
that no operator signed anything. So `lock` embeds the evidence in the
profile (`metadata.attestation`: the exact sign-off text and its operator
signature bundle), and every loader verifies it against the **operators
list in the trust file**:

- the sign-off is well formed, fully confirmed, names an operator, has an
  intact item digest and is for this model;
- it is bound to this profile's **content** (its `profile_sha256` equals the
  canonical digest of the profile as a draft), so evidence copied from
  another profile does not fit;
- the floor recomputed from the content (a confirmed review of every motion
  channel, every unbounded dimension) is met;
- every signature is valid over the exact sign-off bytes under a listed
  operator key (any unknown or bad one refuses), the sign-off's operator
  signed and is the profile's `locked_by`;
- with motion items, at least the trust file's `motion_quorum` distinct
  operators signed.

**Setup** (security officer, on the offline signing station):

```sh
robodr-commission operators --out operators.json \
    --operator Alice=alice.key.pub --operator Bob=bob.key.pub --motion-quorum 2
robodr-commission trust-keys --out profile-trust.json --pub oem-profile.key.pub \
    --operators operators.json --sign-key /secure/oem-root.key
```

Install `profile-trust.json` **and** `profile-trust.json.sig` on every robot
(step 6). Operator keys must differ from profile signing keys and trust
roots (refused otherwise: one person would both sign off and sign). On a
change of staff, issue a new operators list and a new root-signed trust
file; profiles already locked keep verifying as long as their signers stay
listed.

**When it is required.** With `trust_roots` configured, attestation is
required by default, and a trust file without `operators` is refused (every
locked profile then runs observe-only, with the reason). The root-signed
trust file can opt out (`trust-keys ... --no-require-attestation`, i.e.
`"require_attestation": false`) for a transition period, e.g. while
migrated legacy profiles (5.2) are re-commissioned; the opt-out gives the
two-person rule up on those robots. Without trust roots, attestation is
checked only if the trust file asks for it (`--require-attestation`), since
an unsigned trust file can be rewritten anyway.

**Upgrading a fleet:** (1) re-issue revocation lists as v2 (5.3); (2) build
the operators list and a root-signed trust file with `--operators`; (3)
re-lock every profile with this `robodr-commission` (profiles locked by an
older version carry no attestation and are refused) or ship the opt-out
first; (4) install trust file + `.sig`, profile + `.sig`, roots, list.
`verify-profile --trust-roots ...` shows the result offline before rollout.

Limits: the attestation proves that listed operators signed this exact
content; it cannot prove they reviewed it carefully, and colluding
operators (as many as `motion_quorum`) can still attest anything. The
operators list is only as trustworthy as the trust file: root-signed with
trust roots, editable by whoever can write it without.

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

`robodr-agentd` runs as `Type=notify` with `WatchdogSec=60s`; a hung main
loop is restarted. Its `status.json` carries `updated_mono_ms`, `boot_id` and
`stale_after_ms`: treat a stale or other-boot status as `unknown`.
`robodr-pulsard` has no watchdog (Pulsar does not send `sd_notify`
keep-alives), so a hung, still-alive pulsard is not restarted automatically.
Monitor the findings and heartbeat flow on the fleet side.

#### Crashes and restarts (`panic = "abort"`)

Release binaries are built with `panic = "abort"` (`Cargo.toml`,
`[profile.release]`): a panic anywhere, in any thread, ends the whole
process with `SIGABRT` at once. Nothing unwinds, no destructor runs, the
black box is **not** sealed and no `robodr.agentd_stop` note is written.
A hung main loop ends the same way: when no `WATCHDOG=1` arrives for
`WatchdogSec=60s`, systemd sends `WatchdogSignal=` (default `SIGABRT`).

What happens then, for `robodr-agentd`:

| Step | Behaviour |
|---|---|
| Exit | Killed by `SIGABRT` (core dump if enabled); systemd records `Result=core-dump` / `signal` (or `watchdog`). |
| Restart | `Restart=on-failure` restarts it after `RestartSec=5s`. Exit code 2 (configuration error) is never restarted (`RestartPreventExitStatus=2`). |
| Give up | More than `StartLimitBurst=5` starts in `StartLimitIntervalSec=300` leave the unit **failed**: alert on it (the robot is unwatched, its own operation is unaffected). |
| Evidence | The black box keeps every record that reached disk; the restarted daemon authenticates the unsealed tail and chains onto the aborted run (a torn tail is handled as for any crash, see `crates/robodr-blackbox/README.md`), and the next graceful stop seals the whole chain. Findings already in the spool stay there. |
| Status | Until the restart, `status.json` still says `"running": true` with an old `updated_mono_ms`: consumers must treat it as stale (`unknown`), see 6.1. |

The process-level test `crates/robodr-agentd/tests/abort_restart.rs` does
exactly this with the real binary: record, `SIGABRT`, restart on the same
state, record, graceful stop, then verify the whole chain end to end and
both findings in the spool.

The control plane's request journal and replay store (6.4) are fsynced
before an answer leaves agentd, so a SOC sees the same request states after
the restart; a request whose executor order was staged but not yet sent
stays `pending` (the order is dropped, never sent late).

For `robodr-executor` (6.5) a crash or watchdog abort runs the unit's
`ExecStopPost=robodr-executor stop-cleanup`, which deletes the `inet robodr`
table: no action stays in force without a process that can revert it.
`Restart=always` (`RestartSec=2s`, exit code 2 not restarted) brings it
back, and it reconciles its journal against the table at start (6.5). Only
a clean `systemctl stop` keeps actions in force for the next start.

Panics are kept out of the daemon's code paths by lint and by fuzzing:
`robodr-agentd`, `robodr-agent`, `robodr-ros2-pipeline`, `robodr-capture`
and `robodr-rtps` (and their binaries) deny `unwrap` / `expect` / `panic!` /
`unreachable!` / `todo!` / `unimplemented!` outside tests, every integer
division on those paths has a non-zero divisor by construction, and the
parsers that read bus or file input have libFuzzer targets (`fuzz/`).
`robodr-executor` (library and binary) denies the same calls; its order
protocol has no libFuzzer target yet. `robodr-fleet` and `robodr-enroll`
(8.6) deny them too; their token and envelope parsers have libFuzzer
targets (`fleet_token`, `fleet_envelope`), and an aborted lifecycle step
resumes from its journal at the next run.
Slice indexing and overflowing arithmetic are not denied by lint (several
hundred reviewed sites; overflow does not panic in release builds, which do
not enable `overflow-checks`): they rely on review and fuzzing. Other units
(`robodr-uplink`, `robodr-spool-export`, `robodr-pulsard`) follow the same
`Restart=on-failure` rules.

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

### 6.4 agentd features (`/etc/robodr/agentd.json`)

Two examples are installed under `/usr/share/doc/robodr/examples/`.
`agentd.example.json` names only what a commissioned robot has with the
shipped unit (profile, `profile-trust.json`, response policy, the black-box
key credential) and passes `--check-config` when copied verbatim.
`agentd.full.example.json` adds every key below that needs an extra file:
`trust_roots` and `revocation_list` (from the trust-root ceremony) and
`finding_signing`, whose key reaches the daemon only through the drop-in
`robodr-agentd.service.d/20-finding-key.conf.example` (install the drop-in
and the key together, or the unit does not start), and `control_plane`,
which needs the SOC's public key file, the TLS files and the finding key
(below; drop-in `30-control-plane.conf.example`). Copy the keys you need
from it once their files exist, and check every edit with
`robodr-agentd --config /etc/robodr/agentd.json --check-config`.

**Live safety state (`safety_feed`).** Plans are graded by the robot's
safety state. Without a feed, the static `context.safety_state` is used.
With one, agentd reads it **passively**: ROS 2 topics decoded from captured
user DATA (`std_msgs/Bool`, `UInt8`, `String` mapped to states;
`nav_msgs/Odometry` speed with hysteresis to idle / moving slow / moving
fast), and/or a `0600` unix socket of JSON lines from a safety-PLC gateway
(`{"state":"estop_active"}`; put it under `/run/robodr-agentd/`; only
root, agentd's own user `robodr-agentd` and the configured feeders may
report: `socket_mode` / `socket_group` / `allowed_uids` /
`allowed_gids`, every connection checked with `SO_PEERCRED`, section
11.1). A stale source reads `unknown`; disagreeing
sources resolve to the most conservative state. Every topic source must
list its commissioned `writers` (GUID prefixes or writer GUIDs; the
configuration is refused without them). A sample is used only if its
writer is profiled, in that list, and arrived from an IP bound to its
participant (SPDP seen since start-up, or pinned in
`sensor.binding.participant_ips`); anything else is ignored and raises
`robot.safety_state.untrusted_source` (High). Pin the safety writers'
participants: after a restart an unpinned source reads `unknown` until its
participant's next SPDP, and a profiled prefix announced from two hosts
becomes *contested* (Critical `robot.ros2.participant_source_mismatch`):
no source is trusted for it until it is pinned. More fresh writers (or
socket connections) than a source keeps raise
`robot.safety_state.writer_overflow` (High) and read `unknown`; a more
conservative reading is never evicted for a less conservative one. Each
socket connection is a separate writer (redundant gateways combine
most-conservative). Odometry sources treat turning on the spot as moving
(`angular_moving_above`, default 0.1 rad/s). Leave `context.safety_state`
at `unknown` when a feed is configured (the configuration is refused
otherwise). Every change of the combined state is a
`robodr.safety_state_transition` note in the black box; `status.json`
shows `safety_state` and the feed view. Nothing is ever published to the
robot or its safety system. Verified on synthetic traffic only.

**Correlation (`correlation`, on by default).** Combines findings that were
each reported on their own into `robot.correlate.*` findings (discovery
flood, spoofed motion source, motion hijack, ...; the full list is in
`crates/robodr-correlate/README.md`). Each correlated finding cites every
contributing finding (a `robodr.correlated_finding` note in the black box)
and is observe-only whenever one of them was. Add site rules with
`"rules_path": "/etc/robodr/correlation-rules.json"` (validated together
with the shipped rules; a rule file that does not load refuses the
configuration), drop the shipped ones with `"include_default_rules": false`,
or turn it off with `"enabled": false`. The rules are engineering defaults,
not tuned on fleet data: run the first field period observe-only. Rules
that need host (Pulsar) detections fire only with `host_threats` (below).
`robot.agent.correlation_pressure` (observe-only) means the engine had
to evict pending state: many fresh source addresses or participants within
a window. Pending state of the robot's own entities (profiled participants,
IPs bound or pinned to them) and of High / Critical first steps is
protected from such floods; when evidence is evicted anyway, the
observe-only `robot.correlate.correlation_state_evicted` names the rule.

**Host threats (`host_threats`, optional).** Hands every Pulsar threat
(the RoboDR host rules in `/usr/share/robodr/rules/robodr` and Pulsar's own)
to agentd, so the host-dependent correlation rules (`coordinated_intrusion`,
`credential_theft`, `trojaned_package_key_access`, `defense_tampering`,
`host_process_persistence`) can fire. The Pulsar module
`robodr-threat-forward` (in `robodr-pulsard`) writes one JSON line per
threat to a unix socket agentd binds; it skips the ROS 2 sensor's own
threats (agentd sees those through its own capture). Enable both ends:

```sh
# 1. agentd.json (socket under agentd's RuntimeDirectory):
#    "host_threats": { "socket_path": "/run/robodr-agentd/host-threats.sock",
#                      "socket_mode": "0660" }
sudo robodr-agentd --config /etc/robodr/agentd.json --check-config
# 2. robodr-pulsard may reach the 0660 socket only through agentd's group
#    (it has no CAP_DAC_OVERRIDE):
sudo install -D -m 0644 /usr/share/doc/robodr/examples/robodr-pulsard.service.d/30-host-threats.conf.example \
    /etc/systemd/system/robodr-pulsard.service.d/30-host-threats.conf
# 3. /etc/robodr/pulsar.toml:
#    [module.robodr-threat-forward]
#    enabled = true
#    socket_path = "/run/robodr-agentd/host-threats.sock"
sudo systemctl daemon-reload && sudo systemctl restart robodr-agentd robodr-pulsard
```

agentd refuses to start if the socket's directory is writable by group or
others or not owned by root / `robodr`, or if the path is something other
than a socket of its own. Only peers with uid 0 (or `allowed_uids`) may
send (`SO_PEERCRED`); other connections are closed and counted
(`rejected_connections`) and reported as `robot.agent.input_malformed`.
Each threat becomes a `robot.host.pulsar_threat` finding (the Pulsar rule
name and the process are in its detail; severity from the rule) and a
correlation signal named by the Pulsar rule, grouped by process
(pid). The forwarder writes a heartbeat at connect and every
`heartbeat_ms` (default 5 s) when idle: with `host_threats` configured and
`robodr-pulsard` stopped or the module disabled, the input goes silent,
`robot.agent.input_silent` is raised and the state is `unknown`, never
`ok`. Threats the forwarder could not deliver (queue full while agentd was
away) arrive as its `dropped` count and are reported like queue drops
(`robot.agent.queue_overflow`). `status.json` shows the input
(`host:<path>`: `received`, `malformed`, `rejected_connections`,
`connections`, `upstream_dropped`) and `daemon.host_threats`,
`host_heartbeats`, `host_threats_own_skipped`. Process-to-socket
attribution does not exist yet: unit-scoped rules join host and network
evidence by time window only.

**Finding signatures (`finding_signing`, optional).** Signs every finding
with a dedicated Ed25519 key (contract §2a); the signature is the spooled
record's last header, `robodr-finding-sig`, and `robodr-kafka-publish
--spool` forwards it. Never reuse the black-box key (refused):

```sh
sudo robodr-blackbox keygen --out /etc/robodr/keys/agentd-finding.key --key-id finding:ugv-07:1
sudo install -D -m 0644 /usr/share/doc/robodr/examples/robodr-agentd.service.d/20-finding-key.conf.example \
    /etc/systemd/system/robodr-agentd.service.d/20-finding-key.conf
# agentd.json: "finding_signing": { "key_file": "/run/credentials/robodr-agentd.service/finding.key" }
sudo systemctl daemon-reload && sudo systemctl restart robodr-agentd
```

Give the `.pub` to the SOC's finding keyring for this unit id. Across the
diode the per-finding signature is **not** carried (the batch is signed
instead; contract §8), so diode-side consumers must verify in `Optional`
mode.

**Control-plane API (`control_plane`, optional, off by default).** The
SOC API `robodr-control-plane/v2` (contract
`docs/contracts/robodr.control-plane.md`, installed under
`/usr/share/doc/robodr/contracts/`). A SOC may *request* one of the seven
catalog actions on this robot (`restrict_motion`, `quarantine_node`,
`isolate_network`, `record_evidence`, `safe_pause`, `request_safe_state`,
`rollback_config`) and export black-box evidence. agentd judges each
request against the safety state at that moment and the response policy,
records it in the black box and in its request journal, and answers.
**Nothing is executed unless executor v1 is enabled** (section 6.5, off by
default): an accepted request is answered `recorded_not_executed`, a
refused one `refused` with a reason (always while
the e-stop or safe state is active, for everything but `record_evidence`
while the policy is not OEM-validated, for `safe_pause` /
`request_safe_state` when the response policy's `morphology` is `humanoid`
— de-energising a humanoid makes it fall — and for `rollback_config` on a
humanoid or quadruped, or a `restrict_motion` cap below the policy's
`min_motion_factor` there: a legged robot balances actively, also while
idle). The response policy must declare `morphology` once it is
OEM-validated or its platform is `other`; see
`config/response-policy.unitree-g1.example.json` /
`…unitree-go2.example.json`.

Two locks protect it and both are required: **mutual TLS** on the network
listener (the SOC's client certificate, issued by a CA the robot trusts)
and an **Ed25519 signature** on every request (the SOC's signing key).
Every answer is signed with the robot's finding key. Plain HTTP exists only
on loopback and on the unix socket.

```sh
# --- On the SOC side, once ----------------------------------------------
# 1. The SOC signing key (keep the secret there). Name it after the SOC
#    instance: soc:<id>:<n>.
robodr-blackbox keygen --out soc-a.key --key-id soc:soc-a:1
# 2. The SOC's client-certificate CA and the SOC client certificate
#    (EC P-256 shown; keep the CA key offline). The client certificate
#    needs extendedKeyUsage=clientAuth.
openssl ecparam -name prime256v1 -genkey -noout -out soc-ca.key
openssl req -new -x509 -key soc-ca.key -subj "/O=<org>/CN=<org> SOC CA" \
    -days 3650 -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out soc-ca.pem
openssl ecparam -name prime256v1 -genkey -noout -out soc-client.key
openssl req -new -key soc-client.key -subj "/O=<org>/CN=soc-a" -out soc-client.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' >client.ext
openssl x509 -req -in soc-client.csr -CA soc-ca.pem -CAkey soc-ca.key \
    -CAcreateserial -days 825 -extfile client.ext -out soc-client.pem
# (optional) the pin of that certificate's public key:
openssl x509 -in soc-client.pem -pubkey -noout | openssl pkey -pubin -outform DER \
    | sha256sum | cut -d' ' -f1

# --- Per robot -------------------------------------------------------------
# 3. The robot's TLS server key and certificate, issued by the CA the SOC
#    uses for robots; SAN = the address / name the SOC connects to,
#    extendedKeyUsage=serverAuth. The key never leaves the robot:
sudo openssl ecparam -name prime256v1 -genkey -noout | \
    sudo openssl pkcs8 -topk8 -nocrypt -out /etc/robodr/keys/agentd-cp-tls.key
sudo chmod 0600 /etc/robodr/keys/agentd-cp-tls.key
sudo openssl req -new -key /etc/robodr/keys/agentd-cp-tls.key -subj "/O=<org>/CN=ugv-007" \
    -addext "subjectAltName=IP:10.0.7.7" -out ugv-007.csr     # sign it at the robot CA
sudo install -D -o root -g root -m 0644 ugv-007.pem   /etc/robodr/control-plane/robot.pem
sudo install -D -o root -g root -m 0644 soc-ca.pem    /etc/robodr/control-plane/soc-ca.pem
sudo install -D -o root -g root -m 0644 soc-a.key.pub /etc/robodr/soc/soc.pub
# 4. The finding key (answers are signed; section 6.4 finding_signing) and
#    the drop-ins: credentials, state directory, the SOC network.
sudo install -D -m 0644 /usr/share/doc/robodr/examples/robodr-agentd.service.d/30-control-plane.conf.example \
    /etc/systemd/system/robodr-agentd.service.d/30-control-plane.conf
sudoedit /etc/systemd/system/robodr-agentd.service.d/30-control-plane.conf   # IPAddressAllow=
# 5. agentd.json:
#   "control_plane": {
#     "listen_tcp": "10.0.7.7:8787",
#     "tls": { "cert_chain": "/etc/robodr/control-plane/robot.pem",
#              "key_file": "/run/credentials/robodr-agentd.service/cp-tls.key",
#              "client_ca": "/etc/robodr/control-plane/soc-ca.pem",
#              "client_crl": "/etc/robodr/control-plane/soc-ca.crl.pem",   # optional
#              "client_spki_sha256": ["<pin from step 2>"] },
#     "unix_socket": "/run/robodr-agentd/control.sock",
#     "state_dir": "/var/lib/robodr/control-plane/agentd",
#     "soc_keys": ["/etc/robodr/soc/soc.pub"],
#     "evidence": {} }
sudo systemctl daemon-reload
sudo robodr-agentd --config /etc/robodr/agentd.json --check-config
sudo systemctl restart robodr-agentd
# 6. Give the SOC: the robot's address, its CA (or the robot.pem SPKI pin,
#    status.json control_plane.tls.server_spki_sha256), the finding .pub
#    (answers, manifests) and the black-box .pub (evidence bundles).
```

- `state_dir` holds the request journal, the replay store and evidence
  exports. It must be a directory of its own, mode 0700, owned by the
  daemon's user (tmpfiles creates `/var/lib/robodr/control-plane/agentd`);
  agentd refuses to start otherwise. Do not edit or copy files into it.
- The SOC key file must be a public Ed25519 key file owned by root (or
  `robodr`), not writable by group or others, not a symlink; a `device_id`
  in it must be this robot. Never list the robot's own black-box or finding
  key (refused). The TLS key file must have no group/other bits (the
  systemd credential copy has none); certificate files must not be
  group/other-writable.
- The SOC signs every request (contract §2) and needs a clock within
  `max_clock_skew_s` (default 30 s) of the robot's: run NTP on both, or
  requests are refused `stale_timestamp`.
- **First start.** The replay store is created at the first start (and
  whenever `state_dir` was emptied): agentd cannot tell that from a wiped
  store, so it fences and refuses every request for `max_clock_skew_s`
  (default 30 s) after the start (`stale_timestamp`; the SOC signs again).
  Expect that once after commissioning.
- **Restart.** Request states and used nonces survive a restart: the SOC
  can query a request after it and a replay stays refused. If the replay
  store was damaged or removed, or the robot's clock went back below the
  store's high-water mark, agentd fences: requests signed up to
  `max_clock_skew_s` after the start are refused `stale_timestamp` (the
  SOC signs again; `status.json` `control_plane.replay_fence`). A damaged
  journal is copied to `state_dir/quarantine/` and the start note says so.
  Only one torn last line counts as a crash; anything more is damage. A
  damaged request journal is rebuilt from the black box's request and
  revert notes (`state.rebuilt_from_blackbox`); if the black box cannot be
  read, agentd refuses every new request id (503 `state_unavailable`,
  `state.refusing_new_request_ids`) until a restart with a readable black
  box: fix the black box (section 6.4, black-box upkeep) and restart.
- **Connections.** TCP connections in the TLS handshake (or not yet
  authenticated) and authenticated ones have separate slots of
  `max_connections` (default 4) each; one source address holds at most
  `max_connections_per_source` (default 2): raise it if several SOC
  workers share one NAT address. The unix socket has its own 2 slots, so
  an operator on the robot is never locked out by network peers. Rejected
  connections count in `connections_rejected`.
- Watch `status.json` `control_plane` (`unauthenticated`, `tls_failures`,
  `last_auth_failure`, `connections_rejected`, `recorded_not_executed`,
  `refused`, `busy`, `rate_limited`, `journal_errors`, `replay_fence`,
  `state.refusing_new_request_ids`, `evidence`) and the
  findings `robot.agent.control_plane_unauthenticated` (High: someone
  without the certificate or the key is trying) and
  `robot.agent.control_plane_invalid` (Medium: the SOC sent something the
  API never allows). Each decision is a `robodr.control_plane_request` note
  in the black box with the SOC's signature, which re-verifies offline.

**Rotation (no downtime for the SOC).**

| What | How |
| --- | --- |
| SOC signing key | add the new `.pub` to `soc_keys` (both listed), restart agentd, and to `executor.json` `soc.keys` (re-read per order); switch the SOC; remove the old one from both, restart agentd |
| SOC client certificate, same CA | issue the new certificate; with pins, add the new pin to `client_spki_sha256` first (both listed), restart; switch the SOC; remove the old pin |
| SOC client CA | append the new CA certificate to `client_ca` (PEM bundle with both), restart; reissue the SOC certificate; remove the old CA, restart |
| Robot TLS certificate / key | install the new `robot.pem` and key (same paths), restart agentd; if the SOC pins the robot's SPKI, give it the new pin first (`openssl x509 -pubkey ...` as above) |
| SOC client CRL | install the new CRL file (same path, `client_crl`), restart agentd |
| Finding key (answers, manifests) | section 4.3; give the SOC the new `.pub` before the restart |

TLS material and keys are read at start only: every change takes a
restart, which keeps the request state. To cut off a client certificate,
revoke it in the client CA's CRL and install that as `tls.client_crl`
(PEM, X.509 v2; `openssl ca -gencrl`), or remove its pin or its CA, and
restart. With `client_crl` every client CA needs a CRL in the file (a
certificate whose issuer has none is refused); its `nextUpdate` is not
enforced, so refresh it on your own schedule. There is no OCSP.

**Evidence export (`control_plane.evidence`).** The SOC lists the retained
evidence (`GET .../evidence`), asks for an export of a finding's evidence
links (or a seq / time range), downloads it in chunks (resumable, they
survive a restart) and verifies it with the robot's public keys (contract
§11.6). An analyst can check a downloaded bundle offline:

```sh
robodr-blackbox verify bundle.rbbx --keyring agentd-blackbox.key.pub --device ugv-007 \
    [--signing-key <manifest chain.signing_key.key_id>]   # exit 0 = intact
```

Exports are kept in `state_dir/exports/` until they expire
(`export_ttl_s`, default 24 h) or the SOC deletes them; `max_exports`,
`max_export_bytes` (at most 256 MiB) and `max_storage_bytes` bound the
space they take, and an export is refused (507 `storage_full`) unless
64 MiB stay free on the filesystem of `state_dir` (the request and nonce
journals live there). A bundle is streamed to disk while it is built, and
a build that takes over 60 s, or meets a shutdown, is abandoned (503
`evidence_timeout`). Each export is a `robodr.control_plane_evidence_export`
note in the black box.

**Black-box upkeep.** Every tick writes the black box's `head.json`
high-water mark when records were added since the last one. If the
recorder found damaged segments when it opened, they are moved to
`<blackbox>/quarantine/` (with a signed recovery record) and agentd raises
`robot.agent.evidence_quarantined` (observe-only) with the recorder's
severity: High = framing/hash damage in an older segment (failing storage
or an edit), Critical = tampering (a stray segment file above the live
one, a closed segment cut on a frame boundary, the newest segment gone).
If authentic state proves the newest records were cut, agentd raises
Critical `robot.agent.evidence_truncated`. Keep the quarantined files for
the investigation.

**Head anchor.** `blackbox.head_anchor` is optional; without it agentd
warns at start and `status.json` reports `"blackbox": {"anchored":
false}`: `head.json` alone cannot reveal a cut of the newest records
together with a rolled-back `head.json`, or a wiped store.
`{"kind": "file", "path": "/abs/path"}` keeps the mark in a file outside
`blackbox.dir` and `spool.dir`; it is only as strong as the storage it
lives on. **A deployment must anchor to a TPM NV monotonic counter** (kind
`tpm_nv_counter`, below) **or a remote receiver** (kind `remote`, below).

**TPM NV counter anchor** (`tpm_nv_counter`). The TPM counter counts the
black box's head marks and can never go back; a sidecar file signed with
the black-box key binds the count to the newest mark. An attacker who
cuts the log and restores older copies of `head.json`, `checkpoint.json`
and the sidecar is caught: the counter is ahead of the sidecar, and agentd
raises Critical `robot.agent.evidence_truncated`. A deleted or forged
sidecar, a redefined index or a cleared TPM cannot be bounded: the open
counts an anchor failure (`status.json` `anchor_failures`) and names it in
the black box's signed `Resume` record; treat that as tamper evidence.
Needs `tpm2-tools` 5.x and access to the TPM (`/dev/tpmrm0`).

Provision once per unit (as root, before the first start with the anchor):

```sh
# Pick a free owner NV index (tpm2_getcap handles-nv-index lists used ones).
robodr-blackbox tpm-anchor-init --index 0x01500020
#   [--owner-auth-file /path/owner.auth]   owner hierarchy password, if set
#   [--index-auth-file /path/index.auth]   optional index password
robodr-blackbox tpm-anchor-check --index 0x01500020
# Strongly recommended: set owner and lockout authorization and keep the
# values off the unit, so root cannot undefine the index or clear the TPM:
#   tpm2_changeauth -c owner file:...; tpm2_changeauth -c lockout file:...
```

The index gets `authread|authwrite|nt=counter|no_da`, size 8: a counter
(only increments), read and incremented with the index's own
authorization (empty unless `--index-auth-file`), so agentd needs neither
the owner password nor any policy session; `no_da` keeps wrong index
passwords from triggering the TPM's dictionary-attack lockout (which
would affect every other TPM user; a guessed index password only allows
increments, i.e. false alarms). It is not `orderly`: an orderly counter
jumps forward after each power loss, which would read as a truncation.
The command refuses an index that already exists.

```json
"blackbox": {
  "dir": "/var/lib/robodr/blackbox/agentd",
  "key_file": "/run/credentials/robodr-agentd.service/blackbox.key",
  "head_anchor": {
    "kind": "tpm_nv_counter",
    "nv_index": "0x01500020",
    "sidecar_path": "/var/lib/robodr/anchor/blackbox-tpm-sidecar.json",
    "tcti": "device:/dev/tpmrm0",
    "tools_dir": "/usr/bin",
    "auth_file": "/etc/robodr/keys/tpm-index.auth",
    "min_increment_interval_ms": 60000,
    "timeout_ms": 2000
  }
}
```

Only `kind`, `nv_index` and `sidecar_path` are required; the rest show
the defaults (`auth_file`: none, empty authorization). `sidecar_path` must
be absolute and outside `blackbox.dir` and `spool.dir` (a wiped log
directory must not take the sidecar with it); its directory must exist
(create it 0700). `min_increment_interval_ms` (0..=86400000) bounds NV
wear: one increment per interval at most (60 s = about 525,000 a year;
check the NV write endurance in your TPM's datasheet and raise it if
needed). A longer interval only widens the window in which a restored
sidecar of the same count goes unnoticed. Each tool call is killed after
`timeout_ms` (100..=30000). A TPM error never stops recording.
Re-provisioning (new index, or `tpm2_nvundefine` + init): also move the
old sidecar away, or the next open reports the anchor as reset.

Limits: tested against swtpm (`scripts/swtpm-anchor-it.sh`), not yet on a
hardware TPM. Root on the unit can still use the index; the guarantee is
that rollback and truncation become detectable, not that they are
prevented. The window is the newest marks: records after the last mark
(at most 16 records or 1 s, see the black-box README) and, against an
attacker who restores a sidecar of the same count, up to
`min_increment_interval_ms`.

**Remote anchor** (`remote`). The head marks go to
`robodr-anchor-receiver` on a **base station or fleet host** (never the
robot itself), which keeps per robot the highest mark and only ever raises
it. At every start agentd asks for that mark with a fresh nonce; the answer
is signed by the receiver's key and carries the robot's own signed mark, so
a cut log with rolled-back state files is reported as Critical
`robot.agent.evidence_truncated`, and a wiped store too. A receiver that is
down or unreachable never stops recording: the open counts an anchor
failure (`status.json` `anchor_failures`, named in the signed `Resume`
record); marks are queued (newest only) and resent when it is back.

Requirements: an **Ed25519** black-box key (the receiver verifies marks with
its public half; HMAC is refused) and a **reverse channel** from the robot
to the receiver (TCP, default port 7461) at least when agentd starts. A
robot that is air-gapped during the mission needs a receiver on its local
base station (private link), or the detect-only mode below.

Receiver keys and config, on the base station (as root):

```sh
install -d -m 0700 /etc/robodr-anchor-receiver
install -d -m 0755 /etc/robodr-anchor-receiver/units
robodr-blackbox keygen --out /etc/robodr-anchor-receiver/receiver.key --key-id anchor-rx-site1
# carry receiver.key.pub to every robot (vetted media), e.g.
#   /etc/robodr/anchor-receiver.pub (0644, root)
# carry each robot's black-box public key here (from section 4.2), e.g.
#   /etc/robodr-anchor-receiver/units/ugv-07.pub
```

`/etc/robodr-anchor-receiver/receiver.json`:

```json
{
  "listen": "0.0.0.0:7461",
  "state_dir": "/var/lib/robodr-anchor-receiver",
  "key_file": "/run/credentials/robodr-anchor-receiver.service/receiver.key",
  "units": [
    {"unit": "ugv-07", "public_key": "/etc/robodr-anchor-receiver/units/ugv-07.pub"}
  ],
  "max_connections": 64,
  "io_timeout_ms": 5000
}
```

`unit` is the robot's `robot.id`; a public key bound to a device
(`keygen --device`) must name that robot. Then
`systemctl enable --now robodr-anchor-receiver` (the unit runs as a dynamic
user, gets the key through `LoadCredential=`, keeps its state in
`/var/lib/robodr-anchor-receiver`). Restrict who may connect with an
`IPAddressAllow=` drop-in; every mark and answer is authenticated anyway.
`robodr-anchor-receiver status --config /etc/robodr-anchor-receiver/receiver.json`
prints the held seq and alert count per robot: **watch it** (a robot whose
held seq stops moving while it runs has lost its link, or someone is
suppressing its marks).

On the robot (`agentd.json`):

```json
"head_anchor": {
  "kind": "remote",
  "address": "10.20.0.1:7461",
  "receiver_public_key": "/etc/robodr/anchor-receiver.pub",
  "timeout_ms": 2000
}
```

`address` is `host:port` (an IP literal avoids DNS at start);
`receiver_public_key` must be absolute and outside `blackbox.dir` and
`spool.dir`; `timeout_ms` (100..=30000, default 2000) bounds connect, write
and read each, so a start waits at most about three times that for the
receiver. Marks never wait for the network.

**Alerts.** The receiver refuses and records (journal line,
`/var/lib/robodr-anchor-receiver/alerts.jsonl`, per-robot counter): `lower`
(a mark below the held one: the robot went back, e.g. it started without
reaching the receiver after a rollback, or an old mark was replayed),
`fork` (another record at the held seq: the log was rewritten with the
robot's key), `bad_signature`, and `chain_change` (a higher mark of a new
chain: a replaced store, stored). `state_unusable` means a state file in
`units/` no longer verifies: that robot is refused until you investigate;
nothing resets it silently. Treat every alert as tamper evidence until
explained.

**Key rotation** (section 4.3) is a new chain: when a robot's black-box key
changes, replace its `.pub` on the receiver and move
`/var/lib/robodr-anchor-receiver/units/<robot>.json` into the archive with
the old chain (with the service stopped). Replacing the receiver key: give
every robot the new `.pub` at the same time.

**Detect-only through the diode** (no reverse channel at all). On the robot,
with the export (section 8):

```sh
robodr-blackbox anchor-mark /var/lib/robodr/blackbox/agentd \
  --key /etc/robodr/keys/agentd-blackbox.key --unit ugv-07 \
  --out /var/lib/robodr/export/anchor-mark-$(date -u +%Y%m%dT%H%M%SZ).json
```

On the high side, in order of the files' times:

```sh
robodr-anchor-receiver ingest --config /etc/robodr-anchor-receiver/oneway.json FILE...
```

(exit 1 = a mark was refused and alerted). Use a separate root-owned 0700
`state_dir` for one-way ingest (`ingest` needs the directory's lock, so it
cannot share one with a running `serve`). The robot is never told; a
rollback is detected on the far side, at the next mark that arrives.

Limits: tested over loopback with a real receiver process, not across a
real network. Rollback and truncation become detectable, not prevented;
the window is the newest marks that have not reached the receiver. No TLS:
marks (hashes, sequence numbers) are visible on the wire.

### 6.5 Executor v1 (`robodr-executor`, reversible actions)

Off by default. With `executor.enabled` absent or `false`, every accepted
control-plane request stays `recorded_not_executed` and nothing reaches
the robot. With it, an accepted request of an executor action is
answered `pending` and then reads `verified`, `refused` (the executor's own
checks), `failed` or, after a revert or its TTL, `reverted` (contract
§6a). Every answer is signed like any v2 answer, and every state the
executor reports is written to the control plane's request journal
(`state_dir`) before it is answered, so a request reads the same after an
agentd restart (agentd also asks the executor once, at start, about the
requests still open). Enable the executor only after commissioning
(section 5), with an OEM-validated response policy, and after the
acceptance check below.
Design, safety argument and limits are in
[`crates/robodr-executor/README.md`](../crates/robodr-executor/README.md).

**What it does.** It executes two reversible actions, as nftables rules in
its own table `inet robodr`, plus an evidence mark:

| Action | Effect | Lifted |
|---|---|---|
| `isolate_network` | everything dropped except loopback, the management and uplink allow-lists, the control buses (configurable), the motion control path, the robot's DDS discovery (SPDP multicast, IGMP), the DHCP client, path MTU discovery and IPv6 neighbour / router discovery | on revert or TTL |
| `quarantine_node` | one DDS participant dropped (by RTPS GUID prefix and by its SPDP locators, which agentd must have seen and which must lie outside the motion control path; that path is never cut, even by traffic carrying the quarantined prefix) | on revert or TTL |
| `record_evidence` | a signed black-box mark | never: evidence is not reverted |

`restrict_motion` is recorded as advisory: the executor does not drive the
inline gateway (section 6.6), which enforces its own locked profile. The
executor never sends `safe_pause`, `request_safe_state` or
`rollback_config`.

**Capability model.**

| Unit | User | Capabilities | Network |
|---|---|---|---|
| `robodr-agentd` | `robodr` | `CAP_NET_RAW` (capture) | AF_PACKET read, no IP |
| `robodr-executor` | `robodr-exec` (group `robodr`) | `CAP_NET_ADMIN` only | AF_UNIX + AF_NETLINK, `IPAddressDeny=any` |
| `robodr-firewall-gw` (section 6.6, sensor box) | `robodr` | `CAP_NET_ADMIN` only (NFQUEUE) | AF_UNIX + AF_NETLINK, `IPAddressDeny=any` |

agentd talks to the executor over `/run/robodr-executor/executor.sock`
(0660, group `robodr`), using an HMAC-authenticated protocol with a key
held only in `/etc/robodr/keys/executor.key`. Each unit receives the key
as a systemd credential. The executor runs `/usr/sbin/nft` (JSON,
argument vector, empty environment) and never touches any other nftables
table.

**Enable.**

1. Install `nftables` (and `iproute2` for the checks below):
   `apt install nftables iproute2`.
2. Generate the protocol key:
   `robodr-executor keygen --out /etc/robodr/keys/executor.key`
   (written 0600; an existing key is never overwritten).
3. Write `/etc/robodr/executor.json` from
   `/usr/share/doc/robodr/examples/executor.example.json` (Unitree:
   `config/executor.unitree-g1.example.json`). Set the following:
   * `policy_path`: the **same** response policy file agentd uses. The
     executor takes the robot's morphology and `fall_safe_restrict` from
     it.
   * `network.management`: required. Isolation is refused without it, so
     it can never cut the SOC off. List the operator and SOC addresses
     (every address the mutual-TLS control plane accepts: the
     `IPAddressAllow=` of `30-control-plane.conf`), and, if the robot
     depends on them, its DNS, NTP and DHCP servers.
   * `network.uplink`: the findings uplink (`robodr-uplink`'s ingest API).
   * `network.control_buses`: the robot's internal controller networks,
     kept open while `exempt` is `true` (the default).
   * `network.motion_control_path`: every address or interface (with an
     optional UDP port range, the ports **as destination**, and an optional
     DDS participant `guid_prefix` that narrows it) that carries motion
     commands. Every entry needs `cidr` and/or `interface`: a GUID prefix
     alone is refused (anyone can write it into an RTPS header). These
     entries are never cut. Mark the low-level / balance loop
     `low_level: true`: it is never cut, whatever the policy says, and no
     quarantine is possible inside it. An entry with an interface and no
     `cidr` blocks every quarantine (no locator can be proven outside it).
   * `network.discovery`: the SPDP multicast groups and DDS domains kept
     open during isolation (default `239.255.0.1`, domain 0: ports 7400
     and 7401). List your `ROS_DOMAIN_ID`s.
   * `ttl.default_s` / `ttl.max_s`: every executed action is lifted at its
     TTL.
   * `soc.keys`: the SOC public key files, the **same** files as agentd's
     `control_plane.soc_keys` (root-owned, `0644`). The executor verifies
     every SOC approval itself with them (trust boundary M1): without
     them every control-plane order is refused (`soc_signature_invalid`).
     Rotate them together with agentd's. Keep `soc.max_clock_skew_s`
     (default 30) at least agentd's `max_clock_skew_s`. One key file the
     executor cannot read or refuses blocks **every** control-plane order
     (`soc_keys_unavailable`, the start log names the file). Reverts of a
     SOC-approved action need the SOC's signed revert request (agentd
     forwards it; unsigned reverts are refused, the action stays).
   * `soc.robot_keys`: the robot's own public keys (the black-box and
     finding keys' public halves, e.g. `robodr-blackbox keygen` public
     files): never accepted as SOC keys.
   * `network.quarantine.cidrs`: the networks where a participant may be
     quarantined (its SPDP locators must be there, on the robot's DDS
     ports); empty refuses every quarantine (`locator_out_of_scope`).
   * `require_approval_for_all_containment: true` makes every containment
     wait for the SOC (the on-robot planner's orders are refused).
4. Check the configuration:
   `robodr-executor --config /etc/robodr/executor.json --check-config`.
   The running executor re-reads the configuration and the response
   policy before every order (no reload needed); an unreadable or invalid
   file refuses orders (`config_unavailable`) until it is fixed.
5. Give agentd the key with the drop-in example
   `robodr-agentd.service.d/30-executor.conf.example` (section 6.4
   explains how drop-ins are installed). Then add to `agentd.json`:
   ```json
   "executor": {
     "enabled": true,
     "socket": "/run/robodr-executor/executor.sock",
     "key_file": "/run/credentials/robodr-agentd.service/executor.key",
     "planner_orders": false
   }
   ```
   `planner_orders: true` (the default) also hands the on-robot planner's
   executable steps to the executor. These are Eligible plans that need no
   human under the OEM-validated policy. Start with `false`, which limits
   execution to SOC-approved requests.
6. Run `systemctl enable --now robodr-executor`, then
   `systemctl restart robodr-agentd`. agentd logs
   `executor v1 enabled (...)`.

**Acceptance check before relying on it** (on the robot, with the E-stop
in reach):

1. Submit `isolate_network` with `ttl_seconds: 60` from the SOC.
2. Confirm the request state is `verified`.
3. Confirm `nft list table inet robodr` shows the rules.
4. Confirm management access and the robot's motion stack keep working.
5. Confirm a host outside the allow-list cannot reach the robot.
6. Confirm the state turns `reverted` after 60 s and the table is gone.

**Emergency disable** (any time, as root):

```sh
nft delete table inet robodr
```

The executor detects the missing table before its next transaction (a
new order, a revert, a TTL expiry) or within `verify_interval_s`. It drops
every action as `removed_externally`, re-installs nothing, also not after a
restart within the same boot, and **refuses every order**
(`operator_disabled`) until you re-arm it:

```sh
robodr-executor rearm --config /etc/robodr/executor.json --reason "<why>"
```

To keep it from acting at all:

```sh
systemctl disable --now robodr-executor
```

Then set `executor.enabled: false` and restart agentd.

`systemctl stop robodr-executor` alone does **not** lift active actions:
they stay in place until their revert or TTL at the next start. To lift
every action with the service stopped:

```sh
robodr-executor revert-all --config /etc/robodr/executor.json --reason "<why>"
```

After a reboot the kernel ruleset is empty. At the next start the
executor reverts the expired actions and **holds** the others: each is
re-validated against the current configuration and policy (refused ones
are reverted) and re-applied only once agentd's next event poll supplies
a fresh, known safety state that is not engaged. A held action still
expires at its deadline. TTLs run on CLOCK_BOOTTIME within a boot, so a
wall-clock step (NTP at boot) neither extends nor shortens them.

Any failed start (configuration, key, a journal write on a full disk, the
socket) deletes the table before the process exits, and the unit's
`ExecStopPost=robodr-executor stop-cleanup` does the same after every run
that did not end in success, so a unit that gives up
(`StartLimitBurst=`) leaves no rule without TTL enforcement. A revert on a
full disk is reported `reverting` (never `reverted`) until the journal
records it. Bridged traffic is isolated only with `br_netfilter` loaded
(`net.bridge.bridge-nf-call-iptables=1`).

**Watch.**

* `status.json` `executor`: `verified`, `refused`, `failed`, `reverted`,
  `revert_failures`, `unreachable`, `queue_full`, `dropped_unrecorded`,
  `journal_resets`.
* The black-box notes `robodr.executor_event`. `revert_failed`, `drift`,
  `removed_externally` and `journal_reset` are critical. A
  `journal_reset` (detail `HIGH: ...`) means the executor found its
  journal unreadable, deleted its table and lost the history: treat it
  as High, find the cause, and acknowledge it with `rearm` (the flag
  `journal_reset_ms` stays in `robodr-executor status` until then).
* `robodr-executor status --config /etc/robodr/executor.json`: the journal
  of active actions, their deadlines, history and events.
* `journalctl -u robodr-executor`.

A failed revert is retried every 500 ms until it verifies. Treat
`revert_failures > 0` as urgent. The finding for it is not in the
findings contract yet, so watch this counter instead.

### 6.6 Inline Motion Firewall gateway (`robodr-firewall-gw`)

The in-path enforcement mode for a sensor box bridged into the controller
cable (design and safety argument:
[`crates/robodr-firewall-gw/README.md`](../crates/robodr-firewall-gw/README.md);
Unitree specifics: [UNITREE.md section 5.1](UNITREE.md#51-inline-gateway-mode-robodr-firewall-gw)).
**Not a safety-rated device**: the robot's own safety functions remain
primary.

**Install.**

1. Bridge the two NICs without an IP address on the bridge (networkd or
   netplan; `controller_port` faces the controller, `robot_port` the
   robot). Nothing else should be plugged into the controller side.
2. Put the locked, signed profile and the firewall configuration in place
   (sections 4.4, 5) and write `/etc/robodr/firewall-gw.json` from
   `config/firewall-gw.unitree-<model>.example.json`: port names, queue
   number, `allowed_src_ips` for every channel, `on_gateway_down`.
3. `robodr-firewall-gw check-config --config /etc/robodr/firewall-gw.json`
   (exit 0 = everything compiles against the profile and the firewall
   configuration; 2 = the error is printed). In `mode: enforce` a profile
   that fails its trust checks is an error here and at start.
4. `robodr-firewall-gw ruleset --config /etc/robodr/firewall-gw.json`
   prints the netfilter setup it will install; review it once.
5. `systemctl enable --now robodr-firewall-gw-rules.service robodr-firewall-gw.service`.
   The rules unit runs before `network-pre.target` at boot, so no motion
   datagram crosses the bridge before the queue exists.
6. **Check the DDS ports.** The status file's `port_bypass_risk` (and a
   one-time WARNING in the journal) is set when discovery announces a
   locator outside the queued port ranges: RTPS to that port crosses the
   bridge unchecked. Add the ports to `rtps.extra_port_ranges`, re-render
   and re-apply the ruleset (step 4), or pin the DDS ports; repeat until
   the flag stays false while the controller and robot run. The check
   covers the controller's discovery (queued) and the robot's own SPDP /
   SEDP (an NFLOG copy, never queued; `observe.enabled`, default): the
   status shows `observe_unavailable: true` if the copy could not be set
   up (load `nfnetlink_log`). **Commissioning capture (required):** record
   both bridge ports with `tcpdump ... udp` through a full robot and
   controller start-up and confirm every port either side receives RTPS on
   is in a queued range; the check only sees discovery while the gateway
   runs.

**Run observe first.** With `"mode": "observe"` every datagram is forwarded
unchanged while the decisions are made and recorded (`events_path`,
`observe_would_modify` / `observe_would_drop` in the status file). Switch to
`enforce` only after the would-have verdicts match what the robot should
do, and after confirming with the OEM what the robot does on a lost command
stream (that is what `fail_closed` and every suppressed tick rely on).

**Health.** `status_path` (default in the examples
`/var/lib/robodr/firewall-gw/status.json`) is rewritten every
`housekeeping_ms`: gateway counters (`passed`, `limited`, `substituted`,
`suppressed`, `undecidable`, `replays`, `late`, `rewrite_failed`,
`dropped_ip`, `rtps_malformed`, `binding_conflicts`, `sn_jumps`, ...), the firewall's statistics (hold
episodes, holds past `max_hold_ns`), and the recv → verdict latency (p50 /
p99 / max). Treat it as unknown when `updated_mono_ms` is older than
`stale_after_ms`. Firewall deviations are appended to `events_path` (JSON
lines, size-capped by `events_max_bytes`). Watch in particular:

| Counter | Means |
|---|---|
| `suppressed` growing while the controller runs normally | frames refused with nothing to emit: wrong `allowed_src_ips` / sources, a rate window that does not match the controller's loop, or an attack |
| `rewrite_failed` > 0 | a limited / substitute frame could not be written and verified (suppressed instead): report it |
| `late` > 0 | packets read more than `max_queue_delay_ns` after arrival: the box is overloaded or not running the unit's real-time priority |
| `undecidable`, `rtps_malformed`, `unsupported_sample` | malformed or fragmented motion traffic: misconfiguration or an attack |
| `binding_conflicts` > 0 | the motion writer's GUID arrived from another source IP / MAC than the controller's stream: a spoofer on the controller segment (or a second NIC sending the controller's traffic) |
| `sn_jumps` > 0 | a sequence-number jump past `rtps.max_sn_jump` was held back: lost frames between controller and gateway, or a spoofed far-future number |
| `writer_restarts` | a writer restarted with its old GUID (announced by SEDP); expected only when the controller software restarts |
| `arm_weight_step_rejected`, `arm_weight_rate_rejected`, `arm_engage_rejected` | an arm-SDK blend weight that jumped, moved too fast, or rose from 0 with targets away from where `rt/lowstate` says the arms are (the arms were held): a controller that engages faster than the channel allows, or an attack |
| `hand_mode_rejected` | a hand frame with a mode octet the SDK never sends (another motor id, another status) or a hand-SDK weight jump |
| `velocity_expired` | a loco `SetVelocity` ended (the robot stopped on its own): informational |
| `observe_unavailable`, `observe_overruns` | robot-side observation is off (no `rt/lowstate`, no robot-side locator check) / copies lost under load |
| `unknown_undecidable` > 0 | a fragmented / key-only / non-standard sample from a writer the gateway never saw announced was removed: a discovery path around the bridge, a missing `rtps.state_file`, or an attack |
| `non_motor_rejected` > 0 | a `LowCmd_` asked to turn the battery off (`bms_cmd.off`) and was replaced by the substitute: investigate the sender |
| firewall `joint_holds_exceeded` | a humanoid has been held past `max_hold_ns`: escalate (the gateway keeps holding) |

**While the gateway is down** (stopped, crashed, restarting after a
watchdog kill, refused to start) the rules stay in place and the kernel
applies `on_gateway_down`: `fail_closed` (default) drops the queued
commands, `bypass` forwards them unchecked (refused for a humanoid joint
channel). Stopping the gateway is therefore **not** a way to take it out of
the path.

**Maintenance bypass** (an explicit, logged operator action, never
automatic): with the robot in a safe state, flush the queue chain so the
bridge forwards everything unchecked, and restore it afterwards:

```sh
iptables -F ROBODR_GW                         # bridge now forwards unchecked
# ... maintenance ...
systemctl restart robodr-firewall-gw-rules    # re-installs the ruleset
```

Record both steps in the site log; the status file's counters stop moving
while the chain is flushed.

**Troubleshooting.**

* `NFQUEUE <n>: ... (needs CAP_NET_ADMIN and nfnetlink_queue)`: the unit
  lost its capability, or the kernel lacks `nfnetlink_queue`.
* Nothing reaches the gateway (`packets` stays 0): `br_netfilter` is not
  loaded (`sysctl net.bridge.bridge-nf-call-iptables` must be 1), the port
  names in the configuration do not match the bridge ports, or the
  controller uses another DDS domain than `rtps.domain_ids`.
* Every frame suppressed after a gateway restart: the writer map was lost
  (set `rtps.state_file`) and `unknown_writers: pass`; or the controller's
  participant changed and its identity / GUID is not in the firewall's
  `allowed_sources`.
* Large IP datagrams from the controller side disappear: defragmentation
  did not run (another ruleset flushed the `raw` table); re-run the rules
  unit.

## 7. Upgrade and rollback

**Upgrade** (available). Verify the new release (section 2), then run
`sudo sh /usr/lib/robodr/install-bundle.sh install --pubkey … --tarball …`
(the trusted copy the installed release brought; section 3). `dpkg` keeps local edits to
`/etc/robodr/pulsar.toml` (a conffile) and asks before replacing an edited
one. Services that were running are restarted on the new binaries.
`/etc/robodr` (profile, keys, configs) and `/var/lib/robodr` (evidence) are
never touched.

Before upgrading:

- read `CHANGELOG.md` for profile-format or config changes;
- export pending evidence (section 8);
- run `robodr-commission check --profile /etc/robodr/profile.json --pcap <recent run>`
  and `robodr-commission verify-profile --profile /etc/robodr/profile.json
  --trusted-keys /etc/robodr/profile-trust.json` with the **new**
  `robodr-commission` from the extracted `.deb`
  (`dpkg-deb -x robodr_*.deb /tmp/new`). This confirms the new version accepts
  the locked profile (a profile locked before metadata existed needs
  section 5.2 first).

**Upgrading from findings contract 1.x (`robot-edr.findings`, releases
before contract 2.0) to 2.x.** Records written by the old release are still
contract 1.x. Preferred: **drain before upgrading** — let the robot side
empty `<spool>/ready/` (`robodr-spool-export --once` until it exports
nothing, or `robodr-kafka-publish --spool … --once` on a connected site),
transfer every batch in the packer outbox, import them with the old
`robodr-diode-unpack`, and publish the importer's `out/` with the old
`robodr-kafka-publish`, then upgrade the robots first and the SOC side
last. What happens to anything still in flight after the upgrade:

| Where | Unsigned 1.x record | Signed 1.x record (`robodr-finding-sig`) |
|---|---|---|
| agentd spool → `robodr-spool-export` | upgraded to contract 2.0 (same `finding_id` / `event-uid`; labels `--upgrade-data-source` / `--upgrade-topic`, defaults `robodr` / `robodr.findings`) and packed | moved to `<spool>/rejected/` with the reason `legacy 1.x signed record: re-sign required` (kept, never deleted) |
| spool or importer `out/` → `robodr-kafka-publish` | upgraded to contract 2.0 (`data_source` `--upgrade-data-source`, topic `--topic`), sent, counted in `legacy_upgraded` | dead-lettered with the same reason (the record is kept in `dead-letter.jsonl`) |
| 1.x diode batch → `robodr-diode-unpack` | authenticated and chained like any batch; every finding upgraded to 2.0 (`--upgrade-data-source` / `--upgrade-topic`) and the batch accepted | — (findings in a batch carry no per-finding signature; the batch signature is verified) |

A 1.x finding is only upgraded when its 2.0 form validates in full (the 2.0
rule catalog is exactly the 1.3 one); `data_source`, the topic and
`contract_version` are not inputs of the finding identity, so an upgraded
finding deduplicates with any earlier copy. Set the upgrade labels to the
`findings.data_source` / `findings.topic` the upgraded agentds use, or the
SOC sees the upgraded findings under the default labels.

A signed 1.x record cannot be upgraded off the robot: its signature covers
the exact 1.x bytes and only the robot holds the finding key. Either drain
before upgrading, or accept that these records are kept (spool `rejected/`,
publisher `dead-letter.jsonl`) for forensic use and not delivered to the SOC.

**Gap acceptance for a 1.x diode batch.** An intact, authentic 1.x batch
whose findings have no valid 2.0 form (in practice a 1.0–1.2 batch with a
rule that gained its catalog entry in 1.3) is quarantined as
`legacy_not_convertible`, and the importer **moves the unit's chain past
it**: its hash becomes the chain head, so the next batch is accepted
without `--accept-gap` and still has to link to it (nothing can be
inserted or reordered). A *damaged* 1.x batch (hash or size mismatch,
missing file) does not advance the chain: re-send it from the packer
archive (`robodr-diode-pack resend --seq N …`), or, if it is lost for good, accept
the gap with `--accept-gap UNIT:SEQ` for the next batch (section 8.3). The
records of a quarantined batch stay in `quarantine/<unique>/entry` with
`reason.json`.

Package rollback (below) and profile rollback (section 5.1) are separate:
rolling the package back does not touch the anti-rollback state.

**Rollback** (available):

```sh
sudo sh /usr/lib/robodr/install-bundle.sh list       # versions kept on this robot, security floor
sudo sh /usr/lib/robodr/install-bundle.sh rollback 0.1.0~alpha.1-1
```

Rollback reinstalls the kept `.deb` after re-checking its hashes. The
version must be one `list` shows (a version string, never a path). Evidence
written by the newer version stays in place.

**Downgrades and the security floor.** `install` of a release older than
the installed one is refused as a downgrade (it may bring back fixed
vulnerabilities); `rollback` to a kept release is the normal way back, and
`install --allow-downgrade` makes a deliberate downgrade possible. Neither
goes below the unit's **security floor**
(`/var/lib/robodr/releases/security-floor`, shown by `list`): the highest
`min_version` ever seen in an installed bundle's `security-floor` file
(covered by the release signature) or in the SOC's signed ring information
(`robodr-enroll ring`, 8.6). The floor only rises and has no override:
releases below it are known to be vulnerable.

**Black-box format gate** (install and rollback). Every package states the
black-box formats it writes and reads (`/usr/share/robodr/formats`, e.g.
`blackbox_read=RBF1:1`; a release without the file reads `RBF1:1`, the only
format so far). Before `dpkg` runs, `install-bundle.sh` reads the first
frame of every segment in `/var/lib/robodr/blackbox` and
`/var/lib/robodr/fleet/journal` (or the `--blackbox-dir` given) and
**refuses** a release that cannot read a segment in a recognised format
(`RBF1:<version>`), naming the segment and its format: an older agent could
neither verify nor extend that chain. To roll back across a format change,
export the chain (section 8.2) and archive the directory as in a key
rotation (section 4.3, step 3) first, then roll back; or install a release
that reads the format; or, knowingly, accept that one segment with
`--accept-unreadable <segment path>` (the release will neither verify nor
extend it). A file that does not start with a RoboDR frame at all (damaged,
or not RoboDR's) is reported as such and does not block: check it with
`robodr-blackbox verify`. `install-bundle.sh list` shows what each kept
release reads. Only black-box segments are judged: the executor's
journal (6.5), the control plane's request journal and evidence exports
(6.4), the gateway's state (6.6) and `robodr-enroll`'s JSON state are not
black-box chains; each daemon checks its own journal's format when it
opens it. Tested against the real `dpkg` (install, upgrade, rollback,
a refused rollback across a simulated format change, a refused downgrade,
the security floor, unknown frames, a fleet-journal segment, a signed install from a tampered
extracted directory refused, a tampered kept release) in
`crates/robodr-fleet/tests/packaging.rs`; not yet on a robot.

**Ring information.** When `robodr-enroll ring` has recorded the SOC's
update-ring information (8.6), `install-bundle.sh install` prints the ring
and whether the release (and, with `--tarball`, the tarball) is the ring's
target; `install-bundle.sh ring` shows it. Apart from its minimum release,
which raises the security floor, it is information only: the installation
proceeds (or not) exactly as without it.

## 8. Log and evidence export via the diode

The robot side is the **low side**. Evidence leaves through a one-way data
diode, or through vetted media at the entry station. Nothing returns
through the diode.

### 8.1 What is exported

| Data | Location | Integrity |
|---|---|---|
| Black-box chain | `/var/lib/robodr/blackbox/<service>/` | hash-chained, signed (Ed25519; legacy HMAC), checkpointed |
| OCSF findings | `/var/lib/robodr/spool/<service>/` | validated by `robodr-ocsf`; carry evidence links into the black box; optionally signed per finding (6.4); diode batches signed by the unit's diode key (8.3) |
| Journal | `journalctl -u 'robodr-*'` | none of its own; corroborating only |

### 8.2 Black-box bundles

**Connected sites: available on demand.** With `control_plane.evidence`
(section 6.4) the SOC exports a finding's records, or a sequence / time
range, as an `RBBXBND1` bundle over the mutual-TLS control plane, in signed
chunks, and verifies it with the robot's public keys;
`robodr-blackbox verify bundle.rbbx --keyring <black-box .pub> --device <id>`
checks a bundle file offline. This does not move the export cursor or prune
anything: the black box keeps its records (cyclic retention only).

**Diode sites:**
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

Far side, with the robot's public key file (legacy HMAC: the verifier's copy
of the key):

```sh
sha256sum -c SHA256SUMS-$ts
mkdir bb && tar -C bb -xzf blackbox-agentd-$ts.tar.gz
robodr-blackbox verify bb/agentd --keyring /secure/agentd-blackbox.key.pub --device <robot-id>
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

**available** (`robodr-kafka-publish` verified against single-node Apache
Kafka 3.9.1 and 4.1.0 brokers, see below). Two binaries carry
agentd's findings to the SOC over a diode or Kafka (contract section 8.1);
the ingest API path to AutoSecOps, `robodr-uplink`, is in section 8.5 (its
unit conflicts with both units below):

Both ship as systemd units (installed disabled, in `robodr` and
`robodr-focal`); they consume the same spool, so they conflict: enable
exactly one.

```sh
# Air-gapped / diode site, robot side (low side): spool -> signed diode
# batches in /var/lib/robodr/export/diode. Runs as robodr (it renames
# ready/ -> acked/ in agentd's spool), with no network at all.
sudo robodr-blackbox keygen --out /etc/robodr/keys/diode.key   # .pub -> SOC importer
sudo install -m 0640 -o root -g robodr \
    /usr/share/doc/robodr/examples/spool-export.env.example /etc/robodr/spool-export.env
sudoedit /etc/robodr/spool-export.env                          # ROBODR_UNIT_ID=
sudo systemctl enable --now robodr-spool-export
# The unit runs (key handed over by systemd, man robodr-spool-export(1)):
#   robodr-spool-export --spool /var/lib/robodr/spool/agentd \
#     --outbox /var/lib/robodr/export/diode \
#     --state /var/lib/robodr/export/spool-export/state.json \
#     --pack-state /var/lib/robodr/export/spool-export/pack-state.json \
#     --unit $ROBODR_UNIT_ID --key-file /run/credentials/robodr-spool-export.service/diode.key

# Diode site, SOC side (high side), after robodr-diode-unpack has imported
# the batches (a SOC host with its own layout; no unit is shipped for it):
robodr-kafka-publish --bootstrap 10.0.0.5:9092 --state-dir /var/lib/robodr-soc/publish \
    --diode-out /var/lib/robodr-soc/import/out [--topic robodr.findings] [--once]

# Connected site: publish agentd's spool straight from the unit or sensor box.
sudo install -m 0640 -o root -g robodr \
    /usr/share/doc/robodr/examples/kafka-publish.env.example /etc/robodr/kafka-publish.env
sudoedit /etc/robodr/kafka-publish.env                         # ROBODR_KAFKA_BOOTSTRAP=
sudo install -D -m 0644 \
    /usr/share/doc/robodr/examples/robodr-kafka-publish.service.d/50-brokers.conf.example \
    /etc/systemd/system/robodr-kafka-publish.service.d/50-brokers.conf
sudoedit /etc/systemd/system/robodr-kafka-publish.service.d/50-brokers.conf  # every broker
sudo systemctl daemon-reload && sudo systemctl enable --now robodr-kafka-publish
```

The connected-site publisher connects to the bootstrap brokers **and** to
every broker the cluster advertises (each partition's leader), so
`IPAddressAllow=` in `50-brokers.conf` (and a host firewall, e.g. the
sensor-box nftables example) must hold every broker's advertised address;
one bootstrap address is not enough and fails at the first leader change.
The unit allows no other address, DNS servers included: use IP literals
and IP-literal advertised listeners, or `/etc/hosts`.

`robodr-spool-export` takes `ready/` records in order, re-validates them,
packs one diode batch per step with `robodr-diode-pack`'s format (Ed25519
key file, section 4.4; `--allow-hmac` only for legacy keys) and moves the
records to `acked/` only once the batch is durably in the outbox; an intent
journal makes every crash point recoverable without loss or re-packing.
Invalid records go to `<spool>/rejected/` with a reason file, never deleted.
Without `--once` it loops every `--interval-ms` (default 5000).

`robodr-kafka-publish` re-validates every record, re-derives key, headers
and partition from the value (contract §2, §4), publishes to `--topic`
(default `robodr.findings`; findings name the topic agentd was configured
with, `findings.topic`, and records relabelled to `--topic` are counted),
upgrades unsigned contract 1.x records to 2.0 and dead-letters signed
ones (section 7), sends with `acks=all`, and
persists per-batch progress after each acknowledged chunk; invalid or
broker-rejected records go to a dead-letter file. **No TLS / SASL** and
**idempotence off** (at-least-once: consumers drop duplicates on
`event-uid`): run it on an isolated SOC network or through a local TLS
proxy. Without `--once` it loops every `--interval-ms` (default 2000).
`robodr-spool-export.service` and `robodr-kafka-publish.service` run the
loop (no timer needed: both binaries retry on their own; exit 2, a usage
error, is not restarted); the transfer of `/var/lib/robodr/export/diode`
to the diode stays the site's procedure.

Before the first deployment, and after a Kafka upgrade, run the real-broker
test against the SOC's Kafka version (needs docker and the source tree):

```sh
scripts/kafka-it.sh                                   # apache/kafka:3.9.1
KAFKA_IT_IMAGE=apache/kafka:4.1.0 scripts/kafka-it.sh  # any apache/kafka tag
```

It starts a single-node broker, publishes signed findings with
`robodr-kafka-publish` and the library (spool and diode paths, crash and
resume, broker restart, oversized record, unknown topic, ACL denial, quota,
idle connections, SASL/TLS listeners), reads everything back, checks that
each record arrived exactly once with key, headers and partition as in the
contract, re-checks every stored CRC with `kafka-dump-log` and removes the
container. Verified on 2026-10-17 with 3.9.1 and 4.1.0; what it does not
cover (multi-broker clusters, replication) is listed in
`crates/robodr-export/README.md`. To check a SOC cluster by hand, consume a
few records with `kafka-console-consumer.sh --property print.headers=true
--property print.key=true --property print.partition=true`: the headers
must be in contract order with `robodr-finding-sig` last (connected sites
that sign), and a robot's findings must all be in one partition.

Troubleshooting the publisher: an error naming a **TLS record** or **SASL**
means the bootstrap address (or an advertised listener) is a TLS or SASL
listener; this client speaks PLAINTEXT only (use a PLAINTEXT listener or a
local TLS proxy). `UNKNOWN_TOPIC_OR_PARTITION`: the topic does not exist
(it is never auto-created). `TOPIC_AUTHORIZATION_FAILED`: grant WRITE and
DESCRIBE on the findings topic (default `robodr.findings`) to the
publisher's principal.

### 8.4 Journal

```sh
sudo journalctl -u 'robodr-*' --since "<last export>" -o export | gzip -9 > /var/lib/robodr/export/journal-$ts.export.gz
```

### 8.5 Findings to the SOC ingest API (`robodr-uplink`)

**available (producer)**; the AutoSecOps side (`/robot-edr/v2/ingest`) is
built in Sprint 3 against the same contract
(`docs/contracts/robodr.ingest-api.md`) and its shared test vectors. This
is the primary path to the SOC (decision D1); Kafka (8.3) stays for
third-party SIEMs. `robodr-uplink` reads the same inputs as
`robodr-kafka-publish` and POSTs signed NDJSON batches over TLS; a record
leaves the spool only after the server's `200` names it accepted or
rejected (rejected ones: `/var/lib/robodr/export/uplink/dead-letter.jsonl`
with the server's code, and `<spool>/rejected/`).

```sh
# Connected site, on the unit or sensor box.
# 1. Sender key: register keys/uplink.key.pub in AutoSecOps as this
#    robot's `uplink` key (no --key-id: the API names keys by the derived
#    ed25519:<16 hex> id, printed by keygen).
sudo robodr-blackbox keygen --out /etc/robodr/keys/uplink.key
# 2. The SOC's CA certificate(s), and optionally the server key pin.
sudo install -m 0644 soc-ca.pem /etc/robodr/uplink-ca.pem
openssl x509 -in soc-server.pem -pubkey -noout | openssl pkey -pubin -outform der | sha256sum
# 3. Settings, network allow-list, start.
sudo install -m 0640 -o root -g robodr \
    /usr/share/doc/robodr/examples/uplink.env.example /etc/robodr/uplink.env
sudoedit /etc/robodr/uplink.env      # ROBODR_UPLINK_URL=, ROBODR_UPLINK_ARGS="--spki-sha256 <hex>"
sudo install -D -m 0644 \
    /usr/share/doc/robodr/examples/robodr-uplink.service.d/50-soc.conf.example \
    /etc/systemd/system/robodr-uplink.service.d/50-soc.conf
sudoedit /etc/systemd/system/robodr-uplink.service.d/50-soc.conf   # the SOC address
echo '192.0.2.40 soc.example.org' | sudo tee -a /etc/hosts         # name of the certificate
sudo systemctl daemon-reload && sudo systemctl enable --now robodr-uplink

# Diode site, SOC side (high side), after robodr-diode-unpack (a SOC host
# with its own layout; no unit is shipped for it). Register the key as a
# `relay` key: diode findings carry no per-finding signature ("sig":null).
robodr-uplink --url https://soc.example.org/api --key-file /etc/robodr-soc/relay.key \
    --ca-bundle /etc/robodr-soc/ca.pem --state-dir /var/lib/robodr-soc/uplink \
    --diode-out /var/lib/robodr-soc/import/out [--once]
```

`robodr-uplink.service` conflicts with `robodr-spool-export.service` and
`robodr-kafka-publish.service` (one consumer per spool): enable exactly
one. It denies every IP address except the drop-in's, DNS included, so the
URL's host name must be in `/etc/hosts` (or the DNS server allowed in the
drop-in); the name must match the server certificate.

TLS is mandatory: the CA bundle is the only trust anchor, the URL host is
the verified name, `--spki-sha256` (repeatable, for a key rotation) pins
the server key in addition. Plain `http://` is accepted only to a loopback
IP literal (a local TLS-terminating proxy). There is no switch that
disables verification.

Retries: network errors, `429` and `5xx` are retried with the same batch
(same batch id, new timestamp and signature), backing off exponentially and
never sooner than `Retry-After` (honoured in full up to 24 h, also when it
came with the last attempt of a run); after `--max-attempts` the run fails
and the service retries later with the same batch. Batch ids are derived
from the input position and the body, so a restart after a crash re-sends
the same batch under the same id and the server answers from its replay
store (no double processing).

**One process per state directory.** The service holds
`/var/lib/robodr/export/uplink/uplink.lock` while it runs (also between
runs). A manual `robodr-uplink --once` or `robodr-uplink reinject` on the
same state directory exits 1 ("held by another robodr-uplink"): stop the
service first, run as user `robodr`
(`sudo -u robodr robodr-uplink ...`), start it again.

#### Is the queue moving? (status, blocked batch)

Delivery is in order: a batch the server keeps refusing blocks **every**
later finding of this robot until the cause is fixed. It is never silent:

```bash
systemctl status robodr-uplink          # STATUS= line: ok / retrying / blocked, error, backlog
sudo cat /var/lib/robodr/export/uplink/uplink-status.json
journalctl -u robodr-uplink -n 50       # one line per failed run
```

`uplink-status.json` (rewritten after every run): `state` (`ok`,
`retrying` = transient failures, `blocked` = refused, needs a fix),
`last_success_at_ms`, `last_delivery_at_ms`, `last_error` (`kind`,
`status`, `code`, `message`, `retry_after_s`), `stuck_since_ms` (start of
the failure streak; kept across restarts while the same batch is pending),
`pending_batch_id`, `pending_lines`, `pending_failed_runs`, `backlog`
(`spool_ready` records, or `diode_batches`; `reinject_generations`),
`next_attempt_at_ms`, `dead_letter_malformed`, delivery totals. Times are
ms since the epoch. **Monitor it**: alert when `state` is not `ok` for
longer than your tolerance, or when `last_success_at_ms` is old (the
service is not running at all). `--exit-when-stuck-s N` (in
`ROBODR_UPLINK_ARGS`) additionally makes the unit exit 3 after `N` s of
failures, so a unit-state monitor sees it; it is off by default because a
fixed registration then resumes delivery without a restart.

Backoff: after transient failures the next run waits up to
`--backoff-max-ms` (60 s); after refusals and other failures that need a
fix up to `--refused-backoff-max-s` (default 900 s), so a robot with an
unregistered key causes under 200 `401` audit-log entries a day on the
SOC, not ~1440. After the fix, delivery resumes at `next_attempt_at_ms`;
`systemctl restart robodr-uplink` retries at once.

Procedure for a blocked queue (`state: blocked`):

1. Read `last_error.status` / `last_error.code` and act on the table
   below (registration, NTP, CA/pin). Do **not** delete
   `uplink-state.json` or move spool files: the pending batch would be
   re-cut and, at best, reported as duplicates.
2. `400`, `409`, `415`, a single-line `413` or a malformed `200` mean a
   producer/server mismatch or bug: collect `uplink-status.json`, the
   journal lines and the robodr / AutoSecOps versions, and escalate;
   upgrading the side at fault unblocks the queue (the batch is re-sent
   under its id).
3. Confirm: `state` goes back to `ok`, `backlog` drains.

#### Re-injecting dead letters after a fix

Lines the server rejected for registration reasons (`unknown_robot`,
`robot_mismatch`, `site_mismatch`, `missing_finding_signature`,
`bad_finding_signature`) are dead-lettered and acknowledged; they do not
come back by themselves. After fixing the registration:

```bash
sudo systemctl stop robodr-uplink
cd /var/lib/robodr/export/uplink
sudo -u robodr robodr-uplink reinject --state-dir . --spool /var/lib/robodr/spool/agentd \
    $(ls dead-letter.jsonl* | sed 's/^/--dead-letter /') --dry-run     # check the counts
sudo -u robodr robodr-uplink reinject --state-dir . --spool /var/lib/robodr/spool/agentd \
    $(ls dead-letter.jsonl* | sed 's/^/--dead-letter /')
sudo systemctl start robodr-uplink
```

(`--codes a,b` selects other codes; SOC side: `--diode-out` instead of
`--spool`.) The records are sent again under **new** batch ids; running the
command twice queues nothing new. A record rejected again shows up in the
dead letters with `source: "reinject:<generation>"` and can be re-injected
after the next fix. `unavailable` in the report lists records whose
original and dead-letter copy are both gone.

Dead letters: `dead-letter.jsonl` rotates at 64 MiB, keeping 4 rotated
files (`--dead-letter-max-bytes`, `--dead-letter-keep`); a line torn by a
power loss is closed and counted (`dead_letter_malformed`), never merged
with the next entry.

Troubleshooting (journal, `journalctl -u robodr-uplink`):

| Message | Cause, action |
| --- | --- |
| `HTTP 401 unknown_key` | the key is not registered in this workspace, revoked, or registered as a `finding` key: register `uplink.key.pub` (connected site: role `uplink`, bound to this robot) |
| `HTTP 401 stale_timestamp` | the unit's clock is more than 300 s off the server's: fix NTP / the RTC |
| `HTTP 401 bad_signature` | key file and registered public key differ (re-registered after a keygen?) |
| `invalid peer certificate: ... matches no configured pin` | the server key changed: verify out of band, then update `--spki-sha256` (list old and new during a rotation) |
| `invalid peer certificate: UnknownIssuer` / `NotValidForName` | wrong CA bundle, or the URL host is not the name in the certificate |
| `HTTP 400` / `409` / `415` | a producer bug: report it with the journal lines; nothing was acknowledged |
| `... held by another robodr-uplink` | a second process on the same state directory: stop the service before `--once` / `reinject` |
| dead letters with `robot_mismatch` | the findings name another robot than the key is bound to (a sensor box watching several robots needs a `relay` key, or one uplink per robot); then re-inject |
| dead letters with `site_mismatch` | a site-scoped `relay` key sent a robot not registered with its site: fix the robot's site or the key's scope, then re-inject |
| dead letters with code `local` | the record failed RoboDR's own validation before sending (see `reason`) |

### 8.6 Fleet lifecycle: enrollment, key rotation, SOC profiles (`robodr-enroll`)

**available (robot side)**; the AutoSecOps side of the fleet API
(`/robot-edr/v2/fleet/*`, contract `docs/contracts/robodr.fleet-api.md`,
shared vectors `docs/contracts/fixtures/fleet/`) is not built yet.
`robodr-enroll` is a root-only tool (`/usr/sbin`, no service). It keeps its
state in `/var/lib/robodr/fleet` (0700 root, created by the package's
tmpfiles) and records every step in its own signed journal
(`/var/lib/robodr/fleet/journal`, a black-box chain signed with the unit's
black-box key; verify it like agentd's:
`robodr-blackbox verify /var/lib/robodr/fleet/journal --keyring /etc/robodr/keys/agentd-blackbox.key.pub`).
Nothing the SOC sends is executed: tokens, answers, approvals and ring
information are verified data, and a profile takes effect only through
agentd's own check at its next start.

**Configuration** (`/etc/robodr/fleet.json`, from
`/usr/share/doc/robodr/examples/fleet.example.json`): the SOC URL, CA
bundle (the uplink's) and optional SPKI pins, the **SOC fleet public key**
(`/etc/robodr/fleet-soc.pub`: it signs tokens, answers and ring
information, and is never taken from a token), the **SOC approval public
key** (`/etc/robodr/fleet-approval.pub`: the only key profile approvals are
accepted from; a separate, offline key of the SOC, never the fleet key),
the expected workspace, and
the key paths (defaults: `/etc/robodr/keys/uplink.key`,
`agentd-finding.key`, `agentd-blackbox.key`). Robot id, site, profile path
and the profile trust inputs are read from `/etc/robodr/agentd.json`. Both
SOC keys come from the SOC on vetted media like the CA bundle and must be
root-owned, `0644`, in a directory not writable by group or others
(`robodr-enroll` refuses them otherwise). Rotating or revoking a SOC key
means installing the new public file next to the old one, then removing the
old one (contract section 2.7); nothing is ever replaced over the network.

**Enroll (once).** In AutoSecOps, add the robot (id, site); the SOC shows a
single-use token (`rdet1.…`, valid at most 7 days). On the unit:

```sh
sudo install -o root -m 0644 fleet-soc.pub /etc/robodr/fleet-soc.pub            # from the SOC, vetted media
sudo install -o root -m 0644 fleet-approval.pub /etc/robodr/fleet-approval.pub
sudo install -o root -m 0600 token.txt /root/token.txt                          # the token is a secret
sudo robodr-enroll --token-file /root/token.txt
#   key uplink: ed25519:… (generated) …   enrolled: robot ugv-007 in workspace …
sudo shred -u /root/token.txt
```

The token is never accepted on the command line (`--token TOKEN` is
refused: argv shows in `/proc`, sudo logs and the shell history). Give it as
a file owned by root with mode `0600` (anything readable by group or others
is refused), or on standard input with `--token -`. Destroy the file
afterwards (`shred -u`; on flash media see the limits below).

It checks the token's SOC signature, validity (on the unit's clock: set the
clock first), workspace, robot id and site against the unit, generates the
uplink, finding and black-box keys **on the unit** (0600; the `.pub` files
0644), and registers their public halves, the agentd version and the
profile digest with the SOC; the request is signed by each of the three
keys (proof that the unit holds them). The token never leaves the unit (the
request carries an HMAC under it). An existing key file is refused unless
`--reuse-existing-keys` (for example the black-box key of an agentd that
ran before enrollment). Then install the finding-key drop-in
(`20-finding-key.conf`, section 6.4) and enable `robodr-uplink` (8.5).

*Air-gapped units*: `sudo robodr-enroll request --token-file /root/token.txt --out
enroll-request.json`, carry the file to the SOC's import (it holds public
keys and signatures only), bring the answer back and run `sudo
robodr-enroll accept --answer enroll-answer.json`. The SOC must import the
request before the token expires.

If the answer is lost (network, crash), run the same command again: the
pending request is resent unchanged and the SOC answers it again. A token
that was refused (`token_used`, `token_expired`) needs a new token: confirm
with the SOC, then remove `/var/lib/robodr/fleet/enroll-pending.json`.

*Re-enrollment* (another workspace, or after a compromise): the SOC issues
a new token for the robot (a successful enrollment retires every key the
robot had). On the unit, stop `robodr-uplink`, archive
`/var/lib/robodr/fleet` to `/var/lib/robodr/archive/` (it holds the fleet
journal: evidence) and either move the old keys to
`/etc/robodr/keys/retired/` (fresh keys; after a compromise, always) or
pass `--reuse-existing-keys`. The black-box key is normally kept
(`--reuse-existing-keys` registers it again): a new one starts a new chain
(4.3).

**Rotate a key (`uplink` or `finding`).** The old key stays valid until
the SOC confirms the end of the rotation:

```sh
sudo robodr-enroll rotate --role uplink        # new key registered (overlap) and swapped in
sudo systemctl restart robodr-uplink           # finding: sudo systemctl restart robodr-agentd
sudo robodr-enroll rotate --role uplink --finish   # old key retired at the SOC, then shredded
```

The new key is generated next to the active one, registered with the SOC
(signed by both keys), and swapped in with an atomic rename; the old key
waits in `/etc/robodr/keys/retired/` until `--finish`. For `finding`, run
`--finish` only when the findings signed with the old key have reached the
SOC (the spool is drained): the SOC verifies them with the old key until it
is retired. Every phase is journaled; after a crash or a lost answer, run the
same command again: the request is resent unchanged and the SOC answers with
its stored answer. Once the rotate request has been sent (or written with
`--request-out`), the SOC may hold the rotation even if no answer came back,
so it is never discarded locally: `rotate --role R --abort` works only for a
rotation whose request never left the unit. To give up a sent rotation, run
`rotate --role R --cancel`: the cancel request is signed by the old key, the
SOC retires the new key (or records the rotation as cancelled if it never
received it), and the unit shreds the new key; the old key stays active and
a new rotation can start. Air-gapped: `--request-out FILE` and `--answer
FILE` on every step (rotate, `--finish`, `--cancel`). Shredding overwrites the old key file before unlinking it; on
flash storage with wear levelling the old blocks may survive (full-disk
encryption is the remedy). The black-box key is rotated as in section 4.3,
not with this tool.

**Revocation list.** `sudo robodr-enroll revocations` fetches the
root-signed list for the unit's platform (`expect_platform` in agentd's
`profile_trust`, else the active profile's), verifies it against
`trust_roots`, refuses an older serial or the same serial with other content
(the installed list and agentd's accepted state count too), installs it at
`revocation_list` and warns if agentd would refuse the active profile with
it. Air-gapped: `revocations install --file FILE`. Restart agentd to apply
it (section 5.3).

**Profiles from the SOC.**

```sh
sudo robodr-enroll profile publish --draft /var/lib/robodr/commission/draft.json  # for review
sudo robodr-enroll profile fetch       # verify + STAGE the SOC's signed profile (not enforced)
sudo robodr-enroll profile approve --fetch       # or --approval approval.json
sudo systemctl restart robodr-agentd             # agentd verifies it again and enforces it
```

`fetch` verifies the profile with exactly agentd's trust inputs and
anti-rollback state and only stages it. `approve` installs it at agentd's
`profile_path` only with an approval signed by the SOC's **approval key**
for this robot, this exact digest, version and platform, valid at most 7
days, unexpired and never used before; the previous profile and `.sig` are
kept under `/var/lib/robodr/fleet/profile/backup-<ms>/`. The new `.sig` and
profile are both written completely before they are renamed into place
(`.sig` first); two files cannot be swapped in one atomic step, so a crash
between the two renames leaves a pair agentd refuses (observe-only) until
`approve` is run again with the same approval. The observe -> enforce
transition therefore always needs the SOC's approval (its own policy, e.g.
two operators) **and** an operator on the unit. Air-gapped: `profile stage
--profile FILE [--sig FILE]` and `approve --approval FILE`.

**Update ring.** `sudo robodr-enroll ring` shows the ring the SOC put the
unit in (0 canary, 1 early, 2 broad) and its target release, and writes
`/var/lib/robodr/fleet/ring.env`, which `install-bundle.sh install` and
`install-bundle.sh ring` print; "update available" compares the target
with the release dpkg has installed. Information only, with one
restriction: the SOC's minimum release raises the unit's security floor
(section 7). Installing stays the local, signature-checked step of section
7. Ring information issued in the future (beyond 5 minutes of clock skew)
is refused.

| Exit | Meaning |
|---|---|
| 0 | done |
| 1 | refused: verification, binding (workspace, robot, site), rollback, or the SOC refused (code shown) |
| 2 | usage error |
| 3 | the SOC was not reachable: run the same command again later |

## 9. Decommissioning

The package never deletes evidence or keys, not even on `apt purge`.

1. Export everything (section 8) and confirm verification on the far side.
2. `sudo systemctl disable --now robodr-agentd robodr-pulsard`
3. `sudo apt purge robodr` (or `dpkg -P robodr`).
4. Tell the SOC to retire the unit's keys (fleet: remove the robot), so its
   uplink and finding keys authenticate nothing any more.
5. Following the site's evidence-retention and media-sanitisation rules, and
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
| `lock: --operators is required` / `no valid operator signature` | sign-off list not signed, or signed by a key not in the operators list | section 5, step 3 |
| High `robot.agent.evidence_quarantined` | a closed black-box segment failed verification at open | section 6.4: keep `<blackbox>/quarantine/`, check the storage, treat as possible tampering |
| Critical `robot.agent.evidence_quarantined` / `robot.agent.evidence_truncated` | the black-box directory was edited (stray or cut segment files, records cut after the newest mark) | section 6.4: preserve the whole `<blackbox>` directory, treat as tampering |
| `finding_signing.key_file ... black-box key` / `must be an ed25519 key` | finding key reused or HMAC | section 6.4: generate a dedicated Ed25519 key |
| `correlation rules: ...` at start | site rule file invalid or duplicates a shipped id | fix the file, or `--check-config` to see every problem |
| SOC gets no answer at all from the control plane (connection closed during the handshake) | no / wrong client certificate, expired, or its key is not pinned; plain HTTP to the TLS port | `status.json` `control_plane.last_auth_failure` names the TLS reason; section 6.4 "Control-plane API", rotation table |
| SOC gets 401 `stale_timestamp` right after a robot restart | the replay store was damaged or removed: requests signed before the start are fenced | sign again; check the start note / `state_dir/quarantine/` |
| SOC gets 401 `stale_timestamp` / `bad_signature` from the control plane | clocks apart, or the request was signed for another robot id / rewritten by a proxy | section 6.4 "Control-plane API": NTP on both sides; the SOC must sign the exact target and body it sends (mutual TLS ends at agentd: no proxy may rewrite them) |
| every control-plane request `refused` `observe_mode` | profile not enforced or policy not OEM-validated | section 5; the API never acts beyond what the policy allows |
| High `robot.agent.control_plane_unauthenticated` | requests without a valid SOC signature | check `status.json` `control_plane.last_auth_failure`; treat repeated ones as an attempt to reach the robot |
| every finding `[observe-only]` | profile unlocked, missing or invalid | section 5 |
| executor: request `failed` "executor unreachable" | `robodr-executor` not running, wrong `executor.socket`, or the two keys differ | section 6.5: `systemctl status robodr-executor`; the same `/etc/robodr/keys/executor.key` must reach both units |
| executor: `refused` `safety_state_stale` / `safety_state_changed` | agentd's safety state was older than `max_safety_age_ms`, or changed between judgment and apply | expected during transitions; re-judge (submit a new request); check the safety feed if persistent |
| executor: `refused` `fall_hazard` / `motion_path` / `no_management_channel` | the executor's own safety rules (humanoid without `fall_safe_restrict`, a target on the motion path, no management allow-list) | section 6.5; these are by design, never override them |
| executor: `revert_failures` rising, `drift` events | the table cannot be re-rendered (nft error), or something edits `inet robodr` | `journalctl -u robodr-executor`; if in doubt, `nft delete table inet robodr` (emergency disable) |
| Critical `robot.ros2.profile_state_tampered` | anti-rollback state file deleted or rewritten (or agentd stopped mid operator rollback) | section 5.1: investigate; reinstall the recorded profile or roll back with `allow_rollback` |
| `revocation list ... rollback refused` / `now missing` | an older list, or none, replaced the accepted one | section 5.3: install the newest list |
| `robodr-enroll`: `token … expired` / `issued in the future` | token too old, or the unit's clock is wrong | set the clock; ask the SOC for a new token (8.6) |
| `robodr-enroll`: `already used on this unit` / SOC `409 token_used` | a token is single use | ask the SOC for a new token; remove `enroll-pending.json` only after the SOC confirms (8.6) |
| `robodr-enroll`: `is for workspace` / `is for robot` / `is for site` | the token was issued for another workspace, robot or site | issue the token for this unit's `robot.id` / `robot.site` (agentd.json) |
| `robodr-enroll`: `signed by no configured SOC key` | `fleet-soc.pub` missing, wrong, or the document is forged | re-copy the SOC fleet key from the SOC on vetted media; treat repeated failures as an attack |
| `robodr-enroll`: `the enrollment token is not accepted on the command line` | `--token TOKEN` | put the token in a root-only file (`--token-file`, mode 0600) or pipe it (`--token -`) (8.6) |
| `robodr-enroll profile approve`: `approvals are accepted from a SOC approval key only` | the approval is signed by the fleet key, or `fleet-approval.pub` is missing or wrong | install the SOC's approval public key (8.6); an approval signed by the fleet key is never accepted |
| `robodr-enroll rotate --abort`: `may have reached the SOC` | the rotate request was sent (answer lost) or written out | run `rotate --role R` again (stored answer), or `rotate --role R --cancel` (8.6) |
| SOC `409 rotation_in_progress` on a new rotation | an earlier rotation is still open at the SOC | finish it, or `rotate --role R --cancel` on the unit that started it |
| `install-bundle: REFUSED: … differs from the signed tarball` | the extracted bundle directory was modified after extraction | extract the verified tarball again into a fresh directory, or run `/usr/lib/robodr/install-bundle.sh` (section 3) |
| `install-bundle: REFUSED: … a downgrade` / `below this unit's security floor` | an older release, or one below the floor | `rollback` or `--allow-downgrade` for a deliberate downgrade; nothing goes below the floor (section 7) |
| `robodr-enroll rotate`: `holds key … but the SOC has …` | the key file was replaced by hand | restore the registered key, or re-enroll |
| `install-bundle: REFUSED: release … reads black-box formats` | rollback/downgrade across a black-box format change | section 7: export and archive the chain first, or `--accept-unreadable <segment>` |
| capture sees only `lo` | no default route on an air-gapped robot | list the DDS interfaces in `[module.robodr-sensor-ros2.capture] interfaces` |

## 11. Secure delivery on a unit (`robodr-deliverd`, Sprint 13b)

`robodr-deliverd` installs release-signed, depot- and operator-approved
packages (RPKs) of the kinds `files`, `config`, `deb` and `robodr-rules`
from **per-unit media packs**, only while the robot's live safety state is
`idle` or `safe_state_active`, with a health gate, automatic rollback and
anti-rollback floors (`docs/SECURE-DELIVERY.md` §4.2, §6;
`man robodr-deliverd(8)`). Verified offline in tests only: not yet on a
robot, an air-gapped site or a depot (14a).

### 11.1 Before enabling it

1. agentd runs with a **live safety feed** (`safety_feed` in
   `/etc/robodr/agentd.json`: the safety socket a PLC gateway writes, or
   commissioned ROS 2 safety topics). Without a feed every install waits
   (`unknown`): a configured `context.safety_state` is not a reading.
   agentd serves its status on **`spool.status_socket`**
   (`/run/robodr-agentd/status.sock`, in every shipped example); the
   delivery agent reads the safety state only there and only from
   agentd's own user (`SO_PEERCRED`), never from `status.json` in the
   spool (a file, for people and tools). Without the socket every
   install waits.
   * agentd runs as its own user **`robodr-agentd`** (group
     `robodr-agentd`, member of `robodr`); the exporters
     (`robodr-spool-export`, `robodr-kafka-publish`, `robodr-uplink`) keep
     running as `robodr`. The package creates the user and, on upgrade,
     moves agentd's black box, spool, profile state and control-plane
     state to it (`postinst`).
   * The PLC gateway that writes `safety_feed.socket`: by default the
     socket is `0600` and only root and agentd may report a state. For a
     gateway running as its own user, put it in the group
     `robodr-safety` (created by the package) and set
     `"socket_mode": "0660", "socket_group": <gid>, "allowed_gids": [<gid>]`
     (`getent group robodr-safety`), plus `SupplementaryGroups=robodr-safety`
     for both `robodr-agentd.service` (a drop-in) and the gateway's unit.
     Every connection is checked with `SO_PEERCRED` and `SO_PEERGROUPS`:
     the allowed group counts as the peer's primary or a supplementary
     group. An exporter (or any other user) that connects is closed
     before a byte is read and shows as malformed input in agentd's
     health. Never use the exporters' group `robodr` as `socket_group` or
     in `allowed_gids`: agentd refuses to start with it.
2. Write `/etc/robodr/deliverd.json` from
   `/usr/share/doc/robodr/examples/deliverd.example.json`: the unit id
   (as in the trust file's `rings` and the deployments), the site, model,
   platform and architecture, and the delivery **root fingerprints**
   (carried to the site out of band, as for `robodr-release --root`).
   `trust.clock`: `trusted` only if the clock is disciplined (GPS / PTP,
   or set at commissioning and checked); otherwise `untrusted`. With
   `untrusted`, a deployment's **maintenance window never opens** (the
   unit has no signed current time in 13b, and whoever sets the system
   clock must not decide the window): deploy to such units without a
   window and use `install.requires_operator_present` where a person
   must be there.
   Probe users must be regular accounts: the default probe UID range is
   `1000..=59999` (`health.probe_uid_min`), so a system account (a PLC or
   database user) never runs a probe unless you lower it explicitly.
   `install.robodr_programme` names the one trust-file programme whose
   `deb` RPKs may be RoboDR's own packages (`robodr`, `robodr-focal`, and
   then name the other one in their relations); leave it `null` to keep
   RoboDR itself out of delivery (update it with `install-bundle.sh`).
   Every other `.deb` may name only its own package in `Conflicts`,
   `Breaks`, `Replaces` and `Provides`.
   `robodr-deliverd check-config --config /etc/robodr/deliverd.json`.
3. Enrol the trust anchor once, from the site's trust file on vetted
   media:
   `sudo robodr-deliverd init-anchor --config /etc/robodr/deliverd.json --trust /media/usb/trust.json`.
   It prints the trust version and the unit's ring from the trust file.
   The anchor only moves forward by root-signed rotations that arrive in
   media packs.
4. For `robodr-rules`, point Pulsar at the delivered rules (a symlink
   `/usr/share/robodr/rules/delivered -> /etc/robodr-delivered-rules` or
   `rules_path`) and set `install.rules_reload` (default in the example:
   `systemctl try-restart robodr-pulsard.service`).
5. SOC side: findings contract **2.2** validators before the unit's
   `robot.deliver.*` findings are exported (they share agentd's spool and
   exporters).
6. `sudo systemctl enable --now robodr-deliverd`.

### 11.2 Delivering a media pack

Copy (or mount) the pack the depot wrote for this unit under
`/var/lib/robodr/deliverd-media/<name>/` (`trust.json` + `.sig`,
`deployment.json` + `.sig`, `bundles/<label>/`). The agent copies and
verifies it into its own state directory and never reads the media again
for it; remove the media afterwards. `sudo robodr-deliverd status --config
/etc/robodr/deliverd.json` shows the deployment, each item's status and
deferrals, installed versions, floors and any switch in progress.

* **Deferred** items wait for `idle` / `safe_state_active` (and the
  deployment's maintenance window, UTC; never open with
  `trust.clock: untrusted`). Staging continues. A unit that
  never reaches a safe window shows `robot.deliver.deferred_safety`
  (Medium after `findings.deferral_medium_after` deferrals).
* RPKs with `install.requires_operator_present` wait for a local
  operator: `sudo robodr-deliverd confirm --config /etc/robodr/deliverd.json
  --deployment <digest from status> --package <name>`.
* A failed health gate rolls back automatically (also only in a safe
  state) and raises `robot.deliver.health_failed`. If the failing release
  raised the floor above the previous version, there is no rollback
  target: the unit stays on it with `robot.deliver.rollback_blocked_floor`
  (Critical) until an operator delivers a fixed release.
* `robot.deliver.stale` means no fresh deployment (or trust file) arrived
  before the last one expired: the depot or courier may be withholding
  updates or revocations.
* A refused pack is remembered by its **content**: copying a corrected
  pack under the same directory name is enough for it to be judged again
  (no need to rename it). Packs larger than `pack_digest_max_mb` (default
  4096) are recognised by their file names, sizes and times instead. While a pack is being copied it may be judged,
  and refused, more than once; copy it under another name and rename it
  into place when complete.

### 11.3 Evidence and recovery

Every step is a note in `/var/lib/robodr/blackbox/deliverd` (verify with
`robodr-blackbox verify /var/lib/robodr/blackbox/deliverd --keyring
<agentd-blackbox.key.pub>`). A crash or power loss during a switch is
resumed at the next start from the intent in `state.json`
(`robodr.deliver.recovered`).

The floors, the accepted deployment's sequence, the time floor and the
bundle chain heads are also kept in a **signed high-water record**,
`/var/lib/robodr/blackbox/deliverd/highwater.json` (signed with the
unit's black-box key, rewritten before every state write that moves
them, never rotated). Each write gives the record the next
**generation**, which is noted in the journal
(`robodr.deliver.highwater`) and in `state.json`. If `state.json` is
deleted, the agent restores all of them from a current record (and the
floors noted in the journal) and reports it (`robot.deliver.refused`,
`state_restored`); an older `state.json` next to a current record is
raised to it. Downgrades, replayed or expired deployments stay refused.

The agent **locks itself** (`robot.deliver.refused`, `state_lost`;
`status` shows `locked`), importing nothing and installing or rolling
back nothing, when it cannot show that what it has is current:

* the record is older than the generation the journal or `state.json`
  noted (an older copy was put back);
* the record is missing or does not verify while `state.json` or the
  journal exists (for example an older `state.json` put back and the
  record deleted);
* `state.json` and the record are both gone while the journal has
  records.

The lock is part of the signed record, so deleting `state.json` (again)
does not lift it. To lift it, find out why the state was lost, then,
with the service stopped:

```bash
sudo systemctl stop robodr-deliverd
sudo robodr-deliverd reanchor --config /etc/robodr/deliverd.json \
    --key /etc/robodr/keys/agentd-blackbox.key --trust /media/usb/trust.json
sudo systemctl start robodr-deliverd
```

`--key` is needed because the configured `blackbox.key`
(`/run/credentials/robodr-deliverd.service/blackbox.key`) is a systemd
credential that exists only while the service runs; the key file must be
root's, with no group or other permissions. `reanchor` accepts the
site's **current** trust file (the anchor or a newer rotation, under the
pinned roots; a new anchor if none is left) and refuses one older than
the newest version the journal has seen. It rebuilds the newest accepted
deployment, the bundle chain heads, the time floor and the floors from
the notes still in the journal, takes the trust file's signed
`issued_at` as a time floor too, and records the step
(`robodr.deliver.reanchored`). What the journal no longer holds (it is
cyclic) is not restored: floors are then those of the trust file
(`floors`), which the depot should set for every package that has one;
deliver the newest deployment first. Do not delete
`/var/lib/robodr/deliverd` or the black-box directory.

Only notes whose signature verifies with the unit's black-box key count
when the agent reads its history (at start and in `reanchor`).

**Black-box key rotation.** The journal and the record are signed with
the unit's black-box key (§4.3). After a rotation, run `robodr-deliverd
rekey --config ... --old-key <retired key file> --new-key <new key file>`
with the service stopped (§4.3, step 6). It refuses unless the journal
verifies completely with the old key and the record verifies with it and
is current (a locked agent: `reanchor --key <old key>` first, then
`rekey`). It notes the hand-over in the old journal
(`robodr.deliver.key_retired`), renames it to
`blackbox/deliverd.archived-g<N>` (it still verifies with the retired
key), and starts a new journal whose first note
(`robodr.deliver.rekeyed`) carries the baseline, with a record one
generation newer signed with the new key; a lock in the record is kept.
If it is interrupted, run it again: it finishes the swap from
`blackbox/deliverd.rekey-new`. Both key files must be root's with no group
or other permissions, as for `--key`.

### 11.4 Trust and limits

* The safety state comes from agentd alone (status socket, `SO_PEERCRED`
  against `robodr-agentd`); agentd takes safety reports only from root,
  itself and the configured feeders. Whoever controls root, the
  `robodr-agentd` user or a configured feeder can still claim `idle`.
* **Release signers are fully trusted for `deb`** (root-equivalent on
  the unit): a `.deb` without maintainer scripts can still install
  systemd units, cron entries or setuid files (dpkg and apt configuration
  are refused, below), and the agent
  runs as root. The unit's hardening limits accidents, not approved
  content (`docs/SECURE-DELIVERY.md` §6.7). A `deb` RPK's name and
  architecture are its dpkg `Package` and `Architecture`; a `.deb` that
  says otherwise, a package another RPK name already owns, a higher
  serial with a lower dpkg version, a `.deb` whose `Conflicts`,
  `Breaks`, `Replaces` or `Provides` names another package, and anything
  touching RoboDR's own packages outside `install.robodr_programme` are
  refused. A `.deb` under another name also cannot write files of
  another package, not even through a merged-/usr alias such as
  `/lib -> usr/lib`: before the switch every path of the `.deb` is
  resolved through the root's symlinks and refused when another package
  owns it, or when it lies below the agent's own trees, RoboDR's install
  paths (`/etc/robodr*`, `/var/lib/robodr`, `/usr/lib/robodr`,
  `robodr*` binaries and units), `/etc/dpkg`, `/etc/apt` or
  `/var/lib/dpkg`. dpkg runs with `--refuse-all` (then only
  `security-mac`, `downgrade`, `confdef`, `confold`) and
  `--refuse-overwrite` on its command line, so a `force-*` in
  `/etc/dpkg/dpkg.cfg.d` does not apply to the agent's installs.
* After every `dpkg --install` the agent checks every other deb package
  it installed: installed at its version, and `dpkg --verify` (conffiles
  aside) and its file list (`dpkg-query -L`) the same as right after its
  own install. If not, it reinstalls it and fails the switch
  (`robot.deliver.health_failed` or, without an earlier version,
  `robot.deliver.rollback_blocked_floor`). **Let the agent own those
  packages:** if apt (unattended-upgrades) or an operator changes one,
  the agent does not downgrade it; it reports `robot.deliver.refused`
  (High, `changed_outside`) and defers every deb install until the
  package is back at its recorded version or a release of it is
  delivered. Hold them in apt (`apt-mark hold`) or leave them out of
  unattended-upgrades.
* Release-allowed maintainer scripts stay root-equivalent: a `preinst`
  can divert a floored package's file (the file-list check then fails the
  switch, but the script has run).
* `deb` maintainer scripts run only when the release quorum allowed them
  (recorded in the black box), as root under the unit's capability set,
  without network. They cannot write `/proc/sys` (`ProtectKernelTunables=`:
  ship `/etc/sysctl.d/` files instead) or run a JIT
  (`MemoryDenyWriteExecute=`); `.deb`s with setuid / setgid files install
  (`RestrictSUIDSGID=` is not set, review I1).
* Probes run as their (non-system) user with their own limits (CPU =
  timeout + 1 s, `health.probe_max_memory_mb`, `probe_max_open_files`,
  `probe_max_processes`), in a session of their own; whatever a probe
  leaves behind, even a process in another new session, is killed with
  its process group (until none is left, at most 10 s) and fails the
  probe. Only groups outside the agent's own session are signalled, so
  the agent's other processes are never hit.
* Floors are in the state file, the signed high-water record and the
  black box, not a TPM counter (14b). Root deleting or putting back older
  copies of the state file or the record makes the agent lock until
  re-anchored, as long as the journal still shows the unit's history.
  Root deleting the journal too (or flooding it with notes signed with
  the black-box key until the generation notes are evicted, then putting
  an older record back) is **not** detected; the TPM counter closes that.
  Notes in the journal directory that do not verify with the black-box
  key are ignored.
  The high-water record is signed with agentd's black-box key, so a
  compromised agentd could forge one, though it cannot write it into
  place (`blackbox/deliverd` is root's). Sealed RPKs, models, OCI images
  and OS images are refused until 13c / 14a / 14c.
* `robodr-safety-replay` (tests and demos) writes safety states into
  agentd's socket; it is not in the package and must never run on a
  fielded robot.

### 11.5 Upgrading from a release where agentd ran as `robodr`

* The package moves agentd's black box, spool, profile state and
  control-plane state to `robodr-agentd` once (`postinst`). It stops
  `robodr-agentd` and the exporters for that and starts them again; the
  migration removes symlinks, FIFOs and devices from those trees,
  replaces hardlinked files by copies, removes group/other write and
  setuid/setgid bits, and is repeated until it has completed (marker
  `/var/lib/robodr/.agentd-user-migrated`). Do not create the marker by
  hand.
* **Focal (`robodr-focal`):** operator drop-ins under
  `/etc/systemd/system/robodr-agentd.service.d/` copied from older
  examples load agentd's credentials for the user `robodr`
  (`robodr-load-credential load robodr-agentd.service robodr ...`). The
  helper now hands credentials of `robodr-agentd.service` to
  `robodr-agentd` regardless and logs a warning, so agentd still starts;
  change the drop-ins to `robodr-agentd` (as in the shipped
  `*.conf.example` files) and run `systemctl daemon-reload`.
* **Focal (`robodr-focal`), `robodr-deliverd`:** the helper used to refuse
  every credential for `root`, so the focal `robodr-deliverd.service`
  (`User=root`, `robodr-load-credential load robodr-deliverd.service root
  ...`) failed in `ExecStartPre=` and never started. The helper now allows
  `root` for `robodr-deliverd.service` only (its `root_units` list;
  `scripts/check-focal-units.py` keeps it in step with the focal units);
  for every other unit `root` is still refused. Nothing to change on the
  unit; after the upgrade, start it with `systemctl start robodr-deliverd`
  if it is enabled.
* A safety gateway set up with `SupplementaryGroups=robodr-safety` (§11.1)
  is accepted from this release on; remove any workaround such as
  `allowed_gids` = the `robodr` gid (agentd now refuses to start with
  it).
