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
| Runtime libs | glibc, libgcc-s1, libsqlite3-0 (the `.deb` declares them). The libc6 floor is read from the binaries; the release builds the `.deb` in an Ubuntu 22.04 container, so it needs **glibc 2.35** or newer (Ubuntu 22.04 / 24.04, JetPack 6, Debian 12 / 13; [support-matrix.md](customer/support-matrix.md#platform-requirements)). |
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

*First installation* (no RoboDR on the unit yet). Copy the tarball and its
signature **once** into a root-owned 0700 directory and verify, extract and
install **that copy** only: a file on removable media, or in a directory
another user can write, can be swapped between the check and the
extraction (the extraction then unpacks something that was never verified,
and the package's scripts run as root):

```sh
sudo install -d -m 0700 -o root -g root /root/robodr-$V
sudo cp -- robodr-$V-$A-offline.tar.gz robodr-$V-$A-offline.tar.gz.minisig /root/robodr-$V/
sudo minisign -V -p /etc/robodr-trust/robodr-release.pub -m /root/robodr-$V/robodr-$V-$A-offline.tar.gz
#   the "Trusted comment" printed must name robodr-$V-$A-offline.tar.gz
sudo tar -xzf /root/robodr-$V/robodr-$V-$A-offline.tar.gz -C /root/robodr-$V
sudo sh /root/robodr-$V/robodr-$V-$A/install-bundle.sh install \
    --pubkey /etc/robodr-trust/robodr-release.pub \
    --tarball /root/robodr-$V/robodr-$V-$A-offline.tar.gz
```

*Upgrades* use the copy the previous, verified release installed (it makes
its own private copy of the tarball, step 1 below, so the tarball may stay
on the media):

```sh
sudo sh /usr/lib/robodr/install-bundle.sh install \
    --pubkey /etc/robodr-trust/robodr-release.pub \
    --tarball robodr-$V-$A-offline.tar.gz
```

`install-bundle.sh install --pubkey … --tarball …`:

1. refuses a tarball that is not a regular file (symlink, FIFO, device),
   then **copies** it, its `.minisig` and (if present) the release's
   `SHA256SUMS` / `SHA256SUMS.minisig` next to it **once** into a
   **private** directory (`mktemp -d`, 0700; removed afterwards). Every
   check and the extraction below read that copy only; the file named by
   `--tarball` is never opened again, so swapping it afterwards changes
   nothing;
2. checks the copy's minisign signature against the pinned key (with the
   **built-in verifier**, `robodr-deliverd verify-minisign`, once a release
   carrying it is installed; with the `minisign` program before that), and that
   the signature's **trusted comment** names the tarball's file name
   (releases sign with `robodr <version> <file>`): a signed bundle renamed
   to pass for another one (e.g. a `robodr-focal` bundle named like a
   `robodr` one) is refused. If the release's `SHA256SUMS` was signed, its
   signature is checked too and the tarball must be listed in it with its
   hash. Without `--pubkey`/`--tarball` it refuses unless
   `ROBODR_ALLOW_UNSIGNED=1` (labs only, and **only on a unit without the
   built-in verifier**; the bundle is then the directory the script runs
   from);
3. extracts the verified copy in the private directory and checks every
   file there against the inner `SHA256SUMS` (any unlisted file fails).
   Everything below uses that extraction, never an already extracted
   directory. If the script runs from an extracted bundle directory, that
   directory must be identical to the signed content, otherwise it was
   modified after extraction and the run is **refused**;
4. refuses a **downgrade** (a release older than the installed one,
   including a half-installed or half-configured one left by a failed
   upgrade) unless `--allow-downgrade`, and anything below the unit's
   **security floor** (section 7), with no override. A signed tarball must
   hold the variant its name names, and replacing the installed variant
   (`robodr` / `robodr-focal`; the focal variant has no `robodr-pulsard`)
   is **refused** unless `--allow-variant-switch`;
5. runs the black-box format gate (section 7);
6. applies the **safety-state gate** for the gateway and the executor
   (section 7, "Package upgrades and the safety state"; it is decided
   right after the downgrade and variant checks of step 4, before the
   security floor is raised, so a refusal changes nothing), then `dpkg -i`.
   The package creates the users `robodr` (owner of the
   shared group, runs nothing), `robodr-agentd` (agentd), `robodr-exec`
   (executor), one user per network-facing service (`robodr-spool`,
   `robodr-kafka`, `robodr-uplink`, `robodr-gw`; section 11.6) and the
   group `robodr-safety` (sysusers) and the
   directories (tmpfiles), installs the units **disabled**, and installs
   `/usr/lib/robodr/install-bundle.sh`, the trusted verifier for the next
   upgrade;
7. checks the unit's **health** (every RoboDR unit that ran before runs
   again, agentd's heartbeat is fresh) and **rolls back automatically** to
   the previous kept release if it is not healthy (section 7);
8. keeps the `.deb` under `/var/lib/robodr/releases/<version>/` for
   rollback (`--keep N` keeps only the N newest);
9. runs the installed release's **host preflight** (`robodr-setup
   preflight`: BTF, bpffs, nf_tables, systemd, glibc, clock, disk, key
   directory) and prints it. Advisory: a `FAIL` line is a warning, the
   install still succeeds; fix it before enabling RoboDR's services.

Every default above and its only override are listed in
`docs/SECURE-DEFAULTS.md`.

**Signature checks on the robot.** Every release installs RoboDR's own
minisign verifier (`robodr-deliverd verify-minisign`, `robodr-pkg`'s
`minisign` module: prehashed signatures, strict Ed25519, the trusted
comment checked), so from the first installed release on the robot needs
no `minisign` program and `install-bundle.sh` checks every later release
with that verifier, after its built-in known-answer self-test. Only the
**first** install needs a verifier from outside: `minisign` on the robot,
or the entry station. If `minisign` is not on the robot for the first
install, verify on the entry station (section 2), extract the verified
tarball into a fresh root-only directory on the robot and install with
`ROBODR_ALLOW_UNSIGNED=1`; record in the site log that the signature was
checked at the entry station. Once a release with the built-in verifier is
installed, `ROBODR_ALLOW_UNSIGNED` is **refused**: lab builds are signed
with a lab key (`minisign -G`) and installed with `--pubkey lab.pub`.

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
  Unitree images (JetPack 5, Ubuntu 20.04, kernel without BTF) cannot
  install the regular package (glibc 2.35, systemd 247): they take
  `robodr-focal`, agentd only, no host rules. JetPack 6 (Ubuntu 22.04)
  takes the regular package; its `robodr-pulsard` and host rules need a
  kernel with BTF or an external BTF file for the running kernel
  (UNITREE.md section 3.2).

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

On a new unit, `robodr-setup init --role ROLE --unit-id ID` runs the host
preflight and then generates the role's keys (`robodr-setup keys` generates
them alone); neither overwrites an existing key. `robodr-setup fingerprints`
prints the key ids to register (`man robodr-setup`).
`robodr-enroll` (8.6) generates the uplink, finding and black-box keys on
the unit at enrollment and rotates the uplink and finding keys with the
SOC; the black-box key is rotated in place with `robodr-blackbox rotate`
(4.3).

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
> **forge**. They are **refused by default**: `robodr-agentd` needs
> `blackbox.allow_hmac: true`, and `robodr-blackbox`, the diode tools and
> `robodr-spool-export` need `--allow-hmac`; each use then prints a
> warning. Migrate with `robodr-blackbox rotate --allow-hmac` (4.3). The Ed25519 code
> is the audited `ed25519-dalek` crate. Robot keys can be **sealed to the
> TPM at rest** (4.7); a TPM-resident, non-exportable signing key is still
> planned. Commissioning and release keys can stay in a **PKCS#11 token or
> HSM** (4.6).

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

*Legacy key files*: HMAC JSON key files (`robodr-blackbox-key/v1`) and bare
hex (0.1.0-alpha.1, made with `od ... /dev/urandom`; `robodr-agentd` only)
are refused unless explicitly allowed: `blackbox.allow_hmac: true` in
`/etc/robodr/agentd.json`, `blackbox.allow_hmac: true` in
`/etc/robodr/deliverd.json`, `--allow-hmac` for `robodr-blackbox` and
`robodr-replay`. **Upgrading a unit that
still has an HMAC key:** agentd will not start until you either set
`blackbox.allow_hmac: true` (a stopgap) or migrate to Ed25519 with 4.3; do
not hand-write JSON around an old secret on a shared terminal.

Then copy the **public** key file to each verifier (fleet console, the SOC's
evidence store) using vetted media. The diode is one-way, so nothing comes
back. Only legacy HMAC keys require copying the secret itself to the
verifier's protected store.

### 4.3 Rotate a key

**available**: `robodr-blackbox rotate` rotates the black-box key **in
place**. With agentd stopped it writes a `KeyRotation` record, signed by the
old key, that names the new key, and seals under the new key; the chain
(and its chain id) continues, nothing is archived or rewritten. agentd then
signs with the new key and authenticates the older records with the
retired key's **public** file listed in `blackbox.previous_keys`. This is
also how an HMAC unit moves to Ed25519.

A retired key vouches **only for what it signed up to its rotation**:
records after the `KeyRotation` must be signed by the key the chain names
for them (the rotation must be signed by its `from` key, and since v2 it
names the new key's public-key fingerprint); `head.json`,
`checkpoint.json` and a recovery pin signed by a retired key count only for
positions at or before that rotation; the export cursor and the TPM anchor
sidecar must be signed by the current key (`rotate` re-signs the cursor,
checkpoint and head mark, and with `--tpm-sidecar` the sidecar); a
segment may never switch back to an earlier key (`KeySwitchRefused`). So
whoever holds a leaked retired key cannot add or hide records after the
rotation.

1. Export all pending evidence (section 8) and confirm on the far side that
   the last bundle verified.
2. Generate the new key (4.2) with a **new key id**, next to the old one:

   ```sh
   old=<old-key-id>; new=ugv-07-bb-2027q1
   sudo robodr-blackbox keygen --out /etc/robodr/keys/agentd-blackbox-$new.key \
       --key-id $new --device <robot.id>
   ```

3. Stop the agent (`sudo systemctl stop robodr-agentd`; the recorder seals
   on a clean stop) and rotate:

   ```sh
   sudo robodr-blackbox rotate /var/lib/robodr/blackbox/agentd \
       --device <robot.id> \
       --old-key /etc/robodr/keys/agentd-blackbox.key \
       --new-key /etc/robodr/keys/agentd-blackbox-$new.key \
       --reason "scheduled rotation" \
       --tpm-sidecar /var/lib/robodr/anchor/blackbox-tpm-sidecar.json  # TPM head anchor only
   # add --previous-keys <each earlier retired .pub> if the log still holds
   # records of keys retired before; add --allow-hmac when the old key is HMAC
   ```

   It refuses a log that is open (agentd still running), a log being
   exported right now (`export.lock` held by `export-pending`: retry; with
   the export timer, a run that starts between this step and step 4 holds
   the retired key and is refused, exit 2, without touching the cursor),
   the wrong old key,
   an HMAC new key, a reused key id, and a log holding records no given key
   authenticates. `--previous-keys` gets the same checks as agentd's
   `blackbox.previous_keys` (below). Re-running it after success prints
   "already rotated" (and re-signs a `--tpm-sidecar` it did not get to).
4. Retire the old key and install the new one:

   ```sh
   sudo install -d -m 0700 /etc/robodr/keys/retired
   sudo mv /etc/robodr/keys/agentd-blackbox.key /etc/robodr/keys/retired/agentd-blackbox-$old.key
   sudo mv /etc/robodr/keys/agentd-blackbox.key.pub /etc/robodr/keys/retired/agentd-blackbox-$old.key.pub
   sudo mv /etc/robodr/keys/agentd-blackbox-$new.key /etc/robodr/keys/agentd-blackbox.key
   sudo mv /etc/robodr/keys/agentd-blackbox-$new.key.pub /etc/robodr/keys/agentd-blackbox.key.pub
   ```

   agentd cannot read `/etc/robodr/keys` (`InaccessiblePaths=`), so put the
   retired **public** key where it can (it is not secret):

   ```sh
   sudo install -d -m 0755 /etc/robodr/blackbox-previous
   sudo install -m 0644 /etc/robodr/keys/retired/agentd-blackbox-$old.key.pub /etc/robodr/blackbox-previous/
   ```

   In `/etc/robodr/agentd.json` add it and, if `blackbox.key_id` is set,
   update it:

   ```json
   "blackbox": { "dir": "/var/lib/robodr/blackbox/agentd",
                 "key_file": "/run/credentials/robodr-agentd.service/blackbox.key",
                 "previous_keys": [ "/etc/robodr/blackbox-previous/agentd-blackbox-<old>.key.pub" ] }
   ```

   A retired **HMAC** key has no `.pub`: hand the retired secret to agentd
   as a credential (a drop-in with
   `LoadCredential=blackbox-previous.key:/etc/robodr/keys/retired/agentd-blackbox-<old>.key`),
   list `/run/credentials/robodr-agentd.service/blackbox-previous.key` and
   set `"allow_hmac": true` until its records have rotated out of the black
   box.
   `robodr-agentd --check-config` validates the list: absolute paths, at most
   16, public files (an Ed25519 secret is refused), ids distinct and not the
   current key's, a device binding must name `robot.id`, and each file owned
   by root (or agentd's user) and not group/world-writable (`chmod 0644`
   as above; the same rule applies to every `--keyring` / keyring file a
   verifier loads: whoever can write it decides what verifies).
5. Copy the new `.pub` to the verifiers (fleet console, SOC evidence store)
   on vetted media; verifiers keep the old `.pub` too. With a **remote head
   anchor** (`head_anchor.kind remote`), replace the unit's public key on
   the anchor receiver before the next step (its marks are signed with the
   current key). A TPM anchor's sidecar is re-signed by `rotate
   --tpm-sidecar` (step 3); one still signed by the old key is **refused**
   (it names no position the rotation could bound): the first start then
   logs the anchor as unreadable ("signed by a retired key") and the next
   mark rewrites it under the new key.
6. `sudo systemctl start robodr-agentd` and check the journal: no black-box
   error, and `robodr-blackbox verify /var/lib/robodr/blackbox/agentd
   --keyring <old>.key.pub --keyring /etc/robodr/keys/agentd-blackbox.key.pub`
   reports `signing key rotated <old> -> <new>` and `INTACT`.
   **Without `previous_keys` agentd refuses to start** ("record N signature
   does not verify ... list the retired key's public file in
   blackbox.previous_keys"): the black box fails closed rather than chain
   onto records it cannot authenticate.
7. **Units running `robodr-deliverd`** (§11): the delivery agent signs its
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
   the archive with the retired key and keep it with the same retention.
   Moving off HMAC: set `"allow_hmac": true` in the `blackbox` section of
   `/etc/robodr/deliverd.json` for the rekey (robodr-deliverd refuses an
   HMAC key without it), then remove it.
8. Retention: keep the retired public key (HMAC: the key) in
   `previous_keys` while the black box still holds segments it signed, and
   with the verifiers as long as the evidence must remain verifiable. Once
   those segments have rotated out (cyclic retention or export pruning),
   the entry can be removed from `previous_keys`. An Ed25519 secret that is
   retired (after step 7) can be destroyed (`shred -u`).

*Alternative, new chain:* instead of `rotate`, archive the closed chain
(stop agentd, `mv /var/lib/robodr/blackbox/agentd
/var/lib/robodr/archive/blackbox-agentd-$old-$ts`, `systemd-tmpfiles
--create robodr.conf`) and start agentd with the new key and no
`previous_keys`; verify the archive with the retired key. Use this after a
suspected compromise (below), where the chain should not continue.

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

### 4.6 Signing keys in a token or HSM (PKCS#11)

**available** (SALES-READINESS T36). Every key argument of
`robodr-commission` (`--sign-key`: profile, root, operator keys) and
`robodr-release sign --key` (release, root, operator keys) takes either a
key file (4.2) or a **signer file** (`robodr-signer/v1`). A signer file
holds no secret: it names an external signer command and pins the key's
public half. The key stays in the token; for each signature the tool runs
the command, hands it the document on stdin and reads the 64-byte Ed25519
signature from stdout. **Every signature is verified against the pinned
public key before it is used**, so a wrong token, slot or key id, or a
misbehaving adapter, fails the command and writes nothing. The protocol
(cleared environment, deadline, output cap, trusted-path checks of the
signer file and of the command and its directories; the command runs in
its own process group, killed as a whole on a timeout) is documented in
`crates/robodr-signer/src/lib.rs`.

The shipped adapter `/usr/lib/robodr/robodr-signer-pkcs11` drives OpenSC's
`pkcs11-tool` (OpenSC 0.25 or later; `CKM_EDDSA`, pure Ed25519) with any
PKCS#11 module that offers Ed25519: YubiKey 5 (firmware 5.7 or later),
Nitrokey 3, SoftHSM 2, network HSMs. On the signing station:

```sh
# 1. Generate the key ON the token
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libykcs11.so --login \
    --keypairgen --key-type EC:edwards25519 --id 01 --label oem-root-2026
# 2. Write the signer file (reads and pins the token's public key)
/usr/lib/robodr/robodr-signer-pkcs11 signer-file \
    --module /usr/lib/x86_64-linux-gnu/libykcs11.so --id 01 \
    --key-id oem-root-2026 --pin-env ROBODR_PKCS11_PIN > oem-root.signer.json
chmod 0644 oem-root.signer.json   # owned by root or you, not group/other-writable
# 3. Check it (a real test signature: PIN, touch)
read -rs ROBODR_PKCS11_PIN && export ROBODR_PKCS11_PIN
robodr-signer check --key oem-root.signer.json   # key_id, fingerprint, "external"
# 4. Use it wherever a key file went
robodr-commission trust-keys --out profile-trust.json --pub oem-profile.key.pub \
    --operators operators.json --sign-key oem-root.signer.json
robodr-release sign --key oem-root.signer.json --target trust.json
```

`robodr-signer check` prints the key's `public_key_hex` and `fingerprint`
(for `--root` pins and trust files). `sign` and `signer-file` need one
PIN source: the environment variable named by `--pin-env` (listed in the
signer file's `pass_env`) or the first line of `--pin-file`, which must be
a regular file owned by you or root with no group or other access (mode
0600 or 0400; anything else is refused). There is no terminal prompt: the
external signer runs in its own process group with the message on stdin,
so it cannot read the terminal. The PIN never appears on a command line:
the adapter hands it to `pkcs11-tool` as `--pin env:VAR`. That form is
documented for OpenSC 0.25 and tested only with 0.25; a `pkcs11-tool`
without it would send the text `env:VAR` as the PIN and spend one of the
token's PIN retries (a YubiKey PIV locks after 3). The adapter therefore
reads the OpenSC version (`opensc-tool
--info`) and refuses to log in below 0.25 or when the version cannot be
read. Ubuntu 22.04 (0.22) and Debian 12 (0.23) ship older releases:
install OpenSC 0.25 or later on the signing station. The adapter is in
the `robodr` package;
`robodr-signer` (the check tool) is built from the source tree like
`robodr-release` (`cargo build --release -p robodr-signer`).

Limits: tested end to end against SoftHSM 2 (`ROBODR_PKCS11=1 cargo test
-p robodr-signer`). YubiKey, Nitrokey and network HSMs use the same
adapter and mechanism but have not been tested on the hardware yet.
`robodr-commission keygen` and `robodr-release keygen` make file keys
only: token keys are generated with the vendor's or OpenSC's tools. Any
other signer (a vendor CLI, a KMS client) can be used by writing a command
that follows the same protocol.

### 4.7 Robot keys sealed to the TPM

**available** (SALES-READINESS T66; systemd 250 or newer and a TPM 2.0;
not in the focal package). By default the robot's private keys are
root-only files that systemd hands to each service (`LoadCredential=`).
They can instead be stored **sealed to the unit's TPM** as systemd
encrypted credentials: a copied disk or SD card then no longer yields
them. systemd decrypts them at service start into the same place
(`/run/credentials/robodr-agentd.service/<name>`), so `agentd.json` does
not change.

```sh
sudo install -d -m 0750 -o root -g robodr-agentd /etc/robodr/credstore.encrypted
sudo systemd-creds encrypt --with-key=host+tpm2 --tpm2-pcrs=7 --name=blackbox.key \
    /etc/robodr/keys/agentd-blackbox.key /etc/robodr/credstore.encrypted/blackbox.key
sudo chgrp robodr-agentd /etc/robodr/credstore.encrypted/blackbox.key
sudo chmod 0640 /etc/robodr/credstore.encrypted/blackbox.key
sudo install -D -m 0644 \
    /usr/share/doc/robodr/examples/robodr-agentd.service.d/15-tpm-credentials.conf.example \
    /etc/systemd/system/robodr-agentd.service.d/15-tpm-credentials.conf
sudo systemctl daemon-reload && sudo systemctl restart robodr-agentd
sudo robodr-agentd --config /etc/robodr/agentd.json --check-config   # "key blackbox: host+tpm2"
```

Keep the plaintext key file only until the service has started from the
sealed credential and its public key is safely with the verifiers; then
destroy it (on flash storage overwriting is unreliable: rely on the
volume's encryption, see 9). Seal the other keys (`finding.key`,
`cp-tls.key`, `anchor-tls.key`, `executor.key`) the same way, replacing
their drop-in's `LoadCredential=` by `LoadCredentialEncrypted=`.
`host+tpm2` needs both the TPM and the root-only
`/var/lib/systemd/credential.secret`; `--tpm2-pcrs=7` binds the credential
to the Secure Boot state, so a firmware or Secure Boot change needs
re-sealing: plan it with firmware updates. The sealed file is readable by
the `robodr-agentd` group only so that agentd can read its header (it
never decrypts it; the ciphertext is useless without the TPM and the host
secret).

**What agentd reports.** `status.json` carries `key_protection`:

```json
"key_protection": {
  "require": "none", "all_tpm2": false, "fallback": true,
  "keys": [ { "role": "blackbox",
              "path": "/run/credentials/robodr-agentd.service/blackbox.key",
              "protection": "host+tpm2", "tpm2": true, "fallback": false,
              "sealed_source": "/etc/robodr/credstore.encrypted/blackbox.key" },
            { "role": "finding_signing",
              "path": "/run/credentials/robodr-agentd.service/finding.key",
              "protection": "plain-credential", "tpm2": false, "fallback": true } ]
}
```

`protection` is `tpm2` or `host+tpm2` (sealed to this TPM), `host` (host
key file only), `null` (no confidentiality), `unknown` (sealed source
unreadable or not recognised), `plain-credential` (a credential without a
sealed source: `LoadCredential=` from a plain file) or `file` (a plain key
file outside the credentials directory). Everything but `tpm2` and
`host+tpm2` is the **fallback** and is flagged (`fallback: true`).
`robodr-agentd --check-config` prints one line per key. To refuse to
start unless every key is sealed to the TPM, add to `agentd.json`:

```json
"key_protection": { "require": "tpm2" }
```

(`credentials_dir`, default `/run/credentials/robodr-agentd.service`, and
`encrypted_dir`, default `/etc/robodr/credstore.encrypted`, are optional.)

Under systemd, agentd also compares `credentials_dir` with the directory
systemd gave it (`$CREDENTIALS_DIRECTORY`); if they differ, no key counts
as a credential (`protection: "file"`, with a `detail`). `--check-config`
run from a shell has no such variable and trusts the configured directory.

Limits: sealing protects keys **at rest**. While the service runs, the key
is in its private credential ramfs and memory and the TPM does not make the
signatures; root on a running unit can still read it. The report matches a
credential to `<encrypted_dir>/<name>` by name and reads only the header;
it does not read the unit file. systemd places a `LoadCredential=` copy of
a plain file and a `LoadCredentialEncrypted=` decryption in the same
place, identically, and the plain key directory is inaccessible to the
service, so agentd cannot tell them apart: if the sealed file exists but
the unit still loads the plain key (the `15-` drop-in removed or
overridden), the key is reported
as `tpm2`/`host+tpm2` and `require: "tpm2"` accepts it. Check the unit
with `systemctl cat robodr-agentd` after sealing, and destroy the plain
key file as described above. The report catches a missing or weaker seal,
not a unit that loads another source than the sealed one. `robodr-executor`,
`robodr-uplink` and the exporters can be sealed with the same systemd
mechanism but do not report it. Tested against swtpm (`ROBODR_SWTPM=1
cargo test -p robodr-agentd --test key_protection`), not yet on a hardware
TPM.

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
   sudo robodr-ros2-watch --check-config /etc/robodr/pulsar.toml   # offline, read-only
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

   With `sros2_keystore` set (SROS 2 robots, `docs/DDS-TRANSPORTS.md`
   section 3), a missing or unreadable keystore, or one without a grant, is
   a configuration error: the whole `robodr-sensor-ros2` module does not
   start and **all DDS monitoring stops**, not only the SROS 2 check. After
   moving or rotating the keystore, update `sros2_keystore` and run
   `robodr-ros2-watch --check-config` before restarting `robodr-pulsard`.

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

Both units restart on failure. `robodr-agentd` restarts up to 5 times in
300 s, then stays failed (kept on purpose; the reasons are in its unit
file). `robodr-pulsard` has no start limit: a daemon that exits non-zero is
restarted every 10 s for as long as it fails (an event storm can kill it at
its `MemoryMax=` again and again; giving up would leave host detection
off), and each restart is counted in its `NRestarts`. A failed
`AssertPathExists=` (no BTF, no bpffs) is different: systemd runs nothing,
does not restart, and leaves the unit inactive, not failed. A failed or
restarting unit does not affect the robot's operation; it does mean the
robot is not (fully) being watched. Alert on all of these: `robodr-metrics`
exports `robodr_unit_failed`, `robodr_unit_restarts`, `robodr_unit_active`
and `robodr_unit_enabled` per unit (example alerts `RoboDRUnitFailed`,
`RoboDRUnitRestartLoop`, and `RoboDRUnitDown` for an enabled unit that is
not running).

`robodr-agentd` runs as `Type=notify` with `WatchdogSec=60s`; a hung main
loop is restarted. Its `status.json` carries `updated_mono_ms`, `boot_id` and
`stale_after_ms`: treat a stale or other-boot status as `unknown`.
`robodr-pulsard` has no watchdog (Pulsar does not send `sd_notify`
keep-alives), so a hung, still-alive pulsard is not restarted automatically.
Monitor the findings and heartbeat flow on the fleet side.

#### Health record and early warnings (`daemon.self_health`)

Every `health_record_ms` (default 60 s; 0 switches it off, only for replay
and tests) agentd sends one Low, observe-only `robot.agent.health`
finding (findings contract 2.5, §3g), an Update of the same finding each
time, carrying `entity_context.agent_health`: state and reasons,
component and contract versions, per-input freshness and counters, spool
and black-box counters, executor / gateway / pulsard reachability,
credential expiry, clock and free disk space. A SOC rule "no health
record from robot X for N periods" tells a silent robot from a quiet one.
`status.json` `self_health` shows the same probes between records. Under
a producer cap below 2.5 (`findings.max_contract_minor`, contract §5) the
record is off.

The early warnings, all observe-only (they never trigger a response):

| Finding | Severity | When (setting, default) |
|---|---|---|
| `robot.agent.credential_expiring` | Medium; High | the control plane's server certificate or a CRL within `credential_warn_days` (14); within `credential_critical_days` (3) or expired |
| `robot.agent.clock_unsynced` | Medium | the kernel reports the clock unsynchronised for `clock_unsynced_grace_ms` (5 min); never where `adjtimex(2)` is refused, as under the shipped unit (`docs/TIME-SYNC.md`) |
| `robot.agent.clock_jump` | High | the wall clock jumped against the monotonic clock (> 1 s) |
| `robot.agent.disk_low` | Medium; High | the black-box or spool filesystem below `disk_warn_percent` (10 %) free; below `disk_critical_percent` (3 %) |
| `robot.agent.executor_unreachable` | High | the executor has not answered for `executor_unreachable_ms` (30 s) |

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
#              "crl_files": ["/etc/robodr/control-plane/soc-ca.crl.pem"],  # optional
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
  key (refused). **Scope SOC keys** that do not need every action: a
  `soc_keys` entry `{"path": "/etc/robodr/soc/tier1.pub",
  "allowed_actions": ["record_evidence", "isolate_network"],
  "max_ttl_seconds": 900}` lets that key request (and revert) only those
  actions, with at most that TTL; anything else is answered 403 and
  reported as `robot.agent.control_plane_invalid` (contract §4.2).
  `max_ttl_seconds` bounds only actions that take a TTL
  (`restrict_motion`, `isolate_network`): the others (`quarantine_node`,
  `safe_pause`, `request_safe_state`, `rollback_config`) stay in force
  until reverted or restored by an operator, so leave them out of
  `allowed_actions` to keep the key from them. Keep
  the unscoped key (all seven actions) with the people who may ask for
  `safe_pause` / `request_safe_state`. The executor does not apply these
  scopes yet (contract §4.2). The TLS key file must have no group/other bits (the
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
- **Sealed state.** Both journals (format `robodr-cp-journal/v2`) are
  sealed with an HMAC chain under a key derived from the black-box key
  (`state.seal_key_id`), and their heads are recorded as signed black-box
  notes (`robodr.control_plane_state_head`: at start, on heartbeats when
  they moved, and at a clean stop). At start, an edited, deleted or
  reordered entry, a journal under another key, or a journal older than
  (or cut short of) the black box's newest head is never believed: the
  copy goes to `state_dir/quarantine/`, requests are reconciled with the
  black box, the replay store is fenced, and agentd raises
  `robot.agent.control_plane_state_untrusted` (High; Critical for a
  rollback against the signed head). After a crash (no clean-stop head)
  the same reconciliation and fence run without a finding. Restoring
  `state_dir` from a backup therefore reads as a rollback: let agentd
  start, check the finding names the restore, and carry on (nothing is
  lost: the black box is the record). **Rotating the black-box key**
  changes the seal key: expect one High finding (`sealed under another
  key`) at the next start, with the same fail-safe handling.
- **Upgrade to sealed state (one time).** The first start of a release
  that seals finds the v1 (checksummed) journals and no head note in the
  black box: it adopts them once, rewrites them sealed, reconciles with the
  black box, fences the replay store and records a
  `robodr.control_plane_state_upgraded` note. No operator step. Once a head
  note exists, or once `state_dir/sealed.marker` exists (written at every
  sealed start), a v1 file in `state_dir` is a downgrade: refused as damage
  (Critical). Downgrading agentd below the sealing release is not
  supported without emptying `state_dir` (first-start fence).
- **Head notes in a cyclic black box.** The head notes are recorded again
  whenever the black box moved to a new segment (checked every
  heartbeat), so the newest segments always hold one. If the black box
  dropped segments and holds no head note at start (e.g. more than
  `max_segments` rotated within one heartbeat, or a wiped store), both
  journals are treated as unanchored: the replay store is fenced and the
  requests are reconciled with the black box (`state.anchor_lost`).
- **Notes that do not verify.** Only black-box notes whose record hash and
  signature verify under the black-box key settle a decision or restore a
  request; the others are ignored and counted (`state.notes_rejected`, in
  the `control_plane_state_untrusted` finding).
- **Unreconciled requests.** When the journal held entries no authentic
  note backs (an adopted v1 file, a rolled-back copy, lines failing their
  seal), they are dropped and their request ids refused
  (`state.dropped_unbacked`, `state.lost_request_ids`). Those ids, and a
  "refuse every new id" state when the black box could not be read, are
  kept in the sealed `state_dir/unreconciled` marker: every start
  reconciles again and keeps refusing them, also after the journal was
  rewritten clean. It is removed once nothing is left; deleting it by hand
  ends the refusals (do so only after checking the black box).
- **Connections.** TCP connections in the TLS handshake (or not yet
  authenticated) and authenticated ones have separate slots of
  `max_connections` (default 4) each; one source address holds at most
  `max_connections_per_source` (default 2): raise it if several SOC
  workers share one NAT address. The unix socket has its own 2 slots, so
  an operator on the robot is never locked out by network peers. Rejected
  connections count in `connections_rejected`. **Set `soc_sources`** to
  the SOC's egress networks (e.g. `["203.0.113.0/28"]`; a /0 is
  refused): they get `reserved_connections` (default 1) slots of their
  own and cut any unlisted handshake when they need room, so a TLS
  slowloris from other addresses cannot lock the SOC out (W2-4). Without
  `soc_sources`, when the pre-authentication slots are full a new
  connection cuts the oldest handshake older than `pre_auth_evict_after_ms`
  (default 100 ms without `soc_sources`, counted in `connections_evicted`).
  That holds a slowloris back only partly, and under legitimate overload
  over long round trips (more SOC clients than slots, round trip above
  the setting) the clients cut each other's handshakes and few finish;
  workers behind one NAT address at their per-source share cut their own.
  With `soc_sources` nothing is cut by age unless you set
  `pre_auth_evict_after_ms`; `0` turns it off without `soc_sources` too.
  The trade-off for clients **outside** `soc_sources` (another SOC
  worker, a monitoring probe): with nothing cut by age, a slowloris holds
  every general slot for the full 5 s handshake deadline and reopens, so
  every unlisted client is refused for as long as the attack lasts; list
  every legitimate client network in `soc_sources`, or set
  `pre_auth_evict_after_ms` to let some of them through at the cost
  above. Keep the `IPAddressAllow=` drop-in (§6.4) as well: it stops
  unlisted peers before agentd sees them.
- Watch `status.json` `control_plane` (`unauthenticated`, `tls_failures`,
  `last_auth_failure`, `connections_rejected`, `connections_evicted`,
  `fenced`, `recorded_not_executed`,
  `refused`, `busy`, `rate_limited`, `journal_errors`, `replay_fence`,
  `state.refusing_new_request_ids`, `evidence`) and the
  findings `robot.agent.control_plane_unauthenticated` (High: someone
  without the certificate or the key is trying),
  `robot.agent.control_plane_invalid` (Medium: the SOC sent something the
  API never allows), `robot.agent.control_plane_saturated` (Medium:
  connections refused or cut before they authenticated: a handshake flood
  or slowloris, which a cut handshake does not count as an authentication
  failure, or more clients than `max_connections`) and
  `robot.agent.control_plane_request_fenced` (Low: correctly signed
  requests refused by the replay fence after a restart; the SOC re-signs). Each decision is a `robodr.control_plane_request` note
  in the black box with the SOC's signature, which re-verifies offline.

**Rotation (no downtime for the SOC).**

| What | How |
| --- | --- |
| SOC signing key | add the new `.pub` to `soc_keys` (both listed), restart agentd, and to `executor.json` `soc.keys` (re-read per order); switch the SOC; remove the old one from both, restart agentd |
| SOC client certificate, same CA | issue the new certificate; with pins, add the new pin to `client_spki_sha256` first (both listed), restart; switch the SOC; remove the old pin |
| SOC client CA | append the new CA certificate to `client_ca` (PEM bundle with both), restart; reissue the SOC certificate; remove the old CA, restart |
| Robot TLS certificate / key | install the new `robot.pem` and key (same paths), restart agentd; if the SOC pins the robot's SPKI, give it the new pin first (`openssl x509 -pubkey ...` as above) |
| SOC client CRL | write the new CRL next to the old one and `mv` it over the `crl_files` path: the next handshake uses it, no restart |
| Finding key (answers, manifests) | section 4.3; give the SOC the new `.pub` before the restart |

TLS certificates, keys, CAs and pins are read at start only: changing
them takes a restart, which keeps the request state. **CRLs are reloaded
without a restart.** To cut off a client certificate, revoke it in the
client CA's CRL (`openssl ca -revoke`, `openssl ca -gencrl`) and install
it at a `tls.crl_files` path (PEM or DER X.509 v2 CRLs, up to 16 files;
the older `client_crl` is one more entry). The files are `stat`ed before
every handshake and re-read when they change; **replace them by
rename** (write the new file next to the old one, then `mv` it over): an
in-place rewrite can be read half-written (a file whose `stat` changes
during the read is read once more, then the load fails closed). Rules
(fail closed, not configurable):

- every CA in the chain (each client CA, any intermediate) needs a CRL in
  the files: a certificate whose issuer has none is refused;
- `nextUpdate` is enforced: once a CRL is past it, every client of that CA
  is refused until a fresh CRL is installed, so publish CRLs well before
  `nextUpdate` (agentd itself keeps running);
- a replacement that is unreadable, not a CRL or has bad permissions
  refuses every client until fixed (`status.json`
  `control_plane.tls.crl.error`);
- every CRL must carry a **CRL number** (`crlnumber` in the `openssl ca`
  configuration); one without is refused;
- **one CRL per CA is used**: when the files hold several CRLs of one
  issuer (an old CRL left in a bundle next to the new one), the highest
  CRL number wins and the others are ignored; two different CRLs with the
  same number are a configuration error. `status.json`
  `control_plane.tls.crl.in_use` names, per issuer, the CRL number,
  `thisUpdate` and file in use;
- **no going back**: an older genuine CRL put back in place (a lower CRL
  number or an older `thisUpdate` than one already loaded) would
  un-revoke certificates, so it is refused, fail closed
  (`rollback_refusals`), until the current CRL is back. agentd keeps these
  high-water marks in `<control_plane.state_dir>/crl-high-water.json`
  (and the anchor receiver in `<state_dir>/crl-high-water.json`), so a
  restart does not reset them: an older CRL then refuses start. Only the
  marks of CRLs whose signature was verified at load against a trust
  anchor are written there (a CRL of an intermediate CA is checked at the
  handshake; its mark lasts for the process). The TLS clients without a
  state directory (the robot's anchor client, `robodr-uplink`,
  `robodr-enroll`, `robodr-kafka-publish`) keep the marks per process.
  Remove the state file only to accept an older CRL on purpose (a CA that
  was re-keyed and restarted its numbering);
- a CRL claiming a trust anchor as issuer whose signature does not verify
  under it is a configuration error at load.

`status.json` `control_plane.tls.crl` counts `reloads`,
`reload_failures`, `rollback_refusals`, `revoked_rejections` (with
`last_revoked_spki_sha256`),
`expired_crl_rejections` and `unknown_status_rejections`; a refused
revoked client is also a failed authentication
(`robot.agent.control_plane_unauthenticated`, reason `Revoked`).

The same `crl_files` exists on every other TLS path: the remote head
anchor (`blackbox.head_anchor.tls.crl_files` on the robot, `tls.crl_files`
of `robodr-anchor-receiver` for unit certificates), `robodr-kafka-publish
--tls-crl-file`, `robodr-uplink --crl-file` and `robodr-enroll`
(`soc.crl_files` in `fleet.json`). TLS clients with CRLs never resume a
session, so a server revoked after the first connection is refused on the
next one. The site depot's LAN serving needs none: a unit is revoked by
its identity key (`robodr-depot`), checked on every request. It admits at
most `serve.max_connections` connections, `serve.max_connections_per_source`
(default 4) from one address, and cuts a peer that has not completed the
TLS handshake after 10 s. The unit's LAN client (`robodr-deliverd`) bounds
the connect, handshake, request and answer head by one deadline
(`depot.deadline_s`; a pack body gets `deadline_s` more plus one second
per MiB), so a peer trickling bytes cannot hold it.

**No OCSP.** Robots run air-gapped or behind a data diode and cannot reach
an OCSP responder; a soft-fail OCSP check would protect nothing and a
hard-fail one would cut the robot off. A CRL is a signed file that travels
over the same configuration channel as the CA bundle, so it is the only
revocation mechanism.

**Renewing CRLs on an air-gapped site.** A CRL past its `nextUpdate`
refuses every peer of its CA (fail closed), so a renewed CRL must reach
every host that lists it before then:

1. On the (offline) CA, issue the CRL with a `nextUpdate` longer than the
   time it takes to carry a file to every host, plus a margin
   (`openssl ca -gencrl -crldays N -out new.crl.pem`; the CRL number must
   go up, `crlnumber` in the `openssl ca` configuration).
2. Carry it in on the same channel as the CA bundle (media, the site's
   configuration channel) and check it before installing:
   `openssl crl -in new.crl.pem -CAfile ca.pem -noout -crlnumber -nextupdate`
   (the signature must verify under the CA, the number must be higher than
   the one in use).
3. On each host, write it next to the old file and `mv` it over the
   configured path (`tls.crl_files`, `--crl-file`, `--tls-crl-file`,
   `soc.crl_files`). The file is re-read on its next use, no restart.
4. Confirm: agentd `status.json` `control_plane.tls.crl.in_use` shows the
   new CRL number; `<state>/uplink-status.json` `credentials` shows the new
   `days_to_expiry`; `robodr-kafka-publish ... --check`,
   `robodr-anchor-receiver check` and `robodr-enroll check` print the days
   left on each CRL in use.

What warns before a CRL or certificate lapses: agentd raises
`robot.agent.credential_expiring` for the control plane's server
certificate and CRLs (Medium within `daemon.self_health.credential_warn_days`,
default 14; High within `credential_critical_days`, default 3, or once
expired). `robodr-uplink` (its CRLs), `robodr-kafka-publish` (its client
certificate and CRLs) and `robodr-anchor-receiver serve` (its server
certificate and unit CRLs) log a line on stderr within 14 days of expiry,
once per day count; `robodr-depot serve` does the same for its server
certificate. Do not remove a lapsed CRL from the configuration to get
peers through: that switches revocation off for that path.

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

**Black-box retention and sizing** (`blackbox.retention`, optional). Without
it the black box keeps 8 segments of 8 MiB, cyclic: when a ninth starts the
oldest is dropped (a signed `SegmentDropped` record names it). At the soak's
write rate (about 4.7 MB per hour on an idle lab robot) that is 12 to 14
hours of evidence, and much less during an incident. Size it for the site:

```json
"blackbox": {
  "dir": "/var/lib/robodr/blackbox/agentd",
  "key_file": "/run/credentials/robodr-agentd.service/blackbox.key",
  "retention": {
    "mode": "cyclic",
    "segments": 32,
    "segment_bytes": 33554432,
    "unexported_reserve_segments": 16,
    "warn_percent": 80
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `mode` | `cyclic` | `cyclic`: drop the oldest segment when a new one starts. `saturation`: never drop; once `segments` are full refuse non-critical records (`Saturation` record), keep `critical_reserve_segments` more for critical ones until an export prunes |
| `segments` | 8 | segments kept (1..=65536) |
| `segment_bytes` | 8388608 | size of one segment (64 KiB ..= 256 MiB) |
| `unexported_reserve_segments` | 0 | cyclic only: **pending-export protection**. A segment whose records are not all covered by the signed export cursor (8.2) is kept, up to this many segments beyond `segments`; only then is unexported evidence dropped |
| `critical_reserve_segments` | 1 | saturation only |
| `warn_percent` | 80 | unexported share of the capacity that raises the pressure finding (50..=99) |
| `export` | `auto` | whether this site exports the black box (8.2), for the plain-cyclic drop finding below: `auto` reports it only once an export cursor exists (an export ran at least once), `expected` also before the first export, `none` never (the site does not export; refused together with a reserve) |

At start agentd checks that `(segments + reserve) x segment_bytes`, minus
what the directory's segments already hold, fits in the free space of the
black box's filesystem, and refuses to start otherwise (exit 2, the message
names the numbers). agentd re-reads the export cursor every health tick and
raises, observe-only:

| Condition | Finding | Severity |
|---|---|---|
| unexported segments reach `warn_percent` of the capacity, before anything unexported is dropped (once per episode, again at High if it climbs to 95 %; clears 10 points below) | `robot.agent.evidence_retention_pressure` | Medium; High from 95 % |
| cyclic retention dropped unexported evidence (the reserve was used up) | `robot.agent.evidence_unexported_dropped` | High |
| plain cyclic retention (no reserve, the default) dropped segments no export had confirmed, and `export` is `expected`, or `auto` with an export cursor | `robot.agent.evidence_unexported_dropped` | Medium, at most once a day with the count since the last report |

(Both ids are findings contract 2.5 entries; `robot.agent.evidence_degraded`
means only that the recorder failed to store evidence.) Plain cyclic
retention has no pressure finding: without an exporter every segment is
unexported, so it would always read full. Its drops are normal operation
on a unit nobody exports, so with the default `export: auto` they are
reported (once a day at most) only after an export has run at least once:
a unit whose exporter stopped or fell behind says that its oldest
unexported evidence is going, while a unit that was never exported stays
quiet. Drops made before the first export are not reported later. A site
that must export sets `export: expected` (reported from the first drop) and
the reserve; a site that never exports sets `export: none`. Drops are
counted per recorder: a recorder reopened after an outage starts from 0 and
what the previous one dropped but had not reported is carried over.

Sizing (hours of evidence held; a cyclic store holds between `segments - 1`
and `segments` full segments; the oldest is the one dropped next):

| Retention | 1 MB/h (quiet) | 4.7 MB/h (soak, idle lab robot) | 20 MB/h (incident, busy bus) |
|---|---|---|---|
| 8 x 8 MiB = 64 MiB (default) | 2.8 days | 12-14 h | 3 h |
| 16 x 16 MiB = 256 MiB | 11 days | 2.4 days | 13 h |
| 32 x 32 MiB = 1 GiB | 45 days | 9.5 days | 2.2 days |
| 64 x 64 MiB = 4 GiB | 179 days | 38 days | 9 days |

Measure the rate on the unit (`du -sb` of the black box an hour apart, or
the segment indices in `status.json` over a day). On a diode or media site
give the reserve the longest export outage you plan for (diode down, the
interval between media visits) at the incident rate: `reserve >= hours x
MB/h / segment MB`, and run the export (8.2) well inside it. The capacity
needs that much free space on the black box's filesystem.

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
  "max_connections_per_source": 8,
  "io_timeout_ms": 5000,
  "tls": {
    "cert_chain": "/etc/robodr-anchor-receiver/tls/receiver.pem",
    "key_file": "/run/credentials/robodr-anchor-receiver.service/receiver-tls.key",
    "client_ca": "/etc/robodr-anchor-receiver/tls/robots-ca.pem"
  }
}
```

**TLS** (required by default). `tls.cert_chain` is the receiver's
certificate chain (PEM, end-entity first; its SAN must name the address the
robots dial: an `IP:` SAN for an IP literal, a `DNS:` SAN for a name, or
the robots' `server_name`); `tls.key_file` its private key (no access for
others, no group write); `tls.client_ca` (optional) makes every robot
present a client certificate chaining to that CA (mutual TLS: unknown
hosts never reach the request parser). Hand the key over with a drop-in
(`systemctl edit robodr-anchor-receiver`):

```ini
[Service]
LoadCredential=receiver-tls.key:/etc/robodr-anchor-receiver/tls/receiver.key
```

Without `tls` the receiver refuses to start unless the config says
`"allow_plaintext": true` (a lab, or a private link you accept to run in
clear: marks and answers stay Ed25519-signed, see below, but hashes and
sequence numbers are readable on the wire); `tls` together with
`allow_plaintext` is refused. Failed handshakes are logged (the first 16,
then at powers of two). `io_timeout_ms` bounds a whole connection, TLS
handshake included (every read and write is re-armed with the time left,
so a peer trickling bytes is cut), and the answer gets another one;
`max_connections_per_source` (default 8, 1..=4096) caps the connections
one address may hold, authenticated or not, so a single host cannot take
every one of `max_connections`. Every TLS file (and the robot's and the
publisher's, below) must be owned by root or by the service's own user
(`LoadCredential=` files are).

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
  "timeout_ms": 2000,
  "tls": {
    "ca_file": "/etc/robodr/anchor/receiver-ca.pem",
    "cert_chain": "/etc/robodr/anchor/ugv-07.pem",
    "key_file": "/run/credentials/robodr-agentd.service/anchor-tls.key"
  }
}
```

`address` is `host:port` (an IP literal avoids DNS at start);
`receiver_public_key` must be absolute and outside `blackbox.dir` and
`spool.dir`; `timeout_ms` (100..=30000, default 2000) bounds connect, TLS
handshake, write and read each, so a start waits at most about four times
that for the receiver (three without TLS). Marks never wait for the
network.

`tls` (required unless `"allow_plaintext": true`; both together are
refused, neither is refused at load): `ca_file` holds the only trust
anchors for the receiver's certificate, which is always verified (chain,
validity, `serverAuth`, and the host of `address`, or `server_name` if
set: SNI and the verified name are the same); `server_spki_sha256`
(optional, 64 hex digits each) pins the receiver's public key in addition;
`cert_chain` + `key_file` (both or neither) present a client certificate
for a receiver with `client_ca`. All paths absolute; the key file needs
no access for others and no group write; give it to agentd through a
`LoadCredential=anchor-tls.key:/etc/robodr/anchor/ugv-07.key` drop-in
(section 6.4 explains drop-ins). A TLS failure is an anchor failure (the
robot keeps recording, `anchor_failures` counts it); there is no fallback
to plain TCP. Each exchange is bounded as a whole (connect within
`timeout_ms`, then handshake, request and answer within three times it),
so an on-path host that trickles bytes produces counted failures, not a
stalled delivery; a delivery attempt that still has not finished after
its bound (a hanging name lookup: prefer an IP literal) is reported by the
next mark as a failure.

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

**Key rotation** (section 4.3): when a robot's black-box key changes,
replace its `.pub` on the receiver. With the in-place rotation
(`robodr-blackbox rotate`) the chain continues and the unit's state file
stays; only the alternative "new chain" procedure also needs
`/var/lib/robodr-anchor-receiver/units/<robot>.json` moved into the archive
with the old chain (with the service stopped). The in-place rotation with a
remote anchor is not covered by an end-to-end test yet. Replacing the receiver key: give
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
the window is the newest marks that have not reached the receiver. With
`allow_plaintext`, marks (hashes, sequence numbers) are visible on the
wire. Mutual TLS authenticates the robot's host. Bind each unit's
`current` queries to its TLS client certificate with
`units[].client_spki_sha256` (the SHA-256 of the certificate's
SubjectPublicKeyInfo, `openssl x509 -pubkey -noout | openssl pkey -pubin
-outform DER | sha256sum`): then only that certificate reads the unit's
head, and a certificate bound to one unit reads no other (refused `not
bound`). A unit without it can be queried by any certificate `client_ca`
accepts (the receiver lists such units at start). Marks keep their
signature model: any accepted certificate may send marks for any
configured robot (each still has to verify under that robot's key).
Revocation by CRL:
`blackbox.head_anchor.tls.crl_files` on the robot (a revoked receiver
certificate) and `tls.crl_files` of the receiver (a revoked unit
certificate), reloaded when the files change, fail closed (the same rules
as the control plane's `crl_files`, section 6.4); no OCSP.

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

**Upgrade order: the executor before agentd.** An agentd from the
red-team fixes on may send quarantine orders with `guid_only` / `excluded`
(and, since review R3-1, `addresses` / `excluded_addresses`);
an older executor drops them unanswered (the request reads `failed`,
"executor unreachable", nothing applied). Upgrade `robodr-executor`
first; with an older executor a verified quarantine's `containment` reads
`unknown`.

**What it does.** It executes two reversible actions, as nftables rules in
its own table `inet robodr`, plus an evidence mark:

| Action | Effect | Lifted |
|---|---|---|
| `isolate_network` | everything dropped except loopback, the management and uplink allow-lists, the control buses (configurable), the motion control path, the robot's DDS discovery (SPDP multicast, IGMP), the DHCP client, path MTU discovery and IPv6 neighbour / router discovery | on revert or TTL |
| `quarantine_node` | one DDS participant dropped (by RTPS GUID prefix; by the source addresses agentd saw it sending from, cut whole on the robot's DDS ports whatever the source port; and by its SPDP locators on those addresses; all outside the motion control path, which is never cut, even by traffic carrying the quarantined prefix). Cutting an address cuts every DDS participant on that host. The SOC's answer says how far it reaches: `containment` `full` (every observed address and announced locator cut whole), `partial` or `guid_only` (GUID-prefix drop only, evadable), with `state.quarantine` listing what was cut and left out (contract §6a) | on revert or TTL |
| `record_evidence` | a signed black-box mark | never: evidence is not reverted |

Without a `motion` section in `executor.json`, `restrict_motion` is
recorded as advisory and the executor never sends `safe_pause`,
`request_safe_state` or `rollback_config`. With one, they run through the
platform adapters (`gateway`: a restriction file read by the inline
gateway, section 6.6; `unitree_sport`, `nav2`, `ros2_control`, `px4`,
`rollback`), each refused until the site sets its `oem_validated: true`
(`crates/robodr-executor/README.md`, "Motion adapters").

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
   * `soc.key_scopes` (optional): per SOC key id, the `actions` it may
     approve and revert and its `max_ttl_s`, e.g.
     `{"soc:tier1": {"actions": ["quarantine_node"], "max_ttl_s": 900}}`;
     anything else signed with that key is refused `key_scope_denied`.
     `soc.require_key_scopes: true` makes a key without an entry approve
     nothing (recommended once every key has one). An entry whose key id
     matches no key in `soc.keys` (a typo, or a key you removed) makes
     every key without an entry approve and revert nothing until you fix
     or remove the entry; `robodr-executor --check-config` fails on it.
     A normal start does not refuse (reverts and TTL expiry must keep
     working) and only logs it, but containment those keys approved that
     is in force when the executor starts again (a restart or reboot
     re-arms it) is then **not re-armed and released**
     (`key_scope_denied`): isolation and quarantines end. Run
     `--check-config` after every change to `soc.key_scopes`, before the
     executor restarts, above all during an incident.
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
(`operator_disabled`) until you re-arm it, as root, with the executor
stopped (the socket agentd uses has no re-arm: agentd holds its key, and
a compromised agentd must not be able to lift your fence; `rearm` refuses
while an executor serves the socket):

```sh
systemctl stop robodr-executor
robodr-executor rearm --config /etc/robodr/executor.json --reason "<why>"
systemctl start robodr-executor
```

A `safe_pause` in force is **not** undone by the emergency disable (nor by
anything else but a two-person signed revert, below): the robot stays
paused; restore it on the platform once it is safe to move.

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
  journal unreadable or failing its seal, deleted its table and lost the
  history; agentd raises `robot.agent.executor_journal_reset` (High).
  Find the cause and acknowledge it with `rearm`: until then every order
  is refused (`journal_reset`; the flag `journal_reset_ms` stays in
  `robodr-executor status`).
* `robodr-executor status --config /etc/robodr/executor.json`: the journal
  of active actions, their deadlines, history and events (it needs the
  link key to check the journal's seal).
* `journalctl -u robodr-executor`.

A failed revert is retried every 500 ms until it verifies. agentd raises
`robot.agent.executor_revert_failed` (High, added in findings contract 2.4) once
per request until a revert of it succeeds, naming the action, request,
TTL and error: the rules may still be in force. Treat it, and
`revert_failures > 0`, as urgent.

**Sealed journal (upgrade, one time).** The executor's `journal.json` and
`soc_nonces.json` are sealed (HMAC) under a key derived from its link key
(`key_file`). A journal of an earlier release is unsealed: after
upgrading, before the executor first starts (or stop it), run once

```sh
systemctl stop robodr-executor
sudo -u robodr-exec robodr-executor seal-journal --config /etc/robodr/executor.json
systemctl start robodr-executor
```

(as the unit's user, so the rewritten file stays its own; it needs to read
`key_file`, which the unit gets as a systemd credential: pass the same key
file path in `--config`'s `key_file`, or run it with `systemd-run
--property=LoadCredential=...` like the unit) which keeps the actions in
force. Without it the executor does not trust
the old journal at start: table deleted (every action lifted), a
`journal_reset`, orders refused until `rearm`. The unsealed SOC replay
store just fences once. A replaced link key has the same effect as an
edit (the seal names another key). `seal-journal` is refused once the
executor has written its journal sealed (`state_dir/sealed`): an unsealed
file appearing later is a plant, not an upgrade. The actions it adopts are
held after it (re-validated and re-armed only with a fresh safety state).

**Older copies, deleted journals (anchor).** The seal alone does not tell
an older sealed copy from the current one; agentd does. Every journal has
a random epoch; agentd records the executor's journal head (epoch, next
event) in its black box (`robodr.executor_journal_head`) and sends it back
with every event poll. A journal behind it, or of another epoch, is reset
by the executor (`journal_reset`, orders refused until `rearm`), and agentd
raises `robot.agent.executor_journal_reset`. Within a boot, an active
action whose rules are no longer in the table at start is held (re-
validated, re-armed only with a fresh safety state), never re-installed
blindly.

**First start (`first-start` marker).** A missing sealed journal is not a
first start: unless `state_dir/first-start` exists, the executor treats it
as deleted (table deleted, SOC replay store fenced, `journal_reset`, orders
refused until `rearm`). The packages create the marker on first install
(`packaging/deb/postinst`, `packaging/rpm/post`) when no journal exists;
the first start consumes it. For a manual install, or after deliberately
emptying the state directory, create it as the unit's user before the
first start:

```sh
sudo -u robodr-exec install -m 0600 /dev/null /var/lib/robodr/executor/first-start
```

**`revert-all` and `stop-cleanup`** undo motion actions through their
adapters too; one whose undo fails stays `reverting` (retried, a
`revert_failed`) rather than being reported reverted. `stop-cleanup` reads
the sealed journal with the link key (the unit's credential); without it
the table is still deleted but the journal is not marked.

**Motion adapters (Sprint 8).** Off unless `executor.json` has a `motion`
section (example `config/executor.motion.example.json`; contract §6a,
"Motion adapters"; design and gates:
[`crates/robodr-executor/README.md`](../crates/robodr-executor/README.md#motion-adapters-sprint-8)).
To enable:

1. Choose the adapters per action: `restrict_motion` (`gateway`,
   `unitree_sport`), `safe_pause` / `request_safe_state` (`nav2`,
   `ros2_control`, `px4`), `rollback_config` (`rollback`, the site's
   program). The response policy's `safe_pause` / `safe_state` behaviour
   must be one the adapter carries out (Nav2: `controlled_stop`;
   ros2_control: `protective_stop_category2`; PX4: `hold`, and
   `return_to_launch` for the safe state).
2. Test each adapter on the robot with the OEM, then set its
   `oem_validated: true`. Until then every motion order is refused
   `adapter_not_validated`, nothing is sent.
3. Allow the network: install the `40-motion.conf.example` drop-in
   (`AF_INET`, `IPAddressAllow=` the ROS 2 / PX4 peers, the gateway's
   restriction directory) and restart the executor. Give the ROS 2
   adapters a fixed `ros2.participant_prefix` and profile it at
   commissioning (otherwise agentd reports the executor's participant as
   unknown). Keep each action within 4 s (the configuration is refused
   otherwise): agentd waits `executor.timeout_ms` (default 5 s).
4. Gateway adapter: set `restriction_path` / `status_path` in both the
   executor's `motion.gateway` and the gateway's configuration
   (`restriction_path`, `status_path`); create the restriction directory
   owned by `robodr-exec`, group `robodr`, mode `0750`.
5. SOC side: `safe_pause`, `request_safe_state` and `rollback_config` need
   `approved_by` with two people in the signed request (and in a revert of
   a `safe_pause`): names `[A-Za-z0-9._%+@-]{1,100}`, compared
   case-insensitively. The executor trusts the SOC key for who approved:
   enforce the two-person rule in the SOC's workflow too.
6. Set `ros2.peer_participant_prefix` to the robot participant's GUID
   prefix (from the commissioning capture) so only its replies count. With
   both `unitree_sport` and `gateway` for `restrict_motion`, list
   `unitree_sport` first (enforced).

7. On a robot that balances (humanoid, quadruped, unspecified), set
   `motion.envelope` (`max_linear_speed`, `max_joint_speed`: the profile
   envelope's) if the SOC sends absolute caps: a cap is accepted only when
   it is at least the policy's `min_motion_factor` of it, and refused
   (`fall_hazard`) without an envelope. The planner's `limit_motion` is a
   factor; a planner order with an absolute cap is refused
   (`invalid_order`). The gateway applies the same floor on its own (0.05
   of each channel's limit; a restriction file below it is ignored and
   reported as `restriction_error`).
8. `rollback.program` must be a regular file owned by root and not
   writable by group or others, in a directory with the same properties
   (otherwise the rollback fails and nothing runs). It runs without the
   executor's ambient `CAP_NET_ADMIN`.

What to expect: `restrict_motion` answers `verified` and is lifted at its
TTL or by revert. On a humanoid (or unspecified body), and on every robot
with `require_approval_for_all_containment`, a `restrict_motion` needs
a human's approval: the planner's is refused (`needs_approval`).
`safe_pause` answers `verified` and is **never lifted automatically**
(ADR-0006): when it reaches `motion.safe_pause_ttl_s` the executor reports
it (event `expired`, detail `HIGH: ...`) and leaves the robot paused; a
restart, an emergency disable, a failed apply or re-arm leave it paused
too. It is lifted only by the SOC's signed revert with two approvers, and
only when agentd's safety state at that moment is known, fresh, not
engaged and one the adapter allows (otherwise the revert is refused and
the pause stays). While paused, the executor re-asserts the pause every
`motion.safe_pause_latch_s` (default 2 s): Nav2 goals sent meanwhile are
cancelled and a PX4 mode change is set back to hold (a pilot's manual
mode is left to the pilot); each is a High finding
`robot.agent.executor_pause_overridden` (find out who moved the robot).
Every override is cancelled or set back to hold on every run, but per
pause and 5-minute window only the first 3 distinct kinds are reported at
once; repeats of a kind (a pilot staying in a manual mode, a script
re-sending a goal) and kinds beyond those 3 (someone alternating modes)
are counted and reported in one summary with their count, so a pause
writes at most 4 such findings per 5 minutes.
Lifting a pause **releases** it and never resumes a
mission (Nav2 goals are not restored, PX4 stays in hold);
`request_safe_state` and `rollback_config` answer `applied` and are not
reversible. A pause or safe state is refused while `moving_fast` unless
the adapter lists it in `allowed_states`. Watch the executor's events: an
adapter undo that fails (`revert_failed`) is retried every tick (a pause's
failed lift is not retried: it stays in force until the next signed
revert); check the platform by hand.

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
| `late` > 0 | packets read more than `max_queue_delay_ns` after arrival: the box is overloaded or not running the unit's real-time priority (reported as `robot.gateway.overload`, at most once per `overload_interval_ms`) |
| `overload.shed_total` > 0 | packets the kernel queued for the gateway but never delivered (gaps in the NFQUEUE packet ids): the gateway reads too slowly; dropped, or forwarded unchecked with `on_gateway_down: bypass` (also in `robot.gateway.overload`) |
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
* `enforced_writer_table_full` findings (`discovery.enforced_refused`
  rising): the enforced writer table (`rtps.max_enforced_writers`) is full
  of writers that were all seen within `rtps.enforced_idle_evict_s`.
  Stale GUIDs from controller restarts age out on their own; a table held
  by fresh entries means many enforced writers or forged SEDP
  announcements on the controller segment (investigate the sender). New
  writers are probed meanwhile (a fragmented or key-only sample of theirs
  is removed). To reset the table: stop the gateway (the kernel applies
  `on_gateway_down`), delete `rtps.state_file`, start the gateway, then
  restart the controller-side ROS 2 graph so its SEDP crosses the bridge
  again.
* Large IP datagrams from the controller side disappear: defragmentation
  did not run (another ruleset flushed the `raw` table); re-run the rules
  unit.

**ROS 2 joint trajectories, findings feed, restriction (Sprint 8).**

* Trajectory channels (`ros2_joint_trajectory`,
  `ros2_follow_joint_trajectory_goal`, example
  `config/firewall-gw.ros2-arm.example.json`): list every joint with its
  bounds in `trajectory`; the firewall channel is `kind joints` with that
  count. Make the controller send each trajectory in one RTPS DATA (raise
  the DDS message / fragment size, or bound `max_points`): a fragmented
  one is suppressed (`robot.gateway.fragmented_command`). Start with
  `mode: observe` and check `status.json` `gateway.trajectory_refused` /
  `trajectory_time_scaled` against the controller's real trajectories.
* Findings to agentd: set agentd's `gateway_feed` (`socket_path`,
  `allowed_uids` = the gateway's uid, `socket_mode: "0660"` with the
  gateway's user in agentd's group) and the gateway's `findings_socket` to
  the same path. `status.json` `findings_feed` shows `connected`, `sent`,
  `pending`, `dropped`, `last_error`; agentd counts
  `daemon.gateway_findings`; past 4 lines (8 Critical) per rule, channel
  and minute agentd folds the rest into one aggregate per minute, kept in
  the black box line by line up to 1024 folded lines (and 1024 Critical
  ones) a minute (`daemon.gateway_folded`, `daemon.gateway_unrecorded`,
  `daemon.gateway_aggregates`; agentd README, "In-path gateway feed").
  An idle gateway writes a heartbeat line
  every 5 s (`daemon.gateway_heartbeats`), so a quiet gateway is not
  reported as a silent input; a gateway that stops writing still is
  (`robot.agent.input_silent` after `daemon.silence_ms`). Upgrade agentd
  before the gateway: an older agentd counts the heartbeat as a
  malformed line.
* `restrict_motion`: with `restriction_path`, `status.json` `restriction`
  is the restriction in force (`null`: none) and `restriction_error` why a
  file was ignored. Removing the file lifts it at the next housekeeping
  tick; it also lapses at its own expiry. The file must be a regular
  file, not group- or world-writable, owned by root or the directory's
  owner (a symlink or FIFO is refused without blocking). While it is in
  force the gateway refuses the sport `SpeedLevel`. A trajectory the
  controller accepted before the restriction keeps its speeds: pause it.
* Trajectories: a non-zero `header.stamp` is zeroed (status
  `trajectory_stamp_zeroed`); the segments between points are checked as
  the controller's default spline interpolation executes them.

## 7. Upgrade and rollback

**Upgrade** (available). Verify the new release (section 2), then run
`sudo sh /usr/lib/robodr/install-bundle.sh install --pubkey … --tarball …`
(the trusted copy the installed release brought; section 3). `dpkg` keeps local edits to
`/etc/robodr/pulsar.toml` (a conffile) and asks before replacing an edited
one. Services that were running are restarted on the new binaries, except
the gateway and the executor, which restart only through the safety-state
gate (below). `/etc/robodr` (profile, keys, configs) and `/var/lib/robodr`
(evidence) are never touched.

**Package upgrades and the safety state.** Restarting
`robodr-firewall-gw` drops the motion commands queued in it (with
`fail_closed` the bridge refuses motion while it is down, section 6.6), and
restarting `robodr-executor` drops its pending actions. A package upgrade
therefore never restarts these two unguarded:

- the package's maintainer scripts (deb `postinst`, rpm `post`) restart
  the other running services but leave the gateway and the executor on the
  previous binaries and record them in `/var/lib/robodr/pending-restart`
  (also when the package is installed with plain `dpkg`/`rpm` or by
  `robodr-deliverd`);
- `install-bundle.sh install` and `rollback` read the **live** safety state
  first (`robodr-deliverd safety-state`: agentd's status socket, checked
  with `SO_PEERCRED`, fresh, on this boot, from a live safety feed: the
  same rule `robodr-deliverd`'s own installs use). If the gateway or the
  executor runs and the state is not `idle` or `safe_state_active`
  (moving, human nearby, e-stop, `unknown`, or no live safety feed
  configured), the install is **refused before anything changes** (the
  gate is decided before the security floor is raised and before
  `dpkg`/`rpm` runs);
- when the state allows it, the two are restarted right after the package
  is installed (the state is read again first; if it closed meanwhile, the
  restart is deferred);
- `--defer-restart` installs now and leaves the two running the old
  binaries; `sudo sh /usr/lib/robodr/install-bundle.sh restart-pending`
  restarts them later, again only while the state allows it (exit 1 and
  nothing restarted otherwise), then runs the health check below (exit 1
  when unhealthy; no automatic rollback). A reboot also starts the new
  binaries. Until then the package database and the security floor show
  the new version while the two still run the previous binaries;
  `install-bundle.sh list` shows the units waiting (`pending restart`),
  `robodr-agentd`'s `status.json` shows them under
  `self_health.pending_restart`, and once the file is
  `daemon.self_health.restart_pending_grace_ms` old (default 15 min)
  agentd sends the SOC a Medium `robot.agent.restart_pending` naming them,
  again when the units change and then daily until they are restarted
  (also after a plain `dpkg`/`rpm` upgrade, which writes the same file;
  a file agentd cannot read is reported with its units unknown). agentd
  reads the file, not the processes: a gated unit restarted by hand
  (`systemctl restart`) while the file stays is still reported until
  `restart-pending` removes it;
- `--allow-gateway-restart` restarts them whatever the state says. It is
  a deliberate operator decision: motion through the gateway is
  interrupted. Use it only with the robot stopped by other means (e.g.
  an agentd without a live safety feed on a parked robot).

Exception: the upgrade from 0.1.0-alpha.1 moves the gateway's state to its
own user once and must stop the gateway for that; it cannot be deferred
(`--defer-restart` is refused, and a plain `dpkg -i` leaves the package
unconfigured with nothing stopped until `restart-pending` configures it
through the gate; for an `.rpm`, install the release again with
`install-bundle.sh` once the robot is idle). When the installed
`robodr-deliverd` has **no `safety-state` command** (0.1.0-alpha.1),
`install` reads the state with the `robodr-deliverd` of the package being
installed, run as root from a copy in the private staging directory. It
runs after the bundle's checksum check and, with `--pubkey`/`--tarball`,
its signature check, but before the security floor and the format gate;
with `ROBODR_ALLOW_UNSIGNED=1` (lab only) nothing was signature-checked, so
an unsigned package's binary runs as root at that point (installing it
would run its maintainer scripts as root anyway). If that copy cannot run
there (e.g. a `noexec` `TMPDIR`), or the installed `robodr-agentd` does not
serve the status socket and live safety feed this reader needs (not
verified against a real 0.1.0-alpha.1 agentd), the state reads `unknown`
and the gate stays closed: stop the gateway at a safe moment or pass
`--allow-gateway-restart`.

**Releases from before the gate.** The maintainer scripts of
0.1.0-alpha.1 restart the gateway and the executor unconditionally. A
`rollback` (or `install --allow-downgrade`) to such a release therefore
cannot be deferred: with the gateway or the executor running and the
state closed it is **refused**, `--defer-restart` included, unless
`--allow-gateway-restart`. With the state open, it is read once more
right before `dpkg`/`rpm` runs; if it closed meanwhile, nothing is
installed (exit 1). The automatic rollback after a failed health
check goes to such a release only while the state allows it at that
moment; otherwise the unhealthy release stays installed (exit 1) and you
roll back by hand once the robot is idle. `install-bundle.sh` recognises
these releases by their post-install script (no `gated_restart` block).

**Health check and automatic rollback.** After `install` and `rollback`,
every RoboDR unit that was active before must be active again (two checks
in a row, a second apart) and, if `robodr-agentd` was active, its
heartbeat must be fresh (`robodr-deliverd safety-state`, `agentd_fresh`),
within `--health-timeout SECS` (default 120). If not, `install`
reinstalls the release that was installed before (it must be kept under
`/var/lib/robodr/releases`, at or above the security floor and pass the
black-box format gate), checks health again and exits 1; the failed
release is not kept. `--no-auto-rollback` only reports (exit 1). With no
RoboDR unit running (before commissioning) there is nothing to check.

**Kept releases.** `install --keep N` (after a healthy install) or
`install-bundle.sh prune --keep N` keeps the N newest kept releases and
always the installed one; the others are deleted (`prune` is refused when
neither `dpkg` nor `rpm` reports the installed version). The formats file of a
pruned release is kept under `releases/formats-archive/`, so the
black-box format gate still treats what that release wrote as verified.
Keep at least 2 (the installed release and the one to roll back to).

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

Rollback reinstalls the kept `.deb` (or `.rpm`) after re-checking its hashes. The
version must be one `list` shows (a version string, never a path). Evidence
written by the newer version stays in place. Rollback goes through the same
safety-state gate and health check as an upgrade (`--defer-restart`,
`--allow-gateway-restart`, `--health-timeout`); a rollback to a release
from before the gate, such as 0.1.0~alpha.1-1 above, cannot be deferred
(section 7, "Releases from before the gate").

**Downgrades and the security floor.** `install` of a release older than
the installed one is refused as a downgrade (it may bring back fixed
vulnerabilities); `rollback` to a kept release is the normal way back, and
`install --allow-downgrade` makes a deliberate downgrade possible. Neither
goes below the unit's **security floor**
(`/var/lib/robodr/releases/security-floor`, shown by `list`): the highest
`min_version` ever seen in an installed bundle's `security-floor` file
(covered by the release signature) or in the SOC's signed ring information
(`robodr-enroll ring`, 8.6). The floor only rises and has no override:
releases below it are known to be vulnerable. A release below the floor it
would end at is refused before the safety state is read, so the refusal
names the floor, not the safety state.

**Black-box format gate** (install and rollback). Every package states the
black-box formats it writes and reads (`/usr/share/robodr/formats`, e.g.
`blackbox_read=RBF1:1`; a release without the file reads `RBF1:1`, the only
format so far). Before `dpkg` runs, `install-bundle.sh` reads the first
frame of every segment in `/var/lib/robodr/blackbox` and
`/var/lib/robodr/fleet/journal` (or the `--blackbox-dir` given) and
**refuses** a release that cannot read a segment in a recognised format
(`RBF1:<version>`), naming the segment and its format: an older agent could
neither verify nor extend that chain. The segments are writable by
`robodr-agentd`, so their first frame is only a claim: it blocks only when
it is **verified**, i.e. its format is one that a release installed on this
unit writes, by records only root writes (`blackbox_write=` of the
installed package's formats file and of every kept release under
`/var/lib/robodr/releases/`; `RBF1:1` always). A segment claiming a format
no release here ever wrote is reported as `UNKNOWN` (logged with the
segment, non-blocking): a compromised agent cannot block every update by
forging one. Check such a segment with `robodr-blackbox verify`. To roll back across a format change,
export the chain (section 8.2) and archive the directory as in a key
rotation (section 4.3, "Alternative, new chain") first, then roll back; or install a release
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
the security floor, unknown frames, an unverifiable segment that does not
block, a fleet-journal segment, a signed install from a tampered
extracted directory refused, a tarball swapped after its signature check,
a renamed signed tarball, a variant switch, a half-configured package, a
tampered kept release) in
`crates/robodr-fleet/tests/packaging.rs`; not yet on a robot.

**RPM hosts** (RHEL / Rocky / Alma 9, Fedora). The release ships
`robodr-<version>-<arch>-rpm-offline.tar.gz` next to the `.deb` bundle,
with the same `install-bundle.sh`: verify the tarball's minisign signature
on the entry station as in section 2, then `install-bundle.sh install
--pubkey ... --tarball ...` as in section 3. Everything above (private
extraction, checksums, downgrade refusal, security floor, format gate,
kept releases, `list`, `rollback`) is the same; the package is installed
with `rpm -U` (not `dnf`: an air-gapped host has no repository to resolve
from), versions compare in rpm's order, an RPM with an epoch is refused,
and a bundle of one format is refused where robodr was installed through
the other. Tested against the real `rpm` in a separate rpm root (stub
packages: install, upgrade, rollback, downgrade refusal, security floor, a
refused rollback across a format change, a tampered kept release, the
epoch refusal, a signed install of a `make-bundle.sh --rpm` tarball and a
tampered one refused) in `crates/robodr-fleet/tests/packaging.rs`; not yet
on an RPM host.

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

**Diode sites: `robodr-blackbox export-pending`.** It exports every
record after the black box's signed export cursor as `RBBXBND1` bundles
**while agentd records** (it reads the directory, takes its own
`export.lock`, never agentd's lock), then advances the cursor, signed with
the black-box key:

```sh
robodr-blackbox export-pending /var/lib/robodr/blackbox/agentd \
    --key /etc/robodr/keys/agentd-blackbox.key --device <robot-id> \
    --out-dir /var/lib/robodr/export/blackbox
# exported seq 0..=40411 (40412 records) to /var/lib/robodr/export/blackbox/rbbx-<robot>-<chain>-...rbbx
```

Each record's hash, signature and link are checked before it is
exported; each bundle is written durably before the cursor moves (a crash
in between re-exports the same records; the far side reports the replay).
It streams the segments one frame at a time (also past damage, which it
resynchronises over without reading the segment whole), so its memory is
the bundle buffer (never more than `--max-bytes`, 64 MiB, but briefly
about 1.5 times that while it grows) plus a few copies of one frame (at
most 16 MiB), whatever the segment size. After a key rotation (4.3) `--key` must be the new key and
the retired public keys go in `--previous-keys`: a run with the retired
key is refused (exit 2) before it writes anything, because the newest
record is not signed by it. `robodr-blackbox rotate` holds `export.lock`
(it fails while an export runs: retry) and re-signs the newest cursor on
disk under the new key.
Records lost before they were exported (a gap after the cursor) are named
on stderr and the run exits 1 after writing what is there; the far side
reports them too. On the far side, verify each bundle in order with
`robodr-blackbox verify BUNDLE --keyring <robot .pub> --device <robot-id>`
(or `Receiver::accept`, which also checks the link to the previous one, so
a gap, replay or substitution is detected).

agentd re-reads the cursor before cyclic retention drops a segment: with
`blackbox.retention.unexported_reserve_segments` (6.4) a segment this has
not exported is kept, within the reserve, and agentd raises
`robot.agent.evidence_retention_pressure` before evidence is lost.

Run it periodically with the example units
`packaging/systemd/blackbox-export/robodr-blackbox-export.{service,timer}`
(every 15 minutes, as root with only `CAP_DAC_OVERRIDE` and `CAP_CHOWN`,
the cursor handed to agentd's user, bundles `0640 root:robodr` in
`/var/lib/robodr/export/blackbox`; site settings in
`/etc/robodr/blackbox-export.env`, `ROBODR_UNIT_ID=<robot id>`). They are
not yet installed by the package: copy them to `/etc/systemd/system/` and
`systemctl enable --now robodr-blackbox-export.timer`. The diode or media
transfer picks the bundles up from the outbox; remove them there once the
far side has verified them.

**Copy of the chain directory (still available):** export a copy of the
chain directory and verify it on the far side.

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
# batches in /var/lib/robodr/export/diode. Runs as robodr-spool, group robodr (it renames
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
Invalid records go to `<spool>/rejected/` with a reason file (written
before the move, so a crash never leaves a record without one), kept by
default. A spool file that cannot be read (an I/O error such as `EACCES` or
`EIO`, three attempts) is moved there too with the error as its reason
(`quarantined_unreadable` in the JSON report) instead of failing every run:
fix the cause (permissions, disk) and move it back to `ready/` to re-drive.
 `--rejected-max-age-s`, `--rejected-max-count` and
`--rejected-max-bytes` (0 = no bound) delete the oldest ones beyond the
bounds after each run, each with its reason file (a rejected record is never
packed again, so only its forensic copy goes).
Without `--once` it loops every `--interval-ms` (default 5000).

`robodr-kafka-publish` re-validates every record, re-derives key, headers
and partition from the value (contract §2, §4), publishes to `--topic`
(default `robodr.findings`; findings name the topic agentd was configured
with, `findings.topic`, and records relabelled to `--topic` are counted),
upgrades unsigned contract 1.x records to 2.0 and dead-letters signed
ones (section 7), sends with `acks=all`, and
persists per-batch progress after each acknowledged chunk; invalid or
broker-rejected records go to a dead-letter file. A spool file that cannot
be read (I/O error, three attempts) is dead-lettered with the error and
moved to `<spool>/rejected/` (`quarantined_unreadable`; move it back to
`ready/` once fixed). **Clock:** every record is stamped with the
publishing host's clock (Kafka CreateTime); Kafka 4.0 refuses records more
than 1 h ahead of the broker (`log.message.timestamp.after.max.ms`) with
`INVALID_TIMESTAMP`. The publisher never dead-letters for that: the run
fails with "check the clock of the publishing host (NTP)", nothing is
committed, and it retries every `--interval-ms` until the clock is fixed.
Run NTP on the publishing host. The producer is
**idempotent** by default: it takes a producer id (InitProducerId) and
numbers every batch, a batch re-sent after a lost acknowledgement is dropped
by the broker, and the producer id, sequences and the batches of the chunk
in flight are saved in `progress.json` before each request, so a chunk
re-sent after a crash or restart is not duplicated (while the broker
remembers the producer id: `producer.id.expiration.ms`, default one day).
A broker that refuses it (`CLUSTER_AUTHORIZATION_FAILED` on InitProducerId:
before Kafka 3.0 the principal needs the `IDEMPOTENT_WRITE` cluster ACL,
3.0+ imply it from `WRITE` on a topic) stops the publisher with an error
naming the ACL: grant it, or run with `--no-idempotence` (at-least-once:
consumers drop duplicates on `event-uid`). Without `--once` it loops every
`--interval-ms` (default 2000).

**Retention of the state directory** (`robodr-kafka-publish` and
`robodr-uplink`, after each run). `done/` markers older than
`--done-max-age-s` (default 2592000 = 30 days; 0 = keep) or beyond
`--done-max-count` are deleted, but never while their batch is still in
the importer's `out/` (the marker is what stops it being published again):
prune `out/` and the markers follow. Where the tool is the **only
consumer** of `out/`, it can prune `out/` itself: `--out-max-age-s N` /
`--out-max-count N` / `--out-max-bytes N` delete the records and bundles of
the batches it has finished (never one without its `done/` marker); each
directory stays with its `MANIFEST.json` as a small tombstone, so a batch
re-emitted after an importer state reset cannot land under a finished
name. With a spool source,
`--rejected-max-age-s` / `--rejected-max-count` / `--rejected-max-bytes`
bound `<spool>/rejected/` (default: kept); `robodr-uplink
--reinject-max-age-s` / `--reinject-max-count` / `--reinject-max-bytes`
delete the `records.jsonl` of finished re-injection generations (the
ledger stays). All of these are off by default. Sizes: `state_usage` in
`uplink-status.json` and in the publisher's JSON report (entries and bytes
of `done/`, dead letters, `out/` or `rejected/`, re-injection), measured at
most once a minute.

Dead letters: **`robodr-kafka-publish` keeps `dead-letter.jsonl` as one
growing file and never deletes it by default**: its entries are the
findings Kafka refused or that failed validation, and for diode input they
are usually the only copy left. Watch its size (it grows only with refused
records) and archive it off the host as you would `rejected/`. Rotation is
opt-in there (`--dead-letter-max-bytes N`, e.g. 67108864, with
`--dead-letter-keep N`, default 4); `robodr-uplink` rotates by default at
64 MiB keeping 4. With rotation, optionally also bounded by
`--dead-letter-max-age-s`, a rotated file over the bounds is **deleted**
once none of its entries is still needed for deduplication (diode batch not
done, spool file still in `ready/`, re-injected generation not done) and is
otherwise held and reported (`pruned_dead_letters.held` in the JSON
report). Every deletion of a file holding entries is logged on stderr
(`WARNING: deleted rotated dead-letter file ... holding N dead-lettered
record(s)`) and counted (`pruned_dead_letters.removed_entries`). Copy dead
letters off the host before they age out if you need them for longer;
deleted dead letters can no longer be re-injected.

**TLS, mutual TLS, SASL/SCRAM.** TLS is required: `--tls-ca FILE` (PEM,
the only trust anchors) makes every broker connection TLS and verifies
each broker's certificate, bootstrap and advertised alike (chain,
validity, `serverAuth`, the broker's host as dialled, or
`--tls-server-name NAME` for all of them); `--tls-spki-sha256 HEX`
(repeatable) pins broker keys in addition; `--tls-cert FILE --tls-key
FILE` present a client certificate (`ssl.client.auth=required`
listeners). `--sasl-mechanism SCRAM-SHA-256|SCRAM-SHA-512
--sasl-username U --sasl-password-file FILE` authenticate after the
handshake (SASL_SSL listeners; SCRAM only, never `PLAIN`; over TLS only;
a wrong credential, or a broker that cannot prove it knows it, fails the
call at once). A broker session lifetime (`connections.max.reauth.ms`) is
honoured by reconnecting before it ends. Key and password files: no
access for others, no group write, owner root or the service user; hand
them to the unit with the drop-in
example `robodr-kafka-publish.service.d/60-tls-credentials.conf.example`
and set `ROBODR_KAFKA_TLS_ARGS` in `/etc/robodr/kafka-publish.env`. Plain
TCP needs an explicit `--allow-plaintext` (an isolated SOC network or a
local TLS proxy only); without TLS and without it, the publisher exits 2
at start. Upgrading from a release without TLS: add one or the other, or
the unit stops (exit 2 is not restarted).
`robodr-spool-export.service` and `robodr-kafka-publish.service` run the
loop (no timer needed: both binaries retry on their own; exit 2, a usage
error, is not restarted); the transfer of `/var/lib/robodr/export/diode`
to the diode stays the site's procedure.

Before the first deployment, and after a Kafka upgrade, run the real-broker
test against the SOC's Kafka version (needs docker and the source tree):

```sh
scripts/kafka-it.sh                                   # apache/kafka:3.9.1
KAFKA_IT_IMAGE=apache/kafka:4.1.0 scripts/kafka-it.sh  # any apache/kafka tag
KAFKA_HOME=/opt/kafka_2.13-3.9.1 scripts/kafka-tls-it.sh  # no docker: TLS, mTLS, SCRAM
```

`kafka-tls-it.sh` starts a native broker (a Kafka distribution and Java,
no docker) whose certificate is the test PKI of `fixtures/tls/`, with SSL,
SSL + required client certificate and SASL_SSL SCRAM-SHA-256/512
(`connections.max.reauth.ms` 8 s) listeners, and runs the whole
real-broker suite plus the TLS tests (verified 2026-10-30 with 3.9.1).

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

Troubleshooting the publisher: an error naming a **TLS record** means a
TLS listener was dialled in plain TCP (`--allow-plaintext`): give
`--tls-ca` instead. **SASL** after ApiVersions: the listener wants SASL
(`--sasl-*`). `TLS handshake: invalid peer certificate` names the reason
(`UnknownIssuer`: wrong `--tls-ca`; `NotValidForName`: the advertised host
is not in the broker certificate's SAN, fix `advertised.listeners` or use
`--tls-server-name`; `Expired`; a pin mismatch). `SASL_AUTHENTICATION_FAILED`:
wrong user or password, or the mechanism is not enabled for that user. `UNKNOWN_TOPIC_OR_PARTITION`: the topic does not exist
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
service first, run as its user `robodr-uplink` (group `robodr`)
(`sudo -u robodr-uplink -g robodr robodr-uplink ...`), start it again.

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
sudo -u robodr-uplink -g robodr robodr-uplink reinject --state-dir . --spool /var/lib/robodr/spool/agentd \
    $(ls dead-letter.jsonl* | sed 's/^/--dead-letter /') --dry-run     # check the counts
sudo -u robodr-uplink -g robodr robodr-uplink reinject --state-dir . --spool /var/lib/robodr/spool/agentd \
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
files (`--dead-letter-max-bytes`, `--dead-letter-keep`; older rotated files
are deleted once nothing in them is needed for deduplication, each such
deletion logged with its entry count, see "Retention of the state
directory" above); a line torn by a
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
| dead letters with reason `unreadable (I/O error after 3 attempts: ...)`, `quarantined_unreadable` in the status file | a spool file could not be read (permissions, disk error); it was moved to `<spool>/rejected/`: fix the cause, move it back to `ready/` |

### 8.6 Fleet lifecycle: enrollment, key rotation, SOC profiles (`robodr-enroll`)

**available**, robot side and AutoSecOps side: the AutoSecOps side of the
fleet API (`/robot-edr/v2/fleet/*`, contract
`docs/contracts/robodr.fleet-api.md`, shared vectors
`docs/contracts/fixtures/fleet/`) is built on AutoSecOps' unreleased
`claude/robodr-ingest` branch, and fleet enrollment (SOC token,
`robodr-enroll`, three keys registered, signed answer) ran end to end
against it on loopback (`tools/e2e/RESULTS.md`).
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

`robodr-setup preflight` re-checks the host (BTF, bpffs, nf_tables,
systemd, glibc, clock, disk, key directory). For RoboDR support, `sudo
robodr-support-bundle` writes a redacted diagnostics archive (versions,
unit state and journal, status files, the nftables ruleset, configuration
from `/etc/robodr`; never keys, credentials, evidence or findings; mode
0600, to `/var/tmp`).

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
| Medium `robot.agent.control_plane_saturated` | the control plane's TCP slots were full: connections refused (`connections_rejected`) or handshakes cut (`connections_evicted`) | sustained: a handshake flood or slowloris (check the source addresses at the firewall; `soc_sources` keeps the SOC's slot); otherwise more SOC clients than `max_connections` |
| Low `robot.agent.control_plane_request_fenced` | requests signed before the replay fence set at start (the replay store was created, damaged or the clock went back) | expected right after such a start; the SOC signs again |
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
| `install-bundle: REFUSED: … would restart robodr-firewall-gw.service …` | the gateway or executor runs and the live safety state is not idle / safe_state_active | section 7 "Package upgrades and the safety state": wait, `--defer-restart` then `restart-pending`, or `--allow-gateway-restart` |
| `install-bundle: HEALTH CHECK FAILED` / `AUTOMATIC ROLLBACK` | a unit did not come back, or agentd's heartbeat is stale, after the install | the previous release is back; read `journalctl -u <unit>` for the failed one (section 7) |
| `install-bundle: REFUSED: … built-in verifier … ROBODR_ALLOW_UNSIGNED is not accepted` | unsigned lab install on a unit that can check signatures | sign the build with a lab key and pass `--pubkey` (section 3) |
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
* **deb only (T53).** `deb` is for Debian / Ubuntu units. On a unit
  without a dpkg database (`<dpkg_root>/var/lib/dpkg/status`: an
  RPM-based host such as Rocky / RHEL 9) a `deb` RPK is refused before
  anything is unpacked (`robot.deliver.refused`, "kind deb needs a
  Debian / Ubuntu unit ... RoboDR delivers no RPM packages"). There is no
  `rpm` kind: neither the agent nor the depot delivers RPM packages. The
  other kinds (`files`, `config`, `robodr-rules`) work on RPM hosts; RoboDR
  itself is updated there with `install-bundle.sh` (section 7).
* **Delivering RoboDR's own package (self-upgrade, T52).** Every
  `dpkg --install` of the agent runs with `ROBODR_DELIVERD_INSTALL=1`,
  which dpkg hands to the maintainer scripts. RoboDR's `postinst` then
  try-restarts every running RoboDR unit except `robodr-deliverd.service`:
  restarting the agent from inside the dpkg run it waits for would stop
  the unit and kill dpkg and the `postinst` with it (a half-configured
  package). The agent finishes the pass on its old binary (health gate,
  commit or automatic rollback), then sees its own executable replaced
  and exits 3; the unit (`RestartForceExitStatus=3`) starts it again on
  the new binary within `RestartSec=`. Expect one
  `robodr-deliverd.service: Main process exited, status=3` line per
  self-upgrade; it is not a failure.
  The health gate of such an install also runs the **new** binary once,
  `robodr-deliverd self-check --config <file>` (60 s at most), and records
  it as the check `robodr-deliverd self-check`. Read only, it checks what
  the start needs: the configuration, the black-box and finding keys,
  that the journal's segments can be read, the state file and that it is
  this unit's and site's, that the high-water record would not lock the
  start (not usable, of another unit, missing next to a journal with
  records, or older than the journal's or the state's generation), the
  TPM settings of `seal.anti_rollback_nv` (not the counter itself) and
  that an existing trust anchor loads under the pinned roots. If it
  fails, the old agent rolls the package back like any failed gate
  (`robot.deliver.health_failed`). A RoboDR version without the
  `self-check` command therefore cannot be installed by the agent onto
  itself. The check runs only when the switch being judged replaced the
  agent's binary (device and inode before and after the switch), so
  another deb is never rolled back for it.
  If the rollback cannot restore the binary (the security floor blocks it:
  `robot.deliver.rollback_blocked_floor`, Critical), the old agent does
  not exit 3 into the failing binary: it logs that it stays and keeps
  running until it is stopped. A restart, or a reboot, then starts the
  failing binary; deliver a release that passes before that.
  Not covered: a new binary that passes `self-check` but fails
  later in `run` is not rolled back automatically; systemd restarts it
  (`Restart=on-failure`) until its start limit (5 in 300 s) and the unit
  is then failed; an operator restores the previous release (section 7)
  and reports the version. The same holds when the agent is killed
  between the switch and the end of the gate (power loss, or the
  `TimeoutStopSec=` kill below): the next start runs the new binary,
  which resumes the gate without a self-check of itself (it has started)
  and, if it cannot start, is not rolled back. When the agent cannot know
  its own executable (`/proc/self/exe` does not resolve), deb installs
  commit without the self-check and the journal says so at the start
  (`robodr.deliver.self_check_unavailable`, also on stderr).
  The unit also sets `KillMode=mixed`, so `systemctl stop` signals the
  agent only and a dpkg run in progress finishes with its pass, as long
  as that takes less than `TimeoutStopSec=5min`. A longer one
  (`install.dpkg_timeout_s` allows up to 7200 s) is killed with the
  agent at the timeout and recovered from the intent at the next start
  (a half-done dpkg run is rolled back); raise `TimeoutStopSec=` in a drop-in where dpkg runs take
  longer. Tested with the real dpkg and a chrooted `postinst`
  (`tests/kinds.rs`, also the self-check rollback and the floor-blocked
  case with a stand-in package), what `self-check` refuses
  (`tests/binary.rs`), the postinst's restart loop and the exit-3 path of `run`
  (`tests/binary.rs`); the full upgrade on a systemd-booted VM is the VM
  job of T10 (not yet in CI).
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

### 11.6 Upgrading from a release where the exporters and the gateway ran as `robodr`

Earlier releases ran `robodr-spool-export`, `robodr-kafka-publish`,
`robodr-uplink` and `robodr-firewall-gw` as one shared user, `robodr`.
Any of them could therefore read the others' credential copies under
`/run/credentials/<unit>/` (on `robodr-focal`, 0400 files owned by
`robodr`), e.g. the diode signing key or the uplink key, and rewrite the
others' state. Each now runs as a user of its own, with `Group=robodr`
for agentd's spool and `/etc/robodr`:

| unit | user |
|------|------|
| `robodr-spool-export` | `robodr-spool` |
| `robodr-kafka-publish` | `robodr-kafka` |
| `robodr-uplink` | `robodr-uplink` |
| `robodr-firewall-gw` | `robodr-gw` |

and sees only its own credentials directory (`TemporaryFileSystem=` over
`/run/credentials`, its own directory bound back read-only).

* The package (deb `postinst`, RPM `%post`) creates the users (sysusers)
  and moves the state those releases wrote as `robodr` once:
  `/var/lib/robodr/export/{diode,spool-export}` to `robodr-spool`,
  `export/kafka-publish` to `robodr-kafka`, `export/uplink` to
  `robodr-uplink`, `/var/lib/robodr/firewall-gw` to `robodr-gw`. It stops
  the four units for that and starts what it stopped again. The
  migration follows no symlink (it removes symlinks, FIFOs and devices
  from those trees), replaces hardlinked files by copies, removes
  group/other write and setuid/setgid bits, and is repeated until it has
  completed (marker `/var/lib/robodr/.exporter-users-migrated`).
* `robodr` keeps owning the shared group and runs nothing.
* Drop-ins you wrote yourself: a `User=robodr` in a drop-in of one of
  these units undoes the separation; remove it. On `robodr-focal`, a
  drop-in that still passes `robodr` to `robodr-load-credential` (e.g. a
  copy of the old `60-tls-credentials.conf.example`) is mapped to the
  unit's own user with a warning in the journal; update it to
  `robodr-kafka` (or the unit's user above).
* Manual runs of the tools on a unit's state directory use its user, e.g.
  `sudo -u robodr-uplink -g robodr robodr-uplink reinject ...` (section 8.5).
* A host that installs with `adduser` instead of `systemd-sysusers` gets
  the four users from the postinst too.

## 12. Sealed delivery: captured-unit protection (`robodr-seal`, Sprint 13c)

Sealed RPKs keep delivered software, models and mission configuration
unreadable on a captured unit (`docs/SECURE-DELIVERY.md` §7, decisions
§7.9; `man robodr-seal(8)`). The plaintext exists only inside the unit's
**runtime volume**, a LUKS2 volume whose key, like every content key, is
usable only through the unit's TPM under a **signed PCR policy**, a
**policy floor** and an **erase epoch**. Units without a TPM use the
Clevis/Tang fallback (weaker; §12.5). Verified against a software TPM
(swtpm) and a real Tang server in tests only: not yet on a hardware TPM,
a robot or with device-mapper.

### 12.1 Provision the unit's TPM (once, as root)

1. Set the **owner authorization** and the **lockout authorization** to
   secrets that are **not stored on the unit** (kept by the site security
   officer). Required: `provision` refuses a TPM where either is empty,
   and `policy commit` refuses then too, because with an empty owner
   authorization anyone with root could undefine and redefine the policy
   floor and revive every revoked policy:
   `tpm2_changeauth -c o file:-` and `tpm2_changeauth -c l file:-` (each
   reads the new value on stdin; on a TPM that already has one, add
   `-p file:<old>`). `robodr-seal status` shows `owner_auth_set`,
   `lockout_auth_set` and a warning when either is missing.
2. `robodr-seal provision --owner-auth-file /root/owner.auth` (required;
   a regular file only root can read, not a symlink; delete it
   afterwards): defines the erase-epoch
   counter (`0x01500040`), the policy-floor bit field (`0x01500041`) and
   the persistent SRK (`0x81000001`); idempotent; an index that exists
   with other attributes is an error, never redefined. Other handles:
   `--epoch-nv`, `--floor-nv`, `--srk` (then the same in every command and
   in the agent's configuration).
3. TPM session files (they hold session keys) go to `/run/robodr-seal`
   (`--work-dir`, `seal.tpm.work_dir`), which must be on tmpfs: every
   TPM command refuses a work directory on a disk. Directories a killed
   command left behind are removed by the next one.

### 12.2 Keys of the programme office and the site

| Key | Command | Kept |
|---|---|---|
| Policy authority (P-256) | `robodr-seal keygen policy --out authority.key` | offline with the delivery roots; signs PCR policies |
| Depot wrapping key (X25519), one per site depot | `robodr-seal keygen depot --out depot.key` | the site depot (`keys.wrap`; a file today, TPM / HSM planned); `depot.key.pub` goes to the release station and into the trust file's `depot_wrap_keys` (14a) |
| Lease key (P-256), one per site depot (14b) | `robodr-seal keygen lease --out lease.key` | the site depot (`keys.lease`); `lease.key.pub` is given to `enroll --lease-key` on every unit of a site that uses leases (§13.5) |
| Entry-station key (Ed25519, 14a) | `robodr-blackbox keygen` format, listed in the trust file's `entry_keys` | the entry station only; signs entry reports (§13.2) |

### 12.3 Enrol, sign the policy, create the runtime volume

1. On the unit: `robodr-seal enroll --seal-dir /var/lib/robodr-seal
   --unit ugv-07 --platform ugv-x1 --policy-authority authority.key.pub`
   creates the UWK **inside the TPM** and prints the enrolment record
   (public). With a site depot, enrol through it instead (§13.3): it
   verifies the TPM's EK certificate and that the UWK is in that TPM. At
   a site that uses leases, add `--lease-key lease.key.pub` (§13.5).
2. The policy authority signs the platform's reference boot measurements
   (from the golden image, e.g. `tpm2_pcrread sha256:0,2,4,7` on a
   reference unit booted with it):
   `robodr-seal policy sign --key authority.key --platform ugv-x1
   --version 1 --pcr 0=<hex> --pcr 7=<hex> ... --out policy-v1.json`.
3. On the unit: `robodr-seal policy install --seal-dir ... --policy
   policy-v1.json`, then **`robodr-seal policy commit --seal-dir ...`**:
   it first unseals a probe key under the installed policy and only then
   revokes every older version in the TPM. The floor has 64 versions
   (0..=63). Version 63 can never be revoked, so `policy sign --version
   63` needs `--last-version`; the boot-chain update after it needs a new
   enrolment: `erase`, undefine and redefine the floor with the owner
   authorization (`tpm2_nvundefine 0x01500041 -C o -P file:-`, then
   `provision`), enrol again (a new seal directory), re-deliver.
4. Runtime volume: `robodr-seal volume format --seal-dir ... --device
   /dev/<partition>` (a random key, stored only wrapped to the UWK), then
   at every boot, before `robodr-deliverd` starts:
   `robodr-seal volume open --seal-dir ... --device /dev/<partition>
   --name robodr-sealed` and mount `/dev/mapper/robodr-sealed` on the
   runtime root (e.g. `/run/robodr-sealed`, `nodev,nosuid`). If the boot
   does not match the signed policy, the volume does not open: the unit
   still runs everything that is not sealed, RoboDR detection included.
   Configure delivered services as §7.4 says (no core dumps,
   `ProtectSystem=strict`, private `/tmp`, swap encrypted with an
   ephemeral key).
5. The agent's configuration (`/etc/robodr/deliverd.json`):

   ```json
   "seal": {
     "seal_dir": "/var/lib/robodr-seal",
     "runtime_root": "/run/robodr-sealed",
     "device": "/dev/disk/by-partlabel/robodr-sealed",
     "mapper_name": "robodr-sealed",
     "stop_units": ["robot-planner.service"],
     "tpm": {"tcti": "device:/dev/tpmrm0"}
   }
   ```

   `volume_check` defaults to `dm_crypt` (the runtime root must be a
   mounted dm-crypt mapping, otherwise sealed items and models wait);
   `unchecked` exists for tests and labs only, never in production.
   `device` (a stable path to the LUKS2 partition), `mapper_name` and
   `stop_units` (the services that run delivered software from the
   volume) are what erase acts on (§12.6); `device` is required on a unit
   without a TPM. `tpm.work_dir` defaults to `/run/robodr-seal`.
6. The package's `robodr-deliverd.service` reaches the TPM through
   `DeviceAllow=/dev/tpmrm0 rw` under `DevicePolicy=closed` (no
   `PrivateDevices=`, which would hide it); remove a `40-seal.conf`
   drop-in made for an earlier build. `robodr-seal` is in the package
   (`/usr/sbin`).

**Authorised OS / firmware updates** change the PCRs: ship the new
signed policy (next version) with the update, install it before the
reboot, and run `policy commit` after the first boot that unseals with
it. Do not commit before that boot: the old policy is what still works.

### 12.4 Release and depot

* Release station: `robodr-release build rpk --spec SPEC.json --payload
  DIR --out-dir DIR --seal-to depot.key.pub` (one `--seal-to` per site
  depot). Only `files`, `model` and `config` can be sealed; every file
  but the SBOM is encrypted; the content key is written only wrapped to
  the depots. Sign and bundle as usual.
* Depot: `robodr-depot` re-wraps every sealed item for each enrolled
  unit of a stage when it makes the stage's deployment (§13.4); each
  unit's pack carries only its own wraps. Without a depot (labs),
  `robodr-seal rewrap --depot-key depot.key --rpk <imported RPK dir>
  --unit-record ugv-07.json` prints one `wrapped_keys` entry; put all
  entries, sorted by unit and digest, into the deployment before it is
  signed. A media pack moved to another unit gives it nothing: the wraps
  are bound to the unit's own TPM key.

### 12.5 Units without a TPM (fallback)

1. `robodr-seal volume format-tang --device /dev/<partition> --tang-url
   http://<depot>:<port> --tang-thp <thumbprint>` (thumbprint:
   `tang-show-keys <port>` on the Tang server): the volume opens only
   while the unit reaches the site's Tang server; no key is stored on
   the unit. Open at boot with `robodr-seal volume open-tang` (or the
   distribution's `clevis-luks` unlockers) and mount as above.
2. With the volume open: `robodr-seal enroll-fallback --seal-dir ...
   --unit ... --platform ... --key /run/robodr-sealed/.robodr-seal/uwk.key`
   (the UWK lives inside the volume; a key directory that is not on a
   dm-crypt mapping is refused). Configure `seal` without `tpm` and with
   `device` (required: erasing such a unit is wiping that device's
   keyslots).
3. Limits (§7.8): a disk image taken before an erase can be unlocked by
   anyone who reaches the Tang server; on site, the fallback protects
   nothing against someone who can use the site network. Tang keeps no
   per-unit state, so a single unit cannot be "retired" at the server.
   After a unit is lost with its disk intact, rotate the server's keys:
   `/usr/libexec/tangd-rotate-keys -d <keydir>` on the Tang server,
   `clevis luks regen -d DEV -s SLOT` on every remaining unit (while the old keys still answer), then
   delete the old (now hidden, `.`-prefixed) keys from the key database.

### 12.6 Crypto-erase

`robodr-deliverd erase --config /etc/robodr/deliverd.json --trigger
operator [--device /dev/<partition>]` (stop the service first; `--key`
as for `reanchor`; `--device` overrides `seal.device`):

1. **The erase itself.** With a TPM: the erase epoch is incremented, so
   every key sealed to the unit is dead at once; the UWK blobs and the
   volume wrap are deleted, and with a device its keyslots are wiped.
   Without a TPM: the device's LUKS2 keyslots are wiped (required; with
   no device nothing is erased and the command fails), and the UWK file
   is destroyed if the volume is open (if not, the report says it was
   not destroyed: it stays inside the volume, which can no longer be
   opened).
2. **The open runtime volume.** `seal.stop_units` are stopped, the
   runtime root is unmounted and `seal.mapper_name` closed; when it is
   busy it is suspended instead (the kernel wipes the volume key and
   blocks I/O). Plaintext already in memory survives until power-off:
   power the unit off when that matters. Without `mapper_name` the volume
   stays open and the finding says so.

The JSON report lists `destroyed` and `incomplete`; `robot.seal.erased`
(Critical; with `--trigger tamper` also `robot.seal.tamper`) says the
same in words. It is final: recovery is re-enrolment (a new seal
directory) and re-delivery. Automatic erase from the platform's inputs
is §12.8. `robodr-seal erase` (`--device`,
`--mapper`, `--mount`, `--stop-unit`) does the same without the agent's
journal and findings.

### 12.7 Findings and what to do

| Finding | Meaning | Action |
|---|---|---|
| `robot.seal.unseal_failed` (`policy_refused`) | the TPM refused: boot measurements differ from every non-revoked signed policy, or the authority's signature | expected after an update without its policy; otherwise treat the unit as tampered (`Deviation`) |
| `robot.seal.unseal_failed` (`erased`) | the unit's keys were erased | re-enrol and re-deliver, if the unit is trusted again |
| `robot.deliver.refused` (`unauthentic_key`) | a wrap in the deployment is not this unit's (another unit's, tampered) | check the depot's re-wrapping |
| `robot.seal.erased`, `robot.seal.tamper` | crypto-erase ran (trigger, what was destroyed and the volume's state in the detail) | investigate the trigger; if the volume is "STILL OPEN", power the unit off |
| `robot.seal.lease_expired` | a sealed item waits for a site lease (none yet, or the TPM's clock or reboot budget passed it) | bring the unit back into LAN reach of the depot, or give it a media pack with a fresh lease (§13.5) |
| `robot.seal.erase_deferred` | an erase trigger fired while the robot moved (or its state was unknown): the keys are already destroyed; stopping services and closing the runtime volume runs as soon as it is idle, safe-state or e-stopped (High once it waited past `erase.max_lockdown_deferral_s`) | treat as tamper in progress; bring the robot to a safe state |

### 12.8 Executed crypto-erase from platform inputs (Sprint 14b)

The platform's enclosure-tamper input, repeated attestation failure and
repeated failed operator authentication can erase the unit without an
operator: `robodr-deliverd` plans the erase with the responder and runs it
only when agentd's live safety state is `idle`, `safe_state_active` or
`estop_active`; in any other state (also `unknown`) it waits, also across
restarts, and runs as soon as the state allows.

1. In `/etc/robodr/deliverd.json`:

   ```json
   "erase": {
     "trigger_socket": "/run/robodr-deliverd/erase.sock",
     "feeder_uids": [],
     "feeder_gids": [<gid of the platform's tamper-input service>]
   }
   ```

   and the drop-in
   `/usr/share/doc/robodr/examples/robodr-deliverd.service.d/50-depot-lan.conf.example`
   (its `RuntimeDirectory=` creates the socket's directory).
2. The platform's input service (root, or a feeder uid / gid) sends one
   line per event: `robodr-deliverd tamper --socket
   /run/robodr-deliverd/erase.sock --trigger tamper` (or
   `attestation_failed`, `auth_failures`). Anything from another peer, or
   a trigger a person must approve (`operator`, `signed_command`), is
   journaled and ignored.
3. Test it on a bench unit with a disposable enrolment: the erase is
   final.

### 12.9 Anti-rollback floors in a TPM NV counter (Sprint 14b)

Without it, the floors live in the state file, the signed high-water
record and the black box: restoring all three from an old disk image
rolls them back unnoticed. With an NV counter the record names the
counter value it was written at, and an older record is detected:

1. `robodr-seal counter define --index 0x01500042 --owner-auth-file
   /root/owner.auth` (owner authorization, as §12.1).
2. `"seal": {..., "anti_rollback_nv": "0x01500042"}` in deliverd.json, then
   restart the agent: the existing record is migrated into the counter
   once (`robodr.deliver.anchor_migrated` in the journal).
3. From then on a restored disk image, a deleted black box and state, or
   an undefined and redefined counter lock the agent (no import, no
   install; `robot.deliver.refused`). Recovery is `robodr-deliverd
   reanchor` as §11.3, after finding out why.

The counter detects a restored **older** record; it does not stop root,
who holds the black-box key, from writing a new record with lower floors.

---

## 13. Site depot (`robodr-depot`, Sprints 14a and 14b)

The single-box control plane inside the air gap
(`docs/SECURE-DELIVERY.md` §4-§6, §8, §10; `man robodr-depot(8)`): a
bundle enters only with a passing entry report, units enrol with their
TPM and two operators, rollouts go ring by ring and halt on a failing
report, and each unit fetches only its own pack (mutual TLS) or gets a
per-unit media pack. Verified with software TPMs on loopback only.

### 13.1 Set up the depot box

1. Install the `robodr` package; the depot runs as `robodr-depot`
   (`/var/lib/robodr/depot`, `/etc/robodr-depot`, created by the package).
   Run every command below as that user:
   `runuser -u robodr-depot -- robodr-depot --config /etc/robodr-depot/depot.json ...`.
2. Keys in `/etc/robodr-depot/keys` (0600, owned by `robodr-depot`):
   `depot-signing.key` (`robodr-blackbox keygen`, the trust file's depot
   key), `depot-wrap.key` (`robodr-seal keygen depot`), `unit-ca.key`
   (`robodr-seal keygen policy`: the unit CA), and with leases `lease.key`
   (`robodr-seal keygen lease`).
3. The trust file (root-signed, as §11.1) lists the depot's signing key,
   its wrapping key (`depot_wrap_keys`), the entry stations' keys
   (`entry_keys`), the SHA-256 of the TPM vendors' EK CA certificates the
   site accepts (`ek_ca_certs`), and the units' rings. Put those CA
   certificates (PEM or DER) into `enrolment.ek_cas` and their
   intermediates into `enrolment.ek_intermediates`; a certificate whose
   digest the trust file does not list is ignored.
4. `/etc/robodr-depot/depot.json` from
   `/usr/share/doc/robodr/examples/depot.example.json`, then
   `robodr-depot ... init --trust trust.json`. With `anchor` (recommended),
   define the counter first: `robodr-seal counter define --index
   0x01500050 --owner-auth-file ... --tcti device:/dev/tpmrm0` on the depot
   box, and install the drop-in `50-tpm-anchor.conf.example`
   (group `tss`).
5. `systemctl enable --now robodr-depot` (the LAN server). Restrict who
   can connect with `IPAddressAllow=` in a drop-in.

### 13.2 Bring a bundle in

1. On the entry station: `robodr-depot entry scan --bundle DIR --trust
   trust.json --trust-anchor anchor.json --root ... --site SITE --station
   entry-1 --key entry.key --history DIR [--vulndb vulndb.json]
   --out report.json` (the report and `report.json.sig`). A verdict
   `fail` lists what was found at or above `--fail-on`.
2. On the depot: `robodr-depot ... import --bundle DIR --report
   report.json`. Refused (`robot.depot.import_refused`): no or another
   bundle's report, a failing or expired report, a chain gap, a revoked or
   below-floor RPK, a sealed RPK for a depot key the trust file does not
   list.

### 13.3 Enrol a unit

1. Depot: `enrol begin --unit ugv-07` prints a nonce.
2. Unit (root): `robodr-seal enrol-request --seal-dir /var/lib/robodr-seal
   --nonce <hex> --out req.json` (after `provision` and `enroll`, §12).
3. Depot: `enrol verify --request req.json --out challenge.json`.
4. Unit: `robodr-seal enrol-activate --seal-dir ... --challenge
   challenge.json --out resp.json`.
5. Depot: `enrol finish --response resp.json`, then two different
   operators: `enrol approve --unit ugv-07 --key op1.key` and again with
   `op2.key`. `enrol export --unit ugv-07 --out DIR` writes `client.pem`
   and `depot-ca.pem` for the unit.
6. Unit: copy both to `/etc/robodr/depot/`, add to deliverd.json

   ```json
   "depot": {
     "address": "192.0.2.10:8443",
     "server_name": "depot.site-a.internal",
     "ca_file": "/etc/robodr/depot/depot-ca.pem",
     "cert_file": "/etc/robodr/depot/client.pem"
   }
   ```

   and install the drop-in `50-depot-lan.conf.example` with the depot's
   address in `IPAddressAllow=`. The TLS key is the identity key inside
   the TPM; it never leaves it.

Any refusal is `robot.depot.enrolment_refused` with the reason (EK chain,
credential activation, certification, quote, nonce, lease key); after a
wrong challenge answer start again with `enrol begin`.

### 13.4 Roll out

1. `rollout create --id r1 --rpk <digest> [--rpk ...] --stages
   lab,canary,ring-1 [--soak-s 600] [--max-failures 0]` makes the first
   stage's deployment.
2. `deploy approve --seq N --key op1.key` (and a second operator for a
   production ring) activates it; units pull it within a minute and
   report.
3. `inventory` shows each unit's reports; `rollout advance --id r1` makes
   the next stage only when every unit of this one reported its items
   installed and healthy for the soak time.
4. A failing report beyond `--max-failures` halts the rollout
   (`robot.depot.rollout_halted`): nothing more of it is served. Fix the
   release, then `rollout abort` (two operators) and start a new rollout,
   or `rollout resume` (two operators) to deploy the stage again.
5. Units without LAN: `pack --unit ugv-07 --out DIR` writes that unit's
   media pack; carry the unit's report back with `robodr-deliverd report
   --out FILE` and `report import --report FILE`.

### 13.5 Leases (Sprint 14b)

With `keys.lease` and `lease` (`lifetime_s` of TPM powered-on time,
`reboots`) in depot.json, every unit must be enrolled with
`robodr-seal enroll --lease-key lease.key.pub`; the depot refuses others.
Each accepted report renews the unit's lease from its TPM-attested time;
it travels in the answer (LAN) or the media pack. A unit carried off site
keeps running what it has unsealed, but after the lease's time or reboot
budget its TPM refuses every unseal (`robot.seal.lease_expired`). Choose
`reboots` and `lifetime_s` for the longest legitimate time out of LAN
reach.

### 13.6 Recovery

* `robot.depot.locked` (with `anchor`): the database is older than the
  NV counter (a restored backup or disk image) or the counter was
  redefined. Find out why first; then `reanchor --min-deployment-seq N
  --key op1.key --key op2.key`, with `N` the highest deployment sequence
  any unit has seen (`inventory`, units' `status`), so no sequence number
  is reused.
* `unit revoke --unit U --key op1.key --key op2.key`: a lost or retired
  unit is served nothing more and gets no new wraps.
* The depot's keys and database are the site's crown jewels: back up the
  keys offline; a database backup restored later locks the depot (above).

---

## 14. Backup and restore

RoboDR keeps three kinds of state, and they are backed up differently:

1. **Configuration and keys** (`/etc/robodr*`): back up, restore.
2. **Evidence** (black boxes, exports, spools, archive): back up by
   *exporting* (signed bundles, section 8), never by restoring an old copy
   into the live directory.
3. **Monotonic and device-bound state** (anti-rollback floors, replay
   stores, security floor, TPM-bound material): **never restore**. These
   files exist to notice that the unit was put back into an earlier state.
   Restoring an older copy *is* that attack: it lowers a floor that was
   raised for a reason (a revoked profile, a vulnerable release, a revoked
   key, a replayed SOC request), or makes the unit accept something it has
   already seen. Where a TPM NV counter or the remote head anchor backs the
   state, a restored copy is detected and locks the component (sections
   6.4, 11.3, 12.9, 13.6); without them it is silently accepted. Re-create
   such state on the rebuilt unit instead (its own procedure, below).

The paths come from the package (`/usr/lib/tmpfiles.d/robodr.conf`, the
units' `StateDirectory=` / `ReadWritePaths=`) and the example
configurations; if you moved a path in a configuration file, use yours.

### 14.1 What to back up, and what not to restore

| Path | What | Back up | Restore |
|---|---|---|---|
| `/etc/robodr/` (`agentd.json`, `executor.json`, `deliverd.json`, `pulsar.toml`, `firewall-gw*.json`, `control-plane/`, `soc/`, `depot/`, drop-ins under `/etc/systemd/system/robodr-*.service.d/`) | configuration, trust files, certificates | yes | yes (step 2) |
| `/etc/robodr/keys/` (0700 root) | private keys: black-box, finding, diode, uplink, control-plane TLS, profile trust | yes, **encrypted, offline**, two-person custody | yes, or rotate instead (4.3) if the backup medium may have been exposed |
| `/etc/robodr-depot/` (depot box) | depot configuration and keys | yes, encrypted, offline | yes |
| `/etc/robodr-anchor-receiver/` (base station) | receiver configuration, key, robots' public keys | yes | yes |
| `/var/lib/robodr/blackbox/{agentd,pulsard,deliverd}/`, `/var/lib/robodr/fleet/journal/` | black-box chains (evidence) | **export** a copy (8.2, interim procedure; verify it with `robodr-blackbox verify`) and keep it | **no**: archive (section 7) and let the unit start a new chain; an older chain is a rollback of the evidence head (the remote anchor reports it as `lower`) |
| `/var/lib/robodr/archive/`, `/var/lib/robodr/export/` (outboxes), `/var/lib/robodr/control-plane/agentd/exports/` | exported and archived evidence | yes | to an archive host, not back onto the unit |
| `/var/lib/robodr/spool/agentd/`, `/var/lib/robodr/spool/pulsard/` | findings not yet exported | yes (to keep findings that never left) | only `ready/` records, and only on a unit that never exported them (the exporters are at-least-once: duplicates are possible) |
| `/var/lib/robodr/export/{spool-export,kafka-publish,uplink}/` | exporter state (sequence numbers, pack state) | yes | **no** if the SOC / high side has seen later batches: a lower sequence is refused or treated as a gap; start the exporter fresh and accept the gap on the high side (8.3) |
| `/var/lib/robodr/control-plane/agentd/` (request journal, replay store) | anti-replay of SOC requests | no | **no**: an older replay store forgets requests seen since; with none, agentd fences every request signed before its start (troubleshooting, `stale_timestamp`) |
| `/var/lib/robodr/executor/` (`journal.json`) | executor actions in force and their deadlines | no | **no**: it describes network state of the moment it was written; a rebuilt unit has no such rules |
| `/var/lib/robodr/firewall-gw/` (`writers.json` = `rtps.state_file`, `events.jsonl`, `status.json`) | gateway's learned writers, events | `events.jsonl` as evidence | **no** for `writers.json`: let the gateway learn the writers again (restart the ROS 2 graph behind it, 6.6); an old file can vouch for writers that no longer exist |
| `/var/lib/robodr/profile-state/`, `/var/lib/robodr/profile-state-pulsard/` | profile anti-rollback floors | no | **no** (section 5.1): re-install the current signed profile |
| `/var/lib/robodr/releases/` (`security-floor`, kept packages) | release floor, rollback copies | no | **no**: a restored `security-floor` lowers the floor; the next bundle install re-creates both |
| `/var/lib/robodr/fleet/` (except `journal/`) | enrollment, rotation journals, ring information | no | **no**: re-enrol (8.6); ring information is re-fetched from the SOC |
| `/var/lib/robodr/deliverd/` | delivery anti-rollback floors, store, trust anchor | no | **no**: re-enrol with the depot and `reanchor` (11.3); a restored record locks the agent with an NV counter (12.9) |
| `/var/lib/robodr-seal/`, `/var/lib/robodr/anchor/` | TPM-sealed blobs, PCR policy, lease, NV sidecar | no | **no**: bound to that unit's TPM (useless on another one) and to NV counters an older copy no longer matches; re-provision (12.1-12.3) |
| `/var/lib/robodr/depot/` (depot box) | depot database, store, unit CA state | yes (for forensics) | **no** with `anchor`: an older database locks the depot (13.6); restore only after deciding to `reanchor` above every sequence a unit has seen |
| `/var/lib/robodr-anchor-receiver/` (base station) | robots' last anchored heads, alerts | yes, often | yes, then re-ingest every robot's anchors since the backup: an older copy only weakens detection until then |
| `/opt/robodr-delivered`, `/etc/robodr-delivered*` | content installed by robodr-deliverd | no | no: delivered again by the depot |

### 14.2 Backup

`robodr-blackbox backup` does this by the table above:

```sh
# Configuration, drop-ins, receiver state, and a copy of the evidence and
# spools (keys excluded): verify it, keep it.
robodr-blackbox backup create --out /root/robodr-$(hostname)-$(date +%F).rbkup
robodr-blackbox backup verify /root/robodr-$(hostname)-$(date +%F).rbkup
# The keys, encrypted, to offline media (two-person custody):
robodr-blackbox backup create --include-keys --out - | age -r <custodian key> \
    > robodr-keys-$(hostname)-$(date +%F).rbkup.age
```

`create` archives only the "back up: yes" rows (never symlinks or special
files), each file with its SHA-256; the "no" rows are not archived. The
SHA-256 sums and the archive's end record are **not keyed**: `verify`
catches corruption and truncation, not tampering. Anyone who can write an
archive can build a consistent one with other contents, and a restore
writes trust files (profile trust, control-plane and SOC trust, CA
certificates) from it. The archive's authenticity rests entirely on how it
was kept: encrypted (`age`) and on offline media under the site's custody.
Restore only from such a copy. The
same with `tar` and `age` by hand:

```sh
# On the unit, as root. Evidence first: a copy of every chain (8.2,
# interim procedure), to be verified on the far side.
ts=$(date -u +%Y%m%dT%H%M%SZ)
tar -C /var/lib/robodr -czf /var/lib/robodr/export/blackbox-$ts.tar.gz blackbox fleet/journal
# Configuration (keys separately, encrypted, to offline media):
tar -C / -czf robodr-config-$(hostname)-$(date +%F).tar.gz \
    --exclude=etc/robodr/keys etc/robodr etc/systemd/system/robodr-*.service.d
tar -C / -cf - etc/robodr/keys | age -r <custodian key> > robodr-keys-$(hostname)-$(date +%F).tar.age
# Findings not yet exported, and the exported evidence:
tar -C / -czf robodr-evidence-$(hostname)-$(date +%F).tar.gz \
    var/lib/robodr/spool var/lib/robodr/export var/lib/robodr/archive
```

Any encryption tool the site approves can replace `age`. A full disk
image of a unit is **not** a backup to restore: it carries every file of
section 14.1 that must not come back.

### 14.3 Restore (rebuilt or replaced unit)

The order matters: configuration before the services start, monotonic
state re-created by its own procedure, never copied.

1. Install the package from the current bundle (section 3), at or above
   the security floor the fleet runs; this creates the directories and
   `/var/lib/robodr/releases/security-floor` from the bundle.
2. Restore `/etc/robodr` (and the drop-ins) from the configuration
   backup, then the keys; `systemd-tmpfiles --create` resets the owners
   and modes of the packaged directories. With an archive of 14.2:
   `robodr-blackbox backup restore FILE [--evidence-to /srv/archive/<unit>]
   [--spool-ready] [--dry-run]` (decrypt the keys archive first:
   `age -d ... > keys.rbkup`). It verifies the whole archive before writing
   anything, then reads it again to write it, checking every entry and
   every file's bytes against the verified pass before the file replaces
   anything (an archive that changed in between stops the restore with
   exit 1; what was written before is what was verified). It restores
   configuration and the anchor receiver's state (never set-id, sticky,
   group- or world-writable; key material — `/etc/robodr/keys`,
   `/etc/robodr-depot/keys`, any `*.key` file — 0600 in 0700 directories),
   extracts evidence only under `--evidence-to` (a directory that, after
   resolving `..`, relative paths and symlinks, is the root or lies in
   `/etc`, `/var/lib/robodr`, `/var/lib/robodr-anchor-receiver`,
   `/var/lib/robodr-seal` or `/opt/robodr-delivered` is refused, exit 2;
   it is created before the verification pass and must still resolve to
   itself before each evidence file is written, else the restore stops,
   exit 2; the check is not atomic with each write, so put it where only
   the operator can write),
   restores the spools' `ready/` findings only with `--spool-ready` and only
   into an empty `ready/`, and **never** restores a "no" row of 14.1, even
   from an archive that holds one: each refused path is printed with its
   reason. It refuses paths that escape the root and targets behind a
   symlink. Restored files are owned by the user who runs it (root):
   `systemd-tmpfiles --create` resets the packaged directories, not the
   files in them, so give the depot's keys back to its user
   (`chown -R robodr-depot:robodr-depot /etc/robodr-depot/keys`) and check
   any file a service reads as its own user. A replaced unit with a new TPM
   keeps the old keys only if the site decides so; otherwise rotate (4.3).
3. Do **not** copy any "no" row of 14.1. Re-create instead: seal
   provisioning and enrolment (12.1-12.3) and the anchor sidecar (6.4),
   fleet enrollment (8.6), delivery anchor (11.3), depot enrolment (13.3).
4. Commission or re-install the current signed profile (section 5); the
   profile floor starts at it.
5. Start the services (section 6). The black boxes start new chains; the
   SOC and the anchor receiver see a new head (record the rebuild in the
   site log, so the gap is explained).
6. Hand restored `ready/` findings and the evidence archive to the export
   path (section 8); accept the exporter sequence gap on the high side.

Status: this procedure follows from the code's checks (anti-rollback,
replay, security floor, TPM and NV bindings) and the package layout; the
complete restore has not yet been run on a robot. `robodr-blackbox backup`
is tested against a tree with every row of 14.1, including archives
crafted to roll the floors back (`crates/robodr-blackbox/tests/backup_restore.rs`). The package parts
(steps 1 and the floor) are covered by `crates/robodr-fleet/tests/packaging.rs`.
