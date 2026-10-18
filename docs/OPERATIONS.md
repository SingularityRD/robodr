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
6. Verify the archived chain once more with the retired key
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
   creates `/var/lib/robodr/profile-state` (`robodr:robodr`, agentd's
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
and the key together, or the unit does not start). Copy the keys you need
from it once their files exist, and check every edit with
`robodr-agentd --config /etc/robodr/agentd.json --check-config`.

**Live safety state (`safety_feed`).** Plans are graded by the robot's
safety state. Without a feed, the static `context.safety_state` is used.
With one, agentd reads it **passively**: ROS 2 topics decoded from captured
user DATA (`std_msgs/Bool`, `UInt8`, `String` mapped to states;
`nav_msgs/Odometry` speed with hysteresis to idle / moving slow / moving
fast), and/or a `0600` unix socket of JSON lines from a safety-PLC gateway
(`{"state":"estop_active"}`; put it under `/run/robodr-agentd/`, the
gateway must run as `robodr`). A stale source reads `unknown`; disagreeing
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
`tpm_nv_counter`, below) or a remote receiver (not implemented).

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
  and `robodr-commission verify-profile --profile /etc/robodr/profile.json
  --trusted-keys /etc/robodr/profile-trust.json` with the **new**
  `robodr-commission` from the extracted `.deb`
  (`dpkg-deb -x robodr_*.deb /tmp/new`). This confirms the new version accepts
  the locked profile (a profile locked before metadata existed needs
  section 5.2 first).

Package rollback (below) and profile rollback (section 5.1) are separate:
rolling the package back does not touch the anti-rollback state.

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
| Black-box chain | `/var/lib/robodr/blackbox/<service>/` | hash-chained, signed (Ed25519; legacy HMAC), checkpointed |
| OCSF findings | `/var/lib/robodr/spool/<service>/` | validated by `robodr-ocsf`; carry evidence links into the black box; optionally signed per finding (6.4); diode batches signed by the unit's diode key (8.3) |
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

**available (not yet run against a real Kafka broker).** Two binaries carry
agentd's findings to the SOC (contract section 8.1):

```sh
# Robot side (low side): spool -> signed diode batches in the outbox.
# Runs as robodr (it renames ready/ -> acked/ in agentd's spool).
sudo -u robodr robodr-spool-export --spool /var/lib/robodr/spool/agentd \
    --outbox /var/lib/robodr/export/diode --state /var/lib/robodr/export/spool-export-state.json \
    --pack-state /var/lib/robodr/export/pack-state.json --unit ugv-07 \
    --key-file /etc/robodr/keys/diode-ugv-07.key [--interval-ms 5000] [--once]

# SOC side (high side), after robodr-diode-unpack has imported the batches:
robodr-kafka-publish --bootstrap kafka1:9092 --state-dir /var/lib/robodr-soc/publish \
    --diode-out /var/lib/robodr-soc/import/out [--once]
# A connected site publishes straight from a spool copy instead: --spool DIR
```

`robodr-spool-export` takes `ready/` records in order, re-validates them,
packs one diode batch per step with `robodr-diode-pack`'s format (Ed25519
key file, section 4.4; `--allow-hmac` only for legacy keys) and moves the
records to `acked/` only once the batch is durably in the outbox; an intent
journal makes every crash point recoverable without loss or re-packing.
Invalid records go to `<spool>/rejected/` with a reason file, never deleted.
Without `--once` it loops every `--interval-ms` (default 5000).

`robodr-kafka-publish` re-validates every record, re-derives key, headers
and partition from the value (contract §2, §4), sends with `acks=all`, and
persists per-batch progress after each acknowledged chunk; invalid or
broker-rejected records go to a dead-letter file. **No TLS / SASL** and
**idempotence off** (at-least-once: consumers drop duplicates on
`event-uid`): run it on an isolated SOC network or through a local TLS
proxy. Without `--once` it loops every `--interval-ms` (default 2000).
Neither binary ships a systemd unit; run them from the site's transfer
procedure or a timer.

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
| `lock: --operators is required` / `no valid operator signature` | sign-off list not signed, or signed by a key not in the operators list | section 5, step 3 |
| High `robot.agent.evidence_quarantined` | a closed black-box segment failed verification at open | section 6.4: keep `<blackbox>/quarantine/`, check the storage, treat as possible tampering |
| Critical `robot.agent.evidence_quarantined` / `robot.agent.evidence_truncated` | the black-box directory was edited (stray or cut segment files, records cut after the newest mark) | section 6.4: preserve the whole `<blackbox>` directory, treat as tampering |
| `finding_signing.key_file ... black-box key` / `must be an ed25519 key` | finding key reused or HMAC | section 6.4: generate a dedicated Ed25519 key |
| `correlation rules: ...` at start | site rule file invalid or duplicates a shipped id | fix the file, or `--check-config` to see every problem |
| every finding `[observe-only]` | profile unlocked, missing or invalid | section 5 |
| Critical `robot.ros2.profile_state_tampered` | anti-rollback state file deleted or rewritten (or agentd stopped mid operator rollback) | section 5.1: investigate; reinstall the recorded profile or roll back with `allow_rollback` |
| `revocation list ... rollback refused` / `now missing` | an older list, or none, replaced the accepted one | section 5.3: install the newest list |
| capture sees only `lo` | no default route on an air-gapped robot | list the DDS interfaces in `[module.robodr-sensor-ros2.capture] interfaces` |
