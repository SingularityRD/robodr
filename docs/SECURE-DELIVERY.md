# Secure delivery: air-gapped fleet distribution, updates and captured-unit protection

> **Status: design only. Nothing in this document is implemented.** It
> expands ROADMAP Phase 3 ("Air-gapped deployment") and splits the one-line
> Sprint 13 / Sprint 14 items in `docs/SPRINTS.md` with a buildable plan. Every
> component named here that does not already exist is marked `[ ]`, using the
> legend of ROADMAP §2. Where this design reuses existing code, the crate and
> file are named so the reuse can be checked.

RoboDR today can install **itself** on an air-gapped robot
(`packaging/make-bundle.sh`, `packaging/install-bundle.sh`: minisign-signed
tarball, `SHA256SUMS`, `dpkg -i`, kept releases, `rollback <version>`), and
can move evidence **out** of an air gap (`robodr-diode`). It cannot move other
software **in**, cannot roll an update across a fleet, and does nothing to stop
an adversary who holds a unit from reading the software on it.

This document designs three features that close those gaps:

| | Feature | One line |
|---|---|---|
| **A** | Air-gapped fleet distribution | Deliver any software (RoboDR, robot applications, ROS 2 packages, container images, AI models, configs) to every unit of a disconnected fleet, Zarf/UDS-style, without Kubernetes and without a network path to the outside. |
| **B** | Updates | A separate, staged update flow on top of A: rings, health gates, automatic rollback, anti-rollback floors, and installs gated by the robot's physical safety state. |
| **C** | Captured-unit software protection | An adversary who physically captures a unit cannot read the delivered software, models or mission configuration from it: encrypted at rest, keys sealed to the unit's TPM and measured boot, an optional site lease, and cryptographic erase. |

---

## 0. Scope, non-goals and the change to the threat table

**In scope.** Integrity and authenticity of everything delivered to a unit;
confidentiality of delivered payloads at rest on the unit; orderly,
reversible, auditable rollout across a fleet; all of it with no outbound
connectivity.

**Non-goals.**

- **Not a safety system.** Delivery never becomes a dependency of the motion
  stack, the e-stop or command authority (ROADMAP §1, `packaging/README.md`).
  A failed delivery leaves the unit running its previous software.
- **Not physical zeroization.** Erasing hardware, fuses or the platform's own
  key stores remains the platform's job. RoboDR erases the keys **it** owns
  (§7.6), which is enough to make the payloads it delivered unreadable.
- **Not protection of a running, unlocked unit against an attacker with
  physical memory access.** §7.8 states exactly what is and is not claimed.
- **Not an internet update service.** There is no vendor cloud. A site runs
  its own depot (§5) inside the air gap.

**Threat table change.** ROADMAP §0 previously answered *captured-unit
exploitation* with "Measured-boot attestation + sealed keys; tamper response
… (Zeroization/anti-tamper is the platform's job; RoboDR detects and refuses
trust.)". Feature C extends that answer: payloads delivered by RoboDR are
encrypted at rest under keys sealed to the unit's TPM and measured boot, and
RoboDR can cryptographically erase those keys. The ROADMAP row is updated to
point here.

---

## 1. Threat model

### 1.1 Adversaries

| ID | Adversary | Capability |
|---|---|---|
| T1 | **Supply chain** | Plants a trojaned package or dependency upstream of the release (cf. the SROS 2 keystore exfiltration case, ROADMAP §0). |
| T2 | **Compromised entry station or courier** | Swaps, edits, reorders, withholds or replays bundles between release and depot. Holds no release key. |
| T3 | **Site-network attacker** | On the site LAN between depot and units. Can drop, delay, replay and inject traffic. |
| T4 | **Compromised depot** | Root on the site depot. Holds the depot's assignment key, not the release keys. |
| T5 | **Captured unit, powered off** | Has the unit or only its storage. Unlimited time, a forensic lab, can image disks and read the TPM bus. |
| T6 | **Captured unit, powered on and locked** | Unit captured while running. No shell credentials. Can reboot it, attach peripherals, probe ports. |
| T7 | **Captured unit with physical memory access** | Cold boot, DMA, decapping, fault injection on a running unit. |
| T8 | **Rollback / freeze** | Any of T2–T4 presenting older (authentic, vulnerable) releases, or withholding new ones so a unit never learns a fix exists. |
| T9 | **Insider** | One person with legitimate access to one key. |

### 1.2 Assets

1. **Payload integrity**: a unit runs only what a release quorum signed and the
   site approved for that unit.
2. **Payload confidentiality**: application binaries, AI models, mission
   configuration and their keys cannot be extracted from a captured unit.
3. **Fleet state**: which unit runs what, provably, with evidence.
4. **Availability**: a bad release never bricks a fleet; a unit always has a
   known-good version to return to.

### 1.3 What is claimed

The claims table for feature C is in §7.8. For A and B:

| Adversary | Claim |
|---|---|
| T1 | Not prevented by signing (a signed trojan is still a trojan). Mitigated by the entry-station scan (§6.1), SBOM diff and two-person release (§3.4). Detected afterwards by RoboDR's own sensors. |
| T2, T3 | Cannot make a unit install anything not signed by the release quorum **and** assigned by the depot for that unit. Can withhold (detected as staleness, §6.5). |
| T4 | Can only assign, to its own units, artifacts the release quorum signed and the site's trust file allows; cannot forge or downgrade below the floor (§6.4). Can withhold or assign a valid-but-unwanted version: bounded by the site operator quorum on assignments (§5.3). |
| T8 | Downgrade below a signed floor is refused; the floor is held in a TPM NV counter where present (§6.4). Freeze is detected after the freshness window (§6.5), not prevented. |
| T9 | No single key can release (release quorum), assign to a production ring (operator quorum) or rotate trust (root quorum). |

---

## 2. Architecture

```
 CONNECTED SIDE (vendor / programme office)          AIR-GAPPED SITE
 ─────────────────────────────────────────           ─────────────────────────────────────────────

 build ─► robodr-release build ─► RPK artifacts
                │                      │
                │       offline signing station
                │       (release keys, quorum)
                ▼                      ▼
         release bundle  ──── vetted media / INBOUND diode ────►  entry station
         (bundle.json +                                          (verify, scan, SBOM diff)
          RPKs + parity)                                                 │
                                                                         ▼
                                                              robodr-depot   [ ]
                                                              ├ content store (CAS)
                                                              ├ fleet inventory
                                                              ├ deployments (rings)
                                                              ├ per-unit key wrapping
                                                              └ lease / Tang server (§7.5)
                                                                   │  site LAN (mTLS)  │  or per-unit media
                                                                   ▼                   ▼
                                                              robodr-deliverd on each unit   [ ]
                                                              ├ verify → stage → gate → install
                                                              ├ encrypted store, TPM-sealed keys
                                                              ├ health gate / auto-rollback
                                                              └ black box + findings
                                                                   │
                                                                   ▼
                                       ◄──── OUTBOUND diode (existing robodr-diode) ────  delivery evidence
```

Two diodes, never one bidirectional link: the existing `robodr-diode` carries
evidence **out**; an independent inbound transfer (diode or media) carries
releases **in**, with its own keys. A site that has neither works by media in
both directions.

### 2.1 New components

| Component | Kind | Role |
|---|---|---|
| `robodr-pkg` `[ ]` | pure library | RPK and bundle formats (§3): parse, validate, verify, hash. No I/O beyond reading bytes it is given. Fuzzed like `robodr-rtps`. |
| `robodr-seal` `[ ]` | library | Key wrapping, payload encryption, TPM sealing via `tpm2-tools` (same approach as `robodr-blackbox/src/tpm_anchor.rs`), software fallback (§7). |
| `robodr-release` `[ ]` | CLI, connected side | Build RPKs from `.deb` / OCI / files / models, encrypt, sign (quorum), assemble bundles, add Reed-Solomon parity. |
| `robodr-depot` `[ ]` | service, site | Single-box control plane: import bundles, inventory, deployments and rings, per-unit key wrapping, serve units, lease server. This is the air-gapped instance of the planned `robodr-fleet` (ROADMAP §2) and the "single-box control plane" of Sprint 14. |
| `robodr-deliverd` `[ ]` | service, unit | The on-unit agent: reconcile desired vs installed, verify, stage, gate on safety state, install, health-check, roll back, report. Runs separately from `robodr-agentd` so a delivery bug cannot stop detection. |

### 2.2 Reused, unchanged or extended

| Existing | Reuse |
|---|---|
| `robodr-blackbox` key files (`robodr-blackbox-key/v2`, Ed25519 via `ed25519-dalek`) | All signing keys in this design use this format and the `Signer`/`Verifier` traits, as `robodr-diode` and `robodr-commission` already do. |
| `robodr-commission` `trust` module (root-signed trust file, `robodr-profile-revocations/v2`, `min_profile_version` floor, anti-rollback state, operator quorum) | The delivery trust file (§3.4) follows the same model: roots sign it, revocations by public-key fingerprint and digest, monotonic floors, quorum attestations. Generalised, not copied. |
| `robodr-blackbox` `TpmNvCounterAnchor` | The same NV-counter technique holds the anti-rollback floor (§6.4) and the erase epoch (§7.6). |
| `robodr-diode` (`src/fec.rs`, `rs-gf256-0x11d/1`, manifest chaining) | Bundle parity (§3.3) reuses the Reed-Solomon code; inbound bundles chain like diode batches. Evidence from delivery leaves through the existing outbound diode unchanged. |
| `robodr-responder` `SafetyState` and agentd's live `safety_feed` | Installs and erasure are gated on the unit's physical state (§6.3, §7.6). |
| `packaging/install-bundle.sh` | Stays as the bootstrap installer for RoboDR itself on a unit that has no `robodr-deliverd` yet. Once deliverd is present, RoboDR upgrades are ordinary RPKs. |

---

## 3. Artifact and bundle formats

### 3.1 RPK: one deliverable (`robodr-pkg/1`)

An RPK is a directory (or an uncompressed tar of one) with a signed manifest
and content-addressed, chunked payload:

```
rpk_<name>_<version>_<arch>/
  MANIFEST.json      raw bytes are signed and hashed
  MANIFEST.sig       {format, signatures: [{key_id, algorithm, sig}]}   (quorum, §3.4)
  chunks/<sha256>    payload chunks, each AEAD-encrypted (§7.2) or plain (§3.2)
```

Manifest fields (unknown fields rejected, as in `robodr-diode`):

| Field | Meaning |
|---|---|
| `format` | `robodr-pkg/1` |
| `name`, `version` | package name; version as a strictly increasing integer `serial` plus a display string. Ordering uses `serial` only. |
| `kind` | one of `deb`, `oci-image`, `files`, `model`, `config`, `robodr-profile`, `robodr-rules`, `os-image` (§4.2). Closed set; no "run this script" kind. |
| `platform`, `arch`, `hw_compat[]` | where it may be installed; checked on the unit against its attested identity. |
| `requires[]`, `conflicts[]` | name + minimum serial. Resolution is done on the depot and re-checked on the unit. |
| `security_floor` | lowest serial of this package that may ever run again once this one is installed (§6.4). |
| `confidentiality` | `public` (signed only) or `sealed` (encrypted; §7). |
| `content[]` | logical files: path, mode, size, sha256 of plaintext, ordered chunk list. |
| `chunks[]` | sha256 of each stored chunk (ciphertext for sealed RPKs), size. |
| `sbom` | sha256 of the CycloneDX SBOM chunk, mandatory for `deb`, `oci-image`, `os-image`. |
| `install` | declarative install spec for the kind (§4.2), never shell. |
| `health` | post-install checks (§6.2). |
| `expires_at` | optional; a release may refuse to install after a date. |

Domain-separated messages, matching the existing crates:

- signed message: `"robodr-pkg/manifest/v1\0" || MANIFEST.json bytes`
- RPK digest: `SHA-256("robodr-pkg/digest/v1\0" || MANIFEST.json bytes)` — this
  is the identity used everywhere else (deployments, revocations, black box).

Chunking (fixed 4 MiB, last chunk short) gives deduplication across versions
in the depot and unit stores, resumable transfer and per-chunk verification
before anything is decrypted or unpacked.

### 3.2 Why not just reuse `.deb` or Zarf packages

- **`.deb` alone** has no multi-party signature, no encryption, no notion of a
  fleet assignment or a floor, and maintainer scripts run arbitrary shell as
  root. RPK kind `deb` *wraps* a `.deb`; deliverd installs it with
  `dpkg --unpack` into a staging root or `dpkg -i` with maintainer scripts
  allowed only when the release quorum set `install.allow_maintainer_scripts`
  (recorded in the black box).
- **Zarf** (`zarf-dev/zarf`, Apache-2.0) solves the same transport problem
  for Kubernetes clusters. Most robots do not run Kubernetes, Zarf packages
  are not encrypted per unit and have no robot safety gate. Interop is still
  useful: a future kind `zarf` could carry a Zarf package for units or
  depots that do run a cluster. Open question §11.
- **TUF / Uptane.** The trust split below (release keys vs depot assignment
  vs unit) follows Uptane's image-repository / director split, adapted to a
  site with no network and to quorum signing. Freshness (TUF's timestamp
  role) is replaced by expiring deployments plus staleness findings (§6.5),
  because an air-gapped unit cannot be kept online-fresh.

### 3.3 Bundle: one transfer (`robodr-bundle/1`)

A bundle is what crosses the air gap: a set of RPKs, a signed `bundle.json`
listing their digests, a monotonic `bundle_seq` and `prev_bundle_hash` (a
per-programme chain, so a dropped or replayed bundle is visible), and optional
Reed-Solomon parity over the files using `robodr-diode`'s
`rs-gf256-0x11d/1`. The entry station and the depot verify the chain; a gap
is reported, not silently skipped.

### 3.4 Trust: who may sign what

One delivery trust file per site, root-signed, versioned, anti-rollback
protected (the `robodr-commission` model, generalised):

| Role | Holds | Signs | Quorum (default) |
|---|---|---|---|
| **Delivery roots** | offline, programme office | the trust file, revocations, floors | 2 of 3 |
| **Release** | offline signing station | RPK manifests and bundles | 2 distinct release keys |
| **Depot** | the site depot (TPM-held where possible) | deployments for its units (§5.2), per-unit key wraps | 1 (machine key) |
| **Site operators** | people on site | approval of a deployment to a production ring | 2 for `prod` rings, 1 for `lab` |
| **Unit** | each unit's TPM (attestation key) | install reports, health results | 1 |

Revocation lists revoke release, depot and operator keys by public-key
fingerprint and RPKs by digest, exactly as `robodr-profile-revocations/v2`
does for profiles.

---

## 4. Feature A: air-gapped fleet distribution

### 4.1 Flow

1. **Release.** `robodr-release build` turns inputs into RPKs; sealed RPKs are
   encrypted with fresh content keys (§7.2). Two release keys sign each
   manifest and the bundle on the offline signing station.
2. **Cross the gap.** The bundle goes on vetted media or the inbound diode.
3. **Entry station.** Verifies signatures, chain, hashes and parity; runs the
   scan (§6.1); produces a signed entry report. Nothing reaches the depot
   without a passing report.
4. **Import.** `robodr-depot import` stores chunks content-addressed, records
   the RPKs, and refuses anything revoked or below a floor.
5. **Assign.** An operator creates a **deployment**: "these RPK digests on
   these units / this group, in this ring order". The depot signs it; a
   production ring also needs the site-operator quorum.
6. **Deliver.** Units pull their deployment and chunks from the depot over the
   site LAN (mTLS; the unit's client key is TPM-held), or, for units with no
   LAN, the depot writes a **per-unit media pack** that only that unit can
   decrypt (§7.3).
7. **Install and report.** `robodr-deliverd` reconciles, installs, health-checks
   and reports; the report is signed by the unit, written to its black box and
   exported as findings through the existing outbound diode.

### 4.2 What can be delivered (installers per `kind`)

| `kind` | Installer on the unit | Atomicity |
|---|---|---|
| `deb` | `dpkg` (maintainer scripts only if allowed, §3.2) | previous `.deb` kept in the store for rollback |
| `oci-image` | import into the unit's local containerd / podman store; or the depot's local registry when units pull | image digest switch; old image retained |
| `files` | write into a versioned directory under `/opt/robodr-delivered/<name>/<serial>/`, atomic `current` symlink swap | symlink swap is atomic |
| `model` | as `files`, into the sealed runtime volume (§7.4) only | symlink swap |
| `config` | as `files` under `/etc/robodr-delivered/` | symlink swap |
| `robodr-profile` | handed to the existing profile path; `robodr-commission verify-profile` rules still apply (its own signatures, floors and operator attestation) | existing |
| `robodr-rules` | Pulsar rules TOML, validated as `scripts/validate_rules.py` does | file swap + reload |
| `os-image` | **delegated** to an A/B updater (RAUC, SWUpdate or Mender; §11). RoboDR verifies, decrypts, gates and orchestrates; it never writes a bootloader itself | A/B slot switch with boot-count fallback |

### 4.3 Fleet model on the depot

- **Inventory**: unit id, platform, hardware, attested identity (TPM EK/AK
  certificates, §7.1), current attestation state (`Verified` / `Deviation` /
  `Unknown`, the trust states of Sprint 12 in `docs/SPRINTS.md`), installed RPK digests, last report time.
- **Groups and rings**: `lab` → `canary` (one unit) → `ring-1` (≈10 %) →
  `ring-2` (rest). Rings are per site and per platform.
- **Desired state** per unit is the union of deployments targeting it,
  resolved by the depot (`requires` / `conflicts`) and re-checked on the unit.
- **Least distribution**: a unit receives only RPKs its role needs. What is
  not on a unit cannot leak from it (§7).

---

## 5. Depot and deployments

### 5.1 Depot hardening

The depot is the highest-value machine inside the gap. It runs the same
RoboDR host sensors, keeps its signing and wrapping keys in its TPM or an HSM
(never in files on its disk in production), has no route out of the site,
and its own software is delivered and floored like any unit's.

### 5.2 Deployment document (`robodr-deployment/1`)

Signed by the depot key, plus operator attestations for production rings:
`deployment_id`, monotonic `deployment_seq` per site, `targets` (units or
groups), `ring`, `items[] = {rpk_digest, name, serial}`, `not_before`,
`expires_at` (freshness, §6.5), `rollout` (batch size, soak time, failure
threshold), `maintenance_window` (§6.3), and the per-unit wrapped content
keys for sealed items (§7.3).

### 5.3 Operator quorum

Assigning to `prod` rings needs two distinct site operators (the
`motion_quorum` idea from commissioning, applied to delivery). A compromised
depot (T4) can therefore push to `lab` and `canary` only.

---

## 6. Feature B: updates

An update is a deployment whose items supersede installed ones. Everything in
§4 applies; this section adds what makes it safe to change software that is
already running on a fleet.

### 6.1 Entry-station scan

Before import: signature quorum, chain and parity; SBOM present and diffed
against the previous serial (new dependencies and licence changes listed);
known-vulnerability match against an offline vulnerability database carried
in on the same media; the planned Robot Analyzer (ROADMAP §0) when it exists.
The signed entry report is required by `robodr-depot import`.

### 6.2 Staged rollout with health gates

For each ring in order: deliver to the ring's batch; on each unit,
install → **health check** → **soak**; continue only when the batch passes.

Health checks (declared in the manifest's `health`, plus fixed ones):

- the package's own declared checks (service active, a probe command run as
  an unprivileged user, a file present, a ROS 2 node visible on the bus);
- `robodr-agentd` health is `ok` and the profile still verifies;
- no new Critical finding on the unit during the soak window;
- attestation still `Verified` (a changed measurement that the release did
  not declare is a failure, not an update).

On failure the unit rolls back by itself (§6.4) and reports; the depot halts
the rollout when the ring's failure threshold is crossed. No human has to be
present for a halt; a human is needed to resume.

### 6.3 Safety-state gate

`robodr-deliverd` reads the same live safety state agentd uses
(`robodr-responder` `SafetyState`). Installs that restart or replace anything
on the robot run only when the state is `Idle` or `SafeStateActive`, inside
the deployment's maintenance window, and, for kinds marked
`install.requires_operator_present`, after a local operator confirmation.
`MovingSlow`, `MovingFast`, `CollaborativeHumanNearby`, `EStopActive` and
`Unknown` defer the install; downloading, verifying and staging continue. An
update never interrupts motion. Deferrals are findings, so a unit that never
reaches a safe window is visible.

### 6.4 Rollback and anti-rollback

Two different things, deliberately kept apart:

- **Rollback** (availability): the unit keeps the previous installed serial of
  each package in its store and returns to it automatically on a failed health
  gate, or on operator request.
- **Anti-rollback** (security): a release can raise a package's
  `security_floor`. Once a release with floor *F* is installed, no serial below
  *F* may be installed again, by rollback or by deployment. The floor is
  stored in a TPM NV counter per package family where a TPM exists (the
  `TpmNvCounterAnchor` technique: increment-only, survives disk restore), and
  otherwise in the state file and the black box, with the same honest limit as
  `robodr-commission`'s state file (root can delete it; the black box records
  that it happened).

Automatic rollback therefore only ever goes to the previous serial **at or
above** the floor. If none exists the unit stays on the failing version,
raises a Critical finding and waits for an operator. Today's
`install-bundle.sh rollback` has no floor; it remains for bootstrap and lab use
and is documented as such.

### 6.5 Freshness and freeze attacks

An air-gapped unit cannot ask "is there a newer release?". Instead, every
deployment carries `expires_at`. A unit whose newest valid deployment has
expired raises `robot.deliver.stale` (High after a configurable grace). That
makes withholding (T8) visible in the SOC, through the outbound diode, within
one freshness window. It does not make it impossible.

### 6.6 Evidence

Every step (deployment accepted, chunk verified, staged, deferred, installed,
health result, rollback, floor raised, refusal and why) is a signed black-box
record and an OCSF finding (§9). The SOC can answer "what exactly is running
on unit ugv-07, who approved it, and when" from evidence alone.

---

## 7. Feature C: captured-unit software protection

**Goal.** An adversary who captures a unit (T5, T6) cannot obtain the
plaintext of sealed RPKs (application software, models, mission
configuration) or the keys that decrypt them. Against T7 the goal is reduced
to "only what was in memory at that moment, and not the keys of other units
or future releases" (§7.8).

### 7.1 Key hierarchy

```
 Release content key  CK  (random, per sealed RPK)         ── encrypts chunks (§7.2)
        │ wrapped by
        ▼
 Unit wrapping key    UWK (per unit, TPM-resident, non-exportable)
        │ policy: PCR boot chain (signed policy)
        │         AND erase-epoch NV index (§7.6)
        │         AND, optionally, site lease (§7.5)
        ▼
 TPM storage hierarchy (SRK) of that unit's TPM
```

- `CK` never exists in plaintext outside the release station, the depot's
  wrapping step (inside the depot's TPM/HSM) and the unit's TPM-unsealed
  memory at install/run time.
- `UWK` is created **inside** the unit's TPM at enrolment and never leaves it.
  The depot learns only its public part, certified by the unit's attestation
  key, which chains to the TPM's endorsement key certificate. A depot cannot
  be tricked into wrapping keys for a software-emulated "TPM".
- The release side wraps `CK` to the **depot's** key; the depot re-wraps it to
  each assigned unit's `UWK` (§7.3). The release never needs to know the
  fleet; a captured unit holds only wraps for itself.

### 7.2 Payload encryption

Chunks of a sealed RPK are encrypted with XChaCha20-Poly1305 (or AES-256-GCM
where hardware AES is required), one nonce per chunk derived from the chunk
index, the RPK digest bound in as associated data. A chunk that fails
authentication is never written anywhere. Chunk hashes in the manifest are
over ciphertext, so the depot and couriers verify integrity without being
able to decrypt.

### 7.3 Per-unit delivery

The deployment carries, for each sealed item and each target unit,
`wrap(UWK_unit, CK)`. A per-unit media pack (no LAN) contains only that
unit's wraps. Copying a media pack to another unit gives it nothing it can
decrypt.

### 7.4 Plaintext only inside the sealed runtime volume

Installed plaintext of sealed RPKs lives on a dedicated LUKS2 volume (or a
dm-crypt partition) whose volume key is itself sealed to the TPM with the same
policy as `UWK`. The rest of the system, including logs and core dumps, is
configured not to copy from it (core dumps disabled for delivered services,
swap encrypted with an ephemeral key, delivered services run under systemd
with `ProtectSystem=strict`, private `/tmp`, no `CAP_SYS_PTRACE` for anything
but `robodr-pulsard`'s documented use). Models (`kind: model`) are only ever
installed here.

The PCR policy is a **signed policy** (`TPM2_PolicyAuthorize` against a key
held by the delivery roots), not a raw PCR value list. Legitimate OS and
firmware updates delivered through feature B ship a new signed policy with
them, so sealing survives authorised updates and fails for anything else.

Measured boot assumptions (all verified at enrolment, all reported in
attestation): UEFI Secure Boot on; signed kernel and initramfs; kernel
`lockdown=confidentiality`; read-only, `dm-verity`-protected root filesystem
where the platform allows it; IMA measurement on; no interactive console or
debug login enabled in production images. A unit whose boot does not match
the signed policy simply cannot unseal; it still boots and runs everything
that is not sealed, including RoboDR detection, and reports `Deviation`.

### 7.5 Optional site lease

For units that may be carried away powered on (T6), unsealing can also
require a fresh **lease**: a short token signed by the depot, bound to the unit
and to the TPM's clock (`TPM2_PolicySigned` with an expiration, or a lease
counter checked with `TPM2_PolicyNV`). A unit taken out of the site keeps
running with what it has already unsealed, but after its next reboot past the
lease lifetime it can no longer unseal anything. Lease lifetime is per site
policy (hours to weeks), because air-gapped units may be legitimately out of
LAN reach on deployment. With no lease configured, behaviour is as in §7.4.

### 7.6 Cryptographic erase

`UWK` and the runtime-volume key are bound to an **erase epoch**: an NV
counter in the unit's TPM included in their policy (`TPM2_PolicyNV`, "epoch
equals E"). Incrementing that counter once makes every key sealed under epoch
`E` permanently unusable on that TPM, in milliseconds, without touching the
disk. The ciphertext left behind is just ciphertext.

Triggers (each one a finding; each one planned by `robodr-responder`, so it
is graded by safety state and never executed mid-motion unless the platform's
own safety system already holds the robot):

| Trigger | Default |
|---|---|
| Enclosure tamper input from the platform (GPIO / bus signal) | erase |
| Attestation fails N consecutive boots | erase after N (default 3) |
| Lease expired by more than the grace period | erase (only with §7.5) |
| Too many failed local operator authentications | erase |
| Signed "erase unit" command from the depot or SOC | erase |
| Operator erase on the unit (two-person) | erase |

Erase is final for that unit's delivered payloads; recovery is re-enrolment
and re-delivery from the depot. This is RoboDR's own crypto-erase; it does not
replace the platform's physical zeroization (§0).

Nothing executes a response today: `robodr-responder` performs no I/O and
executes nothing (`crates/robodr-responder/src/lib.rs`), the only exit for
plans is the `Executor` seam in `robodr-agent`
(`crates/robodr-agent/src/executor.rs`), whose contract ends the plan
vocabulary at `request_safe_state`, and the control-plane API records
`recorded_not_executed`. This design therefore needs two changes: a new
`crypto_erase` action in the responder's action vocabulary
(`crates/robodr-responder/src/action.rs`), planned under the same
safety-state grading as every other action; and a real `Executor` in
`robodr-agent` that executes that one action under the rules of
`executor.rs`, extended to admit it. Crypto-erase is proposed as the
**first** executed response because it touches no actuator and is safe in
every `SafetyState`.

### 7.7 Units without a TPM (software fallback)

A unit with no TPM 2.0 still gets features A and B. For C it gets a weaker,
clearly labelled mode, shown at a lower trust level as ROADMAP Phase 3
requires for units without a hardware root of trust:

- `UWK` is an X25519 key in a file on the runtime volume, and the runtime
  volume key is **never stored on the unit**: it is unlocked at boot only by
  reaching the site depot's network-bound key service (the Clevis/Tang model:
  the unit can recover its key only while it can talk to the site's Tang
  server; the server never learns the key).
- Optionally combined with an operator passphrase (Clevis `sss` threshold).
- Crypto-erase deletes the local key material and asks the depot to retire
  the unit's binding; it cannot defeat a disk image taken before the erase.

Claims for this mode are in the last column of §7.8.

### 7.8 What is claimed for feature C

| Scenario | TPM 2.0 + measured boot | No TPM (fallback) |
|---|---|---|
| T5: storage imaged, unit absent | Sealed payloads, models and configs unreadable; keys never on disk. | Unreadable while the attacker cannot reach the site's Tang server. |
| T5: whole unit, booted with modified software | Cannot unseal (PCR policy). Unsealed parts boot and report `Deviation`. | Unprotected if the attacker can reach the Tang server, otherwise unreadable. |
| T5: whole unit, booted unmodified, off site | Unseals until the lease expires (if §7.5 on), then cannot. Without lease: unseals; protection then rests on §7.4 lockdown. | Cannot unlock off site. |
| T6: captured running, locked | Plaintext exists in the runtime volume and memory; protection rests on no-login images, lockdown, and erase triggers. **Not claimed** against a determined lab. | Same, weaker. |
| T7: cold boot / DMA / decap / TPM fault injection | **Not claimed.** Mitigations: IOMMU on, encrypted swap, TPM parameter encryption on TPM sessions (defeats passive sniffing of a discrete TPM's bus), short lease. | Not claimed. |
| Other units, future releases | A captured unit holds only its own wraps; content keys of RPKs never assigned to it, and of future releases, are not on it. Erase or revoke the unit at the depot and it receives nothing more. | Same. |
| Integrity (A, B) | Unaffected by capture: a captured unit cannot sign releases or deployments. Its unit key is revoked at the depot. | Same. |

---

## 8. Unit enrolment

1. Unit installed by `install-bundle.sh` with `robodr-deliverd` (bootstrap).
2. `robodr-deliverd enroll`: creates `UWK` and an attestation key in the TPM,
   reads the EK certificate, produces an enrolment request on media or over
   LAN.
3. Depot verifies the EK chain against the platform vendor's CA bundle
   (carried in with the trust file), runs a credential-activation challenge
   (`TPM2_MakeCredential` / `ActivateCredential`) to prove the AK and `UWK`
   live in that TPM, checks the boot measurements against the signed policy,
   and records the unit. Two operators sign the enrolment (insider, T9).
4. The unit's black box records enrolment; its public keys go to the SOC
   through the outbound diode like other evidence.

---

## 9. New findings (OCSF catalog additions)

All under the existing `robot-edr.findings` contract. These are emitted by
in-repo components, so each gets its own catalog entry, like the other
in-repo `robot.*` detectors (deployment-specific ids, such as site
`robot.correlate.*` rules, share a generic entry instead). Adding catalog
entries is a contract minor-version bump and needs the validator updated on
both sides of the diode (`docs/contracts/robot-edr.findings.md`).

| Rule id | Severity | Meaning |
|---|---|---|
| `robot.deliver.installed` | Info | RPK installed and healthy |
| `robot.deliver.deferred_safety` | Low → Medium if repeated | install deferred by safety state |
| `robot.deliver.health_failed` | High | health gate failed; auto-rollback taken |
| `robot.deliver.rollback_blocked_floor` | Critical | failing version, no rollback target at or above floor |
| `robot.deliver.refused` | High | signature, quorum, revocation, floor, platform or hash check failed (reason in finding) |
| `robot.deliver.stale` | Medium → High | no unexpired deployment within the freshness window |
| `robot.deliver.chain_gap` | High | bundle or deployment sequence gap / replay |
| `robot.seal.unseal_failed` | High | TPM refused unseal (policy mismatch) |
| `robot.seal.lease_expired` | Medium | lease expired; sealed payloads unavailable after reboot |
| `robot.seal.erased` | Critical | crypto-erase executed, with trigger |
| `robot.seal.tamper` | Critical | enclosure tamper or erase trigger fired |

---

## 10. Sprint plan

Splits the Sprint 13 and Sprint 14 bullets in `docs/SPRINTS.md`. Sprint
numbers after 14 are unchanged; this work is split into lettered sub-sprints so
nothing else renumbers.

| Sprint | Deliverable (demo) | Exit criteria |
|---|---|---|
| **13a — Formats and release signing** | `robodr-pkg` (RPK, bundle, deployment, trust file parsers, pure, fuzzed); `robodr-release build/sign/verify` with 2-of-N quorum; parity via `robodr-diode` fec. | A bundle built on one host verifies on another; every manifest mutation, missing signature, wrong quorum, revoked key and chain gap is refused in tests; fuzz targets in `fuzz/`. |
| **13b — Unit agent, local** | `robodr-deliverd` installing `files`, `config`, `deb`, `robodr-rules` from a per-unit media pack; store; health gate; auto-rollback; floors in a state file; safety-state gate, tested with recorded JSONL safety reports replayed into agentd's live `safety_feed` socket (a small replay helper is new work). | Demo: bad release auto-rolls back; downgrade below floor refused; install deferred while the replayed safety state is `MovingSlow`. All recorded in the black box. |
| **13c — Sealing** | `robodr-seal`: XChaCha20-Poly1305 chunks; `UWK` in TPM via `tpm2-tools`; signed PCR policy; erase epoch; LUKS2 runtime volume; Clevis/Tang fallback. Tested against `swtpm`, like `TpmNvCounterAnchor`. | Disk image of an enrolled (swtpm) unit yields no plaintext; changed PCR → unseal refused; epoch increment → every sealed key dead; fallback unit cannot unlock without Tang. |
| **14a — Depot and rollout** | `robodr-depot`: import with entry report, inventory, enrolment with credential activation, deployments with operator quorum, rings, per-unit re-wrapping, LAN serving (mTLS), media packs, halt-on-failure. | Demo on ≥ 3 units (VMs with swtpm acceptable): staged rollout lab → canary → ring-1; injected failing release halts at canary; captured-unit VM cannot decrypt a model assigned only to another unit. |
| **14b — Lease, erase execution, evidence** | Lease tokens; crypto-erase as the first executed responder action; `robot.deliver.*` / `robot.seal.*` findings through the existing diode; floors moved to TPM NV counters. | Lease expiry blocks unseal after reboot; erase triggered by a simulated tamper input while state is `Idle`, deferred while `MovingFast`; SOC sees the full chain of findings. |
| **14c — OS A/B and hardware** | `os-image` kind with one A/B updater (decision §11); first run on real TPM hardware (not swtpm) and a real robot computer. | A/B OS update with forced boot failure falls back; sealing survives an authorised OS update (new signed policy) and fails for an unauthorised one. |

Each sub-sprint ends, as `docs/SPRINTS.md` requires, in a demo that runs.

---

## 11. Open questions

1. **A/B updater**: RAUC, SWUpdate or Mender for `os-image`. RAUC and
   SWUpdate are common on embedded Linux and work offline; the choice depends
   on the target robot computers' bootloaders.
2. **Kubernetes interop**: carry Zarf packages as a `zarf` kind for sites whose
   depot or units run a cluster, or stay out of Kubernetes entirely.
3. **Crypto and export control**: feature C adds encryption to the product.
   Classification under the exporting country's dual-use rules (Wassenaar
   Category 5 Part 2) and any national-algorithm requirements of customers
   must be settled before release; this is a legal question, not an
   engineering one.
4. **Discrete TPM vs firmware TPM** on target robot computers; fTPM changes the
   T5/T7 claims (no bus to sniff, different fault-injection surface).
5. **Lease defaults** per mission profile, and who may extend a lease in the
   field.
6. **Depot high availability** and how two depots at one site share the erase
   and revocation state without a network to the outside.
7. **Signed-command source for remote erase**: the depot, the SOC through the
   control-plane API, or both, and with which quorum.

---

## 12. Verification plan

Consistent with the rest of the repository: claims are written as "verified"
only after they run.

- Parsers (`robodr-pkg`): unit tests with hostile inputs, `cargo-fuzz` targets
  in `fuzz/`, and std-only fuzz smoke runs in the crate tests, as
  `robodr-blackbox`, `robodr-commission`, `robodr-ocsf` and `robodr-rtps` do.
  (`robodr-diode`, whose fec code is reused, has no fuzz target yet; adding
  one is part of 13a.)
- Sealing: integration tests against `swtpm`; a separate run on hardware TPMs
  before anything is called field-verified.
- Red-team scenarios before 14c exit: image the disk of an enrolled unit;
  boot it with a modified initramfs; replay an old bundle and an old
  deployment; downgrade below the floor; move a media pack to another unit;
  compromise the depot and try to push to `prod`; capture a unit powered on
  and let its lease expire.
- Every result goes into this document's status line and into
  `docs/SPRINTS.md`, including the ones that fail.
