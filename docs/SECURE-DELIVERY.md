# Secure delivery: air-gapped fleet distribution, updates and captured-unit protection

> **Status: design; Sprints 13a, 13b, 13c, 14a and 14b implemented**
> (13a/13b 2026-10-26, 13c, 14a and 14b 2026-10-30). The
> formats of §3 and release signing exist as `robodr-pkg` (pure parsers
> and validators) and `robodr-release` (build, sign, verify, repair), with
> the decisions of §3.5. The on-unit agent `robodr-deliverd` (13b, §10)
> installs `files`, `config`, `deb` and `robodr-rules` RPKs from per-unit
> media packs behind agentd's live safety-state gate, with a health gate,
> automatic rollback, anti-rollback floors and black-box evidence; the
> `robot.deliver.*` findings of §9 are catalogued (contract 2.2). Sealing
> (13c) exists as `robodr-seal` (library and CLI): sealed RPKs
> (XChaCha20-Poly1305 chunks, `robodr-release build rpk --seal-to`), a
> TPM-resident unit wrapping key behind a signed PCR policy, a policy
> floor and an erase epoch (`tpm2-tools`), the LUKS2 runtime volume and the
> Clevis/Tang fallback; `robodr-deliverd` installs sealed RPKs and models
> only into the runtime volume and crypto-erases; the `robot.seal.*`
> findings are catalogued (contract 2.3). The site depot (14a) exists as
> `robodr-depot` (library and CLI): import behind a signed entry report,
> inventory, TPM enrolment with EK certificate chains and credential
> activation, staged rollouts with operator quorums and halt-on-failure,
> per-unit re-wrapping, mutual-TLS LAN serving with TPM-held client keys,
> media packs. 14b adds TPM-enforced site leases, crypto-erase executed
> from the platform's tamper input under the responder's safety grading,
> anti-rollback floors anchored in TPM NV counters, and the
> `robot.depot.*` / `robot.seal.erase_deferred` findings (contract 2.3,
> block `catalog_2_3_depot`). The exit criteria of all five are
> demonstrated by tests (§10). Verified offline only: on synthetic
> payloads in temporary directories (13b: the host's dpkg against a
> separate dpkg root, a real agentd fed by the replay helper; 13c-14b:
> software TPMs (swtpm) with EK certificates from swtpm's local CA, a real
> Tang server, `cryptsetup` on LUKS2 image files without device-mapper,
> the depot served on loopback), never on a hardware TPM, an air-gapped
> site, an entry station or a robot.
> **Everything else in this document (14c onward) is not implemented.**
> It expands ROADMAP Phase 3 ("Air-gapped deployment") and splits the
> one-line Sprint 13 / Sprint 14 items in `docs/SPRINTS.md` with a
> buildable plan. Every component named here that does not already exist
> is marked `[ ]`, using the legend of ROADMAP §2. Where this design
> reuses existing code, the crate and file are named so the reuse can be
> checked.

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
                                                              robodr-deliverd on each unit   [P]
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
| `robodr-pkg` `[P]` | pure library | RPK, bundle, deployment and trust-file formats (§3): parse, validate, verify, hash. No I/O beyond reading bytes it is given. Fuzzed like `robodr-rtps`. Sprint 13a. |
| `robodr-seal` `[P]` | library + CLI | Key wrapping, payload encryption, TPM sealing via `tpm2-tools` (same approach as `robodr-blackbox/src/tpm_anchor.rs`), software fallback (§7). Sprint 13c: everything in this row, tested against swtpm; decisions in §7.9. |
| `robodr-release` `[P]` | CLI, connected side | Build RPKs from `.deb` / OCI / files / models, encrypt, sign (quorum), assemble bundles, add Reed-Solomon parity. Sprint 13a: builds every kind from a payload directory (kind shape and SBOM checked; a `.deb` or OCI archive is carried as a file, not inspected), quorum signing, chained bundles, parity, verify, repair. 13c: sealed RPKs (`build rpk --seal-to`). |
| `robodr-depot` `[P]` | service, site | Single-box control plane: import bundles, inventory, deployments and rings, per-unit key wrapping, serve units, lease server. This is the air-gapped instance of the planned `robodr-fleet` (ROADMAP §2) and the "single-box control plane" of Sprint 14. Sprints 14a / 14b: everything in this row plus the entry scan and the TPM enrolment, tested against swtpm on loopback; keys are files (not TPM / HSM). |
| `robodr-deliverd` `[P]` | service, unit | The on-unit agent: reconcile desired vs installed, verify, stage, gate on safety state, install, health-check, roll back, report. Runs separately from `robodr-agentd` so a delivery bug cannot stop detection. Sprint 13b: from per-unit media packs, kinds `files`, `config`, `deb`, `robodr-rules`; no LAN, no OS A/B. 13c: sealed `files` / `model` / `config` and every `model` into the runtime volume, `erase`. 14a / 14b: LAN pulls and reports, leases, executed erase from platform triggers, NV-counter floors; no OS A/B. |

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

The trust file also scopes release keys and packages to **programmes**
(a site may take bundles from several programme offices or vendors; one
programme's release quorum signs only its own packages and bundles),
assigns units to the `lab` and `canary` **rings** (so the depot's ring
label cannot choose the smaller operator quorum), and **expires** (so a
withheld newer trust file, carrying a revocation, is detected). A
verifying station keeps one site-wide **trust anchor**: the last trust
file it accepted, which only moves forward by rotation. The exact rules
are §3.5, items 19 and 21–25, and the review section after item 29.

### 3.5 Format decisions (Sprint 13a)

Where §3.1–§3.4 (and §5.2 for deployments) left room, 13a took the
stricter reading. The exact rules are in the `robodr-pkg` module docs;
this is the list of decisions a reviewer should check against the design.

**Every document**

1. **One encoding per value.** A document is signed and hashed over its
   raw bytes (as in `robodr-diode`) and is accepted only if those bytes
   are exactly the compact serialisation of the parsed value: members in
   the documented order, no whitespace, optional members present as
   `null`, set-valued lists sorted without duplicates. Unknown members,
   duplicate keys, alternative number or string encodings, a BOM or a
   trailing newline are refused before any signature is looked at, so a
   depot written later in another language cannot disagree with this
   crate about what was signed.
2. **Hard caps before parsing** (RPK manifest 8 MiB, `bundle.json`
   32 MiB, trust file and deployment 1 MiB, signature file 8 KiB) and on
   every list. Every integer (serials, sequence numbers, times) is at most
   `2^53 - 1`.
3. **Detached signature sets** (`robodr-sigset/1`, file `MANIFEST.sig`,
   `bundle.sig` or `<file>.sig`): Ed25519 only (strict verification),
   1–16 entries sorted by key id. **Every entry must be valid** (listed
   key, role allowed for this document, not revoked, verifies); one bad
   entry refuses the document. Signers are counted **by public-key
   fingerprint**, so two entries by one key never make a quorum of two.
4. **A signing domain per document type**: `robodr-pkg/manifest/v1\0`
   (given in §3.1), `robodr-bundle/manifest/v1\0`,
   `robodr-deployment/v1\0`, `robodr-delivery-trust/v1\0`, and separate
   digest domains for each. Digests are bare lower-case hex; key
   fingerprints are `sha256:<hex>` of the raw public key, the value
   `robodr-commission` already prints and revokes.
5. **Refusals have stable codes** (`robodr_pkg::Code`), the reasons the
   §9 findings will carry.

**RPK (`robodr-pkg/1`)**

6. `version` is `{"serial": N, "display": "..."}`. The directory name is
   `rpk_<name>_<serial>_<arch>` (serial, not the display string, so it
   is unambiguous); package names exclude `_`. `arch` is `amd64`,
   `arm64` or `all`.
7. Chunking is per content file (4 MiB, last short, none for an empty
   file); `chunks[]` lists each distinct chunk once, sorted by hash, and
   content files name their chunks by index. Every chunk must be used.
8. Content paths: relative, `/`-separated components of
   `[A-Za-z0-9_][A-Za-z0-9._+-]*` (no `.`/`..`, no hidden file, nothing
   that reads as an option), at most 16 deep and 255 bytes, unique **also
   case-insensitively**, and no path both a file and a directory.
9. Modes: permission bits only (no setuid, setgid, sticky), owner
   readable, **no group or other write**; data-only kinds (`model`,
   `config`, `robodr-profile`, `robodr-rules`) have no executable bit.
   The builder refuses such payloads; it never normalises them.
10. `security_floor` is `1..=serial` (a release cannot forbid itself).
    `requires` / `conflicts` are name + minimum serial, never the
    package itself, never the same name in both.
11. `sbom` is the SHA-256 of exactly one non-empty content file named
    `*.cdx.json` (the builder checks it is CycloneDX JSON); mandatory for
    `deb`, `oci-image`, `os-image`.
12. Content shape per kind (the SBOM aside): `deb` one `.deb`;
    `oci-image` one `.tar`; `os-image` one file; `robodr-profile` one
    `.json`; `robodr-rules` only `.toml`; other kinds at least one file.
13. `install` is exactly `{allow_maintainer_scripts, requires_operator_present}`;
    maintainer scripts only for `deb`. `health` is a closed set of checks
    (`service_active`, `file_present`, `ros2_node`, `probe` with an argv
    whose first element is absolute, a non-root user and a 1–300 s
    timeout); unknown members inside a check are refused.
14. `expires_at` is Unix seconds; an RPK is refused at and after it.
15. `confidentiality: "sealed"` is refused (`unsupported`) until 13c
    defines the key-wrap members. *13c:* defined: the manifest member
    `seal`, sealed only for `files`, `model`, `config` (§7.9).

**Bundle (`robodr-bundle/1`)**

16. `bundle.json` lists every RPK (`dir`, `name`, `serial`, `arch`,
    `digest`) and **every file of the tree** with size and SHA-256 (a
    signed `SHA256SUMS`). File paths follow a fixed grammar
    (`<rpk dir>/MANIFEST.json`, `<rpk dir>/MANIFEST.sig`,
    `<rpk dir>/chunks/<sha256>`, `parity/g<gggg>-p<jj>.rbpar`); a chunk's
    name must be its hash. Traversal is not expressible. The verifier
    refuses any file or directory not implied by the listing, any
    symlink and any special file.
17. One serial per package and arch per bundle; no RPK twice.
18. The bundle must name a `programme` the site's trust file lists.
19. Chain: from a head `h`, `bundle_seq == h + 1` with
    `prev_bundle_hash == hash(h)` is next; a higher number is a **gap**;
    a lower one a **replay**; the same number with other bytes an
    **equivocation**; the right number with another link a **broken
    chain**; the same bytes again is accepted as a no-op. With no head, a
    verifier must say so explicitly (`--genesis`: only bundle 1 is
    accepted) or name the head (`--after SEQ:HASH`); there is no default.
    The chain state also records the site and the version and digest of
    the trust file the head was accepted under: the trust file crosses the
    gap like a bundle, so an older root-signed trust file (one from before
    a key revocation) is refused as a replay, the same version with other
    content as an equivocation (found in the 13a self-review), and another
    site's file as `wrong_scope` (13a review, finding 1). A *newer* trust
    version is never accepted on the state's word: it must be a rotation
    of the site's trust anchor (item 25), so `--state` needs
    `--trust-anchor`, and a commit advances the anchor before the state.
20. Parity (`rs-gf256-0x11d/1`, `robodr-diode`'s code and parity-length
    rule): the data files (every non-parity entry, in path order) form
    groups of `k`; each group carries `m` parity files (1–32,
    `k + m <= 255`). Up to `m` missing or damaged files per group are
    rebuilt; a rebuilt file is accepted only if its listed hash matches,
    and only after `bundle.json` itself is authenticated.

**Trust file (`robodr-delivery-trust/1`)**

21. Members: `site`, `version`, `issued_at`, `expires_at`,
    `programmes` (`{name, release_keys, packages}`),
    `quorum {root, release, operator_prod, operator_lab}`, `roots`,
    `release_keys`, `depot_keys`, `operator_keys`, `rings`
    (`{ring, units}`), `revoked_keys` (fingerprints), `revoked_rpks`
    (digests), `revoked_serials` (`{name, serial}`), `floors`.
    `issued_at < expires_at <= issued_at + 366 days`; a file is refused at
    and after `expires_at` (`expired`), judged on the verifier's clock.
22. **Roles are disjoint**: one fingerprint and one key id appear at most
    once in the whole file. Keys must be canonical, of large order and
    **torsion-free** (`robodr-blackbox`): a mixed-order "twin" `A + T` of
    a key `A` has another fingerprint but can be signed for with `A`'s
    secret, so it would count as a second signer (13a review, finding 2).
23. Quorum floors: `root >= 2`, `release >= 2`, `operator_prod >= 2`,
    `1 <= operator_lab <= operator_prod`; caps: `root` and `release` at
    most 16 (the signature-set limit), `operator_prod` at most 15 (a
    deployment also carries the depot's signature). The root quorum must
    be reachable with the roots, the release quorum with the non-revoked
    release keys **of every programme**. The depot quorum is fixed at 1.
    A full root rotation needs the old and the new root quorum in one
    16-entry set (shared roots count for both).
24. A revoked key may stay listed (refusals then say `revoked_key`) but
    never counts; a root cannot be revoked by the file it signs. RPKs are
    revoked by digest (`revoked_rpks`) or by package and serial
    (`revoked_serials`, which also catches the same release re-signed
    into another manifest, i.e. another digest). Floors remain the
    control for "everything below N".
25. Standalone acceptance: the file's roots must be **exactly** the
    pinned root fingerprints, its `site` must be the **pinned site**
    (`--site`; the roots belong to the programme office and are normally
    shared by several sites, so roots alone do not tell one site's file
    from another's: 13a review, finding 1), the root quorum must have
    signed, and it must not have expired. Rotation (TUF-style): a higher
    version for the same site, signed by the root quorum of the accepted
    file **and** of the new one; revocations (keys, RPKs, serials) and
    floors only grow; an older version is a replay, the same version with
    other bytes an equivocation. **Trust anchor** (13a review, finding
    4): every verifying station keeps one site-wide anchor (the last
    accepted trust file, for all programmes) and accepts a presented file
    only as that anchor or a rotation of it, for every command (`verify
    rpk|bundle|deployment|trust`, `repair`, `import`, `build bundle`,
    `sign`). The anchor is created once (`verify trust --init-anchor`)
    and moves forward only by an accepted rotation (`verify trust
    --commit`, or `--commit` of a bundle accepted under the rotation).
    Working without it needs the explicit `--no-trust-anchor`, which then
    checks pins, site, quorum and expiry only and cannot be combined with
    a chain state. An expired anchor can still accept its fresh successor.

    *25a.* **Programmes** (13a review, finding 5): each programme names the
    release keys that may sign for it and the packages it may deliver
    (exact names, or a prefix ending in `*`; `*` alone is every name). A
    package name belongs to at most one programme (overlapping patterns
    are refused). An RPK is verified against the release quorum of the
    programme owning its name; a bundle against its own programme's, and
    every RPK in it must be a package of that programme. A signature by
    a release key of another programme refuses the document
    (`wrong_scope`), so one programme's release station can neither sign
    another's packages nor fork or freeze another's chain.

**Deployment (`robodr-deployment/1`)**

26. Signed by depot and operator keys only; at least one depot
    signature. §3.4 says "1 for `lab`", §5.3 reads as if the depot alone
    may push to `lab` and `canary`: the stricter reading is taken, so
    every deployment needs at least `operator_lab` (>= 1) operators and a
    compromised depot alone can push nowhere. **The ring label is bound
    to the targets** (13a review, finding 3): the `ring` string is the
    depot's, so it cannot by itself select the smaller quorum. The
    `operator_lab` quorum applies only when the ring is `lab` or
    `canary`, the targets are **units only** (a group's membership is
    defined on the depot, so a group is never authenticated as lab), every
    unit is assigned to **that** ring by the root-signed trust file
    (`rings`), and a `canary` names exactly one unit (§4.3). Anything
    else, including every `ring-<n>` (`n` in 1–99, the production rings),
    needs `operator_prod` (>= 2). The unit agent must also refuse a
    deployment whose ring is not the unit's own (§10, 13b requirements).
27. `not_before < expires_at`, at most 366 days apart; valid for
    `not_before <= now < expires_at`. Items must not be revoked or below a
    floor. `deployment_seq` must increase (replay, equivocation); a gap is
    normal for one unit, which only sees deployments that target it, so
    gaps are not reported for deployments (bundles only).
28. `wrapped_keys` is present and must be empty until 13c. *13c:* a
    list of `{unit, rpk_digest, wrap}` (§7.9).

**Release tool**

29. `sign` checks before it signs: the document parses; for an RPK the
    files on disk are exactly what it describes (every hash), the site
    policy holds and a programme of the site delivers the package; for a
    bundle the files are exactly the listing (every hash) and **every
    RPK in it verifies completely** (digest, its own release quorum and
    programme, policy, content); and every signature already in the set,
    and the new one, is valid for the document under the site's trust
    (a stale or foreign entry is refused, not kept). It does not check a
    bundle's chain position (that is the verifier's state). `build
    bundle` copies the signed RPKs and verifies the **copies** (release
    quorum, programme, site policy, every hash) before listing them.
    Builds are deterministic: no times or host paths in an RPK.
30. **Verify, then use only the verified copy** (13a review, finding 6).
    Verifying files in place on removable media proves nothing about the
    next read: a malicious USB device can serve the verified bytes to
    `verify` and other bytes to the `cp` or import that follows. `import
    --from MEDIA --to DIR` is the only supported way in: it
    authenticates `bundle.json`, requires the media tree to be exactly
    its listing (no symlink, device, FIFO or stray file), copies each
    listed file reading at most its listed size and hashing as it copies,
    then verifies the **copy** completely (chain, tree, every hash, every
    RPK) and only then renames it to `DIR`. Only `DIR` may be used
    afterwards; the depot (14a) imports from it or from a
    content-addressed store filled from it, never from the media.
31. Listed files are compared by size (`fstat` of the opened file)
    before anything is read and never read past their listed size, so a
    sparse multi-terabyte file costs nothing (13a review, finding 7).
32. CLI: `--help` / `-h` exits 0 only as the whole command line; next to
    other arguments it is a usage error (a stray `-h` spliced into a
    verify command never turns a refusal into success). A system clock
    before 1970 is an error, never read as 0.

**Review of 13a (independent adversarial review, 2026-10-26).** After
the self-review an independent review attacked the implementation with
working PoCs and found one high, five medium and three low issues. All
are fixed, each with a regression test that replays the attack and
failed before the fix (`crates/robodr-release/tests/review_13a.rs`;
unit tests in `robodr-pkg` and `robodr-blackbox`):

| # | Finding | Decision |
|---|---|---|
| 1 | High: another site's trust file (same roots) accepted, bypassing revocations and floors and locking the real file out | site pinned with the roots (item 25); chain state records and compares the site (item 19) |
| 2 | Mixed-order twin keys: one secret, two signers | torsion-free keys only, in `robodr-blackbox` (every key load) (item 22) |
| 3 | `lab` label not bound to targets: depot + one operator reach production | root-signed unit→ring assignment; lab quorum only for assigned units; canary of one unit (item 26) |
| 4 | No trust anti-rollback outside `verify bundle --state`; per-programme only; no expiry (freeze undetectable) | one site-wide trust anchor for every command, advanced only by rotation; mandatory `expires_at` (items 21, 25) |
| 5 | Release keys site-wide: one programme's release quorum signs another's RPKs and bundles | programmes scope release keys and package names (item 25a) |
| 6 | Verify-then-use on removable media | `import`: copy, verify the copy, use only the copy (item 30) |
| 7 | Hash before size (sparse-file DoS) | size first, bounded read (item 31) |
| 8 | `-h` anywhere exits 0 | help only alone (item 32) |
| 9 | Quorums above 16; clock before 1970 read as 0; `sign` trusted a bundle's RPKs and existing entries; revocation by digest only | caps (item 23); clock error (item 32); `sign` checks (item 29); `revoked_serials` (item 24) |

The formats were changed before any release: `robodr-delivery-trust/1`
gained `expires_at`, structured `programmes`, `rings` and
`revoked_serials`; `robodr-bundle-chain/1` gained `site`. Notes for
fields that 13b will act on are in §10 ("13b requirements").

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
| `deb` | `dpkg` (maintainer scripts only if allowed, §3.2); the RPK `name` and `arch` declare the dpkg `Package` and `Architecture` (13b review H2); release signers are root-equivalent here (§6.7) | previous `.deb` kept in the store for rollback |
| `oci-image` | import into the unit's local containerd / podman store; or the depot's local registry when units pull | image digest switch; old image retained |
| `files` | write into a versioned directory under `/opt/robodr-delivered/<name>/<serial>-<digest>/` (named by RPK digest too, 13b review M4), atomic `current` symlink swap | symlink swap is atomic |
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
depot (T4) can therefore push to `lab` and `canary` only, and (13a: §3.5,
item 26) never alone: every deployment needs at least one operator. Which
units are `lab` and `canary` is not the depot's to say: the root-signed
trust file assigns units to those rings, and the smaller quorum applies
only to units assigned to the deployment's ring (a canary is one unit);
a deployment naming any group or any other unit needs the production
quorum.

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

The gate is only as good as its input (13b review H1). The state is taken
from **agentd itself**: agentd runs as its own system user
(`robodr-agentd`), not the user of the network-facing exporters, and
serves its status on a unix socket; `robodr-deliverd` checks the serving
process with `SO_PEERCRED` and treats anything it cannot attribute to that
user (or root) as `Unknown`. agentd in turn accepts safety reports on its
PLC-gateway socket only from root, itself and the configured feeders
(socket mode and group, `SO_PEERCRED`). A maintenance window is judged
only on a time no local process can set: with an untrusted clock and no
signed current time it stays closed (review L3).

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

On a unit (13b), the floor, the accepted deployment's sequence, the time
floor and the bundle chain heads are written to a **signed high-water
record** next to the black box before every state write that moves them;
it is never rotated (the black box's floor notes are, review M1). Every
write gives it the next **generation**, noted in the black box and in the
state file, and the lock is part of the record (review 2, M-A / M-B). A
lost state file is restored from a current record. When the record is
older than the black box or the state file says, is locked, or is missing
or invalid while the state file or the black box exists, the unit
**locks** (no import, install or rollback) until an operator re-anchors
it with a current trust file; re-anchoring rebuilds the deployment
sequence and chain heads from the black box and refuses a trust file
older than the black box has seen. Only black-box notes that verify with
the unit's key count (review 3). Root deleting the black box as well
is not detected (TPM NV counter, 14b). A rotation of the black-box key
(OPERATIONS §4.3) is carried over by `robodr-deliverd rekey`: the old
journal and record must verify with the old key; the journal is archived
next to it and a new one, and a new record one generation newer, are
signed with the new key and carry the whole baseline (review 3, L-R3-3).

Automatic rollback therefore only ever goes to the previous serial **at or
above** the floor. If none exists the unit stays on the failing version,
raises a Critical finding and waits for an operator. Today's
`install-bundle.sh rollback` has no floor; it remains for bootstrap and lab use
and is documented as such.

### 6.5 Freshness and freeze attacks

An air-gapped unit cannot ask "is there a newer release?". Instead, every
deployment carries `expires_at`, and so does the site trust file (13a:
§3.5, item 21), so a courier who withholds a newer trust file (one that
revokes a key or an RPK) is detected when the old one expires: every
verifying station then refuses until a fresh trust file arrives. A unit whose newest valid deployment has
expired raises `robot.deliver.stale` (High after a configurable grace). That
makes withholding (T8) visible in the SOC, through the outbound diode, within
one freshness window. It does not make it impossible.

### 6.6 Evidence

Every step (deployment accepted, chunk verified, staged, deferred, installed,
health result, rollback, floor raised, refusal and why) is a signed black-box
record and an OCSF finding (§9). The SOC can answer "what exactly is running
on unit ugv-07, who approved it, and when" from evidence alone.

### 6.7 What the release quorum is trusted with (13b review I1)

For kind `deb` the release signers are **fully trusted: root-equivalent on
every unit that installs their package.** A `.deb` without maintainer
scripts can still install systemd units, cron entries or setuid files
(`Conflicts` / `Replaces` against other packages and files under
`/etc/dpkg` or `/etc/apt` are refused, below); the delivery agent runs as root and can
reach PID 1. The "no maintainer scripts" rule, the unit's capability set
and its system-call filter limit accidents and what a compromised agent
does directly; they are not a boundary for release-approved content.
Depot and operators decide *where and when*, never *what*.

Within that, the unit keeps what the release declares honest (review
H2): a `deb` RPK's `name` is its dpkg `Package` and its `arch` the dpkg
`Architecture` (`all` allowed under any arch); a `.deb` that says
otherwise, a `Package` the unit records under another RPK name, a higher
serial carrying a lower dpkg `Version`, a `.deb` whose `Conflicts`,
`Breaks`, `Replaces` or `Provides` names any package but its own (review
2, H-A: such a relation lets dpkg take over or remove a floored package,
or another programme's, while the state still records it), and a `.deb`
that is one of RoboDR's own packages (`robodr`, `robodr-focal`) are
refused. RoboDR's own packages, which conflict with and replace each
other, are allowed only for RPKs from bundles of the **designated RoboDR
programme** (`install.robodr_programme` in the unit's configuration;
default none, so RoboDR itself is updated with `install-bundle.sh`).
Floors apply to the dpkg identity because it is the RPK name, so an RPK
under another name cannot carry an older `.deb` **of** a floored package.
It also cannot carry older **files** of one (review 3, H-R3-1): dpkg
detects file conflicts by path name only, and on a merged-/usr system a
`.deb` that ships `lib/nav/ok` writes through `/lib -> usr/lib` onto
`/usr/lib/nav/ok`, owned by `nav`, without a conflict. Right before every
`dpkg --install` the unit lists the `.deb`'s paths (`dpkg-deb
--fsys-tarfile`, read with a strict tar reader), resolves their parent
directories through the target root's symlinks (never leaving the root),
resolves every other package's file list the same way, and refuses a
path another package owns, a path below the agent's own trees, RoboDR's
install paths, `/etc/dpkg`, `/etc/apt` or `/var/lib/dpkg` (a
`force-overwrite` in `dpkg.cfg.d` would defeat the overwrite check, L-R3-2),
and a path below one of the `.deb`'s own symlinks. dpkg runs with
`--refuse-all` and then only the force options the agent needs, plus an
explicit `--refuse-overwrite`, on its command line, which overrides
`dpkg.cfg.d`. Before the switch every other deb package the unit recorded
must be as the unit left it; one changed outside the agent (apt,
unattended-upgrades, an operator) is reported (`robot.deliver.refused`,
High, `changed_outside`) and deb installs wait: the unit never downgrades
it on its own. After every `dpkg --install` the unit checks every other
recorded deb package: installed at its recorded version (`dpkg-query`),
what `dpkg --verify` reports (its **output**: dpkg 1.22 exits 0 even when
it prints `??5??????`; conffiles aside) and its file list (`dpkg-query
-L`) must both be what they were right after its own install. One that
changed is reinstalled and the switch fails (rollback, or
`rollback_blocked_floor` when there is no earlier version). What stays
root-equivalent: release-allowed maintainer scripts (a `preinst` can
`dpkg-divert --rename` a floored package's file; the file-list check then
sees the diversion and fails the switch, but the script has run) and
anything a `.deb` installs that changes the system elsewhere.

Hardening of `robodr-deliverd.service` (review I1), kept where it does not
break an ordinary (script-less) install: `RestrictSUIDSGID=` is **not**
set (dpkg must create the setuid / setgid files ordinary packages ship);
`@resources` is no longer denied (probes get rlimits);
`MemoryDenyWriteExecute=` and `ProtectKernelTunables=` stay (they only
affect release-allowed maintainer scripts and probes: no JIT, no
`sysctl -w`; ship `/etc/sysctl.d/` files instead).

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

**14b implementation.** The lease is enforced by the TPM, not by the unit's
software. A UWK enrolled with `--lease-key` has the authPolicy
`PolicyAuthorize(lease key, H("robodr-seal/lease-ref/v1\0" || unit))`
AND `PolicyNV(epoch)`: the only policies that satisfy it are ones the
depot's lease key signed for this unit. A lease (`robodr-lease/1`, P-256
ECDSA) approves the 13c authority chain followed by
`PolicyCounterTimer(clock < X)` and `PolicyCounterTimer(resetCount <= R)`,
so the TPM refuses the unseal once its own clock passes `X` or after more
than the allowed reboots (error kind `lease_expired`, finding
`robot.seal.lease_expired`). The depot issues a lease with every accepted
report: `X` = the unit's TPM clock + `lease.lifetime_s`, `R` = its reset
count + `lease.reboots`, both taken from a **TPM attestation** of that
time in the report (§10, 14b review). Setting the TPM clock back is refused
by the TPM; an older lease is refused by the unit as a replay. TPM time is
powered-on time: a unit kept switched off does not use up its lease, so
the reboot budget is the bound for units carried away and powered up
elsewhere. Leases reach the unit in the depot's answer to a report (LAN)
or in a media pack.

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

**What erase destroys, and what it does not (13c).** Its essential step is the
epoch increment on a TPM unit and, without a TPM, the wipe of the runtime
volume's LUKS2 keyslots (§7.7: the device is required; an erase without it
reports nothing as erased). Nothing is reported as erased unless that step
happened, and the report and `robot.seal.erased` list exactly what was
destroyed. Erase destroys **keys**, not plaintext: a runtime volume that is
open at that moment still serves its plaintext through its mount, and the
kernel still holds its volume key. Erase therefore also stops the configured
services, unmounts the runtime root and closes the mapping, or, when it is
busy, suspends it (`cryptsetup luksSuspend`: the kernel wipes the volume key
and blocks all I/O). Pages already in memory (page cache, the services'
memory) survive until power-off; what could not be closed is said in the
finding. A unit that must not keep plaintext in memory after erase must also
power off.

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

**14b implementation.** `robodr-responder` gained the `crypto_erase` plan
(`src/erase.rs`, outside the SOC action catalog), in two parts (review
of 2026-10-30, see below): the **keys** (epoch increment, UWK blobs and
volume wrap deleted; without a TPM the keyslot wipe) are destroyed at
once in **every** safety state, `unknown` included, since that part
touches no actuator; the **lockdown** (stop `seal.stop_units`, unmount,
close the mapping) runs in `idle`, `safe_state_active` and
`estop_active` and is deferred in `moving_slow`, `moving_fast`,
`collaborative_human_nearby` and `unknown`, escalating once (High) past
`erase.max_lockdown_deferral_s` (default 600 s); a signed command or an
operator's erase needs two distinct approvers. The executor
is `robodr-deliverd` on the unit, under the rules of
`robodr-agent/src/executor.rs` (re-derive the plan, nothing for a replay,
the live safety state read again immediately before acting, the intent
journaled first, the effect read back). The platform's tamper,
attestation-failure and authentication-failure inputs reach it through
its trigger socket, accepted only from root or configured feeders
(`SO_PEERCRED`); a deferred erase stays pending in the state file across
restarts (`robot.seal.erase_deferred`, Medium, once per state) and runs as
soon as the state allows. While any part of an erase is pending the agent
imports, stores wraps, unwraps and installs nothing. Not routed yet: the lease-expiry trigger (the
TPM already refuses every unseal) and a signed remote command (§11 item 7).

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
- Crypto-erase wipes the runtime volume's LUKS2 keyslots (which hold the
  Tang binding) and destroys the UWK file if the volume is open. **Tang is
  stateless**: it keeps no per-unit binding, so there is nothing to retire
  for one unit, and a disk image taken before the erase can still be
  unlocked by anyone who reaches the Tang server. The only remedy is to
  rotate the Tang server's keys (`tangd-rotate-keys -d <keydir>`, rebind every other
  unit with `clevis luks regen`, then delete the old keys), which affects
  every unit bound to that server (OPERATIONS §12.5).

Claims for this mode are in the last column of §7.8.

### 7.8 What is claimed for feature C

| Scenario | TPM 2.0 + measured boot | No TPM (fallback) |
|---|---|---|
| T5: storage imaged, unit absent | Sealed payloads, models and configs unreadable; keys never on disk. | Unreadable while the attacker cannot reach the site's Tang server. |
| T5: whole unit, booted with modified software | Cannot unseal (PCR policy). Unsealed parts boot and report `Deviation`. | Unprotected if the attacker can reach the Tang server, otherwise unreadable. |
| T5: whole unit, booted unmodified, off site | Unseals until the lease expires (if §7.5 on), then cannot. Without lease: unseals; protection then rests on §7.4 lockdown. | Cannot unlock off site. |
| T6: captured running, locked | Plaintext exists in the runtime volume and memory; protection rests on no-login images, lockdown, and erase triggers. Erase closes (or suspends) the open runtime volume (§7.6) but does not clear memory. **Not claimed** against a determined lab. | Same, weaker. |
| T7: cold boot / DMA / decap / TPM fault injection | **Not claimed.** Mitigations: IOMMU on, encrypted swap, TPM parameter encryption on TPM sessions (defeats passive sniffing of a discrete TPM's bus), TPM session files (with session keys) only on tmpfs, short lease. | Not claimed. |
| Other units, future releases | A captured unit also carries other units' wraps (a signed deployment lists every targeted unit's `wrapped_keys` and travels whole in the media pack), but each wrap opens only with its own unit's UWK. Content keys of RPKs never wrapped to this unit, and of future releases, cannot be recovered from it. Erase or revoke the unit at the depot and it receives nothing more. | Same. |
| Integrity (A, B) | Unaffected by capture: a captured unit cannot sign releases or deployments. Its unit key is revoked at the depot. | Same. |

### 7.9 Decisions taken in Sprint 13c

Where §7.1–§7.7 left room, 13c took these decisions (code:
`crates/robodr-seal`, module docs; the formats in `robodr-pkg`).

**Formats**

1. **Sealed manifest.** `confidentiality: "sealed"` carries a member
   `seal = {scheme: "robodr-seal/1", seal_id, ck_commit, depot_wraps}`.
   Public manifests carry no `seal` member at all (not `null`), so every
   13a/13b manifest keeps its bytes and digest. Sealing is allowed for
   `files`, `model` and `config` only (the kinds installed into the
   runtime volume); a `deb`, OCI image or OS image goes through installers
   that write outside it.
2. **What is encrypted.** Every content file except the SBOM: the SBOM
   stays in clear so the entry station can scan it (§6.1) without a key.
   Paths, modes and sizes stay visible in the signed manifest. A sealed
   file's `sha256` member is a **keyed** digest (HMAC under a key derived
   from `CK`): the plaintext SHA-256 would let anyone confirm a guessed
   low-entropy file (a config) from the manifest alone. Two files of one
   RPK with equal plaintext have equal keyed digests (the key is per RPK),
   so the manifest shows which sealed files are identical; across RPKs the
   digests are unrelated.
3. **Chunks** (§7.2): `nonce (24) || ciphertext || tag (16)`,
   XChaCha20-Poly1305 under `HKDF-SHA256(CK, salt = seal_id,
   "robodr-seal/chunk-key/v1")`. §7.2 says "nonce derived from the chunk
   index, the RPK digest bound in as associated data". The RPK digest
   cannot be bound (the manifest lists the ciphertext hashes, so the
   digest depends on the ciphertext); a random 32-byte `seal_id` in the
   signed manifest stands for the RPK instead. The associated data binds
   `seal_id`, the file's index in `content[]`, the chunk's position and
   the file's chunk count. The nonce is **synthetic**: HMAC of the
   associated data and the plaintext's hash under a second derived key
   (24 bytes), checked again on open; it is unique per (key, place,
   plaintext), so a content key reused by mistake never encrypts two
   different plaintexts under one nonce. A sealed chunk serves exactly one
   position of one file (no deduplication inside sealed RPKs).
4. **Key commitment.** `ck_commit` (HKDF output) is checked right after
   every unwrap, so a wrap of another key (a confused or malicious depot)
   is refused before any chunk is opened; Poly1305 alone does not commit
   to its key.
5. **Wraps.** Ephemeral-static ECDH, HKDF-SHA256, XChaCha20-Poly1305;
   `0x01` X25519 (105 bytes) for depot keys and units without a TPM, `0x02`
   P-256 (138 bytes) for TPM units (the TPM does `TPM2_ECDH_ZGen`; TPMs do
   not do X25519). The KDF info and the associated data bind the
   recipient's public key and the purpose: depot wrap (`seal_id`), unit
   wrap (unit id + RPK digest), volume key (unit id). Low-order X25519
   points are refused.
6. **Release → depot.** The release wraps `CK` to each depot wrapping key
   named with `build rpk --seal-to` (X25519, `robodr-seal keygen depot`)
   into the signed manifest and forgets it. The depot keys are not in the
   site trust file (it is root-signed and versioned; changing its format
   again was not needed for 13c): the release operator pins them.
7. **Depot → unit** (§7.3). Until `robodr-depot` (14a) exists,
   `robodr-seal rewrap` is the depot's step: it recovers `CK` from the
   manifest's depot wrap, checks the commitment and wraps it to the unit's
   UWK from the unit's enrolment record; the deployment's
   `wrapped_keys` lists `{unit, rpk_digest, wrap}` (sorted, an item of
   the deployment, a targeted unit unless groups are targeted). A unit
   keeps only its own entries in its store (`store/wraps/<digest>`); the
   imported deployment, with every unit's entries, stays in its state.
   `rewrap` wraps to whatever UWK the enrolment record names: until the
   record is certified by the TPM's endorsement key (14a, item 12), the
   depot must receive records over a trusted channel. **14a:**
   `robodr-depot` does this step for enrolled units only (their UWK
   certified by an AK that credential activation tied to an EK the vendor
   CA certified); each unit's pack carries only its own wraps, and the
   release's depot wraps must name keys the trust file lists
   (`depot_wrap_keys`).

**TPM**

8. **UWK.** A P-256 ECDH key created inside the TPM under a persistent
   SRK (`0x81000001`): `fixedtpm|fixedparent|sensitivedataorigin|decrypt|
   noda`, no `userwithauth`, so its policy is the only way to use it.
   Its authPolicy is `PolicyAuthorize(policy authority, policyRef =
   H(platform)) AND PolicyNV(erase epoch == E)`. Unwrapping runs in a
   salted policy session with parameter encryption (the shared secret does
   not cross a discrete TPM's bus in clear) and the secret comes back on a
   pipe, never in a file. The tools' object and session contexts (a
   session context holds the session key) go to a per-operation directory
   under `/run/robodr-seal` (`work_dir`), which must be tmpfs (checked from
   mountinfo), never the persistent seal directory; directories left by a
   killed process are swept by the next operation.
9. **Signed PCR policy** (§7.4): `robodr-seal-policy/1`, ECDSA P-256 by
   the **policy authority** over `TPM2_PolicyAuthorize`'s `aHash`; the
   approved policy is `PolicyPCR(sha256 PCRs = signed values) AND
   PolicyNV(floor: bit <version> clear)`, recomputed on the unit from the
   document (every member is bound by the signature). The TPM checks the
   signature itself (`TPM2_VerifySignature` ticket), so a unit's own code
   cannot be talked into a policy the authority did not sign. **One key**:
   `PolicyAuthorize` names one signer, so the TPM cannot enforce the
   roots' quorum; the policy authority is a separate offline P-256 key of
   the delivery roots (§11).
10. **Policy rollback.** A signed policy stays valid forever under
    `PolicyAuthorize` alone, so an older, still signed boot chain could be
    booted again. Every approved policy therefore requires its version's
    bit (0–63) of a `TPM_NT_BITS` NV index (the **policy floor**) to be
    clear. `robodr-seal policy commit` sets the bits of every lower
    version, and only after the policy in force has unsealed on this
    boot (a probe unwrap), so a wrong policy never revokes the right one.
    Bits are never cleared; undefining the index needs the owner
    authorization. `robodr-seal provision` therefore refuses a TPM whose
    owner or lockout authorization is empty (`TPM_PT_PERMANENT`), and
    `policy commit` refuses then too: with an empty owner authorization root
    on the unit can undefine and redefine the floor, which clears every
    revocation (review H1). The site sets both authorizations and does not
    keep them on the unit (OPERATIONS §12.1). **Exhaustion:** 64 versions
    (0..=63); version 63 can never be revoked (there is no higher bit), so
    signing it needs `--last-version`, and the boot-chain update after it
    needs a new enrolment: erase (the old UWK dies with the epoch), undefine
    and redefine the floor with the owner authorization, enrol again. A counter was not used: its first value is the
    TPM's highest counter value ever, which a signing station cannot know.
11. **Erase epoch** (§7.6): a `TPM_NT_COUNTER` index; erase is one
    increment (measured: a few TPM round trips with swtpm). A counter
    that is undefined and defined again starts above every value it ever
    had, so an erased epoch cannot be recreated. The UWK blobs and the
    volume wrap are deleted too (hygiene; the counter is what makes them
    useless).
12. **Enrolment** (§8) in 13c is local: `robodr-seal enroll` creates the
    UWK and prints the record (unit, platform, UWK public key, handles,
    epoch, authority and its TPM name). The EK / AK certification and
    credential activation that keep a depot from wrapping to a
    software-emulated TPM are 14a; until then the depot trusts the
    record's channel. **14a:** done (§8, 14a implementation).

**Runtime volume and fallback**

13. **TPM units.** The LUKS2 volume's only keyslot is a random 256-bit key
    stored only wrapped to the UWK (`volume.wrap`, purpose "volume"):
    the same policy, floor and epoch as every content key. Keys reach
    `cryptsetup` on stdin; PBKDF2 at 1000 iterations (the passphrase is a
    uniform random key).
14. **Units without a TPM** (§7.7). `robodr-seal volume format-tang`: a
    random key, `clevis luks bind` to the site's Tang server (thumbprint
    pinned), then the random key's keyslot killed, so the volume key is
    never stored on the unit. The X25519 UWK is a file inside the volume.
    `enroll-fallback` refuses a key directory that is not on a dm-crypt
    mapping. Erase wipes every LUKS2 keyslot (`cryptsetup erase`; the
    device is required, `seal.device`: that wipe is the erase, and it also
    defeats a later Tang recovery of that header) and destroys the UWK file
    when the volume is open; a UWK file that is not present is reported as
    not destroyed.
15. **On the unit** (`robodr-deliverd`, `seal` configuration): a sealed
    RPK and every `model` are installed only under
    `<runtime_root>/<files|model|config>/`, which must be a mounted
    dm-crypt mapping (`volume_check: dm_crypt`, the default: mountinfo
    and `/sys/dev/block/*/dm/uuid`); otherwise the item waits. A chunk is
    hash-checked, authenticated for its place and only then written; the
    content key lives only while a version is staged. A package never
    moves between sealed and public.
16. **Findings.** `robot.seal.unseal_failed` (High) when the TPM refuses
    (PCRs, floor, signature) or the unit was erased; a wrap that does not
    authenticate is a delivery refusal (`robot.deliver.refused`,
    `unauthentic_key`). `robodr-deliverd erase --trigger T` reports
    `robot.seal.erased` (Critical; its text lists what was destroyed and
    whether the runtime volume was closed, suspended or is still open),
    preceded by `robot.seal.tamper` (Critical) for the trigger `tamper`.
    Erase also stops `seal.stop_units`, unmounts the runtime root and
    closes `seal.mapper_name` (§7.6). `robot.seal.lease_expired` is
    catalogued for 14b.

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

**14a implementation** (`robodr-seal enrol-request` / `enrol-activate` on
the unit, `robodr-depot enrol begin|verify|finish|approve|export`;
`robodr_seal::enrol`, `robodr_seal::attest`, `robodr_depot::x509`):

1. `enrol begin`: the depot draws a 32-byte nonce for a unit the trust
   file assigns to a ring.
2. The unit reads its RSA EK certificate (NV `0x01c00002`), creates an AK
   under the EK (`tpm2_createak`, restricted signing, endorsement
   hierarchy) and a unit identity key (UIK, P-256, `fixedtpm`, under the
   SRK: the TLS client and report-signing key), certifies the UWK and the
   UIK with the AK (`TPM2_Certify`) and quotes the signed policy's PCRs
   with the nonce as qualifying data.
3. `enrol verify`: the EK certificate must chain (webpki, EKU checked only
   where present) to a vendor EK CA certificate whose SHA-256 the trust
   file lists (`ek_ca_certs`), and its RSA key must be the EK public area's;
   the certified UWK and UIK must be TPM-resident (`fixedtpm`,
   `fixedparent`, `sensitivedataorigin`, no `userwithauth` on the UWK),
   the UWK's authPolicy must be the site's authority / epoch (and lease
   key) policy computed offline; the quote must match the signed policy.
   The depot then makes a credential (`TPM2_MakeCredential` in software)
   to the EK for the AK's name.
4. `enrol-activate` on the unit (`TPM2_ActivateCredential`): only the TPM
   that holds both keys recovers the secret; `enrol finish` checks it, and
   one wrong answer closes the enrolment.
5. Two distinct operators approve (`enrol approve`); the depot issues the
   unit's client certificate from its unit CA for the UIK
   (`enrol export`).

A unit without a TPM enrols only with `enrolment.allow_without_tpm`, as
`unattested`. Refusals are `robot.depot.enrolment_refused`, success
`robot.depot.unit_enrolled`.

---

## 9. New findings (OCSF catalog additions)

All under the existing findings contract (now `robodr.findings` 2.x). These are emitted by
in-repo components, so each gets its own catalog entry, like the other
in-repo `robot.*` detectors (deployment-specific ids, such as site
`robot.correlate.*` rules, share a generic entry instead). Adding catalog
entries is a contract minor-version bump and needs the validator updated on
both sides of the diode (`docs/contracts/robodr.findings.md`).

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
| `robot.seal.erase_deferred` | Medium | crypto-erase planned but deferred by the safety state (14b) |
| `robot.depot.import_refused` | High | a bundle refused at the depot: entry report, signatures, chain, revocation, floor, depot wrap keys (14a) |
| `robot.depot.enrolment_refused` | High | an enrolment refused: EK chain, credential activation, certification, quote, nonce, lease key (14a) |
| `robot.depot.unit_enrolled` | Low | a unit enrolled after the operator quorum (14a) |
| `robot.depot.rollout_halted` | High | a stage's failures exceeded its threshold; nothing more of the rollout is served (14a) |
| `robot.depot.locked` | Critical | the depot's database is behind its NV-counter anchor (a restored backup or disk image) and refuses to work until re-anchored (14b) |

13b: the seven `robot.deliver.*` ids are catalogued in contract
`robodr.findings` **2.2** (data source `robodr_delivery`) and emitted by
`robodr-deliverd` into agentd's findings spool (both producers claim
record names with no-replace links). `installed` is reported as Low (the
contract has no informational severity); `deferred_safety` is Low and
Medium after a configurable number of deferrals of one item; `stale` is
Medium and High after a grace period; `refused` also reports a state file
restored from the black box. `chain_gap` covers bundles only: deployment
sequence replays and equivocations are `refused` (gaps are normal for a
unit, §3.5 item 27). 13c: the four `robot.seal.*` ids are catalogued in
contract `robodr.findings` **2.3** (data source `robodr_delivery`, in a
block of their own); `unseal_failed` (High), `erased` and `tamper`
(Critical) are emitted by `robodr-deliverd` (§7.9 item 16),
`lease_expired` (Medium) from 14b. 14a/14b: the five `robot.depot.*` ids
and `robot.seal.erase_deferred` are catalogued in contract
`robodr.findings` **2.3.0** in a block of their own (`catalog_2_3_depot`,
data source `robodr_delivery`, `docs/contracts/robodr.findings.md` §3e);
the depot writes its findings into the agentd spool of its own box with
`robodr-deliverd`'s writer, so they leave the site through the same
exporters and diode. `lease_expired` is now emitted (Medium, once per
reason) while a sealed item waits for a lease.

---

## 10. Sprint plan

Splits the Sprint 13 and Sprint 14 bullets in `docs/SPRINTS.md`. Sprint
numbers after 14 are unchanged; this work is split into lettered sub-sprints so
nothing else renumbers.

| Sprint | Deliverable (demo) | Exit criteria |
|---|---|---|
| **13a — Formats and release signing** (implemented, see below) | `robodr-pkg` (RPK, bundle, deployment, trust file parsers, pure, fuzzed); `robodr-release build/sign/verify` with 2-of-N quorum; parity via `robodr-diode` fec. | A bundle built on one host verifies on another; every manifest mutation, missing signature, wrong quorum, revoked key and chain gap is refused in tests; fuzz targets in `fuzz/`. |
| **13b — Unit agent, local** (implemented, see below) | `robodr-deliverd` installing `files`, `config`, `deb`, `robodr-rules` from a per-unit media pack; store; health gate; auto-rollback; floors in a state file; safety-state gate, tested with recorded JSONL safety reports replayed into agentd's live `safety_feed` socket (a small replay helper is new work). | Demo: bad release auto-rolls back; downgrade below floor refused; install deferred while the replayed safety state is `MovingSlow`. All recorded in the black box. |
| **13c — Sealing** (implemented, see below) | `robodr-seal`: XChaCha20-Poly1305 chunks; `UWK` in TPM via `tpm2-tools`; signed PCR policy; erase epoch; LUKS2 runtime volume; Clevis/Tang fallback. Tested against `swtpm`, like `TpmNvCounterAnchor`. | Disk image of an enrolled (swtpm) unit yields no plaintext; changed PCR → unseal refused; epoch increment → every sealed key dead; fallback unit cannot unlock without Tang. |
| **14a — Depot and rollout** (implemented, see below) | `robodr-depot`: import with entry report, inventory, enrolment with credential activation, deployments with operator quorum, rings, per-unit re-wrapping, LAN serving (mTLS), media packs, halt-on-failure. | Demo on ≥ 3 units (VMs with swtpm acceptable): staged rollout lab → canary → ring-1; injected failing release halts at canary; captured-unit VM cannot decrypt a model assigned only to another unit. |
| **14b — Lease, erase execution, evidence** (implemented, see below) | Lease tokens; crypto-erase as the first executed responder action; `robot.deliver.*` / `robot.seal.*` findings through the existing diode; floors moved to TPM NV counters. | Lease expiry blocks unseal after reboot; erase triggered by a simulated tamper input while state is `Idle`, deferred while `MovingFast`; SOC sees the full chain of findings. |
| **14c — OS A/B and hardware** | `os-image` kind with one A/B updater (decision §11); first run on real TPM hardware (not swtpm) and a real robot computer. | A/B OS update with forced boot failure falls back; sealing survives an authorised OS update (new signed policy) and fails for an unauthorised one. |

Each sub-sprint ends, as `docs/SPRINTS.md` requires, in a demo that runs.

**13a status (2026-10-26): implemented; exit criteria demonstrated by
tests, offline.** `crates/robodr-pkg` (pure, `#![forbid(unsafe_code)]`, no
panicking calls outside tests) and `crates/robodr-release` (binary
`robodr-release`), with the decisions of §3.5. What runs:

| Exit criterion | Demonstrated by |
|---|---|
| A bundle built on one host verifies on another | `robodr-release/tests/cross_host.rs`: through the binary, keys generated, trust file root-signed, a 9 MiB RPK (three chunks + SBOM) built and signed by two release keys, a bundle with parity built and signed by two others; only the bundle directory and the trust file are copied to a second tree, which verifies with the pinned root fingerprints and nothing else, commits its chain head, accepts bundle 2, refuses the replay of 1 and the gap to 3, and repairs a deleted chunk from parity. A third tree rebuilds the RPK and gets identical `MANIFEST.json` bytes. |
| Every manifest mutation is refused | `tests/forgery.rs`: every single-byte change (four XOR masks per byte), every truncation and an extension of `bundle.json` and of an RPK's `MANIFEST.json`; byte flips and truncation of every file of the tree on disk. |
| Missing signature, wrong quorum | no `bundle.sig`, an empty set, one release signature, no `MANIFEST.sig`, an unsigned or once-signed RPK, a site with release quorum 3. |
| Revoked key | the bundle's signer revoked by fingerprint (`revoked_key`), and removed from the role (`unknown_key`); revoked RPK digest; site floor above the serial. |
| Chain gap | gap, replay, equivocation, broken link, genesis with bundle 2, a bundle of another programme. |

The self-review found one gap in the first implementation and closed it:
an older, root-signed trust file carried in next to a bundle signed by a
since-revoked key verified under pinned roots; the chain state now pins
the trust file version (§3.5, item 19; `an_older_trust_file_cannot_reopen_a_revoked_key`).
It also bounded directory listings of untrusted media before reading
them whole, and made `keygen` refuse key ids the formats would refuse.
Also tried in the self-review and refused in tests: duplicate signatures
by one key (same id, or the same key under a second id: the trust file
refuses the alias); reordered signature entries, files or RPKs (even
re-signed by the quorum); a swapped chunk, `MANIFEST.json`,
`MANIFEST.sig` or whole RPK directory (also another validly signed RPK of
the same name and serial), an extra RPK; key confusion (a bundle signed
by depot and operator keys or by roots, an RPK-domain signature or a real
`MANIFEST.sig` used as `bundle.sig`, a trust file signed by release keys,
a key in two roles, an HMAC key); traversal paths in a quorum-signed
`bundle.json`, stray files and directories, symlinked chunks,
directories and `bundle.json`, oversized signature files and manifests,
over-long key ids, symlinks / hidden names / setuid modes in a payload;
repair through a symlinked directory, from a forged `bundle.json`, or
with more than `m` damaged files per group. Deployments (format,
depot + operator quorum by ring, freshness, replay) and trust rotation
are unit-tested in `robodr-pkg`. Fuzzing: `pkg_rpk`, `pkg_bundle`,
`pkg_deployment`, `pkg_trust`, `pkg_parity` (results in
`fuzz/README.md`).

**Independent adversarial review (2026-10-26).** A review after the
self-review found nine issues with working PoCs (one high: another
site's trust file signed by the same roots was accepted). All are fixed
and each has a regression test that replays the attack and failed before
the fix; the decisions are in §3.5 ("Review of 13a"). The review's PoCs
were re-run against the fixed binary and each is refused. Fuzz harnesses
and seeds follow the format changes.

Not in 13a: sealed RPKs and wrapped keys (13c), the entry-station scan
and signed entry report (§6.1), anything on a unit (13b) or a depot (14a).
Signing keys are files on the signing station, not HSM-held.

### 13b requirements (from the 13a review)

The formats carry fields that only an installer acts on. The 13a parsers
bound their shape; these rules are requirements on `robodr-deliverd`
(13b) and the depot (14a), not yet implemented anywhere:

1. **Probe argv is not a shell command.** `health[].probe.argv` may hold
   shell metacharacters (`;`, `|`, `$()`, backticks, globs). The agent
   must `execve` the argv directly (absolute `argv[0]`, no shell, no
   `PATH` lookup, a fixed minimal environment) and never join it into a
   string.
2. **Probe user by UID.** `probe.user` is a name; the agent must resolve
   it once to a UID/GID, refuse UID 0 and any UID below the system range
   it is configured for, refuse a name that resolves differently than at
   install time, and drop privileges (setgroups, setgid, setuid) before
   `execve`.
3. **Rollout limits.** `rollout.batch_size` and `rollout.max_failures`
   are unbounded in the format: the depot must cap them against the size
   of the targeted ring (a batch never larger than the ring, a failure
   threshold below it) and the unit must ignore a deployment whose
   rollout would apply to more units than its ring holds.
4. **The unit's own ring.** A unit learns its ring from the trust file
   (`rings`) and enrolment, and refuses a deployment whose `ring` is not
   its own and, for `lab` / `canary`, one that does not name it as a
   unit (no group expansion on the depot's word).
5. **Maintainer scripts.** `install.allow_maintainer_scripts` lets a
   `deb` run root shell; the agent records it in the black box and runs
   such packages only after the safety gate and, if set,
   `requires_operator_present`.
6. **One architecture per package.** A bundle may hold `name` for `all`
   and for `arm64`; the agent installs at most one, preferring the
   unit's architecture, and refuses two different serials.
7. **Install only from verified bytes.** Like `import` (§3.5, item 30),
   the agent installs from its own content-addressed store, filled by
   verifying chunks as they are written, never from media or a
   depot-served path re-read after the check.
8. **Trust anchor and expiry on the unit.** The unit keeps its own trust
   anchor (§3.5, item 25) and refuses an expired trust file; with no
   trusted clock it treats "trust file expired by the depot's clock" and
   "newest deployment expired" as staleness findings (§6.5).

**13b status (2026-10-26): implemented; exit criteria demonstrated by
tests, offline.** `crates/robodr-deliverd` (binaries `robodr-deliverd` and
the test tool `robodr-safety-replay`), `robodr-deliverd.service`
(installed disabled, focal variant), contract `robodr.findings` 2.2. What
runs:

| Exit criterion | Demonstrated by |
|---|---|
| A bad release auto-rolls back | `tests/exit_criteria.rs` `a_bad_release_rolls_back_automatically` (files: health check fails, `current` back to serial 1, failed version removed, `health_failed` High); `tests/kinds.rs` the same with `deb` and the host's dpkg in a separate root (dpkg downgrades back), and with `robodr-rules` whose reload fails |
| Downgrade below the floor refused | `a_downgrade_below_the_floor_is_refused` (floor raised by the installed release, a validly signed and approved lower serial refused `below_floor`); `a_failing_release_that_raised_the_floor_is_not_rolled_back_below_it` (`rollback_blocked_floor` Critical); `adversarial.rs` `a_deleted_state_file_does_not_reopen_a_downgrade` |
| Install deferred while `MovingSlow`, proceeds when `Idle` | `tests/agentd_replay.rs`: a real `robodr-agentd` with a `safety_feed` socket, `robodr-safety-replay` replaying `moving_slow` for 3 s then `idle`; deferred, then installed after the transition, findings in agentd's own spool; `exit_criteria.rs` also every other unsafe state, a stale or absent status, `safe_state_active` |
| All recorded in the black box | every test above reads the delivery journal (`robodr.deliver.*` notes in order: pack imported, staged, deferred, activating, floor raised, switched, health, installed / rollback / rollback blocked, recovered) and verifies its chain with the unit key |

The 13b requirements above, as implemented:

1. Probes: `execve` of the argv (absolute program, no `PATH` lookup), fixed
   environment, `/` as working directory, stdin `/dev/null`; tested with
   `$(...)`, backticks, `;`, `|`, `&&`, globs (`probe_argv_with_shell_metacharacters_is_not_interpreted`).
2. Probe user resolved at staging from the passwd file (files only),
   refused for UID / GID 0, outside the configured range (default
   `1000..=59999`, never a system account; review L2), `root`, `robodr`,
   `robodr-agentd`, `robodr-exec`, configured names, duplicates; resolved
   again before each run; `setgid`, `setgroups(0)`, `setuid` (tested with
   `id`). Own process group killed on timeout, output bounded
   (`a_probe_that_hangs_…`, `a_probe_that_floods_output_is_bounded`);
   since review L1 also rlimits and a subreaper that kills whatever a
   probe leaves behind.
3. Rollout: a deployment whose targets, batch size or failure threshold
   exceed the unit's ring (when the trust file assigns it) is refused.
4. Ring: from the trust file's `rings`, else enrolment (`unit.ring`, a
   production ring only); lab / canary deployments must name the unit;
   groups only for production rings (`a_pack_for_another_unit_ring_or_site_is_refused`).
5. Maintainer scripts: refused unless the release allowed them; the flag
   is recorded; they run only after the gate and the operator
   confirmation.
6. One architecture: items are chosen by digest; the RPK must be the
   unit's architecture or `all`, a `.deb` too; one item per package.
7. Install only from the store, filled from the verified copy with every
   chunk hashed, materialised with every chunk and file hashed again.
8. The unit keeps its own trust anchor (`init-anchor`, rotations only);
   an expired trust file is refused; `trust.clock: untrusted` judges
   expiry on the newest depot-signed time accepted (never beyond the
   trust file's expiry) and reports staleness
   (`with_an_untrusted_clock_expiry_follows_the_depots_signed_time`).

Decisions taken where the design left room:

* **Media pack** (`robodr-media-pack/1`): `trust.json`, `deployment.json`
  (each with `.sig`) and `bundles/<label>/`, nothing else. It has no
  signature of its own; it is per-unit because its deployment names the
  unit (and, from 14a, because of its key wraps).
* **The deployment is the install authority** (exact digests,
  sequence-protected). Bundles chain per programme on the unit for
  detection: a gap is reported (`chain_gap`) and accepted (a unit sees
  only the bundles carrying its packages), an equivocation or a broken
  link refuses the pack, an older bundle is a content source only.
* **The floor is raised before the switch** (in the intent's write), so
  a failing release that raised it has no rollback target below it
  (§6.4: Critical, operator decides). Rollbacks pass the safety gate too.
* **Safety state source**: agentd's status (fresh by `CLOCK_MONOTONIC`,
  this boot, a live `safety_feed`), since the review served by agentd on
  its status socket and accepted only from agentd's own user (§6.3);
  without a live feed the state is `unknown`.
* **Findings share agentd's spool**: agentd and the agent claim record
  names with no-replace hard links (agentd changed from `rename`). The
  agent's records keep agentd's Critical share (red team F1): below
  Critical they stop at 7/8 of `findings.max_ready_files`;
  `rollback_blocked_floor` (and any Critical finding) may use the last
  eighth, up to one source's cap of it.
* **Evidence**: a black-box chain of the agent's own (single-writer
  recorder), signed with the unit's black-box key; a missing or older
  state file is restored from the signed high-water record (and the
  floors noted in the chain) only when the record is current (its
  generation, noted in the chain and the state file); otherwise the unit
  locks (§6.4; review 2, M-A / M-B).
* **Kinds** `files` / `config` (versioned directory, `current` symlink
  swap; `config` only under `config_root`), `robodr-rules` (versions in
  the state directory, one symlink per package in `rules_active`, Pulsar
  rule-file structure checked, optional external validator, reload
  command in the health gate), `deb` (`dpkg-deb` inspection, `dpkg
  --install`, active version by `dpkg-query`).

Also tested: crash at every step of a good and a bad release
(`tests/crash.rs`: the state after the crash and after recovery is one of
the two versions, intent resolved, floor not lowered, outcome as without
the crash); packs for another unit, ring, site or group, rollout over the
ring, platform or architecture; deployments signed by the depot alone,
depot + one operator, operators alone, with release keys; traversal paths
and symlinks in a quorum-signed payload, symlinks in the media, symlinks
in place of install directories, a directory in place of `current`, a
`config` RPK aimed outside its root; replayed and equivocating
deployments and bundles; trust rollback after a rotation; site
revocations; expiry and staleness (Medium, then High); operator
confirmation; maintenance window; a second agent on the same state.
Fuzzing: `deliverd_state`, `deliverd_inputs` (`fuzz/README.md`).

**Independent adversarial review of 13b (2026-10-27).** A code review of
`robodr-deliverd`, the agentd spool change, the units and the packaging
found two high, four medium, four low and one informational issue. All
but M3 (the SOC side) are fixed; each has a regression test in
`crates/robodr-deliverd/tests/review_13b.rs` that failed before the fix
(M2 is driven through the writer's test seam, so it is deterministic).

| Finding | Fix | Regression test |
|---|---|---|
| **H1** The gate trusted any `status.json` of the right shape in a spool the network-facing exporters (`User=robodr`, agentd's user too) could write; they could also write agentd's PLC safety socket | agentd runs as its own user `robodr-agentd` (sysusers; `postinst` moves its trees; units, focal variants, tmpfiles: spool `2750`/queues `2770` setgid `robodr`); agentd serves its status on `spool.status_socket` and deliverd accepts it only from that user or root (`SO_PEERCRED`), a status file only if it and its directory are owned by that user or root and writable by nobody else; agentd's safety socket takes reports only from root, itself and `allowed_uids` / `allowed_gids` (`socket_mode`, `socket_group`, group `robodr-safety`) | `h1_a_forged_idle_status_written_by_another_robodr_service_is_unknown`; agentd `safety::tests::config_validation`, `status_socket_tests` |
| **H2** The dpkg `Package` was never tied to the RPK: another RPK name could downgrade a floored package or replace RoboDR | the RPK `name` / `arch` are the dpkg `Package` / `Architecture` (or `all`); refused: a mismatch, a `Package` owned by another RPK name, a higher serial with a lower dpkg `Version`, a `.deb` that is or conflicts / breaks / replaces / provides `robodr` or `robodr-focal` unless from `install.robodr_programme` (§6.7) | `h2_an_rpk_under_another_name_cannot_downgrade_a_floored_deb`, `h2_robodrs_own_package_is_not_replaced_by_a_deb_rpk`, `h2_a_deb_that_conflicts_with_robodr_is_refused`, `h2_the_deb_architecture_must_be_the_rpks` |
| **M1** Floor recovery depended on cyclic journal notes and restored floors only | signed high-water record (floors, deployment sequence, time floor, chain heads) written before every state write that moves them, never rotated; restored from on a lost state; without it the unit locks until `robodr-deliverd reanchor` | `m1_floors_and_sequence_survive_a_flooded_journal_and_a_lost_state_file`, `m1_a_lost_state_without_a_complete_record_refuses_installs` |
| **M2** Root linked and removed by path in `tmp.deliverd/`, inside a directory agentd's user owns | records written through held directory descriptors: `O_TMPFILE` in `ready/`, `fchown` / `fsync` on the descriptor, no-replace `linkat` from it (fallback: `O_EXCL` hidden name, linked from the descriptor, unlinked relative to `ready/`); `tmp.deliverd/` is gone | `m2_a_swapped_tmp_directory_in_the_spool_is_never_followed` (both paths) |
| M3 AutoSecOps has no catalog 2.2 entries | **open**: SOC-side work (`robodr.findings` 2.2 is fully specified in `docs/contracts/robodr.findings.md` §3a) | — |
| **M4** Kept version directories were named by serial: the same serial with other content overwrote a rollback target | version directories `<serial>-<digest>`; the same serial with other content is refused while installed, kept or in a switch | `m4_the_same_serial_as_a_kept_target_with_other_content_is_refused` |
| **L1** A detached probe's process survived; no probe resource limits | while a probe runs the agent is a child subreaper; leftovers of the probe's UID are killed, reaped and fail it; `RLIMIT_CPU` (timeout + 1 s), `RLIMIT_AS`, `RLIMIT_NOFILE`, `RLIMIT_NPROC` (configurable); `@resources` no longer filtered | `l1_a_probe_that_detaches_fails_and_its_process_is_killed`, `l1_a_probe_runs_under_resource_limits` |
| **L2** System accounts (UID 100–999) could be probe users | default `probe_uid_min` 1000; `robodr-agentd` always denied | `l2_system_accounts_are_not_probe_users_by_default` |
| **L3** With `clock: untrusted` the window used the system clock | the window is judged only on a trusted clock or a signed current time (none in 13b): closed otherwise | `l3_with_an_untrusted_clock_a_maintenance_window_stays_closed` |
| **L4** A refusal was remembered by directory name and `deployment.json` | packs are remembered by the digest of their whole content (oldest evicted first) | `l4_a_corrected_pack_under_the_same_name_is_judged_again` |
| **I1** The deb sandbox is not a boundary; some hardening broke ordinary packages | §6.7 states that release signers are root-equivalent for `deb`; `RestrictSUIDSGID=` dropped, `MemoryDenyWriteExecute=` and `ProtectKernelTunables=` kept with their trade-offs | (documentation, unit files; `scripts/check-focal-units.py`) |

**Second independent review of 13b (2026-10-27).** A second review of
the fixes above found one high, two medium, six low and three
informational issues. All are fixed except L-C (key custody, below) and
M3 (SOC side, unchanged); each fix has a regression test in
`crates/robodr-deliverd/tests/review2_13b.rs` (agentd: in
`crates/robodr-agentd/src/input.rs`) that failed before it.

| Finding | Fix | Regression test |
|---|---|---|
| **H-A** H2 bypass through dpkg relations: a `.deb` under another RPK name with `Replaces` / `Conflicts` / `Breaks` / `Provides` against a floored package took over its files or removed it | relations may name only the RPK's own package (RoboDR's pair only from `install.robodr_programme`); after every `dpkg --install` (and a deb rollback) every other recorded deb package must still be installed at its recorded version (`dpkg-query`), otherwise it is reinstalled and the switch fails; one that cannot be restored is unhealthy with a Critical `rollback_blocked_floor` | `ha_a_deb_with_relations_on_another_package_is_refused` (four relation variants), `ha_an_install_that_changes_another_recorded_package_fails` |
| **M-A** The lock lived only in `state.json`; the first locked start wrote an unlocked record, so deleting `state.json` twice lifted it | `locked` is part of the signed record; a locked start writes a locked record | `ma_the_lock_survives_deleting_the_state_twice` |
| **M-B** An older signed record (or an older `state.json` with the record deleted) was accepted | the record's monotonic `generation` is noted in the journal (`robodr.deliver.highwater`, with the baseline) after every write and in `state.json`; a record older than either, or a missing / invalid record while the state file or the journal exists, locks | `mb_an_older_signed_record_locks`, `mb_an_older_state_and_a_deleted_record_lock`, `mb_an_older_state_with_the_current_record_is_raised` |
| **L-A** `reanchor` did not rebuild the anti-replay baseline and accepted an older trust file with no anchor left | rebuilds the newest deployment, chain heads, time floor and floors from the journal (`pack_imported` now notes expiry and heads); refuses a trust file older than the newest version the journal saw | `la_reanchor_rebuilds_the_sequence_and_chain_heads_from_the_journal`, `la_reanchor_refuses_a_trust_file_older_than_the_journal_saw` |
| **L-B** The documented `reanchor` could not load the key (a systemd credential, present only while the service runs) | `reanchor --key FILE` (root's file, no group / other bits); OPERATIONS §11.3 | `lb_reanchor_takes_the_black_box_key_file` |
| L-C deliverd signs its record with agentd's black-box key | **open** (documented, OPERATIONS §11.4): a compromised agentd could forge a record but cannot write it into place; a key of deliverd's own is a packaging change for 14b | — |
| **L-D** The feeder check saw only the primary gid, so `SupplementaryGroups=robodr-safety` was refused; nothing refused the exporters' group | supplementary groups from `SO_PEERGROUPS` (taken at `connect` like `SO_PEERCRED`: no pid reuse, no `/proc`, which `ProtectProc=invisible` hides); agentd refuses `robodr` as `socket_group` / in `allowed_gids` | agentd `input::tests::a_supplementary_feeder_group_is_accepted`, `safety` section test |
| **L-E** The postinst migration ran with agentd and the exporters running, kept modes, followed hardlinks and ran only while the top directory was unchanged | `migrate_agentd_tree`: services stopped, symlinks / special files removed, hardlinked files replaced by copies, `chown -h` with `find -P -xdev` of old-owner entries only, `go-w` and no setuid / setgid; resumable with a marker | `le_the_postinst_migration_breaks_links_and_normalises_modes` |
| **L-F** The probe reaper gave up after 64 rounds | kills leftovers with their process groups until none is left or 10 s pass, reaping without blocking | `lf_a_deep_chain_of_leftovers_does_not_outlive_the_reaper` (101 processes; 37 survived before) |
| I-B `pack_digest` followed symlinks, could block on a FIFO and hashed without a cap | `O_NOFOLLOW` / `O_NONBLOCK`, same inode as the walk, at most 64 MiB per file and 16 GiB per pack | `ib_pack_digest_caps_the_bytes_it_hashes` |
| I-C Doc inaccuracies; focal drop-ins from old examples hand agentd's credentials to `robodr` | unit headers and OPERATIONS corrected; the focal credential helper hands `robodr-agentd.service`'s credentials to `robodr-agentd` (with a warning); upgrade notes OPERATIONS §11.5 | (`shellcheck`, `scripts/check-focal-units.py`) |
| I (rules) Rule names unique only within one package | also across the active versions of every other installed `robodr-rules` package | `a_rule_name_used_by_another_installed_rules_package_is_refused` |

**Third independent review of 13b (2026-10-27).** A third review found
one high, two low and four informational issues. All are fixed (L-C
stays open as above); each has a regression test in
`crates/robodr-deliverd/tests/review3_13b.rs` that failed before its fix.

| Finding | Fix | Regression test |
|---|---|---|
| **H-R3-1** The H2 floor bypassed through dpkg path aliasing: on merged-/usr a `.deb` under another name shipping `lib/nav/ok` overwrote `/usr/lib/nav/ok` of the floored `nav` (dpkg compares names; nav still `ii 2.0`) | (a) before the switch every path of the `.deb` is resolved through the root's symlinks (within the root) and refused when another package owns it (their file lists resolved the same way) or it is below the agent's trees, RoboDR's install paths, `/etc/dpkg`, `/etc/apt`, `/var/lib/dpkg` or one of the `.deb`'s own symlinks (`debfs.rs`); (b) every `dpkg --install` runs with `--refuse-all`, the needed forces, and `--refuse-overwrite`; (c) after it, every other recorded package's `dpkg --verify` output and `dpkg-query -L` list must be what they were right after its own install (a baseline in the state), otherwise restored and the switch fails | `hr3_a_path_aliased_onto_a_floored_package_is_refused`, `hr3_dpkg_runs_with_explicit_refusals`, `hr3_post_install_verify_catches_changed_content`, `hr3_post_install_file_list_change_is_damage`, `hr3_path_excluded_files_are_part_of_the_baseline` (no false alarm with `path-exclude`) |
| **L-R3-2** A `force-overwrite` in `dpkg.cfg.d` (which a `.deb` could ship) defeated the overwrite check | `--refuse-all` / `--refuse-overwrite` on the command line override it (dpkg reads its configuration first; it has no option to skip it, `--root` does not change where it is read); `.deb`s shipping files under `/etc/dpkg`, `/etc/apt` or `/var/lib/dpkg` are refused | `hr3_l3r2_a_deb_into_protected_paths_is_refused`, `hr3_dpkg_runs_with_explicit_refusals` |
| **L-R3-3** Rotating the black-box key (OPERATIONS §4.3) left deliverd locked with no procedure; deleting `blackbox/deliverd` would discard the anti-rollback history | `robodr-deliverd rekey --old-key --new-key`: verifies the journal and the record with the old key, closes the old journal with a hand-over note, archives it as `<dir>.archived-g<N>`, starts a new journal (first note `robodr.deliver.rekeyed` with the baseline) and record (next generation) under the new key; resumable; OPERATIONS §4.3, §11.3 | `lr3_rekey_carries_the_floors_to_the_new_key` |
| I `Journal::history` did not verify signatures | only records whose hash is right and whose signature verifies with the unit's key count | `info_history_counts_only_notes_signed_with_the_units_key` |
| I The reaper's group kill could reach the agent's own non-probe descendants that a leftover joined | probes run in a session of their own (`setsid`); the reaper kills only groups of a session other than the agent's | `info_the_reaper_never_kills_a_group_outside_the_probe_session` |
| I A recorded package updated by apt was "restored" (downgraded) by the next unrelated deb install | checked before the switch: reported (`robot.deliver.refused`, High, `changed_outside`), deb installs deferred until it is back or a release of it is delivered; never downgraded by the agent | `info_a_package_updated_outside_the_agent_is_reported_not_downgraded` |
| I `pack_digest` hashed up to 16 GiB per pack | 4 GiB by default, `pack_digest_max_mb` (64..=65536) | `info_pack_digest_cap_is_proportionate_and_configurable` |

Not in 13b: sealed RPKs and key wraps (13c), the depot and LAN delivery
(14a), the soak window and attestation in the health gate (14a / Sprint
12), TPM NV floors (14b), OS A/B (14c), the kinds `oci-image`, `model`,
`robodr-profile`, `os-image` (refused), `ros2_node` health checks
(refused: not evaluable on the unit). Nothing has run on a robot.

**13c status (2026-10-30): implemented; exit criteria demonstrated by
tests against a software TPM, offline.** `crates/robodr-seal` (library
and binary `robodr-seal`, `#![forbid(unsafe_code)]`, no panicking calls
outside tests), sealed RPKs in `robodr-pkg` / `robodr-release`, sealed
installs and erase in `robodr-deliverd`, contract `robodr.findings` 2.3;
the decisions are §7.9. What runs, and against what:

| Exit criterion | Demonstrated by | Against |
|---|---|---|
| Disk image of an enrolled unit yields no plaintext | `robodr-seal/tests/exit_criteria.rs` `a_disk_image_of_an_enrolled_unit_yields_no_plaintext`: a sealed RPK (three files, one over two chunks) released, re-wrapped by the depot, unwrapped through the TPM and installed; the unit's storage (store, deployment wrap, seal directory, LUKS2 runtime-volume image formatted with the TPM-wrapped volume key) holds no plaintext, no content key (raw or hex) and no volume key; the seal directory copied to another machine (another provisioned TPM) unseals nothing; the unit booted with a changed PCR unseals nothing; after a power cycle with the legitimate boot it unseals again and the volume key opens the LUKS2 header. `robodr-deliverd/tests/sealed.rs`: the same through the agent (plaintext only below the runtime volume, none in its state, store, media, journal or spool) | swtpm 0.7 + tpm2-tools 5.6 (`ROBODR_SWTPM=1`); `cryptsetup` 2.7 on an image file |
| Changed PCR: unseal refused | `a_changed_pcr_refuses_unseal`: each selected PCR extended refuses (`PolicyAuthorize`), an unselected one does not; a rogue authority's policy for the new values is refused at install and by the TPM; the authority's signed policy for them unseals again (authorised update) | swtpm |
| Epoch increment: every sealed key dead | `an_epoch_increment_kills_every_sealed_key`: three content-key wraps and the volume key refused after one increment; the pre-erase blobs restored from a backup are refused **by the TPM** (its `PolicyNV` step, the unit's own pre-check bypassed); the epoch counter undefined and defined again starts above the erased value, still refused | swtpm |
| Fallback unit cannot unlock without Tang | `a_fallback_unit_cannot_unlock_without_tang`: a LUKS2 image bound only to a real Tang server (bootstrap keyslot killed); unlocks while Tang is up, not when it is down, again when it is back; neither the passphrase nor the UWK is in the unit's storage; erase with the device wipes the keyslots so Tang no longer helps | tangd 14 + clevis 20 + cryptsetup on an image file (`ROBODR_TANG=1`) |

Adversarial tests (`robodr-seal/tests/adversarial.rs`, unit tests in
`src/chunk.rs`, `src/wrap.rs`, `src/rpk.rs`,
`robodr-release/tests/sealed.rs`, `robodr-deliverd/tests/sealed.rs`):
chunk reordering, truncation (by whole chunks and by bytes), moves to
another file, position or RPK, swaps between two sealed copies (another
unit's or release's) and every flipped byte; nonce reuse (a reused key
gives other nonces for other plaintext; a valid chunk with a chosen nonce
is refused); a wrap for another unit, another RPK, another purpose, a
relabelled wrap of another RPK's key (key commitment), every flipped byte
and truncation of a wrap, an X25519 wrap at a TPM unit, low-order X25519
points; **policy rollback**: after a committed boot-chain update the older
signed policy is refused at install and, written in place, by the TPM's
floor check; a commit is refused while the policy in force does not
unseal; the floor and the epoch cannot be undefined without the owner
authorization; **epoch rollback** (restored blobs, redefined counter); a
foreign policy authority refused by the TPM itself; missing policy, TPM
or other handles fail closed; **Tang unreachable**; deliverd: missing,
another unit's, relabelled and tampered wraps, no seal configuration, a
runtime root that is not a mounted dm-crypt device (nothing written), a
TPM unit refusing after a PCR change (`robot.seal.unseal_failed`) and
erasing on `tamper` (`robot.seal.tamper`, `robot.seal.erased`), after
which nothing unseals. Fuzzing: `seal_policy`, `seal_wrap` (std-only
smoke runs; no libFuzzer campaign yet, `fuzz/README.md`).

Found and fixed while testing: bundle listings capped chunk files at
4 MiB, so a full sealed chunk (4 MiB + 40) could not be bundled.

**Adversarial review of 13c (2026-10-30)**, each fix with a regression
test that failed before it (`robodr-seal/tests/review_13c.rs` unless
noted):

* H1 (high): with an empty TPM owner authorization root could undefine and
  redefine the policy floor and revive a revoked policy. `provision`
  refuses unless the owner and lockout authorizations are set, `policy
  commit` refuses while they are empty, `status` warns (§7.9 item 10).
* H2 (high): a unit without a TPM whose runtime volume was closed was
  reported as erased while nothing was destroyed. Its erase is now the
  keyslot wipe (device required), and the report lists exactly what was
  destroyed (§7.9 item 14).
* M1 (medium): erase left the open runtime volume readable. It now stops
  the configured services, unmounts and closes the volume, or suspends it
  (§7.6; `src/luks.rs`, scripted, not on device-mapper).
* M2 (medium): TPM session contexts were written under the persistent seal
  directory and survived a kill. Now tmpfs only, swept (§7.9 item 8).
* L1: `enroll-fallback` refuses a key directory that is not on dm-crypt.
  L2: a successful epoch increment with a failed read-back counts as the
  erase (`src/unit.rs`). L3: the fallback key and the owner-auth file are
  opened with `O_NOFOLLOW` and checked on the descriptor (a race; tested
  for the symlink case only).
* Documented: Tang is stateless (§7.7), equal plaintexts in one RPK share
  their keyed digest (§7.9 item 2), other units' wraps are on a captured
  unit (§7.8), floor exhaustion at version 63 (§7.9 item 10).

**Gated, not run here:** the dm-crypt path end to end
(`plaintext_only_inside_the_mounted_runtime_volume_dm`,
`ROBODR_SEAL_DM=1`: loop device, `cryptsetup open`, ext4, install, raw
image searched): the test container has no device-mapper, so in every
run above the runtime volume was a directory standing in for the mounted
mapping (`volume_check: unchecked`), and LUKS2 was exercised on image
files (format, keyslot test, Clevis bind / pass, erase), never opened.

Not in 13c: EK / AK certification of the UWK and credential activation
(14a, §8), the depot and LAN re-wrapping (14a), the lease (§7.5) and
erase **triggers** executed by `robodr-responder` (14b; 13c erases on an
operator's command), floors moved to TPM NV (14b), OS A/B and a hardware
TPM (14c). No run on a hardware TPM, a robot or with device-mapper.

**14a status (2026-10-30): implemented; exit criteria demonstrated by
tests against software TPMs, offline.** `crates/robodr-depot` (library and
binary `robodr-depot`, `#![deny(unsafe_code)]` with one local allow for
`flock(2)`, no panicking calls outside tests); the 14a members of the trust
file, the entry report and the LAN framing in `robodr-pkg` (`trust.rs`,
`entry.rs`, `wire.rs`); enrolment evidence in `robodr-seal` (`attest.rs`,
`enrol.rs`, `tpm_ident.rs`); the unit side in `robodr-deliverd`
(`lan.rs`); the TPM-held TLS client key in `robodr-blackbox::tls`
(`load_client_with_signer`). Decisions:

1. **Entry report** (`robodr-entry-report/1`, §6.1): written by `robodr-depot
   entry scan` on the entry station, which verifies the bundle like the
   release tool and matches each RPK's CycloneDX SBOM against an offline
   vulnerability database (`robodr-vulndb/1`); signed by an `entry_keys`
   key of the trust file (a new role, disjoint from every other); bound to
   the site, the bundle hash and the RPK list; valid at most 30 days; a
   finding at or above `fail_on` makes the verdict `fail`. Import refuses a
   missing, foreign, expired, failing or wrongly signed report.
2. **Trust file members** `entry_keys`, `depot_wrap_keys`, `ek_ca_certs`
   (format still `robodr-delivery-trust/1`): omitted when empty, so files
   signed before 14a keep their bytes and meaning. With `depot_wrap_keys`
   listed, every station refuses a sealed RPK wrapped to another depot key
   (`wrong_scope`).
3. **Enrolment** as §8 (14a implementation). The depot keeps the AK public
   area, the UIK, the EK digest and the unit record; the operator approvals
   are a `robodr-sigset/1` over the enrolment digest.
4. **Rollouts.** Stages are rings in ascending order starting at `lab` or
   `canary`; a production ring needs a `canary` stage before it; one
   deployment per stage, signed by the depot and active only at the
   quorum of its ring (§5.3). A stage passes when every unit of it
   reported every item installed and healthy, and again at least `soak_s`
   after the first such report; only then does `rollout advance` make the
   next stage. A report with a failed or refused item of the current stage
   beyond `max_failures` (capped below the stage's unit count) halts the
   rollout (its deployment stops being served) until operators resume it
   (a new deployment, approved again) or abort it. Each unit is served the
   newest active deployment that targets it; least distribution with
   `--unit`.
5. **Per-unit re-wrapping**: at stage deployment, for the stage's
   enrolled, non-revoked, non-erased units only.
6. **LAN serving** (`robodr_pkg::wire`, an HTTP/1.1 subset): `GET /v1/pack`
   streams a canonical JSON listing line (paths of the media-pack grammar,
   sizes, SHA-256) and the files; `POST /v1/report` takes a signed unit
   report and answers with a lease. TLS is rustls with mandatory client
   certificates from the depot's unit CA (hand-written X.509 builder,
   checked with webpki); the unit's private key never leaves its TPM
   (`tpm2_sign` behind rustls' signer). A client is a unit only if its
   **key** is an enrolled unit's UIK; the request names no unit, so client
   confusion is not expressible. The unit verifies the stream against the
   listing, then imports it like a media pack. Units pull at most once a
   minute and skip an unchanged pack after the listing.
7. **Single writer**: `flock` on `state_dir/depot.lock`; the server opens
   the depot per request.

| Exit criterion | Demonstrated by | Against |
|---|---|---|
| Staged rollout lab → canary → ring-1 on ≥ 3 units | `robodr-depot/tests/exit_14a.rs` `staged_rollout_halt_at_canary_and_captured_unit`: four units (lab, canary, two in ring-1), each a swtpm with an EK certificate from a local vendor CA, its own seal directory and delivery agent; every unit enrols with credential activation and two operators; the bundle enters only with its passing entry report (none, or another bundle's, refused); each stage is approved by its ring's quorum (one operator does not activate ring-1), delivered over mutual TLS, installed, reported, and advanced only after the stage passed | swtpm 0.7 + tpm2-tools 5.6 (`ROBODR_SWTPM=1`), loopback TLS |
| An injected failing release halts at canary | same test: release 2 is healthy on the lab unit and fails its health check on the canary; the canary's report halts the rollout (`robot.depot.rollout_halted`), `rollout advance` is refused, the ring-1 units still receive release 1's pack | swtpm |
| A captured unit cannot decrypt a model assigned only to another unit | same test: a sealed model deployed to one ring-1 unit (through its canary stage); the other ring-1 unit's LAN pack has no model and no wrap; given the first unit's media pack (every wrap of the deployment), it refuses the pack and its TPM cannot unwrap that unit's wrap; no plaintext of the model anywhere on it | swtpm |

Adversarial tests (`robodr-depot/tests/adversarial_14a.rs`): forged entry
reports (signed by an operator key instead of an entry key), a report
replayed for another bundle, a bundle out of chain order, a failing
verdict (each a `robot.depot.import_refused`); enrolment
impersonation: an EK certificate from a CA the trust file does not list, a
TPM without an EK certificate, a stale nonce, another TPM's certified UWK,
a non-resident (`userwithauth`) UWK-shaped key, the AK of another TPM (the
challenge cannot be answered by either TPM; a guessed answer closes the
enrolment), changed boot measurements, one operator, the same operator
twice, a release key as an operator; a unit whose UWK names a rogue policy
authority; mutual TLS: another unit's certificate with this unit's TPM
key (handshake fails), a CA-signed certificate for a key that is no
enrolled unit's (403), a request naming another unit (400), a report
sent over another unit's connection or replayed (refused), a revoked unit
(403), a client trickling a TLS record to hold a connection slot (closed
at the request deadline); wrong quorum (depot, release and entry keys
never count); ring skipping; a rolled-back depot database (14b anchor).

**14b status (2026-10-30): implemented; exit criteria demonstrated by
tests against software TPMs, offline.** Decisions:

1. **Lease** as §7.5 (14b implementation): `robodr-seal keygen lease`,
   `enroll --lease-key`, `lease install`; the depot's `lease` section
   (`lifetime_s` of TPM time, `reboots`); `robodr-deliverd` installs leases
   from the depot's report answers and from media packs (also a renewed
   lease next to a deployment it already has).
2. **Erase execution** as §7.6 (14b implementation), with
   `robodr-deliverd tamper` as the platform side of the trigger socket.
3. **Findings through the diode**: the unit's `robot.deliver.*` /
   `robot.seal.*` records and the depot's `robot.depot.*` records are
   written into agentd spools and leave through the existing spool
   exporter, diode pack and import; the tests run that path end to end.
4. **Floors in a TPM NV counter** (`robodr-deliverd`
   `seal.anti_rollback_nv`; the depot's `anchor`): the signed record
   (deliverd's `highwater.json`, the depot's database anchor) names the
   counter value it belongs to; a write stores value + 1 first and then
   increments, so a crash between the two is completed on the next start
   and a record behind the counter is a restored older one: the agent
   locks itself, the depot refuses to work (`robot.depot.locked`) until
   `reanchor` by the operator quorum. A record from before the anchor is
   migrated once, while the counter is still unwritten
   (`robodr.deliver.anchor_migrated` in the journal); an undefined or
   redefined counter locks. The counter is defined with the owner
   authorization (`robodr-seal counter define`) and written only by
   increments.

| Exit criterion | Demonstrated by | Against |
|---|---|---|
| Lease expiry blocks unseal after reboot | `robodr-depot/tests/exit_14b.rs` `lease_expiry_blocks_unseal_after_reboot`: a site with leases refuses a UWK enrolled without the lease key; with no lease the sealed model waits (`robot.seal.lease_expired`), the report's answer brings one and it installs; the TPM clock moved past the lease and a reboot: the unit's probe fails with `lease_expired`, and the TPM itself refuses; a renewed lease (LAN, then by media with an unchanged deployment) opens it again. `robodr-seal/tests/lease_14b.rs`: the TPM refuses after the clock or the reboot budget passed, a lease for another unit or by another key, an older lease (replay), a lengthened lease (signature) and setting the clock back | swtpm (`tpm2_setclock`, `Shutdown(CLEAR)` + restart) |
| Erase from a simulated tamper input: `Idle` executes, `MovingFast` defers | `erase_from_a_tamper_input_is_graded_by_safety_and_cannot_be_spoofed`: the tamper line on the trigger socket while agentd's live safety state is `moving_fast`: the keys are destroyed at once (epoch incremented, `robot.seal.tamper`, `robot.seal.erased`, nothing unseals), the runtime volume's lockdown is deferred (`robot.seal.erase_deferred`) across a restart of the agent; `idle`: the lockdown runs (review of 2026-10-30: before it, the whole erase was deferred). Spoofing does nothing: a process of another uid on the socket, a person's trigger (`operator`) on the platform socket, a `robot.seal.tamper` record dropped into the spool | swtpm, a real agentd status socket |
| The SOC sees the full chain of findings | the same tests export the unit's and the depot's spools with `robodr-spool-export`'s exporter into diode batches, carry and import them with `robodr-diode`, and find `robot.seal.lease_expired`, `robot.deliver.installed`, `robot.seal.erase_deferred`, `robot.seal.tamper`, `robot.seal.erased`, `robot.depot.enrolment_refused` and `robot.depot.unit_enrolled` on the far side, validated against contract 2.3 | in-process exporter / diode |
| Floors moved to TPM NV counters | `floors_in_a_tpm_nv_counter_survive_disk_rollback_and_counter_recreation`: a 13b unit (no anchor) migrates to the counter on its next start; a restored disk image (state, black box and record together), a deleted state and black box, and a recreated counter all lock the agent; `adversarial_14a.rs` `a_rolled_back_depot_database_locks_the_depot`: a restored or deleted depot database and a recreated counter lock the depot | swtpm |

**Adversarial self-review of 14a/14b (2026-10-30)**, each fix with a test
that failed before it:

* High: a lease was computed from the TPM clock and reset count the unit
  report **claims**. Root on a unit can have the TPM-resident identity key
  sign any clock, and so get a lease that never runs out before carrying
  the unit away. A TPM unit's report now carries a quote by its AK
  (restricted: it signs only TPM-generated structures; endorsement
  hierarchy, so the reset count is not obfuscated) qualified by the
  report's digest; the depot verifies it with the AK public area kept
  from enrolment and bases the lease on the attested reset count, with
  the reported clock at most 60 s behind the attested one
  (`exit_14b.rs`: a forged clock with the original attestation, without
  one, and with a fresh AK attestation are all refused).
* Medium: the depot's read timeout was per read, so a client trickling one
  byte of a TLS record at a time (no certificate needed) held one of the
  `max_connections` slots indefinitely. The handshake, the request head
  and a report body now share one deadline (30 s, or `deadline_s` if
  shorter) (`adversarial_14a.rs`).
* Medium: a 14a trust file required the three new members, so a trust
  file signed earlier (a unit's stored anchor) no longer parsed after an
  upgrade. They are omitted when empty (`trust.rs`
  `pre_14a_trust_files_keep_their_bytes`).
* Medium: a lease renewed in a media pack next to a deployment the unit
  had already seen was ignored (the pack was skipped as seen). Leases in
  media packs are now read whatever the deployment, once per distinct
  file (`exit_14b.rs`).
* Low: the agent's loop downloaded its whole pack on every pass (every
  `interval_ms`). It now pulls at most once a minute and stops after the
  listing when the pack is unchanged (`exit_14a.rs`). Also: an overflowing
  `lease.lifetime_s` is refused instead of wrapped; the depot no longer
  serves a unit whose report said it was erased.
* Documented, not fixed: the NV anchor detects a **restored older**
  record; root holding the black-box key (it is on the unit) can still
  write a new record with lower floors, as in 13b. A pack being streamed
  holds a connection slot for as long as an authenticated unit keeps
  reading. (Since the TLS review of 2026-10-30, the unit's LAN client
  bounds the whole exchange by one deadline, `depot.deadline_s` plus one
  second per MiB of pack body, and the depot caps connections per source
  address and cuts an unfinished TLS handshake after 10 s.)

**Review of the delivery chain (2026-10-30)**, after the self-review;
each fix with a regression test that failed before it:

* High: `plan_erase` deferred the **whole** erase in `unknown` and every
  moving state, without limit, and the agent went on importing, storing
  wraps, unwrapping and writing plaintext under the keys slated for
  destruction; whoever can keep the safety feed `unknown` (unplug,
  spoof) or the robot moving kept the keys alive. Key destruction now
  runs at once in every state; only the lockdown waits, escalates past
  its cap, and nothing is imported, stored, unwrapped or installed until
  the erase is complete (`robodr-responder` `keys_are_destroyed_in_every_safety_state`;
  `robodr-deliverd/tests/sealed.rs`
  `erase_destroys_keys_in_unknown_state_and_blocks_imports_until_lockdown`).
* Medium: a missing or unverifiable trust anchor left the unit with no
  anchor and silently skipped the site's revocations, floors and trust
  expiry at install; and a **root-set rotation** made the committed
  anchor stop verifying under the configured pins (exact match), which
  produced exactly that state; `commit_anchor` wrote document and
  signature with two renames. A missing or invalid anchor now locks
  imports and installs (High finding); the anchor keeps its accepted
  rotations in one record (`ANCHOR.chain`, `robodr-trust-anchor/1`)
  committed by a single rename, so the pins advance with an accepted
  rotation and a crash cannot tear it (`robodr-release/tests/anchor_rotation.rs`,
  `robodr-deliverd/tests/review_14b.rs`).
* Medium: the depot skipped the AK's time attestation for a report saying
  `erased` and took the report's **claimed** TPM time as the unit's
  high-water mark, so root on a unit could sign `erased` with a huge
  clock: the unit dropped out of stages, packs and mTLS and every later
  genuine report was a "replay", also after re-enrolment (which carried
  `last_report` over). Every attested unit's report now needs the
  attestation, the mark is the **attested** time, and a new enrolment
  starts a new history above its enrolment quote's TPM time
  (`report_floor`), so reports signed before it are not replayed
  (`depot.rs` tests). The `erased` claim itself is still the unit's
  signed statement (no NV certify of the epoch yet).
* Low: `check_ak` was a superset check (`adminWithPolicy` and other bits
  passed, the authPolicy was ignored); the AK is now held to its exact
  template with an empty authPolicy, like the UWK and UIK
  (`attest.rs` `the_ak_must_be_exactly_the_ak_template`).

Fuzzing: `pkg_entry` (entry reports, pack listings, request and response
heads) and `seal_attest` (TPM public areas, attestations, enrolment
requests and challenges, unit reports, leases); std-only smoke runs in
the crate tests with committed seeds (`fuzz/README.md`); no libFuzzer
campaign yet.

**Gated, not run here:** everything above needs `ROBODR_SWTPM=1` (swtpm,
`swtpm_setup` with `swtpm_localca` for EK certificates, tpm2-tools); without
it the TPM tests skip. No vendor EK CA, hardware TPM, real tamper input,
entry station or robot was involved.

Not in 14a/14b: OS A/B and hardware (14c); keys of the depot in its TPM or
an HSM (files today, §5.1); a second depot (§11 item 6); the lease-expiry
erase trigger and a signed remote erase command (§11 item 7); event-log
based attestation (the quote is compared with the signed policy's PCR
values).

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

What Sprint 13c settled or narrowed (§7.9):

* (3) The algorithms are fixed and listed for the export classification:
  XChaCha20-Poly1305, HKDF / HMAC-SHA256, X25519, ECDH and ECDSA on P-256
  (no national algorithms; AES-256-GCM, §7.2's alternative, is not
  implemented). The legal question stays open.
* (4) Narrowed: the TPM commands used (`ECDH_ZGen`, `PolicyAuthorize`,
  `PolicyNV`, `PolicyPCR`, NV counters and bit fields) exist on discrete
  and firmware TPMs alike; parameter encryption protects the bus of a
  discrete TPM. The claims per TPM type remain for 14c on hardware.
* (7) Narrowed: the local mechanism exists (`robodr-deliverd erase`, an
  operator on the unit); a signed remote command is 14b.
* New: **policy authority quorum.** `TPM2_PolicyAuthorize` names one
  signing key, so a PCR policy is signed by one offline P-256 key of the
  delivery roots, not by their quorum. Options: a policy-of-policies
  (`PolicyOR` of several authorities), or signing on an HSM that enforces
  the quorum.
* New: **depot wrapping keys in the trust file.** The release pins the
  depots' X25519 keys itself (`--seal-to`); carrying them in the
  root-signed trust file would let every station check them (a format
  change).

What Sprints 14a and 14b settled or narrowed:

* **Depot wrapping keys in the trust file** (13c's new question):
  resolved. `depot_wrap_keys` in the root-signed trust file; when listed,
  every station refuses a sealed RPK wrapped to another key.
* **EK / AK certification and credential activation** (§7.9 item 12):
  resolved (§8, 14a implementation). EK CAs are accepted by digest from
  the trust file (`ek_ca_certs`).
* (5) Narrowed: the mechanism and its defaults exist (`lease.lifetime_s`
  in TPM powered-on time, `lease.reboots`; the shipped example: 30 days,
  64 reboots); the depot renews with every accepted report, so only the
  depot extends a lease. Per-mission-profile values remain a site
  decision.
* (6) Open: one depot per site.
* (7) Narrowed: platform triggers execute (tamper, attestation failure,
  authentication failures); the plan requires two people for a signed
  command or an operator's erase, but no signed remote command is routed
  to the unit yet, from the depot or the SOC.
* (4) Unchanged: still swtpm only.

---

## 12. Verification plan

Consistent with the rest of the repository: claims are written as "verified"
only after they run.

- Parsers (`robodr-pkg`): unit tests with hostile inputs, `cargo-fuzz` targets
  in `fuzz/`, and std-only fuzz smoke runs in the crate tests, as
  `robodr-blackbox`, `robodr-commission`, `robodr-ocsf` and `robodr-rtps` do.
  (This sentence used to say `robodr-diode`, whose fec code is reused, had
  no fuzz target. That was out of date when 13a started: `diode_fec`,
  `diode_manifest` and `diode_import` exist since S10, `diode_fec`
  checking the encoder and erasure decoder against an independent oracle.
  13a re-ran `diode_fec` under libFuzzer and added `pkg_parity` for the
  bundle-parity use of the code; see `fuzz/README.md`.)
- Sealing: integration tests against `swtpm`; a separate run on hardware TPMs
  before anything is called field-verified.
- Red-team scenarios before 14c exit: image the disk of an enrolled unit;
  boot it with a modified initramfs; replay an old bundle and an old
  deployment; downgrade below the floor; move a media pack to another unit;
  compromise the depot and try to push to `prod`; capture a unit powered on
  and let its lease expire.
- Every result goes into this document's status line and into
  `docs/SPRINTS.md`, including the ones that fail.
