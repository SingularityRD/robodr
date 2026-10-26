# robodr-pkg

Pure parsers and validators for RoboDR's secure delivery formats
(`docs/SECURE-DELIVERY.md` §3, Sprint 13a). No I/O: every function judges
bytes it is given and returns a value or a `Refusal` with a stable code.
The release tool (`robodr-release`) and, later, the depot and the unit
agent are its callers.

| Module | Format | What it checks |
| --- | --- | --- |
| `rpk` | `robodr-pkg/1` | RPK manifest: name, serial, kind (closed set), platform / arch, dependencies, security floor, content paths and modes, 4 MiB per-file chunking, SBOM, install options, health checks; release quorum of the programme owning the package; site policy (revoked digest or serial, floor, expiry); content hashes from chunks |
| `bundle` | `robodr-bundle/1` | Bundle manifest: RPKs by digest, every file with size and SHA-256 under a fixed path grammar, parity section; release quorum of its programme, whose packages it must carry; per-programme chain (gap, replay, equivocation, broken link); chain state pinned to the site and trust version |
| `deployment` | `robodr-deployment/1` | Deployment: targets, ring, items, validity window, rollout, maintenance window; depot signature plus operator quorum, the lab quorum only for units the trust file assigns to that lab / canary ring; revoked items and floors; replay by sequence number |
| `trust` | `robodr-delivery-trust/1` | Site trust file: disjoint, torsion-free keys (roots, release, depot, operators), programmes scoping release keys and package names, ring assignment of units, capped quorum floors, revocations by key fingerprint, RPK digest and package serial, floors, expiry; acceptance under pinned roots **and site**; root rotation (the only way an accepted trust moves forward) |
| `sig` | `robodr-sigset/1` | Detached Ed25519 signature sets over domain-separated messages; quorum by distinct key |
| `parity` | `rs-gf256-0x11d/1` | Reed-Solomon parity over bundle files, in groups, with `robodr-diode`'s code |

## Rules every format shares

* **Raw bytes are signed and hashed**, with a domain per document type:

  | Document | Signed message | Digest / hash |
  | --- | --- | --- |
  | `MANIFEST.json` | `robodr-pkg/manifest/v1\0` | `robodr-pkg/digest/v1\0` (the RPK digest) |
  | `bundle.json` | `robodr-bundle/manifest/v1\0` | `robodr-bundle/hash/v1\0` (chain link) |
  | deployment | `robodr-deployment/v1\0` | `robodr-deployment/digest/v1\0` |
  | trust file | `robodr-delivery-trust/v1\0` | `robodr-delivery-trust/digest/v1\0` |

* **One encoding per value.** A document is accepted only if its bytes
  are exactly the compact `serde_json` serialisation of the parsed value:
  members in the declared order, no whitespace, optional members present
  as `null`, sets sorted without duplicates. Unknown members, duplicate
  keys, `1.0` for `1`, escaped printable characters, a BOM or a trailing
  newline are refused (`malformed` / `non_canonical`) before any
  signature is looked at.
* **Hard caps before parsing** (manifest 8 MiB, `bundle.json` 32 MiB,
  trust file and deployment 1 MiB, signature file 8 KiB) and on every
  list. Integers are at most `2^53 - 1`, so any JSON parser reads them
  exactly.
* **Every signature in a set must be valid**: a key the trust file lists,
  of a role allowed for the document, not revoked, verifying under strict
  Ed25519. One bad entry refuses the document. Signers are counted by
  public-key fingerprint, so one key cannot fill a quorum twice.
* **Roles are disjoint**: one key (by fingerprint) has at most one role
  in a trust file. Release keys sign RPKs and bundles; the depot and site
  operators sign deployments; roots sign trust files. Anything else is
  `wrong_role`. Keys must be torsion-free (`robodr-blackbox`), so one
  secret has exactly one fingerprint.
* **Release keys belong to programmes**: a release key of another
  programme than the package's (RPK) or the bundle's refuses the document
  (`wrong_scope`).
* **Trust is pinned by roots and site, and expires.** Anti-rollback of
  trust files is the caller's: keep the last accepted file as an anchor
  and accept newer ones only through `verify_trust_update` (what
  `robodr-release --trust-anchor` does).

## Refusal codes

`too_large`, `malformed`, `non_canonical`, `invalid`, `unsupported`,
`unknown_key`, `wrong_role`, `revoked_key`, `bad_signature`,
`duplicate_signer`, `quorum_not_met`, `revoked_rpk`, `below_floor`,
`expired`, `not_yet_valid`, `digest_mismatch`, `missing_file`,
`unexpected_file`, `file_mismatch`, `chain_gap`, `replay`,
`equivocation`, `chain_broken`, `wrong_scope`. They are the reasons the
planned `robot.deliver.refused` / `robot.deliver.chain_gap` findings
(§9 of the design) will carry.

## Not here yet

* Revocation by digest covers one manifest; the same release re-signed
  into another manifest needs `revoked_serials` or a floor.

* `confidentiality: "sealed"` and deployment `wrapped_keys` are reserved
  for Sprint 13c (sealing) and refused (`unsupported`) until then.
* Nothing installs, stores or serves anything: that is `robodr-deliverd`
  (13b) and `robodr-depot` (14a).

## Tests

* Unit tests per module for every rule (`cargo test -p robodr-pkg`).
* `tests/fuzz_smoke.rs`: std-only runs of the `pkg_rpk`, `pkg_bundle`,
  `pkg_deployment`, `pkg_trust` and `pkg_parity` libFuzzer harnesses
  (`fuzz/harness/`), over seeds signed with the harness site's fixed
  keys, plus checks that the seeds are current and reach the verified
  paths.
* The end-to-end and adversarial tests (forged, reordered, truncated,
  swapped, replayed bundles; a bundle built on one tree verified on
  another) are in `crates/robodr-release/tests/`.
