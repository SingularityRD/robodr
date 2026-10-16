# robodr-diode

One-way export of RoboDR findings (`robot-edr.findings`, see
`docs/contracts/robot-edr.findings.md` §8) and black-box evidence bundles from
an air-gapped robot or site console to the SOC (AutoSecOps), across a data
diode or on controlled removable media.

```
 low side (air-gapped)                         high side (SOC)
 ─────────────────────                         ───────────────
 findings ──► Packer ──► outbox/rdd_<unit>_<seq>/ ══ diode / media ══► inbox/
 bundles  ──┘   │                                                    │
                └ pack-state.json                       Importer ◄───┘
                                                          │  ├─► out/<batch>/records.jsonl  ─► Kafka producer
                                                          │  ├─► processed/<batch>
                                                          │  └─► quarantine/<batch> + .reason.json
                                                          └ state.json
```

There is **no network code** here. The diode transfer agent (or a person with
media) moves directories from the outbox to the inbox; a separate producer
publishes `records.jsonl` to Kafka.

## Batch format (`robodr-diode/1`)

One directory per batch, named `rdd_<unit_id>_<seq as 16 digits>`:

| File | Content |
| --- | --- |
| `findings.jsonl` | optional; validated finding values, compact JSON, one per `\n`-terminated line |
| `bundle-0001.rbbx`, … | optional; `robodr-blackbox` export bundles (`RBBXBND1`) |
| `MANIFEST.json` | the manifest; its **raw bytes** are signed and hashed |
| `MANIFEST.sig` | `{format, algorithm, key_id, sig}` (hex signature) |

Manifest fields: `format`, `contract_version` (findings contract, must be
`1.y.z`), `unit_id`, `batch_seq` (1-based, per unit), `prev_batch_hash`
(absent only for seq 1), `created_at` / `created_at_ms`, `key_id`,
`algorithm`, `finding_count`, `first_time` / `last_time` (min/max
`ocsf.time`), `files[] = {name, kind: findings|blackbox_bundle, size, sha256}`.
Unknown fields are rejected.

* Signed message: `"robodr-diode/manifest/v1\0" || MANIFEST.json bytes`.
* Batch hash: `SHA-256("robodr-diode/batch-hash/v1\0" || MANIFEST.json bytes)`.
  It commits to every file (sizes and hashes are in the manifest) and to the
  previous batch, so batch hashes form a per-unit chain.
* Limits: manifest ≤ 128 KiB, signature file ≤ 4 KiB, ≤ 256 files, file names
  `findings.jsonl` / `bundle-NNNN.rbbx` only (allow-list `[a-z0-9][a-z0-9._-]{0,63}`,
  no `..`; separators, absolute paths, NUL, hidden and upper-case names are
  impossible). Packer: data per batch 64 KiB + 1 … 1 GiB (default 16 MiB),
  findings per batch ≥ 1 (default 10 000). Importer: declared data per batch
  ≤ 256 MiB by default.

## Low side: `Packer` / `robodr-diode-pack`

```
robodr-diode-pack --outbox OUT --state pack-state.json --unit ugv-007 \
  --key-id diode-ugv-007 --key-file diode.key \
  --findings findings.jsonl [--bundle export.rbbx]... [--max-batch-bytes N] [--max-findings N]
```

* Every finding is re-validated (`parse_and_validate`, then `to_json`); every
  bundle is parsed. Any invalid input aborts **before** anything is written.
* Publication: stage in `outbox/.tmp-<batch>/` (files `create_new` + `fsync`),
  commit `{next_seq, last_batch_hash}` to the state file atomically, then
  `rename` into the outbox and `fsync` it. **The transfer agent must ignore
  dot-entries.** A crash after the commit leaves a complete staging directory
  that the next `Packer::open` publishes; a crash before it leaves an
  uncommitted one that is discarded. A sequence number is never reused for
  different visible content.
* Refuses a symlinked outbox and never writes through planted symlinks
  (`O_EXCL`/`O_NOFOLLOW` creation, symlinked staging entries abort `open`).

## High side: `Importer` / `robodr-diode-unpack`

```
robodr-diode-unpack --inbox IN --out OUT --quarantine Q --processed P \
  --state state.json --keyring keyring [--partitions 12] \
  [--bundle-key bb-ugv-007:bb.key]... [--accept-gap ugv-007:42]...
```

Keyring file: one `<unit_id> <key_id> <hex-key-file>` per line. Exit code 0
when everything was accepted or a duplicate, 3 when something was quarantined
or held, 1 on error, 2 on usage. The JSON report lists `accepted`,
`duplicates`, `held`, `quarantined` and `in_transit` (dot-entries).

Per inbox entry:

1. Read `MANIFEST.sig` (≤ 4 KiB) and `MANIFEST.json` (≤ 128 KiB) — regular
   files only, never through a symlink (`lstat`, `O_NOFOLLOW|O_NONBLOCK`,
   inode re-check). Verify the signature over the raw manifest bytes with the
   keyring key named in the signature **before** parsing the manifest. The key
   must belong to the manifest's `unit_id`; the directory name must equal
   `rdd_<unit>_<seq>`.
2. Sequence check against `state.json` (per unit: last seq, last hash, the
   last 1024 `(seq, hash)` pairs, accepted gaps):

   | Situation | Result |
   | --- | --- |
   | `seq = last+1`, `prev_batch_hash = last hash` | verify files, accept |
   | `seq = last+1`, other `prev_batch_hash` | quarantine `chain_break` |
   | `seq ≤ last`, same batch hash | duplicate: files verified, moved to `processed/`, nothing re-emitted |
   | `seq ≤ last`, different hash | quarantine `conflict` |
   | `seq ≤ last`, hash unknown (older than window, or in an accepted gap) | quarantine `replay` |
   | `seq > last+1` (or first contact with `seq > 1`) | **held** in the inbox, reported as a gap |
   | same, operator passed `--accept-gap unit:seq` | accept; gap recorded in state |

   Batches are processed in sequence order, so reordered deliveries heal on
   the run after the missing batch arrives.
3. File checks: no entries besides the listed files and the two manifest
   files; each listed file regular, exact size, exact SHA-256 (read capped at
   the declared size). Each findings line is re-validated with
   `robodr_ocsf::parse_and_validate`; count and time range must match. Each
   bundle is parsed; if a black-box verifier for its key id is configured
   (`--bundle-key`), its signatures and chain are verified too.
4. Emit `out/<batch>/` via a staging directory and `rename`: `records.jsonl`
   (one record per line: `{topic, partition, key, headers, value, diode:
   {unit_id, batch_seq, batch_hash, line}}`, same key/partition/headers as
   `robodr_ocsf::record`), the bundles, and copies of the signed manifest and
   signature. Then atomically update the state, then move the batch to
   `processed/`. Re-running after a crash at any point is idempotent.

Anything failing a check goes to `quarantine/<name>` (suffixed `.1`, `.2`, …
if taken) with `<name>.reason.json` (`reason.code`); the state does not
advance, so an intact re-send of the same batch is accepted later.

## Forward-error strategy

A one-way link cannot request retransmission. This crate makes **whole
files and whole batches** the unit of loss and repair: each file is verified
on its own (the reason file names the damaged one), a bad batch never advances
state, and re-sending a batch or the entire outbox history is harmless
(duplicates are recognised by hash; Kafka consumers additionally dedupe on
the deterministic `finding_id` / `event-uid`). Operational recommendation:
send each batch twice (or rely on the diode vendor's FEC), and keep the
outbox until the SOC confirms receipt out of band.

## Honest limits

* **HMAC placeholder.** The only signer available offline is
  `robodr_blackbox::HmacSha256Key`. It is symmetric: the SOC needs the same
  secret to verify, so a compromised SOC (or anyone with the keyring) could
  forge batches, and there is no non-repudiation. Production must plug an
  asymmetric `Signer`/`Verifier` (Ed25519 from an audited crate, or a
  TPM-resident ECDSA key) — the format already carries `algorithm`/`key_id`
  and signatures up to 1024 bytes. The CLIs only load HMAC keys (hex files)
  and warn when a key file is group/other-readable; key distribution,
  rotation and revocation are not implemented.
* **No application-level FEC** (parity/erasure files). Loss of any file
  loses its batch until it is re-sent.
* **Packer state loss** restarts the unit at `batch_seq` 1 with no
  predecessor; the importer then quarantines the new batches (`conflict` /
  `replay`). Recovery is a manual decision: back up `pack-state.json` with the
  black-box key material, or reset that unit's entry in the importer state
  deliberately. Likewise an accepted gap cannot be filled later.
* **Freshness**: a captured old batch replayed into the inbox is recognised
  as a duplicate only while its hash is in the 1024-batch window; older ones
  are quarantined as `replay`, never re-emitted. `created_at` comes from the
  unit's clock and is only range-checked (air-gapped units may have no NTP).
* **Bundle chain continuity** across batches is not tracked here: bundles
  are parsed (and verified individually with `--bundle-key`), but per-chain
  anchors belong in the evidence store (`robodr_blackbox::Receiver`).
* **Single instance**: one packer per state file and one importer per state
  file at a time; there is no lock file. The inbox must be writable (batches
  are moved out of it) and on the same filesystem as `processed/` and
  `quarantine/` (`rename`).
* **Transfer completeness**: the importer treats every non-dot inbox entry
  as complete. If the receiving diode software does not publish atomically,
  an in-flight batch may be quarantined as truncated; the next complete
  re-send is still accepted. Configure the receiver to write into a dot-name
  and rename, or run the importer after the transfer has finished.
* Symlink defences use `O_NOFOLLOW` (Linux x86_64/x86/riscv64/s390x/
  loongarch64/aarch64/arm) plus `lstat` and an inode re-check; on other
  targets only the latter two apply. Directories are not opened with
  `openat`, so an attacker with write access to the *parent* of the inbox
  could still race directory renames; the inbox tree must be writable only by
  the transfer agent and the importer.
* Verified on Linux x86_64 in unit/integration tests only; not exercised
  against real diode hardware or removable-media workflows.
