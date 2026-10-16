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
                ├ pack-state.json (+ .lock)             Importer ◄───┘
                └ pack-state.json.archive/  (resend)      │  (state.json.lock)
                                                          │  ├─► out/<batch>/records.jsonl  ─► Kafka producer
                                                          │  ├─► processed/<batch>
                                                          │  └─► quarantine/<entry>/{entry, reason.json}
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
| `parity-01.rbpar`, … | optional; Reed-Solomon parity files (see *Parity* below) |
| `MANIFEST.json` | the manifest; its **raw bytes** are signed and hashed |
| `MANIFEST.sig` | `{format, algorithm, key_id, sig}` (hex signature) |

Manifest fields: `format`, `contract_version` (findings contract, must be
`1.y.z`), `unit_id`, `batch_seq` (1-based, per unit), `prev_batch_hash`
(absent only for seq 1), `created_at` / `created_at_ms`, `key_id`,
`algorithm`, `finding_count`, `first_time` / `last_time` (min/max
`ocsf.time`), `files[] = {name, kind: findings|blackbox_bundle|parity, size, sha256}` (data
files first, then parity files), and — only in parity batches —
`parity = {scheme, data_shards, parity_shards, shard_size}`. A batch without
parity has no `parity` key at all, so its manifest is byte-identical to the
pre-parity format. Unknown fields are rejected.

* Signed message: `"robodr-diode/manifest/v1\0" || MANIFEST.json bytes`.
* Batch hash: `SHA-256("robodr-diode/batch-hash/v1\0" || MANIFEST.json bytes)`.
  It commits to every file (sizes and hashes are in the manifest) and to the
  previous batch, so batch hashes form a per-unit chain.
* Limits: manifest ≤ 128 KiB, signature file ≤ 4 KiB, ≤ 256 files (≤ 255
  data + parity in a parity batch), file names
  `findings.jsonl` / `bundle-NNNN.rbbx` / `parity-NN.rbpar` only (allow-list `[a-z0-9][a-z0-9._-]{0,63}`,
  no `..`; separators, absolute paths, NUL, hidden and upper-case names are
  impossible). `batch_seq` 1 … 9 999 999 999 999 999 (16 digits).
  Packer: data per batch 64 KiB + 1 … 256 MiB (default 16 MiB), findings per
  batch ≥ 1 (default 10 000). Importer: declared data per batch ≤ 256 MiB by
  default (`--max-batch-bytes`). The packer's ceiling **equals** the
  importer's default, so no packer setting produces a batch that a
  default-configured importer rejects (parity files count against the
  limit on both sides); if you lower the importer's limit,
  lower the packer's `--max-batch-bytes` to match (or below).

### Parity (`rs-gf256-0x11d/1`)

Optional forward error correction for links that lose or damage files
(`--parity M`, default off). The `k` data files of a batch, in manifest
order, and its `M` parity files are the shards of a systematic Reed-Solomon
code over GF(2^8) (reducing polynomial `0x11D`, `α = 2`, generator
`(x-α^0)…(x-α^(M-1))`, `k + M ≤ 255`, `M ≤ 32`) — the code of QR codes,
implemented in std in `src/fec.rs` and tested against published QR
vectors. Byte `o` of every file forms one codeword; data files are
zero-padded to the parity length, which is the largest data file rounded up
to `shard_size` (`--shard-size`, 512 B … 16 MiB, default 64 KiB; the stripe
height). Parity files are listed with size and SHA-256 in the signed
manifest like every other file.

The importer hashes every listed file first. A file that is missing, of the
wrong size or of the wrong SHA-256 is an erasure; **any `M` erasures (data
or parity files) are rebuilt**, each rebuilt file is accepted only if its
size and SHA-256 equal the manifest's (and only after the files it was
rebuilt from re-verify), it replaces the damaged one in the inbox entry
(unique temp `.fec-<pid>-<nonce>-<n>.tmp` + rename; a repair that cannot
create its temp quarantines the batch as `fec_failed` instead of retrying
forever, and a planted `.fec-*` directory is quarantined as an unexpected
file), and then the batch is verified exactly as an undamaged one. The report lists rebuilt files under `accepted[].repaired`.
More than `M` erasures → quarantine `fec_unrecoverable` (`damaged` lists the
files); a rebuild that misses the manifest hash (impossible unless files
change during repair, or the producer wrote parity that does not match its
data) → `fec_failed`, nothing installed. A symlink or directory in place of
a listed file is never "repaired" (it is hostile, not lossy) and fails the
normal checks.

Costs and limits: every parity file is as large as the batch's largest data
file, so `M` parity files cost `M ×` that (counted against
`--max-batch-bytes`); parity is cheapest when a batch holds several similar
files. Recovery granularity is whole files: a batch whose only data file is
lost needs `M ≥ 1` full-size parity files, i.e. it degenerates into
replication. A batch packed with parity is rejected by importers older than
this version (`manifest_invalid`, unknown field) — upgrade the SOC first.

## Low side: `Packer` / `robodr-diode-pack`

```
robodr-blackbox keygen --out diode-ugv-007.key --key-id diode-ugv-007   # once; writes .key + .key.pub
robodr-diode-pack --outbox OUT --state pack-state.json --unit ugv-007 \
  --key-file diode-ugv-007.key [--key-id diode-ugv-007] [--allow-hmac] \
  --findings findings.jsonl [--bundle export.rbbx]... [--max-batch-bytes N] [--max-findings N] \
  [--parity M] [--shard-size BYTES] [--archive-keep N]
robodr-diode-pack resend --outbox OUT --state pack-state.json --unit ugv-007 --seq N
```

* **Single instance**: the packer (and `resend`) takes an exclusive
  `flock` on `<state>.lock` (beside the state file; created 0600, never
  through a symlink, never deleted) for as long as it runs. A second
  instance on the same state file exits 1 with "another robodr-diode-pack
  instance holds …". The kernel drops the lock when the process dies, so
  there is never a stale lock to clean up. The state file must not be inside
  the outbox (its lock and archive would be transferred).
* **Archive and resend**: before a batch is committed, a copy goes to
  `<state>.archive/<batch>/`; the newest `--archive-keep` batches (default
  64, `0` = no archive) are kept. `robodr-diode-pack resend --seq N` (no key
  needed) re-emits batch `N` into the outbox **byte for byte** — same
  manifest, signature, data and parity — for manual retransmission after the
  SOC reports a gap or a quarantine. It first checks that the archived
  manifests from `N` to the newest batch chain to the state's head and that
  every file matches its manifest hash (while copying, via
  `outbox/.resend-<batch>/` and a rename). If an identical copy is already in
  the outbox it does nothing (`already_present: true`); a different entry of
  that name is an error. The importer files a re-delivered batch it already
  has as a duplicate, so resending is always safe. Crash leftovers
  (`.resend-*`, archive temps, archive copies of never-committed batches) are
  removed on the next open.

* **Key**: `--key-file` is a `robodr-blackbox` **secret** key file, Ed25519
  by default (`robodr-blackbox keygen`). It is refused — not merely warned
  about — if it is a symlink, group/other-accessible, or owned by another
  user (root excepted). `--key-id`, if given, must equal the file's id. A
  legacy HMAC key file is refused unless `--allow-hmac` is given, and then a
  warning is printed. Bare hex key files are no longer read.

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
  [--bundle-key ugv-007:bb-ugv-007.key.pub]... [--accept-gap ugv-007:42]... \
  [--max-accept-gap N] [--held-max-age-s N] [--in-transit-max-age-s N] [--allow-hmac]
```

Keyring file: one `<unit_id> <public-key-file>` per line (`#` comments;
relative paths are resolved against the keyring's directory). The older
`<unit_id> <key_id> <key-file>` form still works; the key id must then match
the file's. **The importer holds only public keys**: each entry must be an
Ed25519 *public* key file (`<key>.pub` from `keygen`, or `robodr-blackbox
export-pub`), accepted whatever its mode; an Ed25519 *secret* key file is
refused, so the SOC never holds a key that can sign a batch. Legacy HMAC key
files (secret, 0600, owner-checked) are accepted only with `--allow-hmac`,
with a warning; `--bundle-key UNIT:FILE` (a black-box key for bundle
verification, **bound to UNIT**) follows the same rules.

**Robot allow-list.** By default a unit's batches may only carry findings
whose `entity_context.robot.id` is the unit itself, and bundles whose chain
`device_id` is the unit; anything else is quarantined (`robot_not_allowed`,
`bundle_device_not_allowed`), so a unit's key cannot speak for other robots.
A unit that legitimately exports for others (a site console) gets a keyring
line `robots: <unit_id> <robot_id>...` (library: `Keyring::allow_robot`). A batch signed with an HMAC tag under an Ed25519 key
id is quarantined as `algorithm_mismatch` before any MAC is computed. Exit code 0
when everything was accepted or a duplicate, 3 when something was quarantined
or held or an entry hit an I/O error, 1 on error, 2 on usage. The JSON report
lists `accepted`, `duplicates`, `held`, `quarantined`, `in_transit`
(dot-entries) and `errors` (per-entry I/O failures).

**One bad entry never stops the run.** An I/O error while handling an
entry (e.g. a full `out/` disk) is listed under `errors`, the entry stays in
the inbox for the next run, and the importer carries on with the remaining
entries and units; an entry the importer may not read (permissions) is
quarantined as `unreadable` (or, if it cannot even be moved, listed under
`errors`). Only failing to list the inbox itself fails the run.

**Single instance**: the importer takes an exclusive `flock` on
`<state>.lock` for its lifetime; a second instance on the same state file
exits 1 with "another robodr-diode-unpack instance holds …".

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
   | same, held longer than `--held-max-age-s` (default 30 days, by directory mtime) | quarantine `held_expired` |
   | same, operator passed `--accept-gap unit:seq` | accept; gap recorded in state |
   | same, but the gap skips more than `--max-accept-gap` (default 100 000) batches | quarantine `gap_too_large` |

   Batches are processed in sequence order, so reordered deliveries heal on
   the run after the missing batch arrives. Dot-entries (in transit) older
   than `--in-transit-max-age-s` (default 24 h) are quarantined as
   `stale_in_transit`. `0` disables either expiry.
3. Parity repair (parity batches only; see *Parity* above), then file
   checks: no entries besides the listed files and the two manifest
   files; each listed file regular, exact size, exact SHA-256 (read capped at
   the declared size). Each findings line is re-validated with
   `robodr_ocsf::parse_and_validate` and its robot id checked against the
   unit's allow-list; count and time range must match. Each bundle is parsed
   and its `device_id` checked the same way; if a black-box key with its key
   id is configured (`--bundle-key`) it must be bound to this batch's unit
   (else `bundle_key_unit_mismatch`), and its signatures and chain are
   verified. Files are checked and copied one at a time; findings are read in
   64 KiB chunks (lines ≤ 64 KiB) and their records streamed to the staging
   directory, so memory stays around one bundle / one chunk, not the batch.
4. Emit `out/<batch>/` via a staging directory and `rename`: `records.jsonl`
   (one record per line: `{topic, partition, key, headers, value, diode:
   {unit_id, batch_seq, batch_hash, line}}`, same key/partition/headers as
   `robodr_ocsf::record`), the bundles, and copies of the signed manifest and
   signature. Then atomically update the state, then move the batch to
   `processed/`. Re-running after a crash at any point is idempotent. If
   `out/<batch>/` already exists, its `MANIFEST.json` decides: the same bytes
   → output of an interrupted earlier run, reused; different bytes (e.g. a
   new batch 1 after a deliberate state reset) → this batch is emitted as
   `out/<batch>.<first 16 hex of its batch hash>/`. An accepted batch always
   has its own records on disk; the report's `output` names the directory.

Anything failing a check goes to its own directory `quarantine/<name>/`
(or `<name>.<ns>-<pid>-<n>` if taken) holding the entry as `entry` and the
reason as `reason.json` (`reason.code`). Inbox names therefore cannot
collide with, or masquerade as, reason files, and earlier quarantines can
never exhaust the namespace. The state does not advance, so an intact
re-send of the same batch is accepted later.

## Forward-error strategy

A one-way link cannot request retransmission. This crate makes **whole
files and whole batches** the unit of loss and repair:

1. **Parity** (`--parity M`): up to `M` lost or corrupt files per batch are
   rebuilt on the high side without any back channel.
2. **Resend**: anything worse is quarantined (or held, for a missing batch)
   with a reason naming the damage; the operator re-emits that batch with
   `robodr-diode-pack resend --seq N` and it is accepted on arrival (a bad
   batch never advances state).
3. Re-sending a batch or the entire outbox history is harmless (duplicates
   are recognised by hash; Kafka consumers additionally dedupe on the
   deterministic `finding_id` / `event-uid`).

Operational recommendation: enable parity sized to the link's observed file
loss, keep `--archive-keep` larger than the number of batches produced
between SOC receipt confirmations (out of band), and resend on demand.

## Honest limits

* **Signatures.** Batches are signed with Ed25519 (`robodr_blackbox`'s
  in-crate RFC 8032 implementation: tested against the RFC vectors, **not
  audited**, not verified constant-time). The SOC verifies with public keys
  only, so a compromised SOC or keyring can no longer forge batches; whoever
  holds a unit's secret key file (root on the low side) still can, for that
  unit. HMAC remains available behind `--allow-hmac` for migration, with the
  old limit (symmetric: the SOC could forge, no non-repudiation). Key
  distribution is manual (copy `.pub` files across on vetted media);
  revocation is "remove the line from the keyring"; rotation is "add the new
  public key for the same unit" (several keys per unit are allowed; the
  packer state chains batches across a key change). Keys are files, not
  TPM-held.
* **FEC is erasure-only and file-granular.** Parity rebuilds whole files
  identified as damaged by SHA-256; it does not locate errors on its own,
  and more than `M` damaged files lose the batch until it is resent. The
  Reed-Solomon code is in-crate (tested against QR-code vectors and
  exhaustive small erasure patterns), not a third-party library. Repair
  rewrites the damaged files inside the inbox entry, so the quarantined or
  processed copy holds the rebuilt (manifest-verified) bytes, not the
  damaged originals.
* **Archive** copies are written next to the state file (disk usage ≈
  `--archive-keep` × batch size) and are only as trustworthy as that
  directory: resend verifies them against the state's chain head, which
  catches corruption, but whoever can write the state can also rewrite both.
* **Packer state loss** restarts the unit at `batch_seq` 1 with no
  predecessor; the importer then quarantines the new batches (`conflict` /
  `replay`). Recovery is a manual decision: back up `pack-state.json` with the
  black-box key material, or reset that unit's entry in the importer state
  deliberately (the new batches are then emitted under hash-suffixed `out/`
  names next to the old ones). Likewise an accepted gap cannot be filled
  later.
* **Robot binding** is by id only: a unit key (or a console allowed to
  report on a robot) can still assert anything *about* that robot. The
  allow-list limits which robots a compromised unit key can speak for.
* **Expiry** uses the entry's mtime, which whoever writes the inbox
  controls; it bounds clutter, it is not a security control.
* **Freshness**: a captured old batch replayed into the inbox is recognised
  as a duplicate only while its hash is in the 1024-batch window; older ones
  are quarantined as `replay`, never re-emitted. `created_at` comes from the
  unit's clock and is only range-checked (air-gapped units may have no NTP).
* **Bundle chain continuity** across batches is not tracked here: bundles
  are parsed (and verified individually with `--bundle-key`), but per-chain
  anchors belong in the evidence store (`robodr_blackbox::Receiver`).
* **Single instance** is enforced per *state file* (`flock` on
  `<state>.lock`, advisory, local filesystems; `flock` over NFS depends on
  the server). Two importers with *different* state files on the same inbox
  are not detected — do not configure that. The inbox must be writable (batches
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
