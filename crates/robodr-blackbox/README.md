# robodr-blackbox

Signed, hash-chained black-box evidence recorder for RoboDR (Sprint 9, E1).

The black box is the robot's tamper-evident flight recorder. Every robot
event, deviation and operator note becomes a record. Each record is
hash-chained to its predecessor, bound to a chain identity (device, boot, key)
and signed. Records are stored in append-only segment files. The log survives
crashes, can run as a ring buffer or stop when full, and exports verifiable
bundles through a one-way path. The crate only records and proves what
happened. It never acts on the robot.

Dependencies: std, `serde`/`serde_json`, `robodr-events`. No crypto crates are
available offline, so SHA-256 and HMAC-SHA256 are implemented in `src/crypto.rs`
and pinned to the NIST FIPS 180-4 examples and RFC 4231 test cases 1 to 7.

## Status: Ed25519 is the default; HMAC is legacy

Records are signed with **Ed25519** (RFC 8032, `src/sign_ed25519.rs`) by
default: the unit holds the 32-byte seed, every verifier (fleet console, SOC,
auditor) holds only the public key and **cannot forge** evidence. The
arithmetic is the audited, constant-time `ed25519-dalek` 2.x crate
(`verify_strict`, plus a canonical-encoding check on public keys);
`Ed25519SigningKey` / `Ed25519VerifyingKey` are thin wrappers, so the key
file and signature formats, key ids and verification rules are unchanged
from the earlier in-crate implementation and remain pinned to the RFC 8032
and OpenSSL-derived vectors. The seed is a file on disk, not a TPM-sealed or non-exportable key: root on the
unit can still copy it (see the threat model).

**HMAC-SHA256** (`sign.rs`, `HmacSha256Key`) remains as the legacy
*shared-key* placeholder: anyone who can verify a tag can also forge one. It
is still accepted (old chains, old key files), but `keygen` produces it only
with `--alg hmac`, and the tools warn whenever it is used. The `Signer` and
`Verifier` traits (`src/sign.rs`) are the seam: format, chain, storage and
verifier are the same for both. Signatures are length-prefixed, up to 1024
bytes.

## Keys and the `robodr-blackbox` tool

```
robodr-blackbox keygen     --out FILE [--alg ed25519|hmac] [--key-id ID] [--pub-out FILE]
robodr-blackbox export-pub KEYFILE [--out FILE]
robodr-blackbox verify     DIR --keyring FILE [--keyring FILE]... [--checkpoint FILE]
                           [--device ID] [--strict] [--json]
robodr-blackbox inspect    DIR|SEGMENT [--json] [--limit N]
```

Exit codes: `0` verified intact (warnings allowed unless `--strict`), `1`
verification failed, `2` usage, I/O or key error. Secrets are never taken
from the command line (argv is readable by every process via `/proc`).

- **Key files** (`src/keys.rs`). Format v2 (`robodr-blackbox-key/v2`):
  - secret: `{"format":"robodr-blackbox-key/v2","kind":"secret","algorithm":"ed25519","key_id":"...","public_hex":"...","secret_hex":"<seed>"}`
    (`public_hex` is a consistency check; a mismatch is refused);
  - public: `{"format":"robodr-blackbox-key/v2","kind":"public","algorithm":"ed25519","key_id":"...","public_hex":"..."}`
    (validated: canonical, not of small order).
  Legacy HMAC keys keep format v1
  (`{"format":"robodr-blackbox-key/v1","algorithm":"hmac-sha256","key_id":"...","secret_hex":"..."}`,
  byte-for-byte as before); v2 `kind:"secret"` HMAC files are read too.
  HMAC has no public half. Unknown JSON fields are rejected.
- **`keygen`** draws the seed (or the HMAC key) from `/dev/urandom` (it
  fails rather than fall back), derives `key_id` from the public key
  (`ed25519:<16 hex>`; HMAC: `hmac-sha256:<16 hex>`) unless `--key-id` is
  given, and creates the secret file with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode
  0600, and for Ed25519 the public file `FILE.pub` (or `--pub-out`), mode
  0644. If either target exists nothing is written; it never writes through
  a symlink. It prints only the key id. **`export-pub`** re-derives the
  public file from a secret file (to stdout, or `--out`, never overwriting).
- **Permission rule.** Every load refuses a symlink, a non-regular file and
  files over 256 KiB. A file that holds *secret* material (an Ed25519 seed,
  any HMAC key, a keyring containing either) is also refused if group or
  others have any access (`mode & 0o077 != 0`) or if it is owned by neither
  the effective user nor root. Public key files load whatever their mode.
  `KeyFile::load_public` / `Keyring::load_public_file` refuse secrets
  outright, for verifiers that must never hold signing keys.
- **Keyring** (`Keyring`, file format `robodr-blackbox-keyring/v1`:
  `{"format":"robodr-blackbox-keyring/v1","keys":[<key objects>]}`, any mix
  of public and secret key objects) maps `key_id` to a verifier.
  `Verifier::verify_as(key_id, ..)` picks the key for checkpoints, which
  name their key. Duplicate key ids are refused (nothing from that file is
  added). `verify` prints a warning when the ring holds an HMAC key.
- **API** (additive; nothing renamed): `KeyFile::{generate, generate_ed25519,
  ed25519_from_seed, ed25519_public, kind, is_public, is_symmetric,
  public_key, to_public, ed25519_signing_key, ed25519_verifying_key, signer,
  verifier, load_public, load_secret}`, `keys::{public_key_path, KeyKind,
  KEY_FILE_FORMAT_V2}`, `Keyring::{load_public_file, symmetric_key_ids}`, new
  `KeyFileError` variants (`Owner`, `Ed25519`, `PublicKeyMismatch`,
  `NoPublicKey`, `NoSecret`, `NotPublic`). `KeyFile::secret()` is the seed
  for an Ed25519 secret file and empty for a public one.
- **Rotation**: `Recorder::rotate_key(new_signer, new_verifier, reason)`
  writes a `KeyRotation` record signed by the old key, switches to the new
  key and seals. The chain id keeps binding the first key; later
  `SegmentStart` records name the current key (`signing_key`). After a
  restart, open with `Recorder::open_with_keys(cfg, new_signer, None,
  Some(Box::new(keyring_of_old_keys)), clock)` while segments signed by an
  old key are retained; once they have rotated out, `open` with the new key
  alone works. Verify a log, directory or bundle spanning a rotation with a
  keyring holding both keys (`verify DIR --keyring old.key.pub --keyring
  new.key.pub`). Rotation is also the HMAC-to-Ed25519 migration path.
- **Limit:** `Keyring::verify` (used for records, which do not name their
  key) accepts a signature from *any* key in the ring. Keep one keyring per
  unit (or fleet trust domain). With HMAC every key file is a forging key on
  the verifying side too.

## Usage

```rust
let mut rec = Recorder::open(
    RecorderConfig::new("/var/lib/robodr/blackbox", "ugv-01", boot_id),
    Box::new(signer),                          // impl Signer
    Box::new(SystemClock::new(TimeSource::Gps)),
)?;
rec.append_deviation(&deviation)?;             // critical iff severity >= High (configurable)
rec.append_event(&robot_event, false)?;
let checkpoint = rec.seal()?;                  // ship this off-unit (fleet / TPM NV)
if let Some(bundle) = rec.export_pending(None)? {
    diode.send(&bundle.to_bytes())?;
    rec.mark_exported(&bundle)?;
    rec.prune_exported()?;                     // optional: free exported segments
}

// Anywhere else, with only the files and the verification key:
let report = verify_dir(dir, &verifier, &VerifyOptions { checkpoint: Some(cp), ..Default::default() })?;
assert!(report.is_intact());

// Receiving side of the diode:
let mut rx = Receiver::new(Some("ugv-01".into()));
let report = rx.accept(&Bundle::from_bytes(&bytes)?, &verifier);   // advances only if intact
```

## Format specification (version 1)

### Record

Hashed fields, in this order. All integers are big-endian and fixed width:

| field       | size   | meaning                                                  |
|-------------|--------|----------------------------------------------------------|
| version     | u8     | `1`                                                      |
| chain_id    | 32     | SHA-256 of the chain identity (below)                    |
| seq         | u64    | 0 = genesis, +1 per record, no gaps                      |
| wall_ns     | u64    | ns since Unix epoch; trust depends on `time_source`      |
| mono_ns     | u64    | monotonic ns within one recorder run                     |
| time_source | u8     | 0 unknown, 1 RTC, 2 GPS, 3 PTP                           |
| kind        | u8     | see below                                                |
| flags       | u8     | bit 0 = critical; other bits must be 0                   |
| payload_len | u32    |                                                          |
| payload     | var    | opaque bytes, UTF-8 JSON by convention                   |
| prev_hash   | 32     | `hash` of record `seq-1`; zeros for genesis              |

```
hash = SHA-256("robodr-blackbox/record/v1\0" || hashed_fields)
sig  = Sign("robodr-blackbox/sig/v1\0" || hash)
```

The encoding is canonical by construction. Every field has a fixed width
except the payload, which is length-prefixed, so two different records cannot
produce the same bytes. The payload is hashed **exactly as stored** and is
never re-serialised, so serde_json key order or float formatting can never
change a hash. Parsing is strict: unknown versions, kinds, time sources or
flag bits are rejected, as are trailing bytes. As a result, decoding and
re-encoding a record always gives back the same bytes.

Kinds: `0` Genesis, `1` SegmentStart, `2` Seal, `3` Resume, `4` Recovery,
`5` SegmentDropped, `6` Saturation, `7` SaturationCleared, `8`
TruncationDetected, `9` KeyRotation (control records);
`16` Event (`RobotEvent` JSON), `17` Deviation (`Deviation` JSON), `18` Note
(free-form JSON).

### Chain identity

```
chain_id = SHA-256("robodr-blackbox/chain/v1\0" || lp(device_id) || lp(boot_id)
                   || lp(key_id) || lp(algorithm) || u64(created_wall_ns))
lp(x)    = u32_be(len(x)) || x
```

The genesis record (seq 0) carries the identity in JSON. Every later segment
starts with a `SegmentStart` record that repeats it. Every record carries the
`chain_id`, so every record is bound to the device, to the boot that created
the chain, and to the key. A record copied from another device, boot or
chain therefore shows up as `ForeignChain`. When the recorder reopens an
existing log (process restart or new boot), the chain continues and a
`Resume` record names the current boot.

### Frame and segment

A segment file `seg-<16-digit index>.rbb` is a sequence of frames:

```
frame = "RBF1" | u32 body_len | body
body  = hashed_fields | hash (32) | u16 sig_len | sig
```

**Why length-prefixed binary and not JSONL:** the bytes that are hashed are
the bytes that are stored, so there is no second canonical form to keep in
sync. A torn write is unambiguous because the frame ends early, whereas a cut
JSON line can still parse. Payloads need no escaping. For forensics, records
are rendered on demand (`Record::payload_json`, verifier reports).

After a malformed region, the scanner resynchronises at the next complete,
decodable frame. A corrupted length field therefore cannot hide the records
that follow it.

### Seals and checkpoints

A `Seal` record (with `reason` periodic, rotation, export, shutdown or
manual) is written every `seal_every_records` records and at every rotation,
export and close. Each seal is fsynced. Its `(chain_id, seq, hash, sig)` is a
`Checkpoint`, written atomically to `checkpoint.json`. Every closed segment
ends with a rotation seal.

### Directory

```
seg-0000000000000000.rbb ...   segments
checkpoint.json                latest seal checkpoint
head.json                      high-water mark: Checkpoint of the newest durable record
recovery-pin.json              only between a recovery cut and its Recovery record
export-cursor.json             last exported (chain_id, seq, hash) + unit signature
export-ack.json                last receiver acknowledgement (ack mode)
recorder.lock                  single-writer lock (flock)
quarantine/                    bytes removed by crash recovery (torn-*.bin),
                               damaged closed segments (damaged-seg*.rbb),
                               superseded state files kept as evidence (state-*.json)
```

Stale temp files of the atomic state-file replacement (`.<state>.<hex>.tmp`)
left by a crash are removed at the next open.

Everything the recorder creates is private: directories 0700, files 0600,
created with `O_CREAT|O_EXCL|O_NOFOLLOW`. State files are replaced through a
randomly named temp file and `rename`, so a symlink planted in the directory
is never written through. An existing directory keeps its mode (tightening
it is the integrator's call); the active segment is reset to 0600 on open.

### Bundle (`RBBXBND1`)

```
"RBBXBND1" | u32 id_len | identity JSON | u8 has_anchor
           | [chain_id 32 | seq u64 | hash 32] | u64 frames_len | frames
```

`frames` holds the raw stored frames. The identity is checked against every
record's signed `chain_id`. The anchor (the exporter's cursor) is checked
against the first record's signed `prev_hash`. Neither is trusted on its own.

## Storage behaviour

- **fsync:** `Always`, `Every(n)` or `SealsOnly`. Critical records are also
  fsynced if `fsync_critical` is set (the default). Seals, rotations and
  control records are always fsynced, and the directory is fsynced after
  creating, renaming or deleting files.
- **Opening an existing log:** before chaining onto anything, `open`
  authenticates it with the recorder's own key (`Signer::verify_own`, or the
  verifier given to `open_with_verifier` for keys that cannot self-verify):
  hash, linkage and signature of every record in the active segment, and
  every retained closed segment as described under *Damaged closed
  segments* below. A forged head is `Error::Corrupt`. Segment indices that should exist but do not (a gap, or a
  missing predecessor of the oldest segment with no recorded drop) are listed
  in the `Resume` record and written as `SegmentDropped { missing: true }`.
  `export-cursor.json`, `export-ack.json` and `checkpoint.json` are used only
  if they authenticate and match the chain; rejected ones are listed in the
  `Resume` record (`rejected_state`).
- **Crash recovery:** on open, the last segment is scanned. Crash artefacts
  are copied to `quarantine/`, the file is truncated to the last good frame,
  and a signed `Recovery` record is appended with the offset, length, SHA-256
  of the discarded bytes and the quarantine file name. Recovery is never
  silent. Two cases:
  - an **incomplete frame or a zero-filled tail, with nothing valid after
    it** (torn write): severity medium, verifier **warning**;
  - **zero-filled damage followed by valid frames** (a lost page under
    `SealsOnly`/`Every(n)` while a later page reached disk; the damage holds
    a run of at least 16 zero bytes): the whole suffix is quarantined. The
    record names the authentic records lost with it (`discarded_records`,
    `discarded_seqs`) and those seqs are never reused (the next record jumps
    past them and declares it in `Resume.skipped_seqs`). If nothing after
    the hole was durably synced, a crash explains it: severity high, verifier
    **warning**, and the declared gap is not reported as `Deleted`. If a
    synced record follows (seal, control record, critical record under
    `fsync_critical`, any record under `Always`), it cannot be a crash:
    severity critical, verifier **tamper** (`DamageQuarantined` plus
    `Deleted`). The recorder keeps recording in both cases.

  Anything else in the **active** segment is `Error::Corrupt` and nothing is
  touched: a complete frame whose hash or signature fails without zero
  evidence (a crash cannot produce one, because the hash is computed before
  the frame is written), a record that does not link, non-zero bytes that are
  not a frame. The active segment holds the head the recorder chains onto,
  so it is never "repaired". A write or fsync error poisons the recorder
  until it is reopened, and the reopen recovers the log.

  Before cutting authentic records out of the active segment (the
  zero-hole case), the recorder pins the highest of them in
  `recovery-pin.json` (removed once the `Recovery` record is durable). If
  the process dies between the cut and the record, the next open finds the
  pin beyond the head: `TruncationDetected` (critical), numbering continues
  after it. A plain torn tail has no authentic records to lose; a crash
  between its cut and its record leaves only the `quarantine/torn-*.bin`
  copy.
- **Damaged closed segments (never brick on failing storage):** every
  retained closed segment is verified at open: strict framing, the hash and
  in-segment link of every record, every record's chain id, its first record
  (genesis or its own `SegmentStart`), a final `Seal`, that its last record
  is the one the next retained segment chains onto (`prev_hash`, seq), and
  the signatures of its first and last record and of every
  `SegmentDropped`, `Recovery` and `KeyRotation` record (all signatures with
  `verify_closed_signatures = true`; off by default to keep start-up time
  bounded on large stores: `ed25519-dalek` needs about 25 µs per
  verification on x86-64 in release builds, measured on one host only). A segment that fails is **quarantined**
  and the recorder keeps recording:
  1. its bytes are copied to `quarantine/damaged-seg<idx>.rbb` and fsynced;
  2. a signed, critical `Recovery` record with `quarantined_segment: true`
     names the file, its SHA-256 and size, the count of frames in it with a
     valid hash and this chain's id, the lowest/highest of them whose
     signature verified (`discarded_seqs`), `crash_plausible: false` and a
     severity: `high` only for framing/hash damage (what failing media
     produces) in a segment older than the one the recorder chains onto;
     `critical` for authentic-looking records that do not belong (foreign
     chain, bad signature, broken cross-segment link), for a segment that
     parses cleanly but holds no records or lacks its final seal (frames
     removed on a frame boundary), and for any damaged segment newer than
     the newest intact one;
  3. only then is the original unlinked.

  A crash between 1 and 2 leaves an extra copy in `quarantine/` and the step
  is redone; a crash between 2 and 3 is finished at the next open without a
  second record (the authentic `Recovery` with the same index and SHA-256 is
  found). The verifier reports `SegmentQuarantined` (tamper) plus `Deleted`
  for the lost seqs; older verifiers see `DamageQuarantined`. Seqs are never
  reused: a quarantined segment between retained ones is bounded by its
  successor; if it was the newest closed segment and the active one is
  still empty, the recorder chains onto the newest intact segment before it
  and numbers after the damaged segment's highest authentic seq. A signature
  failure under a key that verifies *no* record in the log is not treated as
  damage (it is a missing `previous_keys` after a rotation): open refuses.
  Open also refuses when the active segment is empty and no closed segment
  is intact (no trustworthy head).

  **Stray segment files** (rev5): if the newest segment file holding
  records does not end with a seal, it is the live segment (a successor is
  created only after a seal is fsynced), and every file above it (empty,
  zeros or garbage) is quarantined the same way as a *critical* stray
  file, instead of turning the live segment into a "closed segment without
  a seal". More than 64 stray files refuse open. Signature work on
  untrusted frames (a damaged segment, the frames after a hole in the
  active segment) is capped at 32 frames from each end; a forged frame
  among those makes the hole not crash-plausible.
  `Recorder::open_incidents()` lists what an open found (quarantines with
  their severity, truncation) for the host to report.
- **High-water mark (`head.json`) and external anchor:** checkpoints exist
  only at seals, so a tail cut after the newest seal used to leave no trace.
  `head.json` is a `Checkpoint` of the newest record (self-authenticating
  through that record's own signature, no extra key operation), rewritten
  atomically every `head_mark_every_records` records (default 16) or, at the
  next append, once `head_mark_interval_ns` (default 1 s, on the records'
  monotonic clock) has passed; also at every seal, at open and close, and on
  demand with `Recorder::mark_head()`. The segment is fsynced first, so a
  mark never names a record a crash can take away. At open: a mark beyond
  the head is truncation (handled like an authentic checkpoint beyond the
  head, below); a mark naming a seq the log holds with another hash refuses
  open (`Error::Untrusted`); a forged or garbled mark is ignored and listed
  in `Resume.rejected_state`. The mark also proves that records up to it
  were synced, so a zero-filled hole before it is not crash-plausible.
  `verify_dir` uses `head.json` in place of `checkpoint.json` when it
  authenticates and is newer. Failed mark writes never fail an append; they
  are counted (`mark_failures()`).

  `RecorderConfig::head_anchor` takes an optional `Arc<dyn HeadAnchor>`
  (`advance(&Checkpoint)`, `current() -> Option<AnchoredHead { chain_id?,
  seq, hash? }>`): e.g. a TPM NV monotonic counter (seq only) or a remote
  receiver (full mark). It receives every mark and is read at open: a seq
  beyond the head is truncation evidence (`external-anchor`), a hash that
  contradicts the log refuses open, a mark of another chain is noted in
  `rejected_state`. Unlike `head.json` it survives rollback or wholesale
  deletion of the directory: a store with **no** segments while the anchor
  holds a mark starts a new chain whose first records declare the gap
  (`Resume` with `skipped_seqs = [1, mark]` and a critical
  `TruncationDetected`), and numbering continues above the mark (a counter
  never goes down). Anchor errors never stop recording
  (`anchor_failures()`, `last_anchor_error()`). `MemoryHeadAnchor` is an
  in-memory reference implementation for tests. `FileHeadAnchor` keeps
  the mark in one file (atomic replace, never decreasing); it is only as
  strong as the storage that file lives on and adds nothing on the log's
  own filesystem. **Deployment requires a TPM NV monotonic counter or a
  remote receiver behind `HeadAnchor`**; those implementations are
  integration work (not done here).

  **Remaining window:** records written after the newest mark and cut with
  the tail leave no local trace and their seqs may be reused: at most
  `head_mark_every_records` records or `head_mark_interval_ns` of recording,
  plus whatever was written since the last append if the recorder then
  idles (call `mark_head()` from a timer to bound that). Unsynced records
  lost in a real crash fall in the same window, which is why it is not
  reported as tampering. Without an external anchor, an attacker who can
  rewrite the directory can also restore an *older* authentic `head.json`
  (they cannot forge a newer one).
- **Truncation evidence:** an authentic `checkpoint.json` or
  `export-cursor.json` naming a seq **beyond** the head proves the tail was
  cut at a frame boundary. The recorder does not brick and does not hide it:
  it copies the state file to `quarantine/state-*.json` (SHA-256 recorded),
  numbers the next record *after* the highest seq that state names (no seq
  is ever reused, so no silent fork), lists the file in
  `Resume.rejected_state` and writes a critical `TruncationDetected` record
  (verifier: `TruncationRecorded` + `Deleted`, tamper). Only then can the
  next seal replace `checkpoint.json`. An authentic checkpoint naming a seq
  the log has, with a different hash, means history was rewritten under the
  chain key: `open` refuses with `Error::Untrusted` and touches nothing.
  `head.json` and the external anchor are checked the same way, and the
  evidence lists every file that proved the cut. A position that the
  quarantined bytes themselves account for is not counted as truncation,
  but only when the damage is crash- or media-plausible (a crash-plausible
  hole in the active segment, a `high` quarantine). A `critical`
  quarantine explains nothing: the state beyond the head still raises
  `TruncationDetected`, whose evidence also lists the authentic records
  beyond the head the quarantine removed (`file` = the segment,
  `preserved_as` = its copy). `verify_dir` honours `recovery-pin.json` and
  `export-cursor.json` the same way open does (an authentic position
  beyond the stored head is `TruncatedTail`).
  Limit: someone who rewrites the newest frame's length prefix makes it look
  torn; the bytes are then quarantined (hash recorded) and the event is a
  warning, not a tamper finding, unless a mark already covered that frame.
  Only an exported checkpoint or the anchor turns that into
  `TruncatedTail`.
- **Single writer:** `open` takes `flock(LOCK_EX|LOCK_NB)` on
  `recorder.lock` before reading or writing anything and returns
  `Error::Locked` if another recorder (in any process, including this one)
  holds it. The kernel releases it when the recorder is dropped or the process
  dies. On non-unix targets there is no lock.
- **Rotation:** when the next record, plus room for two seal frames (a
  periodic seal that may follow it and the rotation or shutdown seal that
  closes the segment), would push the segment past `max_segment_bytes`, the
  recorder writes a rotation seal, creates the next segment and writes
  `SegmentStart` into it.
- **Segment size:** `max_segment_bytes` is a rotation threshold, not a hard
  cap enforced on every write. With signatures of at most 72 bytes
  (HMAC-SHA256: 32, Ed25519: 64) a segment stays within it, *except*:
  (1) a single caller record that does not fit even in a fresh segment (a
  segment always takes one caller record after its header; payloads are
  capped by `max_payload_bytes`); (2) housekeeping records beyond the two
  reserved seals that must go into the current segment: a `Saturation`
  record when no reserve segment is left, extra `seal()` / export seals,
  key-rotation records and their seal, and the resume / quarantine records
  written at `open`; (3) a signer whose signatures exceed 72 bytes (up to
  1024 are accepted), which makes every size estimate low. Each exception
  adds at most one frame per such record. Earlier builds (before the
  two-seal reserve) let every full segment end about one seal frame (about
  200 bytes) past the threshold, e.g. 4291 bytes with
  `max_segment_bytes = 4096`; such logs verify unchanged.
- **Cyclic mode:** this is a ring of `max_segments`. Before the oldest segment
  is deleted, a signed `SegmentDropped` record is written. It names the
  segment, its seq range, the hash of its last record, and whether it had been
  exported. That hash is the carried-forward anchor: the verifier accepts the
  retained tail because a signed record vouches for the head's `prev_hash`.
  The recorder takes the anchor from the authenticated `SegmentStart` of the
  *next* segment (which it wrote itself or verified at open), never from the
  bytes of the segment being deleted, so frames planted there cannot make it
  vouch for anything else. The verifier accepts a drop as covering the head
  only if it names the head segment's index minus one, is not a `missing`
  report, comes later in the chain, and its anchor equals the head's
  `(seq - 1, prev_hash)`.
  If an attacker deletes the oldest segment without that record, the verifier
  reports `HeadMissing`. If a segment vanishes before the recorder deletes it,
  the recorder writes `missing: true` into the drop record.
- **Saturation mode:** once `max_segments` are full, a `Saturation` record is
  written. Non-critical appends are then refused (`Refused(Saturated)`) and
  counted. Critical records go into `critical_reserve_segments` extra segments.
  When those are full too, critical appends return `Refused(Full)` and are
  counted. `prune_exported()` deletes fully exported segments (each deletion is
  recorded) and, if that frees space, writes `SaturationCleared` with the
  refusal counts. The counters are persisted in every `Seal` and `Resume`
  record and restored at open, so the totals survive restarts; refusals
  after the last such record are lost in a crash (`close()` seals them).
- **Store-and-forward:** `export_pending` first writes an export seal, then
  bundles every record after the cursor. `mark_exported` advances the cursor
  (atomic replace) once the bundle has left the unit; the bundle end must be
  an authentic record of the chain, and the persisted cursor is signed by the
  unit's key (domain-separated message), so a forged cursor file is ignored
  and nothing is pruned on its account. Where a return path exists, **ack
  mode** (`require_export_acks(receiver_verifier)`) is stronger:
  `prune_exported` then deletes only what a receiver-signed `Ack`
  (`Receiver::ack`, applied with `apply_ack`) covers. With an asymmetric
  receiver key the unit holds only the public half and cannot fabricate one;
  with HMAC it can, like everything else. `Receiver` verifies each
  bundle against its own last position and advances only when the bundle is
  intact. A skipped bundle shows up as `Deleted`, a replayed one as
  `StaleBundle`, and loss from cyclic wrap before export as
  `DroppedBeforeExport`.

## Verifier diagnoses

`verify_segments(segments, verifier, opts)` and `verify_dir(dir, ...)` return
a `Report`. Each finding has a level (`Tamper` / `Warning` / `Info`) and a
location (segment name and position, byte offset, global position, seq).

| tampering                                  | diagnosis                                   |
|--------------------------------------------|---------------------------------------------|
| record bytes modified                      | `HashMismatch`                              |
| modified and re-hashed, or forged/inserted without the key | `BadSignature`              |
| verifying with the wrong key               | one `KeyMismatch` (not N bad signatures)    |
| record(s) deleted                          | `Deleted { first_missing, last_missing }`   |
| records or segments reordered              | `Reordered { seq, after_seq }`              |
| record replayed / duplicated               | `Duplicate`                                 |
| two different signed records with one seq  | `Fork` (implies key compromise or bug)      |
| record or segment from another device/boot | `ForeignChain`; `WrongDevice` if pinned     |
| substituted record breaking linkage        | `ChainBreak`                                |
| oldest segment deleted without record      | `HeadMissing`                               |
| closed segment truncated                   | `SegmentUnsealed` (+ `Deleted`)             |
| segment file renamed                       | `SegmentIndexMismatch`                      |
| tail truncated after a known checkpoint    | `TruncatedTail`                             |
| history rewritten under a known checkpoint | `CheckpointMismatch`                        |
| garbage bytes / broken frames              | `Malformed`, `TrailingGarbage`              |
| interrupted write never recovered          | `TornTail` (warning)                        |
| tail cut below an authentic local checkpoint/cursor, found by the recorder | `TruncationRecorded` + `Deleted` |
| hole before a synced record, quarantined by the recorder | `DamageQuarantined` + `Deleted` |
| closed segment damaged (bit rot or edit), quarantined by the recorder | `SegmentQuarantined` + `Deleted` |
| tail cut after the newest seal, before the newest mark | `TruncatedTail` (from `head.json`); after reopen `TruncationRecorded` |

`is_intact()` means there are no tamper findings. `is_clean()` means there
are also no warnings. Crash recovery is a warning (the discarded newest
records cannot be told apart from deliberate truncation). Info findings record
normal events: recorded drops, saturation, and an unsealed tail. A
`SegmentMissingReported` (the recorder found a segment gone at open) is a
tamper finding.

## Threat model

**Protects against:**

- **Editing, deleting, inserting, reordering or replaying records** by anyone
  who does not hold the signing key, including someone with full write access
  to the files.
- **Splicing evidence across units or boots.** The chain id binds device,
  boot and key.
- **Silent loss.** Crash recovery, cyclic drops, saturation refusals and pruning
  each leave a signed record.
- **Tail truncation and history rewriting after a checkpoint**, provided the
  checkpoint is held somewhere the attacker cannot rewind. That means the
  fleet (via export) or a TPM NV index / monotonic counter.
- **Tampering in transit.** Bundles are verified independently by the receiver.

**Does not protect against:**

- **An attacker with root on the unit** can read the Ed25519 seed (a 0600
  file, not a TPM-held key) or the HMAC key and rewrite the unit's history
  with valid signatures. With **Ed25519** this needs the unit's secret: a
  fleet verifier, SOC or auditor holding only the `.pub` file cannot forge.
  With **HMAC** every verifier holds a forging key, which is why HMAC is
  legacy and warned about. Non-exportable keys (TPM) would remove key theft
  on the unit. Frequent export plus fleet-side checkpoints bound how much
  history even a live key-holding attacker can rewrite: only what has not
  yet left the unit.
- **Truncation of the newest records with no external anchor.** A
  shortened log is still a valid chain. The local `checkpoint.json` and
  `head.json` help against a crash and an attacker who forgets them, since
  they can be deleted or replaced by older valid ones. Records written after
  the newest mark are never covered locally (see *Remaining window*). Use a
  `HeadAnchor` and export checkpoints.
- **Wholesale deletion** of the log directory or disk, without a
  `HeadAnchor`: detectable only by the receiver (bundles stop arriving or
  show gaps). With an anchor that survives the deletion, the next open
  records it.
- **Lies before recording.** The black box proves what was recorded, not that
  the sensor told the truth. A compromised process with the key can record
  false events.
- **Wall-clock truth.** Timestamps are evidence, not authenticators. The
  time-source tag says how far to trust them. The verifier only warns about
  monotonic regressions within one run.
- **Side channels and memory disclosure.** The in-crate SHA-256/HMAC are
  portable implementations. Key wiping and the constant-time compare use
  `std::hint::black_box`, which is best-effort.
- **Concurrent writers that ignore the lock.** `flock` is advisory: it stops
  a second `Recorder`, not a process that writes the files directly.

## Limits and what is not verified

- The Ed25519 signer wraps the audited `ed25519-dalek` crate (tested here
  against RFC 8032 and OpenSSL-derived vectors); its constant-time
  behaviour has not been re-measured on our target CPUs. TPM integration (sealing the seed, NV-index
  checkpoints) is not implemented; it needs real hardware.
- fsync durability semantics were tested only for logic (torn writes are
  simulated by writing partial or zero bytes). Power-loss behaviour on the
  target filesystem and storage hardware has not been tested.
- Zero-filled damage in the active segment and any damage in a closed
  segment are quarantined and recording continues. Non-zero corruption in
  the **active** segment (a flipped bit from failing storage looks the same
  as tampering), an empty active segment with no intact closed segment, a
  signature failing under a key that verifies nothing, and authentic state
  that contradicts the log still make `open` refuse. Moving the directory
  aside and starting a fresh chain is then an operator decision.
- By default only the first, last and control records of a closed segment
  have their signatures checked at open; a flipped bit inside the signature
  of another record (the hash does not cover the signature) is then not
  quarantined, only reported by the verifier (`BadSignature`).
- Crash safety of rotation, drops, marks, state-file replacement, torn-tail
  recovery and quarantine is tested by fault injection (the process "dies"
  at each step; `src/store_crash_tests.rs`). That models a killed process,
  not lost page-cache writes on power loss, and not a filesystem that
  reorders `rename` against data (ext4 `data=ordered` and the fsync calls
  here are assumed).
- Secret key files hold the Ed25519 seed (or HMAC key) in plain JSON
  (mode 0600, owner = the loading user or root, both checked). Sealing them
  to a TPM is not implemented. Secret buffers are wiped best-effort only.
- `export_pending` reads the retained segments into memory to build a bundle.
  Size bundles with `max_records` on constrained units.
- A segment always takes at least one caller record after its header. A single
  record larger than `max_segment_bytes` therefore produces an oversized
  segment rather than an error. Payloads are capped by `max_payload_bytes`
  (at most 1 MiB).
