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

## Status: HMAC is a placeholder

Records are currently authenticated with **HMAC-SHA256**, which is a
*shared-key* MAC. Anyone who can verify a tag can also forge one. Production
must sign with an **asymmetric, non-exportable key**: Ed25519 from an audited
crate, or ECDSA with the private key held in the TPM. The `Signer` and
`Verifier` traits (`src/sign.rs`) are the seam for this change. Implementing
both for the new backend changes nothing else: format, chain, storage and
verifier stay the same. Signatures are length-prefixed, up to 1024 bytes.

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
`5` SegmentDropped, `6` Saturation, `7` SaturationCleared (control records);
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
export-cursor.json             last exported (chain_id, seq, hash)
quarantine/                    bytes removed by crash recovery
```

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
- **Crash recovery:** on open, the last segment is scanned. If it ends in an
  incomplete, zero-filled or invalid frame **and nothing valid follows**, the
  bytes are copied to `quarantine/` and the file is truncated to the last good
  frame. A signed `Recovery` record is then appended with the offset, length,
  SHA-256 of the discarded bytes and the quarantine file name. Recovery is
  never silent. If corruption is followed by valid frames, or a record in the
  active segment fails its hash or linkage, `open` returns `Error::Corrupt` and
  touches nothing. A write or fsync error poisons the recorder until it is
  reopened, and the reopen recovers the log.
- **Rotation:** when the next record would push the segment past
  `max_segment_bytes`, the recorder writes a rotation seal, creates the next
  segment and writes `SegmentStart` into it.
- **Cyclic mode:** this is a ring of `max_segments`. Before the oldest segment
  is deleted, a signed `SegmentDropped` record is written. It names the
  segment, its seq range, the hash of its last record, and whether it had been
  exported. That hash is the carried-forward anchor: the verifier accepts the
  retained tail because a signed record vouches for the head's `prev_hash`.
  If an attacker deletes the oldest segment without that record, the verifier
  reports `HeadMissing`. If a segment vanishes before the recorder deletes it,
  the recorder writes `missing: true` into the drop record.
- **Saturation mode:** once `max_segments` are full, a `Saturation` record is
  written. Non-critical appends are then refused (`Refused(Saturated)`) and
  counted. Critical records go into `critical_reserve_segments` extra segments.
  When those are full too, critical appends return `Refused(Full)` and are
  counted. `prune_exported()` deletes fully exported segments (each deletion is
  recorded) and, if that frees space, writes `SaturationCleared` with the
  refusal counts.
- **Store-and-forward:** `export_pending` first writes an export seal, then
  bundles every record after the cursor. `mark_exported` advances the cursor
  (atomic replace) once the bundle has left the unit. `Receiver` verifies each
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

`is_intact()` means there are no tamper findings. `is_clean()` means there
are also no warnings. Info findings record normal events: recovery, recorded
drops, saturation, and an unsealed tail.

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

- **An attacker with root and the HMAC key** can rewrite the entire history
  with valid tags. The same holds for anyone else holding the key, including
  a fleet verifier. This is the main reason HMAC is a placeholder.
  Asymmetric keys held in the TPM (non-exportable, so they sign but cannot be
  extracted) remove key theft. Frequent export plus fleet-side checkpoints
  bound how much history even a live key-holding attacker can rewrite: only
  what has not yet left the unit.
- **Truncation of the newest records with no external checkpoint.** A
  shortened log is still a valid chain. The local `checkpoint.json` helps only
  against an attacker who forgets it, since it can be deleted or replaced by an
  older valid one. Seal often and export checkpoints.
- **Wholesale deletion** of the log directory or disk. This is detectable
  only by the receiver (bundles stop arriving or show gaps), not on the unit.
- **Lies before recording.** The black box proves what was recorded, not that
  the sensor told the truth. A compromised process with the key can record
  false events.
- **Wall-clock truth.** Timestamps are evidence, not authenticators. The
  time-source tag says how far to trust them. The verifier only warns about
  monotonic regressions within one run.
- **Side channels and memory disclosure.** The in-crate SHA-256/HMAC are
  portable implementations. Key wiping and the constant-time compare use
  `std::hint::black_box`, which is best-effort.
- **Concurrent writers.** One `Recorder` per directory. This is documented but
  not locked.

## Limits and what is not verified

- No asymmetric signer exists yet, and the TPM integration (sealing the HMAC
  key, NV-index checkpoints) is not implemented. Both need real hardware or
  audited crates.
- fsync durability semantics were tested only for logic (torn writes are
  simulated by writing partial or zero bytes). Power-loss behaviour on the
  target filesystem and storage hardware has not been tested.
- If the recorder finds corruption in the middle of the active segment, it
  refuses to open. Moving the directory aside and starting a fresh chain is an
  operator or integrator decision.
- `export_pending` reads the retained segments into memory to build a bundle.
  Size bundles with `max_records` on constrained units.
- A segment always takes at least one caller record after its header. A single
  record larger than `max_segment_bytes` therefore produces an oversized
  segment rather than an error. Payloads are capped by `max_payload_bytes`
  (at most 1 MiB).
