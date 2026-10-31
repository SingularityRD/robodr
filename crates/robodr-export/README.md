# robodr-export

The two hops of the findings path that nothing else moved (contract
`robodr.findings`: `docs/contracts/robodr.findings.md`, §2, §4, §8 and
§8.1):

```
 robot (air-gapped)                                                   SOC
 ──────────────────                                                   ───
 robodr-agentd ─► spool/ready/<seq>.json
                      │ robodr-spool-export
                      ├─► robodr_diode::Packer ─► outbox/rdd_<unit>_<seq>/ ══ diode ══► inbox/
                      └─► spool/acked/<seq>.json (after the batch is durable)      │ robodr-diode-unpack
                                                                                   ▼
                                                   out/<batch>/records.jsonl ─► robodr-kafka-publish ─► Kafka
 connected site: agentd spool/ready/ ─────────────────────────────────────────► robodr-kafka-publish ─┘
                                                   out/<batch>/records.jsonl ─► robodr-uplink ═ HTTPS ═► AutoSecOps
 connected site: agentd spool/ready/ ─────────────────────────────────────────► robodr-uplink ─┘    /robot-edr/v2/ingest
```

Everything is std + RoboDR crates + serde, plus rustls (with the `ring`
provider) for `robodr-uplink`'s TLS. The Kafka producer is a small
in-crate implementation (`src/kafka/`), because no client crate is
available offline. CI tests it against an in-process fake broker; it has
also been run against real Apache Kafka brokers (3.9.1 and 4.1.0,
single-node KRaft in docker) with `scripts/kafka-it.sh`, see *Real-broker
test* and *Limits*.

## `robodr-spool-export` (robot side)

```
robodr-spool-export --spool /var/lib/robodr/spool --outbox /var/lib/robodr/outbox \
  --state /var/lib/robodr/export-state.json --pack-state /var/lib/robodr/pack-state.json \
  --unit ugv-007 --key-file /etc/robodr/diode-ugv-007.key [--key-id ID] [--allow-hmac] \
  [--max-batch-bytes N] [--max-findings N] [--rejected-dir DIR] [--interval-ms 5000] [--once]
```

Key handling is `robodr-diode-pack`'s (`robodr_diode::cli::load_signer`):
an Ed25519 secret key file, mode 0600, owned by the caller; HMAC only with
`--allow-hmac`. Each run prints a JSON report line when it did something.
Exit codes: 0 (`--once` done), 1 (runtime error with `--once`), 2 (usage).
Without `--once` it polls every `--interval-ms` and, after an error,
re-opens the packer and the exporter (which is what recovers a
half-finished batch).

### Protocol

1. List `ready/` (only `<20 digits>.json` regular files), in name order.
   Parse each as agentd's `SpoolRecord`; check `schema`, `seq` (= file
   name), `topic` (= the value's `ocsf.metadata.log_name`), `key` (= finding
   id) and re-validate the value with
   `robodr_ocsf::parse_and_validate`. A failing record is **moved** to
   `<spool>/rejected/` (with `<name>.reason.json`, written durably
   **before** the move, so a crash never leaves a record without its
   reason; a record found without one is dated when noticed, never by its
   spool time). A file that cannot be read (I/O error such as `EACCES` /
   `EIO`, 3 attempts) is quarantined there the same way with the error as
   reason (`quarantined_unreadable`) instead of failing every run. Kept unless
   `--rejected-max-age-s` / `--rejected-max-count` / `--rejected-max-bytes`
   bound it (then the oldest records beyond the bounds are deleted after a
   run, each with its reason file; a rejected record never comes back to
   `ready/`, so nothing needed is lost but its forensic copy).
2. Cut the batch exactly as the packer's planner would (data bytes and
   finding count, parity included), so that one `Packer::pack` call writes
   **one** diode batch. (`--max-batch-bytes` / `--max-findings` set both
   sides; the binary opens with `Exporter::open_checked`, which refuses an
   `ExportConfig` whose limits differ from the `PackConfig`, or a packer
   state of another unit; `Exporter::open` itself refuses limits that
   differ from the packer's own configuration (`Packer::config`). Library
   users: `ExportConfig::for_packer`.)
3. Write the intent `{batch_seq: packer.next_seq, spool_seqs}` to the state
   file (atomic replace).
4. `Packer::pack`: stage, commit the packer state, rename, fsync.
5. Rename every listed record `ready/ → acked/`; fsync both directories.
6. Clear the intent.

| Crash point | On restart |
| --- | --- |
| before 3 | nothing to do; records still in `ready/` |
| after 3, before the packer commit | `packer.next_seq == intent.batch_seq`: intent dropped, records re-packed under the **same** diode sequence (that number was never visible) |
| after the packer commit, before its rename | `Packer::open` publishes the staged batch; then as below |
| after 4 (batch published), before/while 5 | `packer.next_seq > intent.batch_seq`: a record is acknowledged only if its exact packed line is in a committed batch `intent.batch_seq..next_seq` read back from the outbox or the packer archive (`findings.jsonl` checked against `MANIFEST.json` size + SHA-256); proven records are **not** re-packed |
| a split `pack` (limits differ) failing after its first batch | the records of the committed batch(es) are acknowledged, the rest stay in `ready/` (`recovered: "partial"`) |
| committed batch neither in the outbox nor in the archive (`archive_keep = 0`, already transferred) | its records cannot be proven; they stay in `ready/` and are packed again (duplicate, never loss) |
| after 5 | intent cleared or re-acknowledged idempotently (a record already in `acked/`, or pruned from it by agentd, counts as done) |

Every case is a test in `tests/pipeline.rs` (fail points `AfterIntent`,
`AfterPack`, `AfterFirstAck`, and a hand-rewound "committed but not
renamed" outbox), each followed by a diode import that must yield every
finding exactly once; the split-pack cases are in
`tests/review_regressions.rs`.

## `robodr-kafka-publish` (SOC side)

```
robodr-kafka-publish --bootstrap kafka-1:9092 [--bootstrap kafka-2:9092] \
  --state-dir /var/lib/robodr/publish (--diode-out /srv/diode/out | --spool /srv/site/spool) \
  [--topic robodr.findings] [--chunk 500] [--client-id S] [--request-timeout-ms N] \
  [--produce-timeout-ms N] [--delivery-timeout-ms N] [--retries N] [--max-request-bytes N] [--interval-ms 2000] [--once]
```

* **Input.** Diode: every non-dot directory of the importer's `out/`
  (complete by construction: the importer renames it into place) in name
  order, i.e. per unit in sequence order; `records.jsonl` lines are
  `{topic, partition, key, headers, value, diode}`. Spool: `ready/` files of
  a connected site's agentd.
* **Validation.** The value is re-validated (`parse_and_validate`); key and
  headers must equal what `robodr_ocsf::record` derives from the value
  (contract §2: the value is authoritative), and so must the record's
  `topic` (the value's `ocsf.metadata.log_name`). An unsigned contract 1.x
  value (written before an upgrade) is upgraded to contract 2.0
  (`robodr_ocsf::upgrade_legacy`: same identity, `data_source`
  `--upgrade-data-source`, the publisher's topic) and sent as the upgraded
  value with headers derived from it (`legacy_upgraded`); a signed 1.x value
  is dead-lettered with the reason `legacy 1.x signed record: re-sign
  required`. The spool exporter does the same on the robot side (signed 1.x
  records go to `rejected/` with that reason). Records go to the configured `--topic` (default
  `robodr.findings`) whatever topic their producer named; those are counted
  in `topic_overridden`. The **bytes on disk** are what is sent as the
  value.
  A per-finding signature header `robodr-finding-sig` (contract §2a, agentd
  `finding_signing`) is the one exception: it must be the last header, is
  shape-checked (`FindingSignature::from_header_value`) and forwarded
  verbatim; it is verified by the consumer, which holds the unit's finding
  key. `robodr-spool-export` (diode path) does **not** carry it: the diode
  batch format holds values only (contract §8).
* **Partition** = `toPositive(murmur2(robot_id)) % partitions`, with the
  topic's *current* partition count from Metadata (contract §4). An input
  partition computed for another count is overridden (`partition_overridden`
  in the report).
* **Timestamp** (CreateTime) = publish time. A finding delayed for days by
  a diode must not arrive already past a 7-day retention; the finding's own
  time is `ocsf.time` in the value.
* **Commit.** Records go out in chunks of `--chunk`; once a chunk is fully
  acknowledged (`acks=all`), `<state>/progress.json` (format
  `robodr-kafka-publish-state/2`, `{in_flight: {batch: lines_committed}}`)
  is replaced atomically. The offset is kept **per batch**, so a batch
  imported (and published) while another one was half-done does not reset
  it. A finished batch gets `<state>/done/<batch>`, loses its `in_flight`
  entry and is skipped from then on; entries of batches gone from `out/`
  are pruned, and the map is capped at 1024 entries (beyond that the entry
  with the fewest committed lines is dropped: that batch is re-sent, never
  lost). After a crash each batch resumes after its last committed line. A
  version-1 file (`{batch, lines_committed}`) is migrated on open. For a
  spool source the commit is the rename to `acked/`.
* **Idempotent producer** (default; `--no-idempotence` turns it off).
  The producer gets a producer id (InitProducerId v0–1) and numbers every
  batch per partition; a batch whose acknowledgement was lost is re-sent
  exactly as it was and the broker drops the copy. `progress.json` also
  holds `producer: {state: {producer_id, producer_epoch, sequences},
  chunk: {context, positions, journal}}`, replaced **before** every
  Produce request that carries a newly numbered batch. A publisher
  restarted after a crash re-reads the same chunk, restores the producer id
  and sequences, reports the journal's acknowledged batches without sending
  them and re-sends the batch in doubt with its sequence: **no duplicate**
  (`pipeline.rs`, `publisher_crash_after_send_is_deduplicated_by_the_broker`).
  Errors: `DUPLICATE_SEQUENCE_NUMBER` = success;
  `OUT_OF_ORDER_SEQUENCE_NUMBER`, `UNKNOWN_PRODUCER_ID` = the batch was not
  written: on a broker offering InitProducerId v3+ (Kafka 2.5+) an **epoch
  bump** (KIP-360, as the Java client: same producer id, epoch + 1,
  sequences from 0, `epoch_bumps`); a batch of another partition in doubt
  at that moment keeps its numbering under the older epoch, which that
  partition has not seen, so its re-send is still deduplicated (no
  duplicate). `INVALID_PRODUCER_EPOCH`, `PRODUCER_FENCED` (another writer
  ahead on the same id), an older broker or the largest epoch = new
  producer id, sequences from 0, re-send (`producer_id_resets`; a batch of
  another partition in doubt at that moment may then be written twice).
  The epoch is part of the stored `state`; a restart re-sends a batch in
  doubt under an earlier epoch of the same id as it was. A record-level
  error on a batch being **re-sent** after a lost reply also renumbers
  (epoch bump, else new producer id) instead of freeing its sequences (the
  first copy may be in the log; a later batch reusing them would be
  answered as a duplicate, reported delivered and never written);
  InitProducerId `CLUSTER_AUTHORIZATION_FAILED` = fatal, naming the
  `IDEMPOTENT_WRITE` ACL (needed before Kafka 3.0; implied by topic `WRITE`
  since) and `--no-idempotence`. Limits: the broker remembers a producer id
  for `producer.id.expiration.ms` (default one day) after its last write; a
  restart after that, or a chunk that no longer matches its journal (input
  or `--chunk` changed), may write the batch in doubt twice. With
  `--no-idempotence`, at most one chunk per interrupted batch (plus
  whatever a lost Produce response covered) is sent twice, as before.
* **Retention.** After every run: `done/` markers older than
  `--done-max-age-s` (default 30 days; 0 = keep) or beyond
  `--done-max-count` are deleted, but **never while the batch is still in
  `out/`** (the marker is what keeps it from being published again);
  prune `out/` and the markers follow. `dead-letter.jsonl` is **one
  growing file by default and is never deleted**: a dead letter may be
  the only copy of a finding Kafka refused (monitor its size). Rotation is
  opt-in: `--dead-letter-max-bytes N` (≥ 64 KiB; 0 = never, the default)
  keeping `--dead-letter-keep` rotated files (default 4; needs
  `--dead-letter-max-bytes`), optionally also bounded by
  `--dead-letter-max-age-s`; a rotated file over the bounds is then
  **deleted** once none of its entries can still be needed for
  deduplication (diode: its batch is in `out/` without a `done/` marker;
  spool: its file is still in `ready/`), otherwise it is held and reported
  (`pruned_dead_letters.held`). Every deletion of a file holding entries
  is logged on stderr with the count (`pruned_dead_letters.removed_entries`).
  Opt-in, kept by default: `--out-max-age-s` / `--out-max-count` /
  `--out-max-bytes` (diode source) delete the payload (records, bundles)
  of the importer's `out/` batch directories this tool has **finished**
  (its `done/` marker exists; aged by the marker; an unfinished one is
  held, `pruned_out.held`). The directory and its `MANIFEST.json` stay as
  a tombstone (with its `done/` marker): should that unit's import state
  be reset, a different batch under the same name then goes to the
  importer's hash-suffixed name and is published, instead of landing
  under a name already marked done. `--out-max-count` and
  `--out-max-bytes` rank every batch directory that still has a payload,
  finished or not, from the newest (an unfinished one counts against the
  bounds but is held); tombstones are not counted, so `--out-max-count`
  bounds the batches with a payload, not the entries of `out/`. A batch
  whose payload this tool may not delete (typically the importer's
  `out/<batch>/` without write permission for this tool's user: run it
  as the importer's user or give its group write access there), or one
  that cannot even be measured (its payload or `done/` marker cannot be
  read; it is then neither pruned nor counted against the bounds), does
  not stop publishing or delivery: the other batches are pruned, the error
  (path and remedy) is `out_prune_error` in the publisher's JSON report
  and in `uplink-status.json`, and it is logged once while it lasts. Use these flags
  only when this tool is the **only consumer** of `out/` (a second
  publisher or uplink on the same `out/` would lose those batches; the
  importer itself does not need them). `--rejected-max-age-s` /
  `--rejected-max-count` / `--rejected-max-bytes` (spool source) bound
  `<spool>/rejected/` as `robodr-spool-export` does; a record moved there
  by the publisher or the uplink has its reason in the dead-letter file
  and is dated by the first pass that sees it (a `.reason.json` note is
  written then). `robodr-uplink` also takes `--reinject-max-age-s` /
  `--reinject-max-count` / `--reinject-max-bytes`: the `records.jsonl` of
  finished re-injection generations are deleted, their `origin.jsonl` and
  `done` (the ledger that keeps a dead letter from being re-injected
  twice) stay; a record whose original is gone is re-injected from its
  dead letter's `record` copy. Sizes: `state_usage` (`{entries, bytes}` of
  `done_markers`, `dead_letters`, `diode_out` or `spool_rejected`, and
  `reinject` for the uplink) in the publisher's JSON report and in
  `uplink-status.json`, measured at most once a minute (the uplink
  service keeps that pace across its per-run re-opens; the publisher
  prints a report on every run that measured, so at least once a minute
  while idle). Measuring is monitoring: a failed measurement is reported
  as `state_usage_error` until a measurement succeeds (in every publisher
  report line and in the status file, which keeps the last good
  `state_usage`) and logged once, and never fails a run. Deletions are
  single `unlink`s plus a directory fsync (an `out/` payload loses its
  records file first; a pass interrupted after that is completed by the
  next one): crash-safe at any point.
* **Dead letters.** A record that fails validation, or that Kafka rejects
  as a record (`MESSAGE_TOO_LARGE`, `RECORD_LIST_TOO_LARGE`,
  `INVALID_RECORD`), is appended to `<state>/dead-letter.jsonl`
  (`{source, position, reason, record, at_ms}`) and skipped (spool source:
  moved to `<spool>/rejected/`). A spool file that cannot be read (I/O
  error, 3 attempts) is dead-lettered with the error and moved there too
  (`quarantined_unreadable`; the file is kept, move it back to `ready/` to
  re-drive). `INVALID_TIMESTAMP` is **not** a record error: the publisher
  stamps every record with its own clock, so it means that clock is off
  (Kafka 4.0 refuses CreateTime more than 1 h ahead by default); the run
  fails with "check the clock" and is retried, nothing is dead-lettered. Entries are
  deduplicated on `(source, position)`, so a chunk re-processed after a
  crash does not append its dead letters again (the index is read from the
  current and rotated files on the first dead letter of a run; 16 bytes per
  entry). Any other
  Kafka error stops the run without committing; the next run retries.

## `robodr-uplink` (ingest API, connected site or SOC side)

```
robodr-uplink --url https://soc.example.org/api --key-file /etc/robodr/keys/uplink.key \
  --ca-bundle /etc/robodr/uplink-ca.pem [--spki-sha256 HEX ...] --state-dir /var/lib/robodr/export/uplink \
  (--spool /var/lib/robodr/spool/agentd | --diode-out /srv/diode/out) [--max-lines N] [--max-body-bytes N] \
  [--connect-timeout-ms N] [--request-timeout-ms N] [--max-attempts N] [--backoff-base-ms N] \
  [--backoff-max-ms N] [--refused-backoff-max-s 900] [--exit-when-stuck-s N] \
  [--dead-letter-max-bytes 67108864] [--dead-letter-keep 4] [--dead-letter-max-age-s N] \
  [--done-max-age-s 2592000] [--done-max-count N] [--upgrade-data-source L] \
  [--upgrade-topic T] [--interval-ms 2000] [--once]
robodr-uplink reinject --state-dir DIR (--spool DIR | --diode-out DIR) --dead-letter FILE [...] \
  [--codes unknown_robot,robot_mismatch,site_mismatch,missing_finding_signature,bad_finding_signature] \
  [--dry-run]
```

The producer of the `robodr.ingest` HTTP API, contract v1
([`docs/contracts/robodr.ingest-api.md`](../../docs/contracts/robodr.ingest-api.md)):
`POST {url}/robot-edr/v2/ingest`, NDJSON lines
`{"value":"<finding, verbatim>","sig":null|{...}}`, signed per batch with
an Ed25519 key file. Code: `src/uplink/` (`wire.rs` contract pieces,
`http.rs` transport, `mod.rs` delivery, `service.rs` the loop and status,
`reinject.rs` re-injection), `src/deadletter.rs` (dead-letter files, shared
with `robodr-kafka-publish`), binary `src/bin/robodr-uplink.rs`.

* **Input and validation** are `robodr-kafka-publish`'s (shared code in
  `publish.rs`: `check_record`, the spool and `records.jsonl` readers): the
  value is re-validated, key / topic / headers must be what the value
  derives, unsigned contract 1.x is upgraded, signed 1.x is refused. A
  record that fails is dead-lettered with code `local` and never sent; so
  is a spool file that cannot be read (I/O error, 3 attempts; moved to
  `rejected/`, `quarantined_unreadable`) instead of failing every run.
* **Per-finding signatures.** A spool record's `robodr-finding-sig` header
  (agentd `finding_signing`, contract `robodr.findings` §2a) becomes the
  line's `sig` (shape-checked, re-serialised in the header's own compact
  form). The diode path has none: `findings.jsonl` carries values only and
  the importer's `records.jsonl` has derived headers only (contract §8,
  open item), so `--diode-out` lines are `"sig":null`; the SOC registers
  that sender as a `relay` key and relies on the diode batch signature the
  importer verified.
* **Key.** An Ed25519 secret key file (`robodr-blackbox keygen`, without
  `--key-id`: the contract identifies keys by the derived
  `ed25519:<16 hex>`; another id, a public key file or an HMAC key is
  refused). The role (`uplink` for one robot, `relay` for the workspace) is
  the server's registry entry; the client only signs.
* **Batches.** Records in input order, at most `--max-lines` (≤ 1000) lines
  and `--max-body-bytes` (1–4 MiB) per batch; a diode batch is never mixed
  with another.
* **Batch id** (`wire::batch_id`):
  `"rdu1-" + hex(SHA-256("robodr-uplink/batch-id/v1" 0x00 ‖ u32be(len(source)) ‖ source ‖ u32be(n) ‖ u64be(pos_1) … u64be(pos_n) ‖ SHA-256(body)))[0..32]`,
  `source` = `spool` or `diode:<batch dir>`, `pos_i` = spool seq / line
  number of body line `i`. Deterministic in the input positions and the
  body: the same records re-cut after a crash give the same id, so the
  server answers from its replay store (`replayed: true`, nothing processed
  twice); a different body can never reuse an id (the server's stored
  response numbers *that* body's lines, and the producer acknowledges by
  line number). To make the re-cut identical even when new records arrived
  meanwhile, the batch is persisted before it is sent (below).
* **State** `<state>/uplink-state.json` (atomic replace,
  `robodr-uplink-state/1`): committed line count per diode batch (bounded
  map, as the Kafka publisher) and at most one **pending** batch
  `{batch_id, source, last, positions, body_sha256, result}`.

### Delivery protocol

1. Cut a batch (dead-lettering locally invalid records on the way; spool:
   moved to `rejected/`). Save `pending` (no result).
2. `POST` with the five contract headers; `X-RoboDR-Timestamp` and the
   signature are fresh for every attempt, body and batch id never change.
   Retry network errors, `408`, `429` and `5xx` up to `--max-attempts` per
   run, waiting a random time in `[d/2, d]`, `d = min(max, base·2^(k-1))`,
   but never less than `Retry-After` (delay-seconds, honoured in full up to
   24 h; a larger value, or one too long for a `u64`, counts as 24 h —
   contract §7). When the run's last attempt carried a `Retry-After`, the
   run fails with it (`UplinkError::GaveUp { retry_after }`) and the
   service waits at least that long before the next run.
3. A `200` is accepted only if it names this batch id and accounts for every
   line exactly once (`accepted = created + updated + duplicates`,
   `accepted + rejected = lines`, lines in range, valid codes); otherwise
   nothing is acknowledged (`Protocol` error).
4. Save the rejected lines into `pending.result`; append them to
   `<state>/dead-letter.jsonl` (`{source, position, code, reason, batch_id,
   record, at_ms}`, deduplicated on (source, position) over the current
   and rotated files; fsynced; a line torn by a crash is closed before the
   next append and counted as malformed, `dead_letter_malformed`); acknowledge
   (diode: committed line count; spool: `ready/ → acked/`, rejected ones
   `→ rejected/`, directories fsynced); clear `pending`.

| Crash point | On restart |
| --- | --- |
| before 1 | nothing pending; records still in the input |
| after 1, before the server processed it | the pending batch is rebuilt from its positions; same body SHA-256 → re-sent under the **same** id (processed now) |
| after the server processed it, before 4 | rebuilt, re-sent under the same id → the server's stored response (`replayed: true`), applied; nothing processed twice |
| after `result` was saved, during the acks | finished from the saved result, **no request**; renames tolerate files already moved, dead letters are not repeated |
| input changed under a pending batch (a spool file gone, a diode batch removed, `--upgrade-*` changed) | the pending batch is dropped (reported as `pending_dropped`) and the records are cut afresh under a new id; repeats are `duplicate`s on the server: never a loss, no second case |

Other statuses: `413` halves the line cap for the rest of the run and re-cuts
(nothing was processed; a single-line `413` stops with an error);
`400`, `401`, `409`, `415` and any other `4xx` stop the run without
acknowledging anything; the batch stays pending and the next run re-sends
it under the same id. Every case is a test in `tests/uplink.rs`
(in-memory transport and the reference consumer) or
`tests/uplink_https.rs` (real TLS, and the binary).

### Service loop, status, blocked queue (`src/uplink/service.rs`)

Delivery is in order, so a batch the server keeps refusing blocks every
later record. The loop makes that visible and keeps it cheap:

* **Backoff between failed runs** (equal jitter, from `--interval-ms`):
  transient failures (network, `408`, `429`, `5xx` with the run's attempts
  exhausted) up to `--backoff-max-ms` (60 s); everything else (`400`,
  `401`, `409`, `415`, a single-line `413`, a malformed `200`, local
  errors) up to `--refused-backoff-max-s` (900 s): under 200 refused
  requests a day instead of ~1440 (each `401` is an audit-log entry on the
  SOC); never less than the last `Retry-After`.
* **`<state>/uplink-status.json`** (atomic, after every run;
  `robodr-uplink-status/1`): `state` (`ok`, `retrying`, `blocked`),
  `last_success_at_ms`, `last_delivery_at_ms`, `last_error` {`kind`,
  `status`, `code`, `message`, `retry_after_s`}, `consecutive_failures`,
  `stuck_since_ms` (kept across restarts while the same batch is pending),
  `pending_batch_id`, `pending_source`, `pending_lines`,
  `pending_failed_runs`, `backlog` {`spool_ready` | `diode_batches`,
  `reinject_generations`}, `next_attempt_at_ms`, `dead_letter_malformed`,
  `quarantined_unreadable` (spool files this process could not read) and
  the delivery totals, and `credentials` [{`name`, `expires_ms`,
  `days_to_expiry`}]: each CRL in use (`--crl-file`) as `crl:<issuer>`
  with its `nextUpdate` (empty without CRLs). A CRL within 14 days of its
  `nextUpdate` (or past it) is also logged, once per day count.
* **`sd_notify` `STATUS=`** with the same summary (the units set
  `NotifyAccess=main`; `systemctl status robodr-uplink`), and a log line
  per failed run.
* **`--exit-when-stuck-s N`** (off by default): exit 3 after `N` s of
  failures in this process, so the unit is visibly failed/restarted.
* **One process per state directory**: `<state>/uplink.lock` (`flock`),
  held by the service for its lifetime and taken by `--once` and
  `reinject`; a second process exits 1 with a clear message.
* **Dead-letter rotation**: at `--dead-letter-max-bytes` (64 MiB; ≥ 64 KiB;
  0 = never), keeping `--dead-letter-keep` files (`.1` newest, default 4).
  Rotation only renames; after each successful run, rotated files past
  `keep` or older than `--dead-letter-max-age-s` are deleted once none of
  their entries can still be needed for deduplication (diode batch not
  done, spool file still in `ready/`, re-injected generation not done);
  deleted dead letters can no longer be re-injected (each deletion of a
  file holding entries is logged with the count).
* **`done/` retention**: markers older than `--done-max-age-s` (default 30
  days, 0 = keep) or beyond `--done-max-count`, never while their batch is
  still in `out/`.

### Re-injection (`src/uplink/reinject.rs`)

A rejection an operator can fix (`unknown_robot`, `robot_mismatch`,
`site_mismatch`, `missing_finding_signature`, `bad_finding_signature`: a
registry change on the SOC) is dead-lettered and acknowledged; it never
comes back on its own. After the fix, with the service stopped:

```
robodr-uplink reinject --state-dir /var/lib/robodr/export/uplink --spool /var/lib/robodr/spool/agentd \
  --dead-letter /var/lib/robodr/export/uplink/dead-letter.jsonl [--dead-letter ....1 ...] [--dry-run]
```

Each selected record is re-read from the original input (spool
`rejected/<seq>.json`, the diode batch's `records.jsonl` line, or an
earlier generation's line), else taken from the dead letter's `record`
copy, and written as one **generation** `<state>/reinject/rj-<ms>-<hash>/`
(`records.jsonl`, `origin.jsonl`; built under a temporary name, fsynced,
renamed). The uplink sends each generation after its regular input as the
line-numbered stream `reinject:<generation>` — so under **new batch ids**
(the old ids would return the stored rejection) — with the usual crash
safety, and marks it `done`. Idempotent: dead letters named by any
generation's `origin.jsonl` are skipped. A record rejected again is
dead-lettered as `source: "reinject:<generation>"` and can be re-injected
again. Every record is re-validated before it is sent.

### TLS and HTTP (`src/uplink/http.rs`)

* rustls 0.23 with the **ring** provider (TLS 1.3 and 1.2, rustls' safe
  defaults; no aws-lc-rs, no logging feature). The **only** trust anchors
  are the `--ca-bundle` certificates (no system or built-in roots);
  WebPKI verification of chain, validity, server name (the URL host) and
  serverAuth. `--spki-sha256` (repeatable) adds a pin on the end-entity
  certificate's DER `SubjectPublicKeyInfo`, checked **after** the full
  verification (a pin never replaces it). There is no option that disables
  verification. Pin value:
  `openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der | sha256sum`.
* Plain `http://` only to a loopback **IP literal** (`127.0.0.0/8`, `::1`;
  not `localhost`, which a resolver could map elsewhere), checked when the
  URL is parsed and again by the transport.
* A small HTTP/1.1 client, one request per connection (`Connection:
  close`): no redirects, proxies, cookies, compression or keep-alive.
  Response head ≤ 32 KiB, body ≤ 1 MiB; `Content-Length`, `chunked` or
  read-to-close (TLS close_notify required); interim `1xx` skipped (at most
  8). Name resolution on a bounded helper thread (shared with the Kafka
  client) within `--connect-timeout-ms`; every read and write is bounded by
  the per-request deadline (`--request-timeout-ms`, socket timeouts
  re-armed with the time left), so a trickling server cannot hold the
  exchange open.
* **Why not a client crate.** `ureq` 2.x (rustls) would add `url` →
  `idna` → the ICU4X crates and `webpki-roots` (a built-in trust store this
  tool must never use), and has redirect and proxy logic to switch off;
  `ureq` 3.x takes no custom certificate verifier, which SPKI pinning
  needs. One `POST` with fixed headers does not justify that tree; the HTTP
  part here is a few hundred lines with its own tests (status line, header and
  chunked parsing, truncations, limits). rustls, rustls-webpki and ring do
  the security-critical work.

### Contract test vectors

`docs/contracts/fixtures/ingest/` (contract §9): fixed-seed test keys,
requests (headers, body, server time) and the expected responses, made by
`cargo run -p robodr-export --example ingest_vectors` with this crate's
`wire` code. `tests/ingest_vectors.rs` fails if the committed files differ
from the generator by a byte, and runs every request through a reference
consumer of the contract (`tests/common/ingest.rs`). The batch and
per-finding signatures of the vectors were also verified independently with
Python `cryptography` (Ed25519).

## The Kafka client (`src/kafka/`)

| Piece | What |
| --- | --- |
| `crc32c` | CRC-32C (Castagnoli), table-driven; RFC 3720 B.4 vectors + check value `0xE3069283` |
| `wire` | int8/16/32/64, STRING, NULLABLE_STRING, NULLABLE_BYTES, ARRAY, zig-zag VARINT/VARLONG; bounds-checked reader (array counts checked against remaining bytes) |
| `batch` | RecordBatch v2: magic 2, CRC-32C over attributes..end, attributes 0 (no compression, CreateTime, non-transactional), producerId/epoch/baseSequence -1, per-record varints, headers. Decoder (for tests/fake broker) verifies CRC and lengths |
| `proto` | ApiVersions v0; Metadata v1–8; Produce v3–8 (all non-flexible); request header v1, response header v0 |
| `client` | `Producer`: connect timeout, hard per-request deadline covering the request write and the response read (default 35 s, must exceed `produce_timeout_ms`, default 30 s; checked), name resolution on a bounded helper thread (≤ 4 outstanding, waited ≤ `connect_timeout`; IP literals bypass it), broker list replaced on every metadata refresh and capped at 1024, `max_request_bytes` (1 MiB) and `max_response_bytes` (16 MiB) bounds, correlation-id check, version negotiation per connection, metadata (no auto-create), leader routing, `acks=-1`, one request in flight, retries with exponential backoff (100 ms … 10 s, 10 rounds without progress), `delivery_timeout` (120 s), record-level errors narrowed down by halving the partition's batch (the halved size is kept for the rest of the call), connections idle for `connections_max_idle` (9 min) closed before use, TLS / SASL listeners named in the error |

Error handling: `NOT_LEADER_OR_FOLLOWER`, `LEADER_NOT_AVAILABLE`,
`UNKNOWN_TOPIC_OR_PARTITION`, `NETWORK_EXCEPTION`, `KAFKA_STORAGE_ERROR`,
fenced/unknown leader epoch → refresh metadata and retry;
`REQUEST_TIMED_OUT`, `NOT_ENOUGH_REPLICAS(_AFTER_APPEND)`,
`CORRUPT_MESSAGE` (a CRC mismatch: damaged in transit), `UNKNOWN_SERVER_ERROR`,
throttling → retry; `INVALID_TIMESTAMP` → retry, then fail naming the
clock (the CreateTime is this host's clock; never blamed on a record);
`MESSAGE_TOO_LARGE`, `RECORD_LIST_TOO_LARGE`, `INVALID_RECORD` → halve the
batch until it is accepted or holds one record, then reject that record (a
batch being re-sent after a lost reply resets the producer id rather than
freeing its sequences); anything else (authorisation,
`UNSUPPORTED_VERSION`, invalid topic, ...) → fatal. I/O errors, timeouts,
short or garbage frames and correlation mismatches drop the connection and
retry. A TLS listener (it answers the plaintext ApiVersions with a TLS
alert) and a SASL listener (it answers ApiVersions, then closes the
connection) are retried like any I/O error, but the error says which it
probably is. Broker throttling (`throttle_time_ms`) is not honoured
client-side; the broker's channel muting paces the producer (checked with a
`producer_byte_rate` quota).

## Tests

* Unit: CRC-32C vectors (RFC 3720 B.4: 32×0x00, 32×0xFF, incrementing,
  decrementing, the iSCSI read PDU; catalogue check value; table entries);
  zig-zag/varint byte values; RecordBatch bytes derived by hand from the
  protocol documentation (one record with key, value and a header), null
  key/value and negative timestamp deltas; every single-bit flip in the
  CRC-covered region detected; every truncation of every response type an
  error, never a panic; version negotiation.
* Idempotence (`tests/kafka_fake_broker.rs`): a lost acknowledgement
  re-sent and dropped by the broker (as success with the original offset
  and as `DUPLICATE_SEQUENCE_NUMBER`), sequences per partition across calls
  and a leader move, epoch bumps on `OUT_OF_ORDER_SEQUENCE_NUMBER` /
  `UNKNOWN_PRODUCER_ID` (InitProducerId v3+) and resets on
  `INVALID_PRODUCER_EPOCH` / `PRODUCER_FENCED`, older brokers and the
  largest epoch, without loss or duplicate; another partition's batch in
  doubt across a bump deduplicated (also after a restart), where a reset
  writes it twice; an expired producer, InitProducerId refused
  (`CLUSTER_AUTHORIZATION_FAILED`, not offered, coordinator not ready),
  halving that reuses the refused sequences, a record-level error on a
  re-sent batch (renumbered: the next record is really written),
  `INVALID_TIMESTAMP` retried and reported, never a rejected record (the
  fake broker checks CreateTime against a skewed clock), a restart with the persisted
  state and journal (in-doubt batch deduplicated; more than five batches
  per partition: acknowledged ones skipped), journals that do not fit, a
  journal that cannot be saved (nothing sent), sequence wrap-around.
  Retention: `tests/retention.rs`, `deadletter.rs` and `retention.rs` unit
  tests (markers held while the batch is in `out/`, rotated files held
  while an entry is needed, current file never deleted), `spool_export.rs`
  (rejected pairs, names in `ready/` spared).
* `tests/kafka_fake_broker.rs`: a fake cluster (std `TcpListener`, one
  thread per connection) implementing ApiVersions/Metadata/Produce/
  InitProducerId, decoding every RecordBatch (CRC checked) into a
  per-partition log and enforcing a broker's idempotent-producer checks
  (sequence continuity per producer id and partition, epochs, duplicates of
  the last five batches). Cases: success (order, offsets, headers,
  `acks=-1`, negotiated versions), Produce v3 negotiation, unsupported broker, retriable errors
  without duplicates, leader change (`MoveLeader`) and leadership moved
  between calls, disconnect after append (duplicate with
  `idempotence = false`; deduplicated by the broker otherwise),
  disconnect before append and half frames (exactly once), garbage frame
  and a broker that never answers (timeout), broker `MESSAGE_TOO_LARGE`
  isolated to one record with order kept around it, client-side oversize,
  request splitting under `max_request_bytes`, fatal authorisation error,
  unknown topic and exhausted retries. Regressions from the real-broker run:
  a batch too large only as a whole (`max_batch_bytes`, like the topic's
  `max.message.bytes`) is halved, not sent one record per request; a TLS
  alert and a SASL listener's close after ApiVersions are named in the
  error; a broker that closes idle connections (`idle_close`) costs no
  error when `connections_max_idle` is below its limit.
* `tests/kafka_real_broker.rs` (`#[ignore]`d, needs `ROBODR_KAFKA_BROKER`;
  run by `scripts/kafka-it.sh`): see *Real-broker test*.
* `tests/pipeline.rs`: agentd `Spool` → exporter → packer → copy → importer
  (Ed25519 keyring) → publisher → fake Kafka, checking key, value bytes,
  headers (contract order) and partition of every record; the crash cases
  above; rejected spool records; batch splitting; mismatched planner limits;
  publisher crash after a chunk was acknowledged (exactly one chunk
  duplicated, nothing lost); dead letters (tampered header, garbage,
  overlong line, wrong topic); a connected-site spool; a fatal Kafka error
  that commits nothing.
* `tests/cli.rs`: both binaries as processes (usage exit 2, `--once` runs,
  unreachable broker exit 1 with nothing acknowledged).
* Uplink unit tests (`src/uplink/`): batch signature message bytes (framing
  pinned byte by byte), sign/verify, key id and batch id syntax, batch id
  determinism and content binding (value pinned, computed independently),
  NDJSON line encoding, `200` consistency checks, backoff bounds and caps,
  `Retry-After` parsing, state file parsing, URL parsing (http refused
  except loopback IP literals), SPKI pin parsing, HTTP response parsing
  (chunked, interim, every truncation and limit).
* `tests/uplink.rs` (in-memory transport, reference consumer): partial
  acceptance with dead letters and acks, contract headers and signature,
  per-finding signatures carried, line and byte limits, configuration
  limits, transport-error retries with backoff, `5xx`/`429` retries with the
  same batch id re-signed and `Retry-After` honoured, attempts exhausted
  then resumed under the same id, refusals (`400`/`401`/`409`/`415`)
  acknowledging nothing, malformed `200`s acknowledging nothing, `413`
  halving and single-line `413`, crash at every step (pending saved,
  response received, result saved, first ack) for spool and diode inputs,
  input changed under a pending batch, state bound to its source kind,
  sender key file rules.
* `tests/uplink_https.rs` (in-process rustls HTTPS server, test PKI in
  `tests/data/uplink-tls/`): partial acceptance, host name + pin + chunked
  response, `401`, `413`, `429` + `Retry-After`, `5xx` with the same batch
  id, `replayed: true` after a crash, SPKI pin mismatch refused before any
  request, unknown CA / pin without chain / name mismatch / plain server
  refused, `http://` to non-loopback refused, loopback `http://` works, a
  server that never answers times out, the binary end to end (`--once`,
  usage errors exit 2, unreachable server exit 1, `--version`).
* `tests/ingest_vectors.rs`: the contract vectors (above).

## Real-broker test

```
scripts/kafka-it.sh                                  # apache/kafka:3.9.1
KAFKA_IT_IMAGE=apache/kafka:4.1.0 scripts/kafka-it.sh
KAFKA_IT_DOCKER=docker.exe scripts/kafka-it.sh       # WSL without Docker Desktop integration
```

The script starts a single-node KRaft broker in docker (PLAINTEXT on
19092, plus a SASL_PLAINTEXT and a TLS listener, no topic auto-creation,
`StandardAuthorizer`, `connections.max.idle.ms=10000`), creates the topics
listed at the top of `tests/kafka_real_broker.rs` (an ACL, a quota and
records keyed by robot id from `kafka-console-producer`), runs the
`#[ignore]`d tests with `ROBODR_KAFKA_BROKER` etc. set, re-reads every stored
batch with `kafka-dump-log --deep-iteration` (the broker's own CRC check),
prints one record with `kafka-console-consumer --property
print.headers=true`, and removes the container. To run the tests against
another broker: `ROBODR_KAFKA_BROKER=host:port cargo test -p robodr-export
--test kafka_real_broker -- --ignored --test-threads=1` (single-node
cluster, topics as in the file's header). Records are read back with a
minimal test-only Fetch v4 consumer; every fetched batch goes through
`decode_batches` (CRC-32C checked as served by the broker).

Verified on 2026-10-17 against **Apache Kafka 3.9.1 and 4.1.0** (official
`apache/kafka` images; negotiated Produce v8, Metadata v8):

| Case | Result |
| --- | --- |
| `robodr-kafka-publish --spool`, 300 signed findings of 3 robots, chunks of 40, run twice | each record exactly once; key = finding id; value bytes and all headers identical, contract order, `robodr-finding-sig` last and verifying (Ed25519); partition = contract §4 for 12 partitions (the spooled partition, computed for 7, overridden); CreateTime = publish time; producer id -1; `ready/` empty, 300 in `acked/`, `published_total` 300; second run sends nothing |
| diode path: spool → `robodr-spool-export` logic → packer → copy → importer → publisher | 120 findings exactly once; done marker honoured |
| crash after chunk 2 was acknowledged, before the commit; restart | exactly that chunk (25) twice, nothing lost, spool fully acknowledged |
| 5 000 findings, chunks of 1 000 | exactly once, requests split under 1 MiB |
| broker restarted (`docker restart`) mid-stream; binary in loop mode | 3 000 records, none lost, 0 duplicates (also with `docker kill` + `start`, run by hand) |
| record above the topic's `max.message.bytes` (4096) among 1 KB records | that record rejected (`MESSAGE_TOO_LARGE`), the 11 others delivered in order with the broker's offsets |
| unknown topic | no auto-creation; exit 1 naming `UNKNOWN_TOPIC_OR_PARTITION`; nothing acknowledged |
| ACL denying WRITE | fatal `TOPIC_AUTHORIZATION_FAILED` (29), not retried |
| SASL_PLAINTEXT / TLS listener | fails in bounded time, the error names SASL / TLS |
| broker closes idle connections | delivered exactly once; no error at all with `connections_max_idle` below the broker's limit |
| `producer_byte_rate` quota (64 KiB/s) | throttled (300 findings, ~1.9 MB, chunks of 25: ~17 s), no request timed out, exactly once. With 630 KB requests the per-request throttle (~10 s) reached the test broker's 10 s `connections.max.idle.ms` and the broker expired the muted connection: one retry, still exactly once |
| partitioner vs. the Java client | 205 robot ids produced by `kafka-console-producer` (key = robot id): `partition_for` agrees for every one |
| `kafka-dump-log --deep-iteration` | every stored batch `isvalid: true`, `compresscodec: none`, `producerId: -1` |

Bugs found by this run and fixed (each with a fake-broker regression test
in `tests/kafka_fake_broker.rs`):

1. A batch rejected with `MESSAGE_TOO_LARGE` because it was too large *as a
   whole* (topic `max.message.bytes` below `max_request_bytes`; every record
   fine on its own) switched that partition to one record per request for
   the rest of the call (15 requests for 12 records against 3.9.1). It is now
   halved until it fits (11 requests; 200 records under an 8-record limit:
   ~40 requests instead of 201).
2. A TLS listener's alert (`15 03 03 00 02 02 50`) was reported as
   "response frame size 352518912", and a SASL listener's close after
   ApiVersions as a bare "broker closed the connection". Both errors now
   say what the listener probably wants.
3. A connection closed by the broker's `connections.max.idle.ms` (10 min by
   default; the normal case between rare findings) was only discovered by a
   failed request: an I/O error, a metadata refresh and a backoff on the
   first send after every quiet period. Connections idle for
   `connections_max_idle` (9 min) are now closed before use.

No wire-format bug was found: the RecordBatch encoding, CRC-32C, the request
and response layouts of ApiVersions v0 / Metadata v8 / Produce v8 and the
partitioner all agreed with the real brokers.

## Limits (honest)

* **Real-broker coverage is a single-node cluster** (replication factor 1,
  so `acks=all` means the leader only). Leader moves between brokers, ISR
  shrinkage (`NOT_ENOUGH_REPLICAS`) and a multi-broker bootstrap list are
  covered by the fake broker only; Metadata/Produce versions below v8 (brokers
  older than 2.1) were not run against real brokers.
* **TLS, mutual TLS, SASL/SCRAM** (`src/kafka/client.rs`,
  `src/kafka/sasl.rs`, `robodr_blackbox::tls`). TLS is the default and
  plain TCP is refused unless `allow_plaintext` / `--allow-plaintext` is
  set explicitly (TLS and `allow_plaintext` together are refused; SASL
  needs TLS). rustls + ring as for the uplink; the only trust anchors are
  `--tls-ca`; every broker certificate, bootstrap **and advertised**, is
  verified with the host it is dialled at (SNI = the verified name;
  `--tls-server-name` overrides it for every broker); optional SPKI pins
  add to the chain check; `--tls-cert` / `--tls-key` give mutual TLS. No
  fallback: a TLS producer never retries in plain TCP. The handshake and
  every TLS request are bounded as a whole (`robodr_blackbox::tls::DeadlineTcp`
  re-arms the socket timeout before every read and write), so a broker or
  on-path host trickling bytes cannot outlast the request deadline. SASL is
  SCRAM-SHA-256 / -512 only (SaslHandshake v1, SaslAuthenticate v0–v1,
  RFC 5802 without SASLprep, as the Java client): iteration count
  4096..=100000, the server nonce must extend ours, mandatory extensions
  refused, the server signature is checked in constant time (a TLS-valid
  broker that does not know the credential cannot complete it), failures
  are fatal (not retried). HMAC, PBKDF2 (`Hi`) and SHA-2 are RustCrypto's
  `hmac` / `pbkdf2` / `sha2` with `zeroize` (keyed hash states wiped on
  drop), base64 is `base64ct` (constant time, canonical padding only); the
  previous in-crate code stays in the unit tests as a differential
  reference. A broker session lifetime
  (`connections.max.reauth.ms`) is honoured by closing the connection at
  80 % of it and authenticating a new one (KIP-368 in-band
  re-authentication is not implemented). Not implemented: `PLAIN`,
  `GSSAPI`, `OAUTHBEARER`, CRL / OCSP, encrypted private keys. Tests:
  `tests/kafka_tls.rs` (fake cluster with rustls and the broker side of
  SCRAM; bad CA, wrong host, expired, no `serverAuth`, pin mismatch,
  missing / foreign client certificate, downgrades both ways, wrong
  credentials, impostor broker, downgraded iteration count, session
  renewal, CLI rules), RFC 7677 / RFC 4231 / RFC 7914 vectors, and
  `scripts/kafka-tls-it.sh` against a real Apache Kafka 3.9.1 (SSL, SSL with
  `ssl.client.auth=required`, SASL_SSL SCRAM-SHA-256/512 with
  `connections.max.reauth.ms`). Behind a local TLS proxy instead
  (`--allow-plaintext`), the advertised listeners seen by this client must
  point at the local proxy ports (one per broker), otherwise it bypasses
  the proxy.
* **Idempotence** is on by default (contract §4, `enable.idempotence=true`)
  and verified against the fake broker (sequence numbers, epochs,
  five-batch duplicate window) and against a single-node Kafka 3.9.1
  (`scripts/kafka-tls-it.sh`, run by hand on 2026-10-31: all 17 tests,
  including a crash resumed without duplicate, SCRAM-SHA-256/512 over TLS
  and the epoch bump below; not yet in CI, and no multi-broker cluster).
  With `--no-idempotence` (brokers that
  refuse InitProducerId to this principal) delivery is at-least-once: a
  lost response duplicates a request's records. Either way consumers may
  drop duplicates on `event-uid` (contract §2). Epoch bumps (KIP-360) are
  verified against Kafka 3.9.1 (`tests/kafka_real_broker.rs`,
  `real_kip360_epoch_bump_semantics`, `real_sequence_error_bumps_the_epoch`:
  the broker accepts the bumped epoch at sequence 0, fences the older one
  per partition only, and answers InitProducerId without a transactional
  id with a new producer id, which is why the bump is done client side).
* **DNS.** Host names (bootstrap and advertised listeners) go through the
  system resolver on a helper thread; a lookup that outlives
  `connect_timeout` fails the attempt and its thread is abandoned (at most
  4 at a time, further lookups fail fast until they finish). On an
  air-gapped SOC network use IP literals.
* Only non-flexible API versions (Metadata ≤ 8, Produce ≤ 8). A broker
  that no longer offers them is refused (`Unsupported`), not mis-spoken to.
* No compression; no transactions; one request in flight, single thread —
  throughput is plenty for findings, not for telemetry.
* Partition count changes re-map robots (contract §4); the publisher uses
  the current count at each chunk.
* The exporter supports one instance per spool and packer state (no lock
  file). Losing the exporter state while an intent is pending can pack
  records twice; losing the packer state restarts the diode sequence (see
  the diode README). Black-box bundles and `checkpoint.json` are not
  exported by this tool. `rejected/` is not counted in agentd's spool
  bounds.
* **`robodr-uplink` limits.** Tested against the in-crate reference
  consumer (CI) and, by hand on 2026-10-26, the static musl binary against
  an OpenSSL-based Python TLS server (pin, host name); not yet against
  AutoSecOps itself (Sprint 3 contract tests). One instance per state
  directory (no lock file). Retries within a run are bounded
  (`--max-attempts`); the binary then backs off between runs, so a `401`
  (key not registered, clock off by more than 300 s) is retried slowly
  forever with the batch kept, never dropped. No HTTP proxy support (the
  sites are air-gapped or direct).
* `done/` markers are bounded only once the batch directory has left the
  importer's `out/` (a marker is kept while its batch is there).
  `--out-max-*` removes the bulk (records, bundles) for a sole consumer
  but leaves a tombstone per batch (its `MANIFEST.json` and `done/`
  marker, a few KiB; `state_usage` counts them); removing tombstones
  (and with them, after `--done-max-age-s`, the markers) is the
  operator's call, safe only while no importer state reset re-emits old
  batch names. The re-injection
  ledger (`origin.jsonl` per generation, small) is never pruned; the
  importer's own `processed/` and `quarantine/` are the importer's
  (robodr-diode). No signal handling: both tools are crash-safe by
  design, so SIGTERM/SIGKILL at any point is covered by the recovery rules
  above.
