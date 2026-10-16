# robodr-export

The two hops of the `robot-edr.findings` path that nothing else moved
(contract: `docs/contracts/robot-edr.findings.md`, §2, §4, §8 and §8.1):

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
```

Everything is std + RoboDR crates + serde. The Kafka producer is a small
in-crate implementation (`src/kafka/`), because no client crate is
available offline. **It has never been run against a real Kafka broker**;
see *Limits*.

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
   name), `topic`, `key` (= finding id) and re-validate the value with
   `robodr_ocsf::parse_and_validate`. A failing record is **moved** to
   `<spool>/rejected/` (with `<name>.reason.json`), never deleted.
2. Cut the batch exactly as the packer's planner would (data bytes and
   finding count, parity included), so that one `Packer::pack` call writes
   **one** diode batch. (`--max-batch-bytes` / `--max-findings` set both
   sides; the binary opens with `Exporter::open_checked`, which refuses an
   `ExportConfig` whose limits differ from the `PackConfig`, or a packer
   state of another unit. Library users: `ExportConfig::for_packer`.)
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
  [--topic robot-edr.findings] [--chunk 500] [--client-id S] [--request-timeout-ms N] \
  [--produce-timeout-ms N] [--delivery-timeout-ms N] [--retries N] [--max-request-bytes N] [--interval-ms 2000] [--once]
```

* **Input.** Diode: every non-dot directory of the importer's `out/`
  (complete by construction: the importer renames it into place) in name
  order, i.e. per unit in sequence order; `records.jsonl` lines are
  `{topic, partition, key, headers, value, diode}`. Spool: `ready/` files of
  a connected site's agentd.
* **Validation.** The value is re-validated (`parse_and_validate`); key and
  headers must equal what `robodr_ocsf::record` derives from the value
  (contract §2: the value is authoritative), the topic must be the
  configured one. The **bytes on disk** are what is sent as the value.
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
  lost). After a crash each batch resumes after its last committed line: at
  most one chunk per interrupted batch (plus whatever a lost Produce
  response covered) is sent twice. A version-1 file (`{batch,
  lines_committed}`) is migrated on open. For a spool source the commit is
  the rename to `acked/`.
* **Dead letters.** A record that fails validation, or that Kafka rejects
  as a record (`MESSAGE_TOO_LARGE`, `INVALID_RECORD`, ...), is appended to
  `<state>/dead-letter.jsonl` (`{source, position, reason, record, at_ms}`)
  and skipped (spool source: moved to `<spool>/rejected/`). Entries are
  deduplicated on `(source, position)`, so a chunk re-processed after a
  crash does not append its dead letters again (the index is read from the
  file on the first dead letter of a run; 16 bytes per entry). Any other
  Kafka error stops the run without committing; the next run retries.

## The Kafka client (`src/kafka/`)

| Piece | What |
| --- | --- |
| `crc32c` | CRC-32C (Castagnoli), table-driven; RFC 3720 B.4 vectors + check value `0xE3069283` |
| `wire` | int8/16/32/64, STRING, NULLABLE_STRING, NULLABLE_BYTES, ARRAY, zig-zag VARINT/VARLONG; bounds-checked reader (array counts checked against remaining bytes) |
| `batch` | RecordBatch v2: magic 2, CRC-32C over attributes..end, attributes 0 (no compression, CreateTime, non-transactional), producerId/epoch/baseSequence -1, per-record varints, headers. Decoder (for tests/fake broker) verifies CRC and lengths |
| `proto` | ApiVersions v0; Metadata v1–8; Produce v3–8 (all non-flexible); request header v1, response header v0 |
| `client` | `Producer`: connect timeout, hard per-request deadline covering the request write and the response read (default 35 s, must exceed `produce_timeout_ms`, default 30 s; checked), name resolution on a bounded helper thread (≤ 4 outstanding, waited ≤ `connect_timeout`; IP literals bypass it), broker list replaced on every metadata refresh and capped at 1024, `max_request_bytes` (1 MiB) and `max_response_bytes` (16 MiB) bounds, correlation-id check, version negotiation per connection, metadata (no auto-create), leader routing, `acks=-1`, one request in flight, retries with exponential backoff (100 ms … 10 s, 10 rounds without progress), `delivery_timeout` (120 s), record-level errors narrowed down by re-sending one record at a time |

Error handling: `NOT_LEADER_OR_FOLLOWER`, `LEADER_NOT_AVAILABLE`,
`UNKNOWN_TOPIC_OR_PARTITION`, `NETWORK_EXCEPTION`, `KAFKA_STORAGE_ERROR`,
fenced/unknown leader epoch → refresh metadata and retry;
`REQUEST_TIMED_OUT`, `NOT_ENOUGH_REPLICAS(_AFTER_APPEND)`,
`CORRUPT_MESSAGE`, `UNKNOWN_SERVER_ERROR`, throttling → retry;
`MESSAGE_TOO_LARGE`, `RECORD_LIST_TOO_LARGE`, `INVALID_RECORD`,
`INVALID_TIMESTAMP` → isolate and reject the record; anything else
(authorisation, `UNSUPPORTED_VERSION`, invalid topic, ...) → fatal. I/O
errors, timeouts, short or garbage frames and correlation mismatches drop
the connection and retry.

## Tests

* Unit: CRC-32C vectors (RFC 3720 B.4: 32×0x00, 32×0xFF, incrementing,
  decrementing, the iSCSI read PDU; catalogue check value; table entries);
  zig-zag/varint byte values; RecordBatch bytes derived by hand from the
  protocol documentation (one record with key, value and a header), null
  key/value and negative timestamp deltas; every single-bit flip in the
  CRC-covered region detected; every truncation of every response type an
  error, never a panic; version negotiation.
* `tests/kafka_fake_broker.rs`: a fake cluster (std `TcpListener`, one
  thread per connection) implementing ApiVersions/Metadata/Produce,
  decoding every RecordBatch (CRC checked) into a per-partition log. Cases:
  success (order, offsets, headers, `acks=-1`, producer id -1, negotiated
  versions), Produce v3 negotiation, unsupported broker, retriable errors
  without duplicates, leader change (`MoveLeader`) and leadership moved
  between calls, disconnect after append (duplicate = at-least-once),
  disconnect before append and half frames (exactly once), garbage frame
  and a broker that never answers (timeout), broker `MESSAGE_TOO_LARGE`
  isolated to one record with order kept around it, client-side oversize,
  request splitting under `max_request_bytes`, fatal authorisation error,
  unknown topic and exhausted retries.
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

## Limits (honest)

* **Not tested against a real Kafka broker.** The fake broker was written
  from the same reading of the protocol documentation as the client, so a
  shared misunderstanding would not show. Before deployment run it against
  the SOC's Kafka version (3.x/4.x) and check with `kafka-console-consumer
  --property print.headers=true` that key, headers and partition are as in
  the contract. Only the CRC-32C has independent test vectors.
* **No TLS, no SASL.** Run the publisher on an isolated SOC network
  segment, or through a local TLS proxy (stunnel/sidecar) per broker. Kafka
  clients connect to the hosts in the brokers' *advertised listeners*, so
  with a proxy the advertised listeners seen by this client must point at
  the local proxy ports (one per broker), otherwise it bypasses the proxy.
* **Idempotence off**, contrary to the contract's producer settings (§4,
  `enable.idempotence=true`): delivery is at-least-once. Ordering per
  partition still holds (one request in flight), but a lost response
  duplicates a request's records. Consumers must drop duplicates on
  `event-uid` (contract §2 already allows it).
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
* The publisher's `done/` markers (one empty file per batch) and
  `dead-letter.jsonl` grow without bound; prune them together with the
  importer's `out/`. No signal handling: both tools are crash-safe by
  design, so SIGTERM/SIGKILL at any point is covered by the recovery rules
  above.
