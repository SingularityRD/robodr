# robodr-demo-soc

The SOC of the demo kit (`demo/`, gap T28): receives findings from
`robodr-uplink` over the `robodr.ingest` v1 API, verifies each batch and
each finding signature, keeps them in an append-only NDJSON file and shows
them in a browser viewer with time-to-SOC metrics.

```sh
robodr-demo-soc --config soc.json [--listen 127.0.0.1:8080] [--store findings.ndjson]
```

`soc.json` lists the robots and their uplink and finding public keys
(`demo/scripts/robot.sh` writes one).

## Demo only: keep it on loopback or an isolated lab network

Do not expose it to any network you do not control end to end.

* The ingest endpoint is the reference consumer from `robodr-export`'s tests
  (`crates/robodr-export/tests/common/ingest.rs`), compiled in. It is
  test-grade code: the crate's no-unwrap/no-panic/no-indexing lints are
  relaxed for it, so malformed input can panic. A panic ends that
  connection's thread only (the shared state's lock is recovered), but it
  has not been hardened the way the robot-side daemons are.
* Its replay and dedup state lives in memory and has no bound: every
  accepted batch id and finding id is kept for the life of the process, so
  a sender holding a valid uplink key can grow it until the process runs
  out of memory.
* Plain HTTP only, no TLS and no client authentication beyond the batch
  signatures; `robodr-uplink` sends plain HTTP only to a loopback address.
  The default listen address is `127.0.0.1:8080`; the demo binds
  `0.0.0.0` inside its container and publishes the port on the host's
  loopback only (`demo/docker-compose.yml`).

For a real deployment, findings go to a SIEM (`integrations/`) or to a
production ingest service that implements `docs/contracts/robodr.ingest-api.md`.
