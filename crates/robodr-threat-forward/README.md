# robodr-threat-forward

A **Pulsar module** (not a binary) that hands every Pulsar threat to
`robodr-agentd`'s host-threat socket, so the host-dependent correlation
rules (`robodr-correlate`, e.g. `robot.correlate.coordinated_intrusion`,
`host_process_persistence`, `defense_tampering`) can fire there and host
detections become RoboDR findings (`robot.host.pulsar_threat`).

It is registered by `robodr-pulsard` (`starter.add_module(ThreatForwarder)`,
`DEFAULT_ENABLED = false`) and runs inside that daemon. There is no
standalone executable and no man page: configure it in `pulsar.toml` and
read `robodr-pulsard`'s and `robodr-agentd`'s documentation for running it.

```text
 Pulsar bus ──► on_event (threat?) ──► try_send ──► bounded queue ──► writer thread
  (rules-engine,      │                    │ full: dropped++          │ UnixStream, line framing
   other modules)     │ own sensor: skip   │                          │ reconnect with backoff
                      ▼                    ▼                          ▼
                 skipped_own++        never blocks           agentd host_threats socket
```

## Configuration

```toml
[module.robodr-threat-forward]
enabled = true
socket_path = "/run/robodr-agentd/host-threats.sock"   # required, absolute
# queue_capacity = 1024     # 1..=65536 threats waiting for the writer
# heartbeat_ms = 5000       # 100..=60000; keep well below agentd's daemon.silence_ms
# write_timeout_ms = 1000   # a write blocked longer drops the connection
```

`socket_path` is agentd's `host_threats.socket_path`. agentd's side (peer
uid check, `socket_mode` `0660`, `allowed_uids`) and the systemd drop-in
that lets `robodr-pulsard` reach the socket are in `docs/OPERATIONS.md`
§6.4 and the `host_threats` row of `crates/robodr-agentd/README.md`.

## Wire format (protocol `v` 1, one JSON object per line)

```json
{"kind":"threat","v":1,"rule":"RoboDR: Interactive shell started on robot controller",
 "source":"rules-engine","severity":"medium","category":"execution",
 "ts_ms":1790000000000,"pid":4242,"ppid":1,"uid":0,"gid":0,"image":"/usr/bin/bash",
 "container":false}
{"kind":"heartbeat","v":1,"sent":17,"dropped":0,"skipped_own":3}
```

* **What is forwarded:** every bus event that carries a threat
  (`header.threat`), like Pulsar's own `threat-logger`, except threats
  raised by `robodr-sensor-ros2` (agentd already sees those through its
  own capture; forwarding them would count them twice, and agentd drops
  them too). For the rules-engine, `rule` is the rule `name`
  (`rules/robodr/*.toml`), exactly the host rule id correlation rules
  match; `severity` / `category` come from the rule's `extra` metadata
  when present.
* **Bounded, sanitised strings:** `rule` and `image` at most 256 bytes,
  `source` and `category` 64, control characters replaced by `?` (`image`
  is the exec path of an arbitrary local process and may be hostile); the
  longest possible line stays under agentd's 4 KiB line limit.
* **Heartbeat** right after every connect and whenever nothing was written
  for `heartbeat_ms`, carrying the cumulative `sent` / `dropped` /
  `skipped_own` counters. agentd counts it as liveness: a configured host
  input whose forwarder is gone goes *silent*, and agentd then reports
  `unknown`, never `ok`.

## Never stalls the Pulsar bus

`on_event` only serialises the line and `try_send`s it into a bounded queue.
A full queue drops the threat and counts it (`dropped`, reported in the next
heartbeat and turned into a health finding by agentd). A dedicated OS thread
owns the socket: it connects, writes with a write timeout, and on any error
drops the connection and reconnects with exponential backoff (100 ms to 5 s).
While agentd is not there, threats wait in the queue (up to its capacity)
and are delivered after the reconnect. A line whose write failed is counted
as dropped and never retried (part of it may have reached the peer). The
writer stops when Pulsar drops the module state, also without a graceful
stop.

## Building and testing

Pulsar-dependent (`pulsar-core` from `vendor/pulsar`, which needs Pulsar's
eBPF build toolchain), so it is excluded from the pure-crate build
(`scripts/ci-pure-excludes.py`) and built, linted and tested in CI's
`pulsar` job:

```sh
cargo test -p robodr-threat-forward
cargo build -p robodr-pulsard        # the daemon that registers it
```

The unit tests cover the threat-to-line mapping and bounds, the worst-case
line against agentd's limit, agentd's own parser accepting every line the
forwarder writes (`robodr-agentd` is a dev-dependency), config validation,
forwarding with heartbeats and own-sensor skipping, queueing while agentd is
away, drop-when-full and reconnect, and that `offer` never blocks on a
stalled peer. `crates/robodr-agentd/tests/host_threats.rs` plays the
forwarder's side end to end against the real daemon.

## Limits

* Run only inside `robodr-pulsard` in WSL2 (`docs/PULSAR-INTEGRATION.md`
  §7b), never on a robot.
* Local unix socket only; no authentication beyond agentd's peer-uid check
  and the socket's permissions.
* Delivery is at-most-once per line: a dropped or failed line is counted,
  not retried.

See also: `docs/PULSAR-INTEGRATION.md` §3a (the Pulsar items it uses).
