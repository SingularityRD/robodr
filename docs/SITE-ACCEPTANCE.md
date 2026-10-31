# Site acceptance: connectivity checks

Every exporter and the fleet tool can prove its path to the far side
**without sending a finding and without changing state**, so a site
acceptance test can run them next to the running services and record the
output. Each check prints one line per step (`ok`, `skip`, `warn`,
`FAIL`) and ends with an exit status. Use the exact options of the
installed service (its unit file or drop-in), plus the check flag.

| Order | Command (as root) | Proves | Exit |
| --- | --- | --- | --- |
| 1 | `robodr-agentd --check-config --config /etc/robodr/agentd.json` | agentd's configuration, profile trust and keys load | 0 ok |
| 2 | `robodr-enroll check` | SOC fleet / approval key files; TLS to the SOC (CA bundle, pins, CRLs, with each CRL's days left: warn within 14 days); the URL is the fleet API; once enrolled: the uplink key file is the registered one and the SOC accepts it; a published ring document verifies | 0 ok, 1 failed, 3 SOC not reached |
| 3 | `robodr-uplink <service options> --check` | TLS (CA bundle, pins, CRLs); the URL is the RoboDR ingest API (an empty batch, refused with `400 empty_batch` before authentication: nothing sent or stored); for a `--spool` (uplink) key, the SOC accepts it (read-only fleet request) | 0 passed, 1 failed |
| 3' | `robodr-kafka-publish <service options> --check` | the client certificate and CRLs have not expired (WARN within 14 days), the Kafka cluster answers with this TLS / SASL configuration and the topic's metadata is readable; nothing produced | 0 passed, 1 failed |
| 4 | `robodr-anchor-receiver check --config /etc/robodr-anchor-receiver/receiver.json` (base station) | configuration, every unit key, the receiver key, the TLS chain / key / client CA / CRLs (an expired CRL or server certificate fails here; days left printed, warn within 14 days), every unit's stored state, the listen address | 0 ok, 2 failed |
| 5 | `robodr-agentd selftest --config /etc/robodr/agentd.json` (after 1-4, with agentd and the exporter running) | a finding travels end to end: the running agentd spools a marked Low `robot.agent.selftest` finding carrying a printed nonce, and the exporter acknowledges that record (moves it to `acked/`) | 0 acknowledged, 1 not proven, 2 usage or configuration error |

Notes:

* `robodr-uplink --check` cannot confirm a **relay** key (`--diode-out`)
  before its first batch: relay keys authenticate at ingest only. The
  output says `skip key registration`; the first delivered batch
  (`uplink-status.json` `last_delivery_at_ms`) confirms it. The same holds
  for a SOC that does not serve the fleet API (`warn key registration not
  checked`, exit 0), recognised only by the contract's `404 not_found`
  answer on the fleet ring path; any other 404 there fails the check.
* None of the checks take the services' locks; they run while the
  services run.
* Checks 1-4 do not prove that a finding travels end to end through
  agentd, the spool and the exporter; check 5 does, and it is the only
  one that sends something (one Low, observe-only finding, never a
  correlation input or a response). Its pass means the exporter
  acknowledged the record: for `robodr-uplink` the SOC's ingest API
  accepted it, for `robodr-kafka-publish` the broker acknowledged it, for
  `robodr-spool-export` it was committed into the diode outbox (across the
  diode, confirm at the SOC that a `robot.agent.selftest` finding with the
  printed nonce in its detail arrived). The daemon takes at most one
  request per second; a request still pending blocks a second one (`FAIL
  request not written`).
