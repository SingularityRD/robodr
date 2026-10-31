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
| 2 | `robodr-enroll check` | SOC fleet / approval key files; TLS to the SOC (CA bundle, pins, CRLs); the URL is the fleet API; once enrolled: the uplink key file is the registered one and the SOC accepts it; a published ring document verifies | 0 ok, 1 failed, 3 SOC not reached |
| 3 | `robodr-uplink <service options> --check` | TLS (CA bundle, pins, CRLs); the URL is the RoboDR ingest API (an empty batch, refused with `400 empty_batch` before authentication: nothing sent or stored); for a `--spool` (uplink) key, the SOC accepts it (read-only fleet request) | 0 passed, 1 failed |
| 3' | `robodr-kafka-publish <service options> --check` | the client certificate and CRLs have not expired (WARN within 14 days), the Kafka cluster answers with this TLS / SASL configuration and the topic's metadata is readable; nothing produced | 0 passed, 1 failed |
| 4 | `robodr-anchor-receiver check --config /etc/robodr-anchor-receiver/receiver.json` (base station) | configuration, every unit key, the receiver key, the TLS chain / key / client CA / CRLs (an expired CRL fails here), every unit's stored state, the listen address | 0 ok, 2 failed |

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
* What the checks do not prove: that a finding travels end to end through
  agentd, the spool and the exporter to the SOC. That needs a marked
  self-test finding (`robodr-agentd selftest`, planned with the
  `robot.agent.selftest` rule id: sales-readiness T13, finding-contract
  work package).
