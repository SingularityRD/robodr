# Splunk add-on (TA-robodr)

```sh
tar -C integrations/splunk -czf TA-robodr.tgz TA-robodr
# Splunk: Apps > Install app from file, or copy TA-robodr to $SPLUNK_HOME/etc/apps/
```

* Sourcetype `robodr:finding`: one finding per event (JSON, `KV_MODE = json`,
  time from `timestamp`). Send with Splunk Connect for Kafka (topic
  `robodr.findings`) or HEC. Splunk Connect for Kafka does not verify
  signatures, and an event's producer chooses all of it, so on this
  sourcetype `robodr_verification_status` is always null, whatever
  `robodr_verification` the event carries. Keep `splunk.header.support` off
  on the connector so a Kafka record header cannot choose the sourcetype.
* Sourcetype `robodr:finding:verified`: the same settings, for the output of
  `integrations/verify/robodr_verify.py` only (run it on your own consumer
  and send by HEC with this sourcetype; not shipped). Here
  `robodr_verification_status` is the status the verifier wrote. Give that
  HEC token to the verifier alone.
* CIM Intrusion Detection aliases: `signature_id` (rule id), `signature`,
  `dest` (robot id), `src`/`src_ip` (escaped source address), `severity`,
  `category`, `vendor_product`, `ids_type`. Tag `ids`, `attack`.
* Saved searches (disabled until you enable them): the five detections of
  `integrations/README.md`, which drop events whose
  `robodr_verification_status` is present and not `verified` (events with
  no status still alert), plus "Unverified findings": every event that is
  not verified, including those with no status (counted as `none`).
  Observe-only. No search reads `robodr_verification.status` directly.

Checked by `integrations/check_content.py` (every field and rule id, the two
sourcetypes identical but for the status). Not yet installed on a live
Splunk instance. On `robodr:finding`, a forged top-level
`robodr_verification_status` key in the event JSON is hidden only if the
calculated field `EVAL-robodr_verification_status = null()` replaces the
JSON-extracted field of the same name, as calculated fields are specified
to; that has not been observed on an instance yet.
