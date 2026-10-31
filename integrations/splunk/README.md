# Splunk add-on (TA-robodr)

```sh
tar -C integrations/splunk -czf TA-robodr.tgz TA-robodr
# Splunk: Apps > Install app from file, or copy TA-robodr to $SPLUNK_HOME/etc/apps/
```

* Sourcetype `robodr:finding`: one finding per event (JSON, `KV_MODE = json`,
  time from `timestamp`). Send with Splunk Connect for Kafka (topic
  `robodr.findings`) or HEC. Splunk Connect for Kafka does not verify
  signatures: those events carry no `robodr_verification.status`. To have
  it, run `integrations/verify/robodr_verify.py` on your own consumer and
  send its output by HEC (not shipped).
* CIM Intrusion Detection aliases: `signature_id` (rule id), `signature`,
  `dest` (robot id), `src`/`src_ip` (escaped source address), `severity`,
  `category`, `vendor_product`, `ids_type`. Tag `ids`, `attack`.
* Saved searches (disabled until you enable them): the five detections of
  `integrations/README.md`, which drop events whose
  `robodr_verification.status` is present and not `verified` (events with
  no status still alert), plus "Unverified findings": every event that is
  not verified, including those with no status. Observe-only.

Checked by `integrations/check_content.py` (every field and rule id). Not
yet installed on a live Splunk instance.
