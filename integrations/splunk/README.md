# Splunk add-on (TA-robodr)

```sh
tar -C integrations/splunk -czf TA-robodr.tgz TA-robodr
# Splunk: Apps > Install app from file, or copy TA-robodr to $SPLUNK_HOME/etc/apps/
```

* Sourcetype `robodr:finding`: one finding per event (JSON, `KV_MODE = json`,
  time from `timestamp`). Send with Splunk Connect for Kafka (topic
  `robodr.findings`) or HEC, after `integrations/verify/robodr_verify.py`
  when you want `robodr_verification.status` on each event.
* CIM Intrusion Detection aliases: `signature_id` (rule id), `signature`,
  `dest` (robot id), `src`/`src_ip` (escaped source address), `severity`,
  `category`, `vendor_product`, `ids_type`. Tag `ids`, `attack`.
* Saved searches (disabled until you enable them): the five detections of
  `integrations/README.md` plus "Unverified findings". Observe-only.

Checked by `integrations/check_content.py` (every field and rule id). Not
yet installed on a live Splunk instance.
