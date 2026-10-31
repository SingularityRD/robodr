# Elastic Security

```sh
# 1. Ingest pipeline and index template (data stream logs-robodr.findings-*)
curl -u elastic -H 'Content-Type: application/json' -X PUT \
  "$ES/_ingest/pipeline/robodr-findings" --data-binary @ingest-pipeline-robodr-findings.json
curl -u elastic -H 'Content-Type: application/json' -X PUT \
  "$ES/_ingest/pipeline/robodr-findings-verified" --data-binary @ingest-pipeline-robodr-findings-verified.json
curl -u elastic -H 'Content-Type: application/json' -X PUT \
  "$ES/_index_template/robodr-findings" --data-binary @index-template-robodr-findings.json

# 2. Detection rules (shipped disabled; enable after a look at your data)
for f in detection-rules/*.json; do
  curl -u elastic -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -X POST \
    "$KIBANA/api/detection_engine/rules" --data-binary @"$f"
done
```

Feed: `../logstash/robodr-kafka.conf` (Kafka -> `robodr_verify.py` ->
Elasticsearch with the `robodr-findings-verified` pipeline), or index
`robodr_verify.py` output directly with that pipeline. Anything that did not
pass the verifier goes through `robodr-findings` instead. Both expect the
finding's top-level fields at the document root; `robodr-findings` moves
them under `robodr.*` and sets the ECS fields (`integrations/README.md`,
"Field mapping").

Verification status: `robodr-findings` first removes any
`robodr_verification` and any `robodr` object from the event (a forger on an
unverified path chooses every field), so its documents never have
`robodr.verification`. `robodr-findings-verified` sets the verifier's
`robodr_verification` aside, runs `robodr-findings`, then stores it as
`robodr.verification`. Use it only for `robodr_verify.py` output.

Attacker-controlled values are stored but not indexed: the raw tainted
names (`robodr.entity_context.**.value`; search and show the escaped
`.display` forms), `robodr.ocsf.resources` (tainted participant and topic
names) and `robodr.ocsf.unmapped` (a copy of `entity_context`). Other
strings under `robodr.*` are indexed as keywords. `source.ip` is set from the
escaped source address only when that is an IP address; otherwise the
pipeline drops it and the document is still indexed.

The detection rules drop findings whose `robodr.verification.status` is
present and not `verified`; findings indexed through `robodr-findings` have
no status and still alert. `detection-rules/unverified-findings.json` reports
every finding that is not verified (`integrations/README.md`).

`robodr-findings` first expands dotted top-level keys (`dot_expander`), so
a forged `"robodr.verification.status"` key is removed with the `robodr`
object rather than mapped as that field at index time.

Checked by `integrations/check_content.py` (field references, rule ids, and
both pipelines evaluated on real findings, and on findings carrying a
forged status, by an in-repo evaluator), and by `live_check.py` against a
real Elasticsearch:

```sh
python3 integrations/elastic/live_check.py --es http://127.0.0.1:9200 --findings findings.ndjson
# or, with one finding per catalog rule id:
ROBODR_ES_URL=http://127.0.0.1:9200 cargo test -p robodr-ocsf --test integrations_content
```

It installs both pipelines and the template (overwriting: use a scratch
cluster), `_simulate`s every finding through both pipelines, checks a forged
status is dropped, indexes into `logs-robodr.findings-check`, counts the
verified documents and checks a raw tainted value is not searchable while
its `display` is. It passed with the 166 findings of the cargo test on
Elasticsearch 8.15.3 (Docker image `elasticsearch:8.15.3`, single node,
security off) on 2026-10-31. Not run in CI. The detection rules are
Kibana objects and have not been loaded into Kibana.
