# Elastic Security

```sh
# 1. Ingest pipeline and index template (data stream logs-robodr.findings-*)
curl -u elastic -H 'Content-Type: application/json' -X PUT \
  "$ES/_ingest/pipeline/robodr-findings" --data-binary @ingest-pipeline-robodr-findings.json
curl -u elastic -H 'Content-Type: application/json' -X PUT \
  "$ES/_index_template/robodr-findings" --data-binary @index-template-robodr-findings.json

# 2. Detection rules (shipped disabled; enable after a look at your data)
for f in detection-rules/*.json; do
  curl -u elastic -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -X POST \
    "$KIBANA/api/detection_engine/rules" --data-binary @"$f"
done
```

Feed: `../logstash/robodr-kafka.conf` (Kafka -> `robodr_verify.py` ->
Elasticsearch), or index `robodr_verify.py` output directly with the
`robodr-findings` pipeline. The pipeline expects the finding's top-level
fields at the document root and moves them under `robodr.*`, then sets the
ECS fields (`integrations/README.md`, "Field mapping").

Attacker-controlled values are stored but not indexed: the raw tainted
names (`robodr.entity_context.**.value`; search and show the escaped
`.display` forms), `robodr.ocsf.resources` (tainted participant and topic
names) and `robodr.ocsf.unmapped` (a copy of `entity_context`). Other
strings under `robodr.*` are indexed as keywords. `source.ip` is set from the
escaped source address only when that is an IP address; otherwise the
pipeline drops it and the document is still indexed.

The detection rules drop findings whose `robodr.verification.status` is
present and not `verified`; findings indexed without `robodr_verify.py` have
no status and still alert. `detection-rules/unverified-findings.json` reports
every finding that is not verified (`integrations/README.md`).

Checked by `integrations/check_content.py` (field references, rule ids, and
the pipeline evaluated on real findings by an in-repo evaluator); not yet run
against a live Elasticsearch: `POST _ingest/pipeline/robodr-findings/_simulate`
with a finding from `docs/contracts/robodr-finding.example.json` is the first
thing to do on a real cluster.
