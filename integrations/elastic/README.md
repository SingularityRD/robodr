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

Tainted DDS names (`robodr.entity_context.**.value`) are stored but not
indexed; search and show the escaped `.display` forms. `robodr.ocsf.unmapped`
duplicates `entity_context` and is stored only.

Checked by `integrations/check_content.py` (field references, rule ids, and
the pipeline evaluated on real findings by an in-repo evaluator); not yet run
against a live Elasticsearch: `POST _ingest/pipeline/robodr-findings/_simulate`
with a finding from `docs/contracts/robodr-finding.example.json` is the first
thing to do on a real cluster.
