#!/usr/bin/env python3
"""Run the Elastic content against a real Elasticsearch.

    live_check.py --es URL --findings FINDINGS.ndjson

URL may carry basic-auth credentials (http://user:password@host:9200).

Installs both ingest pipelines and the index template from this directory
(PUT, overwriting objects of the same name: use a scratch cluster), then:

1. `_simulate`s every finding through `robodr-findings` and, with the
   `robodr_verification` object robodr_verify.py adds, through
   `robodr-findings-verified`, and checks the ECS fields check_content.py
   checks (`@timestamp`, `rule.id`, `rule.name`, `host.id`,
   `event.severity`, `event.id`, `robodr.finding_id`, `event.kind` alert,
   `threat.technique.id`, `source.ip`) and where the status ends up;
2. `_simulate`s a finding carrying a forged status (robodr_verification,
   a robodr object, a dotted `robodr.verification.status` key) through
   `robodr-findings`: no robodr.verification;
3. indexes every finding into the data stream `logs-robodr.findings-check`
   (verified pipeline; the template's default pipeline for the forged one)
   and searches it: one verified document per finding, none from the forged
   one, and a tainted `.value` is not searchable while its `.display` is.

The data stream is deleted before and after. Exit 0 when everything holds,
1 with a list of problems. Uses only the standard library.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DS = "logs-robodr.findings-check"
STATUS = {"status": "verified", "key_id": "finding:live-check:1"}

problems: list[str] = []


def problem(msg):
    problems.append(msg)


def call(es, method, path, body=None, ndjson=False, extra_headers=None):
    data = None
    headers = dict(extra_headers or {})
    if body is not None:
        data = body.encode() if ndjson else json.dumps(body).encode()
        headers["Content-Type"] = "application/x-ndjson" if ndjson else "application/json"
    u = urllib.parse.urlsplit(es)
    if u.username is not None:  # http://user:password@host:port
        cred = f"{urllib.parse.unquote(u.username)}:{urllib.parse.unquote(u.password or '')}"
        headers["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
        es = urllib.parse.urlunsplit((u.scheme, u.hostname + (f":{u.port}" if u.port else ""), u.path, "", ""))
    req = urllib.request.Request(es.rstrip("/") + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(doc, path):
    cur = doc
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


def expected(f):
    techs = list(dict.fromkeys(m["technique_id"] for m in f["mitre_predictions"]))
    return {
        "@timestamp": f["timestamp"],
        "rule.id": f["entity_context"]["rule_id"],
        "rule.name": f["title"],
        "host.id": f["entity_context"]["robot"]["id"],
        "event.severity": f["ocsf"]["severity_id"],
        "event.id": f["ocsf"]["metadata"]["uid"],
        "robodr.finding_id": f["finding_id"],
        "event.kind": "alert",
        "threat.technique.id": techs or None,
        "source.ip": get(f, "entity_context.ros.src_ip.display"),
    }


def simulate(es, pipeline, docs):
    code, r = call(es, "POST", f"/_ingest/pipeline/{pipeline}/_simulate",
                   {"docs": [{"_index": DS, "_source": d} for d in docs]})
    if code != 200:
        raise SystemExit(f"_simulate {pipeline}: HTTP {code}: {r}")
    return [d.get("doc", {}).get("_source", {"error": d.get("error")}) for d in r["docs"]]


def install(es):
    """PUT both ingest pipelines and the index template."""
    for name, file in (("robodr-findings", "ingest-pipeline-robodr-findings.json"),
                       ("robodr-findings-verified", "ingest-pipeline-robodr-findings-verified.json")):
        code, r = call(es, "PUT", f"/_ingest/pipeline/{name}", load(file))
        if code != 200:
            raise SystemExit(f"PUT pipeline {name}: HTTP {code}: {r}")
    code, r = call(es, "PUT", "/_index_template/robodr-findings", load("index-template-robodr-findings.json"))
    if code != 200:
        raise SystemExit(f"PUT index template: HTTP {code}: {r}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--es", required=True)
    ap.add_argument("--findings", required=True)
    a = ap.parse_args(argv)
    with open(a.findings, encoding="utf-8") as fh:
        findings = [json.loads(line) for line in fh if line.strip()]
    if not findings:
        raise SystemExit("no findings")
    es = a.es
    code, info = call(es, "GET", "/")
    if code != 200:
        raise SystemExit(f"{es}: HTTP {code}")
    version = info.get("version", {}).get("number", "?")
    install(es)

    # 1. Every finding through both pipelines.
    plain = simulate(es, "robodr-findings", findings)
    verified = simulate(es, "robodr-findings-verified",
                        [dict(copy.deepcopy(f), robodr_verification=dict(STATUS)) for f in findings])
    for n, (f, p, v) in enumerate(zip(findings, plain, verified), 1):
        for pipe, doc, status in (("robodr-findings", p, None), ("robodr-findings-verified", v, STATUS)):
            where = f"{pipe} finding {n} ({f['entity_context']['rule_id']})"
            for k, want in expected(f).items():
                if get(doc, k) != want:
                    problem(f"{where}: {k} = {get(doc, k)!r}, want {want!r} (error {doc.get('error')})")
            if get(doc, "robodr.verification") != status or "robodr_verification" in doc:
                problem(f"{where}: robodr.verification = {get(doc, 'robodr.verification')!r}")
            if "robodr_verified_by_forwarder" in doc:
                problem(f"{where}: staging field left in the document")

    # 2. A forged status on the unverified pipeline.
    forged = copy.deepcopy(findings[0])
    forged["robodr_verification"] = dict(STATUS)
    forged["robodr"] = {"verification": dict(STATUS)}
    # A dotted key: not reachable as the path `robodr` in the pipeline, but
    # mapped as robodr.verification.status when indexed.
    forged["robodr.verification.status"] = "verified"
    (doc,) = simulate(es, "robodr-findings", [forged])
    dotted = [k for k in doc if k.startswith("robodr.") or k.startswith("robodr_verification")]
    if dotted:
        problem(f"robodr-findings kept forged dotted keys {dotted}")
    if get(doc, "event.kind") != "alert" or get(doc, "robodr.verification") is not None:
        problem(f"robodr-findings kept a forged status: {get(doc, 'robodr.verification')!r}, "
                f"event.kind {get(doc, 'event.kind')!r}")

    # 3. Index and search.
    call(es, "DELETE", f"/_data_stream/{DS}")
    lines = []
    for f in findings:
        lines.append(json.dumps({"create": {"_index": DS, "pipeline": "robodr-findings-verified"}}))
        lines.append(json.dumps(dict(copy.deepcopy(f), robodr_verification=dict(STATUS))))
    lines.append(json.dumps({"create": {"_index": DS}}))  # default pipeline: robodr-findings
    lines.append(json.dumps(forged))
    code, r = call(es, "POST", "/_bulk?refresh=true", "\n".join(lines) + "\n", ndjson=True)
    if code != 200 or r.get("errors"):
        bad = [i for i in r.get("items", []) if i.get("create", {}).get("error")]
        problem(f"bulk index: HTTP {code}, {len(bad)} error(s): {bad[:2]}")

    def count(query):
        code, r = call(es, "POST", f"/{DS}/_count", {"query": query})
        if code != 200:
            problem(f"_count {query}: HTTP {code}: {r}")
            return -1
        return r["count"]

    total = count({"match_all": {}})
    if total != len(findings) + 1:
        problem(f"indexed {total} documents, want {len(findings) + 1}")
    n_verified = count({"term": {"robodr.verification.status": "verified"}})
    if n_verified != len(findings):
        problem(f"{n_verified} documents verified, want {len(findings)} (the forged one must not be)")
    tainted = next((f for f in findings if get(f, "entity_context.ros.topic.value")), None)
    if tainted is None:
        problem("no finding with a tainted topic to check the template")
    else:
        topic = tainted["entity_context"]["ros"]["topic"]
        if count({"term": {"robodr.entity_context.ros.topic.display": topic["display"]}}) < 1:
            problem("the escaped topic display is not searchable")
        code, r = call(es, "POST", f"/{DS}/_count",
                       {"query": {"term": {"robodr.entity_context.ros.topic.value": topic["value"]}}})
        if code == 200 and r.get("count"):
            problem("the raw tainted topic value is searchable")
    call(es, "DELETE", f"/_data_stream/{DS}")

    for p in problems:
        print(p)
    print(f"live_check: Elasticsearch {version}, {len(findings)} finding(s), {len(problems)} problem(s)",
          file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
