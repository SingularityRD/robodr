#!/usr/bin/env python3
"""Run the Elastic detection rules in a real Kibana.

    live_check_rules.py --es URL --kibana URL --findings FINDINGS.ndjson

URLs may carry basic-auth credentials (http://user:password@host:port); the
user needs the rights to create detection rules and to read the preview
alerts index. Use a scratch deployment: the pipelines, template and the six
rules (by rule_id) are overwritten, and test documents are indexed into the
data stream `logs-robodr.findings-rulecheck` (deleted before and after).

1. Installs the pipelines and template (live_check.py), and creates every
   rule in detection-rules/ through POST /api/detection_engine/rules, as
   the README does (shipped disabled; the check does not enable them).
2. For each shared detection, takes a finding whose rule id it names and
   indexes four copies with @timestamp now: `verified` (pipeline
   robodr-findings-verified, status verified), `unsigned` (same pipeline,
   status unsigned, as --policy optional writes), `raw` (default pipeline)
   and `forged` (default pipeline, carrying a forged robodr_verification
   and a dotted robodr.verification.status key).
3. Previews each rule (POST /api/detection_engine/rules/preview, one
   invocation) and reads the preview alerts: a shared detection must alert
   on exactly its own verified, raw and forged copies; "Unverified findings"
   on every unsigned, raw and forged copy and on no verified one.

Exit 0 when everything holds, 1 with a list of problems.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import glob
import json
import os
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import live_check  # noqa: E402

DS = "logs-robodr.findings-rulecheck"
SHARED = {
    "unauthorised-motion-source.json",
    "motion-outside-envelope.json",
    "correlated-intrusion.json",
    "sensor-blind.json",
    "unknown-participant-burst.json",
}
UNVERIFIED = "unverified-findings.json"
KBN = {"kbn-xsrf": "true", "elastic-api-version": "2023-10-31"}

problems: list[str] = []


def problem(msg):
    problems.append(msg)


def kibana(url, method, path, body=None):
    return live_check.call(url, method, path, body, extra_headers=KBN)


def rule_ids_of(query):
    """Rule ids (or `x.*` prefixes) a generated query names."""
    import re

    return re.findall(r"rule\.id : \"?([a-z0-9_.*]+)\"?", query)


def matches(rule_id, pats):
    return any(rule_id.startswith(p[:-1]) if p.endswith("*") else rule_id == p for p in pats)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--es", required=True)
    ap.add_argument("--kibana", required=True)
    ap.add_argument("--findings", required=True)
    a = ap.parse_args(argv)
    with open(a.findings, encoding="utf-8") as fh:
        findings = [json.loads(line) for line in fh if line.strip()]
    es, kb = a.es, a.kibana

    code, st = kibana(kb, "GET", "/api/status")
    if code != 200:
        raise SystemExit(f"{kb}: HTTP {code}")
    version = st.get("version", {}).get("number", "?")
    live_check.install(es)

    rules = {}
    for path in sorted(glob.glob(os.path.join(HERE, "detection-rules", "*.json"))):
        with open(path, encoding="utf-8") as fh:
            rules[os.path.basename(path)] = json.load(fh)
    if set(rules) != SHARED | {UNVERIFIED}:
        problem(f"detection-rules: {sorted(rules)}")
    for name, rule in rules.items():
        kibana(kb, "DELETE", f"/api/detection_engine/rules?rule_id={rule['rule_id']}")
        code, r = kibana(kb, "POST", "/api/detection_engine/rules", rule)
        if code != 200:
            problem(f"{name}: create: HTTP {code}: {r}")

    # Test documents, @timestamp now.
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    live_check.call(es, "DELETE", f"/_data_stream/{DS}")
    lines, want = [], {}
    for name in sorted(SHARED & set(rules)):
        pats = rule_ids_of(rules[name]["query"])
        f = next((f for f in findings if matches(f["entity_context"]["rule_id"], pats)), None)
        if f is None:
            problem(f"{name}: no finding for {pats}")
            continue
        for variant in ("verified", "unsigned", "raw", "forged"):
            d = copy.deepcopy(f)
            d["timestamp"] = stamp
            d["ocsf"]["metadata"]["uid"] = f"rulecheck-{variant}-{name}"
            action = {"create": {"_index": DS}}
            if variant in ("verified", "unsigned"):
                action["create"]["pipeline"] = "robodr-findings-verified"
                d["robodr_verification"] = {"status": variant, "key_id": "finding:rulecheck:1"}
            if variant == "forged":
                d["robodr_verification"] = {"status": "verified", "key_id": "finding:rulecheck:1"}
                d["robodr.verification.status"] = "verified"
            lines += [json.dumps(action), json.dumps(d)]
        want[name] = {f"rulecheck-{v}-{name}" for v in ("verified", "raw", "forged")}
    want[UNVERIFIED] = {f"rulecheck-{v}-{n}" for n in SHARED & set(rules) for v in ("unsigned", "raw", "forged")}
    code, r = live_check.call(es, "POST", "/_bulk?refresh=true", "\n".join(lines) + "\n", ndjson=True)
    if code != 200 or r.get("errors"):
        problem(f"bulk index: HTTP {code}: {[i for i in r.get('items', []) if i['create'].get('error')][:2]}")

    end = (now + datetime.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for name, rule in sorted(rules.items()):
        body = {k: v for k, v in rule.items() if k not in ("rule_id", "enabled", "version")}
        body.update({"invocationCount": 1, "timeframeEnd": end})
        code, r = kibana(kb, "POST", "/api/detection_engine/rules/preview", body)
        if code != 200 or r.get("isAborted") or "previewId" not in r:
            problem(f"{name}: preview: HTTP {code}: {r}")
            continue
        errors = [m for log in r.get("logs", []) for m in log.get("errors", [])]
        if errors:
            problem(f"{name}: preview errors: {errors}")
        got = set()
        for _ in range(10):
            code, s = live_check.call(es, "POST", "/.preview.alerts-security.alerts-*/_search", {
                "size": 1000,
                "query": {"term": {"kibana.alert.rule.uuid": r["previewId"]}},
                "_source": ["event.id"],
            })
            got = {live_check.get(h["_source"], "event.id") or h["_source"].get("event.id")
                   for h in s.get("hits", {}).get("hits", [])} if code == 200 else set()
            if got:
                break
            time.sleep(1)
        got = {g for g in got if g and g.startswith("rulecheck-")}
        if got != want.get(name, set()):
            problem(f"{name}: alerts on {sorted(got)}, want {sorted(want.get(name, set()))}")
    live_check.call(es, "DELETE", f"/_data_stream/{DS}")

    for p in problems:
        print(p)
    print(f"live_check_rules: Kibana {version}, {len(rules)} rule(s), {len(problems)} problem(s)", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
