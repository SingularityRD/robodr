#!/usr/bin/env python3
"""Check the SIEM content in integrations/ against the findings contract.

    check_content.py [--findings FINDINGS.ndjson]

1. Every .json / .yaml / .yml file under integrations/ parses.
2. Every finding field the content reads (Splunk props and searches, the
   Elastic pipeline, the Sentinel DCR) exists in the contract schema
   (docs/contracts/robodr-finding.schema.json).
3. Every RoboDR rule id the content names is in the detection catalog
   (docs/customer/detection-catalog.md); a `robot.x.*` prefix must match at
   least one catalog id.
4. The Elastic and Sentinel detection rules are what gen_detections.py
   generates, and Splunk's saved searches name the same rule ids.
5. The Sentinel DCR outputs exactly the table's columns and reads only
   declared input columns, which are contract fields.
6. With --findings: the Elastic ingest pipeline, evaluated on each finding
   by the evaluator below, yields the expected ECS fields and no failure.
   The evaluator implements only the processors and options the pipeline
   uses and fails on anything else, so a new processor needs a new
   evaluator branch (it is not Elasticsearch).

Exit 0 when everything holds, 1 with a list of problems otherwise.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCHEMA = os.path.join(ROOT, "docs/contracts/robodr-finding.schema.json")
CATALOG = os.path.join(ROOT, "docs/customer/detection-catalog.md")
TOP = (
    "contract_version finding_id external_id data_source title description severity "
    "timestamp entity_context mitre_predictions evidence_links anomaly_score "
    "adversary_controlled_fields ocsf"
).split()
# Fields a verifying forwarder adds (integrations/verify/robodr_verify.py).
ADDED = {"robodr_verification", "robodr_verification.status", "robodr_verification.key_id"}

problems: list[str] = []


def problem(msg):
    problems.append(msg)


# ------------------------------------------------------------------ schema


def load_schema():
    with open(SCHEMA, encoding="utf-8") as fh:
        return json.load(fh)


def resolve(schema, node, seen=0):
    while isinstance(node, dict) and "$ref" in node and seen < 20:
        ref = node["$ref"]
        assert ref.startswith("#/"), ref
        node = schema
        for part in ref[2:].split("/"):
            node = node[part]
        seen += 1
    return node


def subschemas(schema, node):
    node = resolve(schema, node)
    out = [node]
    for k in ("allOf", "anyOf", "oneOf"):
        for s in node.get(k, []) if isinstance(node, dict) else []:
            out.extend(subschemas(schema, s))
    return out


def path_exists(schema, path: str) -> bool:
    """`a.b{}.c` (Splunk) / `a.b.c` (arrays transparent) in the schema."""
    parts = [p for p in re.split(r"\.|\{\}", path) if p]
    nodes = [schema]
    for part in parts:
        nxt = []
        for n in nodes:
            for s in subschemas(schema, n):
                if not isinstance(s, dict):
                    continue
                if s.get("type") == "array" or "items" in s:
                    for it in subschemas(schema, s.get("items", {})):
                        props = it.get("properties", {}) if isinstance(it, dict) else {}
                        if part in props:
                            nxt.append(props[part])
                props = s.get("properties", {})
                if part in props:
                    nxt.append(props[part])
        if not nxt:
            return False
        nodes = nxt
    return True


# ------------------------------------------------------------------ catalog


def catalog_ids():
    with open(CATALOG, encoding="utf-8") as fh:
        text = fh.read()
    return set(re.findall(r"^\| `(robot\.[a-z0-9_.]+)` \|", text, re.M))


RULE_RE = re.compile(r"(?<![\w.])robot\.[a-z0-9_]+\.(?:[a-z0-9_]+|\*)(?![\w])")


def check_rule_ids(name, text, ids):
    for r in sorted(set(RULE_RE.findall(text))):
        if r.endswith("*"):
            if not any(i.startswith(r[:-1]) for i in ids):
                problem(f"{name}: rule prefix {r} matches no catalog id")
        elif r not in ids:
            problem(f"{name}: rule id {r} is not in the detection catalog")


# ------------------------------------------------------------------ field refs

FIELD_RE = re.compile(
    r"(?<![\w.'\"])((?:entity_context|ocsf|mitre_predictions|evidence_links|adversary_controlled_fields)"
    r"(?:\{\})?(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\{\})?)*)"
)


def check_fields(name, refs, schema):
    for f in sorted(set(refs)):
        if f in ADDED or f.startswith("robodr_verification."):
            continue
        if not path_exists(schema, f):
            problem(f"{name}: field {f} is not in the contract schema")


def splunk(schema, ids):
    base = os.path.join(HERE, "splunk/TA-robodr/default")
    refs = {}
    for fn in ("props.conf", "savedsearches.conf", "eventtypes.conf"):
        with open(os.path.join(base, fn), encoding="utf-8") as fh:
            text = fh.read()
        check_rule_ids(f"splunk/{fn}", text, ids)
        found = FIELD_RE.findall(text)
        found += re.findall(r"'([a-z_][\w.{}]*)'", text)  # EVAL field references
        refs[fn] = [f for f in found if f.split(".")[0].split("{")[0] in TOP or f in ADDED]
        # Every FIELDALIAS source is a finding field ("finding_id AS id").
        for m in re.finditer(r"^FIELDALIAS-[\w]+\s*=\s*(.*)$", text, re.M):
            toks = m.group(1).split()
            refs[fn] += [toks[i - 1] for i, t in enumerate(toks) if t == "AS" and i > 0]
        check_fields(f"splunk/{fn}", refs[fn], schema)
    # The saved searches name the same rule ids as the generated detections.
    gen = load_gen()
    with open(os.path.join(base, "savedsearches.conf"), encoding="utf-8") as fh:
        stanzas = re.split(r"^\[(.+)\]\s*$", fh.read(), flags=re.M)
    by_name = {stanzas[i]: stanzas[i + 1] for i in range(1, len(stanzas), 2)}
    for d in gen.DET:
        body = by_name.get(d["name"])
        if body is None:
            problem(f"splunk/savedsearches.conf: no saved search [{d['name']}]")
            continue
        got = set(RULE_RE.findall(body))
        if got != set(d["rules"]):
            problem(f"splunk/savedsearches.conf [{d['name']}]: rule ids {sorted(got)} != {sorted(d['rules'])}")


def load_gen():
    spec = importlib.util.spec_from_file_location("gen_detections", os.path.join(HERE, "gen_detections.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def generated_match():
    gen = load_gen()
    with tempfile.TemporaryDirectory() as d:
        import contextlib
        import io

        with contextlib.redirect_stdout(io.StringIO()):
            gen.write(d)
        for sub in ("elastic/detection-rules", "sentinel/analytics"):
            want = sorted(os.listdir(os.path.join(d, sub)))
            have = sorted(f for f in os.listdir(os.path.join(HERE, sub)) if not f.startswith("."))
            if want != have:
                problem(f"{sub}: files {have} != generated {want}")
                continue
            for f in want:
                with open(os.path.join(d, sub, f), encoding="utf-8") as a, open(
                    os.path.join(HERE, sub, f), encoding="utf-8"
                ) as b:
                    if a.read() != b.read():
                        problem(f"{sub}/{f} differs from gen_detections.py output; regenerate")


# ------------------------------------------------------------------ elastic

MUSTACHE = re.compile(r"\{\{\{([^}]+)\}\}\}")


def get_path(doc, path):
    cur = doc
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def set_path(doc, path, value):
    cur = doc
    parts = path.split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def del_path(doc, path):
    cur = doc
    parts = path.split(".")
    for p in parts[:-1]:
        cur = cur[p]
    del cur[parts[-1]]


def render(tpl, doc, ingest):
    def sub(m):
        key = m.group(1).strip()
        if key.startswith("_ingest."):
            v = get_path(ingest, key[len("_ingest."):])
        else:
            v = get_path(doc, key)
        return "" if v is None else (v if isinstance(v, str) else json.dumps(v))

    return MUSTACHE.sub(sub, tpl)


class PipelineError(Exception):
    pass


def run_processor(p, doc, ingest):
    (kind, o), = p.items()
    allowed = {
        "rename": {"field", "target_field", "ignore_missing"},
        "date": {"field", "target_field", "formats"},
        "set": {"field", "value", "copy_from", "ignore_empty_value"},
        "append": {"field", "value", "allow_duplicates"},
        "foreach": {"field", "processor", "ignore_missing"},
    }
    if kind not in allowed or set(o) - allowed[kind]:
        raise SystemExit(f"evaluator: unsupported processor/options {kind} {sorted(o)}")
    if kind == "rename":
        v = get_path(doc, o["field"])
        if v is None:
            if o.get("ignore_missing"):
                return
            raise PipelineError(f"field [{o['field']}] doesn't exist")
        if get_path(doc, o["target_field"]) is not None:
            raise PipelineError(f"field [{o['target_field']}] already exists")
        del_path(doc, o["field"])
        set_path(doc, o["target_field"], v)
    elif kind == "date":
        v = get_path(doc, o["field"])
        if not isinstance(v, str) or not re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$", v):
            raise PipelineError(f"date: unparseable {v!r}")
        set_path(doc, o["target_field"], v)
    elif kind == "set":
        if "copy_from" in o:
            v = get_path(doc, o["copy_from"])
            if v is None:
                raise PipelineError(f"copy_from [{o['copy_from']}] missing")
            set_path(doc, o["field"], copy.deepcopy(v))
        else:
            v = o["value"]
            if isinstance(v, str):
                v = render(v, doc, ingest)
                if v == "" and o.get("ignore_empty_value"):
                    return
            set_path(doc, o["field"], copy.deepcopy(v))
    elif kind == "append":
        v = render(o["value"], doc, ingest) if isinstance(o["value"], str) else o["value"]
        cur = get_path(doc, o["field"])
        lst = [] if cur is None else (cur if isinstance(cur, list) else [cur])
        if o.get("allow_duplicates", True) or v not in lst:
            lst.append(v)
        set_path(doc, o["field"], lst)
    elif kind == "foreach":
        arr = get_path(doc, o["field"])
        if arr is None:
            if o.get("ignore_missing"):
                return
            raise PipelineError(f"foreach field [{o['field']}] missing")
        for item in arr:
            run_processor(o["processor"], doc, {"_value": item})


def run_pipeline(pipeline, doc):
    try:
        for p in pipeline["processors"]:
            run_processor(p, doc, {})
    except PipelineError as e:
        for p in pipeline.get("on_failure", []):
            run_processor(p, doc, {"on_failure_message": str(e)})
    return doc


def elastic(schema, ids, findings):
    with open(os.path.join(HERE, "elastic/ingest-pipeline-robodr-findings.json"), encoding="utf-8") as fh:
        pipeline = json.load(fh)
    text = json.dumps(pipeline)
    check_rule_ids("elastic pipeline", text, ids)
    refs = []
    for p in pipeline["processors"]:
        (kind, o), = p.items()
        if kind == "rename":
            refs.append(o["field"])
        for k in ("field", "copy_from"):
            v = o.get(k)
            if k == "copy_from" and v and v.startswith("robodr."):
                refs.append(v[len("robodr."):])
        for m in MUSTACHE.findall(json.dumps(o)):
            if m.startswith("robodr."):
                refs.append(m[len("robodr."):])
    # Renamed names map back to the contract (robodr.verification <- robodr_verification).
    refs = [r.replace("verification", "robodr_verification", 1) if r.startswith("verification") else r for r in refs]
    check_fields("elastic pipeline", refs, schema)
    for f in os.listdir(os.path.join(HERE, "elastic/detection-rules")):
        with open(os.path.join(HERE, "elastic/detection-rules", f), encoding="utf-8") as fh:
            rule = json.load(fh)
        check_rule_ids(f"elastic/detection-rules/{f}", rule["query"], ids)
        for field in re.findall(r"([a-z_.]+)\s*:", rule["query"]):
            if field not in ("event.module", "rule.id"):
                problem(f"elastic/detection-rules/{f}: query uses {field}, which the pipeline does not set")
    for n, f in enumerate(findings, 1):
        doc = run_pipeline(pipeline, copy.deepcopy(f))
        where = f"elastic pipeline on finding {n} ({f['entity_context']['rule_id']})"
        if doc.get("event", {}).get("kind") != "alert":
            problem(f"{where}: failed: {doc.get('error')}")
            continue
        want = {
            "@timestamp": f["timestamp"],
            "rule.id": f["entity_context"]["rule_id"],
            "rule.name": f["title"],
            "host.id": f["entity_context"]["robot"]["id"],
            "event.severity": f["ocsf"]["severity_id"],
            "event.id": f["ocsf"]["metadata"]["uid"],
            "robodr.finding_id": f["finding_id"],
        }
        for k, v in want.items():
            if get_path(doc, k) != v:
                problem(f"{where}: {k} = {get_path(doc, k)!r}, want {v!r}")
        techs = [m["technique_id"] for m in f["mitre_predictions"]]
        if (get_path(doc, "threat.technique.id") or []) != list(dict.fromkeys(techs)):
            problem(f"{where}: threat.technique.id {get_path(doc, 'threat.technique.id')} != {techs}")
        leftover = [k for k in TOP if k in doc]
        if leftover:
            problem(f"{where}: contract fields left at the root: {leftover}")
        src = get_path(f, "entity_context.ros.src_ip.display")
        if get_path(doc, "source.ip") != src:
            problem(f"{where}: source.ip {get_path(doc, 'source.ip')!r} != {src!r}")


# ------------------------------------------------------------------ sentinel


def sentinel(schema, ids):
    base = os.path.join(HERE, "sentinel")
    with open(os.path.join(base, "RoboDRFindings_CL.table.json"), encoding="utf-8") as fh:
        table = {c["name"]: c["type"] for c in json.load(fh)["properties"]["schema"]["columns"]}
    with open(os.path.join(base, "dcr-robodr-findings.json"), encoding="utf-8") as fh:
        dcr = json.load(fh)
    props = dcr["properties"]
    (stream_name, stream), = props["streamDeclarations"].items()
    inputs = {c["name"] for c in stream["columns"]}
    for c in inputs - set(TOP) - {"robodr_verification"}:
        problem(f"sentinel DCR: input column {c} is not a contract field")
    (flow,) = props["dataFlows"]
    if flow["streams"] != [stream_name] or flow["outputStream"] != "Custom-RoboDRFindings_CL":
        problem("sentinel DCR: data flow does not connect the declared stream to RoboDRFindings_CL")
    kql = flow["transformKql"]
    m = re.match(r"^source \| project (.*)$", kql, re.S)
    if not m:
        problem("sentinel DCR: transformKql must be `source | project ...`")
        return
    outs = re.findall(r"(?:^|,\s*)([A-Za-z]+)\s*=", m.group(1))
    if set(outs) != set(table):
        problem(f"sentinel DCR: outputs {sorted(set(outs) ^ set(table))} differ from the table columns")
    refs = FIELD_RE.findall(kql.replace("['count']", ".count"))
    check_fields("sentinel DCR", refs, schema)
    for r in refs:
        if r.split(".")[0] not in inputs:
            problem(f"sentinel DCR: reads {r} from an undeclared input column")
    for f in os.listdir(os.path.join(base, "analytics")):
        with open(os.path.join(base, "analytics", f), encoding="utf-8") as fh:
            text = fh.read()
        check_rule_ids(f"sentinel/analytics/{f}", text, ids)
        for col in re.findall(r"\b([A-Z][A-Za-z]+)\b", text.split("query: |", 1)[1].split("entityMappings")[0]):
            if col not in table and col not in ("RoboDRFindings", "Count", "FirstSeen", "LastSeen", "RuleIds", "SourceIps", "Verification"):
                problem(f"sentinel/analytics/{f}: query uses unknown column {col}")
    with open(os.path.join(base, "RoboDRFindings.kql"), encoding="utf-8") as fh:
        parser = fh.read()
    for col in re.findall(r"\b([A-Z][A-Za-z]+)\b", parser.split("RoboDRFindings_CL", 1)[1]):
        if col not in table and col not in ("RuleFamily", "TechniqueIds"):
            problem(f"sentinel parser: unknown column {col}")


# ------------------------------------------------------------------ main


def parse_all():
    try:
        import yaml
    except ImportError:
        yaml = None
    for dp, _, fs in os.walk(HERE):
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, HERE)
            try:
                if f.endswith(".json"):
                    with open(p, encoding="utf-8") as fh:
                        json.load(fh)
                elif f.endswith((".yaml", ".yml")):
                    if yaml is None:
                        problem(f"{rel}: PyYAML not installed, cannot check")
                    else:
                        with open(p, encoding="utf-8") as fh:
                            yaml.safe_load(fh)
            except Exception as e:  # noqa: BLE001
                problem(f"{rel}: does not parse: {e}")


def main(argv):
    findings = []
    if "--findings" in argv:
        path = argv[argv.index("--findings") + 1]
        with open(path, encoding="utf-8") as fh:
            findings = [json.loads(line) for line in fh if line.strip()]
    schema = load_schema()
    ids = catalog_ids()
    if len(ids) < 100:
        problem(f"detection catalog has only {len(ids)} ids: is {CATALOG} generated?")
    parse_all()
    splunk(schema, ids)
    generated_match()
    elastic(schema, ids, findings)
    sentinel(schema, ids)
    with open(os.path.join(HERE, "README.md"), encoding="utf-8") as fh:
        readme = fh.read()
    check_rule_ids("README.md", readme, ids)
    check_fields("README.md", FIELD_RE.findall(readme), schema)
    for p in problems:
        print(p)
    print(
        f"check_content: {len(problems)} problem(s), {len(findings)} finding(s) through the Elastic pipeline",
        file=sys.stderr,
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
