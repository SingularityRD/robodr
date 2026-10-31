#!/usr/bin/env python3
"""Check the SIEM content in integrations/ against the findings contract.

    check_content.py [--findings FINDINGS.ndjson]

1. Every .json / .yaml / .yml file under integrations/ parses.
2. Every finding field the content reads (Splunk props and searches, the
   Elastic pipeline, the Sentinel DCR) exists in the contract schema
   (docs/contracts/robodr-finding.schema.json).
3. Every RoboDR rule id the content names is in the detection catalog
   (docs/customer/detection-rules.md); a `robot.x.*` prefix must match at
   least one catalog id.
4. The Elastic and Sentinel detection rules are what gen_detections.py
   generates, and Splunk's saved searches name the same rule ids.
5. The Sentinel DCR outputs exactly the table's columns and reads only
   declared input columns, which are contract fields.
6. With --findings: the Elastic ingest pipeline, evaluated on each finding
   by the evaluator below, yields the expected ECS fields and no failure
   (also for a source address display that is not an IP: no source.ip, the
   document is kept); every adversary_controlled_fields location of each
   finding is stored but not indexed by the index template.
7. Verification status: every one of the shared detections, in all three
   SIEMs, drops findings whose verification status is present and not
   "verified" (findings from a path with no verifier carry no status and
   still alert), and each SIEM has an "Unverified findings" detection for
   everything that is not verified.
8. The status cannot be forged: a finding's producer chooses the whole
   event, so on a path without a verifier any robodr_verification it carries
   is discarded. Splunk: only sourcetype robodr:finding:verified takes
   robodr_verification_status from the event, robodr:finding forces it
   empty, and no search reads robodr_verification.status itself. Elastic:
   robodr-findings removes robodr_verification and any robodr object, also
   given as dotted top-level keys (a forged finding run through it has no
   robodr.verification);
   robodr-findings-verified keeps the verifier's status and refuses a
   document with a dotted top-level key (a forged
   robodr_verification.status would merge into it). Splunk's verified
   sourcetype reads a multivalue status as "malformed". Sentinel: the DCR's
   unverified stream does not declare robodr_verification and sets
   VerificationStatus empty; only the verified stream maps it.
9. verify/robodr_verify.py: its copy of the contract's top-level fields is
   the schema's; a correctly signed finding verifies; and each hostile
   record below (a key outside the envelope, header forms the contract
   refuses, input that used to crash it) is rejected on its own while the
   record after it is still forwarded (needs `cryptography`; skipped with
   a note without it).
   The evaluator implements only the processors and options the pipeline
   uses and fails on anything else, so a new processor needs a new
   evaluator branch (it is not Elasticsearch).

Exit 0 when everything holds, 1 with a list of problems otherwise.
"""

from __future__ import annotations

import contextlib
import copy
import fnmatch
import importlib.util
import io
import ipaddress
import json
import os
import re
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCHEMA = os.path.join(ROOT, "docs/contracts/robodr-finding.schema.json")
CATALOG = os.path.join(ROOT, "docs/customer/detection-rules.md")
TOP = (
    "contract_version finding_id external_id data_source title description severity "
    "timestamp entity_context mitre_predictions evidence_links anomaly_score "
    "adversary_controlled_fields ocsf"
).split()
# Fields a verifying forwarder adds (integrations/verify/robodr_verify.py).
ADDED = {"robodr_verification", "robodr_verification.status", "robodr_verification.key_id"}
# The filter each shared detection carries (gen_detections.py; Splunk by hand).
# robodr_verification_status is computed per sourcetype in props.conf.
SPLUNK_STATUS = "robodr_verification_status"
SPLUNK_VERIFIED = f'(NOT {SPLUNK_STATUS}=* OR {SPLUNK_STATUS}="verified")'
SPLUNK_SOURCETYPES = {
    # sourcetype -> how props.conf computes SPLUNK_STATUS for it
    "robodr:finding": "null()",
    # Only a single value: a forged dotted top-level key would add a second.
    "robodr:finding:verified": "if(mvcount('robodr_verification.status')=1, "
    "'robodr_verification.status', \"malformed\")",
}

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
        search = re.search(r"^search = (.*)$", body, re.M)
        if not search or SPLUNK_VERIFIED not in search.group(1).split("|")[0]:
            problem(f"splunk/savedsearches.conf [{d['name']}]: base search lacks {SPLUNK_VERIFIED}")
    unv = by_name.get(gen.UNVERIFIED["name"], "")
    if not re.search(r"^search = eventtype=robodr_unverified\b", unv, re.M):
        problem(f"splunk/savedsearches.conf: no [{gen.UNVERIFIED['name']}] on eventtype=robodr_unverified")
    # `stats ... by <status>` drops events without it: exactly the unverified ones.
    m = re.search(r"^search = (.*)$", unv, re.M)
    if m and re.search(rf"\bby\b[^|]*\b{SPLUNK_STATUS}\b", m.group(1)) and "fillnull value=" not in m.group(1):
        problem(f"splunk/savedsearches.conf [{gen.UNVERIFIED['name']}]: groups by {SPLUNK_STATUS} without fillnull")
    with open(os.path.join(base, "eventtypes.conf"), encoding="utf-8") as fh:
        et = fh.read()
    st = " OR ".join(f'sourcetype="{t}"' for t in SPLUNK_SOURCETYPES)
    if not re.search(rf"^\[robodr_finding\]\nsearch = {re.escape(st)}$", et, re.M):
        problem(f"splunk/eventtypes.conf: robodr_finding must be {st}")
    if not re.search(rf'^\[robodr_unverified\]\nsearch = eventtype=robodr_finding NOT {SPLUNK_STATUS}="verified"$', et, re.M):
        problem("splunk/eventtypes.conf: robodr_unverified must be every finding that is not verified")
    splunk_status(base)


def splunk_status(base):
    """The status a detection reads cannot come from an unverified event."""
    for fn in ("savedsearches.conf", "eventtypes.conf"):
        with open(os.path.join(base, fn), encoding="utf-8") as fh:
            if "robodr_verification." in fh.read():
                problem(f"splunk/{fn}: reads robodr_verification.* (forgeable on robodr:finding); use {SPLUNK_STATUS}")
    with open(os.path.join(base, "props.conf"), encoding="utf-8") as fh:
        parts = re.split(r"^\[(.+)\]\s*$", fh.read(), flags=re.M)
    stanzas = {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}
    if set(stanzas) != set(SPLUNK_SOURCETYPES):
        problem(f"splunk/props.conf: stanzas {sorted(stanzas)} != {sorted(SPLUNK_SOURCETYPES)}")
        return
    bodies = []
    for t, want in SPLUNK_SOURCETYPES.items():
        lines = [ln for ln in stanzas[t].splitlines() if ln.strip() and not ln.startswith("#")]
        evals = [ln for ln in lines if ln.startswith(f"EVAL-{SPLUNK_STATUS} ")]
        if evals != [f"EVAL-{SPLUNK_STATUS} = {want}"]:
            problem(f"splunk/props.conf [{t}]: needs exactly EVAL-{SPLUNK_STATUS} = {want}")
        rest = [ln for ln in lines if ln not in evals]
        if any("robodr_verification" in ln for ln in rest):
            problem(f"splunk/props.conf [{t}]: reads robodr_verification outside EVAL-{SPLUNK_STATUS}")
        bodies.append(rest)
    if bodies[0] != bodies[1]:
        problem("splunk/props.conf: the two sourcetypes differ in more than the verification status")


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


# ------------------------------------------------------------------ verifier


def load_verify():
    spec = importlib.util.spec_from_file_location("robodr_verify", os.path.join(HERE, "verify/robodr_verify.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def verifier(schema, findings):
    """robodr_verify.py: its envelope is the contract's; hostile records are
    rejected one by one and never stop the run (fuzz cases below)."""
    v = load_verify()
    envelope, required = getattr(v, "ENVELOPE", None), getattr(v, "REQUIRED", None)
    if envelope != set(schema["properties"]) or required != set(schema["required"]):
        problem(f"verify/robodr_verify.py: ENVELOPE/REQUIRED differ from the schema's top-level "
                f"properties {sorted(schema['properties'])} / required {sorted(schema['required'])}")
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("check_content: cryptography not installed, robodr_verify.py fuzz cases skipped", file=sys.stderr)
        return
    if not findings:
        return
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    value = json.dumps(findings[0], separators=(",", ":"))
    robot = findings[0]["entity_context"]["robot"]["id"]
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    sig = sk.sign(v.signed_message("ed25519", "k", value.encode())).hex()
    # A correctly signed record's header; the L2 cases below keep its
    # signature (which verifies) and change only the header's form.
    head = '{"alg":"ed25519","key_id":"k","sig":"' + sig + '"}'

    def rec(val=value, sig=None, **extra):
        headers = [] if sig is None else [["robodr-finding-sig", sig]]
        return json.dumps(dict({"value": val, "headers": headers}, **extra))

    def with_key(key, val="verified"):
        f = dict(findings[0])
        f[key] = val
        return json.dumps(f, separators=(",", ":"))

    deep = "[" * 20000 + "]" * 20000  # within the 64 KiB value cap
    cases = {
        "line not UTF-8": b'{"value": "\xff"}',
        # H3: a key the SIEMs would read as (or merge into) the status.
        "dotted status key": rec(with_key("robodr_verification.status")),
        "own robodr_verification": rec(with_key("robodr_verification", {"status": "verified"})),
        "dotted robodr key": rec(with_key("robodr.verification.status")),
        "unknown top-level key": rec(with_key("x")),
        "missing required key": rec(json.dumps({k: x for k, x in findings[0].items() if k != "title"})),
        # M3: shapes that used to escape the Reject handling.
        "header is a JSON array of ints": rec(sig="[1,2,3]"),
        "header is a JSON string": rec(sig='"x"'),
        "header lone surrogate": rec(sig="\ud800"),
        "value lone surrogate": rec(val="\ud800"),
        "value nested too deep": rec(val=deep),
        "line nested too deep": deep,
        "headers is a number": json.dumps({"value": value, "headers": 5}),
        "header value not a string": rec(headers=[["robodr-finding-sig", 5]]),
        "header pair of three": rec(headers=[["robodr-finding-sig", head, 1]]),
        "header alg is an object": rec(sig='{"alg":{},"key_id":"k","sig":"' + sig + '"}'),
        # L2: forms of a valid signature the contract and the Rust parser
        # refuse (the signature itself verifies).
        "header as pairs array": rec(sig=json.dumps([["alg", "ed25519"], ["key_id", "k"], ["sig", sig]])),
        "header sig with trailing newline": rec(sig=head.replace('"}', '\\n"}')),
        "header with whitespace": rec(sig=head.replace(",", ", ")),
        "header with needless escape": rec(sig=head.replace('"k"', '"\\u006b"')),
    }
    with tempfile.TemporaryDirectory() as d:
        kr = os.path.join(d, "keys.json")
        with open(kr, "w", encoding="utf-8") as fh:
            json.dump({robot: {"k": pub}}, fh)
        # The baseline: the correctly signed record verifies.
        signed = os.path.join(d, "signed")
        with open(signed, "w", encoding="utf-8") as fh:
            fh.write(rec(sig=head) + "\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = v.main(["--keyring", kr, "--reject", os.path.join(d, "rej-signed"), signed])
        if code != 0 or '"status":"verified"' not in out.getvalue():
            problem(f"verify/robodr_verify.py: a correctly signed finding does not verify (exit {code})")
        for name, line in cases.items():
            inp, rej = os.path.join(d, f"in-{len(name)}"), os.path.join(d, f"rej-{name}")
            # The hostile record first, then a good (unsigned) one: the run
            # must reject the first and still forward the second.
            with open(inp, "wb") as fh:
                fh.write((line if isinstance(line, bytes) else line.encode()) + b"\n" + rec().encode() + b"\n")
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    code = v.main(["--keyring", kr, "--policy", "optional", "--reject", rej, inp])
            except Exception as e:  # noqa: BLE001
                problem(f"verify/robodr_verify.py: {name}: crashed ({type(e).__name__}: {e})")
                continue
            with open(rej, encoding="utf-8") as fh:
                rejected = [json.loads(x) for x in fh if x.strip()]
            forwarded = out.getvalue().splitlines()
            if code != 1 or [r["line"] for r in rejected] != [1] or len(forwarded) != 1:
                problem(f"verify/robodr_verify.py: {name}: exit {code}, rejected {rejected}, "
                        f"{len(forwarded)} forwarded (want line 1 rejected, line 2 forwarded)")


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


# Painless `if` conditions the pipelines use, by their exact text, and what
# they mean (the evaluator does not run Painless: a new condition needs an
# entry here).
CONDITIONS = {
    # Any top-level key with a dot (a literal "a.b" key, not a path).
    "ctx.keySet().stream().anyMatch(k -> k.contains('.'))": lambda doc: any("." in k for k in doc),
}


def run_processor(p, doc, ingest):
    (kind, o), = p.items()
    if "if" in o:
        if kind != "fail" or o["if"] not in CONDITIONS:
            raise SystemExit(f"evaluator: unsupported condition on {kind}: {o['if']!r}")
        if not CONDITIONS[o["if"]](doc):
            return
    allowed = {
        "fail": {"if", "message"},
        "rename": {"field", "target_field", "ignore_missing"},
        "date": {"field", "target_field", "formats"},
        "set": {"field", "value", "copy_from", "ignore_empty_value"},
        "append": {"field", "value", "allow_duplicates"},
        "foreach": {"field", "processor", "ignore_missing"},
        "convert": {"field", "type", "ignore_missing", "on_failure"},
        "remove": {"field", "ignore_missing"},
        "pipeline": {"name"},
        "dot_expander": {"field"},
    }
    if kind not in allowed or set(o) - allowed[kind]:
        raise SystemExit(f"evaluator: unsupported processor/options {kind} {sorted(o)}")
    if "on_failure" in o:
        # Processor-level on_failure: handles this processor's failure only.
        try:
            run_processor({kind: {k: v for k, v in o.items() if k != "on_failure"}}, doc, ingest)
        except PipelineError as e:
            for h in o["on_failure"]:
                run_processor(h, doc, {"on_failure_message": str(e)})
        return
    if kind == "fail":
        raise PipelineError(o["message"])
    if kind == "convert":
        if o["type"] != "ip":
            raise SystemExit(f"evaluator: convert type {o['type']} not implemented")
        v = get_path(doc, o["field"])
        if v is None:
            if o.get("ignore_missing"):
                return
            raise PipelineError(f"field [{o['field']}] doesn't exist")
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise PipelineError(f"'{v}' is not an IP string literal") from None
    elif kind == "remove":
        if get_path(doc, o["field"]) is None:
            if o.get("ignore_missing"):
                return
            raise PipelineError(f"field [{o['field']}] not present")
        del_path(doc, o["field"])
    elif kind == "dot_expander":
        if o["field"] != "*":
            raise SystemExit("evaluator: dot_expander only for field *")
        # Every top-level dotted key becomes nested objects (Elasticsearch
        # merges a conflict into an array; a conflict here is only checked
        # for removal, so a list stands in for that).
        for key in [k for k in doc if "." in k]:
            v = doc.pop(key)
            cur = doc
            parts = key.split(".")
            for part in parts[:-1]:
                nxt = cur.get(part)
                if not isinstance(nxt, dict):
                    nxt = cur[part] = {} if nxt is None else {"_conflict": nxt}
                cur = nxt
            old = cur.get(parts[-1])
            cur[parts[-1]] = v if old is None else [old, v]
    elif kind == "pipeline":
        if o["name"] not in PIPELINES:
            raise SystemExit(f"evaluator: unknown pipeline {o['name']}")
        run_pipeline(PIPELINES[o["name"]], doc)
    elif kind == "rename":
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


# Ingest pipelines by name, for the `pipeline` processor (filled by elastic()).
PIPELINES: dict = {}
VERIFIED_PIPELINE = "robodr-findings-verified"
STAGING = "robodr_verified_by_forwarder"


class Refused(Exception):
    """The document is not indexed: a failure inside on_failure (Elasticsearch
    returns it as the bulk item's error)."""


def run_pipeline(pipeline, doc):
    try:
        for p in pipeline["processors"]:
            run_processor(p, doc, {})
    except PipelineError as e:
        try:
            for p in pipeline.get("on_failure", []):
                run_processor(p, doc, {"on_failure_message": str(e)})
        except PipelineError as e2:
            raise Refused(str(e2)) from None
    return doc


def elastic(schema, ids, findings):
    with open(os.path.join(HERE, "elastic/ingest-pipeline-robodr-findings.json"), encoding="utf-8") as fh:
        pipeline = json.load(fh)
    with open(os.path.join(HERE, f"elastic/ingest-pipeline-{VERIFIED_PIPELINE}.json"), encoding="utf-8") as fh:
        verified = json.load(fh)
    PIPELINES.update({"robodr-findings": pipeline, VERIFIED_PIPELINE: verified})
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
    check_fields("elastic pipeline", refs, schema)
    # The shared pipeline never keeps a status: a forger chooses every field.
    keeps = [p for p in pipeline["processors"] if "verification" in json.dumps(p) and "remove" not in p]
    if keeps:
        problem(f"elastic pipeline robodr-findings: maps a verification status (forgeable): {keeps}")
    for f in os.listdir(os.path.join(HERE, "elastic/detection-rules")):
        with open(os.path.join(HERE, "elastic/detection-rules", f), encoding="utf-8") as fh:
            rule = json.load(fh)
        check_rule_ids(f"elastic/detection-rules/{f}", rule["query"], ids)
        for field in re.findall(r"([a-z_.]+)\s*:", rule["query"]):
            if field not in ("event.module", "rule.id", "robodr.verification.status"):
                problem(f"elastic/detection-rules/{f}: query uses {field}, which the pipeline does not set")
        q = rule["query"]
        if f == gen_file(load_gen().UNVERIFIED):
            if q != 'event.module : "robodr" and not robodr.verification.status : "verified"':
                problem(f"elastic/detection-rules/{f}: must match every finding that is not verified")
        elif not q.endswith(ELASTIC_VERIFIED):
            problem(f"elastic/detection-rules/{f}: query does not end with {ELASTIC_VERIFIED}")
    if gen_file(load_gen().UNVERIFIED) not in os.listdir(os.path.join(HERE, "elastic/detection-rules")):
        problem("elastic/detection-rules: no Unverified findings rule")
    with open(os.path.join(HERE, "elastic/index-template-robodr-findings.json"), encoding="utf-8") as fh:
        template = json.load(fh)["template"]["mappings"]
    status = {"status": "verified", "key_id": "finding:check:1"}
    for n, f, pipe in [(n, f, p) for n, f in enumerate(findings, 1) for p in ("robodr-findings", VERIFIED_PIPELINE)]:
        inp = copy.deepcopy(f)
        if pipe == VERIFIED_PIPELINE:
            inp["robodr_verification"] = dict(status)  # what robodr_verify.py adds
        doc = run_pipeline(PIPELINES[pipe], inp)
        where = f"elastic pipeline {pipe} on finding {n} ({f['entity_context']['rule_id']})"
        if doc.get("event", {}).get("kind") != "alert":
            problem(f"{where}: failed: {doc.get('error')}")
            continue
        got = get_path(doc, "robodr.verification")
        if got != (status if pipe == VERIFIED_PIPELINE else None) or STAGING in doc or "robodr_verification" in doc:
            problem(f"{where}: robodr.verification = {got!r}, root keys {sorted(doc)}")
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
        for ptr in f.get("adversary_controlled_fields", []):
            if indexed(template, f, ptr):
                problem(f"{where}: tainted {ptr} would be indexed by the index template")
    # A forged status (or a robodr object) on a path without a verifier is
    # discarded by robodr-findings; on the verified path only the verifier's
    # own status survives.
    for f in findings[:1]:
        forged = copy.deepcopy(f)
        forged["robodr_verification"] = dict(status)
        forged["robodr"] = {"verification": dict(status)}
        forged[STAGING] = dict(status)
        # A dotted key is not the path `robodr` to the pipeline, but
        # Elasticsearch maps it as robodr.verification.status.
        forged["robodr.verification.status"] = "verified"
        doc = run_pipeline(pipeline, copy.deepcopy(forged))
        dotted = [k for k in doc if k.startswith(("robodr.", "robodr_verification"))]
        if dotted:
            problem(f"elastic pipeline robodr-findings keeps forged dotted keys {dotted}")
        if doc.get("event", {}).get("kind") != "alert" or get_path(doc, "robodr.verification") is not None:
            problem(f"elastic pipeline robodr-findings keeps a forged status: robodr.verification = "
                    f"{get_path(doc, 'robodr.verification')!r}, event.kind {get_path(doc, 'event.kind')!r}")
        forged["robodr_verification"] = {"status": "unsigned"}
        doc = run_pipeline(verified, {k: v for k, v in forged.items() if "." not in k})
        if get_path(doc, "robodr.verification") != {"status": "unsigned"} or STAGING in doc:
            problem(f"elastic pipeline {VERIFIED_PIPELINE}: robodr.verification = "
                    f"{get_path(doc, 'robodr.verification')!r}, want the verifier's status only")
        # A dotted top-level key on the verified route (robodr_verify.py
        # never emits one): expanded, robodr_verification.status would merge
        # into the verifier's status (["unsigned", "verified"], which
        # `robodr.verification.status : "verified"` matches); left literal,
        # robodr.verification.status would be indexed as that field. The
        # document is refused, also when the failure handler runs.
        for key in ("robodr_verification.status", f"{STAGING}.status", "robodr.verification.status"):
            one = copy.deepcopy(f)
            one["robodr_verification"] = {"status": "unsigned"}
            one[key] = "verified"
            try:
                doc = run_pipeline(verified, one)
            except Refused:
                continue
            problem(f"elastic pipeline {VERIFIED_PIPELINE}: a dotted {key!r} key is indexed, "
                    f"robodr.verification = {get_path(doc, 'robodr.verification')!r}, "
                    f"root keys {sorted(k for k in doc if '.' in k)}")
    # A source address display that is not an IP (source.ip is mapped `ip`):
    # dropped in the pipeline, not left to fail the whole document at index time.
    with_src = [f for f in findings if get_path(f, "entity_context.ros.src_ip.display")]
    if findings and not with_src:
        problem("elastic: no finding with a source address to check source.ip handling")
    for f in with_src[:1]:
        bad = copy.deepcopy(f)
        bad["entity_context"]["ros"]["src_ip"]["display"] = "not-an-ip"
        doc = run_pipeline(pipeline, bad)
        if doc.get("event", {}).get("kind") != "alert" or get_path(doc, "source.ip") is not None:
            problem(f"elastic pipeline: a non-IP source display gives event.kind={doc.get('event', {}).get('kind')!r}, "
                    f"source.ip={get_path(doc, 'source.ip')!r}; want alert and no source.ip")


def gen_file(d):
    return f"{d['key']}.json"


ELASTIC_VERIFIED = '(not robodr.verification.status : * or robodr.verification.status : "verified")'


def indexed(mappings, finding, ptr):
    """Whether the value at JSON Pointer `ptr` of `finding`, moved under
    robodr.* by the pipeline, would be indexed (searchable) by the template:
    a disabled object on its path, or the first dynamic template that
    matches each string leaf having index false, means not indexed."""
    parts = [p.replace("~1", "/").replace("~0", "~") for p in ptr.lstrip("/").split("/")]
    path = ["robodr"] + parts
    node = {"properties": mappings["properties"]}
    for p in path:
        if p.isdigit():
            continue  # array index: same mapping as the element
        props = node.get("properties", {})
        if p not in props:
            break
        node = props[p]
        if node.get("enabled") is False:
            return False
    cur = finding
    for p in parts:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]

    def leaves(v, prefix):
        if isinstance(v, dict):
            for k, x in v.items():
                yield from leaves(x, f"{prefix}.{k}")
        elif isinstance(v, list):
            for x in v:
                yield from leaves(x, prefix)
        elif isinstance(v, str):
            yield prefix

    dotted = ".".join(p for p in path if not p.isdigit())
    tainted_leaves = [lp for lp in leaves(cur, dotted)]
    if isinstance(cur, dict) and "value" in cur:
        # A Tainted object: only its raw value is attacker-chosen; display is escaped.
        tainted_leaves = [f"{dotted}.value"]
    for leaf in tainted_leaves:
        for dt in mappings.get("dynamic_templates", []):
            (_, spec), = dt.items()
            if spec.get("match_mapping_type", "string") != "string":
                continue
            if fnmatch.fnmatchcase(leaf, spec["path_match"]):
                if spec["mapping"].get("index", True) is not False:
                    return True
                break
        else:
            return True  # default dynamic mapping: text + keyword, indexed
    return False


# ------------------------------------------------------------------ sentinel

SENTINEL_RAW = "Custom-RoboDRFindingsRaw"
SENTINEL_VERIFIED = "Custom-RoboDRFindingsVerified"


def sentinel(schema, ids):
    base = os.path.join(HERE, "sentinel")
    with open(os.path.join(base, "RoboDRFindings_CL.table.json"), encoding="utf-8") as fh:
        table = {c["name"]: c["type"] for c in json.load(fh)["properties"]["schema"]["columns"]}
    with open(os.path.join(base, "dcr-robodr-findings.json"), encoding="utf-8") as fh:
        dcr = json.load(fh)
    props = dcr["properties"]
    # Two streams: unverified findings (no status, whatever they carry) and
    # robodr_verify.py output (its status). Same transformation otherwise.
    status_of = {
        SENTINEL_RAW: 'VerificationStatus = ""',
        SENTINEL_VERIFIED: "VerificationStatus = tostring(robodr_verification.status)",
    }
    streams = props["streamDeclarations"]
    if set(streams) != set(status_of):
        problem(f"sentinel DCR: streams {sorted(streams)} != {sorted(status_of)}")
        return
    flows = {tuple(f["streams"]): f for f in props["dataFlows"]}
    if set(flows) != {(s,) for s in status_of} or len(props["dataFlows"]) != len(status_of):
        problem("sentinel DCR: needs one data flow per stream")
        return
    kqls = {}
    for name, want in status_of.items():
        inputs = {c["name"] for c in streams[name]["columns"]}
        extra = {"robodr_verification"} if name == SENTINEL_VERIFIED else set()
        if inputs != set(TOP) | extra:
            problem(f"sentinel DCR {name}: input columns {sorted(inputs ^ (set(TOP) | extra))} differ")
        flow = flows[(name,)]
        if flow["outputStream"] != "Custom-RoboDRFindings_CL":
            problem(f"sentinel DCR {name}: data flow does not go to RoboDRFindings_CL")
        kql = flow["transformKql"]
        if kql.count("VerificationStatus =") != 1 or want not in kql:
            problem(f"sentinel DCR {name}: VerificationStatus must be `{want}`")
        if name == SENTINEL_RAW and "robodr_verification" in kql:
            problem(f"sentinel DCR {name}: reads robodr_verification (forgeable on this stream)")
        kqls[name] = kql.replace(want, "VerificationStatus = <status>")
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
                problem(f"sentinel DCR {name}: reads {r} from an undeclared input column")
    if len(set(kqls.values())) != 1:
        problem("sentinel DCR: the two transformations differ in more than VerificationStatus")
    for f in os.listdir(os.path.join(base, "analytics")):
        with open(os.path.join(base, "analytics", f), encoding="utf-8") as fh:
            text = fh.read()
        check_rule_ids(f"sentinel/analytics/{f}", text, ids)
        query = text.split("query: |", 1)[1].split("entityMappings")[0]
        if f == f"{load_gen().UNVERIFIED['key']}.yaml":
            if '| where VerificationStatus != "verified"' not in query:
                problem(f"sentinel/analytics/{f}: must match every finding that is not verified")
        elif '| where isempty(VerificationStatus) or VerificationStatus == "verified"' not in query:
            problem(f"sentinel/analytics/{f}: does not drop findings that failed verification")
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
    verifier(schema, findings)
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
