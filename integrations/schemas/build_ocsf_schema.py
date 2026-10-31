#!/usr/bin/env python3
"""Build the pinned OCSF 1.1.0 Detection Finding JSON Schema (gap T61).

Two steps, both reproducible:

1. ``fetch``: download the subset of the official ``ocsf/ocsf-schema`` source
   at tag ``v1.1.0`` that the Detection Finding class (2004) reaches
   (``extends``, ``profiles``, ``$include`` and every object type an
   attribute names), and compile it with the OCSF project's reference
   compiler ``ocsf-lib`` (``python -m ocsf.compile``). Needs network access
   and ``pip install ocsf-lib==0.10.4``.

2. ``convert``: turn the compiled schema export into a JSON Schema 2020-12
   document for ``classes.detection_finding``:

   * every class and object is closed (``additionalProperties: false``):
     an attribute OCSF does not define is an error, as in the OCSF
     server's own validator. ``object`` (OCSF's free-form object, used by
     ``unmapped``) and ``json_t`` stay open;
   * ``requirement: required`` -> ``required``; a profile's required
     attributes (``cloud``, ``action_id``) only when ``metadata.profiles``
     names that profile;
   * integer enums (``*_id``, ``class_uid``, ``type_uid``, ...) -> ``enum``;
   * scalar types resolve through ``types`` (``timestamp_t`` -> long ->
     integer, ``datetime_t`` -> string + regex, ``port_t`` range, ...),
     ``max_len`` -> ``maxLength``, ``regex`` -> ``pattern``;
   * object constraints ``at_least_one`` / ``just_one`` -> ``anyOf`` /
     ``oneOf`` of ``required``.

   String sibling captions (``severity``, ``status``, ...) are not enums in
   OCSF and are not checked against the caption, matching OCSF's rules.

Usage::

    build_ocsf_schema.py fetch  <workdir>            # -> <workdir>/compiled.json
    build_ocsf_schema.py convert <compiled.json> <out.schema.json>

The checked-in output is ``ocsf-1.1.0-detection_finding.schema.json`` next
to this script; ``PROVENANCE.md`` records the hashes. The converter is ours;
the schema data comes unmodified from the OCSF compiler.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request

OCSF_TAG = "v1.1.0"
RAW = f"https://raw.githubusercontent.com/ocsf/ocsf-schema/{OCSF_TAG}/"
CLASS = "detection_finding"
OCSF_LIB = "0.10.4"
SCALARS = {
    "string_t": "string",
    "integer_t": "integer",
    "long_t": "integer",
    "float_t": "number",
    "boolean_t": "boolean",
}


def _includes(doc, acc):
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == "$include":
                acc.extend(v if isinstance(v, list) else [v])
            else:
                _includes(v, acc)
    elif isinstance(doc, list):
        for v in doc:
            _includes(v, acc)


def fetch(workdir: str) -> str:
    src = os.path.join(workdir, "ocsf-schema")
    seen: set[str] = set()

    def get(path):
        if path in seen:
            return None
        seen.add(path)
        dst = os.path.join(src, path)
        if not os.path.exists(dst):
            data = urllib.request.urlopen(RAW + path, timeout=30).read()
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as fh:
                fh.write(data)
        with open(dst, encoding="utf-8") as fh:
            return json.load(fh)

    dictionary = get("dictionary.json")
    get("version.json")
    get("categories.json")
    by_attr = {
        name: a["type"]
        for name, a in dictionary["attributes"].items()
        if a.get("type") and not a["type"].endswith("_t")
    }
    queue = [
        "events/base_event.json",
        "events/findings/finding.json",
        f"events/findings/{CLASS}.json",
    ]
    while queue:
        path = queue.pop()
        doc = get(path)
        if doc is None:
            continue
        inc: list[str] = []
        _includes(doc, inc)
        queue.extend(inc)
        queue.extend(f"profiles/{p}.json" for p in doc.get("profiles") or [])
        if path.startswith("objects/") and doc.get("extends"):
            queue.append(f"objects/{doc['extends']}.json")
        for attr, spec in (doc.get("attributes") or {}).items():
            if attr == "$include" or not isinstance(spec, dict):
                continue
            obj = spec.get("object_type") or by_attr.get(attr)
            if obj and obj != "object":
                queue.append(f"objects/{obj}.json")
    out = os.path.join(workdir, "compiled.json")
    with open(out, "wb") as fh:
        subprocess.run(
            [sys.executable, "-m", "ocsf.compile", src], stdout=fh, check=True
        )
    print(f"fetched {len(seen)} source files; compiled -> {out}")
    return out


def _scalar(types: dict, tname: str) -> dict:
    out: dict = {}
    seen = set()
    while tname not in SCALARS and tname not in ("json_t",):
        if tname in seen or tname not in types:
            raise SystemExit(f"unknown OCSF type {tname}")
        seen.add(tname)
        t = types[tname]
        if t.get("regex") and "pattern" not in out:
            out["pattern"] = t["regex"]
        if t.get("max_len") and "maxLength" not in out:
            out["maxLength"] = t["max_len"]
        if t.get("range") and "minimum" not in out:
            out["minimum"], out["maximum"] = t["range"]
        tname = t.get("type") or ""
    if tname == "json_t":
        return {}
    out["type"] = SCALARS[tname]
    if tname == "string_t" and "maxLength" not in out:
        ml = types.get("string_t", {}).get("max_len")
        if ml:
            out["maxLength"] = ml
    return out


def _attr(types: dict, spec: dict) -> dict:
    t = spec["type"]
    if t == "object":
        node: dict = {"type": "object"}
    elif t.endswith("_t"):
        node = _scalar(types, t)
        enum = spec.get("enum")
        if enum and node.get("type") == "integer":
            node["enum"] = sorted(int(k) for k in enum)
    else:
        node = {"$ref": f"#/$defs/{t}"}
    if spec.get("is_array"):
        node = {"type": "array", "items": node}
    return node


def _shape(types: dict, entity: dict) -> dict:
    attrs = entity.get("attributes") or {}
    node: dict = {
        "type": "object",
        "properties": {k: _attr(types, v) for k, v in sorted(attrs.items())},
        "additionalProperties": False,
    }
    req = sorted(
        k
        for k, v in attrs.items()
        if v.get("requirement") == "required" and not v.get("profile")
    )
    if req:
        node["required"] = req
    # A profile's required attributes are required only when the event
    # declares the profile in metadata.profiles (OCSF profile semantics).
    by_profile: dict = {}
    for k, v in attrs.items():
        if v.get("requirement") == "required" and v.get("profile"):
            by_profile.setdefault(v["profile"], []).append(k)
    if by_profile:
        node["allOf"] = [
            {
                "if": {
                    "required": ["metadata"],
                    "properties": {
                        "metadata": {
                            "required": ["profiles"],
                            "properties": {"profiles": {"contains": {"const": p}}},
                        }
                    },
                },
                "then": {"required": sorted(ks)},
            }
            for p, ks in sorted(by_profile.items())
        ]
    cons = entity.get("constraints") or {}
    if cons.get("at_least_one"):
        node["anyOf"] = [{"required": [k]} for k in sorted(cons["at_least_one"])]
    if cons.get("just_one"):
        node["oneOf"] = [{"required": [k]} for k in sorted(cons["just_one"])]
    return node


def convert(compiled_path: str, out_path: str) -> None:
    with open(compiled_path, encoding="utf-8") as fh:
        schema = json.load(fh)
    types = schema["types"]
    cls = schema["classes"][CLASS]
    defs: dict = {}
    todo = [
        v["type"]
        for v in cls["attributes"].values()
        if not v["type"].endswith("_t") and v["type"] != "object"
    ]
    while todo:
        name = todo.pop()
        if name in defs:
            continue
        obj = schema["objects"][name]
        defs[name] = _shape(types, obj)
        todo.extend(
            v["type"]
            for v in (obj.get("attributes") or {}).values()
            if not v["type"].endswith("_t") and v["type"] != "object"
        )
    root = _shape(types, cls)
    doc = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://schemas.singularityrd.com/robodr/ocsf/{schema['version']}/{CLASS}",
        "title": f"OCSF {schema['version']} {cls['caption']} (class_uid {cls['uid']}), strict",
        "description": (
            "Generated by integrations/schemas/build_ocsf_schema.py from the "
            f"ocsf-lib {OCSF_LIB} compilation of ocsf/ocsf-schema {OCSF_TAG} "
            "(the compiler's list order varies between runs; this output does "
            "not). Do not edit."
        ),
        **root,
        "$defs": dict(sorted(defs.items())),
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=False)
        fh.write("\n")
    print(f"wrote {out_path}: {len(defs)} object definitions")


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "fetch":
        fetch(argv[2])
        return 0
    if len(argv) == 4 and argv[1] == "convert":
        convert(argv[2], argv[3])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
