#!/usr/bin/env python3
"""Validate robodr.findings messages with a third-party JSON Schema validator.

Every message is checked twice with ``jsonschema`` (the reference Python
implementation of JSON Schema, Draft 2020-12, the engine behind
``check-jsonschema``):

* the whole message against the contract schema
  ``docs/contracts/robodr-finding.schema.json``;
* its ``ocsf`` member against the strict OCSF 1.1.0 Detection Finding schema
  ``integrations/schemas/ocsf-1.1.0-detection_finding.schema.json`` (built
  from the official OCSF schema by ``build_ocsf_schema.py``).

Both schemas are meta-validated first. Input files are JSON (one message) or
NDJSON (one message per line). SIEM teams can run this on what they receive.

    validate_findings.py [--json] FILE...

Exit 0 when every message passes both schemas, 1 when any fails, 2 on usage
or tooling errors. ``--json`` prints one machine-readable report on stdout:
``{"messages": N, "errors": [{"file", "line", "schema", "path", "message"}]}``.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CONTRACT = os.path.join(ROOT, "docs", "contracts", "robodr-finding.schema.json")
OCSF = os.path.join(HERE, "ocsf-1.1.0-detection_finding.schema.json")


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _messages(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    stripped = text.strip()
    if stripped.startswith("{") and "\n{" not in stripped:
        yield 1, json.loads(stripped)
        return
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip():
            yield n, json.loads(line)


def main(argv):
    as_json = "--json" in argv
    files = [a for a in argv[1:] if a != "--json"]
    if not files:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        print("python3 module 'jsonschema' (>= 4.18) is required", file=sys.stderr)
        return 2
    validators = {}
    for name, path in (("contract", CONTRACT), ("ocsf", OCSF)):
        schema = _load(path)
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = []
    count = 0
    for path in files:
        for line, msg in _messages(path):
            count += 1
            targets = [("contract", msg)]
            if isinstance(msg, dict) and "ocsf" in msg:
                targets.append(("ocsf", msg["ocsf"]))
            for name, doc in targets:
                for err in validators[name].iter_errors(doc):
                    errors.append(
                        {
                            "file": path,
                            "line": line,
                            "schema": name,
                            "path": "/" + "/".join(str(p) for p in err.absolute_path),
                            "message": err.message[:500],
                        }
                    )
    if as_json:
        json.dump({"messages": count, "errors": errors}, sys.stdout, indent=1)
        sys.stdout.write("\n")
    else:
        for e in errors:
            print(f"{e['file']}:{e['line']}: [{e['schema']}] {e['path']}: {e['message']}")
        print(f"{count} message(s), {len(errors)} error(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
