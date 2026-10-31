#!/usr/bin/env python3
"""Extract the ATT&CK for ICS technique table RoboDR checks its catalog against.

Input: MITRE's official STIX 2.1 bundle ``ics-attack/ics-attack.json`` from
``mitre-attack/attack-stix-data`` (download it yourself; it is ~5 MB and
not checked in). Output: ``attack-ics-techniques.json`` with

* ``attack_version``, ``bundle_sha256``: what the table came from;
* ``techniques``: every current (not revoked, not deprecated) technique and
  sub-technique, ``id -> name``;
* ``revoked``: every revoked technique, ``id -> {name, revoked_by: [[id, name]]}``;
* ``deprecated``: every deprecated technique, ``id -> name``.

``crates/robodr-ocsf/tests/attack_ics.rs`` checks every technique the rule
catalog attaches to a finding against this table.

    extract_attack_ics.py ics-attack.json attack-ics-techniques.json
"""

import hashlib
import json
import sys


def ext_id(obj):
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    return None


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[1], "rb") as fh:
        raw = fh.read()
    bundle = json.loads(raw)
    objs = bundle["objects"]
    by_ref = {o["id"]: o for o in objs}
    version = next(
        (o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"),
        None,
    )
    current, revoked, deprecated = {}, {}, {}
    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        tid = ext_id(o)
        if not tid:
            continue
        if o.get("revoked"):
            revoked[tid] = {"name": o["name"], "revoked_by": []}
        elif o.get("x_mitre_deprecated"):
            deprecated[tid] = o["name"]
        else:
            current[tid] = o["name"]
    for r in objs:
        if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by":
            src, dst = by_ref.get(r["source_ref"]), by_ref.get(r["target_ref"])
            if src and dst and ext_id(src) in revoked:
                revoked[ext_id(src)]["revoked_by"].append([ext_id(dst), dst["name"]])
    for v in revoked.values():
        v["revoked_by"].sort()
    out = {
        "source": "https://github.com/mitre-attack/attack-stix-data ics-attack/ics-attack.json",
        "attack_version": version,
        "bundle_sha256": hashlib.sha256(raw).hexdigest(),
        "techniques": dict(sorted(current.items())),
        "revoked": dict(sorted(revoked.items())),
        "deprecated": dict(sorted(deprecated.items())),
    }
    with open(argv[2], "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
        fh.write("\n")
    print(f"ATT&CK for ICS {version}: {len(current)} current, {len(revoked)} revoked")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
