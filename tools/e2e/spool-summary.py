#!/usr/bin/env python3
"""Summarise an agentd spool: findings by (rule, severity), ready vs acked."""
import collections, json, os, sys

spool = sys.argv[1]
c = collections.Counter(); n = {"ready": 0, "acked": 0}
for sub in ("ready", "acked"):
    p = os.path.join(spool, sub)
    for name in sorted(os.listdir(p)) if os.path.isdir(p) else []:
        rec = json.load(open(os.path.join(p, name)))
        f = json.loads(rec["value"])
        n[sub] += 1
        c[(f["ocsf"]["finding_info"]["analytic"]["uid"], f.get("severity"))] += 1
print(f"ready={n['ready']} acked={n['acked']}")
for (rule, sev), k in sorted(c.items(), key=lambda x: -x[1]):
    print(f"{k:5d}  {sev:8s} {rule}")
