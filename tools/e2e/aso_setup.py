#!/usr/bin/env python3
"""Bootstrap an AutoSecOps tenant for the RoboDR E2E run, only through the API.

1. register + log in the platform superadmin (TRACECAT__AUTH_SUPERADMIN_EMAIL);
2. grant the `robot_edr` entitlement to the default organization with the
   platform admin tier API (PATCH /admin/tiers/organizations/{org},
   entitlement_overrides) -- the multi-tenant tier mechanism, no license key;
3. invite an operator as organization owner, register, log in, accept;
4. pick the workspace.
Writes STATE (JSON): api base, workspace id, operator credentials.

usage: aso_setup.py STATE_FILE [--api http://127.0.0.1:8000/api]
Run it with the AutoSecOps venv python (needs `requests`).
"""
import argparse, json, sys
import requests

ap = argparse.ArgumentParser()
ap.add_argument("state"); ap.add_argument("--api", default="http://127.0.0.1:8000/api")
ap.add_argument("--admin", default="e2e-admin@example.com")
ap.add_argument("--operator", default="e2e-operator@example.com")
ap.add_argument("--password", default="e2e-password-1234")
a = ap.parse_args()
B = a.api

def must(r, *ok):
    if r.status_code not in ok:
        sys.exit(f"{r.request.method} {r.request.url} -> {r.status_code} {r.text[:500]}")
    return r

def login(email):
    s = requests.Session()
    r = s.post(f"{B}/auth/register", json={"email": email, "password": a.password})
    must(r, 201, 400)
    must(s.post(f"{B}/auth/login", data={"username": email, "password": a.password}), 204)
    return s

admin = login(a.admin)
orgs = must(admin.get(f"{B}/admin/organizations"), 200).json()
org = orgs[0]
print(f"org {org['id']} {org['name']}")
r = must(admin.patch(f"{B}/admin/tiers/organizations/{org['id']}",
                     json={"entitlement_overrides": {"robot_edr": True}}), 200)
print("org tier overrides:", r.json().get("entitlement_overrides"))

op = login(a.operator)
if must(op.get(f"{B}/workspaces"), 200, 400).status_code == 400:
    inv = must(admin.post(f"{B}/admin/organizations/{org['id']}/invitations",
                          json={"email": a.operator, "role_slug": "organization-owner"}),
               201).json()
    must(op.post(f"{B}/invitations/accept", json={"token": inv["token"]}), 200)
    print("operator joined org as organization-owner")
ws = must(op.get(f"{B}/workspaces"), 200).json()
print("workspaces:", [(w["id"], w["name"]) for w in ws])
state = {"api": B, "org_id": org["id"], "workspace_id": ws[0]["id"],
         "operator": a.operator, "password": a.password}
json.dump(state, open(a.state, "w"), indent=2)
