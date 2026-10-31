#!/usr/bin/env python3
"""VEX documents for a RoboDR release from security/vex/statements.json.

    vex.py check    [--statements FILE]
    vex.py openvex  --version V --out FILE [--statements FILE] [--timestamp ISO]
    vex.py csaf     --version V --out FILE [--statements FILE] [--timestamp ISO]
    vex.py coverage --version V --findings FILE [--statements FILE]
    vex.py --self-test

statements.json (format robodr-vex-statements/1) is the curated source:
each statement names a vulnerability (RUSTSEC-/CVE-/GHSA- id), the
component (purl), the products (robodr = the .deb, robodr-focal, robodr-rpm)
and versions ("*" or a list) it covers, and a status:
  not_affected        needs `justification` (OpenVEX's five) and `impact_statement`
  affected            needs `action_statement`
  fixed / under_investigation
Unknown members, statuses or justifications are refused.

openvex writes an OpenVEX v0.2.0 document (release asset
robodr-<version>.openvex.json, minisign-signed with the others); csaf a CSAF
2.0 document of category csaf_vex (only when at least one statement applies:
the VEX profile requires a vulnerability). Output is deterministic: the
timestamp is --timestamp, else SOURCE_DATE_EPOCH, else the newest statement
timestamp.

coverage reads advisory ids found for a release (one per line, `#` comments;
.github/workflows/vuln-scan.yml writes them from cargo-deny and osv-scanner)
and fails (exit 1) for every id without an applicable statement: a new
advisory against a published release is never silently ignored.

Exit: 0 ok, 1 refused / uncovered, 2 usage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

FORMAT = "robodr-vex-statements/1"
PRODUCTS = ("robodr", "robodr-focal", "robodr-rpm")
STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)
# CSAF 2.0 flag labels for not_affected (section 3.2.3.5).
CSAF_FLAG = {
    "component_not_present": "component_not_present",
    "vulnerable_code_not_present": "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path": "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary": "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist": "inline_mitigations_already_exist",
}
CSAF_STATUS = {
    "not_affected": "known_not_affected",
    "affected": "known_affected",
    "fixed": "fixed",
    "under_investigation": "under_investigation",
}
VULN_ID = re.compile(r"^(RUSTSEC-[0-9]{4}-[0-9]{4}|CVE-[0-9]{4}-[0-9]{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$")
TS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
PUBLISHER = "Singularity RD"
NAMESPACE = "https://github.com/SingularityRD/robodr"
ALLOWED = {"vulnerability", "aliases", "component", "products", "versions", "status", "justification",
           "impact_statement", "action_statement", "status_notes", "timestamp"}


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise ValueError(f"{path}: format must be {FORMAT}")
    if set(doc) - {"format", "comment", "statements"}:
        raise ValueError(f"{path}: unknown members {sorted(set(doc) - {'format', 'comment', 'statements'})}")
    sts = doc.get("statements")
    if not isinstance(sts, list):
        raise ValueError(f"{path}: statements must be a list")
    seen = set()
    for i, s in enumerate(sts):
        w = f"{path}: statements[{i}]"
        if not isinstance(s, dict):
            raise ValueError(f"{w}: not an object")
        if set(s) - ALLOWED:
            raise ValueError(f"{w}: unknown members {sorted(set(s) - ALLOWED)}")
        v = s.get("vulnerability")
        if not isinstance(v, str) or not VULN_ID.match(v):
            raise ValueError(f"{w}: vulnerability {v!r} is not a RUSTSEC/CVE/GHSA id")
        for a in s.get("aliases", []) or []:
            if not isinstance(a, str) or not VULN_ID.match(a):
                raise ValueError(f"{w}: alias {a!r} is not a RUSTSEC/CVE/GHSA id")
        c = s.get("component")
        if not isinstance(c, str) or not c.startswith("pkg:") or len(c) > 256:
            raise ValueError(f"{w}: component must be a purl")
        prods = s.get("products")
        if not isinstance(prods, list) or not prods or any(p not in PRODUCTS for p in prods):
            raise ValueError(f"{w}: products must be a non-empty subset of {PRODUCTS}")
        vers = s.get("versions")
        if vers != "*" and not (isinstance(vers, list) and vers and all(isinstance(x, str) and VERSION.match(x) for x in vers)):
            raise ValueError(f"{w}: versions must be \"*\" or a list of X.Y.Z[-pre]")
        st = s.get("status")
        if st not in STATUSES:
            raise ValueError(f"{w}: status must be one of {STATUSES}")
        if st == "not_affected":
            if s.get("justification") not in JUSTIFICATIONS:
                raise ValueError(f"{w}: not_affected needs a justification out of {JUSTIFICATIONS}")
            if not str(s.get("impact_statement", "")).strip():
                raise ValueError(f"{w}: not_affected needs an impact_statement")
        elif "justification" in s:
            raise ValueError(f"{w}: justification is only for not_affected")
        if st == "affected" and not str(s.get("action_statement", "")).strip():
            raise ValueError(f"{w}: affected needs an action_statement")
        if not isinstance(s.get("timestamp"), str) or not TS.match(s["timestamp"]):
            raise ValueError(f"{w}: timestamp must be YYYY-MM-DDTHH:MM:SSZ")
        key = (v, c, tuple(sorted(prods)), json.dumps(vers))
        if key in seen:
            raise ValueError(f"{w}: duplicate statement for {v} / {c}")
        seen.add(key)
    return sts


def applies(s: dict, version: str) -> bool:
    return s["versions"] == "*" or version in s["versions"]


def product_id(product: str, version: str) -> str:
    return f"pkg:generic/singularityrd/{product}@{version}"


def doc_time(sts: list[dict], ts: str | None) -> str:
    if ts:
        if not TS.match(ts):
            raise ValueError(f"--timestamp {ts!r}: want YYYY-MM-DDTHH:MM:SSZ")
        return ts
    sde = os.environ.get("SOURCE_DATE_EPOCH")
    if sde:
        return datetime.fromtimestamp(int(sde), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return max((s["timestamp"] for s in sts), default="1970-01-01T00:00:00Z")


def openvex(sts: list[dict], version: str, ts: str | None = None) -> dict:
    if not VERSION.match(version):
        raise ValueError(f"bad version {version!r}")
    mine = [s for s in sts if applies(s, version)]
    out = []
    for s in sorted(mine, key=lambda s: (s["vulnerability"], s["component"])):
        st = {
            "vulnerability": {"name": s["vulnerability"], **({"aliases": sorted(s["aliases"])} if s.get("aliases") else {})},
            "timestamp": s["timestamp"],
            "products": [
                {"@id": product_id(p, version), "subcomponents": [{"@id": s["component"]}]} for p in sorted(s["products"])
            ],
            "status": s["status"],
        }
        for k in ("justification", "impact_statement", "action_statement", "status_notes"):
            if s.get(k):
                st[k] = s[k]
        out.append(st)
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"{NAMESPACE}/vex/robodr-{version}",
        "author": PUBLISHER,
        "role": "Document Creator",
        "timestamp": doc_time(mine, ts),
        "version": 1,
        "tooling": "scripts/vex.py",
        "statements": out,
    }


def csaf(sts: list[dict], version: str, ts: str | None = None) -> dict:
    if not VERSION.match(version):
        raise ValueError(f"bad version {version!r}")
    mine = [s for s in sts if applies(s, version)]
    if not mine:
        raise ValueError(f"no statement applies to {version}: a CSAF VEX document needs at least one vulnerability")
    when = doc_time(mine, ts)
    pids = {p: f"CSAFPID-{p}-{version}" for p in PRODUCTS}
    vulns = []
    for s in sorted(mine, key=lambda s: (s["vulnerability"], s["component"])):
        ids = [s["vulnerability"]] + sorted(s.get("aliases", []) or [])
        v: dict = {}
        cve = next((i for i in ids if i.startswith("CVE-")), None)
        if cve:
            v["cve"] = cve
        others = [i for i in ids if i != cve]
        if others:
            v["ids"] = [{"system_name": i.split("-", 1)[0], "text": i} for i in others]
        prod = sorted(pids[p] for p in s["products"])
        v["product_status"] = {CSAF_STATUS[s["status"]]: prod}
        v["notes"] = [{"category": "description", "title": "Component", "text": s["component"]}]
        if s["status"] == "not_affected":
            v["flags"] = [{"label": CSAF_FLAG[s["justification"]], "product_ids": prod}]
            v["threats"] = [{"category": "impact", "details": s["impact_statement"], "product_ids": prod}]
        if s["status"] == "affected":
            v["remediations"] = [{"category": "mitigation", "details": s["action_statement"], "product_ids": prod}]
        if s["status"] == "under_investigation" and s.get("status_notes"):
            v["notes"].append({"category": "details", "title": "Status", "text": s["status_notes"]})
        vulns.append(v)
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "publisher": {"category": "vendor", "name": PUBLISHER, "namespace": NAMESPACE},
            "title": f"RoboDR {version}: vulnerability exploitability (VEX)",
            "tracking": {
                "id": f"robodr-vex-{version}",
                "status": "final",
                "version": "1",
                "initial_release_date": when,
                "current_release_date": when,
                "revision_history": [{"date": when, "number": "1", "summary": "Generated by scripts/vex.py."}],
                "generator": {"engine": {"name": "robodr scripts/vex.py"}},
            },
        },
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": PUBLISHER,
                    "branches": [
                        {
                            "category": "product_name",
                            "name": p,
                            "branches": [
                                {
                                    "category": "product_version",
                                    "name": version,
                                    "product": {
                                        "name": f"{p} {version}",
                                        "product_id": pids[p],
                                        "product_identification_helper": {"purl": product_id(p, version)},
                                    },
                                }
                            ],
                        }
                        for p in PRODUCTS
                    ],
                }
            ]
        },
        "vulnerabilities": vulns,
    }


def coverage(sts: list[dict], version: str, findings: list[str]) -> list[str]:
    covered = set()
    for s in sts:
        if applies(s, version):
            covered.add(s["vulnerability"])
            covered.update(s.get("aliases", []) or [])
    return sorted({f for f in findings if f not in covered})


def read_findings(path: str) -> list[str]:
    out = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.split("#", 1)[0].strip()
            if not ln:
                continue
            if not VULN_ID.match(ln):
                raise ValueError(f"{path}: {ln!r} is not an advisory id")
            out.append(ln)
    return out


def self_test() -> int:
    import tempfile
    import unittest

    base = {
        "vulnerability": "RUSTSEC-2021-0139",
        "component": "pkg:cargo/ansi_term@0.12.1",
        "products": ["robodr"],
        "versions": "*",
        "status": "not_affected",
        "justification": "vulnerable_code_not_present",
        "impact_statement": "no vulnerability",
        "timestamp": "2026-10-17T00:00:00Z",
    }

    def write(sts):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "s.json")
        with open(p, "w") as f:
            json.dump({"format": FORMAT, "statements": sts}, f)
        return p

    class T(unittest.TestCase):
        def test_repo_file_valid(self):
            here = os.path.dirname(os.path.abspath(__file__))
            load(os.path.join(here, "..", "security", "vex", "statements.json"))

        def test_refusals(self):
            bad = [
                {**base, "status": "maybe"},
                {k: v for k, v in base.items() if k != "justification"},
                {**base, "justification": "trust_me"},
                {**base, "impact_statement": " "},
                {**base, "status": "affected"},  # justification on affected, no action
                {**{k: v for k, v in base.items() if k not in ("justification", "impact_statement")}, "status": "affected"},
                {**base, "vulnerability": "XSA-1"},
                {**base, "products": ["robodr-windows"]},
                {**base, "products": []},
                {**base, "versions": "0.1"},
                {**base, "component": "ansi_term"},
                {**base, "timestamp": "yesterday"},
                {**base, "extra": 1},
            ]
            for s in bad:
                with self.assertRaises(ValueError, msg=json.dumps(s)[:120]):
                    load(write([s]))
            with self.assertRaises(ValueError):
                load(write([base, dict(base)]))

        def test_openvex(self):
            sts = load(write([base, {**base, "vulnerability": "CVE-2026-12345", "versions": ["0.2.0"]}]))
            d = openvex(sts, "0.1.0", "2026-10-31T00:00:00Z")
            self.assertEqual(d["@context"], "https://openvex.dev/ns/v0.2.0")
            self.assertEqual([s["vulnerability"]["name"] for s in d["statements"]], ["RUSTSEC-2021-0139"])
            st = d["statements"][0]
            self.assertEqual(st["justification"], "vulnerable_code_not_present")
            self.assertEqual(st["products"][0]["@id"], "pkg:generic/singularityrd/robodr@0.1.0")
            self.assertEqual(d, openvex(sts, "0.1.0", "2026-10-31T00:00:00Z"))
            self.assertEqual(len(openvex(sts, "0.2.0")["statements"]), 2)
            self.assertEqual(openvex([], "0.1.0")["statements"], [])

        def test_csaf(self):
            aff = {k: v for k, v in base.items() if k not in ("justification", "impact_statement")}
            aff.update(vulnerability="CVE-2026-0001", status="affected", action_statement="upgrade to 0.1.1",
                       aliases=["GHSA-2222-3333-4444"])
            sts = load(write([base, aff]))
            d = csaf(sts, "0.1.0")
            self.assertEqual(d["document"]["category"], "csaf_vex")
            v = {x.get("cve") or x["ids"][0]["text"]: x for x in d["vulnerabilities"]}
            self.assertEqual(v["RUSTSEC-2021-0139"]["product_status"], {"known_not_affected": ["CSAFPID-robodr-0.1.0"]})
            self.assertEqual(v["RUSTSEC-2021-0139"]["flags"][0]["label"], "vulnerable_code_not_present")
            self.assertEqual(v["CVE-2026-0001"]["product_status"], {"known_affected": ["CSAFPID-robodr-0.1.0"]})
            self.assertEqual(v["CVE-2026-0001"]["ids"], [{"system_name": "GHSA", "text": "GHSA-2222-3333-4444"}])
            self.assertIn("remediations", v["CVE-2026-0001"])
            pids = {b["branches"][0]["product"]["product_id"] for b in d["product_tree"]["branches"][0]["branches"]}
            for x in d["vulnerabilities"]:
                for ids in x["product_status"].values():
                    self.assertTrue(set(ids) <= pids)
            with self.assertRaises(ValueError):
                csaf([], "0.1.0")

        def test_coverage(self):
            sts = load(write([{**base, "aliases": ["CVE-2021-1111"]}]))
            self.assertEqual(coverage(sts, "0.1.0", ["RUSTSEC-2021-0139", "CVE-2021-1111"]), [])
            self.assertEqual(coverage(sts, "0.1.0", ["RUSTSEC-2026-0001"]), ["RUSTSEC-2026-0001"])
            p = write([base])
            fd = os.path.join(os.path.dirname(p), "f.txt")
            with open(fd, "w") as f:
                f.write("# found\nRUSTSEC-2021-0139\nRUSTSEC-2026-0001\n")
            self.assertEqual(main(["coverage", "--version", "0.1.0", "--findings", fd, "--statements", p]), 1)
            with open(fd, "w") as f:
                f.write("RUSTSEC-2021-0139\n")
            self.assertEqual(main(["coverage", "--version", "0.1.0", "--findings", fd, "--statements", p]), 0)

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
    return 0 if r.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "security", "vex", "statements.json")
    ap = argparse.ArgumentParser(description="RoboDR VEX documents")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "openvex", "csaf", "coverage"):
        p = sub.add_parser(name)
        p.add_argument("--statements", default=default)
        if name != "check":
            p.add_argument("--version", required=True)
        if name in ("openvex", "csaf"):
            p.add_argument("--out", required=True)
            p.add_argument("--timestamp")
        if name == "coverage":
            p.add_argument("--findings", required=True)
    a = ap.parse_args(argv)
    try:
        sts = load(a.statements)
        if a.cmd == "check":
            print(f"{a.statements}: {len(sts)} statement(s) OK")
            return 0
        if a.cmd == "coverage":
            missing = coverage(sts, a.version, read_findings(a.findings))
            for m in missing:
                print(f"::error::{m} affects a dependency of robodr {a.version} and has no VEX statement "
                      f"(security/vex/statements.json)", file=sys.stderr)
            if not missing:
                print(f"robodr {a.version}: every finding has a VEX statement")
            return 1 if missing else 0
        doc = openvex(sts, a.version, a.timestamp) if a.cmd == "openvex" else csaf(sts, a.version, a.timestamp)
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(json.dumps(doc, indent=2) + "\n")
        print(f"{a.out}: {a.cmd}, {len(doc.get('statements', doc.get('vulnerabilities', [])))} statement(s)")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"vex: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
