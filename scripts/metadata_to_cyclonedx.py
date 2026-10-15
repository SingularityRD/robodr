#!/usr/bin/env python3
"""Convert `cargo metadata --format-version 1` JSON into a CycloneDX 1.5 JSON SBOM.

Fallback SBOM generator for hosts without cargo-cyclonedx (air-gapped build
hosts, the dev sandbox). Python 3.11+ standard library only.

    cargo metadata --format-version 1 --locked > meta.json
    python3 scripts/metadata_to_cyclonedx.py meta.json --lockfile Cargo.lock > robodr.cdx.json
    python3 scripts/metadata_to_cyclonedx.py --check robodr.cdx.json
    python3 scripts/metadata_to_cyclonedx.py --self-test

What it records, per resolved package: name, version, purl, SPDX license
expression (or the raw string as a named license when the string is not a
syntactically valid SPDX expression), the crates.io SHA-256 checksum from
Cargo.lock (when --lockfile is given), the source kind and repository URL, and
the dependency graph from cargo's resolver.

Design choices:
  * Deterministic: the same inputs give byte-identical output. No wall-clock
    timestamp unless SOURCE_DATE_EPOCH is set; serialNumber is a UUIDv5 of the
    content; components and edges are sorted; no absolute build paths (path
    crates are recorded relative to the workspace root).
  * Shipped graph only by default: packages reachable from the workspace
    members solely through dev-dependencies are dropped (--include-dev keeps
    them). Build-dependencies are kept: they are part of the build supply chain.

Limits (honest): the SPDX check is syntactic, not against the SPDX license
list; `cargo metadata` resolves for all targets/features unless filtered by the
caller (`--filter-platform`, feature flags), so the SBOM can be a superset of
what a given binary links; it does not hash the built artefacts themselves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

SPEC_VERSION = "1.5"
TOOL_NAME = "robodr-metadata-to-cyclonedx"
TOOL_VERSION = "1.0.0"
CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}

# --------------------------------------------------------------------------
# SPDX expression syntax check (SPDX 2.3 Annex D grammar, syntax only).
# --------------------------------------------------------------------------
_ID = re.compile(r"^(?:DocumentRef-[A-Za-z0-9.\-]+:)?[A-Za-z0-9.\-]+\+?$")
_OPS = {"AND", "OR", "WITH"}


def _tokenize(expr: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", expr)


def normalize_spdx(expr: str | None) -> str | None:
    """Return a valid SPDX expression for `expr`, or None if it is not one.

    Accepts cargo's legacy `MIT/Apache-2.0` form (rewritten to `OR`).
    """
    if not expr or not isinstance(expr, str):
        return None
    expr = expr.strip()
    if "/" in expr and not any(t in _OPS for t in _tokenize(expr)):
        expr = " OR ".join(p.strip() for p in expr.split("/"))
    toks = _tokenize(expr)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def ident(allow_plus: bool) -> bool:
        nonlocal pos
        t = peek()
        if t is None or t in _OPS or t in "()" or not _ID.match(t):
            return False
        if not allow_plus and t.endswith("+"):
            return False
        pos += 1
        return True

    def atom() -> bool:
        nonlocal pos
        if peek() == "(":
            pos += 1
            if not or_expr() or peek() != ")":
                return False
            pos += 1
            return True
        if not ident(allow_plus=True):
            return False
        if peek() == "WITH":
            pos += 1
            return ident(allow_plus=False)
        return True

    def and_expr() -> bool:
        nonlocal pos
        if not atom():
            return False
        while peek() == "AND":
            pos += 1
            if not atom():
                return False
        return True

    def or_expr() -> bool:
        nonlocal pos
        if not and_expr():
            return False
        while peek() == "OR":
            pos += 1
            if not and_expr():
                return False
        return True

    if not toks or len(toks) > 512:
        return None
    try:
        ok = or_expr() and pos == len(toks)
    except RecursionError:
        return None
    return " ".join(toks).replace("( ", "(").replace(" )", ")") if ok else None


# --------------------------------------------------------------------------
# Conversion
# --------------------------------------------------------------------------
def _lock_checksums(lock: dict | None) -> dict[tuple[str, str, str], str]:
    out: dict[tuple[str, str, str], str] = {}
    for p in (lock or {}).get("package", []) or []:
        if isinstance(p, dict) and p.get("checksum") and p.get("source"):
            out[(p.get("name"), p.get("version"), p["source"])] = p["checksum"]
    return out


def _purl(pkg: dict, root: str) -> str:
    name = quote(str(pkg.get("name", "")), safe="")
    ver = quote(str(pkg.get("version", "")), safe="")
    base = f"pkg:cargo/{name}@{ver}"
    src = pkg.get("source")
    if src is None:
        rel = _rel_dir(pkg, root)
        return f"{base}?download_url={quote('file:' + rel, safe=':/')}"
    if src in CRATES_IO_SOURCES:
        return base
    if src.startswith("git+"):
        url = src[len("git+") :]
        url, _, commit = url.partition("#")
        url = url.split("?", 1)[0]
        q = quote(f"git+{url}" + (f"@{commit}" if commit else ""), safe=":/@")
        return f"{base}?vcs_url={q}"
    reg = src.split("+", 1)[-1]
    return f"{base}?repository_url={quote(reg, safe=':/')}"


def _rel_dir(pkg: dict, root: str) -> str:
    mp = pkg.get("manifest_path") or ""
    d = os.path.dirname(mp)
    if root and d:
        try:
            rel = os.path.relpath(d, root)
        except ValueError:
            rel = os.path.basename(d)
        if not rel.startswith(".."):
            return rel.replace(os.sep, "/")
    return os.path.basename(d) or str(pkg.get("name", ""))


def _licenses(pkg: dict) -> list[dict]:
    raw = pkg.get("license")
    if raw:
        norm = normalize_spdx(raw)
        if norm:
            return [{"expression": norm}]
        return [{"license": {"name": str(raw)}}]
    if pkg.get("license_file"):
        return [{"license": {"name": f"see license file: {os.path.basename(pkg['license_file'])}"}}]
    return []


def _reachable(members: list[str], nodes: dict[str, dict], include_dev: bool) -> set[str]:
    seen = set(members)
    stack = list(members)
    while stack:
        cur = stack.pop()
        for d in (nodes.get(cur) or {}).get("deps", []) or []:
            kinds = [k.get("kind") for k in d.get("dep_kinds", []) or [{"kind": None}]]
            if not include_dev and kinds and all(k == "dev" for k in kinds):
                continue
            pid = d.get("pkg")
            if pid and pid not in seen:
                seen.add(pid)
                stack.append(pid)
    return seen


def convert(
    metadata: dict,
    lock: dict | None = None,
    include_dev: bool = False,
    root_name: str | None = None,
    root_version: str | None = None,
    source_date_epoch: str | None = None,
) -> dict:
    if not isinstance(metadata, dict) or not isinstance(metadata.get("packages"), list):
        raise ValueError("not cargo metadata: missing 'packages' list")
    root = metadata.get("workspace_root") or ""
    pkgs = {p["id"]: p for p in metadata["packages"] if isinstance(p, dict) and "id" in p}
    members = [m for m in metadata.get("workspace_members", []) if m in pkgs]
    resolve = metadata.get("resolve") or {}
    nodes = {n["id"]: n for n in resolve.get("nodes", []) or [] if isinstance(n, dict) and "id" in n}
    keep = _reachable(members, nodes, include_dev) if nodes else set(pkgs)
    sums = _lock_checksums(lock)

    ref_of: dict[str, str] = {}
    used: set[str] = set()
    for pid in sorted(keep):
        p = pkgs.get(pid)
        if p is None:
            continue
        ref = _purl(p, root)
        n = 2
        while ref in used:  # same name@version from two sources
            ref = f"{_purl(p, root)}#{n}"
            n += 1
        used.add(ref)
        ref_of[pid] = ref

    components = []
    for pid, ref in ref_of.items():
        p = pkgs[pid]
        is_member = pid in members
        has_bin = any("bin" in (t.get("kind") or []) for t in p.get("targets", []) or [])
        c: dict = {
            "type": "application" if is_member and has_bin else "library",
            "bom-ref": ref,
            "name": str(p.get("name", "")),
            "version": str(p.get("version", "")),
            "scope": "required",
            "purl": ref.split("#", 1)[0],
        }
        if p.get("description"):
            c["description"] = " ".join(str(p["description"]).split())
        lic = _licenses(p)
        if lic:
            c["licenses"] = lic
        src = p.get("source")
        ck = sums.get((p.get("name"), p.get("version"), src)) if src else None
        if ck and re.fullmatch(r"[0-9a-fA-F]{64}", ck):
            c["hashes"] = [{"alg": "SHA-256", "content": ck.lower()}]
        refs = []
        if p.get("repository"):
            refs.append({"type": "vcs", "url": str(p["repository"])})
        if refs:
            c["externalReferences"] = refs
        props = [
            {"name": "robodr:cargo:source", "value": src if src else "path"},
            {"name": "robodr:cargo:workspace-member", "value": "true" if is_member else "false"},
        ]
        if not src:
            props.append({"name": "robodr:cargo:path", "value": _rel_dir(p, root)})
        c["properties"] = props
        components.append(c)
    components.sort(key=lambda c: c["bom-ref"])

    deps = []
    for pid, ref in ref_of.items():
        node = nodes.get(pid)
        if node is None:
            continue
        on = sorted({ref_of[d["pkg"]] for d in node.get("deps", []) or [] if d.get("pkg") in ref_of})
        deps.append({"ref": ref, "dependsOn": on})
    deps.sort(key=lambda d: d["ref"])

    member_versions = sorted({str(pkgs[m].get("version", "")) for m in members})
    name = root_name or (os.path.basename(root.rstrip("/")) if root else "workspace")
    version = root_version or (member_versions[0] if len(member_versions) == 1 else "0.0.0")
    root_ref = f"pkg:cargo/{quote(name, safe='')}@{quote(version, safe='')}?type=workspace"
    deps.insert(0, {"ref": root_ref, "dependsOn": sorted(ref_of[m] for m in members)})

    meta: dict = {
        "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}]},
        "component": {"type": "application", "bom-ref": root_ref, "name": name, "version": version},
    }
    if source_date_epoch:
        ts = datetime.fromtimestamp(int(source_date_epoch), tz=timezone.utc)
        meta["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    body = {"metadata": meta, "components": components, "dependencies": deps}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'robodr-sbom:' + digest)}",
        "version": 1,
        **body,
    }


# --------------------------------------------------------------------------
# Minimal structural check of a CycloneDX JSON BOM (any producer).
# --------------------------------------------------------------------------
def check_bom(bom) -> list[str]:
    errs: list[str] = []
    if not isinstance(bom, dict):
        return ["BOM is not a JSON object"]
    if bom.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat must be 'CycloneDX'")
    if not re.fullmatch(r"1\.[0-9]+", str(bom.get("specVersion", ""))):
        errs.append("specVersion missing or not 1.x")
    sn = bom.get("serialNumber")
    if sn is not None and not re.fullmatch(r"urn:uuid:[0-9a-f\-]{36}", str(sn)):
        errs.append(f"serialNumber not a urn:uuid: {sn!r}")
    comps = bom.get("components", [])
    if not isinstance(comps, list):
        return errs + ["components is not a list"]
    refs: set[str] = set()
    mc = (bom.get("metadata") or {}).get("component") or {}
    if mc.get("bom-ref"):
        refs.add(mc["bom-ref"])

    def walk(cs, path):
        for i, c in enumerate(cs):
            where = f"{path}[{i}]"
            if not isinstance(c, dict):
                errs.append(f"{where}: not an object")
                continue
            for k in ("type", "name"):
                if not c.get(k):
                    errs.append(f"{where}: missing {k}")
            r = c.get("bom-ref")
            if r is not None:
                if r in refs:
                    errs.append(f"{where}: duplicate bom-ref {r!r}")
                refs.add(r)
            for h in c.get("hashes", []) or []:
                if h.get("alg") == "SHA-256" and not re.fullmatch(r"[0-9a-f]{64}", str(h.get("content", ""))):
                    errs.append(f"{where}: bad SHA-256 {h.get('content')!r}")
            walk(c.get("components", []) or [], where + ".components")

    walk(comps, "components")
    for d in bom.get("dependencies", []) or []:
        if d.get("ref") not in refs:
            errs.append(f"dependencies: unknown ref {d.get('ref')!r}")
        for o in d.get("dependsOn", []) or []:
            if o not in refs:
                errs.append(f"dependencies[{d.get('ref')}]: unknown dependsOn {o!r}")
    return errs


def check_against_lock(bom, lock: dict) -> list[str]:
    """Cross-check a BOM against Cargo.lock.

    Every component must be a package (name + version) recorded in the lock,
    and every SHA-256 the BOM states must equal the lock's checksum for it.
    Lock packages absent from the BOM are not errors (dev-only dependencies
    are omitted by design).
    """
    errs: list[str] = []
    if not isinstance(bom, dict):
        return ["BOM is not a JSON object"]
    by_nv: dict[tuple[str, str], set[str]] = {}
    for p in (lock or {}).get("package", []) or []:
        if isinstance(p, dict):
            key = (str(p.get("name")), str(p.get("version")))
            by_nv.setdefault(key, set())
            if p.get("checksum"):
                by_nv[key].add(str(p["checksum"]).lower())

    def walk(cs):
        for c in cs or []:
            if not isinstance(c, dict):
                continue
            key = (str(c.get("name")), str(c.get("version")))
            if key not in by_nv:
                errs.append(f"component {key[0]}@{key[1]} is not in Cargo.lock")
            else:
                for h in c.get("hashes", []) or []:
                    if h.get("alg") == "SHA-256":
                        got = str(h.get("content", "")).lower()
                        if got not in by_nv[key]:
                            errs.append(f"component {key[0]}@{key[1]}: SHA-256 {got} != Cargo.lock checksum")
            walk(c.get("components"))

    walk(bom.get("components"))
    return errs


# --------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("metadata", nargs="?", default="-", help="cargo metadata JSON file, or - for stdin")
    ap.add_argument("--lockfile", help="Cargo.lock to take SHA-256 checksums from")
    ap.add_argument("--include-dev", action="store_true", help="keep dev-only dependencies")
    ap.add_argument("--name", help="root component name (default: workspace dir name)")
    ap.add_argument("--version", dest="root_version", help="root component version")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    ap.add_argument(
        "--check",
        metavar="BOM",
        help="check a CycloneDX JSON file (with --lockfile: cross-check it against Cargo.lock) and exit",
    )
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)

    if a.self_test:
        return _self_test()
    if a.check:
        try:
            with open(a.check, encoding="utf-8") as f:
                bom = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: {a.check}: {e}", file=sys.stderr)
            return 1
        errs = check_bom(bom)
        if a.lockfile:
            try:
                with open(a.lockfile, "rb") as f:
                    errs += check_against_lock(bom, tomllib.load(f))
            except (OSError, tomllib.TOMLDecodeError) as e:
                errs.append(f"cannot read {a.lockfile}: {e}")
        for e in errs:
            print(f"{a.check}: {e}", file=sys.stderr)
        if not errs:
            print(f"{a.check}: OK ({len(bom.get('components', []))} components)")
        return 1 if errs else 0

    try:
        if a.metadata == "-":
            metadata = json.load(sys.stdin)
        else:
            with open(a.metadata, encoding="utf-8") as f:
                metadata = json.load(f)
        lock = None
        if a.lockfile:
            with open(a.lockfile, "rb") as f:
                lock = tomllib.load(f)
        bom = convert(
            metadata,
            lock=lock,
            include_dev=a.include_dev,
            root_name=a.name,
            root_version=a.root_version,
            source_date_epoch=os.environ.get("SOURCE_DATE_EPOCH") or None,
        )
    except (OSError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    text = json.dumps(bom, indent=2, sort_keys=False) + "\n"
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


def _fixture() -> dict:
    W = "/build/robodr"
    CIO = "registry+https://github.com/rust-lang/crates.io-index"

    def pkg(pid, name, ver, src, lic, manifest=None, bins=False, **extra):
        p = {
            "id": pid,
            "name": name,
            "version": ver,
            "source": src,
            "license": lic,
            "license_file": None,
            "manifest_path": manifest or f"/reg/{name}/Cargo.toml",
            "targets": [{"kind": ["bin" if bins else "lib"]}],
            "repository": None,
            "description": None,
        }
        p.update(extra)
        return p

    ev = f"path+file://{W}/crates/robodr-events#robodr-events@0.1.0"
    cm = f"path+file://{W}/crates/robodr-commission#robodr-commission@0.1.0"
    pc = f"path+file://{W}/vendor/pulsar/crates/pulsar-core#0.11.0"
    se = f"{CIO}#serde@1.0.219"
    dv = f"{CIO}#proptest@1.0.0"
    gi = "git+https://example.com/g.git?rev=abc#abcdef0123"
    return {
        "workspace_root": W,
        "workspace_members": [ev, cm],
        "packages": [
            pkg(
                ev,
                "robodr-events",
                "0.1.0",
                None,
                "Apache-2.0",
                f"{W}/crates/robodr-events/Cargo.toml",
                description="Pure\n  events",
                repository="https://github.com/SingularityRD/robodr",
            ),
            pkg(
                cm,
                "robodr-commission",
                "0.1.0",
                None,
                "Apache-2.0",
                f"{W}/crates/robodr-commission/Cargo.toml",
                bins=True,
            ),
            pkg(
                pc,
                "pulsar-core",
                "0.11.0",
                None,
                "Apache-2.0 WITH BPF probes exception under GPL-2.0",
                f"{W}/vendor/pulsar/crates/pulsar-core/Cargo.toml",
            ),
            pkg(se, "serde", "1.0.219", CIO, "MIT/Apache-2.0"),
            pkg(dv, "proptest", "1.0.0", CIO, "MIT OR Apache-2.0"),
            pkg(
                gi,
                "g",
                "0.1.0",
                "git+https://example.com/g.git?rev=abc#abcdef0123",
                None,
                license_file="/reg/g/LICENSE",
            ),
        ],
        "resolve": {
            "nodes": [
                {
                    "id": ev,
                    "deps": [
                        {"pkg": se, "dep_kinds": [{"kind": None}]},
                        {"pkg": dv, "dep_kinds": [{"kind": "dev"}]},
                    ],
                },
                {
                    "id": cm,
                    "deps": [
                        {"pkg": ev, "dep_kinds": [{"kind": None}]},
                        {"pkg": pc, "dep_kinds": [{"kind": None}]},
                        {"pkg": gi, "dep_kinds": [{"kind": "build"}]},
                    ],
                },
                {"id": pc, "deps": [{"pkg": se, "dep_kinds": [{"kind": None}]}]},
                {"id": se, "deps": []},
                {"id": dv, "deps": [{"pkg": se, "dep_kinds": [{"kind": None}]}]},
                {"id": gi, "deps": []},
            ]
        },
    }


def _self_test() -> int:
    import copy
    import unittest

    lock = tomllib.loads(
        '[[package]]\nname = "serde"\nversion = "1.0.219"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "5F0E2C6ED6606019B4E29E69DBABA95B11854410E5347D525002456DBBB786B6"\n'
    )

    class Spdx(unittest.TestCase):
        def test_valid(self):
            for e in [
                "MIT",
                "Apache-2.0",
                "MIT OR Apache-2.0",
                "(MIT OR Apache-2.0) AND BSD-3-Clause",
                "GPL-2.0-or-later WITH Classpath-exception-2.0",
                "GPL-2.0+",
                "LicenseRef-foo",
                "DocumentRef-x:LicenseRef-y",
                "Apache-2.0 WITH LLVM-exception OR MIT",
            ]:
                self.assertIsNotNone(normalize_spdx(e), e)

        def test_slash_legacy(self):
            self.assertEqual(normalize_spdx("MIT/Apache-2.0"), "MIT OR Apache-2.0")

        def test_invalid(self):
            for e in [
                "Apache-2.0 WITH BPF probes exception under GPL-2.0",
                "",
                None,
                "MIT OR",
                "(MIT",
                "MIT)",
                "AND MIT",
                "MIT WITH",
                "MIT WITH X+",
                "MIT AND AND GPL-2.0",
                "M!T",
                "()",
                "(" * 600 + "MIT" + ")" * 600,
                42,
            ]:
                self.assertIsNone(normalize_spdx(e), repr(e)[:40])

        def test_parens_normalized(self):
            self.assertEqual(normalize_spdx("( MIT  OR Apache-2.0 )"), "(MIT OR Apache-2.0)")

    class Convert(unittest.TestCase):
        def bom(self, **kw):
            return convert(_fixture(), lock=lock, **kw)

        def comp(self, bom, name):
            return next(c for c in bom["components"] if c["name"] == name)

        def test_structure_valid(self):
            b = self.bom()
            self.assertEqual(check_bom(b), [])
            self.assertEqual(b["specVersion"], "1.5")
            self.assertNotIn("timestamp", b["metadata"])

        def test_dev_only_dropped_by_default(self):
            names = {c["name"] for c in self.bom()["components"]}
            self.assertNotIn("proptest", names)
            self.assertIn("g", names)  # build-dep kept
            names = {c["name"] for c in self.bom(include_dev=True)["components"]}
            self.assertIn("proptest", names)

        def test_licenses(self):
            b = self.bom()
            self.assertEqual(self.comp(b, "serde")["licenses"], [{"expression": "MIT OR Apache-2.0"}])
            self.assertEqual(
                self.comp(b, "pulsar-core")["licenses"][0]["license"]["name"],
                "Apache-2.0 WITH BPF probes exception under GPL-2.0",
            )
            self.assertIn("LICENSE", self.comp(b, "g")["licenses"][0]["license"]["name"])

        def test_hash_from_lock_lowercased(self):
            h = self.comp(self.bom(), "serde")["hashes"][0]
            self.assertEqual(h["alg"], "SHA-256")
            self.assertEqual(h["content"], h["content"].lower())
            self.assertNotIn("hashes", self.comp(convert(_fixture()), "serde"))

        def test_purls_and_no_abs_paths(self):
            b = self.bom()
            self.assertEqual(self.comp(b, "serde")["purl"], "pkg:cargo/serde@1.0.219")
            self.assertIn("vcs_url=git%2Bhttps://example.com/g.git@abcdef0123", self.comp(b, "g")["purl"])
            self.assertIn("file:crates/robodr-events", self.comp(b, "robodr-events")["purl"])
            self.assertNotIn("/build/robodr", json.dumps(b))

        def test_app_type_and_root(self):
            b = self.bom()
            self.assertEqual(self.comp(b, "robodr-commission")["type"], "application")
            self.assertEqual(self.comp(b, "robodr-events")["type"], "library")
            self.assertEqual(b["metadata"]["component"]["name"], "robodr")
            self.assertEqual(b["metadata"]["component"]["version"], "0.1.0")
            root = b["dependencies"][0]
            self.assertEqual(len(root["dependsOn"]), 2)

        def test_description_whitespace(self):
            self.assertEqual(self.comp(self.bom(), "robodr-events")["description"], "Pure events")

        def test_deterministic(self):
            a = json.dumps(self.bom())
            m = _fixture()
            m["packages"].reverse()
            m["resolve"]["nodes"].reverse()
            self.assertEqual(a, json.dumps(convert(m, lock=lock)))

        def test_source_date_epoch(self):
            b = self.bom(source_date_epoch="1700000000")
            self.assertEqual(b["metadata"]["timestamp"], "2023-11-14T22:13:20Z")
            self.assertNotEqual(b["serialNumber"], self.bom()["serialNumber"])

        def test_no_resolve_keeps_all(self):
            m = _fixture()
            m["resolve"] = None
            b = convert(m)
            self.assertEqual(len(b["components"]), 6)
            self.assertEqual(check_bom(b), [])

        def test_duplicate_name_version(self):
            m = _fixture()
            extra = copy.deepcopy(m["packages"][3])
            extra["id"] = "other#serde@1.0.219"
            m["packages"].append(extra)
            m["resolve"]["nodes"].append({"id": extra["id"], "deps": []})
            m["resolve"]["nodes"][0]["deps"].append({"pkg": extra["id"], "dep_kinds": [{"kind": None}]})
            b = convert(m)
            self.assertEqual(check_bom(b), [])
            self.assertEqual(sum(c["name"] == "serde" for c in b["components"]), 2)

        def test_hostile_input(self):
            for bad in [None, [], {}, {"packages": "x"}, "str"]:
                with self.assertRaises(ValueError):
                    convert(bad)
            m = {
                "packages": [{"id": "a", "name": "a", "version": "1"}, 7],
                "workspace_members": ["a", "zz"],
                "resolve": {"nodes": [{"id": "a", "deps": [{"pkg": "missing"}]}, "junk"]},
            }
            self.assertEqual(check_bom(convert(m)), [])

    class Check(unittest.TestCase):
        def test_against_lock(self):
            b = convert(_fixture(), lock=lock)
            full = tomllib.loads(
                "".join(
                    f'[[package]]\nname = "{c["name"]}"\nversion = "{c["version"]}"\n'
                    for c in b["components"]
                    if c["name"] != "serde"
                )
            )
            full["package"] += lock["package"]
            self.assertEqual(check_against_lock(b, full), [])
            tampered = copy.deepcopy(b)
            self.comp_named(tampered, "serde")["hashes"][0]["content"] = "0" * 64
            self.assertEqual(len(check_against_lock(tampered, full)), 1)
            self.assertEqual(len(check_against_lock(b, lock)), len(b["components"]) - 1)
            self.assertTrue(check_against_lock("x", lock))

        @staticmethod
        def comp_named(bom, name):
            return next(c for c in bom["components"] if c["name"] == name)

        def test_detects_problems(self):
            self.assertTrue(check_bom([]))
            b = convert(_fixture())
            b["components"].append(copy.deepcopy(b["components"][0]))
            self.assertTrue(any("duplicate" in e for e in check_bom(b)))
            b = convert(_fixture())
            b["dependencies"].append({"ref": "nope", "dependsOn": ["nada"]})
            self.assertEqual(len(check_bom(b)), 2)
            b = convert(_fixture())
            b["bomFormat"] = "SPDX"
            b["components"][0]["hashes"] = [{"alg": "SHA-256", "content": "xyz"}]
            self.assertEqual(len(check_bom(b)), 2)

    suite = unittest.TestSuite()
    for cls in (Spdx, Convert, Check):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    r = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if r.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
