#!/usr/bin/env python3
"""Unsigned secure-delivery RPKs of a release (docs/RELEASE.md "Secure
delivery: RPKs and the 2-of-N signing ceremony"; docs/SECURE-DELIVERY.md).

    release-rpk.py --version V --assets DIR --rules DIR --robodr-release BIN --out DIR
                   [--platform LABEL] [--sha256sums FILE]
    release-rpk.py --self-test

From the release's own assets (the build jobs' output, before signing) it
builds, with `robodr-release build rpk`:

  * robodr        kind deb,          amd64 / arm64: the robodr .deb
  * robodr-focal  kind deb,          amd64 / arm64: the robodr-focal .deb
  * robodr-rules  kind robodr-rules, all:           rules/robodr/*.toml
                                                    of the tagged commit

each with one CycloneDX SBOM (`sbom.cdx.json`: the architecture's per-crate
SBOMs from robodr-<ver>-<arch>-sbom.tar.gz / robodr-focal-...-sbom.tar.gz,
merged), and writes DIR/DELIVERY-MANIFEST.json: every RPK's directory, RPK
digest, name, serial, arch and the SHA-256 of its payload, plus the commands
of the offline 2-of-N ceremony. Every RPK is built TWICE (separate output
directories) and the two digests must agree (the build is deterministic, so
the offline station can rebuild and compare). The RPKs are UNSIGNED: the
release quorum (two holders of the programme's release keys) signs them
offline, then builds and signs the bundle (`robodr-release sign`,
`build bundle`); no delivery key ever reaches CI.

Serial: robodr-pkg orders releases by an integer serial. From the semantic
version X.Y.Z[-pre]: serial = ((X*1000 + Y)*1000 + Z)*1000 + p, with
p = 100+N for alpha.N, 400+N for beta.N, 700+N for rc.N (N <= 99) and 999
for a final release, so 0.1.0-alpha.1 < 0.1.0-rc.2 < 0.1.0 < 0.1.1. Any
other pre-release label is refused.

Exit: 0 built, 1 refused / failed, 2 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

PRE = {"alpha": 100, "beta": 400, "rc": 700}
SEMVER = re.compile(r"^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})(?:-([a-z]+)\.(0|[1-9][0-9]?))?$")
ARCHS = ("amd64", "arm64")
MAX_SBOM_BYTES = 64 * 1024 * 1024  # robodr-pkg MAX_SBOM_BYTES


def serial(version: str) -> int:
    m = SEMVER.match(version)
    if not m:
        raise ValueError(f"version {version!r}: want X.Y.Z or X.Y.Z-(alpha|beta|rc).N with parts < 1000, N < 100")
    x, y, z = (int(m.group(i)) for i in (1, 2, 3))
    if m.group(4) is None:
        p = 999
    elif m.group(4) in PRE:
        p = PRE[m.group(4)] + int(m.group(5))
    else:
        raise ValueError(f"version {version!r}: pre-release label {m.group(4)!r} has no serial (alpha, beta, rc)")
    return ((x * 1000 + y) * 1000 + z) * 1000 + p


def deb_version(version: str) -> str:
    return version.replace("-", "~", 1) + "-1"


def merge_sboms(boms: list[dict], name: str, version: str, deb_name: str, deb_sha: str) -> dict:
    """One CycloneDX 1.5 BOM for a package: the union of its crates' BOMs."""
    comps: dict[str, dict] = {}
    deps: dict[str, set[str]] = {}
    roots: list[str] = []
    form: list[dict] = []
    for b in boms:
        if not isinstance(b, dict) or b.get("bomFormat") != "CycloneDX":
            raise ValueError("not a CycloneDX BOM")
        mc = (b.get("metadata") or {}).get("component")
        if isinstance(mc, dict) and mc.get("bom-ref"):
            roots.append(mc["bom-ref"])
            comps.setdefault(mc["bom-ref"], mc)
        for c in b.get("components", []) or []:
            if isinstance(c, dict) and c.get("bom-ref"):
                comps.setdefault(c["bom-ref"], c)
        for d in b.get("dependencies", []) or []:
            if isinstance(d, dict) and d.get("ref"):
                deps.setdefault(d["ref"], set()).update(d.get("dependsOn", []) or [])
        for f in b.get("formulation", []) or []:
            if f not in form:
                form.append(f)
    root_ref = f"pkg:deb/robodr/{name}@{deb_version(version)}"
    known = set(comps) | {root_ref}
    deps[root_ref] = set(roots)
    out = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": name,
                "version": version,
                "hashes": [{"alg": "SHA-256", "content": deb_sha}],
                "properties": [{"name": "robodr:package-file", "value": deb_name}],
            },
            "tools": {"components": [{"type": "application", "name": "robodr-release-rpk.py", "version": "1"}]},
        },
        "components": [comps[k] for k in sorted(comps)],
        "dependencies": [
            {"ref": r, "dependsOn": sorted(x for x in deps[r] if x in known)} for r in sorted(deps) if r in known
        ],
    }
    if form:
        out["formulation"] = form
    digest = hashlib.sha256(json.dumps(out, sort_keys=True).encode()).hexdigest()
    import uuid

    out["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'robodr-rpk-sbom:' + digest)}"
    return out


def sboms_from_tarball(path: Path) -> list[dict]:
    out = []
    with tarfile.open(path, "r:gz") as t:
        for m in sorted(t.getmembers(), key=lambda m: m.name):
            if m.isfile() and m.name.endswith(".cdx.json"):
                f = t.extractfile(m)
                if f is None or m.size > MAX_SBOM_BYTES:
                    raise ValueError(f"{path}: {m.name} unreadable or too large")
                out.append(json.load(f))
    if not out:
        raise ValueError(f"{path}: no *.cdx.json")
    return out


def spec(name: str, version: str, kind: str, arch: str, platform: str, sbom: bool) -> dict:
    s = {
        "format": "robodr-rpk-spec/1",
        "name": name,
        "version": {"serial": serial(version), "display": version},
        "kind": kind,
        "platform": platform,
        "arch": arch,
        # 1: the release does not forbid older ones; a site raises its floor
        # in its trust file (robodr-release README, "floors").
        "security_floor": 1,
        "install": {
            # The packages' maintainer scripts create the robodr user, units
            # and directories (packaging/deb).
            "allow_maintainer_scripts": kind == "deb",
            "requires_operator_present": False,
        },
        "health": [{"check": "service_active", "unit": "robodr-agentd.service"}] if kind == "deb" else [],
    }
    if sbom:
        s["sbom_path"] = "sbom.cdx.json"
    return s


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def build_one(rr: str, spec_obj: dict, payload: Path, work: Path) -> tuple[str, str]:
    """Build twice; returns (rpk directory name, digest)."""
    sp = work / f"spec-{spec_obj['name']}-{spec_obj['arch']}.json"
    sp.write_text(json.dumps(spec_obj, indent=1) + "\n")
    got = []
    for i in (1, 2):
        out = work / f"build{i}"
        out.mkdir(exist_ok=True)
        p = subprocess.run(
            [rr, "build", "rpk", "--spec", str(sp), "--payload", str(payload), "--out-dir", str(out)],
            capture_output=True,
            text=True,
        )
        if p.returncode != 0:
            raise RuntimeError(f"robodr-release build rpk {spec_obj['name']}/{spec_obj['arch']}: {p.stderr.strip()}")
        v = json.loads(p.stdout)
        got.append((Path(v["rpk"]).name, v["digest"]))
    if got[0] != got[1]:
        raise RuntimeError(f"{spec_obj['name']}/{spec_obj['arch']}: two builds differ: {got}")
    return got[0]


def run(a) -> int:
    version = a.version
    serial(version)
    assets = Path(a.assets)
    out = Path(a.out)
    if out.exists() and any(out.iterdir()):
        raise RuntimeError(f"{out} is not empty")
    out.mkdir(parents=True, exist_ok=True)
    debver = deb_version(version)
    entries = []
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        jobs = []
        for arch in ARCHS:
            jobs.append(("robodr", f"robodr_{debver}_{arch}.deb", f"robodr-{version}-{arch}-sbom.tar.gz", arch))
            jobs.append(("robodr-focal", f"robodr-focal_{debver}_{arch}.deb", f"robodr-focal-{version}-{arch}-sbom.tar.gz", arch))
        for name, deb, sb, arch in jobs:
            debp, sbp = assets / deb, assets / sb
            for p in (debp, sbp):
                if not p.is_file():
                    raise RuntimeError(f"missing release asset {p.name}")
            payload = work / f"payload-{name}-{arch}"
            payload.mkdir()
            # RPK paths allow no '~' (the Debian pre-release separator): the
            # payload carries the package as <name>_<arch>.deb; the manifest
            # below maps it to the release asset's name and hash.
            inner = f"{name}_{arch}.deb"
            shutil.copyfile(debp, payload / inner)
            os.chmod(payload / inner, 0o644)
            dsha = sha256_file(debp)
            merged = merge_sboms(sboms_from_tarball(sbp), name, version, deb, dsha)
            (payload / "sbom.cdx.json").write_text(json.dumps(merged, indent=1) + "\n")
            os.chmod(payload / "sbom.cdx.json", 0o644)
            d, dig = build_one(a.robodr_release, spec(name, version, "deb", arch, a.platform, True), payload, work)
            entries.append({"name": name, "arch": arch, "kind": "deb", "rpk": d, "digest": dig,
                            "payload": {inner: dsha}, "release_asset": deb})
        rules = sorted(Path(a.rules).glob("*.toml"))
        if not rules:
            raise RuntimeError(f"no *.toml in {a.rules}")
        payload = work / "payload-rules"
        payload.mkdir()
        sums = {}
        for r in rules:
            shutil.copyfile(r, payload / r.name)
            os.chmod(payload / r.name, 0o644)
            sums[r.name] = sha256_file(r)
        d, dig = build_one(a.robodr_release, spec("robodr-rules", version, "robodr-rules", "all", a.platform, False),
                           payload, work)
        entries.append({"name": "robodr-rules", "arch": "all", "kind": "robodr-rules", "rpk": d, "digest": dig,
                        "payload": sums})
        for e in entries:
            shutil.copytree(work / "build1" / e["rpk"], out / e["rpk"], symlinks=False)
    manifest = {
        "format": "robodr-delivery-manifest/1",
        "version": version,
        "serial": serial(version),
        "platform": a.platform,
        "signed": False,
        "rpks": sorted(entries, key=lambda e: (e["name"], e["arch"])),
        "ceremony": [
            "Offline signing station, two holders of the programme's release keys (docs/RELEASE.md):",
            "robodr-release sign --key REL_KEY --target rpk_<name>_<serial>_<arch> TRUST   (each RPK, by two holders)",
            "robodr-release build bundle --programme P --seq N (--prev-bundle DIR | --prev-hash HEX) --rpk rpk_... TRUST --parity M --out bundle-N",
            "robodr-release sign --key REL_KEY --target bundle-N TRUST   (by two holders)",
            "robodr-release verify bundle --dir bundle-N TRUST --state chain-P.json",
        ],
    }
    (out / "DELIVERY-MANIFEST.json").write_text(json.dumps(manifest, indent=1) + "\n")
    for e in manifest["rpks"]:
        print(f"{e['rpk']}  {e['digest']}")
    return 0


def self_test() -> int:
    import unittest

    class T(unittest.TestCase):
        def test_serial_order(self):
            order = ["0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-beta.1", "0.1.0-rc.1", "0.1.0-rc.12",
                     "0.1.0", "0.1.1-rc.1", "0.1.1", "0.2.0", "1.0.0", "999.999.999"]
            s = [serial(v) for v in order]
            self.assertEqual(s, sorted(s))
            self.assertEqual(len(set(s)), len(s))
            self.assertEqual(serial("0.1.0-alpha.1"), 1000101)
            self.assertLess(serial("999.999.999"), 2**63)

        def test_serial_refused(self):
            for v in ["0.1", "v0.1.0", "0.1.0-dev.1", "0.1.0-rc", "0.1.0-rc.100", "1000.0.0", "01.0.0", "0.1.0+b"]:
                with self.assertRaises(ValueError, msg=v):
                    serial(v)

        def test_spec(self):
            s = spec("robodr", "0.1.0-alpha.1", "deb", "arm64", "linux", True)
            self.assertEqual(s["version"], {"serial": 1000101, "display": "0.1.0-alpha.1"})
            self.assertTrue(s["install"]["allow_maintainer_scripts"])
            self.assertEqual(s["sbom_path"], "sbom.cdx.json")
            r = spec("robodr-rules", "0.1.0", "robodr-rules", "all", "linux", False)
            self.assertFalse(r["install"]["allow_maintainer_scripts"])
            self.assertNotIn("sbom_path", r)
            self.assertEqual(r["health"], [])

        def test_merge(self):
            a = {"bomFormat": "CycloneDX", "specVersion": "1.5",
                 "metadata": {"component": {"type": "application", "bom-ref": "A", "name": "a"}},
                 "components": [{"type": "library", "bom-ref": "S", "name": "serde"}],
                 "dependencies": [{"ref": "A", "dependsOn": ["S", "GONE"]}],
                 "formulation": [{"bom-ref": "f", "components": []}]}
            b = json.loads(json.dumps(a))
            b["metadata"]["component"] = {"type": "application", "bom-ref": "B", "name": "b"}
            b["dependencies"] = [{"ref": "B", "dependsOn": ["S"]}]
            m = merge_sboms([a, b], "robodr", "0.1.0", "robodr_0.1.0-1_amd64.deb", "0" * 64)
            self.assertEqual([c["bom-ref"] for c in m["components"]], ["A", "B", "S"])
            root = m["dependencies"][[d["ref"] for d in m["dependencies"]].index("pkg:deb/robodr/robodr@0.1.0-1")]
            self.assertEqual(root["dependsOn"], ["A", "B"])
            self.assertNotIn("GONE", json.dumps(m["dependencies"]))
            self.assertEqual(len(m["formulation"]), 1)
            self.assertEqual(m, merge_sboms([a, b], "robodr", "0.1.0", "robodr_0.1.0-1_amd64.deb", "0" * 64))
            with self.assertRaises(ValueError):
                merge_sboms([{"bomFormat": "SPDX"}], "x", "0.1.0", "x.deb", "0" * 64)

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
    return 0 if r.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    ap = argparse.ArgumentParser(description="Unsigned secure-delivery RPKs of a release")
    ap.add_argument("--version", required=True)
    ap.add_argument("--assets", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--robodr-release", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--platform", default="linux")
    a = ap.parse_args(argv)
    try:
        return run(a)
    except (ValueError, RuntimeError, OSError, KeyError, json.JSONDecodeError, tarfile.TarError) as e:
        print(f"release-rpk: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
