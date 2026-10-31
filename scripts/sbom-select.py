#!/usr/bin/env python3
"""Keep in an SBOM directory only the SBOMs of what one package ships.

    scripts/sbom-select.py SBOM_DIR --package PKG [--metadata FILE]
    scripts/sbom-select.py --self-test

cargo-cyclonedx (scripts/sbom.sh) writes one SBOM per workspace crate,
whether or not a given package ships anything built from that crate. This
script, run on SBOM_DIR before scripts/release-sbom-augment.sh and
packaging/make-bundle.sh, removes every per-crate SBOM (*.cdx.json) whose
crate the package PKG (a .deb or .rpm) does not need, and rewrites
SBOM_DIR/SHA256SUMS when it exists. A crate is needed when one of its
[[bin]] programs is a usr/bin or usr/sbin robodr-* program in PKG, or when
a needed crate depends on it (normal or build dependency, workspace members
only; dev-dependencies do not count). The crate graph comes from
`cargo metadata --no-deps` (CARGO, default cargo), or FILE.

release.yml (build, build-rpm, build-static) and scripts/ci-rebuild.sh
(deb, focal) both call it, so the release bundle and its independent
rebuild carry the same SBOM members (scripts/compare-rebuild.py compares
bundle members; only SBOM content may differ). The self-test checks that
every `scripts/sbom.sh` call in those two files is followed by this script.

Fails (exit 1, nothing removed) when an SBOM's root component is not a
workspace crate, when a packaged robodr-* program is not a workspace
[[bin]] target, or when a packaged program's crate has no SBOM in SBOM_DIR.
Exit 0 selected, 1 refused, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
from pathlib import Path

PROGRAM = re.compile(r"usr/s?bin/(robodr-[a-z0-9-]+)")


def package_programs(pkg: Path) -> set[str]:
    """robodr-* program names under usr/bin and usr/sbin in a .deb or .rpm."""
    if pkg.suffix == ".deb":
        data = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(pkg)], check=True, capture_output=True).stdout
        mode = "r:"
    elif pkg.suffix == ".rpm":
        with pkg.open("rb") as fh:
            data = subprocess.run(["rpm2archive", "-"], stdin=fh, check=True, capture_output=True).stdout
        mode = "r:gz"
    else:
        raise ValueError(f"{pkg}: not a .deb or .rpm")
    out = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
        for m in tf:
            hit = PROGRAM.fullmatch(m.name.lstrip("./"))
            if hit and m.isfile():
                out.add(hit.group(1))
    return out


def needed_crates(metadata: dict, programs: set[str]) -> set[str]:
    """Workspace crates the programs are built from, and their workspace dependencies."""
    members = {p["name"]: p for p in metadata["packages"] if p["id"] in set(metadata["workspace_members"])}
    bin_of = {}
    for name, p in members.items():
        for t in p["targets"]:
            if "bin" in t["kind"]:
                bin_of[t["name"]] = name
    unknown = sorted(programs - set(bin_of))
    if unknown:
        raise ValueError(f"packaged program(s) not built by any workspace crate: {', '.join(unknown)}")
    todo = sorted({bin_of[p] for p in programs})
    need: set[str] = set()
    while todo:
        c = todo.pop()
        if c in need:
            continue
        need.add(c)
        for d in members[c].get("dependencies", []):
            if d.get("kind") != "dev" and d["name"] in members:
                todo.append(d["name"])
    return need


def root_name(path: Path) -> str | None:
    try:
        bom = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    name = ((bom.get("metadata") or {}).get("component") or {}).get("name") if isinstance(bom, dict) else None
    return name if isinstance(name, str) else None


def select(sbom_dir: Path, metadata: dict, programs: set[str]) -> tuple[list[Path], list[Path]]:
    """(kept, removed). Raises ValueError (nothing removed) on a refusal."""
    members = {p["name"] for p in metadata["packages"] if p["id"] in set(metadata["workspace_members"])}
    need = needed_crates(metadata, programs)
    kept, removed, roots = [], [], set()
    for f in sorted(sbom_dir.glob("*.cdx.json")):
        r = root_name(f)
        if r is None or r not in members:
            raise ValueError(f"{f.name}: root component {r!r} is not a workspace crate")
        roots.add(r)
        (kept if r in need else removed).append(f)
    shipped_crates = {c for p in programs for c in _crates_of(metadata, p)}
    missing = sorted(shipped_crates - roots)
    if missing:
        raise ValueError(f"no SBOM for the packaged crate(s): {', '.join(missing)}")
    for f in removed:
        f.unlink()
    sums = sbom_dir / "SHA256SUMS"
    if sums.exists():
        sums.write_text("".join(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n" for f in kept))
    return kept, removed


def _crates_of(metadata: dict, program: str) -> set[str]:
    return {
        p["name"]
        for p in metadata["packages"]
        if p["id"] in set(metadata["workspace_members"])
        and any("bin" in t["kind"] and t["name"] == program for t in p["targets"])
    }


def cargo_metadata() -> dict:
    cmd = shlex.split(os.environ.get("CARGO", "cargo")) + ["metadata", "--no-deps", "--format-version", "1"]
    root = Path(__file__).resolve().parent.parent
    return json.loads(subprocess.run(cmd, cwd=root, check=True, capture_output=True).stdout)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sbom_dir", nargs="?")
    ap.add_argument("--package")
    ap.add_argument("--metadata")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.sbom_dir or not a.package:
        ap.print_usage(sys.stderr)
        return 2
    try:
        meta = json.loads(Path(a.metadata).read_text()) if a.metadata else cargo_metadata()
        programs = package_programs(Path(a.package))
        if not programs:
            raise ValueError(f"{a.package}: no robodr-* programs")
        kept, removed = select(Path(a.sbom_dir), meta, programs)
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as e:
        print(f"sbom-select: FAIL: {e}", file=sys.stderr)
        return 1
    for f in removed:
        print(f"sbom-select: - {f.name} (not shipped by {Path(a.package).name})", file=sys.stderr)
    print(f"sbom-select: {len(kept)} SBOM(s) kept for {Path(a.package).name}, {len(removed)} removed", file=sys.stderr)
    return 0


# The release jobs and the rebuild must select the same SBOM set (bundle
# members are compared): every scripts/sbom.sh call is followed by this
# script before the SBOMs are used.
WORKFLOW_FILES = (".github/workflows/release.yml", "scripts/ci-rebuild.sh")


def workflow_problems(text: str, label: str) -> list[str]:
    errs = []
    if re.search(r"rm -f [^\n]*\.cdx\.json", text):
        errs.append(f"{label}: removes SBOMs by hand (use scripts/sbom-select.py)")
    for m in re.finditer(r"scripts/sbom\.sh\b", text):
        rest = text[m.end():]
        use = re.search(r"release-sbom-augment\.sh|make-bundle\.sh[^\n]*--sbom-dir", rest)
        sel = re.search(r"scripts/sbom-select\.py", rest)
        if use and (not sel or sel.start() > use.start()):
            errs.append(f"{label}: scripts/sbom.sh at offset {m.start()} is used without scripts/sbom-select.py first")
    return errs


def self_test() -> int:
    import tempfile
    import unittest

    def meta() -> dict:
        def pkg(name, bins=(), deps=(), lib=True):
            t = [{"name": b, "kind": ["bin"]} for b in bins] + ([{"name": name, "kind": ["lib"]}] if lib else [])
            return {"id": f"{name} 0.1.0", "name": name, "targets": t,
                    "dependencies": [{"name": d, "kind": k} for d, k in deps]}

        pk = [
            pkg("robodr-agentd", ["robodr-agentd"], [("robodr-ocsf", None), ("robodr-buildinfo", "build"),
                                                     ("robodr-testkit", "dev")]),
            pkg("robodr-ocsf"),
            pkg("robodr-buildinfo"),
            pkg("robodr-testkit"),
            pkg("robodr-pulsard", ["robodr-pulsard"], [("robodr-ocsf", None)], lib=False),
            pkg("robodr-ops", ["robodr-setup", "robodr-metrics"]),
            pkg("robodr-attack-sim", ["robodr-attack-sim"]),
            pkg("serde"),
        ]
        return {"packages": pk, "workspace_members": [p["id"] for p in pk if p["name"] != "serde"]}

    def write_dir(d: Path, roots) -> None:
        for r in roots:
            (d / f"crates_{r}_{r}.cdx.json").write_text(json.dumps({"metadata": {"component": {"name": r}}}))
        (d / "SHA256SUMS").write_text("".join(f"x  crates_{r}_{r}.cdx.json\n" for r in roots))

    ALL = ["robodr-agentd", "robodr-ocsf", "robodr-buildinfo", "robodr-testkit", "robodr-pulsard",
           "robodr-ops", "robodr-attack-sim"]

    class T(unittest.TestCase):
        def run_select(self, programs, roots=ALL):
            with tempfile.TemporaryDirectory() as d:
                write_dir(Path(d), roots)
                kept, removed = select(Path(d), meta(), set(programs))
                left = sorted(p.name for p in Path(d).glob("*.cdx.json"))
                sums = Path(d, "SHA256SUMS").read_text()
                return sorted(root_name(k) for k in kept), left, sums

        def test_focal_drops_pulsard_and_unshipped(self):
            kept, left, sums = self.run_select({"robodr-agentd", "robodr-setup"})
            self.assertEqual(kept, ["robodr-agentd", "robodr-buildinfo", "robodr-ocsf", "robodr-ops"])
            self.assertEqual(len(left), 4)
            self.assertNotIn("pulsard", sums)
            self.assertNotIn("testkit", sums)  # dev-dependency only
            self.assertEqual(len(sums.splitlines()), 4)

        def test_standard_keeps_pulsard(self):
            kept, _, _ = self.run_select({"robodr-agentd", "robodr-pulsard", "robodr-metrics"})
            self.assertIn("robodr-pulsard", kept)
            self.assertNotIn("robodr-attack-sim", kept)

        def test_same_input_same_selection(self):
            # The release job and the rebuild select the same members.
            a = self.run_select({"robodr-agentd"})
            b = self.run_select({"robodr-agentd"})
            self.assertEqual(a[1], b[1])

        def test_refusals(self):
            with self.assertRaises(ValueError):  # program from nowhere
                self.run_select({"robodr-unknown"})
            with self.assertRaises(ValueError):  # shipped crate without an SBOM
                self.run_select({"robodr-pulsard"}, roots=["robodr-ocsf"])
            with tempfile.TemporaryDirectory() as d:  # non-workspace root; nothing removed
                write_dir(Path(d), ["robodr-attack-sim", "serde"])
                with self.assertRaises(ValueError):
                    select(Path(d), meta(), {"robodr-agentd"})
                self.assertEqual(len(list(Path(d).glob("*.cdx.json"))), 2)

        def test_workflow_guard(self):
            good = "scripts/sbom.sh dist/sbom\nscripts/sbom-select.py dist/sbom --package x\n" \
                   "scripts/release-sbom-augment.sh dist/sbom\n"
            self.assertEqual(workflow_problems(good, "t"), [])
            bad = "scripts/sbom.sh dist/sbom\nrm -f dist/sbom/*robodr-pulsard*.cdx.json\n" \
                  "packaging/make-bundle.sh --deb x --sbom-dir dist/sbom\n"
            self.assertEqual(len(workflow_problems(bad, "t")), 2)

        def test_repository_workflows(self):
            root = Path(__file__).resolve().parent.parent
            for rel in WORKFLOW_FILES:
                text = (root / rel).read_text()
                self.assertIn("scripts/sbom.sh", text, rel)
                self.assertEqual(workflow_problems(text, rel), [])

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
    print("sbom-select self-test:", "ok" if r.wasSuccessful() else "FAIL")
    return 0 if r.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
