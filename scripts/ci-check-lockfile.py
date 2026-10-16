#!/usr/bin/env python3
"""Fail if Cargo.lock was generated against patched/local copies of registry crates.

The committed Cargo.lock must come from a machine that resolved against
crates.io or the internal mirror (docs/BUILD.md, "Cargo.lock policy"). A lock
generated in a sandbox with `[patch.crates-io] serde = { path = ... }` records
`serde` with no `source` and no `checksum`, which silently pins a local tree;
committing it would break reproducibility and the SBOM. This check rejects:

  * a package with no `source` whose (name, version) is not a local crate of
    this repo. "Local" is derived the way cargo derives path packages: the
    root workspace's members, plus every crate reachable from them through
    `path` dependencies (including `{ workspace = true }` entries resolved in
    [workspace.dependencies]), plus the members of any workspace reached that
    way (vendor/pulsar). `version.workspace = true` is resolved against the
    owning workspace's [workspace.package]. A Cargo.toml that merely EXISTS
    somewhere in the tree (e.g. a vendored serde under third_party/) does NOT
    make its name local, and the version must match too: the review PoC
    `serde 9.9.9` with no source is rejected (it was accepted before because
    any crate name found anywhere counted as local).
  * any `path+...` source, and any source not in the allow-list
    (crates.io index by default; `--allow-source` adds the internal mirror);
  * `git+...` sources unless `--allow-git` is given (deny.toml also bans them);
  * a registry package without a `checksum`.

Usage: ci-check-lockfile.py [Cargo.lock] [--root DIR] [--allow-source URL]...
       ci-check-lockfile.py --self-test
Std-lib only (needs Python >= 3.11 for tomllib).
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
import tomllib

CRATES_IO = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _load(manifest: str) -> dict | None:
    try:
        with open(manifest, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return None


def _ws_root(pkg_dir: str, doc: dict) -> str | None:
    """Directory of the workspace that owns the package in `pkg_dir`."""
    explicit = doc.get("package", {}).get("workspace")
    if isinstance(explicit, str):
        return os.path.normpath(os.path.join(pkg_dir, explicit))
    d = pkg_dir
    while True:
        wdoc = _load(os.path.join(d, "Cargo.toml"))
        if wdoc is not None and isinstance(wdoc.get("workspace"), dict):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def _pkg_version(pkg_dir: str, doc: dict) -> str | None:
    v = doc["package"].get("version", "0.0.0")  # cargo >= 1.75: optional, default 0.0.0
    if isinstance(v, str):
        return v
    if isinstance(v, dict) and v.get("workspace") is True:
        root = _ws_root(pkg_dir, doc)
        wdoc = _load(os.path.join(root, "Cargo.toml")) if root else None
        wv = (wdoc or {}).get("workspace", {}).get("package", {}).get("version")
        return wv if isinstance(wv, str) else None
    return None


def _dep_tables(doc: dict):
    for t in DEP_TABLES:
        if isinstance(doc.get(t), dict):
            yield doc[t]
    targets = doc.get("target")
    if isinstance(targets, dict):
        for tdoc in targets.values():
            if isinstance(tdoc, dict):
                for t in DEP_TABLES:
                    if isinstance(tdoc.get(t), dict):
                        yield tdoc[t]


def _members(ws_dir: str, ws: dict) -> list[str]:
    excl = {os.path.normpath(os.path.join(ws_dir, e)) for e in ws.get("exclude", []) if isinstance(e, str)}
    out = []
    for m in ws.get("members", []):
        if not isinstance(m, str):
            continue
        for d in sorted(glob.glob(os.path.join(ws_dir, m))) if any(c in m for c in "*?[") else [os.path.join(ws_dir, m)]:
            d = os.path.normpath(d)
            if d not in excl and os.path.isfile(os.path.join(d, "Cargo.toml")):
                out.append(d)
    return out


def local_crates(root: str) -> set[tuple[str, str]]:
    """(name, version) of every path package cargo would see from `root`.

    Slight superset by design: when a path crate belongs to another workspace
    (pulsar-core in vendor/pulsar), all members of that workspace count.

    Never follows [patch] / [replace]: a lock that resolves a registry crate
    through a patch to a local path is exactly what must be rejected.
    """
    found: set[tuple[str, str]] = set()
    seen: set[str] = set()
    todo = [os.path.normpath(os.path.abspath(root))]
    while todo:
        d = todo.pop()
        if d in seen:
            continue
        seen.add(d)
        doc = _load(os.path.join(d, "Cargo.toml"))
        if doc is None:
            continue
        ws = doc.get("workspace")
        if isinstance(ws, dict):
            todo.extend(_members(d, ws))
            wdeps = ws.get("dependencies", {})
            if isinstance(wdeps, dict):
                for spec in wdeps.values():
                    if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                        todo.append(os.path.normpath(os.path.join(d, spec["path"])))
        pkg = doc.get("package")
        if not isinstance(pkg, dict):
            continue
        name, version = pkg.get("name"), _pkg_version(d, doc)
        if isinstance(name, str) and version is not None:
            found.add((name, version))
        ws_dir = _ws_root(d, doc)
        if ws_dir:
            todo.append(ws_dir)  # its members are path crates too (vendor/pulsar)
        for table in _dep_tables(doc):
            for dep, spec in table.items():
                if not isinstance(spec, dict):
                    continue
                if isinstance(spec.get("path"), str):
                    todo.append(os.path.normpath(os.path.join(d, spec["path"])))
                elif spec.get("workspace") is True:
                    wdoc = _load(os.path.join(ws_dir, "Cargo.toml")) if ws_dir else None
                    wspec = (wdoc or {}).get("workspace", {}).get("dependencies", {}).get(dep)
                    if isinstance(wspec, dict) and isinstance(wspec.get("path"), str):
                        todo.append(os.path.normpath(os.path.join(ws_dir, wspec["path"])))
    return found


def check_lock(
    lock: dict,
    local: set[tuple[str, str]],
    allowed_sources: set[str],
    allow_git: bool = False,
) -> list[str]:
    errors: list[str] = []
    pkgs = lock.get("package", [])
    if not isinstance(pkgs, list):
        return ["Cargo.lock has no [[package]] array"]
    for p in pkgs:
        name = p.get("name", "?")
        ver = p.get("version", "?")
        src = p.get("source")
        who = f"{name} {ver}"
        if src is None:
            if (name, ver) not in local:
                known = sorted(v for n, v in local if n == name)
                hint = f" (local {name} is {', '.join(known)})" if known else ""
                errors.append(
                    f"{who}: no source but not a local workspace/path crate{hint} "
                    "(lock generated with [patch] to a local path?)"
                )
            continue
        if src.startswith("path+"):
            errors.append(f"{who}: path source {src!r}")
        elif src.startswith("git+"):
            if not allow_git:
                errors.append(f"{who}: git source {src!r} (not allowed)")
        elif src not in allowed_sources:
            errors.append(f"{who}: source {src!r} not in allow-list")
        elif not p.get("checksum"):
            errors.append(f"{who}: registry package without checksum")
    return errors


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("lockfile", nargs="?", default="Cargo.lock")
    ap.add_argument("--root", default=".", help="repo root (its Cargo.toml is the workspace root)")
    ap.add_argument("--allow-source", action="append", default=[])
    ap.add_argument("--allow-git", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    try:
        with open(a.lockfile, "rb") as f:
            lock = tomllib.load(f)
    except FileNotFoundError:
        print(f"error: {a.lockfile} not found", file=sys.stderr)
        return 2
    except tomllib.TOMLDecodeError as e:
        print(f"error: {a.lockfile} is not valid TOML: {e}", file=sys.stderr)
        return 1
    if _load(os.path.join(a.root, "Cargo.toml")) is None:
        print(f"error: {a.root}/Cargo.toml missing or invalid; cannot derive local crates", file=sys.stderr)
        return 2
    errors = check_lock(lock, local_crates(a.root), CRATES_IO | set(a.allow_source), a.allow_git)
    for e in errors:
        print(f"Cargo.lock: {e}", file=sys.stderr)
    if errors:
        print(
            f"{len(errors)} problem(s): regenerate Cargo.lock against crates.io or "
            "the internal mirror (docs/BUILD.md, 'Cargo.lock policy').",
            file=sys.stderr,
        )
        return 1
    print(f"Cargo.lock OK ({len(lock.get('package', []))} packages)")
    return 0


def _self_test() -> int:
    import tempfile
    import unittest

    CIO = "registry+https://github.com/rust-lang/crates.io-index"
    good = f"""
version = 4
[[package]]
name = "robodr-events"
version = "0.1.0"
dependencies = ["serde"]
[[package]]
name = "serde"
version = "1.0.219"
source = "{CIO}"
checksum = "5f0e2c6ed6606019b4e29e69dbaba95b11854410e5347d525002456dbbb786b6"
"""
    patched = """
version = 4
[[package]]
name = "robodr-events"
version = "0.1.0"
[[package]]
name = "serde"
version = "1.0.219"
"""

    class T(unittest.TestCase):
        local = {("robodr-events", "0.1.0")}

        def run_check(self, text, **kw):
            return check_lock(tomllib.loads(text), self.local, CRATES_IO, **kw)

        def test_good(self):
            self.assertEqual(self.run_check(good), [])

        def test_patched_local_registry_crate(self):
            errs = self.run_check(patched)
            self.assertEqual(len(errs), 1)
            self.assertIn("serde", errs[0])

        def test_path_source(self):
            t = good.replace(CIO, "path+file:///home/x/serde")
            self.assertTrue(any("path source" in e for e in self.run_check(t)))

        def test_git_source(self):
            t = good.replace(CIO, "git+https://example.com/serde?rev=abc#abc")
            self.assertTrue(self.run_check(t))
            self.assertEqual(self.run_check(t, allow_git=True), [])

        def test_unknown_registry(self):
            t = good.replace(CIO, "registry+https://evil.example/index")
            self.assertTrue(any("allow-list" in e for e in self.run_check(t)))

        def test_internal_mirror_allowed_when_listed(self):
            m = "sparse+https://crates.mirror.internal/index/"
            t = tomllib.loads(good.replace(CIO, m))
            self.assertTrue(check_lock(t, self.local, CRATES_IO))
            self.assertEqual(check_lock(t, self.local, CRATES_IO | {m}), [])

        def test_missing_checksum(self):
            t = "\n".join(l for l in good.splitlines() if "checksum" not in l)
            self.assertTrue(any("checksum" in e for e in self.run_check(t)))

        def test_garbage_shape(self):
            self.assertTrue(check_lock({"package": "x"}, set(), CRATES_IO))
            self.assertEqual(check_lock({}, set(), CRATES_IO), [])

        @staticmethod
        def _write(d, rel, text):
            path = os.path.join(d, rel, "Cargo.toml")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(text)

        def _repo(self, d):
            """Mini repo shaped like RoboDR: workspace + vendored Pulsar + a cargo-vendor dir."""
            w = self._write
            w(d, ".", '[workspace]\nmembers = ["crates/*"]\nexclude = ["vendor"]\n'
                      '[workspace.package]\nversion = "0.1.0"\n'
                      '[workspace.dependencies]\nrobodr-events = { path = "crates/robodr-events" }\n'
                      'pulsar-core = { path = "vendor/pulsar/crates/pulsar-core" }\n'
                      'serde = "1"\n')
            w(d, "crates/robodr-events", '[package]\nname = "robodr-events"\nversion.workspace = true\n'
                                         '[dependencies]\nserde = { workspace = true }\n')
            w(d, "crates/robodr-sensor", '[package]\nname = "robodr-sensor"\nversion = "0.2.0"\n'
                                         '[dependencies]\npulsar-core = { workspace = true }\n'
                                         '[target.\'cfg(unix)\'.dev-dependencies]\n'
                                         'helper = { path = "../../tools/helper" }\n')
            w(d, "tools/helper", '[package]\nname = "helper"\n')  # no version -> 0.0.0
            w(d, "vendor/pulsar", '[package]\nname = "pulsar"\nversion.workspace = true\n'
                                  '[workspace]\nmembers = ["crates/pulsar-core", "crates/modules/*"]\n'
                                  '[workspace.package]\nversion = "0.11.0-alpha.1"\n'
                                  '[workspace.dependencies]\nvalidatron = { path = "crates/validatron" }\n')
            w(d, "vendor/pulsar/crates/pulsar-core", '[package]\nname = "pulsar-core"\nversion.workspace = true\n'
                                                     '[dependencies]\nvalidatron = { workspace = true }\n')
            w(d, "vendor/pulsar/crates/validatron", '[package]\nname = "validatron"\nversion.workspace = true\n')
            w(d, "vendor/pulsar/crates/modules/rules-engine", '[package]\nname = "rules-engine"\nversion.workspace = true\n')
            # Things that must NOT count as local:
            w(d, "third_party/cargo-vendor/serde-1.0.219", '[package]\nname = "serde"\nversion = "1.0.219"\n')
            w(d, "target/debug/build/x", '[package]\nname = "x"\nversion = "1.0.0"\n')
            w(d, "crates/robodr-events/fixtures/bad", "[package\n")  # malformed, unreachable: ignored

        def test_local_crates_from_workspace_graph(self):
            with tempfile.TemporaryDirectory() as d:
                self._repo(d)
                self.assertEqual(local_crates(d), {
                    ("robodr-events", "0.1.0"), ("robodr-sensor", "0.2.0"), ("helper", "0.0.0"),
                    ("pulsar", "0.11.0-alpha.1"), ("pulsar-core", "0.11.0-alpha.1"),
                    ("validatron", "0.11.0-alpha.1"), ("rules-engine", "0.11.0-alpha.1"),
                })

        def test_review_poc_vendored_name_with_fake_version(self):
            # lockpoc/Cargo.lock: robodr-events + source-less `serde 9.9.9`. With a
            # vendored serde manifest in the tree the old name-only check passed it.
            poc = ('version = 4\n[[package]]\nname = "robodr-events"\nversion = "0.1.0"\n'
                   'dependencies = ["serde"]\n[[package]]\nname = "serde"\nversion = "9.9.9"\n')
            with tempfile.TemporaryDirectory() as d:
                self._repo(d)
                errs = check_lock(tomllib.loads(poc), local_crates(d), CRATES_IO)
                self.assertEqual(len(errs), 1, errs)
                self.assertIn("serde 9.9.9", errs[0])
                # Same name AND the vendored version: still not a workspace/path crate.
                errs = check_lock(tomllib.loads(poc.replace("9.9.9", "1.0.219")), local_crates(d), CRATES_IO)
                self.assertEqual(len(errs), 1, errs)

        def test_local_name_wrong_version(self):
            with tempfile.TemporaryDirectory() as d:
                self._repo(d)
                lock = 'version = 4\n[[package]]\nname = "pulsar-core"\nversion = "0.11.0"\n'
                errs = check_lock(tomllib.loads(lock), local_crates(d), CRATES_IO)
                self.assertEqual(len(errs), 1)
                self.assertIn("local pulsar-core is 0.11.0-alpha.1", errs[0])

        def test_patch_is_not_followed(self):
            with tempfile.TemporaryDirectory() as d:
                self._repo(d)
                with open(os.path.join(d, "Cargo.toml"), "a") as f:
                    f.write('[patch.crates-io]\nserde = { path = "third_party/cargo-vendor/serde-1.0.219" }\n')
                self.assertNotIn(("serde", "1.0.219"), local_crates(d))

        def test_cli_requires_root_manifest(self):
            with tempfile.TemporaryDirectory() as d:
                lock = os.path.join(d, "Cargo.lock")
                with open(lock, "w") as f:
                    f.write(good)
                self.assertEqual(main([lock, "--root", d]), 2)

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
    return 0 if r.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
