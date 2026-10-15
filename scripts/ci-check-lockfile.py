#!/usr/bin/env python3
"""Fail if Cargo.lock was generated against patched/local copies of registry crates.

The committed Cargo.lock must come from a machine that resolved against
crates.io or the internal mirror (docs/BUILD.md, "Cargo.lock policy"). A lock
generated in a sandbox with `[patch.crates-io] serde = { path = ... }` records
`serde` with no `source` and no `checksum`, which silently pins a local tree;
committing it would break reproducibility and the SBOM. This check rejects:

  * a package with no `source` whose name is not a local crate of this repo
    (workspace members, vendor/pulsar crates, fuzz/ ...);
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
import os
import sys
import tomllib

CRATES_IO = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}
SKIP_DIRS = {"target", ".git", "node_modules"}


def local_crate_names(root: str) -> set[str]:
    """Names of every [package] defined by a Cargo.toml under `root`."""
    names: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "Cargo.toml" not in filenames:
            continue
        try:
            with open(os.path.join(dirpath, "Cargo.toml"), "rb") as f:
                doc = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError):
            continue
        name = doc.get("package", {}).get("name")
        if isinstance(name, str):
            names.add(name)
    return names


def check_lock(
    lock: dict,
    local: set[str],
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
            if name not in local:
                errors.append(
                    f"{who}: no source but not a local crate (lock generated with [patch] to a local path?)"
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
    ap.add_argument("--root", default=".", help="repo root to scan for local crates")
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
    errors = check_lock(lock, local_crate_names(a.root), CRATES_IO | set(a.allow_source), a.allow_git)
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
        local = {"robodr-events"}

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

        def test_local_crate_scan(self):
            with tempfile.TemporaryDirectory() as d:
                os.makedirs(os.path.join(d, "crates", "a"))
                os.makedirs(os.path.join(d, "target", "b"))
                with open(os.path.join(d, "crates", "a", "Cargo.toml"), "w") as f:
                    f.write('[package]\nname = "robodr-a"\n')
                with open(os.path.join(d, "target", "b", "Cargo.toml"), "w") as f:
                    f.write('[package]\nname = "ignored"\n')
                with open(os.path.join(d, "Cargo.toml"), "w") as f:
                    f.write("[workspace\n")  # malformed: skipped, no crash
                self.assertEqual(local_crate_names(d), {"robodr-a"})

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
    return 0 if r.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
