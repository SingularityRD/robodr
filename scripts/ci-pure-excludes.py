#!/usr/bin/env python3
"""Print `--exclude <pkg>` arguments for Pulsar-bound workspace members.

CI runs fmt/clippy/test over the *pure* crates with

    cargo test --workspace $(python3 scripts/ci-pure-excludes.py)

A member is Pulsar-bound if it is named in PULSAR_BOUND, depends directly on
one of PULSAR_DEPS, or depends (transitively) on another Pulsar-bound member.
Only members that actually exist in the workspace are emitted: older cargo
versions reject `--exclude` of an unknown package, and newer ones warn, so we
never pass a name that is not there (e.g. `robodr-pulsard` before it lands).

Input: `cargo metadata --no-deps --format-version 1` JSON, read from a file
argument, from stdin (`-`), or by running cargo (default). Std-lib only.

Self-test: `python3 scripts/ci-pure-excludes.py --self-test`.
"""

from __future__ import annotations

import json
import subprocess
import sys

# Members that must be built against Pulsar even if their manifest changes.
PULSAR_BOUND = {"robodr-sensor-ros2", "robodr-pulsard"}
# Any member depending on one of these needs the Pulsar/eBPF build toolchain.
PULSAR_DEPS = {"pulsar-core", "bpf-common", "bpf-builder"}


def pulsar_bound_members(metadata: dict) -> list[str]:
    """Return the sorted names of workspace members that need Pulsar."""
    member_ids = set(metadata.get("workspace_members", []))
    pkgs = [p for p in metadata.get("packages", []) if p.get("id") in member_ids]
    names = {p["name"] for p in pkgs}
    deps = {p["name"]: {d["name"] for d in p.get("dependencies", [])} for p in pkgs}

    bound = {n for n in names if n in PULSAR_BOUND or deps[n] & PULSAR_DEPS}
    changed = True
    while changed:  # propagate through member -> member dependencies
        changed = False
        for n in names - bound:
            if deps[n] & bound:
                bound.add(n)
                changed = True
    return sorted(bound)


def exclude_args(metadata: dict) -> list[str]:
    out: list[str] = []
    for name in pulsar_bound_members(metadata):
        out += ["--exclude", name]
    return out


def _load(argv: list[str]) -> dict:
    if argv and argv[0] != "-":
        with open(argv[0], encoding="utf-8") as f:
            return json.load(f)
    if argv and argv[0] == "-":
        return json.load(sys.stdin)
    raw = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return json.loads(raw)


def _self_test() -> int:
    import unittest

    def pkg(name, *deps):
        return {
            "id": f"path+file:///w/{name}#0.1.0",
            "name": name,
            "dependencies": [{"name": d} for d in deps],
        }

    def meta(*pkgs):
        return {"packages": list(pkgs), "workspace_members": [p["id"] for p in pkgs]}

    class T(unittest.TestCase):
        def test_named_and_dep_based(self):
            m = meta(
                pkg("robodr-events", "serde"),
                pkg("robodr-sensor-ros2", "robodr-events"),
                pkg("robodr-other", "pulsar-core"),
            )
            self.assertEqual(
                exclude_args(m),
                ["--exclude", "robodr-other", "--exclude", "robodr-sensor-ros2"],
            )

        def test_nonexistent_named_member_is_not_emitted(self):
            m = meta(pkg("robodr-events"))
            self.assertEqual(exclude_args(m), [])  # no robodr-pulsard here

        def test_transitive_member(self):
            m = meta(
                pkg("robodr-pulsard", "pulsar-core"),
                pkg("robodr-cli", "robodr-pulsard"),
                pkg("robodr-pure", "robodr-events"),
                pkg("robodr-events"),
            )
            self.assertEqual(pulsar_bound_members(m), ["robodr-cli", "robodr-pulsard"])

        def test_non_members_ignored(self):
            m = meta(pkg("robodr-events"))
            m["packages"].append(pkg("pulsar-core", "tokio"))  # not a member
            self.assertEqual(exclude_args(m), [])

        def test_empty(self):
            self.assertEqual(exclude_args({}), [])

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
    return 0 if r.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return _self_test()
    print(" ".join(exclude_args(_load(argv))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
