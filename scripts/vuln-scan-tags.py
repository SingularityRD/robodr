#!/usr/bin/env python3
"""Which release tags .github/workflows/vuln-scan.yml scans.

    git tag -l 'v[0-9]*' | vuln-scan-tags.py
        Prints a JSON list (sorted) of, for every release line vX.Y:
          * the newest FINAL release (vX.Y.Z, no pre-release suffix), and
          * the newest pre-release (vX.Y.Z-pre) when it is newer than that
            final release (or the line has no final release yet).
        "Newest" is semantic-version precedence (semver.org section 11):
        v0.2.0 is newer than v0.2.0-rc.1, and rc.10 newer than rc.9.
        `sort -V` gets the first wrong (it puts v0.2.0-rc.1 after v0.2.0),
        which would scan a release candidate instead of the shipped final
        release. Tags that are not vX.Y.Z[-pre] are ignored.

    vuln-scan-tags.py --self-test
"""

from __future__ import annotations

import json
import re
import sys

TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?$")


def _pre_key(pre: str) -> tuple:
    # Numeric identifiers sort numerically and below alphanumeric ones;
    # a longer list wins when all earlier identifiers are equal.
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))


def precedence(m: re.Match) -> tuple:
    core = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    pre = m.group(4)
    # A final release ranks above every pre-release of the same core.
    return core + ((1, ()) if pre is None else (0, _pre_key(pre)))


def pick(tags: list[str]) -> list[str]:
    final: dict[tuple[str, str], tuple[tuple, str]] = {}
    prerel: dict[tuple[str, str], tuple[tuple, str]] = {}
    for t in tags:
        m = TAG.match(t)
        if not m:
            continue
        line = (m.group(1), m.group(2))
        key = precedence(m)
        best = final if m.group(4) is None else prerel
        if line not in best or key > best[line][0]:
            best[line] = (key, t)
    out = {t for _, t in final.values()}
    for line, (key, t) in prerel.items():
        if line not in final or key > final[line][0]:
            out.add(t)
    return sorted(out)


def self_test() -> int:
    import unittest

    class Pick(unittest.TestCase):
        def test_final_beats_its_rc(self):
            # The order `sort -V` produces must not matter.
            self.assertEqual(pick(["v0.2.0", "v0.2.0-rc.1"]), ["v0.2.0"])
            self.assertEqual(pick(["v0.2.0-rc.1", "v0.2.0"]), ["v0.2.0"])

        def test_newer_prerelease_scanned_too(self):
            self.assertEqual(pick(["v0.2.0", "v0.2.1-rc.1"]), ["v0.2.0", "v0.2.1-rc.1"])

        def test_prerelease_only_line(self):
            self.assertEqual(
                pick(["v0.1.0-alpha.2", "v0.1.0-alpha.10", "v0.1.0-alpha.9"]), ["v0.1.0-alpha.10"]
            )
            self.assertEqual(pick(["v0.1.0-alpha.1", "v0.1.0-beta"]), ["v0.1.0-beta"])
            self.assertEqual(pick(["v0.1.0-rc", "v0.1.0-rc.1"]), ["v0.1.0-rc.1"])

        def test_numeric_patch_and_lines(self):
            self.assertEqual(
                pick(["v0.1.9", "v0.1.10", "v0.2.0", "v1.0.0", "v0.1.2"]),
                ["v0.1.10", "v0.2.0", "v1.0.0"],
            )

        def test_ignored(self):
            self.assertEqual(pick(["v1", "v1.2", "vx.1.2", "v01.2.3", "v1.2.3+meta", "1.2.3"]), [])

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(Pick))
    return 0 if r.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    print(json.dumps(pick(sys.stdin.read().split())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
