#!/usr/bin/env python3
"""Fail when a test log shows that a privileged test did not really run.

The root / TPM / network-namespace / live-capture tests of RoboDR pass
silently when their environment is missing: they print a line such as

    SKIPPED: needs root, ip and nft in a network namespace (...)
    skipped: set ROBODR_SWTPM=1 (needs swtpm and tpm2-tools)

and return. In the privileged CI job (`.github/workflows/ci-extended.yml`,
`scripts/ci-privileged-tests.sh`) every such line is a failure: the job
exists to run them. The test binaries must be run with `--nocapture`, or
libtest swallows the output of passing tests and nothing can be checked.

Checks, per log file:

* no line contains the word "skipped" (any case), except lines matching an
  `--allow REGEX` (for a skip the job cannot avoid, named with its reason);
* every `running N tests` header has N > 0 and the log has at least one
  (a test filter that matched nothing, or a binary that was not run, is not
  a pass);
* every `test result:` line says `ok` and the log has at least one;
* `--ignored-run`: the binary was run with `--ignored`, so its
  `test result:` must report 0 ignored (a test that is still ignored was
  not run).

Usage:

    ci-no-skips.py [--allow REGEX]... [--ignored-run] LOG...
    ci-no-skips.py --self-test

Exit status 0 when every log passes, 1 otherwise (each problem printed as a
GitHub `::error::` annotation). Std-lib only.
"""

from __future__ import annotations

import argparse
import re
import sys

SKIP = re.compile(r"\bskipped\b", re.IGNORECASE)
RUNNING = re.compile(r"^running (\d+) tests?$")
RESULT = re.compile(
    r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out"
)


def check(text: str, name: str, allow: list[re.Pattern[str]], ignored_run: bool) -> list[str]:
    """Return the problems found in one log (empty: it passes)."""
    problems: list[str] = []
    runs = 0
    results = 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r")
        if SKIP.search(line) and not any(a.search(line) for a in allow):
            problems.append(f"{name}:{n}: a test skipped itself: {line.strip()[:300]}")
        m = RUNNING.match(line.strip())
        if m:
            runs += 1
            if int(m.group(1)) == 0:
                problems.append(f"{name}:{n}: no test ran ('{line.strip()}')")
        m = RESULT.match(line.strip())
        if m:
            results += 1
            status, _passed, failed, ignored = m.group(1), m.group(2), m.group(3), m.group(4)
            if status != "ok" or failed != "0":
                problems.append(f"{name}:{n}: {line.strip()}")
            if ignored_run and ignored != "0":
                problems.append(f"{name}:{n}: {ignored} test(s) still ignored with --ignored")
    if runs == 0:
        problems.append(f"{name}: no 'running N tests' line: the test binary did not run")
    if results == 0:
        problems.append(f"{name}: no 'test result:' line: the test binary did not finish")
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--allow", action="append", default=[], metavar="REGEX")
    ap.add_argument("--ignored-run", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("logs", nargs="*")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.logs:
        ap.error("no log given")
    allow = [re.compile(a) for a in args.allow]
    bad = 0
    for path in args.logs:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        for p in check(text, path, allow, args.ignored_run):
            print(f"::error::{p}")
            bad += 1
    if bad:
        print(f"ci-no-skips: {bad} problem(s)", file=sys.stderr)
        return 1
    print(f"ci-no-skips: {len(args.logs)} log(s) clean")
    return 0


def self_test() -> int:
    ok_log = """
running 3 tests
test a ... ok
test b ... ok
test c ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
"""
    assert check(ok_log, "ok", [], False) == []
    assert check(ok_log, "ok", [], True) == []

    netns_skip = ok_log.replace(
        "test a ... ok",
        "SKIPPED: needs root, ip and nft in a network namespace (EPERM)\ntest a ... ok",
    )
    p = check(netns_skip, "netns", [], False)
    assert len(p) == 1 and "skipped itself" in p[0], p

    swtpm_skip = ok_log.replace("test b ... ok", "skipped: set ROBODR_SWTPM=1 (needs swtpm)\ntest b ... ok")
    assert len(check(swtpm_skip, "tpm", [], False)) == 1
    # An allowed skip (named reason) passes; others still fail.
    allow = [re.compile(r"the temp dir is tmpfs here")]
    tmpfs = ok_log.replace("test c ... ok", "skipped: the temp dir is tmpfs here\ntest c ... ok")
    assert check(tmpfs, "tmpfs", allow, False) == []
    assert len(check(swtpm_skip, "tpm", allow, False)) == 1

    nothing = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s\n"
    assert any("no test ran" in x for x in check(nothing, "empty", [], False))
    assert len(check("", "missing", [], False)) == 2

    failed = ok_log.replace("test result: ok. 3 passed; 0 failed", "test result: FAILED. 2 passed; 1 failed")
    assert len(check(failed, "failed", [], False)) == 1

    still_ignored = ok_log.replace("0 ignored", "2 ignored")
    assert check(still_ignored, "ign", [], False) == []
    assert len(check(still_ignored, "ign", [], True)) == 1

    # CRLF logs and indented lines are handled.
    assert check(ok_log.replace("\n", "\r\n"), "crlf", [], False) == []
    print("ci-no-skips: self-test ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
