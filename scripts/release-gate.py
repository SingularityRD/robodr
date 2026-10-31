#!/usr/bin/env python3
"""Release gates of .github/workflows/release.yml (run before anything is
built, and again right before anything is signed).

    release-gate.py line --commit SHA --version V [--git-dir DIR]
        Which release line the tagged commit belongs to. Accepted:
          * on origin/main (an ancestor of refs/remotes/origin/main):
            line=main, latest=true;
          * otherwise on origin/release/X.Y, where X.Y is the version's
            major.minor (a long-term-support branch; protect it like main):
            line=release/X.Y, latest=false (an older line never becomes the
            repository's "Latest" release).
        Anything else is refused. Prints `line=...` and `latest=...` (append
        to $GITHUB_OUTPUT).

    release-gate.py ci --commit SHA --repo OWNER/REPO [--workflow ci.yml]
                       [--wait-minutes N] [--poll-seconds S] [--runs-json FILE]
        The CI workflow (.github/workflows/ci.yml) must have a COMPLETED,
        SUCCESSFUL run for exactly this commit, started by `push`,
        `workflow_dispatch` or `schedule` (those check out the commit itself;
        a `pull_request` run tests a merge commit, so it does not count).
        Queued / running runs are waited for (polling `gh api`) up to
        --wait-minutes (default 0: no waiting); no qualifying run, or only
        failed / cancelled ones, is refused. --runs-json evaluates a saved
        API response instead of calling gh (tests).

    release-gate.py --self-test

Exit: 0 accepted, 1 refused, 2 usage / API error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time

SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
GOOD_EVENTS = {"push", "workflow_dispatch", "schedule"}


class Refused(Exception):
    pass


def git(git_dir: str | None, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["git"] + (["-C", git_dir] if git_dir else []) + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def release_line(commit: str, version: str, git_dir: str | None = None) -> tuple[str, bool]:
    m = SEMVER.match(version)
    if not m:
        raise Refused(f"version {version!r} is not semantic (X.Y.Z[-pre])")
    full = git(git_dir, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}", check=False).stdout.strip()
    if not full:
        raise Refused(f"{commit} is not a commit")

    def on(ref: str) -> bool | None:
        if git(git_dir, "rev-parse", "--verify", "--quiet", ref, check=False).returncode != 0:
            return None
        return git(git_dir, "merge-base", "--is-ancestor", full, ref, check=False).returncode == 0

    main = on("refs/remotes/origin/main")
    if main is None:
        raise Refused("origin/main not fetched (checkout with fetch-depth: 0)")
    if main:
        return "main", True
    branch = f"release/{m.group(1)}.{m.group(2)}"
    if on(f"refs/remotes/origin/{branch}"):
        return branch, False
    raise Refused(
        f"commit {full} is neither on main nor on {branch}: only reviewed, merged commits "
        f"of main or of the version's long-term-support branch are released"
    )


def evaluate_runs(runs: list[dict], commit: str) -> tuple[str, str]:
    """('pass'|'wait'|'fail', explanation) for the CI runs of one commit."""
    mine = [r for r in runs if isinstance(r, dict) and r.get("head_sha") == commit]
    counted = [r for r in mine if r.get("event") in GOOD_EVENTS]
    ignored = len(mine) - len(counted)
    note = f" ({ignored} pull_request/other run(s) ignored)" if ignored else ""

    def desc(r: dict) -> str:
        return f"#{r.get('run_number')} {r.get('event')} {r.get('status')}/{r.get('conclusion')} {r.get('html_url', '')}".rstrip()

    ok = [r for r in counted if r.get("status") == "completed" and r.get("conclusion") == "success"]
    if ok:
        return "pass", f"CI passed for {commit}: {desc(ok[0])}{note}"
    pending = [r for r in counted if r.get("status") != "completed"]
    if pending:
        return "wait", f"CI still running for {commit}: {', '.join(desc(r) for r in pending)}{note}"
    if counted:
        return "fail", f"CI did not pass for {commit}: {', '.join(desc(r) for r in counted)}{note}"
    return "fail", f"no CI run (push / workflow_dispatch / schedule) for {commit}{note}: push it to main or its release branch first"


def fetch_runs(repo: str, workflow: str, commit: str) -> list[dict]:
    p = subprocess.run(
        [
            "gh", "api", "-X", "GET",
            f"repos/{repo}/actions/workflows/{workflow}/runs",
            "-f", f"head_sha={commit}", "-f", "per_page=100",
        ],
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"gh api failed ({p.returncode}): {p.stderr.strip()}")
    data = json.loads(p.stdout)
    runs = data.get("workflow_runs") if isinstance(data, dict) else None
    if not isinstance(runs, list):
        raise RuntimeError("gh api: no workflow_runs list in the response")
    return runs


def ci_gate(a) -> int:
    if not SHA.match(a.commit):
        print(f"release-gate: --commit must be a full commit id, got {a.commit!r}", file=sys.stderr)
        return 2
    deadline = time.monotonic() + 60 * a.wait_minutes
    while True:
        if a.runs_json:
            with open(a.runs_json, encoding="utf-8") as f:
                runs = json.load(f).get("workflow_runs", [])
        else:
            runs = fetch_runs(a.repo, a.workflow, a.commit)
        verdict, why = evaluate_runs(runs, a.commit)
        if verdict == "pass":
            print(why)
            return 0
        if verdict == "wait" and time.monotonic() < deadline and not a.runs_json:
            print(f"{why}; waiting {a.poll_seconds} s", file=sys.stderr)
            time.sleep(a.poll_seconds)
            continue
        print(f"::error::{why}", file=sys.stderr)
        return 1


def self_test() -> int:
    import os
    import tempfile
    import unittest

    c = "a" * 40

    def run(**kw):
        r = {"head_sha": c, "event": "push", "status": "completed", "conclusion": "success", "run_number": 1}
        r.update(kw)
        return r

    class Ci(unittest.TestCase):
        def test_pass(self):
            self.assertEqual(evaluate_runs([run()], c)[0], "pass")
            self.assertEqual(evaluate_runs([run(conclusion="failure"), run(run_number=2)], c)[0], "pass")
            self.assertEqual(evaluate_runs([run(event="schedule")], c)[0], "pass")

        def test_fail(self):
            self.assertEqual(evaluate_runs([], c)[0], "fail")
            self.assertEqual(evaluate_runs([run(conclusion="failure")], c)[0], "fail")
            self.assertEqual(evaluate_runs([run(conclusion="cancelled")], c)[0], "fail")
            self.assertEqual(evaluate_runs([run(conclusion="skipped")], c)[0], "fail")
            # A green pull_request run tested a merge commit, not this one.
            self.assertEqual(evaluate_runs([run(event="pull_request")], c)[0], "fail")
            # Another commit's green run.
            self.assertEqual(evaluate_runs([run(head_sha="b" * 40)], c)[0], "fail")

        def test_wait(self):
            self.assertEqual(evaluate_runs([run(status="in_progress", conclusion=None)], c)[0], "wait")
            self.assertEqual(evaluate_runs([run(status="queued", conclusion=None), run(conclusion="failure")], c)[0], "wait")

        def test_cli_runs_json(self):
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "r.json")
                for runs, want in (([run()], 0), ([run(conclusion="failure")], 1), ([run(status="queued")], 1)):
                    with open(p, "w") as f:
                        json.dump({"workflow_runs": runs}, f)
                    self.assertEqual(main(["ci", "--commit", c, "--repo", "o/r", "--runs-json", p]), want)
                self.assertEqual(main(["ci", "--commit", "abc", "--repo", "o/r", "--runs-json", p]), 2)

    class Line(unittest.TestCase):
        def setUp(self):
            self.td = tempfile.TemporaryDirectory()
            d = self.d = self.td.name
            env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.invalid",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.invalid"}
            os.environ.update(env)

            def g(*a):
                return git(d, *a).stdout.strip()

            self.g = g
            g("init", "-q", "-b", "main")
            g("config", "commit.gpgsign", "false")
            g("commit", "-q", "--allow-empty", "-m", "base")
            self.base = g("rev-parse", "HEAD")
            g("checkout", "-q", "-b", "release/0.1")
            g("commit", "-q", "--allow-empty", "-m", "lts fix")
            self.lts = g("rev-parse", "HEAD")
            g("checkout", "-q", "-b", "feature", self.base)
            g("commit", "-q", "--allow-empty", "-m", "unreviewed")
            self.feat = g("rev-parse", "HEAD")
            g("checkout", "-q", "main")
            g("commit", "-q", "--allow-empty", "-m", "next")
            self.main = g("rev-parse", "HEAD")
            for b in ("main", "release/0.1"):
                g("update-ref", f"refs/remotes/origin/{b}", g("rev-parse", b))

        def tearDown(self):
            self.td.cleanup()

        def test_main(self):
            self.assertEqual(release_line(self.main, "0.2.0", self.d), ("main", True))
            self.assertEqual(release_line(self.base, "0.1.0", self.d), ("main", True))

        def test_lts_branch(self):
            self.assertEqual(release_line(self.lts, "0.1.3", self.d), ("release/0.1", False))
            self.assertEqual(release_line(self.lts, "0.1.3-rc.1", self.d), ("release/0.1", False))

        def test_refused(self):
            # LTS commit tagged with another line's version.
            with self.assertRaises(Refused):
                release_line(self.lts, "0.2.0", self.d)
            # Not on any protected branch.
            with self.assertRaises(Refused):
                release_line(self.feat, "0.1.4", self.d)
            with self.assertRaises(Refused):
                release_line(self.main, "v0.2", self.d)
            with self.assertRaises(Refused):
                release_line("f" * 40, "0.2.0", self.d)
            self.g("update-ref", "-d", "refs/remotes/origin/main")
            with self.assertRaises(Refused):
                release_line(self.main, "0.2.0", self.d)

    suite = unittest.TestSuite()
    for cls in (Ci, Line):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    r = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if r.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    ap = argparse.ArgumentParser(description="RoboDR release gates")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("line")
    pl.add_argument("--commit", required=True)
    pl.add_argument("--version", required=True)
    pl.add_argument("--git-dir")
    pc = sub.add_parser("ci")
    pc.add_argument("--commit", required=True)
    pc.add_argument("--repo", required=True)
    pc.add_argument("--workflow", default="ci.yml")
    pc.add_argument("--wait-minutes", type=int, default=0)
    pc.add_argument("--poll-seconds", type=int, default=60)
    pc.add_argument("--runs-json")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "line":
            line, latest = release_line(a.commit, a.version, a.git_dir)
            print(f"line={line}")
            print(f"latest={'true' if latest else 'false'}")
            return 0
        return ci_gate(a)
    except Refused as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    except (RuntimeError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as e:
        print(f"release-gate: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
