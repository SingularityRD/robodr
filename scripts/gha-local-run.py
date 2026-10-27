#!/usr/bin/env python3
"""Run one job of a GitHub Actions workflow locally, step by step.

Used by scripts/release-dry-run.sh to replay .github/workflows/release.yml
without GitHub: the `run:` scripts of the workflow are executed AS WRITTEN
(same shell as GitHub: `bash --noprofile --norc -eo pipefail`), with the
workflow, job and step `env:` blocks, `working-directory:`, $GITHUB_ENV and
$GITHUB_OUTPUT handling, and the `${{ ... }}` expressions the release
workflow uses. Nothing is re-implemented from a copy of the workflow, so a
defect in a step script shows up here.

What is NOT GitHub (each one is printed when it applies):
  * `uses:` steps: actions/checkout is a local `git clone` of --repo at
    --sha (submodule content is part of that repository); upload-artifact
    only checks that its path exists and is not empty. Any other action
    fails the run.
  * --subst OLD=>NEW rewrites step scripts (cross-compilation adaptations of
    a job that GitHub runs on a native runner). Every rewrite is logged.
  * --env K=V adds job-level environment (after the job's own env:).
  * Expressions: only plain context references (matrix.*, needs.*.outputs.*,
    steps.*.outputs.*, secrets.*, vars.*, github.*, runner.*). Anything else
    (functions, operators, `if:` conditions) fails the run, so a workflow
    change that needs more is noticed instead of silently mis-evaluated.
Secrets and variables are read from the environment: DRYRUN_SECRET_<NAME>
and DRYRUN_VAR_<NAME> (unset = empty string, as on GitHub).

  gha-local-run.py --workflow W --job J [--matrix k=v ...] --workspace DIR
                   --repo GITREPO --sha SHA --ref-name TAG --runner-temp DIR
                   [--needs J.out=value ...] [--outputs-file F]
                   [--env K=V ...] [--subst 'OLD=>NEW' ...] [--log FILE]

Exit: 0 every step passed, 1 a step failed, 2 usage / unsupported workflow.
Self-test: gha-local-run.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
REF = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$")


class Unsupported(Exception):
    pass


def evaluate(expr: str, ctx: dict) -> str:
    """Resolve a plain context reference such as matrix.arch."""
    if not REF.match(expr):
        raise Unsupported(f"expression '${{{{ {expr} }}}}' is not a plain context reference")
    parts = expr.split(".")
    head = parts[0]
    if head in ("secrets", "vars"):
        if len(parts) != 2:
            raise Unsupported(f"bad {head} reference {expr}")
        return os.environ.get(f"DRYRUN_{head[:-1].upper()}_{parts[1]}", "")
    cur = ctx
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            raise Unsupported(f"unknown context value {expr}")
        cur = cur[p]
    if isinstance(cur, (dict, list)):
        raise Unsupported(f"{expr} is not a scalar")
    return str(cur)


def substitute(text, ctx: dict) -> str:
    if text is None:
        return ""
    if isinstance(text, bool):
        return "true" if text else "false"
    return EXPR.sub(lambda m: evaluate(m.group(1), ctx), str(text))


def parse_env_file(path: Path) -> dict:
    """$GITHUB_ENV / $GITHUB_OUTPUT syntax: K=V lines and K<<DELIM blocks."""
    out: dict = {}
    if not path.exists():
        return out
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip():
            continue
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            key, delim = line.split("<<", 1)
            buf = []
            while i < len(lines) and lines[i] != delim:
                buf.append(lines[i])
                i += 1
            if i >= len(lines):
                raise Unsupported(f"{path}: unterminated {key}<<{delim}")
            i += 1
            out[key] = "\n".join(buf)
        elif "=" in line:
            key, val = line.split("=", 1)
            out[key] = val
        else:
            raise Unsupported(f"{path}: cannot parse line {line!r}")
    return out


def pick_matrix(job: dict, want: dict) -> dict:
    strategy = job.get("strategy") or {}
    matrix = strategy.get("matrix")
    if not matrix:
        if want:
            raise Unsupported("job has no matrix, but --matrix was given")
        return {}
    if set(matrix) - {"include"}:
        raise Unsupported("only matrix.include is supported")
    hits = [e for e in matrix["include"] if all(str(e.get(k)) == v for k, v in want.items())]
    if len(hits) != 1:
        raise Unsupported(f"--matrix {want} selects {len(hits)} entries (need exactly 1)")
    return {k: str(v) for k, v in hits[0].items()}


class Log:
    def __init__(self, path: str | None):
        self.f = open(path, "a", encoding="utf-8") if path else None

    def __call__(self, msg: str) -> None:
        print(msg, flush=True)
        if self.f:
            self.f.write(msg + "\n")
            self.f.flush()


def run_job(a) -> int:
    import yaml  # PyYAML; only needed for a real run

    wf = yaml.safe_load(Path(a.workflow).read_text(encoding="utf-8"))
    jobs = wf.get("jobs") or {}
    if a.job not in jobs:
        print(f"gha-local-run: no job {a.job!r} in {a.workflow}", file=sys.stderr)
        return 2
    job = jobs[a.job]
    log = Log(a.log)
    want = dict(kv.split("=", 1) for kv in a.matrix)
    matrix = pick_matrix(job, want)

    ws = Path(a.workspace).resolve()
    temp = Path(a.runner_temp).resolve()
    temp.mkdir(parents=True, exist_ok=True)
    needs: dict = {}
    for kv in a.needs:
        k, v = kv.split("=", 1)
        j, o = k.split(".", 1)
        needs.setdefault(j, {"outputs": {}})["outputs"][o] = v
    github = {
        "token": "dry-run-no-token",
        "sha": a.sha,
        "ref": f"refs/tags/{a.ref_name}",
        "ref_name": a.ref_name,
        "repository": a.repository,
        "workspace": str(ws),
    }
    runner = {"temp": str(temp), "os": "Linux"}
    steps_ctx: dict = {}
    ctx = {"matrix": matrix, "needs": needs, "github": github, "runner": runner, "steps": steps_ctx}

    for unsupported in ("if", "container", "services", "defaults"):
        if unsupported in job:
            raise Unsupported(f"job key '{unsupported}' is not supported")

    # The dry run's own secrets reach steps only through ${{ secrets.* }},
    # as on GitHub (where a build job never sees the signing key).
    env = {k: v for k, v in os.environ.items() if not k.startswith("DRYRUN_")}
    env.update(
        {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(ws),
            "GITHUB_REF": github["ref"],
            "GITHUB_REF_NAME": a.ref_name,
            "GITHUB_REF_TYPE": "tag",
            "GITHUB_SHA": a.sha,
            "GITHUB_REPOSITORY": a.repository,
            "GITHUB_JOB": a.job,
            "RUNNER_TEMP": str(temp),
            "RUNNER_OS": "Linux",
        }
    )
    for k, v in (wf.get("env") or {}).items():
        env[k] = substitute(v, ctx)
    for k, v in (job.get("env") or {}).items():
        env[k] = substitute(v, ctx)
    for kv in a.env:
        k, v = kv.split("=", 1)
        env[k] = v
        log(f"[dry-run] job env (adaptation): {k}={v}")
    substs = []
    for s in a.subst:
        old, new = s.split("=>", 1)
        substs.append((old, new))

    ws.mkdir(parents=True, exist_ok=True)
    title = substitute(job.get("name", a.job), ctx)
    log(f"=== job {a.job}: {title}  (runs-on on GitHub: {substitute(job.get('runs-on'), ctx)})")
    for n, step in enumerate(job.get("steps") or [], 1):
        name = substitute(step.get("name") or step.get("uses") or step.get("run", "").splitlines()[0], ctx)
        for unsupported in ("if", "continue-on-error", "shell", "timeout-minutes"):
            if unsupported in step:
                raise Unsupported(f"step '{name}': key '{unsupported}' is not supported")
        step_env = dict(env)
        for k, v in (step.get("env") or {}).items():
            step_env[k] = substitute(v, ctx)
        log(f"--- step {n}: {name}")
        if "uses" in step:
            uses = step["uses"]
            with_ = {k: substitute(v, ctx) for k, v in (step.get("with") or {}).items()}
            if uses.startswith("actions/checkout@"):
                if ws.exists():
                    shutil.rmtree(ws)
                ws.parent.mkdir(parents=True, exist_ok=True)
                log(f"[dry-run] actions/checkout -> git clone {a.repo} @ {a.sha} (submodules: content committed in that repository)")
                subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", a.repo, str(ws)], check=True)
                subprocess.run(["git", "-C", str(ws), "checkout", "--quiet", "--detach", a.sha], check=True)
            elif uses.startswith("actions/upload-artifact@"):
                p = ws / with_.get("path", "")
                files = [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else ([p] if p.is_file() else [])
                if not files and with_.get("if-no-files-found") == "error":
                    log(f"[dry-run] upload-artifact: no files at {p}")
                    return 1
                log(f"[dry-run] upload-artifact '{with_.get('name')}': {len(files)} file(s) at {p} (not uploaded)")
            else:
                raise Unsupported(f"action {uses} is not emulated")
            continue
        script = substitute(step["run"], ctx)
        for old, new in substs:
            if old in script:
                script = script.replace(old, new)
                log(f"[dry-run] adaptation in this step: '{old}' -> '{new}'")
        genv = temp / f"_env_{n}"
        gout = temp / f"_out_{n}"
        genv.write_text("")
        gout.write_text("")
        step_env["GITHUB_ENV"] = str(genv)
        step_env["GITHUB_OUTPUT"] = str(gout)
        sfile = temp / f"_step_{n}.sh"
        sfile.write_text(script)
        cwd = ws
        if "working-directory" in step:
            cwd = ws / substitute(step["working-directory"], ctx)
        proc = subprocess.Popen(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(sfile)],
            cwd=cwd,
            env=step_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            log("    " + line.rstrip("\n"))
        rc = proc.wait()
        if rc != 0:
            log(f"!!! step {n} '{name}' FAILED (exit {rc})")
            return 1
        env.update(parse_env_file(genv))
        if "id" in step:
            steps_ctx[step["id"]] = {"outputs": parse_env_file(gout)}
    outputs = {k: substitute(v, ctx) for k, v in (job.get("outputs") or {}).items()}
    if a.outputs_file:
        Path(a.outputs_file).write_text(json.dumps(outputs, indent=1) + "\n")
    log(f"=== job {a.job} passed; outputs {outputs}")
    return 0


def self_test() -> int:
    import tempfile
    import unittest

    class T(unittest.TestCase):
        def test_expr(self):
            ctx = {"matrix": {"arch": "arm64"}, "needs": {"p": {"outputs": {"v": "1.0"}}}}
            self.assertEqual(substitute("a-${{ matrix.arch }}-${{needs.p.outputs.v}}", ctx), "a-arm64-1.0")
            with self.assertRaises(Unsupported):
                substitute("${{ github.ref == 'x' }}", ctx)
            with self.assertRaises(Unsupported):
                substitute("${{ matrix.nope }}", ctx)

        def test_secret_default_empty(self):
            os.environ.pop("DRYRUN_SECRET_NOPE", None)
            self.assertEqual(substitute("${{ secrets.NOPE }}", {}), "")

        def test_env_file(self):
            with tempfile.TemporaryDirectory() as d:
                p = Path(d) / "e"
                p.write_text("A=1\nB<<EOF\nx\ny\nEOF\nC=a=b\n")
                self.assertEqual(parse_env_file(p), {"A": "1", "B": "x\ny", "C": "a=b"})

        def test_matrix(self):
            job = {"strategy": {"matrix": {"include": [{"arch": "amd64"}, {"arch": "arm64"}]}}}
            self.assertEqual(pick_matrix(job, {"arch": "arm64"}), {"arch": "arm64"})
            with self.assertRaises(Unsupported):
                pick_matrix(job, {"arch": "riscv"})

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
    return 0 if r.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    p = argparse.ArgumentParser(description="Run one GitHub Actions job locally (release dry run).")
    p.add_argument("--workflow", required=True)
    p.add_argument("--job", required=True)
    p.add_argument("--matrix", action="append", default=[])
    p.add_argument("--workspace", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--sha", required=True)
    p.add_argument("--ref-name", required=True)
    p.add_argument("--repository", default="local/robodr-release-dry-run")
    p.add_argument("--runner-temp", required=True)
    p.add_argument("--needs", action="append", default=[])
    p.add_argument("--outputs-file")
    p.add_argument("--env", action="append", default=[])
    p.add_argument("--subst", action="append", default=[])
    p.add_argument("--log")
    a = p.parse_args(argv)
    try:
        return run_job(a)
    except Unsupported as e:
        print(f"gha-local-run: unsupported: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
