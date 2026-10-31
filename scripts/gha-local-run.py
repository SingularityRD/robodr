#!/usr/bin/env python3
"""Run one job of a GitHub Actions workflow locally, step by step.

Used by scripts/release-dry-run.sh to replay .github/workflows/release.yml
without GitHub: the `run:` scripts of the workflow are executed AS WRITTEN
(same shell as GitHub: `bash --noprofile --norc -eo pipefail`), with the
workflow, job and step `env:` blocks, `working-directory:`, $GITHUB_ENV,
$GITHUB_PATH, $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY (one file per job,
printed when the job ends) handling, and the `${{ ... }}` expressions
the release workflow uses. Nothing is re-implemented from a copy of the
workflow, so a defect in a step script shows up here.

What is emulated (each one is printed when it applies):
  * `container:` jobs: every `run:` step executes in that image (docker run
    of the pinned digest; workspace and runner temp mounted at the same
    paths; the job's env and the container's `env:` only, as on GitHub).
    --container-mode host runs them on this machine instead (an
    adaptation, logged).
  * `uses:` steps: actions/checkout is a local `git clone` of --repo at
    --sha (submodule content is part of that repository);
    actions/upload-artifact copies its path into the --artifacts store
    (DIR/<name>/; a second upload of a name fails, as on GitHub);
    actions/download-artifact copies by `name`, or by `pattern` with
    `merge-multiple`; actions/attest-build-provenance is skipped (needs
    GitHub's OIDC token; logged). Any other action fails the run.
  * `if:` on jobs and steps: only `<context reference> == '<literal>'` or
    `!=` (e.g. github.event_name == 'push'); anything else fails the run.
  * --event push|workflow_dispatch sets github.event_name, GITHUB_REF
    (refs/tags/<ref-name> or refs/heads/<ref-name>) and GITHUB_REF_TYPE.
  * --subst OLD=>NEW rewrites step scripts (cross-compilation adaptations of
    a job that GitHub runs on a native runner). Every rewrite is logged.
  * --env K=V adds job-level environment (after the job's own env:).
  * Expressions: only plain context references (matrix.*, needs.*.outputs.*,
    steps.*.outputs.*, secrets.*, vars.*, github.*, runner.*). Anything else
    (functions, operators) fails the run, so a workflow change that needs
    more is noticed instead of silently mis-evaluated.
Secrets and variables are read from the environment: DRYRUN_SECRET_<NAME>
and DRYRUN_VAR_<NAME> (unset = empty string, as on GitHub).

  gha-local-run.py --workflow W --job J [--matrix k=v ...] --workspace DIR
                   --repo GITREPO --sha SHA --ref-name REF --runner-temp DIR
                   [--event push|workflow_dispatch] [--artifacts DIR]
                   [--container-mode docker|host]
                   [--needs J.out=value ...] [--outputs-file F]
                   [--env K=V ...] [--subst 'OLD=>NEW' ...] [--log FILE]

Exit: 0 every step passed (or the job's `if:` is false: "skipped"), 1 a step
failed, 2 usage / unsupported workflow.
Self-test: gha-local-run.py --self-test   (the docker part only when docker
works, or always with GHA_LOCAL_RUN_TEST_DOCKER=1)
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
REF = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$")
COND = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*)\s*(==|!=)\s*'([^']*)'$")
ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,200}$")


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


def condition(text, ctx: dict) -> bool:
    """`if:` with exactly one comparison of a context value to a literal."""
    if isinstance(text, bool):
        return text
    s = str(text).strip()
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", s)
    if m:
        s = m.group(1)
    c = COND.match(s)
    if not c:
        raise Unsupported(f"if: {text!r} is not '<context> == / != <literal>'")
    v = evaluate(c.group(1), ctx)
    return (v == c.group(3)) if c.group(2) == "==" else (v != c.group(3))


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


def copy_tree_into(src: Path, dst: Path) -> int:
    """Copy the files under src (a file or a directory) into dst; count."""
    n = 0
    dst.mkdir(parents=True, exist_ok=True)
    if src.is_file():
        shutil.copy2(src, dst / src.name)
        return 1
    for f in sorted(src.rglob("*")):
        if f.is_symlink():
            raise Unsupported(f"artifact: symlink {f} (not uploaded by GitHub either)")
        if f.is_file():
            t = dst / f.relative_to(src)
            t.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, t)
            n += 1
    return n


def upload_artifact(store: Path | None, ws: Path, with_: dict, log: Log) -> bool:
    name = with_.get("name", "")
    if not ARTIFACT_NAME.match(name):
        raise Unsupported(f"upload-artifact: bad or missing name {name!r}")
    p = ws / with_.get("path", "")
    files = [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else ([p] if p.is_file() else [])
    if not files and with_.get("if-no-files-found") == "error":
        log(f"[dry-run] upload-artifact '{name}': no files at {p}")
        return False
    if store is None:
        log(f"[dry-run] upload-artifact '{name}': {len(files)} file(s) at {p} (no --artifacts store: not kept)")
        return True
    dst = store / name
    if dst.exists():
        log(f"[dry-run] upload-artifact: an artifact named '{name}' already exists")
        return False
    n = copy_tree_into(p, dst) if files else 0
    dst.mkdir(parents=True, exist_ok=True)
    log(f"[dry-run] upload-artifact '{name}': {n} file(s) from {p} -> {dst}")
    return True


def download_artifact(store: Path | None, ws: Path, with_: dict, log: Log) -> bool:
    if store is None:
        raise Unsupported("download-artifact needs --artifacts")
    dest = Path(with_.get("path") or ws)
    if not dest.is_absolute():
        dest = ws / dest
    if with_.get("name"):
        names = [with_["name"]]
        if not (store / names[0]).is_dir():
            log(f"[dry-run] download-artifact: no artifact '{names[0]}' in {store}")
            return False
        merge = True
    elif with_.get("pattern"):
        names = sorted(d.name for d in store.iterdir() if d.is_dir() and fnmatch.fnmatchcase(d.name, with_["pattern"]))
        merge = str(with_.get("merge-multiple", "false")).lower() == "true"
    else:
        raise Unsupported("download-artifact without name or pattern (all artifacts) is not emulated")
    n = 0
    for nm in names:
        n += copy_tree_into(store / nm, dest if merge else dest / nm)
    log(f"[dry-run] download-artifact {names} -> {dest}{' (merged)' if merge else ''}: {n} file(s)")
    return True


class Container:
    """A long-running container for the `run:` steps of one job."""

    def __init__(self, image: str, mounts: list[Path], log: Log):
        self.name = f"gha-local-run-{uuid.uuid4().hex[:12]}"
        args = ["docker", "run", "-d", "--rm", "--name", self.name, "--entrypoint", "sleep"]
        for m in mounts:
            args += ["-v", f"{m}:{m}"]
        args += [image, "infinity"]
        log(f"[dry-run] container: {image} as {self.name}")
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

    def cmd(self, env: dict, cwd: Path, script: Path, envfile: Path) -> list[str]:
        envfile.write_text("".join(f"{k}={v}\n" for k, v in env.items() if "\n" not in v))
        multi = [k for k, v in env.items() if "\n" in v]
        if multi:
            raise Unsupported(f"multi-line env values cannot enter a container: {multi}")
        return ["docker", "exec", "--env-file", str(envfile), "-w", str(cwd), self.name,
                "bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)]

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
    store = Path(a.artifacts).resolve() if a.artifacts else None
    if store:
        store.mkdir(parents=True, exist_ok=True)
    needs: dict = {}
    for kv in a.needs:
        k, v = kv.split("=", 1)
        j, o = k.split(".", 1)
        needs.setdefault(j, {"outputs": {}})["outputs"][o] = v
    is_tag = a.event == "push"
    ref = f"refs/tags/{a.ref_name}" if is_tag else f"refs/heads/{a.ref_name}"
    github = {
        "token": "dry-run-no-token",
        "sha": a.sha,
        "ref": ref,
        "ref_name": a.ref_name,
        "ref_type": "tag" if is_tag else "branch",
        "event_name": a.event,
        "repository": a.repository,
        "workspace": str(ws),
        "run_id": a.run_id,
        "server_url": "https://github.com",
    }
    runner = {"temp": str(temp), "os": "Linux"}
    steps_ctx: dict = {}
    ctx = {"matrix": matrix, "needs": needs, "github": github, "runner": runner, "steps": steps_ctx}

    for unsupported in ("services", "defaults"):
        if unsupported in job:
            raise Unsupported(f"job key '{unsupported}' is not supported")
    title = substitute(job.get("name", a.job), ctx)
    if "if" in job and not condition(job["if"], ctx):
        log(f"=== job {a.job}: {title}: skipped (if: {job['if']})")
        if a.outputs_file:
            Path(a.outputs_file).write_text("{}\n")
        return 0

    # The dry run's own secrets reach steps only through ${{ secrets.* }},
    # as on GitHub (where a build job never sees the signing key).
    gh_env = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "GITHUB_WORKSPACE": str(ws),
        "GITHUB_REF": ref,
        "GITHUB_REF_NAME": a.ref_name,
        "GITHUB_REF_TYPE": github["ref_type"],
        "GITHUB_EVENT_NAME": a.event,
        "GITHUB_SHA": a.sha,
        "GITHUB_REPOSITORY": a.repository,
        "GITHUB_JOB": a.job,
        "GITHUB_RUN_ID": a.run_id,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SERVER_URL": "https://github.com",
        "RUNNER_TEMP": str(temp),
        "RUNNER_OS": "Linux",
        "RUNNER_ENVIRONMENT": "self-hosted",
    }
    container_spec = job.get("container")
    container = None
    if container_spec is not None and a.container_mode == "docker":
        if not isinstance(container_spec, dict) or set(container_spec) - {"image", "env"}:
            raise Unsupported("container: only image and env are supported")
        env = dict(gh_env)
        env.update({k: substitute(v, ctx) for k, v in (container_spec.get("env") or {}).items()})
    else:
        env = {k: v for k, v in os.environ.items() if not k.startswith("DRYRUN_")}
        env.update(gh_env)
        if container_spec is not None:
            log(f"[dry-run] adaptation: container {substitute(container_spec.get('image'), ctx)} -> steps run on this host")
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
    extra_path: list[str] = []

    ws.mkdir(parents=True, exist_ok=True)
    log(f"=== job {a.job}: {title}  (runs-on on GitHub: {substitute(job.get('runs-on'), ctx)}, event {a.event})")
    if job.get("environment"):
        log(f"[dry-run] environment '{job['environment']}': no reviewers here; secrets come from DRYRUN_SECRET_*")
    if container_spec is not None and a.container_mode == "docker":
        container = Container(substitute(container_spec["image"], ctx), [ws.parent, temp] + ([store] if store else []), log)
    try:
        for n, step in enumerate(job.get("steps") or [], 1):
            name = substitute(step.get("name") or step.get("uses") or step.get("run", "").splitlines()[0], ctx)
            for unsupported in ("continue-on-error", "shell"):
                if unsupported in step:
                    raise Unsupported(f"step '{name}': key '{unsupported}' is not supported")
            if "if" in step and not condition(step["if"], ctx):
                log(f"--- step {n}: {name}: skipped (if: {step['if']})")
                continue
            step_env = dict(env)
            for k, v in (step.get("env") or {}).items():
                step_env[k] = substitute(v, ctx)
            if extra_path:
                step_env["PATH"] = ":".join(extra_path + [step_env.get("PATH", "")])
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
                    if with_.get("fetch-depth") == "0":
                        # Remote-tracking refs as a fetch-depth: 0 checkout has them.
                        for b in subprocess.run(["git", "-C", a.repo, "for-each-ref", "--format=%(refname:short)", "refs/heads"],
                                                capture_output=True, text=True, check=True).stdout.split():
                            subprocess.run(["git", "-C", str(ws), "update-ref", f"refs/remotes/origin/{b}",
                                            subprocess.run(["git", "-C", a.repo, "rev-parse", b], capture_output=True,
                                                           text=True, check=True).stdout.strip()], check=True)
                elif uses.startswith("actions/upload-artifact@"):
                    if not upload_artifact(store, ws, with_, log):
                        return 1
                elif uses.startswith("actions/download-artifact@"):
                    if not download_artifact(store, ws, with_, log):
                        return 1
                elif uses.startswith("actions/attest-build-provenance@"):
                    log(f"[dry-run] adaptation: {uses} skipped (needs GitHub's OIDC token and attestation store)")
                else:
                    raise Unsupported(f"action {uses} is not emulated")
                continue
            script = substitute(step["run"], ctx)
            for old, new in substs:
                if old in script:
                    script = script.replace(old, new)
                    log(f"[dry-run] adaptation in this step: '{old}' -> '{new}'")
            genv, gout, gpath = temp / f"_env_{n}", temp / f"_out_{n}", temp / f"_path_{n}"
            for f in (genv, gout, gpath):
                f.write_text("")
            step_env["GITHUB_ENV"] = str(genv)
            step_env["GITHUB_OUTPUT"] = str(gout)
            step_env["GITHUB_PATH"] = str(gpath)
            step_env["GITHUB_STEP_SUMMARY"] = str(temp / "_step_summary.md")
            sfile = temp / f"_step_{n}.sh"
            sfile.write_text(script)
            cwd = ws
            if "working-directory" in step:
                cwd = Path(substitute(step["working-directory"], ctx))
                if not cwd.is_absolute():
                    cwd = ws / cwd
            if container:
                cmd, penv = container.cmd(step_env, cwd, sfile, temp / f"_envfile_{n}"), None
            else:
                cmd, penv = ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(sfile)], step_env
            proc = subprocess.Popen(cmd, cwd=None if container else cwd, env=penv, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, errors="replace")
            assert proc.stdout is not None
            for line in proc.stdout:
                log("    " + line.rstrip("\n"))
            rc = proc.wait()
            if rc != 0:
                log(f"!!! step {n} '{name}' FAILED (exit {rc})")
                return 1
            env.update(parse_env_file(genv))
            extra_path = [p for p in gpath.read_text().splitlines() if p.strip()][::-1] + extra_path
            if "id" in step:
                steps_ctx[step["id"]] = {"outputs": parse_env_file(gout)}
    finally:
        if container:
            container.stop()
    summary = temp / "_step_summary.md"
    if summary.is_file() and summary.stat().st_size:
        log(f"--- job summary ($GITHUB_STEP_SUMMARY):\n{summary.read_text(errors='replace')}")
    outputs = {k: substitute(v, ctx) for k, v in (job.get("outputs") or {}).items()}
    if a.outputs_file:
        Path(a.outputs_file).write_text(json.dumps(outputs, indent=1) + "\n")
    log(f"=== job {a.job} passed; outputs {outputs}")
    return 0


def self_test() -> int:
    import tempfile
    import unittest

    def docker_ok() -> bool:
        if os.environ.get("GHA_LOCAL_RUN_TEST_DOCKER") == "1":
            return True
        try:
            return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    class T(unittest.TestCase):
        def test_expr(self):
            ctx = {"matrix": {"arch": "arm64"}, "needs": {"p": {"outputs": {"v": "1.0"}}}}
            self.assertEqual(substitute("a-${{ matrix.arch }}-${{needs.p.outputs.v}}", ctx), "a-arm64-1.0")
            with self.assertRaises(Unsupported):
                substitute("${{ github.ref == 'x' }}", ctx)
            with self.assertRaises(Unsupported):
                substitute("${{ matrix.nope }}", ctx)

        def test_condition(self):
            ctx = {"github": {"event_name": "push"}}
            self.assertTrue(condition("github.event_name == 'push'", ctx))
            self.assertTrue(condition("${{ github.event_name != 'workflow_dispatch' }}", ctx))
            self.assertFalse(condition("github.event_name == 'workflow_dispatch'", ctx))
            for bad in ("success()", "github.event_name == 'a' && true", "github.event_name", "contains(x, 'y')"):
                with self.assertRaises(Unsupported, msg=bad):
                    condition(bad, ctx)

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

        def workflow(self, d: Path, body: str) -> tuple[Path, Path, str]:
            repo = d / "repo"
            repo.mkdir()
            e = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.invalid",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.invalid"}
            (repo / "f.txt").write_text("hello\n")
            for c in (["init", "-q", "-b", "main"], ["config", "commit.gpgsign", "false"], ["add", "-A"],
                      ["commit", "-q", "-m", "x"]):
                subprocess.run(["git", "-C", str(repo), *c], check=True, env=e)
            sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True,
                                 check=True).stdout.strip()
            wf = d / "wf.yml"
            wf.write_text(body)
            return wf, repo, sha

        def run_wf(self, d: Path, wf: Path, repo: Path, sha: str, job: str, *extra: str) -> int:
            return main(["--workflow", str(wf), "--job", job, "--workspace", str(d / f"ws-{job}" / "r"),
                         "--repo", str(repo), "--sha", sha, "--ref-name", "v1.0.0", "--runner-temp",
                         str(d / f"tmp-{job}"), "--artifacts", str(d / "store"), *extra])

        def test_artifacts_if_and_path(self):
            body = """
jobs:
  up:
    runs-on: x
    steps:
      - uses: actions/checkout@abc
      - run: |
          mkdir -p out/sub bin
          echo "${{ github.event_name }}" > out/sub/a.txt
          printf '#!/bin/sh\\necho shim\\n' > bin/mytool && chmod +x bin/mytool
          echo "$PWD/bin" >> "$GITHUB_PATH"
      - run: test "$(mytool)" = shim
      - uses: actions/upload-artifact@abc
        with: {name: rel-amd64-x, path: out, if-no-files-found: error}
      - uses: actions/upload-artifact@abc
        with: {name: rel-arm64-x, path: f.txt}
  down:
    runs-on: x
    steps:
      - uses: actions/download-artifact@abc
        with: {pattern: rel-*-x, merge-multiple: true, path: "${{ runner.temp }}/got"}
      - run: test -f "$RUNNER_TEMP/got/sub/a.txt" && test -f "$RUNNER_TEMP/got/f.txt" && grep -qx push "$RUNNER_TEMP/got/sub/a.txt"
      - if: github.event_name == 'workflow_dispatch'
        run: exit 1
      - uses: actions/attest-build-provenance@abc
  dry:
    runs-on: x
    if: github.event_name == 'workflow_dispatch'
    steps:
      - run: exit 1
  dup:
    runs-on: x
    steps:
      - uses: actions/checkout@abc
      - uses: actions/upload-artifact@abc
        with: {name: rel-arm64-x, path: f.txt}
"""
            with tempfile.TemporaryDirectory() as td:
                d = Path(td)
                wf, repo, sha = self.workflow(d, body)
                self.assertEqual(self.run_wf(d, wf, repo, sha, "up"), 0)
                self.assertEqual(self.run_wf(d, wf, repo, sha, "down"), 0)
                self.assertEqual(self.run_wf(d, wf, repo, sha, "dry"), 0)  # skipped
                self.assertEqual(self.run_wf(d, wf, repo, sha, "dry", "--event", "workflow_dispatch"), 1)
                self.assertEqual(self.run_wf(d, wf, repo, sha, "dup"), 1)  # name taken

        @unittest.skipUnless(docker_ok(), "docker not available")
        def test_container(self):
            image = ("docker.io/library/ubuntu:22.04@sha256:"
                     "076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11")
            body = f"""
jobs:
  c:
    runs-on: x
    container:
      image: {image}
      env: {{FROM_CONTAINER: "yes"}}
    env: {{FROM_JOB: "${{{{ github.sha }}}}"}}
    steps:
      - uses: actions/checkout@abc
      - run: |
          test "$FROM_CONTAINER" = yes
          test -n "$FROM_JOB"
          test -z "${{HOST_ONLY:-}}"
          test -f f.txt
          grep -q '^VERSION_CODENAME=jammy' /etc/os-release
          echo "X=from-container" >> "$GITHUB_ENV"
      - run: test "$X" = from-container
"""
            if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0:
                if subprocess.run(["docker", "pull", "-q", image], capture_output=True).returncode != 0:
                    self.skipTest("cannot pull the ubuntu:22.04 image")
            with tempfile.TemporaryDirectory() as td:
                d = Path(td)
                wf, repo, sha = self.workflow(d, body)
                os.environ["HOST_ONLY"] = "1"
                try:
                    self.assertEqual(self.run_wf(d, wf, repo, sha, "c"), 0)
                    # Host mode (an adaptation) sees the host: HOST_ONLY is set.
                    self.assertEqual(self.run_wf(d, wf, repo, sha, "c", "--container-mode", "host"), 1)
                finally:
                    os.environ.pop("HOST_ONLY", None)

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
    p.add_argument("--event", choices=("push", "workflow_dispatch"), default="push")
    p.add_argument("--repository", default="local/robodr-release-dry-run")
    p.add_argument("--run-id", default="1")
    p.add_argument("--runner-temp", required=True)
    p.add_argument("--artifacts")
    p.add_argument("--container-mode", choices=("docker", "host"), default="docker")
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
