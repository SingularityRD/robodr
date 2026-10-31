#!/usr/bin/env python3
"""SLSA v1 build provenance (in-toto Statement v1) of a RoboDR release.

    slsa-provenance.py generate --assets DIR --version V --out FILE
                                [--workflow-file .github/workflows/release.yml]
    slsa-provenance.py verify --provenance FILE --assets DIR
                              [--commit SHA] [--repo OWNER/REPO] [--tag vV]
    slsa-provenance.py --self-test

generate (release.yml `publish`, before SHA256SUMS and signing) writes one
line of JSON (robodr-<version>.intoto.jsonl): an in-toto Statement v1 whose
subjects are every release asset in DIR (name and SHA-256; signatures,
SHA256SUMS* and the provenance itself excluded) and whose predicate is SLSA
provenance v1 (https://slsa.dev/provenance/v1):
  buildDefinition.buildType     https://actions.github.io/buildtypes/workflow/v1
  externalParameters.workflow   repository, ref (the tag), path of the workflow
  internalParameters.github     event_name, repository_id, repository_owner_id
  resolvedDependencies          the source commit; every git submodule commit
                                (git ls-tree, no fetch); every container image
                                of the workflow by digest; rust-toolchain.toml
  runDetails.builder.id         <server>/<repo>/<workflow path>@<ref>
  runDetails.metadata           invocationId (run id and attempt)
from the GitHub Actions environment (GITHUB_*). The file is signed with
minisign like every other asset, so it verifies offline with the release's
pinned key; release.yml additionally attests the same subjects with GitHub's
actions/attest-build-provenance (Sigstore; online, `gh attestation verify`).

verify (the customer side, after `minisign -V` of the file): the statement
and predicate types, every asset in DIR is a subject with the same SHA-256
and nothing else is, and, when given, the source commit, repository and tag.

Exit: 0 ok, 1 refused, 2 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

STATEMENT = "https://in-toto.io/Statement/v1"
PREDICATE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
EXCLUDE = re.compile(r"(\.minisig$|^SHA256SUMS|\.intoto\.jsonl$)")
IMAGE = re.compile(r"^\s*image:\s*([^\s@]+)@(sha256:[0-9a-f]{64})\s*$", re.M)


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def subjects(assets: Path) -> list[dict]:
    out = []
    for p in sorted(assets.iterdir(), key=lambda p: p.name):
        if p.is_file() and not p.is_symlink() and not EXCLUDE.search(p.name):
            out.append({"name": p.name, "digest": {"sha256": sha256(p)}})
    if not out:
        raise ValueError(f"no assets in {assets}")
    return out


def env(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        raise ValueError(f"{name} is not set (run inside GitHub Actions, or set it)")
    return v


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def resolved_dependencies(commit: str, server: str, repo: str, ref: str, workflow_file: str) -> list[dict]:
    deps = [{"uri": f"git+{server}/{repo}@{ref}", "digest": {"gitCommit": commit}}]
    # Submodules at the recorded commit (gitlinks of the tree; nothing fetched).
    for ln in git("ls-tree", "-r", commit).splitlines():
        meta, _, path = ln.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == "commit":
            url = git("config", "-f", ".gitmodules", "--get", f"submodule.{path}.url").strip() if Path(".gitmodules").exists() else ""
            deps.append({"uri": f"git+{url or path}", "name": path, "digest": {"gitCommit": parts[2]}})
    wf = Path(workflow_file).read_text(encoding="utf-8") if Path(workflow_file).exists() else ""
    for name, digest in sorted(set(IMAGE.findall(wf))):
        deps.append({"uri": f"docker://{name}", "digest": {"sha256": digest.split(":", 1)[1]}})
    tc = Path("rust-toolchain.toml")
    if tc.exists():
        m = re.search(r'(?m)^channel\s*=\s*"([^"]+)"', tc.read_text(encoding="utf-8"))
        if m:
            deps.append({"uri": f"https://static.rust-lang.org/dist/channel-rust-{m.group(1)}.toml", "name": "rust-toolchain",
                         "annotations": {"channel": m.group(1)}})
    return deps


def generate(assets: Path, version: str, workflow_file: str) -> dict:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo, commit, ref = env("GITHUB_REPOSITORY"), env("GITHUB_SHA"), env("GITHUB_REF")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError(f"GITHUB_SHA {commit!r} is not a commit id")
    run_id, attempt = env("GITHUB_RUN_ID"), os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    return {
        "_type": STATEMENT,
        "subject": subjects(assets),
        "predicateType": PREDICATE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "workflow": {"ref": ref, "repository": f"{server}/{repo}", "path": workflow_file},
                },
                "internalParameters": {
                    "github": {
                        "event_name": os.environ.get("GITHUB_EVENT_NAME", ""),
                        "repository_id": os.environ.get("GITHUB_REPOSITORY_ID", ""),
                        "repository_owner_id": os.environ.get("GITHUB_REPOSITORY_OWNER_ID", ""),
                        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT", ""),
                    },
                    "robodr": {"version": version},
                },
                "resolvedDependencies": resolved_dependencies(commit, server, repo, ref, workflow_file),
            },
            "runDetails": {
                "builder": {"id": f"{server}/{repo}/{workflow_file}@{ref}"},
                "metadata": {"invocationId": f"{server}/{repo}/actions/runs/{run_id}/attempts/{attempt}"},
            },
        },
    }


def verify(prov: dict, assets: Path, commit: str | None, repo: str | None, tag: str | None) -> list[str]:
    errs = []
    if prov.get("_type") != STATEMENT:
        errs.append(f"_type is {prov.get('_type')!r}, want {STATEMENT}")
    if prov.get("predicateType") != PREDICATE:
        errs.append(f"predicateType is {prov.get('predicateType')!r}, want {PREDICATE}")
    subj = {}
    for s in prov.get("subject", []) or []:
        if not isinstance(s, dict) or not isinstance(s.get("name"), str):
            errs.append("malformed subject")
            continue
        if s["name"] in subj:
            errs.append(f"duplicate subject {s['name']}")
        subj[s["name"]] = (s.get("digest") or {}).get("sha256")
    have = {s["name"]: s["digest"]["sha256"] for s in subjects(assets)}
    for n, h in have.items():
        if n not in subj:
            errs.append(f"{n}: not a subject of the provenance")
        elif subj[n] != h:
            errs.append(f"{n}: SHA-256 {h} != provenance {subj[n]}")
    for n in subj:
        if n not in have:
            errs.append(f"{n}: subject missing from {assets}")
    bd = (prov.get("predicate") or {}).get("buildDefinition") or {}
    if bd.get("buildType") != BUILD_TYPE:
        errs.append(f"buildType is {bd.get('buildType')!r}")
    src = next(iter(bd.get("resolvedDependencies") or []), {})
    if commit and (src.get("digest") or {}).get("gitCommit") != commit:
        errs.append(f"source commit {(src.get('digest') or {}).get('gitCommit')} != {commit}")
    wf = (bd.get("externalParameters") or {}).get("workflow") or {}
    if repo and not str(wf.get("repository", "")).endswith("/" + repo):
        errs.append(f"repository {wf.get('repository')} is not {repo}")
    if tag and wf.get("ref") != f"refs/tags/{tag}":
        errs.append(f"ref {wf.get('ref')} is not refs/tags/{tag}")
    return errs


def self_test() -> int:
    import tempfile
    import unittest

    class T(unittest.TestCase):
        def setUp(self):
            self.td = tempfile.TemporaryDirectory()
            self.d = Path(self.td.name)
            self.a = self.d / "assets"
            self.a.mkdir()
            for n, b in (("robodr_0.1.0-1_amd64.deb", b"deb"), ("robodr-0.1.0-amd64-sbom.tar.gz", b"sbom"),
                         ("x.deb.minisig", b"sig"), ("SHA256SUMS", b"sums"), ("SHA256SUMS-amd64", b"s")):
                (self.a / n).write_bytes(b)
            self.repo = self.d / "src"
            self.repo.mkdir()
            e = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.invalid",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.invalid"}
            for c in (["init", "-q", "-b", "main"], ["config", "commit.gpgsign", "false"]):
                subprocess.run(["git", "-C", str(self.repo), *c], check=True, env=e)
            (self.repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.98.1"\n')
            wf = self.repo / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "release.yml").write_text("    container:\n      image: docker.io/library/ubuntu:22.04@sha256:" + "a" * 64 + "\n")
            subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True, env=e)
            subprocess.run(["git", "-C", str(self.repo), "commit", "-q", "-m", "x"], check=True, env=e)
            self.sha = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True,
                                      text=True, check=True).stdout.strip()
            self.env = {"GITHUB_REPOSITORY": "SingularityRD/robodr", "GITHUB_SHA": self.sha,
                        "GITHUB_REF": "refs/tags/v0.1.0", "GITHUB_RUN_ID": "42", "GITHUB_EVENT_NAME": "push"}
            self.old = dict(os.environ)
            os.environ.update(self.env)
            self.cwd = os.getcwd()
            os.chdir(self.repo)

        def tearDown(self):
            os.chdir(self.cwd)
            os.environ.clear()
            os.environ.update(self.old)
            self.td.cleanup()

        def gen(self):
            return generate(self.a, "0.1.0", ".github/workflows/release.yml")

        def test_generate(self):
            p = self.gen()
            self.assertEqual([s["name"] for s in p["subject"]], ["robodr-0.1.0-amd64-sbom.tar.gz", "robodr_0.1.0-1_amd64.deb"])
            rd = p["predicate"]["buildDefinition"]["resolvedDependencies"]
            self.assertEqual(rd[0]["digest"]["gitCommit"], self.sha)
            self.assertIn({"uri": "docker://docker.io/library/ubuntu:22.04", "digest": {"sha256": "a" * 64}}, rd)
            self.assertEqual(rd[-1]["annotations"], {"channel": "1.98.1"})
            self.assertEqual(p["predicate"]["runDetails"]["builder"]["id"],
                             "https://github.com/SingularityRD/robodr/.github/workflows/release.yml@refs/tags/v0.1.0")
            self.assertEqual(verify(p, self.a, self.sha, "SingularityRD/robodr", "v0.1.0"), [])

        def test_verify_refuses(self):
            p = self.gen()
            (self.a / "robodr_0.1.0-1_amd64.deb").write_bytes(b"tampered")
            self.assertTrue(any("SHA-256" in e for e in verify(p, self.a, None, None, None)))
            p = self.gen()
            (self.a / "extra.tar.gz").write_bytes(b"x")
            self.assertTrue(any("not a subject" in e for e in verify(p, self.a, None, None, None)))
            (self.a / "extra.tar.gz").unlink()
            self.assertTrue(verify(p, self.a, "b" * 40, None, None))
            self.assertTrue(verify(p, self.a, None, "evil/robodr", None))
            self.assertTrue(verify(p, self.a, None, None, "v9.9.9"))
            bad = dict(p, predicateType="https://example.com/x")
            self.assertTrue(verify(bad, self.a, None, None, None))
            (self.a / "robodr_0.1.0-1_amd64.deb").unlink()
            self.assertTrue(any("missing" in e for e in verify(p, self.a, None, None, None)))

        def test_needs_github_env(self):
            del os.environ["GITHUB_SHA"]
            with self.assertRaises(ValueError):
                self.gen()

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
    return 0 if r.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    ap = argparse.ArgumentParser(description="SLSA v1 provenance of a RoboDR release")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--assets", required=True)
    g.add_argument("--version", required=True)
    g.add_argument("--out", required=True)
    g.add_argument("--workflow-file", default=".github/workflows/release.yml")
    v = sub.add_parser("verify")
    v.add_argument("--provenance", required=True)
    v.add_argument("--assets", required=True)
    v.add_argument("--commit")
    v.add_argument("--repo")
    v.add_argument("--tag")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "generate":
            p = generate(Path(a.assets), a.version, a.workflow_file)
            Path(a.out).write_text(json.dumps(p, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            print(f"{a.out}: {len(p['subject'])} subjects")
            return 0
        lines = [ln for ln in Path(a.provenance).read_text(encoding="utf-8").splitlines() if ln.strip()]
        if len(lines) != 1:
            print(f"{a.provenance}: want exactly one statement, found {len(lines)}", file=sys.stderr)
            return 1
        errs = verify(json.loads(lines[0]), Path(a.assets), a.commit, a.repo, a.tag)
        for e in errs:
            print(f"refused: {e}", file=sys.stderr)
        if not errs:
            print(f"{a.provenance}: every asset in {a.assets} is a subject with its SHA-256")
        return 1 if errs else 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as e:
        print(f"slsa-provenance: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
