#!/usr/bin/env python3
"""Check facts that documents state about the code against the code itself.

Customer, compliance and security documents quote numbers and tables that the
code decides: the findings contract version, the workspace members, the fuzz
targets and the action catalog. They drift every time the code moves. This
script reads each fact from its single source in the code and fails when a
document states something else.

Checks (``--only`` takes these names):

  contract-version
      Source: ``CONTRACT_VERSION`` in crates/robodr-ocsf/src/model.rs.
      * the contract document's header (``version **X**``), the JSON
        Schema's ``$id`` and title, and the golden example's
        ``contract_version`` equal it;
      * in the current-state documents (CURRENT_DOCS below), every
        "`robodr.findings` X" and "findings contract X" names it (X may
        omit the patch level). A mention right after "since", "before",
        "until", "from", "up to", "added in" or "introduced in" is history
        and is not checked.

  workspace-members
      Source: ``[workspace] members`` in Cargo.toml.
      * the README's repository layout lists every member directory, and
        lists no ``robodr-*`` directory that is not a member;
      * in the current-state documents, "all N members", "all N crates",
        "N workspace members", "N workspace crates" and (GA-ROADMAP)
        "N workspace üyesi" state the member count.

  fuzz-targets
      Source: fuzz/fuzz_targets/*.rs.
      * fuzz/Cargo.toml declares exactly one ``[[bin]]`` per target file;
      * fuzz/README.md has a table row for every target;
      * in the current-state documents, "N fuzz targets" and "N cargo-fuzz
        targets" state the target count.

  action-catalog
      Source: ``CATALOG`` in crates/robodr-responder/src/actions.rs (name,
      wire name, step, approval, GA execution) and ``AdapterKind::as_str``
      in crates/robodr-executor/src/motion/mod.rs.
      * the module's own doc table, the responder README "Action catalog"
        table, the control-plane contract's action table and ADR-0005's
        "GA plan" table list exactly the catalog's actions, with the same
        wire name, step, approval and GA execution (``executed`` /
        ``executor``, ``platform adapter``, ``plan only``) wherever the
        table has that column;
      * the executor README's "Motion adapters" table names exactly the
        adapters the code has.

  stamps
      Every document in STAMPED_DOCS carries a line
      "Verified at commit `<sha>`" whose commit exists in this repository
      and is HEAD or an ancestor of it (a stamp that names a commit from an
      unmerged branch, or a typo, fails). ``--max-stamp-age N`` also fails a
      stamp with more than N commits since it that touch crates/, fuzz/,
      packaging/ or Cargo.toml; without it the age is printed only. Needs
      the full history: run it on a clone with ``fetch-depth: 0``, or pass
      ``--skip-git`` to leave this check out (it is then reported as
      skipped, never as passed).

  evidence-links
      Every document in STAMPED_DOCS and EVIDENCE_DOCS is evidence for a
      customer: each relative Markdown link target (``](path)``, anchors
      ignored) and each backticked repository path (``crates/...``,
      ``scripts/...``, ``docs/...``, ``packaging/...``, ``fuzz/...``,
      ``tools/...``, ``config/...``, ``rules/...``, ``man/...``, or a test
      file written as ``robodr-<crate>/tests/<f>.rs`` relative to crates/)
      must exist.

  pulsar-pin
      Source: the gitlink of vendor/pulsar in HEAD. The Pulsar
      due-diligence record names that commit in full, and
      docs/PULSAR-INTEGRATION.md's "Verified against Pulsar commit" names
      its prefix. Needs git (left out, and reported, with --skip-git).

Usage:
  scripts/check-doc-facts.py [--root DIR] [--only CHECK[,CHECK...]]
                             [--max-stamp-age N] [--skip-git]
  scripts/check-doc-facts.py --self-test
Exit 0 ok, 1 drift found, 2 usage error or a source that cannot be parsed.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Documents that describe the product as it is now. History (CHANGELOG,
# SPRINTS, ADR context sections, SECURE-DELIVERY sprint notes) is not
# checked for numbers: it is allowed to say what was true then.
CURRENT_DOCS = (
    "README.md",
    "SECURITY.md",
    "docs/BUILD.md",
    "docs/OPERATIONS.md",
    "docs/GA-ROADMAP.md",
    "docs/compliance/*.md",
    "docs/customer/*.md",
    "fuzz/README.md",
)

# Documents that must carry a "Verified at commit" stamp.
STAMPED_DOCS = (
    "docs/compliance/*.md",
    "docs/customer/data-handling.md",
)

# Further documents whose evidence links must resolve.
EVIDENCE_DOCS = ("SECURITY.md",)

DUE_DILIGENCE_MD = "docs/compliance/third-party-due-diligence.md"
PULSAR_INTEGRATION_MD = "docs/PULSAR-INTEGRATION.md"

MODEL_RS = "crates/robodr-ocsf/src/model.rs"
CONTRACT_MD = "docs/contracts/robodr.findings.md"
SCHEMA_JSON = "docs/contracts/robodr-finding.schema.json"
EXAMPLE_JSON = "docs/contracts/robodr-finding.example.json"
ACTIONS_RS = "crates/robodr-responder/src/actions.rs"
RESPONDER_README = "crates/robodr-responder/README.md"
CONTROL_PLANE_MD = "docs/contracts/robodr.control-plane.md"
ADR_0005 = "docs/adr/0005-action-catalog.md"
MOTION_RS = "crates/robodr-executor/src/motion/mod.rs"
EXECUTOR_README = "crates/robodr-executor/README.md"

CHECKS = (
    "contract-version",
    "workspace-members",
    "fuzz-targets",
    "action-catalog",
    "stamps",
    "evidence-links",
    "pulsar-pin",
)

LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
PATH_RE = re.compile(
    r"`((?:crates|scripts|docs|packaging|fuzz|tools|config|rules|man)/[A-Za-z0-9_./-]+"
    r"|robodr-[a-z0-9-]+/tests/[A-Za-z0-9_]+\.rs)`"
)

HISTORY_MARKERS = re.compile(
    r"(?:\bsince|\bbefore|\buntil|\bfrom|\bup to|\badded in|\bintroduced in)\s+(?:the\s+)?$",
    re.IGNORECASE,
)

STAMP_RE = re.compile(r"Verified at commit `([0-9a-f]{7,40})`")

# Paths whose changes age a stamp (code, packaging, build), as git pathspecs.
STAMP_AGE_PATHS = ("crates", "fuzz", "packaging", "Cargo.toml")


class SourceError(Exception):
    """A fact's source in the code could not be read or parsed."""


# ----------------------------------------------------------------- helpers


def read(root: Path, rel: str) -> str:
    p = root / rel
    try:
        return p.read_text(encoding="utf-8")
    except OSError as e:
        raise SourceError(f"{rel}: cannot read ({e.strerror})") from e


def expand(root: Path, patterns: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for pat in patterns:
        if any(c in pat for c in "*?["):
            out.extend(sorted(str(p.relative_to(root)) for p in root.glob(pat) if p.is_file()))
        elif (root / pat).is_file():
            out.append(pat)
    seen: set[str] = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def is_history(text: str, pos: int) -> bool:
    start = max(0, pos - 40)
    return bool(HISTORY_MARKERS.search(text[start:pos]))


def table_rows(lines: list[str], header_pred) -> list[list[str]]:
    """Cells of the Markdown table whose header line satisfies header_pred.

    Lines may carry a ``//! `` prefix (Rust module docs). Returns the body
    rows (after the separator) of the first matching table.
    """
    rows: list[list[str]] = []
    in_table = False
    for raw in lines:
        line = raw.strip()
        if line.startswith("//!"):
            line = line[3:].strip()
        if not in_table:
            if line.startswith("|") and header_pred(line):
                in_table = True
                rows = []
                sep_seen = False
            continue
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not sep_seen:
            sep_seen = True
            if all(re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) for c in cells):
                continue
        rows.append(cells)
    return rows


def code_name(cell: str) -> str | None:
    m = re.fullmatch(r"`([a-z0-9_]+)`", cell.strip())
    return m.group(1) if m else None


def snake(camel: str) -> str:
    return re.sub(r"(?<!^)([A-Z])", r"_\1", camel).lower()


# ----------------------------------------------------------- code sources


def contract_version(root: Path) -> str:
    m = re.search(r'pub const CONTRACT_VERSION: &str = "(\d+\.\d+\.\d+)";', read(root, MODEL_RS))
    if not m:
        raise SourceError(f"{MODEL_RS}: CONTRACT_VERSION not found")
    return m.group(1)


def workspace_members(root: Path) -> list[str]:
    text = read(root, "Cargo.toml")
    m = re.search(r"^\[workspace\]\s*$(.*?)^\[", text, re.MULTILINE | re.DOTALL)
    body = m.group(1) if m else ""
    mm = re.search(r"^members\s*=\s*\[(.*?)\]", body, re.MULTILINE | re.DOTALL)
    if not mm:
        raise SourceError("Cargo.toml: [workspace] members not found")
    items = []
    for line in mm.group(1).splitlines():
        line = line.split("#", 1)[0]
        items.extend(re.findall(r'"([^"]+)"', line))
    if not items:
        raise SourceError("Cargo.toml: [workspace] members is empty")
    return items


def fuzz_targets(root: Path) -> list[str]:
    d = root / "fuzz" / "fuzz_targets"
    if not d.is_dir():
        raise SourceError("fuzz/fuzz_targets: missing")
    return sorted(p.stem for p in d.glob("*.rs"))


CATALOG_ENTRY = re.compile(
    r"spec\(\s*ActionId::(\w+),\s*\"([a-z_]+)\",\s*\"([a-z_]+)\",\s*Step::(\w+),\s*"
    r"(true|false),\s*(true|false),\s*Approval::(\w+),\s*GaExecution::(\w+),\s*(true|false),?\s*\)",
    re.DOTALL,
)


def action_catalog(root: Path) -> list[dict]:
    text = read(root, ACTIONS_RS)
    m = re.search(r"pub const CATALOG: \[ActionSpec; (\d+)\] = \[(.*?)\n\];", text, re.DOTALL)
    if not m:
        raise SourceError(f"{ACTIONS_RS}: CATALOG not found")
    entries = []
    for e in CATALOG_ENTRY.finditer(m.group(2)):
        entries.append(
            {
                "name": e.group(2),
                "wire": e.group(3),
                "step": snake(e.group(4)),
                "approval": {"Single": "single", "TwoPerson": "two-person"}.get(e.group(7), "?"),
                "ga": snake(e.group(8)),
            }
        )
    if len(entries) != int(m.group(1)) or not entries:
        raise SourceError(
            f"{ACTIONS_RS}: CATALOG declares {m.group(1)} entries, {len(entries)} parsed "
            "(the spec(...) argument order changed? update this script)"
        )
    return entries


def motion_adapters(root: Path) -> list[str]:
    text = read(root, MOTION_RS)
    m = re.search(r"pub fn as_str\(self\) -> &'static str \{\s*match self \{(.*?)\}", text, re.DOTALL)
    if not m:
        raise SourceError(f"{MOTION_RS}: AdapterKind::as_str not found")
    names = re.findall(r'AdapterKind::\w+ => "([a-z0-9_]+)"', m.group(1))
    if not names:
        raise SourceError(f"{MOTION_RS}: AdapterKind::as_str has no arms")
    return sorted(names)


# ------------------------------------------------------------------ checks


def check_contract_version(root: Path) -> list[str]:
    v = contract_version(root)
    major_minor = ".".join(v.split(".")[:2])
    errs: list[str] = []
    head = "\n".join(read(root, CONTRACT_MD).splitlines()[:12])
    m = re.search(r"version \*\*(\d+\.\d+\.\d+)\*\*", head)
    if not m or m.group(1) != v:
        errs.append(f"{CONTRACT_MD}: header names version {m.group(1) if m else '(none)'}, code {v}")
    schema = read(root, SCHEMA_JSON)
    if f'"$id": "https://schemas.singularityrd.com/robodr/findings/{v}"' not in schema:
        errs.append(f"{SCHEMA_JSON}: $id does not end in /{v}")
    if f"contract {v}" not in schema:
        errs.append(f"{SCHEMA_JSON}: title does not name contract {v}")
    ex = re.search(r'"contract_version":\s*"([^"]+)"', read(root, EXAMPLE_JSON))
    if not ex or ex.group(1) != v:
        errs.append(f"{EXAMPLE_JSON}: contract_version {ex.group(1) if ex else '(none)'}, code {v}")
    pat = re.compile(r"(?:`robodr\.findings`|\bfindings contract)\s+v?(\d+\.\d+(?:\.\d+)?)\b")
    for rel in expand(root, CURRENT_DOCS):
        text = read(root, rel)
        for mm in pat.finditer(text):
            got = mm.group(1)
            if got in (v, major_minor) or is_history(text, mm.start()):
                continue
            errs.append(
                f"{rel}:{line_of(text, mm.start())}: says {mm.group(0)!r}; the code emits {v}"
            )
    return errs


def check_workspace_members(root: Path) -> list[str]:
    members = workspace_members(root)
    names = sorted(Path(m).name for m in members)
    errs: list[str] = []
    readme = read(root, "README.md")
    listed = set(re.findall(r"^ {2,}(robodr-[a-z0-9-]+)/(?:\s|$)", readme, re.MULTILINE))
    for n in names:
        if n not in listed:
            errs.append(f"README.md: repository layout does not list crates/{n}/ (a workspace member)")
    for n in sorted(listed - set(names)):
        errs.append(f"README.md: repository layout lists {n}/, which is not a workspace member")
    pats = (
        re.compile(r"\ball (\d+) (?:workspace )?(?:members|crates)\b"),
        re.compile(r"\b(\d+) workspace (?:members|crates)\b"),
        re.compile(r"\b(\d+) workspace üyesi\b"),
    )
    for rel in expand(root, CURRENT_DOCS):
        text = read(root, rel)
        for pat in pats:
            for mm in pat.finditer(text):
                if int(mm.group(1)) != len(members) and not is_history(text, mm.start()):
                    errs.append(
                        f"{rel}:{line_of(text, mm.start())}: says {mm.group(0)!r}; "
                        f"the workspace has {len(members)} members"
                    )
    return errs


def check_fuzz_targets(root: Path) -> list[str]:
    targets = fuzz_targets(root)
    errs: list[str] = []
    cargo = read(root, "fuzz/Cargo.toml")
    bins = re.findall(r'^\[\[bin\]\]\s*\nname\s*=\s*"([^"]+)"', cargo, re.MULTILINE)
    for t in sorted(set(targets) - set(bins)):
        errs.append(f"fuzz/Cargo.toml: no [[bin]] for fuzz_targets/{t}.rs")
    for b in sorted(set(bins) - set(targets)):
        errs.append(f"fuzz/Cargo.toml: [[bin]] {b} has no fuzz_targets/{b}.rs")
    for b in sorted({b for b in bins if bins.count(b) > 1}):
        errs.append(f"fuzz/Cargo.toml: [[bin]] {b} declared more than once")
    readme = read(root, "fuzz/README.md")
    rows = set(re.findall(r"^\| `([a-z0-9_]+)` \|", readme, re.MULTILINE))
    for t in targets:
        if t not in rows:
            errs.append(f"fuzz/README.md: no table row for target {t}")
    pat = re.compile(r"\b(\d+) (?:cargo-fuzz|(?:libFuzzer )?fuzz) targets\b")
    for rel in expand(root, CURRENT_DOCS):
        text = read(root, rel)
        for mm in pat.finditer(text):
            if int(mm.group(1)) != len(targets) and not is_history(text, mm.start()):
                errs.append(
                    f"{rel}:{line_of(text, mm.start())}: says {mm.group(0)!r}; "
                    f"fuzz/fuzz_targets has {len(targets)}"
                )
    return errs


def ga_class(cell: str) -> str | None:
    c = cell.strip().lower()
    if c.startswith("plan only"):
        return "plan_only"
    if "platform adapter" in c:
        return "platform_adapter"
    if c.startswith("executed") or c.startswith("executor"):
        return "executor"
    return None


def approval_class(cell: str) -> str | None:
    c = cell.strip().lower()
    return c if c in ("single", "two-person") else None


def compare_table(
    rel: str,
    rows: list[list[str]],
    catalog: list[dict],
    cols: dict[str, int],
) -> list[str]:
    """cols maps a fact (wire, step, approval, ga) to a column index."""
    errs: list[str] = []
    if not rows:
        return [f"{rel}: action table not found"]
    by_name = {c["name"]: c for c in catalog}
    seen: list[str] = []
    for cells in rows:
        name = code_name(cells[0]) if cells else None
        if name is None:
            errs.append(f"{rel}: action row {cells[0] if cells else ''!r} is not a `name` cell")
            continue
        seen.append(name)
        spec = by_name.get(name)
        if spec is None:
            errs.append(f"{rel}: lists `{name}`, which is not in the catalog")
            continue
        for fact, idx in cols.items():
            if idx >= len(cells):
                errs.append(f"{rel}: `{name}` row has no column {idx + 1} ({fact})")
                continue
            cell = cells[idx]
            if fact == "wire":
                got = code_name(cell)
            elif fact == "step":
                m = re.match(r"`([a-z_]+)`", cell)
                got = m.group(1) if m else None
            elif fact == "approval":
                got = approval_class(cell)
            else:
                got = ga_class(cell)
            if got != spec[fact]:
                errs.append(
                    f"{rel}: `{name}` {fact} is {cell!r}; the catalog says {spec[fact]}"
                )
    for c in catalog:
        if c["name"] not in seen:
            errs.append(f"{rel}: catalog action `{c['name']}` missing from the table")
    for n in sorted({n for n in seen if seen.count(n) > 1}):
        errs.append(f"{rel}: `{n}` listed more than once")
    return errs


def check_action_catalog(root: Path) -> list[str]:
    catalog = action_catalog(root)
    errs: list[str] = []
    full = {"wire": 1, "step": 2, "approval": 4, "ga": 5}

    def header(*needles):
        return lambda line: all(n in line for n in needles)

    lines = read(root, ACTIONS_RS).splitlines()
    rows = table_rows(lines, header("| Action |", "| Wire name |", "| GA |"))
    errs += compare_table(ACTIONS_RS + " (module docs)", rows, catalog, full)

    lines = read(root, RESPONDER_README).splitlines()
    rows = table_rows(lines, header("| Action |", "| Wire name |", "| GA execution |"))
    errs += compare_table(RESPONDER_README, rows, catalog, full)

    lines = read(root, CONTROL_PLANE_MD).splitlines()
    rows = table_rows(lines, header("| `action` |", "| Wire name |", "| GA |"))
    errs += compare_table(CONTROL_PLANE_MD, rows, catalog, {"wire": 1, "approval": 6, "ga": 7})

    lines = read(root, ADR_0005).splitlines()
    rows = table_rows(lines, header("| Action |", "| GA plan |"))
    errs += compare_table(ADR_0005, rows, catalog, {"ga": 1})

    adapters = motion_adapters(root)
    text = read(root, EXECUTOR_README)
    sec = re.search(r"^## Motion adapters.*?(?=^## )", text, re.MULTILINE | re.DOTALL)
    if not sec:
        errs.append(f"{EXECUTOR_README}: section 'Motion adapters' not found")
    else:
        rows = table_rows(sec.group(0).splitlines(), header("| Action |", "| Adapter |"))
        named: set[str] = set()
        for cells in rows:
            if len(cells) > 1:
                named.update(re.findall(r"`([a-z0-9_]+)`", cells[1]))
        for a in adapters:
            if a not in named:
                errs.append(f"{EXECUTOR_README}: Motion adapters table does not name adapter `{a}`")
        for a in sorted(named - set(adapters)):
            errs.append(f"{EXECUTOR_README}: Motion adapters table names `{a}`, which the code lacks")
    return errs


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )


def check_stamps(root: Path, max_age: int | None, notes: list[str]) -> list[str]:
    errs: list[str] = []
    if git(root, "rev-parse", "--verify", "HEAD^{commit}").returncode != 0:
        return [f"{root}: not a git checkout with a HEAD (use --skip-git to leave stamps out)"]
    shallow = git(root, "rev-parse", "--is-shallow-repository").stdout.strip() == "true"
    docs = expand(root, STAMPED_DOCS)
    if not docs:
        return ["no stamped documents found (STAMPED_DOCS)"]
    for rel in docs:
        text = read(root, rel)
        found = STAMP_RE.findall(text)
        if not found:
            errs.append(f"{rel}: no 'Verified at commit `<sha>`' stamp")
            continue
        for sha in found:
            if git(root, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}").returncode != 0:
                hint = " (shallow clone: fetch the full history)" if shallow else ""
                errs.append(f"{rel}: stamp commit {sha} does not exist here{hint}")
                continue
            if git(root, "merge-base", "--is-ancestor", sha, "HEAD").returncode != 0:
                errs.append(f"{rel}: stamp commit {sha} is not HEAD or an ancestor of it")
                continue
            count = git(root, "rev-list", "--count", f"{sha}..HEAD", "--", *STAMP_AGE_PATHS)
            age = int(count.stdout.strip() or 0)
            notes.append(f"{rel}: stamp {sha}, {age} code commit(s) since")
            if max_age is not None and age > max_age:
                errs.append(
                    f"{rel}: stamp {sha} is {age} code commits old (limit {max_age}); "
                    "re-verify the document and restamp it"
                )
    return errs


def check_evidence_links(root: Path) -> list[str]:
    errs: list[str] = []
    for rel in expand(root, STAMPED_DOCS + EVIDENCE_DOCS):
        text = read(root, rel)
        base = (root / rel).parent
        for m in LINK_RE.finditer(text):
            target = m.group(1).split("#", 1)[0]
            if not target or re.match(r"^[a-z]+:", target):
                continue
            if not (base / target).exists():
                errs.append(f"{rel}:{line_of(text, m.start())}: link target {target} does not exist")
        for m in PATH_RE.finditer(text):
            path = m.group(1).rstrip("./")
            cand = root / "crates" / path if path.startswith("robodr-") else root / path
            if not cand.exists():
                errs.append(f"{rel}:{line_of(text, m.start())}: path {m.group(1)} does not exist")
    return errs


def check_pulsar_pin(root: Path) -> list[str]:
    r = git(root, "ls-tree", "HEAD", "vendor/pulsar")
    m = re.match(r"160000 commit ([0-9a-f]{40})\t", r.stdout)
    if r.returncode != 0 or not m:
        raise SourceError("vendor/pulsar is not a submodule gitlink in HEAD")
    sha = m.group(1)
    errs: list[str] = []
    dd = read(root, DUE_DILIGENCE_MD)
    named = re.search(r"Pinned commit \| `([0-9a-f]{40})`", dd)
    if not named or named.group(1) != sha:
        errs.append(
            f"{DUE_DILIGENCE_MD}: pinned commit {named.group(1) if named else '(none)'}, "
            f"vendor/pulsar is at {sha}; review the bump and update the record"
        )
    pi = read(root, PULSAR_INTEGRATION_MD)
    v = re.search(r"Verified against Pulsar commit ([0-9a-f]{7,40})", pi)
    if not v or not sha.startswith(v.group(1)):
        errs.append(
            f"{PULSAR_INTEGRATION_MD}: verified against {v.group(1) if v else '(none)'}, "
            f"vendor/pulsar is at {sha[:12]}"
        )
    return errs


def run(root: Path, only: list[str], max_age: int | None, skip_git: bool) -> tuple[list[str], list[str]]:
    errs: list[str] = []
    notes: list[str] = []
    for name in only:
        try:
            if name == "contract-version":
                errs += check_contract_version(root)
            elif name == "workspace-members":
                errs += check_workspace_members(root)
            elif name == "fuzz-targets":
                errs += check_fuzz_targets(root)
            elif name == "action-catalog":
                errs += check_action_catalog(root)
            elif name == "stamps":
                if skip_git:
                    notes.append("stamps: SKIPPED (--skip-git); nothing about the stamps was checked")
                else:
                    errs += check_stamps(root, max_age, notes)
            elif name == "evidence-links":
                errs += check_evidence_links(root)
            elif name == "pulsar-pin":
                if skip_git:
                    notes.append("pulsar-pin: SKIPPED (--skip-git); the Pulsar pin was not checked")
                else:
                    errs += check_pulsar_pin(root)
        except SourceError as e:
            raise SourceError(f"{name}: {e}") from e
    return errs, notes


# --------------------------------------------------------------- self-test

GOOD_TREE: dict[str, str] = {
    "Cargo.toml": (
        '[workspace]\nmembers = [\n    "crates/robodr-a",\n    # comment "crates/robodr-x"\n'
        '    "crates/robodr-b",\n]\n\n[workspace.package]\nversion = "0"\n'
    ),
    MODEL_RS: 'pub const CONTRACT_VERSION: &str = "2.4.0";\n',
    CONTRACT_MD: "# Contract\n\n| Contract | `robodr.findings`, version **2.4.0** (x) |\n",
    SCHEMA_JSON: (
        '{\n  "$id": "https://schemas.singularityrd.com/robodr/findings/2.4.0",\n'
        '  "title": "msg (contract 2.4.0; also 2.3.x)"\n}\n'
    ),
    EXAMPLE_JSON: '{\n  "contract_version": "2.4.0"\n}\n',
    "README.md": (
        "Layout:\n```\ncrates/\n  robodr-a/   first\n  robodr-b/   second\n```\n"
        "Findings: `robodr.findings` 2.4 over uplink; since `robodr.findings` 2.2 the deliverd.\n"
        "All 2 members inherit it. 3 fuzz targets.\n"
    ),
    "docs/compliance/a.md": (
        "> Verified at commit `STAMP` (date).\n\nfindings contract 2.4.0\n"
        "See [the readme](../../README.md#layout) and `robodr-a/tests/t.rs`, `scripts/x.py`.\n"
    ),
    "crates/robodr-a/tests/t.rs": "",
    "scripts/x.py": "",
    "SECURITY.md": "Report via [web](https://example.invalid/) or [here](#reporting).\n",
    DUE_DILIGENCE_MD: "> Verified at commit `STAMP`.\n\n| Pinned commit | `PULSAR` (date) |\n",
    PULSAR_INTEGRATION_MD: "**Verified against Pulsar commit PULSHORT by reading its source**\n",
    "docs/customer/data-handling.md": "> Verified at commit `STAMP`.\n",
    "fuzz/Cargo.toml": "".join(
        f'[[bin]]\nname = "{t}"\npath = "fuzz_targets/{t}.rs"\n\n' for t in ("t_one", "t_two", "t_three")
    ),
    "fuzz/fuzz_targets/t_one.rs": "",
    "fuzz/fuzz_targets/t_two.rs": "",
    "fuzz/fuzz_targets/t_three.rs": "",
    "fuzz/README.md": "| Target |\n|---|\n| `t_one` | a |\n| `t_two` | b |\n| `t_three` | c |\n",
    ACTIONS_RS: (
        "//! | Action | Wire name | Step | Reversible | Approval | GA | May de-energise |\n"
        "//! |---|---|---|---|---|---|---|\n"
        "//! | `move_less` | `robot_move_less` | `limit_motion` | yes | single | executed | no |\n"
        "//! | `pause` | `robot_pause` | `safe_pause` | yes | two-person | platform adapter only | yes |\n"
        "//! | `undo` | `robot_undo` | `restrict` | no | two-person | plan only | yes |\n"
        "//!\n//! text\n\n"
        "pub const CATALOG: [ActionSpec; 3] = [\n"
        "    spec(\n        ActionId::MoveLess,\n        \"move_less\",\n        \"robot_move_less\",\n"
        "        Step::LimitMotion,\n        true,\n        true,\n        Approval::Single,\n"
        "        GaExecution::Executor,\n        false,\n    ),\n"
        "    spec(\n        ActionId::Pause,\n        \"pause\",\n        \"robot_pause\",\n"
        "        Step::SafePause,\n        true,\n        false,\n        Approval::TwoPerson,\n"
        "        GaExecution::PlatformAdapter,\n        true,\n    ),\n"
        "    spec(\n        ActionId::Undo,\n        \"undo\",\n        \"robot_undo\",\n"
        "        Step::Restrict,\n        false,\n        false,\n        Approval::TwoPerson,\n"
        "        GaExecution::PlanOnly,\n        true,\n    ),\n"
        "];\n"
    ),
    RESPONDER_README: (
        "## Action catalog\n\n"
        "| Action | Wire name | Step | Reversible | Approval | GA execution | May de-energise |\n"
        "|---|---|---|---|---|---|---|\n"
        "| `move_less` | `robot_move_less` | `limit_motion` | yes | single | executor (gateway) | no |\n"
        "| `pause` | `robot_pause` | `safe_pause` | yes | two-person | platform adapter only | yes |\n"
        "| `undo` | `robot_undo` | `restrict` | no | two-person | plan only | yes |\n"
    ),
    CONTROL_PLANE_MD: (
        "| `action` | Wire name | Parameters | `ttl_seconds` | Reversible | Ladder step | SOC approval | GA |\n"
        "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
        "| `move_less` | `robot_move_less` | x | y | yes | `limit_motion` | single | executed |\n"
        "| `pause` | `robot_pause` | none | no | yes | `safe_pause` | two-person | platform adapter only |\n"
        "| `undo` | `robot_undo` | none | no | no | `restrict` | two-person | plan only by default; x |\n"
    ),
    ADR_0005: (
        "| Action | GA plan |\n|---|---|\n| `move_less` | executed (gateway) |\n"
        "| `pause` | only through a platform adapter |\n| `undo` | plan only at GA |\n"
    ),
    MOTION_RS: (
        "impl AdapterKind {\n    pub fn as_str(self) -> &'static str {\n        match self {\n"
        '            AdapterKind::Gateway => "gateway",\n            AdapterKind::Nav2 => "nav2",\n'
        "        }\n    }\n}\n"
    ),
    EXECUTOR_README: (
        "# x\n\n## Motion adapters (Sprint 8)\n\n| Action | Adapter | Apply | Revert |\n"
        "|---|---|---|---|\n| `move_less` | `gateway` | a | b |\n| `pause` | `nav2` | a | b |\n\n## Next\n"
    ),
}

# (check, file, old, new, expected error substring)
MUTATIONS = (
    ("contract-version", MODEL_RS, '"2.4.0"', '"2.5.0"', "header names version 2.4.0, code 2.5.0"),
    ("contract-version", SCHEMA_JSON, "findings/2.4.0", "findings/2.3.0", "$id does not end in /2.4.0"),
    ("contract-version", EXAMPLE_JSON, '"2.4.0"', '"2.3.0"', "contract_version 2.3.0, code 2.4.0"),
    ("contract-version", "README.md", "`robodr.findings` 2.4 over", "`robodr.findings` 2.1 over",
     "says '`robodr.findings` 2.1'"),
    ("contract-version", "docs/compliance/a.md", "contract 2.4.0", "contract 2.2", "findings contract 2.2"),
    ("workspace-members", "Cargo.toml", '"crates/robodr-b",\n', '"crates/robodr-b",\n    "crates/robodr-c",\n',
     "does not list crates/robodr-c/"),
    ("workspace-members", "README.md", "  robodr-b/   second\n", "  robodr-b/   second\n  robodr-z/   gone\n",
     "lists robodr-z/, which is not a workspace member"),
    ("workspace-members", "README.md", "All 2 members", "all 13 members", "says 'all 13 members'"),
    ("fuzz-targets", "fuzz/README.md", "| `t_three` | c |\n", "", "no table row for target t_three"),
    ("fuzz-targets", "README.md", "3 fuzz targets", "23 fuzz targets", "says '23 fuzz targets'"),
    ("fuzz-targets", "fuzz/Cargo.toml", 'name = "t_two"', 'name = "t_2"', "no [[bin]] for fuzz_targets/t_two.rs"),
    ("action-catalog", ACTIONS_RS, "GaExecution::PlanOnly", "GaExecution::Executor",
     "`undo` ga is 'plan only'; the catalog says executor"),
    ("action-catalog", CONTROL_PLANE_MD, "| two-person | platform adapter only |", "| single | platform adapter only |",
     "`pause` approval is 'single'"),
    ("action-catalog", RESPONDER_README, "| `undo` | `robot_undo` | `restrict` | no | two-person | plan only | yes |\n",
     "", "catalog action `undo` missing from the table"),
    ("action-catalog", ADR_0005, "| `move_less` | executed (gateway) |", "| `move_less` | plan only |",
     "`move_less` ga is 'plan only'"),
    ("action-catalog", ADR_0005, "| `undo` | plan only at GA |\n", "| `undo` | plan only at GA |\n| `fly` | plan only |\n",
     "lists `fly`, which is not in the catalog"),
    ("action-catalog", MOTION_RS, '            AdapterKind::Nav2 => "nav2",\n',
     '            AdapterKind::Nav2 => "nav2",\n            AdapterKind::Px4 => "px4",\n',
     "does not name adapter `px4`"),
    ("evidence-links", "docs/compliance/a.md", "`robodr-a/tests/t.rs`", "`robodr-a/tests/gone.rs`",
     "path robodr-a/tests/gone.rs does not exist"),
    ("evidence-links", "docs/compliance/a.md", "(../../README.md#layout)", "(../../READ.md)",
     "link target ../../READ.md does not exist"),
    ("evidence-links", "SECURITY.md", "(#reporting)", "(docs/none.md)", "link target docs/none.md does not exist"),
    ("pulsar-pin", DUE_DILIGENCE_MD, "`PULSAR`", "`" + "a" * 40 + "`", "review the bump"),
    ("pulsar-pin", PULSAR_INTEGRATION_MD, "PULSHORT", "abcdef1", "verified against abcdef1"),
    ("stamps", "docs/customer/data-handling.md", "> Verified at commit `STAMP`.\n", "> Reviewed.\n",
     "no 'Verified at commit"),
    ("stamps", "docs/compliance/a.md", "`STAMP`", "`0123456789abcdef0123456789abcdef01234567`",
     "does not exist here"),
)


def build_tree(root: Path, tree: dict[str, str]) -> None:
    for rel, content in tree.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def git_commit(root: Path, msg: str, gitlink: str | None = None) -> str:
    env = ["-c", "user.name=t", "-c", "user.email=t@invalid", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
    if gitlink:
        # vendor/pulsar as a submodule gitlink (an index entry, no checkout).
        subprocess.run(
            ["git", "-C", str(root), "update-index", "--add", "--cacheinfo",
             f"160000,{gitlink},vendor/pulsar"],
            check=True, capture_output=True,
        )
    subprocess.run(["git", "-C", str(root), *env, "commit", "-q", "--allow-empty", "-m", msg],
                   check=True, capture_output=True)
    return git(root, "rev-parse", "HEAD").stdout.strip()


def self_test() -> int:
    failed = 0
    total = 0

    def expect(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failed, total
        total += 1
        if not ok:
            failed += 1
            print(f"self-test FAIL: {name} {detail}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as td:
        base = Path(td) / "repo"
        base.mkdir()
        subprocess.run(["git", "init", "-q", str(base)], check=True, capture_output=True)
        pulsar = "4796504895ce42f95ffc1e414be19a5d7f40fc0a"

        def fill(v: str, stamp: str) -> str:
            return v.replace("STAMP", stamp).replace("PULSHORT", pulsar[:7]).replace("PULSAR", pulsar)

        build_tree(base, {k: fill(v, "0" * 7) for k, v in GOOD_TREE.items()})
        first = git_commit(base, "first", pulsar)
        stamped = {k: fill(v, first[:12]) for k, v in GOOD_TREE.items()}
        build_tree(base, stamped)
        git_commit(base, "stamp", pulsar)

        errs, notes = run(base, list(CHECKS), None, False)
        expect("consistent tree passes", errs == [], str(errs))
        expect("stamp age noted", any("stamp" in n for n in notes), str(notes))

        # A stamp that names a commit not on HEAD's history.
        side = git(base, "rev-parse", "HEAD").stdout.strip()
        subprocess.run(["git", "-C", str(base), "checkout", "-q", "-b", "side"], check=True)
        build_tree(base, {"other.txt": "x"})
        side_commit = git_commit(base, "side", pulsar)
        subprocess.run(["git", "-C", str(base), "checkout", "-q", side], check=True, capture_output=True)
        p = base / "docs/compliance/a.md"
        p.write_text(stamped["docs/compliance/a.md"].replace(first[:12], side_commit[:12]))
        errs, _ = run(base, ["stamps"], None, False)
        expect("stamp off HEAD's history fails", any("not HEAD or an ancestor" in e for e in errs), str(errs))
        p.write_text(stamped["docs/compliance/a.md"])

        # Stamp age limit: one code commit after the stamp.
        build_tree(base, {"crates/robodr-a/src/lib.rs": "// change\n"})
        git_commit(base, "code", pulsar)
        errs, _ = run(base, ["stamps"], 0, False)
        expect("--max-stamp-age 0 fails an aged stamp", any("code commits old" in e for e in errs), str(errs))
        errs, _ = run(base, ["stamps"], 5, False)
        expect("--max-stamp-age 5 accepts it", errs == [], str(errs))
        errs, notes = run(base, ["stamps"], None, True)
        expect("--skip-git reports skipped", errs == [] and any("SKIPPED" in n for n in notes), str(notes))

        # History markers are not checked.
        rd = base / "README.md"
        rd.write_text(stamped["README.md"] + "Before findings contract 1.3 it was different.\n")
        errs, _ = run(base, ["contract-version"], None, False)
        expect("history mention ignored", errs == [], str(errs))
        rd.write_text(stamped["README.md"])

        for check, rel, old, new, want in MUTATIONS:
            old = old.replace("STAMP", first[:12]).replace("PULSHORT", pulsar[:7]).replace("PULSAR", pulsar)
            p = base / rel
            orig = p.read_text(encoding="utf-8")
            if old not in orig:
                expect(f"mutation setup {rel}", False, f"{old!r} not found")
                continue
            p.write_text(orig.replace(old, new, 1), encoding="utf-8")
            try:
                errs, _ = run(base, [check], None, False)
            except SourceError as e:
                errs = [f"SourceError: {e}"]
            expect(f"{check}: {want}", any(want in e for e in errs), str(errs))
            p.write_text(orig, encoding="utf-8")

        # An unparseable source is a usage error, not a silent pass.
        mr = base / ACTIONS_RS
        orig = mr.read_text()
        mr.write_text(orig.replace("pub const CATALOG", "pub const KATALOG"))
        try:
            run(base, ["action-catalog"], None, False)
            expect("unparseable catalog raises", False)
        except SourceError:
            expect("unparseable catalog raises", True)
        mr.write_text(orig)

        errs, _ = run(base, list(CHECKS), None, False)
        expect("tree restored passes", errs == [], str(errs))

    print(f"self-test: {total - failed}/{total} passed")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--only", default=",".join(CHECKS))
    ap.add_argument("--max-stamp-age", type=int, default=None)
    ap.add_argument("--skip-git", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    only = [x.strip() for x in a.only.split(",") if x.strip()]
    bad = [x for x in only if x not in CHECKS]
    if bad or not only:
        print(f"unknown check(s): {', '.join(bad) or '(none given)'}; known: {', '.join(CHECKS)}",
              file=sys.stderr)
        return 2
    try:
        errs, notes = run(Path(a.root), only, a.max_stamp_age, a.skip_git)
    except SourceError as e:
        print(f"check-doc-facts: {e}", file=sys.stderr)
        return 2
    for n in notes:
        print(f"note: {n}")
    for e in errs:
        print(f"DRIFT: {e}", file=sys.stderr)
    if errs:
        print(f"check-doc-facts: {len(errs)} drift(s) in {', '.join(only)}", file=sys.stderr)
        return 1
    print(f"check-doc-facts: ok ({', '.join(only)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
