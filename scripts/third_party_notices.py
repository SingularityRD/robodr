#!/usr/bin/env python3
"""Generate RoboDR's third-party notices and the Pulsar eBPF source offer.

    python3 scripts/third_party_notices.py            # (re)write both files
    python3 scripts/third_party_notices.py --check    # CI: committed == generated
    python3 scripts/third_party_notices.py --self-test

Writes, at the repository root (both committed, both shipped in the .deb,
the RPM (%license) and the offline bundle):

  THIRD_PARTY_NOTICES      every third-party Rust crate linked into (or run
                           at build time for) a RoboDR program: name, version,
                           SPDX license expression, and the license texts the
                           crate ships, deduplicated (each distinct text once,
                           with the crates that use it).
  GPL-2.0-SOURCE-OFFER     the written offer (GPL-2.0 section 3(b)) for the
                           corresponding source of the Pulsar eBPF probes that
                           robodr-pulsard loads into the kernel: Pulsar commit,
                           every probe source / header / build file with its
                           SPDX identifier and SHA-256.

Offline: crate data comes from `cargo metadata --locked --offline` (the
committed Cargo.lock, crate sources already in CARGO_HOME: `cargo fetch
--locked` once, or the air-gapped mirror) and license texts from the crate
sources and vendor/pulsar; no network, stdlib only. Crates are those reached
from the workspace members over normal and build dependencies (never
dev-dependencies) on the Linux targets RoboDR ships (x86_64 / aarch64, gnu
and musl). A crate that ships no license file gets the canonical text of a
license its expression allows (LICENSES/, packaging/licenses/), marked so.

Every crate's license is checked against deny.toml ([licenses] allow, the
per-crate exceptions and the [[licenses.clarify]] entries): a crate whose
expression cannot be satisfied by the allowed licenses fails the run, as
cargo-deny would. Output is deterministic (sorted, no paths, no dates): the
same Cargo.lock and Pulsar commit give the same bytes, which `--check`
(.github/workflows/ci.yml, job deny) compares with the committed files.
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

ROOT = Path(__file__).resolve().parent.parent
NOTICES = "THIRD_PARTY_NOTICES"
OFFER = "GPL-2.0-SOURCE-OFFER"
PLATFORMS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
)
LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|UNLICENSE|NOTICE|COPYRIGHT)([-._].*)?$", re.I)
# Canonical texts for crates that ship no license file.
CANONICAL = {
    "Apache-2.0": "LICENSES/LICENSE-APACHE-2.0",
    "MIT": "packaging/licenses/MIT.txt",
}
PULSAR = "vendor/pulsar"


# ------------------------------------------------------------- SPDX ------

def tokenize(expr: str) -> list[str]:
    # Old-style "MIT/Apache-2.0" and "Apache-2.0 / MIT" mean OR.
    expr = re.sub(r"\s*/\s*", " OR ", expr.strip())
    return re.findall(r"\(|\)|[A-Za-z0-9.+:-]+", expr)


def parse(expr: str):
    """SPDX expression -> tree: ("or"|"and", [..]) or ("lic", "Id[ WITH Exc]")."""
    toks = tokenize(expr)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def atom():
        t = take()
        if t == "(":
            e = disj()
            if take() != ")":
                raise ValueError(f"unbalanced parentheses in {expr!r}")
            return e
        if t in ("AND", "OR", "WITH", ")"):
            raise ValueError(f"unexpected {t} in {expr!r}")
        if peek() == "WITH":
            take()
            t = f"{t} WITH {take()}"
        return ("lic", t)

    def conj():
        xs = [atom()]
        while peek() == "AND":
            take()
            xs.append(atom())
        return xs[0] if len(xs) == 1 else ("and", xs)

    def disj():
        xs = [conj()]
        while peek() == "OR":
            take()
            xs.append(conj())
        return xs[0] if len(xs) == 1 else ("or", xs)

    if not toks:
        raise ValueError("empty license expression")
    tree = disj()
    if pos != len(toks):
        raise ValueError(f"trailing tokens in {expr!r}")
    return tree


def render(tree) -> str:
    kind, v = tree
    if kind == "lic":
        return v
    parts = [render(x) if x[0] == "lic" or x[0] == kind else f"({render(x)})" for x in v]
    return f" {kind.upper()} ".join(parts)


def satisfied(tree, allowed: set[str]) -> bool:
    kind, v = tree
    if kind == "lic":
        return v in allowed
    if kind == "and":
        return all(satisfied(x, allowed) for x in v)
    return any(satisfied(x, allowed) for x in v)


def ids(tree) -> list[str]:
    kind, v = tree
    if kind == "lic":
        return [v.split(" WITH ")[0]]
    return [i for x in v for i in ids(x)]


# --------------------------------------------------------- deny.toml ------

def load_deny(path: Path) -> dict:
    text = path.read_text()
    try:
        import tomllib  # Python >= 3.11

        lic = tomllib.loads(text)["licenses"]
        return {
            "allow": set(lic.get("allow", [])),
            "exceptions": {e["crate"]: set(e["allow"]) for e in lic.get("exceptions", [])},
            "clarify": {c["crate"]: c["expression"] for c in lic.get("clarify", [])},
        }
    except ImportError:
        pass
    # Fallback for older Pythons: the three constructs deny.toml uses.
    body = re.sub(r"#[^\n]*", "", text)
    sect = re.search(r"^\[licenses\]\n(.*?)(?=^\[(?!\[licenses\.clarify)(?!licenses\.)|\Z)", body, re.S | re.M)
    s = sect.group(1) if sect else ""
    allow = set(re.findall(r'"([^"]+)"', re.search(r"^allow\s*=\s*\[(.*?)\]", s, re.S | re.M).group(1)))
    exc = {}
    for a, c in re.findall(r'\{\s*allow\s*=\s*\[([^\]]*)\]\s*,\s*crate\s*=\s*"([^"]+)"\s*\}', body):
        exc[c] = set(re.findall(r'"([^"]+)"', a))
    clarify = dict(re.findall(r'\[\[licenses\.clarify\]\]\s*crate\s*=\s*"([^"]+)"\s*expression\s*=\s*"([^"]+)"', body))
    return {"allow": allow, "exceptions": exc, "clarify": clarify}


# ------------------------------------------------------------ crates ------

def cargo_metadata() -> dict:
    cmd = ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"]
    for p in PLATFORMS:
        cmd += ["--filter-platform", p]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(
            "third_party_notices: cargo metadata --locked --offline failed (run `cargo fetch "
            f"--locked` once, or point CARGO_HOME at the mirror):\n{r.stderr}"
        )
    return json.loads(r.stdout)


def shipped_packages(meta: dict) -> list[dict]:
    """Third-party packages reachable from the workspace members over normal
    and build dependencies."""
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    members = set(meta["workspace_members"])
    seen, todo = set(), list(members)
    while todo:
        i = todo.pop()
        if i in seen:
            continue
        seen.add(i)
        for d in nodes[i]["deps"]:
            if any(k.get("kind") != "dev" for k in d["dep_kinds"]):
                todo.append(d["pkg"])
    out = [pkgs[i] for i in seen if i not in members]
    return sorted(out, key=lambda p: (p["name"], [int(x) if x.isdigit() else x for x in re.split(r"[.+-]", p["version"])], p["version"]))


def normalise(text: str) -> str:
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def license_files(pkg: dict) -> list[tuple[str, str]]:
    """(file name, text) of the license files a crate ships."""
    d = Path(pkg["manifest_path"]).parent
    names = set()
    for f in os.listdir(d):
        if LICENSE_FILE.match(f) and (d / f).is_file():
            names.add(f)
    if pkg.get("license_file"):
        names.add(pkg["license_file"])
    lic_dir = d / "LICENSES"
    files = [(n, d / n) for n in sorted(names)]
    if lic_dir.is_dir():
        files += [(f"LICENSES/{f}", lic_dir / f) for f in sorted(os.listdir(lic_dir)) if (lic_dir / f).is_file()]
    return [(n, p.read_text(errors="replace")) for n, p in files]


def texts_for(pkg: dict, tree) -> tuple[list[tuple[str, str]], str]:
    """The license texts of a crate and a note on where they come from."""
    path = Path(pkg["manifest_path"]).resolve()
    pulsar = (ROOT / PULSAR).resolve()
    if pkg["source"] is None and pulsar in path.parents:
        # Pulsar's Rust crates: Apache-2.0 (vendor/pulsar/LICENSE).
        return [
            ("Pulsar LICENSE", (pulsar / "LICENSE").read_text()),
            ("Pulsar LICENSES/LICENSE-APACHE-2.0", (pulsar / "LICENSES/LICENSE-APACHE-2.0").read_text()),
        ], "Pulsar (vendor/pulsar)"
    files = license_files(pkg)
    if files:
        return files, ""
    have = ids(tree)
    for i in CANONICAL:  # Apache-2.0 first: a complete text, no copyright line to fill
        if i in have:
            return [(i, (ROOT / CANONICAL[i]).read_text())], (
                f"the crate ships no license file; canonical {i} text"
            )
    sys.exit(f"third_party_notices: {pkg['name']} {pkg['version']} ships no license file and no canonical text "
             f"is known for {render(tree)} (add one to CANONICAL)")


def check_license(pkg: dict, deny: dict) -> tuple[object, str]:
    """(tree to report, note); exits when deny.toml would refuse it."""
    name = pkg["name"]
    declared = pkg.get("license") or ""
    note = ""
    expr = declared
    if name in deny["clarify"]:
        expr = deny["clarify"][name]
        note = f"declared {declared!r}, clarified in deny.toml"
    if not expr:
        sys.exit(f"third_party_notices: {name} {pkg['version']} declares no license")
    tree = parse(expr)
    allowed = deny["allow"] | deny["exceptions"].get(name, set())
    if not satisfied(tree, allowed):
        sys.exit(f"third_party_notices: {name} {pkg['version']}: {render(tree)} is not allowed by deny.toml")
    return tree, note


def notices(meta: dict, deny: dict) -> str:
    rows, texts = [], {}  # texts: hash -> [label, text, users]
    for p in shipped_packages(meta):
        tree, note = check_license(p, deny)
        files, origin = texts_for(p, tree)
        refs = []
        for fname, t in files:
            t = normalise(t)
            h = hashlib.sha256(t.encode()).hexdigest()
            if h not in texts:
                texts[h] = [fname, t, []]
            texts[h][2].append(f"{p['name']} {p['version']}")
            refs.append(h)
        rows.append((p, render(tree), note, origin, refs))
    num = {h: i + 1 for i, h in enumerate(texts)}
    out = [
        "RoboDR third-party notices",
        "==========================",
        "",
        "RoboDR is proprietary software of SingularityRD (/usr/share/doc/robodr/copyright).",
        "Its programs contain or were built with the third-party Rust crates below, each",
        "under its own license. Every crate is listed with its version and SPDX license",
        "expression; the license texts the crates ship follow, each distinct text once",
        "([T<n>], with the crates that carry it). Where an expression offers a choice",
        "(\"MIT OR Apache-2.0\"), RoboDR uses the crate under any one of the licenses",
        "offered; every text the crate ships is reproduced.",
        "",
        "The Pulsar eBPF probes that robodr-pulsard loads into the kernel are not Rust",
        "crates: they are GPL-2.0 programs, see GPL-2.0-SOURCE-OFFER next to this file.",
        "",
        "Generated by scripts/third_party_notices.py from Cargo.lock; do not edit.",
        "",
        f"Crates ({len(rows)})",
        "-" * len(f"Crates ({len(rows)})"),
        "",
    ]
    for p, expr, note, origin, refs in rows:
        out.append(f"{p['name']} {p['version']}")
        out.append(f"    License: {expr}")
        if note:
            out.append(f"    Note:    {note}")
        if origin:
            out.append(f"    Texts:   {origin}")
        out.append("    See:     " + ", ".join(f"[T{num[h]}]" for h in refs))
    out += ["", f"License texts ({len(texts)})", "-" * len(f"License texts ({len(texts)})"), ""]
    for h, (fname, t, users) in texts.items():
        out.append("=" * 78)
        out.append(f"[T{num[h]}] {fname}")
        out.append("Used by: " + ", ".join(users))
        out.append("=" * 78)
        out.append("")
        out.append(t)
    return "\n".join(out)


# ------------------------------------------------------- source offer -----

def git(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def ebpf_sources(pulsar: Path) -> list[Path]:
    """Every file that is part of the probes' corresponding source: probe C
    sources and headers, the shared include directory (libbpf headers,
    vmlinux.h), and the build code that compiles them."""
    out = set()
    for p in pulsar.rglob("*"):
        rel = p.relative_to(pulsar).as_posix()
        if rel.startswith((".git/", "target/")) or "/.git/" in rel:
            continue
        if not (p.is_file() or p.is_symlink()):
            continue
        if (rel.endswith((".bpf.c", ".bpf.h"))
                or rel.startswith("crates/bpf-builder/")
                or (rel.endswith("/build.rs") and (p.parent / "build.rs").exists()
                    and any(p.parent.glob("**/*.bpf.c")))):
            out.add(p)
    return sorted(out, key=lambda p: p.relative_to(pulsar).as_posix())


def spdx_of(p: Path) -> str:
    if p.is_symlink():
        return f"symlink to {os.readlink(p)}"
    with open(p, "rb") as f:
        head = f.read(4096).decode(errors="replace")
    m = re.search(r"SPDX-License-Identifier:\s*(.+?)\s*(\*/)?\s*$", head, re.M)
    if m:
        return m.group(1).strip()
    if p.name.endswith((".c", ".h")):
        return "not stated in the file (Pulsar LICENSE: eBPF probes GPL-2.0)"
    return "not stated in the file (build file; Pulsar LICENSE: userspace Apache-2.0)"


def offer() -> str:
    pulsar = ROOT / PULSAR
    if not (pulsar / "LICENSE").exists():
        sys.exit("third_party_notices: vendor/pulsar is not checked out (git submodule update --init)")
    commit = git("rev-parse", "HEAD", cwd=pulsar)
    url = git("config", "-f", ".gitmodules", "submodule.vendor/pulsar.url")
    files = ebpf_sources(pulsar)
    out = [
        "RoboDR: written offer for the source of the Pulsar eBPF probes (GPL-2.0)",
        "========================================================================",
        "",
        "robodr-pulsard (package robodr, standard variant; not in robodr-focal) embeds",
        "eBPF programs from the Pulsar project (Exein SpA) and loads them into the Linux",
        "kernel. These programs are licensed under the GNU General Public License,",
        "version 2 (some files additionally under BSD-3-Clause or, for the libbpf",
        "headers, LGPL-2.1 OR BSD-2-Clause, as stated per file below). The GPL-2.0 text",
        "is in licenses/LICENSE-GPL-2.0 next to this file. Pulsar's userspace Rust code",
        "is Apache-2.0 and is listed in THIRD_PARTY_NOTICES.",
        "",
        "Offer (GPL-2.0, section 3(b)). For at least three years after SingularityRD last",
        "distributes this RoboDR release, SingularityRD will give any third party, on",
        "request, a complete machine-readable copy of the corresponding source code of",
        "these eBPF programs (the files listed below, including the scripts used to",
        "control their compilation), on a medium customarily used for software",
        "interchange, for a charge no more than the cost of physically performing the",
        "distribution. Send the request to SingularityRD through the support contact",
        "named in your RoboDR licence agreement, quoting the RoboDR version and the",
        "Pulsar commit below.",
        "",
        "The same source is published by the Pulsar project:",
        f"    repository: {url}",
        f"    commit:     {commit}",
        "",
        "Build: the probes are compiled with clang for the BPF target by Pulsar's",
        "bpf-builder crate (crates/bpf-builder/src/lib.rs), called from the build.rs of",
        "each crate listed below; docs/BUILD.md of RoboDR gives the pinned toolchain.",
        "",
        "Generated by scripts/third_party_notices.py; do not edit.",
        "",
        f"Corresponding source files ({len(files)}), paths relative to the Pulsar tree:",
        "",
    ]
    for p in files:
        rel = p.relative_to(pulsar).as_posix()
        h = "-" * 64 if p.is_symlink() else hashlib.sha256(p.read_bytes()).hexdigest()
        out.append(f"{h}  {rel}")
        out.append(f"    SPDX: {spdx_of(p)}")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------ main --------

def self_test() -> int:
    allowed = {"MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "Unicode-3.0"}
    cases = [
        ("MIT OR Apache-2.0", True, "MIT OR Apache-2.0"),
        ("MIT/Apache-2.0", True, "MIT OR Apache-2.0"),
        ("Apache-2.0 / MIT", True, "Apache-2.0 OR MIT"),
        ("(MIT OR Apache-2.0) AND Unicode-3.0", True, "(MIT OR Apache-2.0) AND Unicode-3.0"),
        ("MIT AND BSD-3-Clause", False, "MIT AND BSD-3-Clause"),
        ("GPL-2.0", False, "GPL-2.0"),
        ("Apache-2.0 WITH LLVM-exception OR MIT", True, "Apache-2.0 WITH LLVM-exception OR MIT"),
        ("Apache-2.0 WITH BPF-exception", False, "Apache-2.0 WITH BPF-exception"),
        ("MIT OR Apache-2.0 OR LGPL-2.1-or-later", True, "MIT OR Apache-2.0 OR LGPL-2.1-or-later"),
    ]
    bad = 0
    for expr, ok, rendered in cases:
        t = parse(expr)
        if satisfied(t, allowed) != ok or render(t) != rendered:
            print(f"FAIL {expr!r}: satisfied={satisfied(t, allowed)} render={render(t)!r}")
            bad += 1
    for broken in ["", "MIT OR", "(MIT", "AND MIT"]:
        try:
            parse(broken)
            print(f"FAIL {broken!r} parsed")
            bad += 1
        except (ValueError, IndexError):
            pass
    d = load_deny(ROOT / "deny.toml")
    if "MIT" not in d["allow"] or "pulsar-core" not in d["clarify"] or "tiny-keccak" not in d["exceptions"]:
        print(f"FAIL deny.toml parse: {d}")
        bad += 1
    if normalise("\r\n a \r\nb  \n\n") != " a\nb\n":
        print("FAIL normalise")
        bad += 1
    print("third_party_notices self-test:", "FAIL" if bad else "ok")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="fail if the committed files are not up to date")
    ap.add_argument("--out-dir", default=str(ROOT), help="where to write (default: the repository root)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    deny = load_deny(ROOT / "deny.toml")
    generated = {NOTICES: notices(cargo_metadata(), deny), OFFER: offer()}
    if a.check:
        stale = [n for n, t in generated.items()
                 if not (ROOT / n).exists() or (ROOT / n).read_text() != t]
        if stale:
            print(f"third_party_notices: {', '.join(stale)} out of date: run "
                  "`python3 scripts/third_party_notices.py` and commit the result", file=sys.stderr)
            return 1
        print("third_party_notices: THIRD_PARTY_NOTICES and GPL-2.0-SOURCE-OFFER are up to date")
        return 0
    out = Path(a.out_dir)
    for n, t in generated.items():
        (out / n).write_text(t)
        print(f"third_party_notices: wrote {out / n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
