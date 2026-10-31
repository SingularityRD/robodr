#!/usr/bin/env python3
"""Convert `cargo metadata --format-version 1` JSON into a CycloneDX 1.5 JSON SBOM.

Fallback SBOM generator for hosts without cargo-cyclonedx (air-gapped build
hosts, the dev sandbox). Python 3.11+ standard library only.

    cargo metadata --format-version 1 --locked > meta.json
    python3 scripts/metadata_to_cyclonedx.py meta.json --lockfile Cargo.lock > robodr.cdx.json
    python3 scripts/metadata_to_cyclonedx.py --check robodr.cdx.json
    python3 scripts/metadata_to_cyclonedx.py --self-test

Release SBOMs (.github/workflows/release.yml) also go through --augment, which
adds what cargo's view misses, to any CycloneDX >= 1.5 JSON (cargo-cyclonedx's
too), in place:

    python3 scripts/metadata_to_cyclonedx.py --augment dist/sbom/*.cdx.json \
        --rustc-vv rustc-vV.txt --target aarch64-unknown-linux-musl \
        --self-contained-dir "$(rustc --print sysroot)/lib/rustlib/<triple>/lib/self-contained" \
        [--ebpf-dir target/release/build --ebpf-version 0.11.0] --tool clang=18.1.3 ...
    python3 scripts/metadata_to_cyclonedx.py --check X.cdx.json --require-complete

  * Rust's std, core and alloc (the pinned toolchain's release and commit),
    statically linked into every binary;
  * musl targets: musl (version read from rust-std's libc.a) and LLVM's
    libunwind, with the SHA-256 of the archives that were linked;
  * eBPF objects embedded in robodr-pulsard (*.bpf.o under --ebpf-dir), with
    SHA-256 and GPL-2.0-only;
  * `formulation`: rustc (release, commit, host, LLVM) and every --tool.
--require-complete makes --check refuse a BOM without them (the publish gate).

What it records, per resolved package: name, version, purl, SPDX license
expression (or the raw string as a named license when the string is not a
syntactically valid SPDX expression), the crates.io SHA-256 checksum from
Cargo.lock (when --lockfile is given), the source kind and repository URL, and
the dependency graph from cargo's resolver.

Design choices:
  * Deterministic: the same inputs give byte-identical output. No wall-clock
    timestamp unless SOURCE_DATE_EPOCH is set; serialNumber is a UUIDv5 of the
    content; components and edges are sorted; no absolute build paths (path
    crates are recorded relative to the workspace root).
  * Shipped graph only by default: packages reachable from the workspace
    members solely through dev-dependencies are dropped (--include-dev keeps
    them). Build-dependencies are kept: they are part of the build supply chain.

Limits (honest): the SPDX check is syntactic, not against the SPDX license
list; `cargo metadata` resolves for all targets/features unless filtered by the
caller (`--filter-platform`, feature flags), so the SBOM can be a superset of
what a given binary links; it does not hash the built artefacts themselves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

SPEC_VERSION = "1.5"
TOOL_NAME = "robodr-metadata-to-cyclonedx"
TOOL_VERSION = "1.0.0"
CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}

# --------------------------------------------------------------------------
# SPDX expression syntax check (SPDX 2.3 Annex D grammar, syntax only).
# --------------------------------------------------------------------------
_ID = re.compile(r"^(?:DocumentRef-[A-Za-z0-9.\-]+:)?[A-Za-z0-9.\-]+\+?$")
_OPS = {"AND", "OR", "WITH"}


def _tokenize(expr: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", expr)


def normalize_spdx(expr: str | None) -> str | None:
    """Return a valid SPDX expression for `expr`, or None if it is not one.

    Accepts cargo's legacy `MIT/Apache-2.0` form (rewritten to `OR`).
    """
    if not expr or not isinstance(expr, str):
        return None
    expr = expr.strip()
    if "/" in expr and not any(t in _OPS for t in _tokenize(expr)):
        expr = " OR ".join(p.strip() for p in expr.split("/"))
    toks = _tokenize(expr)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def ident(allow_plus: bool) -> bool:
        nonlocal pos
        t = peek()
        if t is None or t in _OPS or t in "()" or not _ID.match(t):
            return False
        if not allow_plus and t.endswith("+"):
            return False
        pos += 1
        return True

    def atom() -> bool:
        nonlocal pos
        if peek() == "(":
            pos += 1
            if not or_expr() or peek() != ")":
                return False
            pos += 1
            return True
        if not ident(allow_plus=True):
            return False
        if peek() == "WITH":
            pos += 1
            return ident(allow_plus=False)
        return True

    def and_expr() -> bool:
        nonlocal pos
        if not atom():
            return False
        while peek() == "AND":
            pos += 1
            if not atom():
                return False
        return True

    def or_expr() -> bool:
        nonlocal pos
        if not and_expr():
            return False
        while peek() == "OR":
            pos += 1
            if not and_expr():
                return False
        return True

    if not toks or len(toks) > 512:
        return None
    try:
        ok = or_expr() and pos == len(toks)
    except RecursionError:
        return None
    return " ".join(toks).replace("( ", "(").replace(" )", ")") if ok else None


# --------------------------------------------------------------------------
# Conversion
# --------------------------------------------------------------------------
def _lock_checksums(lock: dict | None) -> dict[tuple[str, str, str], str]:
    out: dict[tuple[str, str, str], str] = {}
    for p in (lock or {}).get("package", []) or []:
        if isinstance(p, dict) and p.get("checksum") and p.get("source"):
            out[(p.get("name"), p.get("version"), p["source"])] = p["checksum"]
    return out


def _purl(pkg: dict, root: str) -> str:
    name = quote(str(pkg.get("name", "")), safe="")
    ver = quote(str(pkg.get("version", "")), safe="")
    base = f"pkg:cargo/{name}@{ver}"
    src = pkg.get("source")
    if src is None:
        rel = _rel_dir(pkg, root)
        return f"{base}?download_url={quote('file:' + rel, safe=':/')}"
    if src in CRATES_IO_SOURCES:
        return base
    if src.startswith("git+"):
        url = src[len("git+") :]
        url, _, commit = url.partition("#")
        url = url.split("?", 1)[0]
        q = quote(f"git+{url}" + (f"@{commit}" if commit else ""), safe=":/@")
        return f"{base}?vcs_url={q}"
    reg = src.split("+", 1)[-1]
    return f"{base}?repository_url={quote(reg, safe=':/')}"


def _rel_dir(pkg: dict, root: str) -> str:
    mp = pkg.get("manifest_path") or ""
    d = os.path.dirname(mp)
    if root and d:
        try:
            rel = os.path.relpath(d, root)
        except ValueError:
            rel = os.path.basename(d)
        if not rel.startswith(".."):
            return rel.replace(os.sep, "/")
    return os.path.basename(d) or str(pkg.get("name", ""))


def _licenses(pkg: dict) -> list[dict]:
    raw = pkg.get("license")
    if raw:
        norm = normalize_spdx(raw)
        if norm:
            return [{"expression": norm}]
        return [{"license": {"name": str(raw)}}]
    if pkg.get("license_file"):
        return [{"license": {"name": f"see license file: {os.path.basename(pkg['license_file'])}"}}]
    return []


def _reachable(members: list[str], nodes: dict[str, dict], include_dev: bool) -> set[str]:
    seen = set(members)
    stack = list(members)
    while stack:
        cur = stack.pop()
        for d in (nodes.get(cur) or {}).get("deps", []) or []:
            kinds = [k.get("kind") for k in d.get("dep_kinds", []) or [{"kind": None}]]
            if not include_dev and kinds and all(k == "dev" for k in kinds):
                continue
            pid = d.get("pkg")
            if pid and pid not in seen:
                seen.add(pid)
                stack.append(pid)
    return seen


def convert(
    metadata: dict,
    lock: dict | None = None,
    include_dev: bool = False,
    root_name: str | None = None,
    root_version: str | None = None,
    source_date_epoch: str | None = None,
) -> dict:
    if not isinstance(metadata, dict) or not isinstance(metadata.get("packages"), list):
        raise ValueError("not cargo metadata: missing 'packages' list")
    root = metadata.get("workspace_root") or ""
    pkgs = {p["id"]: p for p in metadata["packages"] if isinstance(p, dict) and "id" in p}
    members = [m for m in metadata.get("workspace_members", []) if m in pkgs]
    resolve = metadata.get("resolve") or {}
    nodes = {n["id"]: n for n in resolve.get("nodes", []) or [] if isinstance(n, dict) and "id" in n}
    keep = _reachable(members, nodes, include_dev) if nodes else set(pkgs)
    sums = _lock_checksums(lock)

    ref_of: dict[str, str] = {}
    used: set[str] = set()
    for pid in sorted(keep):
        p = pkgs.get(pid)
        if p is None:
            continue
        ref = _purl(p, root)
        n = 2
        while ref in used:  # same name@version from two sources
            ref = f"{_purl(p, root)}#{n}"
            n += 1
        used.add(ref)
        ref_of[pid] = ref

    components = []
    for pid, ref in ref_of.items():
        p = pkgs[pid]
        is_member = pid in members
        has_bin = any("bin" in (t.get("kind") or []) for t in p.get("targets", []) or [])
        c: dict = {
            "type": "application" if is_member and has_bin else "library",
            "bom-ref": ref,
            "name": str(p.get("name", "")),
            "version": str(p.get("version", "")),
            "scope": "required",
            "purl": ref.split("#", 1)[0],
        }
        if p.get("description"):
            c["description"] = " ".join(str(p["description"]).split())
        lic = _licenses(p)
        if lic:
            c["licenses"] = lic
        src = p.get("source")
        ck = sums.get((p.get("name"), p.get("version"), src)) if src else None
        if ck and re.fullmatch(r"[0-9a-fA-F]{64}", ck):
            c["hashes"] = [{"alg": "SHA-256", "content": ck.lower()}]
        refs = []
        if p.get("repository"):
            refs.append({"type": "vcs", "url": str(p["repository"])})
        if refs:
            c["externalReferences"] = refs
        props = [
            {"name": "robodr:cargo:source", "value": src if src else "path"},
            {"name": "robodr:cargo:workspace-member", "value": "true" if is_member else "false"},
        ]
        if not src:
            props.append({"name": "robodr:cargo:path", "value": _rel_dir(p, root)})
        c["properties"] = props
        components.append(c)
    components.sort(key=lambda c: c["bom-ref"])

    deps = []
    for pid, ref in ref_of.items():
        node = nodes.get(pid)
        if node is None:
            continue
        on = sorted({ref_of[d["pkg"]] for d in node.get("deps", []) or [] if d.get("pkg") in ref_of})
        deps.append({"ref": ref, "dependsOn": on})
    deps.sort(key=lambda d: d["ref"])

    member_versions = sorted({str(pkgs[m].get("version", "")) for m in members})
    name = root_name or (os.path.basename(root.rstrip("/")) if root else "workspace")
    version = root_version or (member_versions[0] if len(member_versions) == 1 else "0.0.0")
    root_ref = f"pkg:cargo/{quote(name, safe='')}@{quote(version, safe='')}?type=workspace"
    deps.insert(0, {"ref": root_ref, "dependsOn": sorted(ref_of[m] for m in members)})

    meta: dict = {
        "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}]},
        "component": {"type": "application", "bom-ref": root_ref, "name": name, "version": version},
    }
    if source_date_epoch:
        ts = datetime.fromtimestamp(int(source_date_epoch), tz=timezone.utc)
        meta["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    body = {"metadata": meta, "components": components, "dependencies": deps}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'robodr-sbom:' + digest)}",
        "version": 1,
        **body,
    }


# --------------------------------------------------------------------------
# Minimal structural check of a CycloneDX JSON BOM (any producer).
# --------------------------------------------------------------------------
def check_bom(bom) -> list[str]:
    errs: list[str] = []
    if not isinstance(bom, dict):
        return ["BOM is not a JSON object"]
    if bom.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat must be 'CycloneDX'")
    if not re.fullmatch(r"1\.[0-9]+", str(bom.get("specVersion", ""))):
        errs.append("specVersion missing or not 1.x")
    sn = bom.get("serialNumber")
    if sn is not None and not re.fullmatch(r"urn:uuid:[0-9a-f\-]{36}", str(sn)):
        errs.append(f"serialNumber not a urn:uuid: {sn!r}")
    comps = bom.get("components", [])
    if not isinstance(comps, list):
        return errs + ["components is not a list"]
    refs: set[str] = set()
    mc = (bom.get("metadata") or {}).get("component") or {}
    if mc.get("bom-ref"):
        refs.add(mc["bom-ref"])

    def walk(cs, path):
        for i, c in enumerate(cs):
            where = f"{path}[{i}]"
            if not isinstance(c, dict):
                errs.append(f"{where}: not an object")
                continue
            for k in ("type", "name"):
                if not c.get(k):
                    errs.append(f"{where}: missing {k}")
            r = c.get("bom-ref")
            if r is not None:
                if r in refs:
                    errs.append(f"{where}: duplicate bom-ref {r!r}")
                refs.add(r)
            for h in c.get("hashes", []) or []:
                if h.get("alg") == "SHA-256" and not re.fullmatch(r"[0-9a-f]{64}", str(h.get("content", ""))):
                    errs.append(f"{where}: bad SHA-256 {h.get('content')!r}")
            walk(c.get("components", []) or [], where + ".components")

    walk(comps, "components")
    for d in bom.get("dependencies", []) or []:
        if d.get("ref") not in refs:
            errs.append(f"dependencies: unknown ref {d.get('ref')!r}")
        for o in d.get("dependsOn", []) or []:
            if o not in refs:
                errs.append(f"dependencies[{d.get('ref')}]: unknown dependsOn {o!r}")
    return errs


def check_against_lock(bom, lock: dict) -> list[str]:
    """Cross-check a BOM against Cargo.lock.

    Every component must be a package (name + version) recorded in the lock,
    and every SHA-256 the BOM states must equal the lock's checksum for it.
    Lock packages absent from the BOM are not errors (dev-only dependencies
    are omitted by design).
    """
    errs: list[str] = []
    if not isinstance(bom, dict):
        return ["BOM is not a JSON object"]
    by_nv: dict[tuple[str, str], set[str]] = {}
    for p in (lock or {}).get("package", []) or []:
        if isinstance(p, dict):
            key = (str(p.get("name")), str(p.get("version")))
            by_nv.setdefault(key, set())
            if p.get("checksum"):
                by_nv[key].add(str(p["checksum"]).lower())

    def walk(cs):
        for c in cs or []:
            if not isinstance(c, dict):
                continue
            if any(p.get("name") == "robodr:sbom:augmented" for p in c.get("properties", []) or []):
                continue  # not a crate: Rust std, musl, eBPF objects (augment)
            key = (str(c.get("name")), str(c.get("version")))
            if key not in by_nv:
                errs.append(f"component {key[0]}@{key[1]} is not in Cargo.lock")
            else:
                for h in c.get("hashes", []) or []:
                    if h.get("alg") == "SHA-256":
                        got = str(h.get("content", "")).lower()
                        if got not in by_nv[key]:
                            errs.append(f"component {key[0]}@{key[1]}: SHA-256 {got} != Cargo.lock checksum")
            walk(c.get("components"))

    walk(bom.get("components"))
    return errs


# --------------------------------------------------------------------------
# Augmenting a BOM with what cargo does not see (release SBOMs).
# --------------------------------------------------------------------------
RUST_STD_LIBS = ("std", "core", "alloc")
RUST_LICENSE = "MIT OR Apache-2.0"
# vendor/pulsar/LICENSE: "Pulsar eBPF probes are provided under the GPL-2.0 license".
EBPF_LICENSE = "GPL-2.0-only"
MUSL_LICENSE = "MIT"
LIBUNWIND_LICENSE = "Apache-2.0 WITH LLVM-exception"
ROLE_PROP = "robodr:sbom:augmented"
MAX_AR_MEMBER = 1 << 20


def parse_rustc_vv(text: str) -> dict[str, str]:
    """`rustc -vV` output -> {release, commit-hash, host, LLVM version, ...}."""
    out: dict[str, str] = {}
    for ln in text.splitlines():
        if ": " in ln:
            k, v = ln.split(": ", 1)
            out[k.strip()] = v.strip()
    for k in ("release", "commit-hash", "host"):
        if not out.get(k):
            raise ValueError(f"rustc -vV output has no '{k}:' line")
    return out


def ar_member(data: bytes, name: str) -> bytes | None:
    """One member of a System V / GNU `ar` archive (short names only)."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    pos = 8
    while pos + 60 <= len(data):
        hdr = data[pos : pos + 60]
        try:
            size = int(hdr[48:58].decode("ascii").strip())
        except ValueError:
            raise ValueError("ar archive: bad member header") from None
        if size < 0 or pos + 60 + size > len(data):
            raise ValueError("ar archive: truncated member")
        member = hdr[:16].decode("ascii", "replace").strip().rstrip("/")
        if member == name:
            return data[pos + 60 : pos + 60 + min(size, MAX_AR_MEMBER)]
        pos += 60 + size + (size & 1)
    return None


def musl_version(libc_a: bytes) -> str:
    """musl's version string, from the version.lo member of its libc.a."""
    m = ar_member(libc_a, "version.lo")
    found = sorted(set(re.findall(rb"(?<![0-9.])1\.[0-9]{1,2}\.[0-9]{1,2}(?![0-9.])", m or b"")))
    if len(found) != 1:
        raise ValueError(f"cannot tell musl's version from libc.a (version.lo: {found})")
    return found[0].decode()


def _prop(name: str, value: str) -> dict:
    return {"name": name, "value": value}


def _sha(b: bytes) -> list[dict]:
    return [{"alg": "SHA-256", "content": hashlib.sha256(b).hexdigest()}]


def augment(
    bom: dict,
    rustc: dict[str, str],
    target: str,
    self_contained: dict[str, bytes] | None = None,
    ebpf: list[tuple[str, bytes]] | None = None,
    ebpf_version: str | None = None,
    tools: list[tuple[str, str]] | None = None,
) -> dict:
    """Add the components a cargo-based SBOM misses, and the toolchain.

    * Rust's standard library (std, core, alloc) of the pinned toolchain,
      statically linked into every binary.
    * For a musl target: musl's libc.a and LLVM's libunwind.a from rust-std's
      self-contained directory (`self_contained`: file name -> bytes), with
      their SHA-256 and versions (musl's read from libc.a itself, libunwind's
      = rustc's LLVM).
    * eBPF objects (`ebpf`: (relative path, bytes)) embedded in
      robodr-pulsard: GPL-2.0-only, with their SHA-256.
    * `formulation`: rustc (release, commit, host, LLVM) and every `tools`
      entry (name, version): how the artefact was built.
    Every added component becomes a dependency of the BOM's root component.
    Refuses (ValueError) a BOM below CycloneDX 1.5 (no formulation) or one
    that is already augmented.
    """
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX BOM")
    try:
        major, minor = (int(x) for x in str(bom.get("specVersion", "")).split("."))
    except ValueError:
        raise ValueError(f"bad specVersion {bom.get('specVersion')!r}") from None
    if (major, minor) < (1, 5):
        raise ValueError(
            f"specVersion {major}.{minor} < 1.5 (no formulation): generate 1.5 (cargo cyclonedx --spec-version 1.5)"
        )
    if bom.get("formulation") or any(
        isinstance(c, dict) and any(p.get("name") == ROLE_PROP for p in c.get("properties", []) or [])
        for c in bom.get("components", []) or []
    ):
        raise ValueError("BOM is already augmented")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", target):
        raise ValueError(f"bad target triple {target!r}")
    ver = rustc["release"]
    added: list[dict] = []
    for lib in RUST_STD_LIBS:
        added.append(
            {
                "type": "library",
                "bom-ref": f"pkg:generic/rust-lang/{lib}@{ver}?target={target}",
                "supplier": {"name": "The Rust Project"},
                "name": lib,
                "version": ver,
                "scope": "required",
                "purl": f"pkg:generic/rust-lang/{lib}@{ver}",
                "licenses": [{"expression": RUST_LICENSE}],
                "properties": [
                    _prop(ROLE_PROP, "rust-std"),
                    _prop("robodr:rust:commit-hash", rustc["commit-hash"]),
                    _prop("robodr:rust:target", target),
                    _prop("robodr:linkage", "static"),
                ],
            }
        )
    if target.endswith("-musl"):
        sc = self_contained or {}
        for f in ("libc.a", "libunwind.a"):
            if f not in sc:
                raise ValueError(f"musl target {target}: rust-std self-contained {f} not given")
        llvm = rustc.get("LLVM version")
        if not llvm:
            raise ValueError("rustc -vV has no 'LLVM version:' line (libunwind's version)")
        for name, version, lic, f, sup in (
            ("musl", musl_version(sc["libc.a"]), MUSL_LICENSE, "libc.a", "musl libc"),
            ("libunwind", llvm, LIBUNWIND_LICENSE, "libunwind.a", "LLVM Project"),
        ):
            added.append(
                {
                    "type": "library",
                    "bom-ref": f"pkg:generic/{name}@{version}?target={target}",
                    "supplier": {"name": sup},
                    "name": name,
                    "version": version,
                    "scope": "required",
                    "purl": f"pkg:generic/{name}@{version}",
                    "hashes": _sha(sc[f]),
                    "licenses": [{"expression": lic}],
                    "properties": [
                        _prop(ROLE_PROP, "rust-std-self-contained"),
                        _prop("robodr:file", f"lib/rustlib/{target}/lib/self-contained/{f}"),
                        _prop("robodr:linkage", "static"),
                    ],
                }
            )
    for rel, data in sorted(ebpf or []):
        if not isinstance(ebpf_version, str) or not re.fullmatch(r"[0-9A-Za-z.+-]{1,64}", ebpf_version):
            raise ValueError(f"eBPF objects need an eBPF (Pulsar) version, got {ebpf_version!r}")
        if not re.fullmatch(r"[A-Za-z0-9_./+-]{1,256}", rel) or ".." in rel.split("/") or rel.startswith("/"):
            raise ValueError(f"bad eBPF object path {rel!r}")
        added.append(
            {
                "type": "file",
                "bom-ref": f"file:ebpf/{rel}",
                "name": rel.rsplit("/", 1)[-1],
                "version": ebpf_version,
                "scope": "required",
                "hashes": _sha(data),
                "licenses": [{"expression": EBPF_LICENSE}],
                "properties": [
                    _prop(ROLE_PROP, "ebpf-object"),
                    _prop("robodr:ebpf:path", rel),
                    _prop("robodr:linkage", "embedded in robodr-pulsard (include_bytes)"),
                ],
            }
        )
    tool_comps = [
        {
            "type": "application",
            "bom-ref": f"formulation:tool:rustc@{ver}",
            "name": "rustc",
            "version": ver,
            "properties": [
                _prop("robodr:rust:commit-hash", rustc["commit-hash"]),
                _prop("robodr:rust:host", rustc["host"]),
                _prop("robodr:rust:llvm", rustc.get("LLVM version", "")),
            ],
        }
    ]
    for name, version in sorted(tools or []):
        if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", name or "") or not version or len(version) > 200:
            raise ValueError(f"bad tool {name!r}={version!r}")
        tool_comps.append(
            {"type": "application", "bom-ref": f"formulation:tool:{name}", "name": name, "version": version}
        )
    out = json.loads(json.dumps(bom))
    out.setdefault("components", []).extend(added)
    out["formulation"] = [
        {
            "bom-ref": "formulation:robodr-release-build",
            "components": tool_comps,
            "properties": [_prop("robodr:build:target", target)],
        }
    ]
    root = ((out.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if root:
        deps = out.setdefault("dependencies", [])
        entry = next((d for d in deps if isinstance(d, dict) and d.get("ref") == root), None)
        if entry is None:
            entry = {"ref": root, "dependsOn": []}
            deps.insert(0, entry)
        entry["dependsOn"] = sorted(set(entry.get("dependsOn", []) or []) | {c["bom-ref"] for c in added})
    return out


def check_complete(bom) -> list[str]:
    """What a release SBOM must contain beyond cargo's view (see augment)."""
    errs: list[str] = []
    if not isinstance(bom, dict):
        return ["BOM is not a JSON object"]
    try:
        if tuple(int(x) for x in str(bom.get("specVersion", "")).split(".")) < (1, 5):
            errs.append(f"specVersion {bom.get('specVersion')} < 1.5")
    except ValueError:
        errs.append(f"bad specVersion {bom.get('specVersion')!r}")
    roles: dict[str, list[dict]] = {}
    for c in bom.get("components", []) or []:
        if not isinstance(c, dict):
            continue
        for p in c.get("properties", []) or []:
            if p.get("name") == ROLE_PROP:
                roles.setdefault(p.get("value"), []).append(c)
    if sorted(str(c.get("name")) for c in roles.get("rust-std", [])) != sorted(RUST_STD_LIBS):
        errs.append("Rust std/core/alloc components missing (not augmented)")
    targets = {
        p.get("value")
        for c in roles.get("rust-std", [])
        for p in c.get("properties", []) or []
        if p.get("name") == "robodr:rust:target"
    }
    if any(str(t).endswith("-musl") for t in targets) and sorted(
        str(c.get("name")) for c in roles.get("rust-std-self-contained", [])
    ) != ["libunwind", "musl"]:
        errs.append("musl target without musl and libunwind components")
    for c in roles.get("rust-std-self-contained", []) + roles.get("ebpf-object", []):
        if not any(h.get("alg") == "SHA-256" for h in c.get("hashes", []) or []):
            errs.append(f"{c.get('name')}: no SHA-256")
    form = bom.get("formulation")
    if not (
        isinstance(form, list)
        and any(
            isinstance(f, dict) and any(c.get("name") == "rustc" for c in f.get("components", []) or [])
            for f in form
        )
    ):
        errs.append("formulation (toolchain) missing")
    return errs


def augment_main(a) -> int:
    """--augment: rewrite BOM files in place (each one: read, augment, write)."""
    try:
        rustc = parse_rustc_vv(open(a.rustc_vv, encoding="utf-8").read())
        sc: dict[str, bytes] = {}
        if a.target.endswith("-musl"):
            d = a.self_contained_dir
            if not d:
                raise ValueError("musl target: --self-contained-dir is required")
            for f in ("libc.a", "libunwind.a"):
                with open(os.path.join(d, f), "rb") as fh:
                    sc[f] = fh.read()
        ebpf: list[tuple[str, bytes]] = []
        for d in a.ebpf_dir or []:
            for dirpath, _dirs, files in os.walk(d):
                for f in files:
                    if f.endswith(".bpf.o"):
                        p = os.path.join(dirpath, f)
                        with open(p, "rb") as fh:
                            ebpf.append((os.path.relpath(p, d).replace(os.sep, "/"), fh.read()))
        if a.ebpf_dir and not ebpf:
            raise ValueError(f"no *.bpf.o under {a.ebpf_dir}")
        tools = []
        for t in a.tool or []:
            name, sep, version = t.partition("=")
            if not sep:
                raise ValueError(f"--tool {t!r}: want NAME=VERSION")
            tools.append((name, version))
        for path in a.augment:
            with open(path, encoding="utf-8") as fh:
                bom = json.load(fh)
            out = augment(bom, rustc, a.target, sc, ebpf, a.ebpf_version, tools)
            errs = check_bom(out) + check_complete(out)
            if errs:
                raise ValueError(f"{path}: augmented BOM fails its own check: {errs}")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(out, indent=2) + "\n")
            print(f"{path}: augmented (+{len(out['components']) - len(bom.get('components', []) or [])} components, formulation)")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


# --------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("metadata", nargs="?", default="-", help="cargo metadata JSON file, or - for stdin")
    ap.add_argument("--lockfile", help="Cargo.lock to take SHA-256 checksums from")
    ap.add_argument("--include-dev", action="store_true", help="keep dev-only dependencies")
    ap.add_argument("--name", help="root component name (default: workspace dir name)")
    ap.add_argument("--version", dest="root_version", help="root component version")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    ap.add_argument(
        "--check",
        metavar="BOM",
        help="check a CycloneDX JSON file (with --lockfile: cross-check it against Cargo.lock) and exit",
    )
    ap.add_argument(
        "--require-complete",
        action="store_true",
        help="with --check: also require what --augment adds (release SBOMs)",
    )
    ap.add_argument(
        "--augment",
        nargs="+",
        metavar="BOM",
        help="add Rust std, musl/libunwind, eBPF objects and the toolchain to these BOM files (in place)",
    )
    ap.add_argument("--rustc-vv", help="--augment: file with `rustc -vV` of the build")
    ap.add_argument("--target", help="--augment: the Rust target triple of the build")
    ap.add_argument("--self-contained-dir", help="--augment, musl: rust-std's lib/rustlib/<triple>/lib/self-contained")
    ap.add_argument("--ebpf-dir", action="append", help="--augment: directory searched for *.bpf.o (repeatable)")
    ap.add_argument("--ebpf-version", help="--augment: version of the eBPF objects (Pulsar's)")
    ap.add_argument("--tool", action="append", help="--augment: NAME=VERSION of a build tool (repeatable)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)

    if a.self_test:
        return _self_test()
    if a.augment:
        if not (a.rustc_vv and a.target):
            ap.error("--augment needs --rustc-vv and --target")
        return augment_main(a)
    if a.check:
        try:
            with open(a.check, encoding="utf-8") as f:
                bom = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: {a.check}: {e}", file=sys.stderr)
            return 1
        errs = check_bom(bom)
        if a.require_complete:
            errs += check_complete(bom)
        if a.lockfile:
            try:
                with open(a.lockfile, "rb") as f:
                    errs += check_against_lock(bom, tomllib.load(f))
            except (OSError, tomllib.TOMLDecodeError) as e:
                errs.append(f"cannot read {a.lockfile}: {e}")
        for e in errs:
            print(f"{a.check}: {e}", file=sys.stderr)
        if not errs:
            print(f"{a.check}: OK ({len(bom.get('components', []))} components)")
        return 1 if errs else 0

    try:
        if a.metadata == "-":
            metadata = json.load(sys.stdin)
        else:
            with open(a.metadata, encoding="utf-8") as f:
                metadata = json.load(f)
        lock = None
        if a.lockfile:
            with open(a.lockfile, "rb") as f:
                lock = tomllib.load(f)
        bom = convert(
            metadata,
            lock=lock,
            include_dev=a.include_dev,
            root_name=a.name,
            root_version=a.root_version,
            source_date_epoch=os.environ.get("SOURCE_DATE_EPOCH") or None,
        )
    except (OSError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    text = json.dumps(bom, indent=2, sort_keys=False) + "\n"
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


def _fixture() -> dict:
    W = "/build/robodr"
    CIO = "registry+https://github.com/rust-lang/crates.io-index"

    def pkg(pid, name, ver, src, lic, manifest=None, bins=False, **extra):
        p = {
            "id": pid,
            "name": name,
            "version": ver,
            "source": src,
            "license": lic,
            "license_file": None,
            "manifest_path": manifest or f"/reg/{name}/Cargo.toml",
            "targets": [{"kind": ["bin" if bins else "lib"]}],
            "repository": None,
            "description": None,
        }
        p.update(extra)
        return p

    ev = f"path+file://{W}/crates/robodr-events#robodr-events@0.1.0"
    cm = f"path+file://{W}/crates/robodr-commission#robodr-commission@0.1.0"
    pc = f"path+file://{W}/vendor/pulsar/crates/pulsar-core#0.11.0"
    se = f"{CIO}#serde@1.0.219"
    dv = f"{CIO}#proptest@1.0.0"
    gi = "git+https://example.com/g.git?rev=abc#abcdef0123"
    return {
        "workspace_root": W,
        "workspace_members": [ev, cm],
        "packages": [
            pkg(
                ev,
                "robodr-events",
                "0.1.0",
                None,
                "Apache-2.0",
                f"{W}/crates/robodr-events/Cargo.toml",
                description="Pure\n  events",
                repository="https://github.com/SingularityRD/robodr",
            ),
            pkg(
                cm,
                "robodr-commission",
                "0.1.0",
                None,
                "Apache-2.0",
                f"{W}/crates/robodr-commission/Cargo.toml",
                bins=True,
            ),
            pkg(
                pc,
                "pulsar-core",
                "0.11.0",
                None,
                "Apache-2.0 WITH BPF probes exception under GPL-2.0",
                f"{W}/vendor/pulsar/crates/pulsar-core/Cargo.toml",
            ),
            pkg(se, "serde", "1.0.219", CIO, "MIT/Apache-2.0"),
            pkg(dv, "proptest", "1.0.0", CIO, "MIT OR Apache-2.0"),
            pkg(
                gi,
                "g",
                "0.1.0",
                "git+https://example.com/g.git?rev=abc#abcdef0123",
                None,
                license_file="/reg/g/LICENSE",
            ),
        ],
        "resolve": {
            "nodes": [
                {
                    "id": ev,
                    "deps": [
                        {"pkg": se, "dep_kinds": [{"kind": None}]},
                        {"pkg": dv, "dep_kinds": [{"kind": "dev"}]},
                    ],
                },
                {
                    "id": cm,
                    "deps": [
                        {"pkg": ev, "dep_kinds": [{"kind": None}]},
                        {"pkg": pc, "dep_kinds": [{"kind": None}]},
                        {"pkg": gi, "dep_kinds": [{"kind": "build"}]},
                    ],
                },
                {"id": pc, "deps": [{"pkg": se, "dep_kinds": [{"kind": None}]}]},
                {"id": se, "deps": []},
                {"id": dv, "deps": [{"pkg": se, "dep_kinds": [{"kind": None}]}]},
                {"id": gi, "deps": []},
            ]
        },
    }


def _self_test() -> int:
    import copy
    import unittest

    lock = tomllib.loads(
        '[[package]]\nname = "serde"\nversion = "1.0.219"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "5F0E2C6ED6606019B4E29E69DBABA95B11854410E5347D525002456DBBB786B6"\n'
    )

    class Spdx(unittest.TestCase):
        def test_valid(self):
            for e in [
                "MIT",
                "Apache-2.0",
                "MIT OR Apache-2.0",
                "(MIT OR Apache-2.0) AND BSD-3-Clause",
                "GPL-2.0-or-later WITH Classpath-exception-2.0",
                "GPL-2.0+",
                "LicenseRef-foo",
                "DocumentRef-x:LicenseRef-y",
                "Apache-2.0 WITH LLVM-exception OR MIT",
            ]:
                self.assertIsNotNone(normalize_spdx(e), e)

        def test_slash_legacy(self):
            self.assertEqual(normalize_spdx("MIT/Apache-2.0"), "MIT OR Apache-2.0")

        def test_invalid(self):
            for e in [
                "Apache-2.0 WITH BPF probes exception under GPL-2.0",
                "",
                None,
                "MIT OR",
                "(MIT",
                "MIT)",
                "AND MIT",
                "MIT WITH",
                "MIT WITH X+",
                "MIT AND AND GPL-2.0",
                "M!T",
                "()",
                "(" * 600 + "MIT" + ")" * 600,
                42,
            ]:
                self.assertIsNone(normalize_spdx(e), repr(e)[:40])

        def test_parens_normalized(self):
            self.assertEqual(normalize_spdx("( MIT  OR Apache-2.0 )"), "(MIT OR Apache-2.0)")

    class Convert(unittest.TestCase):
        def bom(self, **kw):
            return convert(_fixture(), lock=lock, **kw)

        def comp(self, bom, name):
            return next(c for c in bom["components"] if c["name"] == name)

        def test_structure_valid(self):
            b = self.bom()
            self.assertEqual(check_bom(b), [])
            self.assertEqual(b["specVersion"], "1.5")
            self.assertNotIn("timestamp", b["metadata"])

        def test_dev_only_dropped_by_default(self):
            names = {c["name"] for c in self.bom()["components"]}
            self.assertNotIn("proptest", names)
            self.assertIn("g", names)  # build-dep kept
            names = {c["name"] for c in self.bom(include_dev=True)["components"]}
            self.assertIn("proptest", names)

        def test_licenses(self):
            b = self.bom()
            self.assertEqual(self.comp(b, "serde")["licenses"], [{"expression": "MIT OR Apache-2.0"}])
            self.assertEqual(
                self.comp(b, "pulsar-core")["licenses"][0]["license"]["name"],
                "Apache-2.0 WITH BPF probes exception under GPL-2.0",
            )
            self.assertIn("LICENSE", self.comp(b, "g")["licenses"][0]["license"]["name"])

        def test_hash_from_lock_lowercased(self):
            h = self.comp(self.bom(), "serde")["hashes"][0]
            self.assertEqual(h["alg"], "SHA-256")
            self.assertEqual(h["content"], h["content"].lower())
            self.assertNotIn("hashes", self.comp(convert(_fixture()), "serde"))

        def test_purls_and_no_abs_paths(self):
            b = self.bom()
            self.assertEqual(self.comp(b, "serde")["purl"], "pkg:cargo/serde@1.0.219")
            self.assertIn("vcs_url=git%2Bhttps://example.com/g.git@abcdef0123", self.comp(b, "g")["purl"])
            self.assertIn("file:crates/robodr-events", self.comp(b, "robodr-events")["purl"])
            self.assertNotIn("/build/robodr", json.dumps(b))

        def test_app_type_and_root(self):
            b = self.bom()
            self.assertEqual(self.comp(b, "robodr-commission")["type"], "application")
            self.assertEqual(self.comp(b, "robodr-events")["type"], "library")
            self.assertEqual(b["metadata"]["component"]["name"], "robodr")
            self.assertEqual(b["metadata"]["component"]["version"], "0.1.0")
            root = b["dependencies"][0]
            self.assertEqual(len(root["dependsOn"]), 2)

        def test_description_whitespace(self):
            self.assertEqual(self.comp(self.bom(), "robodr-events")["description"], "Pure events")

        def test_deterministic(self):
            a = json.dumps(self.bom())
            m = _fixture()
            m["packages"].reverse()
            m["resolve"]["nodes"].reverse()
            self.assertEqual(a, json.dumps(convert(m, lock=lock)))

        def test_source_date_epoch(self):
            b = self.bom(source_date_epoch="1700000000")
            self.assertEqual(b["metadata"]["timestamp"], "2023-11-14T22:13:20Z")
            self.assertNotEqual(b["serialNumber"], self.bom()["serialNumber"])

        def test_no_resolve_keeps_all(self):
            m = _fixture()
            m["resolve"] = None
            b = convert(m)
            self.assertEqual(len(b["components"]), 6)
            self.assertEqual(check_bom(b), [])

        def test_duplicate_name_version(self):
            m = _fixture()
            extra = copy.deepcopy(m["packages"][3])
            extra["id"] = "other#serde@1.0.219"
            m["packages"].append(extra)
            m["resolve"]["nodes"].append({"id": extra["id"], "deps": []})
            m["resolve"]["nodes"][0]["deps"].append({"pkg": extra["id"], "dep_kinds": [{"kind": None}]})
            b = convert(m)
            self.assertEqual(check_bom(b), [])
            self.assertEqual(sum(c["name"] == "serde" for c in b["components"]), 2)

        def test_hostile_input(self):
            for bad in [None, [], {}, {"packages": "x"}, "str"]:
                with self.assertRaises(ValueError):
                    convert(bad)
            m = {
                "packages": [{"id": "a", "name": "a", "version": "1"}, 7],
                "workspace_members": ["a", "zz"],
                "resolve": {"nodes": [{"id": "a", "deps": [{"pkg": "missing"}]}, "junk"]},
            }
            self.assertEqual(check_bom(convert(m)), [])

    class Check(unittest.TestCase):
        def test_against_lock(self):
            b = convert(_fixture(), lock=lock)
            full = tomllib.loads(
                "".join(
                    f'[[package]]\nname = "{c["name"]}"\nversion = "{c["version"]}"\n'
                    for c in b["components"]
                    if c["name"] != "serde"
                )
            )
            full["package"] += lock["package"]
            self.assertEqual(check_against_lock(b, full), [])
            tampered = copy.deepcopy(b)
            self.comp_named(tampered, "serde")["hashes"][0]["content"] = "0" * 64
            self.assertEqual(len(check_against_lock(tampered, full)), 1)
            self.assertEqual(len(check_against_lock(b, lock)), len(b["components"]) - 1)
            self.assertTrue(check_against_lock("x", lock))

        @staticmethod
        def comp_named(bom, name):
            return next(c for c in bom["components"] if c["name"] == name)

        def test_detects_problems(self):
            self.assertTrue(check_bom([]))
            b = convert(_fixture())
            b["components"].append(copy.deepcopy(b["components"][0]))
            self.assertTrue(any("duplicate" in e for e in check_bom(b)))
            b = convert(_fixture())
            b["dependencies"].append({"ref": "nope", "dependsOn": ["nada"]})
            self.assertEqual(len(check_bom(b)), 2)
            b = convert(_fixture())
            b["bomFormat"] = "SPDX"
            b["components"][0]["hashes"] = [{"alg": "SHA-256", "content": "xyz"}]
            self.assertEqual(len(check_bom(b)), 2)

    RUSTC_VV = (
        "rustc 1.98.1 (48a229cea 2026-09-01)\nbinary: rustc\n"
        "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985\ncommit-date: 2026-09-01\n"
        "host: x86_64-unknown-linux-gnu\nrelease: 1.98.1\nLLVM version: 22.1.8\n"
    )

    def ar(members: dict[str, bytes]) -> bytes:
        out = b"!<arch>\n"
        for n, d in members.items():
            hdr = f"{n + '/':<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(d):<10}`\n".encode()
            assert len(hdr) == 60
            out += hdr + d + (b"\n" if len(d) & 1 else b"")
        return out

    LIBC = ar({"abs.lo": b"\x7fELF...", "version.lo": b"\x00\x00musl 1.2.5\x00x"})
    UNWIND = b"!<arch>\nlibunwind"

    class Augment(unittest.TestCase):
        def bom(self):
            return convert(_fixture(), lock=lock)

        def aug(self, target="aarch64-unknown-linux-musl", **kw):
            args = dict(
                self_contained={"libc.a": LIBC, "libunwind.a": UNWIND},
                ebpf=[("bpf-filtering-x/out/probes.acl.bpf.o", b"BPF1"), ("p/out/net.none.bpf.o", b"BPF2")],
                ebpf_version="0.11.0",
                tools=[("cargo-cyclonedx", "0.5.9"), ("clang", "18.1.3")],
            )
            args.update(kw)
            return augment(self.bom(), parse_rustc_vv(RUSTC_VV), target, **args)

        def names(self, b):
            return {c["name"] for c in b["components"]}

        def test_plain_bom_is_not_complete(self):
            # The release gate: a cargo-only SBOM is refused.
            errs = check_complete(self.bom())
            self.assertTrue(any("std" in e for e in errs), errs)
            self.assertTrue(any("formulation" in e for e in errs), errs)

        def test_musl_complete(self):
            b = self.aug()
            self.assertEqual(check_bom(b), [])
            self.assertEqual(check_complete(b), [])
            self.assertTrue({"std", "core", "alloc", "musl", "libunwind"} <= self.names(b))
            musl = next(c for c in b["components"] if c["name"] == "musl")
            self.assertEqual(musl["version"], "1.2.5")
            self.assertEqual(musl["hashes"][0]["content"], hashlib.sha256(LIBC).hexdigest())
            unw = next(c for c in b["components"] if c["name"] == "libunwind")
            self.assertEqual(unw["version"], "22.1.8")
            self.assertEqual(unw["licenses"], [{"expression": "Apache-2.0 WITH LLVM-exception"}])
            tools = {c["name"]: c["version"] for c in b["formulation"][0]["components"]}
            self.assertEqual(tools, {"rustc": "1.98.1", "cargo-cyclonedx": "0.5.9", "clang": "18.1.3"})
            root = b["dependencies"][0]
            self.assertEqual(root["ref"], b["metadata"]["component"]["bom-ref"])
            for c in b["components"]:
                if any(p["name"] == ROLE_PROP for p in c.get("properties", [])):
                    self.assertIn(c["bom-ref"], root["dependsOn"])

        def test_ebpf_objects(self):
            b = self.aug()
            e = [c for c in b["components"] if c["type"] == "file"]
            self.assertEqual(len(e), 2)
            self.assertEqual({c["licenses"][0]["expression"] for c in e}, {"GPL-2.0-only"})
            self.assertIn(hashlib.sha256(b"BPF1").hexdigest(), json.dumps(e))
            with self.assertRaises(ValueError):
                self.aug(ebpf=[("../x.bpf.o", b"x")])
            with self.assertRaises(ValueError):
                self.aug(ebpf_version=None)

        def test_gnu_target_needs_no_musl(self):
            b = self.aug(target="x86_64-unknown-linux-gnu", self_contained=None, ebpf=None)
            self.assertEqual(check_complete(b), [])
            self.assertNotIn("musl", self.names(b))

        def test_refusals(self):
            with self.assertRaises(ValueError):
                self.aug(self_contained={"libc.a": LIBC})  # no libunwind.a
            with self.assertRaises(ValueError):
                self.aug(self_contained={"libc.a": ar({"version.lo": b"1.2.4 1.2.5"}), "libunwind.a": UNWIND})
            old = self.bom()
            old["specVersion"] = "1.3"
            with self.assertRaises(ValueError):
                augment(old, parse_rustc_vv(RUSTC_VV), "x86_64-unknown-linux-gnu")
            twice = self.aug()
            with self.assertRaises(ValueError):
                augment(twice, parse_rustc_vv(RUSTC_VV), "aarch64-unknown-linux-musl")
            with self.assertRaises(ValueError):
                parse_rustc_vv("rustc 1.0\n")
            with self.assertRaises(ValueError):
                ar_member(b"not ar", "x")
            with self.assertRaises(ValueError):
                ar_member(b"!<arch>\n" + b"x" * 48 + b"9999999999" + b"`\n", "x")

        def test_musl_check_needs_libs(self):
            b = self.aug()
            b["components"] = [c for c in b["components"] if c["name"] != "musl"]
            self.assertTrue(check_complete(b))

        def test_lock_check_skips_augmented(self):
            b = self.aug()
            full = tomllib.loads(
                "".join(
                    f'[[package]]\nname = "{c["name"]}"\nversion = "{c["version"]}"\n'
                    for c in convert(_fixture(), lock=lock)["components"]
                    if c["name"] != "serde"
                )
            )
            full["package"] += lock["package"]
            self.assertEqual(check_against_lock(b, full), [])

        def test_cli(self):
            import tempfile

            with tempfile.TemporaryDirectory() as d:
                bp = os.path.join(d, "x.cdx.json")
                with open(bp, "w") as f:
                    json.dump(self.bom(), f)
                rv = os.path.join(d, "rustc-vV")
                with open(rv, "w") as f:
                    f.write(RUSTC_VV)
                sc = os.path.join(d, "sc")
                os.makedirs(os.path.join(d, "bpf", "out"))
                os.makedirs(sc)
                with open(os.path.join(sc, "libc.a"), "wb") as f:
                    f.write(LIBC)
                with open(os.path.join(sc, "libunwind.a"), "wb") as f:
                    f.write(UNWIND)
                with open(os.path.join(d, "bpf", "out", "a.none.bpf.o"), "wb") as f:
                    f.write(b"BPF")
                self.assertEqual(main(["--check", bp, "--require-complete"]), 1)
                base = ["--augment", bp, "--rustc-vv", rv, "--target", "aarch64-unknown-linux-musl"]
                self.assertEqual(main(base), 1)  # musl without --self-contained-dir
                ok = base + ["--self-contained-dir", sc, "--ebpf-dir", os.path.join(d, "bpf"),
                             "--ebpf-version", "0.11.0", "--tool", "clang=18.1.3"]
                self.assertEqual(main(ok), 0)
                self.assertEqual(main(["--check", bp, "--require-complete"]), 0)
                self.assertEqual(main(ok), 1)  # already augmented

    suite = unittest.TestSuite()
    for cls in (Spdx, Convert, Check, Augment):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    r = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if r.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
