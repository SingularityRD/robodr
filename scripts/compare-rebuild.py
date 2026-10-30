#!/usr/bin/env python3
"""Compare a release with its independent rebuild before it is signed.

    scripts/compare-rebuild.py --release DIR --rebuild DIR --version V --out FILE
    scripts/compare-rebuild.py --self-test

release.yml `publish` runs it on the build jobs' assets (--release) and the
rebuild jobs' outputs (--rebuild: PACKAGES-<kind>-<arch>.sha256,
BINARIES-<kind>-<arch>.sha256 and the rebuilt packages and bundles, see
scripts/ci-rebuild.sh), and FAILS (exit 1, nothing is signed) unless:

  * every package (.deb, .rpm) the rebuild made is byte-identical to the
    release asset of the same name;
  * every offline bundle (*-offline.tar.gz) is byte-identical, or differs
    only in its SBOM (sbom/*.cdx.json, cargo-cyclonedx output, and the
    lines naming them in the bundle's SHA256SUMS): same members, modes,
    owners and times, same content otherwise;
  * every program in BINARIES-* equals the program of the same name inside
    the release package of that kind and architecture, except
    robodr-pulsard, whose bit-for-bit reproducibility is not claimed: its
    result (reproduced or not, both hashes) is recorded, never hidden;
  * every kind and architecture the release ships was rebuilt.

It writes FILE (REPRODUCIBILITY-<version>.txt): what was compared and the
result, including robodr-pulsard's. publish signs it with the other assets
and appends it to the release notes.

Exit 0 reproduced, 1 a difference (or a missing rebuild), 2 usage error.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import re
import subprocess
import sys
import tarfile
from pathlib import Path

KINDS = ("deb", "rpm", "focal")
ARCHS = ("amd64", "arm64")
RPM_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}
NOT_CLAIMED = {"robodr-pulsard"}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_sums(path: Path) -> dict[str, str]:
    out = {}
    for ln in path.read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", ln.strip())
        if m:
            out[m.group(2)] = m.group(1)
    return out


def release_package(rel: Path, kind: str, arch: str) -> Path | None:
    pats = {
        "deb": f"robodr_*_{arch}.deb",
        "focal": f"robodr-focal_*_{arch}.deb",
        "rpm": f"robodr-*.{RPM_ARCH[arch]}.rpm",
    }
    found = sorted(rel.glob(pats[kind]))
    return found[0] if len(found) == 1 else None


def tar_programs(data: bytes, gz: bool = False) -> dict[str, str]:
    """name -> sha256 of every usr/bin, usr/sbin program in a tar archive."""
    out = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz" if gz else "r:") as tf:
        for m in tf:
            name = m.name.lstrip("./")
            if m.isfile() and re.fullmatch(r"usr/s?bin/robodr-[a-z0-9-]+", name):
                out[name.rsplit("/", 1)[1]] = sha256(tf.extractfile(m).read())
    return out


def package_programs(pkg: Path) -> dict[str, str]:
    if pkg.suffix == ".deb":
        data = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(pkg)], check=True, capture_output=True).stdout
        return tar_programs(data)
    data = subprocess.run(["rpm2archive", "-"], stdin=pkg.open("rb"), check=True, capture_output=True).stdout
    return tar_programs(data, gz=True)


def bundle_diff(a: bytes, b: bytes) -> list[str]:
    """Differences between two offline bundles, ignoring only the SBOM."""
    def members(data: bytes) -> dict[str, tuple]:
        out = {}
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), mode="r:") as tf:
            for m in tf:
                body = tf.extractfile(m).read() if m.isfile() else b""
                out[m.name] = (m.type, m.mode, m.uid, m.gid, m.uname, m.gname, m.mtime, m.linkname, body)
        return out

    def is_sbom(name: str) -> bool:
        return bool(re.fullmatch(r"[^/]+/sbom/[^/]+\.cdx\.json", name))

    def sums_without_sbom(body: bytes) -> list[str]:
        return [ln for ln in body.decode(errors="replace").splitlines() if not re.search(r" [ *]?sbom/", ln)]

    ma, mb = members(a), members(b)
    errs = []
    for n in sorted(set(ma) ^ set(mb)):
        errs.append(f"member {n} only in {'release' if n in ma else 'rebuild'}")
    for n in sorted(set(ma) & set(mb)):
        if ma[n] == mb[n]:
            continue
        if ma[n][:-1] != mb[n][:-1]:
            errs.append(f"member {n}: header differs")
        elif is_sbom(n):
            continue
        elif n.endswith("/SHA256SUMS") and sums_without_sbom(ma[n][-1]) == sums_without_sbom(mb[n][-1]):
            continue
        else:
            errs.append(f"member {n}: content differs")
    return errs


def compare(rel: Path, reb: Path, programs=package_programs) -> tuple[list[str], list[str]]:
    """(errors, report lines)."""
    errs, rep = [], []
    for kind in KINDS:
        for arch in ARCHS:
            label = f"{kind}/{arch}"
            psums, bsums = reb / f"PACKAGES-{kind}-{arch}.sha256", reb / f"BINARIES-{kind}-{arch}.sha256"
            if not psums.exists() or not bsums.exists():
                errs.append(f"{label}: no rebuild (PACKAGES-/BINARIES-{kind}-{arch}.sha256 missing)")
                continue
            for name, h in sorted(read_sums(psums).items()):
                r = rel / name
                if not r.exists():
                    errs.append(f"{label}: {name} rebuilt but not in the release")
                    continue
                rb = r.read_bytes()
                if sha256(rb) == h:
                    rep.append(f"{label}: {name}: reproduced (sha256 {h})")
                elif name.endswith("-offline.tar.gz") and (reb / name).exists():
                    d = bundle_diff(rb, (reb / name).read_bytes())
                    if d:
                        errs += [f"{label}: {name}: {x}" for x in d]
                    else:
                        rep.append(f"{label}: {name}: reproduced except its SBOM (sbom/*.cdx.json, not compared)")
                else:
                    errs.append(f"{label}: {name}: NOT reproduced (release {sha256(rb)}, rebuild {h})")
            pkg = release_package(rel, kind, arch)
            if pkg is None:
                errs.append(f"{label}: no single release package to compare the programs with")
                continue
            shipped = programs(pkg)
            for name, h in sorted(read_sums(bsums).items()):
                if name not in shipped:
                    rep.append(f"{label}: {name}: built, not packaged (not compared)")
                elif shipped[name] == h:
                    rep.append(f"{label}: {name}: reproduced")
                elif name in NOT_CLAIMED:
                    rep.append(f"{label}: {name}: NOT reproduced (release {shipped[name]}, rebuild {h}); "
                               "its bit-for-bit reproducibility is not claimed")
                else:
                    errs.append(f"{label}: {name}: NOT reproduced (release {shipped[name]}, rebuild {h})")
            for name in sorted(set(shipped) - set(read_sums(bsums))):
                errs.append(f"{label}: {name} is in the release package but was not rebuilt")
    return errs, rep


def write_report(path: Path, version: str, rep: list[str], errs: list[str]) -> None:
    head = [
        f"RoboDR {version}: independent rebuild",
        "",
        "Each package, offline bundle and program below was rebuilt by a separate job",
        "(another runner, the toolchain from hash-pinned artifacts, scripts/ci-rebuild.sh)",
        "and compared with the release before signing (scripts/compare-rebuild.py).",
        "robodr-pulsard (Pulsar-bound) is rebuilt too; its bit-for-bit reproducibility",
        "is not claimed, so its result is recorded here either way, and the packages",
        "were compared with the release's robodr-pulsard inside.",
        "",
    ]
    tail = ["", "Result: " + ("REPRODUCED" if not errs else "NOT REPRODUCED")] + [f"  {e}" for e in errs]
    path.write_text("\n".join(head + rep + tail) + "\n")


def self_test() -> int:
    import tempfile

    bad = 0

    def tgz(files: dict[str, bytes], mtime: int = 1) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for n, body in files.items():
                ti = tarfile.TarInfo(n)
                ti.size, ti.mtime, ti.mode = len(body), mtime, 0o644
                tf.addfile(ti, io.BytesIO(body))
        return gzip.compress(buf.getvalue(), mtime=0)

    base = {"b/x.deb": b"deb", "b/sbom/a.cdx.json": b"{1}", "b/SHA256SUMS": b"h1  x.deb\nh2  sbom/a.cdx.json\n"}
    sbom2 = {**base, "b/sbom/a.cdx.json": b"{2}", "b/SHA256SUMS": b"h1  x.deb\nh3  sbom/a.cdx.json\n"}
    other = {**base, "b/x.deb": b"evil", "b/SHA256SUMS": b"h9  x.deb\nh2  sbom/a.cdx.json\n"}
    if bundle_diff(tgz(base), tgz(sbom2)):
        print("FAIL: an SBOM-only difference must pass")
        bad += 1
    if not bundle_diff(tgz(base), tgz(other)):
        print("FAIL: a package difference in a bundle must fail")
        bad += 1
    if not bundle_diff(tgz(base), tgz(base, mtime=2)):
        print("FAIL: a header difference must fail")
        bad += 1
    if not bundle_diff(tgz(base), tgz({**base, "b/extra": b""})):
        print("FAIL: an extra member must fail")
        bad += 1

    with tempfile.TemporaryDirectory() as d:
        rel, reb = Path(d, "rel"), Path(d, "reb")
        rel.mkdir()
        reb.mkdir()
        progs = {}
        for kind in KINDS:
            for arch in ARCHS:
                name = {"deb": f"robodr_1_{arch}.deb", "focal": f"robodr-focal_1_{arch}.deb",
                        "rpm": f"robodr-1-1.{RPM_ARCH[arch]}.rpm"}[kind]
                (rel / name).write_bytes(name.encode())
                (reb / f"PACKAGES-{kind}-{arch}.sha256").write_text(f"{sha256(name.encode())}  {name}\n")
                bins = {"robodr-agentd": "a" * 64}
                if kind != "focal":
                    bins["robodr-pulsard"] = "p" * 64
                (reb / f"BINARIES-{kind}-{arch}.sha256").write_text(
                    "".join(f"{h if n != 'robodr-pulsard' else 'f' * 64}  {n}\n" for n, h in bins.items()))
                progs[name] = bins

        def fake_programs(p: Path) -> dict[str, str]:
            return dict(progs[p.name])

        errs, rep = compare(rel, reb, fake_programs)
        if errs or not any("robodr-pulsard: NOT reproduced" in r for r in rep):
            print(f"FAIL: pulsard mismatch must be recorded, not fail: {errs}")
            bad += 1
        progs["robodr_1_amd64.deb"]["robodr-agentd"] = "b" * 64
        errs, _ = compare(rel, reb, fake_programs)
        if not any("robodr-agentd: NOT reproduced" in e for e in errs):
            print(f"FAIL: an agentd mismatch must fail: {errs}")
            bad += 1
        progs["robodr_1_amd64.deb"]["robodr-agentd"] = "a" * 64
        (rel / "robodr_1_arm64.deb").write_bytes(b"other")
        errs, _ = compare(rel, reb, fake_programs)
        if not any("robodr_1_arm64.deb: NOT reproduced" in e for e in errs):
            print(f"FAIL: a package mismatch must fail: {errs}")
            bad += 1
        (reb / "BINARIES-rpm-arm64.sha256").unlink()
        errs, _ = compare(rel, reb, fake_programs)
        if not any("rpm/arm64: no rebuild" in e for e in errs):
            print(f"FAIL: a missing rebuild must fail: {errs}")
            bad += 1
    print("compare-rebuild self-test:", "FAIL" if bad else "ok")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--release", type=Path)
    ap.add_argument("--rebuild", type=Path)
    ap.add_argument("--version")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.release and a.rebuild and a.version and a.out):
        ap.print_usage(sys.stderr)
        return 2
    errs, rep = compare(a.release, a.rebuild)
    write_report(a.out, a.version, rep, errs)
    for r in rep:
        print(r)
    for e in errs:
        print(f"::error::rebuild differs: {e}", file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
