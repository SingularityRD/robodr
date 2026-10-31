#!/usr/bin/env python3
"""Compare a release with its independent rebuild before it is signed.

    scripts/compare-rebuild.py --release DIR --rebuild DIR --version V --out FILE
    scripts/compare-rebuild.py --ebpf-objects PROGRAM
    scripts/compare-rebuild.py --self-test

release.yml `finalize` (scripts/release-finalize.sh) runs it on the build
jobs' assets (--release) and the rebuild jobs' outputs (--rebuild:
PACKAGES-<kind>-<arch>.sha256, BINARIES-<kind>-<arch>.sha256,
EBPF-<kind>-<arch>.sha256 and the rebuilt packages and bundles, see
scripts/ci-rebuild.sh; the rebuilt robodr-<version>-rpk.tar.gz of job
rebuild-delivery), and FAILS (exit 1, nothing is signed) unless:

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
  * the eBPF objects embedded in the release's robodr-pulsard (deb, rpm)
    are, as a multiset of SHA-256, exactly those embedded in the rebuilt
    one (EBPF-<kind>-<arch>.sha256): the kernel-side code of the root,
    CAP_BPF daemon is checked by an independent build even though the
    program around it is not claimed to be bit-for-bit reproducible;
  * the secure-delivery archive robodr-<version>-rpk.tar.gz (unsigned RPKs
    and DELIVERY-MANIFEST.json, which the offline quorum signs) is
    byte-identical to the one job rebuild-delivery built on another runner
    with the hash-pinned toolchain;
  * every kind and architecture the release ships was rebuilt.

--ebpf-objects PROGRAM prints one `<sha256>  robodr-pulsard` line per eBPF
ELF object (64-bit, e_machine EM_BPF, sliced by its section headers)
embedded in PROGRAM, sorted: what scripts/ci-rebuild.sh writes into
EBPF-<kind>-<arch>.sha256. It fails on a program that embeds none.

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
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

KINDS = ("deb", "rpm", "focal")
ARCHS = ("amd64", "arm64")
RPM_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}
NOT_CLAIMED = {"robodr-pulsard"}
EBPF_HOST = "robodr-pulsard"
EBPF_KINDS = ("deb", "rpm")
EM_BPF = 247
SHT_NOBITS = 8


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


def package_tar(pkg: Path) -> tuple[bytes, bool]:
    """(payload tar, gzip-compressed) of a .deb or .rpm."""
    if pkg.suffix == ".deb":
        return subprocess.run(["dpkg-deb", "--fsys-tarfile", str(pkg)], check=True, capture_output=True).stdout, False
    with pkg.open("rb") as f:
        return subprocess.run(["rpm2archive", "-"], stdin=f, check=True, capture_output=True).stdout, True


def package_programs(pkg: Path) -> dict[str, str]:
    return tar_programs(*package_tar(pkg))


def ebpf_objects(binary: bytes) -> list[str]:
    """Sorted SHA-256 of every 64-bit EM_BPF ELF object embedded in `binary`.

    Pulsar embeds its clang-built objects verbatim (aya's
    include_bytes_aligned!); each is cut out by its own ELF header: the end
    of its section header table or of its last section with file bytes,
    whichever is later. ValueError on an object that runs past the program.
    """
    out, pos = [], 0
    while True:
        off = binary.find(b"\x7fELF\x02", pos)
        if off < 0:
            return sorted(out)
        pos = off + 1
        if off + 64 > len(binary) or binary[off + 5] not in (1, 2):
            continue
        order = "<" if binary[off + 5] == 1 else ">"
        if struct.unpack_from(order + "H", binary, off + 18)[0] != EM_BPF:
            continue
        shoff = struct.unpack_from(order + "Q", binary, off + 0x28)[0]
        shentsize, shnum = struct.unpack_from(order + "HH", binary, off + 0x3A)
        if shnum and shentsize < 64:
            raise ValueError(f"eBPF object at offset {off}: section header size {shentsize}")
        end = max(64, shoff + shentsize * shnum)
        for i in range(shnum):
            sh = off + shoff + i * shentsize
            if sh + 64 > len(binary):
                raise ValueError(f"eBPF object at offset {off}: section header {i} past the end of the program")
            sh_type = struct.unpack_from(order + "I", binary, sh + 4)[0]
            sh_off, sh_size = struct.unpack_from(order + "QQ", binary, sh + 0x18)
            if sh_type != SHT_NOBITS:
                end = max(end, sh_off + sh_size)
        if off + end > len(binary):
            raise ValueError(f"eBPF object at offset {off}: {end} bytes run past the end of the program")
        out.append(sha256(binary[off:off + end]))


def package_ebpf(pkg: Path) -> list[str]:
    """ebpf_objects() of the robodr-pulsard inside a release package."""
    data, gz = package_tar(pkg)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz" if gz else "r:") as tf:
        for m in tf:
            if m.isfile() and m.name.lstrip("./") == f"usr/sbin/{EBPF_HOST}":
                f = tf.extractfile(m)
                return ebpf_objects(f.read() if f else b"")
    return []


def read_ebpf(path: Path) -> list[str]:
    out = []
    for ln in path.read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(EBPF_HOST), ln.strip())
        if not m:
            raise ValueError(f"{path.name}: bad line {ln!r}")
        out.append(m.group(1))
    return sorted(out)


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


def compare(rel: Path, reb: Path, programs=package_programs, ebpf=package_ebpf,
            version: str | None = None) -> tuple[list[str], list[str]]:
    """(errors, report lines)."""
    errs, rep = [], []
    if version is not None:
        rpk = f"robodr-{version}-rpk.tar.gz"
        if not (rel / rpk).exists():
            errs.append(f"delivery: {rpk} is not in the release")
        elif not (reb / rpk).exists():
            errs.append(f"delivery: {rpk}: no rebuild (job rebuild-delivery)")
        elif sha256((rel / rpk).read_bytes()) == sha256((reb / rpk).read_bytes()):
            rep.append(f"delivery: {rpk}: reproduced (sha256 {sha256((rel / rpk).read_bytes())})")
        else:
            errs.append(f"delivery: {rpk}: NOT reproduced (release {sha256((rel / rpk).read_bytes())}, "
                        f"rebuild {sha256((reb / rpk).read_bytes())})")
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
            if kind in EBPF_KINDS:
                esums = reb / f"EBPF-{kind}-{arch}.sha256"
                if not esums.exists():
                    errs.append(f"{label}: no record of the rebuilt {EBPF_HOST}'s eBPF objects ({esums.name} missing)")
                    continue
                try:
                    want, got = ebpf(pkg), read_ebpf(esums)
                except (ValueError, OSError, tarfile.TarError, subprocess.CalledProcessError) as e:
                    errs.append(f"{label}: {EBPF_HOST} eBPF objects: {e}")
                    continue
                if not want:
                    errs.append(f"{label}: the release's {EBPF_HOST} embeds no eBPF object")
                elif want != got:
                    errs.append(f"{label}: {EBPF_HOST} eBPF objects NOT reproduced: release {want}, rebuild {got}")
                else:
                    rep.append(f"{label}: {EBPF_HOST}: its {len(want)} eBPF object(s) reproduced "
                               f"(sha256 {', '.join(want)})")
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
        "were compared with the release's robodr-pulsard inside. The eBPF objects it",
        "embeds (the code it loads into the kernel) must be identical in both builds.",
        "The unsigned secure-delivery RPK archive was rebuilt and compared too.",
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

    def bpf_obj(body: bytes, big: bool = False) -> bytes:
        """A minimal 64-bit EM_BPF relocatable: header, one PROGBITS section
        holding `body`, a NOBITS one claiming more, then the section headers."""
        o = ">" if big else "<"
        shoff = 64 + len(body)
        hdr = b"\x7fELF\x02" + (b"\x02" if big else b"\x01") + b"\x01" + b"\x00" * 9
        hdr += struct.pack(o + "HHIQQQIHHHHHH", 1, EM_BPF, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 0)
        null = b"\x00" * 64
        prog = struct.pack(o + "IIQQQQIIQQ", 1, 1, 0, 0, 64, len(body), 0, 0, 1, 0)
        bss = struct.pack(o + "IIQQQQIIQQ", 2, SHT_NOBITS, 0, 0, 64, 1 << 20, 0, 0, 1, 0)
        return hdr + body + null + prog + bss

    bpf_a, bpf_b = bpf_obj(b"prog-a" * 3), bpf_obj(b"prog-b", big=True)
    x86 = bytearray(bpf_obj(b"host"))
    x86[18:20] = (62).to_bytes(2, "little")  # EM_X86_64: not an eBPF object
    program = b"\x7fELF\x02junk" + bytes(x86) + b"pad" + bpf_a + b"\x00" * 7 + bpf_b + b"tail" + bpf_a
    got = ebpf_objects(program)
    if got != sorted([sha256(bpf_a), sha256(bpf_a), sha256(bpf_b)]):
        print(f"FAIL: eBPF objects not cut out exactly: {got}")
        bad += 1
    if ebpf_objects(b"no objects here"):
        print("FAIL: a program without eBPF objects has none")
        bad += 1
    try:
        ebpf_objects(b"x" + bpf_a[:-10])
        print("FAIL: a truncated eBPF object must be refused")
        bad += 1
    except ValueError:
        pass

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

        objs = sorted(sha256(o) for o in (bpf_a, bpf_b))
        for kind in EBPF_KINDS:
            for arch in ARCHS:
                (reb / f"EBPF-{kind}-{arch}.sha256").write_text("".join(f"{h}  robodr-pulsard\n" for h in objs))
        release_ebpf = {}

        def fake_ebpf(p: Path) -> list[str]:
            return release_ebpf.get(p.name, objs)

        (rel / "robodr-1-rpk.tar.gz").write_bytes(b"rpk")
        (reb / "robodr-1-rpk.tar.gz").write_bytes(b"rpk")
        errs, rep = compare(rel, reb, fake_programs, fake_ebpf, "1")
        if errs or not any("robodr-pulsard: NOT reproduced" in r for r in rep):
            print(f"FAIL: pulsard mismatch must be recorded, not fail: {errs}")
            bad += 1
        if not any("eBPF object(s) reproduced" in r for r in rep) or not any("rpk.tar.gz: reproduced" in r for r in rep):
            print(f"FAIL: eBPF objects and the RPK archive must be reported reproduced: {rep}")
            bad += 1
        # The kernel-side code differs: fails, although pulsard itself is
        # not claimed reproducible.
        release_ebpf["robodr_1_amd64.deb"] = sorted([objs[0], sha256(b"evil")])
        errs, _ = compare(rel, reb, fake_programs, fake_ebpf, "1")
        if not any("eBPF objects NOT reproduced" in e for e in errs):
            print(f"FAIL: an eBPF object mismatch must fail: {errs}")
            bad += 1
        release_ebpf["robodr_1_amd64.deb"] = []
        errs, _ = compare(rel, reb, fake_programs, fake_ebpf, "1")
        if not any("embeds no eBPF object" in e for e in errs):
            print(f"FAIL: a release pulsard without eBPF objects must fail: {errs}")
            bad += 1
        del release_ebpf["robodr_1_amd64.deb"]
        (reb / "EBPF-rpm-arm64.sha256").unlink()
        errs, _ = compare(rel, reb, fake_programs, fake_ebpf, "1")
        if not any("EBPF-rpm-arm64.sha256 missing" in e for e in errs):
            print(f"FAIL: a missing eBPF record must fail: {errs}")
            bad += 1
        (reb / "EBPF-rpm-arm64.sha256").write_text("".join(f"{h}  robodr-pulsard\n" for h in objs))
        (reb / "robodr-1-rpk.tar.gz").write_bytes(b"other")
        errs, _ = compare(rel, reb, fake_programs, fake_ebpf, "1")
        if not any("rpk.tar.gz: NOT reproduced" in e for e in errs):
            print(f"FAIL: an RPK archive mismatch must fail: {errs}")
            bad += 1
        (reb / "robodr-1-rpk.tar.gz").unlink()
        errs, _ = compare(rel, reb, fake_programs, fake_ebpf, "1")
        if not any("no rebuild (job rebuild-delivery)" in e for e in errs):
            print(f"FAIL: a missing RPK rebuild must fail: {errs}")
            bad += 1
        (reb / "robodr-1-rpk.tar.gz").write_bytes(b"rpk")
        progs["robodr_1_amd64.deb"]["robodr-agentd"] = "b" * 64
        errs, _ = compare(rel, reb, fake_programs, fake_ebpf)
        if not any("robodr-agentd: NOT reproduced" in e for e in errs):
            print(f"FAIL: an agentd mismatch must fail: {errs}")
            bad += 1
        progs["robodr_1_amd64.deb"]["robodr-agentd"] = "a" * 64
        (rel / "robodr_1_arm64.deb").write_bytes(b"other")
        errs, _ = compare(rel, reb, fake_programs, fake_ebpf)
        if not any("robodr_1_arm64.deb: NOT reproduced" in e for e in errs):
            print(f"FAIL: a package mismatch must fail: {errs}")
            bad += 1
        (reb / "BINARIES-rpm-arm64.sha256").unlink()
        errs, _ = compare(rel, reb, fake_programs, fake_ebpf)
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
    ap.add_argument("--ebpf-objects", type=Path, metavar="PROGRAM")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if a.ebpf_objects:
        try:
            objs = ebpf_objects(a.ebpf_objects.read_bytes())
        except (ValueError, OSError) as e:
            print(f"compare-rebuild: {a.ebpf_objects}: {e}", file=sys.stderr)
            return 1
        if not objs:
            print(f"compare-rebuild: {a.ebpf_objects} embeds no eBPF object", file=sys.stderr)
            return 1
        sys.stdout.write("".join(f"{h}  {EBPF_HOST}\n" for h in objs))
        return 0
    if not (a.release and a.rebuild and a.version and a.out):
        ap.print_usage(sys.stderr)
        return 2
    errs, rep = compare(a.release, a.rebuild, version=a.version)
    write_report(a.out, a.version, rep, errs)
    for r in rep:
        print(r)
    for e in errs:
        print(f"::error::rebuild differs: {e}", file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
