#!/usr/bin/env python3
"""Bind the release approval to the bytes that are signed and published
(release.yml jobs `finalize`, `publish` and `publish-dry-run`).

The SET DIGEST of a directory is the SHA-256 of its set manifest: one
`<sha256>  <name>` line per file, sorted by name (C locale), exactly what

    find DIR -maxdepth 1 -type f -printf '%P\\n' | LC_ALL=C sort |
        (cd DIR && xargs -r -d '\\n' sha256sum) | sha256sum

prints. A set is well-formed when DIR holds only regular files, SHA256SUMS
lists every file but itself and the per-architecture SHA256SUMS-<x> files
(signed assets that release-finalize.sh leaves out of SHA256SUMS), with the
right hashes, and nothing is signed yet (no *.minisig).

    release-assets.py digest --dir DIR [--manifest FILE]
        Checks that the set is well-formed and prints its set digest
        (--manifest also writes the manifest). `finalize` (no secrets, no
        write access) publishes it as a job output and, with the manifest,
        in its job summary before the `release` environment asks for
        approval: the reviewers approve THAT digest.

    release-assets.py verify-set --dir DIR --set-sha256 HEX
        `publish`, after downloading finalize's artifact and before signing:
        the set is well-formed and its set digest is exactly HEX, so every
        byte signed (SHA256SUMS, every asset and every per-arch sums file)
        is a byte the reviewers saw summarised, whatever happened to the
        run's artifacts in between.

    release-assets.py check-release --dir DIR --names FILE
        `publish`, after signing and uploading, right before the draft is
        published: the files of DIR other than *.minisig form a well-formed
        set, and FILE (one name per line: `gh release view --json assets
        --jq '.assets[].name'`) and DIR both hold exactly those files and
        one `<file>.minisig` for each. An asset that anyone with `contents:
        write` added to the draft (it is visible to the repository's writers
        from `prepare` on) fails the publish instead of being published
        unsigned next to the signed set.

    release-assets.py --self-test

Exit: 0 ok, 1 refused, 2 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

SUMS = "SHA256SUMS"
LINE = re.compile(r"([0-9a-f]{64}) [ *]([^/\s][^/]*)")
PER_ARCH = re.compile(r"SHA256SUMS-[a-z0-9-]+")


class Refused(Exception):
    pass


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_sums(text: str) -> dict[str, str]:
    """name -> sha256; refuses a malformed or duplicate line."""
    out: dict[str, str] = {}
    for n, ln in enumerate(text.splitlines(), 1):
        m = LINE.fullmatch(ln)
        if not m:
            raise Refused(f"{SUMS} line {n} is not '<sha256>  <name>': {ln!r}")
        if m.group(2) in out:
            raise Refused(f"{SUMS} lists {m.group(2)} twice")
        if m.group(2) == SUMS or m.group(2).endswith(".minisig") or PER_ARCH.fullmatch(m.group(2)):
            raise Refused(f"{SUMS} must not list {m.group(2)}")
        out[m.group(2)] = m.group(1)
    if not out:
        raise Refused(f"{SUMS} is empty")
    return out


def dir_entries(d: Path) -> set[str]:
    names = set()
    for p in d.iterdir():
        if p.is_symlink() or not p.is_file():
            raise Refused(f"{p.name} in {d} is not a regular file")
        names.add(p.name)
    return names


def diff(label: str, have: set[str], want: set[str]) -> list[str]:
    return [f"{label}: unexpected {n}" for n in sorted(have - want)] + \
        [f"{label}: missing {n}" for n in sorted(want - have)]


def check_set(d: Path, names: set[str]) -> None:
    """The files `names` of DIR form a well-formed set (module docstring)."""
    sp = d / SUMS
    if SUMS not in names or not sp.is_file():
        raise Refused(f"no {SUMS} in {d}")
    sums = read_sums(sp.read_text(encoding="utf-8"))
    per_arch = {n for n in names if PER_ARCH.fullmatch(n)}
    errs = diff(str(d), names, set(sums) | {SUMS} | per_arch)
    for name, h in sorted(sums.items()):
        p = d / name
        if p.is_file() and sha256_file(p) != h:
            errs.append(f"{name}: SHA-256 differs from {SUMS}")
    if errs:
        raise Refused("; ".join(errs))


def set_digest(d: Path) -> tuple[str, str]:
    """(set digest, manifest) of a well-formed, unsigned DIR."""
    names = dir_entries(d)
    for n in sorted(names):
        if n.endswith(".minisig"):
            raise Refused(f"{n}: the set is signed only after approval")
    check_set(d, names)
    m = "".join(f"{sha256_file(d / n)}  {n}\n" for n in sorted(names, key=lambda n: n.encode()))
    return hashlib.sha256(m.encode()).hexdigest(), m


def verify_set(d: Path, set_sha256: str) -> None:
    got, _ = set_digest(d)
    if got != set_sha256:
        raise Refused(f"the asset set has digest {got}, the approved (finalize) one is {set_sha256}")


def check_release(d: Path, names: list[str]) -> None:
    have = dir_entries(d)
    signed = {n for n in have if not n.endswith(".minisig")}
    check_set(d, signed)
    want = signed | {f"{n}.minisig" for n in signed}
    errs = diff("local signed set", have, want)
    if len(names) != len(set(names)):
        errs.append("release: an asset name occurs twice")
    errs += diff("release assets", set(names), want)
    if errs:
        raise Refused("; ".join(errs))


def self_test() -> int:
    import subprocess
    import tempfile
    import unittest

    def mk(d: Path, files: dict[str, bytes]) -> None:
        for n, b in files.items():
            (d / n).write_bytes(b)
        (d / SUMS).write_text("".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in sorted(files.items())))

    class T(unittest.TestCase):
        def setUp(self):
            self.td = tempfile.TemporaryDirectory()
            self.d = Path(self.td.name, "rel")
            self.d.mkdir()
            mk(self.d, {"a.deb": b"a", "b.tar.gz": b"b"})
            (self.d / "SHA256SUMS-amd64").write_text(f"{hashlib.sha256(b'a').hexdigest()}  a.deb\n")
            self.h, _ = set_digest(self.d)

        def tearDown(self):
            self.td.cleanup()

        def test_verify_ok(self):
            verify_set(self.d, self.h)
            self.assertEqual(main(["verify-set", "--dir", str(self.d), "--set-sha256", self.h]), 0)
            self.assertEqual(main(["digest", "--dir", str(self.d)]), 0)
            # The shell recipe of the docstring (docs/RELEASE.md) gives the
            # same digest, so a reviewer can recompute it from the artifact.
            sh = subprocess.run(
                ["bash", "-c", "find \"$1\" -maxdepth 1 -type f -printf '%P\\n' | LC_ALL=C sort | "
                 "(cd \"$1\" && xargs -r -d '\\n' sha256sum) | sha256sum", "x", str(self.d)],
                capture_output=True, text=True, check=True).stdout.split()[0]
            self.assertEqual(sh, self.h)

        def test_other_set_refused(self):
            # The set changed after the reviewers saw the digest.
            self.assertEqual(main(["verify-set", "--dir", str(self.d), "--set-sha256", "0" * 64]), 1)
            # A per-arch sums file is not in SHA256SUMS, yet bound too.
            (self.d / "SHA256SUMS-amd64").write_text("changed\n")
            with self.assertRaises(Refused):
                verify_set(self.d, self.h)

        def test_changed_or_extra_file_refused(self):
            (self.d / "c.txt").write_bytes(b"x")
            with self.assertRaises(Refused):
                set_digest(self.d)
            (self.d / "c.txt").unlink()
            (self.d / "a.deb").write_bytes(b"evil")
            with self.assertRaises(Refused):
                set_digest(self.d)
            (self.d / "a.deb").unlink()
            with self.assertRaises(Refused):
                set_digest(self.d)

        def test_presigned_refused(self):
            (self.d / "a.deb.minisig").write_bytes(b"sig")
            with self.assertRaises(Refused):
                verify_set(self.d, self.h)

        def test_bad_sums(self):
            for text in ("", "zz  a\n", f"{'0' * 64}  sub/a\n", f"{'0' * 64}  a\n{'1' * 64}  a\n",
                         f"{'0' * 64}  a.minisig\n", f"{'0' * 64}  SHA256SUMS-amd64\n"):
                with self.assertRaises(Refused):
                    read_sums(text)

        def test_check_release(self):
            for n in ("a.deb", "b.tar.gz", SUMS, "SHA256SUMS-amd64"):
                (self.d / f"{n}.minisig").write_bytes(b"s")
            names = sorted(p.name for p in self.d.iterdir())
            check_release(self.d, names)
            with self.assertRaises(Refused):  # an unsigned asset added to the draft
                check_release(self.d, names + ["extra.sh"])
            with self.assertRaises(Refused):  # a signature missing on the release
                check_release(self.d, [n for n in names if n != "a.deb.minisig"])
            with self.assertRaises(Refused):
                check_release(self.d, names + ["a.deb"])
            nf = Path(self.td.name, "names.txt")
            nf.write_text("\n".join(names + ["extra.sh"]) + "\n")
            self.assertEqual(main(["check-release", "--dir", str(self.d), "--names", str(nf)]), 1)
            nf.write_text("\n".join(names) + "\n")
            self.assertEqual(main(["check-release", "--dir", str(self.d), "--names", str(nf)]), 0)
            (self.d / "b.tar.gz.minisig").unlink()
            with self.assertRaises(Refused):  # the local set lost a signature
                check_release(self.d, names)

    r = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
    return 0 if r.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    ap = argparse.ArgumentParser(description="RoboDR release asset set checks")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pd = sub.add_parser("digest")
    pd.add_argument("--dir", required=True, type=Path)
    pd.add_argument("--manifest", type=Path)
    pv = sub.add_parser("verify-set")
    pv.add_argument("--dir", required=True, type=Path)
    pv.add_argument("--set-sha256", required=True)
    pc = sub.add_parser("check-release")
    pc.add_argument("--dir", required=True, type=Path)
    pc.add_argument("--names", required=True, type=Path)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "digest":
            h, m = set_digest(a.dir)
            if a.manifest:
                a.manifest.write_text(m, encoding="utf-8")
            print(h)
        elif a.cmd == "verify-set":
            if not re.fullmatch(r"[0-9a-f]{64}", a.set_sha256):
                print(f"release-assets: --set-sha256 must be 64 hex digits, got {a.set_sha256!r}", file=sys.stderr)
                return 2
            verify_set(a.dir, a.set_sha256)
            print(f"release-assets: the set is the approved one (set digest {a.set_sha256})")
        else:
            names = [n for n in a.names.read_text(encoding="utf-8").splitlines() if n.strip()]
            check_release(a.dir, names)
            print(f"release-assets: the release holds exactly the signed set ({len(names)} assets)")
        return 0
    except Refused as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError) as e:
        print(f"release-assets: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
