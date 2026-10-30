#!/usr/bin/env python3
"""Keep every RoboDR package variant consistent: robodr (.deb), robodr-focal
(.deb, static, systemd 245) and robodr (.rpm).

Static checks (no package needed; CI job `scripts`):

  1. Every robodr-* program the workspace builds ([[bin]] targets and
     src/main.rs packages) is classified in PROGRAMS below (which variants
     ship it, where) or in NEVER_PACKAGED. A new program therefore fails
     until someone decides where it goes.
  2. Every ROBODR_DEB_REQUIRE list in .github/workflows/*.yml equals the
     programs of the variant that step builds (robodr-focal when the step
     passes `--variant focal`, otherwise robodr) minus the three that
     build-deb.sh always requires, so no release or CI build can silently
     ship without one of them.
  3. packaging/build-deb.sh names every packaged program.
  4. The maintainer scripts of both package formats stop (on removal) and
     try-restart (on upgrade) exactly the same units: every shipped
     service except robodr-firewall-gw-rules.service, which is never
     stopped on purpose (its ruleset keeps a fail-closed bridge closed).

  5a. Every unit (regular and focal) and every unit with each of its
     drop-in examples applied: with SecureBits=noroot / noroot-locked, a
     process of uid 0 gets capabilities on execve only through the ambient
     set, so AmbientCapabilities= must hold every capability of
     CapabilityBoundingSet= (else e.g. robodr-pulsard runs without CAP_BPF).

Package checks (`--deb FILE ... --rpm FILE ...`; CI jobs `package-*`):

  5. Per package: every entry root:root, nothing setuid/setgid or
     group/other-writable, no device/FIFO, paths only under /usr and
     /etc/robodr, no private key material (PEM private keys, minisign
     secret keys) anywhere in the payload; exactly the variant's programs,
     each unit together with its program, and a man page for every
     shipped program that has one in man/.
  6. robodr .deb vs robodr .rpm of the same architecture: the same paths
     with the same modes, and byte-identical content except the programs
     (built in different userlands).
  7. robodr .deb vs robodr-focal .deb of the same architecture: the same
     paths and modes except the documented differences (FOCAL_ONLY,
     STANDARD_ONLY).

Usage:
  scripts/check-packages.py                          # static checks
  scripts/check-packages.py --deb A.deb --deb F.deb --rpm R.rpm
  scripts/check-packages.py --self-test
Exit 0 ok, 1 inconsistency found, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import stat
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STD = "robodr"
FOCAL = "robodr-focal"
BOTH = frozenset({STD, FOCAL})

# program -> (install directory, variants that ship it). The RPM is the
# robodr variant.
PROGRAMS: dict[str, tuple[str, frozenset[str]]] = {
    "robodr-commission": ("usr/bin", BOTH),
    "robodr-replay": ("usr/bin", BOTH),
    "robodr-ros2-watch": ("usr/bin", BOTH),
    "robodr-blackbox": ("usr/bin", BOTH),
    "robodr-diode-pack": ("usr/bin", BOTH),
    "robodr-diode-unpack": ("usr/bin", BOTH),
    "robodr-spool-export": ("usr/bin", BOTH),
    "robodr-kafka-publish": ("usr/bin", BOTH),
    "robodr-uplink": ("usr/bin", BOTH),
    "robodr-agentd": ("usr/sbin", BOTH),
    "robodr-executor": ("usr/sbin", BOTH),
    "robodr-firewall-gw": ("usr/sbin", BOTH),
    "robodr-deliverd": ("usr/sbin", BOTH),
    "robodr-seal": ("usr/sbin", BOTH),
    "robodr-enroll": ("usr/sbin", BOTH),
    # Pulsar-bound (glibc, eBPF, needs BTF): not static, not on systemd 245.
    "robodr-pulsard": ("usr/sbin", frozenset({STD})),
    # Base station only: use the robodr package there.
    "robodr-anchor-receiver": ("usr/bin", frozenset({STD})),
}
NEVER_PACKAGED = {
    "robodr-safety-replay": "test tool of robodr-deliverd",
    "robodr-release": "SOC / build-side delivery artifact tool",
}
# build-deb.sh requires these whatever ROBODR_DEB_REQUIRE says.
ALWAYS_REQUIRED = {"robodr-commission", "robodr-replay", "robodr-ros2-watch"}

# program -> units installed with it.
UNITS = {
    "robodr-pulsard": ["robodr-pulsard.service"],
    "robodr-agentd": ["robodr-agentd.service"],
    "robodr-spool-export": ["robodr-spool-export.service"],
    "robodr-kafka-publish": ["robodr-kafka-publish.service"],
    "robodr-uplink": ["robodr-uplink.service"],
    "robodr-executor": ["robodr-executor.service"],
    "robodr-firewall-gw": ["robodr-firewall-gw.service", "robodr-firewall-gw-rules.service"],
    "robodr-anchor-receiver": ["robodr-anchor-receiver.service"],
    "robodr-deliverd": ["robodr-deliverd.service"],
}
NOT_STOPPED = {"robodr-firewall-gw-rules.service"}

# robodr-focal vs robodr (same architecture), as path globs.
STANDARD_ONLY = [
    "/usr/sbin/robodr-pulsard",
    "/usr/lib/robodr/robodr-btf-check",
    "/usr/bin/robodr-anchor-receiver",
    "/usr/lib/systemd/system/robodr-pulsard.service",
    "/usr/lib/systemd/system/robodr-anchor-receiver.service",
    "/usr/share/man/man8/robodr-pulsard.8.gz",
    "/usr/share/man/man8/robodr-anchor-receiver.8.gz",
    "/usr/share/doc/robodr/examples/robodr-pulsard.service.d",
    "/usr/share/doc/robodr/examples/robodr-pulsard.service.d/*",
    "/etc",
    "/etc/robodr",
    "/etc/robodr/pulsar.toml",
    "/usr/share/robodr/rules",
    "/usr/share/robodr/rules/*",
]
FOCAL_ONLY = [
    "/usr/lib/robodr/robodr-load-credential",
]
ALLOWED_ROOTS = ("/usr/", "/etc/robodr")
SECRET_MARKERS = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"minisign encrypted secret key"),
    re.compile(rb"untrusted comment: [^\n]*secret key"),
)


@dataclass(frozen=True)
class Entry:
    kind: str  # "f" file, "d" directory, "l" symlink, "?" other
    mode: int  # permission bits incl. setuid/setgid/sticky
    owner: str
    group: str
    digest: str  # sha256 of a file, link target of a link, "" otherwise


# ---------------------------------------------------------------- static --


def load_manifest(text: str) -> dict:
    """[package] name and [[bin]] names of a Cargo.toml (tomllib when the
    interpreter has it, Python >= 3.11; else a line parser good enough for
    those two keys: Rocky Linux 9's python3 is 3.9)."""
    try:
        import tomllib  # noqa: PLC0415

        return tomllib.loads(text)
    except ImportError:
        pass
    data: dict = {"package": {}, "bin": []}
    section = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("[[") and line.endswith("]]"):
            section = line[2:-2].strip()
            if section == "bin":
                data["bin"].append({})
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        m = re.match(r'name\s*=\s*"([^"]+)"', line)
        if m and section == "package":
            data["package"]["name"] = m.group(1)
        elif m and section == "bin" and data["bin"]:
            data["bin"][-1]["name"] = m.group(1)
    data["bin"] = [b for b in data["bin"] if "name" in b]
    return data


def workspace_programs(root: Path) -> set[str]:
    progs: set[str] = set()
    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        data = load_manifest(manifest.read_text())
        for b in data.get("bin", []):
            progs.add(b["name"])
        name = data.get("package", {}).get("name", "")
        if (manifest.parent / "src" / "main.rs").is_file() and not data.get("bin"):
            progs.add(name)
        for f in sorted((manifest.parent / "src" / "bin").glob("*.rs")):
            progs.add(f.stem)
    return {p for p in progs if p.startswith("robodr-")}


def check_classified(progs: set[str]) -> list[str]:
    errs = []
    known = set(PROGRAMS) | set(NEVER_PACKAGED)
    for p in sorted(progs - known):
        errs.append(f"{p}: built by the workspace but not classified in scripts/check-packages.py PROGRAMS / NEVER_PACKAGED")
    for p in sorted(set(PROGRAMS) - progs):
        errs.append(f"{p}: in PROGRAMS but the workspace does not build it")
    return errs


def variant_programs(variant: str) -> set[str]:
    return {p for p, (_, vs) in PROGRAMS.items() if variant in vs}


REQUIRE_RE = re.compile(r"ROBODR_DEB_REQUIRE:\s*(.+)")


def workflow_requires(text: str) -> list[tuple[int, str, set[str]]]:
    """(line, variant, programs) for every ROBODR_DEB_REQUIRE in a workflow.

    The variant is robodr-focal when the step's run script passes
    `--variant focal`. A step is the text up to the next "- name:" line.
    """
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        m = REQUIRE_RE.search(line)
        if not m or line.lstrip().startswith("#"):
            continue
        # The step around it: back to its "- name:" / "- uses:", forward to the next.
        start = i
        while start > 0 and not re.match(r"\s*- (name|uses):", lines[start]):
            start -= 1
        end = i + 1
        while end < len(lines) and not re.match(r"\s*- (name|uses):", lines[end]):
            end += 1
        step = "\n".join(lines[start:end])
        variant = FOCAL if "--variant focal" in step else STD
        out.append((i + 1, variant, set(m.group(1).split())))
    return out


def check_workflows(root: Path) -> list[str]:
    errs = []
    seen = 0
    for wf in sorted((root / ".github" / "workflows").glob("*.yml")):
        for line, variant, req in workflow_requires(wf.read_text()):
            seen += 1
            want = variant_programs(variant) - ALWAYS_REQUIRED
            got = req - ALWAYS_REQUIRED
            where = f"{wf.relative_to(root)}:{line} ({variant})"
            for p in sorted(want - got):
                errs.append(f"{where}: ROBODR_DEB_REQUIRE lacks {p}")
            for p in sorted(got - want):
                errs.append(f"{where}: ROBODR_DEB_REQUIRE names {p}, which {variant} does not ship")
    if seen == 0:
        errs.append(".github/workflows: no ROBODR_DEB_REQUIRE found")
    return errs


def check_build_deb(root: Path) -> list[str]:
    text = (root / "packaging" / "build-deb.sh").read_text()
    return [f"packaging/build-deb.sh: never installs {p}" for p in sorted(PROGRAMS) if not re.search(rf"\b{re.escape(p)}\b", text)]


FOR_RE = re.compile(r"for u in (.*?); do\n(.*?)\n", re.S)


def unit_loops(text: str) -> dict[str, set[str]]:
    """The unit lists of the script's `for u in ...; do` loops, keyed by the
    systemctl verb of the loop body (try-restart / stop / start)."""
    out: dict[str, set[str]] = {}
    for m in FOR_RE.finditer(text):
        units = set(re.findall(r"robodr-[a-z0-9-]+\.service", m.group(1)))
        body = m.group(2)
        verb = "try-restart" if "try-restart" in body else "stop" if "systemctl stop" in body else "other"
        if units and verb != "other":
            # postinst stops the migration's four units in a loop of its own
            # (guarded by is-active): keep the larger list per verb.
            if len(units) > len(out.get(verb, set())):
                out[verb] = units
    return out


def check_scripts(root: Path) -> list[str]:
    errs = []
    shipped = {u for us in UNITS.values() for u in us}
    unit_files = {f.name for f in (root / "packaging" / "systemd").glob("*.service")}
    for u in sorted(unit_files - shipped):
        errs.append(f"packaging/systemd/{u}: not tied to a program in scripts/check-packages.py UNITS")
    want = shipped - NOT_STOPPED
    pk = root / "packaging"
    checks = [
        ("deb/postinst", "try-restart"),
        ("deb/prerm", "stop"),
        ("rpm/post", "try-restart"),
        ("rpm/preun", "stop"),
    ]
    for rel, verb in checks:
        loops = unit_loops((pk / rel).read_text())
        got = loops.get(verb)
        if got is None:
            errs.append(f"packaging/{rel}: no `for u in ...` loop that runs systemctl {verb}")
            continue
        for u in sorted(want - got):
            errs.append(f"packaging/{rel}: does not {verb} {u}")
        for u in sorted(got - want):
            errs.append(f"packaging/{rel}: {verb}s {u}, which is not a shipped, stoppable unit")
    return errs


def unit_settings(texts: list[str]) -> dict[str, list[str]]:
    """SecureBits= / CapabilityBoundingSet= / AmbientCapabilities= of a unit
    and its drop-ins, applied in order (an empty assignment resets, a
    leading "~" inverts: treated as "not a plain list", reported)."""
    out: dict[str, list[str]] = {"SecureBits": [], "CapabilityBoundingSet": [], "AmbientCapabilities": []}
    for text in texts:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            k, v = (x.strip() for x in line.split("=", 1))
            if k in out:
                if not v:
                    out[k] = []
                else:
                    out[k] += v.split()
    return out


def check_noroot_caps(name: str, texts: list[str]) -> list[str]:
    st = unit_settings(texts)
    if not any(b.startswith("noroot") for b in st["SecureBits"]):
        return []
    bnd, amb = st["CapabilityBoundingSet"], st["AmbientCapabilities"]
    if any(c.startswith("~") for c in bnd + amb):
        return [f"{name}: SecureBits=noroot with an inverted (~) capability list: cannot check"]
    missing = sorted(set(bnd) - set(amb))
    if missing:
        return [
            f"{name}: SecureBits=noroot* but AmbientCapabilities= lacks {' '.join(missing)} "
            "(a uid-0 execve gets no capabilities from its bounding set under noroot)"
        ]
    return []


def check_units_caps(root: Path) -> list[str]:
    errs = []
    sysd = root / "packaging" / "systemd"
    for d in (sysd, sysd / "focal"):
        for unit in sorted(d.glob("*.service")):
            base = unit.read_text()
            rel = unit.relative_to(sysd)
            errs += check_noroot_caps(str(rel), [base])
            for drop in sorted((d / f"{unit.name}.d").glob("*")):
                errs += check_noroot_caps(f"{rel} + {drop.name}", [base, drop.read_text()])
    return errs


def static_checks(root: Path) -> list[str]:
    return (
        check_classified(workspace_programs(root))
        + check_workflows(root)
        + check_build_deb(root)
        + check_scripts(root)
        + check_units_caps(root)
    )


# --------------------------------------------------------------- packages --


def read_deb(path: Path) -> tuple[dict[str, Entry], dict[str, bytes], str, str]:
    """(entries, file contents, package name, architecture) of a .deb."""
    fields = {}
    for key in ("Package", "Architecture"):
        fields[key] = subprocess.run(
            ["dpkg-deb", "-f", str(path), key], check=True, capture_output=True, text=True
        ).stdout.strip()
    data = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(path)], check=True, capture_output=True).stdout
    return (*read_tar(data), fields["Package"], fields["Architecture"])


def read_tar(data: bytes) -> tuple[dict[str, Entry], dict[str, bytes]]:
    entries: dict[str, Entry] = {}
    contents: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for ti in tf.getmembers():
            p = "/" + ti.name.lstrip("./").rstrip("/") if ti.name not in (".", "./") else "/"
            if p == "/":
                continue
            if ti.isdir():
                kind, digest = "d", ""
            elif ti.issym():
                kind, digest = "l", ti.linkname
            elif ti.isfile():
                f = tf.extractfile(ti)
                body = f.read() if f else b""
                contents[p] = body
                kind, digest = "f", hashlib.sha256(body).hexdigest()
            else:
                kind, digest = "?", ""
            entries[p] = Entry(kind, ti.mode & 0o7777, ti.uname or str(ti.uid), ti.gname or str(ti.gid), digest)
    return entries, contents


def read_rpm(path: Path) -> tuple[dict[str, Entry], dict[str, bytes], str, str]:
    """(entries, file contents, package name, architecture) of an .rpm.

    Metadata from rpm's header (modes, owners); contents from the payload
    (rpm2archive, or rpm2cpio + cpio)."""
    qf = "[%{FILEMODES}\\t%{FILEUSERNAME}\\t%{FILEGROUPNAME}\\t%{FILELINKTOS}\\t%{FILENAMES}\\n]"
    out = subprocess.run(["rpm", "-qp", "--qf", qf, str(path)], check=True, capture_output=True, text=True).stdout
    name, arch = subprocess.run(
        ["rpm", "-qp", "--qf", "%{NAME} %{ARCH}", str(path)], check=True, capture_output=True, text=True
    ).stdout.split()
    payload = subprocess.run(["rpm2archive", "-"], input=path.read_bytes(), check=True, capture_output=True).stdout
    _, contents = read_tar(payload)
    entries: dict[str, Entry] = {}
    for line in out.splitlines():
        if not line:
            continue
        mode_s, user, group, link, p = line.split("\t", 4)
        mode = int(mode_s)
        if stat.S_ISDIR(mode):
            kind, digest = "d", ""
        elif stat.S_ISLNK(mode):
            kind, digest = "l", link
        elif stat.S_ISREG(mode):
            kind, digest = "f", hashlib.sha256(contents.get(p, b"")).hexdigest()
        else:
            kind, digest = "?", ""
        entries[p] = Entry(kind, mode & 0o7777, user, group, digest)
    deb_arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, arch)
    return entries, contents, name, deb_arch


def is_program(p: str) -> bool:
    return bool(re.fullmatch(r"/usr/s?bin/robodr-[a-z0-9-]+", p))


def check_package(label: str, variant: str, entries: dict[str, Entry], contents: dict[str, bytes], root: Path) -> list[str]:
    errs = []
    for p, e in sorted(entries.items()):
        if e.owner != "root" or e.group != "root":
            errs.append(f"{label}: {p} owned by {e.owner}:{e.group}")
        if e.kind == "?":
            errs.append(f"{label}: {p} is not a file, directory or link")
        if e.kind != "l" and e.mode & 0o6022:
            errs.append(f"{label}: {p} has mode {e.mode:04o} (setuid/setgid or group/other-writable)")
        if not p.startswith(ALLOWED_ROOTS) and p not in ("/usr", "/etc"):
            errs.append(f"{label}: {p} is outside /usr and /etc/robodr (state belongs to tmpfiles)")
        if e.kind == "f" and e.mode & 0o111 and is_program(p) and e.mode != 0o755:
            errs.append(f"{label}: {p} has mode {e.mode:04o}, programs are 0755")
    for p, body in sorted(contents.items()):
        for m in SECRET_MARKERS:
            if m.search(body):
                errs.append(f"{label}: {p} contains private key material ({m.pattern!r})")
    progs = {p.rsplit("/", 1)[1] for p in entries if is_program(p)}
    want = variant_programs(variant)
    for p in sorted(want - progs):
        errs.append(f"{label}: lacks {p}")
    for p in sorted(progs - want):
        errs.append(f"{label}: ships {p}, which {variant} must not")
    for p in sorted(progs & set(PROGRAMS)):
        d, _ = PROGRAMS[p]
        if f"/{d}/{p}" not in entries:
            errs.append(f"{label}: {p} is not in /{d}")
    for prog, units in UNITS.items():
        for u in units:
            has_unit = f"/usr/lib/systemd/system/{u}" in entries
            if has_unit != (prog in progs):
                errs.append(f"{label}: {u} {'without' if has_unit else 'missing for'} {prog}")
    for prog in sorted(progs):
        for page in sorted((root / "man").glob(f"{prog}.[1-8]")):
            sec = page.suffix[1:]
            if f"/usr/share/man/man{sec}/{page.name}.gz" not in entries:
                errs.append(f"{label}: no man page {page.name} for {prog}")
    return errs


def compare(label: str, a: dict[str, Entry], b: dict[str, Entry], only_a: list[str], only_b: list[str], ignore_content) -> list[str]:
    errs = []
    for p in sorted(set(a) - set(b)):
        if not any(fnmatch(p, g) for g in only_a):
            errs.append(f"{label}: {p} only in the first package")
    for p in sorted(set(b) - set(a)):
        if not any(fnmatch(p, g) for g in only_b):
            errs.append(f"{label}: {p} only in the second package")
    for p in sorted(set(a) & set(b)):
        ea, eb = a[p], b[p]
        if (ea.kind, ea.mode) != (eb.kind, eb.mode):
            errs.append(f"{label}: {p}: {ea.kind} {ea.mode:04o} vs {eb.kind} {eb.mode:04o}")
        elif ea.digest != eb.digest and not ignore_content(p):
            errs.append(f"{label}: {p}: content differs")
    return errs


def focal_differs(p: str) -> bool:
    # Programs (static vs glibc), the units and the drop-in examples that
    # have a systemd 245 variant, the man pages / docs are the same files.
    return (
        is_program(p)
        or p.startswith("/usr/lib/systemd/system/")
        or p.startswith("/usr/share/doc/robodr/examples/robodr-")
        or p in ("/usr/share/doc/robodr/md5sums",)
    )


def rpm_owned(entries: dict[str, Entry]) -> dict[str, Entry]:
    """The .deb's entries an RPM owns: everything but the system directories
    (/usr, /usr/bin, ...), which build-rpm.sh leaves to the filesystem and
    systemd packages (only directories with a robodr* component are %dir)."""
    return {
        p: e
        for p, e in entries.items()
        if e.kind != "d" or any(c.startswith("robodr") for c in p.split("/"))
    }


def package_checks(debs: list[Path], rpms: list[Path], root: Path) -> list[str]:
    errs: list[str] = []
    loaded = []
    for path in debs:
        entries, contents, name, arch = read_deb(path)
        loaded.append(("deb", name, arch, entries, path))
        errs += check_package(path.name, name, entries, contents, root)
    for path in rpms:
        entries, contents, name, arch = read_rpm(path)
        if name != STD:
            errs.append(f"{path.name}: package {name}, only {STD} has an RPM")
        loaded.append(("rpm", name, arch, entries, path))
        errs += check_package(path.name, STD, entries, contents, root)
    for kind, name, arch, entries, path in loaded:
        if kind == "rpm":
            for k2, n2, a2, e2, p2 in loaded:
                if k2 == "deb" and n2 == STD and a2 == arch:
                    errs += compare(f"{p2.name} vs {path.name}", rpm_owned(e2), entries, [], [], is_program)
        if kind == "deb" and name == FOCAL:
            for k2, n2, a2, e2, p2 in loaded:
                if k2 == "deb" and n2 == STD and a2 == arch:
                    errs += compare(f"{p2.name} vs {path.name}", e2, entries, STANDARD_ONLY, FOCAL_ONLY, focal_differs)
    return errs


# -------------------------------------------------------------- self-test --


def self_test() -> int:
    failed = 0

    def expect(name: str, errs: list[str], ok: bool) -> None:
        nonlocal failed
        if (not errs) != ok:
            failed += 1
            print(f"self-test FAIL: {name}: {errs}", file=sys.stderr)

    wf = """jobs:
  a:
    steps:
      - name: deb
        env:
          ROBODR_DEB_REQUIRE: {std}
        run: packaging/build-deb.sh --bin-dir x --arch amd64
      - name: focal
        env:
          ROBODR_DEB_REQUIRE: {foc}
        run: packaging/build-deb.sh --variant focal --bin-dir x --arch amd64
"""
    std = " ".join(sorted(variant_programs(STD) - ALWAYS_REQUIRED))
    foc = " ".join(sorted(variant_programs(FOCAL) - ALWAYS_REQUIRED))
    got = workflow_requires(wf.format(std=std, foc=foc))
    expect("workflow variants", [] if [v for _, v, _ in got] == [STD, FOCAL] else ["variants"], True)

    def wf_errs(text: str) -> list[str]:
        out = []
        for _, v, req in workflow_requires(text):
            if req - ALWAYS_REQUIRED != variant_programs(v) - ALWAYS_REQUIRED:
                out.append(v)
        return out

    expect("workflow lists match", wf_errs(wf.format(std=std, foc=foc)), True)
    expect("focal list lacks seal", wf_errs(wf.format(std=std, foc=foc.replace("robodr-seal", ""))), False)
    expect("focal list names pulsard", wf_errs(wf.format(std=std, foc=foc + " robodr-pulsard")), False)
    expect("unclassified program", check_classified(set(PROGRAMS) | {"robodr-new"}), False)
    expect("all classified", check_classified(set(PROGRAMS) | set(NEVER_PACKAGED)), True)

    loops = unit_loops("for u in a.service robodr-x.service robodr-y.service; do\n    systemctl try-restart \"$u\" || true\ndone\n")
    expect("loop parse", [] if loops.get("try-restart") == {"robodr-x.service", "robodr-y.service"} else [str(loops)], True)

    def ent(kind="f", mode=0o644, owner="root", digest="x"):
        return Entry(kind, mode, owner, "root", digest)

    base = {f"/{d}/{p}": ent(mode=0o755) for p, (d, vs) in PROGRAMS.items() if STD in vs}
    for prog, units in UNITS.items():
        for u in units:
            base[f"/usr/lib/systemd/system/{u}"] = ent()
    for page in (ROOT / "man").glob("robodr-*.[1-8]"):
        if page.stem in base or any(k.endswith("/" + page.stem) for k in base):
            base[f"/usr/share/man/man{page.suffix[1:]}/{page.name}.gz"] = ent()
    expect("clean package", check_package("t", STD, base, {}, ROOT), True)
    expect("setuid", check_package("t", STD, {**base, "/usr/bin/robodr-replay": ent(mode=0o4755)}, {}, ROOT), False)
    expect("not root", check_package("t", STD, {**base, "/usr/share/x": ent(owner="robodr")}, {}, ROOT), False)
    expect("state in payload", check_package("t", STD, {**base, "/var/lib/robodr/x": ent()}, {}, ROOT), False)
    expect("secret", check_package("t", STD, base, {"/usr/share/x": b"-----BEGIN PRIVATE KEY-----\n"}, ROOT), False)
    no_seal = {k: v for k, v in base.items() if not k.endswith("/robodr-seal")}
    expect("program missing", check_package("t", STD, no_seal, {}, ROOT), False)
    no_unit = {k: v for k, v in base.items() if not k.endswith("robodr-deliverd.service")}
    expect("unit missing", check_package("t", STD, no_unit, {}, ROOT), False)
    expect("compare equal", compare("c", base, dict(base), [], [], is_program), True)
    expect("compare mode", compare("c", base, {**base, "/usr/share/x": ent()}, [], [], is_program), False)
    changed = {**base, "/usr/lib/systemd/system/robodr-agentd.service": ent(digest="y")}
    expect("compare content", compare("c", base, changed, [], [], is_program), False)
    prog_changed = {**base, "/usr/sbin/robodr-agentd": ent(mode=0o755, digest="y")}
    expect("program content may differ", compare("c", base, prog_changed, [], [], is_program), True)
    owned = rpm_owned({"/usr": ent("d"), "/usr/share/doc/robodr": ent("d"), "/usr/bin/x": ent()})
    expect("rpm_owned", [] if set(owned) == {"/usr/share/doc/robodr", "/usr/bin/x"} else [str(owned)], True)
    nr = "[Service]\nCapabilityBoundingSet=CAP_BPF CAP_PERFMON\nSecureBits=noroot-locked\n"
    expect("noroot without ambient", check_noroot_caps("u", [nr]), False)
    expect("noroot with ambient", check_noroot_caps("u", [nr + "AmbientCapabilities=CAP_BPF CAP_PERFMON\n"]), True)
    expect("drop-in widens bounding only", check_noroot_caps(
        "u", [nr + "AmbientCapabilities=CAP_BPF CAP_PERFMON\n", "[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN\n"]), False)
    expect("no noroot: not required", check_noroot_caps("u", ["[Service]\nCapabilityBoundingSet=CAP_BPF\n"]), True)
    total = 27
    print(f"self-test: {total - failed}/{total} passed")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--deb", action="append", default=[], type=Path)
    ap.add_argument("--rpm", action="append", default=[], type=Path)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--root", type=Path, default=ROOT)
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    errs = static_checks(a.root)
    n = 0
    if a.deb or a.rpm:
        errs += package_checks(a.deb, a.rpm, a.root)
        n = len(a.deb) + len(a.rpm)
    for e in errs:
        print(f"ERROR: {e}", file=sys.stderr)
    print(f"check-packages: {len(PROGRAMS)} programs, {n} package(s), {len(errs)} error(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
