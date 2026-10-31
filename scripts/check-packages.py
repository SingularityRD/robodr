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
     The units in GATED (gateway, executor; T9) are never try-restarted
     on upgrade: the deb postinst / rpm post hand exactly them to
     mark_pending_restart (install-bundle.sh restarts them through the
     safety-state gate).

  8. Service identities (review: one uid shared by the exporters and the
     gateway let each read the others' credentials): no two units run as
     the same non-root User=; every User= and every tmpfiles.d owner is a
     sysusers.d user; the units in OWN_USER run as exactly that user (the
     focal variants too), hide /run/credentials except their own
     directory, and the deb postinst / rpm post migration
     (migrate_exporter_users, the same block in both) moves exactly the
     tmpfiles directories of those users (and the gateway's
     StateDirectory) from robodr to them; the focal credential helper maps
     the same units to the same users.
  9. robodr-firewall-gw-rules.service (regular and focal) renders the
     ruleset into a file and applies that file: no pipe into a shell, a
     bounded CapabilityBoundingSet (RULES_CAPS), ProtectSystem=strict,
     ProtectHome=, PrivateTmp=, NoNewPrivileges=, a SystemCallFilter=.

  10. release.yml: `prepare` and `publish` refuse a tag whose commit is
     not on main (git merge-base --is-ancestor); every build job has an
     independent rebuild job (the toolchain from
     scripts/ci-install-pinned-toolchain.sh, never rustup) that `publish`
     needs, and `publish` runs scripts/compare-rebuild.py before it writes
     SHA256SUMS and signs.

  11. Resource caps (sales-readiness T76): every long-running service
     (regular and focal; Type= other than oneshot) sets MemoryMax=, so a
     runaway RoboDR daemon hits its own cgroup limit before it can push the
     OOM killer onto the robot's motion stack; the units in CPU_CAPPED
     (event-driven detectors that an event storm could make spin) also set
     CPUQuota=. (The inline gateway is deliberately not CPU-capped: it is a
     real-time process in the motion path, where throttling is latency.)
     Those capped detectors also never give up restarting
     (StartLimitIntervalSec=0, OOMPolicy=stop, Restart=on-failure): an
     attacker who can drive them into their caps again and again must not
     be able to switch detection off for good.

  12. The sensor box image recipe (packaging/sensor-box/image, T77): the
     root partition is read-only (ReadOnly=yes), build-image.sh verifies
     the bundle's minisign signature before it extracts anything and then
     its SHA256SUMS, has no unsigned switch, the post-install script checks
     the package digest and refuses an image with keys, the first-boot
     script generates the keys with robodr-setup init, nftables.service
     loads the host firewall through robodr-nft-load (which falls back to
     the shipped strict default), and no file of the recipe holds key
     material.

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
     each program an ELF of type ET_DYN (PIE, static-pie for robodr-focal),
     each unit together with its program, and a man page for every
     shipped program that has one in man/; the customer documentation
     (no drafts), the demo captures and the operator examples
     (SHIPPED_DOCS).
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
    "robodr-depot": ("usr/sbin", BOTH),
    "robodr-enroll": ("usr/sbin", BOTH),
    # Operator tools (crates/robodr-ops): first-boot setup, support bundle,
    # metrics textfile exporter.
    "robodr-setup": ("usr/sbin", BOTH),
    "robodr-support-bundle": ("usr/sbin", BOTH),
    "robodr-metrics": ("usr/bin", BOTH),
    # Pulsar-bound (glibc, eBPF, needs BTF): not static, not on systemd 245.
    "robodr-pulsard": ("usr/sbin", frozenset({STD})),
    # Base station only: use the robodr package there.
    "robodr-anchor-receiver": ("usr/bin", frozenset({STD})),
}
NEVER_PACKAGED = {
    "robodr-safety-replay": "test tool of robodr-deliverd",
    "robodr-release": "SOC / build-side delivery artifact tool",
    "robodr-signer": "key-ceremony check tool, used next to robodr-release (the PKCS#11 adapter script is packaged)",
    "robodr-attack-sim": "PoC attack simulator (lab and demo use, never on a robot)",
    "robodr-demo-soc": "PoC demo SOC receiver (lab and demo use)",
}
# build-deb.sh requires these whatever ROBODR_DEB_REQUIRE says.
ALWAYS_REQUIRED = {"robodr-commission", "robodr-replay", "robodr-ros2-watch",
                   "robodr-setup", "robodr-support-bundle", "robodr-metrics"}

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
    "robodr-depot": ["robodr-depot.service"],
    # Installed from packaging/metrics/ (a oneshot and its timer).
    "robodr-metrics": ["robodr-metrics.service", "robodr-metrics.timer"],
}
NOT_STOPPED = {"robodr-firewall-gw-rules.service"}
# Not restarted on upgrade: the timer runs the new binary at its next run.
NOT_RESTARTED = {"robodr-metrics.service", "robodr-metrics.timer"}
# Restarted on upgrade only through the safety-state gate (T9): the
# maintainer scripts mark them pending, never try-restart them.
GATED = {"robodr-executor.service", "robodr-firewall-gw.service"}

# Units that used to share the robodr user, and their own users now.
OWN_USER = {
    "robodr-spool-export.service": "robodr-spool",
    "robodr-kafka-publish.service": "robodr-kafka",
    "robodr-uplink.service": "robodr-uplink",
    "robodr-firewall-gw.service": "robodr-gw",
}
# Units that must also cap their CPU time (check 11).
CPU_CAPPED = {"robodr-pulsard.service"}
# The only capabilities the firewall ruleset's commands need.
RULES_CAPS = {"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_MODULE"}

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
# Every variant ships the third-party notices and the eBPF source offer.
NOTICE_FILES = (
    "/usr/share/doc/robodr/THIRD_PARTY_NOTICES",
    "/usr/share/doc/robodr/GPL-2.0-SOURCE-OFFER",
)
# Every variant ships the customer documentation, the demo data and the
# operator examples (sales-readiness T49, T70, T87).
SHIPPED_DOCS = (
    "/usr/share/doc/robodr/customer/quick-start.md",
    "/usr/share/doc/robodr/customer/known-limitations.md",
    "/usr/share/doc/robodr/customer/support-matrix.md",
    "/usr/share/doc/robodr/demo/README.md",
    "/usr/share/doc/robodr/demo/SHA256SUMS",
    "/usr/share/doc/robodr/demo/fastrtps_baseline.pcap",
    "/usr/share/doc/robodr/demo/fastrtps_rogue_cmd_vel.pcap",
    "/usr/share/doc/robodr/examples/metrics/robodr-alerts.example.yml",
    "/usr/share/doc/robodr/examples/modules-load.d/robodr.conf.example",
)
# A key is its header followed by its base64 body. The header alone is not
# key material: programs that detect keys (robodr-support-bundle's final
# scan, minisign parsing) carry it as a string literal, and string literals
# sit back to back in a binary's read-only data.
SECRET_MARKERS = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{40,}"),
    # A minisign secret key file: its base64 body starts with the algorithm
    # bytes "Ed" and the KDF ("Sc" encrypted, two zero bytes with -W) and
    # checksum "B2". A signature ("signature from minisign secret key",
    # body "RUS..." / "RWS...") is not key material.
    re.compile(rb"untrusted comment: [ -~]{0,120}secret key\r?\n(?:RWRTY0Iy|RWQAAEIy)[A-Za-z0-9+/=]{100,}"),
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
    `--variant focal` (build-deb.sh) or runs `scripts/ci-rebuild.sh focal`
    (release.yml's independent rebuild). A step is the text up to the next
    "- name:" line.
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
        variant = FOCAL if re.search(r"--variant focal|ci-rebuild\.sh focal\b", step) else STD
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


FOR_RE = re.compile(r"for u in (.*?); do\n(.*?)\n\s*done\b", re.S)


def unit_loops(text: str) -> dict[str, set[str]]:
    """The unit lists of the script's `for u in ...; do` loops, keyed by the
    systemctl verb of the loop body (try-restart / stop / start)."""
    out: dict[str, set[str]] = {}
    for m in FOR_RE.finditer(text):
        units = set(re.findall(r"robodr-[a-z0-9-]+\.(?:service|timer)", m.group(1)))
        body = m.group(2)
        verb = ("try-restart" if "try-restart" in body else "stop" if "systemctl stop" in body
                else "pending" if "mark_pending_restart" in body else "other")
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
        errs += check_unit_loops(rel, verb, unit_loops((pk / rel).read_text()), want)
    return errs


def check_unit_loops(rel: str, verb: str, loops: dict[str, set[str]], want: set[str]) -> list[str]:
    errs = []
    if verb == "try-restart":
        # T9: the gated units go to mark_pending_restart instead.
        pend = loops.get("pending")
        if pend != GATED:
            errs.append(f"packaging/{rel}: marks {sorted(pend or [])} pending-restart, want exactly {sorted(GATED)}")
        want = want - GATED - NOT_RESTARTED
    got = loops.get(verb)
    if got is None:
        return errs + [f"packaging/{rel}: no `for u in ...` loop that runs systemctl {verb}"]
    for u in sorted(want - got):
        errs.append(f"packaging/{rel}: does not {verb} {u}")
    for u in sorted(got - want):
        errs.append(f"packaging/{rel}: {verb}s {u}, which is not a shipped, stoppable unit"
                    + (" (a gated unit: only through the safety-state gate)" if u in GATED else ""))
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


def check_unit_resources_text(name: str, text: str) -> list[str]:
    if (unit_values(text, "Type") or ["simple"])[-1] == "oneshot":
        return []
    errs = []
    if not unit_values(text, "MemoryMax"):
        errs.append(f"{name}: long-running service without MemoryMax= (a runaway daemon is not capped by its own cgroup)")
    if Path(name).name in CPU_CAPPED and not unit_values(text, "CPUQuota"):
        errs.append(f"{name}: without CPUQuota= (an event storm must not take the robot's CPU)")
    if Path(name).name in CPU_CAPPED:
        if (unit_values(text, "StartLimitIntervalSec") or [""])[-1] != "0":
            errs.append(f"{name}: needs StartLimitIntervalSec=0 (repeated kills at its caps must not leave detection off)")
        if (unit_values(text, "OOMPolicy") or [""])[-1] != "stop" or (unit_values(text, "Restart") or [""])[-1] not in (
                "on-failure", "always"):
            errs.append(f"{name}: needs OOMPolicy=stop and Restart=on-failure (an OOM kill restarts the whole daemon)")
    return errs


def check_unit_resources(root: Path) -> list[str]:
    errs = []
    sysd = root / "packaging" / "systemd"
    for d in (sysd, sysd / "focal"):
        for unit in sorted(d.glob("*.service")):
            errs += check_unit_resources_text(str(unit.relative_to(sysd)), unit.read_text())
    return errs


def check_image_recipe_texts(files: dict[str, bytes]) -> list[str]:
    """files: path relative to packaging/sensor-box/image -> content."""
    errs = []
    t = {k: v.decode("utf-8", "replace") for k, v in files.items()}
    where = "packaging/sensor-box/image"
    root = t.get("mkosi.repart/10-root.conf", "")
    if unit_values(root, "Type") != ["root"] or unit_values(root, "ReadOnly") != ["yes"]:
        errs.append(f"{where}/mkosi.repart/10-root.conf: the root partition must be Type=root, ReadOnly=yes")
    code = "\n".join(ln for ln in t.get("build-image.sh", "").splitlines() if not ln.lstrip().startswith("#"))
    v, x = code.find("minisign -V"), code.find("tar ")
    if v < 0 or x < 0 or v > x:
        errs.append(f"{where}/build-image.sh: must verify the minisign signature before extracting the bundle")
    if x < 0 or "sha256sum -c" not in code[x:]:
        errs.append(f"{where}/build-image.sh: must check the bundle's SHA256SUMS after extracting it")
    if re.search(r"unsigned|minisign -V[^\n]*\|\|\s*true", code, re.I):
        errs.append(f"{where}/build-image.sh: has a way around the signature check")
    post = t.get("mkosi.postinst.chroot", "")
    if "sha256sum -c" not in post or "/etc/robodr/keys" not in post:
        errs.append(f"{where}/mkosi.postinst.chroot: must check the package digest and refuse an image with keys")
    late = t.get("mkosi.extra/usr/lib/robodr-image/robodr-image-late", "")
    if 'robodr-setup "$@"' not in late or "set -- init" not in late:
        errs.append(f"{where}/robodr-image-late: first boot must generate the keys with robodr-setup init")
    drop = t.get("mkosi.extra/usr/lib/systemd/system/nftables.service.d/50-robodr-image.conf", "")
    load = t.get("mkosi.extra/usr/lib/robodr-image/robodr-nft-load", "")
    if unit_values(drop, "ExecStart") != ["/usr/lib/robodr-image/robodr-nft-load"] or \
            "nftables.default.conf" not in load:
        errs.append(f"{where}: nftables.service must load the firewall through robodr-nft-load, "
                    "which falls back to the strict default (no box without a host firewall)")
    for name, body in sorted(files.items()):
        if name.endswith((".key", ".pem")):
            errs.append(f"{where}/{name}: key file in the image recipe")
        for m in SECRET_MARKERS:
            if m.search(body):
                errs.append(f"{where}/{name}: contains private key material")
    return errs


def check_image_recipe(root: Path) -> list[str]:
    d = root / "packaging" / "sensor-box" / "image"
    if not d.is_dir():
        return ["packaging/sensor-box/image: missing"]
    files = {str(f.relative_to(d)): f.read_bytes() for f in sorted(d.rglob("*")) if f.is_file()}
    return check_image_recipe_texts(files)


def unit_values(text: str, key: str) -> list[str]:
    """Every value of KEY= in a unit (in order; an empty one resets)."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        if k == key:
            out = [] if not v else out + [v]
    return out


def sysusers_users(text: str) -> set[str]:
    return {f[1] for f in (ln.split() for ln in text.splitlines()) if len(f) > 1 and f[0] == "u"}


def tmpfiles_owners(text: str) -> dict[str, str]:
    """path -> user of every `d` line."""
    out = {}
    for ln in text.splitlines():
        f = ln.split()
        if len(f) >= 4 and f[0] == "d":
            out[f[1]] = f[3]
    return out


MIGRATE_RE = re.compile(r"# >>> migrate_agentd_tree.*?# <<< migrate_exporter_users\n", re.S)


def check_identities_text(units: dict[str, str], focal: dict[str, str], sysusers: str, tmpfiles: str,
                          postinst: str, rpm_post: str, helper: str) -> list[str]:
    errs = []
    users = sysusers_users(sysusers)
    seen: dict[str, str] = {}
    for name, text in sorted(units.items()):
        us = unit_values(text, "User")
        u = us[-1] if us else ""
        if u and u != "root":
            if u not in users:
                errs.append(f"packaging/systemd/{name}: User={u} is not a sysusers.d user")
            if u in seen:
                errs.append(f"packaging/systemd/{name}: User={u} is also {seen[u]}'s user (one uid per service)")
            seen[u] = name
    for path, owner in tmpfiles_owners(tmpfiles).items():
        if owner != "root" and owner not in users:
            errs.append(f"packaging/tmpfiles.d/robodr.conf: {path} owner {owner} is not a sysusers.d user")
    for name, want in OWN_USER.items():
        for label, texts in (("", units), ("focal/", focal)):
            text = texts.get(name)
            if text is None:
                errs.append(f"packaging/systemd/{label}{name}: missing")
                continue
            us = unit_values(text, "User")
            if us != [want]:
                errs.append(f"packaging/systemd/{label}{name}: User={us} (want {want}, its own user)")
            if unit_values(text, "TemporaryFileSystem") != ["/run/credentials:ro"]:
                errs.append(f"packaging/systemd/{label}{name}: no TemporaryFileSystem=/run/credentials:ro "
                            "(other units' credentials visible)")
            binds = unit_values(text, "BindReadOnlyPaths")
            if any(b.lstrip("-") != f"/run/credentials/{name}" for b in binds):
                errs.append(f"packaging/systemd/{label}{name}: BindReadOnlyPaths={binds} exposes more than its own credentials")
            if (unit_values(text, "LoadCredential") or "robodr-load-credential load" in text) and not binds:
                errs.append(f"packaging/systemd/{label}{name}: loads credentials but does not bind /run/credentials/{name}")
            if label and f"load {name} " in text and f"load {name} {want} " not in text:
                errs.append(f"packaging/systemd/focal/{name}: robodr-load-credential hands the credential to another user than {want}")
            if f"{name}) own={want} ;;" not in helper:
                errs.append(f"packaging/focal/robodr-load-credential: does not map {name} to {want}")
    owners = tmpfiles_owners(tmpfiles)
    want_pairs = {f"{p}:{u}" for p, u in owners.items() if u in OWN_USER.values()}
    gw = units.get("robodr-firewall-gw.service", "")
    for sd in unit_values(gw, "StateDirectory"):
        want_pairs.add(f"/var/lib/{sd}:{OWN_USER['robodr-firewall-gw.service']}")
    m_deb, m_rpm = MIGRATE_RE.search(postinst), MIGRATE_RE.search(rpm_post)
    if not m_deb:
        errs.append("packaging/deb/postinst: no migrate_agentd_tree .. migrate_exporter_users block")
    else:
        got = set(re.findall(r"(/var/lib/robodr/[a-z0-9/_-]+:robodr-[a-z]+)", m_deb.group(0)))
        for x in sorted(want_pairs - got):
            errs.append(f"packaging/deb/postinst: migrate_exporter_users does not move {x}")
        for x in sorted(got - want_pairs):
            errs.append(f"packaging/deb/postinst: migrate_exporter_users moves {x}, not a tree of that user")
        if not m_rpm or m_rpm.group(0) != m_deb.group(0):
            errs.append("packaging/rpm/post: its migrate block differs from packaging/deb/postinst's")
    for label, text in (("deb/postinst", postinst), ("rpm/post", rpm_post)):
        if not re.search(r"^\s*migrate_exporter_users$", text, re.M):
            errs.append(f"packaging/{label}: never calls migrate_exporter_users")
    return errs


def check_identities(root: Path) -> list[str]:
    pk = root / "packaging"
    units = {f.name: f.read_text() for f in (pk / "systemd").glob("*.service")}
    focal = {f.name: f.read_text() for f in (pk / "systemd" / "focal").glob("*.service")}
    return check_identities_text(
        units, focal,
        (pk / "sysusers.d" / "robodr.conf").read_text(),
        (pk / "tmpfiles.d" / "robodr.conf").read_text(),
        (pk / "deb" / "postinst").read_text(),
        (pk / "rpm" / "post").read_text(),
        (pk / "focal" / "robodr-load-credential").read_text(),
    )


def check_rules_unit_text(name: str, text: str) -> list[str]:
    errs = []
    for k in ("ExecStart", "ExecStartPre"):
        for v in unit_values(text, k):
            if re.search(r"\|\s*(/bin/|/usr/bin/)?(ba|da)?sh\b", v):
                errs.append(f"{name}: {k}= pipes into a shell ({v})")
    starts = unit_values(text, "ExecStart")
    if len(starts) != 1 or not re.fullmatch(r"/bin/sh -eu /run/robodr-firewall-gw-rules/\S+", starts[0]):
        errs.append(f"{name}: ExecStart= must apply the rendered file (/bin/sh -eu /run/robodr-firewall-gw-rules/...), got {starts}")
    caps = set(" ".join(unit_values(text, "CapabilityBoundingSet")).split())
    if not caps or caps - RULES_CAPS or any(c.startswith("~") for c in caps):
        errs.append(f"{name}: CapabilityBoundingSet={sorted(caps)} (allowed at most {sorted(RULES_CAPS)})")
    for k, v in (("ProtectSystem", "strict"), ("ProtectHome", "yes"), ("PrivateTmp", "yes"), ("NoNewPrivileges", "yes")):
        if unit_values(text, k)[-1:] != [v]:
            errs.append(f"{name}: needs {k}={v}")
    if not any("@system-service" in v for v in unit_values(text, "SystemCallFilter")):
        errs.append(f"{name}: needs SystemCallFilter=@system-service")
    return errs


def check_rules_unit(root: Path) -> list[str]:
    sd = root / "packaging" / "systemd"
    errs = []
    for f in (sd / "robodr-firewall-gw-rules.service", sd / "focal" / "robodr-firewall-gw-rules.service"):
        errs += check_rules_unit_text(str(f.relative_to(root)), f.read_text())
    return errs


def job_blocks(text: str) -> dict[str, str]:
    """Top-level jobs of a workflow: name -> its text (by indentation)."""
    out, name, buf, on = {}, None, [], False
    for ln in text.splitlines():
        if re.match(r"^jobs:\s*$", ln):
            on = True
            continue
        if not on:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", ln)
        if m:
            if name:
                out[name] = "\n".join(buf)
            name, buf = m.group(1), []
        elif name:
            buf.append(ln)
    if name:
        out[name] = "\n".join(buf)
    return out


REBUILDS = {"build": "rebuild-deb", "build-rpm": "rebuild-rpm", "build-static": "rebuild-static"}


def check_release_workflow_text(text: str) -> list[str]:
    errs = []
    jobs = job_blocks(text)
    for j in ("prepare", "publish"):
        # scripts/release-gate.py line: on origin/main, or on the version's
        # release/X.Y line (merge-base --is-ancestor; refused otherwise).
        if "scripts/release-gate.py line" not in jobs.get(j, ""):
            errs.append(f"release.yml: job {j} does not check that the tagged commit is on main")
    pub = jobs.get("publish", "")
    m = re.search(r"needs:\s*\[([^\]]*)\]", pub)
    needs = {x.strip() for x in m.group(1).split(",")} if m else set()
    for build, rebuild in REBUILDS.items():
        rb = jobs.get(rebuild, "")
        if not rb:
            errs.append(f"release.yml: no independent rebuild job {rebuild} for {build}")
            continue
        if "ci-install-pinned-toolchain.sh" not in rb or "ci-install-rustup.sh" in rb or "rustup " in rb:
            errs.append(f"release.yml: {rebuild} must install the toolchain from pinned artifacts, not rustup")
        if "ci-rebuild.sh" not in rb:
            errs.append(f"release.yml: {rebuild} does not run scripts/ci-rebuild.sh")
        if rebuild not in needs:
            errs.append(f"release.yml: publish does not need {rebuild}")
    fin_at, sign_at = pub.find("scripts/release-finalize.sh"), pub.find("scripts/release-sign.sh")
    if not (0 <= fin_at < sign_at):
        errs.append("release.yml: publish must run scripts/release-finalize.sh before scripts/release-sign.sh")
    return errs


def check_release_finalize_text(text: str) -> list[str]:
    """scripts/release-finalize.sh compares the rebuild before it writes
    SHA256SUMS (release-sign.sh signs only what SHA256SUMS lists)."""
    cmp_at = text.find("compare-rebuild.py")
    sums_at = text.find(">\"$work/SHA256SUMS\"")
    if not (0 <= cmp_at < sums_at):
        return ["scripts/release-finalize.sh: must run compare-rebuild.py before writing SHA256SUMS"]
    return []


def check_release_workflow(root: Path) -> list[str]:
    return check_release_workflow_text((root / ".github" / "workflows" / "release.yml").read_text()) + \
        check_release_finalize_text((root / "scripts" / "release-finalize.sh").read_text())


def static_checks(root: Path) -> list[str]:
    return (
        check_classified(workspace_programs(root))
        + check_workflows(root)
        + check_build_deb(root)
        + check_scripts(root)
        + check_units_caps(root)
        + check_unit_resources(root)
        + check_image_recipe(root)
        + check_identities(root)
        + check_rules_unit(root)
        + check_release_workflow(root)
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
            # removeprefix, not lstrip: ".hidden" keeps its dot.
            if ti.name in (".", "./", "/"):
                continue
            p = "/" + ti.name.removeprefix("./").removeprefix("/").rstrip("/")
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


def deb_conffiles(path: Path) -> set[str]:
    """The .deb's conffiles (DEBIAN/conffiles)."""
    r = subprocess.run(["dpkg-deb", "-I", str(path), "conffiles"], capture_output=True, text=True)
    return {line.strip() for line in r.stdout.splitlines() if line.strip()} if r.returncode == 0 else set()


def rpm_fileflags(path: Path) -> dict[str, str]:
    """path -> rpm file flags letters (c config, n noreplace, d doc, l license)."""
    out = subprocess.run(
        ["rpm", "-qp", "--qf", "[%{FILEFLAGS:fflags}\\t%{FILENAMES}\\n]", str(path)],
        check=True, capture_output=True, text=True,
    ).stdout
    flags = {}
    for line in out.splitlines():
        if "\t" in line:
            f, p = line.split("\t", 1)
            flags[p] = f
    return flags


LICENSE_FILES = (
    "/usr/share/doc/robodr/copyright",
    "/usr/share/doc/robodr/licenses/*",
    "/usr/share/doc/robodr/THIRD_PARTY_NOTICES",
    "/usr/share/doc/robodr/GPL-2.0-SOURCE-OFFER",
)


def check_rpm_flags(label: str, flags: dict[str, str], conffiles: set[str] | None) -> list[str]:
    """%license on the licence files (tsflags=nodocs must not drop them),
    %config(noreplace) exactly on the .deb's conffiles."""
    errs = []
    for p, f in sorted(flags.items()):
        if any(fnmatch(p, g) for g in LICENSE_FILES) and "l" not in f:
            errs.append(f"{label}: {p} is not %license (flags {f!r}): dnf --nodocs would drop it")
    config = {p for p, f in flags.items() if "c" in f}
    for p in sorted(config):
        if "n" not in flags[p]:
            errs.append(f"{label}: {p} is %config without noreplace")
    if conffiles is not None:
        for p in sorted(conffiles - config):
            errs.append(f"{label}: deb conffile {p} is not %config in the RPM")
        for p in sorted(config - conffiles):
            errs.append(f"{label}: %config {p} is not a conffile of the .deb")
    return errs


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


def elf_pie_problems(body: bytes) -> list[str]:
    """[] when body is an ELF with e_type ET_DYN (position-independent: a PIE,
    or static-pie for robodr-focal), so the kernel randomises the image."""
    if len(body) < 18 or body[:4] != b"\x7fELF" or body[5] not in (1, 2):
        return ["not an ELF program"]
    e_type = int.from_bytes(body[16:18], "little" if body[5] == 1 else "big")
    if e_type != 3:
        return [f"not position-independent (e_type {e_type}, want 3 ET_DYN)"]
    return []


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
    for p, body in sorted(contents.items()):
        if is_program(p):
            errs += [f"{label}: {p}: {e}" for e in elf_pie_problems(body)]
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
    for p in NOTICE_FILES:
        if p not in entries:
            errs.append(f"{label}: lacks {p} (scripts/third_party_notices.py)")
    for p in SHIPPED_DOCS:
        if p not in entries:
            errs.append(f"{label}: lacks {p} (packaging/build-deb.sh)")
    for p in entries:
        if p.startswith("/usr/share/doc/robodr/customer/") and p.endswith("-draft.md"):
            errs.append(f"{label}: ships the draft {p}")
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
    conffiles: dict[str, set[str]] = {}
    for path in debs:
        entries, contents, name, arch = read_deb(path)
        loaded.append(("deb", name, arch, entries, path))
        errs += check_package(path.name, name, entries, contents, root)
        if name == STD:
            conffiles[arch] = deb_conffiles(path)
    for path in rpms:
        entries, contents, name, arch = read_rpm(path)
        if name != STD:
            errs.append(f"{path.name}: package {name}, only {STD} has an RPM")
        loaded.append(("rpm", name, arch, entries, path))
        errs += check_package(path.name, STD, entries, contents, root)
        errs += check_rpm_flags(path.name, rpm_fileflags(path), conffiles.get(arch))
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


def _elf(e_type: int, be: bool = False) -> bytes:
    """A 64-bit ELF header prefix with the given e_type."""
    ident = b"\x7fELF\x02" + (b"\x02" if be else b"\x01") + b"\x01" + b"\x00" * 9
    return ident + e_type.to_bytes(2, "big" if be else "little") + b"\x00" * 46


def _tar_with(name: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo(name)
        ti.size = 0
        tf.addfile(ti, io.BytesIO(b""))
    return buf.getvalue()


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
    rebuild = wf.format(std=std, foc=foc).replace(
        "packaging/build-deb.sh --variant focal --bin-dir x --arch amd64", "scripts/ci-rebuild.sh focal amd64 out")
    expect("rebuild step is focal", [] if [v for _, v, _ in workflow_requires(rebuild)] == [STD, FOCAL] else ["v"], True)
    expect("unclassified program", check_classified(set(PROGRAMS) | {"robodr-new"}), False)
    expect("all classified", check_classified(set(PROGRAMS) | set(NEVER_PACKAGED)), True)

    loops = unit_loops("for u in a.service robodr-x.service robodr-y.service; do\n    systemctl try-restart \"$u\" || true\ndone\n")
    expect("loop parse", [] if loops.get("try-restart") == {"robodr-x.service", "robodr-y.service"} else [str(loops)], True)
    gated_ok = ("for u in robodr-a.service; do\n    systemctl try-restart \"$u\" || true\ndone\n"
                "for u in robodr-executor.service robodr-firewall-gw.service; do\n    mark_pending_restart \"$u\"\ndone\n")
    want_t = {"robodr-a.service"} | GATED
    expect("gated units pending", check_unit_loops("t", "try-restart", unit_loops(gated_ok), want_t), True)
    expect("gated unit try-restarted", check_unit_loops("t", "try-restart", unit_loops(
        gated_ok.replace("robodr-a.service;", "robodr-a.service robodr-executor.service;")), want_t), False)
    expect("gated unit not pending", check_unit_loops("t", "try-restart", unit_loops(
        gated_ok.replace(" robodr-firewall-gw.service; do\n    mark", "; do\n    mark")), want_t), False)
    # A timer is a unit like a service: stopped on removal, never restarted.
    want_s = {"robodr-a.service", "robodr-metrics.timer"}
    stop_ok = "for u in robodr-a.service robodr-metrics.timer; do\n    systemctl stop \"$u\"\ndone\n"
    expect("timer stopped", check_unit_loops("t", "stop", unit_loops(stop_ok), want_s), True)
    expect("timer not stopped", check_unit_loops("t", "stop", unit_loops(
        stop_ok.replace(" robodr-metrics.timer;", ";")), want_s), False)
    expect("timer not restarted", check_unit_loops("t", "try-restart", unit_loops(
        gated_ok), want_t | {"robodr-metrics.timer"}), True)

    def ent(kind="f", mode=0o644, owner="root", digest="x"):
        return Entry(kind, mode, owner, "root", digest)

    base = {f"/{d}/{p}": ent(mode=0o755) for p, (d, vs) in PROGRAMS.items() if STD in vs}
    for prog, units in UNITS.items():
        for u in units:
            base[f"/usr/lib/systemd/system/{u}"] = ent()
    for page in (ROOT / "man").glob("robodr-*.[1-8]"):
        if page.stem in base or any(k.endswith("/" + page.stem) for k in base):
            base[f"/usr/share/man/man{page.suffix[1:]}/{page.name}.gz"] = ent()
    for n in NOTICE_FILES + SHIPPED_DOCS:
        base[n] = ent()
    expect("clean package", check_package("t", STD, base, {}, ROOT), True)
    no_notices = {k: v for k, v in base.items() if not k.endswith("/THIRD_PARTY_NOTICES")}
    expect("notices missing", check_package("t", STD, no_notices, {}, ROOT), False)
    no_demo = {k: v for k, v in base.items() if not k.endswith("/fastrtps_rogue_cmd_vel.pcap")}
    expect("demo capture missing", check_package("t", STD, no_demo, {}, ROOT), False)
    expect("draft shipped", check_package(
        "t", STD, {**base, "/usr/share/doc/robodr/customer/eula-draft.md": ent()}, {}, ROOT), False)
    expect("setuid", check_package("t", STD, {**base, "/usr/bin/robodr-replay": ent(mode=0o4755)}, {}, ROOT), False)
    expect("not root", check_package("t", STD, {**base, "/usr/share/x": ent(owner="robodr")}, {}, ROOT), False)
    expect("state in payload", check_package("t", STD, {**base, "/var/lib/robodr/x": ent()}, {}, ROOT), False)
    expect("secret", check_package("t", STD, base, {"/usr/share/x": b"-----BEGIN PRIVATE KEY-----\n" + b"MIIEv" * 20 + b"\n"}, ROOT), False)
    expect("minisign secret", check_package("t", STD, base, {
        "/usr/share/x": b"untrusted comment: minisign encrypted secret key\n" + b"RWRTY0Iy" * 20 + b"\n"}, ROOT), False)
    expect("unencrypted minisign secret", check_package("t", STD, base, {
        "/usr/share/x": b"untrusted comment: minisign secret key\n" + b"RWQAAEIy" * 20 + b"\n"}, ROOT), False)
    expect("minisign signature", check_package("t", STD, base, {
        "/usr/sbin/robodr-x": _elf(3) + b"untrusted comment: signature from minisign secret key\n"
        + b"RUSXwJ4VahqfRBAZ" * 8 + b"\n"}, ROOT), True)
    expect("detector literals", check_package("t", STD, base, {
        "/usr/sbin/robodr-x": _elf(3) + b"-----BEGINPRIVATE KEY-----minisign encrypted secret keyuntrusted comment: secret key"}, ROOT), True)
    expect("program PIE", check_package("t", STD, base, {"/usr/sbin/robodr-agentd": _elf(3)}, ROOT), True)
    expect("program PIE, big-endian", check_package("t", STD, base, {"/usr/sbin/robodr-agentd": _elf(3, be=True)}, ROOT), True)
    expect("program not PIE", check_package("t", STD, base, {"/usr/sbin/robodr-agentd": _elf(2)}, ROOT), False)
    expect("program not ELF", check_package("t", STD, base, {"/usr/sbin/robodr-agentd": b"#!/bin/sh\n"}, ROOT), False)
    expect("program truncated ELF", check_package("t", STD, base, {"/usr/sbin/robodr-agentd": _elf(3)[:17]}, ROOT), False)
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
    lic = {"/usr/share/doc/robodr/copyright": "l", "/usr/share/doc/robodr/licenses/MIT": "l",
           "/usr/share/doc/robodr/README.md": "d", "/etc/robodr/pulsar.toml": "cn"}
    expect("rpm flags ok", check_rpm_flags("r", lic, {"/etc/robodr/pulsar.toml"}), True)
    expect("licence as %doc", check_rpm_flags("r", {**lic, "/usr/share/doc/robodr/copyright": "d"}, None), False)
    expect("notices as %doc", check_rpm_flags("r", {**lic, "/usr/share/doc/robodr/THIRD_PARTY_NOTICES": "d"}, None), False)
    expect("config without noreplace", check_rpm_flags("r", {**lic, "/etc/robodr/pulsar.toml": "c"}, None), False)
    expect("conffile not %config", check_rpm_flags("r", {**lic, "/etc/robodr/pulsar.toml": ""}, {"/etc/robodr/pulsar.toml"}), False)
    hidden, _ = read_tar(_tar_with("./.hidden") )
    root_only, _ = read_tar(_tar_with("."))
    expect("archive root skipped", [] if not root_only else [str(root_only)], True)
    expect("hidden name keeps its dot", [] if "/.hidden" in hidden else [str(hidden)], True)
    # 8. Service identities: the real tree passes; a shared uid, a missing
    # credentials tmpfs, a migration that misses a tree, a helper that
    # hands the credential to robodr, and rpm/deb blocks that differ fail.
    pk = ROOT / "packaging"
    units = {f.name: f.read_text() for f in (pk / "systemd").glob("*.service")}
    focal = {f.name: f.read_text() for f in (pk / "systemd" / "focal").glob("*.service")}
    real = [(pk / x).read_text() for x in ("sysusers.d/robodr.conf", "tmpfiles.d/robodr.conf", "deb/postinst",
                                           "rpm/post", "focal/robodr-load-credential")]
    expect("identities ok", check_identities_text(units, focal, *real), True)
    shared = dict(units)
    shared["robodr-uplink.service"] = shared["robodr-uplink.service"].replace("User=robodr-uplink", "User=robodr-spool")
    expect("shared uid", check_identities_text(shared, focal, *real), False)
    nocred = dict(focal)
    nocred["robodr-spool-export.service"] = nocred["robodr-spool-export.service"].replace(
        "TemporaryFileSystem=/run/credentials:ro", "")
    expect("credentials visible", check_identities_text(units, nocred, *real), False)
    oldload = dict(focal)
    oldload["robodr-uplink.service"] = oldload["robodr-uplink.service"].replace(
        "load robodr-uplink.service robodr-uplink ", "load robodr-uplink.service robodr ")
    expect("focal credential to robodr", check_identities_text(units, oldload, *real), False)
    sysu, tmpf, post, rpost, helper = real
    expect("migration misses a tree", check_identities_text(
        units, focal, sysu, tmpf, post.replace("/var/lib/robodr/export/uplink:robodr-uplink \\\n", ""), rpost, helper), False)
    expect("rpm block differs", check_identities_text(
        units, focal, sysu, tmpf, post, rpost.replace("robodr-kafka", "robodr-kafkaa"), helper), False)
    expect("unknown tmpfiles owner", check_identities_text(
        units, focal, sysu, tmpf + "d /var/lib/robodr/x 0750 robodr-nobody robodr -\n", post, rpost, helper), False)
    # 9. The rules unit.
    rules = (pk / "systemd" / "robodr-firewall-gw-rules.service").read_text()
    expect("rules unit ok", check_rules_unit_text("r", rules), True)
    piped = rules.replace("ExecStart=/bin/sh -eu /run/robodr-firewall-gw-rules/ruleset.sh",
                          "ExecStart=/bin/sh -c '/usr/sbin/robodr-firewall-gw ruleset --config x | /bin/sh -eu'")
    expect("rules piped into sh", check_rules_unit_text("r", piped), False)
    expect("rules full caps", check_rules_unit_text("r", rules.replace(
        "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE", "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN")), False)
    expect("rules no ProtectSystem", check_rules_unit_text("r", rules.replace("ProtectSystem=strict", "")), False)
    # 11. Resource caps: the real units pass; pulsard without its caps fails.
    expect("unit resources ok", check_unit_resources(ROOT), True)
    pulsard = (pk / "systemd" / "robodr-pulsard.service").read_text()
    expect("pulsard without MemoryMax", check_unit_resources_text("p", pulsard.replace("MemoryMax=512M\n", "")), False)
    expect("pulsard without CPUQuota", check_unit_resources_text(
        "robodr-pulsard.service", pulsard.replace("CPUQuota=100%\n", "")), False)
    limited = pulsard.replace("StartLimitIntervalSec=0\n", "StartLimitIntervalSec=300\nStartLimitBurst=5\n")
    expect("pulsard with a start limit", check_unit_resources_text("robodr-pulsard.service", limited), False)
    expect("pulsard without OOMPolicy", check_unit_resources_text(
        "robodr-pulsard.service", pulsard.replace("OOMPolicy=stop\n", "")), False)
    expect("oneshot needs no cap", check_unit_resources_text("o", "[Service]\nType=oneshot\nExecStart=/bin/true\n"), True)
    # 12. The sensor box image recipe.
    img = pk / "sensor-box" / "image"
    real_img = {str(f.relative_to(img)): f.read_bytes() for f in img.rglob("*") if f.is_file()}
    expect("image recipe ok", check_image_recipe_texts(real_img), True)
    rootconf = real_img["mkosi.repart/10-root.conf"].replace(b"ReadOnly=yes", b"")
    expect("writable root", check_image_recipe_texts({**real_img, "mkosi.repart/10-root.conf": rootconf}), False)
    bi = real_img["build-image.sh"].decode()
    moved = bi.replace("minisign -VQ -p", "true -p").replace(
        "(cd \"$top\" && sha256sum", "minisign -VQ -p \"$pubkey\" -m \"$bundle\"\n(cd \"$top\" && sha256sum")
    expect("extract before verify", check_image_recipe_texts({**real_img, "build-image.sh": moved.encode()}), False)
    bypass = bi + "\n[ -n \"${ROBODR_ALLOW_UNSIGNED:-}\" ] && exit 0\n"
    expect("unsigned switch", check_image_recipe_texts({**real_img, "build-image.sh": bypass.encode()}), False)
    no_drop = {k: v for k, v in real_img.items() if "nftables.service.d" not in k}
    expect("no firewall fallback", check_image_recipe_texts(no_drop), False)
    expect("key in recipe", check_image_recipe_texts({**real_img, "mkosi.extra/etc/robodr/keys/a.key": b"x"}), False)
    # 10. The release workflow.
    rel = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    expect("release workflow ok", check_release_workflow_text(rel), True)
    expect("no main check", check_release_workflow_text(rel.replace("scripts/release-gate.py line", "true")), False)
    expect("publish without rebuild", check_release_workflow_text(
        rel.replace(", rebuild-deb, rebuild-rpm, rebuild-static, delivery]", ", delivery]")), False)
    expect("rebuild with rustup", check_release_workflow_text(
        rel.replace('scripts/ci-install-pinned-toolchain.sh "$RUNNER_TEMP/rust"\n', "scripts/ci-install-rustup.sh\n", 1)), False)
    expect("sign before finalize", check_release_workflow_text(
        rel.replace("scripts/release-finalize.sh", "true")), False)
    fin = (ROOT / "scripts" / "release-finalize.sh").read_text()
    expect("finalize ok", check_release_finalize_text(fin), True)
    expect("no comparison", check_release_finalize_text(fin.replace("compare-rebuild.py", "true")), False)
    total = 74
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
