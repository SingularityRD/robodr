#!/usr/bin/env python3
"""Keep the systemd-245 unit variants of the robodr-focal package in step.

packaging/systemd/focal/<unit> is the regular unit packaging/systemd/<unit>
rewritten for systemd 245 (Ubuntu 20.04, NVIDIA JetPack 5). This check fails
unless, for every focal unit:

  1. its directives equal the regular unit's, in order, after these and only
     these rewrites (comments and blank lines are ignored):
       * the regular unit's ProtectProc= / ProcSubset= lines are dropped
         (systemd 247; nothing replaces them on 245);
       * each regular ``LoadCredential=<name>:<source>`` is replaced by
         robodr-load-credential lines in the focal unit:
           ExecStartPre=+/usr/lib/robodr/robodr-load-credential clear <unit>
           ExecStartPre=+/usr/lib/robodr/robodr-load-credential load <unit> <user> <name>:<source> ...
           ExecStopPost=+/usr/lib/robodr/robodr-load-credential clear <unit>
         with exactly the same <name>:<source> pairs, <user> = the unit's
         User=, clear before load, and the helper lines placed where the
         LoadCredential= lines were;
  2. every directive it uses is known to exist in systemd 245, and every
     SystemCallFilter= group too (an unknown key is ignored by systemd with
     a warning, which would silently drop a protection or a credential);
  3. every regular unit that uses LoadCredential=, ProtectProc= or
     ProcSubset= and ships in the focal package has a focal variant.

The focal drop-in examples (packaging/systemd/focal/*.service.d/*) get
check 2 and must not use LoadCredential=.

Usage:
  scripts/check-focal-units.py [--packaging packaging]
  scripts/check-focal-units.py --self-test
Exit 0 ok, 1 drift found, 2 usage error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HELPER = "/usr/lib/robodr/robodr-load-credential"

# Units the focal package ships (packaging/build-deb.sh --variant focal).
FOCAL_UNITS = (
    "robodr-agentd.service",
    "robodr-spool-export.service",
    "robodr-kafka-publish.service",
)

# Directives a focal unit may use: all exist in systemd 245 (version in
# which each appeared, from systemd's NEWS, where newer than 229).
KNOWN_245 = {
    # [Unit]
    "Description", "Documentation", "After", "Before", "Wants", "Requires",
    "BindsTo", "PartOf", "Conflicts", "AssertPathExists", "ConditionPathExists",
    "RequiresMountsFor", "StartLimitIntervalSec", "StartLimitBurst",  # 229
    "DefaultDependencies",
    # [Service]
    "Type", "NotifyAccess", "ExecStart", "ExecStartPre", "ExecStartPost",
    "ExecStopPost", "Restart", "RestartSec", "RestartPreventExitStatus",
    "TimeoutStopSec", "TimeoutStartSec", "WatchdogSec", "EnvironmentFile",
    "Environment", "OOMScoreAdjust", "MemoryHigh", "MemoryMax",  # 231
    "TasksMax", "Nice", "IOSchedulingClass", "IOSchedulingPriority",
    "User", "Group", "SupplementaryGroups", "DynamicUser",  # 235
    "AmbientCapabilities", "CapabilityBoundingSet", "NoNewPrivileges", "UMask",
    "InaccessiblePaths", "ReadWritePaths", "ReadOnlyPaths",  # 231
    "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices",
    "PrivateNetwork", "DevicePolicy", "DeviceAllow",
    "RuntimeDirectory", "RuntimeDirectoryMode", "StateDirectory",  # 235
    "StateDirectoryMode",
    "ProtectKernelTunables", "ProtectKernelModules", "ProtectControlGroups",  # 232
    "ProtectKernelLogs",  # 244
    "ProtectClock",  # 245
    "ProtectHostname",  # 242
    "RestrictAddressFamilies", "IPAddressAllow", "IPAddressDeny",  # 235
    "RestrictNamespaces",  # 233
    "RestrictRealtime", "RestrictSUIDSGID",  # 242
    "LockPersonality",  # 235
    "RemoveIPC",  # 232
    "MemoryDenyWriteExecute", "SystemCallArchitectures", "SystemCallFilter",
    "SystemCallErrorNumber",
    # [Install]
    "WantedBy", "RequiredBy", "Alias",
}

# SystemCallFilter= groups that exist in systemd 245.
KNOWN_GROUPS_245 = {
    "@aio", "@basic-io", "@chown", "@clock", "@cpu-emulation", "@debug",
    "@file-system", "@io-event", "@ipc", "@keyring", "@memlock", "@module",
    "@mount", "@network-io", "@obsolete", "@pkey", "@privileged", "@process",
    "@raw-io", "@reboot", "@resources", "@setuid", "@signal", "@swap",
    "@sync", "@system-service", "@timer", "@default",
}

DROPPED = ("ProtectProc", "ProcSubset")


def directives(text: str) -> list[tuple[str, str]]:
    """(key, value) per directive line, with [Section] lines as ('[', name)."""
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            out.append(("[", line))
            continue
        if "=" not in line:
            out.append(("?", line))
            continue
        k, v = line.split("=", 1)
        out.append((k.strip(), v.strip()))
    return out


def check_known(name: str, ds: list[tuple[str, str]]) -> list[str]:
    errs = []
    for k, v in ds:
        if k == "[":
            continue
        if k == "?":
            errs.append(f"{name}: unparsable line {v!r}")
            continue
        if k not in KNOWN_245:
            errs.append(f"{name}: {k}= is not known to exist in systemd 245")
        if k == "LoadCredential":
            errs.append(f"{name}: LoadCredential= needs systemd 247")
        if k == "SystemCallFilter":
            for tok in v.lstrip("~").split():
                if tok.startswith("@") and tok not in KNOWN_GROUPS_245:
                    errs.append(f"{name}: SystemCallFilter group {tok} not in systemd 245")
    return errs


def helper_line(k: str, v: str) -> list[str] | None:
    """The helper's argv if (k, v) is an ExecStartPre/ExecStopPost helper line."""
    if k in ("ExecStartPre", "ExecStopPost") and v.startswith("+" + HELPER + " "):
        return v[len(HELPER) + 2 :].split()
    return None


def compare(unit: str, regular: str, focal: str) -> list[str]:
    errs: list[str] = []
    rd = directives(regular)
    fd = directives(focal)
    errs += check_known(f"focal/{unit}", fd)

    user = next((v for k, v in rd if k == "User"), None)
    creds = [v for k, v in rd if k == "LoadCredential"]

    # Expected focal directive list: the regular one with ProtectProc/ProcSubset
    # dropped and the LoadCredential block replaced by one marker.
    want: list[tuple[str, str]] = []
    marker_done = False
    for k, v in rd:
        if k in DROPPED:
            continue
        if k == "LoadCredential":
            if not marker_done:
                want.append(("<helper>", ""))
                marker_done = True
            continue
        want.append((k, v))

    got: list[tuple[str, str]] = []
    helpers: list[tuple[str, list[str]]] = []
    for k, v in fd:
        argv = helper_line(k, v)
        if argv is not None:
            helpers.append((k, argv))
            if not got or got[-1][0] != "<helper>":
                got.append(("<helper>", ""))
            continue
        got.append((k, v))

    if got != want:
        for i, (a, b) in enumerate(zip(want, got)):
            if a != b:
                errs.append(f"focal/{unit}: directive {i + 1} differs: regular {a!r}, focal {b!r}")
                break
        else:
            errs.append(f"focal/{unit}: {len(got)} directives, regular unit gives {len(want)}")

    if not creds:
        if helpers:
            errs.append(f"focal/{unit}: helper lines but the regular unit loads no credential")
        return errs
    if user is None:
        errs.append(f"{unit}: LoadCredential= without User=")
        return errs
    expect = [
        ("ExecStartPre", ["clear", unit]),
        ("ExecStartPre", ["load", unit, user, *creds]),
        ("ExecStopPost", ["clear", unit]),
    ]
    if helpers != expect:
        errs.append(f"focal/{unit}: helper lines {helpers!r}, expected {expect!r}")
    return errs


def run(packaging: Path) -> list[str]:
    errs: list[str] = []
    sysd = packaging / "systemd"
    focal = sysd / "focal"
    for unit in FOCAL_UNITS:
        reg, foc = sysd / unit, focal / unit
        if not reg.is_file():
            errs.append(f"{reg}: missing")
            continue
        if not foc.is_file():
            errs.append(f"{foc}: missing (the focal package ships {unit})")
            continue
        errs += compare(unit, reg.read_text(), foc.read_text())
    # Every focal unit is one the focal package ships.
    for f in sorted(focal.glob("*.service")):
        if f.name not in FOCAL_UNITS:
            errs.append(f"{f}: not in FOCAL_UNITS (add it there and to build-deb.sh)")
    for f in sorted(focal.glob("*.service.d/*")):
        errs += check_known(f"focal/{f.parent.name}/{f.name}", directives(f.read_text()))
    return errs


def self_test() -> int:
    reg = """# c
[Unit]
Description=x
[Service]
User=robodr
ExecStart=/usr/bin/x
LoadCredential=a.key:/etc/robodr/keys/a.key
InaccessiblePaths=-/etc/robodr/keys
ProtectProc=invisible
ProcSubset=pid
SystemCallFilter=~@privileged @debug
"""
    good = f"""[Unit]
Description=x
[Service]
User=robodr
ExecStart=/usr/bin/x
ExecStartPre=+{HELPER} clear u.service
ExecStartPre=+{HELPER} load u.service robodr a.key:/etc/robodr/keys/a.key
ExecStopPost=+{HELPER} clear u.service
InaccessiblePaths=-/etc/robodr/keys
SystemCallFilter=~@privileged @debug
"""
    cases = [
        ("identical after rewrite", good, True),
        ("ProtectProc kept", good + "ProtectProc=invisible\n", False),
        ("LoadCredential kept", good.replace("InaccessiblePaths", "LoadCredential=a.key:/x\nInaccessiblePaths"), False),
        ("wrong source", good.replace("a.key:/etc/robodr/keys/a.key", "a.key:/tmp/a.key"), False),
        ("wrong user", good.replace("u.service robodr", "u.service root"), False),
        ("missing ExecStopPost", good.replace(f"ExecStopPost=+{HELPER} clear u.service\n", ""), False),
        ("load before clear", good.replace(
            f"ExecStartPre=+{HELPER} clear u.service\nExecStartPre=+{HELPER} load u.service robodr a.key:/etc/robodr/keys/a.key\n",
            f"ExecStartPre=+{HELPER} load u.service robodr a.key:/etc/robodr/keys/a.key\nExecStartPre=+{HELPER} clear u.service\n"), False),
        ("drifted directive", good.replace("ExecStart=/usr/bin/x", "ExecStart=/usr/bin/y"), False),
        ("extra directive", good + "Nice=5\n", False),
        ("unknown 247 directive", good + "ProtectProc=invisible\n", False),
        ("unknown group", good.replace("@debug", "@sandbox"), False),
        ("helper without '+'", good.replace(f"ExecStopPost=+{HELPER}", f"ExecStopPost={HELPER}"), False),
    ]
    regs = {"identical after rewrite": reg}
    failed = 0
    for name, focal, ok in cases:
        errs = compare("u.service", regs.get(name, reg), focal)
        if (not errs) != ok:
            failed += 1
            print(f"self-test FAIL: {name}: errors {errs}", file=sys.stderr)
    # A regular unit with a directive drifted must be caught from the other side.
    errs = compare("u.service", reg.replace("ExecStart=/usr/bin/x", "ExecStart=/usr/bin/z"), good)
    if not errs:
        failed += 1
        print("self-test FAIL: regular drift not caught", file=sys.stderr)
    # Drop-in style check of a focal example.
    if not check_known("d", directives("[Service]\nLoadCredential=a:/b\n")):
        failed += 1
        print("self-test FAIL: LoadCredential in a drop-in not caught", file=sys.stderr)
    total = len(cases) + 2
    print(f"self-test: {total - failed}/{total} passed")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--packaging", default=None, help="packaging directory (default: <repo>/packaging)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    packaging = Path(a.packaging) if a.packaging else Path(__file__).resolve().parent.parent / "packaging"
    if not (packaging / "systemd").is_dir():
        print(f"check-focal-units: {packaging}/systemd not found", file=sys.stderr)
        return 2
    errs = run(packaging)
    for e in errs:
        print(f"ERROR: {e}", file=sys.stderr)
    print(f"check-focal-units: {len(FOCAL_UNITS)} focal units, {len(errs)} error(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
