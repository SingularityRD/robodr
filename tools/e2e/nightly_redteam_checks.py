#!/usr/bin/env python3
"""The assertions of tools/e2e/nightly-redteam.sh over its OUT_DIR.

    nightly_redteam_checks.py OUT_DIR AGENTD_RC VERIFY_RC RSS_LIMIT_KIB

Reads OUT_DIR/steps.jsonl (tools/e2e/redteam_net.py) and OUT_DIR/verify.txt,
writes OUT_DIR/results.json, prints one PASS/FAIL line per check.
Exit: 0 all checks passed, 1 one failed. Tested by
tools/e2e/test_nightly_redteam_checks.py.
"""
import json
import sys


def evaluate(steps, agentd_rc, verify_rc, verify_text, rss_limit):
    """The checks over `steps` ({step name: redteam_net.py record})."""
    checks = []

    def check(name, ok, detail):
        checks.append({"check": name, "pass": bool(ok), "detail": detail})

    def found(step, uid):
        return steps.get(step, {}).get("new_findings", {}).get(uid, 0)

    for st in ("rogue", "spray", "malformed", "safety"):
        check(f"{st}: step ran", st in steps, list(steps))
        s = steps.get(st, {})
        check(f"{st}: agentd alive", s.get("agentd_alive"), s.get("agentd_alive"))
        rss = s.get("rss_kib_after") or 0
        check(f"{st}: RSS under {rss_limit} KiB", 0 < rss < rss_limit, rss)
    check("R1 rogue: unknown_participant", found("rogue", "robot.ros2.unknown_participant") > 0,
          steps.get("rogue", {}).get("new_findings"))
    check("R1 rogue: unauthorized_motion_writer",
          found("rogue", "robot.ros2.unauthorized_motion_writer") > 0,
          steps.get("rogue", {}).get("new_findings"))
    spray = steps.get("spray", {}).get("new_findings", {})
    check("R2 spray: detected (discovery_flood or unknown_participant)",
          found("spray", "robot.ros2.discovery_flood")
          + found("spray", "robot.ros2.unknown_participant") > 0, spray)
    # REDTEAM.md F1: 3000 sprayed GUIDs once made about 5000 findings; they
    # are aggregated now. A tenth of the packets is the regression bound.
    check("R2 spray: no finding amplification (< 300 findings for 3000 GUIDs)",
          sum(spray.values()) < 300, sum(spray.values()))
    safety = steps.get("safety", {})
    check("R4 safety: untrusted_source", found("safety", "robot.safety_state.untrusted_source") > 0,
          safety.get("new_findings"))
    # status.json's safety_state, read at least 6 s after the last spoofed
    # frame (redteam_net.py settles 6 s after every step but spray) with
    # stale_after_ms 1000: every source is stale, so the feed must read
    # "unknown". A missing or null value (status.json not read), or any
    # state a claim could have set ("idle" from the spoofed /odom), fails.
    check("R4 safety: state not taken from the spoof",
          safety.get("safety_state") == "unknown", safety.get("safety_state"))
    unpriv = safety.get("info", {}).get("unprivileged_socket", "")
    check("R4 safety: unprivileged PLC socket write refused",
          "Permission" in unpriv or "denied" in unpriv, unpriv)
    check("agentd exit 0 on SIGTERM", agentd_rc == 0, agentd_rc)
    check("black box INTACT", verify_rc == 0 and "RESULT: INTACT" in verify_text,
          verify_text.strip().splitlines()[-1:])
    return checks


def read_steps(path):
    steps = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                s = json.loads(line)
                steps[s["step"]] = s
    return steps


def main(argv):
    out, agentd_rc, verify_rc, rss_limit = argv[1], int(argv[2]), int(argv[3]), int(argv[4])
    steps = read_steps(f"{out}/steps.jsonl")
    with open(f"{out}/verify.txt") as f:
        verify_text = f.read()
    checks = evaluate(steps, agentd_rc, verify_rc, verify_text, rss_limit)
    with open(f"{out}/results.json", "w") as f:
        json.dump({"checks": checks, "steps": steps}, f, indent=1)
    for c in checks:
        print(f"nightly-redteam: {'PASS' if c['pass'] else 'FAIL'} {c['check']}: {c['detail']}")
    bad = [c for c in checks if not c["pass"]]
    if bad:
        for c in bad:
            print(f"::error::nightly red team: {c['check']}: {c['detail']}")
        return 1
    print(f"nightly-redteam: all {len(checks)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
