#!/usr/bin/env python3
"""Tests of tools/e2e/nightly_redteam_checks.py (the nightly red team's
assertions) on synthetic redteam_net.py records.

    python3 tools/e2e/test_nightly_redteam_checks.py
"""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nightly_redteam_checks as nc  # noqa: E402

RSS = 65536


def passing_steps():
    def step(name, findings, **extra):
        return {"step": name, "info": extra.pop("info", {}), "new_findings": findings,
                "agentd_alive": True, "rss_kib_before": 20000, "rss_kib_after": 21000,
                "state": "running", "safety_state": extra.pop("safety_state", "unknown")}
    return {
        "rogue": step("rogue", {"robot.ros2.unknown_participant": 1,
                                "robot.ros2.unauthorized_motion_writer": 1}),
        "spray": step("spray", {"robot.ros2.discovery_flood": 2}),
        "malformed": step("malformed", {}),
        "safety": step("safety", {"robot.safety_state.untrusted_source": 1},
                       info={"unprivileged_socket": "PermissionError: [Errno 13] Permission denied"}),
    }


def failing(steps):
    return [c["check"] for c in nc.evaluate(steps, 0, 0, "RESULT: INTACT\n", RSS) if not c["pass"]]


class Checks(unittest.TestCase):
    def test_a_good_run_passes(self):
        self.assertEqual(failing(passing_steps()), [])

    def test_safety_state_must_be_present_and_unknown(self):
        for value in ("idle", None, "moving_slow", {"state": "unknown"}):
            s = passing_steps()
            s["safety"]["safety_state"] = value
            self.assertEqual(failing(s), ["R4 safety: state not taken from the spoof"], value)
        s = passing_steps()
        del s["safety"]["safety_state"]
        self.assertEqual(failing(s), ["R4 safety: state not taken from the spoof"])

    def test_a_missing_step_fails(self):
        s = copy.deepcopy(passing_steps())
        del s["safety"]
        self.assertIn("safety: step ran", failing(s))

    def test_black_box_must_verify(self):
        checks = nc.evaluate(passing_steps(), 0, 1, "RESULT: BROKEN\n", RSS)
        self.assertEqual([c["check"] for c in checks if not c["pass"]], ["black box INTACT"])


if __name__ == "__main__":
    unittest.main()
