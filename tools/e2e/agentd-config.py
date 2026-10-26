#!/usr/bin/env python3
"""Write an agentd.json for the E2E harness (test keys only).

usage: agentd-config.py ROBOT_DIR ROBOT_ID (--pcap FILE | --iface IF) [--control] [--unix-events]

ROBOT_DIR must already hold locked.json + profile-trust.json (commission.sh).
Keys (black box, finding signing) are generated with robodr-blackbox keygen
if missing. Prints the config path.
"""
import argparse, json, os, shutil, subprocess, sys

B = os.environ.get("ROBODR_BIN", "/home/user/robodr/target/release")
REPO = os.environ.get("ROBODR_REPO", "/home/user/robodr")

ap = argparse.ArgumentParser()
ap.add_argument("dir"); ap.add_argument("robot_id")
ap.add_argument("--pcap"); ap.add_argument("--iface")
ap.add_argument("--site", default="lab")
ap.add_argument("--control", action="store_true", help="enable control plane v2 on a unix socket")
ap.add_argument("--soc-key", help="SOC public key file (control plane)")
ap.add_argument("--cp-tls", help="dir with robot.pem, robot.key, soc-ca.pem (mutual TLS listener)")
ap.add_argument("--cp-listen", default="127.0.0.1:8787")
ap.add_argument("--no-exit", action="store_true", help="keep running after a pcap replay ends")
ap.add_argument("--safety-socket", action="store_true")
ap.add_argument("--extra", help="JSON merged into the top level")
ap.add_argument("--out", default="agentd.json")
ap.add_argument("--keys-dir", help="use DIR/blackbox.key + DIR/finding.key (robodr-enroll)")
a = ap.parse_args()
d = os.path.abspath(a.dir)

def keygen(name, kid):
    p = os.path.join(d, name)
    if not os.path.exists(p):
        subprocess.run([f"{B}/robodr-blackbox", "keygen", "--out", p, "--key-id", kid],
                       check=True, stdout=subprocess.DEVNULL)
    return p

if a.keys_dir:
    bb_key = os.path.join(os.path.abspath(a.keys_dir), "blackbox.key")
    fs_key = os.path.join(os.path.abspath(a.keys_dir), "finding.key")
else:
    bb_key = keygen("blackbox.key", f"bb-{a.robot_id}")
    fs_key = keygen("finding.key", f"finding-{a.robot_id}")
policy = os.path.join(d, "policy.json")
shutil.copy(f"{REPO}/crates/robodr-agent/examples/policy-oem-validated.json", policy)
capture = {"enabled": True}
if a.pcap:
    capture["pcap_replay"] = os.path.abspath(a.pcap)
else:
    capture["interfaces"] = [a.iface]
cfg = {
    "robot": {"id": a.robot_id, "site": a.site},
    "sensor": {
        "profile_path": f"{d}/locked.json",
        "listen_spdp": False,
        "capture": capture,
        "motion": {"feedback_topics": ["/odom"]},
        "profile_trust": {
            "trusted_keys": f"{d}/profile-trust.json",
            "state_file": f"{d}/profile-state.json",
            "expect_platform": "lab-ugv",
        },
    },
    "policy_path": policy,
    "blackbox": {"dir": f"{d}/blackbox", "key_file": bb_key},
    "spool": {"dir": f"{d}/spool"},
    "finding_signing": {"key_file": fs_key},
    "event_inputs": [],
    "context": {"safety_state": "moving_slow"},
    "firewall": {"max_angular": {"/cmd_vel": 1.0},
                 "allow": {"/cmd_vel": ["identity:teleop_twist"]}},
    "motion_monitor": {"feedback_sources": {"/odom": "wheel_odometry"}},
    "daemon": {"tick_ms": 1000, "heartbeat_ms": 10000, "silence_ms": 30000,
               "exit_when_inputs_end": bool(a.pcap) and not a.no_exit},
}
if a.control:
    sd = f"{d}/cp-state"; os.makedirs(sd, mode=0o700, exist_ok=True); os.chmod(sd, 0o700)
    cfg["control_plane"] = {
        "unix_socket": f"{d}/control.sock",
        "state_dir": sd,
        "soc_keys": [os.path.abspath(a.soc_key)],
        "evidence": {},
    }
    if a.cp_tls:
        t = os.path.abspath(a.cp_tls)
        cfg["control_plane"]["listen_tcp"] = a.cp_listen
        cfg["control_plane"]["tls"] = {"cert_chain": f"{t}/robot.pem", "key_file": f"{t}/robot.key",
                                       "client_ca": f"{t}/soc-ca.pem"}
if a.extra:
    cfg.update(json.loads(a.extra))
out = os.path.join(d, a.out)
json.dump(cfg, open(out, "w"), indent=2)
print(out)
