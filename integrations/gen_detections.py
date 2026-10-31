#!/usr/bin/env python3
"""Generate the shared RoboDR detections for Elastic and Sentinel.

The five detections of integrations/README.md ("Detections shipped") are
defined once here and written as Elastic detection-engine rules
(elastic/detection-rules/*.json) and Sentinel scheduled analytics rules
(sentinel/analytics/*.yaml). Ids are stable (uuid5). check_content.py fails
when the checked-in files differ from this output; regenerate with

    python3 integrations/gen_detections.py [OUT_DIR]

Splunk's copies are hand-written in splunk/TA-robodr/default/savedsearches.conf
(check_content.py checks they name the same rule ids).
"""
import json
import os
import sys
import uuid

NS = uuid.UUID("6f1c1d38-8f6e-4a43-9c2a-52b0d1e0a001")

DET = [
    {
        "key": "unauthorised-motion-source",
        "name": "RoboDR - Unauthorised motion source",
        "desc": "Something that is not the robot's operator is commanding it: an unauthorised motion writer, a firewall rejection of an unknown source, an unlisted Unitree legacy-UDP sender or an unknown WebRTC controller.",
        "rules": ["robot.ros2.unauthorized_motion_writer", "robot.firewall.rejected_unknown_source",
                  "robot.unitree.legacy_unknown_sender", "robot.unitree.webrtc_unknown_controller"],
        "severity": "critical", "risk": 99, "sentinel_sev": "High",
    },
    {
        "key": "motion-outside-envelope",
        "name": "RoboDR - Motion outside the envelope",
        "desc": "Commanded motion beyond the robot's locked profile (linear, angular or joint speed, joint torque).",
        "rules": ["robot.motion.linear_over_envelope", "robot.motion.angular_over_envelope",
                  "robot.motion.joint_over_envelope", "robot.firewall.joint_torque_out_of_envelope"],
        "severity": "high", "risk": 73, "sentinel_sev": "High",
    },
    {
        "key": "correlated-intrusion",
        "name": "RoboDR - Correlated intrusion",
        "desc": "Several independent RoboDR sensors agree on one intrusion (robot.correlate.* findings cite every contributing detection).",
        "rules": ["robot.correlate.*"],
        "severity": "critical", "risk": 99, "sentinel_sev": "High",
    },
    {
        "key": "sensor-blind",
        "name": "RoboDR - Sensor blind or tampered",
        "desc": "The robot's sensor cannot see (input silent or ended, queue overflow, evidence truncated, discovery not inspected). Treat its silence as unknown, not safe.",
        "rules": ["robot.agent.input_silent", "robot.agent.input_ended", "robot.agent.queue_overflow",
                  "robot.agent.evidence_truncated", "robot.rtps.discovery_not_inspected"],
        "severity": "high", "risk": 73, "sentinel_sev": "Medium",
    },
    {
        "key": "unknown-participant-burst",
        "name": "RoboDR - Unknown participant burst",
        "desc": "Unknown DDS participants or a discovery flood on the robot network: reconnaissance or a rogue node.",
        "rules": ["robot.ros2.unknown_participant", "robot.ros2.discovery_flood"],
        "severity": "medium", "risk": 47, "sentinel_sev": "Medium",
    },
]


def kql_elastic(rules):
    parts = []
    for r in rules:
        parts.append(f"rule.id : {r}" if r.endswith("*") else f'rule.id : "{r}"')
    return "event.module : \"robodr\" and (" + " or ".join(parts) + ")"


def kql_sentinel(rules):
    exact = [r for r in rules if not r.endswith("*")]
    pref = [r[:-1] for r in rules if r.endswith("*")]
    conds = []
    if exact:
        conds.append("RuleId in (" + ", ".join(f'"{r}"' for r in exact) + ")")
    for p in pref:
        conds.append(f'RuleId startswith "{p}"')
    return (
        "RoboDRFindings\n"
        f"| where {' or '.join(conds)}\n"
        "| summarize Count = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),\n"
        "    RuleIds = make_set(RuleId), SourceIps = make_set(SourceIp), Verification = make_set(VerificationStatus)\n"
        "    by RobotId, Site\n"
    )


def write(root):
    os.makedirs(os.path.join(root, "elastic/detection-rules"), exist_ok=True)
    os.makedirs(os.path.join(root, "sentinel/analytics"), exist_ok=True)
    for d in DET:
        rid = str(uuid.uuid5(NS, d["key"]))
        el = {
            "rule_id": rid,
            "name": d["name"],
            "description": d["desc"] + " Observe-only: alerts, never responds.",
            "type": "query",
            "language": "kuery",
            "index": ["logs-robodr.findings-*"],
            "query": kql_elastic(d["rules"]),
            "severity": d["severity"],
            "risk_score": d["risk"],
            "interval": "5m",
            "from": "now-6m",
            "enabled": False,
            "author": ["Singularity RD"],
            "tags": ["RoboDR", "Robotics", "OT"],
            "max_signals": 100,
            "version": 1,
        }
        with open(os.path.join(root, f"elastic/detection-rules/{d['key']}.json"), "w") as fh:
            json.dump(el, fh, indent=2)
            fh.write("\n")
        rules_yaml = "\n".join(f"  - {r}" for r in d["rules"])
        query = "\n".join("  " + line for line in kql_sentinel(d["rules"]).splitlines())
        y = "\n".join(
            [
                f"id: {uuid.uuid5(NS, 'sentinel-' + d['key'])}",
                f"name: {d['name']}",
                "description: |",
                f"  {d['desc']} Observe-only: alerts, never responds.",
                "  RoboDR rule ids (docs/customer/detection-rules.md):",
                rules_yaml.replace("  - ", "    - "),
                f"severity: {d['sentinel_sev']}",
                "requiredDataConnectors: []",
                "queryFrequency: 5m",
                "queryPeriod: 15m",
                "triggerOperator: gt",
                "triggerThreshold: 0",
                "tactics: []",
                "relevantTechniques: []",
                "query: |",
                query,
                "entityMappings:",
                "  - entityType: Host",
                "    fieldMappings:",
                "      - identifier: HostName",
                "        columnName: RobotId",
                "version: 1.0.0",
                "kind: Scheduled",
                "",
            ]
        )
        with open(os.path.join(root, f"sentinel/analytics/{d['key']}.yaml"), "w") as fh:
            fh.write(y)
    print(f"wrote {len(DET)} detections under {root}")


if __name__ == "__main__":
    write(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__)))
