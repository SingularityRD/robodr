# ADR-0008: Licensing is enforced at the SOC; the robot agent never goes blind

| | |
|---|---|
| Status | Proposed (partly implemented on the SOC side: `robot_edr` entitlement, AutoSecOps `9de8854e`; no robot-count claim yet). The robot side has no licence check, as decided |
| Proposed | 2026-10-25, GA-ROADMAP §2.1 D8 (commit `a5c5afd`) |
| Implemented | No. The SOC side is AutoSecOps1 work. This repository holds no licence check, which matches the decision: no match for `entitlement` or `max_robots` in `crates/`. |
| Related | [ADR-0009](0009-robodr-proprietary-license.md) |

## Context

RoboDR is a security product. If the agent stopped detecting or recording
evidence when a licence expired, a billing problem would turn into a
security gap. AutoSecOps1 already has an Ed25519-signed licence token with
entitlements (GA-ROADMAP §1.2). Its embedded key is a development key
(A5) and must be replaced.

## Decision (as proposed)

- The AutoSecOps1 licence token gains a `robot_edr` entitlement and a
  `max_robots` claim. Robots are counted at the SOC.
- The robot agent has **no licence check**. A robot never stops detecting
  or recording because of a licence.

## Consequences

- Enforcement happens only where findings arrive. Over quota, the SOC can
  refuse to register new robots, but it must still accept and store
  findings from robots already registered. The exact over-quota behaviour
  is open.
- An unlicensed party could run the agent and the diode tooling without a
  SOC. The EULA has to cover that, not the code
  ([`docs/customer/eula-draft.md`](../customer/eula-draft.md)).
- License-token production keys need an HSM or offline procedure
  (GA-ROADMAP S13).

## Implementation and evidence

None yet. The SKU and entitlement definitions are listed as open in
GA-ROADMAP §1.2 A9.

## Open items

- Product owner: the over-quota behaviour at the SOC (warn, refuse new
  enrolments, or something else), and which AutoSecOps1 entitlements the
  RoboDR SKU includes.
