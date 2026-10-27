# Architecture decision records

This directory records the architecture and product decisions behind the
RoboDR general-availability (GA) plan. Each record states the context, the
decision, its consequences, and the commits and files that implement it.
The plan itself is [`docs/GA-ROADMAP.md`](../GA-ROADMAP.md), which is written
in Turkish. Decisions D1 to D9 come from its section 2.1. Sprint 0 there asks
for those decisions to be confirmed as ADRs here.

## Status vocabulary

An ADR's status says only what the repository can show. It never says more.

| Status | Meaning |
|---|---|
| **Accepted** | The product owner's decision is recorded with a date in GA-ROADMAP or in the commit history. |
| **Accepted in implementation; ratification pending** | GA-ROADMAP §2.1 lists the decision as proposed ("to be confirmed in S0"), and code or contracts in this repository already follow it. The product owner's S0 sign-off has not been recorded yet. |
| **Proposed** | Listed in GA-ROADMAP §2.1, not implemented (or only in part), and not yet confirmed. |
| **Superseded by ADR-NNNN** | Replaced. The record stays in place for history. |

To ratify an ADR, the product owner changes its status line to
`Accepted (ratified YYYY-MM-DD by <role>)`. That can be the only change in
the commit.

## Index

| ADR | Title | GA-ROADMAP | Status |
|---|---|---|---|
| [0001](0001-findings-transport-native-ingest.md) | Findings reach the SOC through a native HTTPS ingest API; Kafka is optional | D1 | Accepted in implementation; ratification pending (SOC side on an unreleased AutoSecOps branch) |
| [0002](0002-mvp-bridge-webhook-workflow.md) | MVP bridge: webhook + workflow + deduplicate before the native module | D2 | Proposed |
| [0003](0003-findings-contract-v2.md) | Findings contract `robodr.findings/2.x`: vendor-neutral envelope, OCSF 1.1 body | D3 | Accepted in implementation; ratification pending |
| [0004](0004-control-plane-v2.md) | Control plane v2: mTLS, signed requests, persistent state, real outcomes | D4 | Accepted in implementation; ratification pending |
| [0005](0005-action-catalog.md) | One vendor-neutral action catalog, with what GA executes | D5 | Accepted in implementation; ratification pending |
| [0006](0006-approval-never-autonomous.md) | Robot actions are never autonomous; two-person rule for the strongest | D6 | Accepted in implementation; ratification pending (SOC side on an unreleased AutoSecOps branch) |
| [0007](0007-audited-libraries.md) | Audited libraries instead of hand-written HTTP, crypto and Kafka code | D7 | Proposed (partly implemented) |
| [0008](0008-licensing-enforced-at-soc.md) | Licensing is enforced at the SOC; the robot agent never goes blind | D8 | Proposed (partly implemented on the SOC side) |
| [0009](0009-robodr-proprietary-license.md) | RoboDR is proprietary; Pulsar eBPF probes stay GPL-2.0 | D9 | Accepted (2026-10-25) |
| [0010](0010-legal-clearance.md) | Legal clearance: AutoSecOps1 provenance, Pulsar GPL-2.0 eBPF, export control | S0 (L) | Accepted (2026-10-25) |
| [0011](0011-ingest-api-v1.md) | The `robodr.ingest` HTTP API, contract v1 | S2–S3 | Accepted in implementation; ratification pending |
| [0012](0012-balancing-robot-response-rules.md) | Response rules for humanoid and other balancing robots | §3a | Accepted in implementation; ratification pending |

GA-ROADMAP Sprint 0 names the legal record `docs/adr/0001-legal-clearance.md`.
Here it is [ADR-0010](0010-legal-clearance.md), because 0001 to 0009 follow
D1 to D9. The roadmap's file name was a placeholder.

## Writing a new ADR

- Take the next free number. Never reuse or renumber a record.
- Use the same sections as the existing records: header table, Context,
  Decision, Consequences, Implementation and evidence, Open items.
- Cite commits by short hash and files by repository path. Cite only what
  exists: run `git cat-file -e <hash>` and `ls <path>` before committing.
- Do not change the decision text of an Accepted ADR. Write a new ADR that
  supersedes it, and set the old one's status to "Superseded by ADR-NNNN".
- Do not copy customer names, site names, hostnames, keys or legal document
  contents into an ADR. Refer to them as "on file with SingularityRD legal"
  or similar.
