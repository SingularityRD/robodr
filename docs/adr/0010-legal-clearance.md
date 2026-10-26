# ADR-0010: Legal clearance: AutoSecOps1 provenance, Pulsar GPL-2.0 eBPF, export control

| | |
|---|---|
| Status | **Accepted (2026-10-25)** |
| Source | Product owner statement of 2026-10-25, recorded in GA-ROADMAP §1.2 A1, Sprint 0 (L), §4 and §5 (commit `c48b2ee`) |
| Documents | Legal opinions and classification on file with SingularityRD legal. This record cites none of their contents and invents no document numbers. |
| Related | [ADR-0009](0009-robodr-proprietary-license.md) |

GA-ROADMAP Sprint 0 calls this record `docs/adr/0001-legal-clearance.md`.
It is numbered 0010 here because 0001 to 0009 follow D1 to D9.

## Context

Three legal questions blocked GA (GA-ROADMAP §1.1 R7, §1.2 A1, §5):

1. **AutoSecOps1 licensing and provenance.** AutoSecOps1 is derived from
   Tracecat. Could it be distributed commercially under SingularityRD's
   terms?
2. **Pulsar GPL-2.0 eBPF distribution.** RoboDR loads eBPF probe programs
   from Pulsar, which are GPL-2.0, from proprietary userspace. Could they
   be distributed that way, and on what conditions?
3. **Export control.** RoboDR is security software with signing, TLS and
   (in the planned secure-delivery feature) payload encryption. Some
   customers are defence and safety-relevant. What is its classification
   under the dual-use rules that apply (Wassenaar Category 5 Part 2 is
   named in [`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) §11)?

## Decision

According to the product owner's statement of 2026-10-25, legal clearance
has been **obtained** for all three questions. The opinions and the
classification are on file with SingularityRD legal. This ADR records:

- **scope**: the three questions above;
- **date**: 2026-10-25;
- **reference**: "on file with SingularityRD legal". The documents
  themselves are not stored in this repository.

## Consequences

- GA-ROADMAP §4 marks the legal criterion as done:
  "[x] ... legal approval obtained (2026-10-25)".
- **Conditions that still have to be carried out.** None of these is done
  yet:
  - the delivery conditions that come with the export classification
    (for example country restrictions or end-user statements) must be
    built into the sales process and the commercial package
    (GA-ROADMAP S0 and S13, §4 "Commercial / legal");
  - every RoboDR package must carry the third-party notices and the
    GPL-2.0 source offer for the eBPF probes (GA-ROADMAP S12, §4). The
    current offer text is in [`LICENSE`](../../LICENSE);
  - AutoSecOps1 keeps its third-party notices current as dependencies
    change. GA-ROADMAP A1 says this is enforced there by a CI test. That
    has not been verified from this repository.
- **What this record does not establish.** The classification result
  itself (category or control number), the countries or end users it
  restricts, and whether the planned encryption feature (SECURE-DELIVERY
  feature C, not implemented) was in scope of the classification. The
  repository does not hold these facts. Product owner: please confirm that
  feature C was covered, or plan a re-review before it ships.

## Implementation and evidence

- `c48b2ee`, docs(ga-roadmap): "legal clearances obtained; close the
  licensing gate" (2026-10-25).
- [`docs/GA-ROADMAP.md`](../GA-ROADMAP.md): §1.2 A1, Sprint 0 (L), §4,
  §5 (risk table: "Classification obtained").

## Open items

- Record an internal reference (register number or file location at
  SingularityRD legal) for each of the three clearances, in this ADR or
  in an internal register it points to. The register must hold no
  confidential contents.
- Put the export delivery conditions into
  [`docs/customer/eula-draft.md`](../customer/eula-draft.md) and the
  sales process.
