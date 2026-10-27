# DRAFT: End-User Licence Agreement (RoboDR)

> **DRAFT — for review by SingularityRD legal, not legal advice.**
> This is an engineering-prepared outline that lists the points the
> agreement must cover, so legal can draft the real text. It has no legal
> effect. Square brackets mark placeholders and decisions. Until legal
> approves a text, the governing terms are the [`LICENSE`](../../LICENSE)
> file and any signed agreement.

## Parties and scope

1. **Licensor:** SingularityRD [legal entity, registered address].
   **Licensee:** [customer legal entity].
2. **Software:** RoboDR (robot detection and response). This covers the
   binaries, packages, documentation and updates SingularityRD delivers
   under this agreement. The source code is not licensed unless a
   separate source-code agreement says so.
3. **Relation to AutoSecOps:** [state whether the SOC product is
   licensed under this agreement or a separate one; the licence token and
   robot quota are enforced on the SOC side, see ADR-0008].

## Grant

4. A non-exclusive, non-transferable [, non-sublicensable] licence to
   install and use the Software on [the number of robots / sensor boxes in
   the order form] at [the sites in the order form], for the Licensee's
   internal security monitoring.
5. **No technical licence enforcement on robots.** The robot agent has no
   licence check by design. The Licensee's obligation to stay within the
   licensed quantity is contractual, and the SOC counts robots.
   [Legal: audit right? true-up?]
6. Restrictions: no reverse engineering except as mandatory law permits;
   no redistribution; no use to build a competing product; [other].

## Third-party and open-source components

7. Third-party components keep their own licences, as listed in the
   SBOM and the third-party notices shipped with each release
   [notices file: planned, GA-ROADMAP S12].
8. **Pulsar eBPF probes (GPL-2.0).** These kernel programs are licensed
   under GPL-2.0, not under this agreement. The complete corresponding
   source is available from SingularityRD [offer wording, duration,
   address, per legal's clearance, see ADR-0010]. Nothing in this
   agreement restricts rights the Licensee has under GPL-2.0 for those
   components.
9. Vendored Pulsar userspace code: Apache-2.0, NOTICE retained.

## Safety and intended use

10. **Not a safety component.** The Software is a cybersecurity product.
    It is not safety-rated (no SIL or PL), and it must not be used as, or
    in place of, any safety function. The Licensee remains responsible
    for the robot system's risk assessment and safety functions. See
    [`docs/compliance/safety-positioning.md`](../compliance/safety-positioning.md).
11. **Responses.** Response actions require human approval. Where
    enabled in future releases, they run only under a response policy
    that the Licensee (with the OEM) has validated. The Licensee is
    responsible for that validation. [Legal: allocation of liability for
    approved actions.]
12. **Protective use only.** No use for offensive purposes, targeting or
    weapons control. [Legal: align with export conditions.]

## Export control

13. The Software is subject to export-control rules. Legal clearance and
    a classification were obtained on 2026-10-25 and are on file with
    SingularityRD legal (ADR-0010). [Insert the delivery conditions that
    come from the classification: restricted destinations and end uses,
    end-user statements, re-export clauses.]

## Updates, support, security

14. Updates and support as in the support agreement
    ([`sla-support-draft.md`](sla-support-draft.md)). **Support period:
    [N years from first delivery / from release of the version]**. This
    must be consistent with the EU CRA
    ([`docs/compliance/cra-readiness.md`](../compliance/cra-readiness.md)).
15. Security updates are provided [free of charge] for the support period.
    [Legal: CRA alignment.]
16. Vulnerability reporting and coordinated disclosure:
    [`SECURITY.md`](../../SECURITY.md), [`psirt-process.md`](psirt-process.md).

## Data

17. The Software processes robot telemetry metadata, findings and
    evidence on the Licensee's systems. SingularityRD receives no data
    unless the Licensee sends it, for example in a support case. Evidence
    sent for support follows [data-handling terms].
    [Legal: DPA if personal data (for example operator names in
    commissioning sign-offs, analyst ids in requests) is processed by
    SingularityRD.]

## Warranty, liability, term

18. Warranty: [limited warranty / as-is for pre-release versions]. The
    current `LICENSE` text disclaims all warranties. Legal to decide the
    commercial position.
19. Limitation of liability: [cap; exclusions; carve-outs for mandatory
    law].
20. Term and termination: [term]. On termination the Licensee stops
    using the Software. **Evidence and keys stay with the Licensee:**
    termination does not oblige the Licensee to destroy evidence it must
    keep under its own retention rules.
21. Governing law and venue: [ ].

## Open questions for legal

- Pre-release (alpha and beta) evaluation terms for design partners:
  separate evaluation licence?
- Whether the SOC product (AutoSecOps) is covered by this agreement.
- Export conditions to insert in item 13.
- CRA: support period, free security updates, user information duties.
