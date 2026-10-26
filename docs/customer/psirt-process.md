# DRAFT: Product security incident response (PSIRT) process

> **DRAFT — for review by SingularityRD legal, not legal advice.**
> This process extends [`SECURITY.md`](../../SECURITY.md), which stays
> the public policy. If they disagree, `SECURITY.md` wins until this draft
> is approved. Bracketed items are decisions still to be made. The
> process has **not been exercised yet**: no advisory has been published
> and no CVE has been assigned.

## 1. Scope

The process covers vulnerabilities in RoboDR software, packaging,
documentation and release supply chain, as scoped in `SECURITY.md`
"Scope". It does not cover:

- vulnerabilities in the robot platform, ROS 2, DDS vendors or the
  kernel. Those go to their maintainers; we check whether RoboDR detects
  the issue;
- vulnerabilities in vendored Pulsar that do not depend on RoboDR. Those
  go upstream, and we track the fix.

## 2. Roles

| Role | Responsibility | Assigned |
|---|---|---|
| PSIRT lead | Owns each case from intake to closure; decides severity with engineering | [name / role] |
| Engineering owner | Reproduces, fixes and tests | per component |
| Product owner | Approves disclosure dates and customer notices | [ ] |
| Legal | CRA reporting, export-control-sensitive content, researcher agreements | SingularityRD legal |
| Customer liaison | Notifies affected customers, including air-gapped sites through their agreed channel | [ ] |

## 3. Intake

- **Channel today:** GitHub private vulnerability reporting
  (`SECURITY.md`). The repository is private, so external researchers
  cannot reach it. **Add a public channel:** [security mailbox],
  `security.txt` on [domain], and [PGP key or another encrypted channel].
- **Air-gapped finders:** an offline report through the customer's
  normal channel to their RoboDR contact. No live evidence goes in a
  first report.
- Every report gets a case id [format] and is logged in [tracker:
  private, access-limited].

## 4. Triage

| Step | Target (`SECURITY.md`) |
|---|---|
| Acknowledge receipt | 3 working days |
| Initial assessment and severity | 10 working days |

Severity: [CVSS v3.1 or v4.0 base score, plus a RoboDR physical-impact
modifier]. Two rules are fixed:

- **Always Critical:** any way RoboDR could itself move, stop or command
  the robot other than through the documented safe-state request, or
  block or override the safety system; and any way the control plane
  reaches the robot (`SECURITY.md`).
- **High at least:** evasion of a core detection (for example a rogue
  motion writer hidden), and forging or undetectable truncation of
  evidence beyond the documented claims.

Triage also decides:

- **Affected versions**: only the latest release line is supported before
  1.0;
- **Workarounds that need no upgrade.** These matter for air-gapped
  fleets, which may not upgrade promptly;
- **whether the issue is actively exploited.** If it is, the CRA
  reporting clock starts (section 7).

## 5. Fix and release

1. Fix on a private branch with a regression test (the repository's
   `review_regressions.rs` pattern). Get an independent review of the
   fix.
2. Build the fixed release through the normal release workflow:
   reproducible, minisign-signed, with an updated SBOM. *(The release
   workflow has not run yet. The first real release is planned for
   GA-ROADMAP S12.)*
3. Critical and High: release as fast as practical, coordinated with the
   reporter (`SECURITY.md`). [Target: N days for Critical.]

## 6. Disclosure

- Coordinated disclosure: the advisory follows a fixed release and
  credits the reporter if they wish.
- **Advisory channel:** [customer portal / public advisory page /
  GitHub advisory on a public mirror]. The private repository's GitHub
  advisories are not visible to customers.
- **CVE:** [become a CNA, or request through a CNA such as MITRE]. To be
  decided.
- Advisory content: affected versions, fixed version, severity,
  mitigation without an upgrade, how to verify the fixed release. Do not
  include customer identifiers or site data.
- Customers with air-gapped sites get the advisory and the signed bundle
  through their agreed delivery channel.
- Before publication, legal checks that technical detail is not
  export-controlled.

## 7. EU CRA reporting (to be confirmed by legal)

For products on the EU market, an **actively exploited vulnerability**
or a **severe incident** affecting the product's security must be
reported to the designated CSIRT / ENISA single reporting platform:

1. an early warning without undue delay, [within 24 h] of becoming
   aware;
2. a notification [within 72 h];
3. a final report [within 14 days after a corrective measure is
   available] for vulnerabilities, or [1 month] for incidents.

Owner: [PSIRT lead + legal]. Hold a rehearsal before GA. See
[`docs/compliance/cra-readiness.md`](../compliance/cra-readiness.md).

## 8. Closure and learning

Close the case once the fix has shipped, the advisory is out, and the
reporter has been informed. Record the root cause and the SDL gap that
let it through, and add a regression test or fuzz target. Feed the
results into the IEC 62443-4-1 evidence
([`docs/compliance/iec-62443-4-1-sdl-evidence.md`](../compliance/iec-62443-4-1-sdl-evidence.md)).

## 9. Safe harbour

As in `SECURITY.md`: no legal action against good-faith research that
respects the policy, stays in scope, and does not touch robots or data the
researcher is not authorised to test. [Legal: review the wording for each
jurisdiction.]
