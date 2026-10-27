# DRAFT: Support and service levels (RoboDR)

> **DRAFT — for review by SingularityRD legal, not legal advice.**
> This is an engineering-prepared template. Every number in square brackets
> is a **placeholder** for the product owner and legal to set. None of
> them is a commitment. The security response times in
> [`SECURITY.md`](../../SECURITY.md) apply to vulnerability reports from
> anyone, whatever support tier they have.

## 1. Support tiers

| | Standard | Premium | Mission-critical |
|---|---|---|---|
| Hours | [business hours, time zone] | [extended hours] | [24×7] |
| Channels | [portal, email] | [+ phone] | [+ named engineer] |
| Named contacts per customer | [2] | [4] | [8] |
| Air-gapped site assistance (media exchange, on-site) | [—] | [remote guidance] | [on-site, N days/year] |
| Commissioning review (profile sign-off support) | [—] | [1 per year] | [per site] |
| Release advance notice | [—] | [N days] | [N days, with a test bundle] |

## 2. Severity definitions

| Severity | Definition (draft) |
|---|---|
| S1 Critical | RoboDR causes or could cause the robot to move, stop or be commanded other than through the documented safe-state request, or it interferes with the safety system. Also: production robots have lost all detection with no workaround. *(The first case is always also a security incident, see [`psirt-process.md`](psirt-process.md).)* |
| S2 High | Loss of detection, evidence or delivery to the SOC on part of a fleet; a workaround exists but is impractical |
| S3 Medium | Degraded function; a workaround exists |
| S4 Low | Questions, documentation, cosmetic |

## 3. Response targets (placeholders)

| Severity | Initial response | Update interval | Target to workaround or fix |
|---|---|---|---|
| S1 | [1 h] (24×7 tiers) / [4 business h] | [4 h] | [workaround 24 h / fix in next patch release] |
| S2 | [4 business h] | [1 business day] | [5 business days] |
| S3 | [1 business day] | [weekly] | [next minor release] |
| S4 | [3 business days] | — | [best effort] |

Response targets are measured from receipt on a supported channel. For
air-gapped sites, any time spent transferring evidence through the
customer's own media process does not count towards the targets.
[Legal: confirm.]

## 4. Supported versions and support period

- **Support period:** [N years per major version, from GA of that
  version]. This must meet the EU CRA expectation of a period that
  reflects the product's expected use (at least 5 years unless that use
  is shorter; see [`docs/compliance/cra-readiness.md`](../compliance/cra-readiness.md)).
  `SECURITY.md` currently says "from 1.0, the latest minor, and the
  previous one for 6 months", and must be aligned with this.
- **Security fixes:** for every supported version, [free of charge],
  delivered as signed offline bundles.
- **Air-gapped fleets:** advisories state mitigations that need no
  upgrade wherever possible (`SECURITY.md`).

## 5. Customer responsibilities

- Keep the robot and SOC hosts within the
  [`support-matrix.md`](support-matrix.md).
- Verify releases at the entry station with the release key received out
  of band.
- Validate response policies with the OEM before enabling enforcement.
- Provide synthetic or sanitised reproductions where possible. Live
  evidence (black-box exports, captures, keys) is transferred only by
  agreement.

## 6. Exclusions

[Unsupported platforms, modified binaries, third-party components covered
by their own maintainers (ROS 2, DDS vendors, the kernel, the robot
platform), customer-built rules, …]

## 7. Service credits

[Legal / commercial: whether, how much, how claimed.]
