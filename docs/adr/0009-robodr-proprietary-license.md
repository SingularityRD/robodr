# ADR-0009: RoboDR is proprietary; Pulsar eBPF probes stay GPL-2.0

| | |
|---|---|
| Status | **Accepted (2026-10-25)**. Product owner decision recorded in GA-ROADMAP §2.1 D9 (commit `6c3fb3e`). |
| Implemented | 2026-10-25, `24fe84c` (root `LICENSE`, workspace licence, `publish = false`, `deny.toml`, package metadata) |
| Related | [ADR-0010](0010-legal-clearance.md), [ADR-0008](0008-licensing-enforced-at-soc.md) |

## Context

RoboDR began as an Apache-2.0 research codebase. An earlier draft of the
GA plan proposed an open-core split: sensor and parsers under Apache-2.0,
with the executor, firewall gateway and SOC module in a controlled
repository (`c48b2ee`). The product owner then chose a fully proprietary
model, the same as AutoSecOps1's "SingularityRD Proprietary License". The
reasons were the commercial model and export control. The GitHub
repository is private. It was confirmed on 2026-10-25 that no version was
ever published under Apache-2.0 (`ed3e219`).

## Decision

- RoboDR is **proprietary** software of SingularityRD. Use requires a
  separate written licence agreement.
- Exceptions, which keep their own licences:
  - the eBPF probe programs from Pulsar (`*.bpf.c`) stay **GPL-2.0**.
    They are distributed with an offer of the complete corresponding
    source;
  - vendored Pulsar userspace code keeps **Apache-2.0** and its NOTICE;
  - third-party Rust crates keep their own licences, recorded in the SBOM.

## Consequences

- Every RoboDR crate declares `license = "LicenseRef-Proprietary"` and
  `publish = false`. `cargo deny` checks only third-party crates, and it
  allows only permissive licences for userspace crates. Any
  GPL/LGPL/AGPL crate fails CI, so the linked binaries can still be
  distributed under proprietary terms
  ([`docs/BUILD.md`](../BUILD.md), "Licensing").
- Distribution must carry the GPL-2.0 source offer and the third-party
  notices. A RoboDR `THIRD_PARTY_NOTICES` file does not exist yet
  (GA-ROADMAP S12). A GA criterion in §4 is still open.
- The open-core split is off the table, but GA-ROADMAP §4 still lists
  "open-core split applied" as a GA criterion. Product owner: please
  confirm that line is obsolete.
- Customer terms: [`docs/customer/eula-draft.md`](../customer/eula-draft.md)
  (a draft for legal review).

## Implementation and evidence

- [`LICENSE`](../../LICENSE); [`LICENSES/LICENSE-GPL-2.0`](../../LICENSES/LICENSE-GPL-2.0),
  [`LICENSES/LICENSE-APACHE-2.0`](../../LICENSES/LICENSE-APACHE-2.0).
- [`Cargo.toml`](../../Cargo.toml) (`[workspace.package] license`),
  [`deny.toml`](../../deny.toml).
- `.deb` copyright: `packaging/build-deb.sh` installs `LICENSE` as
  `/usr/share/doc/robodr/copyright`.
- Sprint 1 acceptance (GA-ROADMAP, status of 2026-10-26):
  `cargo deny check advisories bans licenses sources` passed locally with
  cargo-deny 0.20.2. GitHub CI has not run.

## Open items

- `packaging/build-deb.sh` still defaults the maintainer to
  `robodr-maintainers@invalid` (GA-ROADMAP R10). A real support address
  must replace it before GA.
- The exact wording of the source offer (how, from whom, for how long) is
  for SingularityRD legal to fix. The current text is in
  [`LICENSE`](../../LICENSE).
