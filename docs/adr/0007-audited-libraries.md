# ADR-0007: Audited libraries instead of hand-written HTTP, crypto and Kafka code

| | |
|---|---|
| Status | Proposed (partly implemented): SHA-256 / HMAC from `sha2` / `hmac` (`86e70e7`); Reed-Solomon kept in-crate, pinned to an independent oracle (`aba80a5`); the HTTP server (fuzzed) and the Kafka client remain hand-written |
| Proposed | 2026-10-25, GA-ROADMAP §2.1 D7 (commit `a5c5afd`); the main work is in Sprints 5 and 10 |
| Implemented in part | Ed25519 through `ed25519-dalek` (before the GA plan). TLS for `robodr-uplink` through rustls + ring (`fa3f3dc`, 2026-10-26). |
| Related | [ADR-0004](0004-control-plane-v2.md), [ADR-0001](0001-findings-transport-native-ingest.md) |

## Context

RoboDR was first built where crates.io was not reachable. Several
security-relevant components were written by hand (GA-ROADMAP §1.1 R8):

- SHA-256 and HMAC-SHA256: [`crates/robodr-blackbox/src/crypto.rs`](../../crates/robodr-blackbox/src/crypto.rs);
- the HTTP/1.1 server of the control plane: [`crates/robodr-agentd/src/control/http.rs`](../../crates/robodr-agentd/src/control/http.rs);
- a Kafka wire client (API v8 and below, no TLS or SASL): [`crates/robodr-export/src/kafka/`](../../crates/robodr-export/src/kafka/);
- Reed-Solomon parity for the diode: [`crates/robodr-diode/src/fec.rs`](../../crates/robodr-diode/src/fec.rs);
- a JSON-Schema-like validator in `robodr-ocsf`.

A product sold for security assurance should rely on audited libraries
where they exist.

## Decision (as proposed)

- The control-plane HTTP server moves to `rustls` plus a minimal, fuzzed
  HTTP layer, or `hyper` is evaluated. Either must fit the MSRV and
  air-gapped builds.
- The in-house SHA-256 is replaced by `sha2`.
- Kafka: **either** add TLS and SASL to the in-house client, **or** move
  the optional export to `rdkafka`. The roadmap leaves this choice for
  Sprint 0.

## Consequences

- More third-party code in the supply chain. Each new crate is checked by
  `cargo deny` (licenses, advisories, sources;
  [`deny.toml`](../../deny.toml)) and appears in the SBOM.
- `rdkafka` would bring a C library (librdkafka) into the build, along
  with its reproducibility and static-build problems. The ring C code
  already needs a pinned clang (`38ac3a7`).

## Implementation and evidence

- Done: Ed25519 signing and verification use `ed25519-dalek` with strict
  verification ([`Cargo.toml`](../../Cargo.toml) workspace dependencies,
  [`crates/robodr-blackbox/src/sign_ed25519.rs`](../../crates/robodr-blackbox/src/sign_ed25519.rs)).
  SHA-512 inside Ed25519 comes from `sha2`.
- Done: `robodr-uplink` uses rustls 0.23 with ring and rustls-webpki, with
  the operator's CA bundle as the only trust anchor and optional SPKI pins
  ([`crates/robodr-export/src/uplink/http.rs`](../../crates/robodr-export/src/uplink/http.rs)).
  Its small HTTP/1.1 *client* is hand-written on purpose. The reasons are
  in [`crates/robodr-export/README.md`](../../crates/robodr-export/README.md),
  "TLS and HTTP".
- Open: SHA-256 and HMAC in `crypto.rs`, the agentd HTTP server, the
  Kafka client, Reed-Solomon.

## Open items

- Product owner: Kafka. Choose TLS and SASL in the in-house client, or
  `rdkafka`.
- Is a hand-written HTTP client still acceptable in `robodr-uplink` if
  TLS is done by rustls? Or does D7 also cover clients?
