# Security policy

RoboDR (Robot Detection & Response) is security software that runs on robots,
some of them in defence and other safety-relevant settings. We treat
vulnerabilities in it as high priority.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report privately through GitHub's private vulnerability reporting:
<https://github.com/SingularityRD/robodr/security/advisories/new>.

If the robot or site is air-gapped and you cannot reach GitHub from where you
found the problem, write the report offline and send it through your
organisation's normal channel to your RoboDR contact. Do not include live
evidence (black-box exports, captures, keys) in a first report. Describe it and
we will agree a secure transfer.

Please include:

- the RoboDR version (`robodr-pulsard --version` prints the RoboDR and Pulsar
  versions and the Pulsar commit), the kernel version and the architecture;
- the component (sensor, capture, RTPS parser, commissioning, Motion Firewall,
  responder, black box, OCSF, packaging/systemd units);
- the impact as you understand it, and the steps or input that reproduce it,
  such as a pcap or JSONL that triggers the issue. Synthetic data is preferred.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement | 3 working days |
| Initial assessment and severity | 10 working days |
| Fix or mitigation for Critical/High | as fast as practical, coordinated with you |
| Public advisory | after a fixed release is available, credited to you if you wish |

We follow coordinated disclosure. We will not take legal action against
good-faith research that respects this policy, stays within the scope below,
and does not touch robots or data you are not authorised to test.

## Scope

RoboDR is **protective only**. It detects, refuses trust, records evidence
and *requests* a safe state through the platform's own interface. It never
targets, never controls weapons, and never overrides the platform's safety
system, e-stop or command authority. Reports in scope include:

- **Evasion**: traffic, process or file activity that RoboDR should detect but
  does not, such as a crafted RTPS message that hides a rogue `cmd_vel`
  writer, or a rule bypass.
- **Integrity of evidence**: forging, truncating, reordering or replaying
  black-box records or export bundles without detection; export-cursor or ack
  forgery; making a head anchor (TPM NV counter, remote receiver) accept a
  lower mark or making a unit accept one from it (see below).
- **Profile and commissioning**: poisoning a learned profile, bypassing
  sign-off, or loading an unsealed or tampered locked profile as enforcing.
- **Robustness**: a crash, hang, unbounded memory or CPU use, or panic driven
  by hostile input (network, pcap, JSONL, config). Any of these can blind the
  sensor.
- **Fail-safe behaviour**: any way RoboDR could itself move, stop or command
  the robot other than through the documented safe-state request, or could
  block or override the platform's safety system. These are always Critical.
- **Privilege**: escaping the systemd confinement in `packaging/systemd/`,
  reading `/etc/robodr/keys`, or using a RoboDR process to gain privileges.
- **Supply chain**: the release workflow, SBOM, signatures, `Cargo.lock`
  policy, and the offline install bundle.

Out of scope:

- requests to add offensive capability (attack tooling, active scanning,
  jamming, "hack back"). RoboDR will not ship these;
- vulnerabilities in the robot platform, ROS 2, DDS vendors or the kernel
  that RoboDR merely observes. Report those to their maintainers. We are glad
  to hear whether RoboDR detects the issue;
- vulnerabilities in vendored Pulsar (`vendor/pulsar`) that do not depend on
  RoboDR. Report them upstream (<https://github.com/exein-io/pulsar>) and tell
  us, so we can track the fix;
- the HMAC-SHA256 black-box authenticator being a shared-key MAC. This is a
  documented placeholder (`crates/robodr-blackbox/README.md`). Report attacks
  on its *use*, not on the fact that it is symmetric.

### Black-box head anchors: what is claimed

A cut of the newest black-box records combined with a rollback of the
unit's state files is detectable only with a head anchor the unit's
attacker cannot rewind (`blackbox.head_anchor`; details in
`crates/robodr-blackbox/README.md`). For the **remote** anchor
(`robodr-anchor-receiver` on a base station) the claims are:

- the receiver never lowers the mark it holds for a unit: only an
  authentic mark (the unit's Ed25519 signature over unit, chain id, seq,
  hash, key id; the record's own signature covers only the hash) with a
  higher seq replaces it; lower seqs, forks at the held seq and bad
  signatures are refused and alerted, and a replayed old mark changes
  nothing;
- a unit never accepts a lower mark (or "none") from the network: the
  answer to its query is bound to a fresh nonce and signed by the receiver
  key it is configured with, and the mark inside must carry the unit's own
  signature;
- a network attacker can drop marks and answers. Dropped marks widen the
  window (the receiver lags; watch `robodr-anchor-receiver status`), a
  dropped answer is an anchor failure on the signed record, never a clean
  open.

Not claimed: confidentiality of marks (no TLS; hashes and seqs only);
protection of a unit whose configuration (receiver address and public key)
an attacker rewrote: then only the receiver's side shows it (marks stop
arriving, or arrive lower). The receiver's own host, state directory and
signing key are trusted. Reports that break the claims above are in scope.

### Control-plane API (`robodr-control-plane/v2`): what is claimed

`robodr-agentd`'s optional `control_plane` API (off unless configured;
contract `docs/contracts/robodr.control-plane.md`) lets a SOC request one
of the seven catalog containment actions and export black-box evidence. The
claims are:

- **Nothing is executed unless executor v1 is enabled.** By default (no
  `executor` section, or `"enabled": false`) the only executor records: an
  accepted request is answered `recorded_not_executed` (`"executed":
  false`) and written to the black box as a plan; nothing is sent to the
  robot, its network, its mission executive or its safety system. With
  `executor.enabled`, agentd hands `isolate_network` / `quarantine_node`
  (reversible nftables rules with a TTL) and `record_evidence` to the
  separate `robodr-executor` (the only `CAP_NET_ADMIN` unit), only after
  the request's black-box note exists; the executor re-checks the live
  safety state before it applies. Its states (`verified`, `refused`,
  `failed`, `reverted`) are signed answers and journalled like every other
  state. Motion, safe-pause, safe-state and rollback actions are never
  executed.
- **No channel without the SOC's certificate.** Off loopback the API is
  served only over mutual TLS (rustls): the peer must present a client
  certificate that chains to the configured SOC CA, is valid now and, if
  pins are configured, has a pinned public key. No session resumption.
  Failed handshakes are counted and reported like failed signatures.
- **No request without a SOC key.** On every listener, every request must
  also carry an Ed25519 signature by a configured SOC public key over the
  method, the exact target, this robot's id, the key id, a timestamp, a
  nonce and the body hash. A modified, re-targeted (another robot) or
  replayed request is refused, **also across a restart**: the nonce store
  is persisted before a request proceeds, fails closed when full or not
  writable, and fences (refuses everything signed before the start) when it
  cannot be trusted. Unauthenticated requests are never judged or recorded
  one by one; they are counted and reported
  (`robot.agent.control_plane_unauthenticated`, High, observe-only).
- **A valid key cannot ask for more.** The seven catalog actions with their own
  parameters and TTL rules; no motion command, force or override field
  exists, and `authority` must be `request`. The strongest action is a
  *request* for a safe state. Every request is judged against the current
  safety state: while the e-stop or safe state is active everything is
  refused, observe mode refuses everything, motion-affecting requests are
  refused while a person commands motion or during take-off / landing, and
  nothing above the response policy's ceiling for the state is accepted.
  Authenticated but invalid requests are refused, recorded and reported
  (`robot.agent.control_plane_invalid`).
- **Every decision is evidence, and is not forgotten.** Request (with its
  signature and body, so it re-verifies offline), safety state, context and
  decision are one signed, fsynced black-box note; if the black box does
  not take it, the answer is `failed` and nothing is claimed or stored. The
  request state is journaled around that note (begin / commit), so a
  restart neither forgets an answered decision nor invents one: a decision
  a crash left half-journaled is settled from the black box.
- **Every answer is authentic.** Every answer to an authenticated request is
  signed with the finding key, bound to the request's signature (a replayed
  answer does not verify); the robot never sends an unsigned success.
- **Evidence leaves only as recorded.** Exports carry the black box's frames
  byte for byte (hashed, chained, signed by the black-box key) with a
  manifest signed by the finding key; no key material and nothing outside
  the black box's segment files is read into one. The SOC verifies them
  with the robot's public keys only.
- **Bounded.** Parsing, TLS handshakes, connections, the per-key rate limits,
  the answer write time, evidence exports (size, count, storage, one at a
  time) and the queue to the main loop are bounded; a flood costs the
  control plane's availability (429 / 503), never the detection loop's.
  The request parser has a libFuzzer target (`control_plane_request`).

Not claimed: confidentiality or authentication on the loopback listener and
the unix socket (local only, file permissions); availability against a
network attacker; protection when the SOC's private key **and** client
certificate, or the robot's configuration (`soc_keys`, `tls`), are
compromised; revocation of a SOC client certificate other than by removing
its CA or pin and restarting; integrity of the request journal against a
person with write access to the state directory (it is checksummed, not
signed: it can be made to forget or to fence, the black box keeps every
decision); correct judgment when the safety state source is wrong (see the
live safety feed's own limits). Reports that break the claims above, or any
way the API reaches the robot, are in scope (the latter is always
Critical).

## Supported versions

RoboDR is pre-1.0. Only the latest release line receives security fixes.

| Version | Supported |
|---|---|
| 0.1.x pre-releases (latest only) | yes: fixes ship as the next pre-release |
| older pre-releases | no: upgrade (offline bundle, `docs/OPERATIONS.md`) |

From 1.0 the latest minor release, and the previous one for 6 months after a
new minor, will be supported. Air-gapped fleets cannot always upgrade promptly,
so advisories will state the mitigations that need no upgrade wherever we can.

## Verifying what you run

Releases are signed with minisign. Each artefact has a `.minisig`, and
`SHA256SUMS` is signed as well. Releases ship CycloneDX SBOMs, and the pure
binaries are built reproducibly. See `docs/OPERATIONS.md`, "Verify a release",
for the offline procedure. The release public key must reach your entry station
through a channel you trust, never from the bundle itself.
