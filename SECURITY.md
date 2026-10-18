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
