# Secure defaults: installation and update path

Every check on the path from a release tarball to running services is on
by default. This table lists each one, what it protects against, and the
only way to relax it. An override is always an explicit flag or variable
on one command line; nothing is relaxed by a configuration file, and
nothing below is relaxed by `ROBODR_ROOT` (staging and tests only).

Scope: `packaging/install-bundle.sh` (installed as
`/usr/lib/robodr/install-bundle.sh`), the deb maintainer scripts / RPM
scriptlets and the commands of `robodr-deliverd` they use. Procedures:
`docs/OPERATIONS.md` sections 3 (install) and 7 (upgrade and rollback).
On-unit delivery of RPKs (`robodr-deliverd`) has its own gates:
`docs/SECURE-DELIVERY.md`.

| Default | Protects against | Override (who, when) |
|---|---|---|
| `install` refuses a bundle whose minisign signature was not checked against the pinned release key (`--pubkey`, `--tarball`) | installing a modified or foreign build | `ROBODR_ALLOW_UNSIGNED=1`, lab only, and **refused** once a release with the built-in verifier is installed: sign lab builds with a lab key instead |
| Signatures are checked with RoboDR's built-in verifier (`robodr-deliverd verify-minisign`, from the installed, verified release) after its known-answer self-test; `minisign` only before the first such release | depending on a third-party tool on the robot; a broken verifier passing everything | none (a verifier failing its self-test stops the install, exit 2) |
| Only prehashed (`ED`) minisign signatures, strict Ed25519, canonical base64; the signed trusted comment must name the tarball's file name | legacy-format edge cases; a signed bundle renamed to pass for another one | none |
| The tarball (and its signatures and `SHA256SUMS`) is copied once into a private 0700 directory; every check and the extraction read only that copy; a modified extracted bundle directory is refused | time-of-check / time-of-use swaps of the tarball or the extracted files | none |
| Downgrades (a release older than the installed one, including a half-configured one) are refused | re-introducing fixed vulnerabilities | `--allow-downgrade` (deliberate); `rollback` to a kept release |
| Nothing installs below the unit's security floor (highest minimum ever seen in a signed bundle or the SOC's signed ring information) | rolling back into a known-vulnerable release | none |
| Replacing the installed variant (`robodr` / `robodr-focal`) is refused | silently losing `robodr-pulsard` (the focal variant has none) | `--allow-variant-switch` |
| Black-box format gate: a release that cannot read a verified on-disk segment is refused | a release that can neither verify nor extend existing evidence | `--accept-unreadable SEG`, per segment, by name |
| Services are installed **disabled** on first install | an uncommissioned robot enforcing | none: the operator enables them after commissioning |
| An upgrade never restarts `robodr-firewall-gw` or `robodr-executor` unguarded: maintainer scripts leave them on the old binaries (`/var/lib/robodr/pending-restart`); `install` / `rollback` refuse while one of them runs and the live safety state is not `idle` / `safe_state_active` | dropping queued motion commands (fail-closed gateway) or pending executor actions while the robot moves | `--defer-restart` (restart later with `restart-pending`, gated; refused for a target release whose maintainer scripts predate the gate, 0.1.0-alpha.1, as they restart both unconditionally); `--allow-gateway-restart` (deliberate, motion interrupted); `ROBODR_GATED_RESTART=allow` in a plain `dpkg`/`rpm` run only lets the one-time gateway user migration stop the gateway |
| The safety state is taken only from agentd (status socket checked with `SO_PEERCRED`, fresh by `CLOCK_MONOTONIC`, this boot, a live safety feed); anything else is `unknown`, i.e. closed | a forged or stale "idle" | none |
| Post-install health check: every unit that ran before runs again and agentd's heartbeat is fresh, else **automatic rollback** to the previous kept release (exit 1) | an upgrade that leaves the robot without detection or response | `--no-auto-rollback` (report only); `--health-timeout SECS` |
| Every installed release is kept for rollback | having nothing to roll back to | `--keep N` / `prune --keep N` (always keeps the installed release, `prune` refused when the installed version is unknown; formats files of pruned releases are archived so the format gate stays strict) |
| On removal the gateway's ruleset (`robodr-firewall-gw-rules`) is not stopped | a removal opening the bridge to unchecked motion | take the gateway out of the path explicitly (OPERATIONS.md 6.6) |
| `on_gateway_down = fail_closed` | unchecked motion while the gateway is down | `bypass` (refused for humanoid joint channels) |

When an override is used the script says so on its output (`WARNING`,
`UNSIGNED install`), so the site log of the install records it.
