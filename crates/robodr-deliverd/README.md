# robodr-deliverd

The on-unit delivery agent of RoboDR's secure delivery
(`docs/SECURE-DELIVERY.md` §2.1, §4.2, §6, Sprint 13b). It installs, from
a **per-unit media pack**, RPKs of the kinds `files`, `config`, `deb` and
`robodr-rules`, behind the robot's **live safety-state gate**, with a
health gate, automatic rollback, anti-rollback floors and black-box
evidence. Formats and signature rules are `robodr-pkg`'s; the
verified-copy import and the trust anchor are `robodr-release`'s (13a
code, reused).

```
robodr-deliverd run          --config FILE      # the daemon (robodr-deliverd.service)
robodr-deliverd once         --config FILE      # one pass, JSON report
robodr-deliverd check-config --config FILE
robodr-deliverd init-anchor  --config FILE --trust TRUST.json   # once, at enrolment
robodr-deliverd status       --config FILE
robodr-deliverd confirm      --config FILE --deployment DIGEST --package NAME
robodr-safety-replay --socket PATH --file REPORTS.jsonl [--repeat-ms N] [--hold-ms N] [--check]
```

Exit codes: 0 ok, 1 refused or error, 2 usage. `man robodr-deliverd(8)`,
`docs/OPERATIONS.md` section 11.

## What a pass does

1. **Media in, verified copy only.** Every directory under `media_dir`
   is a media pack (`robodr-media-pack/1`: `trust.json` + `.sig`,
   `deployment.json` + `.sig`, `bundles/<label>/`; nothing else, no
   symlink anywhere). Its trust file is accepted only as the unit's trust
   anchor or a rotation of it (pinned roots, the unit's own site); the
   deployment needs the depot and the operator quorum of its ring, must
   name this unit (lab / canary: by unit id only; production rings: by
   unit id or an enrolled group), be for the unit's own ring (from the
   root-signed `rings`, else enrolment), fit the ring's size, and be newer
   than the accepted one; each bundle goes through
   `robodr_release::ops::import_bundle` (copy bounded by listed sizes,
   hash while copying, verify the copy). Only then is the copy renamed to
   `packs/<seq>-<digest>`. A refused pack is reported once.
2. **Item by item.** Each RPK the deployment names (by digest) must fit
   the unit (architecture, platform, hardware, kind, evaluable health
   checks, the unit's and the site's floors, revocations, `requires` /
   `conflicts`). It is copied into the content-addressed store (every
   chunk hashed as it is written) and **prepared** next to the running
   version (files / config / rules: a version directory; deb: the `.deb`,
   inspected with `dpkg-deb`, maintainer scripts refused unless the release
   allowed them).
3. **Gate.** The deployment's maintenance window, an operator
   confirmation when the RPK requires one, and agentd's live safety state
   (`status.json`, fresh, this boot, a live `safety_feed`): only `idle` and
   `safe_state_active` let the switch happen, read again immediately before
   it. Otherwise the item is deferred (staging stays; a note per change of
   reason; `robot.deliver.deferred_safety`, Low, Medium when repeated).
4. **Intent, floor, switch.** The write-ahead intent and the raised floor
   are fsynced in the state file before the switch (`current` /
   `rules_active/<name>` symlink swap, or `dpkg --install`).
5. **Health gate.** The RPK's checks (`service_active`, `file_present`,
   `probe`: argv executed without a shell, as the probe user's UID with
   supplementary groups dropped, fixed environment, own process group
   killed on timeout, output bounded) plus agentd healthy.
6. **Install or roll back.** Pass: installed (`robot.deliver.installed`).
   Fail: back to the previous version if it is at or above the floor and
   still in the store (`robot.deliver.health_failed`, also gated by the
   safety state), else the unit stays on the failing version
   (`robot.deliver.rollback_blocked_floor`, Critical).
7. **Freshness.** An expired newest deployment or trust file is
   `robot.deliver.stale` (Medium, High after the grace period). With
   `trust.clock: untrusted` time is the newest depot-signed time accepted
   (never beyond the trust file's expiry), so expiry "by the depot's
   clock" is what is reported.

Every step is a critical note (`robodr.deliver.*`) in the agent's own
black-box chain (`/var/lib/robodr/blackbox/deliverd`, the unit's black-box
key); findings go into agentd's spool with no-replace record names.

## Crash safety

One switch per pass; the intent moves `activating` → `health` →
(`rolling_back`). After a crash the next pass reads what is actually
active (`current` link, `dpkg-query`) and finishes or undoes the switch;
`tests/crash.rs` crashes at every step of a good and a bad release and
checks the state after the crash and after recovery. The state file is
replaced atomically and never written with a lower floor; a missing or
older state file takes the floors recorded in the black box.

## Modules

| Module | What |
| --- | --- |
| `config` | `robodr-deliverd-config/1`: unit identity, pinned roots, clock trust, paths (disjoint trees), tools, health limits |
| `media` | media pack layout, verified-copy import, unit / ring / rollout / item checks, bundle chain heads per programme |
| `store` | content-addressed store, hash-checked materialisation |
| `install` | installers per kind (prepare, switch, active version) |
| `safety` | agentd `status.json` → safety state (fresh, this boot, live feed) |
| `health`, `runner`, `users` | health checks; bounded argv execution; probe users by UID |
| `rules` | structural check of Pulsar rule files (what decides whether they load) |
| `state`, `fault` | durable state, monotonic floors, write-ahead intent; crash points for tests |
| `journal`, `findings` | black-box notes; `robot.deliver.*` findings into the agentd spool |
| `engine` | the reconcile loop and recovery |
| `replay` | `robodr-safety-replay`: recorded safety reports into agentd's `safety_feed` socket |

## Limits (13b)

* Kinds `oci-image`, `model`, `robodr-profile`, `os-image` and sealed RPKs
  are refused (`unsupported`): 13c / 14a / 14c.
* `ros2_node` health checks cannot be evaluated on the unit: an RPK
  declaring one is refused before anything is installed.
* No soak window and no attestation check in the health gate (§6.2):
  14a / Sprint 12.
* Floors are in the state file and the black box, not a TPM NV counter
  (14b): root can delete both.
* Probe users come from the passwd file only (no NSS).
* The safety state is agentd's `status.json`: whoever controls the
  `robodr` user can claim `idle` to agentd's responder and to this gate.
* `deb` maintainer scripts, when the release allows them, run as root
  under the unit's capability bounding set.
* `robodr-rules`: the condition DSL is not type-checked on the unit
  unless `install.rules_validator` runs `validate_rules.py`; Pulsar's own
  compile on reload is the last check (a failed reload rolls back).
* Bundles only chain for detection on a unit (gaps reported, not refused):
  the deployment is the install authority.

## Tests

`cargo test -p robodr-deliverd` (temporary directories; the `deb` tests
use the host's dpkg against a separate dpkg root and need root, else they
are skipped; `ROBODR_REQUIRE_DPKG_TEST=1` makes that a failure):

* `exit_criteria.rs`: bad release rolls back; downgrade below the floor
  refused; deferred while `moving_slow`, proceeds when `idle`; a failing
  release that raised the floor is blocked; all in the black box.
* `agentd_replay.rs`: a real agentd, `robodr-safety-replay` replaying
  `moving_slow` then `idle` into its `safety_feed` socket; findings in
  agentd's own spool.
* `adversarial.rs`: shell metacharacters in probes, hanging and flooding
  probes, privileged probe users, packs for another unit / ring / site /
  group, rollout over the ring, depot-only and wrong-role deployments,
  traversal and symlinks (payload, media, install roots, `current`), a
  config RPK outside its root, replays, equivocation, chain gaps, trust
  rollback, expiry, untrusted clock, operator confirmation, maintenance
  window, deleted state file, rotated revocations, the single-agent lock.
* `crash.rs`, `kinds.rs` (deb with dpkg, rules), `binary.rs`,
  `fuzz_smoke.rs` (`deliverd_state`, `deliverd_inputs`).
