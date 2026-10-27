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
robodr-deliverd reanchor     --config FILE --trust TRUST.json [--key FILE]   # lift the lock after a lost state
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
   `packs/<seq>-<digest>`. A pack is remembered by its **content digest**
   (not its directory name): a refused pack is reported once, a corrected
   copy under the same name is judged again.
2. **Item by item.** Each RPK the deployment names (by digest) must fit
   the unit (architecture, platform, hardware, kind, evaluable health
   checks, the unit's and the site's floors, revocations, `requires` /
   `conflicts`). It is copied into the content-addressed store (every
   chunk hashed as it is written) and **prepared** next to the running
   version (files / config / rules: a version directory named
   `<serial>-<digest>`; deb: the `.deb`, inspected with `dpkg-deb`,
   maintainer scripts refused unless the release allowed them). A serial
   that is installed, kept as a rollback target or in a switch with other
   content is refused (`equivocation`). For `deb` the RPK name and arch
   **are** the dpkg `Package` and `Architecture` (or `all`); a package
   another RPK name owns, a higher serial with a lower dpkg version and a
   `.deb` that is or conflicts / breaks / replaces / provides RoboDR's own
   packages (unless from `install.robodr_programme`) are refused.
3. **Gate.** The deployment's maintenance window (judged on the system
   clock only when it is trusted; with `trust.clock: untrusted` it stays
   closed, there being no signed current time), an operator confirmation
   when the RPK requires one, and agentd's live safety state, **from agentd
   only**: its status socket (`SO_PEERCRED`: agentd's user
   `robodr-agentd` or root) or a status file that only that user or root
   can have written; fresh, this boot, a live `safety_feed`. Only `idle`
   and `safe_state_active` let the switch happen, read again immediately
   before it. Otherwise the item is deferred (staging stays; a note per change of
   reason; `robot.deliver.deferred_safety`, Low, Medium when repeated).
4. **Intent, floor, switch.** The write-ahead intent and the raised floor
   are fsynced in the state file before the switch (`current` /
   `rules_active/<name>` symlink swap, or `dpkg --install`). A `.deb` may
   name only its own package in `Conflicts` / `Breaks` / `Replaces` /
   `Provides`. Right before the switch, every path of the `.deb` is
   resolved through the root's symlinks (merged-/usr aliases such as
   `/lib -> usr/lib`) and refused when another package owns it or it lies
   below the agent's trees, RoboDR's install paths, `/etc/dpkg`,
   `/etc/apt` or `/var/lib/dpkg` (`debfs`); every other recorded deb
   package must be as the agent left it (one changed outside the agent is
   reported, `changed_outside`, and deb installs wait; it is never
   downgraded). dpkg runs with `--refuse-all`, the needed forces and
   `--refuse-overwrite`. After every `dpkg --install` every other recorded
   deb package must still be installed at its recorded version, with the
   `dpkg --verify` output and file list it had right after its own
   install (otherwise it is reinstalled and the switch fails).
5. **Health gate.** The RPK's checks (`service_active`, `file_present`,
   `probe`: argv executed without a shell, as the probe user's UID (a
   regular account, `1000..=59999` by default) with supplementary groups
   dropped, fixed environment, rlimits (CPU, address space, open files,
   processes), own session and process group killed on timeout, output bounded, and
   this process a child subreaper while it runs, so anything it leaves
   behind, even in a new session, is killed with its process group (only
   groups outside the agent's session) until none is left (at most 10 s)
   and fails it) plus agentd healthy.
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
key); findings go into agentd's spool with no-replace record names,
written through directory descriptors (`O_TMPFILE` + `linkat`), never a
path in the directory agentd's user owns, within agentd's spool shares
(findings below Critical stop at 7/8 of `findings.max_ready_files`;
`robot.deliver.rollback_blocked_floor` is Critical and may use the last
eighth, up to one source's cap).

## Crash safety

One switch per pass; the intent moves `activating` → `health` →
(`rolling_back`). After a crash the next pass reads what is actually
active (`current` link, `dpkg-query`) and finishes or undoes the switch;
`tests/crash.rs` crashes at every step of a good and a bad release and
checks the state after the crash and after recovery. The state file is
replaced atomically and never written with a lower floor. The floors,
deployment sequence, time floor and chain heads are also in a signed
high-water record (`<blackbox.dir>/highwater.json`, written first, never
rotated), which also carries the lock and a generation counter noted in
the journal (`robodr.deliver.highwater`) and the state file: a missing
or older state file is restored from a current record (and from the
journal's floor notes). A record older than the journal or the state
file, a locked one, or a missing / invalid one while the state file or
the journal exists locks the agent until `reanchor`, which rebuilds the
deployment sequence and chain heads from the journal and refuses a trust
file older than the journal has seen (`--key`: the black-box key file,
since the configured one is a systemd credential). Only journal notes
that verify with the unit's key count. After a rotation of the black-box
key, `rekey --old-key FILE --new-key FILE` (service stopped) verifies the
journal and the record with the old key, archives the journal as
`<blackbox.dir>.archived-g<N>` and starts a new journal and record under
the new key carrying the whole baseline.

## Modules

| Module | What |
| --- | --- |
| `config` | `robodr-deliverd-config/1`: unit identity, pinned roots, clock trust, paths (disjoint trees), tools, health limits |
| `media` | media pack layout, verified-copy import, unit / ring / rollout / item checks, bundle chain heads per programme |
| `store` | content-addressed store, hash-checked materialisation |
| `install` | installers per kind (prepare, switch, active version); dpkg flags, `dpkg --verify` and file-list baselines |
| `debfs` | a `.deb`'s paths (strict tar reader), resolution through the root's symlinks, owners from dpkg's file lists, protected paths |
| `rekey` | carrying the journal and the record over a black-box key rotation |
| `safety` | agentd's status, from agentd only (socket + `SO_PEERCRED`, or an owner-checked file) → safety state (fresh, this boot, live feed) |
| `health`, `runner`, `users` | health checks; bounded argv execution (probes: rlimits, subreaper); probe users by UID |
| `highwater` | the signed high-water record (floors, sequence, time floor, chain heads) |
| `fdio` | `openat` / `linkat` / `unlinkat` relative to held directory descriptors |
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
* Floors are in the state file, the signed high-water record and the
  black box, not a TPM NV counter (14b): root deleting or rolling back the
  state file or the record makes the agent lock until re-anchored; root
  deleting the journal too (or flooding it and then putting an older
  record back) is not detected. The record is signed with agentd's
  black-box key (13b review 2, L-C, open).
* Probe users come from the passwd file only (no NSS).
* The safety state is taken from agentd's user (or root) only; whoever
  controls root, `robodr-agentd` or a configured safety feeder can still
  claim `idle`.
* Release signers are fully trusted for `deb` (root-equivalent on the
  unit): the unit's hardening does not contain approved content
  (`docs/SECURE-DELIVERY.md` §6.7). Maintainer scripts, when the release
  allows them, run as root under the unit's capability bounding set.
* With `trust.clock: untrusted` maintenance windows never open (no
  signed current time in 13b).
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
* `review_13b.rs`: the self-review regressions and the independent
  review's findings H1-L4 (forged status from another service's user,
  `deb` identity, flooded journal and lost state, swapped spool
  directories through the writer's test seam, kept-version equivocation,
  detached and limited probes, system-account probe users, untrusted
  clock windows, corrected packs under the same name).
* `review2_13b.rs`: the second review's findings (dpkg relations and the
  post-install invariant, the signed lock and generation, older records
  and states, reanchor rebuild / older trust / `--key`, the postinst
  migration, the deep leftover chain, the bounded pack digest, rule names
  across packages).
* `review3_13b.rs`: the third review's findings (merged-/usr path
  aliasing, protected paths, explicit dpkg refusals, `dpkg --verify` and
  file-list damage, `path-exclude` baselines, packages changed outside
  the agent, the probe session and the reaper, `rekey`, signed journal
  history, the pack digest cap).
* `crash.rs`, `kinds.rs` (deb with dpkg, rules), `binary.rs`,
  `fuzz_smoke.rs` (`deliverd_state`, `deliverd_inputs`).
