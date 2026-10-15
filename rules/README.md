# RoboDR host rules for Pulsar's rules engine

The `.toml` files in `rules/robodr/` are robot-specific detection rules for the
Pulsar `rules-engine` module. They cover host-level robot threats that Pulsar's
standard process, file and network probes can already see, so they need no
robot-specific sensor. Detections that need DDS graph context, such as an
unknown participant or an off-profile topic, live in `robodr-sensor-ros2` and
not here.

The old `rules/robot.toml` has been removed. It would not have loaded (see
[What was wrong with robot.toml](#what-was-wrong-with-robottoml)).

Everything below was checked against the vendored Pulsar at rev `4796504`
(`0.11.0-alpha.1`).

## Format and deployment (verified from source)

* **Format:** TOML, not YAML. The engine loads `<rules_path>/**/*.toml`
  recursively (`crates/modules/rules-engine/src/engine.rs:14,113`). The default
  `rules_path` is `/etc/pulsar/rules`, and Pulsar's installer puts its own rules
  there.
* **Deploy:** copy `rules/robodr/` to `/etc/pulsar/rules/robodr/`, next to
  Pulsar's rules, then restart `pulsard`. Rules are read only at module start.
* **Document:** `[[rules]]` tables. Every rule needs all six string keys:
  `name`, `type`, `category`, `severity`, `description` and `condition`
  (`engine.rs:23-30`). Pulsar silently ignores any other key.
* **`category`** must be a MITRE ATT&CK tactic in snake_case:
  `command_and_control`, `credential_access`, `defense_evasion`, `discovery`,
  `execution`, `exfiltration`, `generic`, `impact`, `initial_access`,
  `lateral_movement`, `persistence`, `privilege_escalation`, `reconnaissance`
  or `resource_development`. There is **no** `robotics` category. To let the
  AutoSecOps bridge map our threats to its `robotics` category, every rule name
  here starts with **`RoboDR: `**. The threat event carries the rule name as its
  description (`engine.rs:97-104`).
* **`severity`** must be `low`, `medium`, `high` or `critical`.
* **One bad rule disables everything.** If any rule fails to parse or compile,
  `RuleEngine::new` returns an error, so the whole rules-engine module fails,
  Pulsar's own rules included. Always run the validator before deploying.

### DSL facts that matter (from `dsl.lalrpop` and validatron)

| Topic | Behaviour |
|---|---|
| `AND` / `OR` | **Equal precedence, left-associative.** `a OR b AND c` means `(a OR b) AND c`. Always use parentheses (the validator warns). |
| `NOT` | Applies to one simple condition or one parenthesised group. |
| `IN [..]` | Expands to `f == v1 OR f == v2 ...`, so it only works on types that support `==`. It does not work on `argv`. |
| String literals | Use double quotes. Escapes are **not** processed. Digits may be unquoted. Booleans must be quoted: `"true"` / `"false"`. |
| `String` fields | `== != < > <= >=`, `STARTS_WITH`, `ENDS_WITH`, `CONTAINS` (substring). Matching is case-sensitive. There is no regex. |
| `payload.argv` (`Argv`) | **Only `CONTAINS`**, which matches **one whole argv element exactly**. It cannot match a substring of the command line. `argv[0]` is included. If argv is longer than the probe buffer, it arrives **empty**. |
| `payload.flags` (`FileFlags`) | **Only `CONTAINS`**, with one of `O_RDONLY O_WRONLY O_RDWR O_CREAT O_EXCL O_NOCTTY O_TRUNC O_APPEND O_NONBLOCK O_DIRECTORY`. The access modes are compared as an equality test on the mode, and the other flags as a bit test. |
| `*.ip` (`IpAddr`) | **Only relational operators.** There is no `STARTS_WITH`, so write a CIDR as a `>=` / `<=` range. Every IPv4 address sorts before every IPv6 address. |
| `header.image` | The process image **at the time of the event**. On an `Exec` event it is the **new** image (the same as `payload.filename`), **not the parent**. Pulsar exposes only `header.parent_pid`. |
| `Exec payload.filename` | `bprm->filename` as passed to execve when the path is absolute (it is **not** symlink-resolved: `/bin/sh` stays `/bin/sh`), or the resolved path when it is relative. This is why the rules use `ENDS_WITH "/name"`. |
| `header.container` | `Option`: use `header.container.is_some()` or `header.container?.image`. |
| Event types | `FileCreated FileDeleted DirCreated DirDeleted FileOpened FileLink FileRename ElfOpened Fork Exec Exit ChangeParent CredentialsChange Bind Listen Connect Accept Close Receive DnsQuery DnsResponse Send Custom Empty` |
| Connect payload | `destination.{ip,port}` and `is_tcp`. The module README mentions a `source` field, but the struct has none. |
| FileLink payload | `source` is the **new link** and `destination` is the **target**. For a symlink, the target is the raw string and may be relative. |

## Validation harness

```
python3 scripts/validate_rules.py --pulsar-src vendor/pulsar   # or /home/claude/robodr/vendor/pulsar
python3 scripts/validate_rules.py --self-test
```

The harness uses only the Python standard library (3.11+ for `tomllib`). It:

1. Re-implements the engine's load path: file glob, document schema,
   Category/Severity enums, and the `PayloadDiscriminant` check on `type`.
2. Re-implements the LALRPOP grammar, including its precedence traps.
3. Type-checks every `header.*` / `payload.*` path, operator and literal
   against a schema embedded in the script. Each entry carries a comment with
   the Pulsar source file and line it came from.
4. Runs `scripts/rules_fixtures.json`: 90 sample events, with at least one
   positive and one negative per rule. They are evaluated with the engine's
   matching semantics. Fixtures marked `KNOWN GAP` document misses on purpose.
5. If the Pulsar source is available, it also re-extracts `Payload`, `Header`,
   `Host`, `Category` and `UserRule` from the source and **fails on drift**. It
   then validates Pulsar's own 89 shipped rules, which upstream's
   `shipped_rules_are_valid` test proves compile in the real engine. That
   calibrates the checker.
6. Runs a self-test of 31 cases that must be rejected or accepted. This
   includes the original `robot.toml`.

The last run gave: self-test 31/31; 89/89 upstream rules accepted; no schema
drift; 31 RoboDR rules in 7 files; 90/90 fixtures pass; 0 errors and 0
warnings. Mutation checks showed the harness catches problems: flipping every
negative fixture gave 44 errors, and changing `argv: Argv` in a copy of
`event.rs` was reported as drift.

## The rules

TUNE values that must be set per robot during commissioning:

* `/opt/ros/`: the ROS 2 install prefix.
* `/opt/robot_ws/install/`: the robot's colcon workspace install prefix.
* The cell and fleet subnets.
* The commissioned RMW library.
* Service names.
* The image of the signed update agent.

Each of these is marked `TUNE` in the files.

### `ros2_stack.toml`: the control stack

| Rule | Threat (ROADMAP §0) | False positives / notes |
|---|---|---|
| Interactive shell started on robot controller | Host compromise / reverse shell (demo scenario, Sprint 4) | Operator SSH sessions that run `bash -i`. A login shell is `-bash` with no `-i`, so it is not matched. This cannot be limited to shells spawned by ROS nodes (no parent image). |
| ROS 2 process connects outside the robot's networks | C2 / datalink compromise, exfiltration of stolen keys | Only covers C++ nodes under the two prefixes. rclpy nodes run as `/usr/bin/python3.x` and are not covered. Allowlist the fleet gateway if it sits outside private space. UDP DDS traffic mostly uses `sendto`, not `connect`, so this rule mostly sees TCP plus connected UDP. |
| ROS 2 install tree written outside the package manager | Trojaned/modified node, launch or param files | Root-run rclpy nodes writing `__pycache__`. Fix this by precompiling at commissioning or running nodes unprivileged. `colcon build` on the unit is a dev-only activity. |
| File created or moved into the ROS 2 install tree… | Same, via atomic replace | Same as above. |

### `sros2_keystore.toml`: SROS 2 keystore (Sakib et al. 2025; captured unit)

| Rule | Threat | False positives / notes |
|---|---|---|
| Enclave private key read by a process outside the ROS stack | Keystore exfiltration → authenticated rogue participant | rclpy nodes (python3) and the `ros2` CLI with security enabled. Allowlisting python3 is a deliberate trade-off (see the file header). Backup tools. |
| CA private key accessed on robot | CA keys must never be on a unit | None in a correct deployment. A hit means the keystore was provisioned wrongly or is being stolen. |
| Keystore file written | Widened permissions / swapped identity | Re-provisioning during commissioning. |
| Keystore file renamed or replaced | Same, by atomic rename, or a key moved out | Same. |
| Link created to an SROS 2 private key | Reading the key via an innocuous path | Matches any `*key.pem` target, so TLS keys named like that elsewhere also match. |

### `runtime_hooking.toml`: one-env-var hook ("Seeing is Not Believing", 2026)

Pulsar's `Exec` event has **no environment variables**. Because of that,
`LD_PRELOAD`, `LD_LIBRARY_PATH` and `RMW_IMPLEMENTATION` are detected by their
effect: the loader opening the library.

| Rule | Threat | False positives / notes |
|---|---|---|
| ROS 2 process loaded a library outside allowlisted paths | LD_PRELOAD / LD_LIBRARY_PATH hook into a node | Covers every `python3` process, not only ROS ones: venvs, `pip --user` and vendor SDK directories. Add vendor SDK library directories during commissioning. |
| ROS 2 process loaded `/etc/ld.so.preload` | Persistent system-wide hook | None: the file should not exist. Expect one hit per node start while it does. |
| Unexpected RMW library loaded | `RMW_IMPLEMENTATION` pointed at a malicious RMW | Set the allowlist to the robot's RMW. Library names vary by distro: **verify them on the real install**. Tools that enumerate RMWs (for example `ros2 doctor`) may also match. |
| Shared library opened from a temporary directory | Staged hook library | PyInstaller onefile apps and self-extracting vendor installers. |
| Program executed from a temporary directory | Dropper / implant | Vendor installers and build systems. |
| Shared library written into a system library path outside dpkg | A hook planted where the allowlist trusts it | Manual `make install` and DKMS. |
| Dynamic linker search path changed | Persistent `LD_LIBRARY_PATH` | Non-dpkg installers. |
| Process memory written through `/proc` | Code injection into a running node (T1055.009). Covers part of the ptrace idea. | gdb. Pulsar's upstream rule already covers *reads* of `/proc/*/mem` at low severity. |
| Debugger or tracer started | ptrace-based key theft or patching (Pulsar has no ptrace event) | Field debugging sessions, which should not happen on a fielded unit. |

### `supply_chain.toml`: trojaned package (Sakib et al. 2025; supply chain)

| Rule | Threat | False positives / notes |
|---|---|---|
| Debian package installed on robot controller | Trojaned `.deb` | Authorised maintenance. The alert is then the audit trail. `apt` also runs `dpkg --unpack`, so one install raises two hits. Known gap: bundled flags (`-iE`) and `--install=` forms are missed (a fixture documents this). |
| Package maintainer script executed | Malicious `postinst` / `preinst` running as root | Every legitimate install or remove. Pair it with a maintenance-window record. |
| Debian package database changed | Backstop for renamed or unrecognised dpkg front-ends | Same. |
| Python package installed | Trojaned wheel / typosquat | Commissioning-time `pip install`, which should be built into the image instead. |

### `radio_provisioning.toml`: BLE / Wi-Fi provisioning (UniPwn 2025)

Pulsar does not see Bluetooth sockets or HCI. These rules watch the user-space
tools and the configuration files instead.

| Rule | Threat | False positives / notes |
|---|---|---|
| Bluetooth tooling executed | A wormed robot scanning or attacking nearby robots over BLE | A vendor provisioning service that shells out to `bluetoothctl`. Confirm this during commissioning and exclude it by `header.image`. |
| Wi-Fi configuration tooling executed | Joining an attacker AP / becoming an AP | `nmcli` called by NetworkManager dispatcher scripts. `iw` used by a link-monitoring script. |
| Wireless network configuration modified | Persisted rogue SSID/PSK | Legitimate re-provisioning. NetworkManager writes connection files itself when connections change. |

### `kernel_modules.toml`: rootkits / captured unit

| Rule | Threat | False positives / notes |
|---|---|---|
| Kernel module file written outside dpkg | Rootkit staging (also catches loaders that call `finit_module` directly and drop a `.ko`) | DKMS rebuilds after kernel updates. |
| Module autoload configuration changed | Boot persistence / blacklisting security modules | Non-dpkg driver installers. |

Pulsar's upstream `persistence/kernel_module_injection.toml` already covers
`insmod` and `modprobe` being run (high severity), so that is not duplicated
here.

### `self_protection.toml`: tampering with RoboDR / Pulsar

| Rule | Threat | False positives / notes |
|---|---|---|
| Profile or Pulsar config written / deleted / renamed (3 rules) | Widening the locked profile; deleting rules so detection is blind after restart | The signed update agent. Exclude it by `header.image` once it exists. |
| Attempt to stop the Pulsar or RoboDR service | Turning the sensor off | Planned maintenance. Unit names are placeholders, because Pulsar ships no systemd unit. |

## Commissioning: tuning per robot

1. Set the TUNE values: prefixes, subnets, RMW and service names.
2. Run the robot through its full mission profile in **observe mode** with all
   rules enabled. Record every hit.
3. For each hit, either fix the robot (precompile `.pyc`, remove tools, run
   nodes unprivileged) or add a **narrow** exclusion. A narrow exclusion means
   a `header.image` equality or prefix, never a broad directory.
4. Re-run `scripts/validate_rules.py` and update the fixtures with the new
   exclusions.
5. Lock the rule set together with the model profile, and do the 72-hour clean
   run to measure the false-positive rate (Sprint 4, E1/E2).

## What was wrong with `robot.toml`

* Every rule lacked `severity` and `description`, and every rule used
  `category = "robotics"`. Any one of these makes the **entire** rules-engine
  module fail to start, Pulsar's own rules included.
* "Controller spawns a shell": the rule used `header.image STARTS_WITH
  "/opt/ros"` on an `Exec` event. On `Exec`, `header.image` is the new shell,
  not the parent, so the rule could never match. It also compared
  `payload.filename` against `/bin/sh` exactly, which misses `/usr/bin/bash`.
  The rule was replaced by the interactive-shell rule, and the "spawned by ROS"
  part is a follow-up.
* "Outbound connection": the rule used `payload.destination.ip STARTS_WITH "10."`,
  but `IpAddr` has no `STARTS_WITH`, so it would not compile. It now uses ranges.
* "Write to ROS 2 launch or params directory": `FileCreated` fires only on new
  files, not on overwrites. The rule also did not exclude dpkg. It now uses
  `FileOpened` with write flags plus `FileRename`.
* "Reverse shell pattern": the argv use was correct (`CONTAINS` is valid on
  `Argv`), but the filename used `==` against two paths. It is folded into the
  interactive-shell rule with `ENDS_WITH`.

## Still unverified until run on a real Pulsar daemon

The harness proves that the rules **load, compile and match the intended sample
events under the engine's semantics**. It does **not** prove what the kernel
probes emit. The following need checking on the target controller, with
`pulsard` running and the real ROS distro installed:

* Exact path strings from `get_path_str` for `/proc/<pid>/mem`, `/dev/shm`,
  overlay or bind mounts, and **inside containers**. A ROS stack in Docker
  would see container-relative paths, and `header.image` would be the
  in-container path.
* That glibc's loader opens `LD_PRELOAD` libraries and `/etc/ld.so.preload` in
  a way `security_file_open` reports with the expected path. The same applies
  to `rmw_implementation`'s `dlopen` of `librmw_*.so`, and to the RMW library
  names for the robot's distro.
* That the DDS security plugin (Fast DDS / Cyclone) reads `key.pem` from the
  node process, so that `header.image` is the node binary.
* That dpkg maintainer-script exec events carry `/var/lib/dpkg/info/...` as
  `filename`, and that dpkg's `.list-new` → `.list` rename is reported as
  `FileRename`.
* Whether `security_path_mknod` → `FileCreated` fires for `.ko` files written
  by `cp` / `curl` (expected: yes, through `open(O_CREAT)`).
* Event volume. The library-load rules evaluate on every `FileOpened` event.
  Measure CPU on the controller.
* The false-positive rate on the real robot over a 72-hour clean run.

## Follow-ups that need fields or events Pulsar does not have

| Idea | Missing in Pulsar | Possible path |
|---|---|---|
| Shell or interpreter **spawned by a ROS node** | Parent image on `Exec` (only `parent_pid`). `ProcessTracker::is_descendant_of` exists but is not exposed to the DSL. | Add a `header.parent_image` / ancestry method upstream, or a RoboDR module that checks ancestry and emits a threat. |
| `LD_PRELOAD=` / `RMW_IMPLEMENTATION=` / `ROS_SECURITY_*` in the environment at exec | Exec env (`envp` is not captured by `probes.bpf.c`) | Extend the process-monitor probe to capture selected env keys. |
| ptrace attach to ROS nodes | No ptrace / `process_vm_writev` event | LSM `ptrace_access_check` hook in a new probe. |
| Kernel module load by syscall | No `init_module` / `finit_module` event | LSM `kernel_module_request` / `kernel_read_file` hook. |
| BLE / HCI activity | Network monitor is IP-only | Bluetooth socket probe, or the RoboDR network sensor. |
| Robotics category in the threat itself | `Category` enum is fixed | Use the `RoboDR: ` name prefix (current approach), or an upstream enum extension. |
| Time-boxed maintenance windows | Rules have no time or state | Suppress at the SOC/bridge, not in rules. |
| Rate limiting (for example the ld.so.preload rule on every node start) | None in the engine | Dedupe in threat-logger / bridge. |
