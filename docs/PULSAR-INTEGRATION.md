# Pulsar integration: what is verified, what is not

This page records how `robodr-sensor-ros2` (the ROS 2 / DDS discovery sensor)
and `robodr-pulsard` (the daemon binary that ships it) plug into Pulsar, and
exactly what was checked against which Pulsar source file.

- Pulsar reference: `vendor/pulsar` at commit **4796504**
  (`4796504895ce42f95ffc1e414be19a5d7f40fc0a`, `chore(github): Update PR
  template`), Pulsar version `0.11.0-alpha.1`, toolchain pin 1.98.1.
- None of the Pulsar-dependent code has been through a real `cargo build`
  yet. This environment has no crates.io access, so tokio and Pulsar's
  dependency tree cannot be fetched. Everything below marked **verified by
  reading** was checked line by line against the Pulsar source, not by a
  compiler run against real Pulsar.

## 0. Verification status (read this first)

**Verified against Pulsar commit 4796504 by reading its source and by a
stub type-check. Not yet compiled against the real Pulsar, tokio or clap.**

| What | How | Result |
|---|---|---|
| Every Pulsar item used by `robodr-sensor-ros2` and `robodr-pulsard` | read in `vendor/pulsar` (files listed in §2 and §3) | signatures match; 2 lifecycle mismatches found and fixed (§2a) |
| Both crates' Rust code | `cargo check` + `cargo clippy --all-targets -D warnings` + `cargo doc -D warnings` against hand-written stubs (§6) | clean |
| Cargo manifests (dependency names, Pulsar feature names, versions) | read against `vendor/pulsar/Cargo.toml`. The stub `pulsar` crate declares the same feature names, so a typo would fail resolution | match |
| Real build, link, eBPF probes, runtime | not possible here | **open**, see the checklist in §7 |

The stubs can only catch mistakes in *our* code relative to the signatures
copied into them. If a stub is wrong, the check is wrong in the same way. The
first real build (§7) is what settles it.

## 1. Crates and their Pulsar dependency

| Crate | Needs Pulsar? | Built offline here? |
|---|---|---|
| `robodr-sensor-ros2` | yes (`pulsar-core`, `tokio`) | no. The offline script drops it |
| `robodr-pulsard` (new binary) | yes (`pulsar`, i.e. the whole daemon) | no. The offline script drops it |
| `robodr-ros2-pipeline` (new) | no | yes, with its tests and the `robodr-ros2-watch` binary |
| `robodr-events`, `robodr-rtps`, `robodr-capture`, ... | no | yes |

Everything in the sensor that does not need Pulsar or tokio now lives in the
pure crate `robodr-ros2-pipeline`. Its only dependencies are std,
robodr-events, robodr-rtps, robodr-capture and serde:

| `robodr-ros2-pipeline` module | Purpose |
|---|---|
| `pipeline` | datagram → detailed RTPS parse with one long-lived bounded `FragmentReassembler` → profile deviations + removal / anomaly / fragmentation findings → bounded dedup → sanitised `Finding`s stamped enforce/observe; `load_profile`, `ProfileStatus` (profile validated at load, invalid = refused for enforcement) |
| `config` | `[module.robodr-sensor-ros2]` and its `capture` sub-table, domain-id → SPDP port, capture `RtpsPortMap`, default interfaces, validation |
| `socket` | receive-only SPDP socket with `SO_REUSEADDR`, bound to the group. Uses `socket`/`setsockopt`/`bind` from libc, which std already links |
| `source` | `Datagram` / `DatagramSource` seam (std-only, blocking) and `CaptureDatagramSource` over `robodr_capture::rtps_datagrams`, for live `AF_PACKET` and pcap/pcapng |
| `sanitize`, `dedup`, `watch` | text sanitising, bounded dedup set, the `robodr-ros2-watch` lab tool |

`robodr-sensor-ros2/src/lib.rs` is now glue only: the `SimplePulsarModule`
impl, the tokio listener task over the SPDP socket, the capture channel and
an optional external channel, the capture thread, and `send_threat`.

## 2. Pulsar API items, checked one by one

| Item used | Pulsar file (at 4796504) | Finding |
|---|---|---|
| `SimplePulsarModule` | `crates/pulsar-core/src/pdk/module.rs` | Trait is `Send + Sync`; associated types `Config: DeserializeOwned + Clone + Send + Sync + 'static`, `State: Send + 'static`; associated consts `MODULE_NAME: &'static str`, `DEFAULT_ENABLED: bool`; methods return `impl Future<Output = ...> + Send`. An `async fn` in the impl satisfies that, as in Pulsar's own modules and examples, and the compiler checks the `Send` bound. `on_event` and `graceful_stop` have defaults. Not overriding `on_event` makes the default call `ctx.stop_event_recv()`, so the module stops receiving bus events (`src/pulsard/module_manager.rs`, `run_module_loop`). That is what we want. |
| Config bound | `pdk/module.rs`, `pdk/config.rs`, `src/pulsard/config.rs` | Config is **serde `Deserialize`** (via `ModuleConfig::parse` with `serde_ignored`), **not** `TryFrom<&ModuleConfig>`. Unknown keys are warned about, not rejected. The section is **`[module.<MODULE_NAME>]`**. `enabled` is consumed by Pulsar's `ModuleSection` and overrides `DEFAULT_ENABLED`. **Fixed:** `config/robodr.toml.example` used `[robodr-sensor-ros2]`, which Pulsar would ignore. |
| Config of disabled modules | `src/pulsard/daemon.rs` `add_module` | Pulsar parses the config even for disabled modules. If parsing fails, startup aborts only when the module is enabled; otherwise the error is kept until someone starts it. **Fixed:** `profile_path` was a required field. Every field now has a default, so a missing section parses cleanly. |
| `ModuleContext::send_threat` | `pdk/module_context.rs` | `fn send_threat(&self, process: Pid, timestamp: Timestamp, description: String, extra: Option<Value>)`. It is sync and spawns a task, so it needs a tokio runtime, which the listener task has. It sends `Payload::Empty` with `header.threat = Some(Threat { source: module_name, description, extra })`. **Matches.** |
| `ModuleContext::raise_warning` | `pdk/module_context.rs`, `module_manager.rs` | `async fn raise_warning(&self, String)`. The warning is appended to `ModuleStatus::Running(warnings)`, which `pulsar status` shows. The signal channel has capacity 8. Pulsar's `threat-logger` also calls it from `init_state`. We use it once at start for an observe-only or refused profile, and when the capture source ends while another source remains. When every source is gone we use `raise_error` instead (§2a). |
| `ModuleContext: Clone` | `pdk/module_context.rs` | `#[derive(Clone)]`. We clone it into the listener task. |
| `event::Value` | `crates/pulsar-core/src/event.rs` | `pub struct Value(toml::Value)`. `Value::try_from<T: Serialize>(value: T) -> Result<Value, String>` is an **inherent** associated fn: it serialises through TOML. It is not `std::convert::TryFrom`, and an inherent fn takes precedence over the trait in `Value::try_from(..)`. Pulsar's own test calls `Value::try_from(&native)` the same way. Because the value goes through TOML, `extra` must be a TOML table. `ThreatExtra` is a flat struct of strings, a bool and two unit enums (`Severity` and `Mode`, which serialise to lowercase strings), so it stays a valid table. **Matches.** |
| `Pid` | `pulsar-core/src/lib.rs` → `bpf-common/src/lib.rs` | `pub use nix::unistd::Pid`. The old `Pid::this()` exists in nix, but we use `Pid::from_raw(std::process::id() as i32)`, the form Pulsar itself uses. |
| `Timestamp::now()` | `bpf-common/src/time.rs` | Exists. It reads `CLOCK_MONOTONIC` nanoseconds, the same base Pulsar's header conversion expects. |
| `ModuleError` | `pdk/module.rs` | `Box<dyn Error + Send + Sync + 'static>`. `From<String>` and `From<&str>` come from std, so `?` on `Result<_, String>` works. |
| Process attribution | `pdk/module_context.rs` `send_internal`, `pdk/process_tracker.rs`, `bpf-filtering/src/initializer.rs` | `send_threat` looks the pid up in the process tracker. A network peer has no local pid, so we attribute threats to the daemon's own pid. `process-monitor` seeds the tracker from `/proc` at startup, so the lookup should succeed. If it fails, Pulsar logs `Process not found in tracker` after about 100 ms and **still sends** the threat, with an empty image. |
| Lifecycle | `src/pulsard/module_manager.rs` | `init_state` runs inside a `select!` against a stop command. We spawn the listener only at the end of `init_state`, with no `.await` after the capture thread starts, so a cancelled init leaks nothing. On restart, `init_state` runs again with `&self`. **Fixed:** teardown now lives in `Drop for State`. See §2a. |
| `ModuleContext::raise_error` | `pdk/module_context.rs`, `module_manager.rs` `handle_module_error` | `fn raise_error(&self, ModuleError)`. It is sync (`try_send`). When the module is `Running`, the manager sends the shutdown signal, so `graceful_stop` runs, and the status becomes `Failed(err)`. **Changed:** used when every datagram source is gone. See §2a. |
| Warnings raised during `init_state` | `module_manager.rs` `handle_cmd` / `run_module_manager_actor` | The actor drains the signal channel only after `handle_cmd` returns. By then the status is `Running`, so a warning raised in `init_state` is buffered (capacity 8) and kept. We raise at most one there, so it cannot block. |
| Who consumes our threats | `crates/modules/rules-engine/src/engine.rs` `process`, `crates/modules/threat-logger/src/lib.rs` | The rules engine **skips every event that already carries a threat** (`if event.header().threat.is_none()`), to avoid loops. So RoboDR threats are **not** re-evaluated by Pulsar rules. They reach `threat-logger` (stdout/syslog), the desktop and SMTP notifiers when built, and engine-api subscribers. The earlier text of this page said "threat-logger and the rules engine", which was wrong. |
| `Pid` | `bpf-common/src/lib.rs` | It is nix 0.31's `Pid`. `const fn from_raw(pid_t)` exists. |

### 2a. Mismatches found by this review and fixed

1. **The listener and capture thread outlived the module when Pulsar
   skipped `graceful_stop`.** `run_module_loop` calls
   `T::graceful_stop(state)` only on the shutdown signal. In two cases the
   state is just dropped:
   - the stop command's 5 s timeout fires and the module task is
     `abort()`ed;
   - the loop returns an error.

   Our `State` held a tokio `JoinHandle`, and dropping a `JoinHandle`
   **detaches** the task rather than cancelling it. The listener would then
   keep sending threats from a module Pulsar reports as stopped or failed.
   On restart, a second listener would run next to the first. An external
   source's receiver lock would also stay held for good, so the new
   listener would block on it.

   **Fix:** `impl Drop for State` sets the capture stop flag and aborts
   the listener. `graceful_stop` now only drops the state.
2. **A blind sensor reported itself as healthy.** When every datagram
   source had ended, the listener called `raise_warning` and returned. The
   module stayed in `Running` with a warning that is easy to miss.

   **Fix:** it now calls `raise_error`. Pulsar stops the module, which runs
   `graceful_stop`, and `pulsar status` shows `Failed("no datagram source
   left; ...")`.
   - Consequence: in a lab, a `pcap_replay` run with `listen_spdp = false`
     now ends with the module in `Failed` once the file is consumed. That is
     expected.
   - When only the capture source ends and SPDP is still listening, the
     module still raises a warning and keeps running.

Re-verified, no change needed:
- the `SimplePulsarModule` / `PulsarModule` blanket impl and its `Send`
  future bounds;
- the `send_threat` and `raise_warning` signatures;
- `Value::try_from`, an inherent fn that still wins over the `TryFrom`
  that the `impl<T: Into<toml::Value>> From<T> for Value` blanket implies.
  The stub includes that blanket, so this was compiler-checked;
- config extraction (`ModuleSection` with flatten, then
  `ModuleConfig::parse`);
- `add_module`;
- `pulsar_daemon_run`;
- the feature names;
- the clap derives in `robodr-pulsard`.

## 3. Registration into the daemon (`robodr-pulsard`)

Verified by reading `src/pulsard.rs`, `src/bin/pulsard.rs`,
`src/pulsard/daemon.rs` and `examples/pulsar-extension-module/`:

- `pulsar::pulsard::pulsar_daemon_run(&PulsarDaemonOpts, customize_starter)`
  registers the Pulsar modules enabled by the `pulsar` crate's cargo features
  (`#[cfg(feature = "...")] starter.add_module(...)`). It then calls
  `customize_starter(&mut PulsarDaemonStarter)` before starting the daemon.
- `PulsarDaemonStarter::add_module<T: PulsarModule + 'static>(&mut self, T)
  -> anyhow::Result<()>`. A blanket impl makes every `SimplePulsarModule` a
  `PulsarModule`. Registering the same name twice is an error.
- `crates/robodr-pulsard/src/main.rs` mirrors upstream `src/bin/pulsard.rs`:
  clap `Opts` that flattens `PulsarDaemonOpts` (`--config-file`) and
  `Verbosity<InfoLevel>`, then `pulsar::init_logger`, then
  `pulsar_daemon_run(.., |starter| starter.add_module(Ros2Sensor::new()))`,
  and `pulsar::utils::report_error` with `exit(1)` on error. The only
  difference is the version string. Upstream's `clap_version` helper is
  private to its binaries, so we print our version plus
  `pulsar::metadata::{VERSION, GIT_SHA}`.
- Features (`crates/robodr-pulsard/Cargo.toml`):
  - The default is `pulsar/core` (process, network and file-system monitors
    plus the threat logger) and `pulsar/rules-engine`.
  - Upstream's default (`full` + `tls-openssl`) also adds the desktop and
    SMTP notifiers and an openssl system dependency. An air-gapped robot
    needs neither, so they sit behind the opt-in `pulsar-full` feature.
  - `sqlite3-vendored` bundles SQLite (bpf-common uses rusqlite).
- Root `Cargo.toml` changes (the one allowed root edit):
  - added member `crates/robodr-pulsard`;
  - added workspace dep `pulsar = { path = "vendor/pulsar", default-features = false }`;
  - added workspace dep `robodr-sensor-ros2 = { path = "crates/robodr-sensor-ros2" }`;
  - marked the Pulsar-dependent members with comments.

Enable the sensor in `/etc/pulsar/pulsar.toml`. See
`config/robodr.toml.example` for the full section:

```toml
[module.robodr-sensor-ros2]
enabled = true
profile_path = "/etc/robodr/profile.json"
domain_id = 0

[module.robodr-sensor-ros2.capture]
enabled = true            # passive capture, needs CAP_NET_RAW
# interfaces = ["lo", "eth0"]   default: ["lo", <default-route interface>]
# domain_ids = [0]              default: [domain_id]
# pcap_replay = "/lab/x.pcapng" lab only: replay instead of live
```

How the nested table reaches the module was checked by reading the code.
`src/pulsard/config.rs` `ModuleSection` takes `enabled` and keeps the rest
as a `#[serde(flatten)] toml::Table`. `pdk/config.rs` `ModuleConfig::parse`
then deserialises the whole table with `serde_ignored`. So
`[module.robodr-sensor-ros2.capture]` arrives as the `capture` field. Its
`enabled` key is a field of `CaptureConfig`; it is not Pulsar's
module-level `enabled`.

`robodr-pulsard` needs no change to register the capture source. The sensor
opens it from its own config section in `init_state`.

## 4. Sensor behaviour that was changed or added

- **Port from the domain id.** The SPDP port is `7400 + 250 * domain_id`
  (DDSI-RTPS 2.2 §9.6.1.1, `PB=7400, DG=250, d0=0`).
  - `domain_id` must be in `0..=232`, the largest value whose port fits in
    16 bits.
  - Values in 102..=214 are accepted with a warning: ROS 2 recommends
    0..=101 and 215..=232.
  - `spdp_port` can override the derived port, with a warning.
- **Validation.** `robodr_ros2_pipeline::config` rejects:
  - a non-absolute or empty `profile_path`;
  - a non-multicast `spdp_group`;
  - a multicast or broadcast `interface`;
  - `spdp_port = 0`;
  - `dedup_capacity` outside `1..=1048576`;
  - when capture is enabled:
    - `capture.domain_ids` entries outside `0..=232`;
    - invalid interface names (empty, longer than 15 bytes, `/`, `:`,
      whitespace or control characters);
    - `read_timeout_ms` outside 10..=5000;
    - `queue_capacity` outside 1..=65536;
    - a relative `pcap_replay`.

  It warns on:
  - `pcap_replay`, which replaces live capture;
  - no default route, in which case capture uses `lo` only (common on
    air-gapped robots, so list the interfaces);
  - `interfaces = []`, which means all interfaces;
  - `domain_ids` that omit `domain_id`.

  No SPDP socket, no capture and no external source is rejected in
  `init_state`.
- **Observe mode, enforce mode and refused profiles.** The profile is
  checked with `Profile::validate` when it is loaded:

  | Profile | `extra.profile_status` | Threats |
  |---|---|---|
  | valid, `locked = true` | `enforcing` | `extra.mode = "enforce"`, `observe_only = false` |
  | valid, `locked = false` | `observing` | `mode = "observe"`, `observe_only = true`, description starts with `[observe-only] `, module warning raised |
  | fails validation | `refused` | as observing, plus: every error logged, one module warning, one `robot.ros2.profile_refused` (High, observe-only) threat |

  **Decision (fail closed): a refused profile is never enforced, and the
  sensor keeps running observe-only.**
  - It is not enforced because a broken profile is a configuration fault.
    Escalating it into a safe-state request would let anyone who can corrupt
    the profile file stop the robot.
  - It keeps running because refusing to start would blind the sensor.
  - An unreadable or unparseable profile file is still a start-up error.

  The full `extra` table:
  - `rule`
  - `severity`
  - `detail`
  - `mode` (`"enforce"`/`"observe"`, as `robodr_events::Mode`). It was
    `"locked"`/`"observe"` before this change.
  - `observe_only`
  - `src_ip`
  - `profile_model`
  - `profile_status` (new)

  All are scalars. No new Pulsar event type was added.
- **New findings from the detailed parse** (`parse_datagram_detailed` via
  one long-lived `FragmentReassembler`):

  | Rule | Severity | Raised when |
  |---|---|---|
  | `robot.ros2.participant_removed` | Medium | a profiled participant is announced as disposed or unregistered |
  | `robot.rtps.malformed_discovery` | Low | parse anomalies (`report_anomalies`) |
  | `robot.rtps.fragmented_discovery` | Low | `DATA_FRAG` discovery is seen (`report_fragmentation`) |
  | `robot.rtps.discovery_fragment_rejected` | Medium | fragments are refused by the reassembler (always reported) |

  Fragmented SEDP is now reassembled and evaluated. Before, it was missed.
- **Dedup.**
  - It is bounded at `dedup_capacity` entries, evicting the oldest first.
  - It stores a per-process-keyed 64-bit hash (`RandomState`) instead of the
    key, so memory does not grow with attacker-chosen topic-name length.
  - The previous version cleared the whole set when it was full and stored
    the full strings, up to about 64 KiB each.
- **Sanitising.** Attacker-controlled text (topic and type names in the
  detail) has control characters escaped and is capped at 512 chars. A topic
  name cannot inject newlines or terminal escape codes into the threat
  logger, syslog or the terminal.
- **Socket coexistence.** The previous code bound `0.0.0.0:7400` without
  `SO_REUSEADDR`, which caused two problems:
  - On Linux that either fails, if ROS started first, or makes the robot's
    own DDS participants **fail to bind**, if the sensor started first.
  - Bound to `0.0.0.0`, it could also be handed unicast datagrams meant for a
    DDS participant.

  `robodr_ros2_pipeline::socket` sets `SO_REUSEADDR` before `bind`, which `std` and tokio cannot
  do. It deliberately does not set `SO_REUSEPORT`, which load-balances
  unicast between sockets. It binds to the **group address**, so only
  datagrams sent to the group reach the sensor. The socket never transmits.

## 5. Datagram sources: SPDP socket, passive capture, external

- **SPDP socket** (`listen_spdp`): bound in `init_state`, then registered
  with tokio through `UdpSocket::from_std`.
- **Passive capture** (`capture.enabled`):
  - `init_state` calls `CaptureSettings::open(stop_flag)`. That returns a
    `CaptureDatagramSource` over `AfPacketSource` (live), or over
    `CaptureFile` when `capture.pcap_replay` is set.
  - `spawn_blocking_source` runs it on an OS thread and feeds a bounded
    tokio channel of `capture.queue_capacity`.
  - If the capture cannot be opened, for example without `CAP_NET_RAW`,
    **module start fails**. An operator who enabled capture must not get a
    silent blind spot.
  - Dropping the module `State` sets the stop flag, so the thread exits
    within one `read_timeout_ms`, and aborts the listener, which drops the
    channel. This happens on `graceful_stop` and also when Pulsar drops the
    state without calling it (§2a).
  - When the capture source ends (end of a replay file, socket error), a
    module warning is raised and the SPDP socket keeps running.
- **External source:** `Ros2Sensor::with_external_source(rx)` plus
  `spawn_blocking_source(any DatagramSource, n)` is still available for
  sources that are not configured. The receiver sits behind
  `Arc<tokio::sync::Mutex<..>>`, so it survives a module stop and start.
- `DatagramSource` contract (std-only, blocking):
  - `Ok(Some)` is a datagram;
  - `Ok(None)` means finished or stopped;
  - `Err` is terminal;
  - transient conditions (read timeouts, frame budget) are absorbed inside
    the source.
- All sources feed **one** `Pipeline`, so dedup and `DATA_FRAG` reassembly
  span the sources.
- Without SPDP, capture or an external source, `init_state` fails ("would
  see nothing").

## 6. How the parts that could be checked here were checked

- **`robodr-ros2-pipeline`** is a real workspace member. It is built and
  tested by `tools/offline-cargo.sh` with 73 tests, and is clean under
  clippy `-D warnings` and `cargo fmt --check`. The tests cover:
  - end to end: pcap → `CaptureDatagramSource` → `Pipeline`. The scenario
    is a legit participant and writers plus a rogue participant on
    `rt/cmd_vel`;
  - exact deviations;
  - dedup;
  - observe-only results;
  - a refused profile;
  - `DATA_FRAG` and IP-fragment reassembly;
  - rejected fragments;
  - the `robodr-rtps` synthetic fixtures;
  - the `robodr-ros2-watch` binary, run through `std::process::Command`;
  - `config/robodr.toml.example` against `Config`;
  - live `AF_PACKET` capture on `lo`. This test ran as root here; without
    `CAP_NET_RAW` it is skipped.

  The socket tests ran real `SO_REUSEADDR` binds and a multicast join on
  this Linux host.
- **`robodr-sensor-ros2/src/lib.rs` and `robodr-pulsard/src/main.rs`** were
  type-checked unchanged, from their real `Cargo.toml`s:
  - `cargo check`;
  - `cargo clippy --all-targets -- -D warnings`;
  - `cargo doc -D warnings` (sensor).

  The check ran in a scratch workspace outside the repo whose `pulsar-core`,
  `pulsar`, `tokio`, `log`, `anyhow`, `clap` and `clap-verbosity-flag` are
  hand-written stubs. They are wired in through workspace deps and
  `[patch.crates-io]`. The stubs mirror the real items as follows:
  - **pulsar-core** (edition 2024, like the real crate):
    - `PulsarModule`, `SimplePulsarModule` and the blanket impl are copied
      **verbatim** from `pdk/module.rs`, including the default `on_event`
      that calls `ctx.stop_event_recv()`;
    - `ModuleContext` (`Clone`, `Send + Sync`, `send_threat`,
      `raise_warning`, `raise_error`);
    - `event::Value` with the inherent `try_from` **and** the
      `From<T: Into<toml::Value>>` blanket;
    - nix-style `Pid` and `Timestamp::now`.
  - **pulsar**:
    - `pulsard::{PulsarDaemonOpts (clap::Args), PulsarDaemonStarter::add_module<T: PulsarModule + 'static>, pulsar_daemon_run}`.
      `add_module` also asserts `T: Send + 'static`, because the real
      manager moves the module into a spawned actor;
    - `init_logger`, `utils::report_error`, `metadata::{VERSION, GIT_SHA}`;
    - every cargo feature name of `vendor/pulsar/Cargo.toml`.
  - **tokio**:
    - `mpsc`, `Mutex::lock_owned` / `OwnedMutexGuard`, `UdpSocket`, and
      `spawn` with its `Send + 'static` bounds;
    - `JoinHandle::abort`, `time::sleep` and `#[tokio::main]`;
    - auto traits match the real ones: channel ends and `Mutex` are
      `Send`/`Sync` only when `T: Send`;
    - a `select!` stand-in that keeps all branch futures alive at once and
      drops them before the handler runs, as the real macro does.
  - **clap**: the `Parser`/`Args` derives check that every
    `#[command(flatten)]` field implements `clap::Args` and that
    `version = ..` is a `&'static str`.

  Negative controls confirmed that the stubs bite:
  - an `Rc` held across an await in the listener fails with "future cannot
    be sent between threads safely";
  - a non-`Args` flatten field fails.

  This catches signature, borrow, `Send` and path mistakes in our code. It
  cannot catch differences between the stubs and the real crates.

## 7. Still unverified until a real build (Linux box with crates.io)

1. A real `cargo build -p robodr-sensor-ros2 -p robodr-pulsard`. The
   sensor crate has no tests of its own any more; its logic is tested in
   `robodr-ros2-pipeline`.
2. Cargo resolution of path deps into the **separate** `vendor/pulsar`
   workspace:
   - The `workspace = true` keys in Pulsar's crates should resolve against
     `vendor/pulsar/Cargo.toml`, and `exclude = ["vendor"]` keeps it out of
     our workspace.
   - Our `Cargo.lock` is used, **not** `vendor/pulsar/Cargo.lock`, so
     third-party versions may differ from the ones Pulsar CI tested.
     Consider seeding our lock from Pulsar's.
   - Expect a harmless "profiles for the non root package will be ignored"
     warning.
3. That the `pulsar` crate compiles with only `core` + `rules-engine`. The
   `cfg(feature)` gating in `src/pulsard.rs` looks complete, but no build has
   confirmed it.
4. TOML serialisation of `ThreatExtra` through `Value::try_from`. The enum
   `Severity` should become the string `"high"` and so on. It was only tested
   via serde_json here.
5. `pulsar::metadata::GIT_SHA` needs `VERGEN_GIT_SHA` from Pulsar's
   `build.rs` (vergen-gitcl, which runs `git`). A build from a tarball
   without `.git` may produce a placeholder SHA or fail.
6. Runtime behaviour on a robot:
   - the multicast join on the real interface;
   - coexistence with each DDS vendor's reuse options (Fast DDS, Cyclone
     DDS, Connext). This is a per-vendor lab item; if a vendor binds with
     `SO_REUSEPORT` only, our bind fails, which is the safe direction;
   - the process-tracker lookup for the daemon's pid.
7. End-to-end: a threat from this module shows up in `threat-logger` with
   `extra` intact. The rules engine does not see it by design (§2).
8. Capture inside the daemon:
   - `AF_PACKET` opening under `robodr-pulsard`'s privileges;
   - capture-thread shutdown on module stop and restart, including the
     forced-abort path that `Drop for State` now covers (§2a);
   - behaviour under load (kernel drops are reported by
     `AfPacketSource::kernel_stats`, but the sensor does not surface them
     yet);
   - real DDS traffic, including per-vendor `DATA_FRAG` usage, e.g. Fast DDS
     type information. Until the lab has run it, the Low
     `robot.rtps.fragmented_discovery` finding may fire for every
     participant host.

9. Toolchain and MSRV. `robodr-sensor-ros2` and `robodr-pulsard` inherit
   `rust-version = "1.85"` from the workspace, but their dependency tree
   (Pulsar is edition 2024 and pins 1.98.1; tokio, toml and others) is only
   known to build on Pulsar's 1.98.1. CI's `msrv` job checks only the pure
   crates, so nothing is wrong today. Do not read 1.85 as a promise for
   these two crates.
10. Version floors. The root `Cargo.toml` asks for `tokio = "1"`,
    `log = "0.4"` and `anyhow = "1"`. Pulsar asks for tokio `1.53.1`,
    log `0.4.34` and anyhow `1.0.104`. Cargo unifies to one version that
    satisfies both, so this is fine. Only a `-Z minimal-versions` build
    would differ.

### 7a. First real build: checklist

Run this on a Linux x86_64 host with crates.io (or the internal mirror),
clang, llvm-strip and the 1.98.1 toolchain. Record the outcome of each step
in this file.

1. `git submodule update --init --recursive` and check that
   `git -C vendor/pulsar rev-parse HEAD` is
   `4796504895ce42f95ffc1e414be19a5d7f40fc0a`. If it differs, re-read the
   files in §2 and §3 before going on.
2. `cargo metadata --format-version 1 >/dev/null`. This confirms the path
   deps into the separate Pulsar workspace resolve: `workspace = true`
   inheritance, `exclude = ["vendor"]`, and the feature names `core`,
   `rules-engine`, `full`, `tls-openssl` and `sqlite3-vendored`.
3. `cargo tree -p robodr-pulsard -d`. Confirm there is a single `tokio`,
   `clap` and `pulsar-core` in the graph. Two copies of `pulsar-core`
   would mean `Ros2Sensor` implements a different `PulsarModule` than the
   one `add_module` wants.
4. `cargo build -p robodr-sensor-ros2` first: the glue only, no eBPF.
   Expected compiler-visible risk points:
   - the `async fn` impls against the `impl Future + Send` trait
     signatures;
   - `tokio::select!` over three `Option` sources;
   - `Value::try_from(finding.extra())`.
5. `cargo clippy -p robodr-sensor-ros2 -p robodr-pulsard --all-targets -- -D warnings`.
6. `cargo build -p robodr-pulsard` (default features: `pulsar/core` and
   `pulsar/rules-engine`). This compiles the eBPF probes; it needs clang and
   llvm-strip, and also needs `libsqlite3-dev`, or `--features
   sqlite3-vendored`. Then build again with `--features pulsar-full` to
   check the upstream module set.
7. `./target/debug/robodr-pulsard --version` must print the RoboDR version
   and `pulsar: 0.11.0-alpha.1 (commit 4796504...)`. A placeholder SHA
   means vergen found no `.git` (item 5 above).
8. TOML round trip of `extra`, before any robot work. In a scratch test
   that depends on `pulsar-core`, run
   `Value::try_from(ThreatExtra { .. })` and then format it with `Display`. Expect a
   one-line table like `{ rule = "...", severity = "high", mode =
   "enforce", observe_only = false, ... }`.
9. Smoke test as root, with a test profile and `[module.robodr-sensor-ros2]
   enabled = true`:
   - `pulsar status` lists `robodr-sensor-ros2` as `Running`, with one
     warning if the profile is unlocked;
   - a pcap replay (`capture.pcap_replay`, `listen_spdp = false`) of the
     rogue-`cmd_vel` fixture yields `threat-logger` lines from source
     `robodr-sensor-ros2`;
   - after the file ends, the module shows `Failed("no datagram source
     left; ...")` (§2a);
   - with no process-monitor running, a `Process not found in tracker` log
     line is expected and the threat is still sent.
10. Stop and restart: `pulsar stop robodr-sensor-ros2`, then
    `pulsar start robodr-sensor-ros2` (the `pulsar` CLI subcommands, from
    `src/pulsar.rs`). Check, for example with `ps -T`, that no `robodr-dgram-src`
    thread is left from the first run, and that a single listener is running
    (no duplicate threats).
11. Only after the steps above, go on to the runtime items in point 6 of
    the list above (multicast join on the real interface, coexistence with
    each DDS vendor, tracker lookup) and point 8 (capture under load) on the
    robot.

## 8. Build prerequisites

- Linux on x86_64, aarch64 or riscv64. These are the only arches Pulsar's
  `bpf-builder` and our SPDP socket (`robodr_ros2_pipeline::socket`) support. Live capture also supports x86 and arm.
- Rust **≥ 1.98.1**:
  - `vendor/pulsar/rust-toolchain.toml` pins 1.98.1, and the Pulsar crates
    are edition 2024.
  - That file only applies inside `vendor/pulsar`. Pin the same toolchain
    at the repo root, or install it explicitly.
- Network access to crates.io, or a vendored mirror (`cargo vendor`) for the
  air-gapped build farm.
- `git submodule update --init --recursive`, so `vendor/pulsar` is populated
  (it is empty in a plain worktree), plus `git` itself for vergen.
- `clang` and `llvm-strip` on `PATH` to compile Pulsar's eBPF probes
  (`crates/bpf-builder`). `CLANG` can point to a specific clang.
- SQLite development library, or build with `--features sqlite3-vendored`.
- openssl development library only with `--features pulsar-full`.
- Runtime:
  - root;
  - kernel ≥ 5.5 with BPF and BTF (see `vendor/pulsar/README.md`);
  - bpffs, which `pulsar_daemon_run` mounts if missing.
