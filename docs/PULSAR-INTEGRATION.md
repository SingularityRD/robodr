# Pulsar integration: what is verified, what is not

This page records how `robodr-sensor-ros2` (the ROS 2 / DDS discovery sensor)
and `robodr-pulsard` (the daemon binary that ships it) plug into Pulsar, and
exactly what was checked against which Pulsar source file.

- Pulsar reference: `vendor/pulsar` at commit **4796504**
  (`chore(github): Update PR template`), Pulsar version `0.11.0-alpha.1`.
- None of the Pulsar-dependent code has been through a real `cargo build`
  yet. This environment has no crates.io access, so tokio and Pulsar's
  dependency tree cannot be fetched. Everything below marked **verified by
  reading** was checked line by line against the Pulsar source, not by a
  compiler run against real Pulsar.

## 1. Crates and their Pulsar dependency

| Crate | Needs Pulsar? | Built offline here? |
|---|---|---|
| `robodr-sensor-ros2` | yes (`pulsar-core`, `tokio`) | no. The offline script drops it |
| `robodr-pulsard` (new binary) | yes (`pulsar`, i.e. the whole daemon) | no. The offline script drops it |
| `robodr-events`, `robodr-rtps`, ... | no | yes |

Inside `robodr-sensor-ros2`, the logic is split so that most of it needs
neither Pulsar nor tokio:

| File | Depends on | Purpose |
|---|---|---|
| `src/pipeline.rs` | std, robodr-events, robodr-rtps, serde | datagram → RTPS events → profile deviations → bounded dedup → sanitised `Finding`s; observe-mode tagging; `Datagram` / `DatagramSource` seam |
| `src/config.rs` | std, serde | `[module.robodr-sensor-ros2]` config, domain-id → port, validation |
| `src/socket.rs` | std (+ `socket`/`setsockopt`/`bind` from libc, which std already links) | receive-only SPDP socket with `SO_REUSEADDR`, bound to the group |
| `src/lib.rs` | pulsar-core, tokio | glue only: `SimplePulsarModule` impl, listener task, `send_threat` |

## 2. Pulsar API items, checked one by one

| Item used | Pulsar file (at 4796504) | Finding |
|---|---|---|
| `SimplePulsarModule` | `crates/pulsar-core/src/pdk/module.rs` | Trait is `Send + Sync`; associated types `Config: DeserializeOwned + Clone + Send + Sync + 'static`, `State: Send + 'static`; associated consts `MODULE_NAME: &'static str`, `DEFAULT_ENABLED: bool`; methods return `impl Future<Output = ...> + Send`. An `async fn` in the impl satisfies that, as in Pulsar's own modules and examples, and the compiler checks the `Send` bound. `on_event` and `graceful_stop` have defaults. Not overriding `on_event` makes the default call `ctx.stop_event_recv()`, so the module stops receiving bus events (`src/pulsard/module_manager.rs`, `run_module_loop`). That is what we want. |
| Config bound | `pdk/module.rs`, `pdk/config.rs`, `src/pulsard/config.rs` | Config is **serde `Deserialize`** (via `ModuleConfig::parse` with `serde_ignored`), **not** `TryFrom<&ModuleConfig>`. Unknown keys are warned about, not rejected. The section is **`[module.<MODULE_NAME>]`**. `enabled` is consumed by Pulsar's `ModuleSection` and overrides `DEFAULT_ENABLED`. **Fixed:** `config/robodr.toml.example` used `[robodr-sensor-ros2]`, which Pulsar would ignore. |
| Config of disabled modules | `src/pulsard/daemon.rs` `add_module` | Pulsar parses the config even for disabled modules. If parsing fails, startup aborts only when the module is enabled; otherwise the error is kept until someone starts it. **Fixed:** `profile_path` was a required field. Every field now has a default, so a missing section parses cleanly. |
| `ModuleContext::send_threat` | `pdk/module_context.rs` | `fn send_threat(&self, process: Pid, timestamp: Timestamp, description: String, extra: Option<Value>)`. It is sync and spawns a task, so it needs a tokio runtime, which the listener task has. It sends `Payload::Empty` with `header.threat = Some(Threat { source: module_name, description, extra })`. **Matches.** |
| `ModuleContext::raise_warning` | `pdk/module_context.rs`, `module_manager.rs` | `async fn raise_warning(&self, String)`. The warning is appended to `ModuleStatus::Running(warnings)`, which `pulsar status` shows. The signal channel has capacity 8. Pulsar's `threat-logger` also calls it from `init_state`. We use it once for observe mode and once if every datagram source is gone. |
| `ModuleContext: Clone` | `pdk/module_context.rs` | `#[derive(Clone)]`. We clone it into the listener task. |
| `event::Value` | `crates/pulsar-core/src/event.rs` | `pub struct Value(toml::Value)`. `Value::try_from<T: Serialize>(value: T) -> Result<Value, String>` is an **inherent** associated fn: it serialises through TOML. It is not `std::convert::TryFrom`, and an inherent fn takes precedence over the trait in `Value::try_from(..)`. Pulsar's own test calls `Value::try_from(&native)` the same way. Because the value goes through TOML, `extra` must be a TOML table. `ThreatExtra` is a flat struct of strings, a bool and a unit enum (`Severity`, which serialises to a lowercase string), so it stays a valid table. **Matches.** |
| `Pid` | `pulsar-core/src/lib.rs` → `bpf-common/src/lib.rs` | `pub use nix::unistd::Pid`. The old `Pid::this()` exists in nix, but we use `Pid::from_raw(std::process::id() as i32)`, the form Pulsar itself uses. |
| `Timestamp::now()` | `bpf-common/src/time.rs` | Exists. It reads `CLOCK_MONOTONIC` nanoseconds, the same base Pulsar's header conversion expects. |
| `ModuleError` | `pdk/module.rs` | `Box<dyn Error + Send + Sync + 'static>`. `From<String>` and `From<&str>` come from std, so `?` on `Result<_, String>` works. |
| Process attribution | `pdk/module_context.rs` `send_internal`, `pdk/process_tracker.rs`, `bpf-filtering/src/initializer.rs` | `send_threat` looks the pid up in the process tracker. A network peer has no local pid, so we attribute threats to the daemon's own pid. `process-monitor` seeds the tracker from `/proc` at startup, so the lookup should succeed. If it fails, Pulsar logs `Process not found in tracker` after about 100 ms and **still sends** the threat, with an empty image. |
| Lifecycle | `src/pulsard/module_manager.rs` | `init_state` runs inside a `select!` against a stop command. We spawn the listener only at the end of `init_state`, so a cancelled init leaks nothing. `graceful_stop` aborts the listener. On restart, `init_state` runs again with `&self`. |

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
```

## 4. Sensor behaviour that was changed or added

- **Port from the domain id.** The SPDP port is `7400 + 250 * domain_id`
  (DDSI-RTPS 2.2 §9.6.1.1, `PB=7400, DG=250, d0=0`).
  - `domain_id` must be in `0..=232`, the largest value whose port fits in
    16 bits.
  - Values in 102..=214 are accepted with a warning: ROS 2 recommends
    0..=101 and 215..=232.
  - `spdp_port` can override the derived port, with a warning.
- **Validation.** `config.rs` rejects:
  - a non-absolute or empty `profile_path`;
  - a non-multicast `spdp_group`;
  - a multicast or broadcast `interface`;
  - `spdp_port = 0`;
  - `dedup_capacity` outside `1..=1048576`.

  `listen_spdp = false` without an external source is rejected in
  `init_state`.
- **Observe mode** (`profile.locked == false`):
  - the threat description starts with `[observe-only] `;
  - `extra` has `mode = "observe"`, `observe_only = true`;
  - a module warning is raised.

  Locked profiles produce `mode = "locked"`, `observe_only = false`. The full
  `extra` table is `rule`, `severity`, `detail`, `mode`, `observe_only`,
  `src_ip` and `profile_model`. No new event type was added.
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

  `socket.rs` sets `SO_REUSEADDR` before `bind`, which `std` and tokio cannot
  do. It deliberately does not set `SO_REUSEPORT`, which load-balances
  unicast between sockets. It binds to the **group address**, so only
  datagrams sent to the group reach the sensor. The socket never transmits.

## 5. Seam for the capture-based listener (`robodr-capture`)

`robodr-sensor-ros2` does **not** depend on `robodr-capture`. The seam has
three parts:

- `pipeline::Datagram { payload: Vec<u8>, src_ip: String }`. The payload is
  the UDP payload, starting at `RTPS`.
- `pipeline::DatagramSource`, a std-only blocking trait with
  `fn recv(&mut self) -> io::Result<Option<Datagram>>`:
  - `Ok(None)` means the source is finished;
  - `Err` is terminal;
  - the implementation must handle transient errors itself.

  `robodr-capture` can implement it with no tokio and no Pulsar.
- In the glue:
  - `spawn_blocking_source(source, capacity) -> io::Result<mpsc::Receiver<Datagram>>`
    runs the source on an OS thread, with bounded backpressure.
  - `Ros2Sensor::with_external_source(rx)` feeds that channel into the same
    pipeline, alongside the SPDP socket, or alone if `listen_spdp = false`.

  The receiver sits behind an `Arc<tokio::sync::Mutex<..>>`, so it survives
  a module stop and start.

Integrator wiring, in `robodr-pulsard`'s closure:
`starter.add_module(Ros2Sensor::with_external_source(spawn_blocking_source(capture_source, 1024)?))`.

## 6. How the parts that could be checked here were checked

- `pipeline.rs`, `config.rs` and `socket.rs` were compiled and tested
  offline: 30 unit tests pass and clippy `-D warnings` is clean. They were
  included through `#[path]` into a throwaway crate that depends only on
  robodr-events, robodr-rtps, serde and serde_json. The socket tests did run
  real `SO_REUSEADDR` binds and a multicast join on this Linux host.

  Under `cargo test -p robodr-sensor-ros2` these same tests run as part of
  the crate once Pulsar's dependencies are available. The offline script
  cannot run them in place, because it drops the whole crate.
- `lib.rs` was type-checked, and clippy-checked with `-D warnings`, against
  **hand-written signature stubs** of `pulsar-core` and tokio. The
  `pulsar-core` stubs were copied from the files above; the tokio stubs were
  written from tokio 1.x's public API. This catches signature, borrow and
  `Send` mistakes in our code. It cannot catch differences between the stubs
  and the real crates.
- `robodr-pulsard/src/main.rs` was not compiled at all. It is a near-copy of
  `vendor/pulsar/src/bin/pulsard.rs` and
  `examples/pulsar-extension-module/main.rs`.
- `rustfmt --edition 2021 --check` is clean on all touched `.rs` files.

## 7. Still unverified until a real build (Linux box with crates.io)

1. A real `cargo build -p robodr-sensor-ros2 -p robodr-pulsard` and
   `cargo test -p robodr-sensor-ros2`.
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
7. End-to-end: a threat from this module shows up in `threat-logger` and the
   rules engine, with `extra` intact.

## 8. Build prerequisites

- Linux on x86_64, aarch64 or riscv64. These are the only arches Pulsar's
  `bpf-builder` and our `socket.rs` support.
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
