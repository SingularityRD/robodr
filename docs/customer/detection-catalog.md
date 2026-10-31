# Detection catalog

> **Pre-release draft (2026-10-31).** Every rule id RoboDR can report, as
> catalogued in the `robodr.findings` contract **2.5**
> ([`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md)).
> The tables at the end are generated from the rule catalog in the code
> (`crates/robodr-ocsf/src/builder.rs`) by
> `scripts/check-detection-catalog.py`, which fails when this page and the
> code disagree. Verification levels (V0–V3) are those of
> [`support-matrix.md`](support-matrix.md). Nothing here has been verified
> on a customer robot. Three ids are catalogued in 2.5 for features
> that do not emit them yet: `robot.agent.control_plane_request_fenced`,
> `robot.agent.selftest` and `robot.gateway.overload`.

## How to read a finding

- **Rule id** (`robot.<area>.<name>`): what was detected. It is the stable
  key for SOC rules, dashboards and response policies.
- **Severity** (Low, Medium, High, Critical) is set by the detector at run
  time from what it saw. The same rule can be reported at different
  severities (for example `robot.agent.input_silent` is High; an
  aggregated flood can be raised). It is not a property of the catalog
  entry.
- **Mode**: `observe` or `enforce`. Every finding is `observe` until the
  model profile is locked, signed and trusted; an `observe` finding never
  leads to an action. Even `enforce` findings only lead to an action when
  the executor is enabled and the response policy is OEM-validated
  ([`known-limitations.md`](known-limitations.md), "Response and
  enforcement").
- **Data source** groups the rules by input (discovery, motion commands,
  safety state, host, agent self-health, secure delivery).
- **ATT&CK for ICS** ids are a first mapping, made by the RoboDR team from
  the public matrix; they have not been reviewed by MITRE or a third party.
- **Since**: the contract minor that first catalogued the id. A SOC
  validator older than that minor rejects the finding (upgrade consumers
  before producers: [`support-matrix.md`](support-matrix.md), "Contract
  and AutoSecOps compatibility").

## What each detection needs

"Profile" means the model profile `robodr-commission` learns from clean
runs. A **draft** (learned, not yet locked) profile is enough for the
graph and motion rules: they then report in `observe` mode, which is how a
POC runs ([`poc-guide.md`](poc-guide.md)). Only a locked, signed profile
makes them `enforce`.

| Area | Emitted by | Needs | Works with no profile content | Verified |
|---|---|---|---|---|
| `robot.capture.*`, `robot.rtps.*`, `robot.sensor.*` | `robodr-agentd` (sensor pipeline) | Live capture (AF_PACKET) or pcap replay of the robot bus | **Yes**: packet health, malformed / fragmented / uninspected discovery, Zenoh detected (not decoded) | V2 (real ROS 2 Jazzy captures, red team R3) |
| `robot.agent.*` | `robodr-agentd` | Nothing beyond a running agent; `executor_*` need the executor, `control_plane_*` the control plane | **Yes**: self-health (silent / ended / malformed input, queue overflow, lag, spool full, black-box degraded / quarantined / truncated) | V2 (soak and red team in a lab VM) |
| `robot.host.*` (one id per Pulsar rule RoboDR ships; `robot.host.pulsar_threat` for any other Pulsar rule) | `robodr-pulsard` (Pulsar rules) → `robodr-agentd` | Linux ≥ 5.5 with BTF, `robodr-pulsard` running as root; not in `robodr-focal` | **Yes** | V2 under WSL2 only; rules never loaded on a robot |
| `robot.ros2.*`, `robot.dds.*` | `robodr-agentd` (sensor pipeline, detection core) | A profile: participants, topics, services, actions, readers, motion writers | No: without a profile every participant is unknown | V2 (Jazzy captures, Fast DDS and Cyclone DDS) |
| `robot.motion.*_over_envelope`, `unprofiled_channel`, `command_type_mismatch`, `control_handover`, `api_id_out_of_range` | `robodr-agentd` (detection core) | A profile with motion envelopes, learned from clean runs | No | `Twist` V2; other motion types and Unitree V1 |
| `robot.motion.*` (feedback: `uncommanded_motion`, `frozen_feedback`, `feedback_divergence`, `cross_sensor_disagreement`, …) | `robodr-agentd` (`robodr-motion`) | `sensor.motion.feedback_topics` (odometry, IMU, joint state) | Partly: needs the feedback topics, not the profile's graph | V2 (Gazebo `/odom`), others V1 |
| `robot.firewall.*` | Motion Firewall: in `robodr-agentd` (passive modes: **recorded only**) or in `robodr-firewall-gw` (inline: enforced) | Firewall configuration with envelopes (from the profile or the per-channel config) | No | Passive V1–V2; inline gateway V2 (network namespaces, synthetic traffic) |
| `robot.gateway.*`, `robot.unitree.webrtc_*` | `robodr-firewall-gw` (inline sensor box), reported through `robodr-agentd`'s gateway feed | The gateway installed in the controller cable | No (gateway channels configured) | V2 (network namespaces, synthetic frames) |
| `robot.unitree.legacy_*` | `robodr-agentd` | `sensor.unitree_legacy` (Go1 legacy UDP ports and command senders) | No | V1 |
| `robot.safety_state.*` | `robodr-agentd` (safety-state feed) | `safety_feed` (bus topic or PLC socket) | No profile, but needs the feed | V2 (lab: Gazebo `/odom` and a PLC socket) |
| `robot.correlate.*` | `robodr-agentd` (`robodr-correlate`) | The default rules (untuned engineering defaults) or site rules; the input findings they combine | As far as their inputs do | V2 (`motion_hijack` 11/11 in the soak); the others V1 |
| `robot.profile.*` | `robodr-agentd` | A profile (reports one it cannot enforce) | — | V1 |
| `robot.deliver.*`, `robot.seal.*` | `robodr-deliverd` (secure delivery on the unit) | Secure delivery installed (signed bundles, site depot) | **Yes** (no profile involved) | V1 (swtpm only) |
| `robot.depot.*` | `robodr-depot` (site depot) | A site depot | **Yes** | V1 (swtpm only) |

**With no profile at all** the agent does not start: `sensor.profile_path`
is required. The fastest way to the rows above that need one is to learn
a draft from the first clean capture and run on it in `observe` mode
([`quick-start.md`](quick-start.md) section 4a). The rows marked **Yes**
then report from the first minute; the others report against the draft.

## Not detected today

- Anything inside **Zenoh** (`rmw_zenoh`) traffic: the session is
  reported (`robot.capture.unsupported_middleware`), its content is not
  decoded.
- **DDS-Security / SROS2** encrypted payloads; **RTI Connext** traffic
  (untested); RTPS over TCP or shared memory.
- Traffic the sensor does not see: unicast between the robot's internal
  computers without a mirror, Wi-Fi, cellular, the Go2 app's WebRTC
  content.
- Fieldbuses (CAN, EtherCAT), MAVLink telemetry, OPC UA and closed
  industrial controllers: not on the GA scope ([`README.md`](../../README.md),
  "Scope").
- Host detections on JetPack 5 (`robodr-focal` has no `robodr-pulsard`).
- A Pulsar rule RoboDR does not ship (a site's own rule, or a shipped
  rule renamed on the unit) has no id of its own: it is reported as
  `robot.host.pulsar_threat`, and only the detail names the rule, so a
  response policy cannot single it out.

## Catalog

The generic entry ("RoboDR model-profile deviation", data source
`robodr`) is used only for a rule id that has no catalog entry; agentd
refuses such ids from the gateway feed. Correlation rules a site adds
are reported as `robot.correlate.<rule name>` with the generic
correlation entry.

<!-- BEGIN GENERATED: scripts/check-detection-catalog.py --write -->

254 catalogued rule ids, plus the `robot.correlate.*` prefix entry for site-specific correlation rules.

### `robot.agent.*` (28)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.agent.clock_jump` | Robot wall clock jumped | `robodr_agent` | — | 2.5 |
| `robot.agent.clock_unsynced` | Robot clock not synchronised | `robodr_agent` | — | 2.5 |
| `robot.agent.config_unattested` | Safety configuration not bound to the commissioning | `robodr_agent` | — | 2.5 |
| `robot.agent.control_plane_invalid` | Invalid control-plane action request refused | `robodr_agent` | — | 1.3 |
| `robot.agent.control_plane_request_fenced` | Control-plane request refused by the replay fence | `robodr_agent` | — | 2.5 |
| `robot.agent.control_plane_saturated` | Control-plane connections refused or cut before authentication | `robodr_agent` | — | 2.5 |
| `robot.agent.control_plane_state_untrusted` | Control-plane state failed its integrity check | `robodr_agent` | — | 2.4 |
| `robot.agent.control_plane_unauthenticated` | Control-plane request failed authentication | `robodr_agent` | — | 1.3 |
| `robot.agent.correlation_pressure` | Correlation engine state under pressure | `robodr_agent` | — | 1.3 |
| `robot.agent.credential_expiring` | Agent credential expires soon | `robodr_agent` | — | 2.5 |
| `robot.agent.disk_low` | Agent storage running out of space | `robodr_agent` | — | 2.5 |
| `robot.agent.evidence_degraded` | Black-box recording failing | `robodr_agent` | — | 1.3 |
| `robot.agent.evidence_quarantined` | Damaged black-box segment quarantined | `robodr_agent` | — | 1.3 |
| `robot.agent.evidence_retention_pressure` | Unexported black-box evidence filling the retention | `robodr_agent` | — | 2.5 |
| `robot.agent.evidence_truncated` | Black-box records cut after the newest mark | `robodr_agent` | — | 1.3 |
| `robot.agent.evidence_unexported_dropped` | Unexported black-box evidence dropped | `robodr_agent` | — | 2.5 |
| `robot.agent.executor_journal_reset` | Executor journal untrusted and reset | `robodr_agent` | — | 2.4 |
| `robot.agent.executor_pause_overridden` | Robot set moving while paused | `robodr_agent` | — | 2.5 |
| `robot.agent.executor_revert_failed` | Containment action could not be reverted | `robodr_agent` | — | 2.4 |
| `robot.agent.executor_unreachable` | Response executor unreachable | `robodr_agent` | — | 2.5 |
| `robot.agent.health` | Agent health record | `robodr_agent` | — | 2.5 |
| `robot.agent.input_ended` | Agent input ended | `robodr_agent` | — | 1.3 |
| `robot.agent.input_malformed` | Malformed agent input | `robodr_agent` | — | 1.3 |
| `robot.agent.input_silent` | Agent input silent | `robodr_agent` | — | 1.3 |
| `robot.agent.pipeline_lag` | Agent pipeline lagging | `robodr_agent` | — | 1.3 |
| `robot.agent.queue_overflow` | Agent input queue overflowed | `robodr_agent` | — | 1.3 |
| `robot.agent.selftest` | Agent field acceptance self-test | `robodr_agent` | — | 2.5 |
| `robot.agent.spool_full` | Finding spool full or failing | `robodr_agent` | — | 1.3 |

### `robot.capture.*` (10)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.capture.bad_checksum` | IP or UDP checksum failures | `ros2_dds_discovery` | — | 1.3 |
| `robot.capture.ip_fragment_conflict` | Conflicting overlapping IP fragments | `ros2_dds_discovery` | — | 1.3 |
| `robot.capture.ip_fragment_duplicate_conflict` | Duplicate IP fragment with different content | `ros2_dds_discovery` | — | 1.3 |
| `robot.capture.ip_fragment_refused` | IP fragments refused, reassembly budget full | `ros2_dds_discovery` | — | 1.3 |
| `robot.capture.ip_reassembly_dropped` | IP datagrams dropped in reassembly | `ros2_dds_discovery` | — | 1.3 |
| `robot.capture.ip_reassembly_evicted` | IP datagrams evicted from reassembly | `ros2_dds_discovery` | — | 1.3 |
| `robot.capture.malformed_frames` | Malformed or truncated captured frames | `ros2_dds_discovery` | — | 1.3 |
| `robot.capture.not_udp` | Non-UDP packets reached the sensor | `ros2_dds_discovery` | — | 1.3 |
| `robot.capture.unsupported_middleware` | Robot middleware not inspected (Zenoh) | `ros2_dds_discovery` | — | 1.3 |
| `robot.capture.unsupported_transport` | DDS transport not inspected (shared memory, TCP) | `ros2_dds_discovery` | — | 2.5 |

### `robot.correlate.*` (10)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.correlate.coordinated_intrusion` | Correlated intrusion: unknown participant, foreign motion writer and host anomaly | `robodr_correlation` | T0848, T0855 | 1.3 |
| `robot.correlate.correlation_state_evicted` | Correlation evidence evicted under pressure | `robodr_correlation` | — | 1.3 |
| `robot.correlate.credential_theft` | Correlated credential theft: SROS 2 key read, then a foreign participant | `robodr_correlation` | T0848 | 1.3 |
| `robot.correlate.defense_tampering` | Correlated defense tampering: protected file or service change with a silent input | `robodr_correlation` | — | 1.3 |
| `robot.correlate.discovery_flood` | Correlated discovery flood: unknown participants from many addresses | `robodr_correlation` | T0848 | 1.3 |
| `robot.correlate.host_process_persistence` | Correlated host activity: one process tripped several host rules | `robodr_correlation` | — | 1.3 |
| `robot.correlate.motion_hijack` | Correlated motion hijack: foreign motion source, then unexpected motion | `robodr_correlation` | T0855, T0831 | 1.3 |
| `robot.correlate.sensor_evasion` | Correlated sensor evasion: capture refusals with uninspected discovery | `robodr_correlation` | — | 1.3 |
| `robot.correlate.spoofed_motion_source` | Correlated spoofed motion source from one address | `robodr_correlation` | T0855 | 1.3 |
| `robot.correlate.trojaned_package_key_access` | Correlated supply-chain compromise: package install, then key access | `robodr_correlation` | — | 1.3 |

### `robot.dds.*` (1)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.dds.unknown_raw_writer` | Writer on a raw DDS topic outside the model profile | `ros2_dds_discovery` | T0855 | 1.3 |

### `robot.deliver.*` (7)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.deliver.chain_gap` | Release bundle chain gap or equivocation | `robodr_delivery` | — | 2.2 |
| `robot.deliver.deferred_safety` | Delivery deferred by the robot's safety state | `robodr_delivery` | — | 2.2 |
| `robot.deliver.health_failed` | Delivered package failed its health gate; rolled back | `robodr_delivery` | — | 2.2 |
| `robot.deliver.installed` | Delivered package installed | `robodr_delivery` | — | 2.2 |
| `robot.deliver.refused` | Delivery refused | `robodr_delivery` | — | 2.2 |
| `robot.deliver.rollback_blocked_floor` | Failed package cannot be rolled back | `robodr_delivery` | — | 2.2 |
| `robot.deliver.stale` | No fresh deployment or trust file | `robodr_delivery` | — | 2.2 |

### `robot.depot.*` (5)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.depot.enrolment_refused` | Depot refused a unit enrolment | `robodr_delivery` | — | 2.3 |
| `robot.depot.import_refused` | Depot refused a release bundle | `robodr_delivery` | — | 2.3 |
| `robot.depot.locked` | Depot database failed its anti-rollback check | `robodr_delivery` | — | 2.3 |
| `robot.depot.rollout_halted` | Staged rollout halted | `robodr_delivery` | — | 2.3 |
| `robot.depot.unit_enrolled` | Unit enrolled at the depot | `robodr_delivery` | — | 2.3 |

### `robot.firewall.*` (30)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.firewall.crc_invalid` | Joint command integrity check failed | `ros2_motion_commands` | T0855 | 2.1 |
| `robot.firewall.disabled_motor_energised` | Disabled motor energised | `ros2_motion_commands` | T0831, T0855 | 2.1 |
| `robot.firewall.events_dropped` | Motion firewall events dropped | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.internal_fault` | Motion firewall internal fault | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.joint_gain_below_minimum` | Joint command gain below minimum | `ros2_motion_commands` | T0831 | 2.1 |
| `robot.firewall.joint_gain_out_of_envelope` | Joint command gain out of envelope | `ros2_motion_commands` | T0831 | 2.1 |
| `robot.firewall.joint_hold_exceeded` | Humanoid joint hold exceeded its time limit | `ros2_motion_commands` | — | 2.1 |
| `robot.firewall.joint_limp_frame` | Humanoid joint command would go limp | `ros2_motion_commands` | T0831, T0855 | 2.1 |
| `robot.firewall.joint_mode_inconsistent` | Joint command mode inconsistent | `ros2_motion_commands` | T0831, T0855 | 2.1 |
| `robot.firewall.joint_mode_pin_mismatch` | Joint command operating mode changed | `ros2_motion_commands` | T0831, T0855 | 2.1 |
| `robot.firewall.joint_pd_torque_out_of_envelope` | Joint command proportional torque out of envelope | `ros2_motion_commands` | T0831 | 2.1 |
| `robot.firewall.joint_position_out_of_envelope` | Joint command position out of envelope | `ros2_motion_commands` | T0831 | 2.1 |
| `robot.firewall.joint_rate_violation` | Joint command stream gap | `ros2_motion_commands` | — | 2.1 |
| `robot.firewall.joint_step_out_of_envelope` | Joint command position step out of envelope | `ros2_motion_commands` | T0831 | 2.1 |
| `robot.firewall.joint_torque_out_of_envelope` | Joint command torque out of envelope | `ros2_motion_commands` | T0831 | 2.1 |
| `robot.firewall.joint_velocity_out_of_envelope` | Joint command velocity out of envelope | `ros2_motion_commands` | T0831 | 2.1 |
| `robot.firewall.limited_acceleration` | Motion command acceleration limited | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.limited_jerk` | Motion command jerk limited | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.limited_speed` | Motion command speed limited | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.rejected_clock_regression` | Motion command rejected: clock regression | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.rejected_future_timestamp` | Motion command rejected: future timestamp | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.rejected_kind_mismatch` | Motion command rejected: kind mismatch | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.rejected_non_finite` | Motion command rejected: non-finite value | `ros2_motion_commands` | T0831 | 1.3 |
| `robot.firewall.rejected_out_of_order` | Motion command rejected: out of order | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.rejected_over_hard_limit` | Motion command rejected: over hard limit | `ros2_motion_commands` | T0831 | 1.3 |
| `robot.firewall.rejected_rate_limited` | Motion command rejected: rate limit | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.rejected_stale` | Motion command rejected: stale | `ros2_motion_commands` | — | 1.3 |
| `robot.firewall.rejected_unauthorized_source` | Motion command rejected: unauthorised source | `ros2_motion_commands` | T0855 | 1.3 |
| `robot.firewall.rejected_unknown_channel` | Motion command rejected: unknown channel | `ros2_motion_commands` | T0855 | 1.3 |
| `robot.firewall.rejected_unknown_source` | Motion command rejected: unknown source | `ros2_motion_commands` | T0855 | 1.3 |

### `robot.gateway.*` (10)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.gateway.findings_dropped` | In-path gateway findings lost | `ros2_motion_commands` | — | 2.3 |
| `robot.gateway.fragmented_command` | Fragmented motion command blocked by the in-path gateway | `ros2_motion_commands` | — | 2.3 |
| `robot.gateway.overload` | In-path gateway overloaded | `ros2_motion_commands` | — | 2.5 |
| `robot.gateway.port_bypass_risk` | Motion traffic may bypass the in-path gateway | `ros2_motion_commands` | — | 2.3 |
| `robot.gateway.restriction_changed` | Motion restriction changed on the in-path gateway | `ros2_motion_commands` | — | 2.3 |
| `robot.gateway.sequence_jump` | Motion command sequence jump held back | `ros2_motion_commands` | — | 2.3 |
| `robot.gateway.trajectory_rejected` | Joint trajectory blocked by the in-path gateway | `ros2_motion_commands` | — | 2.3 |
| `robot.gateway.trajectory_time_scaled` | Joint trajectory slowed down by the in-path gateway | `ros2_motion_commands` | — | 2.3 |
| `robot.gateway.undecodable_command` | Undecodable motion command blocked by the in-path gateway | `ros2_motion_commands` | — | 2.3 |
| `robot.gateway.writer_binding_conflict` | Authorised motion writer seen from another address | `ros2_motion_commands` | — | 2.3 |

### `robot.host.*` (87)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.host.autostart_moved` | Service or autostart entry moved into place outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.autostart_written` | Service or autostart entry written outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.bluetooth_keys_modified` | Bluetooth pairing keys or configuration modified outside bluetoothd | `host_runtime` | — | 2.5 |
| `robot.host.bluetooth_keys_moved` | Bluetooth pairing keys or configuration moved into place outside bluetoothd | `host_runtime` | — | 2.5 |
| `robot.host.bluetooth_tooling_executed` | Bluetooth tooling executed on robot controller | `host_runtime` | — | 2.5 |
| `robot.host.boot_hook_linked` | Boot, network or udev hook linked outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.boot_hook_moved` | Boot, network or udev hook moved into place outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.boot_hook_written` | Boot, network or udev hook written outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.deb_database_changed` | Debian package database changed | `host_runtime` | — | 2.5 |
| `robot.host.deb_installed` | Debian package installed on robot controller | `host_runtime` | — | 2.5 |
| `robot.host.deb_maintainer_script` | Debian package maintainer script executed | `host_runtime` | — | 2.5 |
| `robot.host.debugger_started` | Debugger or tracer started on robot controller | `host_runtime` | — | 2.5 |
| `robot.host.elf_from_writable_dir` | ELF opened from a world-writable or user cache directory | `host_runtime` | — | 2.5 |
| `robot.host.exec_from_fd` | Program executed from a file descriptor or /proc path | `host_runtime` | — | 2.5 |
| `robot.host.exec_from_tmp` | Program executed from a temporary directory | `host_runtime` | — | 2.5 |
| `robot.host.exec_noncanonical_path` | Program executed through a non-canonical path | `host_runtime` | — | 2.5 |
| `robot.host.interactive_python` | Interactive or stdin-fed Python interpreter started | `host_runtime` | — | 2.5 |
| `robot.host.interactive_shell` | Interactive shell started on robot controller | `host_runtime` | — | 2.5 |
| `robot.host.interpreter_one_liner` | Interpreter one-liner executed | `host_runtime` | — | 2.5 |
| `robot.host.kernel_module_autoload_changed` | Kernel module autoload configuration changed | `host_runtime` | — | 2.5 |
| `robot.host.kernel_module_linked` | Kernel module file or autoload configuration linked into place outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.kernel_module_moved` | Kernel module file or autoload configuration moved into place outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.kernel_module_written` | Kernel module file written outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.library_from_tmp` | Shared library opened from a temporary directory | `host_runtime` | — | 2.5 |
| `robot.host.linker_path_changed` | Dynamic linker search path changed | `host_runtime` | — | 2.5 |
| `robot.host.login_shell` | Login shell started on robot controller | `host_runtime` | — | 2.5 |
| `robot.host.node_package_installed` | Node.js package installed with npm, npx, pnpm or yarn | `host_runtime` | — | 2.5 |
| `robot.host.overlay_vpn` | Remote-access overlay VPN started on robot | `host_runtime` | — | 2.5 |
| `robot.host.package_manager_foreign_elf` | Package manager mapped an ELF from outside the system paths | `host_runtime` | — | 2.5 |
| `robot.host.package_manager_foreign_library` | Package manager loaded a library from outside the system library paths | `host_runtime` | — | 2.5 |
| `robot.host.pip_installed` | Python package installed on robot controller | `host_runtime` | — | 2.5 |
| `robot.host.proc_memory_written` | Process memory written through /proc | `host_runtime` | — | 2.5 |
| `robot.host.protected_dir_deleted` | RoboDR or Pulsar protected directory deleted | `host_runtime` | — | 2.5 |
| `robot.host.protected_file_deleted` | RoboDR or Pulsar protected file deleted | `host_runtime` | — | 2.5 |
| `robot.host.protected_file_renamed` | RoboDR or Pulsar protected file or directory renamed | `host_runtime` | — | 2.5 |
| `robot.host.protected_file_written` | RoboDR or Pulsar protected file written | `host_runtime` | — | 2.5 |
| `robot.host.protected_path_dir_created` | Directory created in a RoboDR or Pulsar protected path | `host_runtime` | — | 2.5 |
| `robot.host.protected_path_file_created` | File or device node created in a RoboDR or Pulsar protected path | `host_runtime` | — | 2.5 |
| `robot.host.protected_path_linked` | Link created in or to a RoboDR or Pulsar protected path | `host_runtime` | — | 2.5 |
| `robot.host.provisioning_ip_connection` | Bluetooth daemon or Wi-Fi provisioning script opened an IP connection | `host_runtime` | — | 2.5 |
| `robot.host.pty_wrapper` | Pseudo-terminal wrapper executed on robot controller | `host_runtime` | — | 2.5 |
| `robot.host.pulsar_threat` | Host runtime-security detection (Pulsar rule) | `host_runtime` | — | 1.3 |
| `robot.host.python_env_file_created` | File created in the system or ROS Python environment outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.python_env_file_moved` | File moved into the system or ROS Python environment outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.python_env_linked` | Link created in the system or ROS Python environment outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.python_tool_installed` | Python package installed with uv, pipx, poetry or conda/mamba | `host_runtime` | — | 2.5 |
| `robot.host.reverse_tunnel_client` | Reverse tunnel client executed on robot | `host_runtime` | — | 2.5 |
| `robot.host.ros2_external_connection` | ROS 2 process connects outside the robot's networks | `host_runtime` | — | 2.5 |
| `robot.host.ros2_foreign_elf_mapped` | ROS 2 process mapped an ELF from outside the allowlisted paths | `host_runtime` | — | 2.5 |
| `robot.host.ros2_foreign_library` | ROS 2 process loaded a library from outside the allowlisted library paths | `host_runtime` | — | 2.5 |
| `robot.host.ros2_foreign_python` | ROS 2 process imported Python code from outside the allowlisted paths | `host_runtime` | — | 2.5 |
| `robot.host.ros2_install_tree_file_placed` | File created or moved into the ROS 2 install tree outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.ros2_install_tree_linked` | Link created inside the ROS 2 install tree outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.ros2_install_tree_written` | ROS 2 install tree written outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.ros2_ld_preload` | ROS 2 process loaded /etc/ld.so.preload | `host_runtime` | — | 2.5 |
| `robot.host.service_enabled` | Service enabled, masked or linked outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.service_stop_attempt` | Attempt to stop the Pulsar or RoboDR service | `host_runtime` | — | 2.5 |
| `robot.host.shell_network_connection` | Shell or netcat-style tool opened a network connection | `host_runtime` | — | 2.5 |
| `robot.host.shell_startup_linked` | Shell startup or login environment file linked | `host_runtime` | — | 2.5 |
| `robot.host.shell_startup_modified` | Shell startup or login environment file modified | `host_runtime` | — | 2.5 |
| `robot.host.shell_startup_moved` | Shell startup or login environment file moved into place | `host_runtime` | — | 2.5 |
| `robot.host.sros2_ca_key_accessed` | SROS 2 CA private key accessed on robot | `host_runtime` | — | 2.5 |
| `robot.host.sros2_enclave_linked` | Link created inside an SROS 2 enclave directory | `host_runtime` | — | 2.5 |
| `robot.host.sros2_foreign_security_files` | SROS 2 security files loaded from outside the commissioned keystore | `host_runtime` | — | 2.5 |
| `robot.host.sros2_key_linked` | Link created to an SROS 2 private key | `host_runtime` | — | 2.5 |
| `robot.host.sros2_key_read` | SROS 2 enclave private key read by a process outside the ROS stack | `host_runtime` | — | 2.5 |
| `robot.host.sros2_keystore_replaced` | SROS 2 keystore file renamed or replaced | `host_runtime` | — | 2.5 |
| `robot.host.sros2_keystore_written` | SROS 2 keystore file written | `host_runtime` | — | 2.5 |
| `robot.host.ssh_tunnel` | SSH reverse or dynamic tunnel with bundled options | `host_runtime` | — | 2.5 |
| `robot.host.system_library_linked` | Link created in a system library path or linker configuration outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.system_library_moved` | File moved into a system library path or linker configuration outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.system_library_opened_for_write` | Existing file in a system library path opened for writing outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.system_library_written` | Shared library written into a system library path outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.unexpected_rmw_library` | Unexpected ROS 2 middleware (RMW) library loaded | `host_runtime` | — | 2.5 |
| `robot.host.unitree_dds_config_modified` | Unitree DDS configuration modified | `host_runtime` | — | 2.5 |
| `robot.host.unitree_dds_config_moved` | Unitree DDS configuration moved into place | `host_runtime` | — | 2.5 |
| `robot.host.unitree_external_connection` | Unitree robot process connects outside the allowlisted destinations | `host_runtime` | — | 2.5 |
| `robot.host.unitree_sdk_linked` | Unitree SDK or Cyclone DDS library linked outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.unitree_sdk_modified` | Unitree SDK or Cyclone DDS library modified outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.unitree_sdk_moved` | Unitree SDK or Cyclone DDS library moved into place outside the package manager | `host_runtime` | — | 2.5 |
| `robot.host.unitree_wifi_script_executed` | Unitree Wi-Fi provisioning script executed | `host_runtime` | — | 2.5 |
| `robot.host.unitree_wifi_script_opened` | Unitree Wi-Fi provisioning script opened | `host_runtime` | — | 2.5 |
| `robot.host.wifi_tooling_executed` | Wi-Fi configuration tooling executed on robot controller | `host_runtime` | — | 2.5 |
| `robot.host.wireless_config_linked` | Link created in a wireless network configuration directory | `host_runtime` | — | 2.5 |
| `robot.host.wireless_config_modified` | Wireless network configuration modified | `host_runtime` | — | 2.5 |
| `robot.host.wireless_config_moved` | Wireless network configuration moved into or out of place | `host_runtime` | — | 2.5 |
| `robot.host.writable_dir_public_connection` | Program in a user-writable directory connects to a public address | `host_runtime` | — | 2.5 |

### `robot.motion.*` (20)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.motion.angular_over_envelope` | Roll/pitch rate command exceeds the motion envelope | `ros2_motion_commands` | T0831 | 1.0 |
| `robot.motion.api_id_out_of_range` | Robot API request with an aliased call id | `ros2_motion_commands` | T0855 | 2.1 |
| `robot.motion.command_type_mismatch` | Motion command writer with an unexpected type | `ros2_motion_commands` | T0855 | 2.1 |
| `robot.motion.control_handover` | Motor control handed to another channel | `ros2_motion_commands` | T0855 | 2.1 |
| `robot.motion.cross_sensor_disagreement` | Independent motion sensors disagree | `ros2_motion_commands` | T0856 | 1.3 |
| `robot.motion.decode_anomaly` | Motion sample decode anomaly | `ros2_motion_commands` | — | 1.3 |
| `robot.motion.feedback_divergence` | Motion feedback diverges from commands | `ros2_motion_commands` | T0831 | 1.3 |
| `robot.motion.frozen_feedback` | Motion feedback frozen or silent | `ros2_motion_commands` | — | 1.3 |
| `robot.motion.inconsistent_feedback_stream` | Inconsistent motion feedback stream | `ros2_motion_commands` | T0856 | 1.3 |
| `robot.motion.invalid_feedback` | Motion feedback with a non-finite value | `ros2_motion_commands` | — | 1.3 |
| `robot.motion.joint_over_envelope` | Joint speed command exceeds the motion envelope | `ros2_motion_commands` | T0831 | 1.0 |
| `robot.motion.linear_over_envelope` | Linear speed command exceeds the motion envelope | `ros2_motion_commands` | T0831 | 1.0 |
| `robot.motion.multiple_feedback_publishers` | Several publishers for one feedback source | `ros2_motion_commands` | T0856 | 1.3 |
| `robot.motion.non_finite_command` | Motion command with a non-finite value | `ros2_motion_commands` | T0831 | 1.3 |
| `robot.motion.sample_source_mismatch` | Motion sample from an address not bound to its writer | `ros2_motion_commands` | T0855 | 1.3 |
| `robot.motion.unattributed_sample` | Motion sample from an unattributed writer | `ros2_motion_commands` | T0855 | 1.3 |
| `robot.motion.uncommanded_motion` | Uncommanded motion | `ros2_motion_commands` | T0831 | 1.3 |
| `robot.motion.undecodable_sample` | Undecodable motion or feedback sample | `ros2_motion_commands` | — | 1.3 |
| `robot.motion.unprofiled_channel` | Motion command on an unprofiled channel | `ros2_motion_commands` | T0855 | 1.0 |
| `robot.motion.unverifiable_command` | Motion command that cannot be bounded | `ros2_motion_commands` | — | 1.3 |

### `robot.profile.*` (1)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.profile.invalid_envelope` | Motion envelope in the profile cannot be enforced | `ros2_motion_commands` | — | 1.3 |

### `robot.ros2.*` (17)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.ros2.ambiguous_discovery` | Ambiguous discovery announcement | `ros2_dds_discovery` | — | 1.3 |
| `robot.ros2.discovery_flood` | Discovery flood: unknown participants aggregated | `ros2_dds_discovery` | T0848 | 2.1 |
| `robot.ros2.endpoint_source_mismatch` | DDS endpoint announced from an unbound address | `ros2_dds_discovery` | T0848 | 1.3 |
| `robot.ros2.endpoint_unannounced_participant` | DDS endpoint for a participant that never announced itself | `ros2_dds_discovery` | — | 1.3 |
| `robot.ros2.identity_instances_exceeded` | Extra DDS participant claims a robot identity | `ros2_dds_discovery` | T0848 | 1.3 |
| `robot.ros2.participant_removed` | Profiled DDS participant removed | `ros2_dds_discovery` | — | 1.3 |
| `robot.ros2.participant_source_mismatch` | DDS participant announced from an unbound address | `ros2_dds_discovery` | T0848 | 1.3 |
| `robot.ros2.profile_refused` | Model profile refused | `robodr_agent` | — | 1.3 |
| `robot.ros2.profile_state_tampered` | Profile anti-rollback state missing or behind the black box | `robodr_agent` | — | 1.3 |
| `robot.ros2.unauthorized_motion_writer` | Unauthorized publisher on a motion topic | `ros2_dds_discovery` | T0855 | 1.0 |
| `robot.ros2.unknown_action` | Writer on an action outside the model profile | `ros2_dds_discovery` | T0855 | 1.3 |
| `robot.ros2.unknown_participant` | Unknown DDS participant joined the robot graph | `ros2_dds_discovery` | T0848 | 1.0 |
| `robot.ros2.unknown_reader` | Unknown subscriber in the robot graph | `ros2_dds_discovery` | T0801 | 1.0 |
| `robot.ros2.unknown_reader_topic` | Subscriber on a topic outside the reader allowlist | `ros2_dds_discovery` | T0801 | 1.3 |
| `robot.ros2.unknown_service` | Writer on a service outside the model profile | `ros2_dds_discovery` | T0855 | 1.3 |
| `robot.ros2.unknown_writer_topic` | Writer on a topic outside the model profile | `ros2_dds_discovery` | T0855 | 1.0 |
| `robot.ros2.untrusted_security_identity` | Participant outside the robot's SROS 2 keystore | `ros2_dds_discovery` | — | 2.5 |

### `robot.rtps.*` (7)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.rtps.discovery_fragment_conflict` | Conflicting discovery fragments | `ros2_dds_discovery` | — | 1.3 |
| `robot.rtps.discovery_fragment_evicted` | Partial discovery samples evicted | `ros2_dds_discovery` | — | 1.3 |
| `robot.rtps.discovery_fragment_rejected` | Discovery fragments refused | `ros2_dds_discovery` | — | 1.3 |
| `robot.rtps.discovery_not_inspected` | Discovery traffic not inspected | `ros2_dds_discovery` | — | 1.3 |
| `robot.rtps.discovery_removal` | Discovery dispose or unregister | `ros2_dds_discovery` | — | 1.3 |
| `robot.rtps.fragmented_discovery` | Fragmented RTPS discovery data | `ros2_dds_discovery` | — | 1.3 |
| `robot.rtps.malformed_discovery` | Malformed RTPS discovery traffic | `ros2_dds_discovery` | — | 1.3 |

### `robot.safety_state.*` (4)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.safety_state.undecodable_sample` | Undecodable safety-state sample | `robot_safety_state` | — | 1.3 |
| `robot.safety_state.unmapped_value` | Safety-state value outside the configured mapping | `robot_safety_state` | — | 1.3 |
| `robot.safety_state.untrusted_source` | Safety-state sample from an untrusted writer | `robot_safety_state` | T0856 | 1.3 |
| `robot.safety_state.writer_overflow` | Safety-state writer table overflowed | `robot_safety_state` | — | 1.3 |

### `robot.seal.*` (5)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.seal.erase_deferred` | Crypto-erase deferred by the safety state | `robodr_delivery` | — | 2.3 |
| `robot.seal.erased` | Crypto-erase of delivered software executed | `robodr_delivery` | — | 2.3 |
| `robot.seal.lease_expired` | Site lease expired | `robodr_delivery` | — | 2.3 |
| `robot.seal.tamper` | Enclosure tamper or erase trigger fired | `robodr_delivery` | — | 2.3 |
| `robot.seal.unseal_failed` | Unit could not unseal delivered software | `robodr_delivery` | — | 2.3 |

### `robot.sensor.*` (1)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.sensor.findings_capped` | Sensor findings capped for one input | `ros2_dds_discovery` | — | 1.3 |

### `robot.unitree.*` (11)

| Rule id | Title | Data source | ATT&CK for ICS | Since |
|---|---|---|---|---|
| `robot.unitree.legacy_port_rtps` | RTPS traffic on a Unitree legacy UDP port | `ros2_motion_commands` | T0855 | 2.1 |
| `robot.unitree.legacy_sender_flood` | Unitree legacy UDP frames from many unknown hosts | `ros2_motion_commands` | T0855 | 2.1 |
| `robot.unitree.legacy_sender_mac_mismatch` | Unitree legacy command from a listed IP with the wrong MAC | `ros2_motion_commands` | T0855 | 2.1 |
| `robot.unitree.legacy_unknown_sender` | Unitree legacy UDP frame from an unknown host | `ros2_motion_commands` | T0855 | 2.1 |
| `robot.unitree.webrtc_concurrent_sessions` | More concurrent WebRTC control sessions than allowed | `ros2_motion_commands` | — | 2.3 |
| `robot.unitree.webrtc_controller_mac_mismatch` | Listed WebRTC controller seen with another link-layer address | `ros2_motion_commands` | — | 2.3 |
| `robot.unitree.webrtc_media_without_signalling` | WebRTC session without observed signalling | `ros2_motion_commands` | — | 2.3 |
| `robot.unitree.webrtc_new_peer` | New WebRTC peer of the robot | `ros2_motion_commands` | — | 2.3 |
| `robot.unitree.webrtc_relayed_session` | Remote WebRTC session through a relay | `ros2_motion_commands` | — | 2.3 |
| `robot.unitree.webrtc_session_in_denied_window` | WebRTC control session during a denied window | `ros2_motion_commands` | — | 2.3 |
| `robot.unitree.webrtc_unknown_controller` | WebRTC control session from an unlisted host | `ros2_motion_commands` | — | 2.3 |

<!-- END GENERATED -->

## Keeping this page current

```sh
python3 scripts/check-detection-catalog.py           # exit 1 when this page drifted
python3 scripts/check-detection-catalog.py --write   # regenerate the tables
```

A new rule id is a contract minor bump
([`robodr.findings.md`](../contracts/robodr.findings.md) §5): add its
catalog entry, regenerate this page, and check the "What each detection
needs" table above.
