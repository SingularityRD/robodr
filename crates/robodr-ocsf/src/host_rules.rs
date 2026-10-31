//! Per-rule finding ids for host (Pulsar) detections (contract 2.5).
//!
//! Until contract 2.4 every Pulsar host detection was reported under the
//! single rule id `robot.host.pulsar_threat`, with the Pulsar rule name only
//! in the (tainted) detail: a SOC rule or a response-policy override could
//! not single out one host rule. Since 2.5 each rule shipped in
//! `rules/robodr/*.toml` has its own stable OCSF rule id
//! `robot.host.<slug>` ([`HOST_RULES`], [`host_rule_id`]); a Pulsar rule
//! RoboDR does not ship (a deployment's own rule, a renamed rule) keeps the
//! fallback [`HOST_THREAT_FALLBACK`]. The ids are part of the findings
//! contract: renaming a Pulsar rule must keep its id (add the new name with
//! the old id), and an id is never reused for another rule.
//!
//! The table is checked against `rules/robodr/*.toml` by this crate's test
//! suite (`tests/host_rules.rs`), in both directions.

/// The fallback id of a Pulsar detection without its own id.
pub const HOST_THREAT_FALLBACK: &str = "robot.host.pulsar_threat";

/// `(Pulsar rule name, OCSF rule id)` of every shipped host rule.
pub const HOST_RULES: &[(&str, &str)] = &[
    // kernel_modules.toml
    (
        "RoboDR: Kernel module file written outside the package manager",
        "robot.host.kernel_module_written",
    ),
    (
        "RoboDR: Kernel module autoload configuration changed",
        "robot.host.kernel_module_autoload_changed",
    ),
    (
        "RoboDR: Kernel module file or autoload configuration moved into place outside the package manager",
        "robot.host.kernel_module_moved",
    ),
    (
        "RoboDR: Kernel module file or autoload configuration linked into place outside the package manager",
        "robot.host.kernel_module_linked",
    ),
    // radio_provisioning.toml
    (
        "RoboDR: Bluetooth tooling executed on robot controller",
        "robot.host.bluetooth_tooling_executed",
    ),
    (
        "RoboDR: Wi-Fi configuration tooling executed on robot controller",
        "robot.host.wifi_tooling_executed",
    ),
    (
        "RoboDR: Wireless network configuration modified",
        "robot.host.wireless_config_modified",
    ),
    (
        "RoboDR: Wireless network configuration moved into or out of place",
        "robot.host.wireless_config_moved",
    ),
    (
        "RoboDR: Link created in a wireless network configuration directory",
        "robot.host.wireless_config_linked",
    ),
    // ros2_stack.toml
    (
        "RoboDR: Interactive shell started on robot controller",
        "robot.host.interactive_shell",
    ),
    (
        "RoboDR: Login shell started on robot controller",
        "robot.host.login_shell",
    ),
    (
        "RoboDR: ROS 2 process connects outside the robot's networks",
        "robot.host.ros2_external_connection",
    ),
    (
        "RoboDR: ROS 2 install tree written outside the package manager",
        "robot.host.ros2_install_tree_written",
    ),
    (
        "RoboDR: File created or moved into the ROS 2 install tree outside the package manager",
        "robot.host.ros2_install_tree_file_placed",
    ),
    (
        "RoboDR: Link created inside the ROS 2 install tree outside the package manager",
        "robot.host.ros2_install_tree_linked",
    ),
    (
        "RoboDR: Shell or netcat-style tool opened a network connection",
        "robot.host.shell_network_connection",
    ),
    // runtime_hooking.toml
    (
        "RoboDR: ROS 2 process loaded a library from outside the allowlisted library paths",
        "robot.host.ros2_foreign_library",
    ),
    (
        "RoboDR: ROS 2 process mapped an ELF from outside the allowlisted paths",
        "robot.host.ros2_foreign_elf_mapped",
    ),
    (
        "RoboDR: ELF opened from a world-writable or user cache directory",
        "robot.host.elf_from_writable_dir",
    ),
    (
        "RoboDR: ROS 2 process loaded /etc/ld.so.preload",
        "robot.host.ros2_ld_preload",
    ),
    (
        "RoboDR: Unexpected ROS 2 middleware (RMW) library loaded",
        "robot.host.unexpected_rmw_library",
    ),
    (
        "RoboDR: Shared library opened from a temporary directory",
        "robot.host.library_from_tmp",
    ),
    (
        "RoboDR: Program executed from a temporary directory",
        "robot.host.exec_from_tmp",
    ),
    (
        "RoboDR: Shared library written into a system library path outside the package manager",
        "robot.host.system_library_written",
    ),
    (
        "RoboDR: File moved into a system library path or linker configuration outside the package manager",
        "robot.host.system_library_moved",
    ),
    (
        "RoboDR: Link created in a system library path or linker configuration outside the package manager",
        "robot.host.system_library_linked",
    ),
    (
        "RoboDR: Existing file in a system library path opened for writing outside the package manager",
        "robot.host.system_library_opened_for_write",
    ),
    (
        "RoboDR: Dynamic linker search path changed",
        "robot.host.linker_path_changed",
    ),
    (
        "RoboDR: Process memory written through /proc",
        "robot.host.proc_memory_written",
    ),
    (
        "RoboDR: Debugger or tracer started on robot controller",
        "robot.host.debugger_started",
    ),
    (
        "RoboDR: Program executed from a file descriptor or /proc path",
        "robot.host.exec_from_fd",
    ),
    (
        "RoboDR: Program executed through a non-canonical path",
        "robot.host.exec_noncanonical_path",
    ),
    (
        "RoboDR: ROS 2 process imported Python code from outside the allowlisted paths",
        "robot.host.ros2_foreign_python",
    ),
    (
        "RoboDR: Interpreter one-liner executed",
        "robot.host.interpreter_one_liner",
    ),
    (
        "RoboDR: Interactive or stdin-fed Python interpreter started",
        "robot.host.interactive_python",
    ),
    (
        "RoboDR: Pseudo-terminal wrapper executed on robot controller",
        "robot.host.pty_wrapper",
    ),
    (
        "RoboDR: Package manager loaded a library from outside the system library paths",
        "robot.host.package_manager_foreign_library",
    ),
    (
        "RoboDR: Package manager mapped an ELF from outside the system paths",
        "robot.host.package_manager_foreign_elf",
    ),
    // self_protection.toml
    (
        "RoboDR: RoboDR or Pulsar protected file written",
        "robot.host.protected_file_written",
    ),
    (
        "RoboDR: RoboDR or Pulsar protected file deleted",
        "robot.host.protected_file_deleted",
    ),
    (
        "RoboDR: RoboDR or Pulsar protected file or directory renamed",
        "robot.host.protected_file_renamed",
    ),
    (
        "RoboDR: File or device node created in a RoboDR or Pulsar protected path",
        "robot.host.protected_path_file_created",
    ),
    (
        "RoboDR: Link created in or to a RoboDR or Pulsar protected path",
        "robot.host.protected_path_linked",
    ),
    (
        "RoboDR: Directory created in a RoboDR or Pulsar protected path",
        "robot.host.protected_path_dir_created",
    ),
    (
        "RoboDR: RoboDR or Pulsar protected directory deleted",
        "robot.host.protected_dir_deleted",
    ),
    (
        "RoboDR: Attempt to stop the Pulsar or RoboDR service",
        "robot.host.service_stop_attempt",
    ),
    // sros2_keystore.toml
    (
        "RoboDR: SROS 2 enclave private key read by a process outside the ROS stack",
        "robot.host.sros2_key_read",
    ),
    (
        "RoboDR: SROS 2 CA private key accessed on robot",
        "robot.host.sros2_ca_key_accessed",
    ),
    (
        "RoboDR: SROS 2 keystore file written",
        "robot.host.sros2_keystore_written",
    ),
    (
        "RoboDR: SROS 2 keystore file renamed or replaced",
        "robot.host.sros2_keystore_replaced",
    ),
    (
        "RoboDR: Link created to an SROS 2 private key",
        "robot.host.sros2_key_linked",
    ),
    (
        "RoboDR: Link created inside an SROS 2 enclave directory",
        "robot.host.sros2_enclave_linked",
    ),
    (
        "RoboDR: SROS 2 security files loaded from outside the commissioned keystore",
        "robot.host.sros2_foreign_security_files",
    ),
    // supply_chain.toml
    (
        "RoboDR: Debian package installed on robot controller",
        "robot.host.deb_installed",
    ),
    (
        "RoboDR: Debian package maintainer script executed",
        "robot.host.deb_maintainer_script",
    ),
    (
        "RoboDR: Debian package database changed",
        "robot.host.deb_database_changed",
    ),
    (
        "RoboDR: Python package installed on robot controller",
        "robot.host.pip_installed",
    ),
    (
        "RoboDR: Python package installed with uv, pipx, poetry or conda/mamba",
        "robot.host.python_tool_installed",
    ),
    (
        "RoboDR: Node.js package installed with npm, npx, pnpm or yarn",
        "robot.host.node_package_installed",
    ),
    (
        "RoboDR: File created in the system or ROS Python environment outside the package manager",
        "robot.host.python_env_file_created",
    ),
    (
        "RoboDR: File moved into the system or ROS Python environment outside the package manager",
        "robot.host.python_env_file_moved",
    ),
    (
        "RoboDR: Link created in the system or ROS Python environment outside the package manager",
        "robot.host.python_env_linked",
    ),
    // unitree.toml
    (
        "RoboDR: Unitree Wi-Fi provisioning script executed",
        "robot.host.unitree_wifi_script_executed",
    ),
    (
        "RoboDR: Unitree Wi-Fi provisioning script opened",
        "robot.host.unitree_wifi_script_opened",
    ),
    (
        "RoboDR: Bluetooth daemon or Wi-Fi provisioning script opened an IP connection",
        "robot.host.provisioning_ip_connection",
    ),
    (
        "RoboDR: Bluetooth pairing keys or configuration modified outside bluetoothd",
        "robot.host.bluetooth_keys_modified",
    ),
    (
        "RoboDR: Bluetooth pairing keys or configuration moved into place outside bluetoothd",
        "robot.host.bluetooth_keys_moved",
    ),
    (
        "RoboDR: Service or autostart entry written outside the package manager",
        "robot.host.autostart_written",
    ),
    (
        "RoboDR: Service or autostart entry moved into place outside the package manager",
        "robot.host.autostart_moved",
    ),
    (
        "RoboDR: Service enabled, masked or linked outside the package manager",
        "robot.host.service_enabled",
    ),
    (
        "RoboDR: Boot, network or udev hook written outside the package manager",
        "robot.host.boot_hook_written",
    ),
    (
        "RoboDR: Boot, network or udev hook moved into place outside the package manager",
        "robot.host.boot_hook_moved",
    ),
    (
        "RoboDR: Boot, network or udev hook linked outside the package manager",
        "robot.host.boot_hook_linked",
    ),
    (
        "RoboDR: Shell startup or login environment file modified",
        "robot.host.shell_startup_modified",
    ),
    (
        "RoboDR: Shell startup or login environment file moved into place",
        "robot.host.shell_startup_moved",
    ),
    (
        "RoboDR: Shell startup or login environment file linked",
        "robot.host.shell_startup_linked",
    ),
    (
        "RoboDR: Unitree robot process connects outside the allowlisted destinations",
        "robot.host.unitree_external_connection",
    ),
    (
        "RoboDR: Program in a user-writable directory connects to a public address",
        "robot.host.writable_dir_public_connection",
    ),
    (
        "RoboDR: Reverse tunnel client executed on robot",
        "robot.host.reverse_tunnel_client",
    ),
    (
        "RoboDR: SSH reverse or dynamic tunnel with bundled options",
        "robot.host.ssh_tunnel",
    ),
    (
        "RoboDR: Remote-access overlay VPN started on robot",
        "robot.host.overlay_vpn",
    ),
    (
        "RoboDR: Unitree DDS configuration modified",
        "robot.host.unitree_dds_config_modified",
    ),
    (
        "RoboDR: Unitree DDS configuration moved into place",
        "robot.host.unitree_dds_config_moved",
    ),
    (
        "RoboDR: Unitree SDK or Cyclone DDS library modified outside the package manager",
        "robot.host.unitree_sdk_modified",
    ),
    (
        "RoboDR: Unitree SDK or Cyclone DDS library moved into place outside the package manager",
        "robot.host.unitree_sdk_moved",
    ),
    (
        "RoboDR: Unitree SDK or Cyclone DDS library linked outside the package manager",
        "robot.host.unitree_sdk_linked",
    ),
];

/// The OCSF rule id of a Pulsar detection named `pulsar_rule`: its own id
/// when RoboDR ships the rule, `None` otherwise (the caller then uses
/// [`HOST_THREAT_FALLBACK`]). Exact, case-sensitive match on the name.
pub fn host_rule_id(pulsar_rule: &str) -> Option<&'static str> {
    HOST_RULES
        .iter()
        .find(|(name, _)| *name == pulsar_rule)
        .map(|(_, id)| *id)
}

/// The catalog title of a per-rule host id (the Pulsar rule name without
/// its `RoboDR: ` prefix), `None` for any other id.
pub fn host_rule_title(rule_id: &str) -> Option<&'static str> {
    HOST_RULES
        .iter()
        .find(|(_, id)| *id == rule_id)
        .map(|(name, _)| name.strip_prefix("RoboDR: ").unwrap_or(name))
}
