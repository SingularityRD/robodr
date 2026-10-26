//! `robodr-pulsard`: the Pulsar daemon with the RoboDR modules registered.
//!
//! **Pulsar-dependent crate** (links all of vendor/pulsar).
//!
//! This mirrors Pulsar's own `pulsard` binary (vendor/pulsar/src/bin/pulsard.rs)
//! and its documented extension pattern (vendor/pulsar/examples/
//! pulsar-extension-module/main.rs): `pulsar_daemon_run` registers the Pulsar
//! modules compiled in through the `pulsar` crate's features, then calls our
//! closure with the `PulsarDaemonStarter` so we can `add_module` ours before
//! the daemon starts.
//!
//! RoboDR modules ship `DEFAULT_ENABLED = false`; enable them in
//! `/etc/pulsar/pulsar.toml` (see config/robodr.toml.example):
//!
//! ```toml
//! [module.robodr-sensor-ros2]
//! enabled = true
//! profile_path = "/etc/robodr/profile.json"
//!
//! [module.robodr-sensor-ros2.capture]
//! enabled = true   # passive capture: sees unicast SEDP (needs CAP_NET_RAW)
//! ```
//!
//! `robodr-threat-forward` (also `DEFAULT_ENABLED = false`) hands every
//! Pulsar threat except the sensor's own to robodr-agentd's host-threat
//! socket, so agentd's host-dependent correlation rules can fire:
//!
//! ```toml
//! [module.robodr-threat-forward]
//! enabled = true
//! socket_path = "/run/robodr-agentd/host-threats.sock"
//! ```
//!
//! The capture source needs no registration here: the sensor opens it from
//! its own config section in `init_state` (see `robodr_ros2_pipeline`).
//! The daemon must hold `CAP_NET_RAW` for live capture (it already runs as
//! root for eBPF).

// S10 (review I3): no `unsafe` code here (checked with grep; the only
// macros used, `tokio::main` / `tokio::select!` and derives, compile under
// `forbid(unsafe_code)`), and it must stay that way.
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use pulsar::pulsard::PulsarDaemonOpts;
use robodr_sensor_ros2::Ros2Sensor;
use robodr_threat_forward::ThreatForwarder;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    pulsar::init_logger(Some(opts.verbosity.log_level_filter()));

    // Same shape as upstream pulsard: report and exit(1) on error.
    #[allow(clippy::blocks_in_conditions)]
    match pulsar::pulsard::pulsar_daemon_run(&opts.daemon_opts, |starter| {
        // SPDP socket and passive capture are both configured in
        // `[module.robodr-sensor-ros2]`; an additional, non-configured
        // source could be attached with
        // `Ros2Sensor::with_external_source(robodr_sensor_ros2::spawn_blocking_source(src, n)?)`.
        starter.add_module(Ros2Sensor::new())?;
        // Pulsar threats -> robodr-agentd (host-side correlation signals).
        starter.add_module(ThreatForwarder)?;
        Ok(())
    })
    .await
    {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            pulsar::utils::report_error(&e);
            std::process::exit(1);
        }
    }
}

/// Version string: RoboDR version plus the Pulsar version and commit it embeds.
fn long_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        format!(
            "{}\npulsar: {} (commit {})",
            env!("CARGO_PKG_VERSION"),
            pulsar::metadata::VERSION,
            pulsar::metadata::GIT_SHA
        )
    })
}

#[derive(Parser, Debug, Clone)]
#[clap(name = "robodr-pulsard")]
#[clap(about = "RoboDR: Pulsar runtime security agent with robot sensors")]
#[clap(version = long_version())]
#[clap(disable_help_subcommand = true)]
struct Opts {
    #[command(flatten)]
    daemon_opts: PulsarDaemonOpts,

    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
}
