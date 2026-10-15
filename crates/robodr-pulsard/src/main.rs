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
//! ```

use std::sync::OnceLock;

use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use pulsar::pulsard::PulsarDaemonOpts;
use robodr_sensor_ros2::Ros2Sensor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    pulsar::init_logger(Some(opts.verbosity.log_level_filter()));

    // Same shape as upstream pulsard: report and exit(1) on error.
    #[allow(clippy::blocks_in_conditions)]
    match pulsar::pulsard::pulsar_daemon_run(&opts.daemon_opts, |starter| {
        // Future: a capture-fed sensor would be registered here as
        // `Ros2Sensor::with_external_source(robodr_sensor_ros2::spawn_blocking_source(..)?)`.
        starter.add_module(Ros2Sensor::new())?;
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
