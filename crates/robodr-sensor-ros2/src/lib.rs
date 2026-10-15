//! RoboDR ROS 2 / DDS graph sensor, packaged as a Pulsar module.
//!
//! **Pulsar-dependent crate**: this file needs `pulsar-core` and `tokio` and
//! is excluded from the offline build. The logic lives in Pulsar-independent
//! submodules that are unit-tested on their own:
//!
//! - [`pipeline`]: datagram -> RTPS events -> profile deviations -> bounded
//!   dedup -> sanitised findings (observe-mode tagging included), plus the
//!   [`DatagramSource`] seam for `robodr-capture`;
//! - [`config`]: the `[module.robodr-sensor-ros2]` section and its validation
//!   (domain-id-derived SPDP port);
//! - [`socket`]: the receive-only, `SO_REUSEADDR`, group-bound SPDP socket.
//!
//! This file is only the glue: implement `SimplePulsarModule`, open the
//! sources, and turn every [`Finding`] into one `ModuleContext::send_threat`
//! call. Every Pulsar item used here was checked against `vendor/pulsar` at
//! commit 4796504 — see docs/PULSAR-INTEGRATION.md for the file-by-file list.
//!
//! It is **read-only on the network**: it opens one receive socket and never
//! transmits. Enforcement (restricting motion, rejecting a participant) is the
//! Motion Firewall's and the responder's job, never this sensor's.
//!
//! ## Observe mode
//!
//! While `profile.locked == false` every threat description starts with
//! `[observe-only] ` and `extra` carries `mode = "observe"`,
//! `observe_only = true`; a module warning is also raised (shown by
//! `pulsar status`). Consumers must not drive a response from such threats.
//!
//! ## Known gap: SEDP is usually unicast
//!
//! The SPDP **multicast** socket reliably shows *participants*; most DDS
//! implementations send SEDP (writer/reader announcements) **unicast** to each
//! participant's metatraffic port, which this socket does not see. Topic-level
//! detection needs the capture-based listener (`robodr-capture`) feeding the
//! same pipeline through [`Ros2Sensor::with_external_source`].

pub mod config;
pub mod pipeline;
pub mod socket;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pulsar_core::event::Value;
use pulsar_core::pdk::{ModuleContext, ModuleError, SimplePulsarModule};
use pulsar_core::{Pid, Timestamp};
use robodr_events::profile::Profile;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::task::JoinHandle;

pub use config::Config;
pub use pipeline::{Datagram, DatagramSource, Finding, Pipeline, ProfileMode};

/// Module name, i.e. the `[module.<name>]` section in `pulsar.toml`.
pub const MODULE_NAME: &str = "robodr-sensor-ros2";

/// Largest UDP payload; RTPS datagrams are at most this long.
const RECV_BUF_LEN: usize = 65_535;

/// Pause after a socket receive error so a persistent error cannot spin.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Receiving end of an external datagram source, shared so the module can be
/// stopped and restarted by the daemon (each start re-acquires the lock; the
/// previous listener releases it when aborted).
type SharedReceiver = Arc<Mutex<mpsc::Receiver<Datagram>>>;

/// The Pulsar module. Register it with
/// `PulsarDaemonStarter::add_module(Ros2Sensor::new())` (see `robodr-pulsard`).
#[derive(Default)]
pub struct Ros2Sensor {
    external: Option<SharedReceiver>,
}

impl Ros2Sensor {
    /// SPDP multicast socket only.
    pub fn new() -> Self {
        Self::default()
    }

    /// Also consume datagrams from another source (e.g. `robodr-capture`), in
    /// addition to the SPDP socket unless `listen_spdp = false`.
    pub fn with_external_source(rx: mpsc::Receiver<Datagram>) -> Self {
        Self {
            external: Some(Arc::new(Mutex::new(rx))),
        }
    }
}

/// Run a blocking [`DatagramSource`] on a dedicated OS thread and return the
/// channel to pass to [`Ros2Sensor::with_external_source`]. The thread ends
/// when the source finishes or fails, or when the receiver is dropped.
///
/// Backpressure: the channel is bounded (`capacity`, min 1); when the sensor
/// falls behind, the source thread blocks. A capture source that must never
/// block should buffer or drop internally.
pub fn spawn_blocking_source<S>(
    source: S,
    capacity: usize,
) -> std::io::Result<mpsc::Receiver<Datagram>>
where
    S: DatagramSource + Send + 'static,
{
    let (tx, rx) = mpsc::channel(capacity.max(1));
    std::thread::Builder::new()
        .name("robodr-dgram-src".into())
        .spawn(move || {
            let mut source = source;
            loop {
                match source.recv() {
                    Ok(Some(d)) => {
                        if tx.blocking_send(d).is_err() {
                            break; // sensor gone
                        }
                    }
                    Ok(None) => {
                        log::info!(target: MODULE_NAME, "external datagram source finished");
                        break;
                    }
                    Err(e) => {
                        log::error!(target: MODULE_NAME, "external datagram source failed: {e}");
                        break;
                    }
                }
            }
        })?;
    Ok(rx)
}

pub struct State {
    listener: JoinHandle<()>,
}

impl SimplePulsarModule for Ros2Sensor {
    type Config = Config;
    type State = State;

    const MODULE_NAME: &'static str = MODULE_NAME;
    const DEFAULT_ENABLED: bool = false;

    async fn init_state(
        &self,
        config: &Self::Config,
        ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        let (settings, warnings) = config.validate()?;
        for w in &warnings {
            log::warn!(target: MODULE_NAME, "{w}");
        }
        if settings.spdp.is_none() && self.external.is_none() {
            return Err(
                "listen_spdp = false but no external datagram source is attached; \
                        the sensor would see nothing"
                    .into(),
            );
        }

        let profile = load_profile(&settings.profile_path)?;
        let pipeline = Pipeline::new(profile, settings.dedup_capacity);
        if pipeline.mode().is_observe() {
            let msg = format!(
                "profile '{}' is NOT locked: observe mode, deviations are tagged observe-only",
                pipeline::sanitize(&pipeline.profile().model)
            );
            log::warn!(target: MODULE_NAME, "{msg}");
            ctx.raise_warning(msg).await;
        }

        let socket = match settings.spdp {
            Some(spdp) => {
                let std_socket = socket::bind_spdp_multicast(spdp.group, spdp.port, spdp.interface)
                    .map_err(|e| {
                        format!(
                            "binding SPDP {}:{} on {}: {e}",
                            spdp.group, spdp.port, spdp.interface
                        )
                    })?;
                let socket = UdpSocket::from_std(std_socket)
                    .map_err(|e| format!("registering SPDP socket with tokio: {e}"))?;
                log::info!(
                    target: MODULE_NAME,
                    "listening for SPDP on {}:{} (domain {}, interface {})",
                    spdp.group,
                    spdp.port,
                    settings.domain_id,
                    spdp.interface
                );
                Some(socket)
            }
            None => None,
        };
        if self.external.is_some() {
            log::info!(target: MODULE_NAME, "consuming an external datagram source");
        }

        let listener = tokio::spawn(listen_loop(
            socket,
            self.external.clone(),
            pipeline,
            ctx.clone(),
        ));
        Ok(State { listener })
    }

    async fn graceful_stop(state: Self::State) -> Result<(), ModuleError> {
        state.listener.abort();
        Ok(())
    }
}

fn load_profile(path: &Path) -> Result<Profile, ModuleError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("reading profile {}: {e}", path.display()))?;
    let profile: Profile = serde_json::from_str(&raw)
        .map_err(|e| format!("parsing profile {}: {e}", path.display()))?;
    Ok(profile)
}

/// Await the next SPDP datagram, or forever when there is no socket.
async fn recv_spdp(
    socket: Option<&UdpSocket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    match socket {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

/// Await the next external datagram, or forever when there is no source.
/// `None` means the source closed.
async fn recv_external(rx: Option<&mut mpsc::Receiver<Datagram>>) -> Option<Datagram> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Receive loop over both sources; one threat per *new* deviation.
async fn listen_loop(
    socket: Option<UdpSocket>,
    external: Option<SharedReceiver>,
    mut pipeline: Pipeline,
    ctx: ModuleContext,
) {
    // Held for the lifetime of this task; released when it is aborted.
    let mut external: Option<OwnedMutexGuard<mpsc::Receiver<Datagram>>> = match external {
        Some(shared) => Some(shared.lock_owned().await),
        None => None,
    };
    let mut buf = vec![0u8; RECV_BUF_LEN];
    loop {
        if socket.is_none() && external.is_none() {
            let msg = "no datagram source left; the ROS 2 sensor is blind".to_string();
            log::error!(target: MODULE_NAME, "{msg}");
            ctx.raise_warning(msg).await;
            return;
        }
        // Collect the outcome first and handle it after `select!` has
        // returned, so no branch future still borrows `buf` or `external`.
        let next = tokio::select! {
            r = recv_spdp(socket.as_ref(), &mut buf) => Next::Spdp(r),
            d = recv_external(external.as_deref_mut()) => Next::External(d),
        };
        match next {
            Next::Spdp(Ok((len, peer))) => {
                report(&mut pipeline, &ctx, &buf[..len], &peer.ip().to_string());
            }
            Next::Spdp(Err(e)) => {
                log::warn!(target: MODULE_NAME, "SPDP receive error: {e}");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
            }
            Next::External(Some(d)) => report(&mut pipeline, &ctx, &d.payload, &d.src_ip),
            Next::External(None) => {
                log::warn!(target: MODULE_NAME, "external datagram source closed");
                external = None;
            }
        }
    }
}

/// One step of the receive loop.
enum Next {
    Spdp(std::io::Result<(usize, std::net::SocketAddr)>),
    External(Option<Datagram>),
}

/// Run one datagram through the pipeline and raise a threat per finding.
fn report(pipeline: &mut Pipeline, ctx: &ModuleContext, payload: &[u8], src_ip: &str) {
    for finding in pipeline.process(payload, src_ip) {
        let description = finding.description();
        // `Value::try_from` is pulsar-core's inherent fn (serialises through
        // TOML), not `TryFrom`. A failure only drops the structured part.
        let extra = match Value::try_from(finding.extra()) {
            Ok(v) => Some(v),
            Err(e) => {
                log::warn!(target: MODULE_NAME, "threat extra not serialisable: {e}");
                None
            }
        };
        // A network peer has no local pid: attribute the threat to the daemon
        // itself (the process tracker knows it once process-monitor has
        // scanned /proc; otherwise Pulsar logs a lookup error and still sends
        // the threat with an empty image).
        let pid = Pid::from_raw(std::process::id() as i32);
        ctx.send_threat(pid, Timestamp::now(), description.clone(), extra);
        if finding.mode.is_observe() {
            log::info!(target: MODULE_NAME, "[{}] {description}", finding.deviation.rule);
        } else {
            log::warn!(target: MODULE_NAME, "[{}] {description}", finding.deviation.rule);
        }
    }
}
