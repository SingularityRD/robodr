//! RoboDR ROS 2 / DDS graph sensor, packaged as a Pulsar module.
//!
//! **Pulsar-dependent crate**: needs `pulsar-core` and `tokio` and is
//! excluded from the offline build. It is deliberately thin: everything that
//! does not need Pulsar or tokio lives in the pure crate
//! [`robodr_ros2_pipeline`] (re-exported as [`pipeline`]), which is built and
//! tested offline:
//!
//! - the [`Config`] (`[module.robodr-sensor-ros2]`, incl. the `capture`
//!   sub-table) and its validation;
//! - the [`Pipeline`] (RTPS parse with DATA_FRAG reassembly -> profile
//!   deviations + protocol findings -> bounded dedup -> sanitised
//!   [`Finding`]s, observe / enforce marking, profile validation);
//! - the receive-only SPDP multicast socket;
//! - the [`DatagramSource`] seam and the passive-capture adapter (live
//!   `AF_PACKET` or pcap replay).
//!
//! This file only: implements `SimplePulsarModule`, binds the SPDP socket
//! into tokio, runs the capture source on an OS thread, and turns every
//! [`Finding`] into one `ModuleContext::send_threat` call. Every Pulsar item
//! used here was checked against `vendor/pulsar` at commit 4796504 — see
//! docs/PULSAR-INTEGRATION.md for the file-by-file list.
//!
//! It is **read-only on the network**: it opens one receive socket and/or a
//! passive capture socket and never transmits. Enforcement (restricting
//! motion, requesting a safe state) is the Motion Firewall's and the
//! responder's job, never this sensor's.
//!
//! ## Observe mode and refused profiles
//!
//! Every threat carries `extra.mode` (`"enforce"` / `"observe"`),
//! `extra.observe_only` and `extra.profile_status` (`"enforcing"`,
//! `"observing"`, `"refused"`). Observe-only threats' descriptions start
//! with `[observe-only] `. A profile with `locked = false` is observe-only; a
//! profile that fails `Profile::validate` is **refused for enforcement**: the
//! errors are logged, raised as a module warning and sent once as a
//! `robot.ros2.profile_refused` threat, and the sensor keeps running
//! observe-only (fail closed: never act on a profile we cannot trust, never
//! go blind). Consumers must not drive a response from observe-only threats.
//!
//! ## Sources
//!
//! - SPDP multicast socket (`listen_spdp`, default on): reliably shows
//!   *participants*. Most DDS stacks send SEDP (writer/reader announcements)
//!   **unicast**, which this socket does not see.
//! - Passive capture (`capture.enabled`, default off; needs `CAP_NET_RAW`):
//!   sees unicast SEDP and loopback, i.e. *who writes `rt/cmd_vel`*. Opened
//!   in `init_state`; failing to open it fails the module start (an operator
//!   who asked for capture must not silently get a blind spot).
//! - Any other [`DatagramSource`], via [`Ros2Sensor::with_external_source`].
//!
//! All sources feed one [`Pipeline`], so dedup and fragment reassembly span
//! them.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pulsar_core::event::Value;
use pulsar_core::pdk::{ModuleContext, ModuleError, SimplePulsarModule};
use pulsar_core::{Pid, Timestamp};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::task::JoinHandle;

pub use robodr_ros2_pipeline as pipeline;
pub use robodr_ros2_pipeline::{Config, Datagram, DatagramSource, Finding, Pipeline};

use robodr_ros2_pipeline::{load_profile, sanitize, socket, ProfileStatus};

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
    /// Sources come from the config (SPDP socket and/or capture).
    pub fn new() -> Self {
        Self::default()
    }

    /// Also consume datagrams from another source, in addition to the
    /// configured ones.
    pub fn with_external_source(rx: mpsc::Receiver<Datagram>) -> Self {
        Self {
            external: Some(Arc::new(Mutex::new(rx))),
        }
    }
}

/// Run a blocking [`DatagramSource`] on a dedicated OS thread and return the
/// receiving end of a bounded channel (`capacity`, min 1). The thread ends
/// when the source finishes or fails, or when the receiver is dropped (on
/// the next datagram). Backpressure: when the sensor falls behind, the
/// source thread blocks (for live capture, the kernel socket buffer then
/// absorbs or drops; drops are visible in `AfPacketSource::kernel_stats`).
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
                        log::info!(target: MODULE_NAME, "datagram source finished");
                        break;
                    }
                    Err(e) => {
                        log::error!(
                            target: MODULE_NAME,
                            "datagram source failed: {}",
                            sanitize(&e.to_string())
                        );
                        break;
                    }
                }
            }
        })?;
    Ok(rx)
}

/// Running state of the module: the listener task and the capture stop flag.
///
/// Teardown is in [`Drop`], not only in `graceful_stop`: Pulsar's module
/// manager (`src/pulsard/module_manager.rs`) calls `graceful_stop` only on a
/// clean shutdown signal. When the module loop is aborted after the 5 s stop
/// timeout, or exits with an error, the state is simply dropped. Dropping a
/// tokio `JoinHandle` detaches the task rather than cancelling it, so without
/// this `Drop` the listener (and the capture thread) would outlive the module.
/// They would keep sending threats, and a restart would run a second
/// listener next to the first.
pub struct State {
    listener: JoinHandle<()>,
    /// Set on stop so the capture thread exits within one read timeout.
    capture_stop: Option<Arc<AtomicBool>>,
}

impl Drop for State {
    fn drop(&mut self) {
        if let Some(stop) = &self.capture_stop {
            stop.store(true, Ordering::Relaxed);
        }
        self.listener.abort();
    }
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
            log::warn!(target: MODULE_NAME, "{}", sanitize(w));
        }
        if !settings.has_builtin_source() && self.external.is_none() {
            return Err(
                "listen_spdp = false, capture.enabled = false and no external \
                        datagram source is attached; the sensor would see nothing"
                    .into(),
            );
        }

        let profile = load_profile(&settings.profile_path)?;
        let pipeline = Pipeline::new(profile, settings.pipeline);
        if let ProfileStatus::Refused(errors) = pipeline.status() {
            for e in errors {
                log::error!(target: MODULE_NAME, "profile error: {}", sanitize(&e.to_string()));
            }
        }
        if let Some(msg) = pipeline.status_message() {
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

        // Opened last: nothing fallible (and no await) follows, so a failed
        // or cancelled init cannot leak the capture thread.
        let (capture, capture_stop) = match &settings.capture {
            Some(c) => {
                let stop = Arc::new(AtomicBool::new(false));
                let source = c.open(stop.clone()).map_err(|e| {
                    format!(
                        "opening capture {:?}: {} (live capture needs CAP_NET_RAW)",
                        c.input,
                        sanitize(&e.to_string())
                    )
                })?;
                let rx = spawn_blocking_source(source, c.queue_capacity)
                    .map_err(|e| format!("starting capture thread: {e}"))?;
                log::info!(
                    target: MODULE_NAME,
                    "passive capture on {:?} (domains {:?})",
                    c.input,
                    c.domain_ids
                );
                (Some(rx), Some(stop))
            }
            None => (None, None),
        };
        if self.external.is_some() {
            log::info!(target: MODULE_NAME, "consuming an external datagram source");
        }

        let listener = tokio::spawn(listen_loop(
            socket,
            capture,
            self.external.clone(),
            pipeline,
            ctx.clone(),
        ));
        Ok(State {
            listener,
            capture_stop,
        })
    }

    async fn graceful_stop(state: Self::State) -> Result<(), ModuleError> {
        // Teardown (stop flag + abort) is in `State::drop`, so it also runs
        // when Pulsar drops the state without calling this.
        drop(state);
        Ok(())
    }
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

/// Await the next datagram of a channel, or forever when there is none.
/// `None` means the channel closed (its source ended).
async fn recv_channel(rx: Option<&mut mpsc::Receiver<Datagram>>) -> Option<Datagram> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Receive loop over all sources; one threat per *new* finding.
async fn listen_loop(
    socket: Option<UdpSocket>,
    mut capture: Option<mpsc::Receiver<Datagram>>,
    external: Option<SharedReceiver>,
    mut pipeline: Pipeline,
    ctx: ModuleContext,
) {
    for finding in pipeline.status_findings() {
        send(&ctx, &finding);
    }
    // Held for the lifetime of this task; released when it is aborted.
    let mut external: Option<OwnedMutexGuard<mpsc::Receiver<Datagram>>> = match external {
        Some(shared) => Some(shared.lock_owned().await),
        None => None,
    };
    let mut buf = vec![0u8; RECV_BUF_LEN];
    loop {
        if socket.is_none() && capture.is_none() && external.is_none() {
            // A blind sensor must not look healthy. `raise_warning` would
            // leave the module in `Running`; `raise_error` makes Pulsar's
            // module manager stop it (calling `graceful_stop`) and report it
            // as `Failed` in `pulsar status`.
            let msg = "no datagram source left; the ROS 2 sensor is blind";
            log::error!(target: MODULE_NAME, "{msg}");
            ctx.raise_error(msg.into());
            return;
        }
        // Collect the outcome first and handle it after `select!` has
        // returned, so no branch future still borrows `buf` or a receiver.
        let next = tokio::select! {
            r = recv_spdp(socket.as_ref(), &mut buf) => Next::Spdp(r),
            d = recv_channel(capture.as_mut()) => Next::Capture(d),
            d = recv_channel(external.as_deref_mut()) => Next::External(d),
        };
        match next {
            Next::Spdp(Ok((len, peer))) => {
                report(&mut pipeline, &ctx, &buf[..len], &peer.ip().to_string());
            }
            Next::Spdp(Err(e)) => {
                log::warn!(target: MODULE_NAME, "SPDP receive error: {e}");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
            }
            Next::Capture(Some(d)) | Next::External(Some(d)) => {
                report(&mut pipeline, &ctx, &d.payload, &d.src_ip);
            }
            Next::Capture(None) => {
                let msg = "capture source ended; unicast SEDP is no longer watched".to_string();
                log::warn!(target: MODULE_NAME, "{msg}");
                ctx.raise_warning(msg).await;
                capture = None;
            }
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
    Capture(Option<Datagram>),
    External(Option<Datagram>),
}

/// Run one datagram through the pipeline and raise a threat per finding.
fn report(pipeline: &mut Pipeline, ctx: &ModuleContext, payload: &[u8], src_ip: &str) {
    for finding in pipeline.process(payload, src_ip) {
        send(ctx, &finding);
    }
}

/// One finding -> one Pulsar threat.
fn send(ctx: &ModuleContext, finding: &Finding) {
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
    // itself (the process tracker knows it once process-monitor has scanned
    // /proc; otherwise Pulsar logs a lookup error and still sends the threat
    // with an empty image).
    let pid = Pid::from_raw(std::process::id() as i32);
    ctx.send_threat(pid, Timestamp::now(), description.clone(), extra);
    let rule = sanitize(finding.deviation.rule_str());
    if finding.is_observe_only() {
        log::info!(target: MODULE_NAME, "[{rule}] {description}");
    } else {
        log::warn!(target: MODULE_NAME, "[{rule}] {description}");
    }
}
