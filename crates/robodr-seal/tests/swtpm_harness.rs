//! The software-TPM test harness itself (`tests/common`, shared with the
//! depot tests): its ports and its start-up. T24 of
//! docs/SALES-READINESS.md: "swtpm did not start" in two runs of three.
//!
//! The cause: every test process counted its swtpm ports up by two from
//! `40_000 + pid % 5000 * 4`, so two TPM test binaries running at once (pids
//! one apart, bases four apart) walked the same ports, and all eight start
//! attempts failed with "Address already in use" (seen in swtpm's log).

mod common;

use std::net::TcpListener;
use std::sync::Mutex;

/// The two tests allocate ports: run them one at a time (a port one
/// releases may be the next one the other is handed).
static SERIAL: Mutex<()> = Mutex::new(());

/// The ports the old allocator would have handed out first in this process.
fn old_scheme_ports() -> Vec<u16> {
    let base = 40_000 + (std::process::id() % 5000) as u16 * 4;
    (0..20).map(|i| base + i).collect()
}

#[test]
fn a_port_is_free_and_listening_tells_a_server_from_nothing() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for _ in 0..50 {
        let p = common::port();
        assert!(!common::listening(p), "port {p} already has a listener");
        // Free: it can be bound right now.
        let l = TcpListener::bind(("127.0.0.1", p)).expect("the port is free");
        assert!(common::listening(p));
        drop(l);
    }
}

/// Another process holds the ports the old allocator would have used:
/// swtpm must still start (before the fix: eight "Address already in use",
/// then the panic).
#[test]
fn swtpm_starts_while_another_process_holds_the_old_ports() {
    if !common::swtpm_enabled("swtpm_harness") {
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let held: Vec<TcpListener> = old_scheme_ports()
        .into_iter()
        .filter_map(|p| TcpListener::bind(("127.0.0.1", p)).ok())
        .collect();
    // Ports another socket already uses are just as taken for swtpm.
    assert!(!held.is_empty(), "could not occupy any of the old ports");
    let dir = common::tmp("harness-held-ports");
    let sw = common::SwTpm::start(&dir.join("swtpm"));
    assert!(common::listening(sw.port));
    assert!(held
        .iter()
        .all(|l| l.local_addr().map(|a| a.port()).ok() != Some(sw.port)));
    // And it answers as a TPM.
    sw.provision();
    drop(held);
}

/// Readiness asks whether the swtpm process itself listens, not whether
/// anything answers on the port while it runs: another process's listener
/// on the port, with our child alive, fooled the old check
/// (`listening(port)` and the child still running 50 ms later).
#[test]
fn readiness_tells_our_listener_from_another_processes() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let p = l.local_addr().unwrap().port();
    let mut other = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("sleep");
    // What the old check saw: the port answers and the child is running.
    assert!(common::listening(p));
    assert!(other.try_wait().unwrap().is_none());
    // Only the process that holds the socket listens on it.
    assert!(common::listens_on(std::process::id(), p));
    assert!(!common::listens_on(other.id(), p));
    drop(l);
    assert!(!common::listens_on(std::process::id(), p));
    let _ = other.kill();
    let _ = other.wait();
}
